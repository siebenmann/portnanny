#!/usr/bin/python
#
# The actual core, high-level logic of portnanny.
# This is basically: process arguments, establish logging, read config
# file, set up server sockets, drop privledges, and then go into the main
# loop, which repeatedly checks for updated rules and actions files, gets
# a new connection, and dispatches it.
#

import sys, time
import getopt
import thread
try:
	import sets
	_hassets = 1
except:
	_hassets = 0

import log
import conntrack, hinfo
import rules, actions
import cfloader
import proc

#
# Rules evaluation can happen in threads, since it can take quite a while.
# When it does, we need some cross-thread data structures to return the
# results. We cannot handle actions in threads, because on some operating
# systems (say, normal Linux 2.4) only the thread that fork()'d a process
# can wait() for it, which means that we must fork() in the main thread
# since that's where we wait().
#
# ruleslock guards write access to certain communication variables that
# we want to stay accurate. These are 'rulesres', the list of resolved
# rules, 'threadcount' the count of currently active threads, and the
# 'totconnects' counter (which must be updated in rules).
#
# ISSUE: do we need to protect the hinfo connection time stuff with its
# own lock, or are scrambled accesses to it harmless? (I think so.)
ruleslock = thread.allocate_lock()
rulesres = []
threadcount = 0
threadhigh = 0

# This counter adds up total connections ever, because we like to know
# this sort of trivia. If 'aftermaxthreads' is set in the configuration
# file, this doesn't include anything handled that way.
totconnects = 0
# This is timer information.
totruleTime = 0.0
# This is not the same as totconnects, by the way. Totconnects counts
# everything that got past getpeername(), but this only counts things
# we actually matched rules for.
totrules = 0

# How many socket service loops and how many (raw) observed
# connections we have had. This is distinct from totconnects, which
# counts only rules-checking connections and thus does not include
# overloaded connections if 'aftermaxthreads' is set, or things
# which failed getpeername().
totloops = 0
totconns = 0

# Called to reap a PID from the child handler.
def reaper(pid):
	log.debug(4, "reaped PID %d" % (pid,))
	conntrack.down(pid)

# Emergency flush, called from a signal handler.
def kickme():
	log.debug(2, "force-clearing IP times")
	hinfo.cleariptimes()
# Report information on current state.
def repstate():
	log.report("status: total lifetime connections: %d" % (totconnects,))
	pids = conntrack.getpids()
	if len(pids) == 0:
		log.report("status: no active connections.")
	else:
		log.report("status: %d active connections:" % len(pids))
		pids.sort()
		# Now, this is only a snapshot, so take care here. A kid could
		# have died before we get around to pulling it.
		for pid in pids:
			try:
				pi = str(conntrack.getpid(pid))
			except KeyError:
				continue
			log.report("status: " + pi)
	# This is put at the bottom to bookend the active connection info.
	log.report("status: per IP first/last connection times entries: %d" % \
		   (hinfo.iptimessize()))
	if threadcount or threadhigh > 1:
		log.report("status: %d active rules evaluation threads (%d highwater)." % \
			   (threadcount, threadhigh))

	# totruleTime is already a float, because time.time() returns them.
	if totrules and totruleTime:
		log.report("status: average rule evaluation time over %d evals: %0.4f seconds" % (totrules, totruleTime / totrules))

	if totloops:
		log.report("status: %d loops, %d conns, %0.1f conns average" %
			   (totloops, totconns, (totconns*1.0)/totloops))

def conninfo(hi, clslist = None):
	if not clslist:
		return "%s -> %s@%s" % (hi.getip(), hi.getlport(), hi.getlip())
	else:
		return "%s/%s" % (hi.getip(), " ".join(clslist))

whatToFunc = {
	'run': proc.runcmd, 'failrun': proc.runcmd,
	'msg': proc.sendmsg, 'failmsg': proc.sendmsg,
	}
# Dispatch a new socket to the correct action. This involves:
# 1. Obtain HostInfo data store of information about the host.
# 2. Evaluate the classifier rules to find matching rules.
# 3. Pass the matching rules to the actions rules, to determine
#    the action to take.
# 4. Perform the action.
# Any of these steps can tell us that there is (gosh) no work
# to be done, in which case we quietly drop the connection.
def rule(newsock, rroot, aroot):
	global totconnects; global totrules; global totruleTime
	
	hi = hinfo.fromfd(newsock)
	if not hi:
		log.debug(1, "Could not get hostinfo, passing.")
		proc.closesock(newsock)
		return None

	# At this point this is a real connection and we will count it.
	ruleslock.acquire()
	totconnects += 1
	ruleslock.release()

	# If we are missing one or the other root, there is
	# no point in doing anything; we can never match an
	# action. Kill it off and punt.
	if not (rroot and aroot):
		log.debug(2, "A root is missing or empty, dropping %s" %\
			  (conninfo(hi),))
		proc.closesock(newsock)
		return None

	# Run it past the rules, and see if anything comes out. If not
	# we're done.
	ruleslock.acquire(); totrules += 1; ruleslock.release()
	st = time.time()
	rmatch = rroot.eval(hi)
	et = time.time()
	ruleslock.acquire(); totruleTime += (et-st); ruleslock.release()
	if not rmatch:
		log.debug(2, "Nothing matched %s" % (conninfo(hi),))
		proc.closesock(newsock)
		return None
	return (newsock, hi, rmatch)

def action(newsock, hi, rmatch, aroot):
	# While we were fiddling around, our actions might have vanished.
	# If so, we're getting outta here.
	if not aroot:
		return

	rmnames = [x.clsname for x in rmatch]

	# Run it past the actions and see if we have an action to do.
	# If not, we're done. Action evaluation itself can fail if the
	# configuration file supplies a bad string that cannot be formatted.
	action = None
	try:
		action = aroot.genaction(hi, rmatch)
	except actions.BadAction, e:
		log.error("error preparing action for %s: %s" %\
			  (conninfo(hi, rmnames), str(e)))
	if not action:
		log.debug(2, "No actions for %s" % (conninfo(hi, rmnames),))
		proc.closesock(newsock)
		return
	
	# Actions have two components: messages to log, and something to
	# do. Either can be blank (hopefully both are not blank, but).
	for le in action.logmsgs:
		log.report(le)

	# Activate the action's work function (if any) in a separate
	# process and track it if necessary. We do not track the message
	# processes, since they are expected to die fast and we can do
	# without the churning of data structures in the parent.
	if action.what:
		func = whatToFunc[action.what]
		try:
			pid = proc.forkaction(newsock, func, action)
		except proc.Kaboom, e:
			log.error("Cannot start action for %s: %s" %\
				  (conninfo(hi, rmnames), str(e)))
			proc.closesock(newsock)
			return
		log.debug(2, "started PID %d for %s: %s %s" %\
			  (pid, conninfo(hi, rmnames),
			   action.what, action.argstring))
		if action.what.endswith("run"):
			conntrack.up(pid, hi.getip(), rmnames)
	else:
		log.debug(2, "dropping %s" % (conninfo(hi, rmnames),))
	# In all cases, our side of the socket is now dead and we close
	# it. (The child may still have a live connection.)
	proc.closesock(newsock)

# Finish up a completed rule processing by dispatching to actions.
# This always happens in the main thread, which is why this whole
# mess is so complicated (and irritating).
def dispatchaction(aroot):
	# Because we are the only place where stuff comes off this list,
	# we can do this unlocked, because we can never think there is
	# stuff on the list when there isn't (the only fatal case).
	if not rulesres:
		return
	ruleslock.acquire()
	proc.syncpoint.decr()
	r = rulesres.pop(0)
	ruleslock.release()
	action(r[0], r[1], r[2], aroot)

# Handle rule processing in a thread, locking and signalling if we
# have a result.
def threadrule(newsock, rroot, aroot):
	global threadcount
	res = rule(newsock, rroot, aroot)
	ruleslock.acquire()
	threadcount -= 1
	if res:
		rulesres.append(res)
		proc.syncpoint.incr()
	ruleslock.release()

# Dispatch a new socket. If we are using threads and we have not blown
# our thread limit, we dispatch rule processing in a thread and come
# back later when it's done (in dispatchrest). Otherwise, we do it all
# ourselves in the mainline, first evaluating the rule and then going
# on (if appropriate) to actions.
def dispatch(newsock, rroot, aroot, tcfg):
	global threadcount; global threadhigh
	# We may have threads available, or we may not. Having threads
	# available is the simple case, so we handle that first.
	if threadcount < tcfg.max:
		# We increment the thread counter immediately for the
		# best load limiting; otherwise we are the mercy of
		# whenever the scheduling process gets the new thread far
		# enough along to increment the count.
		ruleslock.acquire()
		threadcount += 1
		if threadcount > threadhigh:
			threadhigh = threadcount
		ruleslock.release()
		thread.start_new_thread(threadrule, (newsock, rroot, aroot))
		return
	# Either threads are off entirely or we are over the thread limit.
	# If we've hit the limit, what we do depends on whether maxclass is
	# set; if it is, instead of evaluating the rules in the mainline we
	# synthetically produce a match against that class.
	# We respect maxclass if and only if threading is enabled at all;
	# otherwise we always evaluate in the mainline as a single-threaded
	# program.
	if tcfg.maxclass and tcfg.max:
		# Unfortunately we need to duplicate a bit of rule()'s work,
		# as we need a hostinfo object as well as the fake rule.
		hi = hinfo.fromfd(newsock)
		if not hi:
			log.debug(1, "could not get hostinfo in threadmax")
			proc.closesock(newsock)
			return
		log.debug(2, "too many threads, putting %s connection in %s" % \
			  (hi.getip(), tcfg.maxclass))
		# We have to add the GLOBAL (fake) rule in order to follow
		# the rules; this could be important if the thread overflow
		# class runs something.
		res = [newsock, hi,
		       [rules.genfakerule(tcfg.maxclass), rules.globalrule]]
	else:
		if tcfg.max:
			log.debug(1, "too many threads, handling new socket directly")
		res = rule(newsock, rroot, aroot)
	if not res:
		return
	action(res[0], res[1], res[2], aroot)

class Reloader:
	def __init__(self, fname, loadfunc, error, ftype, droponerr):
		self.fname = fname
		self.loadfunc = loadfunc
		self.error = error
		self.ftype = ftype
		self.droponerr = droponerr
		self.root = None
		# oldtime is 'the last time we tried to reload', with the
		# special value of None for 'the file wasn't there' (what
		# proc.getmtime() returns).
		self.oldtime = 0
	def curroot(self):
		newtime = proc.getmtime(self.fname)
		# This works out so that we complain only once about a
		# missing file, but we do complain once.
		if newtime == self.oldtime:
			return self.root
		# Once we are comitted to loading, kill the old root
		# if we want to drop on errors.
		if self.droponerr:
			self.root = None
		self.oldtime = newtime
		try:
			self.root = self.loadfunc(self.fname)
			log.debug(5, "reloaded %s file %s dated %s" % \
				  (self.ftype, self.fname, self.oldtime))
		except self.error, e:
			log.error("error loading %s file: %s" % \
				  (self.ftype, str(e)))
		return self.root

# This sets up and stores thread configuration information.
class ThreadConf:
	def __init__(self, cfg, threadmax):
		# Do we want to use threading, and if so, how many?
		if threadmax is None and "maxthreads" in cfg:
			threadmax = cfg["maxthreads"]
		elif threadmax is None:
			threadmax = 0
		self.max = threadmax
		if self.max and 'aftermaxthreads' in cfg:
			self.maxclass = cfg['aftermaxthreads']
		else:
			self.maxclass = None

def serve(cfg, sockl, threadmax):
	global totloops, totconns
	# Our expiry timers.
	ttick = 0
	if 'dropipafter' not in cfg:
		expireevery = -1
	elif 'expireevery' in cfg:
		expireevery = cfg['expireevery']
	else:
		# Pick a default.
		expireevery = 60
	
	# Set up our thread configuration object.
	tcfg = ThreadConf(cfg, threadmax)
		
	# Do we want to drop a file on error?
	droponerr = 0
	if 'onfileerror' in cfg and cfg['onfileerror'] == 'drop':
		droponerr = 1

	# Set up the objects through which we will obtain the roots of
	# the rules and actions evaluators.
	loadRules = Reloader(cfg['rulefile'], rules.parsefile, rules.BadInput,
			     "rules", droponerr)
	loadActs = Reloader(cfg['actionfile'], actions.parsefile,
			    actions.BadAction, "actions", droponerr)

	# We attempt our first load now, rather than waiting for our
	# first connection, so that we produce feedback on program
	# startup about broken configuration files.
	rroot = loadRules.curroot()
	aroot = loadActs.curroot()

	# Having acquired our initial setup, start running forever.
	while 1:
		# We are now done. Perform periodic sweep actions.
		# Note that 'expireevery' of 0 means 'on every connection';
		# use a negative number to turn it off.
		if expireevery >= 0 and time.time() - ttick >= expireevery:
			log.debug(3, "Expiring the IP times info")
			ttick = time.time()
			hinfo.expireiptimes()
		# (we do these at the bottom, because they may take some
		# time, and we want to service our active connection first.)
		# Yes, yes, this is the top. Relative to getting a new
		# socket to deal with, it's the bottom.

		newsocks = proc.nextconnection(sockl, reaper)

		# Immediately attempt reload; god knows how long we've
		# been asleep.
		rroot = loadRules.curroot()
		aroot = loadActs.curroot()

		# We may have rules that have completed evaluations
		# waiting for us to turn them into actual actions.
		dispatchaction(aroot)

		# Dispatch does all the work of handling a new connection.
		# newsocks is [] if we were just being signalled that
		# there was work waiting for dispatchaction().
		# dispatch() will thread or not thread things as
		# appropriate.
		if newsocks:
			totloops += 1; totconns += len(newsocks)
			for newsock in newsocks:
				dispatch(newsock, rroot, aroot, tcfg)

		# Make sure we are disassociating ourselves from the new
		# sockets to encourage their deallocation & cleanup, if any
		# is necessary.
		newsocks = None
		# We cannot explicitly close the new sockets, because they
		# may be alive in an asynchronously threaded rules
		# evaluation.

# Check for file loading and some 'lint' issues.
def checkcfg(cfg):
	__pychecker__ = 'no-abstract'
	if not _hassets:
		log.die("-C is not available on this version of Python (no sets module).")
	try:
		rroot = rules.parsefile(cfg['rulefile'])
	except rules.BadInput, e:
		log.error("error loading rules file %s: %s" %\
			  (cfg['rulefile'], str(e)))
		rroot = None
	try:
		aroot = actions.parsefile(cfg['actionfile'])
	except actions.BadAction, e:
		log.error("error loading actions file %s: %s" %\
			  (cfg['actionfile'], str(e)))
		aroot = None
	if rroot == None or aroot == None:
		sys.exit(1)
	if len(rroot) == 0:
		log.error("No rules in the rules file.")
	if len(aroot) == 0:
		log.error("No actions in the actions file.")
	if not (rroot and aroot):
		sys.exit(1)
	
	# 'lint' check: test that the two files define the same set of
	# rules.
	rrset = sets.ImmutableSet(rroot.getclassnames())
	arset = sets.ImmutableSet(aroot.getclassnames())
	# It's okay to have actions and not rules for the default message
	# sources and for the synthetic GLOBAL rule.
	okeset = sets.ImmutableSet(('GLOBAL', 'DEFAULTMSGS', 'DEFAULT-REJECT',
				    'DEFAULT-IPMAX', 'DEFAULT-CONNMAX'))
	onlyRules = rrset.difference(arset)
	onlyActions = arset.difference(rrset).difference(okeset)
	rForDef = rrset.intersection(okeset)

	if onlyRules:
		l = list(onlyRules); l.sort()
		log.error("Rules-only classes: %s" % " ".join(l))
	if onlyActions:
		l = list(onlyActions); l.sort()
		log.error("Actions-only classes: %s" % " ".join(l))
	if rForDef:
		l = list(rForDef); l.sort()
		log.error("Default actions classes with rules: %s" % " ".join(l))

	if not (onlyRules or onlyActions or rForDef):
		return
	sys.exit(1)		

def startup(cfname, checkonly, threadmax):
	# First, parse the config file.
	try:
		cfg = cfloader.parsefile(cfname)
	except cfloader.BadInput, e:
		log.die("Cannot load conf file: %s" % (str(e),))

	# If we are just checking, go straight there:
	if checkonly:
		checkcfg(cfg)
		log.debug(1, "No problems found.")
		return

	# First we do what needs privledges: binding sockets.
	sockl = []
	for h, p in cfg['listen']:
		try:
			sockl.append(proc.getsocket(h, p))
		except proc.Kaboom, e:
			log.die("Could not establish socket %s@%s: %s" % \
				(p, h, str(e)))

	# Renounce privledges if told to.
	if cfg.has_key('user'):
		try:
			proc.changetouser(cfg['user'])
		except proc.Kaboom, e:
			log.die("Could not drop privledges to %s: %s" % \
				(cfg['user'], str(e)))

	# Initialize global parameters.
	if cfg.has_key('dropipafter'):
		hinfo.setiptimesdur(cfg['dropipafter'])
	if cfg.has_key('substitutions'):
		if cfg['substitutions'] == 'off':
			actions.dosubstitutions(0)
		else:
			actions.dosubstitutions(1)

	proc.initsignals(kickme, repstate)
	serve(cfg, sockl, threadmax)

def usage():
	log.die("usage: portnanny2 [-v|-V NUM] [-M MAXTHREADS] [-S STACK] [-C] [-l] conffile")
def main(sargs):
	usesyslog = 0
	checkonly = 0
	threadmax = None
	stacklim = None
	try:
		opts, args = getopt.getopt(sargs, "vV:p:lCM:S:", [])
	except getopt.error, cause:
		log.warn(str(cause))
		usage()
	for o, a in opts:
		if o == '-v':
			log.setdebuglevel(1)
		elif o == '-V':
			log.setdebuglevel(int(a))
		elif o == '-p':
			log.setprogname(a)
		elif o == '-l':
			usesyslog = 1
		elif o == '-C':
			checkonly = 1
		elif o == '-S':
			if a == 'unlimited':
				stacklim = -1L
			else:
				try:
					stacklim = int(a)*1024L
				except ValueError:
					log.die("Bad stack limit '%s'" % a)
		elif o == '-M':
			threadmax = int(a)
			if threadmax < 0:
				threadmax = 0
		else:
			log.die("Chris failed to properly parse option: "+o)
	if len(args) != 1:
		usage()
	# We switch to syslog immediately on startup if told to; all further
	# errors, even fatal ones, may emerge through there.
	if usesyslog:
		log.usesyslog()

	# Set RLIMIT_STACK. Thanks, glibc!
	if stacklim is not None:
		res = proc.setstacklim(stacklim)
		if res:
			log.error("Could not set stacklimit %s: %s" % (stacklim, res))
	# Portnanny only uses threads to deal with things that stall at the
	# operating system level; they don't do any expensive Python-level
	# operations. Because Python is single-threaded at the interpreter
	# bytecode level, we effectively want just voluntary preemption at
	# stall points; switching back and forth between active threads at
	# other times is somewhere between pointless and counterproductive.
	# To approximate this, we tell Python to check for thread switches
	# (and as a side effect, signals) only very, very infrequently.
	# The number here is arbitrary but large.
	sys.setcheckinterval(1000000)

	# Start up the configuration file.
	startup(args[0], checkonly, threadmax)

if __name__ == "__main__":
	main(sys.argv[1:])
