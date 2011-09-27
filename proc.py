#
# This file does all of the gory bits of low-level Unix mangling.
# As such it is a grabbag of random functions.

import socket, fcntl, signal, select, sys, os, pwd
import resource
# Regrettably, we still need to build this ourselves.
import group

class Kaboom(Exception):
	pass

# Open up a listening socket for, you know, server purposes.
def getsocket(h, p):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		# Insure that kids do not inherit this.
		fcntl.fcntl(sock.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
		sock.bind((h, int(p)))
		sock.setblocking(0)
		# This number is reasonably arbitrary, but large is better
		# than small.
		sock.listen(100)
	except socket.error, e:
		# WE LOVE THEM SOCKET ERRORS, WE DO.
		# Admirable how they break all the rules, innit!
		raise Kaboom, e[-1]
	except EnvironmentError, e:
		raise Kaboom, e
	return sock

#
# Changing to a user requires root privledges.
# Not optimizing away the case of 'user' being the current user
# is deliberate, for reasons that do not comfortably fit in this
# margin.
#
# Dropping privledges from root to some other user must be done in the
# right order; in particular, one must setuid() *last*. As initgroups
# sets only the supplementary groups, we setgid() first.  If we were
# content to not set supplementary groups, we could use only pure
# python, without our 'group' extension module. However, it turns out
# that supplementary groups are important sometimes.
#
def changetouser(user):
	try:
		uinfo = pwd.getpwnam(user)
	except KeyError:
		raise Kaboom, "unknown user "+user
	uid = uinfo[2]
	gid = uinfo[3]
	try:
		os.setgid(gid)
		group.initgroups(user, gid)
		os.setuid(uid)
	except EnvironmentError, e:
		raise Kaboom, e
	# Confirm it, just to be sure.
	if os.getuid() != uid or os.getgid() != gid:
		raise Kaboom, "after droppriv, UID or GID was not that of target"

# Set up any signal handlers we routinely care about. We shim the
# callback for SIGUSR1, because at the upper level we so do not care
# about the arguments to signal functions.
def initsignals(usr1func, usr2func):
	def usr1(n, f):
		__pychecker__ = "no-argsused"
		usr1func()
	def usr2(n, f):
		__pychecker__ = "no-argsused"
		usr2func()
	signal.signal(signal.SIGUSR1, usr1)
	signal.signal(signal.SIGUSR2, usr2)

# Get the mtime of a given file. If the file does not exist, return
# None.
def getmtime(fname):
	try:
		return os.stat(fname).st_mtime
	except EnvironmentError:
		return None

# Attempt to reap and report back any dead children.
# Because the callback is not guaranteed to be reentrant, _reaper cannot
# be reentrant. This implies we cannot directly call _reaper() while it
# is also callable as a signal handler.
def _reaper(callback):
	while 1:
		try:
			(pid, stat) = os.waitpid(-1, os.WNOHANG)
		except EnvironmentError:
			return
		# A PID of zero means we have live kids and no more
		# zombies, so bail.
		if pid == 0:
			return
		# Otherwise, call back up and forget it.
		callback(pid)

# This class creates selectable objects that can be used to pass counted
# notifications of pending work between threads. 'selectable' means that
# you can hand them to select(). 'counted' means that they keep track of
# how many work items. The .incr method adds a work item; .decr takes it
# off. .decr blocks if there is no work item to take off.
#
# Internally notifiers are pipe pairs. .incr writes a byte to the write
# end of the pipe, .decr reads a byte from the read end, and we export
# .fileno() so that select can select on the read end.
class Notifier:
	def __init__(self):
		self.pipe = os.pipe()
		# Insure that the pipe vanishes on exec() and does not
		# pass into children to get read from or written to to
		# foul the whole exercise up.
		fcntl.fcntl(self.pipe[0], fcntl.F_SETFD, fcntl.FD_CLOEXEC)
		fcntl.fcntl(self.pipe[1], fcntl.F_SETFD, fcntl.FD_CLOEXEC)
	def fileno(self):
		return self.pipe[0]
	def incr(self):
		os.write(self.pipe[1], "a")
	def decr(self):
		# This will pause if there is nothing there, so beware.
		os.read(self.pipe[0], 1)

# This is our magic synchronization point. It probably should be
# cleaner, but as it is nextconnection() has to be intimately aware
# of it anyways so we might as well make it a magic global.
syncpoint = Notifier()

# To maximize our chance of not screwing Python internals up with
# a huge signal load, we hook SIGCHLD to the reaper only when we
# are sitting in signal wait.
def nextconnection(sockl, pidreaper):
	def sigchld(n, f):
		__pychecker__ = "no-argsused"
		_reaper(pidreaper)
	osigc = signal.signal(signal.SIGCHLD, sigchld)
	# Having set our signal handler, we force ourselves to process
	# any pending dead kids by sending ourselves a synthetic SIGCHLD.
	# We can't call _reaper() directly because it isn't reentrant
	# and calling it directly wouldn't block out a SIGCHLD call.
	# We can't call it before the signal(), because that creates a
	# window for kids to die but not be noticed.
	os.kill(os.getpid(), signal.SIGCHLD)
	nsocks = []
	# This is sleazy, but we need it.
	myl = sockl + [syncpoint,]
	while not nsocks:
		seltup = ([], [], [])
		try:
			seltup = select.select(myl, [], [], None)
		except select.error:
			pass
		if not seltup[0]:
			continue
		# Okay, we have a connection somewhere. Dancing and cheering.
		# Pull it out of seltup[0] and get the damn socket.
		for rsock in seltup[0]:
			if rsock is syncpoint:
				continue
			try:
				# this while loop ends only when socket.error
				# fires.
				while 1:
					(nsock, addr) = rsock.accept()
					# We must insure that this
					# socket will not be inherited
					# by anyone else we are busy
					# spawning.
					fcntl.fcntl(nsock.fileno(),
						    fcntl.F_SETFD,
						    fcntl.FD_CLOEXEC)
					nsocks.append(nsock)
			except socket.error:
				# Note that it is possible for people
				# to close the connection before we get
				# around to accept()'ing it.
				pass
		# It may be that *all* of our connections were, well,
		# kind of bogus. However, we can still have the syncpoint
		# signalling us.
		if syncpoint in seltup[0]:
			# We cannot just return None, because we want to
			# cancel the SIGCHLD signal handler on the way out.
			# This avoids us getting into funny situations where
			# we reap children before they are in our data
			# structures (result: havoc).
			break
	signal.signal(signal.SIGCHLD, osigc)
	return nsocks
	

# This carefully wraps a socket close call against errors. Because
# we may call this in the parent while the child is still actively
# using the socket, we do not shutdown() the socket, just drop our
# reference to it.
def closesock(sock):
	try:
		sock.close()
	except socket.error:
		pass
	except EnvironmentError:
		pass

# ---
# This is where we actually do something.

# Send a message out and then go bye. Bye!
def sendmsg(action):
	def sigalrm(n, f):
		__pychecker__ = 'no-argsused'
		os._exit(1)
	try:
		signal.signal(signal.SIGALRM, sigalrm)
		signal.alarm(2)
		msg = action.argstring
		# This is a lame attempt to be both convenient and to
		# not always force \r\n on the end of messages. Someday
		# I'll find a better solution.
		if msg[-1] in ('\r', '\n'):
			sys.stdout.write(msg)
		else:
			sys.stdout.write(msg + "\r\n")
		sys.stdout.flush()
		os._exit(0)
	except:
		os._exit(1)

# This is more complex because we have to set up the environment before
# exec.
def runcmd(action):
	# The argument list is presplit for us, because of security
	# issues involving string substitution.
	cmd = action.arglist
	os.environ.update(action.env)
	try:
		os.execvp(cmd[0], cmd)
	except:
		os._exit(127)

# Fork an action and perform the function embedded in it.
def forkaction(sock, func, action):
	sys.stdin.flush()
	sys.stdout.flush()
	sys.stderr.flush()
	pid = None
	try:
		pid = os.fork()
	except EnvironmentError, e:
		raise Kaboom, e
	if pid > 0:
		return pid
	# We are now in the child. We need to be careful here.
	fn = sock.fileno()
	# Since this is our socket descriptor, we don't want it closed
	# on exec.
	fcntl.fcntl(fn, fcntl.F_SETFD, 0)
	os.dup2(fn, 0); os.dup2(fn, 1); os.dup2(fn, 2)
	# It can happen that the socket file descriptor itself was
	# given FD 0..2 (this usually requires portnanny to have been
	# start by something strange that closed 0..2, so that when
	# we started opening things we inherited them for ourselves).
	# In this case it is fatal to blindly close the socket; we
	# can only do so if its file descriptor is 3 or more.
	# Because Python assumes it can write errors to stderr, this
	# case is dangerous in general and we probably need to step
	# on it in initialization.
	if fn > 2:
		sock.close()
	# Try to close any stray sockets.
	for fd in range(3,20):
		try:	os.close(fd)
		except:	pass

	# Invoke the action.
	func(action)
	
	# ... and if we are still here, buh-bye.
	os._exit(1)
	# oh shutup, pychecker
	return None

# Set our stack (soft) limit to something.
# Unfortunately, no one can be CONSISTENT in their error exceptions, can
# they.
def setstacklim(val):
	try:
		s, h = resource.getrlimit(resource.RLIMIT_STACK)
		resource.setrlimit(resource.RLIMIT_STACK, (val, h))
		return None
	except EnvironmentError, e:
		return str(e)
	except ValueError, e:
		return str(e)
