#
# Our loader of and interpreter of actions.
# The ultimate output of an action ruleset is an Action object, which
# tells us what to actually do. 
#
# Action creation:
# We have a list of (matching) classes that the rule evaluation created.
# We ignore any that don't have corresponding actions.
#
# To succeed, the connection must pass ipmax and connmax limits
# for all the remaining rules, if they have any such limits.
# If the connection succeeds, the first matching rule with a
# 'msg' or 'run' directive is used as the action for the connection.
#
# If it fails, the first rule who's limits were exceeded becomes
# the failing rule. Its 'failmsg' or 'failrun' is used as the
# action, if it exists. If neither is specified, the connection
# is just dropped without visible message to the remote end.
# (This is, of course, efficient in that it does not require a
# fork.)
#
# In all cases, all matching rules with 'record' messages will
# have them evaluated and logged.
#

import re
import readcf
import util
import conntrack
import msgs

class BadAction(Exception):
	pass

# The types of arguments various directives can take. The values are
# arbitrarily distinct. (Why yes, this should be an enum if Python
# had them.)
noArg, oneInt, aStr, nullStr, aEnv, anArg = range(6)
# This dictionary nominally records how many arguments each action rule
# directive takes. In the process it defines the valid action rule
# directives.
actargs = {
	'reject': noArg, 'drop': noArg, 'quiet': noArg,
	'norepeatlog': noArg,
	'log': nullStr,
	'ipmax': oneInt, 'connmax': oneInt,
	'run': aStr, 'msg': aStr, 'failrun': aStr, 'failmsg': aStr,
	'faillog': aStr, 'record': aStr,
	'see': anArg,
	'setenv': aEnv,	'subst': aEnv,
	}
# Most directives are stored in ActionRule.dirs as directive-name/value
# pairs. Setenv is special; it stores envname / value pairs in
# ActionRule.env. For convenience we support ActionRule['setenv'];
# we don't support ActionRule['setenv'] = value, since the storage
# models are incompatable.
class ActionRule:
	def __init__(self, name):
		self.name = name
		self.env = {}
		self.subst = {}
		self.dirs = {}
	def __getitem__(self, name):
		if not actargs.has_key(name):
			raise KeyError, name
		if name == 'setenv':
			return self.env
		elif name == 'subst':
			return self.subst
		elif self.dirs.has_key(name):
			return self.dirs[name]
		return None
	def __setitem__(self, name, val):
		if not actargs.has_key(name):
			raise KeyError, "unknown action name"
		elif name == 'setenv':
			raise KeyError, "setenv cannot be set this way"
		self.dirs[name] = val
	def has_key(self, name):
		return self.dirs.has_key(name)
	def __contains__(self, name):
		if name == 'setenv':
			return bool(len(self.env))
		elif name == 'subst':
			return bool(len(self.subst))
		else:
			return name in self.dirs
	def __str__(self):
		args = []
		kl = self.dirs.keys()
		kl.sort()
		for k in kl:
			if (actargs[k] == noArg) or \
			   (actargs[k] == nullStr and not self.dirs[k]):
				args.append(k)
			else:
				args.append("%s %s" % (k, self.dirs[k]))
		# setenv makes us grind our teeth, it does.
		envN = self.env.keys()
		envN.sort()
		for ev in envN:
			args.append("setenv %s %s" % (ev, self.env[ev]))
		substN = self.subst.keys()
		substN.sort()
		for sv in substN:
			args.append("subst %s %s" % (sv, self.subst[sv]))
		return '%s: %s' % (self.name, " : ".join(args))

	# This returns true or false, based on testing each thing.
	def doesfail(self, hi, what, cls = None):
		if what not in self.dirs:
			return False
		if not cls:
			cls = self
		val = self.dirs[what]
		if what == "reject":
			return True
		elif what == "ipmax":
			return conntrack.ipcount(hi.getip()) >= val
		else:
			return conntrack.classcount(cls.name) >= val
	def doesfailall(self, hi):
		for i in ("reject", "ipmax", "connmax"):
			if self.doesfail(hi, i):
				return i
		return None

# using actargs, get the value of the keyword or die bitching about
# it. The value is properly formatted for the type of the argument.
def getvalue(keyw, rest):
	def _badarg():
		raise BadAction, "wrong number of arguments for directive "+keyw
	# for some reason, pychecker fails to understand that we always
	# return a value. Probably the raises confuse it.
	__pychecker__ = "no-implicitreturn"
	if not actargs.has_key(keyw):
		raise BadAction, "unknown directive "+keyw
	acnt = actargs[keyw]
	rest = rest.strip()
	# nullStr will accept null or a string; our argument in the null
	# case is a null string, so we're done.
	if acnt == nullStr:
		return rest
	elif acnt == noArg and rest:
		_badarg()
	elif acnt == noArg:
		return 1
	# everything past here requires arguments, so if they don't have
	# any we can bail now.
	elif not rest:
		_badarg()
	elif acnt == oneInt:
		# this will automatically fail if 'rest' has multiple
		# words in it.
		return util.int_or_raise(rest, BadAction)
	elif acnt == aStr:
		return rest
	elif acnt == aEnv:
		# setenv requires an environment variable name and its value.
		# subst is similar enough to use the same code.
		n = rest.split(None, 1)
		if len(n) != 2:
			_badarg()
		return n
	elif acnt == anArg:
		n = rest.split()
		if len(n) != 1:
			_badarg()
		return rest
	# If we have gotten here, something is wrong; either an unhandled
	# argument type or an argument type handler that failed to get out
	# of the function.
	raise KeyError, "internal error: unhandled case for getvalue for "+keyw

spacecolonre = re.compile("\s:\s")
def parseline(line, lineno):
	__pychecker__ = 'no-argsused'
	n = line.split(None, 1)
	if len(n) != 2:
		raise BadAction, "too few elements in action"
	if n[0][-1] != ':':
		raise BadAction, "class name does not end with a ':'"

	clsname = n[0][:-1]
	act = ActionRule(clsname)
	comps = [x.strip() for x in spacecolonre.split(n[1])]
	for c in comps:
		ces = c.split(None, 1)
		keyw = ces[0]
		if len(ces) == 1:
			ces.append('')
		# getvalue checks for validity and everything for us, and
		# returns appropriate decoded values.
		val = getvalue(keyw, ces[1])
		# Check to see if they are trying to specify a key multiple
		# times. This automatically skips multiple setenvs, as setenv
		# does not appear in the main actionrule dictionary.
		if act.has_key(keyw):
			raise BadAction, \
			      "multiple specification of directive "+keyw
		# Setenv values are stored specially.
		if keyw == "setenv":
			if act.env.has_key(val[0]):
				raise BadAction, \
				      "setenv of variable more than once: "+val[0]
			act.env[val[0]] = val[1]
		elif keyw == 'subst':
			if val[0] in act.subst:
				raise BadAction, \
				      "subst variable specified more than once: "+val[0]
			act.subst[val[0]] = val[1]
		else:
			# Everything else is stored in the dictionary with
			# the value getvalue returned.
			act[keyw] = val

	if act['msg'] and act['run']:
		raise BadAction, "cannot specify both msg and run in one action"
	if act['failmsg'] and act['failrun']:
		raise BadAction, "cannot specify both failmsg and failrun in one action"
	return act

# msgs.format can throw KeyError (from the underlying %) if the user
# has specified a %(...) thing that doesn't exist in the current data.
# We must catch this and turn it into a BadAction error.
# Use of string substitutions through format is optional.
formaton = 1
def dosubstitutions(val):
	global formaton
	formaton = val
def format(msg, hi, clsr, sdict = None, **kwargs):
	if not formaton:
		return msg
	try:
		return msgs.format(*(msg, hi, clsr, sdict), **kwargs)
	except KeyError:
		raise BadAction, "cannot format the string: "+msg

# This is just a structure, not an opaque object, so the instance variables
# are the public interface and get used freely.
class Act:
	def __init__(self):
		self.logmsgs = []; self.env = {};
		self.what = None; self.argstring = None; self.arglist = None
defFailDict = {
	'reject': ('DEFAULT-REJECT', 'DEFAULTMSGS'),
	'ipmax': ('DEFAULT-IPMAX', 'DEFAULTMSGS'),
	'connmax': ('DEFAULT-CONNMAX', 'DEFAULTMSGS'),
	}
class ActRules:
	def __init__(self):
		self.actrules = {}
		# This stores the last log/faillog message logged, for
		# 'norepeatlog'.
		self.lastlog = None
	# We make str generate a consistent order; it makes unittesting
	# easier.
	def __str__(self):
		actnames = self.actrules.keys()
		actnames.sort()
		# This should be writeable as one line, not two, but
		# pychecker doesn't like it and this is the lesser evil.
		astrs = [str(self.actrules[x]) for x in actnames]
		return "\n".join(astrs) + "\n"
	def __getitem__(self, name):
		return self.actrules[name]
	def has_key(self, name):
		return self.actrules.has_key(name)
	def __len__(self):
		return len(self.actrules)
	# We disallow adding duplicates.
	def addact(self, act):
		if act.name in self.actrules:
			raise BadAction, \
			      "duplicate class line for class "+act.name
		self.actrules[act.name] = act

	def getclassnames(self):
		return self.actrules.keys()

	# Generate an Act object based on evaluating the limits,
	# messages, and so on, from the matched rules.

	# -- support routines:
	# Take a list of match rules and see if any of them fail.
	# If any do, return why it fails and the match rule. This
	# is complicated by the need to follow see chains, *plus*
	# the fact that 'c1: see c2 : ipmax 20' 'c2: ipmax 0' and
	# a connection in c1 *passes* if the ip connection count
	# is under 20; that means we cannot simply check the limits
	# of every action class in the see chain. Instead we have to
	# keep track of what connection limits have already been passed.
	def trytofail(self, hi, mrlist):
		for mr in mrlist:
			ar = self.actrules[mr.clsname]
			# tsts is dynamically edited to remove tests
			# that we have passed.
			tsts = ['reject', 'ipmax', 'connmax']
			for a in self.getseelist(ar):
				# tl is the list of tests that this action
				# rule has. We check only these.
				tl = [t for t in tsts if t in a]
				for t in tl:
					if a.doesfail(hi, t, ar):
						return (t, mr)
					# If we did not fail because of
					# this limit, we don't want to
					# check it any more.
					tsts.remove(t)
				# Note that tsts will never go empty,
				# because there is no way to pass a
				# 'reject' rule; we will wind up checking
				# 'reject' all the way up the chain.
		return (None, None)
	# Find the first rule that actually acts.
	def findfirstaction(self, mrlist):
		for mr in mrlist:
			ar = self.actrules[mr.clsname]
			# Note that 'drop' counts as a success.
			for a in self.getseelist(ar):
				# SUBTLE: 'drop' must be first, because
				# one can supply it *plus* one of the other
				# two, so we must check for it first.
				for i in ('drop', 'msg', 'run'):
					if i in a:
						return (mr, i)
		return (None, None)

	# getseelist computes the 'see list', by following 'see' directives
	# recursively. It guards against loops. _getslist is an interior
	# helper. 'getseelist' also includes the DEFAULT-* and DEFAULTMSGS
	# fallbacks when asked to.
	def _getslist(self, cur, lst, seend, base):
		if cur in seend:
			raise BadAction, "see loop in %s: saw %s again" % \
			      (base.name, cur.name)
		lst.append(cur); seend[cur] = None
		if not cur['see']:
			return
		ctv = cur['see']
		if ctv not in self.actrules:
			raise BadAction, "class %s says to see class '%s', but there is no such class" % (cur.name, ctv)
		self._getslist(self.actrules[ctv], lst, seend, base)
	def getseelist(self, ac, ftype = None):
		if 'see' in ac:
			l = []
			self._getslist(ac, l, {}, ac)
		else:
			l = [ac]
		if ftype:
			l.extend([self.actrules[x] for x in defFailDict[ftype]
				  if x in self.actrules])
		return l
	# Get the action rule in a see chain that is the source of a given
	# attribute.
	def getattrsource(self, ac, attrn, ftype = None):
		for a in self.getseelist(ac, ftype):
			if attrn in a:
				return a
		return None
	# ETOOMANYPARAMETERS
	# Generate a dictionary from the dictionaries attached to a
	# see chain, formatting entries on the way, not allowing later
	# entries to replace earlier ones.
	def gendictfrom(self, dct, ac, attr, hi, actmatch, sdict):
		for i in self.getseelist(ac):
			for k in i[attr]:
				if k not in dct:
					dct[k] = format(i[attr][k],
							hi, actmatch, sdict)

	# Get the fail action and the action rule that generated it.
	# Fail action is one of 'failmsg' or 'failrun', whichever we
	# find first.
	# This is complicated because we specifically don't support
	# defaulting for 'failrun', so we have to walk the lists in
	# tandem.
	def getfailaction(self, ac, ftype):
		# n1 has only 'see' classes; n2 has them plus DEFAULT*
		# stuff.
		n1 = self.getseelist(ac)
		n2 = self.getseelist(ac, ftype)
		for i in n2:
			if 'failmsg' in i:
				return (i, 'failmsg')
			# This check forces us to not look for 'failrun'
			# on DEFAULT* classes, which are not in n1.
			elif i not in n1:
				break
			elif 'failrun' in i:
				return (i, 'failrun')
		return (ac, None)
	# -- the guts.
	def genaction(self, hi, matchedrules):
		# return the action rule for the rules matcher rule.
		def actionfor(mr):
			return self.actrules[mr.clsname]
		def _getattr(ar, attr, ftype = None):
			r = self.getattrsource(ar, attr, ftype)
			if r:
				return r[attr]
			else:
				return None

		act = Act()

		# First, discard any matched classes we do not have an
		# action rule for. Such matched classes may occur in
		# setups using the class: matcher to simplify life.
		mrlist = [x for x in matchedrules if 
			  self.actrules.has_key(x.clsname)]
		# We may have nothing left; in that case, bail.
		if not mrlist:
			return None

		# Are all of our interesting matchers happy with this
		# connection?
		(fail, actmatch) = self.trytofail(hi, mrlist)
		# If we have failed, trytofail comes back with the
		# 'action rule'. Otherwise, find the first action.
		if not actmatch:
			actmatch, what = self.findfirstaction(mrlist)

		# Find all rules that want to record something.
		reclist = [x for x in mrlist if
			   self.getattrsource(actionfor(x), 'record')]

		# If we have no action and nothing to record, we have no
		# action; bail.
		if not (actmatch or reclist):
			return None

		# Generate the logs.
		for r in reclist:
			msg = _getattr(actionfor(r), 'record')
			act.logmsgs.append(format(msg, hi, r))
		# If we have no terminal rule, we are now done; all that
		# happens for this connection is that we log messages.
		if not actmatch:
			return act
		
		# Pick right bits for logging success or failure.
		ac = actionfor(actmatch)
		# Generate the subst dictionary of additional substitutions.
		sdict = {}
		# Note double use of sdict, here! 'see' people can know
		# that they are only used by previous levels, and use stuff
		# from them.
		self.gendictfrom(sdict, ac, 'subst', hi, actmatch, sdict)

		lmsg = None
		if not fail:
			r = self.getattrsource(ac, 'log')
			if r and r['log']:
				lfmt = r['log']
			elif r:
				lfmt = msgs.logconnect
			else:
				lfmt = None
			if lfmt:
				lmsg = format(lfmt, hi, actmatch, sdict)
		elif fail:
			if self.getattrsource(ac, 'quiet'):
				lfmt = _getattr(ac, 'faillog')
			else:
				lfmt = _getattr(ac, 'faillog', fail)
				# we must fall back to the true defaults.
				if not lfmt:
					lfmt = msgs.rejmsgs[fail]
			if lfmt:
				lmsg = format(lfmt, hi, actmatch, sdict,
					      limit = fail)
		# Handle suppressing repeat messages if we've been asked
		# to, via norepeatlog.
		if lmsg:
			if not (self.getattrsource(ac, 'norepeatlog') and \
				lmsg == self.lastlog):
				act.logmsgs.append(lmsg)
			self.lastlog = lmsg

		# Decide what action is actually going to happen, if
		# any. Because of fail message defaulting (sigh),
		# the action rule used to generate the action's argument
		# may not actually be actmatch rule.
		msgA = ac; atr = None
		if fail:
			(msgA, atr) = self.getfailaction(ac, fail)
		elif what == 'drop':
			pass
		else:
			msgA = self.getattrsource(ac, what)
			atr = what

		# We may have no action, especially on failure.
		if atr:
			act.what = atr
			act.argstring = format(msgA[atr], hi, actmatch, sdict)
			if atr in ('run', 'failrun'):
				act.arglist = [format(x, hi, actmatch, sdict)
					       for x in msgA[atr].split()]

		# Environment variables are simple, but they get run through
		# substitution. (Well, they were simple before defaulting...)
		self.gendictfrom(act.env, ac, 'setenv', hi, actmatch, sdict)

		# And we are finally done.
		return act

	# Check certain consistency things on load.
	# Right now we only check for 'see' loops and for 'see's that go
	# nowhere. We cannot check these before the end of the file,
	# because they require us to have the full set of classes defined;
	# there is no define-before-see requirement.
	def checkconsist(self):
		for ar in self.actrules.values():
			self.getseelist(ar)	

# Parse a whole file. Most of this is generic.
def fromfile(fp, fname):
	actrules = ActRules()
	readcf.readcf(fp, fname, parseline, actrules.addact, BadAction)
	try:
		actrules.checkconsist()
	except BadAction, e:
		raise BadAction, "error loading %s: %s" % (fname, str(e))
	return actrules

def parsefile(fname):
	try:
		fp = open(fname, "r")
	except EnvironmentError, e:
		raise BadAction, "cannot open %s: %s" % (fname, str(e))
	return fromfile(fp, fname)
