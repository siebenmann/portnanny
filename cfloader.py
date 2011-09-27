#
# Load our configuration file.
#
# Note that we do not validate the existence of objects here: we don't
# check to see if files or users exist.

import readcf
import util

class BadInput(Exception):
	pass

# Unlike rule and action files, our overall configuration file is completely
# interdependant. As a result, we hang all our parsing off a class so we can
# do lookups easily.
class NannyConfig:
	def __init__(self):
		self.cf = {}
		# Initialized here so we can always just .append() to it later.
		self.cf['listen'] = []

	# __str__'s job is vastly complicated by listen.
	def __str__(self):
		a = []
		ks = self.cf.keys()
		ks.sort()
		for k in ks:
			if k in ('dropipafter', 'expireevery'):
				a.append("%s %ss" % (k, self.cf[k]))
			elif k != 'listen':
				a.append("%s %s" % (k, self.cf[k]))
		self.cf['listen'].sort()
		for h, p in self.cf['listen']:
			a.append('listen %s@%s' % (p, h))
		return "\n".join(a) + "\n"
	def __getitem__(self, name):
		return self.cf[name]
	def has_key(self, name):
		return self.cf.has_key(name)
	def __contains__(self, name):
		return name in self.cf

	def parseline(self, line, lineno):
		__pychecker__ = 'no-argsused'
		n = line.split()
		# Everything we have is of the form 'directive argument',
		# so we can be really simple:
		if len(n) != 2:
			raise BadInput, "badly formatted line"
		# Every directive except 'listen' can only be given once,
		# so we can do this checking very easily.
		if n[0] != "listen" and self.cf.has_key(n[0]):
			raise BadInput, "can only give one %s directive" % \
			      (n[0],)
		# These three do no contents-checking: they just store it.
		if n[0] in ('rulefile', 'actionfile', 'user', 'aftermaxthreads'):
			self.cf[n[0]] = n[1]
		# I really need a better name for this.
		elif n[0] == 'dropipafter':
			self.cf[n[0]] = util.getsecs_or_raise(n[1], BadInput)
		elif n[0] == 'expireevery':
			self.cf[n[0]] = util.getsecs_or_raise(n[1], BadInput)
		elif n[0] == 'maxthreads':
			self.cf[n[0]] = util.int_or_raise(n[1], BadInput)
		elif n[0] == 'listen':
			# Listen stores host/port pairs in a list, since
			# we can legally accept multiple listen directives.
			# We insist that the port is always specified, but
			# the IP address can be wildcarded.
			r = util.gethostport(n[1])
			if not r:
				raise BadInput, "bad argument to listen"
			if r[1] == '':
				raise BadInput, "listen requires a port"
			self.cf['listen'].append(r)
		elif n[0] == 'onfileerror':
			if n[1] not in ('drop', 'use-old'):
				raise BadInput, "unknown option for onfileerror"
			self.cf[n[0]] = n[1]
		elif n[0] == "substitutions":
			if n[1] not in ("off", "on"):
				raise BadInput, "substitutions must be off or on"
			self.cf[n[0]] = n[1]
		else:
			raise BadInput, "unknown config file directive "+n[0]
		return None
	# Do we have a complete configuration? A complete configuration
	# has at least one 'listen' and both 'rulefile' and 'actionfile'.
	# 'user' and 'dropipafter' are both optional.
	def insurecomplete(self):
		if len(self.cf['listen']) == 0:
			raise BadInput, "no listen directives specified"
		for k in ("rulefile", "actionfile"):
			if not self.cf.has_key(k):
				raise BadInput, "no %s directive given" % (k,)
		if 'dropipafter' in self.cf and 'expireevery' in self.cf:
			if self.cf['expireevery'] < 0:
				raise BadInput, "Dropipafter conflicts with an expireevery that turns expiry processing off"
			

# After the file read has completed but before returning, we force a
# verification that the configuration is complete -- that it specifies
# at least *some* value for everything we need. We do it here because
# the consistency requirement is a meta-format issue of the config
# file.
def fromfile(fp, fname):
	cf = NannyConfig()
	readcf.readcf(fp, fname, cf.parseline, None, BadInput)
	cf.insurecomplete()
	return cf

def parsefile(fname):
	try:
		fp = open(fname, "r")
	except EnvironmentError, e:
		raise BadInput, "cannot open %s: %s" % (fname, str(e))
	return fromfile(fp, fname)
