#
# This module supplies all of the basic matching of various
# characteristics of a hinfo object, via a collection of classes.
# Characteristics are generally expressed in a way broadly similar
# to tcpwrappers, but include things such as regexps based on the
# (remote) host name, DNSBl lookups, and some information on previous
# connections from the same IP address (via hinfo supplied services).
#
# Matchers may take a required argument, in which case their name (as
# shown in MatchInfo.terminals; see rdparse) has a ':' at the end, or
# they may take no arguments. The simplest no-argument matcher is 'ALL'.

import re, string
import netblock
import util

# Utility bits
unitytrans = string.maketrans('', '')

class BadArg(Exception):
	pass

# 'Memoize' certain expensive computations across multiple generations
# of the rules file (we don't expect to see the same thing multiple
# times in the same rules file; that it helps this out is a nice side
# effect). After each 'generation', memoized computations not used in
# the current generation are discarded. End-of-generation is signalled
# by calling .age(); .discard() discards the whole memoization, and is
# used on errors on the principle that on errors *everything* is dead.
#
# AbstractMemo must be subclassed by supplying a .generate() method
# that does the actual computation process and returns the result.
class AbstractMemo:
	def __init__(self):
		self.discard()
	def discard(self):
		self.oldmem = {}
		self.newmem = {}
	def age(self):
		self.oldmem = self.newmem
		self.newmem = {}
	def generate(self, what):
		raise TypeError, "must be overridden in subclass"
	def compile(self, what):
		if what in self.newmem:
			pass
		elif what in self.oldmem:
			self.newmem[what] = self.oldmem[what]
		else:
			self.newmem[what] = self.generate(what)
		return self.newmem[what]
# Compiling regexps is surprisingly expensive, so they are our first
# memoization target.
class REMemo(AbstractMemo):
	def generate(self, regstr):
		try:
			return re.compile(regstr, re.IGNORECASE)
		except re.error, e:
			raise BadArg, "bad regexp '%s': %s" % (regstr, str(e))

# This converts a prefix IP address (with a . on the end) to a CIDR
# in string form. Since the string passed validation earlier, we know
# it is in a very predictable format and we can be simple.
def ippreftocidrs(ipS):
	return "%s/%d" % (ipS[:-1], 8 * ipS.count('.'))
class IAdMemo(AbstractMemo):
	# We generate CIDR netblocks based on the text strings, which
	# may be either something that can be fed to IPRanges.add()
	# straight or may be a prefix match, which must be converted
	# to a CIDR string first.
	def generate(self, rangel):
		nb = netblock.IPRanges()
		for re in rangel:
			try:
				if re[-1] == '.':
					nb.add(ippreftocidrs(re))
				else:
					nb.add(re)
			except netblock.NBError, e:
				raise BadArg, "bad CIDR netblock %s: %s" % (re, str(e))
		return nb
rememo = REMemo()
ipadmemo = IAdMemo()

# agememos() is called after the rules file is loaded.
# errormemos() is called if there is an error during rules file load.
# In both cases, they just apply the particular operation to each of
# our memoization proxies.
def agememos():
	rememo.age()
	ipadmemo.age()
def discardmemos():
	rememo.discard()
	ipadmemo.discard()

# ALL: matches everything.
class AllMatch:
	def __init__(self, name, val):
		__pychecker__ = "no-argsused"
	def __str__(self):
		return "ALL"
	def eval(self, hi):
		__pychecker__ = "no-argsused"
		return 1

# Match against identd data.
# As 'identd:', we get an argument. As 'IDENTD', we do not.
# We need to distinguish those cases in the eval routine.
class IdentdMatch:
	def __init__(self, name, val):
		__pychecker__ = 'no-argsused'
		self.desid = val
	def __str__(self):
		if self.desid:
			return "identd: "+self.desid
		else:
			return "IDENTD"
	def eval(self, hi):
		r = hi.getidentd()
		if not r:
			return 0
		if self.desid:
			return r == self.desid
		else:
			return 1

# Match against the local host and port.
class LocalMatch:
	def __init__(self, name, val):
		__pychecker__ = 'no-argsused'
		r = util.gethostport(val)
		if r == None:
			raise BadArg, "bad local: values"
		self.host, self.port = r
	def __str__(self):
		return "local: %s@%s" % (self.port, self.host)
	def eval(self, hi):
		if self.port and self.port != hi.getlport():
			return 0
		if self.host and self.host != hi.getlip():
			return 0
		return 1

# Match against the hostname status. This takes either tcpwrappers
# style arguments (KNOWN, UNKNOWN, PARANOID) or our specific status
# ones.
hnmapdict = {
	'KNOWN': ('good',), 'UNKNOWN': ('unknown',),
	'PARANOID': ('noforward', 'addrmismatch'),
	'good': ('good',), 'unknown': ('unknown',),
	'addrmismatch': ('addrmismatch',), 'noforward': ('noforward',),
	}	
class HNStatusMatch:
	def __init__(self, name, val):
		if val == None:
			val = name
		try:
			self.wstates = hnmapdict[val]
		except KeyError:
			raise BadArg, "unrecognized hostname state"
		self.name = intern(val)
	def __str__(self):
		return "hnstatus: "+self.name
	def eval(self, hi):
		return hi.gethnstate() in self.wstates

# IP addresses are complicated because we support three different
# matches: a) literal IP addresses or b) CIDR netblocks through the
# netblock code or c) tcpwrappers style shortened forms.
# validateipprefix knows it is being called on a string that ends in a '.'
# and contains only digits and dots.
def validateipprefix(val):
	"Is this a good partial IP address, tcpwrappers style?"
	n = val.split('.')[:-1]
	if len(n) == 0 or len(n) > 3:
		raise BadArg, "bad IP address specifier"
	for octet in n:
		if not octet:
			raise BadArg, "empty IP octet"
		# we know that val contains only numbers and '.'s. We split
		# on '.', so the octet cannot contain anything but numbers.
		# So try/except is pointless; we can just use int straight.
		i = int(octet)
		if not (0 <= i <= 255):
			raise BadArg, "bad IP octet"

# valid characters in the IP address forms we accept.
ipAddrChars = string.digits + "./-"
def validipaddr(val):
	return not (val[0] == '.' or
		    val.translate(unitytrans, ipAddrChars))
class IPAddrMatch(object):
	__slots__ = "cidr", "cname", "ip", "name"
	# 'docheck' is a hack and a private interface; it avoids doing
	# validity checks twice if we're coming through the handledefault()
	# internal path.
	def __init__(self, name, val, docheck = 1):
		if docheck and not validipaddr(val):
			raise BadArg, "bad characters in IP address match "+val
		self.cidr = None
		self.ip = None
		if '/' in val or '-' in val or val[-1] != '.':
			# validation will happen in finalization.
			pass
		else:
			validateipprefix(val)
			self.ip = val
		self.name = [val]
		self.cname = intern(name)
	def __str__(self):
		# EVIL. Note that we know too much here in order to
		# reproduce ourselves acceptably; we are essentially
		# regenerating a fake orlist.
		return " ".join(["%s %s" % (self.cname, x) for x in self.name])
	# EVIL HACK. This supports the attempt of orlist parsing in rdparse
	# to merge subsequent entries into a past one. This is possible for
	# IP address checks, because we can glom them all into one big
	# IPRanges object.
	def finalize(self):
		# if we are a length-one thing of an IP prefix, we're done.
		if len(self.name) == 1 and self.ip:
			return
		# Otherwise, we need to compile to IPAddrRange form. First
		# we need to tuple-ize self.name, so it can be hashed on.
		# Then we compile/memoize.
		self.name = tuple(self.name)
		self.cidr = ipadmemo.compile(self.name)
		self.ip = None
	# TESTING USE ONLY: definalizes a finalized situation.
	def _definalize(self):
		if len(self.name) == 1 and self.ip:
			return
		self.name = list(self.name)
		self.cidr = None
	def merge(self, other):
		# isinstance(other, IPAddrMatch) is still true if the
		# other is LIPAddrMatch (or we are), which is why we
		# have to check .cname too.
		if not (isinstance(other, IPAddrMatch) and \
			other.cname == self.cname):
			return False
		# We don't do anything much here; all the real work
		# happens in finalization. We drive the finalization
		# work off the self.name list, since we have to maintain
		# it anyways and it better be parseable.
		self.ip = None
		self.name.extend(other.name)
		return True
	# This returns both the string and the numeric form of the IP
	# address, because we may need both.
	def _getipS(self, hi):
		return hi.getip()
	def _getipN(self, hi):
		return hi.getipn()
	def eval(self, hi):
		# if self.ip is set, it ends with a dot and is safe to
		# match against the IP address we want to check.
		# Otherwise, CIDR match.
		if self.ip:
			return self._getipS(hi).startswith(self.ip)
		else:
			return self._getipN(hi) in self.cidr
# This matches against the local IP address instead of the remote one.
class LIPAddrMatch(IPAddrMatch):
	def _getipS(self, hi):
		return hi.getlip()
	def _getipN(self, hi):
		return hi.getlipn()

# Match against tcpwrappers style hostnames, which may be either full
# hostnames or '.' with a hostname portion. '.foobar' matches either
# 'nnn.foobar' or 'foobar' itself, and we have to check separately.
# Under some mental protest, we accept '_' as a valid character in
# hostnames. (Strictly speaking it isn't, but it's in common usage.)
hostNameChars = string.lowercase + string.digits + ".-_"
def validhostname(hn):
	return not (hn.translate(unitytrans, hostNameChars) or
		    hn == '.')
class HostnameMatch(object):
	__slots__ = "cname", "host", "hoste"
	def __init__(self, name, val):
		val = val.lower()
		if not validhostname(val):
			raise BadArg, "bad hostname: "+val
		self.cname = intern(name)
		# 'host' is matched against the literal hostname.
		# 'hoste' is matched against the end of the hostname.
		# 'hoste' is set only if the value starts with a '.',
		# in which case 'host' is the value minus the dot.
		# This avoids repeatedly slicing the front off during
		# evaluation, at the expense of more memory.
		if val[0] == '.':
			self.hoste = val
			self.host = val[1:]
		else:
			self.hoste = None
			self.host = val
	def __str__(self):
		# Our small optimization above requires us to be clever
		# here in order to get the original version out, since
		# that is either hoste or host, depending.
		if self.hoste:
			return '%s %s' % (self.cname, self.hoste)
		else:
			return "%s %s" % (self.cname, self.host)
	def _gethostname(self, hi):
		return hi.gethostname_l()
	def eval(self, hi):
		hn = self._gethostname(hi)
		if not hn:
			return False
		elif self.hoste:
			return hn.endswith(self.hoste) or hn == self.host
		else:
			return hn == self.host
# This is *dangerous*: it matches against not the hostname, but the
# claimed hostname.
class ClaimedHNMatch(HostnameMatch):
	def _gethostname(self, hi):
		return hi.getclaimedhn_l()

class ClassMatch:
	def __init__(self, name, val):
		__pychecker__ = 'no-argsused'
		self.cls = val
	def __str__(self):
		return "class: "+self.cls
	def eval(self, hi):
		return self.cls in hi.getclasses()

# Regular expressions turn out to be pretty easy.
class REMatch(object):
	__slots__ = "cname", "rexp"
	def __init__(self, name, val):
		self.rexp = rememo.compile(val)
		self.cname = intern(name)
	def __str__(self):
		return "%s '%s'" % (self.cname, self.rexp.pattern)
	def _gethostname(self, hi):
		return hi.gethostname()
	def eval(self, hi):
		hn = self._gethostname(hi)
		if not hn:
			return 0
		# We cannot just return the search result directly because
		# it isn't a boolean. So we make it one. (Go team.)
		return bool(self.rexp.search(hn))
class ClaimedREMatch(REMatch):
	def _gethostname(self, hi):
		return hi.getclaimedhn()

# This matches based on the *forward* hostname to IP address mapping
# information, as opposed to the reverse. 'forwhn: foobar' will match
# if the connection is coming from one of the IP addresses 'foobar'
# resolves to, irregardless of their reverse mappings.
class ForwhnMatch:
	def __init__(self, name, val):
		__pychecker__ = 'no-argsused'
		val = val.lower()
		if not validhostname(val):
			raise BadArg, "bad forwhn hostname: "+val
		self.forwhn = val
	def __str__(self):
		return "forwhn: "+self.forwhn
	def eval(self, hi):
		ips = hi.gethostips(self.forwhn)
		ip = hi.getip()
		for i in ips:
			if ip == i:
				return 1
		return 0

# Check a IP-based DNS blocklist. The optional /<IP> makes things only
# match if the DNSBl specifically returns that IP address on lookups.
# All lookups are IP address lookups, not TXT-based.
class DNSBlMatch:
	def __init__(self, name, val):
		__pychecker__ = 'no-argsused'
		pos = val.find('/')
		if val[0] == '/' or val[-1] == '/':
			# very funny: -10 points.
			raise BadArg, "bad position of / in dnsbl: argument"
		if pos >= 0:
			self.dnsbl = "." + val[:pos]
			self.ipval = val[pos+1:]
			if not util.isipaddr(self.ipval):
				raise BadArg, "dnsbl: IP address portion isn't an IP address"
		else:
			self.dnsbl = "." + val
			self.ipval = None
	# We have to remember we glued the period on the front.
	def __str__(self):
		if self.ipval:
			return "dnsbl: %s/%s" % (self.dnsbl[1:], self.ipval)
		else:
			return "dnsbl: "+self.dnsbl[1:]
	def eval(self, hi):
		# We have to reverse the IP address in order to perform
		# DNS blacklist lookups. Fortunately the HostInfo data
		# caches that for us.
		revip = hi.getrevip()
		ips = hi.gethostips(revip+self.dnsbl)
		# Do we have to check the IP value? If not, we're done.
		if not self.ipval:
			return len(ips) > 0
		for i in ips:
			if i == self.ipval:
				return 1
		return 0

class AnswersOnMatch:
	def __init__(self, name, val):
		__pychecker__ = "no-argsused"
		self.port = util.int_or_raise(val, BadArg)
		if not (0 <= self.port <= 65536):
			raise BadArg, "port number outside of OK range"
	def __str__(self):
		return "answerson: %d" % self.port
	def eval(self, hi):
		return hi.answerson(self.port)

# These matchers operate based on the time of the first or the most recent
# connection.
class TimedMatch:
	def __init__(self, name, val):
		self.name = name
		self.secsold = util.getsecs_or_raise(val, BadArg)
	def __str__(self):
		return "%s %ds" % (self.name, self.secsold)
class WaitedMatch(TimedMatch):
	def eval(self, hi):
		return hi.getfirsttime() > self.secsold
class StallMatch(TimedMatch):
	def eval(self, hi):
		return hi.getfirsttime() <= self.secsold
# If this is the first connection, we have by definition not seen them
# for an infinite time.
class LastSeenMatch(TimedMatch):
	def eval(self, hi):
		r = hi.getlasttime()
		if r == None:
			return 0
		return r <= self.secsold
# Similarly, if this is the first connection we have not seen them for
# an infinite amount of time.
class NotSeenForMatch(TimedMatch):
	def eval(self, hi):
		r = hi.getlasttime()
		if r == None:
			return 1
		return hi.getlasttime() > self.secsold
class FirstTimeMatch:
	def __init__(self, name, val):
		__pychecker__ = 'no-argsused'
	def __str__(self):
		return "firsttime"
	def eval(self, hi):
		return hi.getlasttime() == None


# This structure is what the rdparse module uses to match up matchers
# with arguments.
class MatchInfo:
	terminals = {
		'ALL': AllMatch,
		'local:': LocalMatch,
		# Hostname state and its aliases,
		'hnstatus:': HNStatusMatch, 'PARANOID': HNStatusMatch,
		'KNOWN': HNStatusMatch, 'UNKNOWN': HNStatusMatch,
		# General stuff.
		"ip:": IPAddrMatch, "localip:": LIPAddrMatch,
		"identd:": IdentdMatch, 'IDENTD': IdentdMatch,
		"hostname:": HostnameMatch,
		're:': REMatch,
		'forwhn:': ForwhnMatch,
		'dnsbl:': DNSBlMatch,
		'answerson:': AnswersOnMatch,
		# These are based on the age of the first or the most recent
		# connection from the IP address.
		'stallfor:': StallMatch, 'waited:': WaitedMatch,
		'seenwithin:': LastSeenMatch,'notseenfor:': NotSeenForMatch,
		'firsttime': FirstTimeMatch,
		# This sort of doesn't belong here, but.
		'class:': ClassMatch,
		# DANGER WILL ROBINSON. Use of these is dangerous and can
		# blow up in your face.
		"claimedhn:": ClaimedHNMatch,
		"claimedre:": ClaimedREMatch,
		}
	error = BadArg
	def defaultterm(self, val):
		#__pychecker__ = "no-returnvalues"
		if validipaddr(val):
			return self.terminals["ip:"]("ip:", val, 1)
		return self.terminals["hostname:"]("hostname:", val)
matchinfo = MatchInfo()
