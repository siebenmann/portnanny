#
# This module looks up and exports 'host information', information (mostly)
# about the remote end of an IP connection. Expensive to compute or
# maintain information is only looked up when it is asked for, and the
# answer is cached for additional lookups.
# The major product of this module is a 'hinfo object' (class HostInfo),
# which aggregates cached information and supplies lookup services.

import socket, time, select, errno
import idclient
import util
import netblock

# Half a second is an experimental value.
IDENTDTIMEOUT = 0.5
CONNTIMEOUT = 0.5

# Determine the name of an ip address as paranoidly as possible.
# There are four possible result states:
# unknown -> no name is known for the IP address.
# noforward -> there is a name for the IP address, but it doesn't exist in
#	       the DNS.
# addrmismatch -> there is a name, but the IP addresses associated with that
#	       name do not include the IP address.
# good -> the name/ip information exists and is consistent.
def getipname(ip):
	try:
		revname = socket.gethostbyaddr(ip)[0]
	except socket.error:
		return ('unknown', None)
	# We have to do this explicitly, because gethostbyname_ex() will
	# work on IP addresses.
	if util.isipaddr(revname):
		return ('noforward', revname)
	try:
		ips = socket.gethostbyname_ex(revname)[2]
	except socket.error:
		return ('noforward', revname)
	for i in ips:
		if i == ip:
			return ('good', revname)
	return ('addrmismatch', revname)

#
# This is necessary because select.select() can bail with EINTR if we
# are signalled. In that case, simply retrying with the timeout intact
# is the wrong choice; we must instead work from a global ending time.
def timeoutsel(r, w, e, timeout):
	# et is the absolute ending time, ie now plus the timeout.
	et = time.time() + timeout
	while 1:
		try:
			return select.select(r, w, e, timeout)
		except select.error, e:
			if e[0] != errno.EINTR:
				raise
			# if timeout is zero, we are receiving a
			# continuous stream of EINTRs and we need
			# to get out somehow.
			if timeout == 0:
				break
			timeout = max(et - time.time(), 0)
	return ([], [], [])

# Can we connect to port on host?
# The Berkeley sockets API complicates our attempts to do this with a
# timeout, so we don't hang for too long if the remote host is down or
# discarding packets to that port. We could try to use SIGALRM, but that
# probably interacts badly with threads.
def canconnectto(host, port, timeout = CONNTIMEOUT):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setblocking(0)
		# connect() on a nonblocking socket immediately returns
		# an error indication. I suppose this makes a certain
		# amount of sense, as does Python propagating it back.
		# I still wish it didn't do that.
		try:
			s.connect((host, port))
		except socket.error, e:
			# Look for immediate failures, check.
			if e[0] not in (errno.EAGAIN, errno.EINPROGRESS):
				return False
			pass
		# The socket will become ready for IO when the connection
		# completes. We must select for write, because only that
		# produces an accurate indication; selecting for read would
		# block until the remote end sends us something, which might
		# be long after the connection was made.
		try:
			rt = timeoutsel([], [s], [], timeout)
		except select.error:
			# Any uncaught errors are assumed to be a 'nope'.
			return False
		# If there is nothing ready to write, our timeout has been
		# exceeded and we declare this a failure.
		if not rt[1]:
			return False
		# Now we get any pending error. If there was one, something
		# went wrong with the connection, so our status is whether
		# or not getsockopt() finds an error.
		return s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
	except socket.error:
		pass
	return False
		

# Keep track of the first and last times we have seen a connection from
# a given IP address. We try fairly hard to do the efficient thing.
# For thread safety, we keep all information for an IP address together
# and update it as a unit; this avoids exceptions if it is expired
# halfway through a check. We don't lock, so checks are allowed to stomp
# over each other and get slightly inconsistent data (eg, two people
# thinking that a connection is new; two people updating the last connected
# time).
class IPTimeCache:
	def __init__(self):
		self.clear()
		self.setexpire(None)
	def clear(self):
		self.tinf = {}
	def setexpire(self, val):
		self.explen = val
	# expire relies on the fact that it is never performed in multiple
	# threads. We also explicitly pull .keys() so that the list is
	# stable in the face of other threads adding entries.
	def expire(self):
		if not self.explen:
			return None
		exptime = time.time() - self.explen
		for k in self.tinf.keys():
			if self.tinf[k][1] < exptime:
				del self.tinf[k]
	def firstlast(self, ipk, now):
		# First connection?
		# A try/except pair is the only thread safe way of doing
		# this, as we may be checking for an entry while .expire()
		# is removing it underneath us.
		try:
			ft, lt = self.tinf[ipk]
		except KeyError:
			# Initialize to now.
			self.tinf[ipk] = (now, now)
			return (0, None)
		# We replace the information instead of editing it in place
		# for thread safety; a .expire could have deleted it between
		# our retrieval and our update.
		self.tinf[ipk] = (ft, now)
		return (now - ft, now - lt)
	def __len__(self):
		return len(self.tinf)

iptcache = IPTimeCache()

def cleariptimes():
	iptcache.clear()
def setiptimesdur(secs):
	iptcache.setexpire(secs)
def expireiptimes():
	iptcache.expire()
def iptimessize():
	return len(iptcache)

# This returns a 32-bit int version of a string IP address.
# We cannot use netblock.strtoip() directly, because it returns longs.
def ipto32int(ip):
	r = netblock.strtoip(ip)
	if r < 0x80000000L:
		return int(r)
	else:
		return int(r-0x100000000L)
# To reduce storage space, we store the IP address and the time as Python
# integers, instead of their natural string and float natures. We have to
# go to some effort (see above) to get the IP address as a true int, not
# a long.
def getiptimes(ip):
	# Integer time will only overflow to long in 2038. Long is
	# acceptable to us.
	now = int(time.time())
	ikey = ipto32int(ip)
	return iptcache.firstlast(ikey, now)

class HostInfo:
	def __init__(self, loc, rem):
		self._rip, self._rport = rem
		self._ripn = None; self._revip = None
		self._lip, self._lport = loc
		self._lipn = None
		self._hnstate = None
		self._rhn = None; self._rhnl = None
		self._chn = None; self._chnl = None
		self.classes = []
		self._id = None
		self._idinit = None
		self._tinit = None
		self._ftime = None
		self._ltime = None
		self._anscache = {}; self._lupcache = {}
	def _fillhn(self):
		if self._hnstate != None:
			return
		self._hnstate, self._chn = getipname(self._rip)
		if self._chn:
			self._chnl = self._chn.lower()
		if self._hnstate == 'good':
			self._rhn = self._chn
			self._rhnl = self._chnl
	def _fillid(self):
		if self._idinit:
			return
		self._idinit = 1
		self._id = idclient.ident(self._rip, self._rport,
					  self._lip, self._lport,
					  IDENTDTIMEOUT)
	def _filltime(self):
		if self._tinit:
			return
		self._tinit = 1
		self._ftime, self._ltime = getiptimes(self._rip)
	def settimes(self, f, l):
		self._ftime = f
		self._ltime = l
		self._tinit = 1

	def getip(self):
		return self._rip
	def getipn(self):
		if self._ripn is None:
			self._ripn = netblock.strtoip(self._rip)
		return self._ripn
	# .split() is remarkably expensive, so it's worth caching the IP
	# address as reversed for DNS blocklist checking. And hey, we have
	# to do it somewhere *anyways*. So.
	def getrevip(self):
		if self._revip is None:
			l = self._rip.split('.')
			l.reverse()
			self._revip = ".".join(l)
		return self._revip
	def getlip(self):
		return self._lip
	def getlipn(self):
		if self._lipn is None:
			self._lipn = netblock.strtoip(self._lip)
		return self._lipn
	def getport(self):
		return str(self._rport)
	def getlport(self):
		return str(self._lport)

	def gethostname(self):
		if not self._hnstate: self._fillhn()
		return self._rhn
	def getclaimedhn(self):
		if not self._hnstate: self._fillhn()
		return self._chn
	def gethnstate(self):
		if not self._hnstate: self._fillhn()
		return self._hnstate
	def gethostname_l(self):
		if not self._hnstate: self._fillhn()
		return self._rhnl
	def getclaimedhn_l(self):
		if not self._hnstate: self._fillhn()
		return self._chnl

	# Class membership is annotated on the host info object because
	# it is associated with the host. Technically this is inaccurate,
	# since it is only associated with a given instance of the host,
	# but structurally this is where we have to put it.
	# getclasses() is equivalent to just using 'self.classes'.
	def getclasses(self):
		return self.classes
	def addclass(self, cls):
		if cls not in self.classes:
			self.classes.append(cls)

	def getidentd(self):
		self._fillid()
		return self._id

	def getfirsttime(self):
		self._filltime()
		return self._ftime
	def getlasttime(self):
		self._filltime()
		return self._ltime

	# We do this here on the grounds that all connection stuff should
	# go through us.
	def answerson(self, port):
		if port not in self._anscache:
			self._anscache[port] = canconnectto(self._rip, port)
		return self._anscache[port]
	# Ditto IP address lookups.
	# This is more dodgy, but a HostInfo struct is our per-connection
	# data object.
	def gethostips(self, host):
		if host not in self._lupcache:
			try:
				ips = socket.gethostbyname_ex(host)[2]
			except socket.error:
				ips = []
			self._lupcache[host] = ips
		return self._lupcache[host]

	# Information formatting.
	def pretty(self, iponly = 0):
		if self._id:
			pref = '%s@' % (self._id,)
		else:
			pref = ''
		if not iponly and self._rhn:
			return pref + self._rhn
		else:
			return pref + self._rip
	# Return an info dictionary based on what we know.
	def getinfo(self):
		d = {}
		d['ip'] = self._rip
		d['remport'] = self._rport
		d['localip'] = self._lip
		d['port'] = self._lport
		if self._hnstate != None:
			d['hnstatus'] = self._hnstate
		if self._chn != None:
			d['claimedhn'] = self._chn
		if self._rhn == None:
			d['hostname'] = self._rip
		else:
			d['hostname'] = self._rhn
		if self._id:
			d['identd'] = self._id
		if self._ftime != None:
			d['seensince'] = self._ftime
		if self._ltime != None:
			d['lastseen'] = self._ltime
		d['connsum'] = self.pretty()
		d['connipsum'] = self.pretty(1)
		return d

def frompairs(loc, rem):
	return HostInfo(loc, rem)
def fromfd(fd):
	# This try is total paranoia. Call me paranoid, thanks.
	try:
		return HostInfo(fd.getsockname(), fd.getpeername())
	except socket.error:
		return None
