#
# This requires a bunch of shimming to actually test, and some of it is
# impossible. Life is like that.
import hinfo
import socket
from errno import *
import unittest
import netblock

from testutils import *

class basicTests(unittest.TestCase):
	def testIPAddrs(self):
		"Test that the right IP addresses come back from setting up fixed information."
		hi = hinfo.frompairs(('127.0.0.1', 1000),
				     ('127.0.0.2', 2000))
		self.assertEqual(hi.getip(), '127.0.0.2')
		self.assertEqual(hi.getport(), '2000')
		self.assertEqual(hi.getlip(), '127.0.0.1')
		self.assertEqual(hi.getlport(), '1000')
		ln = netblock.strtoip('127.0.0.2')
		self.assertEqual(hi.getipn(), ln)
		ln2 = netblock.strtoip('127.0.0.1')
		self.assertEqual(hi.getlipn(), ln2)

	# Each tuple is what-to-add and what-the-result-should-be.
	# The thing is cumulative.
	clsseq = (
		(None, []),
		('abc', ['abc']),
		('10', ['abc', '10']),
		('testing', ['abc', '10', 'testing']),
		('10', ['abc', '10', 'testing']),
		)
	def testClassLabelling(self):
		"Test that classes can be labelled and that duplicates are removed."
		hi = hinfo.frompairs(('127.0.0.1', 100),
				     ('127.0.0.2', 200))
		for add, res in self.clsseq:
			if add:
				hi.addclass(add)
			self.assertEqual(hi.getclasses(), res)

# nngh. The entire purpose of the fail function here is explicitly to die
# hideously. Yet pychecker bitches at us if this is put anywhere else.
__pychecker__ = "no-abstract"
class FailSock:
	def fail(self):
		raise socket.error, "foobar"
	def succeed(self):
		return ('127.0.0.1', 100)
	getpeername = succeed
	getsockname = succeed
__pychecker__ = ''

class socketTests(unittest.TestCase):
	def testSockInfo(self):
		"Test basic information obtained from a real socket."
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Connect to sshd on localhost.
		# TODO: somehow make a better test, which means getting
		# a local listening socket.
		rip = '127.0.0.1'
		s.connect((rip, 22))
		hi = hinfo.fromfd(s)
		self.assertEqual(hi.getip(), rip)
		self.assertEqual(hi.getport(), '22')
		self.assertEqual(hi.getrevip(), "1.0.0.127")
		s.close()

	# Fortunately we can provide a fake socket object that fails
	# deliberately.
	def testFailSockcalls(self):
		"Test that errors are properly trapped by fromfd when getsockname or getpeername fail."
		fs = FailSock()
		# This should work
		self.assertEqual(hinfo.fromfd(fs) != None, 1)
		fs.getpeername = fs.fail
		self.assertEqual(hinfo.fromfd(fs), None)
		fs.getpeername = fs.succeed
		fs.getsockname = fs.fail
		self.assertEqual(hinfo.fromfd(fs), None)

from testshims import *

class shimTests(unittest.TestCase):
	def setUp(self):
		self.ghba = hinfo.socket.gethostbyaddr
		self.ghbne = hinfo.socket.gethostbyname_ex
		self.idc = hinfo.idclient.ident
		hinfo.socket.gethostbyaddr = mygethbaddr
		hinfo.socket.gethostbyname_ex = mygethbname
		hinfo.idclient.ident = myidentd
	def tearDown(self):
		hinfo.socket.gethostbyaddr = self.ghba
		hinfo.socket.gethostbyname_ex = self.ghbne
		hinfo.idclient.ident = self.idc
	knownValues = (
		('127.0.0.100', 'noforward', '127.0.0.100', None),
		('127.0.0.101', 'noforward', 'not-a-forward', None),
		('127.0.0.102', 'addrmismatch', 'mismatch-reverse', None),
		('127.0.0.103', 'good', 'is-a-good-name', 'is-a-good-name'),
		('127.0.0.104', 'unknown', None, None),
		('127.0.0.105', 'good', 'many-ip-addrs', 'many-ip-addrs'),
		('127.100.2.0', 'good', 'many-ip-addrs', 'many-ip-addrs'),
		)

	def testKnownHostnames(self):
		"With shimed socket calls, test hostname resolution."
		for ip, hns, chn, rhn in self.knownValues:
			p = hinfo.frompairs(('127.0.0.1', 100),
					    (ip, 200))
			self.assertEqual(p.gethnstate(), hns)
			self.assertEqual(p.getclaimedhn(), chn)
			self.assertEqual(p.gethostname(), rhn)
	knownIdentdPorts = porttores.keys() + [200,]
	def testKnownIdentd(self):
		"With known identd returns, test that we get them properly."
		for port in self.knownIdentdPorts:
			p = hinfo.frompairs(('127.0.0.1', 100),
					    ('127.0.0.1', port))
			self.assertEqual(p.getidentd(),
					 myidentd(0, port, 0, 0, None))

	def testPrettyPrint(self):
		"Test the pretty-print output of remote connection information."
		hi = hinfo.frompairs(('127.0.0.1', 100),
				     ('127.0.0.103', 202))
		# Neither identd nor hostname info.
		self.assertEqual(hi.pretty(), "127.0.0.103")
		self.assertEqual(hi.pretty(1), "127.0.0.103")
		hi.getidentd()
		self.assertEqual(hi.pretty(0), "cks@127.0.0.103")
		hi.gethostname()
		self.assertEqual(hi.pretty(0), "cks@is-a-good-name")
		self.assertEqual(hi.pretty(1), "cks@127.0.0.103")

	knownInfoVals = (
		('ip', '127.0.0.103'),
		('remport', 202),
		('localip', '127.0.0.1'),
		('port', 10),
		('hnstatus', 'good'),
		('hostname', 'is-a-good-name'),
		('claimedhn', 'is-a-good-name'),
		('identd', 'cks'),
		('seensince', 0),
		('connsum', 'cks@is-a-good-name'),
		('connipsum', 'cks@127.0.0.103'),
		)
	def testGetInfo(self):
		"Test that the getinfo() dictionary exists and has the right contents."
		hi = makehi(rip = '127.0.0.103', rport = 202,
			    lip = '127.0.0.1', lport = 10)
		d = hi.getinfo()
		self.assertEqual(d['hostname'], '127.0.0.103')
		self.assertEqual(d['connsum'], '127.0.0.103')
		# Fill all the info sources, then refetch the dict.
		hi.getfirsttime(); hi.gethostname(); hi.getidentd()
		d = hi.getinfo()
		for k, v in self.knownInfoVals:
			self.assertEqual(d[k], v)

	def testGetLower(self):
		"Test that the gethostname_l() and getclaimedhn_l() routines work."
		hi = makehi(rip = '127.0.2.1')
		self.assertEqual(hi.gethostname(), "BIGBUCKS.SMACK.COM")
		self.assertEqual(hi.gethostname_l(), "bigbucks.smack.com")
		self.assertEqual(hi.getclaimedhn(), "BIGBUCKS.SMACK.COM")
		self.assertEqual(hi.getclaimedhn_l(), "bigbucks.smack.com")
		
# Shim calls to get the current time.
curtime = 0
def settime(t):
	global curtime
	curtime = t
def advtime(t):
	global curtime
	curtime += t
def gettime():
	return curtime

class testConnAge(unittest.TestCase):
	def setUp(self):
		self.otime = hinfo.time.time
		hinfo.time.time = gettime
		hinfo.cleariptimes()
	def tearDown(self):
		hinfo.time.time = self.otime

	def testGetNewTimes(self):
		"Test that HostInfo returns correct basic time info."
		settime(1000)
		hi = makehi()
		# On the first connection, first time diff is 0, and
		# we have no last time information.
		self.assertEqual(hi.getfirsttime(), 0)
		self.assertEqual(hi.getlasttime(), None)
		advtime(10)
		hi = makehi()
		# On a connection 10s forward, both first and last are 10s
		# back.
		self.assertEqual(hi.getfirsttime(), 10)
		self.assertEqual(hi.getlasttime(), 10)
		advtime(10)
		hi = makehi()
		# After another 10 seconds forward, firsttime ages to 20s, but
		# last time is still 10s back.
		self.assertEqual(hi.getfirsttime(), 20)
		self.assertEqual(hi.getlasttime(), 10)
	def testSettimes(self):
		"Test that the HostInfo settimes interface works."
		settime(1000)
		hi = makehi()
		# This set of times together is impossible normally, as
		# firsttime is always >= lasttime.
		hi.settimes(10, 200)
		self.assertEqual(hi.getfirsttime(), 10)
		self.assertEqual(hi.getlasttime(), 200)

	def testPurgeTimes(self):
		"Test that expireiptimes() will sweep and delete old times and not new ones."
		def _mkent(tm, ip):
			settime(tm)
			makehi(rip = ip).getfirsttime()
		def _ftime(ip):
			return makehi(rip = ip).getfirsttime()
		# Start empty:
		self.assertEqual(hinfo.iptimessize(), 0)
		# This entry should die.
		_mkent(1000, '127.0.0.1')
		_mkent(1000, '127.0.0.2')
		# As seen as more recently (just) than the threshold, this
		# should stay.
		_mkent(1100, '127.0.0.3')
		# As seen recently, this entry should stay too.
		_mkent(1200, '127.0.0.2')
		settime(1200)
		self.assertEqual(hinfo.iptimessize(), 3)
		hinfo.setiptimesdur(101)
		hinfo.expireiptimes()
		# We should have dropped one entry, the 127.0.0.1.
		self.assertEqual(hinfo.iptimessize(), 2)
		# 127.0.0.1 should be new, the other two not.
		self.assertEqual(_ftime('127.0.0.1'), 0)
		self.assertEqual(_ftime('127.0.0.2'), 200)
		# We don't use _ftime, because we want to be sure that
		# this entry has not been renewed somehow.
		hi = makehi(rip = '127.0.0.3')
		self.assertEqual(hi.getfirsttime(), 100)
		self.assertEqual(hi.getlasttime(), 100)
		# Now we should have three again.
		self.assertEqual(hinfo.iptimessize(), 3)
		# And another expire should not remove anything:
		hinfo.expireiptimes()
		self.assertEqual(hinfo.iptimessize(), 3)

	knownIPRanges = (
		'0.0.0.0/24',
		'127.255.255.0/24',
		'128.0.0.0/24',
		'128.100.0.0/20',
		'255.255.255.0/24',
		)
	def testVariousIPs(self):
		"Test a series of IP addresses under time check to insure they work properly."
		settime(1000)
		mydict = {}
		for ir in self.knownIPRanges:
			for ip in netblock.IPRanges(ir):
				hi = makehi(rip = ip)
				self.assertEqual(hi.getlasttime(), None)
				self.assertEqual(hi.getfirsttime(), 0)
				mydict[ip] = gettime()
				advtime(10)
		# Now, make sure they're there and all accurate still.
		now = gettime()
		for ir in self.knownIPRanges:
			for ip in netblock.IPRanges(ir):
				hi = makehi(rip = ip)
				self.assertEqual(hi.getlasttime(), now-mydict[ip])
				self.assertEqual(hi.getfirsttime(), now-mydict[ip])

	def testIntTime(self):
		"Test that times are reported as integers, not as floats."
		hi = makehi(rip = '127.0.0.1')
		settime(10)
		hi.getlasttime(); hi.getfirsttime()
		settime(15.9)
		hi = makehi(rip = '127.0.0.1')
		self.assertEqual(hi.getlasttime(), 5)
		self.assertEqual(hi.getfirsttime(), 5)

class sockShimTests(unittest.TestCase):
	def setUp(self):
		self.sockfunc = hinfo.socket.socket
		self.selfunc = hinfo.select.select
	def tearDown(self):
		hinfo.socket.socket = self.sockfunc
		hinfo.select.select = self.selfunc

	# Note that this is familiar with the implementation details
	# of hinfo.connectto(), at least to some degree.
	knownValues = (
		# Connect, data immediately there: true.
		(EAGAIN, "a", 0, True),
		# Connect, no data yet: true.
		(EAGAIN, EAGAIN, 0, True),
		(EINPROGRESS, EAGAIN, 0, True),
		# Immediate connection refused: false.
		(ECONNREFUSED, EAGAIN, 0, False),
		# connect OK, error on recv: false.
		(EAGAIN, ECONNREFUSED, 0, False),
		# connect, select timeout: false.
		(EAGAIN, "a", 1000, False),
		)
	def testConnectTo(self):
		"Test the hostinfo answerson functionality."
		for cR, rR, tmo, res in self.knownValues:
			hi = makehi()
			hinfo.select.select = selectfactory(tmo)
			hinfo.socket.socket = socketfactory(cR, rR)
			self.assertEqual(hi.answerson(10), res)

if __name__ == "__main__":
	unittest.main()
