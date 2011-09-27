#
# This is an evil hack to shim various socket and identd pieces.
# Look ma, shims.
import socket, errno
# for the error.

iptoname = {
	'127.0.0.1': 'localhost',
	'127.0.0.100': '127.0.0.100',
	'127.0.0.101': 'not-a-forward',
	'127.0.0.102': 'mismatch-reverse',
	'127.0.0.103': 'is-a-good-name',
	'127.0.0.105': 'many-ip-addrs',
	'127.100.2.0': 'many-ip-addrs',
	# 127.0.0.104 is not there.
	'127.0.1.1': 'franklin.com',
	'127.0.1.2': 'b.a.franklin.com',
	'127.0.2.1': "BIGBUCKS.SMACK.COM",
	'128.100.102.51': 'hawkwind.utcs.utoronto.ca',
	}
def mygethbaddr(ip):
	if not iptoname.has_key(ip):
		raise socket.error, "my error"
	return (iptoname[ip], [], [ip,])
nametoip = {
	'localhost': ['127.0.0.1'],
	'is-a-good-name': ['127.0.0.103',],
	'mismatch-reverse': ['127.0.0.255',],
	'many-ip-addrs': ['127.100.0.0', '127.100.1.0', '127.100.2.0',
			  '127.0.0.105'],
	'franklin.com': ['127.0.1.1',],
	'b.a.franklin.com': ['127.0.1.2'],
	"BIGBUCKS.SMACK.COM": ['127.0.2.1'],
	"no-reverse-name": ['127.0.10.1'],
	'hawkwind.utcs.utoronto.ca': ['128.100.102.51'],
	# Our DNSBL checks.
	"10.11.12.13.dnsbl1": ['127.0.0.4'],
	"5.6.7.8.dnsbl1": ['127.0.0.3'],
	"1.2.3.15.dnsbl2": ['127.0.0.5', '127.0.0.6'],
	}
def mygethbname(name):
	if not nametoip.has_key(name):
		raise socket.error, "my error 2"
	return (name, [name,], nametoip[name])

porttores = {
	202: 'cks',
	203: '[abcdef]',
	}
def myidentd(rip, rport, lip, lport, timeo):
	__pychecker__ = "no-argsused"
	if porttores.has_key(rport):
		return porttores[rport]
	return None

# Fake sockets.
# These deliberately have no fileno argument, so they detonate on contact
# with a real select() call.
class FakeSocket:
	def __init__(self, connectR, recvR):
		self.blocking = 1
		self.connectR = connectR
		self.recvR = recvR
	def setblocking(self, n):
		self.blocking = n
	def connect(self, pair):
		assert not self.blocking
		assert len(pair) == 2
		raise socket.error, (self.connectR, "BOGUS CONNECT")
	def recv(self, n):
		assert n == 1
		assert not self.blocking
		if isinstance(self.recvR, int):
			raise socket.error, (self.recvR, "BOGUS RECV")
		return self.recvR
	def getsockopt(self, lvl, what):
		assert lvl == socket.SOL_SOCKET
		assert what == socket.SO_ERROR
		if isinstance(self.recvR, int) and self.recvR != errno.EAGAIN:
			return self.recvR
		else:
			return 0

def socketfactory(connectR, recvR):
	# I have no idea why pychecker gets this wrong.
	__pychecker__ = "no-implicitreturns"
	def skt(a, b):
		assert a == socket.AF_INET
		assert b == socket.SOCK_STREAM
		return FakeSocket(connectR, recvR)
	return skt

def selectfactory(duration):
	def slct(r, w, e, tmo):
		if tmo >= duration:
			return (r, w, e)
		else:
			return ([], [], [])
	return slct
