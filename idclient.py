#
# A Python implementation of the client end of the identd protocol.
# This client attempts to have timeouts, just in case. You may call
# it without, in which case it is prone to certain hangup problems.
#
# see ident and sockident functions.
#
# Returned (in general): either the identd return or 'None'.

import string, socket, select, errno, time

# some constants:
MAXSIZE = 1024		# no sane identd return will ever be over this size
IDENTD = 113		# identd/auth/etc TCP port

# This error is thrown, and trapped, to handle all of our expected
# errors that should cause us to just return None.
class TrapErr(Exception):
	pass

class SafeSock:
	"""A wrapper class for sockets that times out operations.

	Initialized with the socket, the wait interval, and the error
	to throw on problems. The wait interval is the TOTAL amount of
	time all operations on this socket are allowed to take, as opposed
	to the time that any individual operation is allowed to take."""
	def __init__(self, sock, wait, err):
		sock.setblocking(0)
		self._s = sock
		if wait != None:
			self._w = time.time() + wait
		else:
			self._w = None
		self._e = err
	def fileno(self):
		return self._s.fileno()
	# General function:
	def selwait(self, dir):
		r = w = []
		if self._w:
			tmo = self._w - time.time()
			# we may have overstayed our welcome. Make sure.
			if tmo < 0:
				raise self._e
		else:
			tmo = None
		if   dir == 0:	r = [self._s]
		elif dir == 1:	w = [self._s]
		else:		r = w = [self._s]
		(r, w, e) = select.select(r, w, [self._s], tmo)
		if not (r or w):
			raise self._e
	def tryop(self, op, args):
		try:
			return (1, apply(op, args, {}))
		except socket.error, (code, emsg):
			if not code in (errno.EAGAIN, errno.EINPROGRESS):
				#print code, emsg
				raise self._e
			return (None, None)
	# opwait is wait after op; waitop is wait before op.
	# waitop requires a direction (0 for read, 1 for write).
	def opwait(self, op, *args):
		(s, r) = self.tryop(op, args)
		if s == None:
			self.selwait(2)
		# the return value may not be so useful, especially if
		# we've had to wait up above.
		return r
	def waitop(self, dir, op, *args):
		self.selwait(dir)
		(s, r) = self.tryop(op, args)
		if not s:
			raise self._e
		return r
	# close is, by definition, a 'go away we don't CARE' operation.
	def close(self):
		try:	self._s.close()
		except:	pass
	# yes, connect can wait and must time out.
	def connect(self, addr):
		return self.opwait(self._s.connect, addr)
	# caller must iterate to accumulate a full buffer (we can't
	# tell what's considered 'full')
	def recv(self, size):
		return self.waitop(0, self._s.recv, size)
	# This is tricky. It works because we have a global timeout.
	# We repeatedly send the remaining piece of the buffer down,
	# counting on the fact that eventually the timeout goes to
	# zero and blows us away if we're not done yet.
	def send(self, what):
		res = len(what)
		while what:
			r = self.waitop(1, self._s.send, what)
			what = what[r:]
		return res
	# this is not trapped specifically; it cannot time out.
	def bind(self, addr):
		return self._s.bind(addr)


# The user-serviceable parts. (sort of. Ignore _ident.)

# this function exists to push cleanup of the socket into one place.
def _ident(s, rh, rp, lh, lp):
	# Theory of operation: any timeout error throws an error, which
	# we catch. This means we can just write the code straight through.
	try:
		# we must bind to the specific interface, because of the
		# case of multihomed hosts; otherwise the remote identd
		# will either give us errors or the wrong answer.
		s.bind((lh, 0))
		s.connect((rh, IDENTD))
		s.send("%d, %d\r\n" % (rp, lp))
		l = ""
		while len(l) < MAXSIZE:
			r = s.recv(MAXSIZE)
			# maybe we got an EOF.
			if not r:
				return None
			l = l + r
			# we could insist on \r\n, but why?
			if '\n' in l:
				break
		if not '\n' in l:
			return None
		# chomp off short in case of a multi-line return.
		l = l[:string.find(l, '\n')]
		fields = map(string.strip, string.split(l, ':'))
		# does this look like a good identd return, with a user ID?
		if len(fields) != 4:
			return None
		if fields[1] != 'USERID':
			return None
		return fields[3]
	except TrapErr:
		return None
	
def ident(rh, rp, lh, lp, wait=None):
	"""Perform the identd protocol and return the result.

	Parameters: remote host, remote port, local host, and local port.
	Optional wait timeout defaults to None."""

	s = SafeSock(socket.socket(socket.AF_INET, socket.SOCK_STREAM), wait,
		     TrapErr)
	# use subroutine to centralize cleanup.
	r = _ident(s, rh, rp, lh, lp)
	s.close()
	return r

def sockident(sock, wait=None):
	"""Given a connected TCP socket, return identd information about it.

	The optional argument is the amount of time to wait for things to
	respond. None is returned if no identification can be made."""
	(rh, rp) = sock.getpeername()
	(lh, lp) = sock.getsockname()
	return ident(rh, rp, lh, lp, wait)
