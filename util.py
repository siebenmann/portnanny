#
# Various utility routines used in multiple modules.

# This is necessary to work around a small flaw in the Python socket API.
# We cannot use socket.inet_aton() for annoying reasons.
def isipaddr(s):
	n = s.split('.')
	if len(n) != 4:
		return 0
	for i in n:
		try:
			v = int(i)
		except ValueError:
			return 0
		if v < 0 or v > 255:
			return 0
	return 1

# Given a string s, return the IP address and port. The string is in
# the form: PORT@HOST; either half is optional, in which case the @ is
# too. The host must be an IP address.
def gethostport(s):
	# No @ means it's either a port or an IP address, and we have
	# to figure out which.
	pos = s.find("@")
	if pos < 0:
		if isipaddr(s):
			return (s, '')
		try:
			int(s)
		except ValueError:
			return None
		return ('', s)
	p = s[:pos]
	h = s[pos+1:]
	if p == "*":
		p = ''
	if h == '*':
		h = ''
	if p:
		try:
			int(p)
		except ValueError:
			return None
	if h and not isipaddr(h):
		return None
	if h or p:
		return (h, p)
	else:
		return None

def int_or_raise(s, error):
	"""Return int(first-arg) or raise the second argument as an error."""
	try:
		return int(s)
	except ValueError:
		raise error, "not an integer: "+s

# We take 'Ns' or 'Nm' or 'Nh' or 'Nd'.
def getsecs_or_raise(val, err):
	if val[-1] not in ('s', 'm', 'h', 'd'):
		raise err, "time duration does not end in s/m/h/d"
	try:
		num = int(val[:-1])
	except ValueError:
		raise err, "not a number in time duration"
	if val[-1] == 's':
		return num
	elif val[-1] == 'm':
		return num * 60
	elif val[-1] == 'h':
		return num * 60 * 60
	else:
		return num * 60 * 60 * 24
