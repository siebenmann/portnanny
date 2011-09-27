#
# Sets of IP address ranges.
# We support IP addresses, CIDR notation, and LOWIP-HIGHIP ranges, and
# produce output generally as CIDR ranges.

# NOTEZ BIEN: use of long integers is deliberate, because it insures that
# various comparisons work right (eg 'low < high', when low has the high
# bit clear and high has it set).
import ranges

class NBError(Exception):
	pass
class BadCIDRError(NBError):
	pass

# mask off 32 bits.
B32M = 0xffffffffL
def m32(n):
	"""Mask a number to 32 bits."""
	return n & B32M

def lenmask(len):
	"""Return the mask for a given network length"""
	return m32(-(1L<<(32-len)))

def cidrrange(addr, length):
	"""Given an IP address and a network size, return the low and high addresses in it."""
	m = lenmask(length)
	# the low end is addr & mask (to make sure no funny business is going
	# on)
	l = addr&m
	# the high end is the low end plus the maximum span of the mask.
	# the maximum span is found by inverting the mask.
	h = l + m32(~0 ^ m)
	# this is essentially the same as the previous, time-wise.
	#h = l + (1L<<(32-length))-1
	return (l, h)

# This accepts 'short' IPs to enable, for example, '127.0/16'.
# However, we only accept them in the CIDR context, not in others.
# Normally specified IP addresses must have all four octets.
def strtoip(ipstr, min = 4):
	"""Convert an IP address in string form to numeric."""
	res = 0L
	n = ipstr.split('.')
	ln = len(n)
	if ln > 4 or ln < min:
		raise NBError, "Invalid number of IP octets"
	for i in n:
		res = res << 8L
		try:
			ot = int(i)
		except ValueError:
			raise NBError, "invalid IP octet"
		if ot < 0 or ot > 255:
			raise NBError, "invalid IP octet"
		res = res + ot
	# Now fix up for omitted trailing octets.
	res = res << (8L * (4-ln))
	return res
def convip(s):
	res = strtoip(s)
	return (res, res)
def convcidr(cstr, strict = 1):
	"""Returns the start and end IPs of a CIDR from a string."""
	pos = cstr.find('/')
	ip = strtoip(cstr[:pos], min = 1)
	try:
		size = int(cstr[pos+1:])
	except ValueError:
		raise NBError, "invalid CIDR size"
	if size < 0 or size > 32:
		raise NBError, "CIDR size not in 0 to 32"
	res = cidrrange(ip, size)
	# For a strict check, the start IP must be the low IP of the
	# CIDR range.
	if strict and res[0] != ip:
		raise BadCIDRError, "CIDR start IP is not properly aligned: "+cstr
	return res
def convrange(s):
	"""Returns the start and end IPs from a string range."""
	pos = s.find('-')
	low = strtoip(s[:pos])
	high = strtoip(s[pos+1:])
	if low > high:
		raise NBError, "IP range has start larger than end."
	return (low, high)

# Convert an incoming string to an IP address range. An incoming
# string is either an IP address, a CIDR netblock, or a string
# range ('IP-IP'). In all cases, the conversion result is a tuple
# of low-high. 'Strict' is whether the CIDR should insist that it
# start on its boundary, and defaults to yes.
def convert(s, strict = 1):
	if '/' in s:
		return convcidr(s, strict)
	elif '-' in s:
		return convrange(s)
	else:
		return convip(s)


# These functions go the other way.
def octet(ip, n):
	"""get octet n (0-3) of ip address ip. 0 is the first (left) octet."""
	s = (3-n) * 8
	return (ip >> s) & 0xff

def ipstr(ip):
	"""Convert IP number to string form"""
	o1, o2, o3, o4 = octet(ip,0), octet(ip,1), octet(ip,2), octet(ip,3)
	return '%d.%d.%d.%d' % (o1, o2, o3, o4)

def cidrtostr(ip, len):
	if len == 32:
		return ipstr(ip)
	else:
		return '%s/%d' % (ipstr(ip), len)

# This finds the largest CIDR length that can start with the IP address,
# based on what the first bit set is.
def fmaxlen(ip):
	# Range excludes the high, so use 0,33 so we go 0 .. 32.
	for i in range(0, 33):
		if ip & (1L<<i):
			return 32-i
	return 0
# For internal use, we append the results to a list.
def lhcidrs(lip, hip, lst):
	"""Convert a range from lowip to highip to a set of address/mask values."""
	while lip <= hip:
		# algorithm:
		# try successively smaller length blocks starting at lip
		# until we find one that fits within lip,hip. add it to
		# the list, set lip to one plus its end, keep going.
		# we must insure that the chosen mask has lip as its proper
		# lower end, and doesn't go lower.
		lb = fmaxlen(lip)
		while lb <= 32:
			(lt, ht) = cidrrange(lip, lb)
			if lt == lip and ht <= hip:
				break
			lb = lb + 1
		assert (0 <= lb <= 32) and (lt == lip and ht <= hip), \
		       "failed to generate a valid, fitting CIDR"
		lst.append((lip, lb))
		lip = ht+1

# This class handles network blocks.
class IPRanges(ranges.Ranges):
	"""Sets of IP address ranges.

	All IP address arguments are supplied as strings."""
	def __init__(self, ival = None):
		ranges.Ranges.__init__(self)
		if ival:
			self.add(ival)

	# We inherit most of __str__ from Ranges, needing only our own
	# routine to pretty-print individual elements.
	def _rel(self, val):
		return ipstr(val)
	def __str__(self):
		return "<IPRanges: %s>" % (" ".join(map(self._rrange, self._l)),)

	# This is the all-purpose interface.
	# Since the three forms of addresses we accept cannot be confused
	# for each other, we accept all three equally and just parse them
	# ourselves.
	def add(self, val):
		(low, high) = convert(val)
		self.addrange(low, high)

	# This allows 'odd' CIDRs, which are rejected by 'add'.
	def addoddcidr(self, val):
		(low, high) = convert(val, 0)

	# Remove works similarly.
	def remove(self, val):
		(low, high) = convert(val)
		self.delrange(low, high)
	def removeoddcidr(self, val):
		(low, high) = convert(val, 0)
		self.delrange(low, high)

	# Our implementation of 'in' takes an IP address string, not a number,
	# because that's our external interface.
	# Except for efficiency's sake, we want to allow a number so that we
	# can avoid repeated strtoip() calls.
	def __contains__(self, val):
		if isinstance(val, (int, long, float)):
			return ranges.Ranges.__contains__(self, val)
		else:
			return ranges.Ranges.__contains__(self, strtoip(val))

	# Convert ourselves to a list of strings of CIDR netblocks.
	def tocidr(self):
		r = []
		for irng in self._l:
			lhcidrs(irng[0], irng[1], r)
		return [cidrtostr(x[0], x[1]) for x in r]
