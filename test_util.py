#
import util
import unittest

class testSplitLocal(unittest.TestCase):
	knownValues = (
		('127.0.0.1', ('127.0.0.1', '')),
		('200', ('', '200')),
		('200@127.0.0.1', ('127.0.0.1', '200')),
		('200@*', ('', '200')),
		('200@', ('', '200')),
		('@127.0.0.1', ('127.0.0.1', '')),
		('@foobar', None),
		('', None),
		("abc@", None),
		("a@b", None),
		("@", None),
		)
	def testGetHostPort(self):
		"Test util.gethostport() with known values."
		for i, j in self.knownValues:
			self.assertEqual(util.gethostport(i), j)

class testIsIpAddr(unittest.TestCase):
	knownValues = (
		('127.0.0.1', 1),
		('255.255.255.255', 1),
		('0.0.0.0', 1),
		('4.10.255.0', 1),
		('001.010.090.05', 1),
		('1.256.0.0', 0),
		('1.1.256.0', 0),
		('1.1.1.256', 0),
		('256.1.1.1', 0),
		('localhost', 0),
		('a.b.c.d', 0),
		('1.-1.0.0', 0),
		('200', 0),
		("200.200", 0),
		("200.200.200", 0),
		("200.200.200.", 0),
		("200.200.200.200.", 0),
		)
	def testIsIpAddr(self):
		"""Test that known input produces the correct result from isipaddr."""
		for i, j in self.knownValues:
			self.assertEqual(util.isipaddr(i), j, "bad result at "+i)

if __name__ == "__main__":
	unittest.main()
