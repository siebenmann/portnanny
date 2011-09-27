#
import msgs
import hinfo
import unittest
from testutils import *

class FakeCls:
	def __init__(self, name, lineno, label):
		self.clsname = name
		self.lineno = lineno
		self.label = label

class basicTests(unittest.TestCase):
	def testFormatMsg(self):
		"Test msgs.formatmsg() against some known values."
		hi = makehi(rip = '127.100.0.10')
		fc = FakeCls('test', 10, 'foo-bar')
		r = msgs.format('%(class)s@%(lineno)d aka %(label)s: %(hostname)s',
				hi, fc)
		self.assertEqual(r, 'test@10 aka foo-bar: 127.100.0.10')
		self.assertEqual(msgs.format("%(frobnitz)s", hi, fc, frobnitz = "foobar"),
				 "foobar")
		self.assertEqual(msgs.format("%(nl)s!%(cr)s!%(eol)s!", hi, fc),
				 "\n!\r!\r\n!")
		fc2 = FakeCls("test", 10, "a_b_c")
		self.assertEqual(msgs.format("!%(label)s+", hi, fc2), "!a b c+")
		self.assertEqual(msgs.format("%(testit)s", hi, fc, testit="abc"), "abc")
	def testExtraDict(self):
		"Test msgs.formatmsg()'s supplementary dictionary parameter."
		hi = makehi(rip = '127.100.0.10')
		fc = FakeCls('test', 10, 'foo-bar')
		sdict = {'abc': 'def'}
		self.assertEqual(msgs.format("%(abc)s", hi, fc, sdict), "def")
		# Assert that sdict is unmangled by msgs.format.
		self.assertEqual(str(sdict), "{'abc': 'def'}")
		# Check that we cannot override stuff supplied from hi et al.
		sdict = {'ip': 'def'}
		self.assertEqual(msgs.format("%(ip)s", hi, fc, sdict), "127.100.0.10")
		self.assertEqual(str(sdict), "{'ip': 'def'}")
		

if __name__ == "__main__":
	unittest.main()
