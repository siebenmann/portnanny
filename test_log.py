#
# We have to shim syslog to check the important stuff.
import log
import StringIO
import unittest

class testFilelogging(unittest.TestCase):
	def testLogtofile(self):
		"Test logging to a StringIO file."
		si = StringIO.StringIO()
		log.usestderr(si)
		log.setprogname("foobar")
		log.setdebuglevel(3)
		log.warn("string 1")
		log.debug(2, "string 2")
		log.debug(3, "string 3")
		log.debug(4, "string 4")
		self.assertEqual(si.getvalue(),
				 "foobar: string 1\nfoobar: string 2\nfoobar: string 3\n")

# String must not contain a \0.
def insistnonzero(lvl, s):
	__pychecker__ = 'no-argsused'
	if "\0" in s:
		raise KeyError, "null in string"
class testSyslogging(unittest.TestCase):
	def setUp(self):
		self.osysl = log.syslog.syslog
		log.syslog.syslog = insistnonzero
	def tearDown(self):
		log.syslog.syslog = self.osysl

	# We shim syslog.syslog so as to not explode over the actual syslog.
	def testSyslogNulls(self):
		"Test that attempting to syslog NULLs does not explode."
		log.usesyslog()
		log.warn("Should have these \0 nulls substituted \0 yep.")

if __name__ == "__main__":
	unittest.main()
