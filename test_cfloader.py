#
import cfloader
import unittest
import StringIO
from testutils import ReadlineError

class basicTests(unittest.TestCase):
	knownLines = (
		("user cks", "user cks\n"),
		("actionfile /dev/null", "actionfile /dev/null\n"),
		("rulefile /not/there", "rulefile /not/there\n"),
		("listen 10", "listen 10@\n"),
		("listen 10@127.0.0.3", "listen 10@127.0.0.3\n"),
		("dropipafter 3600s", "dropipafter 3600s\n"),
		("onfileerror drop", "onfileerror drop\n"),
		("substitutions off", "substitutions off\n"),
		("maxthreads 10", "maxthreads 10\n"),
		("expireevery 10s", "expireevery 10s\n"),
		('dropipafter 1m', 'dropipafter 60s\n'),
		('dropipafter 1h', 'dropipafter 3600s\n'),
		('dropipafter 1d', 'dropipafter 86400s\n'),
		('expireevery -1s', 'expireevery -1s\n'),
		("aftermaxthreads foobar", "aftermaxthreads foobar\n"),
		)
	def testKnownLines(self):
		"Test cfloader's direct parsing of known lines and the invertability of its output."
		# Unlike other tests, we must materialize an object to
		# test with.
		for l, res in self.knownLines:
			cf = cfloader.NannyConfig()
			cf.parseline(l, 0)
			self.assertEqual(str(cf), res)
			cf = cfloader.NannyConfig()
			cf.parseline(res[:-1], 0)
			self.assertEqual(str(cf), res)

	def testDictAccess(self):
		"Test access to the configuration object as a dictionary."
		cf = cfloader.NannyConfig()
		cf.parseline('user cks', 0)
		cf.parseline('actionfile 10', 0)
		cf.parseline('dropipafter 60s', 0)
		self.assertEqual(cf['user'], 'cks')
		self.assertEqual(cf['actionfile'], '10')
		self.assertEqual(cf['dropipafter'], 60)
		# Test that we support 'x in y' and 'has_key'.
		self.assertEqual('user' in cf, True)
		self.assertEqual('onfilerror' in cf, False)
		self.assertEqual(cf.has_key('user'), True)
		self.assertEqual(cf.has_key('onfileerror'), False)


	# Unlike rules and actions files, we must provide a *complete*
	# input sample, because otherwise the consistency check fails.
	def testFromfile(self):
		"Test fromfile to see that it accepts known good input (also tests multiple listen directives)."
		cffile = "actionfile a\nrulefile b\nlisten 80@\nlisten 90@127.0.0.1\n"
		si = StringIO.StringIO(cffile)
		cf = cfloader.fromfile(si, "<t>")
		self.assertEqual(str(cf), cffile)

class failureTests(unittest.TestCase):
	knownBadLines = (
		'',
		'foobar',
		'user',
		'user a b c',
		'listen foobar',
		'listen 127.0.0.1',
		'dropipafter abc',
		'dropipafter',
		'substitutions abc',
		'onfileerror foobar',
		'maxthreads abc',
		'maxthreads',
		'expireevery abc',
		'expireevery',
		'expireevery 10',
		'dropipafter 10',
		'aftermaxthreads',
		)
	def testParselineFailures(self):
		"Test that parseline failes on known bad input."
		for l in self.knownBadLines:
			cf = cfloader.NannyConfig()
			self.assertRaises(cfloader.BadInput, cf.parseline,
					  l, 0)

	def testDuplicateConfig(self):
		base = "actionfile a\nrulefile b\nlisten 80\nuser cks\ndropipafter 10s\n"
		for k in ('user', 'dropipafter', 'actionfile', 'rulefile'):
			si = StringIO.StringIO(base + '%s 80\n' % (k,))
			self.assertRaises(cfloader.BadInput, cfloader.fromfile,
					  si, "<t>")

	# Our approach here is to permute around a list of the three
	# necessary configuration bits, each time excluding the first
	# element of the list (which then becomes the end).
	def testIncompleteConfig(self):
		"Test that errors are raised for an incomplete configuration."
		needed = ["rulefile", "actionfile", "listen"]
		# usefully, all three options can be given the same argument.
		for i in range(0,3):
			excl = needed.pop(0)
			# We use i here as a cheap way to shut pychecker up.
			s = "%s %d\n%s %d\n" % (needed[0], i, needed[1], i)
			si = StringIO.StringIO(s)
			self.assertRaises(cfloader.BadInput, cfloader.fromfile,
					  si, "<t>")
			needed.append(excl)

	def testClashingConfig(self):
		"Test that configuration clashes are properly detected."
		baseF = "actionfile a\nrulefile b\nlisten 80\ndropipafter 10s\n"
		clashF = baseF + "expireevery -1s\n"
		si = StringIO.StringIO(clashF)
		self.assertRaises(cfloader.BadInput, cfloader.fromfile,
				  si, "<t>")
		okayF = baseF + "expireevery 0s\n"
		# This should load OK.
		cfloader.fromfile(StringIO.StringIO(okayF), "<t>")

	# Try to test fromfile's handling of IO errors by providing it with
	# a fake file object that does nothing except explode.
	def testFromfileIO(self):
		fakefp = ReadlineError()
		self.assertRaises(cfloader.BadInput, cfloader.fromfile,
				  fakefp, "<t>")
		# happens even with initial input.
		fakefp = ReadlineError(["user cks"])
		self.assertRaises(cfloader.BadInput, cfloader.fromfile,
				  fakefp, "<t>")

	# Make sure we at least catch open errors.
	def testParseFile(self):
		self.assertRaises(cfloader.BadInput, cfloader.parsefile,
				  "/not/there/at/all")

if __name__ == "__main__":
	unittest.main()
