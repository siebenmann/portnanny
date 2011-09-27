#
# Test the rules module against various things.
#
import rules
import unittest
import StringIO

from testutils import *

class basicTests(unittest.TestCase):
	knownLines = (
		('foobar: ALL', 'foobar: ALL'),
		('foobar/nonterminal: ALL', 'foobar/nt: ALL'),
		('foobar/always: ALL', 'foobar/always: ALL'),
		('foobar/label=a: ALL', 'foobar/label=a: ALL'),
		('f/label=b/nt/always: ALL', 'f/nt/always/label=b: ALL'),
		('f: ip: 127/8', 'f: ip: 127/8'),
		('f: 127. EXCEPT 127.0.0.1', 'f: (ip: 127.) EXCEPT (ip: 127.0.0.1)'),
		('f/label: foobar', 'f/label=foobar: hostname: foobar'),
		)
	def testParseline(self):
		"Basic test for the parseline function."
		for line, res in self.knownLines:
			self.assertEqual(str(rules.parseline(line, 0)),
					 res)
			# test stability too.
			self.assertEqual(str(rules.parseline(res, 0)),
					 res)
	def testFromfile(self):
		"Basic test for the fromfile function."
		for line, good in self.knownLines:
			si = StringIO.StringIO(line)
			res = str(rules.fromfile(si, "<t>"))
			self.assertEqual(res, good+"\n")
		# Should work for empty input.
		si = StringIO.StringIO("")
		res = rules.fromfile(si, "<t>")
		self.assertEqual(len(res), 0)

	knownLabels = (
		("f/label=F: foobar", "F"),
		("f/label: bazorp", "bazorp"),
		("f: blorp", None),
		)
	def testLabels(self):
		"Test that labels are stored correctly."
		for ln, label in self.knownLabels:
			self.assertEqual(rules.parseline(ln, 0).label, label)

class failureTests(unittest.TestCase):
	knownBadLines = (
		'',
		'foobar',
		'foobar baz',
		'foobar:',
		# not an error any more.
		#'foobar/label: ALL',
		'foobar/label=: ALL',
		'foobar/baz: ALL',
		'foobar:ALL',
		'foobar: EXCEPT',
		"foobar: '",
		'foobar: ip: abc',
		# These are implicit IP addresses that should fail hard,
		# not fall over to being hostnames or whatever. Hostname
		# failover masks errors.
		'foobar: 128.100',
		'foobar: /24',
		'foobar: 0.0.0.10-0.0.0.0',
		'foobar: 0.0.0.0/33',
		'foobar: 0.0.0.0/-1',
		'foobar: 0.0.0.1/24',
		'foobar: 0.0.0.0.0',
		'foobar: 0.0.0.0.',
		)
	def testParseline(self):
		"Test that parseline fails predictably on bad input."
		for badline in self.knownBadLines:
			self.assertRaises(rules.BadInput,
					  rules.parseline, badline, 0)
	# This includes parse failures.
	def testFromfile(self):
		"Test that parsefp fails predictably on bad input."
		self.assertRaises(rules.BadInput, rules.fromfile,
				  StringIO.StringIO("  f: ALL"), "<test>")
		for badline in self.knownBadLines:
			# empty input here is EOF, not error.
			if not badline:
				continue
			self.assertRaises(rules.BadInput,
					  rules.fromfile,
					  StringIO.StringIO(badline), "<t>")
	# Try to test fromfile's handling of IO errors by providing it with
	# a fake file object that does nothing except explode.
	def testFromfileIO(self):
		fakefp = ReadlineError()
		self.assertRaises(rules.BadInput, rules.fromfile,
				  fakefp, "<t>")
		# happens even with initial input.
		fakefp = ReadlineError(["foobar: ALL",])
		self.assertRaises(rules.BadInput, rules.fromfile,
				  fakefp, "<t>")

	# Make sure we at least catch open errors.
	def testParseFile(self):
		self.assertRaises(rules.BadInput, rules.parsefile,
				  "/not/there/at/all")

# Test the cases of rule matching that we care about.
# As a side effect this tests for the rule line numbers being correct.
def formatrmatch(matchlist):
	return " ".join(map(lambda x: "%s@%d" % (x.clsname, x.lineno),
			    matchlist))
# This test data also tests that we are properly adding classes to the
# hostinfo class list.
testfile = """
# this is line 2 and starts things.
a: NOT ALL
b/nt: ALL
b2/nt: NOT ALL
b/nt: ALL EXCEPT NOT ALL
c: 255.255.255.255
c: ALL
d: ALL
e/always: ALL
f/always: class: c
g/always: class: d
	class: d
h/always: ALL
"""
class testRulesEval(unittest.TestCase):
	def testRulesEval(self):
		"Test that a set of known rules matches properly."
		rls = rules.fromfile(StringIO.StringIO(testfile), "<t>")
		hi = makehi()
		res = rls.eval(hi)
		self.assertEqual(formatrmatch(res),
				 "b@4 c@8 e@10 f@11 h@14 GLOBAL@-1")
		self.assertEqual(hi.getclasses(), ['b', 'c', 'e', 'f', 'h'])

	def testOnlySuccessGlobal(self):
		"Test that the synthetic rule GLOBAL is only added at the end of successful matches."
		rls = rules.fromfile(StringIO.StringIO("a: NOT ALL\n"), "<t>")
		hi = makehi()
		self.assertEqual(rls.eval(hi), [])

	def testGetCnames(self):
		"Test that rules.getclassnames() works."
		rls = rules.fromfile(StringIO.StringIO(testfile), "<t>")
		rl = rls.getclassnames()
		rl.sort()
		self.assertEqual(rl, ["a", "b", "b2", "c", "d", "e", "f", "g", "h"])

if __name__ == "__main__":
	unittest.main()
