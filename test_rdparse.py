#
import rdparse
import unittest

# This requires a bunch of scaffolding.
class TermError(Exception):
	pass
class Term:
	def __init__(self, name, val):
		self.name = name
		self.val = val
	def __str__(self):
		if self.val != None:
			return '%s %s' % (self.name, self.val)
		else:
			return '%s' % (self.name,)
class ETerm:
	def __init__(self, name, val):
		raise TermError, "fake error"
class EMTerm(Term):
	def __init__(self, name, val):
		if val != "A":
			raise TermError, "bad value"
		Term.__init__(self, name, val)
class NodeInfo:
	terminals = {
		'a:' : Term, 'b:' : Term, 'c': Term, 'd': Term,
		'e:': ETerm,
		'f:': EMTerm,
		}
	error = TermError
	def defaultterm(self, val):
		for i in ('e:', 'f:', 'b:'):
			try:
				return self.terminals[i](i, val)
			except self.error:
				pass
		raise self.error, "bad value"

class testBasicParse(unittest.TestCase):
	knownValues = (
		('c', "c"),
		("c d", "c d"),
		("(c)", "c"),
		("!c", "!(c)"),
		("! (c d)", "!(c d)"),
		("! c d", "!(c) d"),
		("a: b", "a: b"),
		("!a: b", "!(a: b)"),
		("(c d !d)", "c d !(d)"),
		("NOT c", "!(c)"),
		# Default terminal production tests.
		("A", "f: A"),
		("B", "b: B"),
		# EXCEPT
		("d EXCEPT c", "(d) EXCEPT (c)"),
		("d EXCEPT d EXCEPT d", "(d) EXCEPT ((d) EXCEPT (d))"),
		("! (d EXCEPT c)", "!((d) EXCEPT (c))"),
		("( d EXCEPT c ) EXCEPT a: b", "((d) EXCEPT (c)) EXCEPT (a: b)"),
		("d EXCEPT !a: b", "(d) EXCEPT (!(a: b))"),
		# AND
		("d AND c", "(d) AND (c)"),
		("d c AND c", "(d c) AND (c)"),
		("d c AND c EXCEPT a: A", "((d c) AND (c)) EXCEPT (a: A)"),
		("c EXCEPT d AND c", "(c) EXCEPT ((d) AND (c))"),
		("d&&c", "(d) AND (c)"),
		("c AND c AND c", "(c) AND ((c) AND (c))"),
		# Complex nesting.
		("(c EXCEPT d) AND !a: b d", "((c) EXCEPT (d)) AND (!(a: b) d)"),
		("c && c EXCEPT c && d", "((c) AND (c)) EXCEPT ((c) AND (d))"),
		("c && c d EXCEPT !c", "((c) AND (c d)) EXCEPT (!(c))"),
		)

	def testKnownParses(self):
		"Insure that known good parses parse."
		for pstr, strres in self.knownValues:
			self.assertEqual(str(rdparse.parse(pstr, NodeInfo())), strres)
	def testReprParses(self):
		"The string representation of parses should parse to the same thing."
		for pstr, strres in self.knownValues:
			res = str(rdparse.parse(pstr, NodeInfo()))
			self.assertEqual(str(rdparse.parse(res, NodeInfo())), res)

class testFailures(unittest.TestCase):
	knownValues = (
		"",
		"!",
		"a:",
		"(",
		"( c d",
		")",
		"a: AND",
		"a: !",
		"e: any",
		"f: B",
		"nosuchterminal: a",
		"'",
		)
	def testFailures(self):
		"Test parses that should fail to make sure that they do."
		for p in self.knownValues:
			self.assertRaises(rdparse.ParseError,
					  rdparse.parse, p, NodeInfo())

# Now we have evaluation tests.
class BooleanTerm:
	def __init__(self, name, val):
		if val not in ("True", "False", "T", "F", "t", "f"):
			raise TermError, "bad value "+val
		self.val = val
		self.name = name
	def __str__(self):
		return "bool: "+self.val
	def eval(self, data):
		__pychecker__ = "no-argsused"
		return self.val in ("True", "T", "t")
class BoolTInfo:
	terminals = {"bool:": BooleanTerm}
	error = TermError
	def defaultterm(self, val):
		return self.terminals["bool:"]("bool:", val)
class testEvalResults(unittest.TestCase):
	knownResults = (
		# Basics, plus Or.
		("True", 1),
		("False", 0),
		("True False", 1),
		("True True", 1),
		("False False", 0),
		("False True", 1),
		("False False False False True", 1),
		# negation
		("!True", 0),
		("!False", 1),
		("NOT (True False)", 0),
		# AND
		("True AND True", 1),
		("True AND False", 0),
		("False AND True", 0),
		("False AND False", 0),
		# EXCEPT
		("True EXCEPT False", 1),
		("True EXCEPT True", 0),
		("False EXCEPT False", 0),
		("False EXCEPT True", 0),
		# Now we can start constructing complex cases.
		# Our goal is to test that the nesting is evaluated correctly,
		# not just str'd correctly.
		("t t f AND t", 1),
		("t AND f f t", 1),
		("t AND t EXCEPT f", 1),
		("t AND t EXCEPT t AND f", 1),
		("t AND (t EXCEPT t AND f)", 1),
		("t AND (t EXCEPT t)", 0),
		("t EXCEPT f EXCEPT t", 1),
		("(t EXCEPT f) EXCEPT t", 0),
		("t EXCEPT t EXCEPT f", 0),
		("(t EXCEPT t) EXCEPT f", 0),
		("t f f (t AND f) (t EXCEPT f)", 1),
		("f (t AND f) (t EXCEPT f)", 1),
		("f (t AND f) (t EXCEPT t)", 0),
		)
	def testEvaluation(self):
		"Test that the parse trees evaluate properly."
		for s, res in self.knownResults:
			p = rdparse.parse(s, BoolTInfo())
			self.assertEqual(p.eval(None), res, "failed on "+s)

class MergeTerm:
	def __init__(self, name, val):
		self.name = name
		self.val = val
		self.finalized = False
	def merge(self, other):
		if not isinstance(other, MergeTerm) or \
		       self.name != other.name:
			return 0
		self.val = '%s+%s' % (self.val, other.val)
		return 1
	def __str__(self):
		assert self.finalized
		return '%s %s' % (self.name, self.val)
	def finalize(self):
		self.finalized = True
	# We never eval, so we ignore this.
	def eval(self, data):
		__pychecker__ = "no-argsused"
		assert self.finalized, "unfinalized node"
		# false keeps the evaluation going on for as long as
		# possible, allowing us to check orlists more easily.
		return False
	
class MergeTInfo:
	terminals = {"one:": MergeTerm, "two:": MergeTerm,
		     "bool:": BooleanTerm}
	error = TermError
class testOrlistMerging(unittest.TestCase):
	knownValues = (
		("one: a one: b", "one: a+b"),
		("one: a two: b", "one: a two: b"),
		("one: a two: b two: c", "one: a two: b+c"),
		("bool: True bool: True", "bool: True bool: True"),
		("one: a NOT one: b", "one: a !(one: b)"),
		# This merges up through an odd path. The interior or
		# list merges to one: b+c and that node pops up to the
		# top level, which then merges again. This is because
		# rdparse is already dropping pointless nodes.
		("one: a (one: b one: c)", "one: a+b+c"),
		# Finalization tests not implicit in the above.
		("!one: b", "!(one: b)"),
		)
	def testOrListMerge(self):
		"Test the funky feature of or-lists attempting to merge adjacent entries."
		for s, sres in self.knownValues:
			p = rdparse.parse(s, MergeTInfo)
			self.assertEqual(str(p), sres)
			# This will error out if finalize has not been called.
			p.eval(None)
			
		# This case should simply return the end node, no fuss no
		# muss.
		p = rdparse.parse("one: a one: b", MergeTInfo)
		self.assertEqual(isinstance(p, MergeTerm), 1)
		p.eval(None)

# Test that rdparse.py properly handles errors during finalization.
class CanMerge:
	def __init__(self, name, val):
		__pychecker__ = "no-argsused"
	def finalize(self):
		raise TermError, "BOGUS"
	def merge(self, other):
		if isinstance(other, CanMerge):
			return True
		return False
class NoMerge:
	def __init__(self, name, val):
		__pychecker__ = "no-argsused"
class InfoObj:
	terminals = {'merge:': CanMerge, 'nom:': NoMerge}
	error = TermError
	defaultterm = None
class testFinalizeErrors(unittest.TestCase):
	knownValues = (
		"merge: a merge: b",
		"merge: a nom: b",
		"!merge: a",
		)
	def testBadFinalize(self):
		"Test that parsing correctly catches errors from finalization."
		for s in self.knownValues:
			self.assertRaises(rdparse.ParseError,
					  rdparse.parse, s, InfoObj)

if __name__ == "__main__":
	unittest.main()
