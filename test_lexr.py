#
import lexr
import unittest

EOF = ('', '')
def W(s):
	return ('W', s)
def T(s):
	return ('T', s)

class baseTests(unittest.TestCase):
	knownValues = (
		("", [EOF]),
		("a", [W('a'), EOF]),
		("a b", [W('a'), W('b'), EOF]),
		# Are each of the tokens recognized?
		("AND && ( ) EXCEPT ! NOT",
		 [T('AND'), T('&&'), T('('), T(')'),
		  T("EXCEPT"), T("!"), T("NOT"), EOF]),
		("a && b", [W("a"), T("&&"), W("b"), EOF]),
		# Do we properly handle quoted strings, including embedded
		# in full words (middle, start, or end)?
		("'abc'", [W('abc'), EOF]),
		("''", [W(''), EOF]),
		("''''", [W("'"), EOF]),
		("'abc''def'", [W("abc'def"), EOF]),
		("abc'def'ghi", [W("abcdefghi"), EOF]),
		("a'b''c'd", [W("ab'cd"), EOF]),
		("'a'b", [W("ab"), EOF]),
		("a'b'", [W("ab"), EOF]),
		("'a b && d e'", [W("a b && d e"), EOF]),
		# null-length quoted objects embedded in stuff.
		("a''b", [W("ab"), EOF]),
		("''ab", [W("ab"), EOF]),
		("ab''", [W("ab"), EOF]),
		# Are each of the tokens word-breakers?
		# Conversely, are the word tokens not word-breakers?
		("a&&b", [W("a"), T("&&"), W("b"), EOF]),
		("aANDb", [W("aANDb"), EOF]),
		("a(b", [W("a"), T("("), W("b"), EOF]),
		("a)b", [W("a"), T(")"), W("b"), EOF]),
		("a!b", [W("a"), T("!"), W("b"), EOF]),
		("aEXCEPTb", [W("aEXCEPTb"), EOF]),
		("aNOTb", [W("aNOTb"), EOF]),
		# Should not match one &, or some letters of the lead.
		("a&b", [W("a&b"), EOF]),
		("aANb", [W("aANb"), EOF]),
		# Look for quoting behavior.
		("a'&&'b", [W("a&&b"), EOF]),
		("a '&&' b", [W("a"), W("&&"), W("b"), EOF]),
		("a'b'c&&d", [W("abc"), T("&&"), W("d"), EOF]),
		("a b&&(c!d e 'f'g)",
		 [W("a"), W("b"), T('&&'), T('('), W("c"), T("!"), W("d"),
		  W("e"), W("fg"), T(")"), EOF]),
		# Test that things break properly with things after them.
		("ANDOVER", [W("ANDOVER"), EOF]),
		("EXCEPTOVER", [W("EXCEPTOVER"), EOF]),
		("NOTOVER", [W("NOTOVER"), EOF]),
		("&&OVER", [T("&&"), W("OVER"), EOF]),
		("(OVER", [T("("), W("OVER"), EOF]),
		(")OVER", [T(")"), W("OVER"), EOF]),
		("!OVER", [T("!"), W("OVER"), EOF]),
		# Yes, this is a torture test. That's the fun!
		("AND'OVER'", [W("ANDOVER"), EOF]),
		("NOT", [T("NOT"), EOF]),
		)

	def testKnownValues(self):
		"Test for known parses to behave consistently."
		for p, res in self.knownValues:
			self.assertEqual(lexr.tokenize(p), res)

class baseFailTests(unittest.TestCase):
	knownFails = (
		"'",
		"'abc",
		"'abc''",
		"'abc''def",
		"'''",
		)

	def testKnownFails(self):
		"Test that certain known bad inputs raise exceptions."
		for p in self.knownFails:
			self.assertRaises(lexr.BadInput, lexr.tokenize, p)

if __name__ == "__main__":
	unittest.main()
