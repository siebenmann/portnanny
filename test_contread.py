#
import contread
import unittest

import StringIO

def openstring(string):
	fp = StringIO.StringIO(string)
	return contread.fromfile(fp)

test2str1 = "This is the first line.\n"
test2str2 = "This is the second line.\n"
test2str = test2str1 + test2str2

# Basic operations using fromfile.
class fromFpTests(unittest.TestCase):
	def testOpen(self):
		"""Can we open a contread file?"""
		openstring("abc")
		
	def testClose(self):
		"""Can we close an opened contread file?"""
		fp = openstring("abc")
		self.assertEqual(fp.closed, 0)
		fp.close()
		self.assertEqual(fp.closed, 1)
	def testDidClose(self):
		"""Did closing the contread file close the underlying file object?"""
		fp = StringIO.StringIO("abc")
		contread.fromfile(fp).close()
		self.assertEqual(fp.closed, 1)
	def testRaiseOnFirstContLine(self):
		"""Do we return an error if the first real line is a continuation?"""
		fp = openstring(" a")
		self.assertRaises(contread.StartingContinuedLine,
				  fp.readcontline)
	def testRaiseOnFirstContLine_ex(self):
		"""Does the _ex interface raise an error if the first line is a continuation?"""
		fp = openstring(" a")
		self.assertRaises(contread.StartingContinuedLine,
				  fp.readcontline_ex)

class lineTests(unittest.TestCase):
	strdata = "This is a test string."
	fp = None

	def setUp(self):
		self.fp = openstring(self.strdata)
		pass
		
	def testReadline(self):
		"""Reading a line from a test string gets us the test string."""
		self.assertEqual(self.fp.readcontline(), self.strdata)
	def testReadlineex(self):
		"""Reading through the extended interface gets us the test string and the line number."""
		self.assertEqual(self.fp.readcontline_ex(), (1, self.strdata))
	def testRead2(self):
		"""Reading two lines from a one line test string should get EOF."""
		self.fp.readcontline()
		self.assertEqual(self.fp.readcontline(), '')
		# It should continue doing so.
		self.assertEqual(self.fp.readcontline(), '')
	def testRead2ex(self):
		"""Reading through the extended interface should also return EOF as blank."""
		self.fp.readcontline()
		self.assertEqual(self.fp.readcontline_ex(), '')
		self.assertEqual(self.fp.readcontline_ex(), '')

class Test2Lines(unittest.TestCase):
	fp = None

	def setUp(self):
		self.fp = openstring(test2str)

	def testRead2lines(self):
		"""Read multiple lines, ending in EOF."""
		self.assertEqual(self.fp.readcontline(), test2str1)
		self.assertEqual(self.fp.readcontline(), test2str2)
		self.assertEqual(self.fp.readcontline(), '')
	def testRead2linesex(self):
		"""Read multiple lines with line numbers, ending in EOF."""
		self.assertEqual(self.fp.readcontline_ex(), (1, test2str1))
		self.assertEqual(self.fp.readcontline_ex(), (2, test2str2))
		self.assertEqual(self.fp.readcontline_ex(), '')

# Test more complex continued lines.
contStr = """
2
 3
4
 5
 6
7
   8
  9
"""
tabTestStr = "first\n\tsecond.\nthird\n\t\t\tfourth."
class testContlines(unittest.TestCase):
	def testContLines(self):
		"Test continued lines with spaces."
		fp = openstring(contStr)
		self.assertEqual(fp.readcontline_ex(), (2, "2 3\n"))
		self.assertEqual(fp.readcontline_ex(), (4, "4 5 6\n"))
		self.assertEqual(fp.readcontline_ex(), (7, "7 8 9\n"))
	def testContLinesTab(self):
		"Test continued lines with tabs."
		fp = openstring(tabTestStr)
		self.assertEqual(fp.readcontline_ex(), (1, "first second.\n"))
		self.assertEqual(fp.readcontline_ex(), (3, "third fourth."))
	def testContLineWhitespaceRight(self):
		"Test that whitespace on the right of continued lines is trimmed."
		fp = openstring("first   \n second\n")
		self.assertEqual(fp.readcontline_ex(), (1, "first second\n"))

# Test comments, and blank lines in the middle of continued lines.
commentStr = """
# C1
  # c2
4

 6.
7
# 8
  9
  # 10
  11.
12 # not stripped.

"""
class commentTests(unittest.TestCase):
	def testComments(self):
		"Apply torture tests to comments."
		fp = openstring(commentStr)
		self.assertEqual(fp.readcontline_ex(), (4, "4 6.\n"))
		self.assertEqual(fp.readcontline_ex(), (7, "7 9 11.\n"))
		self.assertEqual(fp.readcontline_ex(), (12, "12 # not stripped.\n"))
		self.assertEqual(fp.readcontline_ex(), '')

# Unix tests for the open function. There's not much we can do.
class openTests(unittest.TestCase):
	def testOpenNull(self):
		"Can we open /dev/null and get immediate EOF?"
		fp = contread.openfile("/dev/null")
		self.assertEqual(fp.readcontline(), '')
	def testOpenNotThere(self):
		"Opening a nonexistent file raises an IOError."
		self.assertRaises(IOError, contread.openfile, "/not/there")
	# IF YOU RUN THIS AS ROOT, I SPANK YOU HARD.
	def testOpenBadPerms(self):
		"Opening a file with no permissions fails."
		self.assertRaises(IOError, contread.openfile, "/etc/shadow")

if __name__ == "__main__":
	unittest.main()
