#
import actions
from StringIO import StringIO
import conntrack
import unittest
from testutils import ReadlineError, makehi

# This is a random test action file, just because.
testfile = """
# Test action file.
class0:	record odd connect from non-localhost 127/8: %(ip)s

class2:	faillog DNSB %(label)s rejects %(ip)s :
	reject

class1:	ipmax 3 : connmax 10 :
	run /usr/bin/id
"""
testres = """class0: record odd connect from non-localhost 127/8: %(ip)s
class1: connmax 10 : ipmax 3 : run /usr/bin/id
class2: faillog DNSB %(label)s rejects %(ip)s : reject
"""

class basicTests(unittest.TestCase):
	knownOps = (
		("a: reject", "a: reject"),
		("a: quiet", "a: quiet"),
		("a: drop", "a: drop"),
		("a: ipmax 3", "a: ipmax 3"),
		("a: connmax 10", "a: connmax 10"),
		("a: ipmax 0", "a: ipmax 0"),
		("a: connmax 0", "a: connmax 0"),
		("a: log", "a: log"),
		("a: log foobar", "a: log foobar"),
		("a: faillog foobar", "a: faillog foobar"),
		("a: failmsg foobar", "a: failmsg foobar"),
		("a: run /not/there", "a: run /not/there"),
		("a: failrun /a", "a: failrun /a"),
		("a: msg abc", "a: msg abc"),
		("a: norepeatlog", "a: norepeatlog"),
		("a: msg abc : failrun d", "a: failrun d : msg abc"),
		("a: subst a b", "a: subst a b"),
		("a: subst b c : subst a b", "a: subst a b : subst b c"),
		("a: setenv b 1 : setenv a 2 : msg 3", "a: msg 3 : setenv a 2 : setenv b 1"),
		("a: subst a b : msg 3", "a: msg 3 : subst a b"),
		("a: subst a b : setenv 1 2", "a: setenv 1 2 : subst a b"),
		# Canonical order check HO.
		("a: failmsg FAILMSG : log LOGIT : run DANGIT : ipmax 10 : quiet : connmax 1 : drop : reject : faillog FAILLOG : norepeatlog",
		 "a: connmax 1 : drop : faillog FAILLOG : failmsg FAILMSG : ipmax 10 : log LOGIT : norepeatlog : quiet : reject : run DANGIT"),
		)
	def testActionOperators(self):
		"Test that parseline recognizes and reproduces all of our operators."
		for ops, ress in self.knownOps:
			act = actions.parseline(ops, 0)
			self.assertEqual(str(act), ress)
			# assert stability of the output.
			self.assertEqual(str(actions.parseline(ress, 0)),
					 ress)
	def testDictAccess(self):
		"Test that action objects can be accessed like dictionaries."
		act = actions.parseline("a: reject : log : faillog abc", 0)
		self.assertEqual(act['reject'], 1)
		self.assertEqual(act['log'], '')
		self.assertEqual(act['log'] != None, 1)
		self.assertEqual(act['faillog'], 'abc')
		# Test default value return for known keys.
		self.assertEqual(act['quiet'] == None, 1)
		# Unknown keys should bomb out:
		self.assertRaises(KeyError, lambda x: act[x], 'abc')

	def testFromfile(self):
		"Basic test for the fromfile function."
		for line, good in self.knownOps:
			si = StringIO(line)
			# actions.fromfile just returns a dictionary
			# instead of an object, so we must str-ify it with
			# a utility routine.
			res = str(actions.fromfile(si, "<t>"))
			self.assertEqual(res, good+"\n")
		# Should work for empty input.
		si = StringIO("")
		res = actions.fromfile(si, "<t>")
		self.assertEqual(len(res), 0)
		# Should work for our complex input.
		si = StringIO(testfile)
		res = actions.fromfile(si, "<t>")
		self.assertEqual(str(res), testres)

	def testGetCnames(self):
		"Test that .getclassnames() works."
		res = actions.fromfile(StringIO(testfile), "<t>")
		rl = res.getclassnames()
		rl.sort()
		self.assertEqual(rl, ["class0", "class1", "class2"])

class failureTests(unittest.TestCase):
	knownBadLines = (
		'',
		'a',
		'a b',
		'a:',
		'a: foobar',
		'a: ipmax : quiet',
		'a: quiet : ipmax',
		'a: failmsg : ipmax 1',
		# exhaustively enumerate every failure possibility for each
		# directive. Yes, I am obsessive.
		'a: quiet a', 'a: quiet a a',
		'a: drop a', 'a: drop a a',
		'a: reject a', 'a: reject a a',
		'a: norepeatlog a', 'a: norepeatlog a a',
		'a: ipmax', 'a: ipmax a', 'a: ipmax 1 2',
		'a: connmax', 'a: connmax a', 'a: connmax 1 2',
		'a: run', 'a: msg', 'a: failrun', 'a: failmsg', 'a: faillog',
		'a: record',
		"a: setenv", "a: setenv a",
		"a: subst", "a: subst a",
		"a: see", "a: see a b",
		# compound failures:
		"a: quiet : quiet",
		"a: ipmax 1 : ipmax 10",
		"a: msg a : run b",
		"a: failmsg a : failrun b",
		"a: setenv a 1 : setenv a 2",
		"a: subst a 1 : subst a 2",
		)
	def testBasicOpfail(self):
		"Test that basic bad lines fail to parse."
		for line in self.knownBadLines:
			self.assertRaises(actions.BadAction,
					  actions.parseline, line, 0)
	def testFromFile(self):
		"Test that fromfile fails on bad input."
		self.assertRaises(actions.BadAction, actions.fromfile,
				  StringIO("  a: quiet"), "<t>")
		for badline in self.knownBadLines:
			if not badline:
				continue
			self.assertRaises(actions.BadAction,
					  actions.fromfile,
					  StringIO(badline), "<t>")

	def testDupClasses(self):
		"Test that fromfile rejects a file with duplicate class lines."
		self.assertRaises(actions.BadAction, actions.fromfile,
				  StringIO("a: quiet\na: ipmax 0\n"),
				  "<t>")

	# Try to test fromfile's handling of IO errors by providing it with
	# a fake file object that does nothing except explode.
	def testFromfileIO(self):
		"Test that actions.fromfile correctly errors out if given a pseudo-file object that always fails."
		fakefp = ReadlineError()
		self.assertRaises(actions.BadAction, actions.fromfile,
				  fakefp, "<t>")
		# happens even with initial input.
		fakefp = ReadlineError(["foobar: quiet",])
		self.assertRaises(actions.BadAction, actions.fromfile,
				  fakefp, "<t>")

	# Make sure we at least catch open errors.
	def testParseFile(self):
		"Test that actions.parsefile at least behaves right when the file isn't there."
		self.assertRaises(actions.BadAction, actions.parsefile,
				  "/not/there/at/all")

	# Test that recursive 'see' is properly caught.
	# (If this test fails, Python will probably do bad things, but.)
	def testRecursiveSee(self):
		"Test to insure that see loops are caught on file load."
		si = StringIO("class1: see class2\nclass2: see class3\nclass3: see class1\n")
		self.assertRaises(actions.BadAction, actions.fromfile,
				  si, "<t>")
	def testNonexistantSee(self):
		"Test that a class that tries to 'see' a nonexistant class causes the file load to fail."
		si = StringIO("class1: see class2\n")
		self.assertRaises(actions.BadAction, actions.fromfile,
				  si, "<t>")

# Test evaluation of actions.
class FakeRule:
	def __init__(self, name, label = None):
		self.lineno = -1
		self.clsname = name
		self.label = label
def genrules(lst):
	return map(FakeRule, lst)
actEvalfile = """
class1: record log1
class2: log log2 : run funcarg1
class3: ipmax 10 : faillog log3
class3.5: ipmax 0 : faillog class %(class)s
class4: msg funcarg2
class5: reject : quiet
class6: record log4

# drop should have no effect on explicit log messages.
class7: drop : log log7 : faillog log7-fail : msg doit
class7F: drop : log log7F : faillog log7F-fail : ipmax 0
# quiet just suppresses fail messages.
class8: quiet : log log8 : faillog log8-fail : msg doit
class8F: quiet : log log8F : faillog log8F-fail : ipmax 0
class8FD: quiet : log log8FD : ipmax 0
# But without quiet, we should get the right message.
class9: ipmax 0

classA: failmsg a : ipmax 0
classB: failrun b : ipmax 0
classC: run c
classD: msg d
classE: drop
classF: run F %(ip)s
classG: run G : ipmax 10 : failmsg gfail
classH: run H : ipmax 0 : failmsg hfail
classI: drop : failrun i-fail : run i-success

# environment variables
env1: msg foo : setenv a 1
env2: msg foo : setenv b ip %(ip)s is it
env3: msg foo : setenv foobar 1 : setenv barozp 2
"""
class testActionEval(unittest.TestCase):
	knownDoesfails = (
		("a: reject", "reject"),
		("a: ipmax 0", "ipmax"),
		("a: connmax 0", "connmax"),
		("a: ipmax 0 : connmax 10", "ipmax"),
		("a: connmax 0 : ipmax 10", "connmax"),
		("a: connmax 1 : ipmax 1", None),
		("a: drop", None),
		)
	# TOFIX: this test is probably obsolete, but at least it tests
	# the underlying 'doesfail()' call appropriately. Sort of.
	def testActRDoesFail(self):
		"Test ActRule.doesfailall() with basic known values."
		for s, r in self.knownDoesfails:
			hi = makehi()
			ar = actions.parseline(s, 0)
			self.assertEqual(ar.doesfailall(hi), r)

	knownLogresults = (
		(('class1', 'class3'), ['log1']),
		(('class1', 'class2'), ['log1', 'log2']),
		(('class1', 'class2', 'class6'), ['log1', 'log4', 'log2']),
		(('class1', 'class6', 'class2'), ['log1', 'log4', 'log2']),
		(('class5',), []),
		(('class3.5',), ['class class3.5']),
		(('class7',), ['log7']),
		(('class7F',), ['log7F-fail']),
		(('class8',), ['log8']),
		(('class8F',), ['log8F-fail']),
		(('class8FD',), []),
		(('class9',), ["refused: 127.0.0.1 rejected by class9 ipmax limit"]),
		)
	def testLoggedResults(self):
		"Test what is logged on the generated action."
		actrules = actions.fromfile(StringIO(actEvalfile),
					    "<t>")
		for cls, logres in self.knownLogresults:
			rlist = genrules(cls)
			hi = makehi(rip = '127.0.0.1')
			r = actrules.genaction(hi, rlist)
			if not r:
				self.assertEqual(0, 1, "genaction was null")
			self.assertEqual(r.logmsgs, logres)

	def testLogLabelLine(self):
		"Test that a label is properly logged."
		actrules = actions.fromfile(StringIO("a: ipmax 0 : faillog %(label)s@%(lineno)s\n"), "<t>")
		hi = makehi()
		r = actrules.genaction(hi, (FakeRule('a', 'foobar-label'),))
		self.assertEqual(r.logmsgs, ["foobar-label@-1"])

	knownFuncResults = (
		(("classA",), "failmsg", "a"),
		(("classB",), "failrun", "b"),
		(("classC",), "run", "c"),
		(("classD",), "msg", "d"),
		(("classE",), None, None),
		(("classF",), "run", "F 127.0.0.1"),
		(("classA", "classC"), "failmsg", "a"),
		(("classC", "classD"), "run", "c"),
		(("classG",), "run", "G"),
		(("classH",), "failmsg", "hfail"),
		(("classI",), None, None),
		)
	def testFunctionResults(self):
		"Test that actions evaluation is setting the right functions to run."
		arules = actions.fromfile(StringIO(actEvalfile), "t")
		hi = makehi(rip = '127.0.0.1')
		for cls, fres, vres in self.knownFuncResults:
			rlist = genrules(cls)
			r = arules.genaction(hi, rlist)
			self.assertEqual(r.what, fres)
			self.assertEqual(r.argstring, vres)

	knownEnvResults = (
		("env1", [("a", "1")]),
		("env2", [("b", "ip 127.0.0.1 is it")]),
		("classD", []),
		("env3", [('barozp', "2"), ("foobar", "1")]),
		)
	def testEnvResults(self):
		"Test that the environment is set properly."
		arules = actions.fromfile(StringIO(actEvalfile), "t")
		hi = makehi(rip = '127.0.0.1')
		for clsname, envres in self.knownEnvResults:
			rlist = genrules((clsname,))
			r = arules.genaction(hi, rlist)
			l = r.env.keys(); l.sort()
			rl = [(k, r.env[k]) for k in l]
			self.assertEqual(rl, envres)

	def testActGenMsgFailure(self):
		"Test that we properly raise an error during action evaluation if we are formatting a bad string."
		si = StringIO("a: ipmax 0 : failmsg %(abcdef)s\n")
		aroot = actions.fromfile(si, "<t>")
		rlist = genrules(("a",))
		self.assertRaises(actions.BadAction,
				  aroot.genaction, makehi(), rlist)

	def testNoSubst(self):
		"Test that we can disable string substitutions."
		si = StringIO("a: ipmax 0 : faillog %(ip)s\n")
		aroot = actions.fromfile(si, "<t>")
		actions.dosubstitutions(0)
		r = aroot.genaction(makehi(), genrules(("a,")))
		self.assertEqual(r.logmsgs, ["%(ip)s"])
		# We'd BETTER restore that default!
		actions.dosubstitutions(1)

# Test some basic defaulting behavior. Exhaustive tests are behind me
# right now.
failDefs = """
class1: faillog f1-log : failmsg f1-msg : ipmax 0
class2: ipmax 0
class3: connmax 0
class4: connmax 0 : quiet
class5: ipmax 0 : quiet
class6: faillog c6-l : ipmax 0
class7: failmsg c7-m : ipmax 0
class8: reject
"""
ipDef = "DEFAULT-IPMAX: failmsg ipmax-m : faillog ipmax-l"
ipDefPart = "DEFAULT-IPMAX: failmsg ipmax-m2"
connDef = "DEFAULT-CONNMAX: failmsg connmax-m : faillog connmax-l"
baseDef = "DEFAULTMSGS: failmsg gen-m : faillog gen-l"
rejDef = "DEFAULT-REJECT: failmsg rej-m : faillog rej-l"
allThree = (ipDef, connDef, baseDef)
class testFailDefaults(unittest.TestCase):
	knownValues = (
		([], "class1", "f1-msg", ["f1-log"]),
		(allThree, "class1", "f1-msg", ["f1-log"]),
		(allThree, "class2", "ipmax-m", ["ipmax-l"]),
		(allThree, "class3", "connmax-m", ["connmax-l"]),
		# rejections.
		((rejDef,), "class8", "rej-m", ["rej-l"]),
		((baseDef,), "class8", "gen-m", ["gen-l"]),
		# quiet *does* affect DEFMSG logs, but not the message.
		(allThree, "class4", "connmax-m", []),
		(allThree, "class5", "ipmax-m", []),
		# fallthroughs are correct.
		((ipDef, baseDef), "class2", "ipmax-m", ["ipmax-l"]),
		((ipDef, baseDef), "class3", "gen-m", ["gen-l"]),
		((connDef, baseDef), "class2", "gen-m", ["gen-l"]),
		((connDef, baseDef), "class3", "connmax-m", ["connmax-l"]),
		# One or the other.
		((ipDef,), "class6", "ipmax-m", ["c6-l"]),
		((ipDef,), "class7", "c7-m", ["ipmax-l"]),
		# Incomplete defaults, has a failmsg not a faillog.
		# (And that we don't fall back to the other reject default,
		# just the general one.)
		((ipDefPart, connDef, baseDef), "class2", "ipmax-m2", ["gen-l"]),
		)
	def testDefaultsMatrix(self):
		"Test a matrix of known defaulting failmsg and faillog results."
		hi = makehi()
		for plusList, cls, argRes, logRes in self.knownValues:
			t = "\n".join(plusList)
			si = StringIO(failDefs + t)
			aroot = actions.fromfile(si, "<t>")
			r = aroot.genaction(hi, genrules((cls,)))
			self.assertEqual(r.argstring, argRes)
			self.assertEqual(r.logmsgs, logRes)

# Test data for 'norepeatlog'. As usual, we have a class matrix that
# we'll use in sequence when we start banging rocks together.
testLogRepFile = """
class1: reject : faillog class1-f
class2: reject : faillog class2-f : norepeatlog
class3: record class3-r : norepeatlog
class4: record class4-r : reject : faillog class4-f : norepeatlog
class5: reject : norepeatlog : faillog foobar
class6: reject : norepeatlog : faillog foobar
class7: run foobar : log foobar : norepeatlog
class8: reject : faillog foobar
"""
class testLogRepeats(unittest.TestCase):
	knownValues = (
		# We properly repeat in the abscence of norepeatlog
		(('class1', 'class1'), ["class1-f"]),
		# norepeatlog suppresses repetition
		(('class2', 'class2'), []),
		(('class2', 'class2', 'class2'), []),
		# ... but not the first occurrence.
		(('class2',), ["class2-f"]),
		(('class1', 'class2'), ["class2-f"]),
		# norepeatlog does not suppress record
		(('class3', 'class3'), ["class3-r"]),
		# ... but it does suppress the faillog for the class.
		(('class4', 'class4'), ["class4-r"]),
		# the suppression clears when an off message is generated.
		(('class2', 'class1', 'class2'), ["class2-f"]),
		# ... but is still suppressed for a repeat afterwards.
		(('class2', 'class1', 'class2', 'class2'), []),
		# It doesn't matter if the message is generated in a
		# different class the second time.
		(('class5', 'class6'), []),
		# Or even from a success!
		(('class5', 'class7'), []),
		# However, even if it is a dup, if the class is not
		# norepeatlog it's generated.
		(('class5', 'class8'), ["foobar"]),
		# And even if the first class isn't, if the second class
		# is it's suppressed.
		(('class8', 'class5'), []),
		)
	def testNoRepLog(self):
		"Test that the norepeatlog directive works right"
		hi = makehi()
		for clslst, logres in self.knownValues:
			si = StringIO(testLogRepFile)
			# We generate the action root anew each time
			# to insure that we have a consistent start point.
			aroot = actions.fromfile(si, "<t>")
			for cls in clslst:
				r = aroot.genaction(hi, genrules((cls,)))
			self.assertEqual(r.logmsgs, logres)

splitTFile = """
class1: run foo %(label)s
class2: failrun bar %(label)s : reject
class3: run baz%(label)s
class4: reject : failmsg a b c
"""
class testArgSplit(unittest.TestCase):
	knownValues = (
		("class1", "1 2", ["foo", "1 2"], "foo 1 2"),
		("class2", "3 4", ["bar", "3 4"], "bar 3 4"),
		("class3", "5 6", ["baz5 6"], "baz5 6"),
		("class1", " 1 3", ["foo", " 1 3"], "foo  1 3"),
		("class4", "1 2", None, "a b c"),
		)
	def testRunArgSplit(self):
		"Test that run and failrun properly split their arguments before string substitution."
		aroot = actions.fromfile(StringIO(splitTFile), "<t>")
		hi = makehi()
		for rn, rl, alst, astr in self.knownValues:
			r = aroot.genaction(hi, (FakeRule(rn, rl),))
			self.assertEqual(r.argstring, astr)
			self.assertEqual(r.arglist, alst)

testSubstFile = """
class1: reject : subst abc foo-%(ip)s-bar : subst def HUP HIKE
class2: subst identd UNKNOWN : run id -x %(identd)s
DEFAULT-REJECT: faillog 1: %(abc)s 2: %(def)s
"""
class testSubst(unittest.TestCase):
	def testMsgSubsts(self):
		"Test subst-created additional substitutions."
		hi = makehi(rip = '127.100.1.2')
		aroot = actions.fromfile(StringIO(testSubstFile), "<t>")
		r = aroot.genaction(hi, genrules(("class1",)))
		self.assertEqual(r.logmsgs, ['1: foo-127.100.1.2-bar 2: HUP HIKE'])
		r = aroot.genaction(hi, genrules(("class2",)))
		self.assertEqual(r.arglist, ['id', '-x', 'UNKNOWN'])
		# Now make sure that we haven't mutated the substitutions
		# for class1 somehow (perhaps replacing the pre-expansion
		# versions with the post-expansion ones).
		hi = makehi(rip = '0.0.1.0')
		r = aroot.genaction(hi, genrules(('class1',)))
		self.assertEqual(r.logmsgs, ['1: foo-0.0.1.0-bar 2: HUP HIKE'])

# This tests the full scope of 'see'. My head hurts.
testSeeF = """
class1: see class2 : log froboznik
class1.5: reject : see class2
class2: faillog a : run b : failmsg mf-2

class3: see class4 : ipmax 10 : connmax 10
class3.5: see class6 : ipmax 10
class4: quiet : see class5 : run class4-r
class5: ipmax 0 : connmax 0
class6: connmax 0

# MY HEAD HURTS department of departments of nngh.
classA: setenv a 1 : see classB
classB: setenv a 2 : see classC
classC: setenv b 10 : run foobar : log

# This is the REALLY PERVERSE case. Don't do this at home!
classA1: subst abc def : subst def DEFJAM : see classA2
classA2: subst qzi take-%(abc)s : see classA3
classA3: subst abc HIKE : subst kij HERE :
	run foobar-me : log %(abc)s -- %(qzi)s -- %(def)s -- %(kij)s
classA4: see classA3 : subst qzi IKE : subst def 2IKE : subst kij not-here

# Mixed cascades.
class10: see class11 : drop
class11: see class12 : run foobar
class12: msg baz
class13: run c13-run : see class10

class20: see class21 : failrun 20-fr
class21: see class22 : failmsg 21-fm
class22: reject : faillog 22-F
class23: see class20 : failmsg 23-fm : faillog 23-F

class30: see class31 : ipmax 30
class31: connmax 0 : ipmax 0 : see class31a
class31a: reject
class32: see class31 : connmax 30
class33: see class32 : ipmax 30

# Record showthrough.
class40: see class41
class41: record 41-record
class42: see class40 : record frobnitz-42

# ipmax / connmax of > 0
class50: see class51
class51: ipmax 1 : connmax 1 : faillog failed %(limit)s : run foo

DEFAULT-IPMAX: faillog ipmax-fl
DEFAULT-CONNMAX: faillog connmax-fl
DEFAULT-REJECT: faillog reject-fl
"""
class testSeeOptions(unittest.TestCase):
	knownValues = (
		("class1", "run", "b", ["froboznik"]),
		("class1.5", "failmsg", "mf-2", ["a"]),
		("class2", "run", "b", []),
		("class5", None, None, ["ipmax-fl"]),
		("class4", None, None, []),
		("class3", 'run', 'class4-r', []),
		("class3.5", None, None, ["connmax-fl"]),
		("classA", "run", "foobar", ["accepted: 0.0.0.1 by classA"]),
		# This handily tests all of our string shadowing. Whee.
		("classA1", "run", "foobar-me",
		 ["def -- take-def -- DEFJAM -- HERE"]),
		("classA4", "run", "foobar-me",
		 ["HIKE -- IKE -- 2IKE -- not-here"]),
		# cascade of drop/run/msg.
		("class10", None, None, []),
		("class11", "run", "foobar", []),
		("class12", "msg", "baz", []),
		("class13", "run", "c13-run", []),
		# cascade of failmsg/failrun.
		("class22", None, None, ["22-F"]),
		("class20", "failrun", "20-fr", ["22-F"]),
		("class21", "failmsg", "21-fm", ["22-F"]),
		("class23", "failmsg", "23-fm", ["23-F"]),
		# This tests that we fail for the right reason.
		("class30", None, None, ["connmax-fl"]),
		("class32", None, None, ["ipmax-fl"]),
		("class33", None, None, ["reject-fl"]),
		("class40", None, None, ["41-record"]),
		("class42", None, None, ["frobnitz-42"]),
		)
	def testBasicSees(self):
		"Test that basic 'see' operations work correctly."
		si = StringIO(testSeeF)
		hi = makehi(rip="0.0.0.1")
		aroot = actions.fromfile(si, "<t>")
		for cls, what, argstr, logmsgs in self.knownValues:
			r = aroot.genaction(hi, genrules((cls,)))
			self.assertEqual(r.what, what)
			self.assertEqual(r.argstring, argstr)
			self.assertEqual(r.logmsgs, logmsgs)
			
	def testEnvShadowing(self):
		"Test that setenv environment variables properly get set up."
		si = StringIO(testSeeF)
		hi = makehi()
		aroot = actions.fromfile(si, "<t>")
		r = aroot.genaction(hi, genrules(("classA",)))
		re = r.env.items(); re.sort()
		self.assertEqual(re, [("a", "1"), ("b", "10")])
		r = aroot.genaction(hi, genrules(("classB",)))
		re = r.env.items(); re.sort()
		self.assertEqual(re, [("a", "2"), ("b", "10")])

	knownLimVals = (
		(0, 0, []),
		(1, 0, ["failed ipmax"]),
		(0, 1, ["failed connmax"]),
		(1, 1, ["failed ipmax"]),
		)
	def testMaxLims(self):
		"Test that connmax and ipmax are correctly handled in see situations."
		rip = '0.0.0.1'
		hi = makehi(rip = rip)
		aroot = actions.fromfile(StringIO(testSeeF), "<t>")
		clsl = genrules(("class50",))
		for ipl, connl, lmsg in self.knownLimVals:
			conntrack._clearmaps()
			for i in range(0, ipl):
				conntrack.up(i, rip, [])
			for i in range(0, connl):
				conntrack.up(i+100, 'NOIP', ['class50'])
			r = aroot.genaction(hi, clsl)
			self.assertEqual(r.logmsgs, lmsg)
			# insure that this stays true if we up class51 too.
			conntrack.up(1000, 'NOIP', ['class51'])
			conntrack.up(1001, 'NOIP', ['class51'])
			conntrack.up(1002, 'NOIP', ['class51'])
			r = aroot.genaction(hi, clsl)
			self.assertEqual(r.logmsgs, lmsg)

if __name__ == "__main__":
	unittest.main()
