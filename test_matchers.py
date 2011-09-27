#
# Test the matchers module.
#
# Because the matchers module is a high-level thing, this requires a working
# hinfo and eventually rdparse module.
import matchers
import hinfo
import unittest

from testutils import *

class tUtils(unittest.TestCase):
	# As a side effect of how it works, lcheck checks to see that
	# the MatchInfo data is in place for a given matcher.
	def lcheck(self, name, list):
		mfactory = matchers.MatchInfo.terminals[name]
		for iaddr, val, res in list:
			mo = mfactory(name, val)
			if hasattr(mo, "finalize"):
				mo.finalize()
			hi = makehi(rip = iaddr)
			self.assertEqual(mo.eval(hi), res,
					 "failed for %s/%s" % (iaddr, val))
	def genfinal(self, name, val):
		mfactory = matchers.MatchInfo.terminals[name]
		mo = mfactory(name, val)
		if hasattr(mo, "finalize"):
			mo.finalize()
		return mo

class testSimpleMatchers(tUtils):
	def testAllMatcher(self):
		"Test the ALL matcher."
		mo = matchers.AllMatch(None, None)
		hi = makehi()
		self.assertEqual(mo.eval(hi), 1)

	knownIpAddrMatches = (
		('127.0.0.1', '127.0.0.0/8', 1),
		('128.100.102.1', '127.0.0.0/8', 0),
		('127.0.0.2', '127.0.0.2', 1),
		('127.0.0.1', '127.0.0.2', 0),
		('127.0.0.1', '127.0.0.', 1),
		('127.1.0.0', '127.0.', 0),
		('142.151.255.255', '142.150.0.0/15', 1),
		('142.152.0.0', '142.150.0.0/15', 0),
		# Make sure the low-hi syntax is recognized.
		('127.0.0.1', '127.0.0.0-127.0.0.240', 1),
		# Make sure runt CIDR specifications, ditto.
		('127.0.0.1', '127.0/8', 1),
		)
	def testIPaddrMatcher(self):
		"Test ip: matching against a variety of cases."
		self.lcheck("ip:", self.knownIpAddrMatches)

	def testLIPMatcher(self):
		"Test localip: matching to insure it uses the right IP address."
		li = '127.0.0.1'; ri = '127.0.0.10'
		m1 = self.genfinal("localip:", li)
		m2 = self.genfinal("localip:", ri)
		hi = makehi(lip = li, rip = ri)
		self.assertEqual(m1.eval(hi), 1)
		self.assertEqual(m2.eval(hi), 0)

	def testClassMatcher(self):
		"Test the class: matcher for positive and negative matches."
		mo = matchers.ClassMatch("class:", "foobar")
		hi = makehi()
		self.assertEqual(mo.eval(hi), 0)
		hi.addclass("foobar")
		self.assertEqual(mo.eval(hi), 1)
			
	# Test matcher.LocalMatch. We do this separately because we want
	# to vary to local IP, not the remote one.
	localMatcherValues = (
		('127.0.0.1', 100, '100@', 1),
		('127.0.0.1', 100, '200@', 0),
		('127.0.0.1', 100, '127.0.0.1', 1),
		('127.0.0.1', 100, '100@127.0.0.1', 1),
		('128.100.102.51', 100, '127.0.0.1', 0),
		('128.100.102.51', 100, '*@128.100.102.51', 1),
		)
	def testLocalMatcher(self):
		"Test the local: matcher against a series of known values."
		for ip, port, val, res in self.localMatcherValues:
			mo = matchers.LocalMatch('local:', val)
			hi = hinfo.frompairs((ip, port),
					     ('0.0.0.0', '100'))
			self.assertEqual(mo.eval(hi), res)


	# In the presence of finalization, this is now kind of ugly. It would
	# probably be better to rewrite this test using rdparse instead of
	# magically knowing the rules ourselves. On the other hand, it's a
	# thorough test.
	def testIpMerging(self):
		"Test that ip: and localip: merge correctly and get the right results."
		bo = matchers.IPAddrMatch('ip:', '0.0.0.0')
		ipL = ('127.0.0.1', '127.0.0.2', '127.0.0.3')
		for i in ipL:
			mi = matchers.IPAddrMatch('ip:', i)
			self.assertEqual(bo.merge(mi), 1)
		bo.finalize()
		self.assertEqual(str(bo), 'ip: 0.0.0.0 ip: 127.0.0.1 ip: 127.0.0.2 ip: 127.0.0.3')
		for i in ipL:
			hi = makehi(rip = i)
			self.assertEqual(bo.eval(hi), 1)
		for i in ('0.0.0.1', '127.0.0.0', '127.0.0.4'):
			hi = makehi(rip = i)
			self.assertEqual(bo.eval(hi), 0)
		# Localip should not merge down with 'ip:', but should
		# merge down with each other.
		bo = matchers.IPAddrMatch("ip:", "0.0.0.0")
		mi = matchers.LIPAddrMatch('localip:', '10.10.10.10')
		mi2 = matchers.LIPAddrMatch('localip:', '11/8')
		self.assertEqual(bo.merge(mi), 0)
		self.assertEqual(mi.merge(mi2), 1)
		mi.finalize()
		self.assertEqual(str(mi), 'localip: 10.10.10.10 localip: 11/8')
		# Merge down on the prefixes to make sure that works.
		mi = matchers.IPAddrMatch('ip:', '128.100.100.')
		mi2 = matchers.IPAddrMatch('ip:', '128.100.')
		mi3 = matchers.IPAddrMatch('ip:', '128.')
		# Our first merge is two non-CIDrs.
		self.assertEqual(mi.merge(mi2), 1)
		mi.finalize()
		self.assertEqual(mi.cidr.tocidr(), ['128.100.0.0/16'])
		mi._definalize()
		# Second merge is non-CIDR other, CIDR us.
		self.assertEqual(mi.merge(mi3), 1)
		mi.finalize()
		self.assertEqual(mi.cidr.tocidr(), ['128.0.0.0/8'])
		mi._definalize()
		# By flipping this, we test non-cidr merging with cidr.
		self.assertEqual(mi3.merge(mi), 1)
		mi3.finalize()
		self.assertEqual(mi3.cidr.tocidr(), ['128.0.0.0/8'])
		# Test that we get the /24 case right (it could have been
		# off and subsumed above).
		mi = matchers.IPAddrMatch('ip:', '128.100.100.')
		mi2 = matchers.IPAddrMatch('ip:', '127.0.0.0/24')
		self.assertEqual(mi.merge(mi2), 1)
		mi.finalize()
		self.assertEqual(mi.cidr.tocidr(), ['127.0.0.0/24', '128.100.100.0/24'])
		

from testshims import *

# This stuffs shims into place.
class Shimit(tUtils):
	def setUp(self):
		self.ghba = hinfo.socket.gethostbyaddr
		self.ghbne = hinfo.socket.gethostbyname_ex
		self.idc = hinfo.idclient.ident
		hinfo.socket.gethostbyaddr = mygethbaddr
		hinfo.socket.gethostbyname_ex = mygethbname
		hinfo.idclient.ident = myidentd
	def tearDown(self):
		hinfo.socket.gethostbyaddr = self.ghba
		hinfo.socket.gethostbyname_ex = self.ghbne
		hinfo.idclient.ident = self.idc
	
class testShimMatchers(Shimit):
	knownHNSet = (
		("KNOWN", None,
		 (('127.0.0.2', 0),
		  ('127.0.0.102', 0),
		  ('127.0.0.103', 1))),
		("UNKNOWN", None,
		 (('127.0.0.2', 1),
		  ('127.0.0.103', 0),
		  ('127.0.0.101', 0),)),
		("PARANOID", None,
		 (('127.0.0.103', 0),
		  ('127.0.0.104', 0),
		  ('127.0.0.100', 1),
		  ('127.0.0.101', 1),
		  ('127.0.0.102', 1),)),
		("hnstatus:", "noforward",
		 (('127.0.0.100', 1),
		  ('127.0.0.101', 1),
		  ('127.0.0.103', 0),)),
		("hnstatus:", "addrmismatch",
		 (('127.0.0.100', 0),
		  ('127.0.0.103', 0),
		  ('127.0.0.104', 0),
		  ('127.0.0.102', 1),)),
		)
	def testHNStatus(self):
		"Test the HNStatusMatch matcher against various values."
		for n, v, cases in self.knownHNSet:
			mo = matchers.HNStatusMatch(n, v)
			for ip, res in cases:
				hi = makehi(rip = ip)
				self.assertEqual(mo.eval(hi), res)

	knownHostnames = (
		('127.0.0.103', 'is-a-good-name', 1),
		('127.0.0.105', 'many-ip-addrs', 1),
		('127.0.0.101', 'not-a-forward', 0),
		('127.0.0.100', '127.0.0.100', 0),
		('127.0.1.1', 'franklin.com', 1),
		('127.0.1.1', 'a.franklin.com', 0),
		('127.0.1.1', 'klin.com', 0),
		('127.0.1.2', 'b.a.franklin.com', 1),
		('127.0.1.2', '.a.franklin.com', 1),
		('127.0.1.2', '.franklin.com', 1),
		('127.0.1.2', 'b.a.', 0),
		('127.0.2.1', 'bigbucks.smack.com', 1),
		('127.0.1.1', 'FRANKlin.CoM', 1),
		('127.0.2.1', '.smack.com', 1),
		)
	def testHostnameMatch(self):
		"Test the HostnameMatch matcher against known values."
		self.lcheck('hostname:', self.knownHostnames)

	knownCHostnames = (
		('127.0.0.103', 'is-a-good-name', 1),
		('127.0.0.101', 'not-a-forward', 1),
		('127.0.0.102', 'mismatch-reverse', 1),
		('127.0.0.100', '127.0.0.100', 1),
		('127.0.0.104', '127.0.0.104', 0),
		)
	def testClaimedHNMatch(self):
		"Test the ClaimedHNMatch matcher against known values."
		self.lcheck('claimedhn:', self.knownCHostnames)

	knownREMatches = (
		('127.0.0.103', '^good', 0),
		('127.0.0.103', 'good', 1),
		('127.0.2.1', "smack\.com$", 1),
		('127.0.0.102', 'match', 0),
		)
	def testREMatch(self):
		"Test the re: matching against known values."
		self.lcheck("re:", self.knownREMatches)

	knownCREMatches = (
		('127.0.0.103', 'good', 1),
		('127.0.0.101', '-forward', 1),
		('127.0.0.104', '127', 0),
		)
	def testClaimedREMatch(self):
		"Test the claimedre: matcher to insure it matches against claimed hostnames."
		self.lcheck("claimedre:", self.knownCREMatches)

	knownForwhnMatches = (
		('127.0.0.1', 'no-reverse-name', 0),
		('127.0.10.1', 'no-reverse-name', 1),
		('127.0.1.1', 'franklin.com', 1),
		('127.100.0.0', 'many-ip-addrs', 1),
		('127.0.0.1', 'many-ip-addrs', 0),
		)
	def testForwMatch(self):
		"Test the forwhn: matcher for basic values."
		self.lcheck("forwhn:", self.knownForwhnMatches)

	knownDBLChecks = (
		('13.12.11.10', 'dnsbl1', 1),
		('10.11.12.13', 'dnsbl1', 0),
		('13.12.11.10', 'dnsbl1/127.0.0.4', 1),
		('13.12.11.10', 'dnsbl1/127.0.0.3', 0),
		('15.3.2.1', 'dnsbl2/127.0.0.6', 1),
		('15.3.2.1', 'dnsbl2', 1),
		)
	def testDnsblMatch(self):
		"Test the dnsbl: matcher for basic values."
		self.lcheck('dnsbl:', self.knownDBLChecks)

	identdDataSet = (
		(202, 'cks', 1),
		(202, 'foobar', 0),
		(203, 'cks', 0),
		(201, 'cks', 0),
		)
	def testIdentdMatches(self):
		"Test identd matching."
		for port, iddes, res in self.identdDataSet:
			mo = matchers.IdentdMatch("identd:", iddes)
			hi = makehi(rport = port)
			self.assertEqual(mo.eval(hi), res)
	def testHasIdentd(self):
		"Test for matching when we just want to know if we have identd data."
		mo = matchers.IdentdMatch("IDENTD", None)
		idports = (202, 203)
		for port in idports + (204,):
			hi = makehi(rport = port)
			self.assertEqual(mo.eval(hi), port in idports)

	# Test the time-based matchers.
	knownTBInfo = (
		('firsttime', None, (0, None), 1),
		('firsttime', None, (61, 0), 0),
		('stallfor:', '60s', (50, 20), 1),
		('stallfor:', '60s', (60, 20), 1),
		('stallfor:', '60s', (61, 20), 0),
		# 'waited:' is the inverse of stallfor.
		('waited:', '60s', (50, 20), 0),
		('waited:', '60s', (60, 20), 0),
		('waited:', '60s', (61, 20), 1),
		# 'seenwithin: and 'notseenfor' are the corresponding
		# last-time-connected versions.
		('seenwithin:', '60s', (65, 50), 1),
		('seenwithin:', '60s', (65, 60), 1),
		('seenwithin:', '60s', (65, 61), 0),
		('notseenfor:', '60s', (65, 50), 0),
		('notseenfor:', '60s', (65, 60), 0),
		('notseenfor:', '60s', (65, 61), 1),
		# They treat new connections differently.
		('seenwithin:', '60s', (0, None), 0),
		('notseenfor:', '60s', (0, None), 1),
		)
	def testTimeBasedMatchers(self):
		"Test stallfor:, notseenfor:, and firsttime for correct results."
		for n, v, times, res in self.knownTBInfo:
			mo = matchers.MatchInfo.terminals[n](n, v)
			hi = makehi()
			hi.settimes(times[0], times[1])
			self.assertEqual(mo.eval(hi), res,
					 "failed on %s %s / %s" % (n, v, times))

	def testAnswersTo(self):
		"Do a very basic test for answerson:."
		mo = matchers.MatchInfo.terminals["answerson:"]
		hi = makehi()
		# Now we get intimate with the innards:
		hi._anscache[10] = True
		hi._anscache[25] = False
		self.assertEqual(mo("answerson:", "10").eval(hi), True)
		self.assertEqual(mo("answerson:", "25").eval(hi), False)

# Test things that should fail to be recognized.
class testMatcherRejects(tUtils):
	knownBadIPAddrSet = (
		'abc',
		"localhost.foobar",
		"localhost.foobar.",
		"256.100.100.100",
		"128.100.100.100.",
		"256.100.",
		"128.100.0.0/16/16",
		"128.100.0.0/33",
		"127.0.0.0/",
		"/24",
		# inverted hi-low
		'127.0.0.10-127.0.0.1',
		# incomplete octets
		'127.0.0',
		'206.29.6',
		# Broken CIDR, with the local part not all zeros.
		'127.0.0.1/24',
		'127.0.1.0/16',
		)
	def testBadIPAddrs(self):
		"Test IPAddrMatch to insure it does not accept bad values."
		for v in self.knownBadIPAddrSet:
			self.assertRaises(matchers.BadArg,
					  self.genfinal, "ip:", v)

	def testBadHNStatus(self):
		"Test to insure HNStatus rejects bad values."
		self.assertRaises(matchers.BadArg, matchers.HNStatusMatch,
				  "hnstatus:", "forobtz")

	def testBadLocalMatch(self):
		"Test to insure LocalMatch rejects bad values."
		for a in ('@', '*@', '@*', ''):
			self.assertRaises(matchers.BadArg,
					  matchers.LocalMatch, None, a)
	def testBadHostnames(self):
		"Test to insure hostname: and forwhn: rejects bad names."
		for a in ('.', '%', ' ajk', ';'):
			self.assertRaises(matchers.BadArg,
					  matchers.HostnameMatch, None, a)
			self.assertRaises(matchers.BadArg,
					  matchers.ForwhnMatch, None, a)

	def testBadRegexp(self):
		"Test to insure that REMatch properly handles a bad regexp."
		self.assertRaises(matchers.BadArg, matchers.REMatch,
				  're:', '[ab')
	def testBadDNSBl(self):
		"Test that dnsbl: properly detects badly placed /'s."
		self.assertRaises(matchers.BadArg, matchers.DNSBlMatch,
				  "dnsbl:", "/128.100.1.1")
		self.assertRaises(matchers.BadArg, matchers.DNSBlMatch,
				  "dnsbl:", "128.100.1.1/")
		self.assertRaises(matchers.BadArg, matchers.DNSBlMatch,
				  "dnsbl:", "128.100.1.1/200")

	# The stallfor: matcher is a proxy for all time based matchers,
	# because they all use the same basic code.
	knownBadTimes = ('60', '60k', 'abcs')
	def testBadStall(self):
		"Test that the stallfor: matcher rejects bad times."
		for i in self.knownBadTimes:
			self.assertRaises(matchers.BadArg, matchers.StallMatch,
					  "stallfor:", i)

	def testBadAnswerOn(self):
		"Test that the answerson: matcher rejects bad ports."
		for i in ("a", "-10", "100000"):
			self.assertRaises(matchers.BadArg,
					  matchers.AnswersOnMatch,
					  "answeron:", i)

# All of this testing is all well and good, but we want to test the
# *real* stuff: can we parse and evaluate rules using all of the
# functionality here exposed?
import rdparse
class testParsingEvaling(Shimit):
	basicOps = (
		("ALL", "ALL"),
		("IDENTD", "IDENTD"),
		("identd: foo", "identd: foo"),
		("local: 1@0.0.0.0", "local: 1@0.0.0.0"),
		("local: 1", "local: 1@"),
		("local: 0.0.0.0", "local: @0.0.0.0"),
		("KNOWN", "hnstatus: KNOWN"),
		("UNKNOWN", "hnstatus: UNKNOWN"),
		("PARANOID", "hnstatus: PARANOID"),
		("hnstatus: noforward", "hnstatus: noforward"),
		("ip: 128.", "ip: 128."),
		("ip: 128.0.0.0/16", "ip: 128.0.0.0/16"),
		("localip: 127.", "localip: 127."),
		("hostname: foobar.com", "hostname: foobar.com"),
		("claimedhn: .foobar.com", "claimedhn: .foobar.com"),
		("class: foobar", "class: foobar"),
		("re: ^abcdef", "re: '^abcdef'"),
		("claimedre: ppp", "claimedre: 'ppp'"),
		("re: '(abc|def)'", "re: '(abc|def)'"),
		("forwhn: foobar.com", "forwhn: foobar.com"),
		("dnsbl: sbl.spamhaus.org", "dnsbl: sbl.spamhaus.org"),
		("dnsbl: t.org/127.0.0.1", "dnsbl: t.org/127.0.0.1"),
		("answerson: 25", "answerson: 25"),
		("stallfor: 10s", "stallfor: 10s"),
		# The canonical duration for time-based duration is seconds.
		("stallfor: 1m", "stallfor: 60s"),
		('waited: 30s', 'waited: 30s'),
		("notseenfor: 1h", "notseenfor: 3600s"),
		('seenwithin: 10s', 'seenwithin: 10s'),
		('seenwithin: 1d', 'seenwithin: 86400s'),
		("firsttime", "firsttime"),
		# test the default cascades.
		("127.0.0.1", "ip: 127.0.0.1"),
		("127.0.", "ip: 127.0."),
		("localhost", "hostname: localhost"),
		("foobar.com", "hostname: foobar.com"),
		(".foobar.com", "hostname: .foobar.com"),
		# test no-argument things that expand.
		("UNKNOWN PARANOID", "hnstatus: UNKNOWN hnstatus: PARANOID"),
		# This tests IP address merging (sort of)
		("128.120. 128.100.", "ip: 128.120. ip: 128.100."),
		)
	def testParsedRepr(self):
		"Test the ability of all matchers to be parsed and to report themselves."
		for p, res in self.basicOps:
			tree = rdparse.parse(p, matchers.matchinfo)
			self.assertEqual(str(tree), res)
	def testStableRepr(self):
		"Test that reparsing the string version of a matcher gets the same result."
		for p, res in self.basicOps:
			s1 = str(rdparse.parse(p, matchers.matchinfo))
			s2 = str(rdparse.parse(s1, matchers.matchinfo))
			self.assertEqual(s1, s2, "%s did not stabilize" % (p,))

	# The first two elements of each tuple are the parse and the
	# parse readout. After that is a list of tuples of (IP address,
	# result status).
	knownParseEvals = (
		('localhost', 'hostname: localhost',
		 ('127.0.0.1', 1), ('127.0.0.2', 0)),
		('127.0.0.0/8 EXCEPT 127.0.0.1',
		 '(ip: 127.0.0.0/8) EXCEPT (ip: 127.0.0.1)',
		 ('127.0.0.1', 0), ('127.0.0.2', 1)),
		('127. EXCEPT KNOWN',
		 '(ip: 127.) EXCEPT (hnstatus: KNOWN)',
		 ('127.0.0.1', 0), ('127.0.0.2', 1), ('127.0.1.1', 0),
		 ('127.0.0.101', 1)),
		('UNKNOWN PARANOID', 'hnstatus: UNKNOWN hnstatus: PARANOID',
		 ('127.0.0.1', 0), ('127.0.0.2', 1), ('127.0.0.100', 1),
		 ('127.0.1.1', 0)),
		('ALL EXCEPT KNOWN', '(ALL) EXCEPT (hnstatus: KNOWN)',
		 ('127.0.0.1', 0), ('127.0.0.2', 1), ('127.0.0.100', 1)),
		('class: frotz AND KNOWN',
		 "(class: frotz) AND (hnstatus: KNOWN)",
		 ('127.0.0.1', 1), ('127.0.0.100', 0)),
		('127. 128. AND KNOWN',
		 '(ip: 127. ip: 128.) AND (hnstatus: KNOWN)',
		 ('127.0.0.1', 1), ('128.100.102.1', 0),
		 ('127.0.0.100', 0), ('128.100.102.51', 1)),
		('128.100. 142.150.0.0/15 AND NOT KNOWN',
		 '(ip: 128.100. ip: 142.150.0.0/15) AND (!(hnstatus: KNOWN))',
		 ('127.0.0.1', 0), ('128.100.102.51', 0),
		 ('142.151.1.1', 1), ('128.100.100.1', 1)),
		('128.100. 142.150.0.0/15 AND NOT KNOWN EXCEPT 128.100.100.1',
		 '((ip: 128.100. ip: 142.150.0.0/15) AND (!(hnstatus: KNOWN))) EXCEPT (ip: 128.100.100.1)',
		 ('128.100.102.51', 0), ('142.151.1.1', 1),
		 ('128.100.100.1', 0)),
		)
	def testParseEval(self):
		"Test that we properly parse and evaluate known strings."
		for testline in self.knownParseEvals:
			pstr = testline[0]
			pres = testline[1]
			root = rdparse.parse(pstr, matchers.matchinfo)
			self.assertEqual(str(root), pres)
			# The following re-parsing test is pure paranoia.
			# But I'm paranoid.
			r2 = rdparse.parse(pres, matchers.matchinfo)
			self.assertEqual(str(r2), pres, "%s did not reparse identical" % (pres,))
			for ip, res in testline[2:]:
				hi = makehi(rip = ip)
				# We manually add a class so we can use it.
				hi.addclass("frotz")
				self.assertEqual(root.eval(hi), res,
						 "%s failed on host %s" % (pstr, ip))

if __name__ == "__main__":
	unittest.main()
