#!/usr/bin/python2
#
# Deep hackery. Don't ask.
import sys
import rdparse, matchers, rules

def genNot(mre):
	return "rdparse.NotNode(%s)" % genMatchRule(mre.op)
def genAnd(mre):
	return "rdparse.AndNode(%s, %s)" % (genMatchRule(mre.left),
					    genMatchRule(mre.right))
def genExcept(mre):
	return "rdparse.ExceptNode(%s, %s)" % (genMatchRule(mre.left),
					       genMatchRule(mre.right))
def genOr(mre):
	l = [genMatchRule(x) for x in mre.ops]
	return "rdparse.OrNode((%s,))" % (", ".join(l))

def mName(mo):
	return "matchers.%s" % mo.__class__.__name__
def mStr(mo, name, val):
	cn = mName(mo)
	if val is None:
		return "%s(intern('%s'), None)" % (cn, name)
	else:
		return "%s(intern('%s'), intern('%s'))" % (cn, name, val)
def genIdentd(mo):
	return mStr(mo, 'identd:', mo.desid)
def genLocal(mo):
	return mStr(mo, 'local:', '%s@%s' % (mo.port, mo.host))
def genHNStat(mo):
	return mStr(mo, 'hnstatus:', mo.name)
# HACK ALERT.
def genIPM(mo):
	return "mergeList(%s)" % (", ".join(["%s('%s', '%s')" % (mName(mo), mo.cname, x) for x in mo.name]))
def genHNM(mo):
	if mo.hoste:
		return mStr(mo, mo.cname, mo.hoste)
	else:
		return mStr(mo, mo.cname, mo.host)
def genCMatch(mo):
	return mStr(mo, 'class:', mo.cls)
def genRE(mo):
	return mStr(mo, mo.cname, mo.rexp.pattern)
def genFor(mo):
	return mStr(mo, 'forwhn:', mo.forwhn)
def genDNSBL(mo):
	if mo.ipval:
		return mStr(mo, "dnsbl:", '%s/%s' % (mo.dnsbl[1:], mo.ipval))
	else:
		return mStr(mo, "dnsbl:", mo.dnsbl[1:])
def genTime(mo):
	return mStr(mo, mo.name, "%ss" % mo.secsold)

nodeDict = {
	rdparse.NotNode: genNot,
	rdparse.OrNode: genOr,
	rdparse.AndNode: genAnd,
	rdparse.ExceptNode: genExcept,
	# Many of the matchers are just lambdas.
	matchers.AllMatch: lambda x: "matchers.AllMatch('ALL', None)",
	matchers.IdentdMatch: genIdentd,
	matchers.LocalMatch: genLocal,
	matchers.HNStatusMatch: genHNStat,
	matchers.IPAddrMatch: genIPM, matchers.LIPAddrMatch: genIPM,
	matchers.HostnameMatch: genHNM, matchers.ClaimedHNMatch: genHNM,
	matchers.ClassMatch: genCMatch,
	matchers.REMatch: genRE, matchers.ClaimedREMatch: genRE,
	matchers.ForwhnMatch: genFor,
	matchers.DNSBlMatch: genDNSBL,
	matchers.AnswersOnMatch: lambda x: "%s(intern('answerson:'), '%s')" % (mName(x), x.port),
	matchers.WaitedMatch: genTime, matchers.StallMatch: genTime,
	matchers.LastSeenMatch: genTime, matchers.NotSeenForMatch: genTime,
	matchers.FirstTimeMatch: lambda x: "%s(intern('firsttime'), None)" % mName(x),
	}
def genMatchRule(mre):
	if mre.__class__ not in nodeDict:
		print "PANIC: NODE TYPE NOT KNOWN"
		return
	return nodeDict[mre.__class__](mre)

def genRule(rule):
	print "rule = rules.Rule(%d)" % (rule.lineno)
	print "rule.clsname = '%s'" % (rule.clsname)
	print "rule.nonterminal = %d" % (rule.nonterminal)
	print "rule.always = %d" % (rule.always)
	if rule.label is not None:
		print "rule.label = intern('%s')" % (rule.label)
	# Now generate the matching rule
	print "rule.matcher = ", genMatchRule(rule.matcher)
	print "rroot.addrule(rule)"

mergeUpStr = """
def mergeList(*lst):
	lst = list(lst)
	olst = []
	last = None
	while lst:
		n = lst.pop(0)
		if last is not None and last.merge(n):
			continue
		elif last:
			last.finalize()
			last = None
		if hasattr(n, 'merge'):
			last = n
		olst.append(n)
	if last:
		last.finalize()
	return olst
"""
def genOut(ruleroot):
	print "import rules, rdparse, matchers"
	print mergeUpStr
	print "rroot = rules.RulesList()"
	for r in ruleroot.rules:
		genRule(r)

def process(args):
	for a in args:
		genOut(rules.parsefile(a))
if __name__ == "__main__":
	process(sys.argv[1:])
