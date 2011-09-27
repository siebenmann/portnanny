#
# Our loader of and evaluator of rules.
#
# Rules are (rfc822-style continued) lines of the form
#	CLASS[/annotation[/annotation]...]:	EXPRESSION
# The expression is evaluated through rdparse using matchers.
# The annotations can be 'nonterminal' (aka 'nt'), 'always',
# 'label=<label>'.
#
# Classifier rule matching operates by trying each rule in order (the
# order is that encountered in the file). Rule evaluation stops after
# the first rule not marked 'nonterminal' matches, with the exception
# that rules marked 'always' are always evaluated.
#
# All matching rules are returned in the order that they matched.
# If at least one rule has matched, a synthetic matching rule called
# 'GLOBAL' is added at the end of the match list.

import rdparse
import readcf
import matchers

class BadInput(Exception):
	pass

# Non-underscored variables are public interfaces.
class Rule(object):
	__slots__ = "lineno", "clsname", "nonterminal", "always", "label", "matcher"
	def __init__(self, lineno):
		self.lineno = lineno
		self.clsname = None
		self.nonterminal = 0
		self.always = 0
		self.label = None
		self.matcher = None
	def __str__(self):
		# If we have no matcher, we are an internal rule.
		if not self.matcher:
			return "<Rule: %s>" % (self.clsname)
		# Otherwise, report our reproduction.
		base = self.clsname
		if self.nonterminal:
			base += '/nt'
		if self.always:
			base += '/always'
		if self.label:
			base += '/label='+self.label
		return "%s: %s" % (base, str(self.matcher))

def setrulenotes(r, notes, rulestr):
	n = notes.split('/')
	for k in n:
		if k in ('nt', 'nonterminal'):
			r.nonterminal = 1
		elif k == 'always':
			r.always = 1
		elif k.startswith("label="):
			lname = k[len("label="):]
			if not lname:
				raise BadInput, "empty label on rule"
			if r.label and r.label != lname:
				raise BadInput, "multiple labels on rule"
			r.label = lname			
		elif k == "label":
			# like 'label=', but just uses the rule string.
			r.label = rulestr
		else:
			raise BadInput, "unrecognized rule note"

def parseline(line, lineno):
	r = Rule(lineno)
	n = line.split(None, 1)
	if len(n) < 2:
		raise BadInput, "too few elements in rule"
	if n[0][-1] != ':':
		raise BadInput, "class name does not end with a ':'"
	if n[0][0] == '/':
		raise BadInput, "class name section has no actual name"
	rcomp = n[0][:-1]
	# we rstrip for '/label', because this increases the odds of
	# sharing strings if this is a single-argument matcher (the
	# usual case for '/label'). Since whitespace is meaningless
	# at the end of rules, this is harmless.
	rulestr = n[1].rstrip()
	
	# Our major piece of work is parsing the name portion of the
	# rule. Parsing the rule itself is passed off to rdparse.
	pos = rcomp.find('/')
	# pos is either -1 or larger than zero.
	if pos == -1:
		rname = rcomp
	else:
		rname = rcomp[:pos]
		rnotes = rcomp[pos+1:]
		setrulenotes(r, rnotes, rulestr)
	# Set the final bit.
	r.clsname = rname
	try:
		r.matcher = rdparse.parse(rulestr, matchers.matchinfo)
	except rdparse.ParseError, e:
		raise BadInput, e
	return r

# All matches that match anything also append on to the match list a
# match against a virtual global rule called GLOBAL. This simplifies
# life downstream in the actions department.
def genfakerule(clsname):
	r = Rule(-1)
	r.clsname = clsname
	return r
globalrule = genfakerule("GLOBAL")

class RulesList:
	def __init__(self):
		self.rules = []
		self.havealways = 0
	def __len__(self):
		return len(self.rules)
	def __getitem__(self, key):
		return self.rules[key]
	# we could iterate ourselves for str, but we'll just do it directly
	# with map.
	def __str__(self):
		return "\n".join(map(str, self.rules)) + "\n"
	def addrule(self, rule):
		# Sleazy memory reduction hack.
		# If this rule and the last rule have the same name, we
		# make them actually use the same string object for that
		# name, rather than duplicating it.
		if len(self.rules) and self.rules[-1].clsname == rule.clsname:
			rule.clsname = self.rules[-1].clsname
		self.rules.append(rule)
		if rule.always:
			self.havealways = 1

	def getclassnames(self):
		cnd = {}
		for r in self.rules:
			cnd[r.clsname] = None
		return cnd.keys()

	# Rule evaluation deserves an essay.
	# Rules are evaluated in order. Rules marked '/always' are
	# always evaluated; otherwise, matching stops at the first
	# successful rule that is not marked nonterminal.
	# A given class is only successful once; after the first
	# successful match of the class, all further rules for it
	# are skipped.
	def eval(self, hi):
		matching = []
		matched = 0
		for r in self.rules:
			if (matched and not r.always) or \
			       (r.clsname in hi.classes):
				continue
			res = r.matcher.eval(hi)
			if res:
				matching.append(r)
				hi.addclass(r.clsname)
				if not r.nonterminal:
					matched = 1
					# break out early if we have no
					# 'always' matches; this can win
					# on early or middle matches.
					if not self.havealways:
						break
		# If we matched anything, we add 'GLOBAL' to the list.
		if len(matching) > 0:
			matching.append(globalrule)
		return matching

# Parse an entire file into a rules list, exploding on errors.
def fromfile(fp, fname):
	rules = RulesList()
	try:
		readcf.readcf(fp, fname, parseline, rules.addrule, BadInput)
	except BadInput:
		matchers.discardmemos()
		raise
	matchers.agememos()
	return rules

def parsefile(fname):
	try:
		fp = open(fname, "r")
	except EnvironmentError, e:
		raise BadInput, "cannot open %s: %s" % (fname, str(e))
	return fromfile(fp, fname)
