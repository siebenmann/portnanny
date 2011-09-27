#
# Parse a rule using a (hopefully) simple recursive descend parser.
# It's given a string (which it lexes through lexr.py) and an object
# with information about the terminals, and returns a root object that
# has a eval() method.
#
# The operators we support are, in precedence (high to low):
#	!/NOT and ( ... ), 'implicit OR', AND, EXCEPT
# Operator parsing is left to right, so 'a EXCEPT b EXCEPT c' is
# '(a) EXCEPT ((b) EXCEPT (c))'.
# The operands are matcher invocations, which have three forms:
#	MATCHER: ARGUMENT
#	MATCHER
#	ARGUMENT
# In the last case, a series of default matchers is tried in order; the
# first one that likes the 
#
# The TermInfo object is expect to have three variables:
#	terminals	A dictionary; the keys are the names of matchers
#			(with the ':' included for those that take an
#			argument) and the value is a function to call
#			that will return an appropriate matcher object.
#			Usually the function is a class (thus calling it
#			naturally creates the objects).
#			The functions are called with two arguments, the
#			matcher name and the argument (the argument is
#			None when the matcher takes no arguments).
#	error		The error thrown by matcher functions when they
#			do not like their arguments.
#	defterminals	The list of default matcher names to try for
#			solo arguments.
#
import lexr

# These values are constants.
EXCEPTNODE = (lexr.T("EXCEPT"),)
ANDNODE = (lexr.T("AND"), lexr.T("&&"))
NOTNODE = (lexr.T("!"), lexr.T("NOT"))
OBRACKET = lexr.T("(")
CBRACKET = lexr.T(")")

# Thrown on exception
class ParseError(Exception):
	pass

# Each operator, including implicit or, generates a node that will eval
# itself to decide on true or false. It will also print out its canonical
# form.
class NotNode:
	def __init__(self, op):
		self.op = op
	def __str__(self):
		return '!(%s)' % (str(self.op),)
	def eval(self, data):
		return not self.op.eval(data)
class OrNode:
	def __init__(self, lst):
		self.ops = lst
	def __str__(self):
		return "%s" % (" ".join(map(str, self.ops)))
	def eval(self, data):
		for e in self.ops:
			if e.eval(data):
				return 1
		return 0
class AndNode:
	def __init__(self, left, right):
		self.left = left
		self.right = right
	def __str__(self):
		return "(%s) AND (%s)" % (str(self.left), str(self.right))
	def eval(self, data):
		return self.left.eval(data) and self.right.eval(data)
class ExceptNode:
	def __init__(self, left, right):
		self.left = left
		self.right = right
	def __str__(self):
		return "(%s) EXCEPT (%s)" % (str(self.left), str(self.right))
	def eval(self, data):
		return self.left.eval(data) and not self.right.eval(data)

# Pretty representation of a token tuple.
def pretty(token):
	if token[0] == '':
		return 'EOL'
	else:
		return token[1]

# We use a class for this to capture the lexer list and the information
# about the terminals.
class Parse:
	def __init__(self, lexlst, terminfo):
		self.lex = lexlst
		self.terms = terminfo

	# These are assistants for terml.
	def parsenot(self):
		# Always called with 
		self.lex.pop(0)
		res = self.parseterm()
		if not res:
			raise ParseError, "expecting term, got %s" % (pretty(self.lex[0]),)
		# Our finalization protocol is that any bare term object will
		# have .finalize() called on it (if such a routine exists).
		# Normally they get finalized in orlist processing, but not
		# calls parseterm() directly and so must finalize itself
		# when necessary.
		if hasattr(res, "finalize"):
			try:
				res.finalize()
			except self.terms.error, e:
				raise ParseError, str(e)
		return NotNode(res)

	def parsebrackets(self):
		self.lex.pop(0)
		root = self.parseexcept()
		if self.lex[0] != CBRACKET:
			raise ParseError, "expecting closing ), got %s" % (pretty(self.lex[0]),)
		self.lex.pop(0)
		return root

	# Terminal node:
	# terml -> ! terml 
	#	   ( except )
	#	   TERMINAL: VALUE
	#	   TERMINAL-OR-VALUE
	def parseterm(self):
		if self.lex[0] in NOTNODE:
			return self.parsenot()
		elif self.lex[0] == OBRACKET:
			return self.parsebrackets()
		elif self.lex[0][0] != "W":
			# If it is not a word but a token (or EOF), we don't
			# handle it and we punt.
			return None
		term = self.lex.pop(0)[1]

		# Now we need to distinguish TERMINAL: VALUE from the others.
		# Terminals with values end with :; everything else doesn't.
		if term[-1] == ':':
			if self.lex[0][0] != 'W':
				raise ParseError, "expected argument for %s, got %s" % (term, pretty(self.lex[0]))
			val = self.lex.pop(0)[1]
			# We check explicitly for has_key, instead of just
			# trying and catching KeyError, so that we can tell
			# our KeyErrors from any KeyErrors the function we
			# call might generate. *Those* KeyErrors we want
			# to cause explosions.
			if term not in self.terms.terminals:
				raise ParseError, "no handler called "+term
			try:
				return self.terms.terminals[term](term, val)
			except self.terms.error, e:
				raise ParseError, "handler does not like %s %s: %s" % (term, val, str(e))

		# This is either a bare terminal or a value that needs the
		# tender loving attention of the default handlers.
		if term in self.terms.terminals:
			try:
				return self.terms.terminals[term](term, None)
			except self.terms.error, e:
				raise ParseError, "no-value handler %s refused us: %s" % (term, str(e))
		else:
			# There's no terminal by that name, so try to generate
			# a default value.
			if not self.terms.defaultterm:
				raise ParseError, "no handler called "+term
			try:
				return self.terms.defaultterm(term)
			except self.terms.error, e:
				raise ParseError, "no default for %s: %s" % (term, str(e))

	# orl -> terml orl
	# Note that we cheat by not recursing.
	def parseorlist(self):
		# pychecker is WRONG about 'last has no merge attribute'.
		# for some reason the thing requires 'no-constCond' too
		# in order to SHUT UP.
		__pychecker__ = "no-constCond no-objattrs"
		lst = []
		last = None
		while 1:
			r = self.parseterm()
			if not r:
				break
			# HACK: See if the elements are mergeable. If they
			# are, just discard the new one and go on. The merge
			# protocol is that there is a 'merge' function and it
			# returns true.
			if last is not None and last.merge(r):
				continue
			elif last:
				try:
					last.finalize()
				except self.terms.error, e:
					raise ParseError, str(e)
				last = None
			# last does not get set unless it has signs of
			# the protocol.
			if hasattr(r, 'merge'):
				last = r
			lst.append(r)
		if not lst:
			raise ParseError, "empty OR list"
		# We may need a lingering finalization.
		if last:
			try:
				last.finalize()
			except self.terms.error, e:
				raise ParseError, str(e)
		# Special bonus case to avoid making pointless order-1
		# orl nodes.
		if len(lst) == 1:
			return lst[0]
		else:
			return OrNode(lst)

	# andl -> orl [AND andl]
	def parseand(self):
		left = self.parseorlist()
		if self.lex[0] not in ANDNODE:
			return left
		if not left:
			raise ParseError, "empty left AND clause"
		self.lex.pop(0)
		if self.lex[0] == lexr.EOF:
			raise ParseError, "empty right AND clause"
		return AndNode(left, self.parseand())

	# exceptl -> andl [EXCEPT exceptl]
	def parseexcept(self):
		left = self.parseand()
		if self.lex[0] not in EXCEPTNODE:
			return left
		if not left:
			raise ParseError, "empty left EXCEPT clause"
		self.lex.pop(0)
		if self.lex[0] == lexr.EOF:
			raise ParseError, "empty right EXCEPT clause"
		return ExceptNode(left, self.parseexcept())

	# parsing starts at EXCEPT, demands an EOF at the end, and insists
	# that we have something to start with.
	def parse(self):
		if self.lex[0] == lexr.EOF:
			raise ParseError, "Nothing to parse"
		root = self.parseexcept()
		if self.lex[0] != lexr.EOF:
			raise ParseError, "expected EOL, got token %s" % (self.lex[0][1],)
		return root

# To parse, we generate a parse object to stash data and call it.
def parse(s, terminfo):
	try:
		lexlst = lexr.tokenize(s)
	except lexr.BadInput, e:
		raise ParseError, e
	P = Parse(lexlst, terminfo)
	return P.parse()
