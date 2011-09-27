#
# Our basic lexer.
# The lexer takes a string and tokenizes it, returning a list of the
# resulting tokens. Each token is a tuple; the first element is the
# type (one of 'W', 'T', or '') and the second element is the value.
#
# The '' token is the end of line token; it is always the last
# element of the list and appears nowhere else.
# A 'W' token is a word (an operand). A 'T' token is an operator
# (sometimes called a token, yes this is confusing).
#
# The operators are AND, NOT, EXCEPT, !, &&, (, and ).
#
# Tokens are separated from each other by unquoted whitespace or by the
# occurrence of the (unquoted) !, &, (, and ) operators. The latter
# means that "(a&&b)" tokenizes to T-(, W-a, T-&&, W-b, T-), EOL.
#
# Things, including whitespace, are quoted by putting them in pairs of
# single quotes ('). Within a quoted object, a single quote is quoted
# by another single quote. Quoting an operator turns it into a word.
# Quoting is *not* a tokenization boundary. Thus:
#	'&&'	->	W-"&&"		(*not* T-"&&"; quoting && makes it
#					 a non-operator.)
#	'a&&b'	->	W-"a&&b"
#	a'b c'	->	W-"a b c"
#	'ab'c	->	W-"abc"
#	'a''b'	->	W-"a'b"	
# (where the author hopes the notation is obvious)

import re

class BadInput(Exception):
	pass

# Some manifest semi-constants.
EOF = ('', '')
def W(s):
	return ('W', s)
def T(s):
	return ('T', s)

# This regexp skips to the next tokenizer breakpoint.
# Note that all of the single-character breakpoints are in one
# character class blob.
breakre = re.compile(r"(?:\s|&&|[()!'])")
# Note that breaktok includes the word tokens that do not break words
# on their own, and breakre includes the single quote, which doesn't
# either.
#breaktok = ('AND', 'NOT', 'EXCEPT', '&&', '(', ')', '!')
# Using a regexp is faster than the old way of checking each entry
# in breaktok as 'string.startswith(...)'.
breaktokre = re.compile("(?:[()!]|&&|(?:AND|NOT|EXCEPT)(?=\s|$))")

# We are handed a string that starts with a quote. We return the token
# and the remaining string to parse.
def parsequote(s):
	accum = ''
	while s:
		# Skip initial quote
		s = s[1:]
		# Find the closing quote
		pos = s.find("'")
		# No closing quote? Die.
		if pos < 0:
			raise BadInput, "Unterminated quote"
		accum += s[:pos]
		# We count the closing quote in the length
		# Is this a quoted quote or the actual end of the quote?
		if s[pos:].startswith("''"):
			accum += "'"
			s = s[pos+1:]
		else:
			# We have reached the end of the quote.
			return (W(accum), s[pos+1:])
	# This happens in, eg ''', where we hit EOF after handling
	# the quoted quote.
	raise BadInput, "Unterminated quote"

# The complication for ordinary words is that they may have embedded
# quoted sections, that do not break the word. (Life would be easier
# if quoted sections did break the words, but this is better semantics.)
# MAGIC TRICK: this also handles quoted words, because we need to be
# able to properly turn 'a'b into ab. In this case we will find the
# quote as the first thing in the string and do the right thing.
def parseword(s):
	accum = ''
	while s:
		r = breakre.search(s)
		# Did we find a quote in the middle, or not?
		if not r or s[r.start(0)] != "'":
			break
		# Now life gets complicated, because we have an internal
		# quoted string.
		accum += s[:r.start(0)]
		token, s = parsequote(s[r.start(0):])
		accum += token[1]
	# if r did not match, we've reached EOF.
	if not r:
		return (W(accum + s), '')
	else:
		return (W(accum + s[:r.start(0)]), s[r.start(0):])

def tokenize(s):
	res = []
	s = s.lstrip()
	while s:
		m = breaktokre.match(s)
		if m:
			token = T(m.group(0))
			s = s[len(token[1]):]
		else:
			token, s = parseword(s)
		# Add the generated token.
		res.append(token)
		# Trim the remaining string down.
		s = s.lstrip()

	res.append(EOF)
	return res
