#
# The generic skeleton to read configuration files through contread,
# properly throwing errors with filenames and line numbers, and
# dispatching to line-parsing and line-parsed-successfully functions.
#
# We have no unittests for this because it is essentially a common
# subroutine of all of the configuration file readers and as such is
# tested through each of them.
import contread

def readcf(fp, fname, parseFunc, accumFunc, errObj):
	fp = contread.fromfile(fp)
	while 1:
		try:
			res = fp.readcontline_ex()
			if not res:
				break
			lineno, line = res
		except contread.StartingContinuedLine:
			raise errObj, "%s: first line is a continuation" % \
			      (fname,)
		except EnvironmentError, e:
			raise errObj, "IO error reading %s: %s" % \
			      (fname, str(e))
		if line[-1] == '\n':
			line = line[:-1]
		try:
			r = parseFunc(line, lineno)
			if accumFunc:
				accumFunc(r)
		except errObj, e:
			raise errObj, "error parsing %s line %d: %s" % \
			      (fname, lineno, str(e))
	# At the end, we're just, well, done.
