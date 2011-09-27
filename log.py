#
# Log messages for the rest of the program. (Okay, technically just for
# the main portnanny code; everyone else just throws exceptions.)
#

import sys
import syslog

# Our logging targets: currently any file (normally stderr) and syslog.
class StderrLog:
	def __init__(self, fp):
		self.fp = fp
	# We cannot call self.fp.close(), because that might close oh
	# stderr on us. Bad!
	def close(self):
		self.fp.flush()
		self.fp = None
	def log(self, lvl, msg):
		__pychecker__ = 'no-argsused'
		self.fp.write("%s: %s\n" % (progname, msg))
# Zap the nulls in a string
def zapnulls(s):
	if "\0" not in s:
		return s
	return "\\0".join(s.split("\0"))
class SyslogLog:
	def __init__(self, ident, facil):
		syslog.openlog(ident, syslog.LOG_PID, facil)
	def close(self):
		syslog.closelog()
	def log(self, lvl, msg):
		syslog.syslog(lvl, zapnulls(msg))

# We need somewhere to stick our global logging parameters, so it
# might as well be here. (We cannot stick it on the logger object
# itself, because we shuffle those around.)
debuglevel = 0
progname = "portnanny2"
logger = StderrLog(sys.stderr)

def setprogname(newname):
	global progname
	progname = newname
def setdebuglevel(lvl):
	global debuglevel
	debuglevel = lvl
def usestderr(fp = None):
	global logger
	if fp == None:
		fp = sys.stderr
	logger.close()
	logger = StderrLog(fp)
def usesyslog(facil = None):
	global logger
	if facil == None:
		facil = syslog.LOG_DAEMON
	logger.close()
	logger = SyslogLog(progname, facil)

# Actual message creation and stuff.
def die(msg):
	logger.log(syslog.LOG_ALERT, msg)
	sys.exit(1)
def warn(msg):
	logger.log(syslog.LOG_WARNING, msg)
def error(msg):
	logger.log(syslog.LOG_ERR, msg)
def report(msg):
	logger.log(syslog.LOG_INFO, msg)
def debug(lvl, msg):
	if debuglevel < lvl:
		return
	logger.log(syslog.LOG_DEBUG, msg)
