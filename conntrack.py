#
# Track active connections.
# Active connections are started with PID / IP / Classes, and are ended
# with PID. We can query for how many connections currently exist for a
# given IP address or class.

class DuplicatePid(Exception):
	pass
#class NonexistantPid(Exception):
#	pass

class ConnInfo:
	def __init__(self, pid, ip, classes):
		self.pid = pid
		self.ip = ip
		self.classes = classes
	def __str__(self):
		return "<CI: PID %d, IP %s, classes: %s>" % \
		       (self.pid, self.ip, " ".join(self.classes))

pidmap = {}
clsmap = {}
ipmap = {}

def _clearmaps():
	for k in pidmap.keys():
		del pidmap[k]
	for k in clsmap.keys():
		del clsmap[k]
	for k in ipmap.keys():
		del ipmap[k]

def _addip(pid, ip):
	if not ipmap.has_key(ip):
		ipmap[ip] = {}
	ipmap[ip][pid] = None
def _addclass(pid, cls):
	if not clsmap.has_key(cls):
		clsmap[cls] = {}
	clsmap[cls][pid] = None

def _delip(pid, ip):
	del ipmap[ip][pid]
	if len(ipmap[ip]) == 0:
		del ipmap[ip]
def _delclass(pid, cls):
	del clsmap[cls][pid]
	if len(clsmap[cls]) == 0:
		del clsmap[cls]

def up(pid, ip, classes):
	if pidmap.has_key(pid):
		raise DuplicatePid, "duplicate pid %d" % (pid,)
	c = ConnInfo(pid, ip, classes)
	pidmap[pid] = c
	_addip(pid, ip)
	for c in classes:
		_addclass(pid, c)

def down(pid):
	if not pidmap.has_key(pid):
		return
	c = pidmap[pid]
	del pidmap[pid]
	_delip(pid, c.ip)
	for c in c.classes:
		_delclass(pid, c)

def ipcount(ip):
	if not ipmap.has_key(ip):
		return 0
	return len(ipmap[ip])
def classcount(cls):
	if not clsmap.has_key(cls):
		return 0
	return len(clsmap[cls])

def activeips():
	return ipmap.keys()
def activeclasses():
	return clsmap.keys()

def havepid(pid):
	return pidmap.has_key(pid)
def getpids():
	return pidmap.keys()
def getpid(pid):
	return pidmap[pid]
