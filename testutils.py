# We use the following in so many places we might put it in one.
import hinfo

def makehi(rip = '1.1.1.1', rport = 200,
	   lip = '0.0.0.0', lport = 100):
	return hinfo.frompairs((lip, lport), (rip, rport))

class ReadlineError:
	def __init__(self, lines = []):
		self.lines = lines
	def readline(self):
		if len(self.lines) > 0:
			return self.lines.pop(0)
		raise IOError, "this is a test error"
