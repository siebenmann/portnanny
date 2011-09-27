#
# Test the PID/IP/class connection tracking code.

import conntrack
import unittest

class ConnBasics(unittest.TestCase):
	def _up(self, pid):
		conntrack.up(pid, '127.0.0.1', ('ALL',))
	def _start(self, pid):
		conntrack._clearmaps()
		self._up(pid)
	def _getclasses(self):
		c = conntrack.activeclasses()
		c.sort()
		return c
	def _getips(self):
		i = conntrack.activeips()
		i.sort()
		return i

	def testEmptyCount(self):
		"Test that we can get a zero count for values not in the system"
		conntrack._clearmaps()
		self.assertEqual(conntrack.ipcount("127.100.100.0"), 0)
		self.assertEqual(conntrack.classcount("FOOBAR"), 0)

	def testInsert(self):
		"""If we insert, we should get expected results."""
		self._start(1)
		self.assertEqual(conntrack.ipcount('127.0.0.1'), 1)
		self.assertEqual(conntrack.classcount('ALL'), 1)
		
	def testInsertRemove(self):
		"""If we insert then remove, the result should be null."""
		self._start(1)
		conntrack.down(1)
		self.assertEqual(conntrack.ipcount('127.0.0.1'), 0)
		self.assertEqual(conntrack.classcount('ALL'), 0)

	def testDupInsert(self):
		"""Inserting the same PID twice fails."""
		self._start(1)
		self.assertRaises(conntrack.DuplicatePid, conntrack.up,
				  1, '127.0.0.1', ('ALL',))
	def testRemoveMissing(self):
		"Removing a nonexistent PID succeeds."
		conntrack._clearmaps()
		conntrack.down(1)
		
	def testNoIpLeft(self):
		"""There should be no active IPs left listed after up/down."""
		self._start(1)
		conntrack.down(1)
		self.assertEqual(len(conntrack.activeips()), 0)
	def testNoClassesLeft(self):
		"""There should be no active classes left listed after up/down."""
		self._start(1)
		conntrack.down(1)
		self.assertEqual(len(conntrack.activeclasses()), 0)

	def testClassCount(self):
		"""The active class list should be maintained correctly."""
		self._start(1)
		self.assertEqual(conntrack.activeclasses(), ['ALL',])
		conntrack.up(2, '127.0.0.1', ('ALL', 'foo'))
		self.assertEqual(self._getclasses(), ['ALL', 'foo'])
		self._up(3)
		self.assertEqual(self._getclasses(), ['ALL', 'foo'])

	def testIpCount(self):
		"""The list of active IPs should be maintained correctly."""
		self._start(1)
		self.assertEqual(conntrack.activeips(), ['127.0.0.1',])
		conntrack.up(2, '127.0.0.3', ('ALL',))
		self.assertEqual(self._getips(), ['127.0.0.1', '127.0.0.3'])
		self._up(3)
		self.assertEqual(self._getips(), ['127.0.0.1', '127.0.0.3'])

	def testMultiIPConnects(self):
		"""We should correctly count how many times the same IP is connected, even with different classes."""
		self._start(1)
		conntrack.up(2, '127.0.0.1', ('foo',))
		self.assertEqual(conntrack.ipcount('127.0.0.1'), 2)
		conntrack.up(3, '127.0.0.1', ('bar',))
		self.assertEqual(conntrack.ipcount('127.0.0.1'), 3)
		conntrack.down(1)
		self.assertEqual(conntrack.ipcount('127.0.0.1'), 2)
		conntrack.down(3)
		self.assertEqual(conntrack.ipcount('127.0.0.1'), 1)

	def testMultiClassConnects(self):
		"""We should correctly count how many times a given class is active, even with differnet IPs."""
		self._start(1)
		conntrack.up(2, '127.0.0.2', ('ALL',))
		self.assertEqual(conntrack.classcount('ALL'), 2)
		conntrack.up(3, '127.0.0.3', ('ALL',))
		self.assertEqual(conntrack.classcount('ALL'), 3)
		conntrack.down(1)
		self.assertEqual(conntrack.classcount('ALL'), 2)
		conntrack.down(3)
		self.assertEqual(conntrack.classcount('ALL'), 1)

	def testManyClasses(self):
		"""We should correctly add to each class for multi-class connections."""
		conntrack._clearmaps()
		conntrack.up(1, '127.0.0.1', ('foo', 'bar'))
		self.assertEqual(conntrack.classcount('foo'), 1)
		self.assertEqual(conntrack.classcount('bar'), 1)
		conntrack.down(1)
		self.assertEqual(conntrack.classcount('foo'), 0)
		self.assertEqual(conntrack.classcount('bar'), 0)
		self.assertEqual(len(conntrack.activeclasses()), 0)
		
	def testDiffClassSameIp(self):
		"""For multiple connections from the same IP address with different classes, we should count correctly."""
		self._start(1)
		conntrack.up(2, '127.0.0.1', ('ALL', 'foo'))
		self.assertEqual(conntrack.classcount('ALL'), 2)
		self.assertEqual(conntrack.classcount('foo'), 1)
		conntrack.down(1)
		self.assertEqual(conntrack.classcount('ALL'), 1)
		self.assertEqual(conntrack.classcount('foo'), 1)

	def testHasPid(self):
		"Test that we accurately report whether we are tracking a PID."
		conntrack._clearmaps()
		self.assertEqual(conntrack.havepid(1), 0)
		self._up(1)
		self.assertEqual(conntrack.havepid(1), 1)
		self.assertEqual(conntrack.havepid(2), 0)
		self._up(2)
		self.assertEqual(conntrack.havepid(2), 1)
		conntrack.down(1)
		self.assertEqual(conntrack.havepid(2), 1)
		self.assertEqual(conntrack.havepid(1), 0)
		conntrack.down(2)
		self.assertEqual(conntrack.havepid(2), 0)

	def testGetPids(self):
		"Test that we correctly report what pids we have."
		conntrack._clearmaps()
		self.assertEqual(conntrack.getpids(), [])
		self._up(1)
		self.assertEqual(conntrack.getpids(), [1,])
		self._up(2)
		self._up(3)
		r = conntrack.getpids(); r.sort()
		self.assertEqual(r, [1, 2, 3])
	def testGetPid(self):
		"Test that we can get the conninfo for a particular PID and that it looks correct."
		conntrack._clearmaps()
		conntrack.up(1, "127.0.0.3", ("abc", "def", "GLOBAL"))
		conntrack.up(2, "127.0.0.4", ("test",))
		self.assertEqual(str(conntrack.getpid(1)), "<CI: PID 1, IP 127.0.0.3, classes: abc def GLOBAL>")
		self.assertEqual(str(conntrack.getpid(2)), "<CI: PID 2, IP 127.0.0.4, classes: test>")

if __name__ == "__main__":
	unittest.main()
