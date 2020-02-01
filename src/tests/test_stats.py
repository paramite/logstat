# /usr/bin/env python

import datetime
import unittest

from logstat import guess_severity, update_stats, worker


class MockQueue(object):
    def __init__(self, start=[]):
        self.queue = start

    def put(self, item):
        self.queue.append(item)

    def get(self):
        print(self.queue)
        return self.queue.pop(0)


class TestStats(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime.now()
        self.yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        self.record1 = ('record', 1, self.now, 'host1', 20)
        self.record2 = ('record', 4, self.yesterday, 'host2', 21)
        self.line_queue = MockQueue(start=[
            '<47>Sep 22 15:38:21 mymachine myproc% fatal error, terminating!\n',
            "<34>Jan 25 05:06:34 10.1.2.3 su: 'su root' failed for sprinkles on /dev/pts/8\n",
            '<13>Oct  7 10:09:00 unicorn sched# invalid operation\n',
            '<165>Aug  3 22:14:15 FEDC:BA98:7654:3210:FEDC:BA98:7654:3210 awesomeapp starting up version 3.0.1...\n',
            None
        ])
        self.data_queue = MockQueue()

    def test_severity_guessing(self):
        """The Priority value is calculated by first multiplying the Facility
        number by 8 and then adding the numerical value of the Severity. For
        example, a kernel message (Facility=0) with a Severity of Emergency
        (Severity=0) would have a Priority value of 0.  Also, a "local use 4"
        message (Facility=20) with a Severity of Notice (Severity=5) would
        have a Priority value of 165.
        """
        self.assertEquals(guess_severity(0), 0)
        self.assertEquals(guess_severity(165), 5)

    def test_stats_update(self):
        stats = {}
        update_stats(stats, self.record1)
        update_stats(stats, self.record2)
        self.assertDictEqual(stats, {
            '#global#': {
                'name': '#global#',
                'num': 2,
                'lines': 41,
                'alerts': 1,
                'oldest': self.yesterday,
                'newest': self.now,
                'pad': '-' * 36
            },
            'host1': {
                'name': 'host1',
                'num': 1,
                'lines': 20,
                'alerts': 1,
                'oldest': self.now,
                'newest': self.now,
                'pad': '-' * 37
            },
            'host2': {
                'name': 'host2',
                'num': 1,
                'lines': 21,
                'alerts': 0,
                'oldest': self.yesterday,
                'newest': self.yesterday,
                'pad': '-' * 37
            }
        })

    def test_worker(self):
        worker(self.line_queue, self.data_queue)
        yr = datetime.datetime.now().year
        self.assertListEqual(self.data_queue.queue, [
            ('record', 7, datetime.datetime(2020, 9, 22, 15, 38, 21), 'mymachine', 33),
            ('record', 2, datetime.datetime(2020, 1, 25, 5, 6, 34), '10.1.2.3', 48),
            ('record', 5, datetime.datetime(2020, 10, 7, 10, 9), 'unicorn', 24),
            ('record', 5, datetime.datetime(2020, 8, 3, 22, 14, 15),
             'FEDC:BA98:7654:3210:FEDC:BA98:7654:3210', 39),
            None
        ])


if __name__ == '__main__':
    unittest.main()
