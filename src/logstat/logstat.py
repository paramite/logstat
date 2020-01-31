#!/usr/bin/env python

import click
import datetime
import itertools
import logging
import os
import re
import sys
import time
import multiprocessing


class LogStatException(Exception):
    """Base exception for the application."""


class ParsingException(LogStatException):
    """Used to signal isuues during log records parsing."""


LOG = logging.getLogger('logmon')
RFC3164_FMT = re.compile(
    '\<(?P<PRI>[\d]{1,3})\>'
    '(?P<TIMESTAMP>[JFMASOND][aepuco][nbrylgptvc] [1-9 ][0-9] '
    '[0-9]{2}:[0-9]{2}:[0-9]{2}) '
    '(?P<HOSTNAME>[\w\.\-:]+) '
    '(?P<MSG>.+)\n'
)
OUTPUT_FMT = """{pad}{name}{pad}
 - average length of message: {avg_len}
 - number of emergency and alert messages: {alerts}
 - oldest message: {oldest}
 - newest message: {newest}
"""


def reader(log_path, worker_count, line_queue):
    """Reads file by lines."""
    with open(log_path) as logfile:
        for line in itertools.chain(logfile, (None,)*worker_count):
            line_queue.put(line)


def guess_severity(pri):
    """Tries to figure out severity from priority"""
    # pri = fac * 8 + sev; so: pri - x<0-7> % 8 -> 0 == x is severity
    pri = int(pri)
    if pri == 0:
        return pri
    for i in range(0, 8):
        if not ((int(pri) - i) % 8):
            return i
    else:
        return int(pri)


def worker(line_queue, data_queue):
    """Splits lines to tuple of strings and process the data to collected
    statistics.
    """
    while True:
        line = line_queue.get()
        if line == None:
            data_queue.put(None)
            return

        match = RFC3164_FMT.match(line)
        if not match:
            data_queue.put(('warning',
                            'Skipped log record not matching standard '
                            f'format: {line.strip()}'))
            continue
        dt = datetime.datetime.strptime(
            "%s %s" % (datetime.datetime.now().year, match.group('TIMESTAMP')),
            '%Y %b %d %H:%M:%S')
        data_queue.put(('record', guess_severity(match.group('PRI')), dt,
                        match.group('HOSTNAME'), len(match.group('MSG'))))


def update_stats(stats, record):
    """Updates stats with data from given record."""
    def _update(key):
        st = stats.setdefault(key,
                              {'name': key, 'num': 0, 'lines': 0, 'alerts': 0,
                               'oldest': record[2], 'newest': record[2],
                               'pad': '-' * int((80 - len(key)) / 2)})
        st['num'] += 1
        st['lines'] += record[4]
        st['alerts'] += 1 if record[1] < 2 else 0
        if record[2] < st['oldest']:
            st['oldest'] = record[2]
        if record[2] > st['newest']:
            st['newest'] = record[2]

    _update('#global#')
    _update(record[3])


def print_stats(stats):
    """Pretty prints given stats"""
    for key, item in stats.items():
        item['avg_len'] = int(item['lines'] / item['num'])
        item['oldest'] = item['oldest'].ctime()
        item['newest'] = item['newest'].ctime()
        if key != "#global#":
            print(OUTPUT_FMT.format(**item))
        else:
            item['name'] = '-GLOBAL-'
    print(OUTPUT_FMT.format(**stats['#global#']))


@click.command()
@click.option('--debug', '-d', is_flag=True)
@click.option('--worker-count', '-w', type=int, default=2,
              help="Number of workers processing the data from readers")
@click.argument('log_path')
def main(log_path, worker_count, debug):
    """Processes syslog messages from a file and outputs some statistics."""
    line_queue = multiprocessing.Queue(worker_count)
    data_queue = multiprocessing.Queue()
    pool = [multiprocessing.Process(target=reader,
                                    args=(log_path, worker_count, line_queue))]
    stats = {}
    try:
        pool[0].start()
        for i in range(worker_count):
            pool.append(multiprocessing.Process(target=worker,
                                                args=(line_queue, data_queue)))
            pool[-1].start()

        finished = 0
        while finished != worker_count:
            record = data_queue.get()
            if record == None:
                finished += 1
                continue
            if record[0] != 'record':
                getattr(LOG, record[0])(record[1])
                if record[0] in ('error', 'critical'):
                    raise ParsingException(record[1])
                else:
                    continue
            update_stats(stats, record)
        print_stats(stats)
    finally:
        if finished != worker_count:
            for proc in pool:
                try:
                    proc.terminate()
                except Exception:
                    pass
        line_queue.close()
        data_queue.close()


if __name__ == '__main__':
    main()
