#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(
    name='logstat',
    version='0.0.1',
    author='Martin Mágr',
    author_email='martin.magr@gmail.com',
    description='Simple syslog stats parser',
    install_requires=[
        'click',
    ],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'logstat = logstat.logstat:main',
        ]
    }
)
