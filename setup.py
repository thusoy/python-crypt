#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import setup
import sys

install_requires = []

if sys.version_info < (2, 7, 0):
    install_requires.append('argparse')

setup(
    name='pcrypt',
    version='1.0.0',
    author='Tarjei Husøy',
    author_email='git@thusoy.com',
    url='https://github.com/thusoy/python-crypt',
    description="Pure-python implementation of the SHA2 crypt(3) functions",
    py_modules=['pcrypt'],
    install_requires=install_requires,
    extras_require={
        'test': ['mock', 'pytest'],
    },
    entry_points={
        'console_scripts': [
            'pcrypt = pcrypt:cli',
        ]
    },
    license='MIT',
    classifiers=[
        # 'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
        # 'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
