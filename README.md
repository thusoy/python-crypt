# python-crypt [![Build Status](https://travis-ci.org/thusoy/python-crypt.svg?branch=master)](https://travis-ci.org/thusoy/python-crypt)

Pure-python implementation of the crypt(3) SHA2 functions.

Useful for creating crypt-compatible hashes from non-*nixes (like Windows
and OS X), like when creating password hashes to initialize a *nix server
with.


## Install

    $ pip install pcrypt


## Usage

API is identical to the [built-in crypt](https://docs.python.org/3.5/library/crypt.html) module on *nix:

    import pcrypt, getpass

    print pcrypt.crypt(getpass('Enter password: '))

Without specifying salt manually the module will generate a new salt and use
the strongest hash function available.
