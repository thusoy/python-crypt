# python-crypt [![Build Status](https://travis-ci.org/thusoy/python-crypt.svg?branch=master)](https://travis-ci.org/thusoy/python-crypt)

Pure-python implementation of the crypt(3) SHA2 functions.

Useful for creating crypt-compatible hashes from non-*nixes (like Windows
and OS X), like when creating password hashes to initialize a *nix server
with.


## Install

    $ pip install pcrypt


## Usage

API is identical to the [built-in crypt](https://docs.python.org/3.5/library/crypt.html) module on *nix:

    >>> import pcrypt, getpass
    >>> print(pcrypt.crypt(getpass.getpass()))
    $6$tyjS23QPnY6k37iD$7oM9nObOVQUQ<...>/x7VKbuiyqgT81

If you want to override the number of rounds used for hashing, you can specify the parameter `rounds` to crypt:

    >>> print(pcrypt.crypt(getpass.getpass(), rounds=50000))
    $6$rounds=50000$FEkeiFqoGiU6Bd3v$6jn8ZZ<...>uXKvs7XAbp.

The default number of rounds is 5000, same as for crypt(3).

To use SHA256 instead of the default SHA512:

    >>> print(pcrypt.crypt(getpass.getpass(), pcrypt.METHOD_SHA256))
    $5$Zcxyug8MUozUjGIQ$yqvzOQR<...>pnLMvpOhhmrOWfn5

If the second argument is given it must be either an existing salt string matching the
format `$<algo>$(rounds=<rounds>$)?<salt>($<hash>)?`, or one of `pcrypt.METHOD_SHA256`
or `pcrypt.METHOD_SHA512`.

Without specifying salt manually the module will generate a new salt and use
the strongest hash function available.

As a little extra nugget, there's also a handy CLI to quickly generate a hash:

    $ pcrypt -h
    usage: pcrypt [-h] [-r ROUNDS] [-a {sha256,sha512}] [-s]

    Compute a password hash for SHA256/SHA512 in crypt(3)-compatible format.
    Password will be prompted for.

    optional arguments:
      -h, --help            show this help message and exit
      -r ROUNDS, --rounds ROUNDS
                            How many rounds of hashing to perform. More rounds are
                            slower, making it harder to reverse a hash through
                            brute force. Default: 5000
      -a {sha256,sha512}, --algo {sha256,sha512}
                            Which algorithm to use. Default: sha512
      -s, --single-prompt   Don't ask to repeat the password

**NB**: You'd probably guess from this being a pure-python implementation of a compute-heavy operation, but I just have to say this explicitly: Do not use this for performance-critical applications! Performance is roughly five orders of magnitude slower than the plain C version.
