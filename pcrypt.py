"""
Pure-python implementations of the SHA2-based variants of crypt(3).

Pretty close to direct translation from the glibc crypt(3) source, pardon
the c-isms.
"""

from collections import namedtuple as _namedtuple
from random import SystemRandom as _SystemRandom
import argparse
import getpass
import hashlib
import re
import sys

_BASE64_CHARACTERS = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_SALT_RE = re.compile(r'\$(?P<algo>\d)\$(?:rounds=(?P<rounds>\d+)\$)?(?P<salt>.{1,16})')
_ROUNDS_DEFAULT = 5000 # As used by crypt(3)
_PY2 = sys.version_info < (3, 0, 0)
_sr = _SystemRandom()


class _Method(_namedtuple('_Method', 'name ident salt_chars total_size')):
    """Class representing a salt method per the Modular Crypt Format or the
    legacy 2-character crypt method."""

    def __repr__(self):
        return '<crypt.METHOD_{0}>'.format(self.name)


#  available salting/crypto methods
METHOD_SHA256 = _Method('SHA256', '5', 16, 63)
METHOD_SHA512 = _Method('SHA512', '6', 16, 106)

methods = (
    METHOD_SHA512,
    METHOD_SHA256,
)


def mksalt(method=None, rounds=None):
    """Generate a salt for the specified method.
    If not specified, the strongest available method will be used.
    """
    if method is None:
        method = methods[0]
    salt = ['${0}$'.format(method.ident) if method.ident else '']
    if rounds:
        salt.append('rounds={0:d}$'.format(rounds))
    salt.append(''.join(_sr.choice(_BASE64_CHARACTERS) for char in range(method.salt_chars)))
    return ''.join(salt)


def crypt(word, salt=None, rounds=_ROUNDS_DEFAULT):
    """Return a string representing the one-way hash of a password, with a salt
    prepended.
    If ``salt`` is not specified or is ``None``, the strongest
    available method will be selected and a salt generated.  Otherwise,
    ``salt`` may be one of the ``crypt.METHOD_*`` values, or a string as
    returned by ``crypt.mksalt()``.
    """
    if salt is None or isinstance(salt, _Method):
        salt = mksalt(salt, rounds)

    algo, rounds, salt = extract_components_from_salt(salt)
    if algo == 5:
        hashfunc = hashlib.sha256
    elif algo == 6:
        hashfunc = hashlib.sha512
    else:
        raise ValueError('Unsupported algorithm, must be either 5 (sha256) or 6 (sha512)')

    return sha2_crypt(word, salt, hashfunc, rounds)


def byte2int(value):
    if _PY2:
        return ord(value)
    else:
        return value


def int2byte(value):
    if _PY2:
        return chr(value)
    else:
        return value


def extract_components_from_salt(salt):
    salt_match = _SALT_RE.match(salt)
    if salt_match:
        algo, rounds, salt = salt_match.groups(_ROUNDS_DEFAULT)
        algo = int(algo)
        rounds = int(rounds)
    else:
        algo = 6
        rounds = _ROUNDS_DEFAULT
    return _namedtuple('Salt', 'algo rounds salt')(algo, rounds, salt)


def sha2_crypt(key, salt, hashfunc, rounds=_ROUNDS_DEFAULT):
    """
    This algorithm is insane. History can be found at
    https://en.wikipedia.org/wiki/Crypt_%28C%29
    """
    key = key.encode('utf-8')
    h = hashfunc()
    alt_h = hashfunc()
    digest_size = h.digest_size
    h.update(key)
    h.update(salt.encode('utf-8'))
    key_len = len(key)

    alt_h.update(key)
    alt_h.update(salt.encode('utf-8'))
    alt_h.update(key)
    alt_result = alt_h.digest()

    cnt = key_len
    while cnt > digest_size:
        h.update(alt_result)
        cnt -= digest_size

    h.update(alt_result[:cnt])

    # Take the binary representation of the length of the key and for every
    # 1 add the alternate sum, for every 0 the key.
    cnt = key_len
    while cnt > 0:
        if cnt & 1 == 0:
            h.update(key)
        else:
            h.update(alt_result)
        cnt >>= 1

    alt_result = h.digest()

    h = hashfunc()

    for i in range(key_len):
        h.update(key)

    temp_result = h.digest()

    cnt = key_len
    p_bytes = b''
    while cnt >= digest_size:
        p_bytes += temp_result
        cnt -= digest_size
    p_bytes += temp_result[:cnt]

    cnt = 0
    alt_h = hashfunc()
    while cnt < 16 + byte2int(alt_result[0]):
        alt_h.update(salt.encode('utf-8'))
        cnt += 1

    temp_result = alt_h.digest()

    cnt = len(salt)
    s_bytes = b''
    while cnt >= digest_size:
        s_bytes += temp_result
        cnt -= digest_size
    s_bytes += temp_result[:cnt]

    # Do the actual iterations
    for i in range(rounds):
        h = hashfunc()

        if i & 1 != 0:
            h.update(p_bytes)
        else:
            h.update(alt_result)

        if i % 3 != 0:
            h.update(s_bytes)

        if i % 7 != 0:
            h.update(p_bytes)

        if i & 1 != 0:
            h.update(alt_result)
        else:
            h.update(p_bytes)

        alt_result = h.digest()
    ret = ''
    if digest_size == 64:
        # SHA-512
        ret += b64_from_24bit(alt_result[0], alt_result[21], alt_result[42], 4)
        ret += b64_from_24bit(alt_result[22], alt_result[43], alt_result[1], 4)
        ret += b64_from_24bit(alt_result[44], alt_result[2], alt_result[23], 4)
        ret += b64_from_24bit(alt_result[3], alt_result[24], alt_result[45], 4)
        ret += b64_from_24bit(alt_result[25], alt_result[46], alt_result[4], 4)
        ret += b64_from_24bit(alt_result[47], alt_result[5], alt_result[26], 4)
        ret += b64_from_24bit(alt_result[6], alt_result[27], alt_result[48], 4)
        ret += b64_from_24bit(alt_result[28], alt_result[49], alt_result[7], 4)
        ret += b64_from_24bit(alt_result[50], alt_result[8], alt_result[29], 4)
        ret += b64_from_24bit(alt_result[9], alt_result[30], alt_result[51], 4)
        ret += b64_from_24bit(alt_result[31], alt_result[52], alt_result[10], 4)
        ret += b64_from_24bit(alt_result[53], alt_result[11], alt_result[32], 4)
        ret += b64_from_24bit(alt_result[12], alt_result[33], alt_result[54], 4)
        ret += b64_from_24bit(alt_result[34], alt_result[55], alt_result[13], 4)
        ret += b64_from_24bit(alt_result[56], alt_result[14], alt_result[35], 4)
        ret += b64_from_24bit(alt_result[15], alt_result[36], alt_result[57], 4)
        ret += b64_from_24bit(alt_result[37], alt_result[58], alt_result[16], 4)
        ret += b64_from_24bit(alt_result[59], alt_result[17], alt_result[38], 4)
        ret += b64_from_24bit(alt_result[18], alt_result[39], alt_result[60], 4)
        ret += b64_from_24bit(alt_result[40], alt_result[61], alt_result[19], 4)
        ret += b64_from_24bit(alt_result[62], alt_result[20], alt_result[41], 4)
        ret += b64_from_24bit(int2byte(0), int2byte(0), alt_result[63], 2)
    else:
        # SHA-256
        ret += b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4)
        ret += b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4)
        ret += b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4)
        ret += b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4)
        ret += b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4)
        ret += b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4)
        ret += b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4)
        ret += b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4)
        ret += b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4)
        ret += b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4)
        ret += b64_from_24bit(int2byte(0), alt_result[31], alt_result[30], 3)

    algo = 6 if digest_size == 64 else 5
    if rounds == _ROUNDS_DEFAULT:
        return '${0}${1}${2}'.format(algo, salt, ret)
    else:
        return '${0}$rounds={1}${2}${3}'.format(algo, rounds, salt, ret)


def b64_from_24bit(b2, b1, b0, n):
    b2 = byte2int(b2)
    b1 = byte2int(b1)
    b0 = byte2int(b0)
    index = b2 << 16 | b1 << 8 | b0
    ret = []
    for i in range(n):
        ret.append(_BASE64_CHARACTERS[index & 0x3f])
        index >>= 6
    return ''.join(ret)


def cli(argv=None):
    parser = argparse.ArgumentParser(description='Compute a password hash for '
        'SHA256/SHA512 in crypt(3)-compatible format. Password will be prompted for.')
    parser.add_argument('-r', '--rounds', default=_ROUNDS_DEFAULT, type=int,
        help='How many rounds of hashing to perform. More rounds are slower, making'
        ' it harder to reverse a hash through brute force. Default: %(default)s')
    parser.add_argument('-a', '--algo', choices=('sha256', 'sha512'), default='sha512',
        help='Which algorithm to use. Default: %(default)s')

    args = parser.parse_args(argv)

    if not 1000 < args.rounds < 999999999:
        # limits fetched from crypt(3) source
        print('Rounds must be between 1000 and 999999999.')
        sys.exit(1)

    password = getpass.getpass()
    method = METHOD_SHA256 if args.algo == 'sha256' else METHOD_SHA512
    print(crypt(password, method, rounds=args.rounds))
