import crypt
import mock
import pcrypt
import re


def test_pcrypt():
    test_inputs = [
        ('password', '$5$salt'),
        ('password'*32, '$5$salt'),
        ('password', '$5$saltsalt'),
        ('password', '$5$rounds=10000$salt'),
        ('password'*32, '$5$saltsaltsaltsalt'),
        ('password', '$6$salt'),
        ('password'*32, '$6$salt'),
        ('password', '$6$saltsalt'),
        ('password', '$6$rounds=10000$salt'),
        ('password'*32, '$6$saltsaltsaltsalt'),
    ]
    for password, salt in test_inputs:
        pcrypt_output = pcrypt.crypt(password, salt)
        crypt_output = crypt.crypt(password, salt)
        assert pcrypt_output == crypt_output


def test_custom_rounds():
    output = pcrypt.crypt('password', rounds=50000)
    assert re.match(r'\$6\$rounds=50000\$.{16}\$.{86}', output) is not None


def test_custom_method_and_rounds():
    output = pcrypt.crypt('password', pcrypt.METHOD_SHA256, rounds=10000)
    assert re.match(r'\$5\$rounds=10000\$.{16}\$.{43}', output) is not None


def test_regressions():
    # hashes of 'password'
    known_sha512_hash = '$6$J0V3ugGx.vpdsbWV$.kLA30D9flQ4mffEoVVTqjrynKLstjWzucDvvx85nXA1Qrdwkey4DxlWhMwzCImvMbAcQckZtete8RERiSWqv.'
    assert pcrypt.crypt('password', known_sha512_hash) == known_sha512_hash
    known_sha256_hash = '$5$NaCl$8/OjNSQOAAHmmyQvNzSfdRoIATLniU/krvWPuKAZ1T1'
    assert pcrypt.crypt('password', known_sha256_hash)


def test_cli(capsys):
    args = ['-r', '10000', '-a', 'sha256']
    getpass_mock = mock.Mock(return_value='password')
    with mock.patch('sys.stdin.readline', getpass_mock):
        pcrypt.cli(args)
        output, err = capsys.readouterr()
        match = re.match(r'\$5\$rounds=10000\$.{16}\$.*\n', output)
        assert match is not None

if __name__ == '__main__':
    test_pcrypt()
