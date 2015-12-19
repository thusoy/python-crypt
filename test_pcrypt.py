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


def test_cli(capsys):
    args = ['-r', '10000', '-a', 'sha256']
    getpass_mock = mock.Mock(return_value='password')
    with mock.patch('getpass.getpass', getpass_mock):
        pcrypt.cli(args)
        output, err = capsys.readouterr()
        match = re.match(r'\$5\$rounds=10000\$.{16}\$.*\n', output)
        assert match is not None

if __name__ == '__main__':
    test_pcrypt()
