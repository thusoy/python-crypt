import crypt
import pcrypt

def test_pcrypt():
    test_inputs = [
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

if __name__ == '__main__':
    test_pcrypt()
