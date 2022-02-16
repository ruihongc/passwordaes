import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def genf(salt, pw):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000003,
    )
    key = kdf.derive(pw)
    return AESGCM(key)

def _encrypt(nonce, data, salt, pw):
    f = genf(salt, pw)
    e = nonce + f.encrypt(nonce, data, b'') + salt
    assert f.decrypt(e[:12], e[12:-32], b'') == data # sanity check
    return e

def encrypt(data, pw):
    salt = os.urandom(32)
    nonce = os.urandom(12)
    return _encrypt(nonce, data, salt, pw)

def decrypt(data, pw):
    salt = data[-32:]
    f = genf(salt, pw)
    d = f.decrypt(data[:12], data[12:-32], b'')
    assert (data[:12] + f.encrypt(data[:12], d, b'') + salt) == data # sanity check
    return d

if len(sys.argv) < 4:
    print('Usage: python passwordaes.py mode input-file password [output-file]')
    exit()

data = open(sys.argv[2], 'rb').read()
pw = bytes(sys.argv[3], encoding='latin1')

if sys.argv[1] == 'e':
    print(encrypt(data, pw))
elif sys.argv[1] == 'ef':
    e = encrypt(data, pw)
    with open(sys.argv[2] if len(sys.argv) < 5 else sys.argv[4], 'wb') as of:
        of.write(e)
    print('Encrypted file successfully')
elif sys.argv[1] == 'd':
    print(decrypt(data, pw))
elif sys.argv[1] == 'df':
    d = decrypt(data, pw)
    with open(sys.argv[2] if len(sys.argv) < 5 else sys.argv[4], 'wb') as of:
        of.write(d)
    print('Decrypted file successfully')
else:
    print(f'Invalid mode {sys.argv[1]}, use either e for encrypt or d for decrypt to stdout, ef or df to output file or to overwrite input file if no output file is specified')
