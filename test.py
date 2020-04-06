import os
from crypt4gh.lib import encrypt
from crypt4gh.keys import get_private_key, get_public_key


def encrypt_file(file_path, recipient_pubkey, private_key, passphrase):
    """Encrypt file."""
    filename, _ = os.path.splitext(file_path)
    output_file = os.path.expanduser(f'{filename}.c4ga')
    # list of (method, privkey, recipient_pubkey=None)
    # method supported is 0 https://github.com/EGA-archive/crypt4gh/blob/v1.0/crypt4gh/header.py#L261

    def cb():
        return passphrase

    pubkey = get_public_key(recipient_pubkey)
    seckey = get_private_key(private_key, cb)
    keys = [(0, seckey, pubkey)]
    infile = open(file_path, 'rb')
    try:
        encrypt(keys, infile, open(f'{filename}.c4ga', 'wb'), offset=0, span=None)
        print(f'File {filename}.c4ga is the encrypted file.')
    except Exception as e:
        print(f'Something went wrong {e}')
        raise e
    return output_file


encrypt_file('config/trace.yml', 'config/ega_key.c4gh.pub', 'config/ega_key.c4gh.sec', 'GtZK6xRx7oMwXyyraFnqcyqeZmpxRWoI')
