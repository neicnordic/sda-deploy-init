## Testing script

### Version 1

Testing script is used to replicate upload and submission functionalities from an end user.
If you are running the script after using the "Somewhat Easy" deployment using the `deploy.py` script,
use the same password provided for the CEGA Users RSA key.
your own in the `Makefile`. Also `MAIN_REPO=~/LocalEGA` should reflect the path do the LocalEGA project.

The actual test:
```
pip install -r ../auto/requirements.txt
make upload
make submit
```

Other option: `make clean` to remove generate files.

### Version 2

Python version of the script to be used in those scenarios where `sftp` is not restricted.
Can be used with `docker pull blankdots/docker-browsepy:ftp` image.

```
python sftp input.file
```

Other options available:
```console
╰─$ python sftp.py --help
usage: sftp.py [-h] [--u U] [--uk UK] [--pk PK] [--inbox INBOX]
               [--inbox-port INBOX_PORT] [--s3 S3] [--cm CM]
               [--cm-port CM_PORT]
               input

Encrypting, uploading to inbox and sending message to CEGA.

positional arguments:
  input                 Input file to be encrypted.

optional arguments:
  -h, --help            show this help message and exit
  --u U                 Username to identify the elixir.
  --uk UK               User secret private RSA key.
  --pk PK               Public key file to encrypt file.
  --inbox INBOX         Inbox address, or service name
  --inbox-port INBOX_PORT
                        Inbox address, or service name
  --s3 S3               S3 address, or service name
  --cm CM               CEGA MQ broker IP/name address
  --cm-port CM_PORT     Inbox address, or service name
```
