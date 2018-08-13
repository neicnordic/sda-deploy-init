import paramiko
import os
import pika
import secrets
from hashlib import md5
import json
import string
import uuid
import logging
from legacryptor.crypt4gh import encrypt
import pgpy
import argparse
from base64 import b64decode
from minio import Minio
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from time import sleep


config.load_kube_config()
api_core = client.CoreV1Api()


FORMAT = '[%(asctime)s][%(name)s][%(process)d %(processName)s][%(levelname)-8s] (L:%(lineno)s) %(funcName)s: %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def open_ssh_connection(hostname, user, key_path, key_pass='password', port=2222):
    """Open an ssh connection, test function."""
    try:
        client = paramiko.SSHClient()
        k = paramiko.RSAKey.from_private_key_file(key_path, password=key_pass)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, allow_agent=False, look_for_keys=False, port=port, timeout=0.3, username=user, pkey=k)
        LOG.info(f'ssh connected to {hostname}:{port} with {user}')
    except paramiko.BadHostKeyException as e:
        LOG.error(f'Something went wrong {e}')
        raise Exception('BadHostKeyException on ' + hostname)
    except paramiko.AuthenticationException as e:
        LOG.error(f'Something went wrong {e}')
        raise Exception('AuthenticationException on ' + hostname)
    except paramiko.SSHException as e:
        LOG.error(f'Something went wrong {e}')
        raise Exception('SSHException on ' + hostname)

    return client


def sftp_upload(hostname, user, file_path, key_path, key_pass='password', port=2222):
    """SFTP Client file upload."""
    try:
        k = paramiko.RSAKey.from_private_key_file(key_path, password=key_pass)
        transport = paramiko.Transport((hostname, port))
        transport.connect(username=user, pkey=k)
        LOG.info(f'sftp connected to {hostname}:{port} with {user}')
        sftp = paramiko.SFTPClient.from_transport(transport)
        filename, _ = os.path.splitext(file_path)
        sftp.put(file_path, f'{filename}.c4ga')
        LOG.info(f'file uploaded {filename}.c4ga')
    except Exception as e:
        LOG.error(f'Something went wrong {e}')
        raise e
    finally:
        LOG.debug('sftp done')
        transport.close()


def submit_cega(address, user, file_path, c4ga_md5, port=5672, file_md5=None):
    """Submit message to CEGA along with."""
    # Determine credentials
    mq_password = b64decode(read_secret('cega-connection').to_dict()['data']['address']).decode('utf-8')[12:44]
    mq_address = f'amqp://lega:{mq_password}@{address}:{port}/lega'
    stableID = ''.join(secrets.choice(string.digits) for i in range(16))
    message = {'user': user, 'filepath': file_path, 'stable_id': f'EGA_{stableID}'}
    if c4ga_md5:
        message['encrypted_integrity'] = {'checksum': c4ga_md5, 'algorithm': 'md5'}
    if file_md5:
        message['unencrypted_integrity'] = {'checksum': file_md5, 'algorithm': 'md5'}

    try:
        parameters = pika.URLParameters(mq_address)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.basic_publish(exchange='localega.v1', routing_key='files',
                              body=json.dumps(message),
                              properties=pika.BasicProperties(correlation_id=str(uuid.uuid4()),
                                                              content_type='application/json',
                                                              delivery_mode=2))

        connection.close()
        LOG.info('Message published to CentralEGA')
    except Exception as e:
        LOG.error(f'Something went wrong {e}')
        raise e


def encrypt_file(file_path, pubkey):
    """Encrypt file and extract its md5."""
    file_size = os.path.getsize(file_path)
    filename, _ = os.path.splitext(file_path)
    output_base = os.path.basename(filename)
    c4ga_md5 = None
    output_file = os.path.expanduser(f'{output_base}.c4ga')

    try:
        encrypt(pubkey, open(file_path, 'rb'), file_size, open(f'{output_base}.c4ga', 'wb'))
        with open(output_file, 'rb') as read_file:
            c4ga_md5 = md5(read_file.read()).hexdigest()
        LOG.info(f'File {output_base}.c4ga is the encrypted file with md5: {c4ga_md5}.')
    except Exception as e:
        LOG.error(f'Something went wrong {e}')
        raise e
    return (output_file, c4ga_md5)


def read_secret(name):
    """Read secret."""
    api_response = ''
    try:
        api_response = api_core.read_namespaced_secret(name, "testing", exact=True, export=True)
        LOG.info(f'S3 connection parameters: {name} read.')
    except ApiException as e:
        LOG.error(f'Exception message: {e}')
    else:
        return api_response


def list_s3_objects(minio_address, bucket_name, region_name):
    """Check if there is a file inside s3."""
    s3_keys = read_secret('s3-keys')
    access = b64decode(s3_keys.to_dict()['data']['access']).decode('utf-8')
    secret = b64decode(s3_keys.to_dict()['data']['secret']).decode('utf-8')

    minioClient = Minio(minio_address, access_key=access, secret_key=secret,
                        region=region_name, secure=False)
    LOG.info(f'Connected to S3: {minio_address}.')
    # List all object paths in bucket that begin with my-prefixname.
    objects = minioClient.list_objects_v2(bucket_name, recursive=True)
    for obj in objects:
        assert obj.object_name == '1', f"Wrong file! This is the file you are looking: {obj.object_name.encode('utf-8')}"
        LOG.info(f'Found ingested file: {obj.object_name} of size: {obj.size}.')


def main():
    """Do the sparkles and fireworks."""
    parser = argparse.ArgumentParser(description="Encrypting, uploading to inbox and sending message to CEGA.")

    parser.add_argument('input', help='Input file to be encrypted.')
    parser.add_argument('--u', help='Username to identify the elixir.', default='ega-box-999')
    parser.add_argument('--uk', help='User secret private RSA key.', default='auto/config/user.key')
    parser.add_argument('--pk', help='Public key file to encrypt file.', default='auto/config/key.1.pub')
    parser.add_argument('--inbox', help='Inbox address, or service name', default='inbox.lega.svc')
    parser.add_argument('--inbox-port', help='Inbox address, or service name', default='inbox.lega.svc')
    parser.add_argument('--s3', help='Inbox address, or service name', default='s3.lega.svc')
    parser.add_argument('--cm', help='CEGA MQ broker IP/name address')
    parser.add_argument('--cm-port', help='Inbox address, or service name')

    args = parser.parse_args()

    used_file = os.path.expanduser(args.input)
    key_pk = os.path.expanduser(args.uk)
    pub_key, _ = pgpy.PGPKey.from_file(os.path.expanduser(args.pk))

    inbox_host = args.inbox
    test_user = args.u
    test_file, c4ga_md5 = encrypt_file(used_file, pub_key)
    if c4ga_md5:
        sftp_upload(inbox_host, test_user, test_file, key_pk, port=int(args.inbox_port))
        submit_cega(args.cm, test_user, test_file, c4ga_md5, port=args.cm_port)
        sleep(10)  # wait for the file
        list_s3_objects(args.s3, 'lega', 'lega')
        LOG.info('Should be all!')


if __name__ == '__main__':
    main()
