[![Build Status](https://travis-ci.org/neicnordic/LocalEGA-deploy-init.svg?branch=master)](https://travis-ci.org/neicnordic/LocalEGA-deploy-init)

## LocalEGA Deployment Configuration Init

**NOTE: Requires Python >3.6.**
```
git clone https://github.com/neicnordic/LocalEGA-deploy-init.git
pip install .
legainit
```

Note: If `pip install .` did not install the `legainit` command try running `sudo python setup.py install`.

In parameters can be configured using the `--deploy-config` options:
```json
_localega = {
            "email": "test@csc.fi",
            "key": {"name": "Test PGP",
                    "comment": "some comment",
                    "expire": "30/DEC/30 08:00:00",
                    "id": "key.1"},
            "cert": {"country": "Finland", "country_code": "FI",
                     "location": "Espoo", "org": "CSC",
                     "common_name": "NeICLocalEGA",
                     "org_unit": "EGA SysDev"},
            "keys_password": "password"
            }
```

Using the deploy script:
```
➜ legainit --help
Usage: legainit [OPTIONS]

  Init script generating LocalEGA configuration parameters such as passwords
  and keys.

Options:
  --config-path TEXT    Specify path for the configuration directory, default
                        is `config` folder.
  --cega                Generate mock configuration for CEGA.
  --deploy-config TEXT  JSON key value pair containing country specific
                        configuration.
  --jwt-payload TEXT    JSON with JWT token payload
  --help                Show this message and exit.

```

#### Generating Configuration

By default configuration is generated in `config` folder, in order to specify a path for the configuration directory use:
```
legainit --config-path <path>
```
Generated `config` directory when also using `--cega` option:
```
config
├── cega.config
├── cega.json
├── cega-mq.ca.crt
├── cega-users.ca.crt
├── csr
│   ├── ...
│   └── ...
├── dataedge.ca.crt
├── db.ca.crt
├── dummy.key
├── dummy.pub
├── dummy.yml
├── filedatabase.ca.crt
├── finalize.ca.crt
├── htsget.ca.crt
├── inbox.ca.crt
├── ingest.ca.crt
├── key.1.pub
├── key.1.sec
├── keys.ca.crt
├── mq.ca.crt
├── res.ca.crt
├── root.ca.crt
├── root.ca.key
├── s3.ca.crt
├── ssl.cert
├── ssl.key
├── token.key
├── token.pub
├── trace.yml
└── verify.ca.crt

```

Parameters generated in `config/trace.yml` when also using `--cega` file:
```yaml
config:
  broker_username: "guest"
  cega_users_user: "lega"
  cega_mq_user: "lega"
  cega_vhost: "lega"
  cega_port: 5672
  cega_mq_ssl: 0
secrets:
  cega_users_pass:
  cega_mq_pass:
  mq_password:
  mq_password_hash:
  pgp_passphrase:
  pg_in_password:
  pg_out_password:
  s3_access_key:
  s3_secret_key:
  shared_pgp_password:
  token:
```
