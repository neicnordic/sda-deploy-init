[![Build Status](https://travis-ci.org/NBISweden/LocalEGA-deploy-init.svg?branch=master)](https://travis-ci.org/NBISweden/LocalEGA-deploy-init)

## LocalEGA Deployment Configuration Init

**NOTE: Requires Python >3.6.**
```
git clone https://github.com/NBISweden/LocalEGA-deploy-init.git
pip install .
legainit
```

Note: If `pip install .` did not install the `legainit` command try running `sudo python setup.py install`.

In the `deploy.py` parameters can be configured:
```json
_localega = {
      "email": "test@csc.fi",
      "key": {"name": "Test PGP",
              "comment": "Some comment",
              "expire": "30/DEC/30 08:00:00",
              "id": "key.1"},
      "ssl": {"country": "Finland", "country_code": "FI", "location": "Espoo", "org": "CSC"},
      "keys_password": "password"
  }
```

Using the deploy script:
```
╰─$ legainit --help
Usage: legainit [OPTIONS]

  Init script generating LocalEGA configuration parameters such as passwords
  and keys.

Options:
  --config-path TEXT  Specify path for the configuration directory, default is
                      `config` folder.
  --cega              Generate mock configuration for CEGA.
  --help              Show this message and exit.
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
├── defs.json
├── dummy.key
├── dummy.pub
├── dummy.yml
├── key.1.pub
├── key.1.sec
├── rabbitmq.config
├── ssl.cert
├── ssl.key
├── token.key
├── trace.yml
├── token.pub
├── user.key
└── user.pub

```

Parameters generated in `config/trace.yml` when also using `--cega` file:
```yaml
config:
  cega_username: lega
secrets:
  cega_creds:
  mq_password:
  pgp_passphrase:
  postgres_password:
  s3_access:
  s3_secret:
  shared_pgp_password:
  token:
```
