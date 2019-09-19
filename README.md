[![Build Status](https://travis-ci.org/neicnordic/LocalEGA-deploy-init.svg?branch=master)](https://travis-ci.org/neicnordic/LocalEGA-deploy-init)

## LocalEGA Deployment Configuration Init

**NOTE: Requires:** 
  - Python 3.6+
  - [keytool](https://docs.oracle.com/javase/7/docs/technotes/tools/solaris/keytool.html)
  - [OpenSSL](https://www.openssl.org/)

```
git clone https://github.com/neicnordic/LocalEGA-deploy-init.git
pip install .
legainit
```

Note: If `pip install .` did not install the `legainit` command try running `sudo python setup.py install`.

The parameters can be configured using the `--deploy-config` options:
```json
{
    "email": "test@csc.fi",
    "broker_username": "lega",
    "inbox_user": "dummy",
    "cega_user": "legatest",
    "key": {"name": "Test PGP",
            "comment": "Testing keys",
            "expire": "30/DEC/30 08:00:00",
            "id": "key.1"},
    "root_cert": {"country": "Finland", "country_code": "FI",
                "location": "Espoo", "org": "CSC",
                "cn": "lega",
                "org_unit": "NeIC System Developers"},
    "svc_cert": {"country": "Finland", "country_code": "FI",
                "location": "Espoo", "org": "CSC",
                "org_unit": "NeIC System Developers"},
    "keys_password": "password",
    "prefix_lega": "lega-localega",
    "prefix_cega": ""
}
```
The service list and their DNS Name can be loaded using `--svc-config`:
```json
[
    {"name":"s3","dns":"minio", "ns": "lega"},
    {"name":"keys", "ns": "lega"},
    {"name":"dataedge", "ns": "lega"},
    {"name":"res", "ns": "lega"},
    {"name":"htsget", "ns": "lega"},
    {"name":"inbox", "ns": "lega"},
    {"name":"ingest", "ns": "lega"},
    {"name":"finalize", "ns": "lega"},
    {"name":"verify", "ns": "lega"},
    {"name":"mq-server", "ns": "lega"},
    {"name":"filedatabase", "ns": "lega"},
    {"name":"db", "ns": "lega"},
    {"name":"tester", "ns": "lega"}
 ]
```

Using the deploy script:
```
➜ legainit --help
Usage: legainit [OPTIONS]

  Init script generating LocalEGA configuration parameters such as passwords
  and keys.

Options:
  --config-path TEXT      Specify path for the configuration directory,
                          default is `config` folder.
  --cega                  Generate mock configuration for CEGA.
  --deploy-config TEXT    JSON key value pair containing country specific
                          configuration.
  --jwt-payload TEXT      JSON with JWT token payload
  --svc-config TEXT       JSON with LocalEGA service list, DNSName (Optional)
                          and K8s namespace
  --cega-svc-config TEXT  JSON with CEGA service list, DNSName (Optional) and
                          K8s namespace
  --custom-ca TEXT        Load a custom root CA. Expects the key in same
                          directory with *.key extension.
  --java-store TEXT       Java keystore type can be JKS or PKCS12.
  --java-store-pass TEXT  Java keystore password.
  --help                  Show this message and exit.


```

#### Generating Configuration

The LocalEGA configuration is generated in `config` folder, 
in order to specify a path for the configuration directory use:
```
legainit --config-path <path>
```
The configuration also generates Java compatible certificates for `dataedge`, `res`
`keys` and `filedatabase` services.
Generated `config` directory when also using `--cega` option:
```

config
├── cega.conf
├── cega.json
├── certs
│   ├── cacerts
│   ├── cega-mq.ca.crt
│   ├── cega-mq.ca.key
│   ├── cega-users.ca.crt
│   ├── cega-users.ca.key
│   ├── dataedge.ca.crt
│   ├── dataedge.ca.key
│   ├── dataedge.p12
│   ├── db.ca.crt
│   ├── db.ca.key
│   ├── ega_ssl.cert
│   ├── ega_ssl.key
│   ├── filedatabase.ca.crt
│   ├── filedatabase.ca.key
│   ├── filedatabase.p12
│   ├── finalize.ca.crt
│   ├── finalize.ca.key
│   ├── htsget.ca.crt
│   ├── htsget.ca.key
│   ├── inbox.ca.crt
│   ├── inbox.ca.key
│   ├── ingest.ca.crt
│   ├── ingest.ca.key
│   ├── keys.ca.crt
│   ├── keys.ca.key
│   ├── keys.p12
│   ├── mq-server.ca.crt
│   ├── mq-server.ca.key
│   ├── res.ca.crt
│   ├── res.ca.key
│   ├── res.p12
│   ├── root.ca.crt
│   ├── root.ca.key
│   ├── s3.ca.crt
│   ├── s3.ca.key
│   ├── tester.ca.crt
│   ├── tester.ca.key
│   ├── verify.ca.crt
│   └── verify.ca.key
├── dummy.key
├── dummy.pub
├── key.1.pub
├── key.1.sec
├── token.key
├── token.pub
├── trace.yml
└── users.json
```

Note that the `root.ca.*` files will not be generated if `--custom-ca` option is used.

Parameters generated in `config/trace.yml` when also using `--cega` file:
```yaml
config:
  broker_username: "guest"
  cega_users_user: "lega"
  cega_mq_user: "lega"
  cega_vhost: "lega"
  cega_port: 5672
  cega_mq_ssl: 0
  tls_cert_ending: .ca.crt
  tls_key_ending: .ca.key
  tls_ca_root_file: root.ca.crt
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


### License

`LocalEGA-deploy-init` and all it sources are released under Apache License 2.0.