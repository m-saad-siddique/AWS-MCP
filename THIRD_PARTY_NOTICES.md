# Third-party notices

## RDS public certificate trust bundle

`assets/rds-global-bundle.pem` is the public Amazon RDS global CA bundle from
https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem . It contains
public trust certificates, not private keys. It is used for verified RDS TLS
connections through local Session Manager forwarding. Certificate issuers retain
their respective rights; the project MIT license does not relicense third-party
material. The source and update instructions are also documented in README.md.

## npm dependencies

Dependencies are not vendored. Their names, versions, and integrity hashes are
recorded in package-lock.json. Each installed package supplies its own license;
retain applicable notices when redistributing dependencies.
