# cafinder
X509 Certificate decoder for the purpose of identifying a certificate chain


Usage:
```
cafinder.py -c mycertificate.pem
```
Note: If you don't want to use the cafinder.py script, you can use openssl (```openssl x509 -in cert.pem -noout -text```)

The scripts looks for these fields in the certificate. 

1) The Subject: shows the subject of the certificate to make sure you have included the right certificate.
2) The Issuer: shows the name of the issuing CA. The issuer should have the subject as this issuer field.
3) X509v3 Subject Key Identifier: This is a sha1 hash of the end-entity's public key
4) X509v3 Authority Key Identifier: This is a sha1 hash of the CA issuer's public key
5) Authority Information Access, CA Issuers: This can contain a location (many times a URL) of where you can find the issuer CA certificate

Please ensure that you are using cryptography version 3.1 or greater
