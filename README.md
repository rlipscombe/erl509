# erl509

Erlang library for working with X.509 certificates.

Currently, it only supports creating a CA certificate, using an RSA private key, as follows:

```erlang
RSAPrivateKey = erl509_private_key:create_rsa(2048).
Certificate = erl509_certificate:create_self_signed(RSAPrivateKey, <<"example">>).
PEM = public_key:pem_encode([public_key:pem_entry_encode('Certificate', Certificate)]).
ok = file:write_file("example.crt", PEM).
```

```
% openssl x509 -in example.crt -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 6584168703948165264 (0x5b5faa8d44131090)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=example
        Validity
            Not Before: Mar 25 21:06:24 2025 GMT
            Not After : Mar 23 21:06:24 2035 GMT
        Subject: CN=example
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Certificate Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                ...
            X509v3 Subject Alternative Name:
                DNS:example
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        ...
```

Ideally, we'd eventually reach feature-parity with the [voltone/x509](https://github.com/voltone/x509) package for
Elixir (which is excellent, by the way).
