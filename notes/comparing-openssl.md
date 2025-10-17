# Comparing with openssl

```sh
openssl genrsa -out openssl-ca-2048.key 2048
openssl rsa -in openssl-ca-2048.key -text
```

Round-trip via `erl509`:

```erlang
{ok, Pem} = fle:read_file("openssl-ca-2048.key").
Key = erl509_private_key:from_pem(Pem).
file:write_file("openssl-ca-2048-erl509.key", erl509_private_key:to_pem(Key, [wrapped])).
```

The `erl509`-generated file is one byte larger, because it has an extra LF on the end.

```sh
openssl req -new -x509 -sha256 -subj '/CN=ca' -days 180 -key openssl-ca-2048.key -out openssl-ca.crt
openssl x509 -in openssl-ca.crt -text
```

What size is the signature?

```sh
openssl x509 -in openssl-ca.crt -text -noout | \
    awk 'f{print} /Signature Value:/ {f=1}' | tr -cd '[0-9a-f]' | wc -c
```

A 2048-bit RSA key should result in a signature of the same size. 2048 bits is 256 octets, so the above command should
output `512`, because it's hex-encoded.

BUG: new branch outputs excessively-large signatures.
