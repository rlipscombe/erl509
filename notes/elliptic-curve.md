# Elliptic Curves

## What's in an EC private key?

```
% openssl ecparam -name prime256v1 -genkey -out ec.key
% cat ec.key
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MH...
...RKfQ==
-----END EC PRIVATE KEY-----
```

```
1> rr(public_key).
[...]
2> {ok, K} = file:read_file("ec.key").
{ok,<<"-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMH"...>>}
3> [public_key:pem_entry_decode(E) || E <- public_key:pem_decode(K)].
[{namedCurve,{1,2,840,10045,3,1,7}},
 #'ECPrivateKey'{version = 1,
                 privateKey = <<226,199,226,210,115,105,202,117,232,208,
                                146,205,212,...>>,
                 parameters = {namedCurve,{1,2,840,10045,3,1,7}},
                 publicKey = <<4,15,7,7,27,225,88,57,52,202,135,179,134,
                               147,24,224,200,177,233,102,193,149,...>>,
                 attributes = asn1_NOVALUE}]
```

## What's in an EC public key?

```
% openssl ec -in ec.key -pubout -out ec.pub
% cat ec.pub
-----BEGIN PUBLIC KEY-----
MF...
...RKfQ==
-----END PUBLIC KEY-----
```

```
1> rr(public_key).
[...]
2> {ok, Pub} = file:read_file("ec.pub").
{ok,<<"-----BEGIN PUBLIC KEY-----\nMFkwEwYH"...>>}
3> [public_key:pem_entry_decode(E) || E <- public_key:pem_decode(Pub)].
[{#'ECPoint'{point = <<4,15,7,7,27,225,88,57,52,202,135,
                       179,134,147,24,224,200,177,233,
                       102,193,149,104,244,96,...>>},
  {namedCurve,{1,2,840,10045,3,1,7}}}]
```

## What's in an EC certificate?

```
% openssl req -new -x509 -key ec.key -sha256 -subj "/CN=example" -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            25:fb:de:d6:30:f3:02:9b:c1:96:f8:64:85:7f:31:8b:1d:07:75:4c
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=example
        Validity
            Not Before: Mar 26 10:14:23 2025 GMT
            Not After : Apr 25 10:14:23 2025 GMT
        Subject: CN=example
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:0f:07:07:1b:e1:58:39:34:ca:87:b3:86:93:18:
                    e0:c8:b1:e9:66:c1:95:68:f4:60:e3:1c:e1:1c:38:
                    db:9a:04:76:72:b1:ba:de:52:f3:5a:78:65:11:8e:
                    3f:8d:c3:4d:42:ea:36:00:23:87:50:9f:1a:79:3a:
                    e9:8f:f4:4a:7d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                E3:A6:2E:B2:AC:B1:D6:5F:13:CA:33:62:BD:95:03:4C:30:5D:F4:27
            X509v3 Authority Key Identifier:
                E3:A6:2E:B2:AC:B1:D6:5F:13:CA:33:62:BD:95:03:4C:30:5D:F4:27
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:2f:d7:03:3a:3f:a9:6e:f1:38:9b:9d:67:80:57:
        4a:42:23:b1:90:52:7c:ba:26:92:ab:c5:69:00:06:20:63:13:
        02:21:00:a5:69:48:70:93:e9:55:2c:8d:32:66:2b:bb:ea:a2:
        04:1f:45:fc:b0:39:57:00:11:1c:0e:6e:7f:f0:a8:89:31
```

Note:
- openssl's self-signed certficates have both the SubjectKeyIdentifier and AuthorityKeyIdentifier (as do x509's, but not
  Docker Desktop's).
- Both erl509 and x509 generate serial numbers which are numbers. openssl outputs hex. Why?

If I use an openssl-generated EC key for generating certificates, what's the difference between them?

### OpenSSL

```
% openssl ecparam -name prime256v1 -genkey -out ec.key
% openssl req -new -x509 -key ec.key -sha256 -subj "/CN=example" -out openssl-ec.crt
```

### Elixir

```elixir
k = X509.PrivateKey.from_pem!(File.read!("ec.key"))
cert = X509.Certificate.self_signed(k, "CN=example")
File.write!("elixir-ec.crt", X509.Certificate.to_pem(cert))
```

### Erlang

```erlang
{ok, Pem} = file:read_file("ec.key").
Key = erl509_private_key:from_pem(Pem).
Cert = erl509_certificate:create_self_signed(Key, <<"example">>).
file:write_file("erlang-ec.crt", erl509_certificate:to_pem(Cert)).
```
