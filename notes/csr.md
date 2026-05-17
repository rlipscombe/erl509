# Certificate Signing Requests

Taken from my
[erlang-cluster](https://blog.differentpla.net/blog/2022/12/22/erlang-cluster-k8s-certificate-requests-openssl/)
project, here's how to use OpenSSL to create a basic certificate signing request (CSR):

## Creating keypair and CSR

```sh
# we need a keypair
openssl genrsa -traditional -out server.key 2048

# create the CSR
openssl req -new -key server.key -subj "/CN=example.org" -out server.csr
```

## What's in it?

```
$ openssl req -in server.csr -text -noout
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = example.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a6:42:89:29:1e:66:f0:de:67:be:c4:f8:24:6d:
                    e2:06:52:15:8f:dc:da:9b:b8:e9:f8:fc:e3:ba:c6:
                    97:a0:eb:3c:f3:f5:a7:f2:f3:12:a3:3c:10:ae:3d:
                    9d:61:8d:19:7e:9e:98:6d:03:4c:5d:37:dd:cb:fc:
                    e3:2b:fe:d2:ec:24:4a:f8:39:6a:a6:02:b5:08:de:
                    58:45:ff:8e:b3:02:bf:27:da:dc:08:80:54:63:79:
                    73:3b:77:e2:82:11:d2:a7:07:6f:76:51:db:53:b8:
                    7a:59:23:9e:6e:8a:69:d0:44:ec:83:d3:90:50:55:
                    fe:50:f1:87:1d:bf:6a:30:08:41:5c:a2:36:fd:91:
                    92:6e:89:0c:66:7c:30:d9:3c:a6:ce:dd:6d:b2:c5:
                    30:33:7b:c9:4f:d9:43:a9:fe:52:20:01:3c:ac:68:
                    12:b1:3c:ca:b3:ab:08:e8:ac:53:80:84:57:6e:0a:
                    4b:7d:c7:74:c4:c9:61:c6:86:c2:57:d8:cb:3c:b9:
                    e0:85:40:4c:a1:4e:1a:b3:b0:2b:99:b5:e7:05:b2:
                    a9:98:93:c8:f7:07:de:79:c9:77:ee:4e:52:bb:c3:
                    0d:33:51:ee:1d:55:26:fa:df:92:5b:10:34:44:97:
                    4b:01:52:bd:e8:dc:3f:4a:90:a9:18:5d:9d:50:ee:
                    4a:33
                Exponent: 65537 (0x10001)
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        4d:44:6f:e2:56:bc:b1:f2:b7:85:07:13:4a:f5:a5:4d:a9:46:
        2a:da:4b:0f:42:eb:0d:a9:9b:73:78:db:c9:b9:7f:46:b7:1e:
        c8:65:b4:de:7e:d2:5e:3a:78:fc:b4:aa:9b:b8:b7:33:a2:96:
        50:20:5b:cd:cd:97:9e:2b:ee:18:53:01:fb:e9:b2:06:f3:de:
        4a:e9:82:9a:c7:54:c2:00:65:8e:26:50:38:41:7c:c8:22:a7:
        f4:31:d0:f2:dc:84:38:1b:85:64:a6:9d:0d:b9:4e:52:a6:68:
        fc:6b:6c:d0:ab:fc:a5:21:14:e7:81:fd:0a:76:11:fd:18:a3:
        b4:e4:47:ff:d2:3e:03:9c:93:d0:46:79:75:96:9c:e6:a8:82:
        75:eb:2f:94:53:5a:42:67:6d:14:c2:e7:26:2f:21:20:4c:32:
        81:1e:49:1c:eb:06:a7:39:ca:df:bf:23:4b:78:5c:06:3d:87:
        a7:89:54:ca:49:ed:8e:39:9d:de:c0:9c:af:db:4b:67:46:c2:
        61:2c:9a:7c:dc:2a:63:53:e4:29:2d:b1:34:a1:c2:d7:ce:55:
        8a:f8:6a:8d:34:02:af:e1:b2:c0:84:d8:3a:6f:ff:3d:34:fe:
        13:04:98:b1:0f:8f:ff:d9:95:25:b6:1d:83:ad:ad:96:44:09:
        31:32:5b:23
```

## What's in it? Erlang edition

```erlang
rr(public_key).

{ok, PEM} = file:read_file("server.csr").
[{'CertficationRequest', DER, not_encrypted}] = public_key:pem_decode(PEM).
public_key:der_decode('CertificationRequest', DER).
```

I've reformatted the following...

```
{'CertificationRequest',
    {'CertificationRequestInfo',
        v1,
        {rdnSequence,[
            [
                #'AttributeTypeAndValue'{type = {2,5,4,3}, value = {utf8String,<<"example.org">>}}
            ]
        ]},
        {'CertificationRequestInfo_subjectPKInfo',
            {'CertificationRequestInfo_subjectPKInfo_algorithm', {1,2,840,113549,1,1,1}, {asn1_OPENTYPE,<<5,0>>}},
            <<48,130,1,10,2,130,1,1,0,166,66,137,41,30,102,240,222,103,190,196,...>>},
        []},
    {'CertificationRequest_signatureAlgorithm',{1,2,840,113549,1,1,11},{asn1_OPENTYPE,<<5,0>>}},
        <<77,68,111,226,86,188,177,242,183,133,7,19,74,245,165,77,169,70,42,218,75,15,66,235,13,...>>
}
```
