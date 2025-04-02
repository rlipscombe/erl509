# erl509_docker_desktop_k8s_tests

These tests replicate the certificates used by Docker Desktop's Kubernetes cluster.

To get the relevant certificates (assuming you've installed Docker Desktop and enabled Kubernetes):

The CA certificate (in PEM format) is available with the following command:

```
yq '.clusters[] | select(.name == "docker-desktop") | .cluster.certificate-authority-data' <$KUBECONFIG | base64 -d
```

Piping that through OpenSSL (`... | openssl x509 -text -noout`) gives the following:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 8269647964081397504 (0x72c3b102449a9f00)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=kubernetes
        Validity
            Not Before: Mar 20 13:16:25 2025 GMT
            Not After : Mar 18 13:16:25 2035 GMT
        Subject: CN=kubernetes
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:cf:64:cb:c3:67:7b:af:b3:f6:67:9c:49:bf:f5:
                    ...
                    4e:21
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Certificate Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                90:26:9F:1B:4A:D5:74:85:F0:E0:50:BA:E9:E3:E1:C4:41:78:64:EE
            X509v3 Subject Alternative Name:
                DNS:kubernetes
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        4f:3e:6e:d7:d9:c5:34:ae:99:46:59:25:76:28:3f:fb:74:c8:
        ...
        4f:3e:b4:9c
```

The test attempts to create a CA certificate of the same form.

The server certificate is available with the following command:

```
openssl s_client -connect kubernetes.docker.internal:6443 </dev/null
```

That spits out a large amount of text. The bit we're interested in is the PEM-armoured server certificate. We can
extract that by piping it through awk:

```
openssl s_client -connect kubernetes.docker.internal:6443 </dev/null 2>/dev/null | awk '/-----BEGIN/,/-----END/'
```

Piping that through OpenSSL (`... | openssl x509 -text -noout`) gives the following:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 7196677738769057959 (0x63dfbc46164a88a7)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=kubernetes
        Validity
            Not Before: Mar 20 13:16:25 2025 GMT
            Not After : Mar 20 13:16:25 2026 GMT
        Subject: CN=kube-apiserver
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:98:29:72:cd:f3:be:a9:a0:13:5c:0e:27:a2:2d:
                    ...
                    f4:d1
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier:
                90:26:9F:1B:4A:D5:74:85:F0:E0:50:BA:E9:E3:E1:C4:41:78:64:EE
            X509v3 Subject Alternative Name:
                DNS:docker-for-desktop, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.docker.internal, DNS:localhost, DNS:vm.docker.internal, IP Address:10.96.0.1, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:192.168.65.3
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        7f:17:7f:d6:50:15:5d:3c:b7:28:d0:a3:da:2a:c0:bb:a8:f0:
        ...
        4d:85:14:e5
```
