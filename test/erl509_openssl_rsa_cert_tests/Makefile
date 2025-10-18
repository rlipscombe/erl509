all: openssl-root-ca.crt openssl-root-ca.der.crt

openssl-root-ca.crt: openssl-root-ca.key
	openssl req -new -x509 -sha256 -subj '/CN=root' -days 1800 -key $< -out $@

openssl-root-ca.key:
	openssl genrsa -out $@ 2048

openssl-root-ca.der.crt: openssl-root-ca.crt
	openssl x509 -in $< -inform PEM -out $@ -outform DER
