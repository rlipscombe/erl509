all: openssl-root-ca.crt

openssl-root-ca.crt: openssl-root-ca.key
	openssl req -new -x509 -sha256 -subj '/CN=root' -days 1800 -key $< -out $@

openssl-root-ca.key:
	openssl ecparam -name prime256v1 -genkey -out $@
