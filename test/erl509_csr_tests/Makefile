all: openssl-rsa.csr

openssl-rsa.key:
	openssl genrsa -traditional -out $@ 2048

openssl-rsa.csr: openssl-rsa.key
	openssl req -new -key $< -subj "/CN=example.org" -out $@
