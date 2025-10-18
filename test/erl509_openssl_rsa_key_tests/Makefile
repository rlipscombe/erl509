all: openssl-rsa-2048.key openssl-rsa-2048-p8.key

openssl-rsa-2048.key:
	openssl genrsa -traditional -out $@ 2048

openssl-rsa-2048-p8.key: openssl-rsa-2048.key
	openssl pkcs8 -topk8 -inform PEM -in $< -outform PEM -out $@ -nocrypt
