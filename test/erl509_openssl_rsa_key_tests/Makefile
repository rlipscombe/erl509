all: openssl-rsa-2048.key openssl-rsa-2048-p8.key

openssl-rsa-2048.key:
	openssl genrsa -traditional -out openssl-rsa-2048.key 2048

openssl-rsa-2048-p8.key: openssl-rsa-2048.key
	openssl pkcs8 -topk8 -inform PEM -in openssl-rsa-2048.key -outform PEM -out openssl-rsa-2048-p8.key -nocrypt
