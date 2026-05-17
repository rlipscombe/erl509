all: openssl-rsa-2048.key openssl-rsa-2048-p8.key

# -traditional creates a PKCS#1 file (BEGIN RSA PRIVATE KEY), rather than a PKCS#8 (BEGIN PRIVATE KEY) file.
openssl-rsa-2048.key:
	openssl genrsa -traditional -out $@ 2048

# We can convert it to a PKCS#8 file as follows:
openssl-rsa-2048-p8.key: openssl-rsa-2048.key
	openssl pkcs8 -topk8 -inform PEM -in $< -outform PEM -out $@ -nocrypt
