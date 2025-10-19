all: openssl-ec.key openssl-ec-p8.key

openssl-ec.key:
	openssl ecparam -name prime256v1 -genkey -out $@

openssl-ec-p8.key:
	openssl pkcs8 -topk8 -inform PEM -in $< -outform PEM -out $@ -nocrypt
