#!/usr/bin/env elixir

Mix.install([:x509])

key = X509.PrivateKey.new_ec(:secp256r1)
File.write!("ec.key", X509.PrivateKey.to_pem(key))
File.write!("ec-wrapped.key", X509.PrivateKey.to_pem(key, [:wrap]))

key = X509.PrivateKey.new_rsa(2058)
File.write!("rsa.key", X509.PrivateKey.to_pem(key))
File.write!("rsa-wrapped.key", X509.PrivateKey.to_pem(key, [:wrap]))
