# `OTPCertificate` vs `Certificate`

Originally we used the `Certificate` type to represent certificates. The Elixir `x509` library uses the `OTPCertificate` type.

To read a `Certificate` record from a PEM-encoded certificate file, you can do something like this:

```erlang
{ok, Pem} = file:read_file("ca.crt"),
[Certificate] = [public_key:pem_entry_decode(E) || E <- public_key:pem_decode(Pem)],
#'Certificate'{} = Certificate.
```

However, to read an `OTPCertificate` record, you need to do the following:

```erlang
{ok, Pem} = file:read_file("ca.crt"),
[{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
OTPCertificate = public_key:der_decode('OTPCertificate', Der),
#'OTPCertificate'{} = OTPCertificate.
```
