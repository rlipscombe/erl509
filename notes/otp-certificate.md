# Migrating to 'OTPCertificate'

At the time of writing this note, `erl509` uses `Certificate` records, whereas `x509` uses `OTPCertificate` records.
This wasn't a problem until recently. However, OTP-28.x broke DER-encoding of various `Certificate`-related entities.

So, it's probably worth updating `erl509` to use `OTPCertificate` records instead. That's painful, but the simplest way
is probably to reverse-engineer a known certificate and check that we can recreate it.

So: create `example-ca.cer`, per the README, and then load it back in as an `OTPCertificate`. Then update `erl509` to
create that instead.

```erlang
{ok, Pem} = file:read_file("example-ca.crt").
[{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem).
OTPCertificate = public_key:pkix_decode_cert(Der, otp).
```
