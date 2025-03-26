# Comparing results with the Elixir x509 library

Because this stuff's kinda arcane, it's occasionally useful to compare the behaviour of this library against the
excellent `voltone/x509` library. Here are some snippets showing how to do that.

```sh
# Starting 'iex':
ERL_LIBS=$(rebar3 path --lib) iex
```

Then you can use it as follows:

```elixir
iex(1)> :erl509_private_key.create_ec(:secp256r1)
{:ECPrivateKey, 1,
 <<117, 81, 1, 193, 218, 116, 145, 159, 92, 106, 70, 222, 176, 146, 150, 63,
   224, 168, ...>>,
 {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
 <<4, 26, 103, 173, 126, 242, 236, 255, 106, 5, 70, 124, 155, 26, 212, 166, 111,
   72, 193, 242, 77, 145, 78, 76, 191, 62, 236, 159, 204, ...>>, :asn1_NOVALUE}
```

So, for example, to assert that `erl509` and `x509` create PEM-formatted elliptic private keys in the same way:

```elixir
Mix.install([{:x509, "~> 0.8.3"}])
import ExUnit.Assertions

k = :erl509_private_key.create_ec(:secp256r1)
assert :erl509_private_key.to_pem(k) == X509.PrivateKey.to_pem(k)
```

Asserting certificates is trickier, because `x509` generates `OTPCertificate` objects and `erl509` currently generates
`Certificate` objects.
