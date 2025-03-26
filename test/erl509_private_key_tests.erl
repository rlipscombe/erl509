-module(erl509_private_key_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    PEM = erl509_private_key:to_pem(RSAPrivateKey),
    ?assertMatch(<<"-----BEGIN RSA PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    WrappedPEM = erl509_private_key:to_pem(RSAPrivateKey, [wrapped]),
    ?assertMatch(<<"-----BEGIN PRIVATE KEY-----\n", _Rest/binary>>, WrappedPEM),
    _RSAPublicKey = erl509_private_key:derive_public_key(RSAPrivateKey),
    ok.

ec_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    PEM = erl509_private_key:to_pem(ECPrivateKey),
    ?assertMatch(<<"-----BEGIN EC PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    WrappedPEM = erl509_private_key:to_pem(ECPrivateKey, [wrapped]),
    ?assertMatch(<<"-----BEGIN PRIVATE KEY-----\n", _Rest/binary>>, WrappedPEM),
    _ECPublicKey = erl509_private_key:derive_public_key(ECPrivateKey),
    ok.
