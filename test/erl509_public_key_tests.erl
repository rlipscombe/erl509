-module(erl509_public_key_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    RSAPublicKey = erl509_public_key:derive_public_key(RSAPrivateKey),
    PEM = erl509_public_key:to_pem(RSAPublicKey),
    ?assertMatch(<<"-----BEGIN RSA PUBLIC KEY-----\n", _Rest/binary>>, PEM),
    WrappedPEM = erl509_public_key:to_pem(RSAPublicKey, [wrap]),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, WrappedPEM),
    ok.

ec_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    ECPublicKey = erl509_public_key:derive_public_key(ECPrivateKey),
    % EC public keys are always wrapped.
    PEM = erl509_public_key:to_pem(ECPublicKey),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM),
    WrappedPEM = erl509_public_key:to_pem(ECPublicKey, [wrap]),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, WrappedPEM),
    ok.
