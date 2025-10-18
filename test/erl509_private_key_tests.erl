-module(erl509_private_key_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    PEM = erl509_private_key:to_pem(RSAPrivateKey),
    ?assertMatch(<<"-----BEGIN RSA PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    WrappedPEM = erl509_private_key:to_pem(RSAPrivateKey, [wrap]),
    ?assertMatch(<<"-----BEGIN PRIVATE KEY-----\n", _Rest/binary>>, WrappedPEM),
    _RSAPublicKey = erl509_private_key:derive_public_key(RSAPrivateKey),
    RSAPrivateKey2 = erl509_private_key:from_pem(PEM),
    ?assertEqual(RSAPrivateKey, RSAPrivateKey2),
    RSAPrivateKey3 = erl509_private_key:from_pem(WrappedPEM),
    ?assertEqual(RSAPrivateKey, RSAPrivateKey3),
    ok.

ec_test_() ->
    {setup, fun() -> erl509_private_key:create_ec(secp256r1) end,
        {with, [
            fun ec_to_pem/1,
            fun ec_to_wrapped_pem/1,
            fun ec_derive_public_key/1
        ]}}.

ec_to_pem(Key) ->
    PEM = erl509_private_key:to_pem(Key),
    ?assertMatch(<<"-----BEGIN EC PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    Key2 = erl509_private_key:from_pem(PEM),
    ?assertEqual(Key, Key2),
    ok.

ec_to_wrapped_pem(Key) ->
    PEM = erl509_private_key:to_pem(Key, [wrap]),
    ?assertMatch(<<"-----BEGIN PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    Key2 = erl509_private_key:from_pem(PEM),
    ?assertEqual(Key, Key2),
    ok.

ec_derive_public_key(Key) ->
    _ = erl509_private_key:derive_public_key(Key),
    ok.
