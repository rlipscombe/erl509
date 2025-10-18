-module(erl509_private_key_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_test_() ->
    {setup, fun() -> erl509_private_key:create_rsa(2048) end,
        {with, [
            fun rsa_to_pem/1,
            fun rsa_to_wrapped_pem/1,
            fun rsa_derive_public_key/1
        ]}}.

rsa_to_pem(Key) ->
    PEM = erl509_private_key:to_pem(Key),
    ?assertMatch(<<"-----BEGIN RSA PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    Key2 = erl509_private_key:from_pem(PEM),
    ?assertEqual(Key, Key2),
    ok.

rsa_to_wrapped_pem(Key) ->
    PEM = erl509_private_key:to_pem(Key, [wrap]),
    ?assertMatch(<<"-----BEGIN PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    Key2 = erl509_private_key:from_pem(PEM),
    ?assertEqual(Key, Key2),
    ok.

rsa_derive_public_key(Key) ->
    _ = erl509_private_key:derive_public_key(Key),
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
