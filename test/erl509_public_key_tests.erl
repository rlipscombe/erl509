-module(erl509_public_key_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_test_() ->
    {setup,
        fun() ->
            Key = erl509_private_key:create_rsa(2048),
            erl509_public_key:derive_public_key(Key)
        end,
        {with, [
            fun rsa_to_pem/1,
            fun rsa_to_wrapped_pem/1
        ]}}.

rsa_to_pem(Pub) ->
    PEM = erl509_public_key:to_pem(Pub),
    ?assertMatch(<<"-----BEGIN RSA PUBLIC KEY-----\n", _Rest/binary>>, PEM).

rsa_to_wrapped_pem(Pub) ->
    PEM = erl509_public_key:to_pem(Pub, [wrap]),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM).

ec_test_() ->
    {setup,
        fun() ->
            Key = erl509_private_key:create_ec(secp256r1),
            erl509_public_key:derive_public_key(Key)
        end,
        {with, [
            fun ec_to_pem/1,
            fun ec_to_wrapped_pem/1
        ]}}.

ec_to_pem(Pub) ->
    % EC public keys are always wrapped.
    PEM = erl509_public_key:to_pem(Pub),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM).

ec_to_wrapped_pem(Pub) ->
    PEM = erl509_public_key:to_pem(Pub, [wrap]),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM).
