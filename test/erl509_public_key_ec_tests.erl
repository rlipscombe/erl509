-module(erl509_public_key_ec_tests).
-include_lib("eunit/include/eunit.hrl").

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
