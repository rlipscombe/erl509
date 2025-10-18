-module(erl509_public_key_rsa_tests).
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
    % TODO: X509 defaults to wrapped for PEM-wrapped RSA public keys.
    PEM = erl509_public_key:to_pem(Pub),
    ?assertMatch(<<"-----BEGIN RSA PUBLIC KEY-----\n", _Rest/binary>>, PEM),
    % TODO: X509 defaults to wrapped for DER-wrapped RSA public keys.
    _ = erl509_public_key:to_der(Pub),
    ok.

rsa_to_wrapped_pem(Pub) ->
    PEM = erl509_public_key:to_pem(Pub, [wrap]),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM),
    _ = erl509_public_key:to_der(Pub),
    ok.
