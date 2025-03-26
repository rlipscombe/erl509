-module(erl509_private_key_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    PEM = erl509_private_key:to_pem(RSAPrivateKey),
    ?assertMatch(<<"-----BEGIN RSA PRIVATE KEY-----\n", _Rest/binary>>, PEM),
    WrappedPEM = erl509_private_key:to_pem(RSAPrivateKey, [wrapped]),
    ?assertMatch(<<"-----BEGIN PRIVATE KEY-----\n", _Rest/binary>>, WrappedPEM),
    ok.
