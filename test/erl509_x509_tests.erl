-module(erl509_x509_tests).
-include_lib("eunit/include/eunit.hrl").

%% These tests compare our behaviour against some canned voltone/x509 data.
ec_private_key_test() ->
    {ok, Pem} = file:read_file("test/erl509_x509_tests/ec.key"),
    Key = erl509_private_key:from_pem(Pem),
    Pem = erl509_private_key:to_pem(Key),
    ok.

ec_wrapped_private_key_test() ->
    {ok, Pem} = file:read_file("test/erl509_x509_tests/ec-wrapped.key"),
    Key = erl509_private_key:from_pem(Pem),
    Pem = erl509_private_key:to_pem(Key, [wrap]),
    ok.
