-module(erl509_openssl_rsa_cert_tests).
-include_lib("eunit/include/eunit.hrl").

rsa_root_ca_from_pem_test() ->
    % We generated a root CA certificate openssl; can we read it in?
    Pem = read_file("openssl-root-ca.crt"),
    Certificate = erl509_certificate:from_pem(Pem),

    % TODO: Assert some things about the certificate?

    % Do we write the same thing back out?
    ?assertEqual(Pem, strip_trailing_lf(erl509_certificate:to_pem(Certificate))),
    ok.

rsa_root_ca_from_der_test() ->
    % We generated a root CA certificate openssl; can we read it in?
    Der = read_file("openssl-root-ca.der.crt"),
    Certificate = erl509_certificate:from_der(Der),

    % TODO: Assert some things about the certificate?

    % Do we write the same thing back out?
    ?assertEqual(Der, erl509_certificate:to_der(Certificate)),
    ok.

read_file(Name) ->
    Path = filename:join(["test", atom_to_list(?MODULE), Name]),
    {ok, Data} = file:read_file(Path),
    Data.

% openssl puts one LF at the end; Erlang puts two.
strip_trailing_lf(Bytes) ->
    binary:part(Bytes, 0, byte_size(Bytes) - 1).
