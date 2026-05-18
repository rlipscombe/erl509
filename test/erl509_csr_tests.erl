-module(erl509_csr_tests).
-include_lib("eunit/include/eunit.hrl").

csr_from_pem_test() ->
    % We generated a CSR with openssl; can we read it in?
    Pem = read_file("openssl-rsa.csr"),
    Csr = erl509_csr:from_pem(Pem),

    % Do we write the same thing back out?
    ?assertEqual(Pem, strip_trailing_lf(erl509_csr:to_pem(Csr))),
    ok.

compare_openssl_test() ->
    % Given the same private key, do we generate the same CSR as openssl?
    Key = erl509_private_key:from_pem(read_file("openssl-rsa.key")),
    Csr = erl509_csr:create_csr(Key, <<"CN=example.org">>),

    Pem = read_file("openssl-rsa.csr"),
    ExpectedCsr = erl509_csr:from_pem(Pem),
    ?assertEqual(ExpectedCsr, Csr),
    ok.

% TODO: Generate the CSR; verify the signature of the CSR.

% TODO: extensions, particularly SAN.

% TODO: What other tooling for creating CSRs is there? Can we replicate that?

read_file(Name) ->
    Path = filename:join(["test", atom_to_list(?MODULE), Name]),
    case file:read_file(Path) of
        {ok, Data} -> Data;
        {error, E} -> {error, {E, Name, Path}}
    end.

% openssl puts one LF at the end; Erlang puts two.
strip_trailing_lf(Bytes) ->
    binary:part(Bytes, 0, byte_size(Bytes) - 1).
