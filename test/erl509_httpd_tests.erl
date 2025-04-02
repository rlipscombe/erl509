-module(erl509_httpd_tests).
-include_lib("eunit/include/eunit.hrl").

%% Honestly, this is less of a test, more of an example.

all_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {with, [fun get_https/1]}
    ]}.

setup() ->
    CAKey = erl509_private_key:create_rsa(2048),
    CACert = erl509_certificate:create_self_signed(
        CAKey, <<"CN=ca">>, erl509_certificate_template:root_ca()
    ),

    ServerKey = erl509_private_key:create_rsa(2048),
    ServerPub = erl509_public_key:derive_public_key(ServerKey),
    ServerCert = erl509_certificate:create(
        ServerPub, <<"CN=localhost">>, CACert, CAKey, erl509_certificate_template:server()
    ),

    {ok, Pid, Info} = erl509_httpd:start(ServerCert, ServerKey),
    Port = proplists:get_value(port, Info),
    Url = "https://localhost:" ++ integer_to_list(Port),
    #{pid => Pid, url => Url, cacert => CACert}.

cleanup(#{ pid :=Pid}) ->
    erl509_httpd:stop(Pid).

get_https(#{url := Url, cacert := CACert}) ->
    Headers = [],
    SslOptions = [
        {verify, verify_peer},
        {cacerts, [erl509_certificate:to_der(CACert)]}
    ],
    HttpOptions = [{ssl, SslOptions}],
    Options = [],
    {ok, {{_, 200, _}, _Headers, _Body}} = httpc:request(get, {Url, Headers}, HttpOptions, Options),
    ok.
