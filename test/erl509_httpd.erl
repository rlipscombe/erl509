-module(erl509_httpd).
-export([
    start/2,
    stop/1
]).

start(ServerCert, ServerKey) ->
    {ok, _} = application:ensure_all_started([inets, ssl]),

    Config = [
        {server_name, atom_to_list(?MODULE)},
        {server_root, "."},
        {document_root, "."},

        {port, 0},

        {socket_type,
            {ssl, [
                {cert, erl509_certificate:to_der(ServerCert)},
                {key, {'RSAPrivateKey', erl509_private_key:to_der(ServerKey)}}
            ]}}
    ],
    {ok, Pid} = inets:start(httpd, Config),
    Info = httpd:info(Pid, [port]),
    {ok, Pid, Info}.

stop(Pid) ->
    inets:stop(httpd, Pid),
    ok.
