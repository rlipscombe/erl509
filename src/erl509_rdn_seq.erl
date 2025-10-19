-module(erl509_rdn_seq).
-export([create/1]).

create(<<"/", From/binary>>) ->
    {rdnSequence,
        lists:map(
            fun(Part) ->
                erl509_rdn:create_rdn(string:trim(Part))
            end,
            string:split(From, "/", all)
        )};
create(From) ->
    {rdnSequence,
        lists:map(
            fun(Part) ->
                erl509_rdn:create_rdn(string:trim(Part))
            end,
            string:split(From, ",", all)
        )}.
