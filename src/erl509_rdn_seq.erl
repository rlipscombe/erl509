-module(erl509_rdn_seq).
-export([create/1]).

create(<<"/", From/binary>>) ->
    from_list(string:split(From, "/", all));
create(From) ->
    from_list(string:split(From, ",", all)).

from_list(Parts) ->
    {rdnSequence,
        lists:map(
            fun(Part) ->
                erl509_rdn:create_rdn(string:trim(Part))
            end,
            Parts
        )}.
