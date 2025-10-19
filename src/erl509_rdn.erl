-module(erl509_rdn).
-export([create_rdn/1]).

-include_lib("public_key/include/public_key.hrl").

create_rdn(Value) when is_binary(Value) ->
    create_rdn_attr(list_to_tuple(string:split(Value, <<"=">>)));
create_rdn(Value) when is_list(Value) ->
    create_rdn(list_to_binary(Value)).

create_rdn_attr({<<"CN">>, Value}) when byte_size(Value) =< 256 ->
    [#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, Value}}];
create_rdn_attr({<<"O">>, Value}) when byte_size(Value) =< 256 ->
    [#'AttributeTypeAndValue'{type = ?'id-at-organizationName', value = {utf8String, Value}}];
create_rdn_attr({<<"C">>, Value}) ->
    [#'AttributeTypeAndValue'{type = ?'id-at-countryName', value = binary_to_list(Value)}].
