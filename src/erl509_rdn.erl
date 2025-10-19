-module(erl509_rdn).
-export([create_rdn/1]).

-include_lib("public_key/include/public_key.hrl").

create_rdn(<<"CN=", Value/binary>>) ->
    create_rdn(?'id-at-commonName', Value);
create_rdn(<<"O=", Value/binary>>) ->
    create_rdn(?'id-at-organizationName', Value);
create_rdn(<<"C=", Value/binary>>) ->
    create_rdn(?'id-at-countryName', Value);
create_rdn(Value) when is_list(Value) ->
    create_rdn(list_to_binary(Value)).

create_rdn(Type, Value) ->
    Len = byte_size(Value),
    create_rdn(Type, Len, Value).

create_rdn(Type, Len, Value) when Len =< 255 ->
    [
        #'AttributeTypeAndValue'{
            type = Type,
            value = {printableString, Value}
        }
    ].
