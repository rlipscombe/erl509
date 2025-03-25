-module(erl509_rdn).
-export([create_rdn/1]).

-include_lib("public_key/include/public_key.hrl").

create_rdn(Value) when is_binary(Value) ->
    Len = byte_size(Value),
    {rdnSequence, [
        [
            #'AttributeTypeAndValue'{
                type = ?'id-at-commonName',
                value = <<19, Len:8, Value/binary>>
            }
        ]
    ]}.
