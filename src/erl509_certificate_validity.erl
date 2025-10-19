-module(erl509_certificate_validity).
-export([
    create/1,
    create/2
]).

-include_lib("public_key/include/public_key.hrl").

create(ExpiryDays) ->
    Now = erlang:system_time(second),
    ExpirySeconds = ExpiryDays * 24 * 60 * 60,

    NotBefore = erl509_time:encode_time(Now),
    NotAfter = erl509_time:encode_time(Now + ExpirySeconds),
    create(NotBefore, NotAfter).

create(NotBefore, NotAfter) ->
    #'Validity'{
        notBefore = NotBefore,
        notAfter = NotAfter
    }.
