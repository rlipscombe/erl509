-module(erl509_certificate_template).
-export([
    root_ca/0,
    root_ca/1,

    server/0,
    server/1,

    client/0,
    client/1
]).

-include_lib("public_key/include/public_key.hrl").

root_ca() ->
    #{
        validity => 10 * 365,
        extensions =>
            #{
                key_usage => erl509_certificate_extension:create_key_usage_extension([
                    digitalSignature, keyEncipherment, keyCertSign
                ]),
                basic_constraints => erl509_certificate_extension:create_basic_constraints_extension(
                    true, 1
                ),
                subject_key_identifier => true
            }
    }.

root_ca(Options) ->
    merge(root_ca(), Options).

server() ->
    #{
        validity => 365,
        extensions => #{
            key_usage => erl509_certificate_extension:create_key_usage_extension([
                digitalSignature, keyEncipherment
            ]),
            basic_constraints => erl509_certificate_extension:create_basic_constraints_extension(
                false
            ),
            ext_key_usage => erl509_certificate_extension:create_extended_key_usage_extension(
                [?'id-kp-serverAuth', ?'id-kp-clientAuth']
            ),
            subject_key_identifier => true,
            authority_key_identifier => true
        }
    }.

server(Options) ->
    merge(server(), Options).

client() ->
    #{
        extensions => #{
            key_usage => erl509_certificate_extension:create_key_usage_extension([
                digitalSignature, keyEncipherment
            ]),
            ext_key_usage => erl509_certificate_extension:create_extended_key_usage_extension([
                ?'id-kp-clientAuth'
            ]),
            basic_constraints => erl509_certificate_extension:create_basic_constraints_extension(
                false
            ),
            authority_key_identifier => true,
            subject_key_identifier => true
        }
    }.

client(Options) ->
    merge(client(), Options).

merge(DefaultOptions, ExtraOptions) ->
    maps:merge_with(
        fun(extensions, Extensions1, Extensions2) -> maps:merge(Extensions1, Extensions2) end,
        DefaultOptions,
        ExtraOptions
    ).
