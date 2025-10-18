-module(erl509_rdn_seq_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

cn_test() ->
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-commonName', {printableString, <<"example">>}}
            ]
        ]},
        erl509_rdn_seq:create("CN=example")
    ).

docker_desktop_test() ->
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-organizationName',
                    {printableString, <<"system:masters">>}}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-commonName',
                    {printableString, <<"docker-for-desktop">>}}
            ]
        ]},
        erl509_rdn_seq:create(<<"O=system:masters, CN=docker-for-desktop">>)
    ).
