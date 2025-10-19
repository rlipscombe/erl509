-module(erl509_rdn_seq_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

cn_test() ->
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-commonName', {utf8String, <<"example">>}}
            ]
        ]},
        erl509_rdn_seq:create("CN=example")
    ).

docker_desktop_test() ->
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-organizationName',
                    {utf8String, <<"system:masters">>}}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-commonName',
                    {utf8String, <<"docker-for-desktop">>}}
            ]
        ]},
        erl509_rdn_seq:create(<<"O=system:masters, CN=docker-for-desktop">>)
    ).

isrg_test() ->
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-countryName', "US"}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-organizationName',
                    {utf8String, <<"Not Internet Security Research Group">>}}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-commonName',
                    {utf8String, <<"Not ISRG Root X1">>}}
            ]
        ]},
        erl509_rdn_seq:create(<<"/C=US/O=Not Internet Security Research Group/CN=Not ISRG Root X1">>)
    ).
