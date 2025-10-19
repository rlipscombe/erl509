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

isrg_test() ->
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-countryName',
                    {printableString, <<"US">>}}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-organizationName',
                    {printableString, <<"Not Internet Security Research Group">>}}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-commonName',
                    {printableString, <<"Not ISRG Root X1">>}}
            ]
        ]},
        erl509_rdn_seq:create(<<"/C=US/O=Not Internet Security Research Group/CN=Not ISRG Root X1">>)
    ).
