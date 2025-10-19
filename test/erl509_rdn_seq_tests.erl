-module(erl509_rdn_seq_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

% Note: voltone/x509 defaults to 'plain' format RDN sequences; we implicitly use 'otp'.
%
% If you want to compare output, remember to use, e.g.:
%
%   X509.RDNSequence.new("C=US, ST=New Jersey, L=Jersey City, O=Org, CN=Certification Authority", :otp)

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
                {'AttributeTypeAndValue', ?'id-at-commonName', {utf8String, <<"Not ISRG Root X1">>}}
            ]
        ]},
        erl509_rdn_seq:create(
            <<"/C=US/O=Not Internet Security Research Group/CN=Not ISRG Root X1">>
        )
    ).

github_root_test() ->
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', {2, 5, 4, 6}, "US"}],
            [{'AttributeTypeAndValue', {2, 5, 4, 8}, {utf8String, <<"New Jersey">>}}],
            [{'AttributeTypeAndValue', {2, 5, 4, 7}, {utf8String, <<"Jersey City">>}}],
            [
                {'AttributeTypeAndValue', {2, 5, 4, 10},
                    {utf8String, <<"Not The USERTRUST Network">>}}
            ],
            [
                {'AttributeTypeAndValue', {2, 5, 4, 3},
                    {utf8String, <<"Not USERTrust ECC Certification Authority">>}}
            ]
        ]},
        erl509_rdn_seq:create(
            <<"C=US, ST=New Jersey, L=Jersey City, O=Not The USERTRUST Network, CN=Not USERTrust ECC Certification Authority">>
        )
    ).
