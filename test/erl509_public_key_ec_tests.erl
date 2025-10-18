-module(erl509_public_key_ec_tests).
-include_lib("eunit/include/eunit.hrl").

ec_test_() ->
    {setup,
        fun() ->
            Key = erl509_private_key:create_ec(secp256r1),
            erl509_public_key:derive_public_key(Key)
        end,
        {with, [
            fun ec_to_pem/1,
            fun ec_to_wrapped_pem/1
        ]}}.

ec_to_pem(Pub) ->
    % EC public keys are always wrapped when exported to PEM.
    % TODO: x509 seems to differ slightly on PEM vs DER and wrapping.
    PEM = erl509_public_key:to_pem(Pub),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM),
    _ = erl509_public_key:to_der(Pub),
    ok.

ec_to_wrapped_pem(Pub) ->
    PEM = erl509_public_key:to_pem(Pub, [wrap]),
    ?assertMatch(<<"-----BEGIN PUBLIC KEY-----\n", _Rest/binary>>, PEM),
    _ = erl509_public_key:to_der(Pub),
    ok.

ec_to_der_test() ->
    % Uses a canned EC key originally generated with voltone/x509
    Key =
        {'ECPrivateKey', ecPrivkeyVer1,
            <<10, 102, 89, 18, 53, 145, 207, 8, 206, 6, 94, 6, 45, 206, 33, 186, 104, 252, 110, 222,
                124, 0, 57, 114, 127, 122, 43, 113, 124, 217, 19, 27>>,
            {namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
            <<4, 185, 152, 23, 167, 251, 193, 207, 179, 25, 31, 179, 32, 169, 202, 217, 61, 74, 106,
                120, 21, 108, 106, 114, 88, 44, 158, 60, 101, 120, 82, 46, 167, 74, 154, 37, 141,
                168, 133, 187, 3, 77, 231, 159, 235, 143, 210, 73, 212, 38, 129, 42, 109, 119, 12,
                119, 56, 10, 111, 9, 189, 111, 139, 76, 74>>,
            asn1_NOVALUE},
    Pub = {
        {'ECPoint',
            <<4, 185, 152, 23, 167, 251, 193, 207, 179, 25, 31, 179, 32, 169, 202, 217, 61, 74, 106,
                120, 21, 108, 106, 114, 88, 44, 158, 60, 101, 120, 82, 46, 167, 74, 154, 37, 141,
                168, 133, 187, 3, 77, 231, 159, 235, 143, 210, 73, 212, 38, 129, 42, 109, 119, 12,
                119, 56, 10, 111, 9, 189, 111, 139, 76, 74>>},
        {namedCurve, {1, 2, 840, 10045, 3, 1, 7}}
    },
    Der =
        <<48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3,
            66, 0, 4, 185, 152, 23, 167, 251, 193, 207, 179, 25, 31, 179, 32, 169, 202, 217, 61, 74,
            106, 120, 21, 108, 106, 114, 88, 44, 158, 60, 101, 120, 82, 46, 167, 74, 154, 37, 141,
            168, 133, 187, 3, 77, 231, 159, 235, 143, 210, 73, 212, 38, 129, 42, 109, 119, 12, 119,
            56, 10, 111, 9, 189, 111, 139, 76, 74>>,
    SKIExt =
        {'Extension', {2, 5, 29, 14}, false,
            <<195, 125, 240, 157, 127, 119, 219, 132, 213, 149, 125, 69, 115, 160, 106, 85, 90, 57,
                149, 29>>},
    AKIExt =
        {'Extension', {2, 5, 29, 35}, false,
            {'AuthorityKeyIdentifier',
                <<195, 125, 240, 157, 127, 119, 219, 132, 213, 149, 125, 69, 115, 160, 106, 85, 90,
                    57, 149, 29>>,
                asn1_NOVALUE, asn1_NOVALUE}},

    ?assertEqual(Pub, erl509_private_key:derive_public_key(Key)),
    ?assertEqual(Der, erl509_public_key:to_der(Pub)),
    ?assertEqual(SKIExt, erl509_certificate_extension:create_subject_key_identifier_extension(Pub)),
    ?assertEqual(
        AKIExt, erl509_certificate_extension:create_authority_key_identifier_extension(Pub)
    ),
    ok.
