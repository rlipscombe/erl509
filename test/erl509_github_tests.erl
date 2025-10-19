-module(erl509_github_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% The certificates used by github.com have interesting extensions; can we replicate that?
github_test_() ->
    RootKey = erl509_private_key:create_ec(secp384r1),
    RootPub = erl509_public_key:derive_public_key(RootKey),
    RootSubject =
        <<"C=US, ST=New Jersey, L=Jersey City, O=Not The USERTRUST Network, CN=Not USERTrust ECC Certification Authority">>,
    RootCertificate = erl509_certificate:create_self_signed(
        RootKey,
        RootSubject,
        erl509_certificate_template:root_ca(#{
            hash_algorithm => sha384,
            validity => erl509_certificate_validity:create(
                erl509_time:encode_time(
                    calendar:rfc3339_to_system_time("2010-02-01T00:00:00Z")
                ),
                erl509_time:encode_time(calendar:rfc3339_to_system_time("2038-01-18T23:59:59Z"))
            ),
            extensions => #{
                basic_constraints => erl509_certificate_extension:create_basic_constraints_extension(
                    true
                )
            }
        })
    ),

    [
        {"root certificate signature algorithm",
            ?_assertEqual(
                ?'ecdsa-with-SHA384',
                erl509_certificate_util:get_signature_algorithm(RootCertificate)
            )},
        {"root certificate spki algorithm",
            ?_assertEqual(
                #'PublicKeyAlgorithm'{
                    algorithm = ?'id-ecPublicKey', parameters = {namedCurve, ?'secp384r1'}
                },
                erl509_certificate_util:get_subject_public_key_algorithm(RootCertificate)
            )},
        {"root certificate not after 2038",
            ?_assertEqual(
                #'Validity'{
                    notBefore = {utcTime, "100201000000Z"},
                    notAfter = {utcTime, "380118235959Z"}
                },
                erl509_certificate:get_validity(RootCertificate)
            )},
        {"root certificate extension ski",
            ?_assertEqual(
                #'Extension'{
                    extnID = ?'id-ce-subjectKeyIdentifier',
                    critical = false,
                    extnValue = crypto:hash(sha, erl509_public_key:to_der(RootPub))
                },
                erl509_certificate:get_extension(RootCertificate, ?'id-ce-subjectKeyIdentifier')
            )},
        {"root certificate extension has no aki",
            ?_assertEqual(
                undefined,
                erl509_certificate:get_extension(RootCertificate, ?'id-ce-authorityKeyIdentifier')
            )},
        {"root certificate key usage",
            ?_assertEqual(
                #'Extension'{
                    extnID = ?'id-ce-keyUsage',
                    critical = true,
                    extnValue = [keyCertSign, cRLSign]
                },
                erl509_certificate:get_extension(RootCertificate, ?'id-ce-keyUsage')
            )},
        {"root certificate has no extended key usage",
            ?_assertEqual(
                undefined,
                erl509_certificate:get_extension(RootCertificate, ?'id-ce-extKeyUsage')
            )},
        {"root certificate basic constraints",
            ?_assertEqual(
                #'Extension'{
                    extnID = ?'id-ce-basicConstraints',
                    critical = true,
                    extnValue = #'BasicConstraints'{cA = true, pathLenConstraint = asn1_NOVALUE}
                },
                erl509_certificate:get_extension(RootCertificate, ?'id-ce-basicConstraints')
            )}
    ].
