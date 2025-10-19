-module(erl509_serverfault_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% serverfault.com (and presumably the rest of the StackOverflow fleet) uses slightly unusual algorithms; let's see if
%% we can replicate that.
serverfault_test_() ->
    % Obviously, we don't have their keys, but we can create some using the same parameters.

    % Public Key Algorithm: rsaEncryption (4096), Signature Algorithm: sha256WithRSAEncryption
    RootKey = erl509_private_key:create_rsa(4096),
    RootCertificate = erl509_certificate:create_self_signed(
        RootKey,
        <<"/C=US/O=Not Internet Security Research Group/CN=Not ISRG Root X1">>,
        erl509_certificate_template:root_ca()
    ),

    % ASN1 OID: secp384r1, Signature Algorithm: sha256WithRSAEncryptiom
    IntermediateKey = erl509_private_key:create_ec(secp384r1),
    IntermediatePub = erl509_public_key:derive_public_key(IntermediateKey),
    IntermediateCertificate = erl509_certificate:create(
        IntermediatePub,
        <<"/C=US/O=Not Let's Encrypt/CN=E8">>,
        RootCertificate,
        RootKey,
        erl509_certificate_template:ca()
    ),

    % ASN1 OID: prime256v1, Signature Algorithm: ecdsa-with-SHA384
    % NIST P-256 is `:secp256r1` rather than `:prime256v1`
    ServerKey = erl509_private_key:create_ec(secp256r1),
    ServerPub = erl509_public_key:derive_public_key(ServerKey),
    ServerCert = erl509_certificate:create(
        ServerPub,
        <<"CN=not.serverfault.com">>,
        IntermediateCertificate,
        IntermediateKey,
        erl509_certificate_template:server(#{hash_algorithm => sha384})
    ),

    [
        % Assert the correct signature algorithms.
        ?_assertEqual(?'ecdsa-with-SHA384', get_signature_algorithm(ServerCert)),
        ?_assertEqual(?sha256WithRSAEncryption, get_signature_algorithm(IntermediateCertificate)),
        ?_assertEqual(?sha256WithRSAEncryption, get_signature_algorithm(RootCertificate)),

        % Assert the correct key types.
        ?_assertEqual(
            #'PublicKeyAlgorithm'{
                algorithm = ?'id-ecPublicKey', parameters = {namedCurve, ?'secp256r1'}
            },
            get_subject_public_key_algorithm(ServerCert)
        ),
        ?_assertEqual(
            #'PublicKeyAlgorithm'{
                algorithm = ?'id-ecPublicKey', parameters = {namedCurve, ?'secp384r1'}
            },
            get_subject_public_key_algorithm(IntermediateCertificate)
        ),
        ?_assertEqual(
            #'PublicKeyAlgorithm'{
                algorithm = ?rsaEncryption, parameters = 'NULL'
            },
            get_subject_public_key_algorithm(RootCertificate)
        )
    ].

get_signature_algorithm(
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            signature = #'SignatureAlgorithm'{algorithm = SignatureAlgorithm}
        }
    }
) ->
    SignatureAlgorithm.

get_subject_public_key_algorithm(#'OTPCertificate'{
    tbsCertificate = #'OTPTBSCertificate'{
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{algorithm = SubjectPublicKeyAlgorithm}
    }
}) ->
    SubjectPublicKeyAlgorithm.
