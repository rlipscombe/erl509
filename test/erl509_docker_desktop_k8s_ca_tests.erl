-module(erl509_docker_desktop_k8s_ca_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("erl509_compat.hrl").

ca_test() ->
    CAPrivateKey = erl509_private_key:create_rsa(2048),
    CACert = erl509_certificate:create_self_signed(
        CAPrivateKey,
        <<"CN=kubernetes">>,
        erl509_certificate_template:root_ca(#{
            extensions => #{
                % Docker Desktop CA uses non-default Key Usage values.
                key_usage => erl509_certificate_extension:create_key_usage_extension([
                    digitalSignature, keyEncipherment, keyCertSign
                ]),
                subject_alt_name => erl509_certificate_extension:create_subject_alt_name_extension([
                    <<"kubernetes">>
                ])
            }
        })
    ),

    % The certificate should be self-signed.
    ?assert(pubkey_cert:is_self_signed(CACert)),

    % Certificate:
    #'OTPCertificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm1
    } = CACert,

    % Data:
    #'OTPTBSCertificate'{
        version = Version,
        serialNumber = SerialNumber,
        signature = SignatureAlgorithm2,
        issuer = Issuer,
        validity = Validity,
        subject = Subject,
        subjectPublicKeyInfo = SubjectPublicKeyInfo,
        extensions = Extensions
    } = TbsCertificate,

    % Per RFC 5280, section 4.1.1.2 and 4.1.2.3, "The signatureAlgorithm field ... MUST contain the same algorithm
    % identifier as the signature field in the sequence tbsCertificate".
    ?assertEqual(SignatureAlgorithm1, SignatureAlgorithm2),

    % Version: 3 (0x2)
    ?assertEqual(v3, Version),

    % Serial Number: 8269647964081397504 (0x72c3b102449a9f00)
    ?assert(is_integer(SerialNumber)),

    % Signature Algorithm: sha256WithRSAEncryption
    ?assertEqual(
        #'SignatureAlgorithm'{
            algorithm = ?sha256WithRSAEncryption,
            parameters = ?EXPECTED_SIGNATURE_ALGORITHM_PARAMETERS
        },
        SignatureAlgorithm1
    ),

    % Issuer: CN=kubernetes
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "kubernetes"}}]
        ]},
        Issuer
    ),

    % Validity
    %     Not Before: Mar 20 13:16:25 2025 GMT
    %     Not After : Mar 18 13:16:25 2035 GMT
    {NotBefore, NotAfter} = parse_validity(Validity),

    % Since we generated the certificate with a fixed period; it's relative to now. So we assert that, rather than the
    % fixed validity in the original OpenSSL output above.
    ?assert(NotBefore =< erlang:system_time(second)),
    ?assertEqual(10 * 365 * 24 * 60 * 60, NotAfter - NotBefore),

    % Subject: CN=kubernetes
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "kubernetes"}}]
        ]},
        Subject
    ),

    % Subject Public Key Info:
    #'OTPSubjectPublicKeyInfo'{
        algorithm = Algorithm, subjectPublicKey = SubjectPublicKey
    } = SubjectPublicKeyInfo,

    ?assertEqual(#'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = 'NULL'}, Algorithm),
    ?assertEqual(erl509_public_key:derive_public_key(CAPrivateKey), SubjectPublicKey),

    % X509v3 extensions:
    %     X509v3 Key Usage: critical
    %         Digital Signature, Key Encipherment, Certificate Sign
    %     X509v3 Basic Constraints: critical
    %         CA:TRUE
    %     X509v3 Subject Key Identifier:
    %         90:26:9F:1B:4A:D5:74:85:F0:E0:50:BA:E9:E3:E1:C4:41:78:64:EE
    %     X509v3 Subject Alternative Name:
    %         DNS:kubernetes
    ?assertEqual(4, length(Extensions)),
    ?assertMatch(
        #'Extension'{extnValue = [digitalSignature, keyEncipherment, keyCertSign]},
        erl509_certificate:get_extension(CACert, ?'id-ce-keyUsage')
    ),
    ?assertMatch(
        #'Extension'{
            critical = true,
            extnValue = #'BasicConstraints'{cA = true, pathLenConstraint = 1}
        },
        erl509_certificate:get_extension(CACert, ?'id-ce-basicConstraints')
    ),
    ?assertMatch(
        #'Extension'{extnValue = _},
        erl509_certificate:get_extension(CACert, ?'id-ce-subjectKeyIdentifier')
    ),
    ?assertMatch(
        #'Extension'{extnValue = [{dNSName, "kubernetes"}]},
        erl509_certificate:get_extension(CACert, ?'id-ce-subjectAltName')
    ),

    % Signature Algorithm: sha256WithRSAEncryption
    ?assertEqual(
        #'SignatureAlgorithm'{
            algorithm = ?sha256WithRSAEncryption,
            parameters = ?EXPECTED_SIGNATURE_ALGORITHM_PARAMETERS
        },
        SignatureAlgorithm2
    ),

    % Verify the signature.
    ?assert(public_key:pkix_verify(erl509_certificate:to_der(CACert), SubjectPublicKey)),
    ok.

parse_validity(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    {erl509_time:decode_time(NotBefore), erl509_time:decode_time(NotAfter)}.
