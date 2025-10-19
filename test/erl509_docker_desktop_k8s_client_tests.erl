-module(erl509_docker_desktop_k8s_client_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("erl509_compat.hrl").

client_test() ->
    % Create the CA certificate.
    CAPrivateKey = erl509_private_key:create_rsa(2048),
    CATemplate = erl509_certificate_template:root_ca(#{
        extensions => #{
            subject_alt_name => erl509_certificate_extension:create_subject_alt_name_extension([
                <<"kubernetes">>
            ])
        }
    }),
    CACert = erl509_certificate:create_self_signed(
        CAPrivateKey,
        <<"CN=kubernetes">>,
        CATemplate
    ),

    % Create the client certificate.
    ClientPrivateKey = erl509_private_key:create_rsa(2048),
    ClientPublicKey = erl509_public_key:derive_public_key(ClientPrivateKey),

    ClientTemplate = erl509_certificate_template:client(#{
        extensions => #{
            % Default is to include both authorityKeyIdentifier and subjectKeyIdentifier; Docker Desktop omits the latter.
            authority_key_identifier => true,
            subject_key_identifier => false,
            subject_alt_name => erl509_certificate_extension:create_subject_alt_name_extension([
                {dNSName, <<"docker-for-desktop">>}
            ])
        }
    }),

    ClientCert = erl509_certificate:create(
        ClientPublicKey,
        <<"O=system:masters, CN=docker-for-desktop">>,
        CACert,
        CAPrivateKey,
        ClientTemplate
    ),

    % The certificate should NOT be self-signed.
    ?assertNot(pubkey_cert:is_self_signed(ClientCert)),

    % Certificate:
    #'OTPCertificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm1
    } = ClientCert,

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

    % Serial Number: 7196677738769057959 (0x63dfbc46164a88a7)
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
    %     Not After : Mar 20 13:16:25 2026 GMT
    {NotBefore, NotAfter} = parse_validity(Validity),
    ?assert(NotBefore =< erlang:system_time(second)),
    ?assertEqual(365 * 24 * 60 * 60, NotAfter - NotBefore),

    % Subject: O=system:masters, CN=docker-for-desktop
    ?assertEqual(
        {rdnSequence, [
            [
                {'AttributeTypeAndValue', ?'id-at-organizationName',
                    {printableString, "system:masters"}}
            ],
            [
                {'AttributeTypeAndValue', ?'id-at-commonName',
                    {printableString, "docker-for-desktop"}}
            ]
        ]},
        Subject
    ),

    % Subject Public Key Info:
    #'OTPSubjectPublicKeyInfo'{
        algorithm = Algorithm, subjectPublicKey = SubjectPublicKey
    } = SubjectPublicKeyInfo,

    ?assertEqual(#'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = 'NULL'}, Algorithm),
    ?assertEqual(erl509_public_key:derive_public_key(ClientPrivateKey), SubjectPublicKey),

    % X509v3 extensions:
    %     X509v3 Key Usage: critical
    %         Digital Signature, Key Encipherment
    %     X509v3 Extended Key Usage:
    %         TLS Web Client Authentication
    %     X509v3 Basic Constraints: critical
    %         CA:FALSE
    %     X509v3 Authority Key Identifier:
    %         90:26:9F:1B:4A:D5:74:85:F0:E0:50:BA:E9:E3:E1:C4:41:78:64:EE
    %     X509v3 Subject Alternative Name:
    %         DNS:docker-for-desktop
    ?assertEqual(5, length(Extensions)),
    ?assertMatch(
        #'Extension'{extnValue = [digitalSignature, keyEncipherment]},
        erl509_certificate:get_extension(ClientCert, ?'id-ce-keyUsage')
    ),
    ?assertMatch(
        #'Extension'{
            extnValue = [?'id-kp-clientAuth']
        },
        erl509_certificate:get_extension(ClientCert, ?'id-ce-extKeyUsage')
    ),
    ?assertMatch(
        #'Extension'{
            critical = true,
            extnValue = #'BasicConstraints'{cA = false, pathLenConstraint = asn1_NOVALUE}
        },
        erl509_certificate:get_extension(ClientCert, ?'id-ce-basicConstraints')
    ),
    ?assertMatch(
        #'Extension'{extnValue = _},
        erl509_certificate:get_extension(ClientCert, ?'id-ce-authorityKeyIdentifier')
    ),
    ?assertMatch(
        #'Extension'{
            extnValue = [
                {dNSName, "docker-for-desktop"}
            ]
        },
        erl509_certificate:get_extension(ClientCert, ?'id-ce-subjectAltName')
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
    CAPublicKey = erl509_certificate:get_public_key(CACert),
    ?assert(public_key:pkix_verify(erl509_certificate:to_der(ClientCert), CAPublicKey)),
    ok.

parse_validity(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    {erl509_time:decode_time(NotBefore), erl509_time:decode_time(NotAfter)}.
