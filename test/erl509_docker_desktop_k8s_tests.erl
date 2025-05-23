-module(erl509_docker_desktop_k8s_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

ca_test() ->
    CAPrivateKey = erl509_private_key:create_rsa(2048),
    CACert = erl509_certificate:create_self_signed(
        CAPrivateKey,
        <<"CN=kubernetes">>,
        erl509_certificate_template:root_ca(#{
            extensions => #{
                subject_alt_name => erl509_certificate_extension:create_subject_alt_name_extension([
                    <<"kubernetes">>
                ])
            }
        })
    ),

    % Convert the certificate to 'OTP' format.
    OTPCert = to_otp(CACert),

    % The certificate should be self-signed.
    ?assert(pubkey_cert:is_self_signed(OTPCert)),

    % Certificate:
    #'OTPCertificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm1
    } = OTPCert,

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
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
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
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
        SignatureAlgorithm2
    ),

    % Verify the signature.
    ?assert(public_key:pkix_verify(erl509_certificate:to_der(CACert), SubjectPublicKey)),
    ok.

server_test() ->
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

    % Create the server certificate.
    ServerPrivateKey = erl509_private_key:create_rsa(2048),
    ServerPublicKey = erl509_public_key:derive_public_key(ServerPrivateKey),

    ServerTemplate = erl509_certificate_template:server(#{
        extensions => #{
            % Default for server is serverAuth and clientAuth; Docker Desktop only uses serverAuth.
            ext_key_usage => erl509_certificate_extension:create_extended_key_usage_extension([
                ?'id-kp-serverAuth'
            ]),
            % Default is to include both authorityKeyIdentifier and subjectKeyIdentifier; Docker Desktop omits the latter.
            authority_key_identifier => true,
            subject_key_identifier => false,
            subject_alt_name => erl509_certificate_extension:create_subject_alt_name_extension([
                {dNSName, <<"docker-for-desktop">>},
                {dNSName, <<"kubernetes">>},
                {dNSName, <<"kubernetes.default">>},
                {dNSName, <<"kubernetes.default.svc">>},
                {dNSName, <<"kubernetes.default.svc.cluster.local">>},
                {dNSName, <<"kubernetes.docker.internal">>},
                {dNSName, <<"localhost">>},
                {dNSName, <<"vm.docker.internal">>},
                {iPAddress, <<10, 96, 0, 1>>},
                {iPAddress, <<0, 0, 0, 0>>},
                {iPAddress, <<127, 0, 0, 1>>},
                {iPAddress, <<192, 168, 65, 3>>}
            ])
        }
    }),

    ServerCert = erl509_certificate:create(
        ServerPublicKey,
        <<"CN=kube-apiserver">>,
        CACert,
        CAPrivateKey,
        ServerTemplate
    ),

    % Convert the certificate to 'OTP' format.
    OTPCert = to_otp(ServerCert),

    % The certificate should NOT be self-signed.
    ?assertNot(pubkey_cert:is_self_signed(OTPCert)),

    % Certificate:
    #'OTPCertificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm1
    } = OTPCert,

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
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
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
    ?assertEqual(1 * 365 * 24 * 60 * 60, NotAfter - NotBefore),

    % Subject: CN=kube-apiserver
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "kube-apiserver"}}]
        ]},
        Subject
    ),

    % Subject Public Key Info:
    #'OTPSubjectPublicKeyInfo'{
        algorithm = Algorithm, subjectPublicKey = SubjectPublicKey
    } = SubjectPublicKeyInfo,

    ?assertEqual(#'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = 'NULL'}, Algorithm),
    ?assertEqual(erl509_public_key:derive_public_key(ServerPrivateKey), SubjectPublicKey),

    % X509v3 extensions:
    %     X509v3 Key Usage: critical
    %         Digital Signature, Key Encipherment
    %     X509v3 Extended Key Usage:
    %         TLS Web Server Authentication
    %     X509v3 Basic Constraints: critical
    %         CA:FALSE
    %     X509v3 Authority Key Identifier:
    %         90:26:9F:1B:4A:D5:74:85:F0:E0:50:BA:E9:E3:E1:C4:41:78:64:EE
    %     X509v3 Subject Alternative Name:
    %         DNS:docker-for-desktop, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc,
    %         DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.docker.internal, DNS:localhost,
    %         DNS:vm.docker.internal, IP Address:10.96.0.1, IP Address:0.0.0.0, IP Address:127.0.0.1, IP
    %         Address:192.168.65.3
    ?assertEqual(5, length(Extensions)),
    ?assertMatch(
        #'Extension'{extnValue = [digitalSignature, keyEncipherment]},
        erl509_certificate:get_extension(ServerCert, ?'id-ce-keyUsage')
    ),
    ?assertMatch(
        #'Extension'{
            extnValue = [?'id-kp-serverAuth']
        },
        erl509_certificate:get_extension(ServerCert, ?'id-ce-extKeyUsage')
    ),
    ?assertMatch(
        #'Extension'{
            critical = true,
            extnValue = #'BasicConstraints'{cA = false, pathLenConstraint = asn1_NOVALUE}
        },
        erl509_certificate:get_extension(ServerCert, ?'id-ce-basicConstraints')
    ),
    ?assertMatch(
        #'Extension'{extnValue = _},
        erl509_certificate:get_extension(ServerCert, ?'id-ce-authorityKeyIdentifier')
    ),
    ?assertMatch(
        #'Extension'{
            extnValue = [
                {dNSName, "docker-for-desktop"},
                {dNSName, "kubernetes"},
                {dNSName, "kubernetes.default"},
                {dNSName, "kubernetes.default.svc"},
                {dNSName, "kubernetes.default.svc.cluster.local"},
                {dNSName, "kubernetes.docker.internal"},
                {dNSName, "localhost"},
                {dNSName, "vm.docker.internal"},
                {iPAddress, <<10, 96, 0, 1>>},
                {iPAddress, <<0, 0, 0, 0>>},
                {iPAddress, <<127, 0, 0, 1>>},
                {iPAddress, <<192, 168, 65, 3>>}
            ]
        },
        erl509_certificate:get_extension(ServerCert, ?'id-ce-subjectAltName')
    ),

    % Signature Algorithm: sha256WithRSAEncryption
    ?assertEqual(
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
        SignatureAlgorithm2
    ),

    % Verify the signature.
    CAPublicKey = erl509_certificate:get_public_key(CACert),
    ?assert(public_key:pkix_verify(erl509_certificate:to_der(ServerCert), CAPublicKey)),
    ok.

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

    % Create the server certificate.
    ServerPrivateKey = erl509_private_key:create_rsa(2048),
    ServerPublicKey = erl509_public_key:derive_public_key(ServerPrivateKey),

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
        ServerPublicKey,
        <<"O=system:masters, CN=docker-for-desktop">>,
        CACert,
        CAPrivateKey,
        ClientTemplate
    ),

    % Convert the certificate to 'OTP' format.
    OTPCert = to_otp(ClientCert),

    % The certificate should NOT be self-signed.
    ?assertNot(pubkey_cert:is_self_signed(OTPCert)),

    % Certificate:
    #'OTPCertificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm1
    } = OTPCert,

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
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
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
    ?assertEqual(1 * 365 * 24 * 60 * 60, NotAfter - NotBefore),

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
    ?assertEqual(erl509_public_key:derive_public_key(ServerPrivateKey), SubjectPublicKey),

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
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
        SignatureAlgorithm2
    ),

    % Verify the signature.
    CAPublicKey = erl509_certificate:get_public_key(CACert),
    ?assert(public_key:pkix_verify(erl509_certificate:to_der(ClientCert), CAPublicKey)),
    ok.

to_otp(#'Certificate'{} = Certificate) ->
    DER = public_key:der_encode('Certificate', Certificate),
    public_key:pkix_decode_cert(DER, otp).

parse_validity(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    {erl509_time:decode_time(NotBefore), erl509_time:decode_time(NotAfter)}.
