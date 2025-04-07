-module(erl509_certificate_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

self_signed_rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    RSAPublicKey = erl509_private_key:derive_public_key(RSAPrivateKey),
    Certificate = erl509_certificate:create_self_signed(
        RSAPrivateKey, <<"CN=example">>, erl509_certificate_template:root_ca()
    ),
    _PEM = erl509_certificate:to_pem(Certificate),
    _DER = erl509_certificate:to_der(Certificate),

    OTPCertificate = to_otp(Certificate),

    ?assert(pubkey_cert:is_self_signed(OTPCertificate)),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            version = _,
            serialNumber = _,
            signature = SignatureAlgorithm,
            issuer = Issuer,
            validity = _,
            subject = Subject,
            subjectPublicKeyInfo = SubjectPublicKeyInfo,
            issuerUniqueID = _,
            subjectUniqueID = _,
            extensions = _
        },
        signatureAlgorithm = SignatureAlgorithm,
        signature = _
    } = OTPCertificate,
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "example"}}]
        ]},
        Issuer
    ),
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "example"}}]
        ]},
        Subject
    ),
    ?assertEqual(
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
        SignatureAlgorithm
    ),
    #'OTPSubjectPublicKeyInfo'{
        algorithm = Algorithm,
        subjectPublicKey = SubjectPublicKey
    } = SubjectPublicKeyInfo,
    ?assertEqual(
        #'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = 'NULL'},
        Algorithm
    ),
    ?assertEqual(RSAPublicKey, SubjectPublicKey),
    ok.

self_signed_ec_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    ECPublicKey = erl509_private_key:derive_public_key(ECPrivateKey),
    Certificate = erl509_certificate:create_self_signed(
        ECPrivateKey, <<"CN=example">>, erl509_certificate_template:root_ca()
    ),
    _PEM = erl509_certificate:to_pem(Certificate),

    OTPCertificate = to_otp(Certificate),

    ?assert(pubkey_cert:is_self_signed(OTPCertificate)),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            version = _,
            serialNumber = _,
            signature = SignatureAlgorithm,
            issuer = Issuer,
            validity = _,
            subject = Subject,
            subjectPublicKeyInfo = SubjectPublicKeyInfo,
            issuerUniqueID = _,
            subjectUniqueID = _,
            extensions = Extensions
        },
        signatureAlgorithm = SignatureAlgorithm,
        signature = _
    } = OTPCertificate,
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "example"}}]
        ]},
        Issuer
    ),
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "example"}}]
        ]},
        Subject
    ),
    ?assertEqual(
        #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256', parameters = asn1_NOVALUE},
        SignatureAlgorithm
    ),
    #'OTPSubjectPublicKeyInfo'{
        algorithm = Algorithm,
        subjectPublicKey = SubjectPublicKey
    } = SubjectPublicKeyInfo,
    ?assertEqual(
        #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = {namedCurve, ?secp256r1}},
        Algorithm
    ),
    {ECPoint, _} = ECPublicKey,
    ?assertEqual(ECPoint, SubjectPublicKey),

    % TODO: Assert all of the extensions.
    ?assertEqual(3, length(Extensions)),
    {value, Extn} = lists:search(
        fun(#'Extension'{extnID = ExtnID}) -> ExtnID =:= ?'id-ce-basicConstraints' end, Extensions
    ),
    ?assertMatch(
        #'Extension'{
            critical = true, extnValue = #'BasicConstraints'{cA = true, pathLenConstraint = _}
        },
        Extn
    ),
    ok.

serial_number_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    Certificate = erl509_certificate:create_self_signed(ECPrivateKey, <<"CN=example">>, #{
        serial_number => 12345,
        extensions => #{}
    }),

    OTPCertificate = to_otp(Certificate),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            serialNumber = SerialNumber
        }
    } = OTPCertificate,
    ?assertEqual(12345, SerialNumber),
    ok.

validity_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    Certificate = erl509_certificate:create_self_signed(ECPrivateKey, <<"CN=example">>, #{
        % in days
        validity => 90,
        extensions => #{}
    }),

    OTPCertificate = to_otp(Certificate),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            validity = Validity
        }
    } = OTPCertificate,

    {NotBefore, NotAfter} = parse_validity(Validity),
    ?assert(NotBefore =< erlang:system_time(second)),
    ?assertEqual(90 * 24 * 60 * 60, NotAfter - NotBefore),
    ok.

server_rsa_test() ->
    CAKey = erl509_private_key:create_rsa(2048),
    CACert = erl509_certificate:create_self_signed(
        CAKey, <<"CN=ca">>, erl509_certificate_template:root_ca()
    ),

    ServerKey = erl509_private_key:create_rsa(2048),
    ServerPub = erl509_public_key:derive_public_key(ServerKey),
    ServerCert = erl509_certificate:create(
        ServerPub, <<"CN=server">>, CACert, CAKey, erl509_certificate_template:server()
    ),

    OTPCertificate = to_otp(ServerCert),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            version = _,
            serialNumber = _,
            signature = SignatureAlgorithm,
            issuer = Issuer,
            validity = Validity,
            subject = Subject,
            subjectPublicKeyInfo = SubjectPublicKeyInfo,
            issuerUniqueID = _,
            subjectUniqueID = _,
            extensions = Extensions
        },
        signatureAlgorithm = SignatureAlgorithm,
        signature = _
    } = OTPCertificate,
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "ca"}}]
        ]},
        Issuer
    ),
    ?assertEqual(
        {rdnSequence, [
            [{'AttributeTypeAndValue', ?'id-at-commonName', {printableString, "server"}}]
        ]},
        Subject
    ),
    ?assertEqual(
        #'SignatureAlgorithm'{algorithm = ?sha256WithRSAEncryption, parameters = 'NULL'},
        SignatureAlgorithm
    ),
    #'OTPSubjectPublicKeyInfo'{
        algorithm = Algorithm,
        subjectPublicKey = SubjectPublicKey
    } = SubjectPublicKeyInfo,
    ?assertEqual(
        #'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = 'NULL'},
        Algorithm
    ),
    ?assertEqual(ServerPub, SubjectPublicKey),

    {NotBefore, NotAfter} = parse_validity(Validity),
    ?assert(NotBefore =< erlang:system_time(second)),
    ?assertEqual(1 * 365 * 24 * 60 * 60, NotAfter - NotBefore),

    ?assertEqual(5, length(Extensions)),
    % lists:search(fun(moo) -> false end, Extensions),

    ok.

to_otp(#'Certificate'{} = Certificate) ->
    DER = public_key:der_encode('Certificate', Certificate),
    public_key:pkix_decode_cert(DER, otp).

parse_validity(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    {erl509_time:decode_time(NotBefore), erl509_time:decode_time(NotAfter)}.

% TODO: issuing intermediate CA certificate.
% TODO: issuing client certificates.
% All of the above should flush out some extension details (particularly SKID and AKID).
