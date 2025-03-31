-module(erl509_certificate_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    RSAPublicKey = erl509_private_key:derive_public_key(RSAPrivateKey),
    Certificate = erl509_certificate:create_self_signed(RSAPrivateKey, <<"example">>),
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

ec_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    ECPublicKey = erl509_private_key:derive_public_key(ECPrivateKey),
    Certificate = erl509_certificate:create_self_signed(ECPrivateKey, <<"example">>),
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
    ok.

serial_number_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    Certificate = erl509_certificate:create_self_signed(ECPrivateKey, <<"example">>, #{
        serial_number => 12345
    }),

    OTPCertificate = to_otp(Certificate),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            serialNumber = SerialNumber
        }
    } = OTPCertificate,
    ?assertEqual(12345, SerialNumber),
    ok.

to_otp(#'Certificate'{} = Certificate) ->
    DER = public_key:der_encode('Certificate', Certificate),
    public_key:pkix_decode_cert(DER, otp).
