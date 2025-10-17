-module(erl509_certificate_rsa_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

self_signed_rsa_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    RSAPublicKey = erl509_private_key:derive_public_key(RSAPrivateKey),
    Certificate = erl509_certificate:create_self_signed(
        RSAPrivateKey, <<"CN=example">>, erl509_certificate_template:root_ca()
    ),
    % PEM = erl509_certificate:to_pem(Certificate),
    % ?assertEqual(Certificate, erl509_certificate:from_pem(PEM)),
    _DER = erl509_certificate:to_der(Certificate),

    ?assert(pubkey_cert:is_self_signed(Certificate)),

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
        signature = Signature
    } = Certificate,

    ?assertEqual(2048, 8 * byte_size(Signature)),

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
        signature = Signature
    } = ServerCert,

    ?assertEqual(2048, 8 * byte_size(Signature)),

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
    % TODO: Search the extensions and check they're correct.
    % lists:search(fun(moo) -> false end, Extensions),

    ok.

parse_validity(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    {erl509_time:decode_time(NotBefore), erl509_time:decode_time(NotAfter)}.

% TODO: issuing intermediate CA certificate.
% TODO: issuing client certificates.
% All of the above should flush out some extension details (particularly SKID and AKID).
