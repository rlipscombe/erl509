-module(erl509_certificate_ec_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

self_signed_ec_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    ECPublicKey = erl509_private_key:derive_public_key(ECPrivateKey),
    Certificate = erl509_certificate:create_self_signed(
        ECPrivateKey, <<"CN=example">>, erl509_certificate_template:root_ca()
    ),
    PEM = erl509_certificate:to_pem(Certificate),
    ?assertEqual(Certificate, erl509_certificate:from_pem(PEM)),

    % Round-trip the cert via PEM encoding.
    Cert = erl509_certificate:from_pem(erl509_certificate:to_pem(Certificate)),

    ?assert(pubkey_cert:is_self_signed(Cert)),

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
    } = Cert,
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

% TODO: issuing intermediate CA certificate.
% TODO: issuing client certificates.
% All of the above should flush out some extension details (particularly SKID and AKID).
