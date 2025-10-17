-module(erl509_certificate).
-export([
    create_self_signed/3,
    create/5
]).
-export([
    get_public_key/1,
    get_extension/2
]).
-export([
    from_pem/1,
    to_pem/1,
    to_der/1
]).

-include_lib("public_key/include/public_key.hrl").
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(DER_NULL, <<5, 0>>).

create_self_signed(PrivateKey, Subject, Options) when
    is_binary(Subject)
->
    Options2 = apply_default_options(Options),
    SerialNumber = create_serial_number(Options2),

    SignatureAlgorithm = get_signature_algorithm(PrivateKey),

    % It's self-signed, so the issuer and subject are the same.
    Issuer = Subject,

    SubjectRdn = erl509_rdn_seq:create(Subject),
    IssuerRdn = erl509_rdn_seq:create(Issuer),

    Validity = create_validity(Options2),

    PublicKey = erl509_private_key:derive_public_key(PrivateKey),

    SubjectPublicKeyInfo = create_subject_public_key_info(PublicKey),

    #{extensions := Extensions0} = Options2,
    Extensions = create_extensions(Extensions0, PublicKey, PublicKey),

    % Create the certificate entity. It's a TBSCertificate.
    TbsCertificate = #'TBSCertificate'{
        version = v3,
        serialNumber = SerialNumber,
        signature = SignatureAlgorithm,
        issuer = IssuerRdn,
        validity = Validity,
        subject = SubjectRdn,
        subjectPublicKeyInfo = SubjectPublicKeyInfo,
        issuerUniqueID = asn1_NOVALUE,
        subjectUniqueID = asn1_NOVALUE,
        extensions = Extensions
    },

    % We sign the DER-encoded TBSCertificate entity.
    TbsCertificateDer = public_key:der_encode('TBSCertificate', TbsCertificate),

    % We're using sha256WithRSAEncryption or ecdsa-with-SHA256, so we sign the certificate with this:
    Signature = public_key:sign(TbsCertificateDer, sha256, PrivateKey),

    #'Certificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm,
        signature = Signature
    }.

create(PublicKey, Subject, IssuerCertificate, IssuerKey, Options) ->
    Options2 = apply_default_options(Options),
    SerialNumber = create_serial_number(Options2),

    SignatureAlgorithm = get_signature_algorithm(IssuerKey),
    IssuerPub = erl509_private_key:derive_public_key(IssuerKey),

    % Get Issuer from IssuerCertificate.
    #'Certificate'{
        tbsCertificate = #'TBSCertificate'{
            subject = IssuerRdn
        }
    } = IssuerCertificate,

    SubjectRdn = erl509_rdn_seq:create(Subject),

    Validity = create_validity(Options2),

    SubjectPublicKeyInfo = create_subject_public_key_info(PublicKey),

    #{extensions := Extensions0} = Options2,
    Extensions = create_extensions(Extensions0, PublicKey, IssuerPub),

    % Create the certificate entity. It's a TBSCertificate.
    TbsCertificate = #'TBSCertificate'{
        version = v3,
        serialNumber = SerialNumber,
        signature = SignatureAlgorithm,
        issuer = IssuerRdn,
        validity = Validity,
        subject = SubjectRdn,
        subjectPublicKeyInfo = SubjectPublicKeyInfo,
        issuerUniqueID = asn1_NOVALUE,
        subjectUniqueID = asn1_NOVALUE,
        extensions = Extensions
    },

    % We sign the DER-encoded TBSCertificate entity.
    TbsCertificateDer = public_key:der_encode('TBSCertificate', TbsCertificate),

    % We're using sha256WithRSAEncryption or ecdsa-with-SHA256, so we sign the certificate with this:
    Signature = public_key:sign(TbsCertificateDer, sha256, IssuerKey),

    #'Certificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm,
        signature = Signature
    }.

apply_default_options(Options) ->
    DefaultOptions = #{serial_number => random, validity => 365},
    maps:merge(DefaultOptions, Options).

create_serial_number(#{serial_number := random} = _Options) ->
    rand:uniform(16#7FFF_FFFF_FFFF_FFFF);
create_serial_number(#{serial_number := SerialNumber} = _Options) when is_integer(SerialNumber) ->
    SerialNumber.

create_validity(#{validity := ExpiryDays} = _Options) ->
    ExpirySeconds = ExpiryDays * 24 * 60 * 60,

    NotBefore = erl509_time:encode_time(erlang:system_time(second)),
    NotAfter = erl509_time:encode_time(erlang:system_time(second) + ExpirySeconds),
    #'Validity'{
        notBefore = NotBefore,
        notAfter = NotAfter
    }.

get_signature_algorithm(#'RSAPrivateKey'{}) ->
    #'AlgorithmIdentifier'{
        algorithm = ?sha256WithRSAEncryption,
        parameters = ?DER_NULL
    };
get_signature_algorithm(#'ECPrivateKey'{}) ->
    #'AlgorithmIdentifier'{
        algorithm = ?'ecdsa-with-SHA256',
        parameters = asn1_NOVALUE
    }.

create_subject_public_key_info(#'RSAPublicKey'{} = RSAPublicKey) ->
    #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{algorithm = ?rsaEncryption, parameters = ?DER_NULL},
        subjectPublicKey = public_key:der_encode('RSAPublicKey', RSAPublicKey)
    };
create_subject_public_key_info({#'ECPoint'{point = Point} = _EC, Parameters}) ->
    #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{
            algorithm = ?'id-ecPublicKey',
            parameters = public_key:der_encode('EcpkParameters', Parameters)
        },
        subjectPublicKey = Point
    }.

-spec create_extensions(
    Extensions0 :: map(), SubjectPub :: erl509_public_key:t(), IssuerPub :: erl509_public_key:t()
) -> map().

create_extensions(Extensions0, SubjectPub, IssuerPub) ->
    maps:fold(
        fun
            (_Key, #'Extension'{} = Extension, Acc) ->
                [Extension | Acc];
            (subject_key_identifier, true, Acc) ->
                Extension = erl509_certificate_extension:create_subject_key_identifier_extension(
                    SubjectPub
                ),
                [Extension | Acc];
            (subject_key_identifier, false, Acc) ->
                Acc;
            (authority_key_identifier, true, Acc) ->
                Extension = erl509_certificate_extension:create_authority_key_identifier_extension(
                    IssuerPub
                ),
                [Extension | Acc];
            (authority_key_identifier, false, Acc) ->
                Acc
        end,
        [],
        Extensions0
    ).

get_public_key(#'Certificate'{tbsCertificate = TbsCertificate} = _Certificate) ->
    get_public_key(TbsCertificate);
get_public_key(#'TBSCertificate'{subjectPublicKeyInfo = SubjectPublicKeyInfo} = _TbsCertificate) ->
    erl509_public_key:unwrap(SubjectPublicKeyInfo).

get_extension(#'Certificate'{} = Certificate, ExtnID) ->
    % TODO: voltone/x509 uses OTPCertificate as the internal representation; we should do the same.
    OTPCert = public_key:pkix_decode_cert(public_key:der_encode('Certificate', Certificate), otp),
    get_extension(OTPCert, ExtnID);
get_extension(
    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{extensions = Extensions}}, ExtnID
) ->
    case lists:search(fun(#'Extension'{extnID = ID}) -> ID == ExtnID end, Extensions) of
        {value, Extension} -> Extension;
        false -> undefined
    end.

from_pem(Pem) when is_binary(Pem) ->
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    from_der(Der).

from_der(Der) when is_binary(Der) ->
    public_key:pkix_decode_cert(Der, plain).

to_pem(#'Certificate'{} = Certificate) ->
    public_key:pem_encode([public_key:pem_entry_encode('Certificate', Certificate)]).

to_der(#'Certificate'{} = Certificate) ->
    public_key:der_encode('Certificate', Certificate).

-ifdef(TEST).
create_extensions_test_() ->
    PrivateKey = erl509_private_key:create_rsa(2048),
    PublicKey = erl509_private_key:derive_public_key(PrivateKey),
    [
        % subject_key_identifier and authority_key_identifier are boolean, and control whether the actual identifiers
        % are added as extensions.
        ?_assertEqual([], create_extensions(#{}, PublicKey, PublicKey)),
        ?_assertMatch(
            [
                #'Extension'{extnID = ?'id-ce-subjectKeyIdentifier'},
                #'Extension'{extnID = ?'id-ce-authorityKeyIdentifier'}
            ],
            lists:sort(
                create_extensions(
                    #{subject_key_identifier => true, authority_key_identifier => true},
                    PublicKey,
                    PublicKey
                )
            )
        )
    ].
-endif.
