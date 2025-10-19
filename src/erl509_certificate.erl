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
    to_pem/1,
    from_pem/1,

    to_der/1,
    from_der/1
]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type t() :: #'Certificate'{}.

-spec create_self_signed(
    PrivateKey :: erl509_private_key:t(), Subject :: binary(), Options :: map()
) -> t().

create_self_signed(PrivateKey, Subject, Options) when
    is_binary(Subject)
->
    Options2 = apply_default_options(Options),
    SerialNumber = create_serial_number(Options2),

    SignatureAlgorithm = get_signature_algorithm(PrivateKey),
    SubjectPub = erl509_private_key:derive_public_key(PrivateKey),

    % It's self-signed, so the issuer and subject are the same.
    Issuer = Subject,

    SubjectRdn = erl509_rdn_seq:create(Subject),
    IssuerRdn = erl509_rdn_seq:create(Issuer),

    Validity = create_validity(Options2),
    #{extensions := Extensions0} = Options2,
    create_certificate(
        SubjectPub,
        SubjectRdn,
        PrivateKey,
        IssuerRdn,
        SerialNumber,
        Validity,
        SignatureAlgorithm,
        Extensions0
    ).

create(SubjectPub, Subject, IssuerCertificate, IssuerKey, Options) ->
    Options2 = apply_default_options(Options),
    SerialNumber = create_serial_number(Options2),

    SignatureAlgorithm = get_signature_algorithm(IssuerKey),

    SubjectRdn = erl509_rdn_seq:create(Subject),

    % Get Issuer from IssuerCertificate.
    IssuerRdn = get_issuer_rdn(IssuerCertificate),

    Validity = create_validity(Options2),
    #{extensions := Extensions0} = Options2,
    create_certificate(
        SubjectPub,
        SubjectRdn,
        IssuerKey,
        IssuerRdn,
        SerialNumber,
        Validity,
        SignatureAlgorithm,
        Extensions0
    ).

create_certificate(
    SubjectPub,
    SubjectRdn,
    IssuerKey,
    IssuerRdn,
    SerialNumber,
    Validity,
    SignatureAlgorithm,
    Extensions0
) ->
    SubjectPublicKeyInfo = create_subject_public_key_info(SubjectPub),
    IssuerPub = erl509_private_key:derive_public_key(IssuerKey),

    Extensions = create_extensions(Extensions0, SubjectPub, IssuerPub),

    % Create the certificate entity. It's an OTPTBSCertificate.
    Certificate = #'OTPTBSCertificate'{
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

    from_der(public_key:pkix_sign(Certificate, IssuerKey)).

apply_default_options(Options) ->
    DefaultOptions = #{serial_number => random, validity => 365, extensions => #{}},
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
    #'SignatureAlgorithm'{
        algorithm = ?sha256WithRSAEncryption,
        parameters = {'asn1_OPENTYPE', ?DER_NULL}
    };
get_signature_algorithm(#'ECPrivateKey'{}) ->
    #'SignatureAlgorithm'{
        algorithm = ?'ecdsa-with-SHA256',
        parameters = asn1_NOVALUE
    }.

create_subject_public_key_info(#'RSAPublicKey'{} = RSAPublicKey) ->
    #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = 'NULL'},
        subjectPublicKey = RSAPublicKey
    };
create_subject_public_key_info({#'ECPoint'{} = ECPoint, Parameters}) ->
    #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{
            algorithm = ?'id-ecPublicKey',
            parameters = Parameters
        },
        subjectPublicKey = ECPoint
    }.

-spec create_extensions(
    Extensions0 :: map(), SubjectPub :: erl509_public_key:t(), IssuerPub :: erl509_public_key:t()
) -> [#'Extension'{}].

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

get_public_key(#'OTPCertificate'{tbsCertificate = TbsCertificate} = _Certificate) ->
    get_public_key(TbsCertificate);
get_public_key(#'OTPTBSCertificate'{subjectPublicKeyInfo = SubjectPublicKeyInfo} = _TbsCertificate) ->
    erl509_public_key:unwrap(SubjectPublicKeyInfo);
get_public_key(#'Certificate'{tbsCertificate = TbsCertificate} = _Certificate) ->
    get_public_key(TbsCertificate);
get_public_key(#'TBSCertificate'{subjectPublicKeyInfo = SubjectPublicKeyInfo} = _TbsCertificate) ->
    erl509_public_key:unwrap(SubjectPublicKeyInfo).

get_issuer_rdn(#'OTPCertificate'{tbsCertificate = TbsCertificate}) ->
    get_issuer_rdn(TbsCertificate);
get_issuer_rdn(#'OTPTBSCertificate'{subject = IssuerRdn}) ->
    IssuerRdn.

get_extension(
    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{extensions = Extensions}}, ExtnID
) ->
    case lists:search(fun(#'Extension'{extnID = ID}) -> ID == ExtnID end, Extensions) of
        {value, Extension} -> Extension;
        false -> undefined
    end;
get_extension(#'Certificate'{} = Certificate, ExtnID) ->
    OTPCert = public_key:pkix_decode_cert(to_der(Certificate), otp),
    get_extension(OTPCert, ExtnID).

from_pem(Pem) when is_binary(Pem) ->
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    from_der(Der).

to_pem(Certificate) ->
    public_key:pem_encode([{'Certificate', to_der(Certificate), not_encrypted}]).

to_der(#'OTPCertificate'{} = Certificate) ->
    public_key:pkix_encode('OTPCertificate', Certificate, otp);
to_der(#'Certificate'{} = Certificate) ->
    public_key:pkix_encode('Certificate', Certificate, plain).

from_der(Der) when is_binary(Der) ->
    public_key:pkix_decode_cert(Der, otp).

-ifdef(TEST).
create_extensions_test_() ->
    PrivateKey = erl509_private_key:create_rsa(2048),
    PublicKey = erl509_private_key:derive_public_key(PrivateKey),
    [
        % subject_key_identifier and authority_key_identifier are boolean, and control whether the actual identifiers
        % are added as extensions.
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
        ),
        % here we omit them.
        ?_assertEqual([], create_extensions(#{}, PublicKey, PublicKey))
    ].
-endif.
