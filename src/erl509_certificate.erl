-module(erl509_certificate).
-export([
    create_self_signed/3,
    create/5
]).
-export([
    get_public_key/1,
    get_validity/1,
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

-type t() :: #'OTPCertificate'{}.

-spec create_self_signed(
    PrivateKey :: erl509_private_key:t(), Subject :: binary(), Options :: map()
) -> t().

create_self_signed(PrivateKey, Subject, Options) when
    is_binary(Subject)
->
    Options2 = apply_default_options(Options),
    SerialNumber = create_serial_number(Options2),

    SignatureAlgorithm = get_signature_algorithm(PrivateKey, Options2),
    SubjectPub = erl509_private_key:derive_public_key(PrivateKey),

    % It's self-signed, so the issuer and subject are the same.
    Issuer = Subject,

    SubjectRdn = erl509_rdn_seq:create(Subject),
    IssuerRdn = erl509_rdn_seq:create(Issuer),

    Validity = create_validity(Options2),
    Extensions = create_extensions(Options2, SubjectPub, SubjectPub),
    create_certificate(
        SubjectPub,
        SubjectRdn,
        PrivateKey,
        IssuerRdn,
        SerialNumber,
        Validity,
        SignatureAlgorithm,
        Extensions
    ).

-spec create(
    SubjectPub :: erl509_public_key:t(),
    Subject :: binary(),
    IssuerCertificate :: erl509_certificate:t(),
    IssuerKey :: erl509_private_key:t(),
    Options :: map()
) -> t().

create(SubjectPub, Subject, IssuerCertificate, IssuerKey, Options) ->
    Options2 = apply_default_options(Options),
    SerialNumber = create_serial_number(Options2),

    SignatureAlgorithm = get_signature_algorithm(IssuerKey, Options2),

    SubjectRdn = erl509_rdn_seq:create(Subject),

    % Get Issuer from IssuerCertificate.
    IssuerRdn = get_issuer_rdn(IssuerCertificate),

    Validity = create_validity(Options2),
    Extensions = create_extensions(Options2, SubjectPub, IssuerCertificate),
    create_certificate(
        SubjectPub,
        SubjectRdn,
        IssuerKey,
        IssuerRdn,
        SerialNumber,
        Validity,
        SignatureAlgorithm,
        Extensions
    ).

create_certificate(
    SubjectPub,
    SubjectRdn,
    IssuerKey,
    IssuerRdn,
    SerialNumber,
    Validity,
    SignatureAlgorithm,
    Extensions
) ->
    SubjectPublicKeyInfo = create_subject_public_key_info(SubjectPub),

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
    DefaultOptions = #{
        serial_number => random,
        validity => 365,
        hash_algorithm => sha256,
        extensions => #{}
    },
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

get_signature_algorithm(#'RSAPrivateKey'{}, #{hash_algorithm := sha256}) ->
    #'SignatureAlgorithm'{
        algorithm = ?sha256WithRSAEncryption,
        parameters = {'asn1_OPENTYPE', ?DER_NULL}
    };
get_signature_algorithm(#'ECPrivateKey'{}, #{hash_algorithm := sha256}) ->
    #'SignatureAlgorithm'{
        algorithm = ?'ecdsa-with-SHA256',
        parameters = asn1_NOVALUE
    };
get_signature_algorithm(#'ECPrivateKey'{}, #{hash_algorithm := sha384}) ->
    #'SignatureAlgorithm'{
        algorithm = ?'ecdsa-with-SHA384',
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
    Extensions0 :: map(),
    SubjectPub :: erl509_public_key:t(),
    Issuer :: erl509_public_key:t() | erl509_certificate:t()
) -> [#'Extension'{}].

create_extensions(#{extensions := Extensions} = _Options, SubjectPub, Issuer) ->
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
                Extension = create_authority_key_identifier_extension(Issuer),
                [Extension | Acc];
            (authority_key_identifier, false, Acc) ->
                Acc
        end,
        [],
        Extensions
    ).

% Note that voltone/x509 also allows an arbitrary binary for the AKI.
create_authority_key_identifier_extension(#'OTPCertificate'{} = Issuer) ->
    #'Extension'{extnValue = SKI} = get_extension(Issuer, ?'id-ce-subjectKeyIdentifier'),
    create_authority_key_identifier_extension(SKI);
create_authority_key_identifier_extension(Issuer) ->
    erl509_certificate_extension:create_authority_key_identifier_extension(Issuer).

get_issuer_rdn(#'OTPCertificate'{tbsCertificate = TbsCertificate}) ->
    get_issuer_rdn(TbsCertificate);
get_issuer_rdn(#'OTPTBSCertificate'{subject = IssuerRdn}) ->
    IssuerRdn.

-spec get_public_key(
    Certificate ::
        #'OTPCertificate'{} | #'OTPTBSCertificate'{} | #'Certificate'{} | #'TBSCertificate'{}
) -> erl509_public_key:t().

get_public_key(#'OTPCertificate'{tbsCertificate = TbsCertificate} = _Certificate) ->
    get_public_key(TbsCertificate);
get_public_key(#'OTPTBSCertificate'{subjectPublicKeyInfo = SubjectPublicKeyInfo} = _TbsCertificate) ->
    erl509_public_key:unwrap(SubjectPublicKeyInfo);
get_public_key(#'Certificate'{tbsCertificate = TbsCertificate} = _Certificate) ->
    get_public_key(TbsCertificate);
get_public_key(#'TBSCertificate'{subjectPublicKeyInfo = SubjectPublicKeyInfo} = _TbsCertificate) ->
    erl509_public_key:unwrap(SubjectPublicKeyInfo).

-spec get_validity(Certificate :: #'OTPCertificate'{} | #'OTPTBSCertificate'{}) -> #'Validity'{}.

get_validity(#'OTPCertificate'{tbsCertificate = TbsCertificate} = _Certificate) ->
    get_validity(TbsCertificate);
get_validity(#'OTPTBSCertificate'{validity = Validity}) ->
    Validity.

get_extension(
    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{extensions = Extensions}}, ExtnID
) when is_tuple(ExtnID) ->
    case lists:search(fun(#'Extension'{extnID = ID}) -> ID == ExtnID end, Extensions) of
        {value, Extension} -> Extension;
        false -> undefined
    end;
get_extension(#'Certificate'{} = Certificate, ExtnID) when is_tuple(ExtnID) ->
    OTPCert = public_key:pkix_decode_cert(to_der(Certificate), otp),
    get_extension(OTPCert, ExtnID).

from_pem(Pem) when is_binary(Pem) ->
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    from_der(Der).

-spec to_pem(Certificate :: #'OTPCertificate'{} | #'Certificate'{}) -> binary().

to_pem(Certificate) ->
    Der = to_der(Certificate),
    public_key:pem_encode([{'Certificate', Der, not_encrypted}]).

-spec to_der(Certificate :: #'OTPCertificate'{} | #'Certificate'{}) -> public_key:der_encoded().

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
                    #{
                        extensions => #{
                            subject_key_identifier => true, authority_key_identifier => true
                        }
                    },
                    PublicKey,
                    PublicKey
                )
            )
        ),
        % here we omit them.
        ?_assertEqual([], create_extensions(#{extensions => #{}}, PublicKey, PublicKey))
    ].
-endif.
