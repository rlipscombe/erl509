-module(erl509_csr).
-export([
    create_csr/2
]).
-export([
    to_pem/1,

    to_der/1
]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

-type t() :: #'CertificationRequest'{}.

-spec create_csr(
    SubjectPrivateKey :: erl509_private_key:t(), Subject :: binary()
) -> t().

create_csr(SubjectPrivateKey, Subject) ->
    HashAlgorithm = sha256,

    SubjectPublicKey = erl509_private_key:derive_public_key(SubjectPrivateKey),
    SubjectRdn = erl509_rdn_seq:create(Subject),

    CertificationRequestInfo = #'CertificationRequestInfo'{
        version = v1,
        subject = SubjectRdn,
        subjectPKInfo = erl509_public_key:wrap(
            SubjectPublicKey, 'CertificationRequestInfo_subjectPKInfo'
        ),
        attributes = []
    },

    Der = public_key:der_encode('CertificationRequestInfo', CertificationRequestInfo),

    Signature = public_key:sign(Der, HashAlgorithm, SubjectPrivateKey),
    #'CertificationRequest'{
        certificationRequestInfo = CertificationRequestInfo,
        signatureAlgorithm = #'CertificationRequest_signatureAlgorithm'{
            algorithm = ?'rsaEncryption',
            parameters = {'asn1_OPENTYPE', ?DER_NULL}
        },
        signature = Signature
    }.

-spec to_pem(CertificationRequest :: t()) -> binary().

to_pem(CertificationRequest) ->
    Der = to_der(CertificationRequest),
    public_key:pem_encode([{'CertificationRequest', Der, not_encrypted}]).

-spec to_der(CertificationRequest :: t()) -> public_key:der_encoded().

to_der(CertificationRequest) ->
    public_key:der_encode('CertificationRequest', CertificationRequest).
