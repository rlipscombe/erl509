-module(erl509_csr).
-export([
    create_csr/2
]).
-export([
    to_pem/1,
    from_pem/1,

    to_der/1
]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

-type t() :: #'CertificationRequest'{}.
-type pem_encoded() :: binary().
-type der_encoded() :: binary().

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
            algorithm = ?'sha256WithRSAEncryption',
            parameters = {'asn1_OPENTYPE', ?DER_NULL}
        },
        signature = Signature
    }.

-spec to_pem(CertificationRequest :: t()) -> binary().

to_pem(CertificationRequest) ->
    Der = to_der(CertificationRequest),
    public_key:pem_encode([{'CertificationRequest', Der, not_encrypted}]).

-spec from_pem(Pem :: pem_encoded()) -> t().

from_pem(Pem) when is_binary(Pem) ->
    [{'CertificationRequest', Der, not_encrypted}] = public_key:pem_decode(Pem),
    public_key:der_decode('CertificationRequest', Der).

-spec to_der(CertificationRequest :: t()) -> der_encoded().

to_der(CertificationRequest) ->
    public_key:der_encode('CertificationRequest', CertificationRequest).
