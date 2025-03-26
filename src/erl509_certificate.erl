-module(erl509_certificate).
-export([create_self_signed/2]).
-export([to_pem/1]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

create_self_signed(RSAPrivateKey = #'RSAPrivateKey'{}, Subject) when
    is_binary(Subject)
->
    % We need a serial number. Random will do for now.
    SerialNumber = rand:uniform(16#7FFF_FFFF_FFFF_FFFF),

    SignatureAlgorithm = #'AlgorithmIdentifier'{
        algorithm = ?sha256WithRSAEncryption,
        parameters = ?DER_NULL
    },

    % It's self-signed, so the issuer and subject are the same.
    Issuer = Subject,

    % Note that create_rdn currently assumes that the subject is a CN.
    SubjectRdn = erl509_rdn:create_rdn(Subject),
    IssuerRdn = erl509_rdn:create_rdn(Issuer),

    % 10 years in seconds.
    ExpirySeconds = 10 * 365 * 24 * 60 * 60,

    NotBefore = erl509_time:encode_time(erlang:system_time(second)),
    NotAfter = erl509_time:encode_time(erlang:system_time(second) + ExpirySeconds),
    Validity = #'Validity'{
        notBefore = NotBefore,
        notAfter = NotAfter
    },

    RSAPublicKey = erl509_private_key:derive_public_key(RSAPrivateKey),

    SubjectPublicKeyInfo = #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{algorithm = ?rsaEncryption, parameters = ?DER_NULL},
        subjectPublicKey = public_key:der_encode('RSAPublicKey', RSAPublicKey)
    },

    % The subject key identifier is used by our issued certificates to refer to this certificate.
    SubjectKeyIdentifier = create_subject_key_identifier(RSAPublicKey),

    % These are suitable default extensions for a CA certificate.
    DefaultExtensions = [
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = public_key:der_encode('KeyUsage', [
                digitalSignature, keyEncipherment, keyCertSign
            ])
        },
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = public_key:der_encode('BasicConstraints', #'BasicConstraints'{cA = true})
        },
        #'Extension'{
            extnID = ?'id-ce-subjectKeyIdentifier',
            critical = false,
            extnValue = public_key:der_encode('SubjectKeyIdentifier', SubjectKeyIdentifier)
        }
    ],

    % For now, we'll add a SAN using the subject name.
    Hostname = Subject,

    Extensions =
        DefaultExtensions ++
            [
                #'Extension'{
                    extnID = ?'id-ce-subjectAltName',
                    critical = false,
                    extnValue = public_key:der_encode('SubjectAltName', [{dNSName, Hostname}])
                }
            ],

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

    % We're using sha256WithRSAEncryption, so we sign the certificate with this:
    Signature = public_key:sign(TbsCertificateDer, sha256, RSAPrivateKey),

    #'Certificate'{
        tbsCertificate = TbsCertificate,
        signatureAlgorithm = SignatureAlgorithm,
        signature = Signature
    }.

create_subject_key_identifier(RSAPublicKey = #'RSAPublicKey'{}) ->
    % RFC 5280 says "subject key identifiers SHOULD be derived from the public key or a method that generates unique values".
    %
    % It says a common method of doing that is "the 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey".
    %
    % So we'll do that.
    crypto:hash(sha, public_key:der_encode('RSAPublicKey', RSAPublicKey)).

to_pem(#'Certificate'{} = Certificate) ->
    public_key:pem_encode([public_key:pem_entry_encode('Certificate', Certificate)]).
