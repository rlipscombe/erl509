-module(erl509_certificate_util).
-export([
    get_signature_algorithm/1,
    get_subject_public_key_algorithm/1
]).

-include_lib("public_key/include/public_key.hrl").

get_signature_algorithm(
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            signature = #'SignatureAlgorithm'{algorithm = SignatureAlgorithm}
        }
    }
) ->
    SignatureAlgorithm.

get_subject_public_key_algorithm(#'OTPCertificate'{
    tbsCertificate = #'OTPTBSCertificate'{
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{algorithm = SubjectPublicKeyAlgorithm}
    }
}) ->
    SubjectPublicKeyAlgorithm.
