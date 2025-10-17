-module(erl509_certificate_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

serial_number_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    Certificate = erl509_certificate:create_self_signed(ECPrivateKey, <<"CN=example">>, #{
        serial_number => 12345,
        extensions => #{}
    }),

    OTPCertificate = to_otp(Certificate),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            serialNumber = SerialNumber
        }
    } = OTPCertificate,
    ?assertEqual(12345, SerialNumber),
    ok.

validity_test() ->
    ECPrivateKey = erl509_private_key:create_ec(secp256r1),
    Certificate = erl509_certificate:create_self_signed(ECPrivateKey, <<"CN=example">>, #{
        % in days
        validity => 90,
        extensions => #{}
    }),

    OTPCertificate = to_otp(Certificate),

    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            validity = Validity
        }
    } = OTPCertificate,

    {NotBefore, NotAfter} = parse_validity(Validity),
    ?assert(NotBefore =< erlang:system_time(second)),
    ?assertEqual(90 * 24 * 60 * 60, NotAfter - NotBefore),
    ok.

to_otp(#'Certificate'{} = Certificate) ->
    DER = public_key:der_encode('Certificate', Certificate),
    public_key:pkix_decode_cert(DER, otp).

parse_validity(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    {erl509_time:decode_time(NotBefore), erl509_time:decode_time(NotAfter)}.

% TODO: issuing intermediate CA certificate.
% TODO: issuing client certificates.
% All of the above should flush out some extension details (particularly SKID and AKID).
