-module(erl509_certificate_tests).
-include_lib("eunit/include/eunit.hrl").

is_self_signed_test() ->
    RSAPrivateKey = erl509_private_key:create_rsa(2048),
    Certificate = erl509_certificate:create_self_signed(RSAPrivateKey, <<"example">>),
    CertificateDer = public_key:der_encode('Certificate', Certificate),
    OTPCertificate = public_key:pkix_decode_cert(CertificateDer, otp),
    ?assert(pubkey_cert:is_self_signed(OTPCertificate)).
