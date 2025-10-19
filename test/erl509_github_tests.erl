-module(erl509_github_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% The certificates used by github.com have interesting extensions; can we replicate that?
github_test_() ->
    RootKey = erl509_private_key:create_ec(secp384r1),
    RootSubject =
        <<"C=US, ST=New Jersey, L=Jersey City, O=Not The USERTRUST Network, CN=Not USERTrust ECC Certification Authority">>,
    _RootCertificate = erl509_certificate:create_self_signed(
        RootKey, RootSubject, erl509_certificate_template:root_ca()
    ),

    [
        {"root certificate signature algorithm", ?_assert(false)},
        {"root certificate spki", ?_assert(false)},
        {"root certificate not after 2038", ?_assert(false)},
        {"root certificate extension ski", ?_assert(false)},
        {"root certificate extension has no aki", ?_assert(false)},
        {"root certificate key usage", ?_assert(false)},
        {"root certificate basic constraints", ?_assert(false)}
    ].
