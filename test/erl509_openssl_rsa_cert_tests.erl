-module(erl509_openssl_rsa_cert_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

rsa_root_ca_from_pem_test() ->
    % We generated a root CA certificate openssl; can we read it in?
    Pem = read_file("openssl-root-ca.crt"),
    Certificate = erl509_certificate:from_pem(Pem),

    % TODO: Assert some things about the certificate?

    % Do we write the same thing back out?
    ?assertEqual(Pem, strip_trailing_lf(erl509_certificate:to_pem(Certificate))),
    ok.

rsa_root_ca_from_der_test() ->
    % We generated a root CA certificate openssl; can we read it in?
    Der = read_file("openssl-root-ca.der.crt"),
    Certificate = erl509_certificate:from_der(Der),

    % TODO: Assert some things about the certificate?

    % Do we write the same thing back out?
    ?assertEqual(Der, erl509_certificate:to_der(Certificate)),
    ok.

issue_cert_using_openssl_root_ca_test() ->
    % Using the openssl root certificate (and key), issue a server certificate.
    %
    % In particular, the AuthorityKeyIdentifier must match the SubjectKeyIdentifier of the root certificate.
    RootKey = erl509_private_key:from_pem(read_file("openssl-root-ca.key")),
    RootCertificate = erl509_certificate:from_pem(read_file("openssl-root-ca.crt")),

    ServerKey = erl509_private_key:create_rsa(2048),
    ServerPub = erl509_public_key:derive_public_key(ServerKey),
    ServerCertificate = erl509_certificate:create(
        ServerPub,
        <<"CN=server">>,
        RootCertificate,
        RootKey,
        erl509_certificate_template:server(#{
            % these are the default anyway, but we'll be explicit.
            authority_key_identifier => true,
            subject_key_identifier => true
        })
    ),

    % It doesn't particularly matter _how_ we generate the SKI, as long as there is one, so we don't need to compare it
    % to (say) openssl.
    ?assertMatch(
        #'Extension'{},
        erl509_certificate:get_extension(ServerCertificate, ?'id-ce-subjectKeyIdentifier')
    ),

    % It _is_ important that we copy the issuer's SKI into our AKI. We _do_ need to compare it to the openssl one.
    ExpectedRootSKI = hex_to_binary(
        <<"8B:ED:22:00:5B:43:40:D1:31:A6:33:DA:C6:4E:89:02:93:42:39:1E">>
    ),
    ?assertEqual(
        #'Extension'{
            extnID = ?'id-ce-subjectKeyIdentifier',
            critical = false,
            extnValue = ExpectedRootSKI
        },
        erl509_certificate:get_extension(RootCertificate, ?'id-ce-subjectKeyIdentifier')
    ),
    ?assertEqual(
        #'Extension'{
            extnID = ?'id-ce-authorityKeyIdentifier',
            critical = false,
            extnValue = #'AuthorityKeyIdentifier'{keyIdentifier = ExpectedRootSKI}
        },
        erl509_certificate:get_extension(ServerCertificate, ?'id-ce-authorityKeyIdentifier')
    ),
    ok.

read_file(Name) ->
    Path = filename:join(["test", atom_to_list(?MODULE), Name]),
    {ok, Data} = file:read_file(Path),
    Data.

% openssl puts one LF at the end; Erlang puts two.
strip_trailing_lf(Bytes) ->
    binary:part(Bytes, 0, byte_size(Bytes) - 1).

hex_to_binary(String) when is_binary(String) ->
    binary:decode_hex(binary:replace(String, <<":">>, <<>>, [global])).
