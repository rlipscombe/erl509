-module(erl509_cli).
-export([main/1]).

main(Args) ->
    Command = #{
        commands => #{
            "self-signed" => #{
                handler => fun self_signed/1,
                arguments => [
                    #{name => out_cert, long => "-out-cert", required => true},
                    #{name => out_key, long => "-out-key", required => true},
                    #{
                        name => template,
                        long => "-template",
                        required => true,
                        type => {atom, [root_ca, server]}
                    },
                    #{name => subject, long => "-subject", required => true, type => binary}
                ]
            },

            "create-cert" => #{
                handler => fun create_cert/1,
                arguments => [
                    #{name => issuer_cert, long => "-issuer-cert", required => true},
                    #{name => issuer_key, long => "-issuer-key", required => true},
                    #{name => out_cert, long => "-out-cert", required => true},
                    #{name => out_key, long => "-out-key", required => true},
                    #{
                        name => template,
                        long => "-template",
                        required => true,
                        type => {atom, [root_ca, server]}
                    },
                    #{name => subject, long => "-subject", required => true, type => binary}
                ]
            }
        }
    },
    argparse:run(Args, Command, #{progname => erl509}).

self_signed(Args = #{out_cert := OutCert, out_key := OutKey, subject := Subject}) ->
    PrivateKey = erl509_private_key:create_rsa(2048),
    ok = file:write_file(OutKey, erl509_private_key:to_pem(PrivateKey)),
    Options = get_certificate_options(Args),
    Certificate = erl509_certificate:create_self_signed(PrivateKey, Subject, Options),
    ok = file:write_file(OutCert, erl509_certificate:to_pem(Certificate)).

create_cert(
    Args = #{
        issuer_cert := IssuerCertFile,
        issuer_key := IssuerKeyFile,
        out_cert := OutCert,
        out_key := OutKey,
        subject := Subject
    }
) ->
    PrivateKey = erl509_private_key:create_rsa(2048),
    PublicKey = erl509_public_key:derive_public_key(PrivateKey),
    ok = file:write_file(OutKey, erl509_private_key:to_pem(PrivateKey)),

    {ok, IssuerCertPem} = file:read_file(IssuerCertFile),
    IssuerCertificate = erl509_certificate:from_pem(IssuerCertPem),

    {ok, IssuerKeyPem} = file:read_file(IssuerKeyFile),
    IssuerKey = erl509_private_key:from_pem(IssuerKeyPem),

    Options = get_certificate_options(Args),
    Certificate = erl509_certificate:create(
        PublicKey, Subject, IssuerCertificate, IssuerKey, Options
    ),
    ok = file:write_file(OutCert, erl509_certificate:to_pem(Certificate)).

get_certificate_options(#{template := root_ca}) ->
    erl509_certificate_template:root_ca();
get_certificate_options(#{template := server}) ->
    erl509_certificate_template:server().
