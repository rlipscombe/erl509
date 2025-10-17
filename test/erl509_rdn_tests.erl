-module(erl509_rdn_tests).
-include_lib("eunit/include/eunit.hrl").

-include_lib("public_key/include/public_key.hrl").

create_rdn_test_() ->
    [
        ?_assertEqual(
            [
                #'AttributeTypeAndValue'{
                    type = ?'id-at-commonName', value = {printableString, <<"example-ca">>}
                }
            ],
            erl509_rdn:create_rdn(<<"CN=example-ca">>)
        )
    ].
