-module(erl509_openssl_ec_key_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

ec_from_pem_test() ->
    % We generated an EC key with openssl; can we read it in?
    Pem = read_file("openssl-ec.key"),
    Key = erl509_private_key:from_pem(Pem),
    ?assertEqual(expected_key(), Key),

    % Do we write the same thing back out?
    ?assertEqual(
        get_ec_private_key_from_pem(Pem), strip_trailing_lf(erl509_private_key:to_pem(Key, []))
    ),
    ok.

ec_from_pkcs8_pem_test() ->
    % Wrapped in PKCS#8; can we read it in?
    Pem = read_file("openssl-ec-p8.key"),
    Key = erl509_private_key:from_pem(Pem),
    ?assertEqual(expected_key(), Key),

    % Do we write the same thing back out?
    ?assertEqual(Pem, strip_trailing_lf(erl509_private_key:to_pem(Key, [wrap]))),
    ok.

read_file(Name) ->
    Path = filename:join(["test", atom_to_list(?MODULE), Name]),
    {ok, Data} = file:read_file(Path),
    Data.

% openssl puts one LF at the end; Erlang puts two.
strip_trailing_lf(Bytes) ->
    binary:part(Bytes, 0, byte_size(Bytes) - 1).

% openssl puts EC PARAMETERS at the start; skip over that.
get_ec_private_key_from_pem(Pem) ->
    Lines = binary:split(Pem, <<"\n">>, [global]),
    get_ec_private_key_from_pem2(Lines).

get_ec_private_key_from_pem2([<<"-----BEGIN EC PRIVATE KEY-----">> = Line | Rest]) ->
    iolist_to_binary(lists:join(<<"\n">>, [Line | Rest]));
get_ec_private_key_from_pem2([_ | Rest]) ->
    get_ec_private_key_from_pem2(Rest).

expected_key() ->
    #'ECPrivateKey'{
        version = 1,
        privateKey =
            <<252, 154, 145, 134, 232, 2, 96, 49, 47, 227, 72, 197, 11, 45, 90, 235, 146, 91, 111,
                27, 91, 53, 20, 62, 87, 104, 244, 48, 51, 207, 160, 137>>,
        parameters = {namedCurve, ?'secp256r1'},
        publicKey =
            <<4, 35, 213, 105, 17, 175, 178, 238, 31, 242, 12, 54, 228, 192, 166, 24, 251, 34, 7,
                215, 118, 40, 181, 187, 92, 93, 154, 239, 255, 115, 172, 168, 96, 37, 181, 46, 234,
                24, 74, 200, 149, 24, 87, 241, 87, 24, 15, 250, 21, 255, 56, 48, 78, 206, 29, 72,
                19, 146, 1, 238, 32, 103, 152, 162, 61>>,
        attributes = asn1_NOVALUE
    }.
