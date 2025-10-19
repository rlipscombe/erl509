-module(erl509_public_key).
-export([
    derive_public_key/1,

    wrap/1,
    unwrap/1,

    to_pem/1,
    to_pem/2,

    to_der/1
]).

-export_type([
    t/0
]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

-type t() :: #'RSAPublicKey'{} | {#'ECPoint'{}, {namedCurve, _}}.

derive_public_key(PrivateKey) ->
    erl509_private_key:derive_public_key(PrivateKey).

to_pem(PublicKey) ->
    to_pem(PublicKey, []).

to_pem(PublicKey, Opts) ->
    to_pem(PublicKey, proplists:get_bool(wrap, Opts), Opts).

to_pem(#'RSAPublicKey'{} = RSAPublicKey, _Wrapped = false, _Opts) ->
    public_key:pem_encode([public_key:pem_entry_encode('RSAPublicKey', RSAPublicKey)]);
to_pem(#'RSAPublicKey'{} = RSAPublicKey, _Wrapped = true, _Opts) ->
    SubjectPublicKeyInfo = wrap(RSAPublicKey),
    public_key:pem_encode([
        public_key:pem_entry_encode('SubjectPublicKeyInfo', SubjectPublicKeyInfo)
    ]);
to_pem({#'ECPoint'{point = _}, _} = ECPublicKey, _Wrapped, _Opts) ->
    SubjectPublicKeyInfo = wrap(ECPublicKey),
    public_key:pem_encode([
        public_key:pem_entry_encode('SubjectPublicKeyInfo', SubjectPublicKeyInfo)
    ]).

to_der(PublicKey) ->
    to_der(PublicKey, [wrap]).

to_der(PublicKey, Opts) ->
    case proplists:get_bool(wrap, Opts) of
        true ->
            der_encode(wrap(PublicKey));
        false ->
            der_encode(PublicKey)
    end.

der_encode(#'SubjectPublicKeyInfo'{} = SubjectPublicKeyInfo) ->
    public_key:der_encode('SubjectPublicKeyInfo', SubjectPublicKeyInfo).

wrap(#'RSAPublicKey'{} = RSAPublicKey) ->
    #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{
            algorithm = ?'rsaEncryption',
            parameters = ?DER_NULL
        },
        subjectPublicKey = public_key:der_encode('RSAPublicKey', RSAPublicKey)
    };
wrap({#'ECPoint'{point = Point}, Parameters}) ->
    #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{
            algorithm = ?'id-ecPublicKey',
            parameters = maybe_encode_parameters(Parameters)
        },
        subjectPublicKey = Point
    }.

maybe_encode_parameters(Parameters) ->
    maybe_encode_parameters(Parameters, application:get_key(public_key, vsn)).

maybe_encode_parameters('NULL' = _Parameters, {ok, V}) when V >= "1.18" ->
    'NULL';
maybe_encode_parameters(Parameters, {ok, V}) when V >= "1.18" ->
    Parameters;
maybe_encode_parameters('NULL' = _Parameters, {ok, _V}) ->
    ?DER_NULL;
maybe_encode_parameters(Parameters, {ok, _}) ->
    public_key:der_encode('EcpkParameters', Parameters).

unwrap(
    #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{algorithm = ?rsaEncryption, parameters = _},
        subjectPublicKey = SubjectPublicKey
    } = _SubjectPublicKeyInfo
) ->
    SubjectPublicKey;
unwrap(
    #'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{algorithm = ?rsaEncryption, parameters = _},
        subjectPublicKey = SubjectPublicKey
    } = _SubjectPublicKeyInfo
) ->
    public_key:der_decode('RSAPublicKey', SubjectPublicKey).
