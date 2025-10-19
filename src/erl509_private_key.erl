-module(erl509_private_key).
-export([
    create_rsa/1,
    create_ec/1,

    derive_public_key/1,

    to_pem/1,
    to_pem/2,

    to_der/1,

    from_pem/1
]).

-export_type([
    t/0
]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

-type t() :: #'RSAPrivateKey'{} | #'ECPrivateKey'{}.
-type oid() :: tuple().
-type pem_encoded() :: binary().
-type der_encoded() :: binary().

-spec create_rsa(ModulusSize :: non_neg_integer()) -> t().
create_rsa(ModulusSize) ->
    create_rsa(ModulusSize, 65537).

-spec create_rsa(ModulusSize :: non_neg_integer(), PublicExponent :: non_neg_integer()) -> t().
create_rsa(ModulusSize, PublicExponent) ->
    #'RSAPrivateKey'{} = public_key:generate_key({rsa, ModulusSize, PublicExponent}).

-spec create_ec(Curve :: oid() | atom()) -> t().
create_ec(Curve) ->
    #'ECPrivateKey'{} = public_key:generate_key({namedCurve, Curve}).

-spec derive_public_key(Key :: t()) -> erl509_public_key:t().
derive_public_key(#'RSAPrivateKey'{modulus = Modulus, publicExponent = PublicExponent}) ->
    #'RSAPublicKey'{modulus = Modulus, publicExponent = PublicExponent};
derive_public_key(#'ECPrivateKey'{publicKey = Point, parameters = Parameters}) ->
    {#'ECPoint'{point = Point}, Parameters}.

-spec to_pem(PrivateKey :: t()) -> pem_encoded().
to_pem(PrivateKey) ->
    to_pem(PrivateKey, []).

-spec to_pem(PrivateKey :: t(), Opts :: [wrap]) -> pem_encoded().
to_pem(PrivateKey, Opts) ->
    to_pem(PrivateKey, proplists:get_bool(wrap, Opts), Opts).

to_pem(#'RSAPrivateKey'{} = RSAPrivateKey, _Wrapped = false, _Opts) ->
    public_key:pem_encode([public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey)]);
to_pem(#'RSAPrivateKey'{} = RSAPrivateKey, _Wrapped = true, _Opts) ->
    PrivateKeyInfo = wrap(RSAPrivateKey),
    public_key:pem_encode([public_key:pem_entry_encode('PrivateKeyInfo', PrivateKeyInfo)]);
to_pem(#'ECPrivateKey'{} = ECPrivateKey, _Wrapped = false, _Opts) ->
    public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey)]);
to_pem(#'ECPrivateKey'{} = ECPrivateKey, _Wrapped = true, _Opts) ->
    PrivateKeyInfo = wrap(ECPrivateKey),
    public_key:pem_encode([public_key:pem_entry_encode('PrivateKeyInfo', PrivateKeyInfo)]).

-spec to_der(PrivateKey :: t()) -> der_encoded().
to_der(#'RSAPrivateKey'{} = RSAPrivateKey) ->
    public_key:der_encode('RSAPrivateKey', RSAPrivateKey).

wrap(#'RSAPrivateKey'{} = RSAPrivateKey) ->
    #'PrivateKeyInfo'{
        version = 'v1',
        privateKeyAlgorithm = #'PrivateKeyInfo_privateKeyAlgorithm'{
            algorithm = ?'rsaEncryption',
            parameters = {'asn1_OPENTYPE', ?DER_NULL}
        },
        privateKey = public_key:der_encode('RSAPrivateKey', RSAPrivateKey)
    };
wrap(#'ECPrivateKey'{parameters = Parameters} = ECPrivateKey) ->
    #'PrivateKeyInfo'{
        version = 'v1',
        privateKeyAlgorithm = #'PrivateKeyInfo_privateKeyAlgorithm'{
            algorithm = ?'id-ecPublicKey',
            parameters = {'asn1_OPENTYPE', public_key:der_encode('EcpkParameters', Parameters)}
        },
        privateKey = public_key:der_encode('ECPrivateKey', ECPrivateKey#'ECPrivateKey'{
            parameters = asn1_NOVALUE
        })
    }.

-spec from_pem(Pem :: pem_encoded()) -> t().
from_pem(Pem) when is_binary(Pem) ->
    Entries = public_key:pem_decode(Pem),
    {value, Entry} = lists:search(
        fun
            ({'RSAPrivateKey', _, not_encrypted}) -> true;
            ({'PrivateKeyInfo', _, not_encrypted}) -> true;
            ({'ECPrivateKey', _, not_encrypted}) -> true;
            (_) -> false
        end,
        Entries
    ),
    delete_type_(public_key:pem_entry_decode(Entry)).

% Suppress eqwalizer warnings.
delete_type_(Value) -> Value.
