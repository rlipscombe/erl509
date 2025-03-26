-module(erl509_private_key).
-export([
    create_rsa/1,
    create_ec/1,

    derive_public_key/1,

    to_pem/1,
    to_pem/2
]).

-include_lib("public_key/include/public_key.hrl").
-define(DER_NULL, <<5, 0>>).

create_rsa(ModulusSize) ->
    create_rsa(ModulusSize, 65537).

create_rsa(ModulusSize, PublicExponent) ->
    public_key:generate_key({rsa, ModulusSize, PublicExponent}).

derive_public_key(#'RSAPrivateKey'{modulus = Modulus, publicExponent = PublicExponent}) ->
    #'RSAPublicKey'{modulus = Modulus, publicExponent = PublicExponent}.

to_pem(PrivateKey) ->
    to_pem(PrivateKey, []).

to_pem(PrivateKey, Opts) ->
    to_pem(PrivateKey, proplists:get_bool(wrapped, Opts), Opts).

to_pem(#'RSAPrivateKey'{} = RSAPrivateKey, _Wrapped = false, _Opts) ->
    public_key:pem_encode([public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey)]);
to_pem(#'RSAPrivateKey'{} = RSAPrivateKey, _Wrapped = true, _Opts) ->
    PrivateKeyInfo = #'PrivateKeyInfo'{
        version = 'v1',
        privateKeyAlgorithm = #'PrivateKeyInfo_privateKeyAlgorithm'{
            algorithm = ?'rsaEncryption',
            parameters = {'asn1_OPENTYPE', ?DER_NULL}
        },
        privateKey = public_key:der_encode('RSAPrivateKey', RSAPrivateKey)
    },

    public_key:pem_encode([public_key:pem_entry_encode('PrivateKeyInfo', PrivateKeyInfo)]).
