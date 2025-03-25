-module(erl509_private_key).
-export([create_rsa/1]).
-export([derive_public_key/1]).

-include_lib("public_key/include/public_key.hrl").

create_rsa(ModulusSize) ->
    create_rsa(ModulusSize, 65537).

create_rsa(ModulusSize, PublicExponent) ->
    public_key:generate_key({rsa, ModulusSize, PublicExponent}).

derive_public_key(#'RSAPrivateKey'{modulus = Modulus, publicExponent = PublicExponent}) ->
    #'RSAPublicKey'{modulus = Modulus, publicExponent = PublicExponent}.
