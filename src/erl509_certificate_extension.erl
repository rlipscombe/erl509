-module(erl509_certificate_extension).
-export([
    create_basic_constraints_extension/1,
    create_basic_constraints_extension/2,

    create_key_usage_extension/1,
    create_extended_key_usage_extension/1,

    create_subject_key_identifier_extension/1,
    create_authority_key_identifier_extension/1,

    create_subject_alt_name_extension/1
]).

-include_lib("public_key/include/public_key.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type t() :: #'Extension'{}.

create_key_usage_extension(KeyUsage) ->
    #'Extension'{
        extnID = ?'id-ce-keyUsage',
        critical = true,
        extnValue = KeyUsage
    }.

-spec create_basic_constraints_extension(IsCA :: boolean()) -> t().

create_basic_constraints_extension(IsCA) ->
    create_basic_constraints_extension(IsCA, asn1_NOVALUE).

-spec create_basic_constraints_extension(
    IsCA :: boolean(),
    PathLenConstraint :: non_neg_integer() | asn1_NOVALUE
) -> t().

create_basic_constraints_extension(IsCA, PathLenConstraint) ->
    #'Extension'{
        extnID = ?'id-ce-basicConstraints',
        critical = true,
        extnValue = #'BasicConstraints'{cA = IsCA, pathLenConstraint = PathLenConstraint}
    }.

create_extended_key_usage_extension(ExtendedKeyUsages) when is_list(ExtendedKeyUsages) ->
    #'Extension'{
        extnID = ?'id-ce-extKeyUsage',
        critical = false,
        extnValue = ExtendedKeyUsages
    }.

-spec create_subject_key_identifier_extension(SubjectPub :: erl509_public_key:t()) -> t().

create_subject_key_identifier_extension(SubjectPub) ->
    % The subjectKeyIdentifier (and authorityKeyIdentifier) extensions are used (instead of the name) to build the
    % certificate path.
    SubjectKeyIdentifier = create_subject_key_identifier(SubjectPub),
    #'Extension'{
        extnID = ?'id-ce-subjectKeyIdentifier',
        critical = false,
        extnValue = SubjectKeyIdentifier
    }.

-spec create_authority_key_identifier_extension(IssuerPub :: erl509_public_key:t()) -> t().

create_authority_key_identifier_extension(IssuerPub) ->
    AuthorityKeyIdentifier = create_authority_key_identifier(IssuerPub),
    #'Extension'{
        extnID = ?'id-ce-authorityKeyIdentifier',
        critical = false,
        extnValue = AuthorityKeyIdentifier
    }.

create_subject_alt_name_extension(Names) ->
    #'Extension'{
        extnID = ?'id-ce-subjectAltName',
        critical = false,
        extnValue = lists:map(fun to_subject_alt_name/1, Names)
    }.

to_subject_alt_name(Name) when is_binary(Name) ->
    {dNSName, Name};
to_subject_alt_name({_, _} = Name) ->
    Name.

-spec create_subject_key_identifier(erl509_public_key:t()) -> binary().

create_subject_key_identifier(Key) ->
    create_key_identifier(Key).

-spec create_authority_key_identifier(erl509_public_key:t() | binary()) ->
    #'AuthorityKeyIdentifier'{}.

create_authority_key_identifier(AKI) when is_binary(AKI) ->
    #'AuthorityKeyIdentifier'{keyIdentifier = AKI};
create_authority_key_identifier(Key) ->
    #'AuthorityKeyIdentifier'{keyIdentifier = create_key_identifier(Key)}.

-spec create_key_identifier(erl509_public_key:t()) -> binary().
create_key_identifier(Key) ->
    % RFC 5280 says "subject key identifiers SHOULD be derived from the public key or a method that generates unique values".
    %
    % It says a common method of doing that is "the 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey".
    %
    % So we'll do that.
    crypto:hash(sha, erl509_public_key:to_der(Key)).

-ifdef(TEST).
basic_constraints_test_() ->
    [
        fun basic_constraints_extension_is_ca/0,
        fun basic_constraints_extension_is_not_ca/0
    ].

basic_constraints_extension_is_ca() ->
    ?assertEqual(
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = true, pathLenConstraint = 3}
        },
        erl509_certificate_extension:create_basic_constraints_extension(true, 3)
    ),
    ok.

basic_constraints_extension_is_not_ca() ->
    ?assertEqual(
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = false, pathLenConstraint = asn1_NOVALUE}
        },
        erl509_certificate_extension:create_basic_constraints_extension(false)
    ),
    ok.

key_identifier_test_() ->
    {setup,
        fun() ->
            PrivateKey = erl509_private_key:create_rsa(2048),
            PublicKey = erl509_private_key:derive_public_key(PrivateKey),
            #{private => PrivateKey, public => PublicKey}
        end,

        {with, [
            fun subject_key_identifier_is_hash/1,
            fun authority_key_identifier_is_aki_record/1
        ]}}.

subject_key_identifier_is_hash(#{public := PublicKey}) ->
    #'Extension'{
        extnID = ?'id-ce-subjectKeyIdentifier', critical = false, extnValue = Value
    } = erl509_certificate_extension:create_subject_key_identifier_extension(PublicKey),
    % SubjectKeyIdentifier is just the hash, not a record.
    Hash = crypto:hash(sha, erl509_public_key:to_der(PublicKey)),
    ?assertEqual(Hash, Value),
    ok.

authority_key_identifier_is_aki_record(#{public := PublicKey}) ->
    #'Extension'{
        extnID = ?'id-ce-authorityKeyIdentifier', critical = false, extnValue = Value
    } = erl509_certificate_extension:create_authority_key_identifier_extension(PublicKey),
    % AuthorityKeyIdentifier is a record.
    #'AuthorityKeyIdentifier'{
        keyIdentifier = AuthorityKeyIdentifier,
        authorityCertIssuer = asn1_NOVALUE,
        authorityCertSerialNumber = asn1_NOVALUE
    } = Value,
    Hash = crypto:hash(sha, erl509_public_key:to_der(PublicKey)),
    ?assertEqual(Hash, AuthorityKeyIdentifier),
    ok.
-endif.
