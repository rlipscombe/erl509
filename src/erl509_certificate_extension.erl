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

create_key_usage_extension(KeyUsage) ->
    #'Extension'{
        extnID = ?'id-ce-keyUsage',
        critical = true,
        extnValue = public_key:der_encode('KeyUsage', KeyUsage)
    }.

create_basic_constraints_extension(IsCA) ->
    create_basic_constraints_extension(IsCA, asn1_NOVALUE).

create_basic_constraints_extension(IsCA, PathLenConstraint) ->
    #'Extension'{
        extnID = ?'id-ce-basicConstraints',
        critical = true,
        extnValue = public_key:der_encode('BasicConstraints', #'BasicConstraints'{
            cA = IsCA, pathLenConstraint = PathLenConstraint
        })
    }.

create_extended_key_usage_extension(ExtendedKeyUsages) when is_list(ExtendedKeyUsages) ->
    #'Extension'{
        extnID = ?'id-ce-extKeyUsage',
        critical = false,
        extnValue = public_key:der_encode('ExtKeyUsageSyntax', ExtendedKeyUsages)
    }.

create_subject_key_identifier_extension(SubjectPub) ->
    % The subjectKeyIdentifier (and authorityKeyIdentifier) extensions are used (instead of the name) to build the
    % certificate path.
    SubjectKeyIdentifier = create_subject_key_identifier(SubjectPub),
    #'Extension'{
        extnID = ?'id-ce-subjectKeyIdentifier',
        critical = false,
        extnValue = public_key:der_encode('SubjectKeyIdentifier', SubjectKeyIdentifier)
    }.

create_authority_key_identifier_extension(IssuerPub) ->
    AuthorityKeyIdentifier = create_authority_key_identifier(IssuerPub),
    #'Extension'{
        extnID = ?'id-ce-authorityKeyIdentifier',
        critical = false,
        extnValue = public_key:der_encode('AuthorityKeyIdentifier', AuthorityKeyIdentifier)
    }.

create_subject_alt_name_extension(Names) ->
    #'Extension'{
        extnID = ?'id-ce-subjectAltName',
        critical = false,
        extnValue = public_key:der_encode('SubjectAltName', lists:map(fun to_subject_alt_name/1, Names))
    }.

to_subject_alt_name(Name) when is_binary(Name) ->
    {dNSName, Name};
to_subject_alt_name({_, _} = Name) ->
    Name.

create_subject_key_identifier(Key) ->
    create_key_identifier(Key).

create_authority_key_identifier(Key) ->
    #'AuthorityKeyIdentifier'{keyIdentifier = create_key_identifier(Key)}.

create_key_identifier(#'RSAPublicKey'{} = RSAPublicKey) ->
    % RFC 5280 says "subject key identifiers SHOULD be derived from the public key or a method that generates unique values".
    %
    % It says a common method of doing that is "the 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey".
    %
    % So we'll do that.
    crypto:hash(sha, public_key:der_encode('RSAPublicKey', RSAPublicKey));
create_key_identifier({#'ECPoint'{point = Point} = _EC, _Parameters}) ->
    crypto:hash(sha, public_key:der_encode('ECPoint', Point)).
