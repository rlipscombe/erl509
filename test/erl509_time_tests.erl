-module(erl509_time_tests).
-include_lib("eunit/include/eunit.hrl").

% Per RFC 5280, section 4.1.2.5:
%
% "CAs conforming to this profile MUST always encode certificate validity dates through the year 2049 as UTCTime;
%  certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime."

% 2049-12-31T23:59:59Z
-define(LATEST_UTC_TIME, 2524607999).
% 2049-12-31T23:59:59Z + 1 second.
-define(EARLIEST_GENERALIZED_TIME, ?LATEST_UTC_TIME + 1).

encode_utc_time_earliest_test() ->
    % 1950-01-01T00:00:00Z (yes, negative Unix timestamp).
    ?assertEqual({utcTime, "500101000000Z"}, erl509_time:encode_time(-631152000)).

encode_utc_time_primordial_test() ->
    ?assertError(badarg, erl509_time:encode_time(-631152001)).

encode_utc_time_test() ->
    ?assertEqual({utcTime, "250325204444Z"}, erl509_time:encode_time(1742935484)).

encode_utc_time_latest_test() ->
    ?assertEqual({utcTime, "491231235959Z"}, erl509_time:encode_time(?LATEST_UTC_TIME)).

encode_general_time_earliest_test() ->
    ?assertEqual(
        {generalTime, "20500101000000Z"}, erl509_time:encode_time(?EARLIEST_GENERALIZED_TIME)
    ).

encode_general_time_test() ->
    ?assertEqual({generalTime, "20550318204519Z"}, erl509_time:encode_time(2689015519)).

decode_utc_time_test_() ->
    [
        % 2025-03-25T20:44:44Z
        ?_assertEqual(1742935484, erl509_time:decode_time({utcTime, <<"250325204444Z">>})),
        ?_assertEqual(1742935484, erl509_time:decode_time({utcTime, "250325204444Z"})),

        % Fortunately, we have a time machine -- https://www.imdb.com/title/tt0096928/
        ?_assertEqual(603676800, erl509_time:decode_time({utcTime, <<"890217000000Z">>}))
    ].

decode_utc_time_latest_test() ->
    ?assertEqual(?LATEST_UTC_TIME, erl509_time:decode_time({utcTime, <<"491231235959Z">>})).

decode_general_time_earliest_test() ->
    ?assertEqual(
        ?EARLIEST_GENERALIZED_TIME, erl509_time:decode_time({generalTime, <<"20500101000000Z">>})
    ).

decode_general_time_test_() ->
    [
        ?_assertEqual(2689015519, erl509_time:decode_time({generalTime, <<"20550318204519Z">>})),
        ?_assertEqual(2689015519, erl509_time:decode_time({generalTime, "20550318204519Z"}))
    ].
