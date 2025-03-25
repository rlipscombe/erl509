-module(erl509_time_tests).
-include_lib("eunit/include/eunit.hrl").

utc_time_test() ->
    ?assertEqual({utcTime, <<"250325204444Z">>}, erl509_time:encode_time(1742935484)).

general_time_test() ->
    ?assertEqual({generalTime, <<"20550318204519Z">>}, erl509_time:encode_time(2689015519)).
