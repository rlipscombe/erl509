-module(erl509_time).
-export([encode_time/1]).

encode_time(Time) ->
    encode_universal_time(calendar:system_time_to_universal_time(Time, seconds)).

encode_universal_time({{Ye, Mo, Da}, {Ho, Mi, Se}}) when Ye < 2050 ->
    {utcTime, iolist_to_binary(io_lib:format("~2.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0BZ", [Ye rem 100, Mo, Da, Ho, Mi, Se]))};
encode_universal_time({{Ye, Mo, Da}, {Ho, Mi, Se}}) when Ye >= 2050 ->
    {generalTime, iolist_to_binary(io_lib:format("~4.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0BZ", [Ye, Mo, Da, Ho, Mi, Se]))}.
