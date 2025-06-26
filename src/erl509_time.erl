-module(erl509_time).
-export([
    encode_time/1,
    decode_time/1
]).

% 1950-01-01T00:00:00Z (yes, negative Unix timestamp).
-define(EARLIEST_REPRESENTABLE_TIME, -631152000).

encode_time(Time) when Time >= ?EARLIEST_REPRESENTABLE_TIME ->
    encode_universal_time(calendar:system_time_to_universal_time(Time, second));
encode_time(Time) ->
    error(badarg, [Time]).

encode_universal_time({{Ye, Mo, Da}, {Ho, Mi, Se}}) when Ye < 2050 ->
    {utcTime,
        io_lib:format("~2.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0BZ", [
            Ye rem 100, Mo, Da, Ho, Mi, Se
        ])};
encode_universal_time({{Ye, Mo, Da}, {Ho, Mi, Se}}) when Ye >= 2050 ->
    {generalTime,
        io_lib:format("~4.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0B~2.10.0BZ", [
            Ye, Mo, Da, Ho, Mi, Se
        ])}.

decode_time({Type, Value}) when is_atom(Type), is_list(Value) ->
    decode_time({Type, list_to_binary(Value)});
decode_time({utcTime, <<Year:2/binary, Rest/binary>> = _UtcTime}) when Year >= <<"50">> ->
    % Yes, you'd need a time machine to issue a certificate like this.
    decode_time({generalTime, <<"19", Year/binary, Rest/binary>>});
decode_time({utcTime, <<Year:2/binary, Rest/binary>> = _UtcTime}) ->
    decode_time({generalTime, <<"20", Year/binary, Rest/binary>>});
decode_time(
    {generalTime,
        <<Year:4/binary, Month:2/binary, Day:2/binary, Hour:2/binary, Minute:2/binary,
            Second:2/binary, $Z>>}
) ->
    % Convert to RFC 3339 format and then to system time in seconds.
    % RFC 3339 format looks like this: "2025-04-02T08:34:39Z"
    DateTimeString = binary_to_list(
        <<Year/binary, $-, Month/binary, $-, Day/binary, $T, Hour/binary, $:, Minute/binary, $:,
            Second/binary, $Z>>
    ),
    calendar:rfc3339_to_system_time(DateTimeString, [{unit, second}]).
