create or replace function jwt.test_key_cmd() returns setof text as $$
declare
    p jsonb = jsonb_build_object(
        'sub', '1234567890',
        'name', 'John Doe',
        'iat', 1516239022);
    c jwt.command_string_t = 'select ($1->>''sub'') || ($1->>''name'')';
    t jwt.token_t = to_jwt(p, c);
    a jsonb = from_jwt(t, c);
    k text;
begin
    execute c into k using p;
    return next ok(k = '1234567890John Doe', 'key from payload');
    return next ok(a = p, 'returns same payload');

    a = from_jwt(t, 'select null');
    return next ok (a is null, 'returns null on null key');
    return next ok (to_jwt(null, c) is null, 'returns null on null payload');
end;
$$ language plpgsql;

