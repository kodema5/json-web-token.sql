create or replace function jwt.test_key_cmd() returns setof text as $$
declare
    p jsonb = jsonb_build_object(
        'sub', '1234567890',
        'name', 'John Doe',
        'iat', 1516239022);
    c jwt.command_string_t = 'select ($1->>''sub'') || ($1->>''name'') || ($2->>''secret'')';
    h jsonb = jsonb_build_object('secret', 's3cr3t');
    t jwt.token_t = to_jwt(p, c, h);
    a jsonb = from_jwt(t, c);
    k text;

begin
    execute c into k using p, h;
    return next ok(k = '1234567890John Does3cr3t', 'key from payload');
    return next ok(a = p, 'returns same payload');

    a = from_jwt(t, 'select null');
    return next ok (a is null, 'returns null on null key');
    return next ok (to_jwt(null, c, h) is null, 'returns null on null payload');
end;
$$ language plpgsql;

