create or replace function jwt.test_nulls() returns setof text as $$
declare
    -- a token from jwt-io
    t jwt.token_t = 'xxxx';
    k text = 'your-256-bit-secret';
    p jsonb = from_jwt(t, k);
begin
    return next ok( p is null, 'returns null');
    return next ok(from_jwt(null, k) is null, 'returns null on null token');
    return next ok(to_jwt(null, k) is null, 'returns null on null payload');
end;
$$ language plpgsql;
