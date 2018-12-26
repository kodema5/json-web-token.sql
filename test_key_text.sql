create or replace function jwt.test_key_text() returns setof text as $$
declare
    p jsonb = jsonb_build_object(
        'sub', '1234567890',
        'name', 'John Doe',
        'iat', 1516239022);
    k text = 'your-512-bit-secret';
    t jwt.token_t = to_jwt(p,k);
    a jsonb = from_jwt(t, k);
begin
    return next ok(a = p, 'returns same payload');
    t = to_jwt(p, null);
    return next ok(t is null, 'returns null on null key');
    t = to_jwt(null, k);
    return next ok(t is null, 'returns null on null payload');
end;
$$ language plpgsql;

