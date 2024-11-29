create or replace function tests.test_jwt_io()
    returns setof text
    language plpgsql
    set search_path from current
as $$
declare
    -- a token from jwt-io
    t text = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    k text = 'your-256-bit-secret';
    p jsonb = jwt_decode(t, k);
begin
    return next ok( p->>'sub' = '1234567890', 'has sub');
    return next ok( p->>'name' = 'John Doe', 'has name');
    return next ok( (p->>'iat')::int = 1516239022, 'has iat');
end;
$$;

create or replace function tests.test_jwt()
    returns setof text
    language plpgsql
    set search_path from current

as $$
declare
    p jsonb = jsonb_build_object(
        'sub', '1234567890',
        'name', 'John Doe',
        'iat', 1516239022);
    k text = 'your-512-bit-secret';
    h jsonb = jsonb_build_object();
    t text = jwt_encode(p,k,h);
begin
    return next ok(jwt_decode(jwt_encode(p,k,h), k) = p, 'returns same payload');
    return next ok(jwt_encode(null, k,h) is null, 'returns null on null payload');
    return next ok(jwt_encode(p, null,h) is null, 'returns null on null key');
end;
$$;

create or replace function tests.test_gen_prune_keys()
    returns setof text
    language plpgsql
    set search_path from current
as $$
begin
    return next ok(
        (select count(1) from jwt_key where source='test') = 0,
        'initially 0 keys');

    call gen_keys(source_ => 'test');

    return next ok(
        (select count(1) from jwt_key where source='test') = 10,
        'generated 10 keys');

    perform prune_keys(
        expired_tz_ => now() + '2 day'::interval,
        source_ => 'test'
    );
    return next ok(
        (select count(1) from jwt_key where source='test') = 0,
        'pruned test keys');
end;
$$;