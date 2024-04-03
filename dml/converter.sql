
-- encode jsonb payload as jwt
--
create function jwt_encode (
    payload jsonb,
    key text,
    header jsonb,
    enc text default 'HS256'
)
    returns text
    language sql
    security definer
    stable
    set search_path from current
as $$
    with
    t1 as (
        select jsonb_build_object('typ', 'JWT')
            || header
        as a),
    t2 as (
        select to_utf8(t1.a)
            || '.'
            || to_utf8(payload)
        as a
        from t1)
    select
        t2.a
        || '.' || hash(t2.a, key, enc) from t2;
$$;




-- retrieves the jsonb from jwt if valid
--
create function jwt_decode (
    jwt_text text,
    key text,
    enc text default 'HS256'
)
    returns jsonb
    language sql
    security definer
    stable
    set search_path from current
as $$
    with
    t1 as (
        select string_to_array(jwt_text, '.')
        as a)
    select case
        when hash(a[1] || '.' || a[2], key, enc) = a[3] then from_utf8(a[2])
        else null
        end
    from t1;
$$;





\if :{?test}
\if :test
    create or replace function tests.test_converter_jwt_io()
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

    create or replace function tests.test_converter()
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
\endif
\endif
