-- encode and decode with static key

create function jwt.encode (
    payload jsonb,
    key text,
    header jsonb default '{}'::jsonb,
    enc text default 'HS256'
)
    returns text
    language sql
    stable
as $$
    with
    t1 as (
        select jsonb_build_object('typ', 'JWT')
            || header
        as a),
    t2 as (
        select jwt.to_utf8(t1.a)
            || '.'
            || jwt.to_utf8(payload)
        as a
        from t1)
    select
        t2.a
        || '.' || jwt.hash(t2.a, key, enc) from t2;
$$;


create function jwt.decode (
    txt text,
    key text,
    enc text default 'HS256'
)
    returns jsonb
    language sql
    stable
as $$
    with
    t1 as (
        select string_to_array(txt, '.')
        as a)
    select case
        when jwt.hash(a[1] || '.' || a[2], key, enc) = a[3] then jwt.from_utf8(a[2])
        else null
        end
    from t1;
$$;


\if :test
    create or replace function tests.test_jwt_encode_w_token_from_jwt_io()
        returns setof text
        language plpgsql
    as $$
    declare
        -- a token from jwt-io
        t text = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        k text = 'your-256-bit-secret';
        p jsonb = jwt.decode(t, k);
    begin
        return next ok( p->>'sub' = '1234567890', 'has sub');
        return next ok( p->>'name' = 'John Doe', 'has name');
        return next ok( (p->>'iat')::int = 1516239022, 'has iat');
    end;
    $$;

    create or replace function tests.test_jwt_encode_with_static_key()
        returns setof text
        language plpgsql
    as $$
    declare
        p jsonb = jsonb_build_object(
            'sub', '1234567890',
            'name', 'John Doe',
            'iat', 1516239022);
        k text = 'your-512-bit-secret';
        t text = jwt.encode(p,k);
    begin
        return next ok(jwt.decode(jwt.encode(p,k), k) = p, 'returns same payload');
        return next ok(jwt.encode(null, k) is null, 'returns null on null payload');
        return next ok(jwt.encode(p, null) is null, 'returns null on null key');
    end;
    $$;

    create or replace function tests.test_jwt_encode_invalid_token()
        returns setof text
        language plpgsql
    as $$
    begin
        return next ok(jwt.decode('foo.bar.baz', 'xxx') is null, 'null when invalid-token');
        return next ok(jwt.decode('foo', 'xxx') is null, 'null when invalid-token');
    end;
    $$;
\endif
