create extension if not exists "uuid-ossp" schema public;
create extension if not exists pgcrypto;

\ir src/_jwt/index.sql
\ir src/jwt/index.sql

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
        h jsonb = jsonb_build_object();
        t text = jwt.encode(p,k,h);
    begin
        return next ok(jwt.decode(jwt.encode(p,k,h), k) = p, 'returns same payload');
        return next ok(jwt.encode(null, k,h) is null, 'returns null on null payload');
        return next ok(jwt.encode(p, null,h) is null, 'returns null on null key');
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


    create function tests.test_jwt_w_stored_keys()
        returns setof text
        language plpgsql
    as $$
    declare
        p jsonb = jsonb_build_object('test', 123);
        t text;
        a jsonb;
    begin
        insert into _jwt.key values
            ('foo', 'foo'),  -- text-text
            ('bar', md5(uuid_generate_v4()::text)), -- text-random
            (md5(uuid_generate_v4()::text), md5(uuid_generate_v4()::text)); -- random-random

        t = jwt.encode(p);
        a = jwt.decode(t);
        return next ok(a = p, 'able to use stored keys');
    end;
    $$;

\endif
