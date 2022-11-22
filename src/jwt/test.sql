\if :{?jwt_test_sql}
\else
\set jwt_test_sql true

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

    create function tests.test_jwt_w_stored_keys()
        returns setof text
        language plpgsql
    as $$
    declare
        p jsonb = jsonb_build_object('test', 123);
        t text;
        a jsonb;
        t2 text;
        a2 jsonb;
    begin
        insert into _jwt.key values
            ('foo', '1234567'),  -- text-text
            ('bar', md5(gen_random_uuid()::text)), -- text-random
            (md5(gen_random_uuid()::text), md5(gen_random_uuid()::text)); -- random-random

        -- raise warning '----%',
        --    (select jsonb_pretty(to_jsonb(array_agg(k))) from _jwt.key k);

        t = jwt.encode(p);
        a = jwt.decode(t);
        return next ok(a = p, 'able to use stored keys');

        t = jwt.encode(p, id_ => 'fo%');
        a = jwt.decode(t, '1234567');
        return next ok(a = p, 'able to select key');

        t = jwt.encode(p, now() - '1 hour'::interval);
        a = jwt.decode(t);
        return next ok(a is null, 'rejects expired token');

        t = jwt.encode(p, id_=>'foo');
        a = jwt.decode(t);
        t2 = jwt.renew(t, id_=>'bar');
        return next ok(t2 <> t, 'able to renew');
        a2 = jwt.decode(t2);
        return next ok(a = a2, 'renewed token has same payloads');
    end;
    $$;

    create function tests.test_jwt_invalid_jwt()
        returns setof text
        language plpgsql
    as $$
    declare
        a jsonb;
    begin
        a = jwt.decode(null);
        return next ok(a is null, 'null for null jwt');
        a = jwt.decode('{}');
        return next ok(a is null, 'null for invalid jwt');

        a = jwt.decode('..');
        return next ok(a is null, 'null for invalid jwt');
        a = jwt.decode('a.b.c');
        return next ok(a is null, 'null for invalid jwt');
    end;
    $$;


    create function tests.test_jwt_auth_for_web()
        returns setof text
        language plpgsql
    as $$
    declare
        p jsonb;
        a jsonb;
    begin
        p = jsonb_build_object('user_id', 'test');

        a = jwt.auth(jsonb_build_object(
            '_headers', jsonb_build_object(
                'authorization', 'Test ' || p::text
            ),
            '_origin', '127.0.0.1'
        ));
        return next ok(a->>'user_id' is not null, 'allows test-user from local');

        a = jwt.auth(jsonb_build_object(
            '_headers', jsonb_build_object(
                'authorization', 'Test ' || p::text
            ),
            '_origin', '127.0.0.2'
        ));
        return next ok(a->>'user_id' is null, 'disallow non-local test');


        insert into _jwt.key values
            (md5(gen_random_uuid()::text), md5(gen_random_uuid()::text));

        a = jwt.auth(jsonb_build_object(
            '_headers', jsonb_build_object(
                'authorization', 'Bearer ' || (jwt.encode(p))::text
            )
        ));
        return next ok(a->>'user_id' is not null, 'accepts jwt bearer');

        a = jwt.auth(jsonb_build_object(
            '_headers', jsonb_build_object(
                'authorization', (jwt.encode(p))::text
            )
        ));
        return next ok(a->>'user_id' is not null, 'accepts jwt token');

    end;
    $$;

\endif

\endif