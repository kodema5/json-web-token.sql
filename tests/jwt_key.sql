create function tests.test_jwt_key()
    returns setof text
    language plpgsql
    set search_path from current
as $$
declare
    p jsonb = jsonb_build_object('test', 123);
    t text;
    a jsonb;
    t2 text;
    a2 jsonb;
begin
    insert into jwt_key values
        ('foo', '1234567'),  -- text-text
        ('bar', md5(gen_random_uuid()::text)), -- text-random
        (md5(gen_random_uuid()::text), md5(gen_random_uuid()::text)); -- random-random

    -- raise warning '----%',
    --    (select jsonb_pretty(to_jsonb(array_agg(k))) from _jwt.key k);

    t = jwt_encode(p);
    a = jwt_decode(t);
    return next ok(a = p, 'able to use stored keys');

    t = jwt_encode(p, public_key_like_ => 'fo%');
    a = jwt_decode(t, '1234567');
    return next ok(a = p, 'able to select key');

    t = jwt_encode(p, now() - '1 hour'::interval);
    a = jwt_decode(t);
    return next ok(a is null, 'rejects expired token');

    t = jwt_encode(p, public_key_like_=>'foo');
    a = jwt_decode(t);
    t2 = jwt_recode(t, public_key_like_=>'bar');
    return next ok(t2 <> t, 'able to recode');

    a2 = jwt_decode(t2);
    return next ok(a = a2, 'renewed token has same payloads');
end;
$$;