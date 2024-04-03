-- encode with randomly selected stored jwt_key
--
create function jwt_encode (
    payload jsonb,

    -- minimum expiration time
    expired_tz_ timestamp with time zone
        default (now() + '30 mins'::interval),

    -- filters for vailable key
    public_key_like_ text
        default '%'
)
    returns text
    language sql
    security definer
    stable
    set search_path from current
as $$
    with
    jk as (
        select *
        from jwt_key
        where public_key like public_key_like_
        and expired_tz > expired_tz_
        order by random()
        limit 1
    )
    select jwt_encode (
        payload,
        jk.private_key,
        jsonb_build_object (
            'jti', jk.public_key,
            'exp', to_char(expired_tz_::timestamp at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        ))
    from jk
$$;


-- jwt_decode with stored key
-- jwt_key.public_id is stored as jti
--
create function jwt_decode (
    jwt_text text
)
    returns jsonb
    language plpgsql
    security definer
    stable
    set search_path from current
as $$
begin
    return (
        with
        t1 as (
            select string_to_array(jwt_text, '.') as a),
        t2 as (
            select
                header->>'jti' as public_key,
                now() > to_timestamp(
                    header->>'exp',
                    'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                )::timestamp at time zone 'UTC'
                as is_expired
            from (
                select from_utf8(t1.a[1])
                from t1
            ) t3 (header)
        )
        select case
            when cardinality(t1.a)<>3
                then null
            when t2.public_key is null or t2.is_expired
                then null
            when hash (
                a[1] || '.' || a[2], -- header.payload
                (
                    select private_key
                    from jwt_key
                    where public_key = t2.public_key
                )
                ) = a[3] -- compare signature
                then from_utf8(a[2])
            else null
            end
        from t1, t2
    );
exception
    when others then
        return null;
end;
$$;

-- re-code token with a newer key
--
create function jwt_recode (
    jwt_text text,

    -- expiration
    expired_tz_ timestamp with time zone
        default (now() + '30 mins'::interval),

    -- prefix for key selection
    public_key_like_ text
        default '%'

)
    returns text
    language sql
    security definer
    stable
    set search_path from current
as $$
    with
    t1 as (
        select jwt_decode(jwt_text) as p)
    select case
        when t1.p is null
            then null
        else jwt_encode(t1.p, expired_tz_, public_key_like_)
        end
    from t1
$$;



\if :{?test}
\if :test

    create function tests.test_converter_key()
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

    create function tests.test_invalid_token()
        returns setof text
        language plpgsql
        set search_path from current
    as $$
    declare
        a jsonb;
    begin
        a = jwt_decode(null);
        return next ok(a is null, 'null for null jwt');
        a = jwt_decode('{}');
        return next ok(a is null, 'null for invalid jwt');

        a = jwt_decode('..');
        return next ok(a is null, 'null for invalid jwt');
        a = jwt_decode('a.b.c');
        return next ok(a is null, 'null for invalid jwt');
    end;
    $$;

\endif
\endif