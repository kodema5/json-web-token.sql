
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

