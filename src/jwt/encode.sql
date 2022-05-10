-- initial jwt encode
--
create function jwt.encode (
    payload jsonb,
    key text,
    header jsonb,
    enc text default 'HS256'
)
    returns text
    language sql
    security definer
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


-- jwt.encode with stored key
--
create function jwt.encode (
    payload jsonb,

    -- expiration
    exp_ timestamp with time zone
        default (now() + '30 mins'::interval),

    -- prefix for key selection
    id_ text
        default '%'
)
    returns text
    language sql
    security definer
    stable
as $$
    with
    k as ( -- get random key
        select *
        from _jwt.key
        where id like id_
        order by random()
        limit 1
    )
    select jwt.encode (
        payload,
        k.value, -- key
        jsonb_build_object (
            'jti', k.id,
            'exp', to_char(exp_::timestamp at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        ))
    from k
$$;


