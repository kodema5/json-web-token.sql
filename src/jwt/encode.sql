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


-- to get random keys
--
create function jwt.get_random_key()
    returns _jwt.key
    language sql
    stable
as $$
    select *
    from _jwt.key
    order by random()
    limit 1
$$;

-- jwt.encode with random key
--
create function jwt.encode (
    payload jsonb
)
    returns text
    language plpgsql
    stable
as $$
declare
    k _jwt.key = jwt.get_random_key();
begin
    return jwt.encode(
        payload,
        k.value,  -- key
        jsonb_build_object( -- header
            'key_id', k.id
        )
    );
end;
$$;

