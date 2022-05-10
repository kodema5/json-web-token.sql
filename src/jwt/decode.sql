-- initial jwt decode
--
create function jwt.decode (
    txt text,
    key text,
    enc text default 'HS256'
)
    returns jsonb
    language sql
    security definer
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


-- jwt.decode with stored key
--
create function jwt.decode (
    txt text
)
    returns jsonb
    language sql
    security definer
    stable
as $$
    with
    t1 as (
        select string_to_array(txt, '.') as a),
    t2 as (
        select header->>'jti' as id,
            now() > to_timestamp(
                header->>'exp',
                'YYYY-MM-DD"T"HH24:MI:SS"Z"'
            )::timestamp at time zone 'UTC'
            as is_expired
        from (
            select jwt.from_utf8(t1.a[1])
            from t1
        ) t3 (header)
    )
    select case
        when t2.id is null or t2.is_expired
            then null
        when jwt.hash (
            a[1] || '.' || a[2], -- header.payload
            (
                select value -- get stored key
                from _jwt.key
                where id = t2.id
            )
            -- encoding is hs256 by default
            ) = a[3] -- compare signature
            then jwt.from_utf8(a[2])
        else null
        end
    from t1, t2
$$;

