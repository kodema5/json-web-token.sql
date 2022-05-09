-- initial jwt decode
--
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


-- jwt.decode with stored key
--
create function jwt.get_key (
    id_ text
)
    returns text
    language sql
    stable
as $$
select value
    from _jwt.key
    where id=id_
$$;


create function jwt.decode (
    txt text
)
    returns jsonb
    language sql
    stable
as $$
    with
    t1 as (
        select string_to_array(txt, '.')
        as a),
    t2 as (
        select jwt.from_utf8(t1.a[1])->>'key_id' as id
        from t1
    )
    select case
        when t2.id is null then null
        when jwt.hash(
                a[1] || '.' || a[2], -- header.payload
                jwt.get_key(t2.id)   -- key_id
                                     -- encoding HS256 by default
            ) = a[3] -- signature
            then jwt.from_utf8(a[2])
        else null
        end
    from t1, t2;
$$;
