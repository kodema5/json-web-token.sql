
-- retrieves the jsonb from jwt if valid
--
create function jwt_decode (
    jwt_text text,
    key text,
    enc text default 'HS256'
)
    returns jsonb
    language sql
    security definer
    stable
    set search_path from current
as $$
    with
    t1 as (
        select string_to_array(jwt_text, '.')
        as a)
    select case
        when hash(a[1] || '.' || a[2], key, enc) = a[3] then from_utf8(a[2])
        else null
        end
    from t1;
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
