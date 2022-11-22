
\if :{?jwt_sql}
\else
\set jwt_sql true

-- a json-web-token implementation

create extension if not exists pgcrypto;

drop schema if exists jwt cascade;
create schema jwt;


\ir jwt/hash.sql

-- encode payload into jwt-text with given key and header
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

-- decode jwt-text with given key for its payload
--
create function jwt.decode (
    jwt_text text,
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
        select string_to_array(jwt_text, '.')
        as a)
    select case
        when jwt.hash(a[1] || '.' || a[2], key, enc) = a[3] then jwt.from_utf8(a[2])
        else null
        end
    from t1;
$$;


-- jwt keys can be stored in a table
--
\if :test
\if :local
    drop schema if exists _jwt cascade;
\endif
\endif
create schema if not exists _jwt;


create table if not exists _jwt.key (
    id text  -- key name/id (ex: mi.signon.key)
        not null
        primary key,

    value text -- key.value
        not null,

    until_tz timestamp with time zone
        default (now() + '1 day'::interval)

);


-- generate random keys
--
create procedure jwt.gen_random_keys(
    n int default 10,
    exp_ timestamp with time zone
        default (now() + '1 day'::interval)
)
    language sql
    security definer
as $$
    insert into _jwt.key (id, value, until_tz)
        select
            md5(gen_random_uuid()::text),
            md5(gen_random_uuid()::text),
            exp_
        from generate_series(1,n)
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
    k as ( -- get random key prior to expiration time
        select *
        from _jwt.key
        where id like id_
            and until_tz > exp_
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


-- jwt.decode with stored key
--
create function jwt.decode (
    jwt_text text
)
    returns jsonb
    language plpgsql
    security definer
    stable
as $$
begin
    return (
        with
        t1 as (
            select string_to_array(jwt_text, '.') as a),
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
            when cardinality(t1.a)<>3
                then null
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
    );
exception
    when others then
        return null;
end;
$$;

-- re-encode jwt
\ir jwt/renew.sql


-- jwt.auth(jsonb) authenticates a request json with key in _headers and _origin
--
create function jwt.auth (
    req jsonb,
    jwt_path jsonpath default '$._headers.authorization',
    origin_path jsonpath default '$._origin'
)
    returns jsonb
    language sql
    security definer
    stable
as $$
    with p as (
        select
        -- req->>'_origin' as origin
        jsonb_path_query_first(req, origin_path)->>0 as origin,

        -- req->'_headers'->>'authorization' as auth
        jsonb_path_query_first(req, jwt_path)->>0 as auth
    )
    select case
    when p.auth is null
    then
        null

    -- test if local-test
    when
        p.origin = '127.0.0.1'
        and p.auth like 'Test {%}'
    then (substring(p.auth from '\{.+\}'))::jsonb
        || jsonb_build_object('is_test', true)

    -- for jwt bearer
    when p.auth like 'Bearer %'
    then
        jwt.decode(substring(p.auth from 8))

    -- assume jwt token
    else
        jwt.decode(p.auth)

    end
    from p
$$;


\ir jwt/test.sql

\endif