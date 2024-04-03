-- encode/decode text to base64 byte-array
--
create function to_base64( bytea )
    returns text
    language sql
    security definer
    immutable
    strict
    set search_path from current
as $$
    select translate(
        encode($1, 'base64'),
        E'+/=\n',
        '-_')
$$;


create function from_base64( text )
    returns bytea
    language sql
    security definer
    immutable
    strict
    set search_path from current
as $$
    with
    s as (
        select translate($1, '-_', '+/') s),
    n as (
        select length(s) % 4 as n from s),
    p as (
        select case
        when n.n>0 then repeat('=', 4 - n.n)
        else ''
        end as p
        from n)
    select decode (s.s || p.p, 'base64')
    from s, p
$$;

-- encode/decode json text to utf-8
--
create function to_utf8( jsonb )
    returns text
    language sql
    immutable
    strict
    set search_path from current
as $$
    select to_base64(convert_to($1::text, 'utf8'))
$$;

create function from_utf8( text )
    returns jsonb
    language sql
    security definer
    immutable
    strict
    set search_path from current
as $$
    select convert_from(from_base64($1), 'utf8')::jsonb;
$$;



-- hash `txt` with `key` and `algo` type
--
create function hash(
    txt text,
    key text,
    alg text default 'HS256'
)
    returns text
    language sql
    set search_path from current
    security definer
    immutable
as $$
    with
    t1 as (
        select
        case
        when $3 = 'HS256' then 'sha256'
        when $3 = 'HS384' then 'sha384'
        when $3 = 'HS512' then 'sha512'
        else ''
        end as a),
    t2 as (
        select public.hmac($1, $2, t1.a) as a
        from t1)
    select to_base64(t2.a)
    from t2
$$;
