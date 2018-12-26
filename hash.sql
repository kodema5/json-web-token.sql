create or replace function jwt.hash(
    txt text,
    key text,
    alg text default 'HS256'
) returns text as $$
    with t as (
        select
            case
            when alg = 'HS256' then 'sha256'
            when alg = 'HS384' then 'sha384'
            when alg = 'HS512' then 'sha512'
            else ''
            end as a)
    , dat as (
        select public.hmac(txt, key, t.a) as a
        from t)
    select jwt.to_base64(dat.a)
    from dat
$$ language sql immutable;