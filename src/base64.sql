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