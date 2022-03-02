
create function jwt.to_base64(a bytea)
returns text
as $$
    select translate(
        encode(a, 'base64'),
        E'+/=\n',
        '-_')
$$ language sql strict immutable;


-- create function jwt.from_base64(a text)
-- returns bytea as $$
-- declare
--     s text = translate(a, '-_', '+/');
--     n int = length(s) % 4;
--     p text = '';
-- begin
--     if n>0 then
--         p = repeat('=', 4-n);
--     end if;
--     return decode(s || p, 'base64');
-- end;
-- $$ language plpgsql strict immutable;

create or replace function jwt.from_base64(a text)
returns bytea as $$
with
s as (
    select translate(a, '-_', '+/') s),
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
$$ language sql strict immutable;


create function jwt.from_utf8(a text)
returns jsonb
as $$
    select convert_from(jwt.from_base64(a), 'utf8')::jsonb;
$$ language sql strict immutable;


create function jwt.to_utf8(a jsonb)
returns text
as $$
    select jwt.to_base64(convert_to(a::text, 'utf8'))
$$ language sql strict immutable;


create function jwt.hash(
    txt text,
    key text,
    alg text default 'HS256')
returns text
as $$
with
t1 as (
    select
    case
    when alg = 'HS256' then 'sha256'
    when alg = 'HS384' then 'sha384'
    when alg = 'HS512' then 'sha512'
    else ''
    end as a),
t2 as (
    select public.hmac(txt, key, t1.a) as a
    from t1)
select jwt.to_base64(t2.a)
from t2
$$ language sql immutable;