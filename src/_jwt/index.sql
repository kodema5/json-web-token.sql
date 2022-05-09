\if :local
    drop schema if exists _jwt cascade;
\endif
create schema if not exists _jwt;

-- contains shared private keys
-- ex: mi-jwt-key.v1
--
create table _jwt.key (
    id text
        not null
        primary key,

    value text
        not null

    -- for expiring key
    -- until_tz
    --     timestamp with time zone
    --     default now() + '30 days'
);

