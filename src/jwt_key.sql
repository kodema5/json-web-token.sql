-- jwt keys
create table if not exists jwt_key (
    public_key text
        not null
        primary key,

    private_key text
        not null,

    source text,

    expired_tz timestamp with time zone
        default (now() + '1 day'::interval)
);
