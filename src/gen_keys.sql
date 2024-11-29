-- generate random keys to jwt_key
--
create procedure gen_keys(
    n int default 10,
    expired_tz_ timestamp with time zone
        default (now() + '1 day'::interval),
    source_ text default null
)
    language sql
    security definer
    set search_path from current
as $$
    insert into jwt_key (
        public_key,
        private_key,
        source,
        expired_tz
    )
        select
            md5(gen_random_uuid()::text),
            md5(gen_random_uuid()::text),
            source_,
            expired_tz_
        from generate_series(1,n)
$$;