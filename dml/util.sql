
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


-- removes expired keys
--
create function prune_keys(
    expired_tz_ timestamp with time zone
        default now(),
    source_ text default null

)
    returns setof jwt_key
    language sql
    security definer
    set search_path from current
as $$
    delete from jwt_key
    where expired_tz_ <= expired_tz_
    and (source_ is null or source=source_)
    returning *
$$;

\if :{?test}
\if :test
    create or replace function tests.test_util()
        returns setof text
        language plpgsql
        set search_path from current
    as $$
    begin
        return next ok(
            (select count(1) from jwt_key where source='test') = 0,
            'initially 0 keys');

        call gen_keys(source_ => 'test');

        return next ok(
            (select count(1) from jwt_key where source='test') = 10,
            'generated 10 keys');

        perform prune_keys(
            expired_tz_ => now() + '2 day'::interval,
            source_ => 'test'
        );
        return next ok(
            (select count(1) from jwt_key where source='test') = 0,
            'pruned test keys');
    end;
    $$;
\endif
\endif
