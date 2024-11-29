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