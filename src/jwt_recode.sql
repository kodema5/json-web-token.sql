-- re-code token with a newer key
--
create function jwt_recode (
    jwt_text text,

    -- expiration
    expired_tz_ timestamp with time zone
        default (now() + '30 mins'::interval),

    -- prefix for key selection
    public_key_like_ text
        default '%'

)
    returns text
    language sql
    security definer
    stable
    set search_path from current
as $$
    with
    t1 as (
        select jwt_decode(jwt_text) as p)
    select case
        when t1.p is null
            then null
        else jwt_encode(t1.p, expired_tz_, public_key_like_)
        end
    from t1
$$;
