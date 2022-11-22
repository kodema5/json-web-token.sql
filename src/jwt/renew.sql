\if :{?jwt_renew_sql}
\else
\set jwt_renew_sql true


-- renewing a valid token
--
create function jwt.renew (
    jwt_text text,

    -- expiration
    exp_ timestamp with time zone
        default (now() + '30 mins'::interval),

    -- prefix for key selection
    id_ text
        default '%'

)
    returns text
    language sql
    security definer
    stable
as $$
    with
    t1 as (
        select jwt.decode(jwt_text) as p)
    select case
        when t1.p is null
            then null
        else jwt.encode(t1.p, exp_, id_)
        end
    from t1
$$;


\endif
