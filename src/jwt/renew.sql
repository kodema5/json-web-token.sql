-- renewing a valid token

create function jwt.renew (
    txt text
)
    returns text
    language sql
    security definer
    stable
as $$
    with
    t1 as (
        select jwt.decode(txt) as p)
    select case
        when t1.p is null
            then null
        else jwt.encode(t1.p)
        end
    from t1
$$;

