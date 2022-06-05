-- decorates request json with _auth field from authorization header

create function jwt.auth (
    req jsonb,
    for_auth jsonpath default '$._headers.authorization',
    for_origin jsonpath default '$._origin'
)
    returns jsonb
    language sql
    security definer
    stable
as $$
    with p as (
        select
        -- req->>'_origin' as origin
        jsonb_path_query_first(req, for_origin)->>0 as origin,
        -- req->'_headers'->>'authorization' as auth
        jsonb_path_query_first(req, '$._headers.authorization')->>0 as auth
    )
    select case
    when p.auth is null
    then
        null

    -- test if local-test
    when
        p.origin = '127.0.0.1'
        and p.auth like 'Test {%}'
    then (substring(p.auth from '\{.+\}'))::jsonb
        || jsonb_build_object('is_test', true)

    -- for jwt bearer
    when p.auth like 'Bearer %'
    then
        jwt.decode(substring(p.auth from 8))

    -- assume jwt token
    else
        jwt.decode(p.auth)

    end
    from p
$$;
