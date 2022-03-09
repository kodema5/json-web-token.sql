
create function jwt.set_key (
    id_ text default md5(uuid_generate_v4()::text),
    key_ text default md5(uuid_generate_v4()::text)
)
    returns jwt_.key
    language sql
as $$
    insert into jwt_.key (id, value)
        values (id_, key_)
    on conflict (id)
    do update set
        value = key_
    returning *
$$;


create function jwt.get_key (
    id_ text
)
    returns text
    language sql
    stable
as $$
    select value
    from jwt_.key
    where id=id_
$$;


create function jwt.decode (
    txt text,
    key_path jsonpath,
    enc text default 'HS256'
)
    returns jsonb
    language sql
    stable
as $$
    with
    t1 as (
        select string_to_array(txt, '.')
        as a),
    t2 as (
        select jsonb_path_query_array(jsonb_build_object(
            'header', jwt.from_utf8(t1.a[1]),
            'payload', jwt.from_utf8(t1.a[2])
        ), key_path)->>0 as id
        from t1 )
    select case
        when t2.id is null then null
        when jwt.hash(a[1] || '.' || a[2], jwt.get_key(t2.id), enc) = a[3]
            then jwt.from_utf8(a[2])
        else null
        end
    from t1, t2;
$$;


\if :test
    create function tests.test_jwt_w_stored_keys()
        returns setof text
        language plpgsql
    as $$
    declare
        p jsonb = jsonb_build_object('test', 123);
        t text;
        a jsonb;
    begin
        -- create a random key for 'foo'
        perform jwt.set_key('foo');

        t = jwt.encode(
            p,
            jwt.get_key('foo'), -- get key for 'foo'
            jsonb_build_object('bearer', 'foo'));

        a = jwt.decode(
            t,
            '$.header.bearer'::jsonpath);
        return next ok(a = p, 'able to use stored keys');


        a = jwt.decode(
            t,
            '$.header.x'::jsonpath);
        return next ok(a is null, 'null if key not found');

        t = jwt.encode(
            p,
            jwt.get_key('foox'), -- a null key
            jsonb_build_object('bearer', 'foo'));
        return next ok(t is null, 'null jwt if key not found');

    end;
    $$;
\endif
