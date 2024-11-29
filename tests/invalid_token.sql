create function tests.test_invalid_token()
    returns setof text
    language plpgsql
    set search_path from current
as $$
declare
    a jsonb;
begin
    a = jwt_decode(null);
    return next ok(a is null, 'null for null jwt');
    a = jwt_decode('{}');
    return next ok(a is null, 'null for invalid jwt');

    a = jwt_decode('..');
    return next ok(a is null, 'null for invalid jwt');
    a = jwt_decode('a.b.c');
    return next ok(a is null, 'null for invalid jwt');
end;
$$;