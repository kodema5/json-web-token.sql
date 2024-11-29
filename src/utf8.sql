-- encode/decode json text to utf-8
--
create function to_utf8( jsonb )
    returns text
    language sql
    immutable
    strict
    set search_path from current
as $$
    select to_base64(convert_to($1::text, 'utf8'))
$$;

create function from_utf8( text )
    returns jsonb
    language sql
    security definer
    immutable
    strict
    set search_path from current
as $$
    select convert_from(from_base64($1), 'utf8')::jsonb;
$$;