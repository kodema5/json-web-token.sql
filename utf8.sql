create or replace function jwt.from_utf8(a text)
returns jsonb as $$
begin
    return convert_from(jwt.from_base64(a), 'utf8')::jsonb;
exception
    when others then
        return null;
end;
$$ language plpgsql strict immutable;


create or replace function jwt.to_utf8(a jsonb)
returns text as $$
begin
    return jwt.to_base64(convert_to(a::text, 'utf8'));
end;
$$ language plpgsql strict immutable;
