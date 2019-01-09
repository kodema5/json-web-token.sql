
-- a command_string_t when key is to be evaluated with jsonb payload ($1)
-- ex: 'select $1->>''name'''::jwt.command_string_t

create domain jwt.command_string_t as text not null;

create or replace function to_jwt (
    payload jsonb,
    cmd jwt.command_string_t
        default 'select current_setting(''jwt.key'', true)'::jwt.command_string_t,
    header jsonb default '{}'::jsonb,
    alg text
        default coalesce(current_setting('jwt.algorithm',true), 'HS256')

) returns jwt.token_t as $$
declare
    h jsonb = jsonb_build_object('alg', alg, 'typ', 'JWT') || header;
    k text;
begin
    if payload is null then
        return null;
    end if;

    execute cmd into k using payload, h;
    if k is null then
        return null;
    end if;

    return to_jwt(payload, k, header, alg);
end;
$$ language plpgsql immutable;


create or replace function from_jwt (
    jwt jwt.token_t,
    cmd jwt.command_string_t
        default 'select current_setting(''jwt.key'', true)'::jwt.command_string_t,
    alg text
        default current_setting('jwt.algorithm',true)
) returns jsonb as $$
declare
    r text[] = regexp_split_to_array(jwt, '\.');
    h jsonb = jwt.from_utf8(r[1]);
    a text =  coalesce(alg, h->>'alg', 'HS256');
    p jsonb = jwt.from_utf8(r[2]);
    k text;
begin
    execute cmd into k using p, h;
    if k is null then
        return null;
    end if;

    if r[3] <> jwt.hash(r[1] || '.' || r[2], k, a) then
        return null;
    end if;

    return p;
end;
$$ language plpgsql immutable;
