
create or replace function to_jwt (
    payload jsonb,
    key text,
    alg text default coalesce(current_setting('jwt.algorithm',true), 'HS256')
) returns jwt.token_t as $$
declare
    h jsonb = json_build_object('alg', alg, 'typ', 'JWT');
    t text = jwt.to_utf8(h)
        || '.'
        || jwt.to_utf8(payload);
begin
    return t || '.' || jwt.hash(t, key, alg);
end;
$$ language plpgsql immutable;

create or replace function from_jwt (
    jwt jwt.token_t,
    key text,
    alg text default current_setting('jwt.algorithm',true)
) returns jsonb as $$
declare
    r text[] = regexp_split_to_array(jwt, '\.');
    h jsonb = jwt.from_utf8(r[1]);
    a text =  coalesce(alg, h->>'alg', 'HS256');
    p jsonb = jwt.from_utf8(r[2]);
begin
    if r[3] <> jwt.hash(r[1] || '.' || r[2], key, a) then
        return null;
    end if;

    return p;
end;
$$ language plpgsql immutable;
