
create or replace function jwt.to_base64(a bytea)
returns text as $$
    select translate(
        encode(a, 'base64'),
        E'+/=\n',
        '-_')
$$ language sql strict immutable;

create or replace function jwt.from_base64(a text)
returns bytea as $$
declare
    s text = translate(a, '-_', '+/');
    n int = length(s) % 4;
    p text = '';
begin
    if n>0 then
        p = repeat('=', 4-n);
    end if;
    return decode(s || p, 'base64');
end;
$$ language plpgsql strict immutable;
