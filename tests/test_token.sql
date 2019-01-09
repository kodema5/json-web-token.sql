-- token from jwt.io
create or replace function jwt.test_token() returns setof text as $$
declare
    -- a token from jwt-io
    t jwt.token_t = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    k text = 'your-256-bit-secret';
    p jsonb = from_jwt(t, k);
begin
    return next ok( p->>'sub' = '1234567890', 'has sub');
    return next ok( p->>'name' = 'John Doe', 'has name');
    return next ok( (p->>'iat')::int = 1516239022, 'has iat');
end;
$$ language plpgsql;
