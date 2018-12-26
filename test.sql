select exists (select 1 from pg_available_extensions where name='pgtap') as has_pgtap
\gset
\if :has_pgtap

\i test_key_cmd.sql
\i test_key_text.sql
\i test_nulls.sql
\i test_token.sql

SELECT * FROM public.runtests('jwt'::name);

drop function jwt.test_key_cmd();
drop function jwt.test_nulls();
drop function jwt.test_key_text();
drop function jwt.test_token();

\endif
