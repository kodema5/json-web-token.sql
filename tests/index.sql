\ir ../src/index.sql

\if :{?test}
\if :test

\ir jwt.sql
\ir invalid_token.sql
\ir jwt_key.sql

\endif
\endif