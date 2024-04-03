
create extension if not exists pgcrypto with schema public;

-- to hash text with key and algorithm
--
\ir dml/hash.sql

-- encode/decode jwt with a given key
--
\ir dml/converter.sql

-- encode/decode jwt with key stored in jwt_key table
--
\ir dml/converter_key.sql


-- utility functions to generate/prune stored keys
--
\ir dml/util.sql