--
-- PostgreSQL database dump
--

-- Dumped from database version 16.3 (Debian 16.3-1.pgdg120+1)
-- Dumped by pg_dump version 16.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: jwt; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA jwt;


--
-- Name: jwt_; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA jwt_;


--
-- Name: from_utf8(text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.from_utf8(text) RETURNS jsonb
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $_$
    select convert_from(from_base64($1), 'utf8')::jsonb;
$_$;


--
-- Name: gen_keys(integer, timestamp with time zone, text); Type: PROCEDURE; Schema: jwt; Owner: -
--

CREATE PROCEDURE jwt.gen_keys(IN n integer DEFAULT 10, IN expired_tz_ timestamp with time zone DEFAULT (now() + '1 day'::interval), IN source_ text DEFAULT NULL::text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
    insert into jwt_key (
        public_key,
        private_key,
        source,
        expired_tz
    )
        select
            md5(gen_random_uuid()::text),
            md5(gen_random_uuid()::text),
            source_,
            expired_tz_
        from generate_series(1,n)
$$;


--
-- Name: jwt_decode(text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.jwt_decode(jwt_text text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
begin
    return (
        with
        t1 as (
            select string_to_array(jwt_text, '.') as a),
        t2 as (
            select
                header->>'jti' as public_key,
                now() > to_timestamp(
                    header->>'exp',
                    'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                )::timestamp at time zone 'UTC'
                as is_expired
            from (
                select from_utf8(t1.a[1])
                from t1
            ) t3 (header)
        )
        select case
            when cardinality(t1.a)<>3
                then null
            when t2.public_key is null or t2.is_expired
                then null
            when hash (
                a[1] || '.' || a[2], -- header.payload
                (
                    select private_key
                    from jwt_key
                    where public_key = t2.public_key
                )
                ) = a[3] -- compare signature
                then from_utf8(a[2])
            else null
            end
        from t1, t2
    );
exception
    when others then
        return null;
end;
$$;


--
-- Name: jwt_decode(text, text, text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.jwt_decode(jwt_text text, key text, enc text DEFAULT 'HS256'::text) RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
    with
    t1 as (
        select string_to_array(jwt_text, '.')
        as a)
    select case
        when hash(a[1] || '.' || a[2], key, enc) = a[3] then from_utf8(a[2])
        else null
        end
    from t1;
$$;


--
-- Name: jwt_encode(jsonb, timestamp with time zone, text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.jwt_encode(payload jsonb, expired_tz_ timestamp with time zone DEFAULT (now() + '00:30:00'::interval), public_key_like_ text DEFAULT '%'::text) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
    with
    jk as (
        select *
        from jwt_key
        where public_key like public_key_like_
        and expired_tz > expired_tz_
        order by random()
        limit 1
    )
    select jwt_encode (
        payload,
        jk.private_key,
        jsonb_build_object (
            'jti', jk.public_key,
            'exp', to_char(expired_tz_::timestamp at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        ))
    from jk
$$;


--
-- Name: jwt_encode(jsonb, text, jsonb, text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.jwt_encode(payload jsonb, key text, header jsonb, enc text DEFAULT 'HS256'::text) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
    with
    t1 as (
        select jsonb_build_object('typ', 'JWT')
            || header
        as a),
    t2 as (
        select to_utf8(t1.a)
            || '.'
            || to_utf8(payload)
        as a
        from t1)
    select
        t2.a
        || '.' || hash(t2.a, key, enc) from t2;
$$;


--
-- Name: jwt_recode(text, timestamp with time zone, text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.jwt_recode(jwt_text text, expired_tz_ timestamp with time zone DEFAULT (now() + '00:30:00'::interval), public_key_like_ text DEFAULT '%'::text) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
    with
    t1 as (
        select jwt_decode(jwt_text) as p)
    select case
        when t1.p is null
            then null
        else jwt_encode(t1.p, expired_tz_, public_key_like_)
        end
    from t1
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: jwt_key; Type: TABLE; Schema: jwt_; Owner: -
--

CREATE TABLE jwt_.jwt_key (
    public_key text NOT NULL,
    private_key text NOT NULL,
    source text,
    expired_tz timestamp with time zone DEFAULT (now() + '1 day'::interval)
);


--
-- Name: prune_keys(timestamp with time zone, text); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.prune_keys(expired_tz_ timestamp with time zone DEFAULT now(), source_ text DEFAULT NULL::text) RETURNS SETOF jwt_.jwt_key
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $$
    delete from jwt_key
    where expired_tz_ <= expired_tz_
    and (source_ is null or source=source_)
    returning *
$$;


--
-- Name: to_utf8(jsonb); Type: FUNCTION; Schema: jwt; Owner: -
--

CREATE FUNCTION jwt.to_utf8(jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    SET search_path TO 'jwt', 'jwt_', 'public'
    AS $_$
    select to_base64(convert_to($1::text, 'utf8'))
$_$;


--
-- Name: from_base64(text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.from_base64(text) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $_$
    with
    s as (
        select translate($1, '-_', '+/') s),
    n as (
        select length(s) % 4 as n from s),
    p as (
        select case
        when n.n>0 then repeat('=', 4 - n.n)
        else ''
        end as p
        from n)
    select decode (s.s || p.p, 'base64')
    from s, p
$_$;


--
-- Name: from_utf8(text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.from_utf8(text) RETURNS jsonb
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $_$
    select convert_from(from_base64($1), 'utf8')::jsonb;
$_$;


--
-- Name: gen_keys(integer, timestamp with time zone, text); Type: PROCEDURE; Schema: jwt_; Owner: -
--

CREATE PROCEDURE jwt_.gen_keys(IN n integer DEFAULT 10, IN expired_tz_ timestamp with time zone DEFAULT (now() + '1 day'::interval), IN source_ text DEFAULT NULL::text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
    insert into jwt_key (
        public_key,
        private_key,
        source,
        expired_tz
    )
        select
            md5(gen_random_uuid()::text),
            md5(gen_random_uuid()::text),
            source_,
            expired_tz_
        from generate_series(1,n)
$$;


--
-- Name: hash(text, text, text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.hash(txt text, key text, alg text DEFAULT 'HS256'::text) RETURNS text
    LANGUAGE sql IMMUTABLE SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $_$
    with
    t1 as (
        select
        case
        when $3 = 'HS256' then 'sha256'
        when $3 = 'HS384' then 'sha384'
        when $3 = 'HS512' then 'sha512'
        else ''
        end as a),
    t2 as (
        select public.hmac($1, $2, t1.a) as a
        from t1)
    select to_base64(t2.a)
    from t2
$_$;


--
-- Name: jwt_decode(text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.jwt_decode(jwt_text text) RETURNS jsonb
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
begin
    return (
        with
        t1 as (
            select string_to_array(jwt_text, '.') as a),
        t2 as (
            select
                header->>'jti' as public_key,
                now() > to_timestamp(
                    header->>'exp',
                    'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                )::timestamp at time zone 'UTC'
                as is_expired
            from (
                select from_utf8(t1.a[1])
                from t1
            ) t3 (header)
        )
        select case
            when cardinality(t1.a)<>3
                then null
            when t2.public_key is null or t2.is_expired
                then null
            when hash (
                a[1] || '.' || a[2], -- header.payload
                (
                    select private_key
                    from jwt_key
                    where public_key = t2.public_key
                )
                ) = a[3] -- compare signature
                then from_utf8(a[2])
            else null
            end
        from t1, t2
    );
exception
    when others then
        return null;
end;
$$;


--
-- Name: jwt_decode(text, text, text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.jwt_decode(jwt_text text, key text, enc text DEFAULT 'HS256'::text) RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
    with
    t1 as (
        select string_to_array(jwt_text, '.')
        as a)
    select case
        when hash(a[1] || '.' || a[2], key, enc) = a[3] then from_utf8(a[2])
        else null
        end
    from t1;
$$;


--
-- Name: jwt_encode(jsonb, timestamp with time zone, text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.jwt_encode(payload jsonb, expired_tz_ timestamp with time zone DEFAULT (now() + '00:30:00'::interval), public_key_like_ text DEFAULT '%'::text) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
    with
    jk as (
        select *
        from jwt_key
        where public_key like public_key_like_
        and expired_tz > expired_tz_
        order by random()
        limit 1
    )
    select jwt_encode (
        payload,
        jk.private_key,
        jsonb_build_object (
            'jti', jk.public_key,
            'exp', to_char(expired_tz_::timestamp at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        ))
    from jk
$$;


--
-- Name: jwt_encode(jsonb, text, jsonb, text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.jwt_encode(payload jsonb, key text, header jsonb, enc text DEFAULT 'HS256'::text) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
    with
    t1 as (
        select jsonb_build_object('typ', 'JWT')
            || header
        as a),
    t2 as (
        select to_utf8(t1.a)
            || '.'
            || to_utf8(payload)
        as a
        from t1)
    select
        t2.a
        || '.' || hash(t2.a, key, enc) from t2;
$$;


--
-- Name: jwt_recode(text, timestamp with time zone, text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.jwt_recode(jwt_text text, expired_tz_ timestamp with time zone DEFAULT (now() + '00:30:00'::interval), public_key_like_ text DEFAULT '%'::text) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
    with
    t1 as (
        select jwt_decode(jwt_text) as p)
    select case
        when t1.p is null
            then null
        else jwt_encode(t1.p, expired_tz_, public_key_like_)
        end
    from t1
$$;


--
-- Name: prune_keys(timestamp with time zone, text); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.prune_keys(expired_tz_ timestamp with time zone DEFAULT now(), source_ text DEFAULT NULL::text) RETURNS SETOF jwt_.jwt_key
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $$
    delete from jwt_key
    where expired_tz_ <= expired_tz_
    and (source_ is null or source=source_)
    returning *
$$;


--
-- Name: to_base64(bytea); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.to_base64(bytea) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    SET search_path TO 'jwt_', 'public'
    AS $_$
    select translate(
        encode($1, 'base64'),
        E'+/=\n',
        '-_')
$_$;


--
-- Name: to_utf8(jsonb); Type: FUNCTION; Schema: jwt_; Owner: -
--

CREATE FUNCTION jwt_.to_utf8(jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    SET search_path TO 'jwt_', 'public'
    AS $_$
    select to_base64(convert_to($1::text, 'utf8'))
$_$;


--
-- Name: jwt_key jwt_key_pkey; Type: CONSTRAINT; Schema: jwt_; Owner: -
--

ALTER TABLE ONLY jwt_.jwt_key
    ADD CONSTRAINT jwt_key_pkey PRIMARY KEY (public_key);


--
-- PostgreSQL database dump complete
--

