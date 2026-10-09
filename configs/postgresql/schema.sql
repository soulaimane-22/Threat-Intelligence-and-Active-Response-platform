--
-- PostgreSQL database dump
--

\restrict Ate7TG0pnht9RtAMOiU6Gp8h4W5RuufxETLY75IdaHwS8Zp6wCfIt3Xefr7Ax99

-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: actions_taken; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actions_taken (
    id integer NOT NULL,
    incident_id integer NOT NULL,
    action_type character varying NOT NULL,
    execution_status character varying NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    target_path text,
    target_sha256 text,
    created_at timestamp with time zone DEFAULT now(),
    target_ip text,
    target_pid text
);


--
-- Name: actions_taken_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.actions_taken_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: actions_taken_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.actions_taken_id_seq OWNED BY public.actions_taken.id;


--
-- Name: incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incidents (
    id integer NOT NULL,
    agent_source character varying NOT NULL,
    wazuh_rule_id integer NOT NULL,
    mitre_technique character varying,
    ioc_id integer,
    risk_score double precision NOT NULL,
    criticality character varying NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: incidents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incidents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incidents_id_seq OWNED BY public.incidents.id;


--
-- Name: ioc_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_cache (
    id integer NOT NULL,
    value character varying NOT NULL,
    type character varying NOT NULL,
    source character varying NOT NULL,
    verdict character varying NOT NULL,
    reputation_score double precision,
    last_checked_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_cache_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_cache_id_seq OWNED BY public.ioc_cache.id;


--
-- Name: processed_wazuh_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.processed_wazuh_events (
    wazuh_event_id text NOT NULL,
    scenario text NOT NULL,
    processed_at timestamp with time zone DEFAULT now()
);


--
-- Name: actions_taken id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actions_taken ALTER COLUMN id SET DEFAULT nextval('public.actions_taken_id_seq'::regclass);


--
-- Name: incidents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents ALTER COLUMN id SET DEFAULT nextval('public.incidents_id_seq'::regclass);


--
-- Name: ioc_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_cache ALTER COLUMN id SET DEFAULT nextval('public.ioc_cache_id_seq'::regclass);


--
-- Name: actions_taken actions_taken_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actions_taken
    ADD CONSTRAINT actions_taken_pkey PRIMARY KEY (id);


--
-- Name: incidents incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (id);


--
-- Name: ioc_cache ioc_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_cache
    ADD CONSTRAINT ioc_cache_pkey PRIMARY KEY (id);


--
-- Name: ioc_cache ioc_cache_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_cache
    ADD CONSTRAINT ioc_cache_value_key UNIQUE (value);


--
-- Name: processed_wazuh_events processed_wazuh_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.processed_wazuh_events
    ADD CONSTRAINT processed_wazuh_events_pkey PRIMARY KEY (wazuh_event_id);


--
-- Name: actions_taken actions_taken_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actions_taken
    ADD CONSTRAINT actions_taken_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id);


--
-- Name: incidents incidents_ioc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_ioc_id_fkey FOREIGN KEY (ioc_id) REFERENCES public.ioc_cache(id);


--
-- PostgreSQL database dump complete
--

\unrestrict Ate7TG0pnht9RtAMOiU6Gp8h4W5RuufxETLY75IdaHwS8Zp6wCfIt3Xefr7Ax99

