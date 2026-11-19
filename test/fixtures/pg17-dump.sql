--
-- PostgreSQL database dump
--

\restrict Wm9YGW51STavfOVmBN7t8HLg6KXYH3Y4B0Vhybd3JNXTZye45O3vcrEiRHAG1by

-- Dumped from database version 17.11
-- Dumped by pg_dump version 17.11

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
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
-- Name: LegacyAuditLog; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."LegacyAuditLog" (
    "EventId" bigint,
    total_amount double precision,
    payload text
);


--
-- Name: customer_profile; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_profile (
    customer_id bigint NOT NULL,
    full_name character varying(64) NOT NULL,
    mobile_phone character varying(32),
    id_card_no character varying(32),
    bank_card_number character varying(32),
    email_address character varying(128),
    home_address character varying(255),
    password_hash character varying(255) NOT NULL,
    api_secret_key character varying(128),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE customer_profile; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.customer_profile IS 'Customer profile metadata';


--
-- Name: COLUMN customer_profile.customer_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.customer_id IS 'Primary key';


--
-- Name: COLUMN customer_profile.full_name; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.full_name IS 'Customer full name';


--
-- Name: COLUMN customer_profile.mobile_phone; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.mobile_phone IS 'Mobile phone number';


--
-- Name: COLUMN customer_profile.id_card_no; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.id_card_no IS 'National ID number';


--
-- Name: COLUMN customer_profile.bank_card_number; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.bank_card_number IS 'Bank card number';


--
-- Name: COLUMN customer_profile.email_address; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.email_address IS 'Email address';


--
-- Name: COLUMN customer_profile.home_address; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.home_address IS 'Residential address';


--
-- Name: COLUMN customer_profile.password_hash; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.password_hash IS 'Hashed password';


--
-- Name: COLUMN customer_profile.api_secret_key; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.api_secret_key IS 'API secret credential';


--
-- Name: COLUMN customer_profile.created_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.customer_profile.created_at IS 'Creation timestamp';


--
-- Name: orders_fact; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orders_fact (
    order_id bigint NOT NULL,
    customer_id bigint NOT NULL,
    pay_amount numeric(18,2) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE orders_fact; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.orders_fact IS 'Core orders fact table';


--
-- Name: COLUMN orders_fact.order_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders_fact.order_id IS 'Primary order identifier';


--
-- Name: COLUMN orders_fact.customer_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders_fact.customer_id IS 'Customer identifier';


--
-- Name: COLUMN orders_fact.pay_amount; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders_fact.pay_amount IS 'Payment amount in CNY';


--
-- Name: COLUMN orders_fact.created_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.orders_fact.created_at IS 'Record creation timestamp';


--
-- Name: orders_fact_order_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.orders_fact ALTER COLUMN order_id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.orders_fact_order_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: customer_profile customer_profile_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_profile
    ADD CONSTRAINT customer_profile_pkey PRIMARY KEY (customer_id);


--
-- Name: orders_fact orders_fact_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orders_fact
    ADD CONSTRAINT orders_fact_pkey PRIMARY KEY (order_id);


--
-- PostgreSQL database dump complete
--

\unrestrict Wm9YGW51STavfOVmBN7t8HLg6KXYH3Y4B0Vhybd3JNXTZye45O3vcrEiRHAG1by

