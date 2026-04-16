-- =============================================================================
-- GAZE Security Platform - Database Initialization
-- Security-first PostgreSQL configuration
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Row Level Security Policies
-- =============================================================================

-- Function to get current user role from app context
CREATE OR REPLACE FUNCTION current_app_user_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', true), '')::UUID;
EXCEPTION
    WHEN OTHERS THEN RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION current_app_user_role() RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_role', true), '');
EXCEPTION
    WHEN OTHERS THEN RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- Audit Trigger Function
-- =============================================================================

CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
DECLARE
    audit_row JSONB;
    changes JSONB;
BEGIN
    IF TG_OP = 'DELETE' THEN
        audit_row = to_jsonb(OLD);
        changes = NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        audit_row = to_jsonb(NEW);
        -- Calculate changes
        SELECT jsonb_object_agg(key, jsonb_build_object('before', old_val, 'after', new_val))
        INTO changes
        FROM (
            SELECT key, 
                   to_jsonb(OLD)->key as old_val,
                   to_jsonb(NEW)->key as new_val
            FROM jsonb_object_keys(to_jsonb(NEW)) AS key
            WHERE to_jsonb(OLD)->key IS DISTINCT FROM to_jsonb(NEW)->key
        ) diff;
    ELSE
        audit_row = to_jsonb(NEW);
        changes = NULL;
    END IF;

    INSERT INTO audit_logs (
        table_name,
        record_id,
        action,
        user_id,
        changes,
        old_values,
        new_values,
        created_at
    ) VALUES (
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        TG_OP,
        current_app_user_id(),
        changes,
        CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END,
        NOW()
    );

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- Application User (limited privileges)
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'secops_app') THEN
        CREATE ROLE secops_app WITH LOGIN PASSWORD 'changeme_in_production';
    END IF;
END
$$;

-- Grant minimal required permissions (will be set up after tables are created)
-- GRANT CONNECT ON DATABASE secops TO secops_app;
-- GRANT USAGE ON SCHEMA public TO secops_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secops_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secops_app;

-- =============================================================================
-- Secure Configuration (Development - SSL disabled)
-- For production, enable SSL with proper certificates
-- =============================================================================

-- SSL disabled for development (enable in production with proper certs)
-- ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
ALTER SYSTEM SET log_statement = 'ddl';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
