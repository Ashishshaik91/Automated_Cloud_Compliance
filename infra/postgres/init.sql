-- PostgreSQL initialization for Cloud Compliance Platform
-- This runs automatically on first container start.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone
SET timezone = 'UTC';

-- Create indexes will be handled by SQLAlchemy ORM on startup
