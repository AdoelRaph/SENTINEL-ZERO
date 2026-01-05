-- Sentinel-Zero Database Schema
-- Neon PostgreSQL (Serverless)
-- Version: 1.0.0

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Custom ENUM types for strict data validation
CREATE TYPE asset_type AS ENUM (
    'server',
    'workstation',
    'network_device',
    'iot_device',
    'mobile_device',
    'virtual_machine',
    'container',
    'cloud_instance',
    'unknown'
);

CREATE TYPE asset_status AS ENUM (
    'active',
    'inactive',
    'decommissioned',
    'quarantined',
    'maintenance'
);

CREATE TYPE vulnerability_severity AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'informational'
);

CREATE TYPE vulnerability_status AS ENUM (
    'open',
    'in_progress',
    'remediated',
    'accepted_risk',
    'false_positive'
);

CREATE TYPE remediation_status AS ENUM (
    'pending_approval',
    'approved',
    'rejected',
    'in_progress',
    'completed',
    'failed',
    'rolled_back'
);

CREATE TYPE threat_source AS ENUM (
    'nist_nvd',
    'cisa_kev',
    'exploit_db',
    'internal_scan',
    'ml_detection',
    'manual_entry'
);

CREATE TYPE anomaly_type AS ENUM (
    'dos_loop',
    'backdoor_connection',
    'data_exfiltration',
    'lateral_movement',
    'privilege_escalation',
    'suspicious_port',
    'unknown_destination',
    'protocol_anomaly'
);

-- ============================================================================
-- Core Tables
-- ============================================================================

-- Organizations (multi-tenancy support)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    license_key VARCHAR(64) NOT NULL UNIQUE,
    license_expires_at TIMESTAMPTZ NOT NULL,
    max_assets INTEGER NOT NULL DEFAULT 1000,
    features JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_license CHECK (license_expires_at > created_at)
);

CREATE INDEX idx_org_license ON organizations(license_key);

-- Users and Authentication
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_encrypted BYTEA,
    last_login_at TIMESTAMPTZ,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_email_per_org UNIQUE (organization_id, email),
    CONSTRAINT valid_role CHECK (role IN ('admin', 'analyst', 'viewer', 'api_service'))
);

CREATE INDEX idx_users_org ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);

-- ============================================================================
-- Asset Inventory (Zero-Trust Asset Tracking)
-- ============================================================================

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Identification
    hostname VARCHAR(255),
    ip_address INET NOT NULL,
    mac_address MACADDR,
    asset_type asset_type NOT NULL DEFAULT 'unknown',

    -- Classification
    is_server BOOLEAN NOT NULL DEFAULT FALSE,
    is_critical BOOLEAN NOT NULL DEFAULT FALSE,
    business_unit VARCHAR(100),
    owner_email VARCHAR(255),

    -- System Information
    os_family VARCHAR(50),
    os_version VARCHAR(100),
    os_build VARCHAR(100),
    kernel_version VARCHAR(100),

    -- Network Context
    network_segment VARCHAR(50),
    vlan_id INTEGER,
    gateway_ip INET,

    -- Discovery Metadata
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    discovery_method VARCHAR(50) NOT NULL DEFAULT 'network_scan',

    -- Status Tracking
    status asset_status NOT NULL DEFAULT 'active',
    quarantine_reason TEXT,
    quarantine_at TIMESTAMPTZ,

    -- Extended Attributes
    open_ports INTEGER[] DEFAULT '{}',
    services JSONB DEFAULT '[]',
    installed_software JSONB DEFAULT '[]',
    custom_attributes JSONB DEFAULT '{}',

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_ip_per_org UNIQUE (organization_id, ip_address)
);

-- Comprehensive indexing for asset queries
CREATE INDEX idx_assets_org ON assets(organization_id);
CREATE INDEX idx_assets_ip ON assets(ip_address);
CREATE INDEX idx_assets_mac ON assets(mac_address);
CREATE INDEX idx_assets_hostname ON assets USING gin(hostname gin_trgm_ops);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_last_seen ON assets(last_seen_at DESC);
CREATE INDEX idx_assets_critical ON assets(organization_id, is_critical) WHERE is_critical = TRUE;
CREATE INDEX idx_assets_open_ports ON assets USING gin(open_ports);

-- ============================================================================
-- Vulnerability Management
-- ============================================================================

-- Known Threats (CVE Database)
CREATE TABLE known_threats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- CVE Identification
    cve_id VARCHAR(20) NOT NULL UNIQUE,

    -- Descriptive Information
    title VARCHAR(500) NOT NULL,
    description TEXT,

    -- Severity Scoring
    cvss_v3_score DECIMAL(3, 1),
    cvss_v3_vector VARCHAR(100),
    cvss_v2_score DECIMAL(3, 1),
    severity vulnerability_severity NOT NULL,

    -- Affected Systems
    affected_products JSONB DEFAULT '[]',
    affected_versions JSONB DEFAULT '[]',
    cpe_matches JSONB DEFAULT '[]',

    -- Exploit Information
    is_exploited_in_wild BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_maturity VARCHAR(50),
    exploit_references JSONB DEFAULT '[]',

    -- Source Tracking
    source threat_source NOT NULL,
    source_url TEXT,

    -- Temporal Information
    published_at TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,

    -- CISA KEV Fields
    cisa_kev_added_at TIMESTAMPTZ,
    cisa_due_date DATE,
    cisa_required_action TEXT,

    -- Metadata
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_threats_cve ON known_threats(cve_id);
CREATE INDEX idx_threats_severity ON known_threats(severity);
CREATE INDEX idx_threats_cvss ON known_threats(cvss_v3_score DESC NULLS LAST);
CREATE INDEX idx_threats_exploited ON known_threats(is_exploited_in_wild) WHERE is_exploited_in_wild = TRUE;
CREATE INDEX idx_threats_cisa ON known_threats(cisa_kev_added_at DESC NULLS LAST);
CREATE INDEX idx_threats_products ON known_threats USING gin(affected_products);
CREATE INDEX idx_threats_cpe ON known_threats USING gin(cpe_matches);

-- Asset Vulnerabilities (Many-to-Many with Context)
CREATE TABLE asset_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    threat_id UUID NOT NULL REFERENCES known_threats(id) ON DELETE CASCADE,

    -- Status Tracking
    status vulnerability_status NOT NULL DEFAULT 'open',

    -- Detection Context
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detected_by VARCHAR(50) NOT NULL,
    detection_confidence DECIMAL(5, 4) CHECK (detection_confidence BETWEEN 0 AND 1),

    -- Affected Component
    affected_component VARCHAR(255),
    affected_version VARCHAR(100),
    installed_version VARCHAR(100),

    -- Risk Context
    is_exploitable BOOLEAN,
    network_exposure VARCHAR(50),

    -- Remediation Tracking
    remediated_at TIMESTAMPTZ,
    remediated_by UUID REFERENCES users(id),
    remediation_notes TEXT,

    -- Risk Acceptance
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id),
    acceptance_justification TEXT,
    acceptance_expires_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_asset_threat UNIQUE (asset_id, threat_id)
);

CREATE INDEX idx_asset_vuln_org ON asset_vulnerabilities(organization_id);
CREATE INDEX idx_asset_vuln_asset ON asset_vulnerabilities(asset_id);
CREATE INDEX idx_asset_vuln_threat ON asset_vulnerabilities(threat_id);
CREATE INDEX idx_asset_vuln_status ON asset_vulnerabilities(status);
CREATE INDEX idx_asset_vuln_open ON asset_vulnerabilities(organization_id, status)
    WHERE status = 'open';

-- ============================================================================
-- ML Anomaly Detection
-- ============================================================================

CREATE TABLE anomaly_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    -- Anomaly Classification
    anomaly_type anomaly_type NOT NULL,
    severity vulnerability_severity NOT NULL,

    -- Detection Details
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detection_model_version VARCHAR(50) NOT NULL,
    confidence_score DECIMAL(5, 4) NOT NULL CHECK (confidence_score BETWEEN 0 AND 1),

    -- Source Information
    source_ip INET,
    source_port INTEGER,
    destination_ip INET,
    destination_port INTEGER,
    protocol VARCHAR(20),

    -- Traffic Analysis
    packet_count BIGINT,
    byte_count BIGINT,
    time_window_seconds INTEGER,
    packets_per_second DECIMAL(12, 2),

    -- Feature Vector (for audit/retraining)
    feature_vector JSONB NOT NULL,
    raw_sample_r2_key TEXT,

    -- Investigation Status
    is_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    is_false_positive BOOLEAN,
    investigation_notes TEXT,

    -- Related Alerts
    related_detection_ids UUID[] DEFAULT '{}',

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_anomaly_org ON anomaly_detections(organization_id);
CREATE INDEX idx_anomaly_asset ON anomaly_detections(asset_id);
CREATE INDEX idx_anomaly_type ON anomaly_detections(anomaly_type);
CREATE INDEX idx_anomaly_severity ON anomaly_detections(severity);
CREATE INDEX idx_anomaly_detected ON anomaly_detections(detected_at DESC);
CREATE INDEX idx_anomaly_unacked ON anomaly_detections(organization_id, is_acknowledged)
    WHERE is_acknowledged = FALSE;
CREATE INDEX idx_anomaly_src_ip ON anomaly_detections(source_ip);
CREATE INDEX idx_anomaly_dst_ip ON anomaly_detections(destination_ip);

-- ============================================================================
-- Remediation Workflow
-- ============================================================================

CREATE TABLE remediation_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES asset_vulnerabilities(id) ON DELETE SET NULL,
    anomaly_id UUID REFERENCES anomaly_detections(id) ON DELETE SET NULL,

    -- Task Definition
    task_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    priority vulnerability_severity NOT NULL,

    -- Remediation Details
    remediation_script TEXT,
    remediation_template VARCHAR(100),
    parameters JSONB DEFAULT '{}',

    -- Risk Assessment
    risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    requires_downtime BOOLEAN NOT NULL DEFAULT FALSE,
    estimated_downtime_minutes INTEGER,
    rollback_available BOOLEAN NOT NULL DEFAULT TRUE,
    rollback_script TEXT,

    -- Approval Workflow
    status remediation_status NOT NULL DEFAULT 'pending_approval',
    auto_approved BOOLEAN NOT NULL DEFAULT FALSE,

    requested_by UUID NOT NULL REFERENCES users(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    secondary_approved_by UUID REFERENCES users(id),
    secondary_approved_at TIMESTAMPTZ,

    rejected_by UUID REFERENCES users(id),
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,

    -- Execution Tracking
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Results
    execution_output TEXT,
    error_message TEXT,
    exit_code INTEGER,

    -- Rollback
    rolled_back_at TIMESTAMPTZ,
    rolled_back_by UUID REFERENCES users(id),
    rollback_reason TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT has_source CHECK (vulnerability_id IS NOT NULL OR anomaly_id IS NOT NULL)
);

CREATE INDEX idx_remediation_org ON remediation_tasks(organization_id);
CREATE INDEX idx_remediation_asset ON remediation_tasks(asset_id);
CREATE INDEX idx_remediation_status ON remediation_tasks(status);
CREATE INDEX idx_remediation_priority ON remediation_tasks(priority);
CREATE INDEX idx_remediation_pending ON remediation_tasks(organization_id, status)
    WHERE status = 'pending_approval';

-- ============================================================================
-- Comprehensive Audit Logging
-- ============================================================================

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,

    -- Actor Information
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    actor_type VARCHAR(50) NOT NULL DEFAULT 'user',
    ip_address INET,
    user_agent TEXT,

    -- Action Details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,

    -- Change Tracking
    previous_state JSONB,
    new_state JSONB,
    changes JSONB,

    -- Context
    request_id UUID,
    session_id UUID,

    -- Result
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,

    -- Compliance Fields
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    compliance_flags VARCHAR(50)[] DEFAULT '{}',

    -- R2 Reference (for large payloads)
    r2_detail_key TEXT,

    -- Timestamp (partition key)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create partitions for the current and next 12 months
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
CREATE TABLE audit_logs_2025_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
CREATE TABLE audit_logs_2025_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-03-01') TO ('2025-04-01');
CREATE TABLE audit_logs_2025_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-04-01') TO ('2025-05-01');
CREATE TABLE audit_logs_2025_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-05-01') TO ('2025-06-01');
CREATE TABLE audit_logs_2025_06 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-06-01') TO ('2025-07-01');
CREATE TABLE audit_logs_2025_07 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-07-01') TO ('2025-08-01');
CREATE TABLE audit_logs_2025_08 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
CREATE TABLE audit_logs_2025_09 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');
CREATE TABLE audit_logs_2025_10 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
CREATE TABLE audit_logs_2025_11 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE TABLE audit_logs_2025_12 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

CREATE INDEX idx_audit_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_time ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_sensitive ON audit_logs(organization_id, is_sensitive)
    WHERE is_sensitive = TRUE;

-- ============================================================================
-- Network Allowlists (for backdoor detection)
-- ============================================================================

CREATE TABLE network_allowlists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Rule Definition
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Network Specification
    ip_range CIDR,
    ip_address INET,
    domain_pattern VARCHAR(255),
    port_range INT4RANGE,

    -- Context
    direction VARCHAR(20) NOT NULL DEFAULT 'outbound',
    protocol VARCHAR(20),

    -- Validation
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMPTZ,

    -- Audit
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT has_target CHECK (
        ip_range IS NOT NULL OR ip_address IS NOT NULL OR domain_pattern IS NOT NULL
    ),
    CONSTRAINT valid_direction CHECK (direction IN ('inbound', 'outbound', 'both'))
);

CREATE INDEX idx_allowlist_org ON network_allowlists(organization_id);
CREATE INDEX idx_allowlist_ip ON network_allowlists(ip_address);
CREATE INDEX idx_allowlist_range ON network_allowlists USING gist(ip_range inet_ops);
CREATE INDEX idx_allowlist_active ON network_allowlists(organization_id, is_active)
    WHERE is_active = TRUE;

-- ============================================================================
-- ML Model Registry
-- ============================================================================

CREATE TABLE ml_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,

    -- Model Identification
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    model_type VARCHAR(50) NOT NULL,

    -- Storage
    r2_model_key TEXT NOT NULL,
    r2_metadata_key TEXT,
    file_size_bytes BIGINT NOT NULL,
    checksum_sha256 VARCHAR(64) NOT NULL,

    -- Performance Metrics
    training_samples INTEGER NOT NULL,
    validation_accuracy DECIMAL(5, 4),
    false_positive_rate DECIMAL(5, 4),
    false_negative_rate DECIMAL(5, 4),
    auc_score DECIMAL(5, 4),

    -- Training Context
    training_started_at TIMESTAMPTZ NOT NULL,
    training_completed_at TIMESTAMPTZ NOT NULL,
    training_duration_seconds INTEGER NOT NULL,
    hyperparameters JSONB NOT NULL DEFAULT '{}',
    feature_columns TEXT[] NOT NULL,

    -- Deployment
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    activated_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,

    -- Audit
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_active_model UNIQUE (organization_id, model_name, is_active)
);

CREATE INDEX idx_ml_models_org ON ml_models(organization_id);
CREATE INDEX idx_ml_models_name ON ml_models(model_name);
CREATE INDEX idx_ml_models_active ON ml_models(organization_id, model_name, is_active)
    WHERE is_active = TRUE;

-- ============================================================================
-- Scan History
-- ============================================================================

CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Scan Configuration
    scan_type VARCHAR(50) NOT NULL,
    target_specification TEXT NOT NULL,
    scan_profile VARCHAR(50) NOT NULL DEFAULT 'standard',

    -- Execution
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Results Summary
    assets_discovered INTEGER DEFAULT 0,
    assets_updated INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    errors_encountered INTEGER DEFAULT 0,

    -- Detailed Results (R2 reference for large scans)
    results_summary JSONB,
    r2_full_results_key TEXT,

    -- Audit
    initiated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_jobs_org ON scan_jobs(organization_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_time ON scan_jobs(created_at DESC);

-- ============================================================================
-- Functions and Triggers
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all tables with updated_at
CREATE TRIGGER update_organizations_timestamp BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_users_timestamp BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_assets_timestamp BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_known_threats_timestamp BEFORE UPDATE ON known_threats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_asset_vulnerabilities_timestamp BEFORE UPDATE ON asset_vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_anomaly_detections_timestamp BEFORE UPDATE ON anomaly_detections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_remediation_tasks_timestamp BEFORE UPDATE ON remediation_tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_network_allowlists_timestamp BEFORE UPDATE ON network_allowlists
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_scan_jobs_timestamp BEFORE UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function to check if IP is in allowlist
CREATE OR REPLACE FUNCTION is_ip_allowed(
    p_organization_id UUID,
    p_ip INET,
    p_port INTEGER DEFAULT NULL,
    p_direction VARCHAR(20) DEFAULT 'outbound'
)
RETURNS BOOLEAN AS $$
DECLARE
    v_allowed BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM network_allowlists
        WHERE organization_id = p_organization_id
          AND is_active = TRUE
          AND (expires_at IS NULL OR expires_at > NOW())
          AND (direction = p_direction OR direction = 'both')
          AND (
              ip_address = p_ip
              OR (ip_range IS NOT NULL AND p_ip << ip_range)
          )
          AND (
              p_port IS NULL
              OR port_range IS NULL
              OR p_port <@ port_range
          )
    ) INTO v_allowed;

    RETURN v_allowed;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- Row Level Security (Enterprise Multi-Tenancy)
-- ============================================================================

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE anomaly_detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_allowlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;

-- Policies will be created per-application role
-- Example for a tenant-scoped role:
-- CREATE POLICY tenant_isolation ON assets
--     USING (organization_id = current_setting('app.current_org_id')::UUID);

-- ============================================================================
-- Initial Data
-- ============================================================================

-- Insert default organization for single-tenant deployments
INSERT INTO organizations (
    id,
    name,
    license_key,
    license_expires_at,
    max_assets,
    features
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default Organization',
    'SENTINEL-ZERO-DEFAULT-LICENSE',
    NOW() + INTERVAL '1 year',
    10000,
    '{"ml_enabled": true, "auto_remediation": true, "wireless_scanning": true}'
);

COMMENT ON TABLE organizations IS 'Multi-tenant organization management with license enforcement';
COMMENT ON TABLE assets IS 'Zero-trust asset inventory with comprehensive system metadata';
COMMENT ON TABLE known_threats IS 'Aggregated threat intelligence from NIST NVD, CISA KEV, and other sources';
COMMENT ON TABLE asset_vulnerabilities IS 'Association of discovered vulnerabilities with specific assets';
COMMENT ON TABLE anomaly_detections IS 'ML-detected behavioral anomalies including DoS loops and backdoors';
COMMENT ON TABLE remediation_tasks IS 'Workflow-managed remediation with approval chains';
COMMENT ON TABLE audit_logs IS 'Immutable audit trail for compliance (SOC 2, HIPAA, PCI-DSS)';
COMMENT ON TABLE network_allowlists IS 'Approved network destinations for backdoor detection baseline';
COMMENT ON TABLE ml_models IS 'Registry of trained ML models with versioning and performance metrics';