CREATE SCHEMA IF NOT EXISTS public;
SET search_path TO public;

-- Bảng SBOM Metadata
CREATE TABLE sbom_metadata
(
    sbom_id VARCHAR(255) PRIMARY KEY,
    authors VARCHAR,
    created_timestamp TIMESTAMP,
    system_id INTEGER,
    tool_components VARCHAR,
    tool_services VARCHAR,
    lifecycle_phase TEXT
);

-- Bảng Component
CREATE TABLE component
(
    component_id VARCHAR(255) PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    supplier_name VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    version TEXT,
    purl TEXT,
    cpe TEXT,
    hashes VARCHAR,
    licenses VARCHAR,
    support_level TEXT,
    end_of_support DATE,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Dependency
CREATE TABLE dependency
(
    dependency_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    component_ref VARCHAR(255) NOT NULL,
    depends_on_ref VARCHAR(255) NOT NULL,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE,
    FOREIGN KEY (component_ref) REFERENCES component(component_id),
    FOREIGN KEY (depends_on_ref) REFERENCES component(component_id)
);

-- Bảng Vulnerability
CREATE TABLE vulnerability
(
    vuln_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    installed TEXT,
    fixed_in TEXT,
    package_type TEXT,
    vulnerability VARCHAR(255),
    severity VARCHAR(50),
    epss NUMERIC(6,5),
    risk VARCHAR(50),
    cve_id TEXT,
    description VARCHAR,
    affected_component_ref VARCHAR(255),
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE,
    FOREIGN KEY (affected_component_ref) REFERENCES component(component_id)
);

-- Bảng Composition
CREATE TABLE composition
(
    composition_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    aggregate_type VARCHAR(100),
    assemblies VARCHAR,
    dependencies VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Formulation
CREATE TABLE formulation
(
    formulation_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    components VARCHAR,
    workflows VARCHAR,
    tools VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Annotation
CREATE TABLE annotation
(
    annotation_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    annotator VARCHAR(255),
    created_timestamp TIMESTAMP,
    text TEXT NOT NULL,
    subjects VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Declaration
CREATE TABLE declaration
(
    declaration_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    issuer VARCHAR(255),
    claims VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Citation
CREATE TABLE citation
(
    citation_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    title VARCHAR(255),
    url VARCHAR(500) NOT NULL,
    description VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Definition
CREATE TABLE definition
(
    definition_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    components VARCHAR,
    services VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng Service
CREATE TABLE service
(
    service_id SERIAL PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    version TEXT,
    description VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);

-- Bảng System để lưu các hệ thống / project
CREATE TABLE IF NOT EXISTS system
(
    system_id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_uploaded_at TIMESTAMP
);

-- Repository-first catalog for the Web Application / Single Repository demo.
CREATE TABLE IF NOT EXISTS sbom_repositories (
    repository_id VARCHAR(80) PRIMARY KEY,
    system_id INTEGER REFERENCES system(system_id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    github_url VARCHAR(500) UNIQUE NOT NULL,
    architecture_type VARCHAR(255) NOT NULL,
    tech_stack JSONB NOT NULL DEFAULT '[]'::jsonb,
    package_managers JSONB NOT NULL DEFAULT '[]'::jsonb,
    expected_dependency_files JSONB NOT NULL DEFAULT '[]'::jsonb,
    application_type VARCHAR(80) NOT NULL DEFAULT 'Web Application',
    repo_scope VARCHAR(80) NOT NULL DEFAULT 'Single Repository',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE sbom_metadata
    ADD COLUMN IF NOT EXISTS repository_id VARCHAR(80),
    ADD COLUMN IF NOT EXISTS source_commit VARCHAR(100),
    ADD COLUMN IF NOT EXISTS analyzed_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS source_repository_url VARCHAR(500);

-- Snapshot/version tables for incremental SBOM generation and graph layout
CREATE TABLE IF NOT EXISTS sbom_snapshots (
    snapshot_id VARCHAR(255) PRIMARY KEY,
    project_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(50) NOT NULL,
    base_snapshot_id VARCHAR(255),
    summary JSONB,
    FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
    FOREIGN KEY (base_snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE SET NULL,
    UNIQUE (project_id, version_number)
);

CREATE TABLE IF NOT EXISTS project_artifacts (
    artifact_id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL,
    artifact_path VARCHAR(500) NOT NULL,
    artifact_name VARCHAR(255),
    artifact_type VARCHAR(100),
    content TEXT NOT NULL,
    hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
    UNIQUE (project_id, artifact_path)
);

CREATE TABLE IF NOT EXISTS sbom_components (
    component_id SERIAL PRIMARY KEY,
    snapshot_id VARCHAR(255) NOT NULL,
    stable_key VARCHAR(500) NOT NULL,
    component_ref VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    version TEXT,
    purl VARCHAR(500),
    ecosystem TEXT,
    supplier_name VARCHAR(255),
    licenses VARCHAR,
    hashes VARCHAR,
    status VARCHAR(30) DEFAULT 'ACTIVE',
    FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE,
    UNIQUE (snapshot_id, stable_key)
);

CREATE TABLE IF NOT EXISTS sbom_dependencies (
    dependency_id SERIAL PRIMARY KEY,
    snapshot_id VARCHAR(255) NOT NULL,
    source_key VARCHAR(500) NOT NULL,
    target_key VARCHAR(500) NOT NULL,
    relationship VARCHAR(100) DEFAULT 'DEPENDS_ON',
    is_transitive BOOLEAN DEFAULT FALSE,
    has_cycle BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sbom_artifact_fingerprints (
    fingerprint_id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL,
    artifact_path VARCHAR(500),
    artifact_name VARCHAR(255),
    artifact_type VARCHAR(100),
    hash VARCHAR(64) NOT NULL,
    last_scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    snapshot_id VARCHAR(255) NOT NULL,
    FOREIGN KEY (project_id) REFERENCES system(system_id) ON DELETE CASCADE,
    FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sbom_change_logs (
    change_id SERIAL PRIMARY KEY,
    snapshot_id VARCHAR(255) NOT NULL,
    change_type VARCHAR(30) NOT NULL,
    entity_type VARCHAR(30) NOT NULL,
    entity_key VARCHAR(600) NOT NULL,
    component_name VARCHAR(255),
    previous_value JSONB,
    current_value JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (snapshot_id) REFERENCES sbom_snapshots(snapshot_id) ON DELETE CASCADE
);

