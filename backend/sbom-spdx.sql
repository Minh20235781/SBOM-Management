CREATE SCHEMA IF NOT EXISTS public;
SET search_path TO public;

-- Bảng System dùng chung với schema CycloneDX.
-- Nếu đã chạy file sbom-cyclonedx.sql trước đó thì bảng này sẽ được tái sử dụng.
CREATE TABLE IF NOT EXISTS system
(
    system_id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_uploaded_at TIMESTAMP
);

-- =========================
-- SPDX document metadata
-- =========================

CREATE TABLE IF NOT EXISTS spdx_document
(
    spdx_document_id VARCHAR(255) PRIMARY KEY,
    system_id INTEGER,
    spdx_version VARCHAR(50),
    data_license VARCHAR(255),
    spdx_id VARCHAR(255),
    name VARCHAR(500),
    document_namespace TEXT UNIQUE,
    document_describes VARCHAR,
    comment TEXT,
    created_timestamp TIMESTAMP,
    creators VARCHAR,
    creator_comment TEXT,
    license_list_version VARCHAR(50),
    source_file_name VARCHAR(500),
    raw_json JSONB,
    imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (system_id) REFERENCES system(system_id) ON DELETE SET NULL
);

-- External document references trong SPDX
CREATE TABLE IF NOT EXISTS spdx_external_document_ref
(
    external_document_ref_id SERIAL PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    external_document_id VARCHAR(255) NOT NULL,
    spdx_document_uri TEXT,
    checksum_algorithm VARCHAR(100),
    checksum_value TEXT,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE
);

-- =========================
-- SPDX packages
-- =========================

CREATE TABLE IF NOT EXISTS spdx_package
(
    package_id VARCHAR(255) PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    spdx_id VARCHAR(255) NOT NULL,
    name VARCHAR(500) NOT NULL,
    version_info TEXT,
    supplier VARCHAR(500),
    originator VARCHAR(500),
    download_location TEXT,
    files_analyzed BOOLEAN,
    verification_code TEXT,
    verification_code_excluded_files VARCHAR,
    checksums VARCHAR,
    homepage TEXT,
    source_info TEXT,
    license_concluded TEXT,
    license_declared TEXT,
    license_comments TEXT,
    copyright_text TEXT,
    summary TEXT,
    description TEXT,
    comment TEXT,
    primary_package_purpose VARCHAR(100),
    release_date TIMESTAMP,
    built_date TIMESTAMP,
    valid_until_date TIMESTAMP,
    raw_json JSONB,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE,
    UNIQUE (spdx_document_id, spdx_id)
);

CREATE TABLE IF NOT EXISTS spdx_package_external_ref
(
    external_ref_id SERIAL PRIMARY KEY,
    package_id VARCHAR(255) NOT NULL,
    reference_category VARCHAR(100),
    reference_type VARCHAR(255),
    reference_locator TEXT,
    comment TEXT,
    FOREIGN KEY (package_id) REFERENCES spdx_package(package_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS spdx_package_attribution
(
    attribution_id SERIAL PRIMARY KEY,
    package_id VARCHAR(255) NOT NULL,
    attribution_text TEXT NOT NULL,
    FOREIGN KEY (package_id) REFERENCES spdx_package(package_id) ON DELETE CASCADE
);

-- =========================
-- SPDX files and snippets
-- =========================

CREATE TABLE IF NOT EXISTS spdx_file
(
    file_id VARCHAR(255) PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    spdx_id VARCHAR(255) NOT NULL,
    file_name TEXT NOT NULL,
    file_types VARCHAR,
    checksums VARCHAR,
    license_concluded TEXT,
    license_info_in_files VARCHAR,
    license_comments TEXT,
    copyright_text TEXT,
    notice_text TEXT,
    contributors VARCHAR,
    comment TEXT,
    raw_json JSONB,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE,
    UNIQUE (spdx_document_id, spdx_id)
);

CREATE TABLE IF NOT EXISTS spdx_snippet
(
    snippet_id VARCHAR(255) PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    spdx_id VARCHAR(255) NOT NULL,
    snippet_from_file VARCHAR(255),
    name VARCHAR(500),
    byte_range_start INTEGER,
    byte_range_end INTEGER,
    line_range_start INTEGER,
    line_range_end INTEGER,
    license_concluded TEXT,
    license_info_in_snippets VARCHAR,
    license_comments TEXT,
    copyright_text TEXT,
    comment TEXT,
    raw_json JSONB,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE,
    FOREIGN KEY (snippet_from_file) REFERENCES spdx_file(file_id) ON DELETE SET NULL,
    UNIQUE (spdx_document_id, spdx_id)
);

-- =========================
-- SPDX relationships and annotations
-- =========================

CREATE TABLE IF NOT EXISTS spdx_relationship
(
    relationship_id SERIAL PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    spdx_element_id VARCHAR(255) NOT NULL,
    relationship_type VARCHAR(100) NOT NULL,
    related_spdx_element VARCHAR(255) NOT NULL,
    comment TEXT,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS spdx_annotation
(
    annotation_id SERIAL PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    spdx_id VARCHAR(255),
    annotation_type VARCHAR(100),
    annotator VARCHAR(500),
    annotation_date TIMESTAMP,
    comment TEXT,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE
);

-- =========================
-- SPDX licenses
-- =========================

CREATE TABLE IF NOT EXISTS spdx_extracted_licensing_info
(
    license_info_id SERIAL PRIMARY KEY,
    spdx_document_id VARCHAR(255) NOT NULL,
    license_id VARCHAR(255) NOT NULL,
    extracted_text TEXT,
    name VARCHAR(500),
    see_alsos VARCHAR,
    comment TEXT,
    FOREIGN KEY (spdx_document_id) REFERENCES spdx_document(spdx_document_id) ON DELETE CASCADE,
    UNIQUE (spdx_document_id, license_id)
);

-- =========================
-- Indexes
-- =========================

CREATE INDEX IF NOT EXISTS idx_spdx_document_system_id
    ON spdx_document(system_id);

CREATE INDEX IF NOT EXISTS idx_spdx_package_document_id
    ON spdx_package(spdx_document_id);

CREATE INDEX IF NOT EXISTS idx_spdx_package_name
    ON spdx_package(name);

CREATE INDEX IF NOT EXISTS idx_spdx_package_spdx_id
    ON spdx_package(spdx_document_id, spdx_id);

CREATE INDEX IF NOT EXISTS idx_spdx_file_document_id
    ON spdx_file(spdx_document_id);

CREATE INDEX IF NOT EXISTS idx_spdx_relationship_document_id
    ON spdx_relationship(spdx_document_id);

CREATE INDEX IF NOT EXISTS idx_spdx_relationship_source
    ON spdx_relationship(spdx_document_id, spdx_element_id);

CREATE INDEX IF NOT EXISTS idx_spdx_relationship_target
    ON spdx_relationship(spdx_document_id, related_spdx_element);

CREATE INDEX IF NOT EXISTS idx_spdx_external_ref_package_id
    ON spdx_package_external_ref(package_id);
