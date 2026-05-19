-- Bảng SBOM Metadata
CREATE TABLE sbom_metadata
(
    sbom_id VARCHAR(255) PRIMARY KEY,
    authors VARCHAR,
    created_timestamp TIMESTAMP,
    tool_components VARCHAR,
    tool_services VARCHAR,
    lifecycle_phase VARCHAR(100)
);

-- Bảng Component
CREATE TABLE component
(
    component_id VARCHAR(255) PRIMARY KEY,
    sbom_id VARCHAR(255) NOT NULL,
    supplier_name VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    purl VARCHAR(255),
    cpe VARCHAR(255),
    hashes VARCHAR,
    licenses VARCHAR,
    support_level VARCHAR(100),
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
    cve_id VARCHAR(100) NOT NULL,
    description VARCHAR,
    severity VARCHAR(50),
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
    version VARCHAR(100),
    description VARCHAR,
    FOREIGN KEY (sbom_id) REFERENCES sbom_metadata(sbom_id) ON DELETE CASCADE
);
