# Knowledge pipeline and OKF

## Purpose

This document defines the proposed knowledge-preparation path for ForensIQ. It prepares security knowledge for investigation; it does not describe organization-specific application context.

## Inputs

The initial knowledge sources are:

- MITRE Enterprise ATT&CK data, including its tactics, techniques, relationships, and descriptions.
- CVE JSON records, including vulnerability identifiers, affected products where available, descriptions, references, and metadata.

Other sources must be explicitly designed and approved before becoming part of this pipeline. In particular, organization architecture, workflows, normal behavior, policy documents, and internal security documentation are not inputs to the OKF as currently defined.

## Knowledge Compression Pipeline (KCP)

KCP transforms the supported raw knowledge sources into traceable, structured records. It should:

1. Parse and validate source data.
2. Normalize identifiers, timestamps, vendor/product names, and common fields where safe to do so.
3. Extract meaningful entities and relationships.
4. Compress repetitive or verbose content without changing the source meaning.
5. Preserve source identifiers, versions, references, and links to the original data.
6. Emit records that can be loaded and retrieved consistently.

KCP is a preparation and structuring layer, not a binary threat/benign classifier. It must not silently discard source facts merely to reduce volume.

## OKF representation and Cognee

After KCP processing, MITRE Enterprise ATT&CK and CVE JSON knowledge is stored in Cognee in **OKF format**. Here, OKF is the structured knowledge framework used for these security datasets—not a framework of organization-specific context.

Cognee is responsible for managing the OKF records and their relationships, so investigation agents can retrieve relevant ATT&CK and CVE knowledge. It should retain provenance, source version, ingestion time, and relationships such as:

- ATT&CK tactic, technique, sub-technique, software, group, and related data relationships provided by the source.
- CVE identifier, description, affected product information, severity metadata, and source references where available.
- Evidence-supported links created during an investigation, kept distinct from source facts.

Cognee integration and the OKF schema are proposed work and are not implemented in the current repository.

## Retrieval rules

Investigations may query Cognee for relevant ATT&CK and CVE records. Retrieval must preserve each source's meaning:

- ATT&CK describes adversary tactics and techniques.
- CVE identifies publicly cataloged vulnerabilities.

A retrieved record is context for an investigation, not proof that a technique occurred or a vulnerability was exploited. The system must not invent mappings based only on vague keyword overlap.

## Evidence and quality requirements

- Preserve raw datasets or durable references to them.
- Version source ingestions and OKF records.
- Keep compressed records traceable to their source identifiers.
- Make summaries and omitted detail auditable.
- Treat source facts, direct log observations, and agent inferences as distinct data types.

## Open decisions

1. What is the first version of the OKF schema for ATT&CK and CVE data?
2. Which authoritative CVE feeds and update cadence will be used?
3. How will KCP measure compression quality and information loss?
4. Which operational records remain outside Cognee?
5. Will additional sources be added after the initial ATT&CK and CVE scope is validated?
