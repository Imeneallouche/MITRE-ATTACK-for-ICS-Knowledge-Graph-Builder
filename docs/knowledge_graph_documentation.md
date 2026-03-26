# Automatic Construction of a MITRE ATT&CK for ICS Knowledge Graph Using Neo4j

## Component Documentation — Final Report

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background](#2-background)
3. [System Architecture of the Knowledge Graph Component](#3-system-architecture-of-the-knowledge-graph-component)
4. [Data Sources and Preprocessing](#4-data-sources-and-preprocessing)
5. [Graph Data Model](#5-graph-data-model)
6. [Graph Construction Process](#6-graph-construction-process)
7. [Implementation Details](#7-implementation-details)
8. [Integration with the Recommendation System](#8-integration-with-the-recommendation-system)
9. [Performance Considerations](#9-performance-considerations)
10. [Limitations](#10-limitations)
11. [Future Improvements](#11-future-improvements)
12. [Example Queries and Use Cases](#12-example-queries-and-use-cases)
13. [Conclusion](#13-conclusion)

---

## 1. Introduction

### 1.1 Purpose of the Knowledge Graph in the Global System

Industrial Control Systems (ICS) and Operational Technology (OT) environments are increasingly targeted by sophisticated cyber-adversaries whose attack campaigns span multiple stages, exploit domain-specific protocols, and leverage weaknesses unique to supervisory control and data acquisition (SCADA) architectures. To defend against such threats, security practitioners require a structured, queryable, and semantically rich representation of adversary behavior, detection capabilities, and available countermeasures.

The MITRE ATT&CK for ICS Knowledge Graph constitutes one of the four core components of a Recommendation System designed to generate personalized detection and mitigation measures for ICS/OT environments. The four components of the global system are:

1. **ICS/OT Simulation Environment** — executes realistic attack chains (e.g., using Caldera for OT) to produce observable adversarial behaviors.
2. **Detection and Correlation Engine** — ingests centralized logs from Elasticsearch and applies MITRE ATT&CK DataComponents to detect attack patterns.
3. **MITRE ATT&CK for ICS Knowledge Graph** — models the entirety of the MITRE ATT&CK for ICS framework as a labeled property graph in Neo4j, capturing techniques, tactics, mitigations, detection strategies, software, threat groups, campaigns, assets, and their interrelationships.
4. **Prioritization Engine** — ranks techniques and recommendations according to risk, usage frequency, and operational impact metrics derived from the knowledge graph.

The knowledge graph serves as the central semantic backbone of the recommendation system. It enables the other components to perform structured queries such as: *"Given that technique T0853 (Scripting) has been detected, what mitigations should be recommended, and which threat groups are known to employ this technique?"* Without a graph-based representation, answering such multi-hop relational questions would require complex join operations across multiple flat tables or JSON documents.

### 1.2 Role Within the Recommendation System

Within the recommendation pipeline, the knowledge graph fulfills several critical roles:

- **Technique-to-Mitigation Mapping** — When the detection engine identifies a technique, the knowledge graph is queried to retrieve all mitigations that address that technique, along with their descriptions and applicability metadata.
- **Technique-to-Detection Strategy Mapping** — The graph provides the complete detection chain: from detection strategies, through the analytics they contain, down to the specific data components required for log-based detection.
- **Threat Attribution** — The graph links techniques to threat groups and campaigns, enabling the prioritization engine to weight recommendations based on the likelihood that a particular adversary is active in the defended sector.
- **Asset Exposure Analysis** — The graph models which techniques target which ICS assets, allowing the recommendation system to tailor its output to the specific asset inventory of the defended environment.

### 1.3 Why a Graph Model (Neo4j) Instead of Relational or Document-Based Models

The MITRE ATT&CK for ICS framework is inherently relational: techniques belong to tactics, mitigations address techniques, groups use software to apply techniques, detection strategies contain analytics that rely on data components. These relationships form a dense, heterogeneous network that is ill-suited to tabular representation.

A **relational database** model would require numerous join tables to capture the many-to-many relationships between entity types. Multi-hop queries — such as *"Which mitigations address the techniques used by APT group G0034, and what data components are required to detect those techniques?"* — would demand multiple self-joins and subqueries, resulting in complex SQL statements and degraded query performance as the number of hops increases.

A **document-based model** (e.g., MongoDB) would embed relationships as nested arrays within documents, leading to data duplication and inconsistency when the same entity (e.g., a mitigation) is referenced from multiple parent documents. Update anomalies would be frequent and difficult to resolve.

**Neo4j**, a native graph database, offers several decisive advantages for this use case:

- **Index-free adjacency** — Each node directly stores pointers to its neighbors, enabling constant-time traversal regardless of total graph size. Multi-hop queries execute in time proportional to the subgraph traversed, not the total dataset.
- **Expressive query language (Cypher)** — Cypher's pattern-matching syntax directly mirrors the conceptual patterns in the ATT&CK framework (e.g., `(Group)-[:USES]->(Technique)<-[:MITIGATES]-(Mitigation)`), making queries readable, maintainable, and auditable.
- **Schema flexibility** — The labeled property graph model accommodates the heterogeneous node and relationship types in ATT&CK without requiring schema migrations when new entity types (e.g., DataComponent, Analytic) are introduced in newer framework versions.
- **Visualization** — Neo4j's built-in browser and third-party tools enable interactive visual exploration of the threat landscape, which is valuable for analyst training and report generation.

---

## 2. Background

### 2.1 Overview of MITRE ATT&CK for ICS

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally recognized knowledge base of adversary behavior, organized as a matrix of tactics and techniques. The **ATT&CK for ICS** variant specifically addresses the threat landscape of Industrial Control Systems, including SCADA systems, Distributed Control Systems (DCS), Programmable Logic Controllers (PLCs), Remote Terminal Units (RTUs), and other operational technology.

The ATT&CK for ICS matrix, maintained by MITRE, catalogs adversary behaviors observed in real-world incidents targeting critical infrastructure sectors such as energy, water, manufacturing, and transportation. As of version 18.0, the matrix comprises 83 techniques distributed across 12 tactics, supplemented by comprehensive metadata on threat groups, software, campaigns, mitigations, detection strategies, analytics, data components, and ICS-specific assets.

### 2.2 Key Entities

The MITRE ATT&CK for ICS framework defines the following key entity types, each of which is represented as a distinct node type in the knowledge graph:

| Entity | Description | Example |
|--------|-------------|---------|
| **Technique** | A specific adversary behavior or action performed during an attack (e.g., *Scripting*, *Modify Controller Tasking*). Each technique is identified by a unique ID (e.g., T0853). | T0853 — Scripting |
| **Tactic** | A high-level adversary objective that a technique serves (e.g., *Initial Access*, *Lateral Movement*, *Impact*). Tactics represent the "why" behind techniques. | TA0108 — Initial Access |
| **Mitigation** | A security control or countermeasure that reduces the risk of a technique being successfully executed (e.g., *Network Segmentation*, *Code Signing*). | M0930 — Network Segmentation |
| **DataComponent** | A specific type of observable data that can be collected from an ICS environment for detection purposes (e.g., *Network Traffic Content*, *File Modification*). Introduced in v18 to replace the coarser DataSource entity. | DC0061 — File Modification |
| **DetectionStrategy** | A documented approach for detecting a specific technique, describing the logic, data requirements, and expected indicators. | DET0802 |
| **Analytic** | A concrete detection rule or analytic procedure that implements part of a detection strategy, specifying the data analysis logic. | AN1855 |
| **Software** | Malware or tools known to be used by adversaries in ICS attacks (e.g., *Industroyer*, *Triton*). | S0604 — Industroyer |
| **Group** | A named threat actor or intrusion set known to target ICS environments (e.g., *Sandworm Team*, *XENOTIME*). | G0034 — Sandworm Team |
| **Campaign** | A coordinated series of intrusion activities sharing common objectives and attributed to a group (e.g., *2015 Ukraine Electric Power Attack*). | C0028 |
| **Asset** | An ICS-specific device or system type that may be targeted by techniques (e.g., *Engineering Workstation*, *PLC*, *HMI*). | A0002 — Engineering Workstation |
| **DataSource** | (v17 only) A coarser-grained data collection category (e.g., *Process monitoring*, *Network traffic*), replaced by DataComponent in v18. | DS0029 — Network Traffic |

### 2.3 Importance of Relationships Between Entities

The true analytical power of the ATT&CK framework lies not in the entities themselves but in the relationships between them. Key relationship types include:

- **Tactic → Technique (USES)** — Indicates which techniques serve which tactical objectives. A single technique may serve multiple tactics.
- **Mitigation → Technique (MITIGATES)** — Specifies which mitigations address which techniques, forming the foundation of the recommendation system's mitigation suggestions.
- **DetectionStrategy → Technique (DETECTS)** — Links detection strategies to the techniques they are designed to detect.
- **DetectionStrategy → Analytic (CONTAINS)** — Decomposes a detection strategy into its constituent analytics.
- **Analytic → DataComponent (USES)** — Specifies which data components an analytic requires, enabling the recommendation system to verify whether the necessary data collection is in place.
- **Group → Technique/Software (USES)** — Records known adversary tradecraft.
- **Campaign → Group (ATTRIBUTED_TO)** — Links campaigns to their attributed threat groups.
- **Technique → Asset (TARGETS)** — Identifies which ICS assets are vulnerable to which techniques.

These relationships enable multi-hop graph traversals that answer complex operational questions, such as identifying the complete detection and mitigation posture for a given adversary group targeting a specific asset type.

---

## 3. System Architecture of the Knowledge Graph Component

### 3.1 High-Level Architecture

The Knowledge Graph component follows a three-stage Extract-Transform-Load (ETL) architecture:

```
┌───────────────────────────────────────────────────────────────────-──┐
│                     DATA SOURCES                                     │
│                                                                      │
│  ┌──────────────────────┐  ┌──────────────────────────────────────┐  │
│  │  MITRE ATT&CK ICS    │  │  Complementary Data                  │  │
│  │  Excel Export        │  │  (Scraped from MITRE website)        │  │
│  │  (v17.1 / v18.0)     │  │  - Analytic → DetectionStrategy      │  │
│  │                      │  │  - Analytic → DataComponent          │  │
│  └──────────┬───────────┘  └──────────────-─┬─────────────────────┘  │
│             │                               │                        │
└─────────────┼───────────────────────────────┼────────────────────────┘
              │                               │
              ▼                               ▼
┌───────────────────────────────────────────────────────────────────-──┐
│                   PREPROCESSING PIPELINE                             │
│                                                                      │
│  ┌───────────────────-─┐  ┌──────────────────────────────────────┐   │
│  │  ds_analytic_       │  │  extract_datacomponents.py           │   │
│  │  relation.py        │  │  Web scraper: Analytic URLs →        │   │
│  │  URL parser:        │  │  DataComponent IDs via HTML parsing  │   │
│  │  Analytic → DET ID  │  │                                      │   │
│  └────────┬────────────┘  └──────────────-┬──────────────────────┘   │
│           │                               │                          │
│           └──────────┬────────────────────┘                          │
│                      ▼                                               │
│           ┌──────────────────────┐                                   │
│           │  Complementary Excel │                                   │
│           │  (v18.0-complementary│                                   │
│           │   .xlsx)             │                                   │
│           └──────────────────────┘                                   │
└───────────────────────────────────────────────────────────────-──────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 GRAPH CONSTRUCTION ENGINE                             │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  mitre_ics_matrix_v18_to_kg.py                               │   │
│  │  (or mitre_ics_matrix_v17_to_kg.py for legacy v17)           │   │
│  │                                                              │   │
│  │  1. Clear database (MATCH (n) DETACH DELETE n)               │   │
│  │  2. Create constraints & indexes                             │   │
│  │  3. Load nodes: Tactic → Technique → Software → Group →      │   │
│  │     Campaign → Asset → Mitigation → DataComponent →          │   │
│  │     Analytic → DetectionStrategy                             │   │
│  │  4. Load matrix relationships (Tactic ─USES→ Technique)      │   │
│  │  5. Load relationships sheet (MITIGATES, DETECTS, TARGETS,   │   │
│  │     USES, ATTRIBUTED_TO)                                     │   │
│  │  6. Create additional indexes on name properties             │   │
│  │  7. Compute and log statistics                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  add_missing_relationships.py                                │   │
│  │                                                              │   │
│  │  1. Verify Analytic, DetectionStrategy, DataComponent nodes  │   │
│  │  2. Add DetectionStrategy ─CONTAINS→ Analytic                │   │
│  │  3. Add Analytic ─USES→ DataComponent                        │   │
│  │  4. Verify and log statistics                                │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      NEO4J GRAPH DATABASE                           │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  410 Nodes  ·  10 Labels  ·  ~1500+ Relationships            │   │
│  │                                                              │   │
│  │  Queried by:                                                 │   │
│  │  - Recommendation Engine (mitigation queries)                │   │
│  │  - Detection Engine (detection strategy queries)             │   │
│  │  - Prioritization Engine (risk scoring queries)              │   │
│  │  - Analyst Dashboard (exploration queries)                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow: Ingestion → Transformation → Graph Creation

The data flow proceeds through the following stages:

**Stage 1: Data Acquisition.** The MITRE ATT&CK for ICS dataset is obtained as an Excel workbook exported from the official MITRE ATT&CK repository. Each entity type occupies a dedicated worksheet (e.g., `techniques`, `tactics`, `mitigations`). Additionally, a `relationships` sheet encodes typed, directed edges between entities using STIX-compatible source/target identifiers and mapping type labels. A `matrix` sheet provides the canonical tactic-technique mapping as a columnar layout.

**Stage 2: Complementary Data Extraction.** Because the official Excel export does not include certain fine-grained relationships — specifically, the mapping between detection strategies and their constituent analytics, and the mapping between analytics and their required data components — two auxiliary scripts extract this information. The script `ds_analytic_relation.py` parses the `url` field of each analytic record to extract the parent detection strategy identifier using regular expressions. The script `extract_datacomponents.py` performs HTTP requests to each analytic's URL on the MITRE ATT&CK website, parses the "Log Sources" HTML table using BeautifulSoup, and extracts data component identifiers and names. The outputs of these two scripts are consolidated into a complementary Excel workbook (`ics-attack-v18.0-complementary.xlsx`).

**Stage 3: Graph Construction.** The primary builder script (`mitre_ics_matrix_v18_to_kg.py`) reads the main Excel workbook, clears the target Neo4j database, creates uniqueness constraints and indexes, and iterates through each entity sheet to create nodes via parameterized `MERGE` queries. It then processes the matrix sheet and relationships sheet to create edges. Finally, it creates additional B-tree indexes on `name` properties for query performance.

**Stage 4: Complementary Enrichment.** The script `add_missing_relationships.py` reads the complementary Excel workbook and creates the `CONTAINS` and `USES` edges that link detection strategies to analytics and analytics to data components, completing the detection chain in the graph.

### 3.3 Interaction with Other System Components

The knowledge graph interacts with the other system components through Cypher queries executed via the Neo4j Bolt protocol:

- **Detection Engine → Knowledge Graph:** After detecting a potential attack technique from log analysis, the detection engine queries the graph to retrieve the full detection context (e.g., `MATCH (ds:DetectionStrategy)-[:DETECTS]->(t:Technique {id: $detected_technique_id}) RETURN ds`).
- **Recommendation Engine → Knowledge Graph:** The recommendation engine queries the graph for mitigations applicable to detected techniques, ranked by the number of techniques each mitigation addresses.
- **Prioritization Engine → Knowledge Graph:** The prioritization engine queries the graph for threat group associations, campaign history, and asset targeting information to compute risk scores.

---

## 4. Data Sources and Preprocessing

### 4.1 Source of MITRE ATT&CK ICS Data

The primary data source is the official MITRE ATT&CK for ICS dataset, exported as a multi-sheet Microsoft Excel workbook. The project supports two dataset versions:

| File | Framework Version | Description |
|------|-------------------|-------------|
| `input/ics-attack-v17.1.xlsx` | ATT&CK for ICS v17.1 | Legacy version with DataSource as the detection entity |
| `input/ics-attack-v18.0.xlsx` | ATT&CK for ICS v18.0 | Current version introducing DataComponent, Analytic, and DetectionStrategy entities |
| `input/ics-attack-v18.0-complementary.xlsx` | Supplementary | Contains Analytic-to-DetectionStrategy and Analytic-to-DataComponent mappings derived from web scraping |

The Excel workbooks are structured with one worksheet per entity type. The column naming convention follows the MITRE ATT&CK STIX export format (e.g., `ID`, `STIX ID`, `name`, `description`, `url`, `created`, `last modified`, `domain`, `version`). Relationship data is encoded in a dedicated `relationships` worksheet with columns: `source ID`, `source type`, `target ID`, `target type`, `mapping type`, and `mapping description`.

### 4.2 Data Formats

The MITRE ATT&CK data consumed by this component is exclusively in **Microsoft Excel (.xlsx)** format, which is one of the export formats provided by the MITRE ATT&CK repository alongside STIX 2.1 JSON bundles and Navigator layer files. The Excel format was selected for this implementation because it provides a tabular, human-readable structure that simplifies validation and debugging during development, while being directly consumable by the `pandas` library.

Although the underlying MITRE ATT&CK data model is based on the **STIX 2.1** (Structured Threat Information Expression) standard, the conversion from STIX objects to Excel rows is performed upstream by MITRE's export tooling. The builder scripts therefore do not directly parse STIX JSON; they consume the pre-flattened Excel representation. The `source type` and `target type` columns in the relationships sheet retain STIX-compatible type identifiers (e.g., `attack-pattern`, `course-of-action`, `intrusion-set`), which are mapped to Neo4j labels by the `map_stix_type_to_label()` method.

### 4.3 Parsing and Normalization Steps

The following parsing and normalization operations are performed during data ingestion:

**4.3.1 Value Sanitization.** The `clean_value()` static method (v18) and `sanitize_value()` method (v17) handle missing or malformed cell values. Values that are `NaN`, empty strings, or the literal string `'nan'` are converted to `None` and excluded from node properties. String values are stripped of leading and trailing whitespace.

```python
@staticmethod
def clean_value(value: Any) -> Optional[Any]:
    if pd.isna(value) or value == '' or value == 'nan':
        return None
    if isinstance(value, str):
        return value.strip()
    return value
```

**4.3.2 List Field Parsing.** Several ATT&CK fields contain multi-valued data encoded as comma-separated, newline-separated, or semicolon-separated strings within a single Excel cell (e.g., the `tactics`, `platforms`, `data sources`, and `contributors` columns). The `parse_list_field()` method splits these strings using a regular expression that handles all three delimiter types:

```python
@staticmethod
def parse_list_field(value: Any, separator: str = ',') -> List[str]:
    if pd.isna(value) or value == '':
        return []
    value_str = str(value)
    items = re.split(r'[,\n;]+', value_str)
    return [item.strip() for item in items if item.strip()]
```

**4.3.3 STIX Type Mapping.** The `map_stix_type_to_label()` method converts STIX 2.1 type identifiers used in the relationships sheet to the Neo4j node labels used in the graph schema. The mapping handles both STIX-format identifiers (e.g., `attack-pattern` → `Technique`, `course-of-action` → `Mitigation`, `intrusion-set` → `Group`) and simplified lowercase identifiers that appear in some worksheet variants (e.g., `technique` → `Technique`, `detectionstrategy` → `DetectionStrategy`). Both `malware` and `tool` STIX types are unified under the `Software` label.

**4.3.4 Relationship Type Normalization.** In the v18 builder, relationship types are normalized by converting the `mapping type` string to uppercase and replacing hyphens and spaces with underscores (e.g., `attributed-to` → `ATTRIBUTED_TO`, `mitigates` → `MITIGATES`). This produces clean, Neo4j-compatible relationship type identifiers. The v17 builder uses a more granular heuristic normalization (detailed in Section 6.4) that distinguishes sub-types of the `uses` relationship based on the source and target node types.

### 4.4 Handling Inconsistencies or Missing Data

Several data quality challenges were encountered and addressed:

- **Missing cell values:** Rows with `NaN` or empty critical fields (e.g., `ID`) are skipped entirely. Optional properties with missing values are excluded from the node property map rather than stored as null, keeping the graph clean.
- **Duplicate relationships:** The use of Cypher `MERGE` (rather than `CREATE`) for edges ensures that duplicate relationships are not created when the same pair appears in both the `tactics` column of the techniques sheet and the separate matrix sheet.
- **Absent complementary data:** The detection-chain relationships (DetectionStrategy → Analytic → DataComponent) are not present in the official Excel export. This gap was bridged by the web scraping and URL parsing scripts described in Section 3.2.
- **STIX type inconsistencies:** The mapping function includes a fallback clause that title-cases unrecognized type strings, ensuring that novel entity types introduced in future ATT&CK versions do not cause hard failures.
- **Failed relationship creation:** Individual edge creation failures (e.g., due to a missing source or target node) are caught, logged as warnings, and aggregated. The first five failures are logged in detail for debugging, and the pipeline continues without interruption.

---

## 5. Graph Data Model

### 5.1 Node Types

The knowledge graph (v18) contains **ten** distinct node labels:

| Label | Count (v18) | Description | Key Properties |
|-------|-------------|-------------|----------------|
| `Technique` | 83 | Adversary behaviors | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version`, `detection`, `platforms` (list), `data_sources` (list), `contributors` (list) |
| `Tactic` | 12 | Adversary objectives | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version` |
| `Software` | 23 | Malware and tools | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version`, `type`, `platforms` (list), `aliases` (list), `contributors` (list) |
| `Group` | 14 | Threat actor groups | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version`, `associated_groups` (list), `contributors` (list) |
| `Campaign` | 7 | Coordinated intrusion activities | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version`, `first_seen`, `last_seen`, `associated_campaigns` (list) |
| `Asset` | 18 | ICS device/system types | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version`, `platforms` (list), `sectors` (list), `related_assets` (list), `related_assets_description` |
| `Mitigation` | 52 | Security countermeasures | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version` |
| `DataComponent` | 36 | Observable data types | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version` |
| `Analytic` | 82 | Detection rules/procedures | `id`, `stix_id`, `name`, `description`, `url`, `created`, `last_modified`, `domain`, `version` |
| `DetectionStrategy` | 83 | Detection approaches | `id`, `stix_id`, `name`, `url`, `created`, `last_modified`, `domain`, `version` |
| **Total** | **410** | | |

### 5.2 Relationship Types

The following relationship types are defined in the v18 knowledge graph:

| Relationship Type | Source | Target | Count (v18) | Semantic Meaning |
|-------------------|--------|--------|-------------|------------------|
| `USES` | Tactic | Technique | 94 | Tactic employs technique to achieve objective |
| `USES` | Group | Software | — | Group uses software in operations |
| `USES` | Group | Technique | — | Group applies technique |
| `USES` | Campaign | Technique | — | Campaign employs technique |
| `USES` | Campaign | Software | — | Campaign employs software |
| `USES` | Software | Technique | — | Software implements technique |
| `USES` | Analytic | DataComponent | * | Analytic requires data component (added by complementary enrichment) |
| `MITIGATES` | Mitigation | Technique | 331 | Mitigation reduces risk of technique |
| `DETECTS` | DetectionStrategy | Technique | 83 | Detection strategy can detect technique |
| `TARGETS` | Technique | Asset | 685 | Technique targets specific asset type |
| `ATTRIBUTED_TO` | Campaign | Group | 5 | Campaign attributed to threat group |
| `CONTAINS` | DetectionStrategy | Analytic | * | Detection strategy contains analytic (added by complementary enrichment) |
| `ASSOCIATED_WITH` | Group | Group | — | Groups known to be associated |
| `ASSOCIATED_WITH` | Campaign | Campaign | — | Related campaigns |
| `RELATED_TO` | Asset | Asset | — | Related ICS asset types |

\* *Counts for `CONTAINS` and Analytic→DataComponent `USES` are added during the complementary enrichment phase and depend on the completeness of the scraped data.*

The total relationship count after the primary v18 build is **1,382 relationships**, distributed as: `TARGETS` (685), `USES` (361, aggregating all USES sub-types), `MITIGATES` (331), and `ATTRIBUTED_TO` (5). After complementary enrichment, additional `CONTAINS` and `USES` edges are added.

### 5.3 Properties of Nodes and Relationships

**Node properties** follow a consistent pattern across all entity types:

- `id` (String, unique, indexed) — The MITRE ATT&CK identifier (e.g., `T0853`, `M0930`, `G0034`). Serves as the primary key and is enforced unique by a constraint.
- `stix_id` (String) — The full STIX 2.1 identifier (e.g., `attack-pattern--2fedbe69-...`).
- `name` (String, indexed) — The human-readable name of the entity.
- `description` (String) — A detailed textual description from the ATT&CK knowledge base.
- `url` (String) — The canonical URL on the MITRE ATT&CK website.
- `created` and `last_modified` (String) — Timestamps of the entity's creation and last modification in the ATT&CK repository.
- `domain` (String) — The ATT&CK domain (e.g., `ics-attack`).
- `version` (String) — The entity's version number within the ATT&CK framework.

Several node types have additional specialized properties stored as list (array) types:

- `Technique`: `platforms`, `data_sources`, `contributors`
- `Software`: `platforms`, `aliases`, `contributors`
- `Group`: `associated_groups`, `contributors`
- `Campaign`: `associated_campaigns`, `first_seen`, `last_seen`
- `Asset`: `platforms`, `sectors`, `related_assets`, `related_assets_description`

**Relationship properties** are used selectively:

- `description` (String) — Present on relationships loaded from the relationships sheet; contains a mapping description from the ATT&CK data.
- `mapping_type` (String, v17 only) — The original STIX mapping type string, preserved for traceability.

### 5.4 Schema Design Decisions and Tradeoffs

Several deliberate schema design decisions were made:

**5.4.1 Polymorphic `USES` Relationship.** The `USES` relationship type is intentionally overloaded to represent several semantically distinct relationships (e.g., Tactic→Technique, Group→Software, Analytic→DataComponent). This decision favors simplicity and alignment with the ATT&CK framework's own terminology over strict semantic precision. Queries distinguish the intended semantics by specifying source and target node labels (e.g., `MATCH (g:Group)-[:USES]->(s:Software)` vs. `MATCH (tac:Tactic)-[:USES]->(tech:Technique)`). The tradeoff is that aggregate queries over all `USES` relationships require additional filtering.

**5.4.2 Evolution from v17 to v18 Schema.** The v17 schema uses a `DataSource` label and a `DETECTS` relationship from DataSource to Technique. The v18 schema replaces `DataSource` with three finer-grained labels: `DataComponent`, `Analytic`, and `DetectionStrategy`, reflecting MITRE's own evolution toward more actionable detection guidance. The v17 schema also uses more granular relationship types (e.g., `MITIGATED_BY`, `USES_SOFTWARE`, `APPLIES_TECHNIQUE`, `USES_TECHNIQUE`) via heuristic normalization, while the v18 schema directly adopts the ATT&CK mapping type names (e.g., `MITIGATES`, `USES`, `TARGETS`), which are simpler and more closely aligned with the source data. The v18 approach was adopted as the primary schema for the production knowledge graph.

**5.4.3 MERGE vs. CREATE for Nodes.** The v18 builder uses `MERGE` for node creation, which creates a node only if one with the same `id` does not already exist, and updates its properties if it does. This makes the pipeline idempotent. The v17 builder uses `CREATE`, which would fail or create duplicates if run multiple times; the database is therefore cleared at the start of each run. The v18 approach is preferable for robustness.

**5.4.4 List Properties vs. Separate Nodes.** Multi-valued attributes such as `platforms`, `sectors`, and `aliases` are stored as array properties on their parent nodes rather than modeled as separate nodes with relationships. This decision was made because these attributes are relatively static, have no properties of their own, and are primarily used for filtering rather than traversal. Modeling them as separate nodes would increase the node count without adding significant query flexibility.

---

## 6. Graph Construction Process

### 6.1 Step-by-Step Pipeline

The complete graph construction pipeline, using the v18 builder as the reference implementation, proceeds through the following ordered steps:

#### Step 1: Database Initialization

The pipeline begins by clearing all existing nodes and relationships from the target Neo4j database:

```cypher
MATCH (n) DETACH DELETE n
```

The `DETACH DELETE` clause ensures that all relationships connected to each node are removed before the node itself is deleted, preventing referential integrity errors.

#### Step 2: Constraint and Index Creation

Uniqueness constraints are created on the `id` property for each node label. These constraints serve a dual purpose: they enforce data integrity (preventing duplicate nodes) and automatically create a backing B-tree index on the constrained property, accelerating `MATCH` lookups by `id`.

```cypher
CREATE CONSTRAINT technique_id IF NOT EXISTS
    FOR (t:Technique) REQUIRE t.id IS UNIQUE

CREATE CONSTRAINT tactic_id IF NOT EXISTS
    FOR (t:Tactic) REQUIRE t.id IS UNIQUE

-- ... (analogous constraints for all 10 node labels)
```

The `IF NOT EXISTS` clause ensures idempotent execution — the constraint creation succeeds even if the constraint was already defined.

#### Step 3: Node Loading (Dependency-Ordered)

Nodes are loaded in a specific order to ensure that referenced nodes exist before relationships are created:

1. **Tactics** — Loaded first because Technique loading creates Tactic→Technique edges.
2. **Techniques** — Loaded second; during loading, `USES` relationships to tactics are created immediately.
3. **Software** — No dependencies on other entities.
4. **Groups** — May create `ASSOCIATED_WITH` edges to other groups by name.
5. **Campaigns** — May create `ASSOCIATED_WITH` edges to other campaigns by name.
6. **Assets** — May create `RELATED_TO` edges to other assets by name.
7. **Mitigations** — No dependencies on other entities.
8. **DataComponents** — No dependencies on other entities.
9. **Analytics** — No dependencies on other entities.
10. **DetectionStrategies** — No dependencies on other entities.

For each entity, the builder iterates over the corresponding DataFrame rows, constructs a property dictionary from the Excel columns, cleans the values, and executes a `MERGE` query:

```cypher
MERGE (n:Technique {id: $id})
SET n += {id: $id, stix_id: $stix_id, name: $name, description: $description, ...}
```

The `MERGE` on `id` followed by `SET n += {...}` ensures that existing nodes are updated and new nodes are created, achieving upsert semantics.

#### Step 4: Matrix Relationship Loading

The matrix sheet provides a columnar representation of the Tactic→Technique mapping. Each column header is a tactic name, and each cell value is a technique ID. The builder iterates over each column and each non-null cell to create `USES` edges:

```cypher
MATCH (tac:Tactic {name: $tactic_name})
MATCH (tech:Technique {id: $tech_id})
MERGE (tac)-[:USES]->(tech)
```

#### Step 5: Relationship Sheet Processing

The relationships sheet contains typed, directed edges between arbitrary entity pairs. For each row, the builder maps the STIX source/target types to Neo4j labels, normalizes the mapping type to a valid relationship type string, and executes a parameterized `MERGE`:

```cypher
MATCH (source:Mitigation {id: $source_id})
MATCH (target:Technique {id: $target_id})
MERGE (source)-[r:MITIGATES]->(target)
SET r.description = $description
```

#### Step 6: Additional Index Creation

After all nodes and relationships are loaded, additional B-tree indexes are created on the `name` property of frequently queried node types to accelerate name-based lookups:

```cypher
CREATE INDEX technique_name IF NOT EXISTS FOR (t:Technique) ON (t.name)
CREATE INDEX tactic_name IF NOT EXISTS FOR (t:Tactic) ON (t.name)
CREATE INDEX software_name IF NOT EXISTS FOR (s:Software) ON (s.name)
CREATE INDEX group_name IF NOT EXISTS FOR (g:Group) ON (g.name)
CREATE INDEX campaign_name IF NOT EXISTS FOR (c:Campaign) ON (c.name)
CREATE INDEX asset_name IF NOT EXISTS FOR (a:Asset) ON (a.name)
CREATE INDEX mitigation_name IF NOT EXISTS FOR (m:Mitigation) ON (m.name)
```

#### Step 7: Complementary Enrichment

After the primary build completes, the `add_missing_relationships.py` script is executed to add the detection-chain edges. This script:

1. Verifies that Analytic, DetectionStrategy, and DataComponent nodes exist in the database.
2. Reads the `analytic_detectionstrategy` sheet and creates `CONTAINS` relationships.
3. Reads the `analytic_datacomponents` sheet (with semicolon-separated DataComponent IDs) and creates `USES` relationships.
4. Verifies the created relationships and reports statistics.

```cypher
-- DetectionStrategy → Analytic
MATCH (ds:DetectionStrategy {id: $detection_strategy_id})
MATCH (a:Analytic {id: $analytic_id})
MERGE (ds)-[r:CONTAINS]->(a)

-- Analytic → DataComponent
MATCH (a:Analytic {id: $analytic_id})
MATCH (dc:DataComponent {id: $datacomponent_id})
MERGE (a)-[r:USES]->(dc)
```

#### Step 8: Statistics and Verification

The pipeline concludes with a comprehensive statistics report that enumerates all node labels with their counts, all relationship types with their counts, and verifies the existence of key structural patterns (e.g., Mitigation→MITIGATES→Technique, DetectionStrategy→DETECTS→Technique).

### 6.2 Cypher Query Patterns Used

The implementation relies on a small set of recurring Cypher patterns:

| Pattern | Purpose | Example |
|---------|---------|---------|
| `MERGE (n:Label {id: $id}) SET n += $props` | Idempotent node upsert | Node creation |
| `MATCH (a:L1 {id: $id1}) MATCH (b:L2 {id: $id2}) MERGE (a)-[:REL]->(b)` | Relationship creation between identified nodes | Edge creation |
| `MATCH (a:L1 {name: $name})` | Name-based node lookup | Tactic→Technique edges |
| `MATCH (n) DETACH DELETE n` | Full database wipe | Rebuild strategy |
| `CALL db.labels()` / `CALL db.relationshipTypes()` | Schema introspection | Statistics |
| `MATCH (s:L1)-[r:REL]->(t:L2) RETURN count(r)` | Pattern counting | Verification |

### 6.3 Idempotency and Update Strategy

The system employs a **full rebuild** strategy rather than incremental updates. Each execution of the primary builder script clears the entire database and reconstructs the graph from scratch. This approach was chosen for several reasons:

- **Simplicity** — No change-detection or delta-computation logic is required.
- **Correctness** — Deleted or modified entities in the source data are correctly reflected in the graph without orphan-detection logic.
- **MITRE ATT&CK release cadence** — The ATT&CK for ICS framework is updated approximately quarterly, making full rebuild a practical strategy given the modest graph size.

The v18 builder offers a `clear_existing` parameter that can be set to `False` to skip the database wipe, enabling additive loading. The use of `MERGE` for both nodes and edges ensures that re-running the builder without clearing does not create duplicates.

---

## 7. Implementation Details

### 7.1 Technologies Used

| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.x | Primary implementation language |
| **Neo4j** | 5.x (Aura) | Graph database platform |
| **neo4j (Python driver)** | Latest | Neo4j Bolt protocol client |
| **pandas** | Latest | Excel parsing and DataFrame manipulation |
| **openpyxl** | Latest | Excel file I/O engine for pandas |
| **requests** | Latest | HTTP client for web scraping (complementary data extraction) |
| **BeautifulSoup4** | Latest | HTML parser for web scraping (complementary data extraction) |

The Neo4j deployment uses **Neo4j Aura**, a managed cloud database service, accessed via the `neo4j+s://` URI scheme (TLS-secured Bolt protocol). The implementation is compatible with any Neo4j 5.x instance, including self-hosted deployments.

### 7.2 Code Structure

The project consists of five Python modules, each with a well-defined responsibility:

```
MITRE-ATTACK-for-ICS-Knowledge-Graph/
├── input/
│   ├── ics-attack-v17.1.xlsx           # ATT&CK for ICS v17.1 dataset
│   ├── ics-attack-v18.0.xlsx           # ATT&CK for ICS v18.0 dataset
│   └── ics-attack-v18.0-complementary.xlsx  # Derived complementary data
├── output/
│   ├── analytic_detectionstrategy_mapping.xlsx  # Analytic→DET ID mapping
│   └── analytics_with_datacomponents.xlsx       # Analytic→DC ID mapping
├── terminal_output/
│   ├── output_v17.txt                  # Captured build log (v17)
│   └── output_v18.txt                  # Captured build log (v18)
├── mitre_ics_matrix_v17_to_kg.py       # V17 graph builder (legacy)
├── mitre_ics_matrix_v18_to_kg.py       # V18 graph builder (primary)
├── add_missing_relationships.py        # Complementary relationship loader
├── ds_analytic_relation.py             # URL parser for Analytic→DET mapping
├── extract_datacomponents.py           # Web scraper for Analytic→DC mapping
├── requirements.txt                    # Python dependencies
└── README.md                           # Project description
```

### 7.3 Module Responsibilities and Key Functions

#### 7.3.1 `mitre_ics_matrix_v18_to_kg.py` — Primary Graph Builder (v18)

**Class: `MITREKnowledgeGraphBuilder`**

This is the central class responsible for constructing the v18 knowledge graph. Its key methods are:

| Method | Responsibility |
|--------|---------------|
| `__init__(uri, username, password)` | Initializes the Neo4j driver connection |
| `close()` | Closes the Neo4j driver |
| `clear_database()` | Deletes all nodes and relationships |
| `create_constraints_and_indexes()` | Creates uniqueness constraints on `id` for all 10 labels |
| `clean_value(value)` | Sanitizes individual cell values (NaN → None, strip whitespace) |
| `parse_list_field(value, separator)` | Splits multi-valued fields into Python lists |
| `map_stix_type_to_label(stix_type)` | Maps STIX type identifiers to Neo4j labels |
| `create_node(session, label, properties)` | Generic node MERGE with dynamic property construction |
| `load_techniques(df)` | Creates Technique nodes and Tactic→Technique USES edges |
| `load_tactics(df)` | Creates Tactic nodes |
| `load_software(df)` | Creates Software nodes with platforms, aliases, contributors |
| `load_groups(df)` | Creates Group nodes with ASSOCIATED_WITH edges |
| `load_campaigns(df)` | Creates Campaign nodes with ASSOCIATED_WITH edges |
| `load_assets(df)` | Creates Asset nodes with RELATED_TO edges |
| `load_mitigations(df)` | Creates Mitigation nodes |
| `load_datacomponents(df)` | Creates DataComponent nodes |
| `load_analytics(df)` | Creates Analytic nodes |
| `load_detectionstrategies(df)` | Creates DetectionStrategy nodes |
| `load_matrix(df)` | Creates Tactic→Technique USES edges from matrix sheet |
| `load_relationships(df)` | Creates all inter-entity edges from relationships sheet |
| `create_additional_indexes()` | Creates B-tree indexes on `name` properties |
| `analyze_relationships_sheet(df)` | Logs source/target/mapping type distributions |
| `get_statistics()` | Queries and logs node/relationship counts and key patterns |
| `build_knowledge_graph(excel_file, clear_existing)` | Orchestrates the complete build pipeline |

#### 7.3.2 `mitre_ics_matrix_v17_to_kg.py` — Legacy Graph Builder (v17)

**Class: `MITREAttackKGBuilder`**

This class implements the v17 variant of the builder, which differs from the v18 version in several respects:

- Uses `DataSource` nodes instead of `DataComponent`, `Analytic`, and `DetectionStrategy`.
- Uses `CREATE` instead of `MERGE` for node creation (non-idempotent).
- Implements `normalize_relationship_type()` with heuristic logic that produces finer-grained relationship types (e.g., `MITIGATED_BY`, `USES_SOFTWARE`, `APPLIES_TECHNIQUE`, `USES_TECHNIQUE`).
- Includes `create_additional_relationships()` which creates `TARGETED_BY` edges between Asset and Technique nodes based on platform overlap.
- Includes `create_datasource_technique_relationships()` which creates `DETECTS` edges using a `MERGE` on DataSource name (potentially creating name-only DataSource nodes).

#### 7.3.3 `add_missing_relationships.py` — Complementary Enrichment

**Class: `MITRERelationshipAdder`**

| Method | Responsibility |
|--------|---------------|
| `verify_nodes_exist()` | Counts Analytic, DetectionStrategy, DataComponent nodes to confirm prerequisites |
| `add_detection_strategy_analytic_relationships(df)` | Creates DetectionStrategy→CONTAINS→Analytic edges |
| `add_analytic_datacomponent_relationships(df)` | Parses semicolon-separated DC IDs and creates Analytic→USES→DataComponent edges |
| `verify_relationships()` | Counts created edges and samples DetectionStrategy→Analytic→DataComponent paths |
| `get_relationship_statistics()` | Reports all relationship type counts |
| `process_complementary_file(excel_file)` | Orchestrates the enrichment pipeline |

#### 7.3.4 `ds_analytic_relation.py` — URL Parser

This module contains two functions that extract the detection strategy identifier from the URL of each analytic. The URL pattern `https://attack.mitre.org/detectionstrategies/DET0722#AN1855` encodes the parent detection strategy ID (`DET0722`) in the path segment, which is extracted using the regular expression `/detectionstrategies/(DET\d+)`. The output is a two-column DataFrame (`analytic_ID`, `detectionstrategy_ID`) written to an Excel file.

#### 7.3.5 `extract_datacomponents.py` — Web Scraper

This module performs HTTP requests to each analytic's URL on the MITRE ATT&CK website, parses the HTML response using BeautifulSoup, and extracts data component identifiers from the "Log Sources" table. The scraper implements rate limiting (`time.sleep(1)` between requests), a custom User-Agent header, and a 30-second request timeout. Data component IDs are extracted from link text matching the pattern `Name (DCXXXX)` using a regular expression.

### 7.4 Error Handling and Logging

The project uses Python's standard `logging` module configured at the `INFO` level with timestamps:

```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
```

Error handling follows a consistent pattern across all builder modules:

- **Constraint/index creation:** Wrapped in try/except blocks that log warnings if the constraint already exists, allowing repeated execution.
- **Individual node/edge creation:** Failed operations are caught, logged, and skipped. The pipeline continues to process remaining entities. The v18 `load_relationships()` method collects failed relationships into a list and logs the first five failures for debugging.
- **Top-level orchestration:** The `build_knowledge_graph()` method wraps the entire pipeline in a try/except block that logs the error with full stack trace (`exc_info=True`) and re-raises the exception. The `main()` function uses a `finally` clause to ensure the Neo4j driver is closed even if an exception occurs.
- **Web scraping:** Both `requests.exceptions.RequestException` and generic `Exception` are caught per URL, ensuring that a failure to scrape one analytic page does not abort the processing of subsequent pages.

---

## 8. Integration with the Recommendation System

### 8.1 How the Graph Is Queried by Other Components

The knowledge graph is queried by other system components via the Neo4j Python driver (Bolt protocol). Components establish a session, execute parameterized Cypher queries, and process the returned records. The graph's schema — with its typed nodes, typed relationships, and indexed properties — enables efficient, targeted queries for each component's specific needs.

### 8.2 Example Queries for Retrieving Mitigations

Given a detected technique, the recommendation engine retrieves all applicable mitigations:

```cypher
MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique {id: $technique_id})
RETURN m.id AS mitigation_id,
       m.name AS mitigation_name,
       m.description AS mitigation_description
```

To retrieve mitigations ranked by their breadth of coverage (i.e., the number of techniques each mitigation addresses):

```cypher
MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique {id: $technique_id})
WITH m
MATCH (m)-[:MITIGATES]->(t2:Technique)
RETURN m.id, m.name, count(t2) AS techniques_covered
ORDER BY techniques_covered DESC
```

### 8.3 Example Queries for Retrieving Detection Strategies

To retrieve the complete detection chain for a technique:

```cypher
MATCH (ds:DetectionStrategy)-[:DETECTS]->(t:Technique {id: $technique_id})
OPTIONAL MATCH (ds)-[:CONTAINS]->(a:Analytic)
OPTIONAL MATCH (a)-[:USES]->(dc:DataComponent)
RETURN ds.id AS strategy_id,
       ds.name AS strategy_name,
       collect(DISTINCT {
           analytic_id: a.id,
           analytic_name: a.name,
           data_components: collect(DISTINCT dc.name)
       }) AS analytics
```

### 8.4 Example Queries for Linking Techniques to Assets

To identify which techniques threaten a specific asset type:

```cypher
MATCH (t:Technique)-[:TARGETS]->(a:Asset {name: $asset_name})
RETURN t.id, t.name, t.description
ORDER BY t.id
```

### 8.5 Comprehensive Attack Path Queries

The most powerful queries leverage multi-hop traversals to build complete attack-defense pictures:

```cypher
-- For a given threat group, find all techniques they use,
-- the assets those techniques target,
-- and the mitigations that address those techniques
MATCH (g:Group {id: $group_id})-[:USES]->(t:Technique)
OPTIONAL MATCH (t)-[:TARGETS]->(a:Asset)
OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
RETURN g.name AS group_name,
       t.id AS technique_id,
       t.name AS technique_name,
       collect(DISTINCT a.name) AS targeted_assets,
       collect(DISTINCT m.name) AS available_mitigations
```

---

## 9. Performance Considerations

### 9.1 Graph Size and Scalability

The MITRE ATT&CK for ICS knowledge graph is relatively modest in size:

| Metric | v17 | v18 |
|--------|-----|-----|
| Total nodes | 258 | 410 |
| Total relationships | 1,459 | 1,382+ |
| Build time | ~218 seconds | ~215 seconds |

The graph's small scale (hundreds, not millions, of nodes) means that query performance is not a bottleneck for interactive use. The build time is dominated by the latency of individual Neo4j transactions over the network connection to the cloud-hosted Aura instance, not by computational complexity.

However, the architecture is designed to scale gracefully if the ATT&CK for ICS framework expands significantly or if additional data sources (e.g., threat intelligence feeds, vulnerability databases) are integrated:

- Uniqueness constraints on `id` ensure O(log n) node lookups.
- Name-based indexes accelerate pattern matching for human-readable queries.
- The `MERGE`-based upsert pattern supports incremental additions without full rebuilds.

### 9.2 Query Optimization Strategies

Several strategies are employed to optimize query performance:

**9.2.1 Constraint-Backed Indexes.** Every uniqueness constraint automatically creates a B-tree index on the `id` property, which is used for all `MATCH` operations during node lookup. This ensures O(log n) performance for node-by-id queries.

**9.2.2 Additional Name Indexes.** B-tree indexes on the `name` property of high-frequency entity types (Technique, Tactic, Software, Group, Campaign, Asset, Mitigation) accelerate name-based lookups that are common in analyst-facing queries.

```cypher
CREATE INDEX technique_name IF NOT EXISTS FOR (t:Technique) ON (t.name)
```

**9.2.3 Parameterized Queries.** All Cypher queries use parameter substitution (`$parameter`) rather than string interpolation, enabling Neo4j to cache and reuse query execution plans across different parameter values.

**9.2.4 MERGE for Deduplication.** The use of `MERGE` instead of `CREATE` + existence check eliminates the need for separate existence queries, reducing the total number of database round trips.

### 9.3 Indexing Strategy

The indexing strategy comprises two tiers:

1. **Tier 1 — Uniqueness constraints** (created before data loading): These enforce data integrity and automatically create backing indexes on the `id` property for all 10 node labels. These indexes support the bulk of the MATCH operations during graph construction and relationship queries.

2. **Tier 2 — B-tree indexes on `name`** (created after data loading): These indexes are created after all nodes are loaded to avoid the overhead of maintaining them during bulk insertion. They support analyst-facing queries that search by entity name rather than by MITRE ID.

### 9.4 Tradeoffs

- **Per-row transactions vs. batch transactions:** The current implementation creates one Neo4j transaction per row (per `session.run()` call within the DataFrame iteration loop). This approach prioritizes simplicity and fine-grained error isolation over throughput. A batch approach using `UNWIND` with parameter lists would significantly reduce network round trips and improve build time, at the cost of all-or-nothing failure semantics for each batch.
- **Cloud-hosted vs. local database:** The use of Neo4j Aura introduces network latency on each transaction. A locally hosted Neo4j instance would reduce build times by an order of magnitude but requires infrastructure management.
- **Full rebuild vs. incremental update:** The full-rebuild strategy ensures correctness but discards all graph data (including any analyst annotations or custom relationships) on each run. An incremental approach would preserve such additions but require change-detection logic.

---

## 10. Limitations

### 10.1 Data Completeness Issues

- **Missing detection chain relationships:** The official MITRE ATT&CK ICS Excel export does not include the mappings between detection strategies, analytics, and data components. These relationships are derived through URL parsing and web scraping, which introduces fragility (HTML structure changes could break the scraper) and potential incompleteness (network errors during scraping are silently skipped).
- **Incomplete web scraping dependencies:** The `requirements.txt` file does not list the `requests` and `beautifulsoup4` packages required by the web scraping module, which could cause runtime failures if the environment is provisioned solely from the requirements file.

### 10.2 Static vs. Dynamic Updates

The knowledge graph is constructed from a static Excel snapshot and does not receive real-time updates from the MITRE ATT&CK repository. When MITRE releases a new version of the ATT&CK for ICS framework, the entire pipeline must be re-executed manually. There is no automated mechanism to detect new releases, download updated datasets, or apply incremental patches.

### 10.3 Coverage Gaps in MITRE ATT&CK for ICS

The MITRE ATT&CK for ICS framework, while comprehensive, has known coverage gaps:

- **Sector-specific techniques:** Some attack behaviors specific to certain industrial sectors (e.g., oil and gas, nuclear) may not yet be cataloged in the framework.
- **Sub-technique granularity:** Unlike the Enterprise ATT&CK matrix, the ICS matrix does not extensively use sub-techniques, resulting in coarser-grained technique definitions.
- **Limited threat group coverage:** Only 14 threat groups are cataloged in the ICS matrix (v18), compared to over 140 in the Enterprise matrix, reflecting the narrower (but growing) body of publicly documented ICS-targeted campaigns.

### 10.4 Credential Management

The current implementation embeds Neo4j connection credentials (URI, username, password) directly in the `main()` function of each builder script. This practice is unsuitable for production deployment and poses a security risk if the source code is committed to a public repository. Credentials should be externalized to environment variables or a secrets management system.

### 10.5 Single-Statement Transactions

The use of individual `session.run()` calls within row-iteration loops results in one database round trip per entity, which is suboptimal for bulk loading. On a cloud-hosted Neo4j instance, this translates to a build time of approximately 3.5 minutes for ~410 nodes and ~1,400 relationships.

---

## 11. Future Improvements

### 11.1 Real-Time Updates

A future version of the pipeline could implement automated polling of the MITRE ATT&CK repository (via the TAXII 2.1 server or the GitHub releases API) to detect and ingest new framework versions. A differential update mechanism would compare the new dataset against the existing graph and apply only the changes (new nodes, modified properties, new or removed relationships), preserving any analyst-added annotations.

### 11.2 Integration with Threat Intelligence Feeds

The knowledge graph could be enriched with real-time threat intelligence from external feeds (e.g., MISP, OpenCTI, STIX/TAXII feeds) to add context such as:

- Recently observed technique usage in the wild.
- Indicators of Compromise (IoCs) linked to specific techniques or software.
- Sector-specific threat advisories linked to relevant techniques.

This would transform the knowledge graph from a static reference into a living threat intelligence platform.

### 11.3 Graph Embeddings and Machine Learning on Graphs

Graph representation learning techniques (e.g., Node2Vec, GraphSAGE, TransE) could be applied to the knowledge graph to generate vector embeddings for each node. These embeddings could then be used for:

- **Technique similarity analysis:** Identifying clusters of related techniques for grouped mitigation recommendations.
- **Link prediction:** Predicting undocumented relationships (e.g., which techniques a newly discovered group is likely to use, based on similarities to known groups).
- **Risk scoring:** Training a model to estimate the risk score of a technique based on its graph neighborhood (connected groups, campaigns, assets, and mitigations).

### 11.4 Better Linking with Detection Engine Outputs

The current integration between the detection engine and the knowledge graph is query-based: the detection engine identifies a technique ID and queries the graph for related information. A more tightly integrated architecture could:

- Automatically map Elasticsearch detection rules to graph Analytic nodes using identifier matching.
- Propagate detection confidence scores from the detection engine into the graph as relationship properties.
- Enable feedback loops where successful detections increase the priority of associated mitigations in the recommendation engine.

### 11.5 Batch Transaction Optimization

The current per-row transaction model could be replaced with batch loading using Cypher `UNWIND` clauses:

```cypher
UNWIND $techniques AS tech
MERGE (t:Technique {id: tech.id})
SET t += tech
```

This would reduce the number of database round trips from O(n) to O(1) per entity type, potentially reducing build times by an order of magnitude.

### 11.6 Version-Aware Graph Management

A future enhancement could maintain multiple ATT&CK versions simultaneously in the same database using version labels or properties, enabling temporal analysis of how the threat landscape has evolved between framework releases.

---

## 12. Example Queries and Use Cases

### 12.1 Detection Recommendations

**Use Case:** Given a detected technique, recommend detection strategies and identify the data components needed for comprehensive detection coverage.

```cypher
// Find all detection strategies for a specific technique
MATCH (ds:DetectionStrategy)-[:DETECTS]->(t:Technique {id: 'T0853'})
RETURN ds.id AS strategy_id, ds.name AS strategy_name

// Find the complete detection chain for a technique
MATCH (ds:DetectionStrategy)-[:DETECTS]->(t:Technique {id: 'T0853'})
MATCH (ds)-[:CONTAINS]->(a:Analytic)
MATCH (a)-[:USES]->(dc:DataComponent)
RETURN ds.name AS detection_strategy,
       a.name AS analytic,
       collect(dc.name) AS required_data_components
```

### 12.2 Mitigation Recommendations

**Use Case:** For techniques used by a specific threat group, recommend mitigations ordered by their breadth of coverage.

```cypher
// Find mitigations for all techniques used by a threat group
MATCH (g:Group {name: 'Sandworm Team'})-[:USES]->(t:Technique)
MATCH (m:Mitigation)-[:MITIGATES]->(t)
WITH m, collect(t.name) AS addressed_techniques
RETURN m.id AS mitigation_id,
       m.name AS mitigation_name,
       m.description AS description,
       addressed_techniques,
       size(addressed_techniques) AS technique_count
ORDER BY technique_count DESC
```

### 12.3 Prioritization Logic

**Use Case:** Rank techniques by risk, considering the number of groups that use them, the number of assets they target, and whether mitigations are available.

```cypher
MATCH (t:Technique)
OPTIONAL MATCH (g:Group)-[:USES]->(t)
OPTIONAL MATCH (t)-[:TARGETS]->(a:Asset)
OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
WITH t,
     count(DISTINCT g) AS group_count,
     count(DISTINCT a) AS asset_count,
     count(DISTINCT m) AS mitigation_count
RETURN t.id AS technique_id,
       t.name AS technique_name,
       group_count,
       asset_count,
       mitigation_count,
       CASE WHEN mitigation_count = 0 THEN 'CRITICAL'
            WHEN mitigation_count < 3 THEN 'HIGH'
            ELSE 'MEDIUM'
       END AS priority
ORDER BY group_count DESC, asset_count DESC, mitigation_count ASC
```

### 12.4 Threat Group Profiling

**Use Case:** Generate a comprehensive profile of a threat group's capabilities.

```cypher
MATCH (g:Group {id: 'G0034'})
OPTIONAL MATCH (g)-[:USES]->(t:Technique)
OPTIONAL MATCH (g)-[:USES]->(s:Software)
OPTIONAL MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(g)
RETURN g.name AS group_name,
       g.description AS description,
       collect(DISTINCT t.name) AS techniques,
       collect(DISTINCT s.name) AS software,
       collect(DISTINCT c.name) AS campaigns
```

### 12.5 Asset Exposure Analysis

**Use Case:** For a specific ICS asset type, identify all techniques that target it and the available mitigations.

```cypher
MATCH (t:Technique)-[:TARGETS]->(a:Asset {name: 'Engineering Workstation'})
OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
RETURN t.id AS technique_id,
       t.name AS technique_name,
       collect(DISTINCT m.name) AS mitigations,
       size(collect(DISTINCT m.name)) AS mitigation_coverage
ORDER BY mitigation_coverage ASC
```

### 12.6 Detection Gap Analysis

**Use Case:** Identify techniques that have no detection strategies, representing gaps in the detection posture.

```cypher
MATCH (t:Technique)
WHERE NOT EXISTS {
    MATCH (ds:DetectionStrategy)-[:DETECTS]->(t)
}
RETURN t.id AS technique_id,
       t.name AS technique_name,
       t.description AS description
ORDER BY t.id
```

### 12.7 Campaign Impact Analysis

**Use Case:** Trace the full impact chain of a campaign.

```cypher
MATCH (c:Campaign {name: '2015 Ukraine Electric Power Attack'})
MATCH (c)-[:ATTRIBUTED_TO]->(g:Group)
MATCH (c)-[:USES]->(t:Technique)
OPTIONAL MATCH (t)-[:TARGETS]->(a:Asset)
RETURN c.name AS campaign,
       g.name AS attributed_group,
       collect(DISTINCT {technique: t.name, assets: collect(DISTINCT a.name)}) AS attack_details
```

### 12.8 Cross-Component Detection Path

**Use Case:** Given a detected technique, trace the full path from detection strategy through analytics to the required data components, enabling verification that all necessary data collection is in place.

```cypher
MATCH path = (ds:DetectionStrategy)-[:DETECTS]->(t:Technique {id: $technique_id})
MATCH chain = (ds)-[:CONTAINS]->(a:Analytic)-[:USES]->(dc:DataComponent)
RETURN t.name AS technique,
       ds.name AS detection_strategy,
       a.name AS analytic,
       dc.name AS data_component
ORDER BY ds.name, a.name
```

---

## 13. Conclusion

### 13.1 Summary of the Component's Value

The MITRE ATT&CK for ICS Knowledge Graph component provides a structured, queryable, and semantically rich representation of the complete MITRE ATT&CK for ICS framework. By modeling the framework's entities and their interrelationships as a labeled property graph in Neo4j, the component enables complex multi-hop queries that would be impractical with flat or tabular data representations. The automated construction pipeline — from Excel ingestion through complementary data extraction to graph materialization — ensures reproducibility and consistency with each new ATT&CK release.

The implementation covers 10 distinct entity types (Technique, Tactic, Mitigation, DetectionStrategy, Analytic, DataComponent, Software, Group, Campaign, Asset), 410 nodes, and over 1,500 typed relationships in its v18 configuration. The graph's schema was designed to balance semantic precision with practical simplicity, using polymorphic relationship types where appropriate and typed nodes to enable targeted queries.

### 13.2 Importance in the Overall System

Within the broader Recommendation System for ICS/OT security, the knowledge graph serves as the central semantic backbone that connects all other components:

- It enables the **detection engine** to contextualize observed behaviors within the broader adversary landscape.
- It provides the **recommendation engine** with the structured mappings needed to generate actionable mitigation and detection recommendations.
- It supplies the **prioritization engine** with the graph-based metrics (e.g., threat group usage counts, asset targeting breadth, mitigation coverage) that inform risk-based prioritization.
- It offers **security analysts** an interactive, visual exploration interface for understanding the ICS threat landscape and validating system-generated recommendations.

The knowledge graph transforms the MITRE ATT&CK for ICS framework from a static reference document into a dynamic, queryable decision-support tool that is integral to the operational effectiveness of the complete recommendation system.

---

## References

1. MITRE ATT&CK for ICS. Available at: https://attack.mitre.org/techniques/ics/
2. Neo4j Graph Database. Available at: https://neo4j.com/
3. STIX 2.1 Specification. OASIS Cyber Threat Intelligence Technical Committee.
4. MITRE ATT&CK Framework Design and Philosophy. MITRE Corporation, 2020.

---

*This documentation was prepared as part of the graduation project report for the Recommendation System for ICS/OT Security, covering the Knowledge Graph Construction component.*
