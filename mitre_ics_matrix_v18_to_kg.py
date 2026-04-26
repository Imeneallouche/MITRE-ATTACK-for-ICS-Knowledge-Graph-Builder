"""
MITRE ATT&CK for ICS VERSION 18 Knowledge Graph Builder
Converts Excel file with MITRE ATT&CK ICS VERSION 18 data into Neo4j Knowledge Graph
"""

import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from neo4j import GraphDatabase

_REPO = Path(__file__).resolve().parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
from config import (
    ConfigurationError,
    get_clear_database_default,
    get_neo4j_credentials,
    path_v18_matrix_excel,
    safe_log_neo4j_target,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MITREKnowledgeGraphBuilder:
    """Builds MITRE ATT&CK ICS Knowledge Graph in Neo4j"""
    
    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j connection
        
        Args:
            uri: Neo4j database URI (e.g., 'bolt://localhost:7687')
            username: Neo4j username
            password: Neo4j password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        logger.info("Connected to Neo4j at %s", safe_log_neo4j_target(uri))
    
    def close(self):
        """Close Neo4j connection"""
        self.driver.close()
        logger.info("Neo4j connection closed")
    
    def clear_database(self):
        """Clear all nodes and relationships from the database"""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.info("Database cleared")
    
    def create_constraints_and_indexes(self):
        """Create uniqueness constraints and indexes for performance"""
        constraints = [
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT software_id IF NOT EXISTS FOR (s:Software) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
            "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE",
            "CREATE CONSTRAINT datacomponent_id IF NOT EXISTS FOR (d:DataComponent) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT analytic_id IF NOT EXISTS FOR (a:Analytic) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT detectionstrategy_id IF NOT EXISTS FOR (d:DetectionStrategy) REQUIRE d.id IS UNIQUE"
        ]
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.info(f"Created constraint: {constraint.split('FOR')[1].split('REQUIRE')[0].strip()}")
                except Exception as e:
                    logger.warning(f"Constraint may already exist: {e}")
    
    @staticmethod
    def clean_value(value: Any) -> Optional[Any]:
        """Clean and normalize values from Excel"""
        if pd.isna(value) or value == '' or value == 'nan':
            return None
        if isinstance(value, str):
            return value.strip()
        return value
    
    @staticmethod
    def parse_list_field(value: Any, separator: str = ',') -> List[str]:
        """Parse comma-separated or multi-line fields into list"""
        if pd.isna(value) or value == '':
            return []
        
        value_str = str(value)
        # Handle both comma and newline separators
        items = re.split(r'[,\n;]+', value_str)
        return [item.strip() for item in items if item.strip()]
    
    @staticmethod
    def map_stix_type_to_label(stix_type: str) -> str:
        """Map STIX type names to Neo4j node labels"""
        type_mapping = {
            'attack-pattern': 'Technique',
            'course-of-action': 'Mitigation',
            'intrusion-set': 'Group',
            'malware': 'Software',
            'tool': 'Software',
            'campaign': 'Campaign',
            'x-mitre-tactic': 'Tactic',
            'x-mitre-asset': 'Asset',
            'x-mitre-data-component': 'DataComponent',
            'x-mitre-data-source': 'DataSource',
            'relationship': 'Relationship',
            # Handle lowercase versions from relationships sheet
            'technique': 'Technique',
            'mitigation': 'Mitigation',
            'group': 'Group',
            'software': 'Software',
            'tactic': 'Tactic',
            'asset': 'Asset',
            'datacomponent': 'DataComponent',
            'detectionstrategy': 'DetectionStrategy',
            'analytic': 'Analytic'
        }
        
        # Return mapped label or use the original if not found
        return type_mapping.get(stix_type.lower(), stix_type.title())
    
    def create_node(self, session, label: str, properties: Dict[str, Any]):
        """Create a node with given label and properties"""
        # Clean properties
        clean_props = {k: self.clean_value(v) for k, v in properties.items() if self.clean_value(v) is not None}
        
        if not clean_props.get('id'):
            logger.warning(f"Skipping node creation - no ID provided for {label}")
            return
        
        # Build cypher query
        props_str = ', '.join([f"{k}: ${k}" for k in clean_props.keys()])
        query = f"MERGE (n:{label} {{id: $id}}) SET n += {{{props_str}}}"
        
        session.run(query, **clean_props)
    
    def load_techniques(self, df: pd.DataFrame):
        """Load Technique nodes from techniques sheet"""
        logger.info(f"Loading {len(df)} techniques...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version')),
                    'detection': self.clean_value(row.get('detection'))
                }
                
                self.create_node(session, 'Technique', properties)
                
                # Create relationships to Tactics (stored as comma-separated in 'tactics' column)
                tactics = self.parse_list_field(row.get('tactics'))
                for tactic in tactics:
                    session.run("""
                        MATCH (tac:Tactic {name: $tactic_name})
                        MATCH (tech:Technique {id: $tech_id})
                        MERGE (tac)-[:USES]->(tech)
                    """, tactic_name=tactic, tech_id=properties['id'])
                
                # Store platforms as list property
                platforms = self.parse_list_field(row.get('platforms'))
                if platforms:
                    session.run("""
                        MATCH (t:Technique {id: $tech_id})
                        SET t.platforms = $platforms
                    """, tech_id=properties['id'], platforms=platforms)
                
                # Store data sources as list property
                data_sources = self.parse_list_field(row.get('data sources'))
                if data_sources:
                    session.run("""
                        MATCH (t:Technique {id: $tech_id})
                        SET t.data_sources = $data_sources
                    """, tech_id=properties['id'], data_sources=data_sources)
                
                # Store contributors as list property
                contributors = self.parse_list_field(row.get('contributors'))
                if contributors:
                    session.run("""
                        MATCH (t:Technique {id: $tech_id})
                        SET t.contributors = $contributors
                    """, tech_id=properties['id'], contributors=contributors)
        
        logger.info(f"✓ Loaded {len(df)} techniques")
    
    def load_tactics(self, df: pd.DataFrame):
        """Load Tactic nodes from tactics sheet"""
        logger.info(f"Loading {len(df)} tactics...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version'))
                }
                
                self.create_node(session, 'Tactic', properties)
        
        logger.info(f"✓ Loaded {len(df)} tactics")
    
    def load_software(self, df: pd.DataFrame):
        """Load Software nodes from software sheet"""
        logger.info(f"Loading {len(df)} software...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version')),
                    'type': self.clean_value(row.get('type'))
                }
                
                self.create_node(session, 'Software', properties)
                
                # Store platforms as list property
                platforms = self.parse_list_field(row.get('platforms'))
                if platforms:
                    session.run("""
                        MATCH (s:Software {id: $soft_id})
                        SET s.platforms = $platforms
                    """, soft_id=properties['id'], platforms=platforms)
                
                # Store aliases as list property
                aliases = self.parse_list_field(row.get('aliases'))
                if aliases:
                    session.run("""
                        MATCH (s:Software {id: $soft_id})
                        SET s.aliases = $aliases
                    """, soft_id=properties['id'], aliases=aliases)
                
                # Store contributors as list property
                contributors = self.parse_list_field(row.get('contributors'))
                if contributors:
                    session.run("""
                        MATCH (s:Software {id: $soft_id})
                        SET s.contributors = $contributors
                    """, soft_id=properties['id'], contributors=contributors)
        
        logger.info(f"✓ Loaded {len(df)} software")
    
    def load_groups(self, df: pd.DataFrame):
        """Load Group nodes from groups sheet"""
        logger.info(f"Loading {len(df)} groups...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version'))
                }
                
                self.create_node(session, 'Group', properties)
                
                # Store contributors as list property
                contributors = self.parse_list_field(row.get('contributors'))
                if contributors:
                    session.run("""
                        MATCH (g:Group {id: $group_id})
                        SET g.contributors = $contributors
                    """, group_id=properties['id'], contributors=contributors)
                
                # Store associated groups as list property
                associated_groups = self.parse_list_field(row.get('associated groups'))
                if associated_groups:
                    session.run("""
                        MATCH (g:Group {id: $group_id})
                        SET g.associated_groups = $associated_groups
                    """, group_id=properties['id'], associated_groups=associated_groups)
                    
                    # Create ASSOCIATED_WITH relationships
                    for assoc_group in associated_groups:
                        session.run("""
                            MATCH (g1:Group {id: $group_id})
                            MATCH (g2:Group {name: $assoc_name})
                            MERGE (g1)-[:ASSOCIATED_WITH]->(g2)
                        """, group_id=properties['id'], assoc_name=assoc_group)
        
        logger.info(f"✓ Loaded {len(df)} groups")
    
    def load_campaigns(self, df: pd.DataFrame):
        """Load Campaign nodes from campaigns sheet"""
        logger.info(f"Loading {len(df)} campaigns...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version')),
                    'first_seen': self.clean_value(row.get('first seen')),
                    'last_seen': self.clean_value(row.get('last seen'))
                }
                
                self.create_node(session, 'Campaign', properties)
                
                # Store associated campaigns as list property
                associated_campaigns = self.parse_list_field(row.get('associated campaigns'))
                if associated_campaigns:
                    session.run("""
                        MATCH (c:Campaign {id: $campaign_id})
                        SET c.associated_campaigns = $associated_campaigns
                    """, campaign_id=properties['id'], associated_campaigns=associated_campaigns)
                    
                    # Create ASSOCIATED_WITH relationships
                    for assoc_campaign in associated_campaigns:
                        session.run("""
                            MATCH (c1:Campaign {id: $campaign_id})
                            MATCH (c2:Campaign {name: $assoc_name})
                            MERGE (c1)-[:ASSOCIATED_WITH]->(c2)
                        """, campaign_id=properties['id'], assoc_name=assoc_campaign)
        
        logger.info(f"✓ Loaded {len(df)} campaigns")
    
    def load_assets(self, df: pd.DataFrame):
        """Load Asset nodes from assets sheet"""
        logger.info(f"Loading {len(df)} assets...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version')),
                    'related_assets_description': self.clean_value(row.get('related assets description'))
                }
                
                self.create_node(session, 'Asset', properties)
                
                # Store platforms as list property
                platforms = self.parse_list_field(row.get('platforms'))
                if platforms:
                    session.run("""
                        MATCH (a:Asset {id: $asset_id})
                        SET a.platforms = $platforms
                    """, asset_id=properties['id'], platforms=platforms)
                
                # Store sectors as list property
                sectors = self.parse_list_field(row.get('sectors'))
                if sectors:
                    session.run("""
                        MATCH (a:Asset {id: $asset_id})
                        SET a.sectors = $sectors
                    """, asset_id=properties['id'], sectors=sectors)
                
                # Store related assets as list property
                related_assets = self.parse_list_field(row.get('related assets'))
                if related_assets:
                    session.run("""
                        MATCH (a:Asset {id: $asset_id})
                        SET a.related_assets = $related_assets
                    """, asset_id=properties['id'], related_assets=related_assets)
                    
                    # Create RELATED_TO relationships between assets
                    for related_asset in related_assets:
                        session.run("""
                            MATCH (a1:Asset {id: $asset_id})
                            MATCH (a2:Asset {name: $related_name})
                            MERGE (a1)-[:RELATED_TO]->(a2)
                        """, asset_id=properties['id'], related_name=related_asset)
        
        logger.info(f"✓ Loaded {len(df)} assets")
    
    def load_mitigations(self, df: pd.DataFrame):
        """Load Mitigation nodes from mitigations sheet"""
        logger.info(f"Loading {len(df)} mitigations...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version'))
                }
                
                self.create_node(session, 'Mitigation', properties)
        
        logger.info(f"✓ Loaded {len(df)} mitigations")
    
    def load_datacomponents(self, df: pd.DataFrame):
        """Load DataComponent nodes from datacomponents sheet"""
        logger.info(f"Loading {len(df)} data components...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version'))
                }
                
                self.create_node(session, 'DataComponent', properties)
        
        logger.info(f"✓ Loaded {len(df)} data components")
    
    def load_analytics(self, df: pd.DataFrame):
        """Load Analytic nodes from analytics sheet"""
        logger.info(f"Loading {len(df)} analytics...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'description': self.clean_value(row.get('description')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version'))
                }
                
                self.create_node(session, 'Analytic', properties)
        
        logger.info(f"✓ Loaded {len(df)} analytics")
    
    def load_detectionstrategies(self, df: pd.DataFrame):
        """Load DetectionStrategy nodes from detectionstrategies sheet"""
        logger.info(f"Loading {len(df)} detection strategies...")
        
        with self.driver.session() as session:
            for idx, row in df.iterrows():
                properties = {
                    'id': self.clean_value(row.get('ID')),
                    'stix_id': self.clean_value(row.get('STIX ID')),
                    'name': self.clean_value(row.get('name')),
                    'url': self.clean_value(row.get('url')),
                    'created': self.clean_value(row.get('created')),
                    'last_modified': self.clean_value(row.get('last modified')),
                    'domain': self.clean_value(row.get('domain')),
                    'version': self.clean_value(row.get('version'))
                }
                
                self.create_node(session, 'DetectionStrategy', properties)
        
        logger.info(f"✓ Loaded {len(df)} detection strategies")
    
    def load_matrix(self, df: pd.DataFrame):
        """
        Load matrix relationships between Tactics and Techniques
        Matrix sheet has tactics as columns and techniques as rows
        """
        logger.info("Loading matrix relationships...")
        
        with self.driver.session() as session:
            relationship_count = 0
            
            # Iterate through each column (tactic)
            for tactic_col in df.columns:
                if tactic_col and tactic_col.strip():
                    tactic_name = tactic_col.strip()
                    
                    # Get all technique IDs in this column
                    technique_ids = df[tactic_col].dropna().tolist()
                    
                    for tech_id in technique_ids:
                        tech_id_clean = self.clean_value(tech_id)
                        if tech_id_clean:
                            # Create USES relationship from Tactic to Technique
                            session.run("""
                                MATCH (tac:Tactic {name: $tactic_name})
                                MATCH (tech:Technique {id: $tech_id})
                                MERGE (tac)-[:USES]->(tech)
                            """, tactic_name=tactic_name, tech_id=tech_id_clean)
                            relationship_count += 1
            
            logger.info(f"✓ Created {relationship_count} Tactic-Technique relationships from matrix")
    
    def load_relationships(self, df: pd.DataFrame):
        """
        Load all relationships from relationships sheet
        Handles: attributed-to, detects, mitigates, targets, uses
        """
        logger.info(f"Loading {len(df)} relationships...")
        
        with self.driver.session() as session:
            relationship_counts = {}
            failed_relationships = []
            
            for idx, row in df.iterrows():
                source_id = self.clean_value(row.get('source ID'))
                source_type = self.clean_value(row.get('source type'))
                target_id = self.clean_value(row.get('target ID'))
                target_type = self.clean_value(row.get('target type'))
                mapping_type = self.clean_value(row.get('mapping type'))
                mapping_description = self.clean_value(row.get('mapping description'))
                
                if not all([source_id, source_type, target_id, target_type, mapping_type]):
                    continue
                
                # Map STIX types to our Neo4j labels
                source_label = self.map_stix_type_to_label(source_type)
                target_label = self.map_stix_type_to_label(target_type)
                
                # Normalize relationship type
                rel_type = mapping_type.upper().replace('-', '_').replace(' ', '_')
                
                try:
                    # Create relationship with properties
                    query = f"""
                        MATCH (source:{source_label} {{id: $source_id}})
                        MATCH (target:{target_label} {{id: $target_id}})
                        MERGE (source)-[r:{rel_type}]->(target)
                    """
                    
                    # Add description if available
                    if mapping_description:
                        query += " SET r.description = $description"
                        result = session.run(query, 
                                  source_id=source_id, 
                                  target_id=target_id,
                                  description=mapping_description)
                    else:
                        result = session.run(query, source_id=source_id, target_id=target_id)
                    
                    # Track relationship counts
                    relationship_counts[rel_type] = relationship_counts.get(rel_type, 0) + 1
                    
                except Exception as e:
                    failed_relationships.append({
                        'source_id': source_id,
                        'source_type': source_label,
                        'target_id': target_id,
                        'target_type': target_label,
                        'rel_type': rel_type,
                        'error': str(e)
                    })
            
            # Log relationship type counts
            logger.info("\n=== Relationship Creation Summary ===")
            for rel_type, count in sorted(relationship_counts.items()):
                logger.info(f"  ✓ Created {count} {rel_type} relationships")
            
            if failed_relationships:
                logger.warning(f"\n⚠ Failed to create {len(failed_relationships)} relationships")
                # Log first few failures for debugging
                for failure in failed_relationships[:5]:
                    logger.warning(f"  - {failure['source_type']}({failure['source_id']}) -[{failure['rel_type']}]-> {failure['target_type']}({failure['target_id']})")
        
        logger.info(f"✓ Loaded {sum(relationship_counts.values())} relationships")
    
    def create_additional_indexes(self):
        """Create additional indexes for better query performance"""
        indexes = [
            "CREATE INDEX technique_name IF NOT EXISTS FOR (t:Technique) ON (t.name)",
            "CREATE INDEX tactic_name IF NOT EXISTS FOR (t:Tactic) ON (t.name)",
            "CREATE INDEX software_name IF NOT EXISTS FOR (s:Software) ON (s.name)",
            "CREATE INDEX group_name IF NOT EXISTS FOR (g:Group) ON (g.name)",
            "CREATE INDEX campaign_name IF NOT EXISTS FOR (c:Campaign) ON (c.name)",
            "CREATE INDEX asset_name IF NOT EXISTS FOR (a:Asset) ON (a.name)",
            "CREATE INDEX mitigation_name IF NOT EXISTS FOR (m:Mitigation) ON (m.name)"
        ]
        
        with self.driver.session() as session:
            for index in indexes:
                try:
                    session.run(index)
                    logger.info(f"Created index: {index.split('FOR')[1].split('ON')[0].strip()}")
                except Exception as e:
                    logger.warning(f"Index may already exist: {e}")
    
    def analyze_relationships_sheet(self, df: pd.DataFrame):
        """Analyze the relationships sheet to understand data structure"""
        logger.info("\n=== Analyzing Relationships Sheet ===")
        
        # Get unique source and target types
        source_types = df['source type'].dropna().unique()
        target_types = df['target type'].dropna().unique()
        mapping_types = df['mapping type'].dropna().unique()
        
        logger.info(f"Source types found: {list(source_types)}")
        logger.info(f"Target types found: {list(target_types)}")
        logger.info(f"Mapping types found: {list(mapping_types)}")
        
        # Count relationships by type
        logger.info("\nRelationship type distribution:")
        rel_counts = df['mapping type'].value_counts()
        for rel_type, count in rel_counts.items():
            logger.info(f"  {rel_type}: {count}")
        
        # Sample relationships
        logger.info("\nSample relationships:")
        for idx, row in df.head(10).iterrows():
            logger.info(f"  {row['source type']}({row['source ID']}) -[{row['mapping type']}]-> {row['target type']}({row['target ID']})")
    
    def get_statistics(self):
        """Get and display graph statistics"""
        with self.driver.session() as session:
            # Count nodes by label
            logger.info("\n=== Node Statistics ===")
            total_nodes = 0
            
            # Get all labels
            labels_result = session.run("CALL db.labels()")
            labels = [record['label'] for record in labels_result]
            
            for label in sorted(labels):
                result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                count = result.single()['count']
                total_nodes += count
                logger.info(f"{label}: {count}")
            
            logger.info(f"Total Nodes: {total_nodes}")
            
            # Count relationships by type
            logger.info("\n=== Relationship Statistics ===")
            total_rels = 0
            
            # Get all relationship types
            rel_types_result = session.run("CALL db.relationshipTypes()")
            rel_types = [record['relationshipType'] for record in rel_types_result]
            
            for rel_type in sorted(rel_types):
                result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count")
                count = result.single()['count']
                total_rels += count
                logger.info(f"{rel_type}: {count}")
            
            logger.info(f"Total Relationships: {total_rels}")
            
            # Verify specific relationship patterns
            logger.info("\n=== Verifying Key Relationships ===")
            
            key_patterns = [
                ("Mitigation", "MITIGATES", "Technique"),
                ("DetectionStrategy", "DETECTS", "Technique"),
                ("Technique", "TARGETS", "Asset"),
                ("Campaign", "ATTRIBUTED_TO", "Group"),
                ("Group", "USES", "Software"),
                ("Group", "USES", "Technique"),
                ("Campaign", "USES", "Software"),
                ("Campaign", "USES", "Technique"),
                ("Software", "USES", "Technique"),
                ("Tactic", "USES", "Technique")
            ]
            
            for source, rel, target in key_patterns:
                result = session.run(f"""
                    MATCH (s:{source})-[r:{rel}]->(t:{target})
                    RETURN count(r) as count
                """)
                count = result.single()['count']
                status = "✓" if count > 0 else "✗"
                logger.info(f"  {status} {source} -[{rel}]-> {target}: {count}")
    
    def build_knowledge_graph(self, excel_file: str, clear_existing: bool = True):
        """
        Main method to build the complete knowledge graph
        
        Args:
            excel_file: Path to the MITRE ATT&CK ICS Excel file
            clear_existing: Whether to clear existing data before loading
        """
        logger.info(f"Starting knowledge graph build from {excel_file}")
        
        try:
            # Clear database if requested
            if clear_existing:
                self.clear_database()
            
            # Create constraints and indexes
            self.create_constraints_and_indexes()
            
            # Read all sheets
            logger.info("Reading Excel file...")
            sheets = pd.read_excel(excel_file, sheet_name=None)
            
            # Load nodes in order (load referenced nodes first)
            if 'tactics' in sheets:
                self.load_tactics(sheets['tactics'])
            
            if 'techniques' in sheets:
                self.load_techniques(sheets['techniques'])
            
            if 'software' in sheets:
                self.load_software(sheets['software'])
            
            if 'groups' in sheets:
                self.load_groups(sheets['groups'])
            
            if 'campaigns' in sheets:
                self.load_campaigns(sheets['campaigns'])
            
            if 'assets' in sheets:
                self.load_assets(sheets['assets'])
            
            if 'mitigations' in sheets:
                self.load_mitigations(sheets['mitigations'])
            
            if 'datacomponents' in sheets:
                self.load_datacomponents(sheets['datacomponents'])
            
            if 'analytics' in sheets:
                self.load_analytics(sheets['analytics'])
            
            if 'detectionstrategies' in sheets:
                self.load_detectionstrategies(sheets['detectionstrategies'])
            
            # Load matrix relationships (Tactic -> Technique)
            if 'matrix' in sheets:
                self.load_matrix(sheets['matrix'])
            
            # Load all other relationships from relationships sheet
            if 'relationships' in sheets:
                # First analyze the relationships sheet
                self.analyze_relationships_sheet(sheets['relationships'])
                self.load_relationships(sheets['relationships'])
            
            # Create additional indexes for performance
            self.create_additional_indexes()
            
            # Display statistics
            logger.info("\n" + "="*50)
            self.get_statistics()
            logger.info("="*50)
            
            logger.info("\n✓ Knowledge graph build completed successfully!")
            
        except Exception as e:
            logger.error(f"Error building knowledge graph: {e}")
            raise


def main():
    """
    Main execution function with example usage.
    Configuration: ``.env`` / environment (see ``.env.example``).
    """
    try:
        uri, username, password = get_neo4j_credentials()
    except ConfigurationError as e:
        logger.error("%s", e)
        sys.exit(1)

    excel_path = path_v18_matrix_excel()
    clear_db = get_clear_database_default()

    # Create builder instance
    builder = MITREKnowledgeGraphBuilder(
        uri=uri,
        username=username,
        password=password,
    )
    
    try:
        # Build the knowledge graph
        builder.build_knowledge_graph(
            excel_file=str(excel_path),
            clear_existing=clear_db,
        )
        
        # Example queries to verify the graph
        logger.info("\n=== Sample Queries ===")
        
        with builder.driver.session() as session:
            # Query 1: Find all techniques used by a specific tactic
            logger.info("\n1. Techniques for 'Initial Access' tactic:")
            result = session.run("""
                MATCH (tac:Tactic {name: 'Initial Access'})-[:USES]->(tech:Technique)
                RETURN tech.id, tech.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['tech.id']}: {record['tech.name']}")
            
            # Query 2: Find mitigations for a specific technique
            logger.info("\n2. Mitigations for techniques:")
            result = session.run("""
                MATCH (m:Mitigation)-[:MITIGATES]->(tech:Technique)
                RETURN m.name, tech.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['m.name']} mitigates {record['tech.name']}")
            
            # Query 3: Find detection strategies
            logger.info("\n3. Detection strategies for techniques:")
            result = session.run("""
                MATCH (ds:DetectionStrategy)-[:DETECTS]->(tech:Technique)
                RETURN ds.name, tech.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['ds.name']} detects {record['tech.name']}")
            
            # Query 4: Find techniques targeting specific assets
            logger.info("\n4. Techniques targeting assets:")
            result = session.run("""
                MATCH (tech:Technique)-[:TARGETS]->(asset:Asset)
                RETURN tech.name, asset.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['tech.name']} targets {record['asset.name']}")
            
            # Query 5: Find campaign attribution to groups
            logger.info("\n5. Campaign attributions:")
            result = session.run("""
                MATCH (camp:Campaign)-[:ATTRIBUTED_TO]->(grp:Group)
                RETURN camp.name, grp.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['camp.name']} attributed to {record['grp.name']}")
            
            # Query 6: Find software used by groups
            logger.info("\n6. Software used by groups:")
            result = session.run("""
                MATCH (grp:Group)-[:USES]->(soft:Software)
                RETURN grp.name, soft.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['grp.name']} uses {record['soft.name']}")
            
            # Query 7: Find techniques used by campaigns
            logger.info("\n7. Techniques used by campaigns:")
            result = session.run("""
                MATCH (camp:Campaign)-[:USES]->(tech:Technique)
                RETURN camp.name, tech.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['camp.name']} uses {record['tech.name']}")
            
            # Query 8: Complex path - Group to Technique to Mitigation
            logger.info("\n8. Attack paths (Group -> Technique -> Mitigation):")
            result = session.run("""
                MATCH (grp:Group)-[:USES]->(tech:Technique)<-[:MITIGATES]-(mit:Mitigation)
                RETURN grp.name, tech.name, mit.name
                LIMIT 5
            """)
            for record in result:
                logger.info(f"   - {record['grp.name']} uses {record['tech.name']} (mitigated by {record['mit.name']})")
    
    finally:
        # Close connection
        builder.close()


if __name__ == "__main__":
    """
    Usage:
    1. Install required packages:
       pip install pandas openpyxl neo4j
    
    2. Ensure Neo4j is running (default: bolt://localhost:7687)
    
    3. Copy .env.example to .env and set NEO4J_URI, NEO4J_USER (or NEO4J_USERNAME), NEO4J_PASSWORD
       Optional: MITRE_ICS_V18_EXCEL, MITRE_KG_CLEAR_EXISTING (true/false)
    
    4. Run the script:
       python mitre_ics_matrix_v18_to_kg.py
    
    Note: This script uses APOC procedures for statistics.
    If APOC is not installed, comment out the get_statistics() call
    or use alternative Cypher queries.
    """

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     MITRE ATT&CK for ICS Knowledge Graph Builder             ║
    ║                                                              ║
    ║  This script builds a comprehensive knowledge graph from     ║
    ║  MITRE ATT&CK ICS data with all critical relationships.      ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    main()