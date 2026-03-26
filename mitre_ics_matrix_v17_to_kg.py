"""
MITRE ATT&CK for ICS VERSION 17 Knowledge Graph Builder
Converts Excel file with MITRE ATT&CK ICS VERSION 17 data into a Neo4j Knowledge Graph
"""

import pandas as pd
import re
from neo4j import GraphDatabase
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MITREAttackKGBuilder:
    """Build MITRE ATT&CK ICS Knowledge Graph in Neo4j"""
    
    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j connection
        
        Args:
            uri: Neo4j database URI (e.g., 'bolt://localhost:7687')
            username: Neo4j username
            password: Neo4j password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        logger.info("Connected to Neo4j database")
    
    def close(self):
        """Close Neo4j connection"""
        self.driver.close()
        logger.info("Closed Neo4j connection")
    
    def clear_database(self):
        """Clear all nodes and relationships from the database"""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.info("Database cleared")
    
    def create_constraints_and_indexes(self):
        """Create uniqueness constraints and indexes for better performance"""
        constraints = [
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT software_id IF NOT EXISTS FOR (s:Software) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT group_id IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
            "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.id IS UNIQUE",
            "CREATE CONSTRAINT datasource_id IF NOT EXISTS FOR (d:DataSource) REQUIRE d.id IS UNIQUE",
        ]
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.info(f"Created constraint: {constraint.split('FOR')[1].split('REQUIRE')[0].strip()}")
                except Exception as e:
                    logger.warning(f"Constraint may already exist: {e}")
    
    def sanitize_value(self, value: Any) -> Any:
        """Clean and sanitize values for Neo4j"""
        if pd.isna(value) or value == '' or value == 'nan':
            return None
        if isinstance(value, str):
            return value.strip()
        return value
    
    def parse_list_field(self, field: str) -> List[str]:
        """Parse comma or newline separated fields into list"""
        if pd.isna(field) or field == '':
            return []
        # Split by comma or newline
        items = re.split(r'[,\n]+', str(field))
        return [item.strip() for item in items if item.strip()]
    
    def create_techniques(self, df: pd.DataFrame):
        """Create Technique nodes"""
        logger.info(f"Creating {len(df)} Technique nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                    'detection': self.sanitize_value(row['detection']),
                }
                
                # Handle list fields
                if 'tactics' in row:
                    properties['tactics'] = self.parse_list_field(row['tactics'])
                if 'platforms' in row:
                    properties['platforms'] = self.parse_list_field(row['platforms'])
                if 'data sources' in row:
                    properties['data_sources'] = self.parse_list_field(row['data sources'])
                if 'contributors' in row:
                    properties['contributors'] = self.parse_list_field(row['contributors'])
                
                # Remove None values
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (t:Technique $props)",
                    props=properties
                )
        
        logger.info("Technique nodes created successfully")
    
    def create_tactics(self, df: pd.DataFrame):
        """Create Tactic nodes"""
        logger.info(f"Creating {len(df)} Tactic nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                }
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (t:Tactic $props)",
                    props=properties
                )
        
        logger.info("Tactic nodes created successfully")
    
    def create_software(self, df: pd.DataFrame):
        """Create Software nodes"""
        logger.info(f"Creating {len(df)} Software nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                    'type': self.sanitize_value(row['type']),
                }
                
                if 'platforms' in row:
                    properties['platforms'] = self.parse_list_field(row['platforms'])
                if 'aliases' in row:
                    properties['aliases'] = self.parse_list_field(row['aliases'])
                if 'contributors' in row:
                    properties['contributors'] = self.parse_list_field(row['contributors'])
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (s:Software $props)",
                    props=properties
                )
        
        logger.info("Software nodes created successfully")
    
    def create_groups(self, df: pd.DataFrame):
        """Create Group nodes"""
        logger.info(f"Creating {len(df)} Group nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                }
                
                if 'contributors' in row:
                    properties['contributors'] = self.parse_list_field(row['contributors'])
                if 'associated groups' in row:
                    properties['associated_groups'] = self.parse_list_field(row['associated groups'])
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (g:Group $props)",
                    props=properties
                )
        
        logger.info("Group nodes created successfully")
    
    def create_campaigns(self, df: pd.DataFrame):
        """Create Campaign nodes"""
        logger.info(f"Creating {len(df)} Campaign nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                    'first_seen': self.sanitize_value(row['first seen']),
                    'last_seen': self.sanitize_value(row['last seen']),
                }
                
                if 'associated campaigns' in row:
                    properties['associated_campaigns'] = self.parse_list_field(row['associated campaigns'])
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (c:Campaign $props)",
                    props=properties
                )
        
        logger.info("Campaign nodes created successfully")
    
    def create_assets(self, df: pd.DataFrame):
        """Create Asset nodes"""
        logger.info(f"Creating {len(df)} Asset nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                }
                
                if 'platforms' in row:
                    properties['platforms'] = self.parse_list_field(row['platforms'])
                if 'sectors' in row:
                    properties['sectors'] = self.parse_list_field(row['sectors'])
                if 'related assets' in row:
                    properties['related_assets'] = self.parse_list_field(row['related assets'])
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (a:Asset $props)",
                    props=properties
                )
        
        logger.info("Asset nodes created successfully")
    
    def create_mitigations(self, df: pd.DataFrame):
        """Create Mitigation nodes"""
        logger.info(f"Creating {len(df)} Mitigation nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'last_modified': self.sanitize_value(row['last modified']),
                    'domain': self.sanitize_value(row['domain']),
                    'version': self.sanitize_value(row['version']),
                }
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (m:Mitigation $props)",
                    props=properties
                )
        
        logger.info("Mitigation nodes created successfully")
    
    def create_datasources(self, df: pd.DataFrame):
        """Create DataSource nodes"""
        logger.info(f"Creating {len(df)} DataSource nodes...")
        
        with self.driver.session() as session:
            for _, row in df.iterrows():
                properties = {
                    'id': self.sanitize_value(row['ID']),
                    'stix_id': self.sanitize_value(row['STIX ID']),
                    'name': self.sanitize_value(row['name']),
                    'description': self.sanitize_value(row['description']),
                    'url': self.sanitize_value(row['url']),
                    'created': self.sanitize_value(row['created']),
                    'modified': self.sanitize_value(row['modified']),
                    'type': self.sanitize_value(row['type']),
                    'version': self.sanitize_value(row['version']),
                }
                
                if 'collection layers' in row:
                    properties['collection_layers'] = self.parse_list_field(row['collection layers'])
                if 'platforms' in row:
                    properties['platforms'] = self.parse_list_field(row['platforms'])
                if 'contributors' in row:
                    properties['contributors'] = self.parse_list_field(row['contributors'])
                
                properties = {k: v for k, v in properties.items() if v is not None}
                
                session.run(
                    "CREATE (d:DataSource $props)",
                    props=properties
                )
        
        logger.info("DataSource nodes created successfully")
    
    def create_tactic_technique_relationships(self, techniques_df: pd.DataFrame):
        """Create USES relationships from Tactic to Technique"""
        logger.info("Creating Tactic --USES--> Technique relationships...")
        
        count = 0
        with self.driver.session() as session:
            for _, row in techniques_df.iterrows():
                technique_id = self.sanitize_value(row['ID'])
                tactics = self.parse_list_field(row['tactics'])
                
                for tactic_name in tactics:
                    # Match tactic by name and create relationship
                    session.run(
                        """
                        MATCH (tactic:Tactic)
                        WHERE toLower(tactic.name) = toLower($tactic_name)
                        MATCH (tech:Technique {id: $tech_id})
                        MERGE (tactic)-[:USES]->(tech)
                        """,
                        tactic_name=tactic_name,
                        tech_id=technique_id
                    )
                    count += 1
        
        logger.info(f"Created {count} Tactic --USES--> Technique relationships")
    
    def create_matrix_relationships(self, matrix_df: pd.DataFrame):
        """Create relationships from matrix sheet (Tactic -> Technique mapping)"""
        logger.info("Creating relationships from matrix sheet...")
        
        count = 0
        with self.driver.session() as session:
            for col in matrix_df.columns:
                tactic_name = col.strip()
                techniques = matrix_df[col].dropna().tolist()
                
                for technique_id in techniques:
                    technique_id = self.sanitize_value(technique_id)
                    if technique_id:
                        session.run(
                            """
                            MATCH (tactic:Tactic)
                            WHERE toLower(tactic.name) = toLower($tactic_name)
                            MATCH (tech:Technique {id: $tech_id})
                            MERGE (tactic)-[:USES]->(tech)
                            """,
                            tactic_name=tactic_name,
                            tech_id=technique_id
                        )
                        count += 1
        
        logger.info(f"Created {count} relationships from matrix")
    
    def create_datasource_technique_relationships(self, techniques_df: pd.DataFrame):
        """Create DETECTS relationships from DataSource to Technique"""
        logger.info("Creating DataSource --DETECTS--> Technique relationships...")
        
        count = 0
        with self.driver.session() as session:
            for _, row in techniques_df.iterrows():
                technique_id = self.sanitize_value(row['ID'])
                data_sources = self.parse_list_field(row['data sources'])
                
                for ds_name in data_sources:
                    # Match or create datasource and create relationship
                    session.run(
                        """
                        MERGE (ds:DataSource {name: $ds_name})
                        WITH ds
                        MATCH (tech:Technique {id: $tech_id})
                        MERGE (ds)-[:DETECTS]->(tech)
                        """,
                        ds_name=ds_name,
                        tech_id=technique_id
                    )
                    count += 1
        
        logger.info(f"Created {count} DataSource --DETECTS--> Technique relationships")
    
    def create_relationships_from_sheet(self, relationships_df: pd.DataFrame):
        """Create relationships from the relationships sheet"""
        logger.info(f"Processing {len(relationships_df)} relationships from relationships sheet...")
        
        relationship_counts = {}
        
        with self.driver.session() as session:
            for _, row in relationships_df.iterrows():
                source_id = self.sanitize_value(row['source ID'])
                source_type = self.sanitize_value(row['source type'])
                target_id = self.sanitize_value(row['target ID'])
                target_type = self.sanitize_value(row['target type'])
                mapping_type = self.sanitize_value(row['mapping type'])
                description = self.sanitize_value(row['mapping description'])
                
                if not all([source_id, source_type, target_id, target_type, mapping_type]):
                    continue
                
                # Normalize node type names
                source_label = self.normalize_node_type(source_type)
                target_label = self.normalize_node_type(target_type)
                rel_type = self.normalize_relationship_type(mapping_type, source_type, target_type)
                
                # Create relationship with properties
                query = f"""
                MATCH (source:{source_label} {{id: $source_id}})
                MATCH (target:{target_label} {{id: $target_id}})
                MERGE (source)-[r:{rel_type}]->(target)
                SET r.description = $description,
                    r.mapping_type = $mapping_type
                """
                
                try:
                    session.run(
                        query,
                        source_id=source_id,
                        target_id=target_id,
                        description=description,
                        mapping_type=mapping_type
                    )
                    relationship_counts[rel_type] = relationship_counts.get(rel_type, 0) + 1
                except Exception as e:
                    logger.warning(f"Failed to create relationship {rel_type}: {e}")
        
        for rel_type, count in relationship_counts.items():
            logger.info(f"Created {count} {rel_type} relationships")
    
    def normalize_node_type(self, node_type: str) -> str:
        """Normalize node type string to label"""
        type_mapping = {
            'technique': 'Technique',
            'attack-pattern': 'Technique',
            'mitigation': 'Mitigation',
            'course-of-action': 'Mitigation',
            'software': 'Software',
            'malware': 'Software',
            'tool': 'Software',
            'group': 'Group',
            'intrusion-set': 'Group',
            'campaign': 'Campaign',
            'asset': 'Asset',
            'data source': 'DataSource',
            'data-source': 'DataSource',
            'datasource': 'DataSource',
        }
        return type_mapping.get(node_type.lower(), node_type.title())
    
    def normalize_relationship_type(self, mapping_type: str, source_type: str, target_type: str) -> str:
        """Normalize relationship type based on mapping and node types"""
        mapping_lower = mapping_type.lower()
        source_lower = source_type.lower()
        target_lower = target_type.lower()
        
        # Define specific relationship types based on node combinations
        if 'mitigate' in mapping_lower:
            return 'MITIGATED_BY'
        elif 'detect' in mapping_lower:
            return 'DETECTED_BY'
        elif 'use' in mapping_lower:
            if 'software' in source_lower and 'technique' in target_lower:
                return 'APPLIES_TECHNIQUE'
            elif 'group' in source_lower and 'software' in target_lower:
                return 'USES_SOFTWARE'
            elif 'technique' in target_lower:
                return 'USES_TECHNIQUE'
            return 'USES'
        elif 'target' in mapping_lower:
            return 'TARGETED_BY'
        elif 'subtechnique' in mapping_lower or 'sub-technique' in mapping_lower:
            return 'SUBTECHNIQUE_OF'
        elif 'revoke' in mapping_lower:
            return 'REVOKED_BY'
        elif 'deprecate' in mapping_lower:
            return 'DEPRECATED_BY'
        elif 'related' in mapping_lower:
            return 'RELATED_TO'
        else:
            # Default: convert to uppercase and replace spaces/hyphens with underscores
            return mapping_type.upper().replace(' ', '_').replace('-', '_')
    
    def create_additional_relationships(self, techniques_df: pd.DataFrame, assets_df: pd.DataFrame):
        """Create Asset --TARGETED_BY--> Technique relationships based on platforms"""
        logger.info("Creating Asset --TARGETED_BY--> Technique relationships...")
        
        count = 0
        with self.driver.session() as session:
            for _, tech_row in techniques_df.iterrows():
                technique_id = self.sanitize_value(tech_row['ID'])
                tech_platforms = self.parse_list_field(tech_row['platforms'])
                
                for _, asset_row in assets_df.iterrows():
                    asset_id = self.sanitize_value(asset_row['ID'])
                    asset_platforms = self.parse_list_field(asset_row['platforms'])
                    
                    # Check if there's platform overlap
                    if any(tp.lower() in [ap.lower() for ap in asset_platforms] for tp in tech_platforms):
                        session.run(
                            """
                            MATCH (a:Asset {id: $asset_id})
                            MATCH (t:Technique {id: $tech_id})
                            MERGE (a)-[:TARGETED_BY]->(t)
                            """,
                            asset_id=asset_id,
                            tech_id=technique_id
                        )
                        count += 1
        
        logger.info(f"Created {count} Asset --TARGETED_BY--> Technique relationships")
    
    def build_knowledge_graph(self, excel_file: str):
        """Main method to build the complete knowledge graph"""
        logger.info(f"Starting to build Knowledge Graph from {excel_file}")
        start_time = datetime.now()
        
        try:
            # Read all sheets
            logger.info("Reading Excel file...")
            sheets = pd.read_excel(excel_file, sheet_name=None)
            
            # Clear existing data
            self.clear_database()
            
            # Create constraints and indexes
            self.create_constraints_and_indexes()
            
            # Create nodes
            if 'techniques' in sheets:
                self.create_techniques(sheets['techniques'])
            
            if 'tactics' in sheets:
                self.create_tactics(sheets['tactics'])
            
            if 'software' in sheets:
                self.create_software(sheets['software'])
            
            if 'groups' in sheets:
                self.create_groups(sheets['groups'])
            
            if 'campaigns' in sheets:
                self.create_campaigns(sheets['campaigns'])
            
            if 'assets' in sheets:
                self.create_assets(sheets['assets'])
            
            if 'mitigations' in sheets:
                self.create_mitigations(sheets['mitigations'])
            
            if 'datasources' in sheets:
                self.create_datasources(sheets['datasources'])
            
            # Create relationships
            if 'techniques' in sheets and 'tactics' in sheets:
                self.create_tactic_technique_relationships(sheets['techniques'])
            
            if 'matrix' in sheets:
                self.create_matrix_relationships(sheets['matrix'])
            
            if 'techniques' in sheets:
                self.create_datasource_technique_relationships(sheets['techniques'])
            
            if 'relationships' in sheets:
                self.create_relationships_from_sheet(sheets['relationships'])
            
            if 'techniques' in sheets and 'assets' in sheets:
                self.create_additional_relationships(sheets['techniques'], sheets['assets'])
            
            # Generate statistics
            self.print_statistics()
            
            elapsed = datetime.now() - start_time
            logger.info(f"Knowledge Graph built successfully in {elapsed.total_seconds():.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error building knowledge graph: {e}", exc_info=True)
            raise
    
    def print_statistics(self):
        """Print statistics about the created knowledge graph"""
        logger.info("=" * 60)
        logger.info("Knowledge Graph Statistics")
        logger.info("=" * 60)
        
        with self.driver.session() as session:
            # Count nodes
            node_types = ['Technique', 'Tactic', 'Software', 'Group', 'Campaign', 'Asset', 'Mitigation', 'DataSource']
            
            for node_type in node_types:
                result = session.run(f"MATCH (n:{node_type}) RETURN count(n) as count")
                count = result.single()['count']
                logger.info(f"{node_type} nodes: {count}")
            
            logger.info("-" * 60)
            
            # Count relationships
            result = session.run("""
                MATCH ()-[r]->()
                RETURN type(r) as rel_type, count(r) as count
                ORDER BY count DESC
            """)
            
            logger.info("Relationships:")
            for record in result:
                logger.info(f"  {record['rel_type']}: {record['count']}")
            
            # Total relationships
            result = session.run("MATCH ()-[r]->() RETURN count(r) as count")
            total_rels = result.single()['count']
            logger.info(f"\nTotal relationships: {total_rels}")
            
        logger.info("=" * 60)


def main():
    """Main execution function"""
    # Configuration
    NEO4J_URI = "YOUR_URI"
    NEO4J_USERNAME = "YOUR_USERNAME"
    NEO4J_PASSWORD = "YOUR_PASSWORD"
    EXCEL_FILE = "input/ics-attack-v17.1.xlsx"

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     MITRE ATT&CK for ICS Knowledge Graph Builder             ║
    ║                                                              ║
    ║  This script builds a comprehensive knowledge graph from     ║
    ║  MITRE ATT&CK ICS data with all critical relationships.      ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Build the knowledge graph
    builder = MITREAttackKGBuilder(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD)
    
    try:
        builder.build_knowledge_graph(EXCEL_FILE)
    finally:
        builder.close()


if __name__ == "__main__":
    main()