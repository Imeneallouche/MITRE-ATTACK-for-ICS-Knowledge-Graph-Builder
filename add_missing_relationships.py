"""
Add Missing Relationships to MITRE ATT&CK ICS Knowledge Graph
Adds relationships between:
1. DetectionStrategy -> Analytic (CONTAINS relationship)
2. Analytic -> DataComponent (USES relationship)
"""

import pandas as pd
from neo4j import GraphDatabase
import logging
from typing import List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MITRERelationshipAdder:
    """Adds missing relationships to existing MITRE ATT&CK ICS Knowledge Graph"""
    
    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j connection
        
        Args:
            uri: Neo4j database URI (e.g., 'bolt://localhost:7687')
            username: Neo4j username
            password: Neo4j password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        logger.info(f"Connected to Neo4j at {uri}")
    
    def close(self):
        """Close Neo4j connection"""
        self.driver.close()
        logger.info("Neo4j connection closed")
    
    @staticmethod
    def clean_value(value) -> Optional[str]:
        """Clean and normalize values"""
        if pd.isna(value) or value == '' or value == 'nan':
            return None
        return str(value).strip()
    
    @staticmethod
    def parse_semicolon_list(value) -> List[str]:
        """Parse semicolon-separated values into list"""
        if pd.isna(value) or value == '':
            return []
        
        value_str = str(value)
        items = [item.strip() for item in value_str.split(';') if item.strip()]
        return items
    
    def verify_nodes_exist(self):
        """Verify that required node types exist in the database"""
        logger.info("\n=== Verifying Required Nodes ===")
        
        with self.driver.session() as session:
            node_types = ['Analytic', 'DetectionStrategy', 'DataComponent']
            
            for node_type in node_types:
                result = session.run(f"MATCH (n:{node_type}) RETURN count(n) as count")
                count = result.single()['count']
                
                if count > 0:
                    logger.info(f"✓ Found {count} {node_type} nodes")
                else:
                    logger.warning(f"⚠ Warning: No {node_type} nodes found!")
    
    def add_detection_strategy_analytic_relationships(self, df: pd.DataFrame):
        """
        Create relationships between DetectionStrategy and Analytic nodes
        Relationship: DetectionStrategy -[CONTAINS]-> Analytic
        
        This represents that a detection strategy contains/includes specific analytics
        
        Args:
            df: DataFrame with columns: analytic_ID, detectionstrategy_ID
        """
        logger.info(f"\n=== Adding DetectionStrategy -> Analytic Relationships ===")
        logger.info(f"Processing {len(df)} analytic-detection strategy mappings...")
        
        with self.driver.session() as session:
            successful = 0
            failed = 0
            missing_detection_strategies = set()
            missing_analytics = set()
            
            for idx, row in df.iterrows():
                analytic_id = self.clean_value(row.get('analytic_ID'))
                detection_strategy_id = self.clean_value(row.get('detectionstrategy_ID'))
                
                if not analytic_id or not detection_strategy_id:
                    logger.warning(f"  [{idx + 1}] Skipping row with missing IDs")
                    failed += 1
                    continue
                
                try:
                    # Create CONTAINS relationship from DetectionStrategy to Analytic
                    result = session.run("""
                        MATCH (ds:DetectionStrategy {id: $detection_strategy_id})
                        MATCH (a:Analytic {id: $analytic_id})
                        MERGE (ds)-[r:CONTAINS]->(a)
                        RETURN ds, a, r
                    """, detection_strategy_id=detection_strategy_id, analytic_id=analytic_id)
                    
                    record = result.single()
                    
                    if record:
                        successful += 1
                        if successful <= 5:  # Show first 5 for verification
                            logger.info(f"  ✓ [{idx + 1}] {detection_strategy_id} -[CONTAINS]-> {analytic_id}")
                    else:
                        # Check which node is missing
                        ds_exists = session.run(
                            "MATCH (ds:DetectionStrategy {id: $id}) RETURN count(ds) as count",
                            id=detection_strategy_id
                        ).single()['count']
                        
                        a_exists = session.run(
                            "MATCH (a:Analytic {id: $id}) RETURN count(a) as count",
                            id=analytic_id
                        ).single()['count']
                        
                        if not ds_exists:
                            missing_detection_strategies.add(detection_strategy_id)
                        if not a_exists:
                            missing_analytics.add(analytic_id)
                        
                        failed += 1
                
                except Exception as e:
                    logger.error(f"  ✗ [{idx + 1}] Error creating relationship {detection_strategy_id} -> {analytic_id}: {e}")
                    failed += 1
            
            logger.info(f"\n--- DetectionStrategy -> Analytic Summary ---")
            logger.info(f"✓ Successfully created: {successful} relationships")
            logger.info(f"✗ Failed: {failed} relationships")
            
            if missing_detection_strategies:
                logger.warning(f"\n⚠ Missing DetectionStrategy nodes: {sorted(missing_detection_strategies)}")
            if missing_analytics:
                logger.warning(f"⚠ Missing Analytic nodes: {sorted(missing_analytics)}")
    
    def add_analytic_datacomponent_relationships(self, df: pd.DataFrame):
        """
        Create relationships between Analytic and DataComponent nodes
        Relationship: Analytic -[USES]-> DataComponent
        
        This represents that an analytic uses specific data components for detection
        
        Args:
            df: DataFrame with columns: analytic_ID, datacomponent_IDs (semicolon-separated)
        """
        logger.info(f"\n=== Adding Analytic -> DataComponent Relationships ===")
        logger.info(f"Processing {len(df)} analytics with data components...")
        
        with self.driver.session() as session:
            total_relationships = 0
            successful = 0
            failed = 0
            missing_analytics = set()
            missing_datacomponents = set()
            
            for idx, row in df.iterrows():
                analytic_id = self.clean_value(row.get('analytic_ID'))
                datacomponent_ids_str = self.clean_value(row.get('datacomponent_IDs'))
                
                if not analytic_id:
                    logger.warning(f"  [{idx + 1}] Skipping row with missing analytic_ID")
                    failed += 1
                    continue
                
                if not datacomponent_ids_str:
                    logger.warning(f"  [{idx + 1}] Analytic {analytic_id} has no data components")
                    continue
                
                # Parse semicolon-separated data component IDs
                datacomponent_ids = self.parse_semicolon_list(datacomponent_ids_str)
                
                if not datacomponent_ids:
                    continue
                
                # Create relationships for each data component
                analytic_relationships = 0
                for dc_id in datacomponent_ids:
                    try:
                        # Create USES relationship from Analytic to DataComponent
                        result = session.run("""
                            MATCH (a:Analytic {id: $analytic_id})
                            MATCH (dc:DataComponent {id: $datacomponent_id})
                            MERGE (a)-[r:USES]->(dc)
                            RETURN a, dc, r
                        """, analytic_id=analytic_id, datacomponent_id=dc_id)
                        
                        record = result.single()
                        
                        if record:
                            analytic_relationships += 1
                            total_relationships += 1
                            
                            if total_relationships <= 5:  # Show first 5 for verification
                                logger.info(f"  ✓ {analytic_id} -[USES]-> {dc_id}")
                        else:
                            # Check which node is missing
                            a_exists = session.run(
                                "MATCH (a:Analytic {id: $id}) RETURN count(a) as count",
                                id=analytic_id
                            ).single()['count']
                            
                            dc_exists = session.run(
                                "MATCH (dc:DataComponent {id: $id}) RETURN count(dc) as count",
                                id=dc_id
                            ).single()['count']
                            
                            if not a_exists:
                                missing_analytics.add(analytic_id)
                            if not dc_exists:
                                missing_datacomponents.add(dc_id)
                            
                            failed += 1
                    
                    except Exception as e:
                        logger.error(f"  ✗ Error creating relationship {analytic_id} -> {dc_id}: {e}")
                        failed += 1
                
                if analytic_relationships > 0:
                    successful += 1
                    if successful <= 5:  # Show details for first 5
                        logger.info(f"  ✓ [{idx + 1}] {analytic_id}: created {analytic_relationships} data component relationships")
            
            logger.info(f"\n--- Analytic -> DataComponent Summary ---")
            logger.info(f"✓ Analytics with relationships: {successful}")
            logger.info(f"✓ Total relationships created: {total_relationships}")
            logger.info(f"✗ Failed relationships: {failed}")
            
            if missing_analytics:
                logger.warning(f"\n⚠ Missing Analytic nodes: {sorted(missing_analytics)}")
            if missing_datacomponents:
                logger.warning(f"⚠ Missing DataComponent nodes: {sorted(missing_datacomponents)}")
    
    def verify_relationships(self):
        """Verify that relationships were created successfully"""
        logger.info("\n=== Verifying Created Relationships ===")
        
        with self.driver.session() as session:
            # Check DetectionStrategy -[CONTAINS]-> Analytic
            result = session.run("""
                MATCH (ds:DetectionStrategy)-[r:CONTAINS]->(a:Analytic)
                RETURN count(r) as count
            """)
            contains_count = result.single()['count']
            logger.info(f"✓ DetectionStrategy -[CONTAINS]-> Analytic: {contains_count} relationships")
            
            # Check Analytic -[USES]-> DataComponent
            result = session.run("""
                MATCH (a:Analytic)-[r:USES]->(dc:DataComponent)
                RETURN count(r) as count
            """)
            uses_count = result.single()['count']
            logger.info(f"✓ Analytic -[USES]-> DataComponent: {uses_count} relationships")
            
            # Show sample of DetectionStrategy -> Analytic -> DataComponent paths
            logger.info("\n=== Sample Detection Paths ===")
            result = session.run("""
                MATCH (ds:DetectionStrategy)-[:CONTAINS]->(a:Analytic)-[:USES]->(dc:DataComponent)
                RETURN ds.id as detection_strategy, 
                       a.id as analytic, 
                       collect(dc.id) as data_components
                LIMIT 5
            """)
            
            for record in result:
                dc_list = ', '.join(record['data_components'])
                logger.info(f"  {record['detection_strategy']} -> {record['analytic']} -> [{dc_list}]")
    
    def get_relationship_statistics(self):
        """Display comprehensive relationship statistics"""
        logger.info("\n" + "="*70)
        logger.info("=== Final Relationship Statistics ===")
        logger.info("="*70)
        
        with self.driver.session() as session:
            # Get all relationship types and counts
            result = session.run("""
                CALL db.relationshipTypes() YIELD relationshipType
                RETURN relationshipType
            """)
            rel_types = [record['relationshipType'] for record in result]
            
            for rel_type in sorted(rel_types):
                result = session.run(f"""
                    MATCH ()-[r:{rel_type}]->()
                    RETURN count(r) as count
                """)
                count = result.single()['count']
                logger.info(f"{rel_type}: {count}")
            
            # Show total
            result = session.run("MATCH ()-[r]->() RETURN count(r) as total")
            total = result.single()['total']
            logger.info(f"\nTotal Relationships: {total}")
    
    def process_complementary_file(self, excel_file: str):
        """
        Main method to process the complementary Excel file and add relationships
        
        Args:
            excel_file: Path to the complementary Excel file with relationship data
        """
        logger.info("="*70)
        logger.info("MITRE ATT&CK ICS - Adding Missing Relationships")
        logger.info("="*70)
        logger.info(f"\nReading file: {excel_file}")
        
        try:
            # Read both sheets
            sheets = pd.read_excel(excel_file, sheet_name=None)
            
            # Verify required sheets exist
            required_sheets = ['analytic_datacomponents', 'analytic_detectionstrategy']
            missing_sheets = [sheet for sheet in required_sheets if sheet not in sheets]
            
            if missing_sheets:
                logger.error(f"✗ Missing required sheets: {missing_sheets}")
                logger.error(f"Available sheets: {list(sheets.keys())}")
                return
            
            logger.info(f"✓ Found all required sheets")
            logger.info(f"  - analytic_datacomponents: {len(sheets['analytic_datacomponents'])} rows")
            logger.info(f"  - analytic_detectionstrategy: {len(sheets['analytic_detectionstrategy'])} rows")
            
            # Verify existing nodes
            self.verify_nodes_exist()
            
            # Add DetectionStrategy -> Analytic relationships
            self.add_detection_strategy_analytic_relationships(
                sheets['analytic_detectionstrategy']
            )
            
            # Add Analytic -> DataComponent relationships
            self.add_analytic_datacomponent_relationships(
                sheets['analytic_datacomponents']
            )
            
            # Verify relationships were created
            self.verify_relationships()
            
            # Display final statistics
            self.get_relationship_statistics()
            
            logger.info("\n" + "="*70)
            logger.info("✓ All relationships added successfully!")
            logger.info("="*70)
            
        except FileNotFoundError:
            logger.error(f"✗ Error: File '{excel_file}' not found!")
        except Exception as e:
            logger.error(f"✗ Error processing file: {e}")
            raise


def main():
    """Main execution function"""
    
    # Configuration - UPDATE THESE VALUES
    NEO4J_URI = "YOUR_NEO4J_URI"
    NEO4J_USERNAME = "YOUR_NEO4J_USERNAME"
    NEO4J_PASSWORD = "YOUR_NEO4J_PASSWORD"
    EXCEL_FILE = "input/ics-attack-v18.0-complementary.xlsx"
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║  MITRE ATT&CK ICS - Add Missing Relationships                ║
    ║                                                              ║
    ║  Adding:                                                     ║
    ║  1. DetectionStrategy -[CONTAINS]-> Analytic                 ║
    ║  2. Analytic -[USES]-> DataComponent                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create relationship adder instance
    adder = MITRERelationshipAdder(
        uri=NEO4J_URI,
        username=NEO4J_USERNAME,
        password=NEO4J_PASSWORD
    )
    
    try:
        # Process the complementary file and add relationships
        adder.process_complementary_file(EXCEL_FILE)
        
        # Show some example queries to explore the new relationships
        logger.info("\n=== Example Queries to Explore New Relationships ===")
        logger.info("""
1. Find all analytics for a detection strategy:
   MATCH (ds:DetectionStrategy {id: 'DET0722'})-[:CONTAINS]->(a:Analytic)
   RETURN a.id, a.name

2. Find all data components used by an analytic:
   MATCH (a:Analytic {id: 'AN1855'})-[:USES]->(dc:DataComponent)
   RETURN dc.id, dc.name

3. Find complete detection path (Strategy -> Analytic -> Data Components):
   MATCH (ds:DetectionStrategy)-[:CONTAINS]->(a:Analytic)-[:USES]->(dc:DataComponent)
   RETURN ds.name, a.name, collect(dc.name) as data_components
   LIMIT 10

4. Find detection strategies and their techniques through analytics:
   MATCH (ds:DetectionStrategy)-[:DETECTS]->(t:Technique)
   MATCH (ds)-[:CONTAINS]->(a:Analytic)
   RETURN ds.name, t.name, collect(a.name) as analytics

5. Find analytics that use specific data components:
   MATCH (a:Analytic)-[:USES]->(dc:DataComponent {id: 'DC0061'})
   RETURN a.id, a.name
        """)
    
    finally:
        # Close connection
        adder.close()


if __name__ == "__main__":
    """
    Usage:
    1. Install required packages:
       pip install pandas openpyxl neo4j
    
    2. Ensure your Neo4j database is running with existing nodes
    
    3. Update configuration in main() function:
       - NEO4J_URI: Your Neo4j connection URI
       - NEO4J_USERNAME: Your Neo4j username
       - NEO4J_PASSWORD: Your Neo4j password
       - EXCEL_FILE: Path to your complementary Excel file
    
    4. Run the script:
       python add_missing_relationships.py
    
    Expected Input File Structure:
    - Sheet 1: analytic_datacomponents
      Columns: analytic_ID, datacomponent_IDs (semicolon-separated)
    
    - Sheet 2: analytic_detectionstrategy
      Columns: analytic_ID, detectionstrategy_ID
    
    Relationships Created:
    - DetectionStrategy -[CONTAINS]-> Analytic
    - Analytic -[USES]-> DataComponent
    """
    main()