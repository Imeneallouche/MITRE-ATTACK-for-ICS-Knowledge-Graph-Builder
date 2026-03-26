import pandas as pd
import re
from typing import Optional

def extract_detection_strategy_id(url: str) -> Optional[str]:
    """
    Extract the detection strategy ID from an analytic URL.
    
    Example:
        Input: "https://attack.mitre.org/detectionstrategies/DET0722#AN1855"
        Output: "DET0722"
    
    Args:
        url: The URL of the analytic page
        
    Returns:
        The detection strategy ID (e.g., "DET0722") or None if not found
    """
    try:
        # Pattern to match detection strategy ID (DETXXXX format)
        # The ID appears after /detectionstrategies/ and before # or end of path
        pattern = r'/detectionstrategies/(DET\d+)'
        
        match = re.search(pattern, url)
        
        if match:
            return match.group(1)
        else:
            print(f"Warning: Could not extract detection strategy ID from URL: {url}")
            return None
            
    except Exception as e:
        print(f"Error parsing URL {url}: {e}")
        return None

def create_analytic_detection_strategy_mapping(input_file: str, output_file: str, sheet_name: str = 'analytics'):
    """
    Create an Excel file mapping analytics to their detection strategies.
    
    Args:
        input_file: Path to the input Excel file (e.g., "ics-attack-v18.0.xlsx")
        output_file: Path to the output Excel file to create
        sheet_name: Name of the sheet containing analytics data (default: 'analytics')
    """
    print("=" * 70)
    print("Analytics to Detection Strategy Mapper")
    print("=" * 70)
    print(f"\nReading input file: {input_file}")
    print(f"Sheet name: {sheet_name}")
    
    try:
        # Read the analytics sheet
        df = pd.read_excel(input_file, sheet_name=sheet_name)
        print(f"✓ Successfully loaded {len(df)} analytics")
        
    except FileNotFoundError:
        print(f"✗ Error: File '{input_file}' not found!")
        print("Please make sure the file exists in the current directory.")
        return
    except ValueError as e:
        print(f"✗ Error: Sheet '{sheet_name}' not found in the Excel file!")
        print(f"Error details: {e}")
        return
    except Exception as e:
        print(f"✗ Error reading Excel file: {e}")
        return
    
    # Check if required columns exist
    required_columns = ['ID', 'url']
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        print(f"✗ Error: Missing required columns: {missing_columns}")
        print(f"Available columns: {list(df.columns)}")
        return
    
    print("\nProcessing analytics...")
    print("-" * 70)
    
    # Prepare lists for output
    analytic_ids = []
    detection_strategy_ids = []
    
    # Process each row
    successful_count = 0
    failed_count = 0
    
    for idx, row in df.iterrows():
        analytic_id = row['ID']
        url = row['url']
        
        # Extract detection strategy ID from URL
        det_strategy_id = extract_detection_strategy_id(url)
        
        # Store results
        analytic_ids.append(analytic_id)
        detection_strategy_ids.append(det_strategy_id if det_strategy_id else '')
        
        # Track success/failure
        if det_strategy_id:
            successful_count += 1
            print(f"  [{idx + 1:3d}/{len(df)}] {analytic_id:8s} → {det_strategy_id}")
        else:
            failed_count += 1
            print(f"  [{idx + 1:3d}/{len(df)}] {analytic_id:8s} → [NOT FOUND]")
    
    # Create output DataFrame
    output_df = pd.DataFrame({
        'analytic_ID': analytic_ids,
        'detectionstrategy_ID': detection_strategy_ids
    })
    
    # Save to Excel
    print("\n" + "-" * 70)
    print(f"Saving results to: {output_file}")
    
    try:
        output_df.to_excel(output_file, index=False, sheet_name='analytic_detection_strategy')
        print(f"✓ Successfully created output file!")
        
    except Exception as e:
        print(f"✗ Error saving Excel file: {e}")
        return
    
    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total analytics processed:           {len(output_df)}")
    print(f"Successfully mapped:                 {successful_count}")
    print(f"Failed to extract detection strategy: {failed_count}")
    print(f"\nOutput file: {output_file}")
    print("=" * 70)
    
    # Show sample of results
    if len(output_df) > 0:
        print("\nSample of results (first 5 rows):")
        print("-" * 70)
        print(output_df.head().to_string(index=False))
    
    # Show any failed mappings
    if failed_count > 0:
        print("\n⚠ Warning: Some analytics could not be mapped to detection strategies")
        failed_analytics = output_df[output_df['detectionstrategy_ID'] == '']
        print(f"Analytics without detection strategy mapping: {list(failed_analytics['analytic_ID'])}")

def main():
    """Main execution function."""
    
    # Configuration
    INPUT_FILE = "input/ics-attack-v18.0.xlsx"  
    OUTPUT_FILE = "analytic_detectionstrategy_mapping.xlsx"
    SHEET_NAME = "analytics" 
    
    # Run the mapping process
    create_analytic_detection_strategy_mapping(INPUT_FILE, OUTPUT_FILE, SHEET_NAME)
    
    print("\n✓ Process completed!")

if __name__ == "__main__":
    main()