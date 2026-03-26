import pandas as pd
import requests
from bs4 import BeautifulSoup
import time
import re
from typing import List, Tuple

def extract_data_components_from_url(url: str) -> Tuple[List[str], List[str]]:
    """
    Extract data component IDs and names from an analytic URL.
    
    Args:
        url: The URL of the analytic page
        
    Returns:
        Tuple of (list of data component IDs, list of data component names)
    """
    try:
        # Add delay to avoid overwhelming the server
        time.sleep(1)
        
        # Fetch the page
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find the "Log Sources" section
        log_sources_heading = soup.find('h5', string=re.compile(r'Log Sources', re.IGNORECASE))
        
        if not log_sources_heading:
            print(f"Warning: No 'Log Sources' section found for {url}")
            return [], []
        
        # Find the table after the Log Sources heading
        table = log_sources_heading.find_next('table')
        
        if not table:
            print(f"Warning: No table found after 'Log Sources' heading for {url}")
            return [], []
        
        # Extract data component information
        data_component_ids = []
        data_component_names = []
        
        # Find all rows in the table body
        tbody = table.find('tbody')
        if not tbody:
            print(f"Warning: No tbody found in table for {url}")
            return [], []
        
        rows = tbody.find_all('tr')
        
        for row in rows:
            # Find the first cell with data component link
            data_component_cell = row.find('td')
            
            if data_component_cell:
                # Find the anchor tag with the data component
                link = data_component_cell.find('a')
                
                if link:
                    # Extract the full text (e.g., "File Modification (DC0061)")
                    full_text = link.get_text(strip=True)
                    
                    # Use regex to extract name and ID
                    match = re.match(r'(.+?)\s*\(([A-Z0-9]+)\)', full_text)
                    
                    if match:
                        name = match.group(1).strip()
                        dc_id = match.group(2).strip()
                        
                        # Only add if not already in the list (avoid duplicates)
                        if dc_id not in data_component_ids:
                            data_component_ids.append(dc_id)
                            data_component_names.append(name)
        
        return data_component_ids, data_component_names
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return [], []
    except Exception as e:
        print(f"Error parsing {url}: {e}")
        return [], []

def process_analytics_excel(input_file: str, output_file: str):
    """
    Process the analytics Excel file and create a new file with data component information.
    
    Args:
        input_file: Path to the input Excel file containing analytics
        output_file: Path to the output Excel file to create
    """
    print("Reading input Excel file...")
    
    # Read the analytics sheet
    try:
        df = pd.read_excel(input_file, sheet_name='analytics')
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return
    
    print(f"Found {len(df)} analytics to process")
    
    # Prepare lists for the output data
    analytic_ids = []
    datacomponent_ids_list = []
    datacomponent_names_list = []
    
    # Process each analytic
    for idx, row in df.iterrows():
        analytic_id = row['ID']
        url = row['url']
        
        print(f"Processing {idx + 1}/{len(df)}: {analytic_id} - {url}")
        
        # Extract data components from the URL
        dc_ids, dc_names = extract_data_components_from_url(url)
        
        # Store the results
        analytic_ids.append(analytic_id)
        
        # Join multiple IDs and names with semicolons
        datacomponent_ids_list.append('; '.join(dc_ids) if dc_ids else '')
        datacomponent_names_list.append('; '.join(dc_names) if dc_names else '')
        
        print(f"  Found {len(dc_ids)} data components")
    
    # Create the output DataFrame
    output_df = pd.DataFrame({
        'analytic_ID': analytic_ids,
        'datacomponent_IDs': datacomponent_ids_list,
        'datacomponent_names': datacomponent_names_list
    })
    
    # Save to Excel
    print(f"\nSaving results to {output_file}...")
    output_df.to_excel(output_file, index=False, sheet_name='analytics_datacomponents')
    
    print(f"Done! Processed {len(output_df)} analytics")
    print(f"Results saved to: {output_file}")
    
    # Print summary statistics
    with_components = output_df[output_df['datacomponent_IDs'] != ''].shape[0]
    without_components = output_df[output_df['datacomponent_IDs'] == ''].shape[0]
    print(f"\nSummary:")
    print(f"  Analytics with data components: {with_components}")
    print(f"  Analytics without data components: {without_components}")

if __name__ == "__main__":
    # Configuration
    INPUT_FILE = "input/ics-attack-v18.0.xlsx"  
    OUTPUT_FILE = "analytics_with_datacomponents.xlsx"
    
    print("MITRE ATT&CK Analytics Data Component Scraper")
    print("=" * 60)
    
    # Process the file
    process_analytics_excel(INPUT_FILE, OUTPUT_FILE)