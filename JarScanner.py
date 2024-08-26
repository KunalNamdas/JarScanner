
import zipfile
import os
import subprocess
import requests
import argparse
import time
import sys
import signal
import logging
from setup.sprint import sprint  # Ensure this module is available and correctly implemented
from setup.colors import c, r, ran, lr, lc, lg, g, ly, y  # Ensure this module is available and correctly implemented
from setup.banner import banner, banner2, clear  # Ensure this module is available and correctly implemented
from termcolor import colored

# Configure logging
logging.basicConfig(
    filename='jar_analysis.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Function to handle Ctrl+C
def signal_handler(sig, frame):
    print_message("🚪 Program terminated successfully.", 'green')
    logging.info("Program terminated by user (Ctrl+C).")
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to print messages with colors
def print_message(message, color='cyan'):
    print(colored(message, color))
    logging.info(message)

# Function for loading animation
def loading_animation(message, duration=5):
    animation = ['|', '/', '-', '\\']
    end_time = time.time() + duration
    while time.time() < end_time:
        for symbol in animation:
            sys.stdout.write(f'\r{message} {symbol}')
            sys.stdout.flush()
            time.sleep(0.2)
    sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')
    sys.stdout.flush()

# Function for spinner animation
def spinner_animation(message, duration=5):
    spinner = ['⠋', '⠙', '⠚', '⠹', '⠸', '⠼', '⠴', '⠦']
    end_time = time.time() + duration
    while time.time() < end_time:
        for symbol in spinner:
            sys.stdout.write(f'\r{message} {symbol}')
            sys.stdout.flush()
            time.sleep(0.2)
    sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')
    sys.stdout.flush()

# Function to extract JAR file
def extract_jar(jar_path, extract_to):
    print_message(f"🔍 Extracting JAR file: {jar_path}...", 'yellow')
    try:
        with zipfile.ZipFile(jar_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print_message("✅ Extraction complete.", 'green')
    except Exception as e:
        print_message(f"❌ Error extracting JAR file: {e}", 'red')
        logging.error(f"Error extracting JAR file: {e}")

# Function to get dependencies from MANIFEST.MF
def get_dependencies_from_manifest(manifest_path):
    print_message(f"🔎 Reading dependencies from MANIFEST.MF...", 'yellow')
    dependencies = []
    try:
        with open(manifest_path, 'r') as file:
            for line in file:
                if line.startswith('Class-Path:'):
                    dependencies.extend(line.strip().split()[1:])
    except FileNotFoundError:
        print_message(f"⚠️ Manifest file not found at {manifest_path}", 'red')
        logging.warning(f"Manifest file not found at {manifest_path}")
    except Exception as e:
        print_message(f"❌ Error reading manifest file: {e}", 'red')
        logging.error(f"Error reading manifest file: {e}")
    return dependencies

# Function to fetch CVE data from NVD
def fetch_cve_data(cve_id):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/{}"
    try:
        response = requests.get(base_url.format(cve_id))
        if response.status_code == 200:
            return response.json()
        else:
            print_message(f"❌ Failed to fetch data for CVE ID: {cve_id}", 'red')
            logging.error(f"Failed to fetch data for CVE ID: {cve_id}")
            return None
    except requests.RequestException as e:
        print_message(f"❌ Network error: {e}", 'red')
        logging.error(f"Network error: {e}")
        return None

# Function to check CVEs for a list of identifiers
def check_vulnerabilities(cve_ids):
    found_cves = False
    print_message("🔍 Checking for CVEs...", 'yellow')
    for cve_id in cve_ids:
        cve_data = fetch_cve_data(cve_id)
        if cve_data:
            print_message(f"CVE ID: {cve_id}", 'magenta')
            description = cve_data.get('result', {}).get('CVE_Items', [{}])[0].get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value')
            if description:
                print_message(f"Description: {description}", 'yellow')
            else:
                print_message("No description available.", 'yellow')
            found_cves = True
        print()
    
    if not found_cves:
        print_message("✅ No CVEs found for the detected dependencies.", 'green')

# Function to run SpotBugs and generate an HTML report
def run_spotbugs(directory, output_html):
    print_message("🔍 Running SpotBugs analysis...", 'yellow')
    spinner_animation("Analyzing", duration=10)
    try:
        result = subprocess.run(['spotbugs', '-html', '-output', output_html, directory],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print_message(f"✅ SpotBugs Analysis complete. Report saved to: {output_html}", 'green')
        logging.info(f"SpotBugs Analysis complete. Report saved to: {output_html}")
        logging.info(result.stdout.decode())
        if result.stderr:
            print(g + result.stderr.decode())
            logging.error(result.stderr.decode())
    except subprocess.CalledProcessError as e:
        print_message(f"❌ Error running SpotBugs: {e}", 'red')
        logging.error(f"Error running SpotBugs: {e}")
        logging.error(e.stderr.decode())
    except Exception as e:
        print_message(f"❌ Unexpected error: {e}", 'red')
        logging.error(f"Unexpected error: {e}")

# Function to analyze class files for CVEs (simple example)
def analyze_class_files(directory):
    print_message("🔍 Analyzing class files for CVEs...", 'yellow')
    class_files = [os.path.join(root, file)
                   for root, dirs, files in os.walk(directory)
                   for file in files if file.endswith('.class')]
    
    # Placeholder: For each class file, map to known CVEs
    # Example: Use a mapping or heuristics to find CVEs
    cve_ids = []  # Implement actual mapping logic here
    return cve_ids

def analyze_jar(jar_path, output_dir):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Extract the JAR file
        extract_jar(jar_path, output_dir)
        
        # Determine dependencies from manifest
        manifest_path = os.path.join(output_dir, 'META-INF', 'MANIFEST.MF')
        dependencies = get_dependencies_from_manifest(manifest_path)
        
        # Check vulnerabilities for dependencies
        print_message("🔎 Checking for vulnerabilities in dependencies...", 'yellow')
        cve_ids_from_dependencies = []  # Map dependencies to CVEs
        check_vulnerabilities(cve_ids_from_dependencies)
        
        # Analyze class files for CVEs
        cve_ids_from_class_files = analyze_class_files(output_dir)
        check_vulnerabilities(cve_ids_from_class_files)
        
        # Run static code analysis with SpotBugs
        html_report_path = os.path.join(output_dir, 'spotbugs-results.html')
        run_spotbugs(output_dir, html_report_path)
        
        print_message("🎉 Analysis complete.", 'green')
        logging.info("JAR analysis complete.")
    
    except Exception as e:
        print_message(f"❌ An error occurred during JAR analysis: {e}", 'red')
        logging.error(f"An error occurred during JAR analysis: {e}")

if __name__ == "__main__":
    # Set up command-line argument parsing
    clear()  # Ensure this function is implemented in `setup.banner`
    banner()  # Ensure this function is implemented in `setup.banner`
    parser = argparse.ArgumentParser(description='Analyze a JAR file for vulnerabilities using SpotBugs and NVD.')
    parser.add_argument('jar_file', type=str, help='Path to the JAR file to analyze.')
    parser.add_argument('output_dir', type=str, help='Directory to extract the JAR file and store results.')
    
    args = parser.parse_args()
    
    # Run the analysis with provided arguments
    analyze_jar(args.jar_file, args.output_dir)
