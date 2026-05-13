import os
import re
import json
import requests
import feedparser
from datetime import datetime
from dateutil import parser

# Configuration
FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.securityweek.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://feeds.feedburner.com/tenable/qaXL",
    "https://www.zerodayinitiative.com/rss/published/",
    #"https://www.rapid7.com/rss.xml"
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Regex for CVE IDs, handling various dash types (hyphen, en-dash, em-dash)
CVE_REGEX = r"CVE[-—–]\d{4}[-—–]\d{4,}"

def extract_cves(text):
    """Finds unique CVEs and standardizes them to use standard hyphens."""
    matches = re.findall(CVE_REGEX, text, re.IGNORECASE)
    # Standardize dash variations to "-"
    standardized = {m.replace('—', '-').replace('–', '-').upper() for m in matches}
    return standardized

def extract_cves(text):
    matches = re.findall(CVE_REGEX, text, re.IGNORECASE)
    return {m.replace('—', '-').replace('–', '-').upper() for m in matches}

def save_cve_entry(date_str, cve_id, title, link):
    """Helper to save or update the CVE JSON file with year subdirectories."""
    # Extract the year from the date string (YYYY-MM-DD)
    year = date_str.split('-')[0]
    
    # Update path to include the year: news/YYYY/YYYY-MM-DD/
    dir_path = os.path.join("news", year, date_str)
    os.makedirs(dir_path, exist_ok=True)
    
    file_path = os.path.join(dir_path, f"{cve_id}.json")
    
    data = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

    # Check for uniqueness based on link
    if not any(item.get('link') == link for item in data):
        data.append({
            "title": title,
            "link": link
        })
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Saved: {cve_id} in {date_str}")

def process_rss_feeds():
    for url in FEEDS:
        print(f"Fetching RSS: {url}")
        feed = feedparser.parse(url)
        for entry in feed.entries:
            title = entry.get('title', '')
            link = entry.get('link', '')
            description = entry.get('description', '')
            
            try:
                pub_date_raw = entry.get('published') or entry.get('pubDate')
                dt = parser.parse(pub_date_raw)
                date_str = dt.strftime('%Y-%m-%d')
            except:
                date_str = datetime.now().strftime('%Y-%m-%d')

            found_cves = extract_cves(f"{title} {description}")
            for cve in found_cves:
                save_cve_entry(date_str, cve, title, link)

def process_cisa_kev():
    print(f"Fetching CISA KEV...")
    try:
        response = requests.get(CISA_KEV_URL)
        response.raise_for_status()
        kev_data = response.json()
        
        for vuln in kev_data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID', '').upper()
            date_added = vuln.get('dateAdded', '') # Format is already YYYY-MM-DD
            
            # The 'notes' field often contains multiple URLs separated by semicolons
            # We'll take the first one as the primary link
            notes = vuln.get('notes', '')
            link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"
            
            title = f"New vulnerability added to CISA KEV: {cve_id}"
            
            if cve_id and date_added:
                save_cve_entry(date_added, cve_id, title, link)
    except Exception as e:
        print(f"Error processing CISA KEV: {e}")

if __name__ == "__main__":
    process_rss_feeds()
    process_cisa_kev()
