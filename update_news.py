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

def save_cve_entry(date_str, cve_id, title, link):
    """Saves CVE entries into the new dual-structure: news/ and cves/."""
    
    # 1. Handle news/<date>.json structure
    os.makedirs("news", exist_ok=True)
    news_file = os.path.join("news", f"{date_str}.json")
    
    news_data = {}
    if os.path.exists(news_file):
        with open(news_file, 'r') as f:
            try:
                news_data = json.load(f)
            except json.JSONDecodeError:
                news_data = {}

    if cve_id not in news_data:
        news_data[cve_id] = []
    
    # Check for uniqueness in news entry
    if not any(item.get('link') == link for item in news_data[cve_id]):
        news_data[cve_id].append({
            "title": title,
            "link": link
        })
        with open(news_file, 'w') as f:
            json.dump(news_data, f, indent=4)

    # 2. Handle cves/<year>/<CVEID>.json structure
    # Extract year from CVE-ID (e.g., CVE-2025-1234 -> 2025)
    try:
        cve_year = cve_id.split('-')[1]
    except IndexError:
        cve_year = "unknown"

    cve_dir = os.path.join("cves", cve_year)
    os.makedirs(cve_dir, exist_ok=True)
    cve_file = os.path.join(cve_dir, f"{cve_id}.json")

    cve_data = []
    if os.path.exists(cve_file):
        with open(cve_file, 'r') as f:
            try:
                cve_data = json.load(f)
            except json.JSONDecodeError:
                cve_data = []

    # Check for uniqueness in CVE entry
    if not any(item.get('link') == link for item in cve_data):
        cve_data.append({
            "title": title,
            "link": link,
            "date": date_str
        })
        with open(cve_file, 'w') as f:
            json.dump(cve_data, f, indent=4)
        print(f"Updated: {cve_id} (Date: {date_str})")

def migrate_old_data():
    """
    Temporary function to migrate from news/YYYY/YYYY-MM-DD/CVE-ID.json 
    to the new structures.
    """
    print("Starting migration of old data structure...")
    old_news_root = "news"
    if not os.path.exists(old_news_root):
        return

    # Old structure: news/<year>/<date_str>/<cve_id>.json
    for year_dir in os.listdir(old_news_root):
        year_path = os.path.join(old_news_root, year_dir)
        if not os.path.isdir(year_path) or not year_dir.isdigit():
            continue
        
        for date_dir in os.listdir(year_path):
            date_path = os.path.join(year_path, date_dir)
            if not os.path.isdir(date_path):
                continue
            
            # date_dir should be YYYY-MM-DD
            for cve_file in os.listdir(date_path):
                if not cve_file.endswith(".json"):
                    continue
                
                cve_id = cve_file.replace(".json", "")
                full_path = os.path.join(date_path, cve_file)
                
                try:
                    with open(full_path, 'r') as f:
                        entries = json.load(f)
                        for entry in entries:
                            save_cve_entry(
                                date_str=date_dir,
                                cve_id=cve_id,
                                title=entry.get('title'),
                                link=entry.get('link')
                            )
                except Exception as e:
                    print(f"Error migrating {full_path}: {e}")

    print("Migration complete. (Note: Old directories were not deleted automatically).")

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
            
            link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"
            title = f"New vulnerability added to CISA KEV: {cve_id}"
            
            if cve_id and date_added:
                save_cve_entry(date_added, cve_id, title, link)
    except Exception as e:
        print(f"Error processing CISA KEV: {e}")

if __name__ == "__main__":
    # Run migration first (remove this line after the first successful run)
    migrate_old_data()
    
    # Process new data
    process_rss_feeds()
    process_cisa_kev()
