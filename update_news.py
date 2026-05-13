import os
import re
import json
import feedparser
from datetime import datetime
from dateutil import parser

# Configuration
FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.securityweek.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.rapid7.com/rss.xml"
]

# Regex for CVE IDs, handling various dash types (hyphen, en-dash, em-dash)
CVE_REGEX = r"CVE[-—–]\d{4}[-—–]\d{4,}"

def extract_cves(text):
    """Finds unique CVEs and standardizes them to use standard hyphens."""
    matches = re.findall(CVE_REGEX, text, re.IGNORECASE)
    # Standardize dash variations to "-"
    standardized = {m.replace('—', '-').replace('–', '-').upper() for m in matches}
    return standardized

def process_feeds():
    for url in FEEDS:
        print(f"Fetching: {url}")
        feed = feedparser.parse(url)
        
        for entry in feed.entries:
            title = entry.get('title', '')
            link = entry.get('link', '')
            description = entry.get('description', '')
            
            # Use dateutil to handle various RSS date formats
            try:
                pub_date_raw = entry.get('published') or entry.get('pubDate')
                dt = parser.parse(pub_date_raw)
                date_str = dt.strftime('%Y-%m-%d')
            except (ValueError, TypeError):
                # Fallback to today if date parsing fails
                date_str = datetime.now().strftime('%Y-%m-%d')

            # Search for CVEs in title and description
            content_to_search = f"{title} {description}"
            found_cves = extract_cves(content_to_search)

            if not found_cves:
                continue

            # Ensure directory exists: news/YYYY-MM-DD/
            dir_path = os.path.join("news", date_str)
            os.makedirs(dir_path, exist_ok=True)

            for cve in found_cves:
                file_path = os.path.join(dir_path, f"{cve}.json")
                
                # Load existing data or start new list
                data = []
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        try:
                            data = json.load(f)
                        except json.JSONDecodeError:
                            data = []

                # Check if link already exists in this specific CVE file
                if not any(item.get('link') == link for item in data):
                    data.append({
                        "title": title,
                        "link": link
                    })
                    
                    with open(file_path, 'w') as f:
                        json.dump(data, f, indent=4)
                    print(f"Updated {file_path} with {cve}")

if __name__ == "__main__":
    process_feeds()
