import os
import re
import json
import requests
import feedparser
from datetime import datetime
from dateutil import parser
from io import BytesIO
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
]

# Configuration
FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.securityweek.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://feeds.feedburner.com/tenable/qaXL",
    "https://www.zerodayinitiative.com/rss/published/",
    "https://cybersecuritynews.com/feed/",
    "https://gbhackers.com/feed/",
    "https://www.helpnetsecurity.com/feed/",
    "https://www.webpronews.com/feed/",
    "https://www.techrepublic.com/feed/",
    "https://cyberpress.org/feed/",
    "https://www.itsecuritynews.info/feed/"
]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_REGEX = r"CVE[-—–]\d{4}[-—–]\d{4,}"

def extract_cves(text):
    """Finds unique CVEs and standardizes them."""
    matches = re.findall(CVE_REGEX, text, re.IGNORECASE)
    return {m.replace('—', '-').replace('–', '-').upper() for m in matches}

def save_cve_entry(date_str, cve_id, title, link):
    print(f"Saving {cve_id} for {date_str}")

    # --- Ignore itsecuritynews if title already exists ---
    if "itsecuritynews.info" in link:
        # 1. Immediately drop daily/weekly/monthly summary posts
        summaries = ["it security news daily summary", "it security news weekly summary", "it security news monthly summary"]
        if any(summary in title.lower() for summary in summaries):
            return

        # 2. Drop if the exact title was already logged by another source
        cve_year = cve_id.split('-')[1] if '-' in cve_id else "unknown"
        cve_file = os.path.join("cves", cve_year, f"{cve_id}.json")
        if os.path.exists(cve_file):
            with open(cve_file, 'r') as f:
                try:
                    if any(item.get('title') == title for item in json.load(f)):
                        return 
                except Exception:
                    pass
    
    """
    Saves entries to two structures:
    1. news/<YYYY>/<MM>/<date>.json (Dictionary keyed by CVE)
    2. cves/<year>/<CVEID>.json (List of news sources)
    """
                    
    # --- 1. Structure: news/<YYYY>/<MM>/<date>.json ---
    # date_str format is YYYY-MM-DD
    year_news = date_str[:4]
    month_news = date_str[5:7]
    
    news_dir = os.path.join("news", year_news, month_news)
    os.makedirs(news_dir, exist_ok=True)
    news_file = os.path.join(news_dir, f"{date_str}.json")
    
    news_data = {}
    if os.path.exists(news_file):
        with open(news_file, 'r') as f:
            try:
                news_data = json.load(f)
            except json.JSONDecodeError:
                news_data = {}

    if cve_id not in news_data:
        news_data[cve_id] = []
    
    if not any(item.get('link') == link for item in news_data[cve_id]):
        news_data[cve_id].append({"title": title, "link": link})
        with open(news_file, 'w') as f:
            json.dump(news_data, f, indent=4)

    # --- 2. Structure: cves/<year>/<CVEID>.json ---
    try:
        cve_year = cve_id.split('-')[1]
    except (IndexError, AttributeError):
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

    if not any(item.get('link') == link for item in cve_data):
        cve_data.append({
            "title": title,
            "link": link,
            "date": date_str
        })
        with open(cve_file, 'w') as f:
            json.dump(cve_data, f, indent=4)
        print(f"Logged {cve_id} for {date_str}")

def process_rss_feeds():
    # Set up a robust HTTP session with 3 retries
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    session.mount('http://', HTTPAdapter(max_retries=retries))

    for url in FEEDS:
        print(f"Fetching RSS: {url}")
        
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Pass the raw bytes to feedparser
            feed = feedparser.parse(BytesIO(response.content))
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch {url} after retries: {e}")
            continue # Skip to the next feed URL if this one is completely dead

        for entry in feed.entries:
            title = entry.get('title', '')
            link = entry.get('link', '')
            description = entry.get('description', '')

            content = ""
            if 'content' in entry:
                content = " ".join([c.get('value', '') for c in entry.content])
                
            try:
                pub_date_raw = entry.get('published') or entry.get('pubDate')
                dt = parser.parse(pub_date_raw)
                date_str = dt.strftime('%Y-%m-%d')
            except:
                date_str = datetime.now().strftime('%Y-%m-%d')

            found_cves = extract_cves(f"{title} {description} {content}")
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
            date_added = vuln.get('dateAdded', '')
            link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"
            title = f"CISA KEV Addition: {cve_id}"
            if cve_id and date_added:
                save_cve_entry(date_added, cve_id, title, link)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":  
    process_rss_feeds()
    process_cisa_kev()
