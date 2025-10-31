import re
from collections import Counter
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup


class CrawlerStats:
    def __init__(self):
        self.unique_pages = set()
        self.longest_page_url = None
        self.longest_page_word_count = 0
        self.word_frequencies = Counter()
        self.subdomain_to_count = {}

        # Basic English stop words (no external deps)
        self.stop_words = set(
            [
                'a','about','above','after','again','against','all','am','an','and','any','are','as','at','be','because',
                'been','before','being','below','between','both','but','by','could','did','do','does','doing','down',
                'during','each','few','for','from','further','had','has','have','having','he','her','here','hers',
                'herself','him','himself','his','how','i','if','in','into','is','it','its','itself','just','me','more',
                'most','my','myself','no','nor','not','now','of','off','on','once','only','or','other','our','ours',
                'ourselves','out','over','own','same','she','should','so','some','such','than','that','the','their',
                'theirs','them','themselves','then','there','these','they','this','those','through','to','too','under',
                'until','up','very','was','we','were','what','when','where','which','while','who','whom','why','with',
                'you','your','yours','yourself','yourselves'
            ]
        )

    def _extract_visible_text(self, soup):
        for tag in soup(['script', 'style', 'noscript']):
            tag.decompose()
        text = soup.get_text(separator=' ')
        return text

    def _tokenize(self, text):
        tokens = re.findall(r"[A-Za-z]{2,}", text.lower())
        return [t for t in tokens if t not in self.stop_words]

    def update_from_page(self, page_url, html_bytes, outgoing_links):
        try:
            # Track unique page by defragmented URL
            page_url, _ = urldefrag(page_url)
            if page_url not in self.unique_pages:
                self.unique_pages.add(page_url)

                # Subdomain counting for uci.edu
                parsed = urlparse(page_url)
                host = parsed.hostname or ''
                if host.endswith('.uci.edu') or host == 'uci.edu':
                    # Subdomain is the full host (e.g., vision.ics.uci.edu)
                    self.subdomain_to_count[host] = self.subdomain_to_count.get(host, 0) + 1

            # Compute word counts and update longest page and frequency stats
            soup = BeautifulSoup(html_bytes, 'lxml')
            visible_text = self._extract_visible_text(soup)
            words = self._tokenize(visible_text)
            word_count = len(words)

            if word_count > self.longest_page_word_count:
                self.longest_page_word_count = word_count
                self.longest_page_url = page_url

            if words:
                self.word_frequencies.update(words)
        except Exception:
            pass


# Global stats instance
STATS = CrawlerStats()

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    try:
        if resp is None or resp.status != 200:
            return []
        raw = getattr(resp, 'raw_response', None)
        if raw is None:
            return []
        content_type = ''
        if hasattr(raw, 'headers') and raw.headers is not None:
            content_type = raw.headers.get('Content-Type', '')
        if 'text/html' not in content_type.lower():
            return []
        html_bytes = getattr(raw, 'content', b'') or b''
        if not html_bytes:
            return []
        if len(html_bytes) > 10 * 1024 * 1024:
            # Defensive: skip extremely large pages
            return []

        soup = BeautifulSoup(html_bytes, 'lxml')

        links = set()
        base_url = getattr(raw, 'url', None) or url
        for tag in soup.find_all(['a', 'area']):
            href = tag.get('href')
            if not href:
                continue
            try:
                abs_url = urljoin(base_url, href)
                abs_url, _ = urldefrag(abs_url)
                if abs_url:
                    links.add(abs_url)
            except Exception:
                continue

        # Update crawl statistics based on this page
        try:
            STATS.update_from_page(base_url, html_bytes, links)
        except Exception:
            pass

        return list(links)
    except Exception:
        return []

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        hostname = parsed.hostname or ""
        allowed = (
            hostname == "ics.uci.edu" or hostname.endswith(".ics.uci.edu") or
            hostname == "cs.uci.edu" or hostname.endswith(".cs.uci.edu") or
            hostname == "informatics.uci.edu" or hostname.endswith(".informatics.uci.edu") or
            hostname == "stat.uci.edu" or hostname.endswith(".stat.uci.edu")
        )
        if not allowed:
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
