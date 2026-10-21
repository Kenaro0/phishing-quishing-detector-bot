#  phishing_detector.py  --  Text & URL phishing analysis engine
#  FC382 Defense Mechanisms -- Spring 2026

#    extract_urls(text)               -> list   Pull every URL out of a message
#    normalize_url(url)               -> str    Add http:// so the URL can be parsed
#    get_domain(url)                  -> str    Get the bare domain (e.g. "bit.ly")
#    contains_keyword(text)           -> bool   Scan for known phishing phrases
#    looks_like_fake_brand_domain(d)  -> bool   Detect brand-impersonation domains
#    analyze_url(url)                 -> dict   Score ONE url            [CORE]
#    analyze_text(text)               -> dict   Final verdict for a message [CORE]


import re
from urllib.parse import urlparse


class PhishingDetector:
    """Rule-based phishing detector for chat messages and decoded QR text."""

    
    # DETECTION DATA
    # These lists are the "knowledge" the detector compares messages against.
    # They are kept here at the top so they are easy to find and extend.
    

    # Social-engineering phrases that show up again and again in phishing bait.
    # Source: OWASP Phishing Guidelines + APWG keyword analysis.
    SUSPICIOUS_KEYWORDS = [
        "free nitro",
        "claim reward",
        "verify your account",
        "your account will be disabled",
        "urgent action required",
        "limited time offer",
        "click here now",
        "login now",
        "confirm password",
        "gift card",
        "free steam",
        "free robux",
        "free giveaway",
        "scan this qr",
        "scan the code",
    ]

    # Well-known brands that attackers love to imitate inside fake domains
    # (e.g. "discord-nitro-free.xyz" pretends to be Discord).
    SUSPICIOUS_BRAND_WORDS = [
        "discord",
        "steam",
        "paypal",
        "microsoft",
        "google",
        "epic games",
        "riot",
    ]

    # Link-shortening services. They are flagged because a short link hides
    # the real destination from the user until it is too late.
    # Source: APWG Q1 2025 Phishing Trends Report.
    SHORTENER_DOMAINS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "cutt.ly",
        "is.gd",
        "shorturl.at",
        "rebrand.ly",
    }

    # Real, official domains. A domain on this list is NEVER penalised for
    # containing a brand word, which prevents false alarms on legit links.
    TRUSTED_DOMAINS = {
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "google.com",
        "github.com",
        "microsoft.com",
        "youtube.com",
    }

   
    # REGULAR EXPRESSIONS (patterns used to find things inside text)
    

    # Matches any link that starts with http://, https://, or www.
    URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

    # Matches a URL whose host is a raw IP address such as http://185.23.10.4/login
    IP_URL_REGEX = re.compile(
        r"^(https?://)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(/[^\s]*)?$",
        re.IGNORECASE,
    )

    
    # URL HELPERS  (small functions that prepare a URL for analysis)
   

    def extract_urls(self, text: str) -> list[str]:
        """Return a list of every URL found inside the given text."""
        if not text or not isinstance(text, str):
            return []
        return self.URL_REGEX.findall(text)

    def normalize_url(self, url: str) -> str:
        """
        Make sure the URL has a scheme (http:// or https://).
        urlparse cannot read the domain correctly without one, so we add a
        default http:// to links written as plain "example.com".
        """
        if not url:
            return ""
        if not url.startswith(("http://", "https://")):
            return f"http://{url}"
        return url

    def get_domain(self, url: str) -> str:
        """
        Extract just the domain from a full URL.
        Example: "https://www.Bit.LY/abc" -> "bit.ly"
        The leading "www." is stripped so comparisons stay consistent.
        """
        normalized = self.normalize_url(url)
        parsed = urlparse(normalized)
        domain = parsed.netloc.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain

    
    # INDICATOR CHECKS  (each one looks for a single warning sign)
    

    def contains_keyword(self, text: str) -> tuple[bool, list[str]]:
        """
        Look for any known phishing phrase inside the text.
        Returns (True/False, list of the phrases that matched).
        """
        found = []
        lowered = text.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                found.append(keyword)
        return len(found) > 0, found

    def looks_like_fake_brand_domain(self, domain: str) -> bool:
        """
        Detect domains that borrow a famous brand name but are NOT official,
        which is a classic impersonation trick (e.g. "discordnitro-gift.xyz").

        How it works: we remove dots and dashes to defeat tricks like
        "disc-ord", then check if a brand word is hiding inside. If a brand
        word is present and the domain is not on the trusted list -> suspicious.
        """
        if not domain:
            return False

        compact_domain = domain.replace("-", "").replace(".", "")

        for brand in self.SUSPICIOUS_BRAND_WORDS:
            brand_word = brand.replace(" ", "")
            if brand_word in compact_domain and domain not in self.TRUSTED_DOMAINS:
                return True

        return False

    
    # CORE SCORING
    

    def analyze_url(self, url: str) -> dict:
        """
        Score a SINGLE URL by adding up points for each warning sign it shows.
        Higher points = more suspicious. The point weights below reflect how
        strong each signal is in published phishing research.

        Returns a dict: url, domain, is_suspicious, risk_score, reasons.
        """
        reasons = []
        risk_score = 0

        # Guard against bad input (empty value or wrong type).
        if not url or not isinstance(url, str):
            return {
                "url": url,
                "domain": "",
                "is_suspicious": False,
                "risk_score": 0,
                "reasons": ["Invalid URL input"],
            }

        domain = self.get_domain(url)

        # A URL we cannot even parse is itself a small red flag.
        if not domain:
            return {
                "url": url,
                "domain": "",
                "is_suspicious": True,
                "risk_score": 2,
                "reasons": ["Could not parse domain"],
            }

        # +2  Shortened links hide their final destination from the user.
        #     Source: APWG Q1 2025 (shorteners seen in >35% of phishing URLs).
        if domain in self.SHORTENER_DOMAINS:
            risk_score += 2
            reasons.append("Shortened URL detected")

        # +2  A link pointing straight to an IP address (no real domain name)
        #     is a strong phishing sign. Maps to MITRE ATT&CK T1566 (Phishing).
        if self.IP_URL_REGEX.match(url):
            risk_score += 2
            reasons.append("Direct IP-based URL detected")

        # +2  The "@" trick: a browser ignores everything before "@", so
        #     http://discord.com@evil.site actually sends you to evil.site.
        if "@" in url:
            risk_score += 2
            reasons.append("@ symbol found in URL")

        # +3  Brand impersonation is the single strongest indicator, so it
        #     carries the most weight (e.g. a fake "discord" domain).
        if self.looks_like_fake_brand_domain(domain):
            risk_score += 3
            reasons.append("Possible brand impersonation domain")

        # +1  Many dashes (e.g. "free-discord-nitro-gift") is a weak hint
        #     on its own, so it only adds a single point.
        if domain.count("-") >= 2:
            risk_score += 1
            reasons.append("Too many hyphens in domain")

        # +1  Cheap / throwaway top-level domains are common for short-lived
        #     phishing sites. Source: APWG Q4 2024.
        if domain.endswith((".zip", ".click", ".shop", ".xyz")):
            risk_score += 1
            reasons.append("High-risk domain suffix")

        # A single URL is treated as suspicious once it reaches 2 points.
        return {
            "url": url,
            "domain": domain,
            "is_suspicious": risk_score >= 2,
            "risk_score": risk_score,
            "reasons": reasons,
        }

    def analyze_text(self, text: str) -> dict:
        """
        MAIN ENTRY POINT for the detector.

        It blends three independent checks into one final decision:
            1) keyword scan       -- suspicious wording in the message
            2) URL scan           -- every link is scored by analyze_url()
            3) urgency + link     -- pressure language next to a clickable link

        All the points are summed. A message is reported as phishing once the
        total reaches 3, which requires more than one weak signal to agree.

        Returns a dict: is_phishing, risk_score, reasons, urls_found, url_results.
        """
        if text is None:
            text = ""

        reasons = []
        total_score = 0

        # --- Check 1: suspicious keywords ---------------------------------
        has_keywords, found_keywords = self.contains_keyword(text)
        if has_keywords:
            total_score += 2
            reasons.append(f"Suspicious keywords found: {', '.join(found_keywords)}")

        # --- Check 2: score every URL in the message ----------------------
        urls = self.extract_urls(text)
        url_results = []

        for url in urls:
            result = self.analyze_url(url)
            url_results.append(result)
            total_score += result["risk_score"]
            for reason in result["reasons"]:
                reasons.append(f"[URL] {reason}")

        # --- Check 3: urgency wording together with a link ----------------
        # Pressure words alone are harmless, and links alone are normal, but
        # the two TOGETHER are a documented phishing pattern (OWASP).
        lowered = text.lower()
        urgency_words = ["urgent", "immediately", "now", "verify", "claim", "limited"]
        if any(word in lowered for word in urgency_words) and urls:
            total_score += 2
            reasons.append("Urgent language combined with a link")

        # Final verdict: phishing if the combined score reaches the threshold.
        return {
            "is_phishing": total_score >= 3,
            "risk_score": total_score,
            "reasons": reasons,
            "urls_found": urls,
            "url_results": url_results,
        }
