from datetime import datetime, timezone
from flask import Flask, render_template, request
from pathlib import Path
import base64
import json
import os
import re
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PHISHTANK_CACHE_FILE = DATA_DIR / "phishtank_cache.json"
PHISHTANK_CACHE_HOURS = int(os.getenv("PHISHTANK_CACHE_HOURS", "12"))
PHISHTANK_MAX_CACHE_ITEMS = int(os.getenv("PHISHTANK_MAX_CACHE_ITEMS", "5000"))

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
APP_USER_AGENT = os.getenv("APP_USER_AGENT", "ScamShield/1.0 security scanner")

TRUSTED_DOMAINS = ["google.com", "facebook.com", "amazon.com", "paypal.com", "apple.com", "microsoft.com"]
TRUSTED_BRANDS = ["google", "facebook", "amazon", "paypal", "apple", "microsoft", "steam", "bank", "netflix", "dhl"]
SHORT_DOMAINS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "rb.gy", "cutt.ly", "tiny.cc", "is.gd"]
SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "update", "bank", "account", "confirm", "password",
    "wallet", "bonus", "claim", "gift", "recovery", "billing", "unlock", "suspended",
]
URGENT_PHRASES = [
    "urgent", "immediately", "right now", "within 24 hours", "today only", "last warning",
    "act now", "final notice", "avoid suspension", "limited time", "respond now", "asap",
]
SENSITIVE_REQUESTS = [
    "verify your account", "confirm your account", "confirm your identity", "reset your password",
    "send the code", "share the code", "enter your password", "update your payment",
    "provide your card", "provide your bank details", "upload your id", "wallet recovery phrase",
    "provide your ssn", "confirm your otp", "send us the 6-digit code",
]
MONEY_LURE_PHRASES = [
    "guaranteed profit", "double your", "no experience needed", "earn money quickly",
    "daily payout", "limited bonus", "claim your reward", "free gift", "investment return",
    "withdraw instantly", "promo code", "bonus instantly", "paid training", "hourly rate",
]
FEAR_PHRASES = [
    "account locked", "account suspended", "unauthorized login", "security alert",
    "payment failed", "delivery failed", "tax penalty", "final attempt",
]
BRAND_IMPERSONATION_HINTS = [
    "paypal", "apple", "microsoft", "google", "bank", "dhl", "steam",
    "netflix", "amazon", "visa", "mastercard", "zelle", "fedex", "mrbeast",
]
SOCIAL_ENGINEERING_CHANNELS = [
    "telegram", "whatsapp", "signal", "discord", "text me", "contact the recruiter on telegram",
]
RECRUITMENT_OUTREACH_TERMS = [
    "creator", "creators", "ambassador", "influencer", "brand collab", "paid partnership",
    "creator program", "recruiting team", "onboarding", "small group", "exclusive access",
    "early access", "invite you", "invitation", "partnership opportunity", "campaign",
]
COMPLIMENT_PHRASES = [
    "love your content", "love your page", "love your work", "big fan", "enjoyed your content",
    "found your page", "found your @ page", "love your videos",
]
REWARD_INVITATION_PHRASES = [
    "$50", "bonus", "joining bonus", "on us", "just for joining", "gift card", "compensation",
    "paid collaboration", "paid collab", "earn for joining",
]
CRYPTO_PROMO_PHRASES = [
    "crypto casino", "promo code", "withdraw instantly", "register now", "bonus instantly",
    "giveaway", "claim your reward",
]
SCHEDULING_LURE_PHRASES = [
    "schedule a meeting", "schedule a meeting with our founder", "choose a time slot",
    "book a time", "confirm you've done so", "calendly",
]
ADVANCE_FEE_CRYPTO_PHRASES = [
    "anti-money laundering", "pay a deposit", "withdrawal is under review", "account will be frozen",
    "deposit payable", "withdrawal can be released",
]
GIFT_CARD_SCAM_PHRASES = [
    "apple gift card", "gift card online", "send the code", "mark the item as sold", "pay half now",
]
CONVERSATION_STAGE_PHRASES = [
    "reply and i'll send the link", "reply and ill send the link", "reply for the link",
    "reply if interested", "respond and we will send the details", "message back for details",
    "i'll send over the link", "ill send over the link",
]
PROFESSIONAL_POSITIVE_MARKERS = [
    "campaign brief", "deliverables", "timeline", "contract", "rate card", "invoice",
    "company website", "brand partnerships", "partnership manager", "official website",
]
GENERIC_RECRUITING_SIGNATURES = [
    "recruiting team", "talent team", "partnerships team", "creator team", "collab team",
]
PAYMENT_PRESSURE_PHRASES = [
    "processing fee", "small fee", "delivery fee", "unlock your account", "pay now",
    "confirm payment", "settle now", "complete the payment", "release your parcel",
    "pay half now", "deposit", "withdrawal release",
]
BENIGN_PHRASES = [
    "no action required", "official app", "official website", "see you at", "meeting at",
    "attached is the invoice", "thanks", "please review when you have time",
    "statement is ready", "available in the app", "call me when free", "are we still on for",
]
BENIGN_CONTEXTS = [
    "calendar", "presentation", "schedule", "lunch", "meeting", "invoice", "notes",
    "reminder", "class", "project update", "family dinner",
]
BENIGN_BUSINESS_MARKERS = [
    "best regards", "kind regards", "thanks", "thank you", "team", "schedule a call",
    "let me know", "when you have time", "attached", "review", "tomorrow", "thursday",
    "official app", "official website", "no action required",
]
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".shop", ".live", ".buzz", ".loan", ".vip", ".rest", ".fit", ".gq",
]
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "verify", "secure", "wallet", "recover", "billing", "payment", "auth", "signin", "password",
]
MESSAGE_SIGNAL_WEIGHTS = {
    "urgency": 7,
    "sensitive": 10,
    "money": 8,
    "fear": 7,
    "brand_plus_sensitive": 8,
    "off_platform": 9,
    "payment_pressure": 9,
    "link_to_action": 8,
    "credentials_cluster": 9,
    "capital_pressure": 5,
    "punctuation_pressure": 4,
    "has_urls": 6,
}
ADVANCED_MESSAGE_PATTERNS = [
    {
        "label": "credential_theft_flow",
        "phrases": ["verify your account", "click the link", "security alert"],
        "boosts": {"Phishing Scam": 24, "Bank Scam": 16},
        "reason": "The message combines an account warning with a direct request to follow a link and verify credentials.",
    },
    {
        "label": "bank_fraud_flow",
        "phrases": ["unauthorized", "transaction", "confirm"],
        "boosts": {"Bank Scam": 26, "Phishing Scam": 14},
        "reason": "The message combines fraud-alert wording with an instruction to confirm activity, which is common in fake bank alerts.",
    },
    {
        "label": "parcel_fee_flow",
        "phrases": ["package", "delivery fee", "confirm your address"],
        "boosts": {"Parcel Scam": 26, "Phishing Scam": 10},
        "reason": "The message combines delivery trouble with a payment or address confirmation request, which is common in parcel scams.",
    },
    {
        "label": "job_fee_flow",
        "phrases": ["no experience needed", "telegram", "fee"],
        "boosts": {"Job Scam": 28, "Crypto Scam": 8},
        "reason": "The message mixes easy-money job bait with off-platform contact and a fee request.",
    },
    {
        "label": "wallet_takeover_flow",
        "phrases": ["connect your wallet", "seed phrase"],
        "boosts": {"Crypto Scam": 30, "Phishing Scam": 8},
        "reason": "The message asks for wallet access or recovery data, which is a strong crypto scam indicator.",
    },
    {
        "label": "creator_recruitment_lure",
        "phrases": ["creator", "early access", "$50"],
        "boosts": {"Social Engineering / Recruitment Scam": 30, "Job Scam": 12},
        "reason": "The message combines creator outreach, exclusivity, and a joining reward, which is common in social-engineering recruitment lures.",
    },
    {
        "label": "conversation_stage_lure",
        "phrases": ["reply", "send the link"],
        "boosts": {"Social Engineering / Recruitment Scam": 18, "Phishing Scam": 8},
        "reason": "The sender avoids giving the destination immediately and tries to move the victim into a follow-up conversation, which is a common scam funnel tactic.",
    },
    {
        "label": "business_document_lure",
        "phrases": ["document", "review", "access it here"],
        "boosts": {"Phishing Scam": 26},
        "reason": "The message uses a document-review lure with a direct access prompt, which is common in business phishing.",
    },
    {
        "label": "cloud_billing_lockout",
        "phrases": ["storage is full", "update your payment"],
        "boosts": {"Phishing Scam": 28, "Bank Scam": 12},
        "reason": "The message combines account disruption with a billing update request, which is common in cloud-account phishing.",
    },
    {
        "label": "payment_hold_flow",
        "phrases": ["account on hold", "business user"],
        "boosts": {"Bank Scam": 28, "Phishing Scam": 10},
        "reason": "The message claims funds are pending or on hold until the account is upgraded, which is common in payment-app scams.",
    },
    {
        "label": "refund_identity_flow",
        "phrases": ["refund", "card details", "verify your identity"],
        "boosts": {"Bank Scam": 30, "Phishing Scam": 10},
        "reason": "The message uses a refund lure while requesting identity or payment details, which is a strong bank-scam signal.",
    },
    {
        "label": "streaming_billing_scare",
        "phrases": ["subscription", "card was declined", "update billing"],
        "boosts": {"Phishing Scam": 24, "Bank Scam": 8},
        "reason": "The message uses a subscription billing problem to pressure the user into taking account action.",
    },
    {
        "label": "parcel_release_fee_flow",
        "phrases": ["total due", "handling fee", "release the package"],
        "boosts": {"Parcel Scam": 28, "Phishing Scam": 8},
        "reason": "The message combines delivery release wording with explicit charges, which is common in parcel-fee scams.",
    },
    {
        "label": "shopping_product_lure",
        "phrases": ["pre-owned", "online store", "item-details"],
        "boosts": {"Phishing Scam": 24},
        "reason": "The message pushes the user to an external product page with generic shopping language, which is common in ad-driven scam lures.",
    },
    {
        "label": "charge_review_flow",
        "phrases": ["charge", "did not authorize", "review your account"],
        "boosts": {"Bank Scam": 26, "Phishing Scam": 10},
        "reason": "The message uses a payment scare and asks the user to review account activity, which is common in fake billing alerts.",
    },
    {
        "label": "quota_reactivation_flow",
        "phrases": ["mailbox is over quota", "data loss", "reactivate storage"],
        "boosts": {"Phishing Scam": 26},
        "reason": "The message pressures the user with a mailbox or storage failure and a reactivation action, which is common in account phishing.",
    },
    {
        "label": "payment_upgrade_fee_flow",
        "phrases": ["paid you", "transfer is pending", "refundable fee"],
        "boosts": {"Bank Scam": 30, "Job Scam": 8},
        "reason": "The message claims money is waiting but requires an upgrade or refundable fee first, which is common in payment-app scams.",
    },
    {
        "label": "wallet_validation_flow",
        "phrases": ["validate your wallet", "recovery phrase"],
        "boosts": {"Crypto Scam": 30, "Phishing Scam": 8},
        "reason": "The message asks the user to validate wallet access or reveal recovery information, which is a strong crypto scam indicator.",
    },
    {
        "label": "celebrity_crypto_giveaway",
        "phrases": ["crypto casino", "promo code", "withdraw instantly"],
        "boosts": {"Crypto Scam": 34, "Social Engineering / Recruitment Scam": 10},
        "reason": "The message uses a celebrity-style promotion, free bonus, and instant withdrawal promise, which is common in crypto scam campaigns.",
    },
    {
        "label": "founder_meeting_recruitment_lure",
        "phrases": ["schedule a meeting", "founder", "reply once you have booked"],
        "boosts": {"Social Engineering / Recruitment Scam": 28, "Job Scam": 12},
        "reason": "The message pressures the user to book a meeting and confirm attendance, which is common in staged recruitment scams.",
    },
    {
        "label": "aml_deposit_release_scam",
        "phrases": ["anti-money laundering", "pay a deposit", "account will be frozen"],
        "boosts": {"Crypto Scam": 34, "Phishing Scam": 10},
        "reason": "The message uses compliance language to demand an advance deposit before releasing funds, which is a strong crypto scam pattern.",
    },
    {
        "label": "reply_yes_job_lure",
        "phrases": ["reply yes", "online interview", "remote data entry"],
        "boosts": {"Job Scam": 28, "Social Engineering / Recruitment Scam": 12},
        "reason": "The message uses a simplified reply-YES flow to move the victim into a staged job scam funnel.",
    },
    {
        "label": "gift_card_payment_pivot",
        "phrases": ["apple gift card", "send the code"],
        "boosts": {"Phishing Scam": 28, "Job Scam": 8},
        "reason": "The sender pivots away from normal payment methods and asks for a gift card code, which is a strong scam signal.",
    },
    {
        "label": "zelle_hold_flow",
        "phrases": ["zelle", "account on hold", "business user"],
        "boosts": {"Bank Scam": 34, "Phishing Scam": 8},
        "reason": "The message claims a payment-app transfer is blocked until the account is changed or verified, which is common in fake payment scams.",
    },
    {
        "label": "trading_signal_lure",
        "phrases": ["btc/usdt", "buy 1% of your account balance"],
        "boosts": {"Crypto Scam": 24},
        "reason": "The message uses trading-signal language to push immediate speculative action, which is common in crypto scam funnels.",
    },
    {
        "label": "high_pay_reply_yes_job_lure",
        "phrases": ["reply yes", "hourly rate", "paid training"],
        "boosts": {"Job Scam": 26, "Social Engineering / Recruitment Scam": 10},
        "reason": "The message uses unusually attractive remote-job terms and a simple reply-YES step to start a staged job scam.",
    },
    {
        "label": "tax_refund_lure",
        "phrases": ["tax refund", "card details", "verify your identity"],
        "boosts": {"Bank Scam": 34, "Phishing Scam": 10},
        "reason": "The message uses a refund or tax-release lure while requesting payment details or identity verification.",
    },
    {
        "label": "subscription_decline_flow",
        "phrases": ["subscription", "card was declined", "update billing now"],
        "boosts": {"Phishing Scam": 28, "Bank Scam": 10},
        "reason": "The message uses a subscription payment problem to rush the victim into account action.",
    },
    {
        "label": "remote_job_fee_flow",
        "phrases": ["telegram", "processing fee", "start today"],
        "boosts": {"Job Scam": 34, "Social Engineering / Recruitment Scam": 8},
        "reason": "The message combines job bait, off-platform contact, and a starting fee, which is a strong job-scam pattern.",
    },
]
SCAM_PATTERNS = {
    "Phishing Scam": {
        "weight": 1.35,
        "keywords": [
            "verify", "login", "click", "password", "account", "security alert", "reset",
            "credentials", "2fa", "otp", "one-time code", "sign in", "suspended", "unusual activity",
            "document", "review", "storage", "payment information", "deactivated", "subscription", "billing",
        ],
        "phrases": [
            "your account has been limited", "we detected unusual activity", "click the link below",
            "confirm your identity", "verify your account now", "login to avoid suspension",
            "document awaiting review", "update your payment information", "your cloud account may be deactivated",
        ],
        "examples": [
            "We noticed suspicious activity on your account. Verify now to avoid suspension.",
            "Your email account is expiring today. Sign in immediately to keep access.",
        ],
    },
    "Job Scam": {
        "weight": 1.15,
        "keywords": [
            "remote job", "work from home", "telegram interview", "whatsapp interview", "salary",
            "easy money", "commission", "upfront", "processing fee", "hiring", "part time", "earn daily",
            "daily payouts", "onboarding", "recruiter",
        ],
        "phrases": [
            "no experience needed", "pay a small fee", "earn money quickly", "message us on telegram",
            "daily payout", "flexible online work", "join our whatsapp onboarding",
        ],
        "examples": [
            "Earn $300 daily from home, no experience needed. Contact us on Telegram to start.",
            "Congratulations, you've been selected. Pay a setup fee to secure your remote role.",
        ],
    },
    "Social Engineering / Recruitment Scam": {
        "weight": 1.22,
        "keywords": [
            "creator", "creators", "ambassador", "influencer", "recruiting team", "creator program",
            "brand collab", "paid partnership", "small group", "exclusive", "early access",
            "invite", "onboarding", "campaign", "collaboration", "founder", "schedule", "meeting",
        ],
        "phrases": [
            "love your content", "found your email from your page", "reply and i'll send the link",
            "small group of creators", "early access plus", "just for joining",
            "schedule a meeting with our founder", "reply once you have booked",
        ],
        "examples": [
            "Love your content. We are inviting a small group of creators to a new platform and offering a joining bonus if you reply for the link.",
            "Our recruiting team is onboarding creators for an exclusive early-access campaign. Reply and we will send the details.",
        ],
    },
    "Bank Scam": {
        "weight": 1.3,
        "keywords": [
            "unauthorized", "transaction", "confirm", "pin", "account locked", "bank alert",
            "security hold", "debit card", "credit card", "refund pending", "chargeback",
            "zelle", "transfer", "business user", "refund", "card details", "payment due",
            "charge", "applepay", "pending", "refundable fee", "upgrade your account",
        ],
        "phrases": [
            "your account has been locked", "unauthorized login attempt", "confirm the transaction",
            "your card has been restricted", "bank verification required", "account on hold",
            "verify your identity", "your transfer is pending", "did not authorize this",
            "review your account immediately",
        ],
        "examples": [
            "Unauthorized transaction detected. Confirm your banking details immediately.",
            "Your card has been temporarily locked. Verify your PIN to restore access.",
        ],
    },
    "Crypto Scam": {
        "weight": 1.2,
        "keywords": [
            "crypto", "bitcoin", "tokens", "investment", "send eth", "wallet", "seed phrase",
            "airdrop", "staking", "double your", "giveaway", "usdt", "blockchain",
            "recovery phrase", "validate your wallet", "wallet validation",
            "crypto casino", "promo code", "withdraw instantly", "withdrawal", "deposit", "anti-money laundering",
        ],
        "phrases": [
            "double your bitcoin", "claim your airdrop", "connect your wallet", "validate your wallet",
            "enter your recovery phrase", "guaranteed crypto returns", "wallet validation required",
            "withdrawal is under review", "pay a deposit", "account will be frozen",
        ],
        "examples": [
            "Claim your exclusive airdrop now. Connect your wallet and confirm your seed phrase.",
            "Send 0.5 BTC and receive 1 BTC back in our promotional giveaway.",
        ],
    },
    "Parcel Scam": {
        "weight": 1.1,
        "keywords": [
            "package", "undelivered", "shipping", "fee", "delivery", "customs", "tracking",
            "carrier", "dispatch", "parcel", "pickup point", "reschedule", "handling fee", "insurance charge",
            "total due", "release package",
        ],
        "phrases": [
            "your package could not be delivered", "pay the delivery fee", "confirm your address",
            "reschedule your parcel", "tracking update available", "release the package",
            "settle the outstanding fee",
        ],
        "examples": [
            "Your parcel is on hold. Pay a small delivery fee to release it today.",
            "Delivery failed due to an address issue. Confirm your details through the link.",
        ],
    },
}

SAFE_EXAMPLES = [
    "Your monthly electricity bill is ready. Log in through the official provider app you already use.",
    "Hi Ana, are we still meeting at 6? I also emailed you the presentation.",
    "Your bank statement is available in the official mobile app. No action is required by message.",
]

PRIVACY_NOTES = [
    {
        "title": "What Is Stored",
        "body": "By default, the app keeps scan input in memory only for the current request-response cycle. It does not intentionally save pasted messages to a database.",
    },
    {
        "title": "What May Be Cached",
        "body": "A small local cache can be used for PhishTank lookup results so the app does not repeatedly call the same external feed. The cache stores domain-level reputation results, not full message bodies.",
    },
    {
        "title": "What Is Sent Out",
        "body": "Links may be sent to external providers such as Google Safe Browsing, RDAP, VirusTotal, or PhishTank when those checks are enabled. This is required to enrich the link with threat intelligence.",
    },
    {
        "title": "API Key Handling",
        "body": "API keys should remain in server-side environment variables only. They should never be hardcoded into frontend code, screenshots, or source control.",
    },
]

EMPTY_IOCS = {
    "urls": [],
    "domains": [],
    "emails": [],
    "phones": [],
    "crypto_wallets": [],
    "brands": [],
}

SCAM_EXAMPLES = {name: details["examples"] for name, details in SCAM_PATTERNS.items()}


def ensure_url_scheme(value):
    value = value.strip()
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("www.") or "." in value:
        return f"http://{value}"
    return value


def extract_domain(url):
    parsed = urlparse(ensure_url_scheme(url))
    domain = parsed.netloc.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split(":")[0]


def get_url_parts(url):
    parsed = urlparse(ensure_url_scheme(url))
    return {
        "scheme": parsed.scheme.lower(),
        "domain": extract_domain(url),
        "path": parsed.path.lower() or "/",
        "query": parsed.query.lower(),
    }


def extract_urls(message):
    pattern = r'((?:https?://|www\.)[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?)'
    seen = []
    for candidate in re.findall(pattern, message):
        cleaned = candidate.rstrip('.,!?)"]\'')
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
    return seen


def normalize_confusables(text):
    replacements = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
        "_": "",
    })
    return text.lower().translate(replacements)


def levenshtein_distance(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (char_a != char_b)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def count_matches(text, patterns):
    total = 0
    for pattern in patterns:
        if pattern in text:
            total += 1
    return total


def count_regex_matches(text, regex):
    return len(re.findall(regex, text))


def tokenize_message(message):
    return re.findall(r"[a-zA-Z0-9@.\-']+", message.lower())


def keyword_hits_by_category(msg, config):
    hits = []
    for keyword in config["keywords"]:
        if keyword.lower() in msg:
            hits.append(keyword)
    for phrase in config["phrases"]:
        if phrase.lower() in msg:
            hits.append(phrase)
    return hits


def extract_iocs(message, urls):
    emails = list(dict.fromkeys(re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b", message)))
    phones = list(dict.fromkeys(re.findall(r"(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3}[\s-]?\d{3,4}", message)))
    crypto_wallets = list(dict.fromkeys(re.findall(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,59})\b", message)))
    domains = list(dict.fromkeys(extract_domain(url) for url in urls if extract_domain(url)))

    brands = []
    lowered = message.lower()
    for brand in TRUSTED_BRANDS:
        if brand in lowered:
            brands.append(brand)

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "phones": phones[:5],
        "crypto_wallets": crypto_wallets[:5],
        "brands": list(dict.fromkeys(brands)),
    }


def is_recent_timestamp(timestamp, max_age_hours):
    if not timestamp:
        return False
    try:
        saved_at = datetime.fromisoformat(timestamp)
    except ValueError:
        return False
    age = datetime.now(timezone.utc) - saved_at.replace(tzinfo=timezone.utc)
    return age.total_seconds() <= max_age_hours * 3600


def load_phishtank_cache():
    if not PHISHTANK_CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(PHISHTANK_CACHE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_phishtank_cache(cache):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    trimmed_items = list(cache.items())[-PHISHTANK_MAX_CACHE_ITEMS:]
    PHISHTANK_CACHE_FILE.write_text(json.dumps(dict(trimmed_items), indent=2), encoding="utf-8")


def update_phishtank_cache_entry(domain, flagged, message):
    cache = load_phishtank_cache()
    cache[domain] = {
        "flagged": flagged,
        "message": message,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    save_phishtank_cache(cache)


def check_phishtank_cache(domain):
    cache = load_phishtank_cache()
    entry = cache.get(domain)
    if not entry:
        return None
    if not is_recent_timestamp(entry.get("checked_at"), PHISHTANK_CACHE_HOURS):
        return None
    flagged = entry.get("flagged")
    if flagged:
        return True, "PhishTank local cache contains a recent phishing match for this domain."
    return False, "PhishTank local cache has a recent non-match for this domain."


def score_domain(domain):
    reasons = []
    risk = 0.12
    normalized_domain = normalize_confusables(domain)
    labels = [label for label in re.split(r"[.\-]", domain) if label]
    normalized_labels = [normalize_confusables(label) for label in labels]

    if domain in TRUSTED_DOMAINS:
        return 0.0, ["Matches an explicitly trusted domain."]

    if any(short_domain == domain for short_domain in SHORT_DOMAINS):
        risk += 0.22
        reasons.append("This is a shortened-link domain, which hides the final destination.")

    if domain.count(".") >= 2:
        risk += 0.12
        reasons.append("The hostname is more complex than a normal consumer-facing login domain.")

    registrable_label = labels[-2] if len(labels) >= 2 else labels[0] if labels else ""
    vowel_count = sum(char in "aeiou" for char in registrable_label)
    vowel_ratio = (vowel_count / len(registrable_label)) if registrable_label else 0
    if registrable_label and len(registrable_label) >= 6 and re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", registrable_label):
        risk += 0.16
        reasons.append("The domain name contains an unusual consonant-heavy pattern often seen in disposable scam domains.")
    elif registrable_label and len(registrable_label) >= 6 and vowel_ratio <= 0.25:
        risk += 0.1
        reasons.append("The registrable domain looks randomly generated or low-trust.")

    labels = domain.split(".")
    if len(labels) >= 3:
        subdomain_labels = labels[:-2]
        if any(any(brand in normalize_confusables(label) for brand in TRUSTED_BRANDS) for label in subdomain_labels):
            risk += 0.2
            reasons.append("A brand-like name appears in the subdomain instead of the real registrable domain, which is common in phishing links.")

    for keyword in SUSPICIOUS_URL_KEYWORDS:
        if keyword in normalized_domain:
            risk += 0.1
            reasons.append(f"The link contains a pressure word like '{keyword}'.")

    for brand in TRUSTED_BRANDS:
        if brand in normalized_domain and domain not in TRUSTED_DOMAINS:
            if not domain.endswith(f"{brand}.com"):
                risk += 0.24
                reasons.append(f"The domain references '{brand}' but is not the official brand domain.")

    for label in normalized_labels:
        for brand in TRUSTED_BRANDS:
            distance = levenshtein_distance(label, brand)
            if label != brand and len(label) >= 5 and distance in (1, 2):
                risk += 0.32
                reasons.append(f"The hostname looks like a typo-squatted variant of '{brand}'.")
                break

    if re.search(r"\d", domain):
        risk += 0.06
        reasons.append("The hostname mixes in digits, which is common in throwaway scam domains.")

    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        risk += 0.12
        reasons.append("The domain uses multiple hyphens, which is common in impersonation and throwaway scam domains.")

    digit_count = sum(char.isdigit() for char in domain)
    if digit_count >= 3:
        risk += 0.08
        reasons.append("The domain contains many digits, which is often seen in disposable scam infrastructure.")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk += 0.18
        reasons.append("The domain uses a high-abuse top-level domain often seen in scam infrastructure.")

    if domain.startswith("xn--"):
        risk += 0.18
        reasons.append("The domain uses punycode, which can be abused for lookalike phishing domains.")

    if not reasons:
        reasons.append("No strong local red flags were triggered, but reputation checks can still miss brand-new scams.")

    return min(risk, 0.99), reasons


def score_url_structure(url):
    parts = get_url_parts(url)
    path = parts["path"]
    query = parts["query"]
    reasons = []
    risk = 0.0

    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if f"/{keyword}" in path or keyword in query:
            risk += 0.1
            reasons.append(f"The URL path or query contains '{keyword}', which often appears on phishing pages.")

    if "@" in ensure_url_scheme(url):
        risk += 0.12
        reasons.append("The URL includes an '@' symbol, which can be abused to disguise the real destination.")

    if len(path.strip("/").split("/")) >= 3 and path != "/":
        risk += 0.08
        reasons.append("The URL path is unusually deep, which can be a sign of disguised or generated phishing pages.")

    if any(token in path for token in ["/products/", "/item-details", "/review", "/invoice", "/document"]):
        risk += 0.08
        reasons.append("The URL path uses a lure-style content route that is common in document or shopping scam links.")

    return min(risk, 0.35), reasons


def expand_short_url(url):
    domain = extract_domain(url)
    if domain not in SHORT_DOMAINS:
        return None, "URL expansion not needed."

    try:
        response = requests.head(
            ensure_url_scheme(url),
            timeout=6,
            allow_redirects=True,
            headers={"User-Agent": APP_USER_AGENT},
        )
        expanded = response.url
        if expanded and expanded != ensure_url_scheme(url):
            return expanded, f"Short link expands to {expanded}."
        return None, "Short link did not reveal a different final destination."
    except requests.RequestException:
        return None, "Short link expansion failed."


def score_message(message, urls):
    msg = message.lower()
    tokens = tokenize_message(message)
    scores = {}
    supporting_reasons = []
    triggered_patterns = []
    signal_groups = {}
    risk_floor = 0.0

    urgency_hits = count_matches(msg, URGENT_PHRASES)
    sensitive_hits = count_matches(msg, SENSITIVE_REQUESTS)
    money_hits = count_matches(msg, MONEY_LURE_PHRASES)
    fear_hits = count_matches(msg, FEAR_PHRASES)
    brand_hits = count_matches(msg, BRAND_IMPERSONATION_HINTS)
    off_platform_hits = count_matches(msg, SOCIAL_ENGINEERING_CHANNELS)
    payment_pressure_hits = count_matches(msg, PAYMENT_PRESSURE_PHRASES)
    recruitment_hits = count_matches(msg, RECRUITMENT_OUTREACH_TERMS)
    compliment_hits = count_matches(msg, COMPLIMENT_PHRASES)
    reward_invitation_hits = count_matches(msg, REWARD_INVITATION_PHRASES)
    conversation_stage_hits = count_matches(msg, CONVERSATION_STAGE_PHRASES)
    crypto_promo_hits = count_matches(msg, CRYPTO_PROMO_PHRASES)
    scheduling_lure_hits = count_matches(msg, SCHEDULING_LURE_PHRASES)
    advance_fee_crypto_hits = count_matches(msg, ADVANCE_FEE_CRYPTO_PHRASES)
    gift_card_scam_hits = count_matches(msg, GIFT_CARD_SCAM_PHRASES)
    positive_professional_hits = count_matches(msg, PROFESSIONAL_POSITIVE_MARKERS)
    generic_signature_hits = count_matches(msg, GENERIC_RECRUITING_SIGNATURES)

    upper_count = sum(1 for char in message if char.isupper())
    alpha_count = sum(1 for char in message if char.isalpha())
    uppercase_ratio = (upper_count / alpha_count) if alpha_count else 0
    punctuation_burst = count_regex_matches(message, r"[!?]{2,}")
    link_to_action_hits = count_regex_matches(msg, r"(click|tap|open|visit)\s+(the\s+)?(link|url)")
    credential_regex_hits = count_regex_matches(msg, r"(otp|one-time code|security code|verification code|password|pin|seed phrase|recovery phrase)")
    domain_like_hits = count_regex_matches(msg, r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
    message_length = len(tokens)
    benign_phrase_hits = count_matches(msg, BENIGN_PHRASES)
    benign_context_hits = count_matches(msg, BENIGN_CONTEXTS)
    benign_business_hits = count_matches(msg, BENIGN_BUSINESS_MARKERS)
    high_severity_hits = sensitive_hits + fear_hits + payment_pressure_hits + credential_regex_hits + link_to_action_hits
    moderate_signal_hits = urgency_hits + money_hits + recruitment_hits + reward_invitation_hits + off_platform_hits + brand_hits

    for scam_type, config in SCAM_PATTERNS.items():
        keyword_hits = count_matches(msg, [item.lower() for item in config["keywords"]])
        phrase_hits = count_matches(msg, [item.lower() for item in config["phrases"]])
        unique_hits = len(set(keyword_hits_by_category(msg, config)))
        score = (keyword_hits * 9 + phrase_hits * 18 + unique_hits * 5) * config["weight"]
        scores[scam_type] = score

    if urgency_hits:
        supporting_reasons.append("The message uses urgency language to pressure a quick decision.")
        scores["Phishing Scam"] += urgency_hits * MESSAGE_SIGNAL_WEIGHTS["urgency"]
        scores["Bank Scam"] += urgency_hits * 6
        scores["Parcel Scam"] += urgency_hits * 4
        signal_groups["urgency_pressure"] = urgency_hits * MESSAGE_SIGNAL_WEIGHTS["urgency"]

    if sensitive_hits:
        supporting_reasons.append("The sender asks for sensitive information, account access, or security codes.")
        scores["Phishing Scam"] += sensitive_hits * MESSAGE_SIGNAL_WEIGHTS["sensitive"]
        scores["Bank Scam"] += sensitive_hits * 8
        scores["Crypto Scam"] += sensitive_hits * 6
        signal_groups["credential_request"] = sensitive_hits * MESSAGE_SIGNAL_WEIGHTS["sensitive"]

    if money_hits:
        supporting_reasons.append("The text uses bait like rewards, profit, fast money, or giveaway language.")
        scores["Job Scam"] += money_hits * MESSAGE_SIGNAL_WEIGHTS["money"]
        scores["Crypto Scam"] += money_hits * MESSAGE_SIGNAL_WEIGHTS["money"]
        signal_groups["money_lure"] = money_hits * MESSAGE_SIGNAL_WEIGHTS["money"]

    if fear_hits:
        supporting_reasons.append("The text uses fear-based language such as lockout, failed delivery, or fraud alerts.")
        scores["Phishing Scam"] += fear_hits * MESSAGE_SIGNAL_WEIGHTS["fear"]
        scores["Bank Scam"] += fear_hits * MESSAGE_SIGNAL_WEIGHTS["fear"]
        scores["Parcel Scam"] += fear_hits * 6
        signal_groups["fear_trigger"] = fear_hits * MESSAGE_SIGNAL_WEIGHTS["fear"]

    if brand_hits and sensitive_hits:
        supporting_reasons.append("The sender appears to name a trusted brand while also asking for verification or sensitive information.")
        scores["Phishing Scam"] += brand_hits * MESSAGE_SIGNAL_WEIGHTS["brand_plus_sensitive"]
        scores["Bank Scam"] += brand_hits * 8
        signal_groups["brand_impersonation"] = brand_hits * MESSAGE_SIGNAL_WEIGHTS["brand_plus_sensitive"]

    if brand_hits and fear_hits:
        supporting_reasons.append("The message combines a trusted brand or payment service name with fear-based account or billing language.")
        scores["Bank Scam"] += brand_hits * 7
        scores["Phishing Scam"] += brand_hits * 5
        signal_groups["brand_fear_combo"] = brand_hits * 7

    if brand_hits and payment_pressure_hits:
        supporting_reasons.append("The message mixes a trusted brand or payment service with a demand for payment or account action.")
        scores["Bank Scam"] += brand_hits * 8
        scores["Phishing Scam"] += brand_hits * 4
        signal_groups["brand_payment_combo"] = brand_hits * 8

    if off_platform_hits:
        supporting_reasons.append("The message tries to move the conversation to informal channels like Telegram or WhatsApp, which is a common scam pattern.")
        scores["Job Scam"] += off_platform_hits * MESSAGE_SIGNAL_WEIGHTS["off_platform"]
        scores["Crypto Scam"] += off_platform_hits * 6
        signal_groups["off_platform_redirect"] = off_platform_hits * MESSAGE_SIGNAL_WEIGHTS["off_platform"]

    if payment_pressure_hits:
        supporting_reasons.append("The sender is pushing for a payment or fee before a normal verification process.")
        scores["Parcel Scam"] += payment_pressure_hits * MESSAGE_SIGNAL_WEIGHTS["payment_pressure"]
        scores["Job Scam"] += payment_pressure_hits * 7
        scores["Bank Scam"] += payment_pressure_hits * 5
        scores["Crypto Scam"] += payment_pressure_hits * 6
        signal_groups["payment_pressure"] = payment_pressure_hits * MESSAGE_SIGNAL_WEIGHTS["payment_pressure"]

    if recruitment_hits:
        supporting_reasons.append("The message uses creator, ambassador, or recruitment-style outreach language often seen in social-engineering lures.")
        scores["Social Engineering / Recruitment Scam"] += recruitment_hits * 9
        scores["Job Scam"] += recruitment_hits * 5
        signal_groups["recruitment_outreach"] = recruitment_hits * 9

    if compliment_hits:
        supporting_reasons.append("The sender uses compliments or personal flattery, which can be a tactic to lower suspicion in outreach scams.")
        scores["Social Engineering / Recruitment Scam"] += compliment_hits * 8
        signal_groups["flattery_hook"] = compliment_hits * 8

    if reward_invitation_hits:
        supporting_reasons.append("The outreach includes a joining reward or incentive, which raises the risk of a recruitment or creator scam.")
        scores["Social Engineering / Recruitment Scam"] += reward_invitation_hits * 10
        scores["Job Scam"] += reward_invitation_hits * 6
        scores["Crypto Scam"] += reward_invitation_hits * 8
        signal_groups["reward_lure"] = reward_invitation_hits * 10

    if conversation_stage_hits:
        supporting_reasons.append("The sender asks you to reply first and promises to send the link or details later, which is a common conversation-stage scam tactic.")
        scores["Social Engineering / Recruitment Scam"] += conversation_stage_hits * 12
        scores["Phishing Scam"] += conversation_stage_hits * 4
        signal_groups["conversation_stage_lure"] = conversation_stage_hits * 12

    if crypto_promo_hits:
        supporting_reasons.append("The message uses crypto promo or instant-withdrawal language, which is common in bonus and giveaway scams.")
        scores["Crypto Scam"] += crypto_promo_hits * 11
        scores["Social Engineering / Recruitment Scam"] = max(0, scores["Social Engineering / Recruitment Scam"] - 6)
        signal_groups["crypto_promo_lure"] = crypto_promo_hits * 11

    if scheduling_lure_hits:
        supporting_reasons.append("The message uses scheduling pressure and authority language to move the victim into a staged recruitment flow.")
        scores["Social Engineering / Recruitment Scam"] += scheduling_lure_hits * 9
        scores["Job Scam"] += scheduling_lure_hits * 7
        signal_groups["scheduling_lure"] = scheduling_lure_hits * 9

    if advance_fee_crypto_hits:
        supporting_reasons.append("The message demands a deposit or compliance payment before funds can be released, which is a strong advance-fee crypto scam signal.")
        scores["Crypto Scam"] += advance_fee_crypto_hits * 12
        scores["Bank Scam"] += advance_fee_crypto_hits * 3
        signal_groups["advance_fee_crypto"] = advance_fee_crypto_hits * 12

    if gift_card_scam_hits:
        supporting_reasons.append("The sender asks for a gift card or code instead of a normal payment method, which is a strong marketplace scam signal.")
        scores["Phishing Scam"] += gift_card_scam_hits * 11
        signal_groups["gift_card_pivot"] = gift_card_scam_hits * 11

    if "online interview" in msg and "remote" in msg and ("hourly rate" in msg or "paid training" in msg):
        supporting_reasons.append("The message advertises an attractive remote role with a simplified interview funnel, which is a common job-scam pattern.")
        scores["Job Scam"] += 18
        signal_groups["remote_job_offer_combo"] = 18

    if "btc/usdt" in msg or "signal period" in msg or "prediction: call" in msg:
        supporting_reasons.append("The message uses trading-signal language to push immediate action on a crypto pair.")
        scores["Crypto Scam"] += 18
        signal_groups["trading_signal_push"] = 18

    if link_to_action_hits:
        supporting_reasons.append("The message explicitly tells the user to click or open a link, which is a common delivery method for phishing pages.")
        scores["Phishing Scam"] += link_to_action_hits * MESSAGE_SIGNAL_WEIGHTS["link_to_action"]
        scores["Bank Scam"] += link_to_action_hits * 5
        signal_groups["link_delivery"] = link_to_action_hits * MESSAGE_SIGNAL_WEIGHTS["link_to_action"]

    if credential_regex_hits >= 2:
        supporting_reasons.append("The message references multiple credential or authentication terms, which strongly suggests account takeover intent.")
        scores["Phishing Scam"] += credential_regex_hits * MESSAGE_SIGNAL_WEIGHTS["credentials_cluster"]
        scores["Bank Scam"] += credential_regex_hits * 7
        signal_groups["auth_terms_cluster"] = credential_regex_hits * MESSAGE_SIGNAL_WEIGHTS["credentials_cluster"]

    if domain_like_hits >= 1 and link_to_action_hits:
        supporting_reasons.append("The message mixes a visible domain or URL with a strong call to click, which is a classic phishing delivery pattern.")
        scores["Phishing Scam"] += 12
        scores["Bank Scam"] += 6
        signal_groups["url_call_to_action_combo"] = 12

    if message_length <= 30 and (urgency_hits or sensitive_hits or fear_hits):
        supporting_reasons.append("The message is short and highly directive, which is common in SMS-style scam campaigns.")
        scores["Phishing Scam"] += 6
        scores["Parcel Scam"] += 4
        signal_groups["short_directive_style"] = 6

    if uppercase_ratio >= 0.35:
        supporting_reasons.append("The text uses an unusually high amount of capital letters, which is common in scam messages.")
        scores["Phishing Scam"] += MESSAGE_SIGNAL_WEIGHTS["capital_pressure"]
        scores["Job Scam"] += 3
        signal_groups["visual_pressure"] = MESSAGE_SIGNAL_WEIGHTS["capital_pressure"]

    if punctuation_burst:
        supporting_reasons.append("The text uses repeated exclamation or question marks to create pressure.")
        scores["Phishing Scam"] += punctuation_burst * MESSAGE_SIGNAL_WEIGHTS["punctuation_pressure"]
        scores["Crypto Scam"] += punctuation_burst * 3
        signal_groups["punctuation_pressure"] = punctuation_burst * MESSAGE_SIGNAL_WEIGHTS["punctuation_pressure"]

    if urls:
        supporting_reasons.append("The message includes a link, which raises the risk when combined with pressure tactics.")
        scores["Phishing Scam"] += len(urls) * MESSAGE_SIGNAL_WEIGHTS["has_urls"]
        scores["Bank Scam"] += len(urls) * 4
        scores["Parcel Scam"] += len(urls) * 3
        signal_groups["embedded_urls"] = len(urls) * MESSAGE_SIGNAL_WEIGHTS["has_urls"]

    for pattern in ADVANCED_MESSAGE_PATTERNS:
        if all(phrase in msg for phrase in pattern["phrases"]):
            triggered_patterns.append(pattern["label"])
            supporting_reasons.append(pattern["reason"])
            for scam_type, boost in pattern["boosts"].items():
                scores[scam_type] += boost
            signal_groups[f"pattern:{pattern['label']}"] = max(pattern["boosts"].values())
            if pattern["label"] in {"business_document_lure", "streaming_billing_scare", "shopping_product_lure", "quota_reactivation_flow"}:
                risk_floor = max(risk_floor, 0.46)
            elif pattern["label"] in {"cloud_billing_lockout", "payment_hold_flow", "parcel_release_fee_flow", "charge_review_flow", "payment_upgrade_fee_flow"}:
                risk_floor = max(risk_floor, 0.58)
            elif pattern["label"] in {"refund_identity_flow", "wallet_takeover_flow", "wallet_validation_flow", "credential_theft_flow", "bank_fraud_flow", "celebrity_crypto_giveaway", "aml_deposit_release_scam", "gift_card_payment_pivot", "zelle_hold_flow", "tax_refund_lure"}:
                risk_floor = max(risk_floor, 0.68)
            elif pattern["label"] in {"founder_meeting_recruitment_lure", "reply_yes_job_lure", "high_pay_reply_yes_job_lure"}:
                risk_floor = max(risk_floor, 0.48)
            elif pattern["label"] in {"trading_signal_lure"}:
                risk_floor = max(risk_floor, 0.45)
            elif pattern["label"] in {"subscription_decline_flow"}:
                risk_floor = max(risk_floor, 0.46)
            elif pattern["label"] in {"remote_job_fee_flow"}:
                risk_floor = max(risk_floor, 0.58)

    if compliment_hits and reward_invitation_hits and recruitment_hits:
        supporting_reasons.append("The message combines flattery, an invitation, and a reward, which is a strong creator-outreach scam pattern.")
        scores["Social Engineering / Recruitment Scam"] += 24
        scores["Job Scam"] += 8
        signal_groups["compliment_reward_invitation_combo"] = 24
        risk_floor = max(risk_floor, 0.42)

    if recruitment_hits and conversation_stage_hits:
        supporting_reasons.append("The message tries to start a private back-and-forth before revealing the destination, which fits a conversation-stage social-engineering funnel.")
        scores["Social Engineering / Recruitment Scam"] += 18
        signal_groups["conversation_stage_social_engineering"] = 18
        risk_floor = max(risk_floor, 0.48)

    if urls and (brand_hits or payment_pressure_hits or fear_hits):
        risk_floor = max(risk_floor, 0.52)

    if credential_regex_hits >= 2 or ("seed phrase" in msg) or ("wallet" in msg and "connect" in msg):
        risk_floor = max(risk_floor, 0.72)

    if ("refund" in msg and "card details" in msg) or ("tax refund" in msg and "verify your identity" in msg):
        risk_floor = max(risk_floor, 0.66)

    if ("zelle" in msg or "transfer" in msg) and ("account on hold" in msg or "business user" in msg):
        risk_floor = max(risk_floor, 0.64)

    if ("delivery fee" in msg or "handling fee" in msg or "insurance charge" in msg) and ("package" in msg or "shipment" in msg):
        risk_floor = max(risk_floor, 0.6)

    if ("no experience needed" in msg and ("telegram" in msg or "whatsapp" in msg)) or (off_platform_hits and payment_pressure_hits):
        risk_floor = max(risk_floor, 0.66)

    if ("daily payout" in msg or "daily payouts" in msg) and ("whatsapp" in msg or "telegram" in msg or "onboarding" in msg):
        risk_floor = max(risk_floor, 0.48)

    if ("charge" in msg or "applepay" in msg) and ("did not authorize" in msg or "review your account" in msg):
        risk_floor = max(risk_floor, 0.46)

    if ("mailbox is over quota" in msg or "reactivate storage" in msg or "data loss" in msg):
        risk_floor = max(risk_floor, 0.46)

    if ("paid you" in msg or "transfer is pending" in msg) and ("refundable fee" in msg or "upgrade your account" in msg):
        risk_floor = max(risk_floor, 0.68)

    if ("validate your wallet" in msg or "wallet validation" in msg) and ("recovery phrase" in msg or "wallet" in msg):
        risk_floor = max(risk_floor, 0.72)

    if crypto_promo_hits >= 2 and ("register" in msg or "promo code" in msg):
        risk_floor = max(risk_floor, 0.72)

    if scheduling_lure_hits >= 2 and ("remote role" in msg or "resume" in msg or "founder" in msg):
        risk_floor = max(risk_floor, 0.46)

    if advance_fee_crypto_hits >= 2 and ("withdrawal" in msg or "usdt" in msg):
        risk_floor = max(risk_floor, 0.72)

    if gift_card_scam_hits >= 2:
        risk_floor = max(risk_floor, 0.64)

    if ("btc/usdt" in msg or "signal period" in msg or "buy 1% of your account balance" in msg):
        risk_floor = max(risk_floor, 0.52)

    if ("remote data entry" in msg or "online interview" in msg) and "reply yes" in msg:
        risk_floor = max(risk_floor, 0.46)

    if recruitment_hits and generic_signature_hits and positive_professional_hits == 0:
        supporting_reasons.append("The outreach claims to be professional, but it lacks normal business context such as a clear role, deliverables, timeline, or contract details.")
        scores["Social Engineering / Recruitment Scam"] += 14
        signal_groups["thin_professional_context"] = 14
        risk_floor = max(risk_floor, 0.44)

    if recruitment_hits and positive_professional_hits >= 2 and reward_invitation_hits == 0 and conversation_stage_hits == 0:
        supporting_reasons.append("Some normal business context is present, which slightly reduces the chance that this is a low-effort recruitment scam.")
        scores["Social Engineering / Recruitment Scam"] = max(0, scores["Social Engineering / Recruitment Scam"] - 10)
        signal_groups["professional_context_offset"] = -10

    benign_score = 0
    benign_reasons = []
    if benign_phrase_hits:
        benign_score += benign_phrase_hits * 8
        benign_reasons.append("The message contains calm phrases often seen in normal communication or official app notices.")
    if benign_context_hits:
        benign_score += benign_context_hits * 6
        benign_reasons.append("The message contains everyday context such as meetings, reminders, invoices, or personal coordination.")
    if not urls and not sensitive_hits and not urgency_hits and not fear_hits and message_length <= 25:
        benign_score += 10
        benign_reasons.append("The message is short and conversational without links, urgency, or credential requests.")
    if "official app" in msg or "no action required" in msg:
        benign_score += 14
        benign_reasons.append("The message points the user to an existing official channel instead of pushing a direct link.")
    if benign_business_hits >= 2 and not urls and high_severity_hits == 0:
        benign_score += 12
        benign_reasons.append("The wording looks closer to ordinary business or personal communication than to a pressure-based scam message.")
    if benign_business_hits >= 3 and moderate_signal_hits <= 1 and high_severity_hits == 0:
        benign_score += 10
        benign_reasons.append("The message contains multiple normal-context markers and only weak scam-style indicators.")

    if benign_score:
        scores["Phishing Scam"] = max(0, scores["Phishing Scam"] - benign_score * 0.9)
        scores["Bank Scam"] = max(0, scores["Bank Scam"] - benign_score * 0.7)
        scores["Parcel Scam"] = max(0, scores["Parcel Scam"] - benign_score * 0.5)
        scores["Job Scam"] = max(0, scores["Job Scam"] - benign_score * 0.4)
        scores["Crypto Scam"] = max(0, scores["Crypto Scam"] - benign_score * 0.4)
        scores["Social Engineering / Recruitment Scam"] = max(0, scores["Social Engineering / Recruitment Scam"] - benign_score * 0.65)
        signal_groups["benign_context_offset"] = -benign_score

    if not urls and high_severity_hits == 0 and payment_pressure_hits == 0:
        if recruitment_hits == 0 and off_platform_hits == 0 and reward_invitation_hits == 0:
            best_soft_cap = 16 if benign_score >= 10 else 20
            for category in scores:
                scores[category] = min(scores[category], best_soft_cap)
            signal_groups["low_evidence_cap"] = -4 if benign_score >= 10 else -2
        elif recruitment_hits >= 1 and reward_invitation_hits == 0 and conversation_stage_hits == 0 and positive_professional_hits >= 1:
            scores["Social Engineering / Recruitment Scam"] = min(scores["Social Engineering / Recruitment Scam"], 34)
            signal_groups["recruitment_context_cap"] = -6

    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    sorted_scores = sorted(scores.values(), reverse=True)
    runner_up = sorted_scores[1] if len(sorted_scores) > 1 else 0
    margin = max(best_score - runner_up, 0)
    confidence = min(0.99, 0.28 + (best_score / 140) + (margin / 210))

    if best_score < 18:
        return {
            "scam_type": "Unknown / Needs Review",
            "confidence": max(0.3, confidence - 0.2),
            "reasons": supporting_reasons,
            "score": best_score,
            "benign_reasons": benign_reasons,
            "benign_score": benign_score,
            "signal_groups": signal_groups,
            "risk_floor": risk_floor,
            "signal_summary": {
                "urgency_hits": urgency_hits,
                "sensitive_hits": sensitive_hits,
                "money_hits": money_hits,
                "fear_hits": fear_hits,
                "brand_hits": brand_hits,
                "credential_hits": credential_regex_hits,
                "pattern_hits": len(triggered_patterns),
                "link_to_action_hits": link_to_action_hits,
                "recruitment_hits": recruitment_hits,
                "compliment_hits": compliment_hits,
                "reward_invitation_hits": reward_invitation_hits,
                "conversation_stage_hits": conversation_stage_hits,
            },
        }

    return {
        "scam_type": best_type,
        "confidence": confidence,
        "reasons": supporting_reasons,
        "score": best_score,
        "benign_reasons": benign_reasons,
        "benign_score": benign_score,
        "signal_groups": signal_groups,
        "risk_floor": risk_floor,
        "signal_summary": {
            "urgency_hits": urgency_hits,
            "sensitive_hits": sensitive_hits,
            "money_hits": money_hits,
            "fear_hits": fear_hits,
            "brand_hits": brand_hits,
            "credential_hits": credential_regex_hits,
            "pattern_hits": len(triggered_patterns),
            "link_to_action_hits": link_to_action_hits,
            "recruitment_hits": recruitment_hits,
            "compliment_hits": compliment_hits,
            "reward_invitation_hits": reward_invitation_hits,
            "conversation_stage_hits": conversation_stage_hits,
        },
    }


def google_safe_browsing_check(url):
    if not GOOGLE_API_KEY:
        return None, "Google Safe Browsing is not configured."

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "ScamShield", "clientVersion": "3.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": ensure_url_scheme(url)}],
        },
    }

    try:
        res = requests.post(
            endpoint,
            json=payload,
            timeout=8,
            headers={"User-Agent": APP_USER_AGENT},
        )
        data = res.json()
        if "matches" in data:
            return True, "Google Safe Browsing found this URL on a known threat list."
        return False, "Google Safe Browsing did not flag it. That usually means it is not blocklisted yet, not that it is trustworthy."
    except requests.RequestException:
        return None, "Google Safe Browsing could not be reached."


def phishtank_check(url):
    domain = extract_domain(url)
    cached = check_phishtank_cache(domain)
    if cached is not None:
        return cached

    if not PHISHTANK_API_KEY:
        return None, "PhishTank is not configured. A local cache file is supported if you already have feed access."

    try:
        endpoint = "http://checkurl.dev.phishtank.com/checkurl/"
        payload = {
            "url": ensure_url_scheme(url),
            "format": "json",
            "app_key": PHISHTANK_API_KEY,
        }
        headers = {
            "User-Agent": APP_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        res = requests.post(endpoint, data=payload, headers=headers, timeout=10)

        if res.status_code == 509:
            return None, "PhishTank rate-limited this lookup (HTTP 509)."
        if res.status_code >= 400:
            return None, f"PhishTank lookup failed with HTTP {res.status_code}."

        data = res.json()
        results = data.get("results", {})
        in_database = results.get("in_database")
        valid = results.get("valid")
        verified = results.get("verified")

        if in_database and valid:
            update_phishtank_cache_entry(domain, True, "PhishTank confirmed this URL as phishing and the result was cached locally.")
            verification_note = "verified" if verified else "listed"
            return True, f"PhishTank {verification_note} this URL as phishing and the result was cached locally."

        update_phishtank_cache_entry(domain, False, "PhishTank found no phishing record and the result was cached locally.")
        return False, "PhishTank found no phishing record and the result was cached locally."
    except requests.RequestException as exc:
        return None, f"PhishTank request failed. This often happens because the official API endpoint is HTTP-only and may be blocked. Details: {exc.__class__.__name__}."
    except json.JSONDecodeError:
        return None, "PhishTank returned an unreadable response."


def domain_age_check(domain):
    endpoint = f"https://rdap.org/domain/{domain}"
    try:
        res = requests.get(
            endpoint,
            timeout=8,
            headers={"User-Agent": APP_USER_AGENT, "Accept": "application/rdap+json, application/json"},
        )
        if res.status_code == 403:
            return None, None, "Domain age lookup was denied by the RDAP service (HTTP 403)."
        if res.status_code == 404:
            return None, None, "Domain age lookup could not find an authoritative RDAP record (HTTP 404)."
        if res.status_code == 429:
            return None, None, "Domain age lookup was rate-limited by the RDAP service (HTTP 429)."
        if res.status_code >= 500:
            return None, None, f"Domain age lookup failed on the RDAP service side (HTTP {res.status_code})."

        data = res.json()
        dates = []
        for event in data.get("events", []):
            event_name = event.get("eventAction", "").lower()
            event_date = event.get("eventDate")
            if event_date and event_name in {"registration", "registered", "creation"}:
                dates.append(event_date)

        if not dates:
            return None, None, "Domain age could not be determined from RDAP."

        created_at = min(datetime.fromisoformat(item.replace("Z", "+00:00")) for item in dates)
        age_days = (datetime.now(timezone.utc) - created_at).days

        if age_days < 7:
            return age_days, 0.99, f"The domain appears to be only {age_days} days old, which is an extremely strong scam signal."
        if age_days < 30:
            return age_days, 0.94, f"The domain appears to be only {age_days} days old, which is a very strong scam signal."
        if age_days < 90:
            return age_days, 0.78, f"The domain appears to be {age_days} days old, which is still unusually new for a trusted service."
        if age_days < 365:
            return age_days, 0.42, f"The domain appears to be {age_days} days old, which is still somewhat young."
        return age_days, 0.08, f"The domain appears to be {age_days} days old."
    except requests.RequestException as exc:
        return None, None, f"Domain age lookup failed: {exc.__class__.__name__}."
    except (ValueError, json.JSONDecodeError):
        return None, None, "Domain age lookup returned unreadable data."


def virus_total_check(url):
    if not VT_API_KEY:
        return None, None, "VirusTotal is not configured."

    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    try:
        url_id = base64.urlsafe_b64encode(ensure_url_scheme(url).encode()).decode().strip("=")
        headers["User-Agent"] = APP_USER_AGENT
        res = requests.get(f"{endpoint}/{url_id}", headers=headers, timeout=10)
        data = res.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values()) if stats else 0
        weighted_hits = malicious + (suspicious * 0.6)

        if malicious >= 10:
            vt_risk = 0.98
        elif malicious >= 5:
            vt_risk = 0.94
        elif malicious >= 1:
            vt_risk = 0.84
        elif suspicious >= 3:
            vt_risk = 0.62
        elif suspicious >= 1:
            vt_risk = 0.48
        else:
            vt_risk = min(0.08, weighted_hits / max(total, 1))

        if malicious or suspicious:
            return vt_risk, stats, f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections."
        if stats:
            return 0.02, stats, f"VirusTotal found no malicious verdicts in the current scan summary ({harmless} harmless engines)."
        return None, None, "VirusTotal returned no analysis details for this URL."
    except requests.RequestException:
        return None, None, "VirusTotal could not be reached."


def combine_risk_scores(message_analysis, link_signals):
    reasons = []
    message_risk = min(0.95, 0.12 + (message_analysis["score"] / 120))
    message_risk = max(message_risk, message_analysis.get("risk_floor", 0.0))
    overall = message_risk
    signal_summary = message_analysis.get("signal_summary", {})
    high_severity_hits = (
        signal_summary.get("sensitive_hits", 0)
        + signal_summary.get("fear_hits", 0)
        + signal_summary.get("credential_hits", 0)
        + signal_summary.get("link_to_action_hits", 0)
    )
    recruitment_only = (
        signal_summary.get("recruitment_hits", 0) > 0
        and signal_summary.get("reward_invitation_hits", 0) == 0
        and signal_summary.get("conversation_stage_hits", 0) == 0
        and high_severity_hits == 0
    )

    if message_analysis["reasons"]:
        reasons.extend(message_analysis["reasons"][:3])

    if link_signals:
        max_link_risk = max(signal["risk_score"] / 100 for signal in link_signals)
        average_link_risk = sum(signal["risk_score"] / 100 for signal in link_signals) / len(link_signals)
        overall = (message_risk * 0.35) + (max_link_risk * 0.45) + (average_link_risk * 0.20)
    else:
        if message_analysis.get("benign_score", 0) >= 16 and high_severity_hits == 0:
            overall = min(overall, 0.24)
        elif message_analysis.get("benign_score", 0) >= 10 and high_severity_hits == 0:
            overall = min(overall, 0.32)
        elif recruitment_only:
            overall = min(overall, 0.39)

    for signal in link_signals:
        signal_risk = signal["risk_score"] / 100

        if signal["vt_risk"] is not None and signal["vt_risk"] >= 0.84:
            overall = max(overall, 0.9, signal_risk)
        elif signal["vt_risk"] is not None and signal["vt_risk"] >= 0.62:
            overall = max(overall, 0.72, signal_risk)
        elif signal["google_flagged"] is True or signal["phishtank_flagged"] is True:
            overall = max(overall, 0.78, signal_risk)
        else:
            overall = max(overall, signal_risk)

        if signal["reasons"]:
            reasons.append(f"Domain signal for '{signal['domain']}': {signal['reasons'][0]}")
        if signal["domain_age_message"]:
            reasons.append(signal["domain_age_message"])
        if signal["vt_message"] and signal["vt_risk"] not in (None, 0.02):
            reasons.append(signal["vt_message"])

    return min(overall, 0.99), reasons[:6]


def provider_status_from_message(provider_name, message, configured=True):
    message = message or ""
    lowered = message.lower()

    if not configured or "not configured" in lowered:
        return {
            "name": provider_name,
            "status": "Not Configured",
            "severity": "neutral",
            "detail": message,
        }
    if "rate-limited" in lowered or "http 429" in lowered or "http 509" in lowered:
        return {
            "name": provider_name,
            "status": "Rate Limited",
            "severity": "warning",
            "detail": message,
        }
    if "failed" in lowered or "unavailable" in lowered or "could not be reached" in lowered or "unreadable" in lowered or "denied" in lowered:
        return {
            "name": provider_name,
            "status": "Unavailable",
            "severity": "warning",
            "detail": message,
        }
    return {
        "name": provider_name,
        "status": "Online",
        "severity": "good",
        "detail": message,
    }


def build_provider_statuses(link_reports, include_vt=False):
    if not link_reports:
        return [
            provider_status_from_message("Google Safe Browsing", "Waiting for a URL to scan.", configured=bool(GOOGLE_API_KEY)),
            provider_status_from_message("PhishTank", "Waiting for a URL to scan.", configured=bool(PHISHTANK_API_KEY)),
            provider_status_from_message("RDAP Domain Age", "Waiting for a URL to scan.", configured=True),
            provider_status_from_message("VirusTotal", "Deep scan not requested yet.", configured=bool(VT_API_KEY)),
        ]

    first_report = link_reports[0]
    statuses = [
        provider_status_from_message("Google Safe Browsing", first_report.get("google_safe_browsing"), configured=bool(GOOGLE_API_KEY)),
        provider_status_from_message("PhishTank", first_report.get("phishtank"), configured=bool(PHISHTANK_API_KEY)),
        provider_status_from_message("RDAP Domain Age", first_report.get("domain_age_message"), configured=True),
    ]

    if include_vt:
        statuses.append(provider_status_from_message("VirusTotal", first_report.get("vt_message"), configured=bool(VT_API_KEY)))
    else:
        statuses.append(provider_status_from_message("VirusTotal", "Deep scan not requested yet.", configured=bool(VT_API_KEY)))

    return statuses


def build_explainability(message_analysis, link_reports):
    explainability = []
    for reason in message_analysis.get("reasons", [])[:4]:
        explainability.append({"source": "Message Signal", "detail": reason})

    for report in sorted(link_reports, key=lambda item: item["risk_score"], reverse=True)[:2]:
        if report.get("reasons"):
            explainability.append({
                "source": f"Link Signal: {report['domain']}",
                "detail": report["reasons"][0],
            })
        if report.get("domain_age_message"):
            explainability.append({
                "source": f"Domain Age: {report['domain']}",
                "detail": report["domain_age_message"],
            })
        if report.get("vt_message") and report.get("vt_risk") not in (None, 0.02):
            explainability.append({
                "source": f"VirusTotal: {report['domain']}",
                "detail": report["vt_message"],
            })

    deduped = []
    seen = set()
    for item in explainability:
        key = (item["source"], item["detail"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped[:6]


def build_evidence_breakdown(message_analysis, link_reports):
    breakdown = []

    for group, value in sorted(message_analysis.get("signal_groups", {}).items(), key=lambda item: abs(item[1]), reverse=True):
        label = group.replace("pattern:", "pattern ").replace("_", " ").title()
        breakdown.append({
            "source": "Message",
            "label": label,
            "impact": round(value, 1),
        })

    for report in sorted(link_reports, key=lambda item: item["risk_score"], reverse=True)[:3]:
        breakdown.append({
            "source": "Link",
            "label": f"{report['domain']} overall link risk",
            "impact": report["risk_score"],
        })
        if report.get("domain_age_risk") is not None:
            breakdown.append({
                "source": "Link",
                "label": f"{report['domain']} domain age",
                "impact": round(report["domain_age_risk"] * 100, 1),
            })
        if report.get("vt_risk") is not None:
            breakdown.append({
                "source": "Link",
                "label": f"{report['domain']} VirusTotal",
                "impact": round(report["vt_risk"] * 100, 1),
            })

    return breakdown[:8]


def build_recommended_actions(scan_summary, message_analysis, link_reports):
    actions = []
    risk = scan_summary["risk_percent"]
    scam_type = scan_summary["scam_type"]
    has_link = bool(link_reports)
    high_risk_link = any(report["risk_score"] >= 75 for report in link_reports)

    if risk >= 75:
        actions.append({
            "label": "Block",
            "detail": "Do not click, reply, or continue contact. Treat the message as hostile until independently verified.",
        })
    if has_link:
        actions.append({
            "label": "Verify",
            "detail": "Open the official app or manually type the real website instead of using the link in the message.",
        })
    if risk >= 55 or high_risk_link:
        actions.append({
            "label": "Report",
            "detail": "Report the message to the platform, email provider, or your organization’s security team so the sender or URL can be reviewed.",
        })
    if risk < 45 and scam_type == "Unknown / Needs Review":
        actions.append({
            "label": "Ignore",
            "detail": "Do not engage until you can confirm the sender through a trusted channel. If it is unsolicited, ignoring it is often the safest move.",
        })
    else:
        actions.append({
            "label": "Ignore",
            "detail": "If the sender cannot be verified quickly, stop interacting and leave the message unanswered.",
        })

    return actions[:4]


def build_link_report(url, include_vt=False):
    domain = extract_domain(url)
    expanded_url, expansion_message = expand_short_url(url)
    url_to_score = expanded_url or url
    domain = extract_domain(url_to_score)
    domain_risk, domain_reasons = score_domain(domain)
    structure_risk, structure_reasons = score_url_structure(url_to_score)
    heuristic_risk = min(0.99, domain_risk + structure_risk)
    reasons = domain_reasons + structure_reasons
    google_flagged, google_message = google_safe_browsing_check(url_to_score)
    phishtank_flagged, phishtank_message = phishtank_check(url_to_score)
    domain_age_days, domain_age_risk, domain_age_message = domain_age_check(domain)
    vt_risk = None
    vt_stats = None
    vt_message = None

    weighted_risk = heuristic_risk * 0.68
    if google_flagged is True:
        weighted_risk += 0.22
    elif google_flagged is False:
        weighted_risk += 0.02

    if phishtank_flagged is True:
        weighted_risk += 0.24
    elif phishtank_flagged is False:
        weighted_risk += 0.02

    if domain_age_risk is not None:
        weighted_risk += domain_age_risk * 0.34

    if include_vt:
        vt_risk, vt_stats, vt_message = virus_total_check(url_to_score)
        if vt_risk is not None:
            weighted_risk += vt_risk * 0.36

    if heuristic_risk >= 0.7:
        weighted_risk = max(weighted_risk, 0.78)
    elif heuristic_risk >= 0.55:
        weighted_risk = max(weighted_risk, 0.64)
    elif heuristic_risk >= 0.42:
        weighted_risk = max(weighted_risk, 0.52)

    if heuristic_risk >= 0.64 and (google_flagged is not False and phishtank_flagged is not False):
        weighted_risk = max(weighted_risk, 0.76)

    if vt_risk is not None and vt_risk >= 0.84:
        weighted_risk = max(weighted_risk, 0.9)
    elif google_flagged is True or phishtank_flagged is True:
        weighted_risk = max(weighted_risk, 0.78)
    elif domain_age_days is not None and domain_age_days < 7:
        weighted_risk = max(weighted_risk, 0.78)
    elif domain_age_days is not None and domain_age_days < 30:
        weighted_risk = max(weighted_risk, 0.62)
    elif domain_age_days is not None and domain_age_days < 90 and heuristic_risk >= 0.32:
        weighted_risk = max(weighted_risk, 0.52)
    elif domain_age_risk is not None and domain_age_risk >= 0.7 and heuristic_risk >= 0.45:
        weighted_risk = max(weighted_risk, 0.68)

    final_risk = min(weighted_risk, 0.99)
    status = "high-risk" if final_risk >= 0.7 else "medium-risk" if final_risk >= 0.4 else "low-risk"

    return {
        "url": url,
        "expanded_url": expanded_url,
        "expansion_message": expansion_message,
        "domain": domain,
        "risk_score": round(final_risk * 100),
        "status": status,
        "reasons": reasons,
        "google_safe_browsing": google_message,
        "phishtank": phishtank_message,
        "google_flagged": google_flagged,
        "phishtank_flagged": phishtank_flagged,
        "domain_age_days": domain_age_days,
        "domain_age_risk": domain_age_risk,
        "domain_age_message": domain_age_message,
        "vt_risk": vt_risk,
        "vt_stats": vt_stats,
        "vt_message": vt_message,
    }


def generate_explanation(scan_summary, urls, reasons, message_analysis, link_reports):
    explanation = []
    scam_type = scan_summary["scam_type"]
    signal_summary = message_analysis.get("signal_summary", {})

    if scam_type != "Unknown / Needs Review":
        explanation.append(f"Assessment: this content aligns with {scam_type.lower()} behavior and should be treated as potentially malicious.")
    else:
        explanation.append("Assessment: this content is not clearly benign, but it does not yet align strongly enough with one single scam family.")

    if signal_summary.get("sensitive_hits"):
        explanation.append("Primary finding: the sender requests account access, security codes, credentials, or other sensitive information.")

    if signal_summary.get("urgency_hits") or signal_summary.get("fear_hits"):
        explanation.append("Primary finding: the language uses pressure, urgency, or fear to reduce the chance of careful verification.")

    if signal_summary.get("brand_hits") and signal_summary.get("sensitive_hits"):
        explanation.append("Primary finding: the message appears to impersonate a trusted company or financial service while asking for action.")

    if signal_summary.get("recruitment_hits"):
        explanation.append("Primary finding: the message uses creator, recruiter, ambassador, or partnership-style outreach that can be used to start a social-engineering conversation.")

    if signal_summary.get("compliment_hits") and signal_summary.get("reward_invitation_hits"):
        explanation.append("Primary finding: the outreach combines flattery with a reward or incentive, which is a common trust-building tactic in recruitment scams.")

    if signal_summary.get("conversation_stage_hits"):
        explanation.append("Primary finding: the sender wants you to reply first and only reveal the next step later, which is a common way scam funnels avoid immediate scrutiny.")

    if urls and link_reports:
        highest_link = max(link_reports, key=lambda report: report["risk_score"])
        explanation.append(
            f"Link assessment: the strongest URL signal is '{highest_link['domain']}' with an overall link risk of {highest_link['risk_score']}%."
        )

    explanation.extend(reasons[:5])

    if urls:
        explanation.append("Analyst note: a reputation service saying 'safe' only means the URL is not currently blocklisted. Newly created scam domains often appear before threat feeds catch up.")

    explanation.extend([
        "Recommended action: do not click the link or reply with passwords, OTP codes, banking details, personal IDs, or wallet phrases.",
        "Safe next step: verify through the official app, a website you type manually, or a phone number from a real statement or bank card.",
        "Plain-English summary: this message is risky because it tries to create pressure and move you toward a link, payment, or sensitive account action.",
    ])
    return explanation


def run_scan(message, include_vt=False):
    urls = extract_urls(message)
    iocs = extract_iocs(message, urls)
    message_analysis = score_message(message, urls)
    link_reports = [build_link_report(url, include_vt=include_vt) for url in urls]
    final_risk, final_reasons = combine_risk_scores(message_analysis, link_reports)
    provider_statuses = build_provider_statuses(link_reports, include_vt=include_vt)
    explainability = build_explainability(message_analysis, link_reports)
    evidence_breakdown = build_evidence_breakdown(message_analysis, link_reports)

    scan_summary = {
        "scam_type": message_analysis["scam_type"],
        "confidence": round(message_analysis["confidence"] * 100, 1),
        "risk_percent": round(final_risk * 100, 1),
        "status": "High Risk" if final_risk >= 0.75 else "Medium Risk" if final_risk >= 0.45 else "Low Risk",
        "confidence_label": "Classification Confidence",
        "risk_label": "Overall Risk",
    }
    explanation_lines = generate_explanation(scan_summary, urls, final_reasons, message_analysis, link_reports)
    recommended_actions = build_recommended_actions(scan_summary, message_analysis, link_reports)
    return scan_summary, explanation_lines, link_reports, provider_statuses, explainability, recommended_actions, iocs, evidence_breakdown


def get_view_mode():
    return request.form.get("view_mode") or request.args.get("view") or "simple"


def build_page_context(include_vt=False, message=""):
    return {
        "message": message,
        "scan_summary": None,
        "explanation_lines": None,
        "link_reports": [],
        "deep_results": [] if include_vt else None,
        "provider_statuses": build_provider_statuses([], include_vt=include_vt),
        "explainability": [],
        "recommended_actions": [],
        "iocs": dict(EMPTY_IOCS),
        "evidence_breakdown": [],
        "view_mode": get_view_mode(),
        "privacy_notes": PRIVACY_NOTES,
        "scam_examples": SCAM_EXAMPLES,
        "safe_examples": SAFE_EXAMPLES,
    }


def render_index(context):
    return render_template("index.html", **context)


@app.route("/", methods=["GET", "POST"])
def home():
    context = build_page_context(include_vt=False)

    if request.method == "POST":
        message = request.form["message"].strip()
        context["message"] = message
        if message:
            (
                context["scan_summary"],
                context["explanation_lines"],
                context["link_reports"],
                context["provider_statuses"],
                context["explainability"],
                context["recommended_actions"],
                context["iocs"],
                context["evidence_breakdown"],
            ) = run_scan(message, include_vt=False)

    return render_index(context)


@app.route("/deep", methods=["POST"])
def deep_scan():
    message = request.form["message"].strip()
    context = build_page_context(include_vt=True, message=message)

    if message:
        (
            context["scan_summary"],
            context["explanation_lines"],
            context["link_reports"],
            context["provider_statuses"],
            context["explainability"],
            context["recommended_actions"],
            context["iocs"],
            context["evidence_breakdown"],
        ) = run_scan(message, include_vt=True)
        for report in context["link_reports"]:
            context["deep_results"].append({
                "url": report["url"],
                "status": "Flagged" if report["vt_risk"] and report["vt_risk"] > 0.05 else "Not Flagged" if report["vt_risk"] is not None else "Unavailable",
                "message": report["vt_message"] or "VirusTotal was not used for this result.",
            })

    return render_index(context)


if __name__ == "__main__":
    app.run()
