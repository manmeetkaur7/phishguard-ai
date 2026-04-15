import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "account suspended",
    "urgent",
    "click here",
    "login now",
    "confirm password",
    "reset your password",
    "security alert",
    "unauthorized login",
    "payment failed",
    "limited access",
    "update billing",
    "security alert",
    "unauthorized activity",
    "billing issue",
    "customer support",
    "account locked",
    "confirm identity",
    "action required",
    "immediately",
]

PRIZE_KEYWORDS = [
    "win",
    "winner",
    "prize",
    "congratulations",
    "lottery",
    "claim your prize",
    "gift card",
    "reward",
    "free gift",
    "exclusive offer",
    "limited time offer",
    "enter to win",
    "instant cash",
    "cash prize",
    "grand prize",
    "no purchase necessary",
    "click to claim",
    "you have been selected",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
]

TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
]

def extract_urls(text: str):
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+)", text)

def has_ip_url(text: str):
    return bool(re.search(r"https?://(?:\d{1,3}\.){3}\d{1,3}", text))

def has_shortened_url(text: str):
    text = text.lower()
    return any(s in text for s in SHORTENERS)

def suspicious_keywords_found(text: str):
    text = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]

def prize_keywords_found(text: str):
    text = text.lower()
    return [kw for kw in PRIZE_KEYWORDS if kw in text]

def detect_attack_type(text: str, keywords: list[str], urls: list[str]):
    normalized = text.lower()

    if any(kw in normalized for kw in PRIZE_KEYWORDS):
        return "Prize scam"
    if re.search(r"\b(job|recruiter|hiring|interview|career)\b", normalized):
        return "Job scam"
    if re.search(r"\b(visa|immigration|passport|green card|immigrant|immigration)\b", normalized):
        return "Visa/Immigration scam"
    if re.search(r"\b(package|delivery|tracking|parcel|shipment|UPS|FedEx|DHL)\b", normalized):
        return "Package delivery scam"
    if re.search(r"\b(bank|account|payment|transaction|invoice|verify|secure|paypal|stripe)\b", normalized):
        return "Banking/payment scam"
    if re.search(r"\b(otp|one[- ]time code|verification code|PIN|code)\b", normalized):
        return "OTP/code scam"
    if re.search(r"\b(tech support|support team|help desk|computer issue|virus|malware|system update)\b", normalized):
        return "Tech support scam"
    if re.search(r"\b(call transcript|call|voicemail|phone call|phone)\b", normalized):
        return "Suspicious call transcript"
    if re.search(r"\b(whatsapp|sms|text message|message|whatsapp scam|sms scam)\b", normalized):
        return "WhatsApp/SMS scam"
    if re.search(r"\b(phishing|password|login|account suspended|verify your account|security alert)\b", normalized):
        return "Phishing email"
    if urls:
        return "Suspicious URL"
    return "Unknown"

def has_urgent_tone(text: str):
    urgent_words = ["urgent", "immediately", "asap", "now", "action required", "final warning"]
    text = text.lower()
    return any(word in text for word in urgent_words)

def suspicious_domain(url: str):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")

        if not domain:
            return False

        if any(td in domain for td in TRUSTED_DOMAINS):
            return False

        return "-" in domain or domain.count(".") > 2 or any(ch.isdigit() for ch in domain)
    except:
        return False

def analyze_text(input_text: str, input_type: str):
    score = 0
    explanations = []

    keywords = suspicious_keywords_found(input_text)
    prize_keywords = prize_keywords_found(input_text)
    urls = extract_urls(input_text)

    indicators = {
        "urgent_words": False,
        "shortened_url": False,
        "ip_url": False,
        "suspicious_keywords_count": len(keywords),
        "prize_keywords_count": len(prize_keywords),
        "suspicious_domains": [],
        "urls_found": urls,
    }

    if keywords:
        score += min(len(keywords) * 12, 36)
        explanations.append(f"Suspicious wording found: {', '.join(keywords[:4])}")

    if prize_keywords:
        score += min(len(prize_keywords) * 18, 45)
        explanations.append(f"Prize scam wording found: {', '.join(prize_keywords[:4])}")

    if has_urgent_tone(input_text):
        score += 15
        indicators["urgent_words"] = True
        explanations.append("Uses urgent language to pressure the user.")

    if has_shortened_url(input_text):
        score += 18
        indicators["shortened_url"] = True
        explanations.append("Contains a shortened link that may hide the destination.")

    if has_ip_url(input_text):
        score += 20
        indicators["ip_url"] = True
        explanations.append("Contains an IP-based URL instead of a normal domain.")

    flagged_domains = [url for url in urls if suspicious_domain(url)]
    if flagged_domains:
        score += min(len(flagged_domains) * 12, 24)
        indicators["suspicious_domains"] = flagged_domains
        explanations.append("Contains suspicious-looking domain patterns.")

    score = min(score, 100)

    if score >= 65:
        verdict = "Scam"
        confidence = "High"
    elif score >= 35:
        verdict = "Suspicious"
        confidence = "Medium"
    else:
        verdict = "Safe"
        confidence = "Low"

    if not explanations:
        explanations.append("No major phishing indicators were detected.")

    return {
        "verdict": verdict,
        "score": round(score / 100, 2),
        "confidence": confidence,
        "attack_type": detect_attack_type(input_text, keywords + prize_keywords, urls),
        "explanations": explanations,
        "indicators": indicators
    }