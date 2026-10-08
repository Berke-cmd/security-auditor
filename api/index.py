import os
import re
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import httpx

app = FastAPI(title="Security & Defensive Auditor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SAST_RULES = [
    {
        "id": "OWASP-A02-01",
        "severity": "HIGH",
        "owasp": "A02:2021 - Cryptographic Failures",
        "category": "Kriptografi",
        "pattern": r"(?i)\b(hashlib\.(md5|sha1)|crypto\.createHash\(['\"](md5|sha1)['\"]\)|md5\(|sha1\()",
        "exts": {".py", ".js", ".ts", ".php"},
        "title": "Zayıf Özetleme/Şifreleme Algoritması (MD5/SHA-1)",
        "remediation": "Parolalar için Argon2id veya bcrypt; veri bütünlüğü için SHA-256 tercih edin.",
    },
    {
        "id": "OWASP-A02-02",
        "severity": "CRITICAL",
        "owasp": "A02:2021 - Cryptographic Failures",
        "category": "Gizli Bilgi İfşası",
        "pattern": r"(?i)(api[_-]?key|secret[_-]?key|aws[_-]?secret|password|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{12,}['\"]",
        "exts": {".py", ".js", ".jsx", ".ts", ".php"},
        "title": "Sabit Kodlanmış Gizli Anahtar / Parola",
        "remediation": "Hassas kimlik doğrulama anahtarlarını kodda tutmayın; ortam değişkenleri (.env) kullanın.",
    },
    {
        "id": "OWASP-A03-01",
        "severity": "HIGH",
        "owasp": "A03:2021 - Injection",
        "category": "SQL Injection",
        "pattern": r"(?i)(execute|query)\s*\(\s*(f['\"].*SELECT|f['\"].*INSERT|f['\"].*UPDATE|\$.*SELECT|\$.*INSERT|\$.*UPDATE)",
        "exts": {".py", ".js", ".ts", ".php"},
        "title": "Dinamik String Birleştirmeli SQL Sorgusu",
        "remediation": "Parametreli sorgular (Prepared Statements) veya ORM yapıları kullanın.",
    },
    {
        "id": "OWASP-A03-02",
        "severity": "CRITICAL",
        "owasp": "A03:2021 - Injection",
        "category": "Komut Enjeksiyonu",
        "pattern": r"\b(system|shell_exec|exec|passthru|proc_open|eval|subprocess\.(Popen|call|run)\([^)]*shell\s*=\s*True)\s*\(",
        "exts": {".py", ".js", ".ts", ".php"},
        "title": "Güvensiz Sistem / Dinamik Kod Yürütme",
        "remediation": "Dış sistem komutlarını çalıştırmaktan kaçının; parametreleri dizi olarak güvenli fonksiyonlara iletin.",
    },
    {
        "id": "OWASP-A01-01",
        "severity": "MEDIUM",
        "owasp": "A01:2021 - Broken Access Control",
        "category": "Açık Yönlendirme",
        "pattern": r"(?i)(header\s*\(['\"]Location:\s*['\"]\s*\.\s*\$_(GET|POST|REQUEST)|redirect\s*\(\s*request\.(args|GET|POST))",
        "exts": {".py", ".php"},
        "title": "Doğrulanmamış URL Yönlendirmesi (Open Redirect)",
        "remediation": "Yönlendirme öncesinde hedef URL'yi beyaz liste (allowlist) doğrulamasına tabi tutun.",
    },
]

WIFI_RULES = [
    {
        "pattern": r"(?i)(encryption|auth|security)\s*[:=]\s*['\"]?(wep|open|none)['\"]?",
        "severity": "CRITICAL",
        "title": "Güvensiz / Şifresiz Kablosuz Ağ Protokolü",
        "detail": "Ağ yapılandırmasında WEP veya Açık şifreleme tespit edildi.",
        "remediation": "En az WPA2-AES (CCMP) veya WPA3 standardına geçiş yapın.",
    },
    {
        "pattern": r"(?i)(encryption|cipher)\s*[:=]\s*['\"]?tkip['\"]?",
        "severity": "HIGH",
        "title": "Zayıf Şifreleme Algoritması (TKIP)",
        "detail": "TKIP protokolü güvenli kabul edilmemektedir.",
        "remediation": "Yalnızca AES/CCMP şifrelemesini zorunlu kılın.",
    },
    {
        "pattern": r"(?i)(wps|wps_state|wps_enable)\s*[:=]\s*['\"]?(1|true|enable|enabled)['\"]?",
        "severity": "HIGH",
        "title": "WPS (Wi-Fi Protected Setup) Etkin",
        "detail": "WPS PIN mekanizması kaba kuvvet saldırılarına karşı risklidir.",
        "remediation": "Yönlendirici ayarlarından WPS özelliğini tamamen devre dışı bırakın.",
    },
]

def audit_zip(zip_path: str) -> List[Dict[str, str]]:
    findings = []
    with tempfile.TemporaryDirectory() as temp_dir:
        base_path = Path(temp_dir).resolve()
        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in archive.infolist():
                target_path = (base_path / member.filename).resolve()
                if not str(target_path).startswith(str(base_path)):
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Arşiv Güvenliği",
                        "owasp": "A01:2021 - Broken Access Control",
                        "title": "Zip Slip Dizin Dışına Çıkma Riski",
                        "detail": f"Dizin dışına taşan dosya: {member.filename}",
                        "remediation": "Arşiv içeriğini güvenilir kaynaklardan temin edin.",
                    })
                    return findings
            archive.extractall(temp_dir)

        for root, _, files in os.walk(temp_dir):
            for file_name in files:
                ext = Path(file_name).suffix.lower()
                file_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(file_path, temp_dir)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        lines = content.splitlines()
                except Exception:
                    continue

                for line_no, line in enumerate(lines, start=1):
                    for rule in SAST_RULES:
                        if ext in rule["exts"] and re.search(rule["pattern"], line):
                            findings.append({
                                "severity": rule["severity"],
                                "owasp": rule["owasp"],
                                "category": f"SAST / {rule['category']}",
                                "title": rule["title"],
                                "detail": f"Dosya: {rel_path} (Satır {line_no})\nKod: {line.strip()[:140]}",
                                "remediation": rule["remediation"],
                            })

                if ext in {".conf", ".cfg", ".ini", ".xml", ".yaml", ".json"}:
                    for w_rule in WIFI_RULES:
                        if re.search(w_rule["pattern"], content):
                            findings.append({
                                "severity": w_rule["severity"],
                                "owasp": "A05:2021 - Security Misconfiguration",
                                "category": "Wi-Fi & Ağ Altyapısı",
                                "title": w_rule["title"],
                                "detail": f"Yapılandırma Dosyası: {rel_path}\nBulgu: {w_rule['detail']}",
                                "remediation": w_rule["remediation"],
                            })
    return findings


async def audit_url(url: str) -> List[Dict[str, str]]:
    findings = []
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(verify=True, follow_redirects=True, timeout=8.0) as client:
            res = await client.get(url)
            headers = res.headers

            header_checks = {
                "Content-Security-Policy": (
                    "HIGH",
                    "A03:2021 - Injection",
                    "XSS saldırılarını önlemek için CSP başlığı tanımlanmalıdır.",
                ),
                "Strict-Transport-Security": (
                    "MEDIUM",
                    "A05:2021 - Security Misconfiguration",
                    "İletişimi zorunlu HTTPS üzerinde tutmak için HSTS eklenmelidir.",
                ),
                "X-Frame-Options": (
                    "MEDIUM",
                    "A01:2021 - Broken Access Control",
                    "Clickjacking saldırılarına karşı X-Frame-Options eklenmelidir.",
                ),
                "X-Content-Type-Options": (
                    "LOW",
                    "A05:2021 - Security Misconfiguration",
                    "MIME türü koruması için 'nosniff' eklenmelidir.",
                ),
            }

            for header, (sev, owasp_cat, fix) in header_checks.items():
                if header not in headers:
                    findings.append({
                        "severity": sev,
                        "owasp": owasp_cat,
                        "category": "Güvenlik Başlığı",
                        "title": f"Eksik Başlık: {header}",
                        "detail": f"Sunucu yanıtında '{header}' başlığı bulunamadı.",
                        "remediation": fix,
                    })

            if headers.get("Access-Control-Allow-Origin") == "*":
                findings.append({
                    "severity": "MEDIUM",
                    "owasp": "A01:2021 - Broken Access Control",
                    "category": "CORS Yapılandırması",
                    "title": "Aşırı Geniş CORS İzni ('*')",
                    "detail": "Sunucu tüm kaynaklardan gelen istekleri kabul ediyor.",
                    "remediation": "CORS politikasında '*' yerine sadece güvenilir domainleri tanımlayın.",
                })

            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                if "httponly" not in set_cookie.lower():
                    findings.append({
                        "severity": "HIGH",
                        "owasp": "A07:2021 - Identification & Authentication Failures",
                        "category": "Çerez Güvenliği",
                        "title": "HttpOnly Bayrağı Eksik",
                        "detail": "Oturum çerezi JavaScript tarafından okunabilir.",
                        "remediation": "Hassas oturum çerezlerine 'HttpOnly' bayrağı ekleyin.",
                    })
                if "secure" not in set_cookie.lower() and url.startswith("https"):
                    findings.append({
                        "severity": "HIGH",
                        "owasp": "A02:2021 - Cryptographic Failures",
                        "category": "Çerez Güvenliği",
                        "title": "Secure Bayrağı Eksik",
                        "detail": "Çerez şifrelenmemiş HTTP üzerinden sızdırılabilir.",
                        "remediation": "Çerezlere 'Secure' bayrağı ekleyin.",
                    })

            soup = BeautifulSoup(res.text, "html.parser")
            pw_fields = soup.find_all("input", {"type": "password"})
            if pw_fields and not url.startswith("https://"):
                findings.append({
                    "severity": "CRITICAL",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "category": "Form Güvenliği",
                    "title": "HTTP Üzerinde Şifre Girişi",
                    "detail": "Şifre formu şifrelenmemiş bağlantıda sunuluyor.",
                    "remediation": "Trafiği zorunlu HTTPS protokolüne taşıyın.",
                })

    except Exception as e:
        findings.append({
            "severity": "HIGH",
            "owasp": "A05:2021 - Security Misconfiguration",
            "category": "Bağlantı Hatası",
            "title": "Web Uygulamasına Erişilemedi",
            "detail": str(e),
            "remediation": "Hedef URL'nin erişilebilir olduğunu doğrulayın.",
        })

    return findings

@app.get("/")
async def read_index():
    """Yerel geliştirme sırasında public/index.html dosyasını ekrana basar."""
    html_path = Path(__file__).resolve().parent.parent / "public" / "index.html"
    if html_path.exists():
        return FileResponse(html_path)
    return {"message": "public/index.html bulunamadi"}


@app.post("/api/scan")
async def scan(
    target_url: Optional[str] = Form(None),
    zip_file: Optional[UploadFile] = File(None),
):
    findings: List[Dict[str, str]] = []
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if zip_file and zip_file.filename:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            tmp.write(await zip_file.read())
            tmp_path = tmp.name

        try:
            zip_findings = audit_zip(tmp_path)
            findings.extend(zip_findings)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    if target_url and target_url.strip():
        url_findings = await audit_url(target_url.strip())
        findings.extend(url_findings)

    for f in findings:
        sev = f["severity"].upper()
        if sev in stats:
            stats[sev] += 1

    return JSONResponse({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target_url or (zip_file.filename if zip_file else "Bilinmeyen"),
        "stats": stats,
        "findings": findings,
    })