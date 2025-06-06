# scanner.py
from datetime import datetime
import os, time
import pandas as pd
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import textwrap
from bs4 import BeautifulSoup
from fpdf import FPDF
from fpdf.enums import XPos, YPos  # type: ignore
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import NoAlertPresentException
from concurrent.futures import ThreadPoolExecutor

import ai_detector

# XSS 페이로드 리스트
xss_payloads = [
    "<script>alert(1)</script>", "'><svg/onload=confirm(1)>",
    "<img src=x onerror=alert(1)>", "<svg><script>confirm(1)</script>",
    "<body onload=prompt(1)>"
]

# PDF 리포트용 텍스트 줄바꿈
def safe_multiline(pdf: FPDF, text: str, width: int = 90):
    for line in textwrap.wrap(text, width=width):
        pdf.cell(0, 8, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


# 크롤러: 링크 수집
def fetch_links(url: str, base_url: str, visited: set) -> list:
    found_links = []
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        res = requests.get(url, headers=headers, timeout=3)
        soup = BeautifulSoup(res.text, "html.parser")
        visited.add(url)
        if "?" in url and "=" in url:
            found_links.append(('get', url))
        if soup.find("form"):
            found_links.append(('form', url))
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a['href'])
            if urlparse(link).netloc == urlparse(base_url).netloc and link not in visited:
                found_links.append(('next', link))
    except:
        pass
    return found_links


# 제한된 범위 사이트 크롤링
def smart_crawl_site(base_url: str, max_links: int) -> list:
    visited, to_visit = set(), [base_url]
    get_targets, form_targets = [], []
    with ThreadPoolExecutor(max_workers=10) as executor:
        while to_visit and len(visited) < max_links:
            futures = [executor.submit(fetch_links, u, base_url, visited) for u in to_visit[:10]]
            to_visit = to_visit[10:]
            for f in futures:
                for kind, link in f.result():
                    if kind == 'get': get_targets.append(link)
                    elif kind == 'form': form_targets.append(link)
                    elif kind == 'next' and link not in visited: to_visit.append(link)
    no_param = [u for u in visited if '?' not in u]
    fake_params = [u + '?test=x' for u in no_param]
    return list(set(get_targets + fake_params + form_targets))

# 보안 헤더 검사
def run_scan(url: str) -> dict:
    checked_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    security_headers = {
        "Content-Security-Policy": ["default-src 'self'"],
        "X-Frame-Options": ["deny","sameorigin"],
        "Strict-Transport-Security": ["max-age=63072000"],
        "X-Content-Type-Options": ["nosniff"],
        "Referrer-Policy": ["no-referrer","strict-origin-when-cross-origin"]
    }
    rec_detail = {
        "Content-Security-Policy": "출처별 리소스 제어",
        "X-Frame-Options": "클릭재킹 방지",
        "Strict-Transport-Security": "HTTPS 강제",
        "X-Content-Type-Options": "MIME 스니핑 방지",
        "Referrer-Policy": "Referrer 정보 제한"
    }
    try:
        res = requests.get(url, timeout=5)
        hdrs = {k.lower(): v.strip().lower() for k,v in res.headers.items()}
    except Exception as e:
        return {"url": url, "checked_at": checked_at, "error": str(e), "results": []}
    results = []
    for header, expected in security_headers.items():
        act = hdrs.get(header.lower())
        if act is None: status = 'missing'
        elif not any(ev in act for ev in [v.lower() for v in expected]): status = 'warning'
        else: status = 'ok'
        results.append({"header": header, "status": status, "actual": act, "recommended": expected, "recommendation_detail": rec_detail[header]})
    return {"url": url, "checked_at": checked_at, "results": results}

# 룰 기반 XSS/SQLi/CSRF 검출
from urllib.parse import urlparse, parse_qs, urlencode

def detect_get_param_xss(url: str) -> list:
    results = []
    p = urlparse(url)
    q = parse_qs(p.query)
    if not q: return results
    for pl in xss_payloads:
        nq = {k: pl for k in q}
        new_url = p._replace(query=urlencode(nq, doseq=True)).geturl()
        try:
            r = requests.get(new_url, timeout=5)
            if pl in r.text: results.append((url, new_url, 'GET', pl))
        except: pass
    return results

def detect_form_xss(url: str) -> list:
    results = []
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method','get').lower()
            inputs = form.find_all(['input','textarea'])
            tgt = urljoin(url, action)
            for pl in xss_payloads:
                data = {inp.get('name'): pl for inp in inputs if inp.get('name')}
                try:
                    rr = requests.post(tgt, data=data, timeout=5) if method=='post' else requests.get(tgt, params=data, timeout=5)
                    if pl in rr.text: results.append((url, tgt, method.upper(), pl)); break
                except: pass
    except: pass
    return results

def detect_sqli(url: str) -> list:
    payloads = ["'", '"', "'--", '"--', "')--", "' or '1'='1", '" or "1"="1"', "' OR sleep(5)--"]
    errors = ["sql syntax","mysql_fetch","ora-00933"]
    results = []
    p = urlparse(url)
    q = parse_qs(p.query)
    for param in q:
        for pl in payloads:
            nq = q.copy(); nq[param] = pl
            inj = p._replace(query=urlencode(nq, doseq=True)).geturl()
            try:
                start = time.time()
                r = requests.get(inj, timeout=8)
                if any(err in r.text.lower() for err in errors) or time.time()-start>4.5:
                    results.append((url, inj, 'SQLi', pl)); break
            except: pass
    return results

def detect_csrf(url: str) -> list:
    results = []
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        cookies = r.headers.get('Set-Cookie','').lower()
        for form in soup.find_all('form'):
            if form.get('method','get').lower()=='post':
                names = [i.get('name','').lower() for i in form.find_all('input')]
                if not any('csrf' in n or 'token' in n for n in names):
                    notes = ['CSRF 토큰 없음']
                    if 'samesite' not in cookies: notes.append('SameSite 없음')
                    if 'secure' not in cookies: notes.append('Secure 없음')
                    results.append((url, urljoin(url, form.get('action')), 'CSRF', ' | '.join(notes)))
    except: pass
    return results

# DOM 기반 XSS (Selenium)
def detect_dom_xss_selenium(urls: list) -> list:
    options = Options(); options.add_argument('--headless=new'); options.add_argument('--window-size=1280,800')
    results = []
    try:
        # selenium에러 때문에 코드를 수정함
        # driver = webdriver.Chrome(service=Service('chromedriver.exe'), options=options, executable_path='C:/Program Files/Google/Chrome/Application/chromedriver-win64/chromedriver.exe')
        service = Service('C:/Program Files/Google/Chrome/Application/chromedriver-win64/chromedriver.exe')
        driver = webdriver.Chrome(service=service, options=options)
        for u in urls:
            try:
                driver.get(u); time.sleep(1)
                for pl in xss_payloads:
                    for inp in driver.find_elements(By.TAG_NAME,'input'):
                        try: inp.clear(); inp.send_keys(pl)
                        except: pass
                    for btn in driver.find_elements(By.TAG_NAME,'button'):
                        try: btn.click()
                        except: pass
                    time.sleep(1)
                    try:
                        alert = driver.switch_to.alert; alert.accept(); results.append((u,u,'DOM',pl)); break
                    except NoAlertPresentException: pass
            except: pass
        driver.quit()
    except Exception as e:
        print(f"[❌ Selenium 오류] {e}")
    return results

# PDF 리포트 생성 함수
def generate_korean_pdf_report(results, header_reports, target_url, start_time, end_time):
    from flask_app import db, app, List
    pdf = FPDF()
    base_dir = os.getcwd()
    font_path = os.path.join(base_dir, "NanumGothic-Regular.ttf")
    bold_path = os.path.join(base_dir, "NanumGothic-Bold.ttf")
    pdf.add_font("Nanum", "", font_path)    # uni=True
    pdf.add_font("Nanum", "B", bold_path)   # uni=True
    pdf.set_font("Nanum", size=12)
    pdf.add_page()
    safe_multiline(pdf, "웹 통합 취약점 탐지 보고서")
    safe_multiline(pdf, f"대상 사이트: {target_url}")
    safe_multiline(pdf, f"총 탐지된 취약점 수: {len(results)}건")
    safe_multiline(pdf, f"탐지 시간: {start_time.strftime('%Y-%m-%d %H:%M:%S')} ~ {end_time.strftime('%H:%M:%S')}")
    pdf.ln(5)
    # 취약점별 정리
    categories = {"XSS": [], "SQLi": [], "CSRF": [], "DOM": []}
    for origin, tested_url, method, payload in results:
        if method in ["GET", "POST"]:
            categories["XSS"].append((origin, tested_url, method, payload))
        elif method == "SQLi":
            categories["SQLi"].append((origin, tested_url, method, payload))
        elif method == "CSRF":
            categories["CSRF"].append((origin, tested_url, method, payload))
        elif method == "DOM":
            categories["DOM"].append((origin, tested_url, method, payload))
    for cat, items in categories.items():
        if not items:
            continue
        title = {
            "XSS": "[XSS 취약점 결과]",
            "SQLi": "[SQLi 취약점 결과]",
            "CSRF": "[CSRF 취약점 결과]",
            "DOM": "[DOM-XSS 취약점 결과]"
        }.get(cat)
        safe_multiline(pdf, title)
        for i, (orig, url_, m, pl) in enumerate(items, 1):
            safe_multiline(pdf, f"{i}. 원본: {orig}")
            safe_multiline(pdf, f"   방식: {m}")
            safe_multiline(pdf, f"   페이로드: {pl}")
            safe_multiline(pdf, f"   URL: {url_}")
            pdf.ln(2)
            with app.app_context():
                db.create_all()
                a = List(method=m, originalPage=orig, testURL=url_, payload=pl)
                db.session.add(a)
                db.session.commit()
    # 보안 헤더 점검 결과
    pdf.add_page()
    pdf.set_font("Nanum", size=12)
    safe_multiline(pdf, "[보안 헤더 점검 결과]")
    for report in header_reports:
        pdf.set_font("Nanum", "B", size=12)
        safe_multiline(pdf, f"URL: {report['url']}")
        pdf.set_font("Nanum", size=11)
        if report.get("error"):
            safe_multiline(pdf, f"에러: {report['error']}")
        else:
            for res in report.get("results", []):
                hdr = res.get("header")
                st = res.get("status")
                act = res.get("actual") or "없음"
                safe_multiline(pdf, f"• {hdr}: 상태={st} / 실제값={act}")
                detail = res.get("recommendation_detail")
                if st.lower() != "ok" and detail:
                    pdf.set_font("Nanum", size=9)
                    pdf.set_text_color(100,100,100)
                    safe_multiline(pdf, f"   → 권장: {detail}", width=100)
                    pdf.set_text_color(0,0,0)
                    pdf.set_font("Nanum", size=11)
    # 저장
    report_dir = os.path.join(base_dir, "static", "reports")
    os.makedirs(report_dir, exist_ok=True)
    domain = urlparse(target_url).netloc.replace('.', '_')
    filename = f"{domain}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(report_dir, filename)
    try:
        pdf.output(path)
    except Exception as e:
        print(f"[❌ PDF 저장 실패] {e}")
        path = None
    return path


# 전체 스캔 실행
def run_full_scan(base_url: str, n: int):
    from flask_app import app, Scan, db, List
    start_time = datetime.now()
    pages = smart_crawl_site(base_url,n)
    all_results = []
    header_reports = []
    print(f"[🔍 총 {len(pages)} URL 탐지]")
    for idx, page in enumerate(pages,1):
        print(f"[{idx}/{len(pages)}] 스캔: {page}")
        with app.app_context():
            db.create_all()
            a = Scan(scanId=len(pages), scanURL=page)
            db.session.add(a)
            db.session.commit()
        header_reports.append(run_scan(page))
        all_results.extend(detect_form_xss(page))
        if '?' in page:
            all_results.extend(detect_get_param_xss(page))
            all_results.extend(detect_sqli(page))
        all_results.extend(detect_csrf(page))
        all_results.extend(ai_detector.detect_sqli_ai(page))
        all_results.extend(ai_detector.detect_xss_ai(page))
    all_results.extend(detect_dom_xss_selenium(pages))
    end_time = datetime.now()
    print("[✅ 전체 점검 완료]")
    if all_results:
        df = pd.DataFrame(all_results, columns=["원본", "탐지 URL", "기법", "페이로드"])
        print(df)
        with app.app_context():
            db.create_all()
            objects = [
                List(
                    originalPage=row["원본"],
                    testURL=row["탐지 URL"],
                    method=row["기법"],
                    payload=row["페이로드"]
                )
                for _, row in df.iterrows()
            ]
            db.session.add_all(objects)
            db.session.commit()
    else:
        print("탐지된 취약점이 없습니다.")
    import pickle
    with open('time_scan.pkl', 'wb') as f:
        pickle.dump((all_results,header_reports,base_url,start_time,end_time),f)
    # return all_results,header_reports,base_url,start_time,end_time
    # pdf_path = generate_korean_pdf_report(all_results, header_reports, base_url, start_time, end_time)
    # print(f"[📄 보고서 경로] {pdf_path}")

def main(url,num):
    from flask_app import app, db
    with app.app_context():
        db.create_all()
    run_full_scan(url, num)

main('http://testphp.vulnweb.com',10)

