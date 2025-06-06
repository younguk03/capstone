import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from sklearn.feature_extraction.text import TfidfVectorizer  # 머신러닝을 위해 sklearn을 불러옴
from flask_app import app, List, db
import joblib
import pandas as pd
import pickle
import random
# 전처리 및 벡터화
df = pd.read_csv('XSS_dataset.csv')
payloads = df['Sentence'].dropna().unique().tolist()


# 열의 이름이 sentence
X = df['Sentence']
y = df['Label'] # 1: 악성, 0: 정상
vectorizer = TfidfVectorizer()
X_vec = vectorizer.fit_transform(X)


# 모델 학습
model = joblib.load('xss_model.pkl')
vectorizer = joblib.load('vectorizer.pkl')
malicious_payloads = df[df['Label'] == 1]['Sentence'].dropna().unique().tolist()

with open('filtered_payloads.pkl', 'wb') as f:
    pickle.dump(malicious_payloads, f)
with open('filtered_payloads.pkl', 'rb') as f:
    xss_payloads = pickle.load(f)
# xss_payloads = random.sample(xss_payloads, 20)
# maxlink=1로 맞추기
def is_malicious(text):
    vec = vectorizer.transform([text])
    return model.predict(vec)[0] == 1

# # 악성 페이로드 필터링
# filtered_payloads = [p for p in payloads if is_malicious(p)]
#
# # 파일로 저장
# with open('filtered_payloads.pkl', 'wb') as f:
#     pickle.dump(filtered_payloads, f)

def smart_crawl_site(base_url, max_links=10):
    visited, to_visit, collected = set(), [base_url], []
    get_candidates, form_candidates = [], []

    while to_visit and len(collected) < max_links:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            res = requests.get(url, timeout=1)
            soup = BeautifulSoup(res.text, 'html.parser')
            visited.add(url)
            collected.append(url)
            # GET 파라미터가 있는 URL 후보 수집
            if "?" in url and '=' in url:
                get_candidates.append(url)
            # 폼이 있으면 POST 후보로
            if soup.find('form'):
                form_candidates.append(url)
            # 내부 링크 크롤링
            for a in soup.find_all('a', href=True):
                link = urljoin(url, a['href'])
                # 같은 도메인만
                if urlparse(link).netloc == urlparse(base_url).netloc:
                    if link not in visited and link not in to_visit:
                        to_visit.append(link)
        except Exception as e:
            continue
    return get_candidates, form_candidates


def test_get_xss(url, payloads):
    with app.app_context():
        results = []
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for payload in payloads:
                # 모든 파라미터에 페이로드 삽입
                test_params = {k: payload for k in qs}
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                try:
                    resp = requests.get(test_url, timeout=1)
                    if payload in resp.text:
                        results.append({
                            "원본 페이지": url,
                            "요청 방식": "GET",
                            "페이로드": payload,
                            "테스트된 URL": test_url
                        })
                        db.create_all()
                        a = List(type='GET', originalPage=url, testURL=test_url, payload=payload)
                        db.session.add(a)
                        db.session.commit()

                except Exception as e:
                    continue
                try:
                    resp = requests.post(test_url, timeout=1)
                    if payload in resp.text:
                        results.append({
                            "원본 페이지": url,
                            "요청 방식": "POST",
                            "페이로드": payload,
                            "테스트된 URL": test_url
                        })
                        a = List(type='POST', originalPage=url, testURL=test_url, payload=payload)
                        db.session.add(a)
                        db.session.commit()
                except Exception as e:
                    continue
        except Exception as e:
            pass

        return results


def test_post_xss(url, payloads):
    with app.app_context():
        results = []
        try:
            res = requests.get(url, timeout=2)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'textarea'])
                data = {}
                for inp in inputs:
                    name = inp.get('name')
                    if not name:
                        continue
                    data[name] = payload
                action_url = urljoin(url, action) if action else url
                for payload in payloads:
                    for k in data:
                        data[k] = payload
                    try:
                        if method == 'post':
                            resp = requests.post(action_url, data=data, timeout=2)
                            if payload in resp.text:
                                results.append({
                                    "원본 페이지": url,
                                    "요청 방식": 'POST',
                                    "페이로드": payload,
                                    "테스트된 URL": f"{action_url} (data: {data})"
                                })
                                a = List(type='POST', originalPage=url, testURL=f'{action_url}?{urlencode(data)}',
                                         payload=payload)
                                db.session.add(a)
                                db.session.commit()
                        elif method == 'get':
                            resp = requests.get(action_url, params=data, timeout=2)
                            if payload in resp.text:
                                results.append({
                                    "원본 페이지": url,
                                    "요청 방식": 'GET',
                                    "페이로드": payload,
                                    "테스트된 URL": f"{action_url} (data: {data})"
                                })
                                b = List(type='GET', originalPage=url, testURL=f'{action_url}?{urlencode(data)}',
                                        payload=payload)
                                db.session.add(b)
                                db.session.commit()
                    except Exception as e:
                        continue
        except Exception as e:
            pass
        return results


def main(url):
    with app.app_context():
        db.create_all()
    get_candidates, form_candidates = smart_crawl_site(url, max_links=40)
    report = []
    for url_text in get_candidates:
        report.extend(test_get_xss(url_text, xss_payloads))
    for url_text in form_candidates:
        report.extend(test_post_xss(url_text, xss_payloads))

    a = len(report)


    # 보고서 출력
    print("XSS / DOM XSS 취약점 탐지 보고서\n")
    print(f"대상 URL: {url}")
    print(f"총 탐지 수: {len(report)}건\n")
    print(f"{'번호':<4} {'주소':<40} {'위험':<6} {'설명'}")
    for idx, item in enumerate(report, 1):
        # print(f"{idx}. 원본 페이지: {item['원본 페이지']}")
        # print(f"요청 방식: {item['요청 방식']}")
        # print(f"페이로드: {item['페이로드']}")
        # print(f"테스트된 URL: {item['테스트된 URL']}\n")
        # 기존 코드에서 report 출력 부분을 아래처럼 바꿔보세요
        print(f"{idx:<4} {item['원본 페이지'][:38]:<40} {'발견됨':<6} 해커가 이 주소에 악성 코드를 넣을 수 있습니다.")
        print("\n※ 발견된 주소는 웹 개발자 또는 보안 담당자에게 전달해 주세요.")

if __name__ == "__main__":
    url = 'http://testphp.vulnweb.com'
    main(url=url)

