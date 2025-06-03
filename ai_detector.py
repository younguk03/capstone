
# ai_detector.py
import os
from urllib.parse import urlparse, parse_qs
import joblib

# 모델 파일 경로 (models 디렉터리에 저장)
SQLI_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'sqli_detector.pkl')
XSS_MODEL_PATH  = os.path.join(os.path.dirname(__file__), 'models', 'xss_detector.pkl')

# AI 모델 로드
sqli_model = joblib.load(SQLI_MODEL_PATH)
xss_model  = joblib.load(XSS_MODEL_PATH)


def vectorize_input(url: str, param: str, value: str) -> list:
    features = []
    features.append(len(url))
    features.append(len(param))
    features.append(len(value))
    features.append(value.count("'") + value.count('"'))
    features.append(sum(1 for c in value if not c.isalnum()))
    return features


def detect_sqli_ai(url: str):
    from urllib.parse import urlparse, parse_qs
    results = []
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for param, vals in query.items():
        vec = vectorize_input(url, param, vals[0])
        pred = sqli_model.predict([vec])[0]
        if pred == 1:
            results.append((url, url, 'SQLi-AI', f"AI의심: {param}={vals[0]}"))
    return results


def detect_xss_ai(url: str):
    from urllib.parse import urlparse, parse_qs
    results = []
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for param, vals in query.items():
        vec = vectorize_input(url, param, vals[0])
        pred = xss_model.predict([vec])[0]
        if pred == 1:
            results.append((url, url, 'XSS-AI', f"AI의심: {param}={vals[0]}"))
    return results
