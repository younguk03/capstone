import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 테스트용 페이로드
xss_payloads = [
    "<script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)",
    "svg/onload=alert(1)>"
]

# xss 탐지 모듈
def detect_xss(url):
    print(f"[+] 스캔중: {url}")
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all('form')
        if not forms:
            print('[-]입력 폼 없음')
            return

        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            form_url = urljoin(url, action)
            print(f' [+] 폼 URL: {form_url}, 메소드 {method.upper()}')

            for payload in xss_payloads:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                if method == 'post':
                    r = requests.post(form_url, data=data)
                else:
                    r = requests.get(form_url, params=data)

                if payload in r.text:
                    print(f' [!] xss 가능성 있음: {form_url}')
                    print(f'     사용된 페이로드: {payload}')
    except Exception as e:
        print(f'[1] 오류 발생:{e}')


if __name__ == "__main__":
    test_url = input('검사할 url 입력: ')
    detect_xss(test_url)
