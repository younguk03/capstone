import time

from flask import Flask, render_template, request, send_file
from flask_sqlalchemy import SQLAlchemy
import os
from urllib.parse import urlparse
import subprocess

# utils 폴더의 절대경로를 sys.path에 추가
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:///form.db')
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:///form.db')
db = SQLAlchemy(app)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scanId = db.Column(db.String(10))
    scanURL = db.Column(db.String(40))

class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(20))
    originalPage = db.Column(db.String(80))
    testURL = db.Column(db.String(80))
    payload = db.Column(db.String(80))


@app.route('/', methods=['POST', 'GET'])
def form():
    return render_template('./home.html')


@app.route('/deep_scan_result_page', methods=['POST', 'GET'])
def precision():
    import scanner
    url = request.form.get('url') if request.method == 'POST' else request.args.get('url', '')
    with app.app_context():
        List.query.delete()
        Scan.query.delete()
        db.session.commit()
    if url:
        scanner.main(url, 25)
    lists = List.query.all()
    scans = Scan.query.all()
    return render_template('./resultPage/page.html', url=url, lists=lists, scans=scans)


@app.route('/general_result_page', methods=['POST', 'GET'])
def result_page():
    import scanner
    # GET 또는 POST에 따라 url 받기
    url = request.form.get('url') if request.method == 'POST' else request.args.get('url', '')
    with app.app_context():
        List.query.delete()
        Scan.query.delete()
        db.session.commit()

    if url:
        scanner.main(url, 10)
    lists = List.query.all()
    scans = Scan.query.all()
    return render_template('./resultPage/page.html', url=url, lists=lists, scans=scans)


@app.route("/download_report", methods=["GET"])
def download_report():
    from scanner import generate_korean_pdf_report
    import pickle
    with open("time_scan.pkl", "rb") as f:
        all_results, header_reports, base_url, start_time, end_time = pickle.load(f)
    pdf_path = generate_korean_pdf_report(all_results, header_reports, base_url, start_time, end_time)
    if not all([all_results, header_reports, start_time, end_time, base_url]):
        return "❌ 스캔 결과가 없습니다. 먼저 스캔을 실행해주세요.", 400
    return send_file(pdf_path, as_attachment=True)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
