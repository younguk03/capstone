from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy


# utils 폴더의 절대경로를 sys.path에 추가
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = ('sqlite:////대학/3학년/1학기/캡스톤디자인/project/capstone/form.db')
db = SQLAlchemy(app)


class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20))
    originalPage = db.Column(db.String(80))
    testURL = db.Column(db.String(80))
    payload = db.Column(db.String(80))


@app.route('/', methods=['POST', 'GET'])
def form():

    return render_template('./home.html')


@app.route('/resultPage', methods=['POST', 'GET'])
def result_page():
    import test2
    url = request.args.get('url', '')
    with app.app_context():
        List.query.delete()
        db.session.commit()
    if url:
        test2.main(url)
    lists = List.query.all()

    return render_template('resultPage/page.html', url=url, lists=lists)


if __name__ == '__main__':
    app.run(port=5000, debug=True)
