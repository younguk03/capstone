from flask_app import app, db, List


def search():
    with app.app_context():
        db.session.execute('DELETE FROM List;')
        db.session.commit()

if __name__ == "__main__":
    search()
