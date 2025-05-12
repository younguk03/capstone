from flask_app import app, List, db

with app.app_context():
    db.create_all()
    List.query.delete()
    db.session.commit()
