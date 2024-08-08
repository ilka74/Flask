from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tpbuh.db'

    db.init_app(app)

    with app.app_context():
        db.create_all()  # Создаем все таблицы, если они еще не существуют
        print("Database and tables created!")

    return app
