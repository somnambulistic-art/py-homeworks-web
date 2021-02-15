import os
import hashlib
from datetime import datetime, timedelta

import jsonschema
from flask import Flask, jsonify, request
from flask.views import MethodView
from flask_migrate import Migrate
from sqlalchemy import exc
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token


app = Flask(__name__)


# ПАРАМЕТРЫ КОНФИГУРАЦИИ, константы
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = '5f352379324c22463451387a0aec5d2f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SALT = 'skdfhglas1235_kfgoask-rgo13261'

#  Инициализация БД, миграция
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#  Создание экземпляра JWTManager'а
jwt = JWTManager(app)

if __name__ == '__main__':
    app.run()


#  МИКСИН
class BaseModelMixin:
    @classmethod
    def by_id(cls, obj_id):
        obj = cls.query.get(obj_id)
        if obj:
            return obj
        else:
            raise NotFound

    @classmethod
    def by_user_id(cls, obj_id, user_id):
        obj = cls.query.filter_by(id=obj_id).filter(cls.user_id == user_id).all()
        if obj:
            return obj
        else:
            raise NotFound

    def add(self):
        db.session.add(self)
        try:
            db.session.commit()
        except exc.IntegrityError:
            raise BadLuck

    def delete(self):
        db.session.delete(self)
        try:
            db.session.commit()
        except exc.IntegrityError:
            raise BadLuck


#  МОДЕЛЬ ПОЛЬЗОВАТЕЛЯ
class User(db.Model, BaseModelMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password = db.Column(db.String(128))
    adverts = db.relationship('Advert', backref='user')

    def __init__(self, username: str, password: str, email: str):
        self.username = username
        self.password = password
        self.email = email

    def __str__(self):
        return f'<User {self.username}>'

    def __repr__(self):
        return str(self)

    def set_password(self, raw_password: str):
        raw_password = f'{raw_password}{SALT}'
        self.password = hashlib.md5(raw_password.encode()).hexdigest()

    def check_password(self, raw_password: str):
        raw_password = f'{raw_password}{SALT}'
        return self.password == hashlib.md5(raw_password.encode()).hexdigest()

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email
        }


#  МОДЕЛЬ ОБЪЯВЛЕНИЯ
class Advert(db.Model, BaseModelMixin):
    id = db.Column(db.Integer, primary_key=True)
    headline = db.Column(db.String(256), index=True, unique=True)
    description = db.Column(db.String(1024), index=True, unique=True)
    creation_date = db.Column(db.DateTime(), default=datetime.utcnow)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))

    def __init__(self, headline: str, description: str):
        self.headline = headline
        self.description = description

    def __str__(self):
        return f'<Advert {self.headline}>'

    def __repr__(self):
        return str(self)

    def to_dict(self):
        return {
            'id': self.id,
            'headline': self.headline,
            'description': self.description,
            'creation_date': self.creation_date,
            'user': self.user_id,
        }


# КЛАСС ОБРАБОТЧИКА ОШИБОК
class BasicException(Exception):
    status_code = 0
    default_message = 'Unknown Error'

    def __init__(self, message: str = None, status_code: int = None):
        super().__init__(message)
        self.message = message
        request.status = self.status_code
        if status_code is not None:
            self.status_code = status_code

    def to_dict(self):
        return {
            'message': self.message or self.default_message
        }


class NotFound(BasicException):
    status_code = 404
    default_message = 'Not found'


class ValidationError(BasicException):
    status_code = 401
    default_message = 'Validation error'


class BadLuck(BasicException):
    status_code = 400
    default_message = 'Bad luck'


@app.errorhandler(BadLuck)
@app.errorhandler(NotFound)
@app.errorhandler(ValidationError)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


# ВАЛИДАТОР
def validate(source: str, req_schema: dict):
    """Валидатор входящих запросов"""

    def decorator(func):

        def wrapper(*args, **kwargs):
            try:
                jsonschema.validate(
                    instance=getattr(request, source), schema=req_schema,
                )
            except jsonschema.ValidationError:
                raise ValidationError

            result = func(*args, **kwargs)

            return result

        return wrapper

    return decorator


# JSON-СХЕМЫ ДЛЯ ВАЛИДАЦИИ
USER_CREATE = {
    "type": "object",
    "properties": {
        "username": {
            "type": "string"
        },
        "email": {
            "type": "string",
            "pattern": """(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"""
        },

        "password": {
            "type": "string",
            "pattern": "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
        }
    },
    "required": ["username", "email", "password"]
}

ADVERT_CREATE = {
    "type": "object",
    "properties": {
        "headline": {
            "type": "string"
        },
        "description": {
            "type": "string",
        },
    },
    "required": ["headline", "description"]
}


# ПРЕДСТАВЛЕНИЕ-КЛАСС (CBV) ПОЛЬЗОВАТЕЛЕЙ
class UserView(MethodView):
    def get(self, user_id):
        user = User.by_id(user_id)
        return jsonify(user.to_dict())

    @validate('json', USER_CREATE)
    def post(self):
        user = User(**request.json)
        user.set_password(request.json['password'])
        user.add()

        expires = timedelta(days=7)
        access_token = create_access_token(identity=str(user.id), expires_delta=expires)
        return {'token': access_token}, 200


# ПРЕДСТАВЛЕНИЕ-КЛАСС (CBV) ОБЪЯВЛЕНИЙ
class AdvertView(MethodView):
    def get(self, advert_id):
        advert = Advert.by_id(advert_id)
        return jsonify(advert.to_dict())

    @jwt_required
    @validate('json', ADVERT_CREATE)
    def post(self):
        advert = Advert(**request.json)
        advert.user_id = get_jwt_identity()
        advert.add()
        return jsonify(advert.to_dict())

    @jwt_required
    def delete(self, advert_id):
        user_id = get_jwt_identity()
        adverts = Advert.by_user_id(advert_id, user_id)
        for advert in adverts:
            advert.delete()
        return 'advert deleted', 200


# URL-правила для методов CBV ПОЛЬЗОВАТЕЛЕЙ И ОБЪЯВЛЕНИЙ
app.add_url_rule('/api/users/<int:user_id>', view_func=UserView.as_view('users_get'), methods=['GET', ])
app.add_url_rule('/api/login/', view_func=UserView.as_view('users_create'), methods=['POST', ])
app.add_url_rule('/api/adverts/<int:advert_id>', view_func=AdvertView.as_view('adverts_get'), methods=['GET', ])
app.add_url_rule('/api/adverts/', view_func=AdvertView.as_view('adverts_create'), methods=['POST', ])
app.add_url_rule('/api/adverts/<int:advert_id>', view_func=AdvertView.as_view('adverts_delete'), methods=['DELETE', ])
