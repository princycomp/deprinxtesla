from flask import current_app as app
from bson.objectid import ObjectId


def get_user_by_username(username):
    with app.app_context():
        return app.mongo.db.users.find_one({"username": username})


def get_user_by_email(email):
    with app.app_context():
        return app.mongo.db.users.find_one({"email": email})


def get_user_by_id(user_id):
    with app.app_context():
        return app.mongo.db.users.find_one({"_id": ObjectId(user_id)})