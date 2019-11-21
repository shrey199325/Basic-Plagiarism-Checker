"""
Objectives:
    Registration of Users
    {/register | POST | username & password |
    200 OK + 305 Invalid USERNAME + 303 ALREADY REGISTERED}
    Detect similarity of text
    {/detect | POST | username & password & text1+text2 |
     200 OK + 301 OUT OF TOKEN + 302 INVALID USER/PASS + 305}
    Refill token amount
    {/refill | POST | username & admin password & refill amount |
     200 OK + 301 OUT OF TOKEN + 302 INVALID USER/PASS + 305}
"""
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
import bcrypt
from pymongo import MongoClient
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDatabase
users = db["Users"]
ADMIN_USER = "admin"
HASSHED_ADMIN_PASS = b'$2b$12$tpvo4zJQgkoBeAoaZ/1rc.8b83qU4l/BmDcMQIKe4ryVTErUYlaha'
# admin

### Status Codes###
OK = 200
OUT_OF_TOKENS = 301
INVALID_USER_INFO = 302
USER_ALREADY_EXISTS = 303
INVALID_ADMIN_USERNAME_PASSWORD = 305
####


def generate_admin_user():
    try:
        _ = users.find({"Username": ADMIN_USER})[0]
    except IndexError:
        users.insert({
            "Username": ADMIN_USER,
            "Password": HASSHED_ADMIN_PASS,
            "admin": True,
            "Tokens": 10
        })


generate_admin_user()


def verify_pass(username, password, check_pass=True, admin=False):
    try:
        user = users.find({
            "Username": username
        })[0]
        hashedPASS = user["Password"]
        is_admin = user["admin"]
    except IndexError:
        return False
    if check_pass:
        return bcrypt.hashpw(password.encode("utf8"),
                             hashedPASS) == hashedPASS and is_admin == admin
    else:
        return True


def count_token(username):
    token = users.find({
        "Username": username
    })[0]["Tokens"]
    return int(token)


class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        user_exists = users.find({"Username": username})
        if len(list(user_exists)) != 0:
            ret_json = {"status": USER_ALREADY_EXISTS,
                        "msg": "User Already Exists!"}
            return ret_json
        hashed_pw = bcrypt.hashpw(password.encode("utf8"),
                                  bcrypt.gensalt())
        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "admin": False,
            "Tokens": 10
        })
        ret_json = {
            "status": OK, "msg": "Successfully signed in"
        }
        return jsonify(ret_json)


class Detect(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        correct_pass = verify_pass(username, password)
        if not correct_pass:
            ret_json = {
                "status": INVALID_USER_INFO,
                "msg": "Invalid"
            }
            return ret_json
        total_token = count_token(username)
        if total_token <= 0:
            ret_json = {"status": OUT_OF_TOKENS}
            return ret_json
        nlp = spacy.load("en_core_web_sm")
        text1 = nlp(text1)
        text2 = nlp(text2)
        ratio = text1.similarity(text2)

        ret_json = {
            "status": OK,
            "similarity percentage": ratio * 100,
            "msg": "Similarity score calculated successfully"
        }

        users.update({
            "Username": username
        }, {
            "$set": {"Tokens": total_token - 1}
        })
        return jsonify(ret_json)


class Refill(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        refill_user = postedData["refill_user"]
        refill_amt = postedData["refill"]
        correct_admin_pass = verify_pass(username, password, admin=True)
        # Only admin user can have the access to increase the Tokens
        if not correct_admin_pass:
            ret_json = {
                "status": INVALID_ADMIN_USERNAME_PASSWORD,
                "msg": "Invalid Admin Username and Password"
            }
            return jsonify(ret_json)
        user_exists = verify_pass(refill_user, None, False)
        if not user_exists:
            ret_json = {
                "status": INVALID_USER_INFO,
                "msg": "Refill Username doesn't exists!!!"
            }
            return jsonify(ret_json)
        total_token = count_token(refill_user)
        users.update({
            "Username": refill_user
        }, {
            "$set": {
                "Tokens": total_token + int(refill_amt)
            }
        })
        ret_json = {"status": OK, "msg": "Refill successful"}
        return jsonify(ret_json)


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(host='0.0.0.0')
