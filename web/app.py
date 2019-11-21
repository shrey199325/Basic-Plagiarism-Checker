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

### Status Codes###
OK = 200
OUT_OF_TOKENS = 301
INVALID_USER_INFO = 302
USER_ALREADY_EXISTS = 303
INVALID_ADMIN_USERNAME_PASSWORD = 305
####


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
            "Tokens": 10
        })
        ret_json = {
            "status": OK, "msg": "Successfully signed in"
        }
        return jsonify(ret_json)


def verify_pass(username, password):
    try:
        hashedPASS = users.find({
            "Username": username
        })[0]["Password"]
    except IndexError:
        return False
    return bcrypt.hashpw(password.encode("utf8"),
                         hashedPASS) == hashedPASS


def count_token(username):
    token = users.find({
        "Username": username
    })[0]["Tokens"]
    return int(token)


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
            "similarity": ratio,
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
        password = postedData["admin_pw"]
        refill_amt = postedData["refill"]
        correct_pass = verify_pass(username, password)
        if not correct_pass:
            ret_json = {
                "status": INVALID_ADMIN_USERNAME_PASSWORD
            }
            return ret_json
        total_token = count_token(username)
        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": total_token - int(refill_amt)
            }
        })
        ret_json = {"status": OK, "msg": "Refill successful"}
        return jsonify(ret_json)


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")


if __name__ == "__main__":
    app.run(host='0.0.0.0')
