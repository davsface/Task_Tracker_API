from google.cloud import datastore
from flask import Flask, request, make_response, jsonify, _request_ctx_stack
import requests
import constants
import equipment

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.register_blueprint(equipment.bp)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

CLIENT_ID = 'v8ZjjSNJiBmAtEdhxuhdZKzgfs98vv4t'
CLIENT_SECRET = '9yTCDQ9do_mCER3Zfgh8o-CPXEkiLWnXu4xFdv3Ar8ebb3LXgapxbqW2QUDyZkjI'
DOMAIN = 'cs493-portfolio-1.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /tasks to use this API"


# Create and get a task if the Authorization header contains a valid JWT
@app.route('/tasks', methods=['POST', 'GET', 'DELETE', 'PATCH', 'PUT'])
def task_create_read():
    # if no auth provided, 403
    if 'Authorization' not in request.headers:
        return {"Error": "User access denied"}, 403
    # if request type is not json, 415
    if 'application/json' not in request.accept_mimetypes:
        return {"Error": "Not Acceptable"}, 406

    if request.method == 'POST':
        # verify jwt and create new task with jwt as task owner
        payload = verify_jwt(request)
        content = request.get_json()
        new_task = datastore.entity.Entity(key=client.key(constants.task))
        new_task.update({"task name": content["task name"], "start date": content["start date"],
                         "due date": content["due date"], "equipment": [], "owner": payload["sub"]})
        client.put(new_task)
        # add self link and id as attributes to task
        new_task.update({"id": new_task.key.id})
        new_task["self"] = request.host_url + "/tasks/" + str(new_task.key.id)
        client.put(new_task)
        return json.dumps(new_task), 201

    elif request.method == 'GET':
        if 'Authorization' not in request.headers:
            # else get all tasks in the datastore and send response
            query = client.query(kind=constants.task)
            query.add_filter('public', '=', True)
            results = list(query.fetch())
            return json.dumps(results), 200

        else:
            payload = verify_jwt(request)
            query = client.query(kind=constants.task)
            query.add_filter('owner', '=', payload["sub"])
            results = list(query.fetch())
            return json.dumps(results), 200

    else:
        return {"Error": "Method not recognized"}, 405


@app.route('/tasks/<id>', methods=['PUT', 'PATCH'])
def tasks_update(id):
    if 'Authorization' not in request.headers:
        return {"Error": "User access denied"}, 403
    # if request type is not json, 415
    if 'application/json' not in request.accept_mimetypes:
        return {"Error": "Not Acceptable"}, 406
    payload = verify_jwt(request)
    # find the task
    content = request.get_json()
    task_key = client.key(constants.task, int(id))
    task = client.get(key=task_key)
    # if no task found, 404
    if task is None:
        return {"Error": "No task with this id exists"}, 404
    # if the user accessing is not the owner of the task, 403
    if task["owner"] != payload["sub"]:
        return {"Error": "User access denied"}, 403

    if request.method == 'PATCH':
        # task exists loop through and verify content and update entity where new content is present, update the entity
        # and send response
        for attribute in content:
            if attribute in ["id", "task name", "start date", "due date", "equipment"]:
                if attribute == "id":
                    return {"Error": "Modifying task ID is not allowed"}, 403
                task.update({attribute: content[attribute]})
        client.put(task)
        return task, 200

    if request.method == 'PUT':
        content = request.get_json()
        # if request is missing the required content, 400
        if 'task name' not in content or 'start date' not in content or 'due date' not in content:
            return {"Error": "The request object is missing at least one of the required attributes"}, 400

        # if client is trying to modify id or equipment, send 403
        if 'id' in content or 'equipment' in content:
            return {"Error": "Modifying task ID is not allowed"}, 403

        # if no task with id exists, 404
        if task is None:
            return {"Error": "No task with this task_id exists"}, 404
        # if the user accessing is not the owner of the task, 403
        if task["owner"] != payload["sub"]:
            return {"Error": "User access denied"}, 403

        # task exists and the correct content exists in the request body, update the entity and send response
        task.update({"task name": content["task name"], "start date": content["start date"], "due date": content["due date"]})
        client.put(task)
        return task, 303


@app.route('/tasks/<id>', methods=['GET', 'DELETE'])
def tasks_read_delete(id):
    if 'Authorization' not in request.headers:
        return {"Error": "User access denied"}, 403
    # if request type is not json, 406
    if 'application/json' not in request.accept_mimetypes:
        return {"Error": "Not Acceptable"}, 406
    payload = verify_jwt(request)
    task_key = client.key(constants.task, int(id))
    task = client.get(key=task_key)
    # if no task with id exists, 404
    if task is None:
        return {"Error": "No task with this id exists"}, 404
    # if the user accessing is not the owner of the task, 403
    if task["owner"] != payload["sub"]:
        return {"Error": "User access denied"}, 403

    if request.method == 'DELETE':
        client.delete(task_key)
        return '', 204

    elif request.method == 'GET':
        return task, 200


@app.route('/tasks/<tid>/equipment/<eid>', methods=['PUT', 'DELETE'])
def add_delete_task_equipment(tid, eid):
    # if request type is not json, 406
    if 'application/json' not in request.accept_mimetypes:
        return {"Error": "Not Acceptable"}, 406
    payload = verify_jwt(request)
    task_key = client.key(constants.task, int(tid))
    task = client.get(key=task_key)
    equipment_key = client.key(constants.equipment, int(eid))
    equipment_obj = client.get(key=equipment_key)
    # check if both equipment and task exist, if not 404
    if task is None or equipment_obj is None:
        return {"Error": "The specified task and/or equipment does not exist"}, 404
    # if the user accessing is not the owner of the task, 403
    if task["owner"] != payload["sub"]:
        return {"Error": "User access denied"}, 403
    print(task)
    print(equipment_obj)

    if request.method == 'PUT':
        # check is load is already assigned, if so 403
        if equipment_obj['assigned to'] is not None:
            return {"Error": "This equipment is already assigned"}, 403
        # add loads to the boat and assign boat as carrier of load
        task['equipment'].append({'id': equipment_obj.id, 'name': equipment_obj['name'], 'self': request.host_url + '/equipment/' + str(equipment_obj.id)})
        equipment_obj['assigned to'] = {'id': task.id, 'task name': task['task name'], 'self': request.host_url + '/task/' + str(task.id)}
        client.put(task)
        client.put(equipment_obj)
        return('',204)

    # if request.method == 'DELETE':
    #     boat_key = client.key(constants.boats, int(bid))
    #     boat = client.get(key=boat_key)
    #     load_key = client.key(constants.loads, int(lid))
    #     load = client.get(key=load_key)
    #     #check if both load and boat exist, if not 404
    #     if load is None or boat is None:
    #         return {"Error": "No boat with this boat_id is loaded with the load with this load_id"}, 404
    #     # loop through loads on the boat and remove if load with lid is found and reset carrier of the load to None
    #     for boat_load in boat['loads']:
    #         if boat_load['id'] == int(lid):
    #             boat['loads'].remove(boat_load)
    #             client.put(boat)
    #             load['carrier'] = None
    #             client.put(load)
    #             return ('', 204)
    #     # no load with this lid exists on this boat
    #     return {"Error": "No boat with this boat_id is loaded with the load with this load_id"}, 404


@app.route('/users', methods=['GET'])
def get_users():
    if request.method == 'GET':
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        return json.dumps(results), 200


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    query = client.query(kind=constants.users)
    query.add_filter('username', '=', username)
    result = list(query.fetch())
    if not result:
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({"username": username})
        client.put(new_user)
        # add id as attributes to task
        new_user.update({"id": new_user.key.id})
        client.put(new_user)
        user_id = new_user["id"]
    else:
        user = result[0]
        user_id = user["id"]
    id_token = r.json()["id_token"]
    response_data = {
        "id_token": id_token,
        "user_id": user_id
    }
    response_json = json.dumps(response_data)
    return response_json, 200, {'Content-Type': 'application/json'}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

