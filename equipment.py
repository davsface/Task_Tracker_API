from flask import Blueprint, request
from google.cloud import datastore
import json
import constants

client = datastore.Client()
bp = Blueprint('equipment', __name__, url_prefix='/equipment')

# Create and get a task if the Authorization header contains a valid JWT
@bp.route('', methods=['POST', 'GET', 'DELETE', 'PATCH', 'PUT'])
def equipment_create_read():
    # if request type is not json, 415
    if 'application/json' not in request.accept_mimetypes:
        return {"Error": "Not Acceptable"}, 406

    if request.method == 'POST':
        # create new task with jwt as task owner
        content = request.get_json()
        new_equipment = datastore.entity.Entity(key=client.key(constants.equipment))
        new_equipment.update({"name": content["name"], "type": content["type"],
                         "status": content["status"], "assigned to": None})
        client.put(new_equipment)
        # add self link and id as attributes to task
        new_equipment.update({"id": new_equipment.key.id})
        new_equipment["self"] = request.host_url + "/equipment/" + str(new_equipment.key.id)
        client.put(new_equipment)
        return json.dumps(new_equipment), 201

    elif request.method == 'GET':
        # else get all tasks in the datastore and send response
        query = client.query(kind=constants.equipment)
        results = list(query.fetch())
        return json.dumps(results), 200

    else:
        return {"Error": "Method not recognized"}, 405


@bp.route('/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def equipment_read_update_delete(id):
    # if request type is not json, 415
    if 'application/json' not in request.accept_mimetypes:
        return {"Error": "Not Acceptable"}, 406
    content = request.get_json()

    if request.method == 'PATCH':
        # find the task
        #content = request.get_json()
        equipment_key = client.key(constants.equipment, int(id))
        equipment = client.get(key=equipment_key)
        # if no task found, 404
        if equipment is None:
            return {"Error": "No equipment with this id exists"}, 404

        # equipment exists loop through and verify content and update entity where new content is present,
        # update the entity and send response
        for attribute in content:
            if attribute in ["id", "name", "type", "status", "assigned to"]:
                if attribute == "id":
                    return {"Error": "Modifying equipment id is not allowed"}, 403
                if attribute == "assigned to":
                    return {"Error": "Modifying equipment id is not allowed, please use task/<id>/equipment endpoint"}, 403
                equipment.update({attribute: content[attribute]})
        client.put(equipment)
        return equipment, 200

    if request.method == 'PUT':
        #content = request.get_json()
        # if request is missing the required content, 400
        if 'name' not in content or 'type' not in content or 'status' not in content:
            return {"Error": "The request object is missing at least one of the required attributes"}, 400

        # if client is trying to modify id or equipment, send 403
        if 'id' in content or 'assigned to' in content:
            return {"Error": "Unable to modify equipment id or assignment"}, 403

        equipment_key = client.key(constants.equipment, int(id))
        equipment = client.get(key=equipment_key)
        # if no equipment with id exists, 404
        if equipment is None:
            return {"Error": "No equipment with this id exists"}, 404

        # equipment exists and the correct content exists in the request body, update the entity and send response
        equipment.update({"name": content["name"], "type": content["type"], "status": content["status"]})
        client.put(equipment)
        return equipment, 303

    elif request.method == 'DELETE':
        equipment_key = client.key(constants.equipment, int(id))
        equipment = client.get(key=equipment_key)
        # if no equipment with id exists, 404
        if equipment is None:
            return {"Error": "No equipment with this id exists"}, 404
        # delete equipment and send response
        client.delete(equipment_key)
        return '', 204

    elif request.method == 'GET':
        equipment_key = client.key(constants.equipment, int(id))
        equipment = client.get(key=equipment_key)
        # if no equipment with id exists, 404
        if equipment is None:
            return {"Error": "No equipment with this id exists"}, 404
        return equipment, 200