from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


"""
librerias que conectan el frontend con el api gateway
"""
import datetime
import requests
import re

"""
servicio de prueba  api gateway
"""

app = Flask(__name__)
cors = CORS(app)

#############################################################################################################
""" metodo para realizar login mediante un token """

app.config["JWT_SECRET_KEY"] = "super-secret" # Cambiar por el que se conveniente
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validar'
    response =requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user,expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401


############################################################################################################
# Funcion que se ejecutará siempre de primero antes de que la consulta llegue a la ruta solicitada-- MIDELWARE
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePersmiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401
def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url
def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso

##############################--REDIRECCIONAMIENTO DE MICROSERVICIO SEGURIDAD--######################

################################--redireccionamiento usuario--######################################

################################--redireccionamiento rol--######################################

################################--redireccionamiento permiso--######################################

################################--redireccionamiento permiso-rol --###################################

##############################--REDIRECCIONAMIENTO DE MICROSERVICIO INVENTARIO--######################

##########################--redireccionamiento cliente--#############################################

@app.route("/clientes", methods=['GET'])
def getClientes():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/clientes'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/clientes", methods=['POST'])
def crearCliente():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/clientes'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/clientes/<string:id>", methods=['GET'])
def getCliente(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/clientes/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/clientes/<string:id>", methods=['PUT'])
def modificarCliente(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/clientes/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/clientes/<string:id>", methods=['DELETE'])
def eliminarCliente(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/clientes/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

##########################--redireccionamiento producto--#############################################

##########################--redireccionamiento proveedor--#############################################

##########################--redireccionamiento comprobante venta--#############################################

@app.route("/comprobantes", methods=['GET'])
def getComprobantes():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/comprobantes'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/comprobantes/<string:id>", methods=['GET'])
def getComprobante(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/comprobantes/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/comprobantes/producto/<string:id_producto>/cliente/<string:id_cliente>", methods=['POST'])
def crearComprobante(id_producto, id_cliente):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/comprobantes/producto/' + id_producto + '/cliente/' + id_cliente
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/comprobantes/<string:id_comprobante>/producto/<string:id_producto>/cliente/<string:id_cliente>", methods=['PUT'])
def modificarComprobante(id_comprobante, id_producto, id_cliente):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/comprobantes/' + id_comprobante + '/producto/' + id_producto + '/cliente/' + id_cliente
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/comprobantes/<string:id>", methods=['DELETE'])
def eliminarComprobante(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/comprobantes/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


############################################################################################################

@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running: " + "http://" + dataConfig["url-backend"] +
          ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])