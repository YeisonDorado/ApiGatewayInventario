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

app.config["JWT_SECRET_KEY"] = "super-secret"  # Cambiar por el que se conveniente
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
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

@app.route("/usuarios", methods=['GET'])
def getUsuarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios", methods=['POST'])
def crearUsuario():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/usuarios/<string:id>", methods=['GET'])
def getUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>", methods=['PUT'])
def modificarUsuario(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/usuarios/<string:id>", methods=['DELETE'])
def eliminarUsuario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id
    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        # Si el estado es 204 No Content, devolver un mensaje adecuado
        return jsonify({'message': 'Usuario eliminado exitosamente'}), 200
    else:
        try:
            json_response = response.json() if response.content else None
        except requests.exceptions.JSONDecodeError:
            json_response = None

        error_message = {
            'error': 'Error al eliminar el usuario',
            'details': json_response if json_response else 'Respuesta no es JSON válido o está vacía'
        }
        return jsonify(error_message), response.status_code

@app.route("/usuarios/<string:id>/rol/<string:id_rol>", methods=['PUT'])
def asignarRolAUsuario(id, id_rol):
    #data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/' + id + '/rol/' + id_rol
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)




################################--redireccionamiento rol--######################################

@app.route("/roles", methods=['GET'])
def getRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)
@app.route("/roles", methods=['POST'])
def crearRol():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/roles/<string:id>", methods=['GET'])
def getRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>", methods=['PUT'])
def modificarRol(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/roles/<string:id>", methods=['DELETE'])
def eliminarRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/roles/' + id
    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        # Si el estado es 204 No Content, devolver un mensaje adecuado
        return jsonify({'message': 'Rol eliminado exitosamente'}), 200
    else:
        try:
            json_response = response.json() if response.content else None
        except requests.exceptions.JSONDecodeError:
            json_response = None

        error_message = {
            'error': 'Error al eliminar el rol',
            'details': json_response if json_response else 'Respuesta no es JSON válido o está vacía'
        }
        return jsonify(error_message), response.status_code




################################--redireccionamiento permiso--######################################

@app.route("/permisos", methods=['GET'])
def getPermisos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos", methods=['POST'])
def crearPermiso():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>", methods=['GET'])
def getPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos/<string:id>", methods=['PUT'])
def modificarPermiso(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/permisos/<string:id>", methods=['DELETE'])
def eliminarPermiso(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos/' + id
    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        # Si el estado es 204 No Content, devolver un mensaje adecuado
        return jsonify({'message': 'Permiso eliminado exitosamente'}), 200
    else:
        try:
            json_response = response.json() if response.content else None
        except requests.exceptions.JSONDecodeError:
            json_response = None

        error_message = {
            'error': 'Error al eliminar el permiso',
            'details': json_response if json_response else 'Respuesta no es JSON válido o está vacía'
        }
        return jsonify(error_message), response.status_code


################################--redireccionamiento permiso-rol --###################################
@app.route("/permisos-roles", methods=['GET'])
def getPermisosRoles():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/rol/<string:id_rol>/permiso/<string:id_permiso>", methods=['POST'])
def crearPermisoRol(id_rol, id_permiso):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/rol/' + id_rol + '/permiso/' + id_permiso
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>", methods=['GET'])
def getPermisoRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id
    response = requests.get(url, headers=headers)
    print("respuesta del servidor", response)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id_per_rol>/rol/<string:id_rol>/permiso/<string:id_permiso>", methods=['PUT'])
def modificarPermisoRol(id_per_rol, id_rol, id_permiso):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id_per_rol + '/rol/' + id_rol + '/permiso/' + id_permiso
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/permisos-roles/<string:id>", methods=['DELETE'])
def eliminarPermisoRol(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/permisos-roles/' + id
    response = requests.delete(url, headers=headers)

    if response.status_code == 204:
        # Si el estado es 204 No Content, devolver un mensaje adecuado
        return jsonify({'message': 'Permiso-rol eliminado exitosamente'}), 200
    else:
        try:
            json_response = response.json() if response.content else None
        except requests.exceptions.JSONDecodeError:
            json_response = None

        error_message = {
            'error': 'Error al eliminar el permiso-rol',
            'details': json_response if json_response else 'Respuesta no es JSON válido o está vacía'
        }
        return jsonify(error_message), response.status_code

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
@app.route("/productos", methods=['GET'])
def getProductos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/productos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/productos", methods=['POST'])
def crearProducto():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/productos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['GET'])
def getProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/productos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['PUT'])
def modificarProducto(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/productos/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['DELETE'])
def eliminarProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/productos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>/proveedor/<string:id_proveedor>", methods=['PUT'])
def asignarProveedorAProducto(id, id_proveedor):
    #data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/productos/' + id + '/proveedor/' + id_proveedor
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)


##########################--redireccionamiento proveedor--#############################################
@app.route("/proveedores", methods=['GET'])
def getProveedores():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/proveedores'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/proveedores", methods=['POST'])
def crearProveedor():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/proveedores'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/proveedores/<string:id>", methods=['GET'])
def getProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/proveedores/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/proveedores/<string:id>", methods=['PUT'])
def modificarProveedor(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/proveedores/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)
@app.route("/proveedores/<string:id>", methods=['DELETE'])
def eliminarProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventory"] + '/proveedores/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)





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


@app.route("/comprobantes/<string:id_comprobante>/producto/<string:id_producto>/cliente/<string:id_cliente>",
           methods=['PUT'])
def modificarComprobante(id_comprobante, id_producto, id_cliente):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig[
              "url-backend-inventory"] + '/comprobantes/' + id_comprobante + '/producto/' + id_producto + '/cliente/' + id_cliente
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
