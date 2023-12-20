from flask import Blueprint, jsonify, current_app
from pydantic import ValidationError
from web3.exceptions import TransactionNotFound
from MySignalsApp import db

error = Blueprint("error", __name__)


class UtilError(Exception):
    def __init__(self, error, code, message):
        self.error = error
        self.code = code
        self.message = message


@error.teardown_app_request
def clean_up(exc):
    try:
        db.session.remove()
    except:
        pass


@error.app_errorhandler(UtilError)
def resource_not_found(err):
    return (
        jsonify({"error": err.error, "message": err.message, "status": False}),
        err.code,
    )


@error.app_errorhandler(ValidationError)
def input_validation_error(e):
    msg = [{"field": err["loc"][0], "error": err["msg"]} for err in e.errors()]
    return (
        jsonify({"error": "Bad Request", "message": msg, "status": False}),
        400,
    )


@error.app_errorhandler(TransactionNotFound)
def transaction_not_fount(e):
    return (
        jsonify({"error": "Resource not found", "message": str(e), "status": False}),
        404,
    )


@error.app_errorhandler(400)
def bad_request(error):
    return (
        jsonify({"error": error.name, "message": error.description, "status": False}),
        400,
    )


@error.app_errorhandler(404)
def resource_not_found(error):
    return (
        jsonify({"error": error.name, "message": error.description, "status": False}),
        404,
    )


@error.app_errorhandler(405)
def method_not_allowed(error):
    return (
        jsonify({"error": error.name, "message": error.description, "status": False}),
        405,
    )


@error.app_errorhandler(422)
def cant_process(error):
    return (
        jsonify({"error": error.name, "message": error.description, "status": False}),
        422,
    )


@error.app_errorhandler(429)
def cant_process(error):
    return (
        jsonify({"error": error.name, "message": error.description, "status": False}),
        429,
    )


@error.app_errorhandler(500)
def server_error(error):
    current_app.log_exception(exc_info=error)
    return (
        jsonify(
            {"error": error.name, "message": "Its not you its us", "status": False}
        ),
        500,
    )
