from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)

# from flaskr.db import get_db

bp = Blueprint('operators', __name__, url_prefix='/operators')

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 12345


@bp.route('/', methods=(['GET']))
def list_operators():
    return jsonify([])
