from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)

# from everywan.db import get_db

bp = Blueprint('operators', __name__, url_prefix='/operators')


@bp.route('/', methods=(['GET']))
def list_operators():
    return jsonify([])
