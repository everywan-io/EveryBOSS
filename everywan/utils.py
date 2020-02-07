import json
from bson import json_util


def mongo_cursor_to_json(mongo_cursor):
    data = [json.loads(json.dumps(item, default=json_util.default))
            for item in mongo_cursor]
    return data
