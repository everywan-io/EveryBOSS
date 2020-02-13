#  Copyright 2020 Francesco Lombardo
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import json
from bson import json_util


def mongo_cursor_to_json(mongo_cursor):
    data = [json.loads(json.dumps(id_to_string(item), default=json_util.default))
            for item in mongo_cursor]
    return data


def id_to_string(item):
    item._id = str(item._id)
    return item
