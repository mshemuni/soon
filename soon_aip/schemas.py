from datetime import datetime
from typing import List, Any

from ninja import Schema

class ReturnSchema(Schema):
    timestamp: int
    message: str
    data: Any

class ScriptSchema(Schema):
    order: int
    script: str
    parameters: str


class ScriptsSchema(Schema):
    login: List[ScriptSchema] = []
    logoff: List[ScriptSchema] = []
    startup: List[ScriptSchema] = []
    shutdown: List[ScriptSchema] = []


class GPOSchema(Schema):
    created_at: datetime
    updated_at: datetime
    name: str
    CN: str
    DN: str
    path: str
    local_path: str
    version: int
    user_extension_names: str
    machine_extension_names: str
    functionality_version: int
    linked_to: List[str]
    # scripts: ScriptsSchema
