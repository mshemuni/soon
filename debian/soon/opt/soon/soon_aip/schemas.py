from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID
from ninja import Schema
from pydantic import RootModel, ConfigDict, BaseModel


class ReturnSchema(Schema):
    timestamp: int
    status: int
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


class ScriptAsText(Schema):
    script: str


class TrusteeSchema(Schema):
    trustee: str


class TrusteesSchema(Schema):
    trustees: List[str]


class ScriptFileSchema(Schema):
    scripts: List[str]
