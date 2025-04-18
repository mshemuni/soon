from datetime import date
from typing import Optional
from pydantic import EmailStr
from ninja import Schema


class PeopleShema(Schema):
    tks_id: str
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    unit: str


class PeopleAddShema(Schema):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    unit: str


class PeoplePatchShema(Schema):
    tks_id: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    unit: Optional[str] = None
