import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal, Union
from ninja import Router
from ninja import File
from ninja.files import UploadedFile

from soon.errors import DoesNotExistException, AlreadyIsException, FileException, IdentityException, ActionException
from soon.utils import GPOObject, Script, GPOScripts
from soon_aip import settings

from soon_aip.schemas import ReturnSchema

router = Router()


def script_dataclass_to_schema(script: Script):
    return {
        "order": script.order,
        "script": str(script.script),
        "parameters": script.parameters
    }


def scripts_dataclass_to_schema(scripts: GPOScripts):
    return {
        "login": [script_dataclass_to_schema(each) for each in scripts.login],
        "logoff": [script_dataclass_to_schema(each) for each in scripts.logoff],
        "startup": [script_dataclass_to_schema(each) for each in scripts.startup],
        "shutdown": [script_dataclass_to_schema(each) for each in scripts.shutdown],
    }


def gpo_dataclass_to_schema(gpo: GPOObject):
    return {
        "created_at": gpo.created_at,
        "updated_at": gpo.updated_at,
        "name": gpo.name,
        "CN": gpo.CN,
        "DN": gpo.DN,
        "path": gpo.path,
        "local_path": str(gpo.local_path),
        "version": gpo.version,
        "user_extension_names": gpo.user_extension_names,
        "machine_extension_names": gpo.machine_extension_names,
        "functionality_version": gpo.functionality_version,
        "linked_to": gpo.linked_to
    }


def returnify(status, message, data):
    return status, {
        "timestamp": int(datetime.now().timestamp() * 1000),
        "status": status,
        "message": message,
        "data": data
    }


@router.get('', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema}, tags=["GPO"],
            description="Returns a GPO if `uuid` is given, all GPOs if `uuid` is not provided")
def get_gpos(request, uuid: Optional[str] = None):
    try:
        gpos = settings.gpo.get(uuid)
        if uuid is None:
            return returnify(200, "Success", [gpo_dataclass_to_schema(gpo) for gpo in gpos])
        else:
            return returnify(200, "Success", gpo_dataclass_to_schema(gpos))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.get('/scripts',
            response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
            tags=["GPO"],
            description="Returns all scripts belong to a GPO")
def get_scripts(request, uuid: str):
    try:
        return returnify(200, "Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.post('/health-check', response={200: ReturnSchema, 500: ReturnSchema}, tags=["GPO"], description="Health Check")
def health_check(request):
    try:
        _ = settings.gpo.dn
        staff = request.auth.is_staff
        return returnify(200, "Success", {"is_staff": staff})
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.post('', response={201: ReturnSchema, 202: ReturnSchema, 402: ReturnSchema, 500: ReturnSchema}, tags=["GPO"],
             description="Creates a GPO. `201` means a GPO is created and is available over all domain controllers and "
                         "a GPO object is returned. `202` mean a GPO is created but it is not available over all "
                         "domain controllers and a GUID is returned as a string.")
def create_gpo(request, name: str):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        gpo = settings.gpo.create(name)

        if isinstance(gpo, str):
            return returnify(202, "Success", gpo)

        return returnify(201, "Success", gpo_dataclass_to_schema(gpo))

    except AlreadyIsException as e:
        return returnify(402, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/link',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Links a GPO to a container")
def link_gpo(request, uuid: str, container: str):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        settings.gpo.link_single(uuid, container)
        return returnify(200, "Success", gpo_dataclass_to_schema(settings.gpo.get(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except AlreadyIsException as _:
        return returnify(200, "Already Exist", gpo_dataclass_to_schema(settings.gpo.get(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/unlink',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Unlinks a GPO from a container. If container not given it will unlink from all containers")
def unlink_gpo(request, uuid: str, container: Optional[str] = None):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        settings.gpo.unlink_single(uuid, container)
        return returnify(200, "Success", gpo_dataclass_to_schema(settings.gpo.get(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except AlreadyIsException as _:
        return returnify(200, "Success", gpo_dataclass_to_schema(settings.gpo.get(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/script',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Adds a script to a GPO, Script kinds can be: `Login`, `Logoff`, `Startup`, `Shutdown`")
def script_add(request, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], parameters: str = "",
               file: UploadedFile = File(...)):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir) / file.name

        with open(temp_path, 'w') as temp_file:
            for line in file:
                temp_file.write(line.decode())
        settings.gpo.add_script(uuid, kind, temp_path, parameters_value=parameters)

        return returnify(200, "Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except FileNotFoundError as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except FileException as e:
        return returnify(500, f"{e}", {})
    except IdentityException as e:
        return returnify(500, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except AlreadyIsException as _:
        return returnify(200, "success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.delete('',
               response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
               tags=["GPO"], description="Deletes a GPO")
def delete_gpo(request, uuid: str):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        settings.gpo.delete(uuid)
        return returnify(200, "GPO Deleted", {})
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.delete('/script',
               response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
               tags=["GPO"],
               description="Removes a script from a GPO. Deleting a script requires the script name or Order in the script parameter")
def script_delete(request, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], script: Union[str, int]):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        if script.isnumeric():
            the_script = int(script)
        else:
            the_script = script
        settings.gpo.delete_script(uuid, kind, the_script)

        return returnify(200, "Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except FileNotFoundError as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except FileException as e:
        return returnify(500, f"{e}", {})
    except IdentityException as e:
        return returnify(500, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except AlreadyIsException as _:
        return returnify(200, "Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.get('/integrity', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
            tags=["GPO"],
            description="Returns GPO's Integrity")
def get_gpo_integrity(request, uuid: str):
    try:

        return returnify(200, "Success", settings.gpo.integrity(uuid))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.get('/availability', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
            tags=["GPO"],
            description="Returns GPO's Availability")
def get_gpo_availability(request, uuid: str):
    try:

        return returnify(200, "Success", settings.gpo.availability(uuid))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})
