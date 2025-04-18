import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal, Union
from ninja import Router
from ninja import File
from ninja.files import UploadedFile

from soon.errors import DoesNotExistException, AlreadyIsException, FileException, IdentityException
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
        "linked": gpo.linked
    }


def returnify(message, data):
    return {
        "timestamp": int(datetime.now().timestamp() * 1000),
        "message": message,
        "data": data
    }

@router.post('/health-check', response={200: ReturnSchema, 500: ReturnSchema}, tags=["GPO"], description="Health Check")
def health(request):
    try:
        _ = settings.gpo.dn
        staff = request.auth.is_staff
        return 200, returnify("Success", {"is_staff": staff})
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.get('/', response={200: ReturnSchema, 500: ReturnSchema}, tags=["GPO"], description="Returns all GPOs")
def get_gpos(request):
    try:
        gpos = settings.gpo.get()
        return 200, returnify("Success", [gpo_dataclass_to_schema(gpo) for gpo in gpos])
    except Exception as e:
        return 500, returnify(f"{e}", {})


# {"timestamp": 123123, "message": data, "data": json}

@router.get('', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema}, tags=["GPO"],
            description="Returns a GPO")
def get_gpo(request, uuid: str):
    try:
        gpo = settings.gpo.get(uuid)
        return 200, returnify("Success", gpo_dataclass_to_schema(gpo))
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.get('/scripts', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
            tags=["GPO"],
            description="Returns all scripts belong to a GPO")
def get_scripts(request, uuid: str):
    try:
        return 200, returnify("Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.post('/', response={201: ReturnSchema, 402: ReturnSchema, 500: ReturnSchema}, tags=["GPO"],
             description="Creates a GPO")
def create_gpo(request, name: str, container: Optional[str] = None):
    try:
        if not request.auth.is_staff:
            return 401, returnify("Must be Staff", {})
        # returnify("Success", )
        gpo = settings.gpo.create(name, containers=container)
        return 201, returnify("Success", gpo_dataclass_to_schema(gpo))
    except AlreadyIsException as e:
        return 402, returnify(f"{e}", {})
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.delete('/', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema}, tags=["GPO"],
               description="Deletes a GPO")
def delete_gpo(request, uuid: str):
    try:
        if not request.auth.is_staff:
            return 401, returnify("Must be Staff", {})

        settings.gpo.delete(uuid)
        return 200, returnify("GPO Deleted", {})
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.patch('/link', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Links a GPO to a container")
def link_gpo(request, uuid: str, container: str):
    try:
        if not request.auth.is_staff:
            return 401, returnify("Must be Staff", {})

        settings.gpo.link(uuid, container)
        return 200, returnify("Success", gpo_dataclass_to_schema(settings.gpo.get(uuid)))
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except AlreadyIsException as e:
        return 200, gpo_dataclass_to_schema(settings.gpo.get(uuid))
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.patch('/unlink', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Unlinks a GPO from a container. If container not given it will unlink from all containers")
def unlink_gpo(request, uuid: str, container: Optional[str] = None):
    try:
        if not request.auth.is_staff:
            return 401, returnify("Must be Staff", {})

        settings.gpo.unlink(uuid, container)
        return 200, returnify("Success", gpo_dataclass_to_schema(settings.gpo.get(uuid)))
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except AlreadyIsException as e:
        return 200, gpo_dataclass_to_schema(settings.gpo.get(uuid))
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.patch('/script', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Adds a script to a GPO")
def script_add(request, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], parameters: str = "",
               file: UploadedFile = File(...)):
    try:
        if not request.auth.is_staff:
            return 401, returnify("Must be Staff", {})

        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir) / file.name

        with open(temp_path, 'w') as temp_file:
            for line in file:
                temp_file.write(line.decode())

        settings.gpo.add_script(uuid, kind, temp_path, parameters_value=parameters)

        return 200, returnify("Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except FileNotFoundError as e:
        return 404, returnify(f"{e}", {})
    except FileException as e:
        return 500, returnify(f"{e}", {})
    except IdentityException as e:
        return 500, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except AlreadyIsException as e:
        return 200, scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid))
    except Exception as e:
        return 500, returnify(f"{e}", {})


@router.delete('/script', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
               tags=["GPO"],
               description="Removes a script from a GPO")
def script_delete(request, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], script: Union[str, int]):
    try:
        if not request.auth.is_staff:
            return 401, returnify("Must be Staff", {})

        if script.isnumeric():
            the_script = int(script)
        else:
            the_script = script
        settings.gpo.delete_script(uuid, kind, the_script)

        return 200, returnify("Success", scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid)))
    except ValueError as e:
        return 400, returnify(f"{e}", {})
    except FileNotFoundError as e:
        return 404, returnify(f"{e}", {})
    except FileException as e:
        return 500, returnify(f"{e}", {})
    except IdentityException as e:
        return 500, returnify(f"{e}", {})
    except DoesNotExistException as e:
        return 404, returnify(f"{e}", {})
    except AlreadyIsException as e:
        return 200, scripts_dataclass_to_schema(settings.gpo.list_scripts(uuid))
    except Exception as e:
        return 500, returnify(f"{e}", {})
