import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal, Union, List
from ninja import Router, Query
from ninja import File, Body
from ninja.files import UploadedFile

from soon import GPO
from soon.errors import DoesNotExistException, AlreadyIsException, FileException, IdentityException, ActionException
from soon.utils import GPOObject, Script, GPOScripts
from soon_aip import settings

from soon_aip.schemas import ReturnSchema, ScriptAsText

router = Router()


def script_dataclass_to_schema(script: Script):
    return {
        "order": script.order,
        "script_path": str(script.script),
        "script_name": str(script.script.name),
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        gpos = gpo.get(uuid)
        if uuid is None:
            return returnify(200, "Success", [gpo_dataclass_to_schema(the_gpo) for the_gpo in gpos])
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        _ = gpo.dn
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

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        the_gpo = gpo.create(name)

        if isinstance(the_gpo, str):
            return returnify(202, "Success", the_gpo)

        return returnify(201, "Success", gpo_dataclass_to_schema(the_gpo))

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

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        gpo.link_single(uuid, container)
        return returnify(200, "Success", gpo_dataclass_to_schema(gpo.get(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except AlreadyIsException as _:
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Already Exist", gpo_dataclass_to_schema(gpo.get(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        gpo.unlink_single(uuid, container)
        return returnify(200, "Success", gpo_dataclass_to_schema(gpo.get(uuid)))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except ActionException as e:
        return returnify(409, f"{e}", {})
    except AlreadyIsException as _:
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Success", gpo_dataclass_to_schema(gpo.get(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/script',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Adds a script to a GPO, Script kinds can be: `Login`, `Logoff`, `Startup`, `Shutdown`")
def script_add(request, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], parameters: str = "",
               overwrite: bool = False, file: UploadedFile = File(...)):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir) / file.name

        with open(temp_path, 'w') as temp_file:
            for line in file:
                temp_file.write(line.decode())

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))

        scripts = gpo.list_scripts(uuid)
        for each_script in getattr(scripts, kind.lower()):
            if each_script.script.name == Path(temp_file.name).name:
                if overwrite:
                    gpo.delete_script(uuid, kind, each_script.order)
                    each_script.script.unlink()

        gpo.add_script(uuid, kind, temp_path, parameters_value=parameters)

        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/script/multiple',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Adds a script to a GPO, Script kinds can be a combination of: `Login`, `Logoff`, `Startup`, `Shutdown`")
def script_add_multiple(request, uuid: str, kinds: List[Literal["Login", "Logoff", "Startup", "Shutdown"]] = Query(...),
                        parameters: str = "", overwrite: bool = False, file: UploadedFile = File(...)):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir) / file.name

        with open(temp_path, 'w') as temp_file:
            for line in file:
                temp_file.write(line.decode())

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))

        scripts = gpo.list_scripts(uuid)
        for kind in kinds:
            for each_script in getattr(scripts, kind.lower()):
                if each_script.script.name == Path(temp_file.name).name:
                    if overwrite:
                        gpo.delete_script(uuid, kind, each_script.order)
                        each_script.script.unlink()

            gpo.add_script(uuid, kind, temp_path, parameters_value=parameters)

        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/script/text',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Adds a script to a GPO, Script kinds can be: `Login`, `Logoff`, `Startup`, `Shutdown`")
def script_add_text(request, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"],
                    body: ScriptAsText = Body(...),
                    parameters: str = ""):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))

        gpo.add_script(uuid, kind, body.script, parameters_value=parameters)

        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.patch('/script/text/multiple',
              response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
              tags=["GPO"],
              description="Adds a script to a GPO, Script kinds can be a combination of: `Login`, `Logoff`, `Startup`, `Shutdown`")
def script_add_multiple_text(request, uuid: str,
                             kinds: List[Literal["Login", "Logoff", "Startup", "Shutdown"]] = Query(...),
                             body: ScriptAsText = Body(...),
                             parameters: str = ""):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))

        for kind in kinds:
            gpo.add_script(uuid, kind, body.script, parameters_value=parameters)

        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.delete('',
               response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
               tags=["GPO"], description="Deletes a GPO")
def delete_gpo(request, uuid: str):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))

        gpo.delete(uuid)
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
def script_delete(request, uuid: str, script: Union[str, int], kind: Literal["Login", "Logoff", "Startup", "Shutdown"]):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        if script.isnumeric():
            the_script = int(script)
        else:
            the_script = script

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        gpo.delete_script(uuid, kind, the_script)

        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.delete('/script/multiple',
               response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 409: ReturnSchema, 500: ReturnSchema},
               tags=["GPO"],
               description="Removes scripts from a GPO. Deleting a script requires the script name or Order in the script parameter")
def script_delete_multiple(request, uuid: str,
                           script: Union[str, int],
                           kinds: List[Literal["Login", "Logoff", "Startup", "Shutdown"]] = Query(...)):
    try:
        if not request.auth.is_staff:
            return returnify(401, "Must be Staff", {})

        if script.isnumeric():
            the_script = int(script)
        else:
            the_script = script

        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        for kind in kinds:
            gpo.delete_script(uuid, kind, the_script)

        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Success", scripts_dataclass_to_schema(gpo.list_scripts(uuid)))
    except Exception as e:
        return returnify(500, f"{e}", {})


@router.get('/integrity', response={200: ReturnSchema, 400: ReturnSchema, 404: ReturnSchema, 500: ReturnSchema},
            tags=["GPO"],
            description="Returns GPO's Integrity")
def get_gpo_integrity(request, uuid: str):
    try:
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Success", gpo.integrity(uuid))
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
        gpo = GPO(settings.soon_admin, settings.soon_password, machine=settings.machine,
                  logger=settings.logging.getLogger('soon_api'))
        return returnify(200, "Success", gpo.availability(uuid))
    except ValueError as e:
        return returnify(400, f"{e}", {})
    except DoesNotExistException as e:
        return returnify(404, f"{e}", {})
    except Exception as e:
        return returnify(500, f"{e}", {})
