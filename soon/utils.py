import configparser
import os
import stat
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from logging import Logger, getLogger
from pathlib import Path
from typing import List, Union, Literal, Optional
import re

from soon.errors import FileException, DoesNotExistException


@dataclass
class Script:
    order: int
    script: Path
    parameters: str


@dataclass
class GPOScripts:
    login: List[Script] = field(default_factory=list)
    logoff: List[Script] = field(default_factory=list)
    startup: List[Script] = field(default_factory=list)
    shutdown: List[Script] = field(default_factory=list)


@dataclass
class GPOObject:
    created_at: datetime
    updated_at: datetime
    name: str
    CN: str
    DN: str
    path: str
    local_path: Path
    version: int
    user_extension_names: str
    machine_extension_names: str
    functionality_version: int
    linked_to: List[str]


class Checker:
    @staticmethod
    def safe(value: str, the_field: str = "input") -> None:
        """
        Checks if the given value is safe

        Parameters
        ----------
        value : str
            The value to be checked
        the_field : str
            The name of the value

        Returns
        -------
        None
        """
        if not re.match(r"^[\w\-.]+$", value):
            raise ValueError(f"Unsafe characters detected in {the_field}: '{value}'")

    @staticmethod
    def uuid(uuid: str) -> None:
        """
        Checks if the given value is uuid

        Parameters
        ----------
        uuid : str
            The uuid to be checked

        Returns
        -------
        None
        """
        if not re.match(r"^\{?[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$", uuid):
            raise ValueError(f"Invalid UUID format: '{uuid}'")

    @staticmethod
    def check_integrity(config: configparser.ConfigParser, section: str) -> bool:
        """
        Checks the integrity of the ini file.

        Parameters
        ----------
        config : configparser.ConfigParser
            The configparser of the given file
        section : str
            The section to be checked

        Returns
        -------
        bool :
            True if the integrity is held
        """
        if section not in config.sections():
            config.add_section(section)

        cmdline_keys = [key for key in config[section] if 'CmdLine' in key]
        param_keys = [key for key in config[section] if 'Parameters' in key]

        if len(cmdline_keys) != len(param_keys):
            raise FileException("psscripts.ini file integrity error")

        for i in range(len(cmdline_keys)):
            cmd_key = cmdline_keys[i]
            param_key = param_keys[i]
            if int(cmd_key[:-7]) != int(param_key[:-10]):
                raise FileException("psscripts.ini file integrity error")

        return True


class Fixer:
    @staticmethod
    def uuid(uuid: str) -> str:
        """
        Checks if the given value is uuid

        Parameters
        ----------
        uuid : str
            The uuid to be checked

        Returns
        -------
        None
        """

        matcher = r"^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$"
        if re.match(matcher, uuid):
            return uuid

        if re.match(matcher, f"{{{uuid}}}"):
            return f"{{{uuid}}}"

        raise ValueError(f"Invalid UUID format: '{uuid}'")

    @staticmethod
    def logger(logger: Optional[Logger] = None, name: Optional[str] = None) -> Logger:
        """
        Checks if a logger is passed as an argument. If not, it returns a logger with the specified name
        or a default name.


        Parameters
        ----------
        logger: Logger, default = None
            An optional Logger instance.
        name: str, default = None
            An optional string representing the name of the logger.

        Returns
        -------
        units.Quantity
            The converted value in time.
        """
        if logger is None:
            if name is None:
                return getLogger("soon")
            else:
                return getLogger(name)
        else:
            return logger

    @staticmethod
    def apply_reference_permissions_and_owner(reference: Path, target: Path) -> None:
        """
        Changes all permissions and ownership of the target path to be the same as reference. Recursivly

        Parameters
        ----------
        reference : Path
            The configparser of the given file
        target : Path
            The section to be checked

        Returns
        -------
        None
        """

        def apply(ref: Path, dest: Path):
            ref_stat = ref.stat()
            dest.chmod(stat.S_IMODE(ref_stat.st_mode))
            os.chown(dest, ref_stat.st_uid, ref_stat.st_gid)

        try:
            reference = Path(reference)
            target = Path(target)

            if not reference.exists() or not target.exists():
                raise FileNotFoundError("Reference and target must both exist")

            apply(reference, target)

            for item in target.rglob('*'):
                if item.is_symlink():
                    continue
                apply(reference, item)
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def script(script: Union[str, Path]) -> Path:
        """
        Changes the script.
        If the script is a Path it returns it.
        if it is a path as str it creates a Path and returns it.
        if it is the body of the script it creates a temp script and return the Path of the file.

        Parameters
        ----------
        script : Union[str, Path]
            It can be a Path object of a given script. It also can be the path as string.
            It also can be a command as string. A script file would be automatically created.

        Returns
        -------
        Path :
            The Path object of the script.
        """
        if isinstance(script, Path):
            if not script.is_file():
                raise FileNotFoundError("Script not found")

            return script

        script_path = Path(script)
        if script_path.is_file():
            return script_path

        with tempfile.NamedTemporaryFile(
                delete=False, mode='w', encoding='utf-8',
                prefix="soon_", suffix=".ps1"
        ) as temp_file:
            temp_file.write(script)
            return Path(temp_file.name)

    @staticmethod
    def gpo_script_base_path(gpo: GPOObject, kind: Literal["Login", "Logoff", "Startup", "Shutdown"]) -> Path:
        """
        Checks and creates the script base path.

        Parameters
        ----------
        gpo : GPOObject
            The GPO
        kind : Literal["Login", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run

        Returns
        -------
        Path :
            The Path object of script base path
        """
        try:
            if kind in ["Login", "Logoff"]:
                script_base_path = gpo.local_path / "User"/ "Scripts" / kind
            else:
                script_base_path = gpo.local_path / "Machine"/ "Scripts" / kind

            script_base_path.mkdir(parents=True, exist_ok=True)

            return script_base_path
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def gpo_script_ini_file(gpo: GPOObject, kind: Literal["Login", "Logoff", "Startup", "Shutdown"]) -> Path:
        """
        Checks and creates the psscripts.ini file.

        Parameters
        ----------
        gpo : GPOObject
            The GPO
        kind : Literal["Login", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run

        Returns
        -------
        Path :
            The Path object of psscripts.ini
        """
        try:
            if kind in ["Login", "Logoff"]:
                script_ini_file = gpo.local_path / "User" / "Scripts" / "psscripts.ini"
            else:
                script_ini_file = gpo.local_path / "Machine" / "Scripts" / "psscripts.ini"

            if not script_ini_file.exists():
                script_ini_file.touch()

            return script_ini_file
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def copy_with_unique_name(src_path: Path, dest_dir: Path) -> Path:
        """
        Copies the source file to the destination file and makes sure it does not overwrite another file

        Parameters
        ----------
        src_path : Path
            The source file to be copied
        dest_dir : Path
            The destination

        Returns
        -------
        Path :
            The Path object destination file
        """
        try:
            dest_path = dest_dir / src_path.name

            if dest_path.exists():
                stem = src_path.stem
                suffix = src_path.suffix
                unique_suffix = f"_{uuid.uuid4().hex[:8]}"
                dest_path = dest_dir / f"{stem}{unique_suffix}{suffix}"

            shutil.copy2(src_path, dest_path)
            return dest_path
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def script_creator(file_path: Path, section: str) -> List[Script]:
        """
        Returns all scripts in the given psscripts.ini file section

        Parameters
        ----------
        file_path : Path
            The Path of the psscripts.ini
        section : str
            The section of the psscripts.ini. It is the kind

        Returns
        -------
        List[Script] :
            The list of scripts defined in a psscripts.ini's section
        """

        if not file_path.exists():
            return []

        config = configparser.ConfigParser()
        config.optionxform = str
        config.read(file_path)

        if not config.has_section(section):
            return []

        Checker.check_integrity(config, section)

        pairs = []
        cmdline_keys = [key for key in config[section] if 'CmdLine' in key]
        param_keys = [key for key in config[section] if 'Parameters' in key]
        for i in range(len(cmdline_keys)):
            cmd_key = cmdline_keys[i]
            param_key = param_keys[i]
            pairs.append(
                Script(
                    order=int(param_key[0]),
                    script=file_path.parent / section / config[section][cmd_key],
                    parameters=config[section][param_key]
                )
            )

        return pairs

    @staticmethod
    def add_ordered_entry(file_path: Path, section: str, cmdline_value: Path, parameters_value: str = "") -> None:
        """
        Adds a new entry to a psscripts.ini file section

        Parameters
        ----------
        file_path : Path
            The Path of the psscripts.ini
        section : str
            The section of the psscripts.ini. It is the kind
        cmdline_value : Path
            The Path object of the script file
        parameters_value : str
            The parameters of the script

        Returns
        -------
        None
        """
        try:
            config = configparser.ConfigParser()
            config.optionxform = str  # preserve case
            config.read(file_path)

            Checker.check_integrity(config, section)

            if not config.has_section(section):
                config.add_section(section)

            indices = [
                int(key[0]) for key in config[section]
                if key.endswith("CmdLine") and key[0].isdigit()
            ]
            next_index = max(indices, default=-1) + 1

            config.set(section, f"{next_index}CmdLine", cmdline_value.name)
            config.set(section, f"{next_index}Parameters", parameters_value)

            with open(file_path, 'w') as f:
                config.write(f)
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def script_prepare(gpo: GPOObject, kind: Literal["Login", "Logoff", "Startup", "Shutdown"],
                       script: Union[str, Path], parameters_value: Optional[str] = None) -> None:
        """
        Copies and creates ldap records and psscripts.ini file in order to add a script to a GPO

        Parameters
        ----------
        gpo : GPOObject
            The GPO
        kind : Literal["Login", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run
        script : Union[str, Path]
            It can be a Path object of a given script. It also can be the path as string.
            It also can be a command as string. A script file would be automatically created.
        parameters_value: str
            The parameters to be passwed to the script as it runs.

        Returns
        -------
        None
        """
        script_base_path = Fixer.gpo_script_base_path(gpo, kind=kind)
        script_path = Fixer.copy_with_unique_name(script, script_base_path)
        psscript_path = Fixer.gpo_script_ini_file(gpo, kind=kind)
        Fixer.add_ordered_entry(psscript_path, kind, script_path, parameters_value)
        Fixer.apply_reference_permissions_and_owner(gpo.local_path, gpo.local_path)

    @staticmethod
    def script_to_order(file_path: Path, section: str, script: Union[str, Path]) -> int:
        """
        Returns an integer. The order of the given script of a GPO

        Parameters
        ----------
        file_path : Path
            The Path of the psscripts.ini
        section : str
            The section of the psscripts.ini. It is the kind
        script : Union[str, Path]
            The Path object of the script file or the path of the script file as string

        Returns
        -------
        int :
            The order of the script
        """
        try:
            if isinstance(script, Path):
                script_name = script.name
            else:
                script_name = Path(script).name

            config = configparser.ConfigParser()
            config.optionxform = str  # preserve key case
            config.read(file_path)

            if section not in config:
                return -1  # or raise an exception if preferred

            for key in config[section]:
                if key.endswith("CmdLine") and config[section][key] == script_name:
                    try:
                        index = int(key[0])
                        return index
                    except ValueError as e:
                        continue

            return -1
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def remove_script(file_path: Path, section: str, index_to_remove: int) -> None:
        """
        Returns an script from a GPO

        Parameters
        ----------
        file_path : Path
            The Path of the psscripts.ini
        section : str
            The section of the psscripts.ini. It is the kind
        index_to_remove : int
            The index of the script of the GPO

        Returns
        -------
        None
        """
        try:
            config = configparser.ConfigParser()
            config.optionxform = str
            config.read(file_path)

            key_cmd = f"{index_to_remove}CmdLine"
            key_param = f"{index_to_remove}Parameters"

            if section in config:
                if key_cmd in config[section]:
                    del config[section][key_cmd]
                else:

                    raise DoesNotExistException("The script does not exist")

                if key_param in config[section]:
                    del config[section][key_param]
                else:
                    raise DoesNotExistException("The script does not exist")

            with open(file_path, 'w') as configfile:
                config.write(configfile)
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def scripts(gpo: GPOObject) -> GPOScripts:
        """
        Returns all scripts belonging to a GPO

        Parameters
        ----------
        gpo : GPOObject
            The GPO

        Returns
        -------
        GPOScripts :
            All scripts defined in all psscripts.ini files
        """
        user_scripts_ini = gpo.local_path / "User" / "Scripts" / "psscripts.ini"
        machine_scripts_ini = gpo.local_path / "Machine" / "Scripts" / "psscripts.ini"

        return GPOScripts(
            login=Fixer.script_creator(user_scripts_ini, "Login"),
            logoff=Fixer.script_creator(user_scripts_ini, "Logoff"),
            startup=Fixer.script_creator(machine_scripts_ini, "Startup"),
            shutdown=Fixer.script_creator(machine_scripts_ini, "Shutdown")

        )
