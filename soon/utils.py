import configparser
import os
import stat
import shutil
import struct
import tempfile
import uuid
from dataclasses import dataclass, field
from logging import Logger, getLogger
from pathlib import Path
from typing import List, Union, Literal, Optional, Dict
import re

import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

from samba import param
from samba.auth import system_session
from samba.samdb import SamDB
import ldb

from soon.errors import FileException, DoesNotExistException, IdentityException, ActionException


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

    @staticmethod
    def get_list_of_controllers() -> List[str]:
        """
        Returns a list of domain controllers

        Returns
        -------
        List[str] :
            a list of Domain Controllers as COMPUTER_NAME.REALM
        """
        lp = param.LoadParm()
        lp.load_default()

        sam_database = SamDB(session_info=system_session(), lp=lp)

        domain_controllers = sam_database.search(
            base=sam_database.get_default_basedn(),
            scope=ldb.SCOPE_SUBTREE,  # Search entire directory
            expression="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            attrs=["name", "dNSHostName"]
        )

        return [
            str(dc.get("dNSHostName"))
            for dc in domain_controllers
        ]

    @staticmethod
    def gpo_availability(uuid: str) -> Dict[str, bool]:
        """
        Returns a dictionary of availability of a GPO on all domain controllers

        Parameters
        ----------
        uuid : str
            GUID of a GPO

        Returns
        -------
        Dict[str, bool] :
            Availability of a GPO on all domain controllers as a dictionary as {"domain_controller": bool}
        """
        Fixer.uuid(uuid)

        lp = param.LoadParm()
        lp.load_default()

        result = {}
        for dc in Checker.get_list_of_controllers():
            ldap_uri = f"ldap://{dc}"

            samba_database = SamDB(
                url=ldap_uri,
                session_info=system_session(),
                lp=lp
            )

            gpo_dn = f"CN={uuid},CN=Policies,CN=System,{samba_database.domain_dn()}"

            try:
                _ = samba_database.search(
                    base=gpo_dn,
                    scope=ldb.SCOPE_BASE,
                    attrs=["displayName", "gPCFileSysPath", "versionNumber"]
                )
                result[dc] = True

            # except ldb.LdbError as _:
            except:
                result[dc] = False

        return result

    @staticmethod
    def gpo_integrity(uuid: str) -> bool:
        """
        Returns an integrity of a GPO on all domain controllers. True if is/is not available on all controllers

        Parameters
        ----------
        uuid : str
            GUID of a GPO

        Returns
        -------
        bool :
            True if a GPO is or is not available on all controllers
        """
        Fixer.uuid(uuid)

        gpo_availability = Checker.gpo_availability(uuid)
        return all(gpo_availability.values()) or not any(gpo_availability.values())

    @staticmethod
    def is_sid(string: str) -> bool:
        pattern = r"^S-\d+(-\d+)+$"
        return bool(re.match(pattern, string))


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
    def gpo_script_base_path(gpo: GPOObject, kind: Literal["Logon", "Logoff", "Startup", "Shutdown"]) -> Path:
        """
        Checks and creates the script base path.

        Parameters
        ----------
        gpo : GPOObject
            The GPO
        kind : Literal["Logon", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run

        Returns
        -------
        Path :
            The Path object of script base path
        """
        try:
            if kind in ["Logon", "Logoff"]:
                script_base_path = gpo.local_path / "User" / "Scripts" / kind
            else:
                script_base_path = gpo.local_path / "Machine" / "Scripts" / kind

            script_base_path.mkdir(parents=True, exist_ok=True)

            return script_base_path
        except Exception as e:
            raise FileException(f"{e}")

    @staticmethod
    def gpo_script_ini_file(gpo: GPOObject, kind: Literal["Logon", "Logoff", "Startup", "Shutdown"]) -> Path:
        """
        Checks and creates the psscripts.ini file.

        Parameters
        ----------
        gpo : GPOObject
            The GPO
        kind : Literal["Logon", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run

        Returns
        -------
        Path :
            The Path object of psscripts.ini
        """
        try:
            if kind in ["Logon", "Logoff"]:
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
    def script_prepare(gpo: GPOObject, kind: Literal["Logon", "Logoff", "Startup", "Shutdown"],
                       script: Union[str, Path], parameters_value: Optional[str] = None) -> None:
        """
        Copies and creates ldap records and psscripts.ini file in order to add a script to a GPO

        Parameters
        ----------
        gpo : GPOObject
            The GPO
        kind : Literal["Logon", "Logoff", "Startup", "Shutdown"]
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
    def remove_script(file_path: Path, section: str, index_to_remove: int) -> str:
        """
        removes a script from a GPO

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
            script_line = ""

            if section in config:
                if key_cmd in config[section]:
                    script_line = config[section][key_cmd]
                    del config[section][key_cmd]
                else:
                    raise DoesNotExistException("The script does not exist")

                if key_param in config[section]:
                    del config[section][key_param]
                else:
                    raise DoesNotExistException("The script does not exist")

            with open(file_path, 'w') as configfile:
                config.write(configfile)

            if script_line:
                return script_line.split("=")[-1]

            raise ValueError("Couldn't find expected script")
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
            login=Fixer.script_creator(user_scripts_ini, "Logon"),
            logoff=Fixer.script_creator(user_scripts_ini, "Logoff"),
            startup=Fixer.script_creator(machine_scripts_ini, "Startup"),
            shutdown=Fixer.script_creator(machine_scripts_ini, "Shutdown")

        )

    @staticmethod
    def empty_directory(path: Union[str, Path]) -> None:
        """
        Remove a directory and all its contents.

        Parameters:
            path (Union[str, Path]): Path to the directory to remove.
        """
        dir_path = Path(path)
        if not dir_path.exists():
            raise FileNotFoundError(f"No such directory: {dir_path}")
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path}")

        for item in dir_path.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        @staticmethod
        def parse_sddl(sddl: str) -> Dict[str, List[Dict[str, str]]]:
            def parse_ace(ace: str) -> Dict[str, str]:
                parts = ace.strip("()").split(";")
                return {
                    "ace_type": parts[0],
                    "ace_flags": parts[1],
                    "rights": parts[2],
                    "object_guid": parts[3],
                    "inherit_object_guid": parts[4],
                    "sid": parts[5],
                }

            # Split SDDL sections
            parts = re.split(r'([OGDS]:)', sddl)
            structured = {}
            current = None
            for part in parts:
                if part in ['O:', 'G:', 'D:', 'S:']:
                    current = part[0]
                    structured[current] = []
                elif current:
                    # Extract ACEs
                    aces = re.findall(r'\([^\)]+\)', part)
                    structured[current].extend([parse_ace(ace) for ace in aces])
            return structured

    @staticmethod
    def decode_sid(sid_bytes: bytes) -> str:
        # Revision (1 byte) + SubAuthority Count (1 byte) + Identifier Authority (6 bytes)
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

        # SubAuthorities (4 bytes each)
        sub_authorities = [
            struct.unpack('<I', sid_bytes[8 + i * 4:12 + i * 4])[0]
            for i in range(sub_authority_count)
        ]

        # Format SID string
        sid_str = f"S-{revision}-{identifier_authority}" + ''.join(f"-{sa}" for sa in sub_authorities)
        return sid_str

    @staticmethod
    def sign_script(script_path: Union[str, Path], private_key_path: Union[str, Path],
                    out_put_path: Optional[Union[str, Path]] = None, password: Optional[str] = None):
        if isinstance(script_path, str):
            script_path_to_use = Path(script_path)
        else:
            script_path_to_use = script_path

        if isinstance(private_key_path, str):
            private_key_path_to_use = Path(private_key_path)
        else:
            private_key_path_to_use = private_key_path

        if out_put_path is None:
            out_put_path_to_use = script_path_to_use.parent / Path(
                script_path_to_use.stem + "-signed" + script_path_to_use.suffix)
        else:
            if isinstance(out_put_path, str):
                out_put_path_to_use = Path(out_put_path)
            else:
                out_put_path_to_use = out_put_path

        if not script_path_to_use.exists():
            raise FileNotFoundError("Script does not exist")

        if not private_key_path_to_use.exists():
            raise FileNotFoundError("Private key does not exist")

        if out_put_path_to_use.exists():
            raise FileExistsError("Output file already exists")

        command = [
            "osslsigncode", "sign", "-pkcs12", private_key_path_to_use.as_posix(),
            "-in", script_path_to_use.as_posix(), "-out", out_put_path_to_use.as_posix()
        ]

        if password is not None:
            command.extend(["-pass", password])


        try:
            _ = subprocess.run(command, check=True, text=True, capture_output=True)

            Fixer.apply_reference_permissions_and_owner(script_path_to_use, out_put_path_to_use)

            if out_put_path is None:
                script_path_to_use.unlink()
                out_put_path_to_use.rename(script_path)

        except subprocess.CalledProcessError as e:
            raise IdentityException(f"{e}")

    @staticmethod
    def unsign_script(script_path: Union[str, Path], out_put_path: Optional[Union[str, Path]] = None):
        if isinstance(script_path, str):
            script_path_to_use = Path(script_path)
        else:
            script_path_to_use = script_path

        if out_put_path is None:
            out_put_path_to_use = script_path_to_use.parent / Path(
                script_path_to_use.stem + "-signed" + script_path_to_use.suffix)
        else:
            if isinstance(out_put_path, str):
                out_put_path_to_use = Path(out_put_path)
            else:
                out_put_path_to_use = out_put_path

        if not script_path_to_use.exists():
            raise FileNotFoundError("Script does not exist")

        if out_put_path_to_use.exists():
            raise FileExistsError("Output file already exists")

        command = ["osslsigncode", "remove-signature", "-in", script_path_to_use.as_posix(), "-out",
                   out_put_path_to_use.as_posix()]

        try:
            _ = subprocess.run(command, check=True, text=True, capture_output=True)

            Fixer.apply_reference_permissions_and_owner(script_path_to_use, out_put_path_to_use)

            if out_put_path is None:
                script_path_to_use.unlink()
                out_put_path_to_use.rename(script_path)

        except subprocess.CalledProcessError as e:
            raise IdentityException(f"{e}")

    @staticmethod
    def create_keys(name: str,
                    keys_dir: Union[str, Path],
                    pfx_password: Optional[str] = None) -> str:
        """
        Generate private key, certificate, and PFX bundle for code signing,
        storing them under keys_dir/private, keys_dir/public, keys_dir/pfx.

        Parameters
        ----------
        name : str
            Base filename and Common Name (CN) for the certificate.
        keys_dir : str or Path
            Root directory containing private/, public/, and pfx/ subfolders.
        pfx_password : str, optional
            Password for the .pfx bundle. If None, no password is used.

        Returns
        -------
        str
            The key name
        """
        pattern = r'^[A-Za-z_][A-Za-z0-9_]*$'
        if not bool(re.match(pattern, name)):
            raise ValueError("Key name must start with an ascii and can only contain ascii, digits and underscores")


        keys_dir_to_use = Path(keys_dir)
        private_dir = keys_dir_to_use / "private"
        public_dir = keys_dir_to_use / "public"
        pfx_dir = keys_dir_to_use / "pfx"

        for d in [private_dir, public_dir, pfx_dir]:
            d.mkdir(parents=True, exist_ok=True)

        existing_keys = Fixer.get_keys(keys_dir_to_use)

        if name in existing_keys:
            components = existing_keys[name]
            if any(components.values()):
                existing_paths = [str(p) for p in components.values() if p is not None]
                raise FileExistsError(f"Files already exist for name '{name}': {existing_paths}")

        key_file = private_dir / f"{name}.key"
        crt_file = public_dir / f"{name}.crt"
        pfx_file = pfx_dir / f"{name}.pfx"

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(crt_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        try:
            subprocess.run([
                "openssl", "pkcs12", "-export",
                "-out", str(pfx_file),
                "-inkey", str(key_file),
                "-in", str(crt_file),
                "-name", name,
                "-passout", f"pass:{pfx_password or ''}"
            ], check=True)
        except subprocess.CalledProcessError as e:
            raise IdentityException(f"OpenSSL pkcs12 export failed: {e}")

        return name

    @staticmethod
    def get_keys(keys_dir: Union[str, Path]) -> Dict[str, Dict[str, Optional[Path]]]:
        """
        List all available key names with paths to their components as a dictionary.

        Parameters
        ----------
        keys_dir : str or Path
            Root directory containing private/, public/, and pfx/ subfolders.

        Returns
        -------
        Dict[str, Dict[str, Optional[Path]]]
            Dict with:
              key: base key name (str)
              value: dict with keys "private", "public", "pfx" and values Path or None
        """
        keys_dir = Path(keys_dir)
        private_dir = keys_dir / "private"
        public_dir = keys_dir / "public"
        pfx_dir = keys_dir / "pfx"

        names = set()

        for folder, ext in [(private_dir, ".key"), (public_dir, ".crt"), (pfx_dir, ".pfx")]:
            if folder.exists() and folder.is_dir():
                for f in folder.glob(f"*{ext}"):
                    if f.is_file():
                        names.add(f.stem)

        result = {}
        for name in sorted(names):
            private_path = private_dir / f"{name}.key"
            public_path = public_dir / f"{name}.crt"
            pfx_path = pfx_dir / f"{name}.pfx"

            result[name] = {
                "private": private_path if private_path.exists() else None,
                "public": public_path if public_path.exists() else None,
                "pfx": pfx_path if pfx_path.exists() else None,
            }

        return result

    @staticmethod
    def delete_key(name: str, keys_dir: Union[str, Path]) -> None:
        """
        Delete the private key, public certificate, and PFX bundle files
        associated with the given key name, if it exists.

        Parameters
        ----------
        name : str
            Base filename/key name to delete.
        keys_dir : str or Path
            Root directory containing private/, public/, and pfx/ subfolders.
        """
        keys_dir = Path(keys_dir)
        key_map = Fixer.get_keys(keys_dir)

        if name not in key_map:
            raise FileNotFoundError(f"Key {name} not found")

        for file in key_map[name].values():
            if file and file.exists():
                try:
                    file.unlink()
                except Exception:
                    pass
