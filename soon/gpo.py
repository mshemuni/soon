import re
import shutil
import subprocess
import uuid as pyuuid
from datetime import datetime
from logging import Logger
from pathlib import Path
from typing import Optional, List, Union, Literal, Dict

from functools import wraps

from soon.errors import DoesNotExistException, AlreadyIsException, FileException, IdentityException, ActionException

from samba.netcmd.gpo import get_gpo_dn
from samba import param
from samba.auth import system_session
from samba.samdb import SamDB

import ldb

from .models import GPOModel
from .utils import GPOObject, Checker, Fixer, GPOScripts

class GPO(GPOModel):
    def __init__(self, user: str, passwd: str, machine: Optional[str] = None, logger: Optional[Logger] = None) -> None:

        Checker.safe(user, "Username")
        Checker.safe(passwd, "Password")

        self.user = user
        self.passwd = passwd
        self.machine = machine

        self.logger = Fixer.logger(logger)

        self.lp = param.LoadParm()
        self.lp.load_default()

        self.sysvol_root = self.lp.get("path", "sysvol")

        try:
            url = f"ldap://{self.machine}" if self.machine is not None else None
            self.sam_database = SamDB(url=url, session_info=system_session(), lp=self.lp)
        except ldb.LdbError as e:
            raise DoesNotExistException(e)

        self.ATTRS = ["displayName", "name", "distinguishedName", "gPCFileSysPath", "whenCreated", "whenChanged",
                      "versionNumber", "gPCUserExtensionNames", "gPCMachineExtensionNames", "gPCFunctionalityVersion"]
        self.CSE = {
            "Login": {
                "gPCUserExtensionNames": "[{42B5FA88-6536-11D2-AE5A-0000F87571E3}]"
            },
            "Logoff": {
                "gPCUserExtensionNames": "[{42B5FA88-6536-11D2-AE5A-0000F87571E3}]"
            },
            "Startup": {
                "gPCMachineExtensionNames": "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
            },
            "Shutdown": {
                "gPCMachineExtensionNames": "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
            },
        }

    def __container_exists(self, dn: str) -> bool:
        """
        Checks if the given container exists

        Parameters
        ----------
        dn : str
            A single container (DN string) or a list of containers to which the GPO will be linked.

        Returns
        -------
        bool :
            True if the container exists
        """
        self.logger.info(f"Checking if the container does exist. param({dn=})")

        try:
            result = self.sam_database.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["distinguishedName"])
            return bool(result)
        except:
            return False

    def __gpo_object_creator(self, gpo: ldb.Message) -> GPOObject:
        """
        Creates a GPO object from a ldb.Message

        Parameters
        ----------
        gpo : ldb.Message
            The message returned by ldb.

        Returns
        -------
        GPOObject :
            A GPOObject object
        """
        self.logger.info("Creating a GPOObject from the ldb.Message")

        return GPOObject(
            created_at=datetime.strptime(str(gpo.get("whenCreated", None)[0]), "%Y%m%d%H%M%S.%fZ"),
            updated_at=datetime.strptime(str(gpo.get("whenChanged", None)[0]), "%Y%m%d%H%M%S.%fZ"),
            name=str(gpo.get("displayName", ["<No Name>"])[0]),
            CN=str(gpo.get("name", ["<No CN>"])[0]),
            path=str(gpo.get("gPCFileSysPath", ["<No Path>"])[0]),
            local_path=Path(self.sysvol_root) / str(self.realm) / "Policies" / str(gpo.get("name", ["<No PATH>"])[0]),
            DN=str(gpo.get("distinguishedName", ["<No DN>"])[0]),
            version=int(gpo.get("versionNumber", [-1])[0]),
            user_extension_names=str(gpo.get("gPCUserExtensionNames", ["<No DN>"])[0]),
            machine_extension_names=str(gpo.get("gPCMachineExtensionNames", ["<No DN>"])[0]),
            functionality_version=int(gpo.get("gPCFunctionalityVersion", ["<No DN>"])[0]),
            linked_to=self.__linked_to(str(gpo.get("name", ["<No CN>"])[0])),
        )

    def __ldap_add(self, dn: str, attributes: Dict[str, str]) -> None:
        """
        Adds an entry to the ldap

        Parameters
        ----------
        dn : str
            The DN to be added
        attributes: Dict[str, str]
            The pairs of all attribute and their values

        Returns
        -------
        None
        """
        self.logger.info(f"Adding new entry to ldap. param({dn=}, {attributes=})")

        try:
            msg = ldb.Message()
            msg.dn = ldb.Dn(self.sam_database, dn)

            for attr, values in attributes.items():
                if not isinstance(values, list):
                    values = [values]
                msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_ADD, attr)

            self.sam_database.add(msg)

        except Exception as e:
            self.logger.error(f"{e}")
            raise IdentityException(f"{e}")

    def __ldap_modify(self, dn: str, attributes: Dict[str, str]) -> None:
        """
        MOdifies an entry to the ldap

        Parameters
        ----------
        dn : str
            The DN to be modified
        attributes: Dict[str, str]
            The pairs of all attribute and their values

        Returns
        -------
        None
        """
        self.logger.info(f"Modifying an entry to ldap. param({dn=}, {attributes=})")

        try:
            msg = ldb.Message()
            msg.dn = ldb.Dn(self.sam_database, dn)

            for attr, values in attributes.items():
                if not isinstance(values, list):
                    values = [values]
                msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)

            self.sam_database.modify(msg)
        except Exception as e:
            self.logger.error(f"{e}")
            raise IdentityException(f"{e}")

    def __ldap_delete(self, dn: str) -> None:
        """
        Deletes an entry to the ldap

        Parameters
        ----------
        dn : str
            The DN to be deleted

        Returns
        -------
        None
        """
        self.logger.info(f"Deleting an entry to ldap. param({dn=})")

        try:
            dn = ldb.Dn(self.sam_database, dn)
            self.sam_database.delete(dn)

        except Exception as e:
            self.logger.error(f"{e}")
            raise IdentityException(f"{e}")

    def __linked_to(self, uuid: str) -> List[str]:
        """
        Finds all containers that GPO is linked to

        Parameters
        ----------
        uuid : str
            UUID of the GPO

        Returns
        -------
        None
        """
        self.logger.info(f"Getting linked containers of a GPO. param({uuid=})")

        gpo_dn_pattern = f"CN={uuid},CN=Policies,CN=System,{self.dn}".upper()
        results = self.sam_database.search(
            base=self.dn,
            scope=ldb.SCOPE_SUBTREE,
            expression="(gPLink=*)",
            attrs=["gPLink", "distinguishedName"]
        )

        linked_containers = []

        for entry in results:
            dn = entry["distinguishedName"][0]
            gp_links = str(entry["gPLink"][0])
            links = re.findall(r"\[LDAP://(.*?);[0-9]+\]", gp_links.upper())
            for link_dn in links:
                if link_dn == gpo_dn_pattern:
                    linked_containers.append(str(dn))
        return linked_containers

    def connect(self):

        try:
            url = f"ldap://{self.machine}" if self.machine is not None else None
            self.sam_database = SamDB(url=url, session_info=system_session(), lp=self.lp)
        except ldb.LdbError as e:
            raise DoesNotExistException(e)

    @property
    def dn(self) -> str:
        """
        Returns the DN of the realm. DN=example,DC=com

        Returns
        -------
        str:
            The DN of the realm
        """
        self.logger.info(f"Getting dn")

        return self.sam_database.domain_dn()

    @property
    def realm(self):
        """
        Returns realm. example.com

        Returns
        -------
        str :
            The realm
        """
        self.logger.info(f"Getting realm")

        dn = self.dn
        domain_parts = [rdn.split('=')[1] for rdn in dn.split(',') if rdn.lower().startswith('dc=')]
        return '.'.join(domain_parts)

    def get(self, uuid: Optional[str] = None) -> Union[GPOObject, List[GPOObject]]:
        """
        Returns a GPO or a list of GPOs

        Parameters
        ----------
        uuid : str, optional
            The uuid of the GPO. If not given all GPOs would be returned

        Returns
        -------
        GPOObject or list of GPOObject :
            A single GPO object if a UUID is specified; otherwise, a list of all GPO objects
        """
        self.logger.info(f"Getting GPO(s). param({uuid=})")

        if uuid is not None:
            uuid = Fixer.uuid(uuid)

            gpo_results = self.sam_database.search(
                base=f"CN=Policies,CN=System,{self.dn}",
                scope=ldb.SCOPE_ONELEVEL,
                expression=f"(cn={uuid})",
                attrs=self.ATTRS
            )

            if not gpo_results:
                raise DoesNotExistException(f"GPO with GUID {uuid} not found.")

            return self.__gpo_object_creator(gpo_results[0])


        else:
            gpo_results = self.sam_database.search(
                base=f"CN=Policies,CN=System,{self.dn}",
                scope=ldb.SCOPE_ONELEVEL,
                expression="(objectClass=groupPolicyContainer)",
                attrs=self.ATTRS
            )

            return [
                self.__gpo_object_creator(gpo)
                for gpo in gpo_results
            ]

    def link_single(self, uuid: str, container: str) -> None:
        """
        Links a GPO to only one container

        Parameters
        ----------
        uuid : str, optional
            The uuid of the GPO
        container : str
            the DN of the container. OU=test_ou,DC=example,DC=com

        Returns
        -------
        None
        """
        self.logger.info(f"Linking a container to a given GPO. param({uuid=}, {container=})")

        uuid = Fixer.uuid(uuid)

        if self.machine is None:
            if not all(self.availability(uuid).values()):
                raise ActionException("The GPO is not available on all domain controllers")

        if not self.__container_exists(container):
            raise DoesNotExistException(f"Container {container} not found")

        gpo_results = self.sam_database.search(
            base=f"CN=Policies,CN=System,{self.dn}",
            scope=ldb.SCOPE_ONELEVEL,
            expression=f"(cn={uuid})",
            attrs=["displayName", "name", "distinguishedName", "gPCFileSysPath", "whenCreated", "whenChanged"]
        )

        if not gpo_results:
            raise DoesNotExistException(f"GPO with GUID {uuid} not found.")

        gpo_dn = gpo_results[0]["distinguishedName"][0]
        gp_link_entry = f"[LDAP://{gpo_dn};0]"

        container_entry = self.sam_database.search(base=container, scope=ldb.SCOPE_BASE, attrs=["gPLink"])
        current_gp_links = container_entry[0].get("gPLink", [""])[0]

        if str(gp_link_entry) in str(current_gp_links):
            self.logger.error(f"Container {container} already linked to {gp_link_entry}")
            raise AlreadyIsException(f"Container {container} already linked to {gp_link_entry}")

        new_gp_links = str(current_gp_links) + str(gp_link_entry) if str(current_gp_links) else str(gp_link_entry)

        self.__ldap_modify(container, {"gPLink": new_gp_links})

    def link(self, uuid: str, containers: Union[List[str], str]) -> None:
        """
        Links a GPO to one or more containers

        Parameters
        ----------
        uuid : str, optional
            The uuid of the GPO
        containers : Union[List[str], str]
            the DN of the container or list of DNs of containers OU=test_ou,DC=example,DC=com

        Returns
        -------
        None
        """
        self.logger.info(f"Linking container(s) to a given GPO. param({uuid=}, {containers=})")

        if isinstance(containers, str):
            self.link_single(uuid, containers)
        else:
            for container in containers:
                try:
                    self.link_single(uuid, container)
                except AlreadyIsException:
                    continue

    def unlink_single(self, uuid: str, container: str) -> None:
        """
        Unlinks a GPO from only one container

        Parameters
        ----------
        uuid : str, optional
            The uuid of the GPO
        container : str
            the DN of the container. OU=test_ou,DC=example,DC=com

        Returns
        -------
        None
        """
        self.logger.info(f"Unlinking a container from a given GPO. param({uuid=}, {container=})")

        uuid = Fixer.uuid(uuid)

        if self.machine is None:
            if not all(self.availability(uuid).values()):
                raise ActionException("The GPO is not available on all domain controllers")

        if not self.__container_exists(container):
            self.logger.error(f"Container {container} not found")
            raise DoesNotExistException(f"Container {container} not found")

        gpo_results = self.sam_database.search(
            base=f"CN=Policies,CN=System,{self.dn}",
            scope=ldb.SCOPE_ONELEVEL,
            expression=f"(cn={uuid})",
            attrs=["distinguishedName"]
        )

        if not gpo_results:
            raise DoesNotExistException(f"GPO with GUID {uuid} not found.")

        gpo_dn = gpo_results[0]["distinguishedName"][0]
        gpo_link_str = f"[LDAP://{gpo_dn};0]"

        container_entry = self.sam_database.search(
            base=container,
            scope=ldb.SCOPE_BASE,
            attrs=["gPLink"]
        )

        current_gp_links = container_entry[0].get("gPLink", [""])[0]
        gp_links_str = str(current_gp_links)

        if gpo_link_str not in gp_links_str:
            raise AlreadyIsException(f"GPO is not linked to container {container}")

        new_gp_links = gp_links_str.replace(gpo_link_str, "").strip()

        new_gp_links = new_gp_links.strip()
        if new_gp_links and not new_gp_links.startswith("["):
            new_gp_links = "[" + new_gp_links
        if new_gp_links and not new_gp_links.endswith("]"):
            new_gp_links += "]"

        msg = ldb.Message()
        msg.dn = ldb.Dn(self.sam_database, container)

        if new_gp_links:
            gp_links_to_use = new_gp_links
        else:
            gp_links_to_use = []

        self.__ldap_modify(container, {"gPLink": gp_links_to_use})

    def unlink(self, uuid: str, containers: Optional[Union[List[str], str]] = None) -> None:
        """
        Unlinks a GPO from one or more containers

        Parameters
        ----------
        uuid : str
            The uuid of the GPO
        containers : Union[List[str], str], optional
            the DN of the container or list of DNs of containers. OU=test_ou,DC=example,DC=com.
            If not given unlinks all containers

        Returns
        -------
        None
        """
        self.logger.info(f"Unlinking containers from a given GPO. param({uuid=}, {containers=})")

        if containers is None:
            for each_ou in self.__linked_to(uuid):
                self.unlink_single(uuid, each_ou)

            return

        if isinstance(containers, str):
            self.unlink_single(uuid, containers)
        else:
            for each_container in containers:
                try:
                    self.unlink_single(uuid, each_container)
                except AlreadyIsException:
                    continue

    def create(self, name: str) -> Union[GPOObject, str]:
        """
        Creates a GPO and links to the container if given.
        Uses samba-tool. But it might change later.

        Parameters
        ----------
        name : str
            The uuid of the GPO

        Returns
        -------
        GPOObject :
            The GPOObject of the created GPO.

        """
        self.logger.info(f"Creating a GPO. param({name=})")

        return self.samba_create(name)

    def samba_create(self, name: str) -> Union[GPOObject, str]:
        """
        Creates a GPO using samba-tool and links to the container if given

        Parameters
        ----------
        name : str
            The uuid of the GPO

        Returns
        -------
        GPOObject :
            The GPOObject of the created GPO.

        """
        self.logger.info(f"Creating a GPO using samba-tool. param({name=})")

        Checker.safe(name, "Name")

        gpo_results = self.sam_database.search(
            base=f"CN=Policies,CN=System,{self.dn}",
            scope=ldb.SCOPE_ONELEVEL,
            expression=f"(displayName={name})",
            attrs=self.ATTRS
        )

        if gpo_results:
            self.logger.error(f"A GPO already existing with name {name}")
            raise AlreadyIsException(f"A GPO already existing with name {name}")

        Checker.safe(self.user, "User")
        Checker.safe(self.passwd, "Password")

        command = ["samba-tool", "gpo", "create", name, "-U", self.user]
        try:
            result = subprocess.run(command, input=f"{self.passwd}\n", check=True, text=True, capture_output=True)

            match = re.search(r'\{([0-9A-Fa-f\-]{36})\}', result.stdout.strip())

            if match:
                uuid = match.group(1)
                try:
                    return self.get(f"{{{uuid}}}")
                except:
                    return f"{{{uuid}}}"

            self.logger.error("Cannot create GPO")
            raise ValueError("Cannot create GPO")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"{e}")
            raise IdentityException(f"{e}")

    def pseudo_create(self, name: str) -> Union[GPOObject, str]:
        """
        Creates a GPO using ldap and links to the container if given

        Parameters
        ----------
        name : str
            The uuid of the GPO

        Returns
        -------
        GPOObject :
            The GPOObject of the created GPO.
        """
        self.logger.info(f"Creating a GPO using ldap. param({name=})")

        # Copy & pasted from cmd_create(GPOCommand):
        try:
            default_gpo = self.get("{31B2F340-016D-11D2-945F-00C04FB984F9}")
        except:
            raise DoesNotExistException(f"Cannot find the default GPO")

        gpo_results = self.sam_database.search(
            base=f"CN=Policies,CN=System,{self.dn}",
            scope=ldb.SCOPE_ONELEVEL,
            expression=f"(displayName={name})",
            attrs=self.ATTRS
        )

        if gpo_results:
            raise AlreadyIsException(f"A GPO already existing with name {name}")

        guid = str(pyuuid.uuid4())
        gpo = f"{{{guid.upper()}}}"
        unc_path = f"\\\\{self.realm}\\sysvol\\{self.realm}\\Policies\\{gpo}"
        gpodir = Path(self.sysvol_root) / str(self.realm) / "Policies" / gpo
        try:
            gpodir.mkdir()
            (gpodir / "Machine").mkdir()
            (gpodir / "User").mkdir()
            open(gpodir / "GPT.INI", "w").write("[General]\r\nVersion=0\r\n")
        except Exception as e:
            raise FileException(f"{e}")

        self.sam_database.transaction_start()
        try:
            gpo_dn = get_gpo_dn(self.sam_database, gpo)
            m = ldb.Message()
            m.dn = gpo_dn
            m['a01'] = ldb.MessageElement("groupPolicyContainer", ldb.FLAG_MOD_ADD, "objectClass")
            self.sam_database.add(m)

            m = ldb.Message()
            m.dn = ldb.Dn(self.sam_database, "CN=User,%s" % str(gpo_dn))
            m['a01'] = ldb.MessageElement("container", ldb.FLAG_MOD_ADD, "objectClass")
            self.sam_database.add(m)

            m = ldb.Message()
            m.dn = ldb.Dn(self.sam_database, "CN=Machine,%s" % str(gpo_dn))
            m['a01'] = ldb.MessageElement("container", ldb.FLAG_MOD_ADD, "objectClass")
            self.sam_database.add(m)

            m = ldb.Message()
            m.dn = gpo_dn
            m['a02'] = ldb.MessageElement(name, ldb.FLAG_MOD_REPLACE, "displayName")
            m['a03'] = ldb.MessageElement(unc_path, ldb.FLAG_MOD_REPLACE, "gPCFileSysPath")
            m['a05'] = ldb.MessageElement("0", ldb.FLAG_MOD_REPLACE, "versionNumber")
            m['a07'] = ldb.MessageElement("2", ldb.FLAG_MOD_REPLACE, "gpcFunctionalityVersion")
            m['a04'] = ldb.MessageElement("0", ldb.FLAG_MOD_REPLACE, "flags")
            controls = ["permissive_modify:0"]
            self.sam_database.modify(m, controls=controls)
        except Exception as e:
            self.sam_database.transaction_cancel()
            self.logger.error(f"{e}")
            raise IdentityException(f"{e}")
        else:
            self.sam_database.transaction_commit()

        created_gpo = self.get(gpo)
        Fixer.apply_reference_permissions_and_owner(default_gpo.local_path, created_gpo.local_path)

        return created_gpo

    def delete(self, uuid: str) -> None:
        """
        Deletes a GPO.
        Uses samba-tools. Might change later

        Parameters
        ----------
        uuid : str
            The uuid of the GPO

        Returns
        -------
        None
        """
        self.logger.info(f"Deletes a GPO. param({uuid=})")

        self.samba_delete(uuid)

    def samba_delete(self, uuid: str) -> None:
        """
        Deletes a GPO using samba-tool

        Parameters
        ----------
        uuid : str
            The uuid of the GPO

        Returns
        -------
        None
        """
        self.logger.info(f"Deletes a GPO using samba-tool. param({uuid=})")

        uuid = Fixer.uuid(uuid)
        _ = self.get(uuid)

        Checker.safe(self.user, "User")
        Checker.safe(self.passwd, "Password")

        if self.machine is None:
            if not all(self.availability(uuid).values()):
                raise ActionException("The GPO is not available on all domain controllers")

        command = ["samba-tool", "gpo", "del", uuid, "-U", self.user]
        try:
            result = subprocess.run(command, input=f"{self.passwd}\n", check=True, text=True, capture_output=True)

            match = re.search(r'\{([0-9A-Fa-f\-]{36})\}', result.stdout.strip())

            if not match:
                self.logger.error("Cannot delete GPO")
                raise ValueError("Cannot delete GPO")

        except subprocess.CalledProcessError as e:
            raise IdentityException(f"{e}")

    def pseudo_delete(self, uuid: str) -> None:
        """
        Deletes a GPO using ldap

        Parameters
        ----------
        uuid : str
            The uuid of the GPO

        Returns
        -------
        None
        """
        self.logger.info(f"Deletes a GPO using ldap. param({uuid=})")

        # Copy & pasted from cmd_create(GPOCommand):

        gpo = self.get(uuid)

        if gpo.linked_to:
            self.unlink(gpo.CN, gpo.linked_to)

        self.sam_database.transaction_start()
        try:
            gpo_dn = get_gpo_dn(self.sam_database, gpo.CN)
            self.sam_database.delete(ldb.Dn(self.sam_database, "CN=User,%s" % str(gpo_dn)))
            self.sam_database.delete(ldb.Dn(self.sam_database, "CN=Machine,%s" % str(gpo_dn)))
            self.sam_database.delete(gpo_dn)
        except Exception as e:
            self.sam_database.transaction_cancel()
            self.logger.error(f"{e}")
            raise IdentityException(f"{e}")
        else:
            self.sam_database.transaction_commit()

        try:
            shutil.rmtree(gpo.local_path)
        except Exception as e:
            raise FileException(f"{e}")

    def add_script(self, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], script: Union[str, Path],
                   parameters_value: str = "") -> None:

        """
        Adds a script to the given GPO.

        Parameters
        ----------
        uuid : str
            The uuid of the GPO
        kind : Literal["Login", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run
        script : Union[str, Path]
            It can be a Path object of a given script. It also can be the path as string.
            It also can be a command as string. A script file would be automatically created.
        parameters_value: str
            The parameters to be passed to the script as it runs.

        Returns
        -------
        None
        """
        self.logger.info(f"Adding a script to a GPO. param({uuid=}, {kind=}, {script=})")

        uuid = Fixer.uuid(uuid)

        if self.machine is None:
            if not all(self.availability(uuid).values()):
                raise ActionException("The GPO is not available on all domain controllers")

        the_gpo = self.get(uuid)
        the_script = Fixer.script(script)
        Fixer.script_prepare(the_gpo, kind, the_script, parameters_value=parameters_value)
        self.__ldap_modify(the_gpo.DN, self.CSE[kind])
        self.__ldap_modify(the_gpo.DN, {"versionNumber": str(the_gpo.version + 1)})

    def delete_script(self, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"],
                      script: Union[str, Path, int]) -> None:
        """
        Removes a script from the given GPO.

        Parameters
        ----------
        uuid : str
            The uuid of the GPO
        kind : Literal["Login", "Logoff", "Startup", "Shutdown"]
            The kind of the script. Actually it indicates when the script would run
        script : Union[str, Path, int]
            It can be a Path object of a given script. It also can be the path as string.
            It also can be an integer. The order of the script.

        Returns
        -------
        None
        """
        self.logger.info(f"Removing a script from a GPO. param({uuid=}, {kind=}, {script=})")

        uuid = Fixer.uuid(uuid)

        if self.machine is None:
            if not all(self.availability(uuid).values()):
                raise ActionException("The GPO is not available on all domain controllers")

        the_gpo = self.get(uuid)
        if kind in ["Startup", "Shutdown"]:
            user_scripts_ini = the_gpo.local_path / "Machine" / "Scripts" / "psscripts.ini"
        else:
            user_scripts_ini = the_gpo.local_path / "User" / "Scripts" / "psscripts.ini"

        if isinstance(script, (str, Path)):
            the_script = Fixer.script_to_order(user_scripts_ini, kind, script)
        else:
            the_script = script

        if the_script == -1:
            self.logger.error("The script does not exist")
            raise DoesNotExistException("The script does not exist")

        Fixer.remove_script(user_scripts_ini, kind, the_script)

    def list_scripts(self, uuid: str) -> GPOScripts:
        """
        Returns a list of scripts belong to the GPO

        Parameters
        ----------
        uuid : str
            The uuid of the GPO

        Returns
        -------
        GPOScripts :
            all Login, Logout, Startup and Shutdown scripts belonging to the GPO
        """
        self.logger.info(f"Listing all scripts of a GPO. param({uuid=})")

        uuid = Fixer.uuid(uuid)

        if self.machine is None:
            if not all(self.availability(uuid).values()):
                raise ActionException("The GPO is not available on all domain controllers")

        the_gpo = self.get(uuid)
        return Fixer.scripts(the_gpo)

    def integrity(self, uuid: str) -> bool:
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
        self.logger.info(f"Checking the integrity of a GPO. param({uuid=})")

        return Checker.gpo_integrity(uuid)

    def availability(self, uuid: str) -> Dict[str, bool]:
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
        self.logger.info(f"Checking the availability of a GPO. param({uuid=})")

        return Checker.gpo_availability(uuid)
