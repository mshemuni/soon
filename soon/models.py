from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Optional, Union, Literal

from .utils import GPOObject as GPOObject, GPOScripts


class GPOModel(ABC):

    @abstractmethod
    def get(self, uuid: Optional[str] = None) -> Union[GPOObject, List[GPOObject]]:
        """Return list of all GPOs"""

    @abstractmethod
    def link(self, uuid: str, containers: str) -> None:
        """Links a GPO to the given container"""

    @abstractmethod
    def unlink(self, uuid: str, containers: Optional[Union[List[str], str]]  = None) -> None:
        """Unlinks a GPO from the given container"""

    @abstractmethod
    def create(self, name: str) -> Union[GPOObject, str]:
        """Creates a new GPO"""

    @abstractmethod
    def delete(self, name: str) -> None:
        """Deletes a new GPO"""


    @abstractmethod
    def add_script(self, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"], script: Union[str, Path],
                   parameters_value: str = "") -> None:
        """Adds a new script to the scripts of a GPO"""

    @abstractmethod
    def delete_script(self, uuid: str, kind: Literal["Login", "Logoff", "Startup", "Shutdown"],
                      script: Union[str, Path, int]) -> None:
        """Removes a new script from the scripts of a GPO"""

    @abstractmethod
    def list_scripts(self, uuid: str) -> GPOScripts:
        """Returns all available scripts of GPO"""