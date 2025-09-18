import tempfile
import unittest
from pathlib import Path

from soon import GPO
from soon.errors import DoesNotExistException, AlreadyIsException
from soon.utils import GPOObject, GPOScripts

from random import choices
from string import ascii_letters


class TestGPO(unittest.TestCase):
    def setUp(self):
        self.URL = "/api/v1/gpo"
        self.GPO = GPO("Administrator", "Qq123456")

        self.GPOS = [
            self.GPO.create("".join(choices(ascii_letters, k=12)))
            for _ in range(2)
        ]


    def tearDown(self):
        for each in self.GPOS:
            try:
                self.GPO.delete(each)
            except Exception as e:
                print(e)

    def test_get(self):
        pass