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
        self.GPO = GPO("Administrator", "Qq123456")

        self.NEW_GPO = self.GPO.create("".join(choices(ascii_letters, k=12)))

    def tearDown(self):
        self.GPO.delete(self.NEW_GPO.CN)

    def test_get_all(self):
        gpos = self.GPO.get()

        self.assertIsInstance(gpos, list)
        names = []
        for each_gpo in gpos:
            self.assertIsInstance(each_gpo, GPOObject)
            names.append(each_gpo.name)

        self.assertIn("Default Domain Policy", names)
        self.assertIn("Default Domain Controllers Policy", names)

    def test_single(self):
        gpo = self.GPO.get("{31B2F340-016D-11D2-945F-00C04FB984F9}")

        self.assertIsInstance(gpo, GPOObject)
        self.assertEqual(gpo.name, "Default Domain Policy")

    def test_single_does_not_exist(self):
        with self.assertRaises(DoesNotExistException):
            _ = self.GPO.get("{00000000-0000-0000-0000-000000000000}")

    def test_single_wrong(self):
        with self.assertRaises(ValueError):
            _ = self.GPO.get("BAD")

    # def test_create(self):
    #     new_name = "".join(choices(ascii_letters, k=12))
    #     new_gpo = self.GPO.create(new_name)
    #
    #     self.assertIsInstance(new_gpo, GPOObject)
    #     self.assertEqual(new_gpo.name, new_name)
    #
    #     with self.assertRaises(AlreadyIsException):
    #         _ = self.GPO.create(new_gpo.name)


    def test_create_bad_name(self):
        new_name = "ABC;DCE"

        with self.assertRaises(ValueError):
            self.GPO.create(new_name)

    def test_delete(self):
        new_gpo = self.GPO.create("".join(choices(ascii_letters, k=12)))
        self.GPO.delete(new_gpo.CN)

    def test_delete_does_not_exist(self):
        with self.assertRaises(DoesNotExistException):
            self.GPO.delete("{00000000-0000-0000-0000-000000000000}")

    def test_delete_wrong(self):
        with self.assertRaises(ValueError):
            self.GPO.delete("BAD")

    def test_link(self):

        self.assertListEqual(self.NEW_GPO.linked_to, [])
        self.GPO.link(self.NEW_GPO.CN, self.GPO.dn)
        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [self.GPO.dn])


    def test_link_does_not_exist(self):
        with self.assertRaises(DoesNotExistException):
            self.GPO.link("{00000000-0000-0000-0000-000000000000}", self.GPO.dn)

    def test_link_wrong(self):
        with self.assertRaises(ValueError):
            self.GPO.link("BAD", self.GPO.dn)

    def test_link_container_does_not_exist(self):
        self.assertListEqual(self.NEW_GPO.linked_to, [])

        with self.assertRaises(DoesNotExistException):
            self.GPO.link(self.NEW_GPO.CN, "BAD")

        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [])


    def test_link_already_linked(self):
        self.GPO.link(self.NEW_GPO.CN, self.GPO.dn)

        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [self.GPO.dn])

        with self.assertRaises(AlreadyIsException):
            self.GPO.link(self.NEW_GPO.CN, self.GPO.dn)

    def test_unlink(self):
        self.GPO.link(self.NEW_GPO.CN, self.GPO.dn)

        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [self.GPO.dn])

        self.GPO.unlink(self.NEW_GPO.CN, self.GPO.dn)

        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [])

    def test_unlink_does_not_exist(self):
        with self.assertRaises(DoesNotExistException):
            self.GPO.unlink("{00000000-0000-0000-0000-000000000000}", self.GPO.dn)

    def test_unlink_wrong(self):
        with self.assertRaises(ValueError):
            self.GPO.unlink("BAD", self.GPO.dn)

    def test_unlink_container_does_not_exist(self):
        self.assertListEqual(self.NEW_GPO.linked_to, [])

        with self.assertRaises(DoesNotExistException):
            self.GPO.unlink(self.NEW_GPO.CN, "BAD")

        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [])


    def test_unlink_already_unlinked(self):
        self.assertListEqual(self.GPO.get(self.NEW_GPO.CN).linked_to, [])
        with self.assertRaises(AlreadyIsException):
            self.GPO.unlink(self.NEW_GPO.CN, self.GPO.dn)

    def test_scripts(self):
        scripts = self.GPO.list_scripts(self.NEW_GPO.CN)

        self.assertIsInstance(scripts, GPOScripts)
        self.assertListEqual(scripts.login, [])
        self.assertListEqual(scripts.logoff, [])
        self.assertListEqual(scripts.startup, [])
        self.assertListEqual(scripts.shutdown, [])

    def test_script_add(self):
        name = "".join(choices(ascii_letters, k=5))
        parameters = "".join(choices(ascii_letters, k=5))
        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir) / f"{name}.ps1"

        with open(temp_path, 'w') as temp_file:
            temp_file.write("# Do nothing")

        self.GPO.add_script(self.NEW_GPO.CN, "Startup", temp_path, parameters)

        scripts = self.GPO.list_scripts(self.NEW_GPO.CN)
        self.assertEqual(scripts.startup[0].order, 0)
        self.assertEqual(scripts.startup[0].script.name, temp_path.name)
        self.assertEqual(scripts.startup[0].parameters, parameters)
        self.assertEqual(self.GPO.get(self.NEW_GPO.CN).version, self.NEW_GPO.version + 1)


    def test_add_twice(self):
        name = "".join(choices(ascii_letters, k=5))
        parameters = "".join(choices(ascii_letters, k=5))
        temp_dir = tempfile.gettempdir()
        temp_path = Path(temp_dir) / f"{name}.ps1"

        with open(temp_path, 'w') as temp_file:
            temp_file.write("# Do nothing")

        self.GPO.add_script(self.NEW_GPO.CN, "Startup", temp_path, parameters)
        self.GPO.add_script(self.NEW_GPO.CN, "Startup", temp_path, parameters)

        scripts = self.GPO.list_scripts(self.NEW_GPO.CN)
        self.assertEqual(scripts.startup[1].order, 1)
        self.assertNotEqual(scripts.startup[1].script.name, temp_path.name)
        self.assertEqual(scripts.startup[1].parameters, parameters)
        self.assertEqual(self.GPO.get(self.NEW_GPO.CN).version, self.NEW_GPO.version + 2)