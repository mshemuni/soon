import getpass
import os, sys
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional
import socket

import django
from django.core.management.utils import get_random_secret_key
from django.core.management import call_command
from ldap3 import Server, Connection, ALL, SUBTREE

ENV_PATH = "/opt/soon/.env"
LDAP_CONF = "/etc/ldap/ldap.conf"
SOON_PATH = "/root/soon/"

sys.path.append(SOON_PATH)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "soon_aip.settings")
os.environ.setdefault("SoonSECRET_KEY", "coming soon")
os.environ.setdefault("SoonMachine", "coming soon")
os.environ.setdefault("SoonADAdmin", "coming soon")
os.environ.setdefault("SoonADPassword", "coming soon")
os.environ.setdefault("SoonKeys", "coming soon")
django.setup()

from user.models import CustomUser as CU


def ask_yes_no(question: str) -> bool:
    while True:
        answer = input(f"{question} (y/n): ").strip().lower()
        if answer.upper() in ["YES", "Y"]:
            return True
        elif answer.upper() in ["NO", "N"]:
            return False
        else:
            print("Please answer with 'y/yes' or 'n/no'.")


def ensure_tls_reqcert_allow():
    if not os.path.exists(LDAP_CONF):
        raise FileNotFoundError(f"{LDAP_CONF} does not exist.")

    timestamp = int(time.time())
    backup_path = f"{LDAP_CONF}.backup_{timestamp}"
    shutil.copy2(LDAP_CONF, backup_path)

    with open(LDAP_CONF, "r") as f:
        lines = f.readlines()

    tls_pattern = re.compile(r'^(?P<leading>\s*)TLS_REQCERT\s+\S+.*$')
    found = False

    for i, line in enumerate(lines):
        match = tls_pattern.match(line)
        if match:
            leading = match.group("leading") or ""
            lines[i] = f"{leading}TLS_REQCERT\tallow\n"
            found = True
            break

    if not found:
        lines.append("\nTLS_REQCERT\tallow\n")

    with open(LDAP_CONF, "w") as f:
        f.writelines(lines)


def generate_secret_key() -> str:
    """Generate a new Django SECRET_KEY."""
    return get_random_secret_key()


def get_secret_key() -> str:
    """Get a Django SECRET_KEY."""
    secret_key = input("Enter Django Secret Key (leave empty to generate one): ")
    if secret_key:
        return secret_key
    print("No secret key provided, generating one now")
    return generate_secret_key()


def get_administrator_username() -> str:
    """Asks for administrator username."""
    username = input("Enter Administrator's username: ")
    return username


def get_administrator_password() -> str:
    """Asks for administrator password."""
    password = getpass.getpass("Enter Administrator's password: ")
    return password


def get_certificates_path() -> str:
    """Asks for path to certificates directory."""
    certificates_path = input("Enter path where the certificate files are stored: ")
    path = Path(certificates_path)
    if not path.exists():
        path.mkdir()

    return certificates_path


def get_controller() -> Optional[str]:
    """Asks for controller."""
    controller = input("Enter controller (Leave empty to not set): ")
    if controller:
        return controller
    return None


def is_domain_reachable(controller_fqdn: str, port: int = 88) -> bool:
    """Check if a domain resolves and is reachable on a given port (default Kerberos 88)."""
    try:
        socket.gethostbyname(controller_fqdn)
        with socket.create_connection((controller_fqdn, port), timeout=3):
            return True
    except Exception:
        return False


def check_ad_connection(controller_fqdn: str, username: str, password: str) -> bool:
    """Checks if an administrator can connect to a given controller."""
    try:
        if controller_fqdn.startswith('ldap://'):
            use_ssl = False
            host = controller_fqdn[len('ldap://'):]
        elif controller_fqdn.startswith('ldaps://'):
            use_ssl = True
            host = controller_fqdn[len('ldaps://'):]
        else:
            use_ssl = True
            host = controller_fqdn

        if '@' in username:
            full_username = username
            domain = username.split('@')[1]
        else:
            if host.count(".") < 2:
                domain_parts = host.split('.')
            else:
                domain_parts = host.split('.')[1:]
            domain = '.'.join(domain_parts)
            full_username = f"{username}@{domain}"

        base_dn = ','.join(f'dc={part}' for part in domain.split('.'))

        server = Server(host, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, user=full_username, password=password, auto_bind=True)
        conn.search(base_dn, '(objectClass=*)', search_scope=SUBTREE, attributes=['*'])
        conn.unbind()
        return True
    except Exception:
        return False


def get_controller_safe() -> Optional[str]:
    """Gets the FDQN controller name safely..."""
    controller_fqdn = get_controller()
    while controller_fqdn is not None and not is_domain_reachable(controller_fqdn):
        print("FDQN is not reachable")
        controller_fqdn = get_controller()

    return controller_fqdn


def get_user_name_password_safe(controller_fqdn: Optional[str] = None):
    """Gets the username password safely..."""

    def get_user():
        username = get_administrator_username()
        while not username:
            print("Username is not set")
            username = get_administrator_username()

        return username

    def get_password():
        password = get_administrator_password()
        while not password:
            print("Password is not set")
            password = get_administrator_password()

        return password

    username = get_user()
    password = get_password()

    if controller_fqdn is not None:
        connection = check_ad_connection(controller_fqdn, username, password)
        while not connection:
            print("Connection failed")
            username = get_user()
            password = get_password()
            connection = check_ad_connection(controller_fqdn, username, password)

    return username, password


def get_controller_user_password_safe():
    """Gets the Controller, username and password safely..."""
    controller_fdqn = get_controller_safe()
    username, password = get_user_name_password_safe(controller_fdqn)
    return controller_fdqn, username, password


def create_env_file(secret_key, controller_fdqn, username, password, certificates_path):
    print("File's content is:")
    print(f"\tSoonSECRET_KEY = \"{secret_key}\"")
    if controller_fdqn is not None:
        print(f"\tSoonMachine = \"{controller_fdqn}\"")
    print(f"\tSoonADAdmin = \"{username}\"")
    print(f"\tSoonADPassword = \"{password}\"")
    print(f"\tSoonKeys = \"{certificates_path}\"")

    if os.path.exists(ENV_PATH):
        unix_time = int(time.time())
        backup_path = f"{ENV_PATH}.backup_{unix_time}"
        shutil.copy2(ENV_PATH, backup_path)
        print(f"Backup created: {backup_path}")

    with open(ENV_PATH, "w") as env_file:
        env_file.write(f"SoonSECRET_KEY = \"{secret_key}\"\n")
        if controller_fdqn is not None:
            env_file.write(f"SoonMachine = \"{controller_fdqn}\"\n")
        env_file.write(f"SoonADAdmin = \"{username}\"\n")
        env_file.write(f"SoonADPassword = \"{password}\"\n")
        env_file.write(f"SoonKeys = \"{certificates_path}\"\n")


def make_migrations():
    print("Making migrations...")
    call_command('makemigrations')


def apply_migrations():
    print("Migrating...")
    call_command('migrate')


def create_superuser(username, email, password):
    print("Creating superuser...")
    if not CU.objects.filter(username=username).exists():
        CU.objects.create_superuser(username=username, email=email, password=password)
    else:
        print(f"Superuser '{username}' already exists.")


def get_superuser_username() -> str:
    """Asks for superuser username and ensures it is provided."""
    while True:
        username = input("Enter Superuser's username: ").strip()
        if username:
            return username
        print("Username cannot be empty.")


def get_superuser_password() -> str:
    """Asks for superuser password and ensures it is provided."""
    while True:
        password = getpass.getpass("Enter Superuser's password: ").strip()
        if password:
            return password
        print("Password cannot be empty.")


def get_superuser_email() -> str:
    """Asks for superuser email and ensures it is valid."""
    email_pattern = r'^[^@]+@[^@]+\.[^@]+$'
    while True:
        email = input("Enter Superuser's email: ").strip()
        if not email:
            print("Email cannot be empty.")
        elif not re.match(email_pattern, email):
            print("Invalid email format. Example: user@example.com")
        else:
            return email


def configure_django():
    make_migrations()
    apply_migrations()
    superuser_username = get_superuser_username()
    superuser_password = get_superuser_password()
    superuser_email = get_superuser_email()
    create_superuser(superuser_username, superuser_email, superuser_password)


def enable_and_start_service():
    try:
        subprocess.run(
            ["systemctl", "enable", "soon"],
            check=True
        )

        subprocess.run(
            ["systemctl", "start", "soon"],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error while managing service 'soon': {e}")


def main():
    print("Welcome to soon post installation configuration.")
    print("")
    print("1) Make sure TLS_REQCERT is allowed for ldap connections")
    print(f"The file `{LDAP_CONF}` will be modified. A backup will be created before each edit")
    yes = ask_yes_no("Allow the modification? If you want to modify it yourself type `n/no`")
    if yes:
        ensure_tls_reqcert_allow()
    print()

    print(f"2) Create an env file here: `{ENV_PATH}`. A backup will be created before each edit")
    print("")
    print("The file's contents will look like:")
    print("\tSoonSECRET_KEY=\"your_django_secret_key\"")
    print("\tSoonMachine=\"controller.domain.ext\" # If available")
    print("\tSoonADAdmin=\"your_administrator_username\"")
    print("\tSoonADPassword=\"your_administrator_password\"")
    print("\tSoonKeys=\"/opt/soon/keys\"")
    yes = ask_yes_no("Allow the modification? If you want to modify it yourself type `n/no`")
    if yes:
        secret_key = get_secret_key()
        controller_fdqn, username, password = get_controller_user_password_safe()
        certificates_path = get_certificates_path()
        create_env_file(secret_key, controller_fdqn, username, password, certificates_path)
    print()

    print("3) Configure Django server")
    print("Will `makemigrations`, `migrate` and `createsuperuser`")
    print("You can use Super User created here to login to django admin panel http://[THIS-MACHINES-IP]:8006/admin")
    print("Create user's and copy their apikeys.")
    yes = ask_yes_no("Allow configuration? If you want to configure it yourself type `n/no`")
    if yes:
        configure_django()
    print()

    print("4) Soon Service")
    print("Will enable and start the soon's service")
    yes = ask_yes_no("Allow to enable and start soon service? If you want to do it yourself type `n/no`")
    if yes:
        enable_and_start_service()
    print()


if __name__ == "__main__":
    main()
