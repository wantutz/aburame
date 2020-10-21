import pytest

# shieldx library
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

users_to_create = [
    {
        "login": "sxapi",
        "name": "APIUser",
        "password": "Admin@123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "replaycenter",
        "name": "ReplaycenterUser",
        "password": "Admin@123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "deploysetup",
        "name": "DeploySetup",
        "password": "Admin@123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "admin2",
        "name": "LegacyUser",
        "password": "SXwonder#2018",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "admin5",
        "name": "LegacyDeployUser",
        "password": "SXwonder#2018",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "paras",
        "name": "Intern",
        "password": "Admin@2018",
        "role": "SecurityAnalyst",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "paras@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "manoj",
        "name": "Manager",
        "password": "Manoj@SX123",
        "role": "SecurityAnalyst",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "manoj@shieldx.com",
        "status": "Enabled"
    },
]

users_to_update = [
    {
        "login": "sxapi",
        "password": "Admin@123",
        "name": "Modified Role to Security Analyst",
        "role": "SecurityAnalyst",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "replaycenter",
        "password": "Admin@123",
        "name": "Modified Name Replay Center User",
        "role": "SecurityAdministrator",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "deploysetup",
        "password": "Admin@123",
        "name": "Disabled this newly minted Security Administrator",
        "role": "SecurityAdministrator",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Disabled"
    },
]

users_to_delete = [
    "sxapi",
    "replaycenter",
    "deploysetup",
]

@pytest.mark.users_bats
@pytest.mark.parametrize("user_info", users_to_create)
def test_bats_000_create_user(sut_handle, user_info):
    manage = SysMgmt(sut_handle)

    # Get existing users
    users = manage.get_users()

    if any((user["login"] == user_info["login"]) for user in users):
        # Skip creation (no-op), user already exist
        print("No-op, create user.")
    else:
        # Create user
        is_user_created = manage.create_user(user_info)

        assert is_user_created == True, "Not able to create the user."

@pytest.mark.users_bats
@pytest.mark.parametrize("user_info", users_to_create)
def test_bats_001_check_user(sut_handle, user_info):
    manage = SysMgmt(sut_handle)

    # Get users
    users = manage.get_users()

    print("User check: {}".format(user_info))

    assert any((user["login"] == user_info["login"]) for user in users), "User not found."

@pytest.mark.users_bats
@pytest.mark.parametrize("user_info", users_to_update)
def test_bats_002_update_user(sut_handle, user_info):
    manage = SysMgmt(sut_handle)

    # Get existing users
    users = manage.get_users()

    # Check if user exist before proceeding from a list of users
    if any((user["login"] == user_info["login"]) for user in users):
        # User found, proceed with update
        is_user_updated = manage.update_user(user_info)

        assert is_user_updated == True, "Not able to udpate the user."
    else:
        # Skip update (no-op), user not found
        print("No-op, update user.")

@pytest.mark.users_bats
@pytest.mark.parametrize("user_login", users_to_delete)
def test_bats_003_delete_user(sut_handle, user_login):
    manage = SysMgmt(sut_handle)

    # Get the specific user
    user_info = manage.get_user(user_login)

    # If user info is found, proceed with delete
    if len(user_info) != 0:
        # User found, proceed with update
        is_user_deleted = manage.delete_user(user_login)

        assert is_user_deleted == True, "Not able to delete the user."
    else:
        # Skip update (no-op), user not found
        print("No-op, delete user.")

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m users_bats
#  python3 -m pytest shieldxqe/test/func/test_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k create_user
#  python3 -m pytest shieldxqe/test/func/test_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k check_user
#  python3 -m pytest shieldxqe/test/func/test_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k update_user
#  python3 -m pytest shieldxqe/test/func/test_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k delete_user
