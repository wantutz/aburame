import pytest

# shieldx library
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

users_to_create = [
    {
        "login": "raji",
        "name": "APIUser",
        "password": "Raji@SX123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "raji@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "juan",
        "name": "APIUser",
        "password": "Juan@SX123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "juan@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "esha",
        "name": "APIUser",
        "password": "Esha@SX123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "esha@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "vamsi",
        "name": "APIUser",
        "password": "Vamsi@SX123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "vamsikrishna@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "surbhi",
        "name": "APIUser",
        "password": "Surbhi@SX123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "surbhi@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "tony",
        "name": "APIUser",
        "password": "Tony@SX123",
        "role": "SuperUser",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "tony@shieldx.com",
        "status": "Enabled"
    },
    {
        "login": "paras",
        "name": "Intern",
        "password": "Paras@SX123",
        "role": "SecurityAnalyst",
        "authType": "LOCAL",
        "tenantId": 1,
        "email": "para@shieldx.com",
        "status": "Enabled"
    },
]

users_to_delete = [
    "raji",
    "juan",
    "esha",
    "vamsi",
    "surbhi",
    "tony",
    "paras",
]

@pytest.mark.users_qe
@pytest.mark.parametrize("user_info", users_to_create)
def test_create_user(sut_handle, user_info):
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

@pytest.mark.users_qe
@pytest.mark.parametrize("user_info", users_to_create)
def test_check_user(sut_handle, user_info):
    manage = SysMgmt(sut_handle)

    # Get users
    users = manage.get_users()

    print("User check: {}".format(user_info))

    assert any((user["login"] == user_info["login"]) for user in users), "User not found."

@pytest.mark.users_qe
@pytest.mark.parametrize("user_info", users_to_create)
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
def test_delete_user(sut_handle, user_login):
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
#  python3 -m pytest shieldxqe/test/func/test_create_qe_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k create_user
#  python3 -m pytest shieldxqe/test/func/test_create_qe_users.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k delete_user
