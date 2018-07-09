###
#
# Lenovo Redfish examples - Get the current BMC User Accounts
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


import sys
import logging
import json
import redfish
import lenovo_utils as utils


def get_bmc_user_accounts(ip, login_account, login_password):
    """Get BMC user accounts    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns BMC user accounts when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    # GET the Accounts resource
    response_base_url = REDFISH_OBJ.get("/redfish/v1", None)
    if response_base_url.status == 200:
        account_service_url = response_base_url.dict["AccountService"]["@odata.id"]
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result
    response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
    if response_account_service_url.status == 200:
        accounts_url = response_account_service_url.dict["Accounts"]["@odata.id"]
    else:
        result = {'ret': False, 'msg': "response account service_url Error code %s" % response_account_service_url.status}
        REDFISH_OBJ.logout()
        return result

    accounts_url_response = REDFISH_OBJ.get(accounts_url, None)
    if accounts_url_response.status == 200:
        # Loop through Accounts and print info
        account_count = accounts_url_response.dict["Members@odata.count"]
    else:
        result = {'ret': False, 'msg': "accounts url response Error code %s" % accounts_url_response.status}
        REDFISH_OBJ.logout()
        return result
    x = 0
    user_details = []
    for x in range(0, account_count):
        bmc_user = {}
        account_x_url = accounts_url_response.dict["Members"][x]["@odata.id"]
        response_account_x_url = REDFISH_OBJ.get(account_x_url, None)
        if response_account_x_url.status == 200:
            # Print out account information if account is valid (UserName not blank)
            if response_account_x_url.dict["UserName"]:
                Name = response_account_x_url.dict["Name"]
                UserName = response_account_x_url.dict["UserName"]
                if 'Enabled' in response_account_x_url.dict:
                    Enabled = response_account_x_url.dict["Enabled"]
                else:
                    Enabled = ''
                if 'Locked' in response_account_x_url.dict:
                    Locked = response_account_x_url.dict["Locked"]
                else:
                    Locked = ''
                bmc_user['Name'] = Name
                bmc_user['UserName'] = UserName
                bmc_user['Enabled'] = Enabled
                bmc_user['Locked'] = Locked
                # Get account privileges
                if "Links" in response_account_x_url.dict:
                    accounts_role_url = response_account_x_url.dict["Links"]["Role"]["@odata.id"]
                else:
                    user_details.append(bmc_user)
                    continue
                response_accounts_role_url = REDFISH_OBJ.get(accounts_role_url, None)
                if response_accounts_role_url.status == 200:
                    AssignedPrivileges = response_accounts_role_url.dict["AssignedPrivileges"]
                    if "OemPrivileges" in response_accounts_role_url.dict:
                        OemPrivileges = response_accounts_role_url.dict["OemPrivileges"]
                    else:
                        OemPrivileges = []
                    bmc_user['AssignedPrivileges'] = AssignedPrivileges
                    bmc_user['OemPrivileges'] = OemPrivileges
                    user_details.append(bmc_user)
                else:
                    result = {'ret': False,
                              'msg': "response accounts role url Error code %s" % response_accounts_role_url.status}
                    REDFISH_OBJ.logout()
                    return result
        else:
            result = {'ret': False, 'msg': "response account_x_url Error code %s" % response_account_x_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['entries'] = user_details
    # Logout of the current session
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    
    # Get BMC inventory and check result
    result = get_bmc_user_accounts(ip, login_account, login_password)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])