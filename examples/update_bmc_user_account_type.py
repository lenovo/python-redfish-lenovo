###
#
# Lenovo Redfish examples - updata user account type
#
# Copyright Notice:
#
# Copyright 2024 Lenovo Corporation
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
import redfish
import json
import traceback
import lenovo_utils as utils

def update_bmc_user_account_type(ip, login_account, login_password, username, account_type, account_url=None):
    """update user account type    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: Username to be modified by the user
    :type username: string
    :params account_type: Account type to be modified by the user
    :type account_type: string
    :params account_url: BMC account url
    :type account_url: string
    :returns: returns update user account type result when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server
        REDFISH_OBJ.login(auth="basic")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # change default BMC account's type or specified account (treat userid 1 as default account)
    if username == None or account_url:
        headers = {"If-Match": "*"}
        parameter = {"AccountTypes": account_type}
        default_account_url = '/redfish/v1/AccountService/Accounts/1'
        if account_url:
            default_account_url = account_url
        response_modified_account_type = REDFISH_OBJ.patch(default_account_url, body=parameter, headers=headers)
        error_message = utils.get_extended_error(response_modified_account_type)
        if response_modified_account_type.status in [200,204]:
            result = {'ret': True, 'msg': "The type of default BMC account is successfully updated."}
            return result
        elif response_modified_account_type.status == 400 and "The property AccountTypes is not in the list of valid properties" in error_message:
            result = {'ret': False, 'msg': "Update default BMC account type failed, response error code %s \nerror_message: This platform does not support modifying the account type.\n" % (response_modified_account_type.status)}
            return result
        else:
            result = {'ret': False, 'msg': "Update default BMC account type failed, response error code %s \nerror_message: %s\n" % (response_modified_account_type.status, error_message)}
            return result

    # change specified username account type
    try:
        # Get response_base_url resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get account service url
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        # Get AccountService resource
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status == 200:
            accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (account_service_url, response_account_service_url.status, error_message)}
            return result

        # Get url accounts resource
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        if response_accounts_url.status == 200:
            account_count = response_accounts_url.dict["Members@odata.count"]
            # Loop the BMC user list and get all the bmc username
            for x in range(0, account_count):
                account_x_url = response_accounts_url.dict["Members"][x]["@odata.id"]
                response_account_x_url = REDFISH_OBJ.get(account_x_url, None)
                if response_account_x_url.status == 200:
                    bmc_username = response_account_x_url.dict['UserName']
                    # Update the BMC user account type when the specified BMC username is in the BMC user list.
                    if bmc_username == username:
                        if "@odata.etag" in response_account_x_url.dict:
                            etag = response_account_x_url.dict['@odata.etag']
                        else:
                            etag = ""
                        headers = {"If-Match": etag}
                        parameter = {"AccountTypes": account_type}
                        response_modified_account_type = REDFISH_OBJ.patch(account_x_url, body=parameter, headers=headers)
                        error_message = utils.get_extended_error(response_modified_account_type)
                        if response_modified_account_type.status in [200,204]:
                            result = {'ret': True, 'msg': "The BMC user '%s' account type is successfully updated." % username}
                            return result
                        elif response_modified_account_type.status == 400 and "The property AccountTypes is not in the list of valid properties" in error_message:
                            result = {'ret': False, 'msg': "Update default BMC account type failed, response error code %s \nerror_message: This platform does not support modifying the account type.\n" % (response_modified_account_type.status)}
                            return result
                        else:
                            result = {'ret': False, 'msg': "Update BMC user account type failed, url '%s' response error code %s \nerror_message: %s\n" % (account_x_url, response_modified_account_type.status, error_message)}
                            return result

                # account_x_url response failed
                else:
                    try:
                        error_message = utils.get_extended_error(response_account_x_url)
                    except:
                        error_message = response_account_x_url
                    result = {'ret': False, 'msg': "response_account_x_url Error code %s \nerror_message: %s" % (
                        response_account_x_url.status, error_message)}
                    return result
            result = {'ret': False, 'msg': "Specified BMC username doesn't exist. Please check whether the BMC username is correct."}
        else:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (accounts_url,
            response_accounts_url.status, error_message)}
    except Exception as e:
        traceback.print_exc()
        result = {'ret':False, 'msg':"Error message %s" %e}
    finally:
        # Logout
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--username', type=str, help='Input the name of BMC user to be updated.')
    argget.add_argument('--accounttype', type=str, required=True, nargs="+", choices=["WebUI","Redfish","ManagerConsole","IPMI","SNMP"], help='Input account type of BMC user')
    argget.add_argument('--url', type=str, help='Input account url of BMC user to update the account type.(e.g., /redfish/v1/AccountService/Accounts/2)')


def add_parameter():
    """Add update user account type parameter"""
    example = """
    Example:  
        Change the account type for the default BMC account:
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --accounttype WebUI Redfish"
        Change the account type for the specified user:
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --username USERNAME --accounttype WebUI Redfish"
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --accounttype WebUI Redfish --url /redfish/v1/AccountService/Accounts/2"
            """
    argget = utils.create_common_parameter_list(example_string=example)
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["username"] = args.username
    parameter_info["account_type"] = args.accounttype
    parameter_info["account_url"] = args.url
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    username = parameter_info['username']
    account_type = parameter_info['account_type']
    account_url = parameter_info['account_url']

    # Update user account type result and check result   
    result = update_bmc_user_account_type(ip, login_account, login_password, username, account_type, account_url)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
