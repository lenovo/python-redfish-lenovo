###
#
# Lenovo Redfish examples - Delete bmc user
#
# Copyright Notice:
#
# Copyright 2019 Lenovo Corporation
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
import lenovo_utils as utils


def lenovo_delete_bmc_user(ip, login_account, login_password, username):
    """Delete bmc user
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username:BMC user name by user specified
    :type username: string
    :returns: returns disable user result when succeeded or error message when failed
    """
    result = {}
    if username == "" or username.strip() == "":
        result = {"ret":False,"msg":"username invalid please check your input"}
        return result
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct." % repr(e)}
        return result

    # Get ServiceRoot resource
    try:
        # Get /redfish/v1
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result

        # Get /redfish/v1/AccountService
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status != 200:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                account_service_url, response_account_service_url.status, error_message)}
            return result

        # Get /redfish/v1/AccountService/Accounts
        accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        # Get the user account url
        if response_accounts_url.status != 200:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                accounts_url, response_accounts_url.status, error_message)}
            return result

        # Find target account url
        max_account_num = response_accounts_url.dict["Members@odata.count"]
        list_account_url = []
        for i in range(max_account_num):
            account_url = response_accounts_url.dict["Members"][i]["@odata.id"]
            list_account_url.append(account_url)
        dest_account_url = ""
        for account_url in list_account_url:
            response_account_url = REDFISH_OBJ.get(account_url, None)
            if response_account_url.status == 200:
                account_username = response_account_url.dict["UserName"]
                if account_username == username:
                    dest_account_url = account_url
                    break
            else:
                error_message = utils.get_extended_error(response_account_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    account_url, response_account_url.status, error_message)}
                return result
        if dest_account_url == "":
            result = {'ret': False,
                      'msg': "Account %s is not existed" %username}
            return result

        # set header
        if "@odata.etag" in response_account_url.dict:
            etag = response_account_url.dict['@odata.etag']
        else:
            etag = ""
        
        # Check user delete mode
        delete_mode = "DELETE_Action"
        if response_accounts_url.dict["Members@odata.count"] in [9, 12]:
            delete_mode = "PATCH_Action"
            
        if delete_mode == "DELETE_Action":
            headers = {"If-Match": "*" }
            # delete bmc user
            response_delete_account_url = REDFISH_OBJ.delete(dest_account_url, headers=headers)
            if response_delete_account_url.status == 200 or response_delete_account_url.status == 204:
                result = {'ret': True, 'msg': "account %s delete successfully" % username}
                return result
            else:
                error_message = utils.get_extended_error(response_delete_account_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    response_delete_account_url, response_delete_account_url.status, error_message)}
                return result

        if delete_mode == "PATCH_Action":
            headers = {"If-Match": etag}
            # Set the body info
            parameter = {
                "Enabled": False,
                "UserName": ""
            }
            #delete bmc user
            response_delete_account_url = REDFISH_OBJ.patch(dest_account_url, body=parameter, headers=headers)
            if response_delete_account_url.status in [200, 204]:
                result = {'ret': True, 'msg': "Account %s deleted successfully" % username}
                return result
            else:
                error_message = utils.get_extended_error(response_delete_account_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    response_delete_account_url, response_delete_account_url.status, error_message)}
                return result

    except Exception as e:
        result = {'ret': False, 'msg': "exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


import argparse
def add_helpmessage(argget):
    argget.add_argument('--username', type=str, required=True, help='Input the username')


def add_parameter():
    """Add delete bmc user parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["username"] = args.username
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

    # Get delete bmc user result and check result
    result = lenovo_delete_bmc_user(ip, login_account, login_password,username)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
