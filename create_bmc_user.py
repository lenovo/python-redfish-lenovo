###
#
# Lenovo Redfish examples - Create bmc user
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


def create_bmc_user(ip, login_account, login_password, username, password, authority):
    """create bmc user
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: new  username by user specified
    :type userid: string
    :params password: new password by user specified
    :type password: string
    :params authority: user authority by user specified
    :type authority: list
    :returns: return successful result when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get ServiceBase resource
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status == 200:
            accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
            #create new user account
            headers = None
            parameter = {
                "Password": password,
                "Name": username,
                "UserName": username,
                "RoleId":authority
                }
            response_create_url = REDFISH_OBJ.post(accounts_url, body=parameter, headers=headers)
            if response_create_url.status == 200 or response_create_url.status == 201 or response_create_url.status == 204:
                result = {'ret': True, 'msg': "create new user successful"}
                return result
            else:
                error_message = utils.get_extended_error(response_create_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    response_create_url, response_create_url.status, error_message)}
                return result

        else:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                account_service_url, response_account_service_url.status, error_message)}
            return result
            
    except Exception as e:
        result = {'ret': False, 'msg': "exception msg %s" % e}
        return result
    finally:
        REDFISH_OBJ.logout()


import argparse
def add_helpmessage(argget):
    argget.add_argument('--newusername', type=str, required=True, help='Input the update account username')
    argget.add_argument('--newuserpasswd', type=str, required=True, help='Input the user new userpasswd')
    help_str = "The value of this parameter shall be the privileges that this user includes"
    argget.add_argument('--authority', type=str, choices=["Administrator", "Operator", "NoAccess", "ReadOnly"], required=True, help=help_str)


def add_parameter():
    """Add create bmc user parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["newusername"] = args.newusername
    parameter_info["newuserpasswd"] = args.newuserpasswd
    parameter_info["authority"] = args.authority
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    username = parameter_info['newusername']
    password = parameter_info['newuserpasswd']
    authority = parameter_info['authority']

    # create bmc user result and check result
    result = create_bmc_user(ip, login_account, login_password, username, password,authority)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

