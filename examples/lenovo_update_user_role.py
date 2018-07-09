###
#
# Lenovo Redfish examples - updata user role
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


import sys, json
import redfish
import lenovo_utils as utils

def updata_user_role(ip, login_account, login_password, userid, role_id):
    """update user role id    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params userid: UserID to be modified by the user
    :type userid: string
    :params role_id: New role_id to be modified by the user
    :type role_id: string
    :returns: returns update user role id result when succeeded or error message when failed
    """
    result = {}
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
  
    # Get ServiceBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_base_url
    if response_base_url.status == 200:
        account_service_url = response_base_url.dict['AccountService']['@odata.id']
    else:
        
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result
    response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
    if response_account_service_url.status == 200:
        accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
        userid = userid
        if accounts_url[-1] == '/':
            accounts_url += str(userid)
        else:
            accounts_url = accounts_url + '/' + str(userid)
        response_account_url = REDFISH_OBJ.get(accounts_url, None)
        if "@odata.etag" in response_account_url.dict:
            etag = response_account_url.dict['@odata.etag']
        else:
            etag = ""
        headers = {"If-Match": etag, "Content-Type": "application/json"}
        parameter = {"RoleId": role_id}
        response_accounts_url = REDFISH_OBJ.patch(accounts_url, body=parameter, headers=headers)
        if response_accounts_url.status == 200:
            result = {'ret': True, 'msg': "updata user role successful"}
        else:
    
            result = {'ret': False, 'msg': "response accounts url Error code %s" % response_accounts_url.status}
            REDFISH_OBJ.logout()
            return result
    else:
        result = {'ret': False, 'msg': "response account service Error code %s" % response_account_service_url.status}
    
    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add update user role parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--userid', type=str, help='Input the user Id')
    argget.add_argument('--roleid', type=str, help='Input the role Id')
    args = argget.parse_args()
    system_info = utils.parse_parameter(args)
    return system_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']

    # Get set info from the parameters user specified
    try:
        userid = parameter_info['userid']
        role_id = parameter_info['roleid']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Update user role id result and check result 
    result = updata_user_role(ip, login_account, login_password, userid, role_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])