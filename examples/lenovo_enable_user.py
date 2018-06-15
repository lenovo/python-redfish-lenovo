###
#
# Lenovo Redfish examples - enable user
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
import redfish
import json


def enable_user(ip, login_account, login_password, userid):
    result = {}
    login_host = "https://" + ip
    try:
        # Create a REDFISH object
        # Connect using the BMC address, account name, and password
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    
    # Get response_base_url resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get account service url
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
        accounts_url += str(userid)
        
        response_account_url = REDFISH_OBJ.get(accounts_url, None)
        etag = response_account_url.dict['@odata.etag']
        username = response_account_url.dict["UserName"]
        
        headers = {"If-Match": etag}
        
        parameter = {"Enabled": True,
                     "UserName": username}
        response_accounts_url = REDFISH_OBJ.patch(accounts_url, body=parameter, headers=headers)
        
        if response_accounts_url.status == 200:
            result = {'ret': True, 'msg': "User %s enable successfully" %userid}
        else:
            result = {'ret': False, 'msg': "response accounts url Error code %s" % response_accounts_url.status}
            REDFISH_OBJ.logout()
            return result
    else:
        result = {'ret': False, 'msg': "response account service url Error code %s" % response_account_service_url.status}

    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'

    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    # Input the user ID you want to modify.
    # 1-12
    userid = sys.argv[4]

    result = enable_user(ip, login_account, login_password, userid)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
