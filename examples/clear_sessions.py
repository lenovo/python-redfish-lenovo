###
#
# Lenovo Redfish examples - Clear sessions
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
import string
import traceback
import lenovo_utils as utils

def clear_sessions(ip, login_account, login_password, username):
    """Get BMC inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: username which session will be cleared
    :type username: string
    :returns: returns session list when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="basic")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    session_list = []
    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_update_service_url
    if response_base_url.status == 200:
        session_service_url = response_base_url.dict['SessionService']['@odata.id']
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result

    response_session_service_url = REDFISH_OBJ.get(session_service_url, None)
    if response_session_service_url.status == 200:
        sessions_url = response_session_service_url.dict['Sessions']['@odata.id']
        response_sessions_url = REDFISH_OBJ.get(sessions_url, None)
        if response_sessions_url.status == 200:
            for single_session in response_sessions_url.dict["Members"]:
                single_session_url = single_session['@odata.id']
                if username != None and len(username) !=0:
                    response_single_session = REDFISH_OBJ.get(single_session_url, None)
                    if response_single_session.status == 200:
                        if 'UserName' in response_single_session.dict:
                            if username == response_single_session.dict['UserName']:
                                body = {}
                                response_clear_session = REDFISH_OBJ.delete(single_session_url) 
                                if response_clear_session.status in [200, 204]:
                                    continue
                                else:
                                    result = {'ret': False, 'msg': "response clear session Error code %s" % response_clear_session.status}
                                    REDFISH_OBJ.logout()
                                    return result
                    else:
                        result = {'ret': False, 'msg': "response single session Error code %s" % response_single_session.status}
                        REDFISH_OBJ.logout()
                        return result
                else:
                    body = {}
                    response_clear_session = REDFISH_OBJ.delete(single_session_url)
                    if response_clear_session.status in [200, 204]:
                        continue
                    else:
                        result = {'ret': False, 'msg': "response clear session Error code %s" % response_clear_session.status}
                        REDFISH_OBJ.logout()
                        return result
        else:
            result = {'ret': False, 'msg': "response sessions url Error code %s" % response_sessions_url.status}
            REDFISH_OBJ.logout()
            return result
    else:
        result = {'ret': False, 'msg': "response session service_url Error code %s" % response_session_service_url.status}
        REDFISH_OBJ.logout()
        return result

    result = {'ret': True, 'msg': 'Clear sessions successfully.'}

    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


import argparse
def add_helpmessage(parser):
    parser.add_argument('--username', type=str, required=False, help='Input the user name, sessions created by this user name will be cleared. Default is to clear all sessions.')


def add_parameter():
    """Add clear sessions parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['user_name'] = args.username
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        username = parameter_info['user_name']
    except:
        username = ""
    
    # Get sessions information and check result
    result = clear_sessions(ip, login_account, login_password, username)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
