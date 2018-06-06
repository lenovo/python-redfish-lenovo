###
#
# Lenovo Redfish examples - Set manager ntp
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


def set_manager_ntp(ip, login_account, login_password,  ntp_server, ProtocolEnabled):
    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
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
        manager_url = response_base_url.dict['Managers']['@odata.id']
    else:
        result = {'ret': False, 'msg': " response_base_url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status == 200:
        for request in response_manager_url.dict['Members']:
            request_url = request['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status == 200:
                network_url = response_url.dict['NetworkProtocol']['@odata.id']
                Protocol = {"NTPServers":list(ntp_server),"ProtocolEnabled":  bool(int(ProtocolEnabled))}
                parameter = {"NTP": Protocol}
                response_network_url = REDFISH_OBJ.patch(network_url, body=parameter)
                if response_network_url.status == 200:
                    result = {'ret': True, 'msg': " Set manager ntp successful"}
                else:
                    result = {'ret': False, 'msg': "response network Error code %s" % response_network_url.status}
                    REDFISH_OBJ.logout()
                    return result
            else:
                result = {'ret': False, 'msg': "response  url Error code %s" % response_url.status}
                REDFISH_OBJ.logout()
                return result

    else:
        result = {'ret': False, 'msg': "response manager url Error code %s" % response_manager_url.status}
        REDFISH_OBJ.logout()
        return result

    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    # ["64.113.44.54","","",""]
    ntp_server = sys.argv[4]
    # "ProtocolEnabled": True
    # 0:false, 1:true
    ProtocolEnabled = sys.argv[5]

    result = set_manager_ntp(ip, login_account, login_password, ntp_server, ProtocolEnabled)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])