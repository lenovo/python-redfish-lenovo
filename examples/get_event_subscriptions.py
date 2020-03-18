###
#
# Lenovo Redfish examples - Get event subscriptions
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
import lenovo_utils as utils

def get_event_subscriptions(ip, login_account, login_password):
    """Get event subscriptions
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns Get event subscriptions result when succeeded or error message when failed
        """

    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status == 200:
            event_url = response_base_url.dict["EventService"]["@odata.id"]
            response_event_url = REDFISH_OBJ.get(event_url,None)
            if response_event_url.status == 200:
                subscriptions_url = response_event_url.dict["Subscriptions"]["@odata.id"]
                response_subscriptions_url = REDFISH_OBJ.get(subscriptions_url,None)
                if response_subscriptions_url.status == 200:
                    dict_subscriptions = {}
                    for key in response_subscriptions_url.dict:
                        if key.startswith("@") or key == "Members@odata.navigationLink" or key == "Members":
                            continue
                        dict_subscriptions[key] = response_subscriptions_url.dict[key]
                    list_member = []
                    for item in response_subscriptions_url.dict["Members"]:
                        sub_url = item["@odata.id"]
                        sub_url_response = REDFISH_OBJ.get(sub_url,None)
                        if sub_url_response.status == 200:
                            tmpdict = {}
                            for key in sub_url_response.dict:
                                if key.startswith("@"):
                                    continue
                                else:
                                    tmpdict[key] = sub_url_response.dict[key]
                            list_member.append(tmpdict)
                        else:
                            error_message = utils.get_extended_error(sub_url_response)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                sub_url, sub_url_response.status, error_message)}
                            return result
                    dict_subscriptions["Members"] = list_member
                    result = {"ret":True,"entries":dict_subscriptions}
                    return result
                else:
                    error_message = utils.get_extended_error(response_subscriptions_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        subscriptions_url, response_subscriptions_url.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_event_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    event_url, response_event_url.status, error_message)}
                return result
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "Exception msg %s" % e}
        return result
    finally:
        REDFISH_OBJ.logout()

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get event subscriptions and check result
    result = get_event_subscriptions(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])