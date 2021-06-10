###
#
# Lenovo Redfish examples - Del event subscriptions
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
import traceback
import lenovo_utils as utils

def del_event_subscriptions(ip, login_account, login_password,option_command):
    """Del event subscriptions
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params option_command: optional command
        :type option_command: dict
        :returns: returns Del event subscriptions result when succeeded or error message when failed
        """

    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
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
                    headers = {"Content-Type": "application/json"}
                    delete_url_list = []
                    for item in  response_subscriptions_url.dict["Members"]:
                        tmp_url = item["@odata.id"]
                        for key in option_command:
                            if key == "destination":
                                response_tmp_url = REDFISH_OBJ.get(tmp_url, None)
                                if response_tmp_url.status == 200:
                                    if option_command[key] in response_tmp_url.dict["Destination"]:
                                        delete_url_list.append(tmp_url)
                                else:
                                    error_message = utils.get_extended_error(response_tmp_url)
                                    result = {'ret': False,
                                              'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                                  tmp_url, response_tmp_url.status, error_message)}
                                    return result
                            elif key == "id":
                                if option_command[key] in tmp_url:
                                    delete_url_list.append(tmp_url)
                                break                                       #id is unique
                            else:
                                delete_url_list.append(tmp_url)
                    if len(delete_url_list) == 0:
                        result = {"ret":False,"msg":"There are no destination url is congruent"}
                        return result
                    else:
                        for delelte_url in delete_url_list:
                            response_del_subscriptions = REDFISH_OBJ.delete(delelte_url, headers=headers)
                            if response_del_subscriptions.status == 200 or response_del_subscriptions.status == 204:
                                result = {"ret": True, "msg": "Del event subscriptions successfully"}
                            else:
                                error_message = utils.get_extended_error(response_del_subscriptions)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                    delelte_url, response_del_subscriptions.status, error_message)}
                                return result
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
        traceback.print_exc()
        result = {'ret': False, 'msg': "Exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass

def add_helpmessage(argget):
    group = argget.add_mutually_exclusive_group(required=True)
    group.add_argument('--destination', type=str, help="The destination ip/servername you want to delete. Note: All matched items will be deleted.")
    group.add_argument('--all', help="Delete all subscriptions", action="store_true")
    group.add_argument('--id', type=str, help="The subscription id you want to delete")

def add_parameter():
    """Add event subscriptions parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    dict_option = {}
    if args.destination:
        dict_option["destination"] = args.destination
    elif args.id:
        dict_option["id"] = args.id
    else:
        dict_option["all"] = "all"
    parameter_info["opcommand"] = dict_option
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    option_command = parameter_info["opcommand"]

    # Del event subscriptions and check result
    result = del_event_subscriptions(ip,login_account,login_password,option_command)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
