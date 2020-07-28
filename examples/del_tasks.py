###
#
# Lenovo Redfish examples - Delete tasks
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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

def del_tasks(ip, login_account, login_password,option_command):
    """Delete all tasks or the task specified
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params option_command: optional command
        :type option_command: dict
        :returns: returns Delete tasks result when succeeded or error message when failed
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
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    # Get ServiceBase resource
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status == 200:
            taskservice_url = response_base_url.dict["Tasks"]["@odata.id"]
            response_taskservice_url = REDFISH_OBJ.get(taskservice_url,None)
            if response_taskservice_url.status == 200:
                tasks_url = response_taskservice_url.dict["Tasks"]["@odata.id"]
                response_tasks_url = REDFISH_OBJ.get(tasks_url,None)
                if response_tasks_url.status == 200:
                    if len(response_tasks_url.dict["Members"]) == 0:
                        result = {"ret":True,"msg":"There are no tasks found in this system!"}
                        return result
                    headers = {"Content-Type": "application/json"}
                    delete_url_list = []
                    for item in  response_tasks_url.dict["Members"]:
                        tmp_url = item["@odata.id"]
                        for key in option_command:
                            if key == "id":
                                if option_command[key] == tmp_url.split("/")[-1]:
                                    delete_url_list.append(tmp_url)
                                break                                       #id is unique
                            else:
                                delete_url_list.append(tmp_url)
                    if len(delete_url_list) == 0:
                        result = {"ret":False,"msg":"There are no tasks to match the id specified."}
                        return result
                    else:
                        for delelte_url in delete_url_list:
                            response_del_task = REDFISH_OBJ.delete(delelte_url, headers=headers)
                            if response_del_task.status == 200 or response_del_task.status == 204:
                                result = {"ret": True, "msg": "Delete tasks successfully."}
                            else:
                                error_message = utils.get_extended_error(response_del_task)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                    delelte_url, response_del_task.status, error_message)}
                                return result
                        return result
                else:
                    error_message = utils.get_extended_error(response_tasks_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        subscriptions_url, response_tasks_url.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_taskservice_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    event_url, response_taskservice_url.status, error_message)}
                return result
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "Exception msg %s" % repr(e)}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass

def add_helpmessage(argget):
    group = argget.add_mutually_exclusive_group(required=True)
    group.add_argument('--all', help="Delete all tasks", action="store_true")
    group.add_argument('--id', type=str, help="The task id you want to delete")

def add_parameter():
    """Add deleting tasks parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    dict_option = {}
    if args.id:
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
    result = del_tasks(ip,login_account,login_password,option_command)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
