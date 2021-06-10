###
#
# Lenovo Redfish examples - Reset bios default
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
import json
import time
import redfish
import traceback
import lenovo_utils as utils


def reset_bios_default(ip, login_account, login_password, system_id):
    """Reset the BIOS attributes to default    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns reset bios default result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result
        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the ComputerBios resource
                bios_url = response_system_url.dict['Bios']['@odata.id']
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (system_url, response_system_url.status, error_message)}
                return result
            response_bios_url = REDFISH_OBJ.get(bios_url, None)
            if response_bios_url.status == 200:
                # Get the Bios reset url
                reset_bios_url = response_bios_url.dict['Actions']['#Bios.ResetBios']['target']
                body = {}
                # get parameter requirement if ActionInfo is provided
                if "@Redfish.ActionInfo" in response_bios_url.dict["Actions"]["#Bios.ResetBios"]:
                    actioninfo_url = response_bios_url.dict["Actions"]["#Bios.ResetBios"]["@Redfish.ActionInfo"]
                    response_actioninfo_url = REDFISH_OBJ.get(actioninfo_url, None)
                    if (response_actioninfo_url.status == 200) and ("Parameters" in response_actioninfo_url.dict):
                        for parameter in response_actioninfo_url.dict["Parameters"]:
                            if ("Name" in parameter) and ("AllowableValues" in parameter):
                               body[parameter["Name"]] = parameter["AllowableValues"][0]

                # Reset bios default
                headers = {"Content-Type":"application/json"}
                if body:
                    response_reset_bios = REDFISH_OBJ.post(reset_bios_url, body=body, headers=headers)
                elif "settings" in reset_bios_url:
                    body = {"ResetType": "default"}
                    response_reset_bios = REDFISH_OBJ.post(reset_bios_url, body=body, headers=headers)
                else:
                    response_reset_bios = REDFISH_OBJ.post(reset_bios_url, headers=headers, body=body)
                if response_reset_bios.status in [200, 204]:
                    result = {'ret': True, 'msg': 'Reset bios default successfully'}
                elif response_reset_bios.status == 202:
                    task_uri = response_reset_bios.dict["@odata.id"]
                    result = task_monitor(REDFISH_OBJ, task_uri)
                    # Delete the task when the task state is completed without any warning
                    if result["ret"] is True and "Completed" == result["task_state"] and result["msg"] == "":
                        REDFISH_OBJ.delete(task_uri, None)
                    if result["ret"] is True:
                        task_state = result["task_state"]
                        if task_state == "Completed":
                            result["msg"] = "Reset bios default successfully. %s" %(result["msg"])
                        else:
                            result["ret"] = False
                            result["msg"] = "Reset bios default failed. %s" %(result["msg"])
                    else:
                        return result
                else:
                    error_message = utils.get_extended_error(response_reset_bios)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s"% (reset_bios_url, response_reset_bios.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_bios_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (bios_url, response_bios_url.status, error_message)}
                return result
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def task_monitor(REDFISH_OBJ, task_uri):
    """Monitor task status"""
    RUNNING_TASK_STATE = ["New", "Pending", "Service", "Starting", "Stopping", "Running", "Cancelling", "Verifying"]
    END_TASK_STATE = ["Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended"]
    current_state = ""
    messages = []
    percent = 0

    while True:
        response_task_uri = REDFISH_OBJ.get(task_uri, None)
        if response_task_uri.status == 200:
            task_state = response_task_uri.dict["TaskState"]

            if "Messages" in response_task_uri.dict:
                messages = response_task_uri.dict["Messages"]
            if "PercentComplete" in response_task_uri.dict:
                percent = response_task_uri.dict["PercentComplete"]

            if task_state in RUNNING_TASK_STATE:
                if task_state != current_state:
                    current_state = task_state
                    print("Task state is %s, wait a minute" %current_state)
                    continue
                else:
                    flush(percent)
            elif task_state in END_TASK_STATE:
                sys.stdout.write(' ' * 100 + '\r')
                sys.stdout.flush()
                print("End of the task")
                result = {'ret':True, 'task_state':task_state, 'msg': ' Messages: %s' %str(messages) if messages != [] else ''}
                return result
            else:
                result = {'ret':False, 'task_state':task_state}
                result['msg'] = ('Unknown TaskState %s. ' %task_state) + 'Task Not conforming to Schema Specification. ' + (
                    'Messages: %s' %str(messages) if messages != [] else '')
                return result
        else:
            message = utils.get_extended_error(response_task_uri)
            result = {'ret': False, 'task_state':None, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                task_uri, response_task_uri.status, message)}
            return result


def flush(percent):
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + (('          PercentComplete: %d' %percent) if percent > 0 else '') + '\r')
        sys.stdout.flush()
        time.sleep(0.1)


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get reset bios default result and check result
    result = reset_bios_default(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
