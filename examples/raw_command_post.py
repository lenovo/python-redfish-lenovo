###
#
# Lenovo Redfish examples - Perform a specified action
#
# Copyright Notice:
#
# Copyright 2021 Lenovo Corporation
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


def raw_command_post(ip, login_account, login_password, action_target, body=None):
    """Post specified resource
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params action_target: redfish resource uri
    :type action_target: string
    :params body: json string body for redfish post request
    :type body: string
    :returns: returns specified resource information when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object 
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout, 
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE, max_retry=3)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    request_url = action_target
    if body == None:
        request_body = {}
    else:
        request_body = json.loads(body)
    response_url = REDFISH_OBJ.post(request_url, body=request_body)
    if response_url.status not in [200, 202, 204]:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            request_url, response_url.status, error_message)}
        return result

    message_extendedinfo = ""
    if response_url.status == 202:
        task_uri = response_url.dict['@odata.id']
        print("This is a time consuming action. Start to monitor the generated task %s.\n" %(task_uri))
        result = task_monitor(REDFISH_OBJ, task_uri)
        if result['msg'] != "":
            message_extendedinfo = "task_state: %s, msg: %s" %(result['task_state'], result['msg'])
        else:
            message_extendedinfo = "task_state: %s" %(result['task_state'])
    elif response_url.status != 204:
        message_extendedinfo = "Response body: " + str(response_url.dict)

    result['ret'] = True
    result['msg'] = "Perform resource uri action %s successfully. %s" %(action_target, message_extendedinfo)
    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def flush(percent):
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + (('          PercentComplete: %d' %percent) if percent > 0 else '') + '\r')
        sys.stdout.flush()
        time.sleep(0.1)


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
            if 'Messages' in response_task_uri.dict:
                messages = response_task_uri.dict['Messages']
            if 'PercentComplete' in response_task_uri.dict:
                percent = response_task_uri.dict['PercentComplete']

            if task_state in RUNNING_TASK_STATE:
                if task_state != current_state:
                    current_state = task_state
                    print('Task state is %s, wait a minute' % current_state)
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


def add_helpmessage(parser):
    parser.add_argument('--action_target', type=str, required=True,
                        help='Specify redfish action target. Ex: "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"')
    parser.add_argument('--body', type=str,
            help='Specify json string body for redfish post request. Ex: \'{"ResetType": "On"}\'')


def add_parameter():
    """Add parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["action_target"] = args.action_target
    parameter_info["body"] = args.body
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get action_target and body
    action_target = parameter_info["action_target"]
    body = parameter_info["body"]

    # Post redfish resource with body and check result
    result = raw_command_post(ip, login_account, login_password, action_target, body)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

