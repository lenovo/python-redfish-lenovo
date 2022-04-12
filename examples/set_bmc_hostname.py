###
#
# Lenovo Redfish examples - Set BMC Host Name
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


def set_bmc_hostname(ip, login_account, login_password, hostname):
    """Set BMC host name
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params hostname: BMC host name
    :type hostname: string
    :returns: returns set result when succeeded or error message when failed
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
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    # Get ServiceBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_base_url
    if response_base_url.status == 200:
        manager_url = response_base_url.dict['Managers']['@odata.id']
    else:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '/redfish/v1' response error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
        return result

    # Get the manager url response resource
    target_ethernet_uri = None
    nic_addr = ip.split(':')[0]  # split port if existing

    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status != 200:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
            manager_url, response_manager_url.status, error_message)}
        return result

    for request in response_manager_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            return result

        if 'EthernetInterfaces' not in response_url.dict:
            continue

        request_url = response_url.dict["EthernetInterfaces"]["@odata.id"]
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            return result

        # Find target EthernetInterface
        for nic_request in response_url.dict['Members']:
            sub_request_url = nic_request['@odata.id']
            sub_response_url = REDFISH_OBJ.get(sub_request_url, None)
            if sub_response_url.status != 200:
                error_message = utils.get_extended_error(sub_response_url)
                result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                    sub_request_url, sub_response_url.status, error_message)}
                return result

            data = sub_response_url.dict
            if '"' + nic_addr + '"' in str(data) or "'" + nic_addr + "'" in str(data):
                target_ethernet_uri = sub_request_url
                break

        if target_ethernet_uri is not None:
            break

    if target_ethernet_uri is None:
        return {'ret': False, 'msg': "No matched EthernetInterface found under Manager"}

    headers = {"If-Match": "*"}
    body = {'HostName': hostname}

    # Send Patch Request to Modify BMC host Name
    response_host_name_url = REDFISH_OBJ.patch(target_ethernet_uri, body=body, headers=headers)
    if response_host_name_url.status in [200, 204]:
        result = {'ret': True,
                  'msg': "Set BMC host name %s successfully" % hostname}
    elif response_host_name_url.status == 202:
        task_uri = response_host_name_url.dict['@odata.id']
        while True:
            result = utils.task_monitor(REDFISH_OBJ, task_uri)
            if result["ret"] is False and result["task_state"] == 401:
                while True:
                    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
                    if response_base_url.status == 200:
                        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
                        REDFISH_OBJ.login(auth=utils.g_AUTH)
                        break
                    else:
                        time.sleep(1)
                        continue
                continue
            break
        # Delete the task when the task state is completed without any warning
        severity = ''
        if result["ret"] is True and "Completed" == result["task_state"] and result['msg'] != '':
            result_json = json.loads(result['msg'].replace("Messages:","").replace("'","\""))
            if "Severity" in result_json[0]:
                severity = result_json[0]["Severity"]
        if result["ret"] is True and "Completed" == result["task_state"] and (result['msg'] == '' or severity == 'OK'):
            REDFISH_OBJ.delete(task_uri, None)
        if result["ret"] is True:
            task_state = result["task_state"]
            if task_state == "Completed":
                result['msg'] = "Set BMC host name %s successfully. %s" % (hostname, result['msg'])
            else:
                result['ret'] = False
                result['msg'] = "Failed to set BMC host name %s. %s" % (hostname, result['msg'])
        return result
    else:
        error_message = utils.get_extended_error(response_host_name_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" %
                                       (target_ethernet_uri, response_host_name_url.status, error_message)}

    try:
        REDFISH_OBJ.logout()
    except:
        pass

    return result


def add_helpmessage(argget):
    argget.add_argument('--hostname', type=str, required=True,
                        help='Set BMC host name, after set, you can use script get_bmc_inventory.py to check the result')


def add_parameter():
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["host_name"] = args.hostname
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info["ip"]
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        host_name = parameter_info["host_name"]
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # set host name and check result
    result = set_bmc_hostname(ip, login_account, login_password, host_name)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

