###
#
# Lenovo Redfish examples - Get metric inventory
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
import traceback
import lenovo_utils as utils

def get_metric_definition_report(ip, login_account, login_password):
    """Get metric inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns metric inventory when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check if the username, password, IP is correct."}
        return result

    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_telemetry_service_url
    if response_base_url.status == 200:
        if 'TelemetryService' in response_base_url.dict:
            telemetry_service_url = response_base_url.dict['TelemetryService']['@odata.id']
        else:
            result = {'ret': False, 'msg': "TelemetryService is not supported"}
            REDFISH_OBJ.logout()
            return result
    else:
        result = {'ret': False, 'msg': "Access url /redfish/v1 failed. Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result

    response_telemetry_service_url = REDFISH_OBJ.get(telemetry_service_url, None)
    if response_telemetry_service_url.status != 200:
        result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (telemetry_service_url, response_telemetry_service_url.status)}
        REDFISH_OBJ.logout()
        return result

    metric_inventory = {}
    # Get MetricDefinition collection
    metric_collection_url = response_telemetry_service_url.dict['MetricDefinitions']['@odata.id']
    response_metric_collection_url = REDFISH_OBJ.get(metric_collection_url, None)
    if response_metric_collection_url.status != 200:
        result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (metric_collection_url, response_metric_collection_url.status)}
        REDFISH_OBJ.logout()
        return result

    # Get each MetricDefinition
    metric_definitons = []
    for metric_member in response_metric_collection_url.dict["Members"]:
        metric_url = metric_member['@odata.id']
        metric_list = metric_url.split("/")
        response_metric_url = REDFISH_OBJ.get(metric_url, None)
        if response_metric_url.status == 200:
            metric_detail = {}
            for property in response_metric_url.dict:
                if property not in ["Description","@odata.context","@odata.id","@odata.type","@odata.etag", "Links", "Actions", "RelatedItem"]:
                    metric_detail[property] = response_metric_url.dict[property]
            metric_entry = {metric_list[-1]: metric_detail}
            metric_definitons.append(metric_entry)
        else:
            result = {'ret': False,
                      'msg': "Access url %s failed. Error code %s" %(metric_url, response_metric_url.status)}
            REDFISH_OBJ.logout()
            return result

    # Get MetricReports collection
    metric_collection_url = response_telemetry_service_url.dict['MetricReports']['@odata.id']
    response_metric_collection_url = REDFISH_OBJ.get(metric_collection_url, None)
    if response_metric_collection_url.status != 200:
        result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (metric_collection_url, response_metric_collection_url.status)}
        REDFISH_OBJ.logout()
        return result

    # Get each MetricReport
    metric_reports = []
    for metric_member in response_metric_collection_url.dict["Members"]:
        metric_url = metric_member['@odata.id']
        metric_list = metric_url.split("/")
        response_metric_url = REDFISH_OBJ.get(metric_url, None)
        if response_metric_url.status == 200:
            metric_detail = {}
            for property in response_metric_url.dict:
                if property not in ["Description","@odata.context","@odata.id","@odata.type","@odata.etag", "Links", "Actions", "RelatedItem"]:
                    metric_detail[property] = response_metric_url.dict[property]
            metric_entry = {metric_list[-1]: metric_detail}
            metric_reports.append(metric_entry)
        else:
            result = {'ret': False,
                      'msg': "Access url %s failed. Error code %s" %(metric_url, response_metric_url.status)}
            REDFISH_OBJ.logout()
            return result

    # Set result
    metric_inventory['MetricDefinitions'] = metric_definitons
    metric_inventory['MetricReports'] = metric_reports
    result['ret'] = True
    result['metric_inventory'] = metric_inventory

    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_parameter():
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info



if __name__ == '__main__':
     # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
   
    # Get metric inventory and check result
    result = get_metric_definition_report(ip, login_account, login_password)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['metric_inventory'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
