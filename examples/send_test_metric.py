###
#
# Lenovo Redfish examples - Send Test Metric Report
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
import datetime
from . import lenovo_utils as utils

def send_test_metric(ip, login_account, login_password, reportname):
    """Send Test Metric
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params reportname: The MetricReportName you want to send
    :type reportname: string
    :returns: returns Send test metric result when succeeded or error message when failed
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

    # Get TelemetryService resource
    response_telemetry_service_url = REDFISH_OBJ.get(telemetry_service_url, None)
    if response_telemetry_service_url.status != 200:
        result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (telemetry_service_url, response_telemetry_service_url.status)}
        REDFISH_OBJ.logout()
        return result

    # Get SummitTestMetricReport URI
    summit_test_metric_uri = response_telemetry_service_url.dict['Actions']['#TelemetryService.SubmitTestMetricReport']['target']

    # Get MetricReports collection
    metric_collection_url = response_telemetry_service_url.dict['MetricReports']['@odata.id']
    response_metric_collection_url = REDFISH_OBJ.get(metric_collection_url, None)
    if response_metric_collection_url.status != 200:
        result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (metric_collection_url, response_metric_collection_url.status)}
        REDFISH_OBJ.logout()
        return result

    # Get each MetricReport
    flag_found = False
    metric_reportname_list = []
    GeneratedMetricReportValues = []
    for metric_member in response_metric_collection_url.dict["Members"]:
        metric_name = metric_member['@odata.id'].split('/')[-1]
        metric_reportname_list.append(metric_name)
        if reportname == metric_name:
            flag_found = True
            break

    if flag_found == False:
        result = {'ret': False, 'msg': "Invalid reportname. Allowable reportname list: %s" % str(metric_reportname_list)}
        REDFISH_OBJ.logout()
        return result

    # Set default MetricReportValues
    metric_value_obj = {}
    metric_value_obj["MetricProperty"] = ""
    metric_value_obj["Timestamp"] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+00:00')
    metric_value_obj["MetricValue"] = "0"
    GeneratedMetricReportValues.append(metric_value_obj)

    # POST the metric test report 
    headers = {"Content-Type": "application/json", "If-match": "*"}
    parameter = {"MetricReportName":reportname, "GeneratedMetricReportValues":GeneratedMetricReportValues}
    response_send_metric = REDFISH_OBJ.post(summit_test_metric_uri,headers=headers,body=parameter)
    if response_send_metric.status == 200 or response_send_metric.status == 204:
        result = {"ret":True,"msg":"Send Test Metric successsfully, Metric data: " + str(parameter) }
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result
    else:
        error_message = utils.get_extended_error(response_send_metric)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            summit_test_metric_uri, response_send_metric.status, error_message)}
        REDFISH_OBJ.logout()
        return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--reportname', type=str,default="CPUTemp",help="The MetricReportName you want to send, such as CPUTemp,InletAirTemp,PowerMetrics,PowerSupplyStats")

def add_parameter():
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['reportname'] = args.reportname
    return parameter_info


if __name__ == '__main__':
     # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    reportname = parameter_info['reportname']
   
    # Send test metric report and check result
    result = send_test_metric(ip, login_account, login_password, reportname)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + "\n")
    else:
        sys.stderr.write(result['msg'] + '\n')
