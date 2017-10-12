###
# Copyright Notice:
#
# Copyright 2017 Lenovo Corporation
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
import logging
import redfish
from redfish import redfish_logger


def get_system_url(base_url, redfish_obj):
    """Get ComputerSystem instance URL
    
    :params base_url: URL of the Redfish Service Root
    :type base_url: string
    :params http_response: Response from HTTP
    :type redfish_obj: redfish client object
    :returns: returns string URL to ComputerSystem resource
    
    """
    # Get ServiceRoot resource
    response_base_url = redfish_obj.get(base_url, None)

    # Get ComputerSystemCollection resource
    systems_url = response_base_url.dict["Systems"]["@odata.id"]
    response_systems_url = redfish_obj.get(systems_url, None)

    # Get the first ComputerSystem resource from the collection members
    #  NOTE: Assume only 1 ComputerSystem instance
    system_url = response_systems_url.dict["Members"][0]["@odata.id"]

    return system_url


def get_extended_error(response_body):
    expected_dict = response_body.dict
    message_dict = expected_dict["error"]["@Message.ExtendedInfo"][0]
    return str(message_dict["Message"])
