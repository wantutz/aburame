#/*
#* ShieldX Networks Inc. CONFIDENTIAL
#* ----------------------------------
#*
#* Copyright (c) 2016 ShieldX Networks Inc.
#* All Rights Reserved.
#*
#* NOTICE:  All information contained herein is, and remains
#* the property of ShieldX Networks Incorporated and its suppliers,
#* if any.  The intellectual and technical concepts contained
#* herein are proprietary to ShieldX Networks Incorporated
#* and its suppliers and may be covered by U.S. and Foreign Patents,
#* patents in process, and are protected by trade secret or copyright law.
#* Dissemination of this information or reproduction of this material
#* is strictly forbidden unless prior written permission is obtained
#* from ShieldX Networks Incorporated.
#*/

# standard library
import json

class CustomConfigReader(object):

    def __init__(self):
        pass

    def read_json_config(self, json_file):
        json_config = None

        with open(json_file, "r") as config_file:
            json_config = json.load(config_file)

        return json_config

    def write_json_config(self, data, json_file):
        with open(json_file, "w") as config_file:
            json.dump(data, config_file)

if __name__ == '__main__':
    pass
