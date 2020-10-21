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

class DataStructureConverter(object):

    def __init__(self):
        pass

    def list_of_dict_to_dict(self, list_of_dict, key):
        output_dict = dict()

        for item in list_of_dict:
            output_dict[item[key]] = item

        return output_dict

if __name__ == '__main__':
    pass
