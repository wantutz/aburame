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
import os
from pathlib import Path

# 3rd party library
from datetime import datetime

class CustomResults(object):
    def __init__(self, result_dir, column_names, column_widths):
        # Result directory
        self.result_dir = result_dir

        # Insert timestamp column
        self.column_names = column_names
        self.column_names.insert(0, "Date/Time")

        # Timestamp column width
        self.column_widths = column_widths
        self.column_widths.insert(0, 20)

    def craft_header(self):
        entry_items = ["{value:^{width}}|".format(value=self.column_names[0], width=self.column_widths[0])]

        for (item, width) in zip(self.column_names[1:], self.column_widths[1:]):
            entry_items.append("{value:^{width}}|".format(value=item, width=width))

        # width of each column + separators
        total_width = (sum(self.column_widths) + len(self.column_widths))

        return("{}".format("".join(entry_items)) + "\n" + "{}".format("=" * total_width) + "\n")

    def craft_entry(self, result):
        now = datetime.now()
        timestamp = now.strftime("%Y/%m/%d %H:%M:%S")

        entry_items = ["{value:>{width}}|".format(value=timestamp, width=self.column_widths[0])]

        for (item, width) in zip(result, self.column_widths[1:]):
            entry_items.append("{value:>{width}}|".format(value=item, width=width))

        # width of each column + separators
        total_width = (sum(self.column_widths) + len(self.column_widths))

        return("{}".format("".join(entry_items)) + "\n" + "{}".format("-" * total_width) + "\n")

    def add(self, result):
        # Base filename on build
        filename = result[0].strip()

        # Create repo dir if necessary
        path = Path(self.result_dir)
        path.mkdir(parents=True, exist_ok=True)

        # Full path + filename
        if filename is not None:
            result_file = self.result_dir + filename
        else:
            result_file = self.result_dir + "None"

        # Write/Append result
        if os.path.isfile(result_file):
            # Existing result file, append entry
            with open(result_file, "a") as result_fh:
                entry = self.craft_entry(result)
                result_fh.write(entry)
        else:
            # New result file, create file then write entry
            with open(result_file, "w") as result_fh:
                header = self.craft_header()
                entry = self.craft_entry(result)
                result_fh.write(header)
                result_fh.write(entry)

if __name__ == "__main__":
    result_dir = "./"

    column_names = ["Build", "Model-ID-Iter", "SPS", "HA", "Cpty", "TxRate", "RxRate", "AvgTCPResp"]
    column_widths = [26, 34, 14, 4, 4, 8, 8, 10]

    custom_results = CustomResults(result_dir, column_names, column_widths)

    result0 = ["Mgmt2.1.757Cnt2.1.33", "SxTestDev1 - 100 - 10100", "None", "N", "2Gb", "8000", "8000", "62"]
    result1 = ["Mgmt2.1.757Cnt2.1.33", "SxTestDev1 - 101 - 10101", "Discover", "N", "2Gb", "2000", "2000", "271"]
    result2 = ["Mgmt2.1.757Cnt2.1.33", "SxTestDev1 - 102 - 10102", "Testing", "N", "2Gb", "1000", "1000", "324"]
    result3 = ["Mgmt2.1.757Cnt2.1.33", "SxTestDev1 - 103 - 10103", "All Inclusive", "Y", "unli", "100", "100", "824"]

    custom_results.add(result0)
    custom_results.add(result1)
    custom_results.add(result2)
    custom_results.add(result3)
