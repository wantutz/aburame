#!/bin/bash

echo "Run iperf3 in Port Group 1"
./run_perf_test_pg1.sh &

echo "Run iperf3 in Port Group 2"
./run_perf_test_pg2.sh &

echo "Run iperf3 in Port Group 3"
./run_perf_test_pg3.sh &

echo "Run iperf3 in Port Group 4"
./run_perf_test_pg4.sh &

