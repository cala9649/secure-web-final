#!/bin/sh

curl -X POST -k -F "title=abc" -F "friendID=1" -F "baseID=1" -F "start=2018-01bad" -F "end=-02" -F "current=0" -F "tdy=0" https://localhost/add_job

