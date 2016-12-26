#!/bin/bash

openssl s_client -connect 127.0.0.1:8080 -cert Openentropyd-Client.crt -key Openentropyd-Client.key -CAfile OpenEntropyd.crt
