#!/bin/bash

openssl s_client -connect 127.0.0.1:321 -cert Openentropyd-Client.crt -key Openentropyd-Client.key -CAfile OpenEntropyd.crt
