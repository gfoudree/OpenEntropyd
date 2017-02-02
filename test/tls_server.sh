#!/bin/bash

openssl s_client -connect 127.0.0.1:321 -cert client.crt -key client.key -CAfile ca.crt
