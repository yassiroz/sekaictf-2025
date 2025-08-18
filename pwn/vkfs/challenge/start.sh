#!/bin/bash

mkdir -p ./mount
./vkfs -o allow_other,default_permissions -s ./mount
