#!/bin/bash

if [ ! -z ${RANCHER_DEBUG} ]; then
    set -x
fi

/opt/rancher/bin/caas-security
