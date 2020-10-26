#!/bin/bash
set -ex

setup

/usr/bin/odyssey /scram/config.conf
/scram/test_scram_backend.sh
/scram/test_scram_frontend.sh
ody-restart

/ody-intergration-test

teardown
