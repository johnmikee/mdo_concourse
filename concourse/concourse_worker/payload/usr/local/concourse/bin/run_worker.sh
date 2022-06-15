#!/bin/sh 

CONCOURSE_HOST="localhost"

/usr/local/concourse/bin/concourse worker \
    --work-dir /usr/local/concourse/work_dir \
    --tsa-host $CONCOURSE_HOST:2222 \
    --tsa-public-key /usr/local/concourse/keys/tsa_host_key.pub \
    --tsa-worker-private-key /usr/local/concourse/keys/worker_id_rsa