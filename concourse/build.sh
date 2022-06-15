#!/bin/sh

# make sure munkipkg is installed
MUNKIPKG=$(which munkipkg)
if [ -z "$MUNKIPKG" ]; then
    echo "munkipkg is not installed. Please grab it from https://github.com/munki/munki-pkg/blob/main/munkipkg, install, and retry."
    exit 2
fi

# hash: the sha256 of the concourse tgz
# outfile: the name to output the concourse download
# package: the link to download concourse 
# version: the version for munkipkg
while getopts p:h:o:v: flag
do
    case "${flag}" in
        h) HASH=${OPTARG};;
        o) OUTFILE=${OPTARG};;
        p) PACKAGE=${OPTARG};;
        v) VERSION=${OPTARG};;
    esac
done

# download concourse
curl -L $PACKAGE -o $OUTFILE
# check the hash
bash ../autopkg/check_hash.sh $OUTFILE $HASH
if [ $? -eq 0 ]; then
    tar -xzf $OUTFILE -C concourse_worker/payload/usr/local/
    rm $OUTFILE
else
    rm $OUTFILE
    exit 3
fi

# generate the keys for the web node
ssh-keygen -t rsa -b 4096 -m PEM -f concourse_keys/session_signing_key -q -N ""
ssh-keygen -t rsa -b 4096 -m PEM -f concourse_keys/tsa_host_key -q -N ""
ssh-keygen -t rsa -b 4096 -m PEM -f concourse_keys/worker_key -q -N ""
# concourse_worker/payload/usr/local/concourse/bin/concourse generate-key -t rsa -f concourse_keys/session_signing_key
# concourse_worker/payload/usr/local/concourse/bin/concourse generate-key -t ssh -f concourse_keys/tsa_host_key
# concourse_worker/payload/usr/local/concourse/bin/concourse generate-key -t ssh -f concourse_keys/worker_key

# generate key for local macOS worker
ssh-keygen -t rsa -b 4096 -m PEM -f concourse_worker/payload/usr/local/concourse/keys/worker_id_rsa -q -N ""
# concourse_worker/payload/usr/local/concourse/bin/concourse generate-key -t ssh -f concourse_worker/payload/usr/local/concourse/keys/worker_id_rsa
# copy the host public key to the worker
cp concourse_keys/tsa_host_key.pub concourse_worker/payload/usr/local/concourse/keys/
# add it to the authorized worker keys
cat concourse_worker/payload/usr/local/concourse/keys/worker_id_rsa.pub \
 concourse_keys/worker_key.pub | tee -a concourse_keys/authorized_worker_keys

# package it up
cd concourse_worker/

# grab current build version
CURRENT_BUILD_VERSION=$(cat build-info.json | grep '"version":' | awk {'print $2'} | xargs)
# compare to what we want and change if needed
if [ "$CURRENT_BUILD_VERSION" != "$VERSION" ]; then
    sed -i '' -e "s/\s*\"version\".*/\"version\": \"${VERSION}\","/g"" build-info.json
fi

munkipkg .
