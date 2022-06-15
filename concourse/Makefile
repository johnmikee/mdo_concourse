HASH="7d5f195fc19485a0894974f5da642e3b3b280365452f4d7907e85c3f0fb8ef20"
OUTFILE="concourse.tgz"
PACKAGE="https://github.com/concourse/concourse/releases/download/v7.8.0/concourse-7.8.0-darwin-amd64.tgz"
VERSION="0.0.1"

demo: pkg compose set-pipeline
	
pkg:
	./build.sh -h ${HASH} -o ${OUTFILE} -p ${PACKAGE} -v ${VERSION}
	sudo installer -pkg concourse_worker/build/concourse_worker-${VERSION}.pkg -target /

compose:
	docker-compose up --force-recreate -d
	sleep 10

set-pipeline:
	fly -t ci login -c http://localhost:8080 -u test -p test
	fly -t ci set-pipeline -p autopkg -c ../pipelines/autopkg.yml -l credentials.yml
	fly -t ci unpause-pipeline -p autopkg

clean:
	docker-compose down 
	rm -rf concourse_worker/payload/usr/local/concourse/keys/*
	rm -rf concourse_worker/payload/usr/local/concourse/bin/concourse
	rm -rf concourse_worker/payload/usr/local/concourse/fly-assets
	rm -rf concourse_keys/*
	-ps aux | grep -ie concourse | awk '{print $$2}' | sudo xargs kill -9
	launchctl unload ~/Library/LaunchAgents/com.mdo.concourse.worker.plist
	rm -f ~/Library/LaunchAgents/com.mdo.concourse.worker.plist
	sudo rm -rf /usr/local/concourse
