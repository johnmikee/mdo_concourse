# mdo_concourse
This repo contains the resources used for my talk on running AutoPkg in Concourse

## [autopkg](autopkg)
Contains the autopkg [wrapper](autopkg/autopkg_tools_concourse.py), overrides, configuration, and helper tools used in the Concourse pipeline.

## [concourse](concourse)
This contains the configuration to setup a test instance of Concourse locally. See the [readme](concourse/README.md) for more details.

## [munki_repo](munki_repo)
An example munki_repo layout used to test importing applications via AutoPkg.

## [pipelines](pipelines)
There are two pipelines - a simple hello world [pipeline](pipelines/hello_world.yml) as well as the autopkg [pipeline](pipelines/autopkg.yml) used in the demo.