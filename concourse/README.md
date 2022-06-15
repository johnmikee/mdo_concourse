# Requirements
[hub](https://hub.github.com/)

[munkipkg](https://github.com/munki/munki-pkg/blob/main/munkipkg)

* You must enable git-lfs archives on your Git repo for this to run.

# Credentials
Before running the demo fill out the credentials.yml file with the following values:
  * github_token: [your personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) used with hub to open PR's.
  * private_key: the key used to clone the repo
  * slack: the webhook url for notifications

# Usage
To build a package to create your local machine as a concourse worker run `make demo`.
This does a few things:
  * downloads concourse for use with the worker
  * generates the required keys for the web, linux, and macOS workers
  * creates a package and installs it to configure the machine as a concourse worker
  * loads the user Launch Agent to run the worker
  * runs the docker compose file to spin up the concourse web worker as well as an additional linux worker

To clean up the keys, remove the concourse assets, and uninstall the concourse files locally run `make clean`

# Note
The example used in this repo is contrived and should not be used outside outside of demoing the functionality of concourse. 

I set out to use the [helm chart](https://github.com/concourse/concourse-chart) provided by concourse for this demo, however this does not work on M1 machines - which led to the workaround you see here. 

