# Worker Dependencies
Concourse workers on macOS do not have the ability to create containers the way they do on linux machines.
This means we only need to install the dependencies once, unless you want to freshly install them each time.

If you want to install autopkg and munki on each run set [this](autopkg.yml?#L62) to true. Otherwise, this will skip the installation.