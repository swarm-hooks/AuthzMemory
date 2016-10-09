# AuthzMemory

###WIP

This plugin is a [docker authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/)
Which has two Goals:

1 - Vrify that each container create request sepcifies the -m flag in order to limit the maximun amount of memory used by that contaner

2 - Make sure the the daemon never overcommits memory

In ordet to devlop or just run it you have to work according to the [documentation for docker plugins](https://docs.docker.com/engine/extend/plugin_api/#plugin-discovery)

###Prerequisites:

1. Go 1.7 or later.
2. Docker 1.12 or later.
3. Git.

###Example on Ubuntu OS:

###### Build the plugin
```
git clone https://github.com/swarm-hooks/AuthzMemory
cd AuthzMemory/broker
go build
```
Executable binary file will be created. It can be copied to any directory.

###### Stop running docker service
```

sudo service docker stop
```

###### Run the plugin binary
```

./broker
```

###### Run the docker daemon and tell it to use the plugin:

```

... sudo .../dockerd --authorization-plugin=authz-broker
```

###All Set now work with the docker engine and the engine will use the plugin. 
