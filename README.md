# AuthzMemory

###WIP

This plugin is a [docker authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/)
Which has two Goals:

1 - Vrify that each container create request sepcifies the -m flag in order to limit the maximun amount of memory used by that contaner

2 - Make sure the the daemon never overcommits memory

In ordet to devlop or just run it you have to work according to the [documentation for docker plugins](https://docs.docker.com/engine/extend/plugin_api/#plugin-discovery):

###Example on Ubuntu VM:

###### Stop running docker service
```

sudo service docker stop
```

###### Run the plugin binary
from

```

.../github.com/AuthzMemory/broker
```

run 
```

./broker
```

###### Run the docker daemon and tell it to use the plugin:

```

... sudo .../dockerd --authorization-plugin=authz-broker
```

###All Set now work with the docker engine and the engine will use the plugin. 
