# About

Helot is a cluster command and control application. It describes and utilizes a lightweight event protocol using [Serf](http://www.serfdom.io/) to start, stop, restart, upgrade and downgrade applications within a serf connected cluster.

# Protocol

## Serf Agents

Nodes appear "online" when the serf agent is started on the host.

### Application Nodes

When an application host comes online a tag with the key "apps" should be provided with a comma separated list of application names.

    apps=website,webapi

An example serf command for an application node would be:

    $ serf agent -event-handler=... -tag=apps=website,webapi -discover=deploy

Additionally, application tags should be set that include the version and status of the application.

    $ serf agent -event-handler=... -tag=apps=website,webapi -discover=deploy -tag=website=1.0.0,running -tag=webapi=1.1.0,stopped

## Events

### Payloads

All events support a key/value pair payload. These payloads follow the following BNF:

    <key> ::= <a-z0-9->
    <value ::= <a-z0-9=-,>
    <pair> ::= <key> "=" <value>
    <payload> ::= <pair> | <pair> " " <payload>

### Deploy

Deploy events are published by deploy manager nodes. They are specific to applications as the string for a deploy event is the application name with the string "-deploy" appended. Example events include:

1. website-deploy
2. webapi-deploy

Deploy events also contain payloads in the form of key value pairs. Although the payload is often specific to the event handler associated with the deploy event, there are several common attributes.

 * version=x.y.z
 * node
 * even
 * odd

The `version` attribute is used to determine what version the application must upgrade to. The `node`, `odd` and `even` attributes are used identify single nodes for the deploy or to do 50/50 deploys.

An example deploy message would be

    website-deploy 'node=server1.us.foo version=1.1.0'

### Start

Start events are published by deploy manager nodes to be consumed by application nodes. They are used to direct a given application node to start a given application.

1. website-start
2. webapi-start

They payload for the event is a single node attribute.

    $ website-start 'node=server1.us.foo'

### Stop

Stop events are published by deploy manager nodes to be consumed by application nodes. They are used to direct a given application node to stop a given application.

1. website-stop
2. webapi-stop

They payload for the event is a single node attribute.

    $ website-stop 'node=server1.us.foo'

### Restart

Restart events are published by deploy manager nodes to be consumed by application nodes. They are used to direct a given application node to restart a given application.

1. website-restart
2. webapi-restart

They payload for the event is a single node attribute.

    $ website-restart 'node=server1.us.foo'

### Status

Status events are published by application nodes.

A status event is an event that begins with an app name and ends with the string "-status". Status events must have a payload that contains a node identifier and a status string.

#### Transitioning

A status type 'transitioning' indicates that a node is in the process of upgrading or downgrading an application. The payload must contain a 'to' key with a value that is a valid semantic version string.

An example transitioning status message would be:

    webapi-status 'node=server1.us.foo status=transitioning to=1.1.0'

#### Transitioned

A status type 'transitioned' indicates that a node has completed upgrading or downgrading an application. The payload must contain a 'version' key with a value that is a valid semantic version string.

An example transitioning status message would be:

    webapi-status 'node=server1.us.foo status=transitioned version=1.1.0'

# Behaviors And Workflows

## Application Upgrade

In this workflow, one or more nodes are deployed with a working version of an application that is running and receive an upgrade message.

 1. server1.us.foo is brought online with application website v1.0.0
    * The server starts a serf agent with `serf agent -node=server1.us.foo -event-handler=./website-deploy.sh -tag=apps=website -tag=website=1.0.0,running -discover=deploy`
 1. server2.us.foo is brought online with application website v1.0.0
    * The server starts a serf agent with `serf agent -node=server2.us.foo -event-handler=./website-deploy.sh -tag=apps=website -tag=website=1.0.0,running -discover=deploy`
 1. manager1.us.foo is brought online
    * The server starts a serf agent with `serf agent -node=manager1.us.foo -event-handler=./event-publish.sh -discover=deploy`
    * The manager regularly refreshes its node list using `serf members -format=json`, updating its internal state with the nodes, their apps and their app verions.
 1. The manager receives a version update notification for the website app from CI/CD
    * This comes in the form of an HTTP request to `/api/versions?app=website&version=1.1.0`
 1. Through the manager web interface, an engineer initiates a deploy of website v1.1.0 by clicking on the "1.0.0" dropdown item of the deploy button for the server1.us.foo node.
    * This sends an event using `serf event website-deploy 'node=server1.us.foo version=1.1.0'`
 1. The server1.us.foo serf agent receives the message and relays it to the website-deploy.sh script.
    * Because the script looks for the `node` key/value pair and there is a match, the event is processed.
    * The script sends an event using `serf event website-status 'node=server1.us.foo status=transitioning to=1.1.0'`
    * The script attempts to stop the website application, upgrade it and start the application.
    * When the upgrade completes, the script sends an event using `serf event website-status 'node=server1.us.foo status=transitioned version=1.1.0'`
 1. The server2.us.foo serf agent receives the message and relays it to the website-deploy.sh script.
    * Because the script looks for the `node` key/value pair and there is not a match, the event is ignored.
 1. The manager receives status events from server1.foo.us and updates its state accordingly.
    * When the 'transitioning' status event is received, it updates the UI indicating that upgrade/downgrade actions cannot be performed.
    * When the 'transitioned' status event is received, it updates the UI indicating that upgrade/downgrade acctions can be performed again.

# Testing

To test the app, do the following:

First, ensure that the `event-publish.sh` is executable (`chmod +x event-publish.sh`), the required python libraries are installed (`pip install -r requirements.txt`) and serf is installed.

Start the web application:

    $ python ./app.py

Start an agent using the following command:

    $ serf agent -log-level=debug -event-handler=./event-publish.sh -tag=apps=website,webapi -tag=website=1.0.0,running -discover=deploy

When the agent starts, it should immediately publish a `member-join` event to the web application through the `event-publish.sh` script.

Open a browser to http://localhost:9999/ and make note of the single node with two apps (website and webapi). One will have a version of ?.?.? and the other 1.0.0.

Make a request to the versions API resource to set known versions of the apps:

    curl "http://localhost:9999/api/versions?app=website&version=1.0.0"
    curl "http://localhost:9999/api/versions?app=webapi&version=1.0.0"
    curl "http://localhost:9999/api/versions?app=webapi&version=1.0.1"
    curl "http://localhost:9999/api/versions?app=webapi&version=1.1.0"

Refresh the root page and note that the website app bar is green indicating that the installed version is the latest version available.

Make a request to the versions API resource to add an upgradable version of website:

    curl "http://localhost:9999/api/versions?app=website&version=1.1.0"

Refresh the root page and note that the website bar is now yellow, indicating that it is not running the latest version. There should appear an upgrade button with the 1.1.0 version available.

Make a request to the versions API resource to add an downgradable version of website:

    curl "http://localhost:9999/api/versions?app=website&version=0.9.0"

Refresh the root page and observe that a downgrade button with the 0.9.0 version is available.

Through the `serf` command, set the website tag for the node.

    $ serf tags -set website=1.1.0,running

Refresh the root page and note that the website app bar is green indicating that the installed version is the latest version available and the upgrade button is no longer available.

## Simulating App Upgrades

First start the app.

    $ python2.7 ./app.py

In a separate terminal, start the agent.

    $ serf agent -log-level=debug -event-handler=./event-publish.sh -tag=apps=website -tag=website=1.0.0,running -discover=deploy

Create a new version of the website app.

    $ curl "http://localhost:9999/api/versions?app=website&version=1.0.0"
    $ curl "http://localhost:9999/api/versions?app=website&version=1.1.0"

In a browser, go to `http://localhost:9999/` and click the deploy button for the app to start a deploy for 1.1.0. This will send the deploy event and payload, but isn't received by anything in this demo.

In a separate terminal, send the following status command indicating that the transition was received and is starting:

    $ serf event website-status 'node=eirena status=transitioning to=1.1.0'

Back in the browser, refresh the "/" page and see that the website app in the node is now transitioning.

Then, send the following status command indicating that the transition is complete:

    $ serf event website-status 'node=eirena status=transitioned version=1.1.0'

The simulated app will also update the tag that includes the version information.

    $ serf tags -set website=1.1.0,running

Back in the browser, refresh the "/" page and see that the website app in the node is now on version 1.1.0 and is green with no upgrade buttons available.

# TODO

 * Add info/warning/danger colors to nodes based on node status.
 * Add info/warning/danger colors to apps based on app status.
 * Apply consistent sort order to node list.

# License

Copyright (c) 2014 Nick Gerakines <nick@gerakines.net> and Chris Antenesse <chris@antenesse.net>

This project and its contents are open source under the MIT license.
