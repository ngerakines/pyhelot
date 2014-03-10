#!/bin/sh

event=""
if [ "$SERF_EVENT" = "user" ]
then
  event=$SERF_USER_EVENT
else
  event=$SERF_EVENT
fi

while read line; do
	curl -vv -X POST -d "$line" "http://localhost:9999/event?event=${event}"
done

