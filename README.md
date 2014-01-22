BeRoads Workers
===============

These are the workers and the server that are deployed on the BeRoads backend.


# Meet the team !

* traffic_loader : loads traffic information from our sources
* webcams_loader : fetch images from live highway webcams
* road_watcher : watchdog for new events

# Give it a try

```
git clone
cd
pip install -r requirements
python worker_name.py
```

# Server

The server is written with Tornado and provide the push notification backend of BeRoads by pushing messages to iOS devices
through Apple Push Notification Services, Android devices via Google Cloud Messaging and web devices through WebSocket.
It also provide a kind of 'analytics panel' to the BeRoads team members.

# Workers

## traffic_loader

This worker take care of the traffic information retrieval. It rely heavily on multiprocessing and inter-process queues.
A process fetch the raw data from our sources websites and push it in a queue where our parsing process is listening.
Our parsing process read raw data from the queue, parse it and send it to the storing queue. Our storing process retrieve
json encoded data from that queue and store it in our MySQL server.


## webcams_loader

Webcams loader works like traffic_loader. A scraping process fetch data from our sources website to retrieve images urls and
push a json encoded string in a queue. A loading process obtain these strings from the queue and retrieve images.
Once they are downloaded, a processus test the images to see if they really are available (see blog post about dead webcams).

## road_watcher

Road watcher fetch events that have been stored in our MySQL server since the last update time. He then leverage the
Twitter API to tweet about these events. Events have a specific language, so do our accounts. Every tweet contains a
url that link back to our server (ie. http://beroads.com/events/2330)

Visit our website at http://beroads.com and contact us at info@beroads.com