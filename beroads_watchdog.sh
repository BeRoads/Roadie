#!/bin/bash
running=`ps aux | grep webcams_loader.py | wc -l`
if [ "$running" -lt 2 ]
then
source ./dashboard/bin/activate
python webcams_loader.py -t 900 &
fi

running=`ps aux | grep traffic_loader.py | wc -l`
sleeping=`ps aux | grep defunct | wc -l` 
if [ "$running" -lt 2 ] && [ "$sleeping" -lt 2]
then
source ./dashboard/bin/activate
python traffic_loader.py -t 900 &
fi

running=`ps aux | grep road_watcher.py | wc -l`
if [ "$running" -lt 2 ]
then
source ./dashboard/bin/activate
python road_watcher.py -t 900 &
fi

running=`ps aux | grep main.py | wc -l`
if [ "$running" -lt 2 ]
then
source ./dashboard/bin/activate
python main &
fi
