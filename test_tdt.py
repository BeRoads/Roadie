__author__ = 'quentinkaiser'
import requests
import json
import time
import multiprocessing

regions = ['all', 'wallonia', 'flanders', 'brussels', 'federal']
languages = ['fr', 'nl', 'en', 'de']

def crawl(url, result_queue):
    import requests
    print "Loading %s"%(url)
    page = requests.get(url)
    try:
        data = json.loads(page.content)
        result_queue.put("Loaded %d events in %d seconds"%(len(data['TrafficEvent']['item']), time.time()-t))
    except ValueError as e:
        result_queue.put("Error while loading %s : %s"%(url, e.message))


processs = []
result_queue = multiprocessing.Queue()
for region in regions:
    for language in languages:
        url = 'http://data.beroads.com/IWay/TrafficEvent/%s/%s.json'%(language, region)
        process = multiprocessing.Process(target=crawl, args=[url, result_queue])
        process.start()
        processs.append(process)

        print "Waiting for result..."

        result = result_queue.get() # waits until any of the proccess have `.put()` a result

        for process in processs: # then kill them all off
            process.terminate()

        print result

