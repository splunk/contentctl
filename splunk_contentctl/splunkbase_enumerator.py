import requests
import json
import time
import xml.etree.ElementTree 
import threading
import queue
URL_TEMPLATE = "https://splunkbase.splunk.com/api/v2/apps/?order=popular&offset={offset}&archive={archive}&product=all&limit={limit}"
ENRICH_TEMPLATE = "https://splunkbase.splunk.com/api/apps/entriesbyid/{app_id}/"
LIMIT = 99


def launch_threads(func, args):
    collection_queue = queue.Queue()
    threads = []
    for arg in args:
        t = threading.Thread(target=func, args=(arg, collection_queue))
        t.start()
        #time.sleep(.1)
        threads.append(t)
    for thread in threads:
        thread.join()
    return collection_queue

    



def enrich_app(app_id):
    formatted_query = ENRICH_TEMPLATE.format(app_id=app_id)
    res = requests.get(formatted_query) 
    content = res.content
    #get all the href fields
    xml_root = xml.etree.ElementTree.fromstring(content)
    elements_with_href = [xml_root] if 'href' in xml_root.attrib else []
    elements_with_href.extend(xml_root.findall('.//*[@href]'))
    return [elem.attrib["href"].replace(formatted_query,"") for elem in elements_with_href]


def get_basic_app_stats():
    formatted_query = URL_TEMPLATE.format(offset=0, archive="false", limit=0)
    #print(formatted_query)
    res = requests.get(formatted_query) 
    #print(res.content)
    json_content = json.loads(res.content)
    return json_content['total']

def get_all_info(offset, collection_queue):
    
    formatted_query = URL_TEMPLATE.format(offset=offset, archive="false", limit=LIMIT)    
    #print(formatted_query)
    res = requests.get(formatted_query)
    json_content = json.loads(res.content)
    collection_queue.put(json_content['results'])
        

def process_result(result):
    versions = enrich_app(result['app_id'])
    result['versions'] = sorted(versions)
    return result

def complex():
    number_of_apps = get_basic_app_stats()
    print(f"We will need to fetch info about [{number_of_apps}] apps")
    all_results = launch_threads(get_all_info, list(range(0,number_of_apps, LIMIT)))
    all_results_list = []
    while not all_results.empty():
        all_results_list += all_results.get(block=False)




    all_results_list.sort(key=lambda l:l['id'])
    with open('all_results.json', 'w') as all_results_file:
        json.dump(all_results_list, all_results_file)

    import sys

    ids = set()
    print(len(all_results_list))
    for entry in all_results_list:
        
        if entry['id'] in ids:
            print(f"duplicate id for {entry['id']}")
        ids.add(entry['id'])

    print(len(ids))

    import sys
    sys.exit(1)
    result_dict = {}
    for ind,result in enumerate(all_results):
        print(f"{ind} of {len(all_results)}")
        result_dict[result['id']] = process_result(result)

    with open("all_of_splunkbase.json","w") as splunkbase:
        json.dump(result_dict, splunkbase)


DEFAULT_LIMIT = 100
TARGET_URL = "https://splunkbase.splunk.com/api/v1/app/?include=releases&limit={limit}&offset={offset}&order={order}"
def simple(limit:int=DEFAULT_LIMIT, order:str="latest", include_archived:bool=False)->list[dict]:
    offset = 0
    all_apps = []
    
    while True:
        print(f"Checking offset {offset}")
        request_url = TARGET_URL.format(limit=limit, offset = offset, order = order)
        req = requests.get(request_url)
        content = req.content
        json_obj = json.loads(content)
        results = json_obj['results']
        total = json_obj['total']
        
        for result in results:
            if result['is_archived'] and include_archived == False:
                #Don't add this to the list
                continue
            else:
                app_obj = {'uid': result['uid'], 'appid': result['appid'], 'title': result['title'], 'description': result['description'], 'releases': [r['title'] for r in result['releases']]} 
                all_apps.append(app_obj)


        #Do another round. We check the return every time because
        #a new app COULD be created and added while we're checking
        if offset > total:
            break
        else:
            offset += limit

    #Sort all of the apps by title (human readable name)
    all_apps = sorted(all_apps, key=lambda a: a['title'])
    print(f"Total apps in Splunklbase : {total}")
    print(f"Enumerated Splunkbase apps: {len(all_apps)}")
    print(f"Delta between all and enum: {total - len(all_apps)}")

    with open("scratch.json", "w") as app_data:
        json.dump(all_apps, app_data, indent=3) 
    return all_apps

'''
all_apps = simple()
with open("scratch.json", "w") as app_data:
    json.dump(all_apps, app_data, indent=3)
'''

