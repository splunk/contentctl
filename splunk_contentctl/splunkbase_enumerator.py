import requests
import json
import xml.etree.ElementTree 
import threading
import queue
from typing import Union
import os.path
import sys

SPLUNKBASE_APP_INFO_CACHE = "splunkbase_app_info_cache.json"
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

def get_all_app_data_from_file()->list[dict]:
    if not os.path.exists(SPLUNKBASE_APP_INFO_CACHE):
        raise(Exception(f"Could not load Splunkbase App Info Cache: {SPLUNKBASE_APP_INFO_CACHE}"))
        
    
    with open(SPLUNKBASE_APP_INFO_CACHE, "r") as info_cache_file:
        json_data = json.load(info_cache_file)
    
    return json_data
    
    


def get_all_app_data_from_splunkbase(limit:int=DEFAULT_LIMIT, order:str="latest", include_archived:bool=False, force_refresh_app_data:bool=False)->Union[list[dict],None]:
    offset = 0
    all_apps = []
    number_of_archived_apps = 0
    soft_error_string = f"Failed to reach Splunkbase API, but App Data Update is not required.  Falling back to file {SPLUNKBASE_APP_INFO_CACHE}"
    
    print("Downloading the latest application info from Splunkbase.  This may take a minute...",end='',flush=True)
    try:
        while True:
            print(".",end='',flush=True)
            request_url = TARGET_URL.format(limit=limit, offset = offset, order = order)
            req = requests.get(request_url)
            if req.status_code != 200:
                if force_refresh_app_data is True:
                    raise(Exception(f"Failed to reach Splunkbase API with the request {request_url} and App Data Update is required."))
                else:
                    print(soft_error_string)
                    return None
            content = req.content
            json_obj = json.loads(content)
            results = json_obj['results']
            total = json_obj['total']
            
            for result in results:
                if 'is_archived' in result and result['is_archived'] and include_archived == False:
                    #Don't add this to the list
                    number_of_archived_apps += 1
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
    except Exception as e:
        if force_refresh_app_data:
            raise(Exception(f"Splunkbase API Error and App Data Update is required: {str(e)}"))
        else:
            print(f"Failed to reach Splunkbase API, but App Data Update is not required.  Falling back to file {SPLUNKBASE_APP_INFO_CACHE}")
            return None

    print("done")

    #Sort all of the apps by title (human readable name)
    all_apps = sorted(all_apps, key=lambda a: a['title'])
    
    if (number_of_archived_apps + len(all_apps)) != total:
        raise(Exception(f"Total number of apps [{total}] does not equal non-archived [{len(all_apps)}] + archived [{number_of_archived_apps}] ({len(all_apps) + number_of_archived_apps})")) 
    
    print(f"Total apps found in Splunkbase : {total}")
    if include_archived is False:
        print(f"Number of archived apps ignored: {number_of_archived_apps}")

    print(f"Updating {SPLUNKBASE_APP_INFO_CACHE}...", end='', flush=True)
    with open(SPLUNKBASE_APP_INFO_CACHE, "w") as app_data:
        json.dump(all_apps, app_data, indent=3) 
    print("done")
    return all_apps


def get_all_app_data(limit:int=DEFAULT_LIMIT, order:str="latest", include_archived:bool=False, force_refresh_app_data:bool=False, force_no_splunkbase:bool=False)->list[dict]:
    
    try:
        if force_no_splunkbase is False:
            app_data = get_all_app_data_from_splunkbase(limit, order, include_archived, force_refresh_app_data)
        else:
            #Forcing us to use the file, not Splunkbase
            app_data = None
        if app_data is None:
            app_data = get_all_app_data_from_file()
            print("Splunkbase App Data loaded from file")
        
    except Exception as e:
        print(f"Failure getting Splunkbase App Data: {str(e)}.\nQuitting...")
        sys.exit(1)

    return app_data