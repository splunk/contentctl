#!/usr/bin/env python
import requests
import cgi
import argparse
from bs4 import BeautifulSoup
import os
import pathlib


def get_form_details(form):
    """Returns the HTML details of a form,
    including action, method and list of form controls (inputs, etc)"""
    # get the form action (requested URL)
    action = form.attrs.get('action').lower()
    # get the form method (POST, GET, DELETE, etc)
    # if not specified, GET is the default in HTML
    method = form.attrs.get('method', 'get').lower()
    # get all form inputs
    data = {}
    for input_tag in form.find_all('input'):
        # get name attribute
        input_name = input_tag.attrs.get('name')
        # get the default value of that input tag
        input_value = input_tag.attrs.get('value', '')
        # add everything to the data object
        data[input_name] = input_value
    return action, method, data


def submit_form(session, form):
    action, method, form_data = get_form_details(form)
    if method == 'post':
        session.post(action, data=form_data)
    elif method == 'get':
        session.get(action, data=form_data)

def download_all_apps(username, password, apps:list[dict], target_directory:pathlib.Path=pathlib.Path('.')):
    session = login_and_get_splunkbase_session(username, password)
    for app in apps[0:1]:
        appid = app['appid']
        release = app['release']
        uid = app['uid']
        download_app_with_session(session, appid,uid,release,target_directory)
    for app in apps[1:]:
        appid = app['appid']
        release = app['release']
        uid = app['uid']
        download_app_with_session(session, appid,uid,release,target_directory)

def download_app_with_session(session:requests.Session, appid:str, uid:int,release:str,target_directory:pathlib.Path=pathlib.Path('.')):
    print(f'Downloading app {appid} version {release}...',end='',flush=True)

    url = f'https://splunkbase.splunk.com/app/{uid}/release/{release}/download'
    '''
    # Try requesting the download url for the release. The first request actually returns a okta intersitual page that needs to be resolved and submitted
    if first:    
        soup = BeautifulSoup(session.get(url).content, 'html.parser')
    
        # Scrape out the intersitual page and submit it
        submit_form(session, soup.find('form'))
    '''
    
    # The second request returns the package
    response = session.get(url)
    
    _, params = cgi.parse_header(response.headers.get('Content-Disposition'))
    
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)
    
    filename = f"{appid}_{uid}_{release}.tar.gz"
    full_path = os.path.join(target_directory, filename)
    
    with open(full_path, 'wb') as f:
        f.write(response.content)
    print(f'done')



def login_and_get_splunkbase_session(username, password)->requests.Session:
    print(f"Logging into Splunkbase...",end='', flush=True)
    urlauth = 'https://account.splunk.com/api/v1/okta/auth'
    session = requests.session()
    # Base auth with okta, store cookies
    auth_req = session.post(
        urlauth, json={'username': username, 'password': password}).json()
    if 'status_code' in auth_req and auth_req['status_code'] != 200:
        raise ValueError('Error authenticating, response: ',
                         auth_req['message'])
    
    #First request has to get past in interstitial. This doesn't even need to be a real app!
    #We can just use the placeholder uid=0 and release="0.0.0"
    url = 'https://splunkbase.splunk.com/app/{uid}/release/{release}/download'.format(uid=0,release="0.0.0")
    # Try requesting the download url for the release. The first request actually returns a okta intersitual 
    # page that needs to be resolved and submitted
    
    soup = BeautifulSoup(session.get(url).content, 'html.parser')
    # Scrape out the intersitual page and submit it
    submit_form(session, soup.find('form'))

    print("done")
    return session

def download(username, password, app_id, version, title=None, target_directory=pathlib.Path('.')):
    print(f'Downloading app with id {app_id} version {version}...')
    url = f'https://splunkbase.splunk.com/app/{app_id}/release/{version}/download'
    urlauth = 'https://account.splunk.com/api/v1/okta/auth'
    session = requests.session()
    # Base auth with okta, store cookies
    auth_req = session.post(
        urlauth, json={'username': username, 'password': password}).json()
    if 'status_code' in auth_req and auth_req['status_code'] != 200:
        raise ValueError('Error authenticating, response: ',
                         auth_req['message'])
    # Try requesting the download url for the release. The first request actually returns a okta intersitual page that needs to be resolved and submitted
    soup = BeautifulSoup(session.get(url).content, 'html.parser')
    # Scrape out the intersitual page and submit it
    submit_form(session, soup.find('form'))
    # The second request returns the package
    response = session.get(url)
    _, params = cgi.parse_header(response.headers.get('Content-Disposition'))
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)
    raise(Exception("implement proper file name"))
    full_path = os.path.join(target_directory, params['filename'])
    
    with open(full_path, 'wb') as f:
        print(f"Writing {params['filename']} to {target_directory}")
        f.write(response.content)
    print(f'Successfully downloaded package {full_path}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('username', help='Splunkbase username')
    parser.add_argument('password', help='Splunkbase password')
    parser.add_argument('app', help='Application to download in the format {app_id}-{version}')
    args = parser.parse_args()
    app_def = args.app.split('-')
    if len(app_def) != 2:
        raise ValueError(f'{args.app} - definition for the app to download must be in the format {{app_id}}-{{version}}')
    download(args.username, args.password, app_id=app_def[0], version=app_def[1])
