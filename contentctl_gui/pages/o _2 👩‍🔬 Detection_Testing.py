import streamlit as st
import time, os, pandas as pd
import contentctl.contentctl as contentctl
import argparse, subprocess
from contentctl.objects.enums import (
    DetectionTestingMode,
    PostTestBehavior,
)
from typing import Union
import threading, queue
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)
from contentctl.input.director import update_queue as module1_queue
from contentctl.helper.utils import update_queue_downloads as module2_queue
from contentctl.actions.detection_testing.views.DetectionTestingViewWeb import container_data as module3_queue

st.set_page_config(
    page_title="Splunk Content Creation",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)
hide_streamlit_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

if 'test_thread' not in st.session_state:
    st.session_state['test_thread']: Union[threading.Thread, None] = None
if 'output_dto' not in st.session_state:
    st.session_state['output_dto']: Union[DetectionTestingManagerOutputDto, None] = None
if 'cwd' not in st.session_state:
    st.session_state['cwd'] = None



placeholder = st.empty()
result_placeholder = st.empty()
placeholder.markdown("""#### Contentctl initializing in temp folder""")
try:
    cwd = os.getcwd()
    files = os.listdir(cwd)
    current_folder = os.path.basename(cwd)
    in_dir = False
    temp_exist = False
    if current_folder == "temp":
        in_dir = True
    else:
        for file in files:
            if file == "temp":
                temp_exist = True
                break
            else:
                temp_exist = False

    if temp_exist == False and in_dir == False:
        subprocess.run("mkdir temp", shell=True, capture_output=True, text=True)
        result = subprocess.run(
            "cd temp && contentctl init", shell=True, capture_output=True, text=True
        )
        result_placeholder.text(result.stdout)
        os.chdir(f"{os.getcwd()}/temp")
        st.session_state['cwd'] = os.getcwd()
        placeholder.markdown("""### Initialization was successful 🙌🏽""")
    elif in_dir == True:
        placeholder.markdown("### Already Initialized 🤙🏽")
        art = contentctl.print_ascii_art()
        result_placeholder.text(art)
        st.session_state['cwd'] = os.getcwd()
    elif temp_exist == True:
        placeholder.markdown("### Already Initialized 🤙🏽")
        art = contentctl.print_ascii_art()
        result_placeholder.text(art)
        os.chdir(f"{os.getcwd()}/temp")
        st.session_state['cwd'] = os.getcwd()
    time.sleep(3)
    result_placeholder.empty()


except ValueError as e:
    placeholder.markdown(f"### Failed: {e} 🫥")


st.success(f"Current Working Directory: {st.session_state['cwd']}")
#st.write(os.listdir(st.session_state['cwd']))

parser = argparse.ArgumentParser()
parser.add_argument("--path", default=".", help="Path to directory")
parser.add_argument(
    "--mode",
    required=False,
    default=DetectionTestingMode.all.name,
    type=str,
    choices=DetectionTestingMode._member_names_,
    help="Controls which detections to test.",
)
parser.add_argument(
    "--behavior",
    required=False,
    default=PostTestBehavior.always_pause.name,
    type=str,
    choices=PostTestBehavior._member_names_,
    help="Controls what to do when a test completes",
)
parser.add_argument(
    "-d",
    "--detections_list",
    required=False,
    nargs="+",
    type=str,
    help="An explicit list "
    "of detections to test. Their paths should be relative to the app path.",
)
parser.add_argument("--unattended", action=argparse.BooleanOptionalAction)
parser.set_defaults(func=contentctl.test)

args = parser.parse_args()

validation_text = st.empty()
pbarTitle = st.empty()
download_container = st.empty()
instance_placeholder = st.empty()

# Define a callback function to handle updates
def handle_validation_update(update_value, update_dl_value, pbar):
        with validation_text.container():
            st.markdown(
            """
                ---
                ### Validating 🤖
                ---
            """
            )
            for update in update_value:
                st.write(f"{str(update)}\n")
            st.markdown(
            """
                ---
                ### Validation Completed 🤖
                ---
            """
            )


def handle_download_update(update_value, update_dl_value, pbar, pbarTitle):
    with download_container.container():
        if pbar != None:
            status = "" 
        if update_dl_value['status'] == 1:
            status = "[PREVIOUSLY CACHED] "
        else:
            status = "Downloading "
        pbarTitle.markdown("### Setting up environment... 🌎")
        pbar.progress(int(update_dl_value['update']), text=f"{status} {update_dl_value['path']} ...{int(update_dl_value['update'])}%")


def handle_container_update(update_container_value):
    instance_list = list(update_container_value['currentTestingQueue'].keys())
    instance_name = instance_list[0]
    test = update_container_value['currentTestingQueue'][instance_name]["name"]
    search = update_container_value['currentTestingQueue'][instance_name]["search"]
    time = update_container_value['currentTestingQueue'][instance_name]["time"]
    complete = update_container_value['percent_complete']
    data = {'Instance Name': str(instance_name),'Current Test': str(test),'Search': str(search),'Time': str(time),'Complete': str(complete)}
    columns = ['Instance Name', 'Current Test', 'Search', 'Time', 'Complete']
    df = pd.DataFrame(data,index=[0],columns=columns)
    instance_placeholder.table(df)


def test(args, dl_container, pbarTitle):
    st.success("Testing your detection!", icon="✅")
    st.session_state['output_dto'] = DetectionTestingManagerOutputDto()
    st.session_state['test_thread']= threading.Thread(target=contentctl.test, args=(args, st.session_state['output_dto']))
    st.session_state['test_thread'].start()
    # Check for updates while the worker thread is running
    update_value = []
    update_dl_value = {}
    update_container_value = {}
    pbar = dl_container
    timeout = 30
    # Process updates from module1 queue
    module1_empty = True
    while module1_empty:
        try:
            update_value.append(module1_queue.get(block=True, timeout=3))
            handle_validation_update(update_value, update_dl_value, pbar)
        except queue.Empty:
            module1_empty = False
            time.sleep(2)
            validation_text.success(
            """
                ---
                #### Validation Completed 🤖
                ---
            """
            )
            time.sleep(1)
            validation_text.empty()
    # Process updates from module2 queue
    module2_empty = True
    while module2_empty:
        try:
            update_dl_value.update(module2_queue.get(block=True, timeout=timeout))
            if update_dl_value['status'] == 1:
                timeout = 1
            handle_download_update(update_value, update_dl_value, pbar, pbarTitle)
        except queue.Empty:
            module2_empty = False
            pbarTitle.success(""" 
                               --- 
                               #### Environment Setup Successfully! 🌎
                               ---
                               """)
            time.sleep(2)
            pbarTitle.empty()
            pbar.empty()
    # Process updates from module3 queue
    module3_empty = True
    while module3_empty:
        try:
            update_container_value.update(module3_queue.get(block=True, timeout=3))
            handle_container_update(update_container_value)
        except queue.Empty:
            module3_empty = False
    # stop_testing()

def stop_testing():
    # Make sure both of these values are not None
    if st.session_state['test_thread'] == None:
        st.text("Cannot stop testing, it is not running")
        return
    elif st.session_state['output_dto'] == None:
        st.text("Weird, testing is running but output_dto was None!")
        return
    #stop the instance from sending data from webview   
    # st.text("Update the terminate value in the sync object")
    st.session_state['output_dto'].terminate = True
    time.sleep(1)
    st.session_state['test_thread'].join()
    stop_ph = st.empty()
    stop_ph.warning(f"Testing has stopped!", icon="🛑")
    time.sleep(3)
    stop_ph.empty()
    st.stop() 

with st.sidebar:
    #get current working directory
    cwd = st.session_state['cwd']
    options = os.listdir(f"{cwd}")
    for file in options:
        if file == "detections":
            options = os.listdir(f"{os.getcwd()}/{file}")
            st.selectbox("select a detection", options)
    col1, col2 = st.columns([.5,.7])

    with col1:
    
        value = st.button("Start Test")

    with col2:
        # st.markdown("<div style='margin-top:130px;'></div>",unsafe_allow_html=True)
        stopTestingButton = st.button("Stop Test")
        if stopTestingButton:
            stop_testing()

    if value:
        test(args, download_container, pbarTitle)
    
