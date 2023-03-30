import streamlit as st
import contentctl.contentctl as contentctl
import argparse, subprocess
import os
from contentctl.objects.enums import (
    DetectionTestingMode,
    PostTestBehavior,
)
from typing import Union
import threading
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)

if 'test_thread' not in st.session_state:
    st.session_state['test_thread']: Union[threading.Thread, None] = None
if 'output_dto' not in st.session_state:
    st.session_state['output_dto']: Union[DetectionTestingManagerOutputDto, None] = None

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

placeholder = st.empty()
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
        st.text(result.stdout)
        os.chdir(f"{os.getcwd()}/temp")
        placeholder.markdown("""### Initialization was successful 🙌🏽""")
    elif in_dir == True:
        placeholder.markdown("### Already Initialized 🤙🏽")
        art = contentctl.print_ascii_art()
        st.text(art)
    elif temp_exist == True:
        placeholder.markdown("### Already Initialized 🤙🏽")
        art = contentctl.print_ascii_art()
        st.text(art)
        os.chdir(f"{os.getcwd()}/temp")


except ValueError as e:
    placeholder.markdown(f"### Failed: {e} 🫥")


st.text(f"Current Working Directory: {os.getcwd()}")
st.write(os.listdir(os.getcwd()))

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

def test(args):

    st.text("starting contentctl and testing your detection")
    st.session_state['output_dto'] = DetectionTestingManagerOutputDto()
    st.session_state['test_thread'] = threading.Thread(target=contentctl.test, args=(args, st.session_state['output_dto']))
    st.text("starting test thread")
    st.session_state['test_thread'].start()
    st.text("started thread")
   
    st.write(
        "Note - even though this is a global variable the value seems to be overwritten. How to set persistent variables/values in Streamlit?"
    )
    st.write(st.session_state['test_thread'])
    import time

    time.sleep(15)
    stop_testing()

def stop_testing():
    # Make sure both of these values are not None
    if st.session_state['test_thread'] == None:
        st.text("Cannot stop testing, it is not running")
        return
    elif st.session_state['output_dto'] == None:
        st.text("Weird, testing is running but output_dto was None!")
        return

    st.text("Update the terminate value in the sync object")
    st.session_state['output_dto'].terminate = True
    st.text("Wait for the testing thread to complete...")
    st.text("*******************************")
    st.text(
        "If testing is paused and you are debugging a detection, you MUST hit CTRL-D at the prompt to complete shutdown."
    )
    st.text("*******************************")
    st.session_state['test_thread'].join()
    st.text("test thread joined!")
    st.write(st.session_state['test_thread'])


st.markdown(
        """
    When you click _**Test Detection**_ the test will begin
    # 👇🏽
    """
    )

col1, col2 = st.columns([.1,.7])

with col1:
   
    value = st.button("Test Detection")

with col2:
    # st.markdown("<div style='margin-top:130px;'></div>",unsafe_allow_html=True)
    stopTestingButton = st.button("Stop Testing")
    if stopTestingButton:
        stop_testing()

if value:
    test(args)