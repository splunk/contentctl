import streamlit as st
import contentctl.contentctl as contentctl
import argparse, subprocess
import os
from contentctl.objects.enums import (
    SecurityContentType,
    SecurityContentProduct,
    DetectionTestingMode,
    PostTestBehavior,
)
from typing import Union
import threading
from contentctl.actions.detection_testing.infrastructures.DetectionTestingInfrastructure import (
    DetectionTestingManagerOutputDto,
)

test_thread: Union[threading.Thread, None] = None
output_dto: Union[DetectionTestingManagerOutputDto, None] = None

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
        st.code(art)
    elif temp_exist == True:
        placeholder.markdown("### Already Initialized 🤙🏽")
        art = contentctl.print_ascii_art()
        st.code(art)
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
    global test_thread
    global output_dto

    st.text("starting contentctl and testing your detection")
    output_dto = DetectionTestingManagerOutputDto()
    test_thread = threading.Thread(target=contentctl.test, args=(args, output_dto))
    print("starting test thread")
    test_thread.start()
    print("started thread")
    print(
        "Note - even though this is a global variable the value seems to be overwritten. How to set persistent variables/values in Streamlit?"
    )
    import time

    time.sleep(15)
    stop_testing()


def stop_testing():
    # Make sure both of these values are not None
    if test_thread == None:
        print("Cannot stop testing, it is not running")
        return
    elif output_dto == None:
        print("Weird, testing is running but output_dto was None!")
        return

    print("Update the terminate value in the sync object")
    output_dto.terminate = True
    print("Wait for the testing thread to complete...")
    print("*******************************")
    print(
        "If testing is paused and you are debugging a detection, you MUST hit CTRL-D at the prompt to complete shutdown."
    )
    print("*******************************")
    test_thread.join()
    print("test thread joined!")


st.markdown(
    """
When you click _**Test Detection**_ the test will begin
# 👇🏽
"""
)
value = st.button("Test Detection", True)
if value:

    test(args)

stopTestingButton = st.button("Stop Testing", key="stopTestingButton")
if stopTestingButton:
    stop_testing()
