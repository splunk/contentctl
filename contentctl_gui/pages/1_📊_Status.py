import streamlit as st
import contentctl.contentctl
import argparse, subprocess
import os
print(os.getcwd())

# subprocess.Popen("mkdir temp",)

parser = argparse.ArgumentParser()
parser.add_argument("--path", default=".", help="Path to directory")

args = parser.parse_args()

def start(args):
    contentctl.start(args)


st.button("start", on_click=start(args))

