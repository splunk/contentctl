import openai
import uuid
import yaml
import content_fields as content_fields
import new_content_questions as new_content_questions
import datetime, random, sys
import streamlit as st

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


# def init_router():
#     return stx.Router({"/": Contentctl_GUI, 
#                        "/status": status,
#                        "/detections_creation": detection_creation
#                        })
# def Contentctl_GUI():
#     pass

# def detection_creation():
#     detection_page

# def status():
#     status_page


# router = init_router()
# router.show_route_view()

st.write("welcome!")


# c1, c2, c3 = st.columns(3)

# with c1:
#     st.header("Current route")
#     current_route = router.get_url_route()
#     st.write(f"{current_route}")
# with c2:
#     st.header("Set route")
#     new_route = st.text_input("route")
#     if st.button("Route now!"):
#         router.route(new_route)
# with c3:
#     st.header("Session state")
#     st.write(st.session_state)


import websocket
import threading

# Define the WebSocket server URL
WS_URL = "ws://127.0.0.1:6807"

def on_message(ws, message):
    # Handle incoming messages from the client
    print("Received message:", message)

def on_error(ws, error):
    # Handle errors from the WebSocket connection
    print("Error:", error)

def on_close(ws, close_status_code, close_reason):
    # Handle WebSocket connection close events
    print("WebSocket closed with status code:", close_status_code, "reason:", close_reason)

def on_open(ws):
    # Handle WebSocket connection open events
    print("WebSocket connected")

def start_websocket_server():
    # Start the WebSocket server in a separate thread
    websocket.enableTrace(True)
    ws = websocket.WebSocketApp(WS_URL,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)
    ws.on_open = on_open
    ws.run_forever()

threading.Thread(target=start_websocket_server).start()

