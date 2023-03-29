import streamlit as st
import requests
import websocket, json

# Define the WebSocket server URL
WS_URL = "ws://127.0.0.1:6807"

# Define a function to handle incoming WebSocket messages
def on_message(message):
    # Parse the message as JSON
    data = json.loads(message)

    # Do something with the data
    st.write(data)

# Connect to the WebSocket server
ws = websocket.WebSocketApp(WS_URL, on_message=on_message)
ws.run_forever()

value = st.experimental_get_query_params()
st.write("say something!")
st.write(value)


# # Define the HTTP endpoint URL
# URL = "http://localhost:7999/data"

# # Make a GET request to the endpoint
# response = requests.get(URL)

# # Check if the request was successful
# if response.status_code == 200:
#     # Extract the data from the response
#     data = response.text

#     # Display the data in the Streamlit app
#     st.write(data, unsafe_allow_html=True)
# else:
#     st.error("Failed to retrieve data from HTTP endpoint")