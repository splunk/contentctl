
import streamlit as st
import random, os
from PIL import Image

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


if 'init' not in st.session_state:
    st.session_state['init'] = False
if 'parent_dir' not in st.session_state:
    st.session_state['parent_dir'] = ""


cwd = os.getcwd()
if cwd != st.session_state['parent_dir'] and st.session_state['init'] == True:
    os.chdir(st.session_state['parent_dir'])
else:
    st.session_state['init'] = True
    st.session_state['parent_dir'] = cwd

st.markdown(
        """

        #### ContentCtl GUI is an open-source webapp built specifically for creating security content.
        #### **👈🏽 Click the 🕵🏽 Detection Creation on the left** to create your detection

    """
    )

col1, col2, col3 = st.columns([.2,.5,.2])
    
with col1:
    pass

with col2:
    st.markdown(
        """
        ### Want to learn more?

        - Check out [Splunk ContentCtl](https://github.com/splunk/contentctl)
        - Jump into our [documentation](https://github.com/splunk/contentctl/wiki)
        - Having issues? Sumbit a [new issue
          ](https://github.com/splunk/contentctl/issues)
        """ )
with col3:
    pass


col4, col5, col6 = st.columns([.2,.6,.2])

with col5:
    image = Image.open('contentctl_logo_black.png')
    motds = ["Make content happen! 😎","The best content! 🥰","You are the content! 🤓","Content of the day! 🍻","What content?! 🔥"]
    st.image(image, width=300)
    st.markdown(f"""## {motds[random.randint(0,4)]}""")