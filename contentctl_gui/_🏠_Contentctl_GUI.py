
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

st.markdown(
        """

        #### ContentCtl GUI is an open-source webapp built specifically for creating security content.
        ### **👈 Click the 🕵🏽 Detection Creation on the left** to create your detection

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
          ](https://github.com/splunk/contentctl/issues))
        """ )
with col3:
    pass


