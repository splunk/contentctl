import streamlit as st
import openai
import uuid
import yaml
import content_fields as content_fields
import new_content_questions as new_content_questions
import datetime, random, sys

questions = new_content_questions.NewContentQuestions.get_questions_detection()
selectField = content_fields.ContentFields.get_content_fields()

# Initialization indvidually
if 'description' not in st.session_state:
    st.session_state['description'] = 'Enter description here or use OpenAI to generate.'
if 'detection_name' not in st.session_state:    
    st.session_state['detection_name'] = questions[2]['default']
if 'detection_search' not in st.session_state:    
    st.session_state['detection_search'] = questions[6]['default']
if 'prompt' not in st.session_state:    
    st.session_state['prompt'] = 'Can you expand on the description Powershell Encoded Command?'
if 'apikey' not in st.session_state:    
    st.session_state['apikey'] = ''
if 'yaml_result' not in st.session_state:    
    st.session_state['yaml_result'] = ''
if 'references' not in st.session_state:    
    st.session_state['references'] = 'https://redcanary.com/blog/threat-hunting-psexec-lateral-movement/\nhttps://attack.mitre.org/tactics/TA0008/'
if 'uuid' not in st.session_state:
    st.session_state['uuid'] = f'{str(uuid.uuid4())}'
if 'openai' not in st.session_state:
    st.session_state['openai'] = 'Can you expand on the description Powershell Encoded Command?'
if 'ai_field' not in st.session_state:
    st.session_state['ai_field'] = "description"
if 'implement' not in st.session_state:
    st.session_state['implement'] = "Explain how to implment Powershell Encoded Command" 

def proc():
    st.session_state['prompt'] = st.session_state['openai']
def getKey():
        openai.api_key = st.session_state['apikey']
def openAI():
    if st.session_state['apikey'] == "":
        return
    response = openai.Completion.create(
            model="text-davinci-003",
            prompt = st.session_state['prompt'],
            temperature=0.5,
            max_tokens=100
        )
    stripped = str(response.choices[0].text)
    if st.session_state['ai_field'] == 'description':
        st.session_state['description'] = stripped.strip()
    elif st.session_state['ai_field'] == 'search (SPL)':
        st.session_state['detection_search'] = stripped.strip()
    elif st.session_state['ai_field'] == 'how to implement':
        st.session_state['implement'] = stripped.strip()


def generateYaml():
    filename = selectField['name'] + '.yaml'
    with open(filename, 'w') as file:
        yaml.dump(selectField, file, sort_keys=False)
    print(yaml.safe_dump(selectField, sort_keys=False))


col1, col2 = st.columns([1,1],gap="large")

with col1:
    
    st.title("Splunk Content Creation")

    with st.sidebar:
        from PIL import Image
        col5, col6 = st.columns([.2,.8])
        image = Image.open('contentctl_gui/contentctl_logo_black.png')
        motds = ["Make content happen! 😎","The best content! 🥰","You are the content! 🤓","Content of the day! 🍻","What content?! 🔥"]
        with col6: 
            st.image(image, caption=motds[random.randint(0,4)], width=175)
            
            st.title("Content Settings")

            selectField['tags']['product'] = st.selectbox(questions[0]['message'],(questions[0]['choices']))

            detection_kind = st.selectbox(questions[1]['message'],(questions[1]['choices']))

            selectField['type'] = st.selectbox(questions[4]['message'],(questions[4]['choices']))

            datamodels = st.multiselect(questions[5]['message'],(questions[5]['choices']),
            help="You may select multiple data models")

            kill_chain_phases = st.multiselect(questions[8]['message'],(questions[8]['choices']),
                                            help="You may select multiple phases")

            selectField['tags']['security_domain'] = st.selectbox(questions[9]['message'],(questions[9]['choices']))

            st.text_input("Enter OpenAI API KEY", on_change=getKey ,help="Disclaimer for API Key use", key="apikey", type="password")

    selectField['id'] = st.session_state['uuid']
    selectField['version'] = 1
    selectField['date'] = datetime.date.today()
    selectField['author'] = st.text_input(questions[3]['message'], "Splunk")
    selectField['name'] =  st.text_input(questions[2]['message'], key="detection_name").replace(' ', "_")
    selectField['description'] = st.text_area("security content description", key="description")
    selectField['search'] = st.text_area(questions[6]['message'], key="detection_search")
    selectField['how_to_implement'] = st.text_area("how to implement it:", key="implement")
    selectField['known_false_positives'] =  st.text_area("known false positives:")
    ref = str(st.text_area("references:", key="references")).split('\n')
    selectField['references'] = ref
    mitre = st.text_input(questions[7]['message'],questions[7]['default']).replace(' ','').split(',')
    if st.session_state['apikey'] != "":
        st.markdown("""<hr style="height:2px;border:none;color:#fff;background-color:#fff;" /> """, unsafe_allow_html=True)    
        st.text_area("Enter question for OpenAI to auto generate response", on_change=proc, key="openai")
        st.selectbox("field for AI to generate", ('description','search (SPL)', 'how to implement'), key='ai_field')

    selectField['tags']['mitre_attack_id'] = mitre

    col3, col4 = st.columns(2)

    with col3: 
        st.button("GENERATE TEST DETECTION YAML", on_click=generateYaml)
        if st.session_state['yaml_result'] != "" or st.session_state['yaml_result'] == "None":
            st.warning(st.session_state['yaml_result'], icon="😲")
    with col4:
        if st.session_state['apikey'] != "":
            st.button("OPENAI GENERATE FIELDS", on_click=openAI)
            st.warning('Please enter API Key', icon="🫤")

with col2:
    st.write('<h1>Detection Yaml Template</h1>', unsafe_allow_html=True)
    st.code(yaml.safe_dump(selectField, sort_keys=False))
