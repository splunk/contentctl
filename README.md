
# Splunk Contentctl
![logo](docs/contentctl-logo.png)
=====


## Installation


### Using pip (Available when released)
Install contentctl using pip: 
```
pip install splunk-contentctl
```

### From Source
Make sure you have poetry installed:
```
git clone git@github.com:splunk/contentctl.git
poetry install
poetry shell
contentctl --help
```


## Usage

1. **init** - Initilialize a new repo from scratch so you can easily add your own content to a custom application. 
2. **new** - Creates new content (detection, story)
3. **validate** - Validates written content
4. **build** - Builds an application suitable for deployment on a search head using Slim, the Splunk Packaging Toolkit
5. **deploy** - Deploy the security content pack to a Splunk Server
6. **docs** - Create documentation as Markdown
7. **reporting** - Create different reporting files such as a Mitre ATT&CK overlay


