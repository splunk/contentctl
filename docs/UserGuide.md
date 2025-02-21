## Quick Start Guide
1) Use [pipx](https://pipx.pypa.io/stable/installation/) to install contentctl on your computer. 
```shell
pipx install contentctl
```

2) Create a new directory to serve as your repository for content
```shell
mkdir MyNewContentPack
```

3) Initialize the project. This will create the scaffolding for you.
```shell
contentctl init
```
At this point, you have a fully functioning app that you can build with
```shell
contentctl build
```
and install on your Splunk server! But there's not much to it just yet, so we should create new content.


4) You can create new content via a wizard on the terminal:
```shell
contentctl new --type detection
```
or 
```shell
contentctl new --type story
```
If you're not already familiar with the types of content, you should read the [splunk/security_content wiki](https://github.com/splunk/security_content/wiki/3.-Content-Structure-and-Versioning) - all of the objects we use to create ESCU are available to use in your own app. The short version is that Analytic Stories are an object that you can use to group Detections together, whether its by common data source, techniques used in a campaign, or the color you assign in your mind to each detection. There's no strict rules in your own app for this. Meanwhile, detections are the correlation searches (pre-ES8) or Event-Based Detections (post-ES8) that power your security operations.

Once you've run through the wizard and created a new piece of content, you should open it up in a text editor. There will be some fields that still need to be configured, depending on what prompts you answered. 

5) As you go about developing your app, you may have questions about whether or not the value you've supplied for a field is valid or not, or whether a field requires a single item or can take a list of items. You can check your work as you go with 
```shell
contentctl validate
```
which will surface validation errors with your configurations. 

## Risk Based Alerting
There are more details around how to utilize Risk Based Alerting in `contentctl` present in both the [v5 migration guide](contentctl_v5_migration_guide.md) and the [RBA Types](RBA_Types.md) documents.

## Shell tab-complete

Leveraging the tab completion featureset of the CLI library we're using, you can generate tab completions for `contentctl` automatically, for zsh, bash, and tcsh. For additional details, you can view the docs for the library [here.](https://brentyi.github.io/tyro/tab_completion/) 

### Zsh
If you already have a location for your ZSH tab completions, you only need to run the generation line and can skip the folder creation, configuring the rest to fit with your shell config.

```zsh
mkdir -p ~/.zfunc
contentctl --tyro-write-completion zsh ~/.zfunc/_contentctl
echo "fpath+=~/.zfunc" >> ~/.zshrc
echo "autoload -Uz compinit && compinit" >> ~/.zshrc
source ~/.zshrc
```

### Bash

```bash
completion_dir=${BASH_COMPLETION_USER_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion}/completions/
mkdir -p $completion_dir
contentctl --tyro-write-completion bash ${completion_dir}/_contentctl
```