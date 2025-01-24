# Time to upgrade!

There's some BIG changes with the v5.0 release of `contentctl` that we think you're going to love. Here's some details about the biggest ones and some tips to help you migrate your own content repos from using v4.x to v5!

### Strict Fields

Over the years, the YAML files we track our content in have had a lot of different fields in them. There have been varying levels of success when it comes to removing the fields that were no longer necessary, which lead to fields that didn't do anything sticking around. This is no longer the case. We've tweaked the settings on the classes to no longer allow extra fields. This will likely create a small pile of work in order to remove them. Common legacy fields within our own content were `datamodel`, `dataset`, as well as some of the fields we've removed as part of the other updates detailed below. You can run `contentctl validate` with a v5.0+ build and get the validation errors for each and every file. The errors messages will describe what the error is, such as "No Extra Fields":

![a terminal emulator screenshot of a validation error caused by extra fields](validation_error.png)

### RBA Changes

Historically, there were a lot of different fields involved in configuring the Risk Based Alerting configuration for a specific detection. And not all of them used terminology common with Splunk Enterprise Security, or any other Splunk product. We'll use the sample detection from this repository as an example: 

```YAML
tags:
...
  confidence: 80
  impact: 80
  message: An instance of $parent_process_name$ spawning $process_name$ was identified
    on endpoint $dest$ by user $user$. This behavior is indicative of suspicious loading
    of 7zip.
  observable:
  - name: user
    type: User
    role:
    - Victim
  - name: dest
    type: Hostname
    role:
    - Victim
  - name: parent_process_name
    type: Process
    role:
    - Attacker
  - name: process_name
    type: Process
    role:
    - Attacker
```

In this example, `tags.confidence` and `tags.impact` are integers between 0 and 100 that are then multiplied together and divided by 100 to produce a risk score. The `tags.message` field became the risk message. And then you have `tags.observable`- the most convoluted of the fields. This was a list of objects that became either risk objects or threat objects depending on the `role` (Victim became risk objects, Attacker became threat objects). All of the risk objects recieved the same risk score config based on the math described above. The `name` field for each of these objects was the field in your search results, and the `type` took a lot of different options and for risk objects would translate them to `system` or `user`, generally, while there were LOTS of options for threat objects.

This has been replaced with:

```YAML
rba:
  message: An instance of $parent_process_name$ spawning $process_name$ was identified
    on endpoint $dest$ by user $user$. This behavior is indicative of suspicious loading
    of 7zip.
  risk_objects:
    - field: user
      type: user
      score: 56
    - field: dest
      type: system
      score: 60
  threat_objects:
    - field: parent_process_name
      type: parent_process_name
    - field: process_name
      type: process_name
tags:
...
```
We have shifted the RBA config out of the `tags` object, and re-oriented it around the actual in-product usage. The `rba.message` field is a direct replacement for the old `tags.message` field. Risk object config is now much more obvious. `rba.risk_objects` takes a list of risk objects that consist of a `field` (the field from your search), `type` (user, system, or other, as defined in Enterprise Security), and a `score` - an integer between 0 and 100. Each risk object can now have their own independent risk score, as detailed in the above snippet. Finally, the threat object config is similarly obvious. `rba.threat_objects` takes a list of objects consisting of a `field` (the field in your search) and `type` (a selection of fields that can be seen [here](https://github.com/splunk/contentctl/blob/0ce5a79d49606609cce55e66708e015abc1257d0/contentctl/objects/rba.py#L17)). These fields are now also only required AND only allowed when the detection recieves a risk-related configuration via its deployment. So, your Hunting searches that power dashboards or your Correlation searches that create risk notables, but don't create more risk on their own- none of those require RBA configs, and `contentctl` will give you an error if they do.

Depending on how much content you have to migrate, you may consider writing some quick scripts or a notebook that will create the new RBA objects based on your existing configuration. If you go this route, we found great success with [ruamel.yaml](https://pypi.org/project/ruamel.yaml/) as opposed to PyYAML for the sake of preserving the existing order of fields in your YAMLs. _Technically_, the field order doesn't matter when the objects are parsed and read in, but we have found that the consistency of order of fields helps reviewers identify changes, and keeps diffs easy to understand.

### Managed Lookup Filenames

Depending on where your Splunk deployment lives (SplunkCloud's Victoria Experience, Classic Experience, or in your own datacenter, or your own public cloud tenant), you may have experienced some significant pains with deploying lookups as part of your app. If you're not already aware of this odd behavior, you can read more about it [here](https://docs.splunk.com/Documentation/SplunkCloud/9.3.2408/Admin/PrivateApps#Manage_lookups_in_Splunk_Cloud_Platform). Essentially, depending on what your Splunk deployment looks like, updating an app that has changes to lookup files may cause those files to be entirely ignored, with the previously used versions staying in use.

We've come up with a solution for this that should generally work for folks, no matter their deployment, that will allow you to use new lookups when you update an app without manually editing them. CSV Lookups in `contentctl` built apps now have a datestamp added to the end of the filename automatically, as derived from the date in the lookup file. This means updating an app adds a new file instead of one that would be ignored during the update process. The lookup definition that gets written to `transforms.conf` also gets this new filename. Our searches leverage the lookup definitions instead of the raw filenames, so when a new version of a lookup appears, it will seamlessly be used in favor of the old one. There are some changes to the lookup YAML files to support this, which will also throw errors (likely, the first errors you'll see as part of migration). You can review the configs used in ESCU for these files [here](https://github.com/splunk/security_content/tree/develop/lookups) if you'd like to see how we're using some of the fields.
