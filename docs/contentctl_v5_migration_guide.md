# Time to upgrade!

There's some BIG changes with the v5.0 release of `contentctl` that we think you're going to love. Here's some details about the biggest ones and some tips to help you migrate your own content repos from using v4.x to v5!

### Strict Fields

Over the years, the YAML files we track our content in have had a lot of different fields in them. There have been varying levels of success when it comes to removing the fields that were no longer necessary, which lead to fields that didn't do anything sticking around. This is no longer the case. We've tweaked the settings on the classes to no longer allow extra fields. This will likely create a small pile of work in order to remove them. Common legacy fields within our own content were `datamodel`, `dataset`, as well as some of the fields we've removed as part of the other updates detailed below. You can run `contentctl validate` with a v5.0+ build and get the validation errors for each and every file. The errors messages will describe what the error is, such as "No Extra Fields"

### RBA Changes



### Managed Lookup Lifecycles

