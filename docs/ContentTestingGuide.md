## Testing Modes
There are a number of different testing modes that control which content will be tested.  This can be controlled with the `--mode {}` option at the command line
- all - This will test all of the content in the content pack. Please note that by default only detections marked production will be tested (detections marked as deprecated or experimental, for example, will be ignored).
- selected - Detections whose relative paths are provided on the command line will be tested.  This is particularly useful if you would like to troubleshoot or update just a handful of detections and can save a significant amount of time.  For example, to test two detections use the following command `contentctl test --mode selected --detections_list detections/detection_one.yml detections/detection_two.yml`
- changes - If you have a large number of detections and use a branching workflow to create new content or update content, then this is an easy way to automatically find and test only that content automatically.  This prevents you from needing to explicitly list the subset of content to test using "selected"

## Testing Behavior
contentctl test's default mode allows it to quickly test all content with requiring user interaction.  This makes it suitable for local tests as well as CI/CD workflows.  However, users often want to troubleshoot a test if it fails.  contentctl allows you to change the tool's behavior if and/or when a test fails:
- --behavior never_pause - The default behavior.  If a test does not pass, the tool begins the next test immediately
- --behavior pause_on_failure - If a test fails, then additional information about that test, and the raw SPL of the test, is printed to the terminal.  A user may then click (or CMD+Click) the "LINK" to begin interactively debugging the failed test on the Splunk Server.  Note that the credentials for the server are printed out at the very beginning of the test.  After you have finished debugging the failure, hit "Return" in the terminal to move on to the next test. The attack_data for this test remains loaded on the server for debugging until the user moves on to the next test.
- --behavior always_pause - Similar to pause_on_failure, but this pauses after every test regardless of whether it passes or fails.  


## Advanced Usage

The following sections may not work without additional setup. The documentation of these features is not yet complete. These will be updated as the features become stabilized and ready to use by a larger audience.

### Test Dry Run

When setting up testing or when using the `test_servers` mode, you can utilize a `--plan-only` flag like
```shell
contentctl test --plan-only mode:changes --mode.target-branch develop
```
in order to generate a test plan. This can be saved and then used at a later time.

### Test Server command

Contentctl also has a `test_servers` mode that allows for the full test run against a preconfigured Splunk server, rather than the ephemeral Docker containers that `test` spins up. 