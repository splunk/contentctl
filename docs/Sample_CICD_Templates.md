## Sample CI/CD Templates

Not only does `contentctl` work as a good tool for running on your workstation, but you can use it in CI/CD pipelines to verify your content, and move that work off of your computer. The examples below are picked from the [splunk/security_content](https://github.com/splunk/security_content) repo where STRT builds ESCU. Some references to `DA-ESS-ContentUpdate-latest.tar.gz` exist but should be replaced with the name of your content pack. All of these examples are for GitHub Actions, but you can use them as inspiration for other CI/CD platforms.


### Build

```YAML
name: build
on:
  pull_request:
    types: [opened, reopened, synchronize]
  push:
    branches:
      - develop
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Check out the repository code
        uses: actions/checkout@v4
       
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          architecture: 'x64'
          
      - name: Install Python Dependencies and ContentCTL and Atomic Red Team
        run: |
          pip install contentctl==5.0.0
          git clone --depth=1 --single-branch --branch=master https://github.com/redcanaryco/atomic-red-team.git external_repos/atomic-red-team
          git clone --depth=1 --single-branch --branch=master https://github.com/mitre/cti external_repos/cti
      
      - name: Running build with enrichments
        run: |
          contentctl build --enrichments
          mkdir artifacts
          mv dist/DA-ESS-ContentUpdate-latest.tar.gz artifacts/

      - name: store_artifacts
        uses: actions/upload-artifact@v4
        with:
          name: content-latest
          path: |
            artifacts/DA-ESS-ContentUpdate-latest.tar.gz
```
This job is relatively simple and we recommend running often (every commit to a PR is a great idea). `contentctl build` runs all of the same validations that `contentctl validate` does, plus more, and it produces an app that can be fetched out of the pipeline and loaded into a Splunk environment of your choice for manual testing. 

### Testing

```YAML
name: unit-testing
on:
  pull_request:
    types: [opened, reopened, synchronize]
jobs:
  unit-testing:
    runs-on: ubuntu-latest
    if: "!contains(github.ref, 'refs/tags/')" #don't run on tags - future steps won't run either since they depend on this job
    steps:
        #For fork PRs, always check out security_content and the PR target in security content!
        - name: Check out the repository code
          uses: actions/checkout@v4
          with:
            repository: 'splunk/security_content' #this should be the TARGET repo of the PR. we hardcode it for now
            ref: ${{ github.base_ref }}
          

        - uses: actions/setup-python@v5
          with:
            python-version: '3.11' #Available versions here - https://github.com/actions/python-versions/releases  easy to change/make a matrix/use pypy
            architecture: 'x64' # optional x64 or x86. Defaults to x64 if not specified

        - name: Install Python Dependencies and ContentCTL
          run: |
            python -m pip install --upgrade pip
            pip install contentctl==5.0.0
           
        # Running contentctl test with a few arguments, before running the command make sure you checkout into the current branch of the pull request. This step only performs unit testing on all the changes against the target-branch. In most cases this target branch will be develop
        # Make sure we check out the PR, even if it actually lives in a fork
        # Instructions for pulling a PR were taken from: 
        # https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/checking-out-pull-requests-locally
        - name: Run ContentCTL test for changes against target branch
          run: |
            
            echo "Current Branch (Head Ref): ${{ github.head_ref }}"
            echo "Target Branch (Base Ref): ${{ github.base_ref }}"
            git pull > /dev/null 2>&1
            #We checkout into a new branch - new_branch_for_testing to avoid name collisions with develop incase the forked PR is from develop
            git fetch origin pull/${{ github.event.pull_request.number }}/head:new_branch_for_testing
            #We must specifically get the PR's target branch from security_content, not the one that resides in the fork PR's forked repo           
            git switch new_branch_for_testing
            contentctl test --disable-tqdm --no-enable-integration-testing --container-settings.num-containers 2 --post-test-behavior never_pause mode:changes --mode.target-branch ${{ github.base_ref }}
            echo "contentctl test - COMPLETED"
          continue-on-error: true

        # Store test_results/summary.yml and dist/DA-ESS-ContentUpdate-latest.tar.gz to job artifact-test_summary_results.zip
        - name: store_artifacts
          uses: actions/upload-artifact@v4
          with:
            name: test_summary_results
            path: |
              test_results/summary.yml
              dist/DA-ESS-ContentUpdate-latest.tar.gz
          continue-on-error: true

        # Print entire result summary so that the users can view it in the Github Actions logs 
        - name: Print entire test_results/summary.yml
          run: cat test_results/summary.yml
          continue-on-error: true

        # Run a simple custom script created to pretty print results in a markdown friendly format in Github Actions Summary
        - name: Check the test_results/summary.yml for pass/fail.
          run: |       
            echo "This job will fail if there are failures in unit-testing"  
            python .github/workflows/format_test_results.py >> $GITHUB_STEP_SUMMARY
            echo "The Unit testing is completed. See details in the unit-testing job summary UI "
```

The Testing workflow again has some things that are particular to the setup required for [splunk/security_content](https://github.com/splunk/security_content). Notably, the repository being checked out is hardcoded and should be updated to your repo. There is some additional behavior present related to our repository recieving PRs from forks and ensuring the right jobs are run in the right environment that are also potentially not necessary for your own private repository. Also, there are still hardcoded references to `DA-ESS-ContentUpdate-latest.tar.gz` that should be updated. Additionally, this job relies on [an additional script](https://github.com/splunk/security_content/blob/develop/.github/workflows/format_test_results.py) in its last step to format the results nicely for Github Actions. 