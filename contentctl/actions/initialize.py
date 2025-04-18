import os
import pathlib
import shutil

from contentctl.objects.baseline import Baseline
from contentctl.objects.config import test
from contentctl.objects.dashboard import Dashboard
from contentctl.objects.data_source import DataSource
from contentctl.objects.deployment import Deployment
from contentctl.objects.detection import Detection
from contentctl.objects.investigation import Investigation
from contentctl.objects.lookup import Lookup
from contentctl.objects.macro import Macro
from contentctl.objects.playbook import Playbook
from contentctl.objects.removed_security_content_object import (
    RemovedSecurityContentObject,
)
from contentctl.objects.story import Story
from contentctl.output.yml_writer import YmlWriter


class Initialize:
    def execute(self, config: test) -> None:
        # construct a test object from the init object
        # This way we can easily populate a yml with ALL the important
        # fields for validating, building, and testing your app.

        YmlWriter.writeYmlFile(str(config.path / "contentctl.yml"), config.model_dump())

        # Create the following empty directories. Each type of content,
        # even if you don't have any of that type of content, need its own directory to exist.
        for contentType in [
            Detection,
            Playbook,
            Story,
            DataSource,
            Investigation,
            Macro,
            Lookup,
            Dashboard,
            Baseline,
            Deployment,
            RemovedSecurityContentObject,
        ]:
            contentType.containing_folder().mkdir(exist_ok=False, parents=True)

        # Some other directories that do not map directly to a piece of content also must exist

        for emptyDir in [
            "docs",
            "reporting",
            "detections/application",
            "detections/cloud",
            "detections/endpoint",
            "detections/network",
            "detections/web",
        ]:
            # Throw an error if this directory already exists
            (config.path / emptyDir).mkdir(exist_ok=False, parents=True)

        # If this is not a bare config, then populate
        # a small amount of content into the directories
        if not config.bare:
            # copy the contents of all template directories
            for templateDir, targetDir in [
                ("../templates/detections/", "detections"),
                ("../templates/data_sources/", "data_sources"),
                ("../templates/macros/", "macros"),
                ("../templates/stories/", "stories"),
            ]:
                source_directory = pathlib.Path(os.path.dirname(__file__)) / templateDir
                target_directory = config.path / targetDir

                # Do not throw an exception if the directory exists. In fact, it was
                # created above when the structure of the app was created.
                shutil.copytree(source_directory, target_directory, dirs_exist_ok=True)

        # The contents of app_template must ALWAYS be copied because it contains
        # several special files.
        # For now, we also copy the deployments because the ability to create custom
        # deployment files is limited with built-in functionality.
        for templateDir, targetDir in [
            ("../templates/app_template/", "app_template"),
            ("../templates/deployments/", "deployments"),
        ]:
            source_directory = pathlib.Path(os.path.dirname(__file__)) / templateDir
            target_directory = config.path / targetDir
            # Throw an exception if the target exists
            shutil.copytree(source_directory, target_directory, dirs_exist_ok=True)

        # Create a README.md file.  Note that this is the README.md for the repository, not the
        # one which will actually be packaged into the app. That is located in the app_template folder.
        shutil.copyfile(
            pathlib.Path(os.path.dirname(__file__)) / "../templates/README.md",
            "README.md",
        )

        print(
            f"The app '{config.app.title}' has been initialized. "
            "Please run 'contentctl new --type {detection,story}' to create new content"
        )
