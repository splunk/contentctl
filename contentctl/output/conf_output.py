from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from contentctl.objects.baseline import Baseline
    from contentctl.objects.dashboard import Dashboard
    from contentctl.objects.detection import Detection
    from contentctl.objects.investigation import Investigation
    from contentctl.objects.lookup import Lookup
    from contentctl.objects.macro import Macro
    from contentctl.objects.story import Story

import pathlib
import shutil
import tarfile

from contentctl.objects.config import build

# These must be imported separately because they are not just used for typing,
# they are used in isinstance (which requires the object to be imported)
from contentctl.objects.lookup import FileBackedLookup, MlModel
from contentctl.output.conf_writer import ConfWriter


class ConfOutput:
    config: build

    def __init__(self, config: build):
        self.config = config

        # Create the build directory if it does not exist
        config.getPackageDirectoryPath().parent.mkdir(parents=True, exist_ok=True)

        # Remove the app path, if it exists
        shutil.rmtree(config.getPackageDirectoryPath(), ignore_errors=True)

        # Copy all the template files into the app
        shutil.copytree(config.getAppTemplatePath(), config.getPackageDirectoryPath())

    def writeHeaders(self) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        for output_app_path in [
            "default/analyticstories.conf",
            "default/savedsearches.conf",
            "default/collections.conf",
            "default/es_investigations.conf",
            "default/macros.conf",
            "default/transforms.conf",
            "default/workflow_actions.conf",
            "default/app.conf",
            "default/content-version.conf",
        ]:
            written_files.add(
                ConfWriter.writeConfFileHeader(
                    pathlib.Path(output_app_path), self.config
                )
            )

        return written_files

        # The contents of app.manifest are not a conf file, but json.
        # DO NOT write a header for this file type, simply create the file
        with open(
            self.config.getPackageDirectoryPath() / pathlib.Path("app.manifest"), "w"
        ):
            pass

    def writeMiscellaneousAppFiles(self) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()

        written_files.add(
            ConfWriter.writeConfFile(
                pathlib.Path("default/content-version.conf"),
                "content-version.j2",
                self.config,
                [self.config.app],
            )
        )

        written_files.add(
            ConfWriter.writeManifestFile(
                pathlib.Path("app.manifest"),
                "app.manifest.j2",
                self.config,
                [self.config.app],
            )
        )

        written_files.add(ConfWriter.writeServerConf(self.config))

        written_files.add(ConfWriter.writeAppConf(self.config))

        return written_files

    # TODO (#339): we could have a discrepancy between detections tested and those delivered
    #   based on the jinja2 template
    #   {% if (detection.type == 'TTP' or detection.type == 'Anomaly' or
    #       detection.type == 'Hunting' or detection.type == 'Correlation') %}
    def writeDetections(self, objects: list[Detection]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        for output_app_path, template_name in [
            ("default/savedsearches.conf", "savedsearches_detections.j2"),
            ("default/analyticstories.conf", "analyticstories_detections.j2"),
        ]:
            written_files.add(
                ConfWriter.writeConfFile(
                    pathlib.Path(output_app_path), template_name, self.config, objects
                )
            )
        return written_files

    def writeFbds(self) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()

        # Path to the static FBD configuration file
        fbd_config_path = self.config.path / "static_configs" / "savedsearches_fbd.conf"

        if not fbd_config_path.exists():
            # If the file doesn't exist, just return empty set - no FBDs to write
            print("No FBD configuration file found; skipping FBD writing to conf.")
            return written_files
        print(f"Reading FBD configuration from {fbd_config_path}")

        # Read and parse the FBD configuration file
        fbd_stanzas = self._parse_fbd_config_file(fbd_config_path)

        if fbd_stanzas:  # Only write if there are actual stanzas
            written_files.add(
                ConfWriter.writeConfFile(
                    pathlib.Path("default/savedsearches.conf"),
                    "savedsearches_fbds.j2",
                    self.config,
                    fbd_stanzas,
                )
            )

        return written_files

    def _parse_fbd_config_file(self, file_path: pathlib.Path) -> list:
        """Parse the FBD configuration file into individual stanza objects."""
        stanzas = []
        current_stanza_lines = []

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped_line = line.strip()

                # Skip comment lines (lines starting with # after stripping whitespace)
                if stripped_line.startswith("#"):
                    continue

                # If we hit a blank line and have accumulated stanza content, finalize the current stanza
                if not stripped_line:
                    if current_stanza_lines:
                        stanza_content = "\n".join(current_stanza_lines)
                        stanza_obj = type(
                            "FbdStanza", (), {"content": stanza_content}
                        )()
                        stanzas.append(stanza_obj)
                        current_stanza_lines = []
                    continue

                # Accumulate non-empty, non-comment lines for the current stanza
                current_stanza_lines.append(line.rstrip())
        # Handle the last stanza if the file doesn't end with a blank line
        if current_stanza_lines:
            stanza_content = "\n".join(current_stanza_lines)
            stanza_obj = type("FbdStanza", (), {"content": stanza_content})()
            stanzas.append(stanza_obj)

        return stanzas

    def writeStories(self, objects: list[Story]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        written_files.add(
            ConfWriter.writeConfFile(
                pathlib.Path("default/analyticstories.conf"),
                "analyticstories_stories.j2",
                self.config,
                objects,
            )
        )
        return written_files

    def writeBaselines(self, objects: list[Baseline]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        written_files.add(
            ConfWriter.writeConfFile(
                pathlib.Path("default/savedsearches.conf"),
                "savedsearches_baselines.j2",
                self.config,
                objects,
            )
        )
        return written_files

    def writeInvestigations(self, objects: list[Investigation]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        for output_app_path, template_name in [
            ("default/savedsearches.conf", "savedsearches_investigations.j2"),
            ("default/analyticstories.conf", "analyticstories_investigations.j2"),
        ]:
            ConfWriter.writeConfFile(
                pathlib.Path(output_app_path), template_name, self.config, objects
            )

        workbench_panels: list[Investigation] = []
        for investigation in objects:
            if investigation.inputs:
                response_file_name_xml = (
                    investigation.lowercase_name + "___response_task.xml"
                )
                workbench_panels.append(investigation)
                investigation.search = investigation.search.replace(">", "&gt;")
                investigation.search = investigation.search.replace("<", "&lt;")

                ConfWriter.writeXmlFileHeader(
                    pathlib.Path(
                        f"default/data/ui/panels/workbench_panel_{response_file_name_xml}"
                    ),
                    self.config,
                )

                ConfWriter.writeXmlFile(
                    pathlib.Path(
                        f"default/data/ui/panels/workbench_panel_{response_file_name_xml}"
                    ),
                    "panel.j2",
                    self.config,
                    [investigation.search],
                )

        for output_app_path, template_name in [
            ("default/es_investigations.conf", "es_investigations_investigations.j2"),
            ("default/workflow_actions.conf", "workflow_actions.j2"),
        ]:
            written_files.add(
                ConfWriter.writeConfFile(
                    pathlib.Path(output_app_path),
                    template_name,
                    self.config,
                    workbench_panels,
                )
            )
        return written_files

    def writeLookups(self, objects: list[Lookup]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        for output_app_path, template_name in [
            ("default/collections.conf", "collections.j2"),
            ("default/transforms.conf", "transforms.j2"),
        ]:
            # DO NOT write MlModels to transforms.conf.  The enumeration of
            # those files happens in the MLTK app by enumerating the __mlspl_*
            # files in the lookups/ directory of the app
            written_files.add(
                ConfWriter.writeConfFile(
                    pathlib.Path(output_app_path),
                    template_name,
                    self.config,
                    [lookup for lookup in objects if not isinstance(lookup, MlModel)],
                )
            )

        # Get the path to the lookups folder
        lookup_folder = self.config.getPackageDirectoryPath() / "lookups"

        # Make the new folder for the lookups
        # This folder almost certainly already exists because mitre_enrichment.csv has been writtent here from the app template.
        lookup_folder.mkdir(exist_ok=True)

        # Copy each lookup into the folder
        for lookup in objects:
            # All File backed lookups, including __mlspl_ files, should be copied here,
            # even though the MLModel info was intentionally not written to the
            # transforms.conf file as noted above.
            if isinstance(lookup, FileBackedLookup):
                with (
                    open(lookup_folder / lookup.app_filename.name, "w") as output_file,
                    lookup.content_file_handle as output,
                ):
                    output_file.write(output.read())
        return written_files

    def writeMacros(self, objects: list[Macro]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        written_files.add(
            ConfWriter.writeConfFile(
                pathlib.Path("default/macros.conf"), "macros.j2", self.config, objects
            )
        )
        return written_files

    def writeDashboards(self, objects: list[Dashboard]) -> set[pathlib.Path]:
        written_files: set[pathlib.Path] = set()
        written_files.update(ConfWriter.writeDashboardFiles(self.config, objects))
        return written_files

    def packageAppTar(self) -> None:
        with tarfile.open(
            self.config.getPackageFilePath(include_version=True), "w:gz"
        ) as app_archive:
            app_archive.add(
                self.config.getPackageDirectoryPath(),
                arcname=self.config.getPackageDirectoryPath().name,
            )

        shutil.copy2(
            self.config.getPackageFilePath(include_version=True),
            self.config.getPackageFilePath(include_version=False),
            follow_symlinks=False,
        )

    def packageAppSlim(self) -> None:
        raise Exception(
            "Packaging with splunk-packaging-toolkit not currently supported as slim only supports Python 3.7. "
            "Please raise an issue in the contentctl GitHub if you encounter this exception."
        )
        try:
            import logging

            import slim
            from slim.utils import SlimLogger

            # In order to avoid significant output, only emit FATAL log messages
            SlimLogger.set_level(logging.ERROR)
            try:
                slim.package(
                    source=self.config.getPackageDirectoryPath(),
                    output_dir=pathlib.Path(self.config.getBuildDir()),
                )
            except SystemExit as e:
                raise Exception(f"Error building package with slim: {e!s}")

        except Exception as e:
            print(
                "Failed to import Splunk Packaging Toolkit (slim).  slim requires Python<3.10.  "
                "Packaging app with tar instead. This should still work, but appinspect may catch "
                "errors that otherwise would have been flagged by slim."
            )
            raise Exception(f"slim (splunk packaging toolkit) not installed: {e!s}")

    def packageApp(self, method: Callable[[ConfOutput], None] = packageAppTar) -> None:
        return method(self)
