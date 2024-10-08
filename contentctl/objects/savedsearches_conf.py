
from pathlib import Path
from typing import Any, ClassVar
import re
import tempfile
import tarfile

from pydantic import BaseModel, Field, PrivateAttr

from contentctl.objects.detection_stanza import DetectionStanza


class SavedsearchesConf(BaseModel):
    """
    A model of the savedsearches.conf file, represented as a set of stanzas

    NOTE: At present, this model only parses the detections themselves from the .conf; thing like
    baselines or response tasks are left alone currently
    """
    # The path to the conf file
    path: Path = Field(...)

    # The app label (used for pattern matching in the conf) (e.g. ESCU)
    app_label: str = Field(...)

    # A dictionary mapping rule names to a model of the corresponding stanza in the conf
    detection_stanzas: dict[str, DetectionStanza] = Field(default={}, init=False)

    # A internal flag indicating whether we are currently in the detections portion of the conf
    # during parsing
    _in_detections: bool = PrivateAttr(default=False)

    # A internal flag indicating whether we are currently in a specific section of the conf
    # during parsing
    _in_section: bool = PrivateAttr(default=False)

    # A running list of the accumulated lines identified as part of the current section
    _current_section_lines: list[str] = PrivateAttr(default=[])

    # The name of the current section
    _current_section_name: str | None = PrivateAttr(default=None)

    # The current line number as we continue to parse the file
    _current_line_no: int = PrivateAttr(default=0)

    # A format string for the path to the savedsearches.conf in the app package
    PACKAGE_CONF_PATH_FMT_STR: ClassVar[str] = "{appid}/default/savedsearches.conf"

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)
        self._parse_detection_stanzas()

    def is_section_header(self, line: str) -> bool:
        """
        Given a line, determine if the line is a section header, indicating the start of a new
        section

        :param line: a line from the conf file
        :type line: str

        :returns: a bool indicating whether the current line is a section header or not
        :rtype: bool
        """
        # Compile the pattern based on the app name
        pattern = re.compile(r"\[" + self.app_label + r" - .+ - Rule\]")
        if pattern.match(line):
            return True
        return False

    def section_start(self, line: str) -> None:
        """
        Given a line, adjust the state to track a new section

        :param line: a line from the conf file
        :type line: str
        """
        # Determine the new section name:
        new_section_name = line.strip().strip("[").strip("]")

        # Raise if we are in a section already according to the state (we cannot statr a new section
        # before ending the previous section)
        if self._in_section:
            raise Exception(
                "Attempting to start a new section w/o ending the current one; check for "
                f"parsing/serialization errors: (current section: '{self._current_section_name}', "
                f"new section: '{new_section_name}') [see line {self._current_line_no} in "
                f"{self.path}]"
            )

        # Capture the name of this section, reset the lines, and indicate that we are now in a
        # section
        self._current_section_name = new_section_name
        self._current_section_lines = [line]
        self._in_section = True

    def section_end(self) -> None:
        """
        Adjust the state end the section we were enumerating; parse the lines as a DetectionStanza
        """
        # Name should have been set during section start
        if self._current_section_name is None:
            raise Exception(
                "Name for the current section was never set; check for parsing/serialization "
                f"errors [see line {self._current_line_no} in {self.path}]."
            )
        elif self._current_section_name in self.detection_stanzas:
            # Each stanza should be unique, so the name should not already be in the dict
            raise Exception(
                f"Name '{self._current_section_name}' already in set of stanzas [see line "
                f"{self._current_line_no} in {self.path}]."
            )

        # Build the stanza model from the accumulated lines and adjust the state to end this section
        self.detection_stanzas[self._current_section_name] = DetectionStanza(
            name=self._current_section_name,
            lines=self._current_section_lines
        )
        self._in_section = False

    def _parse_detection_stanzas(self) -> None:
        """
        Open the conf file, and parse out DetectionStanza objects from the raw conf stanzas
        """
        # We don't want to parse the stanzas twice (non-atomic operation)
        if len(self.detection_stanzas) != 0:
            raise Exception(
                f"{len(self.detection_stanzas)} stanzas have already been parsed from this conf; we"
                " do not need to parse them again"
            )

        # Open the conf file and iterate over the lines
        with open(self.path, "r") as file:
            for line in file:
                self._current_line_no += 1

                # Break when we get to the end of the app detections
                if line.strip() == f"### END {self.app_label} DETECTIONS ###":
                    break
                elif self._in_detections:
                    # Check if we are in the detections portion of the conf, and then if we are in a
                    # section
                    if self._in_section:
                        # If we are w/in a section and have hit an empty line, close the section
                        if line.strip() == "":
                            self.section_end()
                        elif self.is_section_header(line):
                            # Raise if we encounter a section header w/in a section
                            raise Exception(
                                "Encountered section header while already in section (current "
                                f"section: '{self._current_section_name}') [see line "
                                f"{self._current_line_no} in {self.path}]."
                            )
                        else:
                            # Otherwise, append the line
                            self._current_section_lines.append(line)
                    elif self.is_section_header(line):
                        # If we encounter a section header while not already in a section, start a
                        # new one
                        self.section_start(line)
                    elif line.strip() != "":
                        # If we are not in a section and have encountered anything other than an
                        # empty line, something is wrong
                        raise Exception(
                            "Found a non-empty line outside a stanza [see line "
                            f"{self._current_line_no} in {self.path}]."
                        )
                elif line.strip() == f"### {self.app_label} DETECTIONS ###":
                    # We have hit the detections portion of the conf and we adjust the state
                    # accordingly
                    self._in_detections = True

    @staticmethod
    def init_from_package(package_path: Path, app_name: str, appid: str) -> "SavedsearchesConf":
        """
        Alternate constructor which can take an app package, and extract the savedsearches.conf from
        a temporary file.

        :param package_path: Path to the app package
        :type package_path: :class:`pathlib.Path`
        :param app_name: the name of the app (e.g. ESCU)
        :type app_name: str

        :returns: a SavedsearchesConf object
        :rtype: :class:`contentctl.objects.savedsearches_conf.SavedsearchesConf`
        """
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Open the tar/gzip archive
            with tarfile.open(package_path) as package:
                # Extract the savedsearches.conf and use it to init the model
                package_conf_path = SavedsearchesConf.PACKAGE_CONF_PATH_FMT_STR.format(appid=appid)
                package.extract(package_conf_path, path=tmpdir)
                return SavedsearchesConf(
                    path=Path(tmpdir, package_conf_path),
                    app_label=app_name
                )
