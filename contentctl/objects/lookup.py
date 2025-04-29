from __future__ import annotations

import abc
import csv
import datetime
import pathlib
import re
from enum import StrEnum, auto
from functools import cached_property
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self

from pydantic import (
    BeforeValidator,
    Field,
    FilePath,
    HttpUrl,
    NonNegativeInt,
    TypeAdapter,
    ValidationInfo,
    computed_field,
    field_validator,
    model_serializer,
    model_validator,
)

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto
    from contentctl.objects.config import validate

from io import StringIO, TextIOBase

from contentctl.objects.enums import ContentStatus
from contentctl.objects.security_content_object import SecurityContentObject

# This section is used to ignore lookups that are NOT  shipped with ESCU app but are used in the detections. Adding exclusions here will so that contentctl builds will not fail.
LOOKUPS_TO_IGNORE = set(["outputlookup"])
LOOKUPS_TO_IGNORE.add(
    "ut_shannon_lookup"
)  # In the URL toolbox app which is recommended for ESCU
LOOKUPS_TO_IGNORE.add(
    "identity_lookup_expanded"
)  # Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add(
    "cim_corporate_web_domain_lookup"
)  # Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add(
    "cim_corporate_email_domain_lookup"
)  # Shipped with the Enterprise Security
LOOKUPS_TO_IGNORE.add("cim_cloud_domain_lookup")  # Shipped with the Enterprise Security

LOOKUPS_TO_IGNORE.add(
    "alexa_lookup_by_str"
)  # Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add(
    "interesting_ports_lookup"
)  # Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add(
    "asset_lookup_by_str"
)  # Shipped with the Asset and Identity Framework
LOOKUPS_TO_IGNORE.add("admon_groups_def")  # Shipped with the SA-admon addon
LOOKUPS_TO_IGNORE.add(
    "identity_lookup_expanded"
)  # Shipped with the Enterprise Security

# Special case for the Detection "Exploit Public Facing Application via Apache Commons Text"
LOOKUPS_TO_IGNORE.add("=")
LOOKUPS_TO_IGNORE.add("other_lookups")


class Lookup_Type(StrEnum):
    csv = auto()
    kvstore = auto()
    mlmodel = auto()


# TODO (#220): Split Lookup into 2 classes
class Lookup(SecurityContentObject, abc.ABC):
    # We need to make sure that this is converted to a string because we widely
    # use the string "False" in our lookup content.  However, PyYAML reads this
    # as a BOOL and this causes parsing to fail. As such, we will always
    # convert this to a string if it is passed as a bool
    default_match: Annotated[
        str, BeforeValidator(lambda dm: str(dm).lower() if isinstance(dm, bool) else dm)
    ] = Field(
        default="",
        description="This field is given a default value of ''"
        "because it is the default value specified in the transforms.conf "
        "docs. Giving it a type of str rather than str | None simplifies "
        "the typing for the field.",
    )
    # Per the documentation for transforms.conf, EXACT should not be specified in this list,
    # so we include only WILDCARD and CIDR
    match_type: list[Annotated[str, Field(pattern=r"(^WILDCARD|CIDR)\(.+\)$")]] = Field(
        default=[]
    )
    min_matches: None | NonNegativeInt = Field(default=None)
    max_matches: None | Annotated[NonNegativeInt, Field(ge=1, le=1000)] = Field(
        default=None
    )
    case_sensitive_match: None | bool = Field(default=None)
    status: ContentStatus = ContentStatus.production

    @field_validator("status", mode="after")
    @classmethod
    def NarrowStatus(cls, status: ContentStatus) -> ContentStatus:
        return cls.NarrowStatusTemplate(status, [ContentStatus.production])

    @classmethod
    def containing_folder(cls) -> pathlib.Path:
        return pathlib.Path("lookups")

    @model_serializer
    def serialize_model(self):
        # Call parent serializer
        super_fields = super().serialize_model()

        # All fields custom to this model
        model = {
            "default_match": self.default_match,
            "match_type": self.match_type_to_conf_format,
            "min_matches": self.min_matches,
            "max_matches": self.max_matches,
            "case_sensitive_match": "true"
            if self.case_sensitive_match is True
            else "false",
        }

        # return the model
        model.update(super_fields)
        return model

    @model_validator(mode="before")
    def fix_lookup_path(cls, data: Any, info: ValidationInfo) -> Any:
        if data.get("filename"):
            config: validate = info.context.get("config", None)
            if config is not None:
                data["filename"] = config.path / "lookups/" / data["filename"]
            else:
                raise ValueError(
                    "config required for constructing lookup filename, but it was not"
                )
        return data

    @computed_field
    @cached_property
    def match_type_to_conf_format(self) -> str:
        return ", ".join(self.match_type)

    @staticmethod
    def get_lookups(
        text_field: str,
        director: DirectorOutputDto,
        ignore_lookups: set[str] = LOOKUPS_TO_IGNORE,
    ) -> list[Lookup]:
        # Comprehensively match all kinds of lookups, including inputlookup and outputlookup
        inputLookupsToGet = set(
            re.findall(
                r"[^\w]inputlookup(?:\s*(?:(?:append|strict|start|max)\s*=\s*(?:true|t|false|f))){0,4}\s+([\w]+)",
                text_field,
                re.IGNORECASE,
            )
        )
        outputLookupsToGet = set(
            re.findall(
                r"[^\w]outputlookup(?:\s*(?:(?:append|create_empty|override_if_empty|max|key_field|allow_updates|createinapp|create_context|output_format)\s*=\s*[^\s]*))*\s+([\w]+)",
                text_field,
                re.IGNORECASE,
            )
        )
        lookupsToGet = set(
            re.findall(
                r"[^\w](?:(?<!output)(?<!input))lookup(?:\s*(?:(?:local|update)\s*=\s*(?:true|t|false|f))){0,2}\s+([\w]+)",
                text_field,
                re.IGNORECASE,
            )
        )

        input_lookups = Lookup.mapNamesToSecurityContentObjects(
            list(inputLookupsToGet - LOOKUPS_TO_IGNORE), director
        )
        output_lookups = Lookup.mapNamesToSecurityContentObjects(
            list(outputLookupsToGet - LOOKUPS_TO_IGNORE), director
        )
        lookups = Lookup.mapNamesToSecurityContentObjects(
            list(lookupsToGet - LOOKUPS_TO_IGNORE), director
        )

        all_lookups = set(input_lookups + output_lookups + lookups)

        return list(all_lookups)

    @computed_field
    @cached_property
    def researchSiteLink(self) -> HttpUrl:
        raise NotImplementedError(
            f"researchSiteLink has not been implemented for [{type(self).__name__} - {self.name}]"
        )


class FileBackedLookup(Lookup, abc.ABC):
    # For purposes of the disciminated union, the child classes which
    # inherit from this class must declare the typing of lookup_type
    # themselves, hence it is not defined in the Lookup class

    @model_validator(mode="after")
    def ensure_lookup_file_exists(self) -> Self:
        if not self.filename.exists():
            raise ValueError(f"Expected lookup filename {self.filename} does not exist")
        return self

    @computed_field
    @cached_property
    @abc.abstractmethod
    def filename(self) -> FilePath:
        """
        This function computes the backing file for the lookup. It is abstract because different types of lookups
        (CSV for MlModel) backing files have different name format.
        """
        pass

    @computed_field
    @cached_property
    @abc.abstractmethod
    def app_filename(self) -> FilePath:
        """
        This function computes the filenames to write into the app itself.  This is abstract because
        CSV and MLmodel requirements are different.
        """
        pass

    @property
    def content_file_handle(self) -> TextIOBase:
        return open(self.filename, "r")


class CSVLookup(FileBackedLookup):
    lookup_type: Literal[Lookup_Type.csv]

    @model_serializer
    def serialize_model(self):
        # Call parent serializer
        super_fields = super().serialize_model()

        # All fields custom to this model
        model = {"filename": self.app_filename.name}

        # return the model
        model.update(super_fields)
        return model

    @computed_field
    @cached_property
    def filename(self) -> FilePath:
        """
        This function computes the backing file for the lookup. The names of CSV files must EXACTLY match the
        names of their lookup definitions except with the CSV file extension rather than the YML file extension.
        """
        if self.file_path is None:
            raise ValueError(
                f"Cannot get the filename of the lookup {self.lookup_type} for content [{self.name}] because the YML file_path attribute is None"
            )  # type: ignore

        csv_file = self.file_path.parent / f"{self.file_path.stem}.{self.lookup_type}"  # type: ignore

        return csv_file

    @computed_field
    @cached_property
    def app_filename(self) -> FilePath:
        """
        This function computes the filenames to write into the app itself.  This is abstract because
        CSV and MLmodel requirements are different.
        """

        return pathlib.Path(
            f"{self.name}_{self.date.year}{self.date.month:02}{self.date.day:02}.{self.lookup_type}"
        )

    @model_validator(mode="after")
    def ensure_correct_csv_structure(self) -> Self:
        # https://docs.python.org/3/library/csv.html#csv.DictReader
        # Column Names (fieldnames) determine by the number of columns in the first row.
        # If a row has MORE fields than fieldnames, they will be dumped in a list under the key 'restkey' - this should throw an Exception
        # If a row has LESS fields than fieldnames, then the field should contain None by default. This should also throw an exception.
        csv_errors: list[str] = []

        RESTKEY = "extra_fields_in_a_row"
        with self.content_file_handle as handle:
            csv_dict = csv.DictReader(handle, restkey=RESTKEY)

            if csv_dict.fieldnames is None:
                raise ValueError(
                    f"Error validating the CSV referenced by the lookup: {self.filename}:\n\t"
                    "Unable to read fieldnames from CSV. Is the CSV empty?\n"
                    "  Please try opening the file with a CSV Editor to ensure that it is correct."
                )
            # Remember that row 1 has the headers and we do not iterate over it in the loop below
            # CSVs are typically indexed starting a row 1 for the header.
            for row_index, data_row in enumerate(csv_dict):
                row_index += 2
                if len(data_row.get(RESTKEY, [])) > 0:
                    csv_errors.append(
                        f"row [{row_index}] should have [{len(csv_dict.fieldnames)}] columns,"
                        f" but instead had [{len(csv_dict.fieldnames) + len(data_row.get(RESTKEY, []))}]."
                    )

                for column_index, column_name in enumerate(data_row):
                    if data_row[column_name] is None:
                        csv_errors.append(
                            f"row [{row_index}] should have [{len(csv_dict.fieldnames)}] columns, "
                            f"but instead had [{column_index}]."
                        )
        if len(csv_errors) > 0:
            err_string = "\n\t".join(csv_errors)
            raise ValueError(
                f"Error validating the CSV referenced by the lookup: {self.filename}:\n\t{err_string}\n"
                f"  Please try opening the file with a CSV Editor to ensure that it is correct."
            )

        return self


class RuntimeCSV(CSVLookup):
    contents: str = Field(
        description="This field contains the contents that would usually "
        "be written to a CSV file. However, we store these in memory, "
        "rather than on disk, to avoid needing to create a CSV file "
        "before copying it into the app build."
    )
    # Since these are defined at runtime, they always have
    # a date of today
    date: datetime.date = Field(default=datetime.date.today())

    @model_validator(mode="after")
    def ensure_lookup_file_exists(self) -> Self:
        # Because the contents of this file are created at runtime, it does
        # not actually need to exist. As such, we do not validate it
        return self

    @property
    def content_file_handle(self) -> TextIOBase:
        return StringIO(self.contents)


class KVStoreLookup(Lookup):
    lookup_type: Literal[Lookup_Type.kvstore]
    fields: list[str] = Field(
        description="The names of the fields/headings for the KVStore.", min_length=1
    )

    @field_validator("fields", mode="after")
    @classmethod
    def ensure_key(cls, values: list[str]):
        if values[0] != "_key":
            raise ValueError(f"fields MUST begin with '_key', not '{values[0]}'")
        return values

    @computed_field
    @cached_property
    def collection(self) -> str:
        return self.name

    @computed_field
    @cached_property
    def fields_to_fields_list_conf_format(self) -> str:
        return ", ".join(self.fields)

    @model_serializer
    def serialize_model(self):
        # Call parent serializer
        super_fields = super().serialize_model()

        # All fields custom to this model
        model = {
            "collection": self.collection,
            "fields_list": self.fields_to_fields_list_conf_format,
        }

        # return the model
        model.update(super_fields)
        return model


class MlModel(FileBackedLookup):
    lookup_type: Literal[Lookup_Type.mlmodel]

    @computed_field
    @cached_property
    def filename(self) -> FilePath:
        """
        This function computes the backing file for the lookup. The names of mlmodel files must EXACTLY match the
        names of their lookup definitions except with:
        - __mlspl_ prefix
        - .mlmodel file extension rather than the YML file extension.
        """
        if self.file_path is None:
            raise ValueError(
                f"Cannot get the filename of the lookup {self.lookup_type} because the YML file_path attribute is None"
            )  # type: ignore

        if not self.file_path.stem.startswith("__mlspl_"):
            raise ValueError(
                f"The file_path for ML Model {self.name} MUST start with '__mlspl_', but it does not."
            )

        return self.file_path.parent / f"{self.file_path.stem}.{self.lookup_type}"

    @computed_field
    @cached_property
    def app_filename(self) -> FilePath:
        """
        This function computes the filenames to write into the app itself.  This is abstract because
        CSV and MLmodel requirements are different.
        """
        return pathlib.Path(f"{self.filename.stem}.{self.lookup_type}")


LookupAdapter: TypeAdapter[CSVLookup | KVStoreLookup | MlModel] = TypeAdapter(
    Annotated[CSVLookup | KVStoreLookup | MlModel, Field(discriminator="lookup_type")]
)

# The following are defined as they are used by the Director.  For normal SecurityContentObject
# types, they already exist. But do not for the TypeAdapter
setattr(LookupAdapter, "containing_folder", lambda: "lookups")
setattr(LookupAdapter, "__name__", "Lookup")
