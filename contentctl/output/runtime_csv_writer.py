from __future__ import annotations

import csv
from io import StringIO
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from contentctl.input.director import DirectorOutputDto

from contentctl.objects.config import CustomApp
from contentctl.objects.data_source import DataSource


class RuntimeCsvWriter:
    @staticmethod
    def generateDeprecationCSVContent(
        director: DirectorOutputDto, app: CustomApp
    ) -> str:
        with StringIO() as output_buffer:
            fieldNames = [
                "Name",
                "Content Type",
                "Removed in Version",
                "Reason",
                "Replacement Content",
                "Replacement Content Link",
            ]

            writer = csv.DictWriter(output_buffer, fieldnames=fieldNames)
            writer.writeheader()

            for content in director.name_to_content_map.values():
                if content.deprecation_info is not None:
                    try:
                        writer.writerow(
                            {
                                "Name": content.deprecation_info.contentType.static_get_conf_stanza_name(
                                    content.name, app
                                ),
                                "Content Type": content.deprecation_info.contentType.__name__,
                                "Removed in Version": content.deprecation_info.removed_in_version,
                                "Reason": content.deprecation_info.reason,
                                "Replacement Content": "\n".join(
                                    [
                                        c.name
                                        for c in content.deprecation_info.replacement_content
                                    ]
                                )
                                or "No Replacement Content Available",
                                "Replacement Content Link": "\n".join(
                                    [
                                        str(c.researchSiteLink)
                                        for c in content.deprecation_info.replacement_content
                                    ]
                                )
                                or "No Content Link Available",
                            }
                        )
                    except Exception as e:
                        print(e)
                        import code

                        code.interact(local=locals())
            return output_buffer.getvalue()

    @staticmethod
    def generateDatasourceCSVContent(
        data_source_objects: List[DataSource],
    ) -> str:
        with StringIO() as output_buffer:
            writer = csv.writer(output_buffer)
            # Write the header
            writer.writerow(
                [
                    "name",
                    "id",
                    "author",
                    "source",
                    "sourcetype",
                    "separator",
                    "supported_TA_name",
                    "supported_TA_version",
                    "supported_TA_url",
                    "description",
                ]
            )
            # Write the data
            for data_source in data_source_objects:
                if len(data_source.supported_TA) > 0:
                    supported_TA_name = data_source.supported_TA[0].name
                    supported_TA_version = data_source.supported_TA[0].version
                    supported_TA_url = data_source.supported_TA[0].url or ""
                else:
                    supported_TA_name = ""
                    supported_TA_version = ""
                    supported_TA_url = ""
                writer.writerow(
                    [
                        data_source.name,
                        data_source.id,
                        data_source.author,
                        data_source.source,
                        data_source.sourcetype,
                        data_source.separator,
                        supported_TA_name,
                        supported_TA_version,
                        supported_TA_url,
                        data_source.description,
                    ]
                )
            return output_buffer.getvalue()
