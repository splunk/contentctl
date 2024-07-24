import csv
from contentctl.objects.data_source import DataSource
from contentctl.objects.event_source import EventSource
from typing import List
import pathlib

class DataSourceWriter:

    @staticmethod
    def writeDataSourceCsv(data_source_objects: List[DataSource], file_path: pathlib.Path):
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            # Write the header
            writer.writerow([
                "name", "id", "author", "source", "sourcetype", "separator", 
                "supported_TA_name", "supported_TA_version", "supported_TA_url",
                "description"
            ])
            # Write the data
            for data_source in data_source_objects:
                if data_source.supported_TA and isinstance(data_source.supported_TA, list) and len(data_source.supported_TA) > 0:
                    supported_TA_name = data_source.supported_TA[0].get('name', '')
                    supported_TA_version = data_source.supported_TA[0].get('version', '')
                    supported_TA_url = data_source.supported_TA[0].get('url', '')
                else:
                    supported_TA_name = ''
                    supported_TA_version = ''
                    supported_TA_url = ''
                writer.writerow([
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
                ])
