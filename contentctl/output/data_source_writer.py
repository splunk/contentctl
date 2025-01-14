import csv
from contentctl.objects.data_source import DataSource
from typing import List
import pathlib
from contentctl.input.director import DirectorOutputDto
from contentctl.objects.enums import DetectionStatus
from contentctl.objects.config import CustomApp
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
                if  len(data_source.supported_TA) > 0:
                    supported_TA_name = data_source.supported_TA[0].name
                    supported_TA_version = data_source.supported_TA[0].version
                    supported_TA_url = data_source.supported_TA[0].url or ''
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

    @staticmethod
    def writeDeprecationCsv(director: DirectorOutputDto, app:CustomApp, file_path: pathlib.Path):
        rows:list[dict[str,str]] = []
        for category in [
            director.detections,
            #director.stories,
            # director.baselines,
            # director.investigations,
            # director.playbooks,
            # director.macros,
            # director.lookups,
            # director.deployments,
            # director.dashboards,
        ]:
            
            for obj in filter(lambda obj: obj.status == DetectionStatus.deprecated, category):
                rows.append(
                    {
                        "Name": obj.get_conf_stanza_name(app),
                        "ID": str(obj.id),
                        "Content Type": type(obj).__name__,
                        "Deprecation Date": str(obj.date),
                        "Reason": "Give a unique reason in the model here",
                        "Migration Guide": "https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjhmaGNuaTVuNm52bWNvNWdzZzdxeHN4dmh0Z29tcjAybHpjNjdmeSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/0hLOxvKJHArT2OjHba/giphy.gif",
                        "Replacements": "\n".join(["https://research.splunk.com/endpoint/35682718-5a85-11ec-b8f7-acde48001122/", 
                                         "https://research.splunk.com/endpoint/5f1d2ea7-eec0-4790-8b24-6875312ad492/", 
                                         "do we want these to be links to content on the research site or on the actual splunk server?"])
                    }
                )
                
                



        with open(file_path, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["Name", "ID", "Content Type", "Deprecation Date", "Reason", "Migration Guide", "Replacements"])
            # Write the header
            writer.writeheader()
            # Write the data
            writer.writerows(rows)

                
