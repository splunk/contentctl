import os
import asyncio
import sys

from pathlib import Path

from contentctl.objects.enums import SecurityContentType
from contentctl.output.jinja_writer import JinjaWriter


class DocMdOutput():
    index = 0
    files_to_write = 0
    
    def writeObjects(self, objects: list, output_path: str) -> None:
        self.files_to_write = sum([len(obj) for obj in objects])
        self.index = 0
        progress_percent = ((self.index+1)/self.files_to_write) * 100
        if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()):
            print(f"\r{'Docgen Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)

        attack_tactics = set()
        datamodels = set()
        categories = set()
        for story in objects[0]:
            if story.tags.category:
                categories.update(story.tags.category)

        for detection in objects[1]:
            if detection.tags.mitre_attack_enrichments:
                for attack in detection.tags.mitre_attack_enrichments:
                    attack_tactics.update(attack.mitre_attack_tactics)

            if detection.datamodel:
                datamodels.update(detection.datamodel)
        
        Path(os.path.join(output_path, 'overview')).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(output_path, 'detections')).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(output_path, 'stories')).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(output_path, 'playbooks')).mkdir(parents=True, exist_ok=True)

        JinjaWriter.writeObjectsList('doc_story_page.j2', os.path.join(output_path, 'overview/stories.md'), sorted(objects[0], key=lambda x: x.name))
        self.writeObjectsMd(objects[0], os.path.join(output_path, 'stories'), 'doc_stories.j2')

        JinjaWriter.writeObjectsList('doc_detection_page.j2', os.path.join(output_path, 'overview/detections.md'), sorted(objects[1], key=lambda x: x.name))
        self.writeObjectsMd(objects[1], os.path.join(output_path, 'detections'), 'doc_detections.j2')

        JinjaWriter.writeObjectsList('doc_playbooks_page.j2', os.path.join(output_path, 'overview/paybooks.md'), sorted(objects[2], key=lambda x: x.name))
        self.writeObjectsMd(objects[2], os.path.join(output_path, 'playbooks'), 'doc_playbooks.j2')
        
        print("Done!")
    
    
    # def writeNavigationPageObjects(self, objects: list, output_path: str) -> None:
    #     for obj in objects:
    #         JinjaWriter.writeObject('doc_navigation_pages.j2', os.path.join(output_path, '_pages', obj.lower().replace(' ', '_') + '.md'),
    #             {
    #                 'name': obj
    #             }
    #         )

    def writeObjectsMd(self, objects, output_path: str, template_name: str) -> None:
        for obj in objects:
            progress_percent = ((self.index+1)/self.files_to_write) * 100
            self.index+=1
            if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()):
                print(f"\r{'Docgen Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)

            JinjaWriter.writeObject(template_name, os.path.join(output_path, obj.name.lower().replace(' ', '_') + '.md'), obj)

