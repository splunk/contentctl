import os

from dataclasses import dataclass
import pathlib
import splunk_appinspect

@dataclass(frozen=True)
class InspectInputDto:
    path: pathlib.Path


class Inspect:

    def execute(self, input_dto: InspectInputDto) -> None:
        '''
        director_output_dto = DirectorOutputDto([],[],[],[],[],[],[],[])
        director = Director(director_output_dto)
        director.execute(input_dto.director_input_dto)

        #svg_output = SvgOutput()
        #svg_output.writeObjects(director_output_dto.detections, input_dto.output_path)
        
        attack_nav_output = AttackNavOutput()        
        attack_nav_output.writeObjects(
            director_output_dto.detections, 
            os.path.join(input_dto.director_input_dto.input_path, "reporting")
        )
        '''
        if not input_dto.path.is_file():
            raise Exception(f'Error inspecting {input_dto.path}: The file does not exist')
        
        
        import subprocess
        my_args = ["splunk-appinspect", "inspect", "dist/ESCU.tar.gz"]
        print(my_args)
        subprocess.run(args=my_args)
        

        try:
            print(f'Inspection of {input_dto.path} successful')
        except Exception as e:
            raise Exception(f'Error inspecting {input_dto.path}: {str(e)}')