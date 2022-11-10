from argparse import Namespace
from bin.objects.test_config import TestConfig
from bin.detection_testing.detection_testing_execution import main
from bin.input.director import DirectorOutputDto
import sys
import yaml

class Test:
    
    def execute(self, config :TestConfig, director: DirectorOutputDto)->None:
        main(config,director)
        
        
    
    