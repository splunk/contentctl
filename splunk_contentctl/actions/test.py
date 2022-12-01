from argparse import Namespace
from splunk_contentctl.objects.test_config import TestConfig
from splunk_contentctl.actions.detection_testing.detection_testing_execution import main
from splunk_contentctl.actions.generate import DirectorOutputDto


class Test:
    def execute(self, config :TestConfig, director: DirectorOutputDto)->None:
        main(config,director)
        
        
    
    