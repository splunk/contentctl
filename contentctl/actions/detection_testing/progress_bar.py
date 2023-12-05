import time
from enum import Enum
from tqdm import tqdm
import datetime


class TestReportingType(str, Enum):
    """
    5-char identifiers for the type of testing being reported on
    """
    # Reporting around general testing setup (e.g. infra, role configuration)
    SETUP = "SETUP"

    # Reporting around a group of tests
    GROUP = "GROUP"

    # Reporting around a unit test
    UNIT = "UNIT "

    # Reporting around an integration test
    INTEGRATION = "INTEG"


class TestingStates(str, Enum):
    """
    Defined testing states
    """
    BEGINNING_GROUP = "Beginning Test Group"
    BEGINNING_TEST = "Beginning Test"
    DOWNLOADING = "Downloading Data"
    REPLAYING = "Replaying Data"
    PROCESSING = "Waiting for Processing"
    SEARCHING = "Running Search"
    DELETING = "Deleting Data"
    DONE_GROUP = "Test Group Done"
    PRE_CLEANUP = "Pre-run Cleanup"
    POST_CLEANUP = "Post-run Cleanup"
    FORCE_RUN = "Forcing Detection Run"
    VALIDATING = "Validating Risks/Notables"


# the longest length of any state
LONGEST_STATE = max(len(w.value) for w in TestingStates)


class FinalTestingStates(str, Enum):
    """
    The possible final states for a test (for pbar reporting)
    """
    FAIL = "\x1b[0;30;41m" + "FAIL ".ljust(LONGEST_STATE) + "\x1b[0m"
    ERROR = "\x1b[0;30;41m" + "ERROR".ljust(LONGEST_STATE) + "\x1b[0m"
    PASS = "\x1b[0;30;42m" + "PASS ".ljust(LONGEST_STATE) + "\x1b[0m"
    SKIP = "\x1b[0;30;47m" + "SKIP ".ljust(LONGEST_STATE) + "\x1b[0m"


# max length of a test name
# TODO: this max size is declared, and it is used appropriately w/ .ljust, but nothing truncates
#   test names to makes them the appropriate size
MAX_TEST_NAME_LENGTH = 70

# The format string used for pbar reporting
PBAR_FORMAT_STRING = "[{test_reporting_type}] {test_name} >> {state} | Time: {time}"


def format_pbar_string(
    pbar: tqdm,
    test_reporting_type: TestReportingType,
    test_name: str,
    state: str,
    start_time: float,
    set_pbar: bool = True,
) -> str:
    """
    Utility function to log testing information via pbar; returns a formatted string that can be
    written and optionally updates the existing progress bar
    :param pbar: a tqdm instance to use for updating
    :param test_reporting_type: the type of reporting to be done (e.g. unit, integration, group)
    :param test_name: the name of the test to be logged
    :param state: the state/message of the test to be logged
    :param start_time: the start_time of this progres bar
    :param set_pbar: bool indicating whether pbar.update should be called
    :returns: a formatted string for use w/ pbar
    """
    # Extract and ljust our various fields
    field_one = test_reporting_type.value
    field_two = test_name.ljust(MAX_TEST_NAME_LENGTH)
    field_three = state.ljust(LONGEST_STATE)
    field_four = datetime.timedelta(seconds=round(time.time() - start_time))

    # Format the string
    new_string = PBAR_FORMAT_STRING.format(
        test_reporting_type=field_one,
        test_name=field_two,
        state=field_three,
        time=field_four,
    )

    # Update pbar if set
    if set_pbar:
        pbar.bar_format = new_string
        pbar.update()

    # Return formatted string
    return new_string
