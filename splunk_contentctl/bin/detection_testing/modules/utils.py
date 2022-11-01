import os
import shutil
import requests
import random
import string
from timeit import default_timer
import pathlib
import datetime

TOTAL_BYTES = 0
TOTAL_DOWNLOAD_TIME = 0
def download_file_from_http(file_path:str, destination_file:str, overwrite_file:bool=False, chunk_size:int=1024*1024, verbose_print:bool=False)->None:
    global TOTAL_BYTES, TOTAL_DOWNLOAD_TIME
    
    try:
        if pathlib.Path(file_path).is_file():
            shutil.copyfile(file_path, destination_file)
            return
    except Exception as e:
        print(f"Could not copy local file {file_path} the file because {str(e)}")

    
    if os.path.exists(destination_file) and overwrite_file is False:
        print(f"[{destination_file}] already exists...using cached version")
        return
    if verbose_print:
        print(f"downloading to [{destination_file}]...",end="", flush=True)
    try:
        download_start_time = default_timer()
        bytes_written=0
        file_to_download = requests.get(file_path, stream=True)
        if file_to_download.status_code != 200:
            if verbose_print:
                print("FAILED")
            raise Exception(f"Error downloading the file {file_path}: Status Code {file_to_download.status_code}")
        with open(destination_file, "wb") as output:
            for piece in file_to_download.iter_content(chunk_size=chunk_size):
                bytes_written += output.write(piece)
        if verbose_print:
            print("Done")
        download_stop_time = default_timer()
        timedelta = download_stop_time-download_start_time
        TOTAL_BYTES += bytes_written
        TOTAL_DOWNLOAD_TIME += timedelta
        
    except Exception as e:
        if verbose_print:
            print("FAILED")
        raise e
    return


def print_total_download_stats()->None:
    
    time_string = datetime.timedelta(seconds=round(TOTAL_DOWNLOAD_TIME))
    print(f"Download statistics:\n"
          f"\tTotal MB     :{(TOTAL_BYTES/(1024*1024)):.0f}MB\n"
          f"\tTotal Seconds:{time_string}s")

# taken from attack_range
def get_random_password(password_min_length: int = 16, password_max_length: int = 26) -> str:
    random_source = string.ascii_letters + string.digits
    password = random.choice(string.ascii_lowercase)
    password += random.choice(string.ascii_uppercase)
    password += random.choice(string.digits)

    for i in range(random.randrange(password_min_length, password_max_length)):
        password += random.choice(random_source)

    password_list = list(password)
    random.SystemRandom().shuffle(password_list)
    password = "".join(password_list)
    return password