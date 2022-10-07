import os
import requests
import random
import string


def download_file_from_http(url:str, destination_file:str, overwrite_file:bool=False, chunk_size:int=1024*1024, verbose_print:bool=False)->None:
    if os.path.exists(destination_file) and overwrite_file is False:
        print(f"[{destination_file}] already exists...using cached version")
        return
    if verbose_print:
        print(f"downloading to [{destination_file}]...",end="", flush=True)
    try:
        file_to_download = requests.get(url, stream=True)
        if file_to_download.status_code != 200:
            if verbose_print:
                print("FAILED")
            raise Exception(f"Error downloading the file {url}: Status Code {file_to_download.status_code}")
        with open(destination_file, "wb") as output:
            for piece in file_to_download.iter_content(chunk_size=chunk_size):
                output.write(piece)
        if verbose_print:
            print("Done")
    except Exception as e:
        if verbose_print:
            print("FAILED")
        raise e

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