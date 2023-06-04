import os
import git
import shutil
import requests
import random
import string
from timeit import default_timer
import pathlib
import datetime
from typing import Union, Tuple
from pydantic import ValidationError
import tqdm
from contentctl.objects.security_content_object import SecurityContentObject
from math import ceil

TOTAL_BYTES = 0
ALWAYS_PULL = True


class Utils:
    @staticmethod
    def get_all_yml_files_from_directory(path: str) -> list[pathlib.Path]:
        listOfFiles:list[pathlib.Path] = []
        for (dirpath, dirnames, filenames) in os.walk(path):
            for file in filenames:
                if file.endswith(".yml"):
                    listOfFiles.append(pathlib.Path(os.path.join(dirpath, file)))
    
        return sorted(listOfFiles)


    @staticmethod
    def add_id(id_dict:dict[str, list[pathlib.Path]], obj:SecurityContentObject, path:pathlib.Path) -> None:     
        if hasattr(obj, "id"):
            obj_id = obj.id
            if obj_id in id_dict:
                id_dict[obj_id].append(path)
            else:
                id_dict[obj_id] = [path]
    # Otherwise, no ID so nothing to add....

    @staticmethod
    def check_ids_for_duplicates(id_dict:dict[str, list[pathlib.Path]])->list[Tuple[pathlib.Path,  ValueError]]:
        validation_errors:list[Tuple[pathlib.Path,  ValueError]] = []
        
        for key, values in id_dict.items():
            if len(values) > 1:
                error_file_path = pathlib.Path("MULTIPLE")
                all_files = '\n\t'.join(str(pathlib.Path(p)) for p in values)
                exception = ValueError(f"Error validating id [{key}] - duplicate ID was used in the following files: \n\t{all_files}")
                validation_errors.append((error_file_path, exception))
                
        return validation_errors

    @staticmethod
    def validate_git_hash(
        repo_path: str, repo_url: str, commit_hash: str, branch_name: Union[str, None]
    ) -> bool:

        # Get a list of all branches
        repo = git.Repo(repo_path)
        if commit_hash is None:
            # No need to validate the hash, it was not supplied
            return True

        try:
            all_branches_containing_hash = repo.git.branch(
                "--contains", commit_hash
            ).split("\n")
            # this is a list of all branches that contain the hash.  They are in the format:
            # * <some number of spaces> branchname (if the branch contains the hash)
            # <some number of spaces>   branchname (if the branch does not contain the hash)
            # Note, of course, that a hash can be in 0, 1, more branches!
            for branch_string in all_branches_containing_hash:
                if branch_string.split(" ")[0] == "*" and (
                    branch_string.split(" ")[-1] == branch_name or branch_name == None
                ):
                    # Yes, the hash exists in the branch (or branch_name was None and it existed in at least one branch)!
                    return True
            # If we get here, it does not exist in the given branch
            raise (Exception("Does not exist in branch"))

        except Exception as e:
            if branch_name is None:
                branch_name = "ANY_BRANCH"
            if ALWAYS_PULL:
                raise (
                    ValueError(
                        f"hash '{commit_hash}' not found in '{branch_name}' for repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"
                    )
                )
            else:
                raise (
                    ValueError(
                        f"hash '{commit_hash}' not found in '{branch_name}' for repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"
                        "If the hash is new, try pulling the repo."
                    )
                )

    @staticmethod
    def get_default_branch_name(repo_path: str, repo_url: str) -> str:
        # Even though the default branch is only a notion in GitHub or
        # similar systems, we will consinder the default branch
        # to be the name of the branch that is the HEAD of the repo.
        # This means that it should work for ANY repo with a remote.

        repo = git.Repo(repo_path)

        # Only works for remotes!
        for remote in repo.remotes.origin.refs:
            if remote.name.endswith("/HEAD"):
                # return the name of this branch.  it will be prefixed with 'origin/', so remove the origin/
                return remote.ref.name.replace("origin/", "")
        raise (
            ValueError(
                f"Failed to find default branch in repo_path: {repo_path}\n  * repo_url: {repo_url}"
            )
        )

    @staticmethod
    def validate_git_branch_name(repo_path: str, repo_url: str, name: str) -> bool:
        # Get a list of all branches
        repo = git.Repo(repo_path)

        all_branches = [branch.name for branch in repo.refs]
        # remove "origin/" from the beginning of each branch name
        all_branches = [branch.replace("origin/", "") for branch in all_branches]

        if name in all_branches:
            return True

        else:
            if ALWAYS_PULL:
                raise (
                    ValueError(
                        f"branch '{name}' not found in repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"
                    )
                )
            else:
                raise (
                    ValueError(
                        f"branch '{name}' not found in repo located at:\n  * repo_path: {repo_path}\n  * repo_url: {repo_url}"
                        "If the branch is new, try pulling the repo."
                    )
                )

    @staticmethod
    def validate_git_pull_request(repo_path: str, pr_number: int) -> str:
        # Get a list of all branches
        repo = git.Repo(repo_path)
        # List of all remotes that match this format.  If the PR exists, we
        # should find exactly one in the format SHA_HASH\tpull/pr_number/head
        pr_and_hash = repo.git.ls_remote("origin", f"pull/{pr_number}/head")

        if len(pr_and_hash) == 0:
            raise (
                ValueError(
                    f"pr_number {pr_number} not found in Remote '{repo.remote().url}'"
                )
            )

        pr_and_hash_lines = pr_and_hash.split("\n")
        if len(pr_and_hash_lines) > 1:
            raise (
                ValueError(
                    f"Somehow, more than 1 PR was found with pr_number {pr_number}:\n{pr_and_hash}\nThis should not happen."
                )
            )

        if pr_and_hash_lines[0].count("\t") == 1:
            hash, _ = pr_and_hash_lines[0].split("\t")
            return hash
        else:
            raise (
                ValueError(
                    f"Expected PR Format:\nCOMMIT_HASH\tpull/{pr_number}/head\nbut got\n{pr_and_hash_lines[0]}"
                )
            )

        return hash

    @staticmethod
    def check_required_fields(
        thisField: str, definedFields: dict, requiredFields: list[str]
    ):
        missing_fields = [
            field for field in requiredFields if field not in definedFields
        ]
        if len(missing_fields) > 0:
            raise (
                ValueError(
                    f"Could not validate - please resolve other errors resulting in missing fields {missing_fields}"
                )
            )

    @staticmethod
    def verify_file_exists(
        file_path: str, verbose_print=False, timeout_seconds: int = 10
    ) -> None:

        try:
            if pathlib.Path(file_path).is_file():
                # This is a file and we know it exists
                return None
        except Exception as e:
            print(f"Could not copy local file {file_path} the file because {str(e)}")

        # Try to make a head request to verify existence of the file
        try:
            req = requests.head(
                file_path, timeout=timeout_seconds, verify=True, allow_redirects=True
            )
            if req.status_code > 400:
                raise (Exception(f"Return code {req.status_code}"))
        except Exception as e:
            raise (
                Exception(
                    f"Cannot confirm the existence of '{file_path}' - are you sure it exists: {str(e)}"
                )
            )

    @staticmethod
    def copy_local_file(
        file_path: str,
        destination_file: str,
        overwrite_file: bool = True,
        verbose_print: bool = False,
    ):
        sourcePath = pathlib.Path(file_path)
        destPath = pathlib.Path(destination_file)
        if verbose_print:
            print(
                f"Copying [{sourcePath}] to [{destPath}]...",
                end="",
                flush=True,
            )
        try:
            # generates an exception only if the copyfile fails.
            # if we try this with a URL, it won't be found as a file and no
            # exception will be generated
            if sourcePath.is_file():
                if destPath.is_file():
                    if overwrite_file and not sourcePath.samefile(destPath):
                        shutil.copyfile(sourcePath, destPath)
                    else:
                        # Don't do anything, don't overwrite the file
                        pass
                elif destPath.exists():
                    raise (
                        Exception(
                            f"[{destPath}] exists, but it is not a file.  It cannot be overwritten."
                        )
                    )
                else:
                    shutil.copyfile(sourcePath, destPath)
            else:
                raise (Exception(f"[{sourcePath}] does not exist"))
        except Exception as e:
            raise (
                Exception(
                    f"Error: Could not copy local file [{sourcePath}] to [{destPath}]: [{str(e)}]"
                )
            )
        if verbose_print:
            print("Done")

    @staticmethod
    def download_file_from_http(
        file_path: str,
        destination_file: str,
        input_pbar: Union[tqdm.tqdm, None] = None,
        overwrite_file: bool = False,
    ):
        global TOTAL_BYTES
        sourcePath = pathlib.Path(file_path)
        destinationPath = pathlib.Path(destination_file)

        if input_pbar is None:
            pbar = tqdm.tqdm(
                total=100,
                desc="Downloading File",
                unit="B",
                unit_scale=True,
                bar_format=f"Downloading {sourcePath.name}".ljust(80)
                + "{percentage:3.0f}%[{bar:20}]"
                + "[{n_fmt}/{total_fmt} | ETA: {remaining}]",
            )
        else:
            pbar = input_pbar
            pbar.bar_format = (
                f"Downloading {sourcePath.name}".ljust(80)
                + "{percentage:3.0f}%[{bar:20}]"
                + "[{n_fmt}/{total_fmt} | ETA: {remaining}]"
            )
            pbar.unit = "B"
            pbar.unit_scale = True

            pbar.reset()

        if destinationPath.is_file() and overwrite_file is False:
            pbar.bar_format = (
                f"Downloading {sourcePath.name}".ljust(80)
                + "{percentage:3.0f}%[{bar:20}]"
                + "[PREVIOUSLY CACHED]"
            )
            pbar.update(100)
            if input_pbar is None:
                pbar.close()
            return
        elif destinationPath.is_file() and overwrite_file is True:
            # Overwrite the file
            pass
        elif destinationPath.exists():
            # The path exists but it is not a file.  This is an issue
            # regardless of whether or not overwrite_file is enabled

            raise (
                Exception(
                    f"[{destinationPath}] already exists, but it is not a file. We cannot overwrite it."
                )
            )

        try:
            download_start_time = default_timer()
            bytes_written = 0
            file_to_download = requests.get(file_path, stream=True)
            file_to_download.raise_for_status()
            content_length = int(file_to_download.headers["Content-length"])

            chunk_size = max(1024 * 1024, ceil(content_length / 100))
            pbar.total = content_length
            pbar.reset()

            pbar.bar_format = (
                f"Downloading {sourcePath.name}".ljust(80)
                + "{percentage:3.0f}%[{bar:20}]"
                + "[{n_fmt}/{total_fmt} | ETA: {remaining}]"
            )

            # pbar.update()

            with destinationPath.open("wb") as output:
                for piece in file_to_download.iter_content(chunk_size=chunk_size):
                    bytes_written += output.write(piece)
                    pbar.update(len(piece))

            TOTAL_BYTES += bytes_written

        except requests.exceptions.ConnectionError as e:
            raise (
                Exception(
                    f"Error: Could not download file [{file_path}] to [{destinationPath}] (Unable to connect to server. Are you sure the server exists and you have connectivity to it?): [{str(e)}]"
                )
            )

        except requests.exceptions.HTTPError as e:
            raise (
                Exception(
                    f"Error: Could not download file [{file_path}] to [{destinationPath}] (The file was probably not found on the server): [{str(e)}]"
                )
            )
        except requests.exceptions.Timeout as e:
            raise (
                Exception(
                    f"Error: Could not download file [{file_path}] to [{destinationPath}] (Timeout getting file): [{str(e)}]"
                )
            )
        except Exception as e:
            raise (
                Exception(
                    f"Error: Could not download file [{file_path}] to [{destinationPath}] (Unknown Reason): [{str(e)}]"
                )
            )
        finally:
            if input_pbar is None:
                pbar.close()
            # Otherwise, don't close it because we will keep using it

        pbar.reset()
        return

    # taken from attack_range
    @staticmethod
    def get_random_password(
        password_min_length: int = 16, password_max_length: int = 26
    ) -> str:
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

    @staticmethod
    def warning_print(
        msg: str, prefix: str = "MESSAGE TO CONTENTCTL DEV", suppress=False
    ):
        if not suppress:
            print(f"{prefix}: {msg}")

    @staticmethod
    def getFixedWidth(num: float, decimal_places: int) -> str:
        fstring = "{:." + str(decimal_places) + "f}"
        return fstring.format(num)

    @staticmethod
    def getPercent(numerator: float, denominator: float, decimal_places: int) -> str:
        if denominator == 0:
            return "UKNOWN"
        ratio = numerator / denominator
        percent = ratio * 100
        return Utils.getFixedWidth(percent, decimal_places) + "%"
