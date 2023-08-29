import os
from tabulate import tabulate
from detect_secrets.core import baseline
from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
from detect_secrets.settings import default_settings, get_settings
from typing import List, Any


def parse_secrets(secrets: Any, commit: str, exclusions: List) -> list:
    new_secrets = []
    secrets = secrets.json()
    for group in secrets:
        for secret in secrets[group]:
            new_secret = {
                "commitHash": commit,
                "fileName": secret['filename'],
                "lineNumber": secret['line_number'],
                "regex": secret['type'],
                "hashedValue": secret['hashed_secret'],
                "isHashedValueSkipped": secret['notify'],
                "branch": secret['branch'],
            }
            if secret["is_verified"]:
                new_secret["isVerified"] = True
                new_secret["isValid"] = True
            elif not secret["is_verified"]:
                new_secret["isVerified"] = True
                new_secret["isValid"] = False
            else:
                new_secret["isVerified"] = False
                new_secret["isValid"] = None
            if new_secret["hashedValue"] not in exclusions:
                new_secrets.append(new_secret)
    return new_secrets


def get_commit_sha():
    """
    :return: Commit sha
    """
    return os.environ["GITHUB_SHA"]


def get_branch():
    """
    :return: Branch to which the commit was made
    """
    return os.environ["GITHUB_REF_NAME"]


def get_baseline():
    """
    To be implemented
    :return: Previous Baseline of the customer
    """
    return None


def get_config():
    """
    To be implemented
    :return: Config for secret scanning
    """
    plugins_used = []
    with default_settings():
        plugins = list(get_settings().plugins.keys())

        for plugin in plugins:
            plugins_used.append({'name': plugin})
    config = {
        'plugins_used': plugins_used,
    }

    return config


def get_file_mapping():
    root_dir = "action"
    file_map = dict()

    for dir_, _, files in os.walk(root_dir):
        for file_name in files:
            path = os.path.join(dir_, file_name)
            file_map[path] = os.path.relpath(path, root_dir)
    return file_map


def print_table(secrets):
    headers = list(secrets[0].keys())
    display_headers = ["Commit Hash","File Name", "Line Number","Regex", "Hashed Value", "Is HashedValue Skipped", "Branch", "Is Verified", "Is Valid"]
    table_data = [[entry[key] for key in headers] for entry in secrets]
    table = tabulate(table_data, headers=display_headers, tablefmt='grid')
    print(table)


def send_diff(secrets):
    """
    To be implemented
    :param secrets:
    :return: None
    Sends the new secrets found to rails backend
    """


def upload_baseline():
    """
    To be implemented
    :return: None
    Uploads the baseline file to respective bucket
    """


if __name__ == '__main__':
    secret_collection = SecretsCollection()
    prev_baseline = get_baseline()
    config = get_config()
    commit_id = get_commit_sha()
    branch = get_branch()
    if prev_baseline:
        secret_collection = SecretsCollection().load_from_baseline(prev_baseline)
    file_mapping = get_file_mapping()
    # try:
    new_secrets = SecretsCollection()
    new_secrets.scan_files(*(file_mapping.keys()))
    new_secrets.rename_files(filelist=file_mapping)
    new_secrets.add_commit(commit_id)
    new_secrets.add_branch(branch)
    diff_secrets = secret_collection.get_diff(new_secrets)
    temp = SecretsCollection()
    all_secrets = temp.get_diff(new_secrets)
    print_table(all_secrets)
    del temp
    send_diff(diff_secrets)
    baseline.save_to_file(new_secrets, ".new_baseline")
    upload_baseline()
    # except Exception as e:
    #     print(f"Secret Scanning Failed: {e}")
