import os
from detect_secrets.core import baseline
from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
from detect_secrets.settings import default_settings, get_settings

def get_commit_sha():
    """
    To be implemented
    :return: Commit sha
    """
    return ""

def get_branch():
    """
    To be implemented
    :return: Branch to which the commit was made
    """
    return ""

def get_baseline():
    """
    To be implemented
    :return: Previous Baseline of the customer
    """

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

if __name__ == '__main__':
    secret_collection = SecretsCollection()
    prev_baseline = get_baseline()
    config = get_config()
    commit_id = get_commit_sha()
    branch = get_branch()
    if prev_baseline:
        SecretsCollection().load_from_baseline(prev_baseline)
    file_mapping = get_file_mapping()
    try:
        file_secrets = SecretsCollection()
        file_secrets.scan_files(*(file_mapping.keys()))
        file_secrets.rename_files(filelist=file_mapping)
        file_secrets.add_commit(commit_id)
        file_secrets.add_branch(branch)
