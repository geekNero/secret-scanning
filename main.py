import os
import json
import requests
from tabulate import tabulate
from detect_secrets.core import baseline
from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
from detect_secrets.settings import default_settings, get_settings
from typing import List, Any
import magic
import hmac
import hashlib


class Validation:
    def __init__(self, headers: dict = None, url: str = None, method: str = "get"):
        self.headers = headers
        self.url = url
        self.method = method

    def parse_headers(self, secret):
        for key in self.headers:
            self.headers[key] = self.headers[key].replace("{secret}", secret)

    def validate(self, secret):
        self.parse_headers(secret)
        if self.method.lower() == "post":
            response = requests.post(url=self.url, headers=self.headers)
        else:
            response = requests.get(url=self.url, headers=self.headers)
        if response.status_code == 200:
            return True
        return False


def parse_secrets(secrets: Any, exclusions: List) -> list:
    new_secrets = []
    secrets = secrets.json()
    for group in secrets:
        for secret in secrets[group]:
            if secret['hashed_secret'] in exclusions:
                continue
            new_secret = {
                "commitHash": secret['commit'],
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


def fetch_params():
    """
    Uses config.json to fetch exclusions and custom regexes
    :return: exclusions: dict, custom_regex: list
    """
    with open('config.json') as f:
        conf = json.load(f)
    return conf["exclusions"], conf["custom-regex"]


def is_extension_binary(file_name, binary_extensions):
    file_extension = os.path.splitext(file_name)[1]
    if file_extension in binary_extensions:
        print(f"skipping binary file: {file_name}")
        return True
    return False


def is_content_binary(content, binary_mimetypes):
    # Initialize the magic library
    file_type_checker = magic.Magic(mime=True)

    # Determine the MIME type of the file
    mime_type = file_type_checker.from_buffer(content)

    # Check if the file is binary
    return mime_type in binary_mimetypes


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


def get_config(custom_regex, exclusions):
    """
    To be implemented
    :return: Config for secret scanning
    """
    plugins_used = []
    regexes = []
    with default_settings():
        plugins = list(get_settings().plugins.keys())
        for plugin in plugins:
            plugins_used.append({'name': plugin})

    for regex in custom_regex:
        regexes.append({'name': regex, 'regex': custom_regex[regex]})

    with open('default_regexes.json', 'r') as file:
        default_regex = json.load(file)
    regexes = regexes + default_regex['patterns']

    for i in regexes:
        val = repr(i['regex'])[1:-1]
        if val in exclusions:
            regexes.remove(i)
        else:
            i['regex'] = val
    mapping = {}
    with open('validations_mapping.json') as file:
        mapping = json.load(file)
    validations = []

    for name in mapping:
        val = Validation(headers=mapping[name]["headers"], url=mapping[name]["url"], method=mapping[name]["method"])
        pair = {"name": name, "function": val.validate}
        validations.append(pair)
    config = {
        'plugins_used': plugins_used,
        'custom_regex': regexes,
        'verify': validations,
        'filters_used': [
            {"path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
             "min_level": 1,
             }
        ]
    }
    return config


def get_file_mapping(exclusions):
    root_dir = "actions"
    file_map = dict()
    with open("binary_extensions.json", 'r') as f:
        binary_extensions = f.read()
    with open("binary_mimetypes.json", 'r') as f:
        binary_mimetypes = f.read()

    for dir_, _, files in os.walk(root_dir):
        for file_name in files:
            path = os.path.join(dir_, file_name)
            mapping_path = os.path.relpath(path, root_dir)
            if mapping_path in exclusions:
                continue
            try:
                with open(path, 'r') as f:
                    content = f.read()
            except:
                continue
            if is_extension_binary(mapping_path, binary_extensions) or is_content_binary(content, binary_mimetypes):
                continue
            file_map[path] = mapping_path
    return file_map


def print_table(secrets):
    display_headers = ["Commit SHA", "File Name", "Line Number", "Plugin", "Is Verified", "Is Valid"]
    table_data = [[entry["commitHash"], entry["fileName"], entry["lineNumber"], entry["regex"], entry["isVerified"], entry["isValid"]] for entry in secrets]
    table = tabulate(table_data, headers=display_headers, tablefmt='grid')
    print(table)


def upload_response(secrets):
    """
    :return: None
    Uploads detected secrets to real-time backend
    """
    url = os.environ["CDX_API_ENDPOINT"]
    token = os.environ["CDX_AUTHZ_TOKEN"]
    secret_key = os.environ["SECRET_KEY"]
    headers = {
        "content-type": "application/json",
        'X-GitHub-Event': "push",
        "Authorization": f"token {token}"
    }
    data = {
        "organization": {
            "login": os.environ["GITHUB_REPOSITORY_OWNER"]
        },
        "repository": {
            "name": os.environ["GITHUB_REPOSITORY"]
        },
        "action": "github_rt_push_changes",
        "secretScanning": {"scan": {
            "CI": True,
            "repository": {
                "full_name": os.environ["GITHUB_REPOSITORY"],
                "branch": get_branch(),
                "commit": get_commit_sha(),
            },
            "secrets": secrets,
        },
            "sender": {
            "login": os.environ["GITHUB_TRIGGERING_ACTOR"]
        }
        }
    }
    digest = hmac.new(secret_key.encode('utf-8'), json.dumps(data, separators=(",", ":")).encode('utf-8'), hashlib.sha256)
    s = "sha256=" + digest.hexdigest()
    headers["X-Hub-Signature-256"] = s
    response = requests.post(url=url, data=data, headers=headers)
    if response.status_code == 200:
        print("Results updated succesfully")
    else:
        print("Failed to update results")


if __name__ == '__main__':
    exclusions, custom_regex = fetch_params()

    secret_collection = SecretsCollection()
    config = get_config(custom_regex, exclusions["regex"])
    commit_id = get_commit_sha()
    branch = get_branch()

    file_mapping = get_file_mapping(exclusions["file"])
    # try:
    with transient_settings(config=config):
        new_secrets = SecretsCollection()
        new_secrets.scan_files(*(file_mapping.keys()))
        new_secrets.rename_files(filelist=file_mapping)
        new_secrets.add_commit(commit_id)
        new_secrets.add_branch(branch)
        all_secrets = parse_secrets(new_secrets, exclusions["hash"])
        if all_secrets:
            print(f"Branch: {branch}")
            print_table(all_secrets)
        else:
            print("No Secrets Detected")
    upload_response(new_secrets.json())
    # except Exception as e:
    #     print(f"Secret Scanning Failed: {e}")
