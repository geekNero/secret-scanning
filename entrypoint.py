import sys
import json

file_exclusions = []
hash_exclusions = []
regex_exclusions = []
custom_regexes = []

if sys.argv[1] != '0':
    file_exclusions = list(sys.argv[1].split(','))
if sys.argv[2] != '0':
    hash_exclusions = list(sys.argv[2].split(','))
if sys.argv[3] != '0':
    regex_exclusions = list(sys.argv[3].split())
if sys.argv[4] != '0':
    custom_regexes = list(sys.argv[4].split())

with open('cofig.json', 'w+') as f:
    json.dump({
        'exclusions': {
            'file': file_exclusions,
            'hash': hash_exclusions,
            'regex': regex_exclusions,
        },
        'custom-regex': custom_regexes
    }, f)
