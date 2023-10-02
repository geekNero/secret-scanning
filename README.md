# secret-scanning v1
This action scans your repository under `$GITHUB_WORKSPACE` for any potential secrets such as AWS_ACCESS_KEY and 
notifies. Secret log is maintained if you are Cloudanix client.

# Usage
<!-- start usage -->
```yaml
- uses: geek-nero/secret-scanning@v1
  with: 
    # Complete file paths of the files to be excluded from scanning, seprated by commas, avoid adding unnecessary spaces.
    file-exclusions: "file1.txt,file2.txt"
    # Add comma seprated hashes of the secret you want to skip, avoid adding unnecessary spaces.
    hash-exclusions: "a79abde231aa49cf3ef6f0a0856730860bbd1894"
    # Add comma seprated plugins or regex names to exclude, avoid adding unnecessary spaces.
    plugin-exclusions: "GitHub Token"
    # Add space sperated regexes to exclude scanning with those regexes, avoid adding unneccessary spaces. In this case
    # the regexes would be "foo" and "bar".
    custom-regexes: "foo bar"
```
<!-- end usage -->

# Client Only:

Build should contain the following variables in environment to send response to backend:

- CDX_API_ENDPOINT
- CDX_AUTHZ_TOKEN
- SECRET_KEY

They can be added using GitHub secrets.