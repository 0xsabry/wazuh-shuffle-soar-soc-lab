# Security and Public Evidence

This repository describes a security lab. Treat screenshots, logs, sample configurations, and exported workflow results as potentially sensitive before publishing them.

## Publishing evidence

- Remove credentials, bearer tokens, webhook identifiers, account email addresses, and identifying user details from screenshots and logs.
- Use reserved or clearly synthetic values in examples. Do not publish live tailnet addresses or real webhook URLs.
- Store actual API keys and passwords in the relevant secret store; do not place them in source files or workflow exports.
- The gallery is illustrative evidence, not a guarantee that every workflow or configuration is currently deployable. Follow the setup guide and validate against the Wazuh and Shuffle versions in your own isolated lab.

## If a secret was published

Assume it is compromised. Revoke or rotate it at the issuing service first. Removing or replacing a file in a later commit does not erase the original blob from Git history, forks, caches, or existing clones. For historical removal, coordinate a repository history rewrite and GitHub's sensitive-data removal process after rotating the credential.

