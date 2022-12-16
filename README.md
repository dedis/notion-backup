# Notion backup

This repo provides a simple utility tool to perform automated and encrypted
backups of Notion blocks. Please see `mod.go` for usage.

## Get a Notion token

Check the following documentation to get a Notion token:
https://www.notion.so/Find-Your-Notion-Token-5da17a8df27a4fb290e9e3b5d9ba89c4.

This notion token (token_v2) is associated to your personal account and expires
after 3 months. Notion just recently added
[support](https://www.notion.so/Find-Your-Notion-Token-5da17a8df27a4fb290e9e3b5d9ba89c4)
for "service" token. We should eventually move to that once it is out of beta.