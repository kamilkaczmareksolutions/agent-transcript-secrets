# Examples

Every token in this directory is synthetic. Each one contains `FAKE` or `EXAMPLE`, and the shapes are the wrong length or the wrong character set for GitHub secret scanning. They are fixtures for `agent-secrets scan examples/`. None of them is a credential.

`examples/clean/placeholders.json` holds the allowlisted placeholders `sk-xxx`, `your-api-key`, and `<TOKEN>`. A scan reports nothing in that file.

Cursor files under `agent-transcripts` are marked experimental in JSON output. The xAI sample uses the `xai-` prefix, which the README also marks experimental.
