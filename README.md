# freedumb

Blog post: https://awsteele.com/blog/2020/11/02/nitro-enclaves-first-impressions.html

## Why shouldn't I use this in production?

Other than there being zero docs? Here are a few things you probably want to do first:

* Some error handling, rather than just exploding
* Send a non-zero nonce as part of the attestation document
* Store those nonces in a DynamoDB table and refuse to allow replayed requests for credentials
* Cred server should proactively refresh credentials in the background every N hours to avoid latency
* Probably worth switching to web identity federation as that would be more general purpose than just AWS IAM
* Just don't do it, ok
