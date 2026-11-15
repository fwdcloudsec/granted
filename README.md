<p align="center"><img src="./docs/logo.svg" height="80" /></p>

<h1 align="center">Granted</h1>
<p align="center">The easiest way to access your cloud.</p>

<p align="center">
<a align="center" href="https://twitter.com/intent/tweet?url=https%3A%2F%2Fgranted.dev&text=I%20just%20used%20Granted%20to%20log%20in%20to%20all%20my%20AWS%20accounts%20at%20once%21"><img src="https://img.shields.io/twitter/url/https/github.com/tterb/hyde.svg?style=social" alt="tweet" /></a>
<a href="https://fwdcloudsec.org/forum/"><img src="https://img.shields.io/badge/slack-fwd:cloudsec-1F72FE.svg?logo=slack" alt="slack" /></a>
</p>

<p align="center">
    <a href="https://docs.granted.dev/getting-started">🚀 Get Started</a>
</p>

<p align="center">
    <a href="https://granted.dev" alt="visit the Granted website">
        <img src="./docs/demo.gif">
    </a>
</p>

<br/>

## What is Granted?

Granted is a command line interface (CLI) application which simplifies access to cloud roles and allows multiple cloud accounts to be opened in your web browser simultaneously. The goals of Granted are:

- Provide a fast experience around finding and assuming roles

- Leverage native browser functionality to allow multiple accounts to be accessed at once

- Encrypt cached credentials to avoid plaintext SSO tokens being saved on disk

## What does Granted work with?

Granted supports MacOS, Linux, and Windows. Our Windows support is less extensively tested than other platforms so if you run into any problems please [let us know](https://join.slack.com/t/commonfatecommunity/shared_invite/zt-q4m96ypu-_gYlRWD3k5rIsaSsqP7QMg).

Currently Granted supports accessing roles in AWS. If you'd like to see support for another cloud provider please [open an issue](https://github.com/fwdcloudsec/granted/issues/new)!

Granted works with profiles backed by IAM Identity Center (SSO), IAM users, `credential_process`, and `aws login` sessions (AWS CLI 2.32.0 or later; Granted runs `aws login` for you when the session is missing or expired), plus role chaining via `source_profile` on top of any of these.

To keep an `aws login` session in your keychain instead of the AWS CLI's plaintext cache, declare the profile with `granted_login_session` and route the CLI through Granted:

```ini
[profile personal]
granted_login_session = arn:aws:iam::123456789012:user/alice
credential_process    = granted credential-process --profile=personal
region                = us-east-1
```

Then `assume personal` signs you in (once per 12 hour session) and refreshes the 15 minute credentials from secure storage for as long as the session lasts. Profiles that `aws login` created itself (`login_session`) also work, using the CLI's own cache.

## Documentation

Get started by [reading our documentation](https://docs.granted.dev/getting-started).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to contribute. We welcome all contributors - [join our Slack](https://fwdcloudsec.org/forum/) to discuss the project!

See [MAINTAINERS.md](./MAINTAINERS.md) for the list of project maintainers.

## Security

See [SECURITY.md](./SECURITY.md) for security information, including how to report a vulnerability. You can view our full security documentation on the [Granted website](https://docs.granted.dev/security).
