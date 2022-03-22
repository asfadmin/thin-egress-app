# Thin Egress App
## Purpose of TEA

TEA is a fully Earthdata Cloud (EDC) compliant application to enable
distribution of EOSDIS data from Amazon S3 while ensuring data
providers have all the tools, controls and metrics required for data
distribution restriction and reporting compliance. TEA Distribution supports
only static S3 data, and is not intended for service-style or dynamic data
distribution.

This documentation is intended to support stand-alone TEA deployments, and
while it may be a valuable tool for TEA deployments provisioned through
Cumulus, we suggest you visit the
[Cumulus documentation](https://nasa.github.io/cumulus/docs/deployment/thin_egress_app)
for guidance on using and customizing TEA from within Cumulus.

## Make it better

Join us on this journey! Together we can make TEA better!

### Contribute

We love contributions from outside the team! We have 2 requirements for
accepting contributions:

* All contributions should conform to our [TEA Vision](vision.md)
* Contributions should come with unit tests to validate the feature

### Requesting features

If you have a feature you'd like to request, first confirm the feature
aligns with our [TEA Vision](vision.md). If you think the feature
belongs in TEA, you have TWO options:

* Request the feature using [Github Issue](https://github.com/asfadmin/thin-egress-app/issues)
* Request the feature in the `#tea-pot` Slack Channel

## History of TEA

TEA was originally designed as a lightweight S3 distribution application with Earthdata Login
(EDL) support meant to help test and evaluate the (then) forethcoming NGAP Enterprise Egress
platform. TEA leveraged much of the design and features of ASF's original full-featured s3
distribution app, without any of the throttling or egress tracking capabilities. Without the
need to do throttling, TEA ditched docker/nginx/ECS in favor of the lighter, more nimble
Lambda + API Gateway architecture.
