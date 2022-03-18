## History of TEA

TEA was originally designed as a lightweight S3 distribution application with Earthdata Login
(EDL) support meant to help test and evaluate the (then) forethcoming NGAP Enterprise Egress
platform. TEA leveraged much of the design and features of ASF's original full-featured s3
distribution app, without any of the throttling or egress tracking capabilities. Without the
need to do throttling, TEA ditched docker/nginx/ECS in favor of the lighter, more nimble
Lambda + API Gateway architecture.
