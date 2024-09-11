FROM public.ecr.aws/lambda/python:3.10

RUN yum install -y git zip
RUN pip install pip-tools
