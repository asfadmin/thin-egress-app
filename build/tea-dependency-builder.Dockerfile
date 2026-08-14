FROM public.ecr.aws/lambda/python:3.12

RUN dnf install -y git zip
RUN pip install pip-tools
