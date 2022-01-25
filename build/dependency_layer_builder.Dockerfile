FROM amazonlinux:2


ENV ZIPFILENAME=asf-ursdependencylayer.zip

RUN yum update -y && \
    yum install -y amazon-linux-extras && \
    amazon-linux-extras enable python3.8 && \
    yum install -y zip git python38 python38-pip && \
    rm -rf /var/cache/yum && yum clean all && mkdir -p /depbuild/pkg && mkdir -p /depbuild/out && mkdir /depbuild/in

ADD dependency_builder.sh /depbuild/
WORKDIR /depbuild

# When running, you must specify `-v /local/dir/you/want/zip/to/appear/in:/depbuild/out -v /local/dir/where/requirements.txt/lives:/depbuild/in`
# This will output the zipfile at /depbuild/out

CMD ["./dependency_builder.sh"]
