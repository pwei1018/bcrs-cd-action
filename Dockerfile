FROM ubuntu:20.04

ARG OP_VERSION=1.8.0
ARG OC_VERSION=4.6

RUN apt-get update && apt-get install -y curl unzip jq && \
    curl -o 1password.zip https://cache.agilebits.com/dist/1P/op/pkg/v$OP_VERSION/op_linux_amd64_v$OP_VERSION.zip && \
    unzip 1password.zip -d /usr/local/bin && \
    rm 1password.zip

RUN curl -sLo /tmp/oc.tar.gz https://mirror.openshift.com/pub/openshift-v$(echo $OC_VERSION | cut -d'.' -f 1)/clients/oc/$OC_VERSION/linux/oc.tar.gz && \
    tar xzvf /tmp/oc.tar.gz -C /usr/local/bin/ && \
    rm -rf /tmp/oc.tar.gz

CMD ["bash"]
