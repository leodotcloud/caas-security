FROM ubuntu:14.04
MAINTAINER leodotcloud@gmail.com

RUN apt-get update && \
    apt-get install -y curl vim tcpdump iptables ipset && \
    cp /usr/sbin/tcpdump /root/tcpdump

RUN mkdir -p /opt/rancher/bin

ADD run.sh /opt/rancher/bin/run.sh
ADD caas-security /opt/rancher/bin/caas-security

CMD ["/opt/rancher/bin/run.sh"]
