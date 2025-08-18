FROM ubuntu@sha256:440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076

RUN apt-get update && \
    apt-get install -y wget supervisor openssh-server libfuse3-3 vulkan-tools libvulkan1 fuse3

RUN echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config && \
    mkdir /var/run/sshd && \
    useradd -m user -s /bin/bash && \
    passwd -d user

RUN echo "user_allow_other\nmount_max=1" >> /etc/fuse.conf

RUN useradd -m quandale
RUN chmod 755 /home/quandale

COPY supervisord.conf /etc/supervisord.conf

COPY --chown=quandale:quandale start.sh /home/quandale/
COPY --chown=quandale:quandale vkfs /home/quandale/
COPY --chown=quandale:quandale flag.txt /home/quandale

RUN chmod 700 /home/quandale/start.sh
RUN chmod 700 /home/quandale/vkfs
RUN chmod 400 /home/quandale/flag.txt

COPY entrypoint.sh /root
RUN chmod +x /root/entrypoint.sh

ENTRYPOINT ["/root/entrypoint.sh"]
