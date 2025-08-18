FROM python:3.14.0a7-bookworm

# dependencies
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y xinetd
RUN rm -rf /var/lib/apt/lists/*

# setup unpriv user
RUN mkdir /ctf
RUN useradd -M -d /ctf ctf

# copy files
RUN echo "Connection blocked" > /etc/banner_fail
COPY ctf.xinetd /etc/xinetd.d/ctf
COPY ./src /ctf/

# file perms
RUN chown -R root:ctf /ctf 
RUN chmod -R 750 /ctf

# run
EXPOSE 40000
CMD ["/usr/sbin/xinetd", "-dontfork"]
