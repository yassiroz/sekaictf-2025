FROM snwo/sekai-lending:1337

ADD ./framework/chall /work/framework/chall
ADD ./framework/src/main.rs /work/framework/src/

WORKDIR /work/framework/chall
RUN sui move build

WORKDIR /work/framework
RUN touch src/main.rs

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

EXPOSE 31337

ENTRYPOINT ["/entrypoint.sh"]