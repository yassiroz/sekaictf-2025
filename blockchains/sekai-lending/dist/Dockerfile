FROM snwo/sekai-lending:1337

ADD ./framework/chall /work/framework/chall
ADD ./framework/src/main.rs /work/framework/src/

WORKDIR /work/framework/chall
RUN sui move build

WORKDIR /work/framework

RUN touch src/main.rs

EXPOSE 31337

CMD cargo r --release