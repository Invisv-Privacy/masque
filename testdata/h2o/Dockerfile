FROM alpine:3.19

ENV H2O_DOWNLOAD_SHA256 f8cbc1b530d85ff098f6efc2c3fdbc5e29baffb30614caac59d5c710f7bda201

RUN apk add --no-cache --virtual .build-deps \
                git \
                bison \
                build-base \
                cmake \
                curl \
                libuv-dev \
                linux-headers \
                openssl-dev \
                ruby \
                ruby-dev \
                wslay-dev \
                yaml-dev \
                zlib-dev \
                perl

# download H2O source code and verify integrity
RUN git clone --recurse-submodules https://github.com/h2o/h2o.git /usr/src/h2o

WORKDIR /usr/src/h2o/build

RUN cmake .. -DWITH_BUNDLED_SSL=on \
                 -DCMAKE_INSTALL_PREFIX=/usr \
                 -DWITH_MRUBY=off

RUN make

RUN make install

# install runtime dependencies
RUN apk add --no-cache --virtual .runtime-deps \
        libstdc++ \
        openssl \
        perl \
        zlib

RUN apk del .build-deps

# forward request and error logs to the docker log collector
RUN mkdir -p /var/log/h2o/
RUN ln -sf /dev/stdout /var/log/h2o/access.log
RUN ln -sf /dev/stderr /var/log/h2o/error.log

RUN mkdir /etc/h2o

EXPOSE 8444

CMD ["h2o", "--conf", "/etc/h2o/connect.conf"]
