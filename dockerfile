# Copyright (c) 2017 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:xenial

RUN apt-get update && \
	apt-get install -y git build-essential autoconf pkg-config libtool sudo check
RUN rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/JakubGrajciar/libmemif.git /libmemif
WORKDIR /libmemif
RUN git checkout dev
RUN ./bootstrap
RUN ./configure
RUN make
RUN make install

RUN mkdir /var/vpp

RUN ulimit -c unlimited

CMD ./.libs/icmp_responder
