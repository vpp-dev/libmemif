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

AUTOMAKE_OPTIONS = foreign subdir-objects

#
# main lib
#
libmemif_la_SOURCES = src/main.c
lib_LTLIBRARIES = libmemif.la
include_HEADERS = src/libmemif.h

#
# ICMP responder example
#
icmp_responder_SOURCES = examples/icmp_responder/main.c
icmp_responder_LDADD = libmemif.la
icmp_responder_CPPFLAGS = $(AM_CPPFLAGS) -Isrc
noinst_PROGRAMS = icmp_responder
