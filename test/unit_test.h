/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#ifndef _UNIT_TEST_H_
#define _UNIT_TEST_H_

#include <stdio.h>  
#include <string.h>

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define DEFAULT "\x1b[0m"

#define INFO(...) do {                                                          \
                    printf (DEFAULT"info: "__VA_ARGS__);                        \
                    printf ("\n");                                              \
                } while (0)

#define TEST_SET(...) do {                                                      \
                        printf (YELLOW"TEST SET: "__VA_ARGS__);                 \
                        printf (DEFAULT"\n");                                   \
                        printf ("=============================================\n");  \
                    } while (0)

#define TEST_OK(...) do {                                                       \
                        printf ("%-40s", DEFAULT"test: "__VA_ARGS__);           \
                        printf ("\t"GREEN"OK!"DEFAULT"\n");                     \
                    } while (0)

#define TEST_FAIL(...) do {                                                     \
                        printf ("%-40s", DEFAULT"test: "__VA_ARGS__);           \
                        printf ("\t"RED"FAIL!"DEFAULT"\n");                     \
                      } while (0)                                               \

#define ERROR(...) do {                                                         \
                        printf (RED"ERROR:"DEFAULT"%s:%d: ",__func__, __LINE__);\
                        printf (__VA_ARGS__);                                   \
                        printf ("\n");                                          \
                    } while (0)

#define UNIX_ERROR(...) do {                                                         \
                        printf (RED"UNIX ERROR:"DEFAULT"%s:%d: ",__func__, __LINE__);\
                        printf (__VA_ARGS__);                                   \
                        printf ("\n");                                          \
                    } while (0)

#define TEST_APP_NAME "unit_test_app"
#define TEST_IF_NAME  "unit_test_if"
#define TEST_SECRET   "psst"

#endif /* _UNIT_TEST_H_ */
