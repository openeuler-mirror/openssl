#! /usr/bin/env perl
# Copyright 2022 Huawei Technologies Co., Ltd. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT data_file/;

setup("test_tlcp");

plan skip_all => "TLCP is not supported by this OpenSSL build"
    if disabled("tlcp");

plan tests => 1;

ok(run(test(["tlcptest",
            data_file("sm2-root-cert.pem"),             # 0
            data_file("sm2-server-sig-cert.pem"),       # 1
            data_file("sm2-server-sig-key.pem"),        # 2
            data_file("sm2-server-enc-cert.pem"),       # 3
            data_file("sm2-server-enc-key.pem"),        # 4
            data_file("sm2-client-sig-cert.pem"),       # 5
            data_file("sm2-client-sig-key.pem"),        # 6
            data_file("sm2-client-enc-cert.pem"),       # 7
            data_file("sm2-client-enc-key.pem"),        # 8
            data_file("ecdsa-root-cert.pem"),           # 9
            data_file("ecdsa-server-cert.pem"),         # 10
            data_file("ecdsa-server-key.pem"),          # 11
            data_file("ecdsa-client-cert.pem"),         # 12
            data_file("ecdsa-client-key.pem")           # 13
            ])));