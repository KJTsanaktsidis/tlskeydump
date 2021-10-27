#!/usr/bin/env ruby
require_relative 'spec_helper'

# This spec file runs all the various builds of the client program, with OpenSSL debug
# symbols available in different ways.
# tlskeydump should be able to find the debug symbols for all of these.

describe 'finding debuginfo' do
    it 'works with debug symbols compiled into the binary' do
        testprog_lines, tlskeylog_lines = run_tlskeylog_test_program(
            testprog: OPENSSL_1_1_1_TESTPROG_DYN_DBG_CLIENT_EXE,
            tlskeylog_args: ["--debug-dir", File.join(OPENSSL_1_1_1_DBG_PREFIX, "debug")],
        )

        assert_equal testprog_lines, tlskeylog_lines
        assert_equal testprog_lines.size, 5 # 5 lines means TLSv1.3
    end

    it 'works with symbols in a .build-id directory' do
        testprog_lines, tlskeylog_lines = run_tlskeylog_test_program(
            testprog: OPENSSL_1_1_1_TESTPROG_DYN_BUILDID_CLIENT_EXE,
            tlskeylog_args: ["--debug-dir", File.join(OPENSSL_1_1_1_BUILDID_PREFIX, "debug")],
        )

        assert_equal testprog_lines, tlskeylog_lines
        assert_equal testprog_lines.size, 5
    end
end
