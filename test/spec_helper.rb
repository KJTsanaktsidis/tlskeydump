# SPDX-License-Identifier: GPL-2.0-or-later

ENV['BUNDLE_GEMFILE'] = "#{__dir__}/Gemfile"
require 'bundler/setup'
require 'minitest/autorun'
require 'minitest/reporters'
require 'tempfile'

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

OPENSSL_1_1_1_TESTPROG_DYN_DBG_CLIENT_EXE = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_DBG_CLIENT_EXE'
OPENSSL_1_1_1_DBG_PREFIX = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_DBG_PREFIX'
OPENSSL_1_1_1_TESTPROG_DYN_BUILDID_CLIENT_EXE = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_BUILDID_CLIENT_EXE'
OPENSSL_1_1_1_BUILDID_PREFIX = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_BUILDID_PREFIX'
OPENSSL_1_1_1_TESTPROG_DYN_DEBUGLINK_CLIENT_EXE = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_DEBUGLINK_CLIENT_EXE'
OPENSSL_1_1_1_DEBUGLINK_PREFIX = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_DEBUGLINK_PREFIX'
OPENSSL_1_1_1_TESTPROG_DYN_DWZ_CLIENT_EXE = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_TESTPROG_DYN_DWZ_CLIENT_EXE'
OPENSSL_1_1_1_DWZ_PREFIX = ENV.fetch 'TLSKEYDUMP_TESTS__OPENSSL_1_1_1_DWZ_PREFIX'
TLSKEYLOG_EXE = ENV.fetch 'TLSKEYDUMP_TESTS__TLSKEYDUMP_EXE'

def run_tlskeylog_test_program(testprog:, tlskeylog_args: [], testprog_args: [])
    testprog_out = Tempfile.new('testprog_out')
    tlskeylog_out = Tempfile.new('tlskeylog_out')
    invocation = [
        TLSKEYLOG_EXE, '--out', tlskeylog_out.path, *tlskeylog_args, '--',
        testprog, testprog_out.path, *testprog_args,
    ]
    pid = ::Process.spawn(*invocation)
    _, status = ::Process.waitpid2(pid)
    raise "tlskeylog invocation #{invocation} failed: #{status}" unless status.success?

    testprog_lines = testprog_out.read.lines.map(&:chomp).sort
    tlskeylog_lines = tlskeylog_out.read.lines.map(&:chomp).sort

    return [testprog_lines, tlskeylog_lines]
end
