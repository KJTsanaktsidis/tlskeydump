ENV['BUNDLE_GEMFILE'] = "#{__dir__}/Gemfile"
require 'bundler/setup'

require 'fileutils'
require 'rake'
require 'open3'
require 'forwardable'
require 'optparse'

include FileUtils
extend Forwardable
def_delegators File, :directory?, :join, :basename, :dirname, :absolute_path

def build_id_for_file(so)
    stdout, status = Open3.capture2('readelf', '--notes', so)
    raise "readelf failed" unless status.success?
    stdout.split("\n\n").find { |l|
     l.strip.lines[0] =~ /\.note\.gnu\.build-id/
    } =~ /Build ID: ([A-Za-z0-9]+)/
    raise "could not find build id for #{so}" unless $1
    return $1.downcase
end

openssl_prefix = nil
openssl_srcdir = nil
debug_sym_mode = nil
OptionParser.new do |opts|
    opts.on("--prefix=PREFIX", "prefix") do |p|
        openssl_prefix = p
    end
    opts.on("--srcdir=SRCDIR", "srcdir for openssl") do |p|
        openssl_srcdir = p
    end 
    opts.on("--symtype=SYMTYPE", "which type of build symbols") do |s|
        debug_sym_mode = s.to_sym
    end
end.parse!

# Configure, make, make install into the build directory
sh join(openssl_srcdir, 'config'), '-d', "--prefix=#{openssl_prefix}"
sh 'make'
sh 'make', 'install_sw', 'install_ssldirs'

# Some toolchains will produce openssl in a lib64 instead of a lib directory.
# Paper over this with a symlink.
if !directory?(join(openssl_prefix, "lib")) && directory?(join(openssl_prefix, "lib64"))
    ln_s "lib64", join(openssl_prefix, "lib")
end

if debug_sym_mode == :buildid
    # Copy all the shared objects to the debug directory
    # Strip the symbols from the originals
    # Strip everything else from the copies
    Dir[join(openssl_prefix, "lib/*.so")].each do |so|
        build_id = build_id_for_file so
        debug_file_location = join(openssl_prefix, "debug/.build-id", build_id[0...2], build_id[2..-1] + ".debug")
        mkdir_p dirname(debug_file_location)
        cp so, debug_file_location

        sh "strip", "--strip-debug", so
        sh "strip", "--only-keep-debug", debug_file_location
    end
elsif debug_sym_mode == :strip
    Dir[join(openssl_prefix, "lib/*.so")].each do |so|
        sh "strip", "--strip-debug", so
    end
elsif debug_sym_mode == :dbg
    # do nothing
elsif debug_sym_mode == :debuglink
    # Symbols in $DEBUG_DIR/$PREFIX/file.so
    Dir[join(openssl_prefix, "lib/*.so")].each do |so|
        debug_file_location = join(openssl_prefix, "debug", absolute_path(so) + ".debug")
        mkdir_p dirname(debug_file_location)
        cp so, debug_file_location

        sh "strip", "--only-keep-debug", debug_file_location
        sh "strip", "--strip-debug", so
        sh "objcopy", "--add-gnu-debuglink", debug_file_location, so
    end
else
    raise "Unknown debug sym mode #{debug_sym_mode}"
end

