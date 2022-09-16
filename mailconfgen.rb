require 'yaml'
require 'fileutils'
require 'erb'

class VirtualUsers
  include Enumerable

  def initialize(data)
    @data = data
  end

  def each
    @data['domains'].each do |domain, domaindata|
      domaindata['addresses'].each do |addr, virtual_users|
        virtual_users = domaindata['default'] if virtual_users.nil? or virtual_users.empty?
        virtual_users = [virtual_users] if virtual_users.is_a?(String)
        virtual_users = virtual_users.map {|vu| validate_virtual_user(vu)}
        yield "#{addr}@#{domain}", virtual_users
      end
    end
  end

  private def validate_virtual_user(vu)
    if vu.start_with?("/")
      vu = vu.delete_prefix("/")
      # This is an account
      if @data['accounts'].has_key?(vu)
        vu
      else
        raise "No account found for virtual user alias #{vu}"
      end
    else
      raise unless vu.include?("@")
      vu
    end
  end
end

class Accounts
  include Enumerable

  def initialize(data)
    @data = data
  end

  def each
    @data['accounts'].each do |name, accountdata|
      yield Account.new(name: name, data: accountdata, cred: @data['creds'][name])
    end
  end
end

class Account
  def initialize(name:, data:, cred:)
    @name, @data, @cred = name, data, cred
  end

  def name() = @name
  def uid() = Integer(@data['uid'] || raise).to_s
  def gid() = Integer(@data['gid'] || raise).to_s
  def home() = @data['home'] || raise

  def cred(for_service:)
      case @cred
      when Hash
        validate_account_cred(@cred[for_service], for_service)
      when String
        validate_account_cred(@cred, for_service)
      else
        raise
      end
  end

  private def validate_account_cred(cred, for_service)
    case for_service
    when "smtpd" 
      if cred.start_with?("{SHA256-CRYPT}")
        cred.delete_prefix("{SHA256-CRYPT}")
      elsif cred.start_with?("{")
        raise
      else
        cred
      end
    when "dovecot"
      if cred.start_with?("{")
        cred
      else
        raise
      end
    else
      raise "Invalid service #{for_service}"
    end
  end
end

class MailConf
  def self.from_yaml_files(*filenames)
    new(data: {}.merge(*filenames.map {|f| YAML.load_file(f) }))
  end

  def initialize(data:)
    @data = data
  end

  attr_reader :data

  def allowed_recipients
    @data['domains'].map do |domain, values|
      (values['addresses'] || []).map {|addr, _| "#{addr}@#{domain}"}
    end.flatten
  end

  def accounts
    Accounts.new(@data)
  end

  def domains
    @data['domains'].keys
  end

  # Returns a mapping of email address -> account/email addresses
  def virtual_users
    VirtualUsers.new(@data)
  end
end

class ConfFile
  attr_reader :name, :absolute_path, :out

  def initialize(name:, absolute_path:, out:)
    @name = name
    @absolute_path = absolute_path
    @out = out
  end
end

class TemplateModel
  VERSION = '0.0.1'

  def initialize(conf, gen)
    @conf, @gen = conf, gen
    @defines_file = nil
  end

  def get_binding
    binding
  end

  def defines_file(filename=nil)
    if filename
      @defines_file = filename
    else
      @defines_file
    end
  end

  def absolute_file_path(filename)
    @gen.file(filename).absolute_path
  end

  def requires_version(version)
    raise "Template / Generator version mismatch" unless version == VERSION
  end

  def opensmtpd_filter_dkimsign_params
    dkimsign_params = @conf.domains.map {|dom| "-d #{dom}"}
    dkimsign_params << "-s #{confval!('dkimsign.selector')}"
    dkimsign_params << "-k #{confval!('dkimsign.key')}"
    dkimsign_params.join(" ")
  end

  def confval!(key)
    value = confval(key)
    raise "Value is nil (key: #{key})" if value.nil?
    value
  end

  def confval(key)
    value = @conf.data
    for part in key.split('.')
      raise "No value for key #{key} (part: #{part}, value: #{value})" unless value.is_a? Hash
      value = value[part]
    end
    value
  end
end

class MailConfGen
  def self.from_yaml_conf(*files)
    new(conf: MailConf.from_yaml_files(*files))
  end

  def initialize(conf:)
    @files = {}
    @filemap = {}
    @conf = conf
  end

  def map_files_relative_to_root(*files, root:)
    raise unless root
    relative_to_root = -> f { File.join(root, f) }

    for file in files
      @filemap[file] = relative_to_root
    end
    self
  end

  def file(filename)
    if absolute_path = @filemap[filename]
      if file_entry = @files[filename]
        file_entry
      else
        if absolute_path.is_a? Proc
          absolute_path = absolute_path.call(filename)
        end

        file_entry = ConfFile.new(name: filename, absolute_path: absolute_path, out: [])
        @files[filename] = file_entry
        file_entry
      end
    else
      raise "File #{filename} not allowed"
    end
  end

  def generate(service:)
    Dir["templates/#{service}/*.erb"].each {|t| run_template(template: t)}
    self
  end

  def write_files_relative_to!(root)
    FileUtils.mkdir_p(root)
    for file in @files.values
      data = file.out.join("\n") + "\n"
      path = File.join(root, file.absolute_path)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, data)
    end
  end

  private def run_template(template:)
    model = TemplateModel.new(@conf, self)
    result = ERB.new(File.read(template), trim_mode: "-").result(model.get_binding)
    file(model.defines_file || raise).out << result
  end
end

if __FILE__ == $0
  case ARGV.shift
  when 'generate'
    MailConfGen
      .from_yaml_conf(*ARGV)
      .map_files_relative_to_root(
        "smtpd/smtpd.conf",
        "smtpd/allowed-recipients",
        "smtpd/virtual-users",
        "smtpd/virtual-user-base",
        "smtpd/passwd",
        "dovecot/dovecot.conf",
        "dovecot/passwd",
        root: '/etc/mail')
      .generate(service: 'smtpd')
      .generate(service: 'dovecot')
      .write_files_relative_to!('_stage')
  else
    raise "Usage: #{$0} generate [*.yml]"
  end
end
