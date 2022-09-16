require 'yaml'
require 'fileutils'

def error_context(context)
  begin
    yield
  rescue
    raise "#{context}: #{$!}"
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

  def list_allowed_recipients
    @data['domains'].map do |domain, values|
      (values['addresses'] || []).map {|addr, _| "#{addr}@#{domain}"}
    end.flatten
  end

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

  def accounts
    @data['accounts']
  end

  def domains
    @data['domains'].keys
  end

  # Returns a mapping of email address -> account/email addresses
  def virtual_users
    VirtualUsers.new(@data)
  end

  def list_account_creds(for_service:)
    @data['accounts'].keys.map {|account|
      entry = @data['creds'][account]
      cred = case entry
      when Hash
        entry[for_service]
      when String
        entry
      else
        raise
      end
      [account, validate_account_cred(cred, for_service)]
    }.to_h
  end

  def validate_account_cred(cred, for_service)
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

class ConfFile
  attr_reader :name, :absolute_path, :out

  def initialize(name:, absolute_path:, out:)
    @name = name
    @absolute_path = absolute_path
    @out = out
  end
end

class ConfGen
  def initialize(filemap:)
    @files = {}
    @filemap = filemap
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
end

# Generator for OpenSMTPd `smtpd.conf` and related files. 
class SmtpdConfGen < ConfGen
  def initialize(conf:)
    root = "/etc/smtpd"
    relative_to_root = -> f { File.join(root, f) }

    filemap = {
      "smtpd.conf" => relative_to_root,
      "allowed-recipients" => relative_to_root,
      "virtual-users" => relative_to_root,
      "virtual-user-base" => relative_to_root,
      "passwd" => relative_to_root,
    }
    super(filemap: filemap)
    @conf = conf
  end

  def generate
    gen_table_allowed_recipients
    gen_table_passwd
    gen_table_virtual_users
    gen_table_virtual_user_base
    gen_smtpd_conf
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

  private def gen_smtpd_conf
    out = file("smtpd.conf").out
    gen_smtpd_pki(out)
    gen_smtpd_filters(out)
    gen_smtpd_tables(out)
    gen_smtpd_listens(out)
    gen_smtpd_actions(out)
    gen_smtpd_matches(out)
  end

  private def gen_smtpd_actions(out)
    out << decl(<<~'END')
      action "local"
        lmtp "/var/run/dovecot/lmtp"
        virtual <virtual-users>
        userbase <virtual-user-base>
      END

    out << decl(<<~"END")
      action "outbound"
        relay
        helo "#{confval! 'server.name'}"
      END
  end

  private def gen_smtpd_matches(out)
    out << decl(<<~"END")
      match
        from any
        for rcpt-to <allowed-recipients>
        action "local"
      END
    out << decl(<<~"END")
      match
        from any
          auth
        for any
        action "outbound"
      END
  end

  private def gen_smtpd_pki(out)
    out << %(pki pki_#{confval! 'server.name'} cert "#{confval! 'server.pki.cert'}")
    out << %(pki pki_#{confval! 'server.name'} key "#{confval! 'server.pki.key'}")
    out << "\n"
  end

  private def gen_smtpd_filters(out)
    out << decl(<<~'END')
      filter check_dyndns phase connect match rdns regex
        { '.*\.dyn\..*', '.*\.dsl\..*' }
        disconnect "550 no residential connections
      END

    out << decl(<<~'END')
      filter check_rdns phase connect match !rdns
        disconnect "550 no rDNS is so 80s"
      END

    out << decl(<<~'END')
      filter check_fcrdns phase connect match !fcrdns
        disconnect "550 no FCrDNS is so 80s"
      END

    out << decl(<<~'END')
      filter senderscore
        proc-exec "opensmtpd-filter-senderscore -blockBelow 10 -junkBelow 70 -slowFactor 5000"
      END

    dkimsign_params = @conf.domains.map {|dom| "-d #{dom}"}
    dkimsign_params << "-s #{confval!('dkimsign.selector')}"
    dkimsign_params << "-k #{confval!('dkimsign.key')}"

    out << decl(<<~"END")
      filter dkimsign
        proc-exec "opensmtpd-filter-dkimsign #{dkimsign_params.join(' ')}"
        user _dkimsign group _dkimsign
      END

  end

  private def gen_smtpd_tables(out)
    for table in %w(allowed-recipients virtual-users virtual-user-base passwd) 
      out << decl_file_table(table)
    end
    out << "\n"
  end

  private def confval(key)
    value = @conf.data
    for part in key.split('.')
      raise "No value for key #{key} (part: #{part}, value: #{value})" unless value.is_a? Hash
      value = value[part]
    end
    value
  end

  private def confval!(key)
    value = confval(key)
    raise "Value is nil (key: #{key})" if value.nil?
    value
  end

  private def gen_smtpd_listens(out)
    iface = confval! 'server.iface'
    name = confval! 'server.name'
    out << "# Public"
    out << decl(<<~"END")
      listen on #{iface}
        port smtp
        tls
        pki pki_#{name}
        hostname "#{name}"
        filter { check_dyndns, check_rdns, check_fcrdns, senderscore }
      END
    out << "# Auth submission"
    out << decl(<<~"END")
      listen on #{iface}
        port submission
        tls-require
        pki pki_#{name}
        hostname "#{name}"
        auth <passwd>
        filter dkimsign
      END
  end

  private def decl_file_table(name)
    "table #{name} file:#{file(name).absolute_path}"
  end

  private def gen_table_allowed_recipients
    file("allowed-recipients").out << table_list(@conf.list_allowed_recipients)
  end

  private def gen_table_passwd
    data = @conf.list_account_creds(for_service: "smtpd")
    file("passwd").out << table_map(data)
  end

  private def gen_table_virtual_users
    data = @conf.virtual_users.to_h.transform_values{|addrs| addrs.join(",") }
    file("virtual-users").out << table_map(data)
  end

  private def gen_table_virtual_user_base
    data = @conf.accounts.transform_values {|account| account.values_at('uid', 'gid', 'home').join(":") }
    file("virtual-user-base").out << table_map(data)
  end

  private def decl(s)
    s.split("\n").join(" \\\n ") + "\n"
  end

  private def table_list(values)
    linify(values)
  end

  private def table_map(pairs)
    linify(pairs.map {|k,v| [k,v].join("\t")})
  end

  private def linify(items)
    items.join("\n")
  end

end

if __FILE__ == $0
  conf = MailConf.from_yaml_files("sample.yml", "sample-creds.yml")
  SmtpdConfGen
    .new(conf: conf)
    .generate
    .write_files_relative_to!('_stage')
end
