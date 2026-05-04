# frozen_string_literal: true

require 'net/ldap'

class LdapAuthenticator
  class AuthenticationError < StandardError; end

  def initialize(login, password)
    @login = login.to_s
    @password = password.to_s
    @settings = Rails.application.config.x.ldap.settings
  end

  # Returns { dn: <user_dn>, attributes: { 'mail' => [...], ... } }
  def authenticate
    raise AuthenticationError, 'LDAP disabled' unless Rails.application.config.x.ldap.enabled?

    ldap = build_connection

    # If a bind DN is provided, first bind with it to perform a search
    if @settings[:bind_dn].present?
      ldap.auth(@settings[:bind_dn], @settings[:bind_password])
      raise AuthenticationError, 'LDAP bind failed' unless ldap.bind

      user_dn, attrs = find_user_dn(ldap)
    else
      user_dn = build_user_dn(@login)
      attrs = {}
    end

    # Try to bind as the user with provided password
    user_ldap = build_connection
    user_ldap.auth(user_dn, @password)
    raise AuthenticationError, 'Invalid credentials' unless user_ldap.bind

    { dn: user_dn, attributes: attrs }
  rescue Net::LDAP::Error => e
    raise AuthenticationError, e.message
  end

  private

  def build_connection
    opts = { host: @settings[:host], port: @settings[:port] }
    case @settings[:encryption].to_s
    when 'start_tls'
      opts[:encryption] = { method: :start_tls }
    when 'simple_tls'
      opts[:encryption] = { method: :simple_tls }
    end
    Net::LDAP.new(opts)
  end

  def find_user_dn(ldap)
    uid_attr = @settings[:uid_attribute] || 'uid'
    filter = Net::LDAP::Filter.eq(uid_attr, @login)
    treebase = @settings[:base]
    result = ldap.search(base: treebase, filter: filter, attributes: ['dn', '*']).first
    raise AuthenticationError, 'User not found in LDAP' unless result

    dn = result.dn
    attrs = {}
    result.each do |entry|
      entry.each do |attr, values|
        attrs[attr] = values
      end
    end
    [dn, attrs]
  end

  def build_user_dn(login)
    uid_attr = @settings[:uid_attribute] || 'uid'
    "#{uid_attr}=#{login},#{@settings[:base]}"
  end
end
