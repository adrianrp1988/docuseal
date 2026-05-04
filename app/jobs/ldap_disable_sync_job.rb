# frozen_string_literal: true

# Periodic job that checks LDAP for disabled accounts and archives local ldap_user users when they are disabled upstream.
class LdapDisableSyncJob < ApplicationJob
  queue_as :default

  def perform
    return unless Rails.application.config.x.ldap.enabled?

    settings = Rails.application.config.x.ldap.settings
    disabled_attribute = settings[:disabled_attribute]
    disabled_values = Array(settings[:disabled_values] || []).map(&:to_s)

    ldap = Net::LDAP.new(host: settings[:host], port: settings[:port])
    case settings[:encryption].to_s
    when 'start_tls'
      ldap.encryption(method: :start_tls)
    when 'simple_tls'
      ldap.encryption(method: :simple_tls)
    end

    if settings[:bind_dn].present?
      ldap.auth(settings[:bind_dn], settings[:bind_password])
      unless ldap.bind
        Rails.logger.error('[LDAP] Unable to bind with search account for disable sync')
        return
      end
    end

    User.where(ldap_user: true).find_each do |user|
      next if user.ldap_uid.blank?

      begin
        # Search the user entry by DN
        entry = ldap.search(base: user.ldap_uid, scope: Net::LDAP::SearchScope_BaseObject, attributes: [disabled_attribute]).first

        next unless entry

        if disabled_attribute.present? && disabled_values.any?
          val = Array(entry[disabled_attribute]).map(&:to_s)
          if (val & disabled_values).any?
            # Archive the local user
            user.update!(archived_at: Time.current)
            Rails.logger.info("[LDAP] Archived local user id=#{user.id} because LDAP reports disabled")
            ActiveSupport::Notifications.instrument('ldap.user_disabled', user_id: user.id, ldap_dn: user.ldap_uid)
          end
        end
      rescue Net::LDAP::Error => e
        Rails.logger.error("[LDAP] Error checking user #{user.id}: #{e.message}")
      end
    end
  end
end
