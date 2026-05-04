# Update SessionsController notify methods to persist provisioning conflicts

module SessionsControllerPatches
  def notify_admin_of_conflict(existing_user, email, ldap_dn)
    ProvisioningConflict.create!(email: email, ldap_dn: ldap_dn, existing_user: existing_user)

    Rails.logger.error("[LDAP] Provisioning conflict for email=#{email}, existing_user_id=#{existing_user&.id}, ldap_dn=#{ldap_dn}")
    Rollbar.error("LDAP provisioning conflict for #{email}") if defined?(Rollbar)
    ActiveSupport::Notifications.instrument('ldap.provision_conflict', email: email, user_id: existing_user&.id, ldap_dn: ldap_dn)
  end

  def notify_admin_of_existing_local(existing_user, auth)
    ProvisioningConflict.create!(email: existing_user.email, ldap_dn: auth[:dn], ldap_attributes: auth[:attributes], existing_user: existing_user)

    Rails.logger.error("[LDAP] Local user exists for email=#{existing_user.email}; automatic linking disabled. ldap_dn=#{auth[:dn]}")
    Rollbar.info("LDAP found local user for #{existing_user.email}; admin linking required") if defined?(Rollbar)
    ActiveSupport::Notifications.instrument('ldap.existing_local', email: existing_user.email, user_id: existing_user.id, ldap_dn: auth[:dn])
  end

  def notify_admin_missing_mapping(auth)
    ProvisioningConflict.create!(email: (auth[:attributes]['mail'] || []).first, ldap_dn: auth[:dn], ldap_attributes: auth[:attributes])

    Rails.logger.error("[LDAP] Missing account mapping for ldap_dn=#{auth[:dn]}, attrs=#{auth[:attributes].keys}")
    Rollbar.error('LDAP missing account mapping') if defined?(Rollbar)
    ActiveSupport::Notifications.instrument('ldap.missing_mapping', ldap_dn: auth[:dn], attrs: auth[:attributes])
  end
end
