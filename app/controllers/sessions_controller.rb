# frozen_string_literal: true

class SessionsController < Devise::SessionsController
  before_action :configure_permitted_parameters

  around_action :with_browser_locale

  def create
    email = sign_in_params[:email].to_s.downcase

    # Attempt LDAP authentication first when enabled
    if Rails.application.config.x.ldap.enabled?
      login = email
      password = sign_in_params[:password]

      if login.present? && password.present?
        begin
          auth = LdapAuthenticator.new(login, password).authenticate

          # Find by stable mapping: ldap_uid
          user = User.find_by(ldap_uid: auth[:dn])

          if user
            Rails.logger.info("[LDAP] Successful login for #{login}, matched user id=#{user.id}")
            sign_in_and_redirect user, event: :authentication and return
          end

          # No local user found: attempt provisioning if enabled
          if Rails.application.config.x.ldap.settings[:create_users]
            mapped_account = map_ldap_to_account(auth[:attributes])

            # Determine email from LDAP attributes or fallback to login
            email_attr = (auth[:attributes]['mail'] || [login]).first&.downcase

            # If email already exists in DB, abort provisioning (no automatic linking)
            if email_attr.present?
              existing = User.find_by('lower(email) = ?', email_attr)

              if existing
                # If existing user belongs to a different account than the mapped account -> abort and alert
                if mapped_account && existing.account_id != mapped_account.id
                  Rails.logger.warn("[LDAP] Provisioning aborted: email #{email_attr} exists in different account (user=#{existing.id})")
                  notify_admin_of_conflict(existing, email_attr, auth[:dn])
                  flash[:alert] = I18n.t('ldap.provision_conflict', default: 'Account provisioning requires administrator approval. Please contact your administrator.')
                  return redirect_to new_session_path(resource_name)
                end

                # Existing local user found (same account or no mapping): do NOT auto-link; require admin to link
                Rails.logger.warn("[LDAP] Provisioning aborted: local user with email #{email_attr} exists; automatic linking is disabled")
                notify_admin_of_existing_local(existing, auth)
                flash[:alert] = I18n.t('ldap.provision_needs_admin', default: 'Your account must be linked by an administrator before signing in. Please contact your administrator.')
                return redirect_to new_session_path(resource_name)
              end
            end

            # If we cannot determine a mapped account, abort and alert
            if mapped_account.nil?
              Rails.logger.warn("[LDAP] Provisioning aborted: unable to map LDAP attributes to an account for #{login}")
              notify_admin_missing_mapping(auth)
              flash[:alert] = I18n.t('ldap.no_account_mapping', default: 'Unable to determine account for your organization. Please contact your administrator.')
              return redirect_to new_session_path(resource_name)
            end

            # Proceed to provision a new user linked to the mapped account
            user = User.new(
              email: email_attr || login,
              first_name: auth[:attributes]['givenName']&.first,
              last_name: auth[:attributes]['sn']&.first,
              ldap_uid: auth[:dn],
              ldap_user: true,
              account: mapped_account,
              role: 'user'
            )

            user.set_unusable_password!
            user.confirmed_at = Time.current if user.respond_to?(:confirmed_at)

            # Save without strict validations if LDAP data is incomplete; log for admin review
            if user.valid?
              user.save!
            else
              user.save!(validate: false)
              Rails.logger.info("[LDAP] Provisioned user #{user.email} with incomplete attributes; admin review required (user_id=#{user.id})")
            end

            Rails.logger.info("[LDAP] Provisioned new user id=#{user.id} for ldap_dn=#{auth[:dn]}")
            sign_in_and_redirect user, event: :authentication and return
          end
        rescue LdapAuthenticator::AuthenticationError => e
          Rails.logger.info("[LDAP] Authentication failed for #{login}: #{e.message}")
          Rollbar.warning("LDAP auth failed for #{login}: #{e.message}") if defined?(Rollbar)

          unless Rails.application.config.x.ldap.settings[:fallback_to_db]
            flash[:alert] = I18n.t('devise.failure.invalid', default: 'Invalid email or password.')
            return redirect_to new_session_path(resource_name)
          end
          # else fall through to DB authentication
        end
      end
    end

    # Existing local behavior and Devise checks
    if Docuseal.multitenant? && !User.exists?(email:)
      Rollbar.warning('Sign in new user') if defined?(Rollbar)

      return redirect_to new_registration_path(sign_up: true, user: sign_in_params.slice(:email)),
                         notice: I18n.t('create_a_new_account')
    end

    if User.exists?(email:, otp_required_for_login: true) && sign_in_params[:otp_attempt].blank?
      return render :otp, locals: { resource: User.new(sign_in_params) }, status: :unprocessable_content
    end

    super
  end

  private

  def after_sign_in_path_for(...)
    if params[:redir].present?
      return console_redirect_index_path(redir: params[:redir]) if params[:redir].starts_with?(Docuseal::CONSOLE_URL)

      return params[:redir]
    end

    super
  end

  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_in, keys: [:otp_attempt])
  end

  def set_flash_message(key, kind, options = {})
    return if key == :alert && kind == 'already_authenticated'

    super
  end

  # Map LDAP attributes to an Account instance
  # Mapping strategy: first try LDAP_ACCOUNT_MAPPING env JSON; fallback to matching attribute values to Account name or domain
  def map_ldap_to_account(attrs)
    account_attribute = Rails.application.config.x.ldap.settings[:account_attribute] || 'memberOf'
    values = Array(attrs[account_attribute] || attrs[account_attribute.downcase])

    # Load explicit mapping from ENV (JSON: { "cn=group,ou=...,dc=example,dc=org": "acme" })
    mapping_json = ENV['LDAP_ACCOUNT_MAPPING']
    mapping = mapping_json.present? ? JSON.parse(mapping_json) rescue {} : {}

    values.each do |val|
      # explicit mapping
      if mapping[val].present?
        mapped = mapping[val]
        account = find_account_by_identifier(mapped)
        return account if account
      end

      # fallback: try to find Account by name or domain
      account = Account.find_by(name: val) || Account.find_by(domain: val)
      return account if account

      # If the attribute contains a CN=... value (group DN), try to extract CN
      if val =~ /cn=([^,]+)/i
        cn = Regexp.last_match(1)
        account = Account.find_by(name: cn)
        return account if account
      end
    end

    nil
  end

  def find_account_by_identifier(id_or_slug)
    return nil if id_or_slug.blank?

    if id_or_slug.to_s =~ /\A\d+\z/
      Account.find_by(id: id_or_slug.to_i)
    else
      Account.find_by(slug: id_or_slug.to_s) || Account.find_by(name: id_or_slug.to_s)
    end
  end

  def notify_admin_of_conflict(existing_user, email, ldap_dn)
    Rails.logger.error("[LDAP] Provisioning conflict for email=#{email}, existing_user_id=#{existing_user.id}, ldap_dn=#{ldap_dn}")
    Rollbar.error("LDAP provisioning conflict for #{email}") if defined?(Rollbar)
    ActiveSupport::Notifications.instrument('ldap.provision_conflict', email: email, user_id: existing_user.id, ldap_dn: ldap_dn)
  end

  def notify_admin_of_existing_local(existing_user, auth)
    Rails.logger.error("[LDAP] Local user exists for email=#{existing_user.email}; automatic linking disabled. ldap_dn=#{auth[:dn]}")
    Rollbar.info("LDAP found local user for #{existing_user.email}; admin linking required") if defined?(Rollbar)
    ActiveSupport::Notifications.instrument('ldap.existing_local', email: existing_user.email, user_id: existing_user.id, ldap_dn: auth[:dn])
  end

  def notify_admin_missing_mapping(auth)
    Rails.logger.error("[LDAP] Missing account mapping for ldap_dn=#{auth[:dn]}, attrs=#{auth[:attributes].keys}")
    Rollbar.error('LDAP missing account mapping') if defined?(Rollbar)
    ActiveSupport::Notifications.instrument('ldap.missing_mapping', ldap_dn: auth[:dn], attrs: auth[:attributes])
  end
end
