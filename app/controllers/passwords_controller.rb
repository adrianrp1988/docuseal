# frozen_string_literal: true

class PasswordsController < Devise::PasswordsController
  # rubocop:disable Rails/LexicallyScopedActionFilter
  skip_before_action :require_no_authentication, only: %i[edit update]
  # rubocop:enable Rails/LexicallyScopedActionFilter

  around_action :with_browser_locale

  class Current < ActiveSupport::CurrentAttributes
    attribute :user
  end

  def create
    # Prevent password reset for LDAP-backed users
    email = params.dig(resource_name, :email)&.downcase
    user = User.find_by('lower(email) = ?', email) if email.present?

    if user&.ldap_user?
      # Do not send reset instructions for LDAP users. Show a non-enumerating message.
      flash[:alert] = I18n.t('ldap.password_managed', default: 'Password for this account is managed by your organization. Please contact your administrator.')
      redirect_to new_session_path(resource_name)
      return
    end

    super do |resource|
      resource.errors.clear unless Docuseal.multitenant?
    end
  end

  def update
    # Prevent applying a password reset for LDAP-backed users
    token = params.dig(resource_name, :reset_password_token)

    if token.present?
      resource = resource_class.with_reset_password_token(token)
      if resource&.ldap_user?
        flash[:alert] = I18n.t('ldap.password_managed', default: 'Password for this account is managed by your organization. Please contact your administrator.')
        redirect_to new_session_path(resource_name)
        return
      end
    end

    super do |resource|
      Current.user = resource
    end
  end

  private

  def after_resetting_password_path_for(_)
    new_session_path(resource_name)
  end
end
