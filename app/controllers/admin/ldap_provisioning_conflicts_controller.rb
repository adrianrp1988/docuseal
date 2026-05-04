# frozen_string_literal: true

module Admin
  class LdapProvisioningConflictsController < ApplicationController
    before_action :authenticate_user!
    before_action :ensure_admin!
    before_action :set_conflict, only: %i[show approve_link approve_provision reject]

    def index
      @conflicts = ProvisioningConflict.accessible_by(current_ability).order(created_at: :desc).page(params[:page])
    end

    def show; end

    def approve_link
      unless @conflict.existing_user
        redirect_to admin_ldap_provisioning_conflict_path(@conflict), alert: 'No existing user to link.' and return
      end

      user = @conflict.existing_user
      user.transaction do
        user.update!(ldap_uid: @conflict.ldap_dn, ldap_user: true)
        @conflict.update!(status: 'approved', admin: current_user, notes: "Linked to existing user id=#{user.id}")
      end

      redirect_to admin_ldap_provisioning_conflicts_path, notice: 'User linked to LDAP and provisioning conflict approved.'
    rescue StandardError => e
      Rails.logger.error("[LDAP][Admin] Error approving link: #{e.message}")
      redirect_to admin_ldap_provisioning_conflict_path(@conflict), alert: 'Error linking user.'
    end

    def approve_provision
      if @conflict.mapped_account.nil?
        redirect_to admin_ldap_provisioning_conflict_path(@conflict), alert: 'No mapped account available to provision user.' and return
      end

      attrs = @conflict.ldap_attributes || {}
      email = (@conflict.email || attrs['mail']&.first).to_s.downcase

      user = User.new(
        email: email,
        first_name: attrs['givenName']&.first,
        last_name: attrs['sn']&.first,
        ldap_uid: @conflict.ldap_dn,
        ldap_user: true,
        account: @conflict.mapped_account,
        role: 'user'
      )

      user.set_unusable_password!
      user.confirmed_at = Time.current if user.respond_to?(:confirmed_at)

      if user.save
        @conflict.update!(status: 'approved', admin: current_user, notes: "Provisioned user id=#{user.id}")
        redirect_to admin_ldap_provisioning_conflicts_path, notice: 'User provisioned and approved.'
      else
        @conflict.update!(notes: "Provision attempt failed: #{user.errors.full_messages.join('; ')}")
        redirect_to admin_ldap_provisioning_conflict_path(@conflict), alert: 'Provisioning failed; see conflict notes.'
      end
    rescue StandardError => e
      Rails.logger.error("[LDAP][Admin] Error provisioning user: #{e.message}")
      redirect_to admin_ldap_provisioning_conflict_path(@conflict), alert: 'Error provisioning user.'
    end

    def reject
      @conflict.update!(status: 'rejected', admin: current_user)
      redirect_to admin_ldap_provisioning_conflicts_path, notice: 'Conflict rejected.'
    end

    private

    def set_conflict
      @conflict = ProvisioningConflict.find(params[:id])
      authorize! :manage, @conflict
    end

    def ensure_admin!
      authorize! :manage, ProvisioningConflict
    rescue CanCan::AccessDenied
      redirect_to root_path, alert: 'Not authorized'
    end
  end
end
