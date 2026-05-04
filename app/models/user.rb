# frozen_string_literal: true

class User < ApplicationRecord
  ROLES = [
    ADMIN_ROLE = 'admin'
  ].freeze

  EMAIL_REGEXP = /[^@;,<>\s]+@[^@;,<>\s]+/

  FULL_EMAIL_REGEXP =
    /\A[a-z0-9][.']?(?:(?:[a-z0-9_-]+[.+'])*[a-z0-9_-]+)*@(?:[a-z0-9]+[.-])*[a-z0-9]+\.[a-z]{2,}\z/i

  has_one_attached :signature
  has_one_attached :initials

  belongs_to :account
  has_one :access_token, dependent: :destroy
  has_many :access_tokens, dependent: :destroy
  has_many :mcp_tokens, dependent: :destroy
  has_many :templates, dependent: :destroy, foreign_key: :author_id, inverse_of: :author
  has_many :template_folders, dependent: :destroy, foreign_key: :author_id, inverse_of: :author
  has_many :user_configs, dependent: :destroy
  has_many :encrypted_configs, dependent: :destroy, class_name: 'EncryptedUserConfig'
  has_many :email_messages, dependent: :destroy, foreign_key: :author_id, inverse_of: :author

  devise :two_factor_authenticatable, :recoverable, :rememberable, :validatable, :trackable, :lockable

  attribute :role, :string, default: ADMIN_ROLE
  attribute :uuid, :string, default: -> { SecureRandom.uuid }

  scope :active, -> { where(archived_at: nil) }
  scope :archived, -> { where.not(archived_at: nil) }
  scope :admins, -> { where(role: ADMIN_ROLE) }

  validates :email, format: { with: /\A[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\z/ }

  def access_token
    super || build_access_token.tap(&:save!)
  end

  def active_for_authentication?
    super && !archived_at? && !account.archived_at?
  end

  def remember_me
    true
  end

  def sidekiq?
    return true if Rails.env.development?

    role == 'admin'
  end

  def self.sign_in_after_reset_password
    if PasswordsController::Current.user.present?
      !PasswordsController::Current.user.otp_required_for_login
    else
      true
    end
  end

  def initials
    [first_name&.first, last_name&.first].compact_blank.join.upcase
  end

  def full_name
    [first_name, last_name].compact_blank.join(' ')
  end

  def friendly_name
    if full_name.present?
      %("#{full_name.delete('"')}" <#{email}>)
    else
      email
    end
  end

  # Return true if this account is backed by LDAP (boolean column :ldap_user)
  def ldap_user?
    self.ldap_user == true
  end

  # Devise calls this to decide whether to validate presence/format of password.
  # For LDAP users we skip local password validations so we can provision accounts without a password.
  def password_required?
    return false if ldap_user?

    super
  end

  # Make the stored password unusable for local authentication.
  # We write an encrypted random value so the DB doesn't contain a nil/blank value
  # and local sign-in will fail even if fallback is accidentally enabled.
  def set_unusable_password!
    self.encrypted_password = Devise::Encryptor.digest(self.class, SecureRandom.hex(32))
  end
end
