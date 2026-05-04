# frozen_string_literal: true

class ProvisioningConflict < ApplicationRecord
  STATUSES = %w[pending approved rejected].freeze

  belongs_to :existing_user, class_name: 'User', optional: true
  belongs_to :mapped_account, class_name: 'Account', optional: true
  belongs_to :admin, class_name: 'User', optional: true

  validates :status, inclusion: { in: STATUSES }
end
