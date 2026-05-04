class CreateProvisioningConflicts < ActiveRecord::Migration[7.0]
  def change
    create_table :provisioning_conflicts do |t|
      t.string :email
      t.string :ldap_dn
      t.jsonb :ldap_attributes, default: {}
      t.bigint :existing_user_id
      t.bigint :mapped_account_id
      t.string :status, null: false, default: 'pending'
      t.bigint :admin_id
      t.text :notes

      t.timestamps
    end

    add_index :provisioning_conflicts, :email
    add_index :provisioning_conflicts, :ldap_dn
    add_index :provisioning_conflicts, :existing_user_id
    add_index :provisioning_conflicts, :mapped_account_id
  end
end
