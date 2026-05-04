class AddLdapFieldsToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :ldap_uid, :string
    add_column :users, :ldap_user, :boolean, default: false, null: false
    add_index :users, :ldap_uid, unique: true
  end
end
