class OpenidUser < ActiveRecord::Migration
  def self.up
    # add_column :users, :openid, :string
     remove_column :users, :password
    # remove_column
  end

  def self.down
    # remove_column :users, :openid
    add_column :users, :password, :string
  end
end
