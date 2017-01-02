class User < ApplicationRecord
  acts_as_token_authenticatable
  # before_save :set_auth_token
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable


  def as_json(options={})
  {
    id: self.id,
    email: self.email
  }
  end
end
