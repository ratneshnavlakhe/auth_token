class ApplicationController < ActionController::Base
  acts_as_token_authentication_handler_for User
  protect_from_forgery with: :null_session, :if => Proc.new { |c| c.request.format == 'application/json' }
  respond_to :json
end
