module Grape
  module OAuth2
    module ActiveRecord
      # Grape::OAuth2 Access Token role mixin for ActiveRecord.
      # Includes all the required API, associations, validations and callbacks.
      module MacAccessToken
        extend ActiveSupport::Concern
        include Grape::OAuth2::ActiveRecord::AccessToken
        included do
          validates :secret, :presence => true
          validates :algorithm, :presence => true, :inclusion => [
            'hmac-sha-1',
            'hmac-sha-256'
          ]
          before_validation :generate_secret, on: :create
 
          class << self
            def authenticate(token, type: :access_token, request: nil)
              if type && type.to_sym == :refresh_token
                find_by(refresh_token: token.to_s)
              else
                found = find_by(token: token.to_s)
                found && Rack::OAuth2::AccessToken::MAC.new(found.to_mac_token).verify!(request) && found
              end
            end
          end
 
          def to_mac_token
            {
              access_token:  token,
              mac_key:       secret,
              mac_algorithm: algorithm ||  'hmac-sha-256',
              expires_in:    expires_at && Grape::OAuth2.config.access_token_lifetime.to_i,
              refresh_token: refresh_token,
            }
          end
        
          def token_type
            'mac'
          end

          protected

          def generate_secret
            self.secret = Grape::OAuth2::UniqueToken.generate if secret.blank?
          end
        end
      end
    end
  end
end