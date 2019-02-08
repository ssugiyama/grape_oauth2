module Grape
  module OAuth2
    # Grape::OAuth2 strategies namespace
    module Strategies
      # Base Grape::OAuth2 Strategies class .
      # Contains common functionality for all the descendants.
      class Base
        class << self
          # Authenticates Client from the request.
          def authenticate_client(request)
            config.client_class.authenticate(request.client_id, request.try(:client_secret))
          end

          # Authenticates Resource Owner from the request.
          def authenticate_resource_owner(client, request)
            config.resource_owner_class.oauth_authenticate(client, request.username, request.password)
          end

          # Short getter for Grape::OAuth2 configuration
          def config
            Grape::OAuth2.config
          end

          # Converts scopes from the request string. Separate them by the whitespace.
          # @return [String] scopes string
          #
          def scopes_from(request)
            return nil if request.scope.nil?

            Array(request.scope).join(' ')
          end

          # Exposes token object to Bearer token.
          #
          # @param token [#to_bearer_token]
          #   any object that responds to `to_bearer_token`
          # @return [Rack::OAuth2::AccessToken::Bearer]
          #   bearer token instance
          #
          def expose_to_bearer_token(token)
            Rack::OAuth2::AccessToken::Bearer.new(token.to_bearer_token)
          end

          # Exposes token object mac token.
          #
          # @param token [#to_mac_token]
          #   any object that responds to `to_mac_token`
          # @return [Rack::OAuth2::AccessToken::Mac]
          #   mac token instance
          #
          def expose_to_mac_token(token)
            Rack::OAuth2::AccessToken::MAC.new(token.to_mac_token)
          end
        end
      end
    end
  end
end
