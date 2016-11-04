require 'spec_helper'

describe 'Token Endpoint' do
  describe 'POST /oauth/revoke' do
    describe 'Revoke Token flow' do
      context 'with valid params' do
        let(:api_url) { '/api/v1/oauth/revoke' }
        let(:application) { Application.create(name: 'App1') }
        let(:user) { User.create(username: 'test', password: '12345678') }

        let(:headers) { { 'HTTP_AUTHORIZATION' => ('Basic ' + Base64::encode64("#{application.key}:#{application.secret}")) } }

        describe 'for public token' do
          context 'when request is invalid' do
            before { AccessToken.create_for(application, user)  }

            it 'do nothing' do
              expect {
                post api_url, { token: 'invalid token' }, headers
              }.not_to change { AccessToken.active.count }

              expect(json_body).to eq({})
              expect(last_response.status).to eq 200

              expect(AccessToken.last).not_to be_revoked
            end
          end

          context 'with valid data' do
            before { AccessToken.create_for(application, user)  }

            it 'revokes Access Token by its token' do
              expect {
                post api_url, { token: AccessToken.last.token }, headers
              }.to change { AccessToken.active.count }.from(1).to(0)

              expect(json_body).to eq({})
              expect(last_response.status).to eq 200

              expect(AccessToken.last).to be_revoked
              expect(AccessToken.last).not_to be_accessible
            end

            it 'revokes Access Token by its refresh token' do
              refresh_token = SecureRandom.hex(16)
              AccessToken.last.update_column(:refresh_token, refresh_token)

              expect {
                post api_url, { token: refresh_token, token_type_hint: 'refresh_token' }, headers
              }.to change { AccessToken.active.count }.from(1).to(0)

              expect(json_body).to eq({})
              expect(last_response.status).to eq 200

              expect(AccessToken.last).to be_revoked
              expect(AccessToken.last).not_to be_accessible
            end
          end
        end

        describe 'for private token' do
          before { AccessToken.create_for(application, user)  }

          context 'with valid data' do
            it 'revokes token with client authorization' do
              expect {
                post api_url, { token: AccessToken.last.token}, headers
              }.to change { AccessToken.active.count }.from(1).to(0)
            end
          end

          context 'with invalid credentials' do
            it 'does not revokes access token' do
              expect {
                post api_url, token: AccessToken.last.token
              }.to_not change { AccessToken.active.count }

              expect(json_body[:error]).to eq('invalid_client')
            end
          end
        end
      end
    end
  end
end