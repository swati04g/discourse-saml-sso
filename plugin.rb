# name: discourse-saml
# about: SAML Auth Provider
# version: 0.1
# author: Robin Ward

require_dependency 'auth/oauth2_authenticator'

gem 'macaddr', '1.0.0'
gem 'uuid', '2.3.7'
gem 'ruby-saml', '1.4.2'
gem "omniauth-saml", '1.6.0'
#gem 'saml2ruby', '1.1.0'

request_method = GlobalSetting.try(:saml_request_method) || 'get'

class SamlAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :saml,
                      :name => 'saml',
                      :issuer => Discourse.base_url,
                      :idp_sso_target_url => GlobalSetting.saml_target_url,
                      :idp_cert_fingerprint => GlobalSetting.try(:saml_cert_fingerprint),
                      :idp_cert => GlobalSetting.try(:saml_cert),
                      :attribute_statements => { :nickname => ['screenName'] },
                      :assertion_consumer_service_url => Discourse.base_url + "/auth/saml/callback",
                      :custom_url => (GlobalSetting.try(:saml_request_method) == 'post') ? "/discourse_saml" : nil
  end
  
  
  
  def after_authenticate(auth)
    Rails.logger.info 'after authenticate'
    result = Auth::Result.new

    if GlobalSetting.try(:saml_log_auth)
      ::PluginStore.set("saml", "saml_last_auth", auth.inspect)
      ::PluginStore.set("saml", "saml_last_auth_raw_info", auth.extra[:raw_info].inspect)
      ::PluginStore.set("saml", "saml_last_auth_extra", auth.extra.inspect)
    end

    uid = auth[:uid]
    result.name = auth[:info].name || uid
    result.username = uid
    if auth.extra.present? && auth.extra[:raw_info].present?
      result.username = auth.extra[:raw_info].attributes['screenName'].try(:first) || uid
    end

    if GlobalSetting.try(:saml_use_uid) && auth.extra.present? && auth.extra[:raw_info].present?
      result.username = auth.extra[:raw_info].attributes['uid'].try(:first) || uid
    end

    result.email = auth[:info].email || uid
    result.email_valid = true
    result.skip_email_validation = true
   

    current_info = ::PluginStore.get("saml", "saml_user_#{uid}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    end

    result.user ||= User.where(email: Email.downcase(result.email)).first

    if GlobalSetting.try(:saml_clear_username) && result.user.blank?
      result.username = ''
    end
    
    result.extra_data = { saml_user_id: uid }
    groups = auth.extra[:raw_info].attributes['role']
        update_user_groups(result.user, groups)
    result
  end

  def after_create_account(user, auth)
    groups = auth.extra[:raw_info].attributes['role']
    ::PluginStore.set("saml", "saml_user_#{auth[:extra_data][:saml_user_id]}", {user_id: user.id })
    update_user_groups(user, groups)
  end

  def update_user_groups(user, grouplist)
    Rails.logger.info 'update user groups'
    #grouplist = groups.select { |item| item.starts_with?("beta-") }.map { |item| item[5, item.length - 5] }
    #Rails.logger.info  grouplist
    #Group.joins(:users).where(users: { id: user.id } ).each do |c|
    #  gname = c.name
     # if gname.start_with?("beta_")
      #  gname = gname[5, gname.length - 5]
      #  if grouplist.include?(gname)
      #    grouplist.delete(gname) # remove it from the list
      #  else
       #   c.group_users.where(user_id: user.id).destroy_all
      #     Rails.logger.info "Would remove group " + c.name
      #  end
      #end
   # end
    if grouplist.include?('discourse-moderators')
         user.moderator=true
         user.save
     end
  end


end

if request_method == 'post'
  after_initialize do

    module ::DiscourseSaml
      class Engine < ::Rails::Engine
        engine_name "discourse_saml"
        isolate_namespace DiscourseSaml
      end
    end

    class DiscourseSaml::DiscourseSamlController < ::ApplicationController
      skip_before_filter :check_xhr
      def index
        authn_request = OneLogin::RubySaml::Authrequest.new

        metadata_url = GlobalSetting.try(:saml_metadata_url)

        settings = nil

        if metadata_url
          idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
          settings = idp_metadata_parser.parse_remote(metadata_url)
          settings.idp_sso_target_url = GlobalSetting.saml_target_url
          settings.idp_cert ||= GlobalSetting.try(:saml_cert)
        else
          settings = OneLogin::RubySaml::Settings.new(:idp_sso_target_url => GlobalSetting.saml_target_url,
                                                      :idp_cert_fingerprint => GlobalSetting.try(:saml_cert_fingerprint),
                                                      :idp_cert => GlobalSetting.try(:saml_cert))
        end

        settings.compress_request = false
        settings.passive = false
        settings.issuer = Discourse.base_url
        settings.assertion_consumer_service_url = Discourse.base_url + "/auth/saml/callback"
        settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:protocol"

        saml_params = authn_request.create_params(settings, {})
        @saml_req = saml_params['SAMLRequest']

       
      end
    end

    DiscourseSaml::Engine.routes.draw do
      get '/' => 'discourse_saml#index'
    end

    Discourse::Application.routes.append do
      mount ::DiscourseSaml::Engine, at: "/discourse_saml"
    end
  end
end

title = GlobalSetting.try(:saml_title) || "SAML"
button_title = GlobalSetting.try(:saml_button_title) || GlobalSetting.try(:saml_title) || "with SAML"

auth_provider :title => button_title,
              :authenticator => SamlAuthenticator.new('saml'),
              :message => "Authorizing with #{title} (make sure pop up blockers are not enabled)",
              :frame_width => 600,
              :frame_height => 380,
              :background_color => '#003366',
              :full_screen_login => GlobalSetting.try(:saml_full_screen_login) || false,
              :custom_url => request_method == 'post' ? "/discourse_saml" : nil
