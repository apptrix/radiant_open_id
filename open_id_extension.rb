# Uncomment this if you reference any of your controllers in activate
require_dependency 'application_controller'
require 'pathname'
require "openid"
require 'openid/extensions/sreg'
require 'openid/extensions/pape'
require 'openid/store/filesystem'

class OpenIdExtension < Radiant::Extension
  version "1.0"
  description "Describe your extension here"
  url "http://yourwebsite.com/open_id"



  define_routes do |map|

 map.with_options(:controller => 'admin/welcome') do |welcome|
    welcome.admin          'admin',                              :action => 'index'
    welcome.welcome        'admin/welcome',                      :action => 'index'
    welcome.login          'admin/login',                        :action => 'login'
    welcome.logout         'admin/logout',                       :action => 'logout'
    welcome.autologin      'admin/autologin',                    :action => 'autologin'#, :conditions => { :method => :post }
 end
 
    map.namespace :admin, :member => { :remove => :get } do |admin|
      admin.resources :open_id
      #admin.resources :settings
    end

    map.resource :openid, :member => { :complete => :get }
    map.complete '/admin/complete', :controller => 'admin/welcome', :action => 'complete'
  end

  def activate
    #OpenId

    User.send :include, OpenId::OpenIdUser
    #LoginSystem.send :extend, OpenId::OpenIdLogin
    #Admin::WelcomeController.send :include, OpenId::OpenIdLoginControl
    # admin.nav[:content] << admin.nav_item(:open_id, "Open", "/admin/open_id"), :after => :pages

    Admin::WelcomeController.class_eval do
      def autologin
        flash[:autologin] = true
        login
      end

      def login   # AKA start
        if (request.post? || flash[:autologin] == true)
          begin
            identifier = params[:openid_identifier]     # This paramater is what our overridden form will submit
            if identifier.nil?
              flash[:error] = "Enter an OpenID identifier"
              redirect_to :action => 'index'      # TODO
              return
            end
            oidreq = consumer.begin(identifier)
          rescue OpenID::OpenIDError => e
            flash[:error] = "Discovery failed for #{identifier}: #{e}"
            redirect_to :action => 'index'
            return
          end
          #if params[:use_sreg]
            sregreq = OpenID::SReg::Request.new
            # required fields
            sregreq.request_fields(['email', 'nickname'], true)
            # optional fields
            sregreq.request_fields(['dob', 'fullname'], false)
            oidreq.add_extension(sregreq)
            oidreq.return_to_args['did_sreg'] = 'y'
          #end
          if params[:use_pape]
            papereq = OpenID::PAPE::Request.new
            papereq.add_policy_uri(OpenID::PAPE::AUTH_PHISHING_RESISTANT)
            papereq.max_auth_age = 2*60*60
            oidreq.add_extension(papereq)
            oidreq.return_to_args['did_pape'] = 'y'
          end
          if params[:force_post]
            oidreq.return_to_args['force_post']='x'*2048
          end
          return_to = url_for :action => 'complete', :only_path => false
          realm = url_for :action => 'index', :only_path => false

          if oidreq.send_redirect?(realm, return_to, params[:immediate])  # Sends realm and return to, to masquerade
            redirect_to oidreq.redirect_url(realm, return_to, params[:immediate])
          else
            render :text => oidreq.html_markup(realm, return_to, params[:immediate], {'id' => 'openid_form'})
          end
        else

          if current_user
            if params[:remember_me]
              current_user.remember_me
              set_session_cookie
            end
            redirect_to (session[:return_to] || welcome_url)
            session[:return_to] = nil
          else
            render :template => 'openid/login.html.haml'
          end
        end
      end

      #alias login start

      def complete
        # FIXME - url_for some action is not necessarily the current URL.
        current_url = url_for(:action => 'complete', :only_path => false)
        parameters = params.reject{|k, v|request.path_parameters[k]}
        oidresp = consumer.complete(parameters, current_url)
        case oidresp.status
          when OpenID::Consumer::FAILURE
            if oidresp.display_identifier
              flash[:error] = ("Verification of #{oidresp.display_identifier}"\
                         " failed: #{oidresp.message}")
            else
              flash[:error] = "Verification failed: #{oidresp.message}"
            end
          when OpenID::Consumer::SUCCESS

            # Modify the user model to accept authentication here
            u = User.find_by_login(oidresp.display_identifier)

            sreg_resp = OpenID::SReg::Response.from_success_response(oidresp)


              sreg_message = "Simple Registration data was requested"
              if sreg_resp.empty?
                sreg_message << ", but none was returned."
              else
                sreg_message << ". The following data were sent:"
                sreg_resp.data.each {|k, v|
                  sreg_message << "<br/><b>#{k}</b>: #{v}"
                }
              end
              flash[:sreg_results] = sreg_message

            if u
              u.name = sreg_resp.data['nickname']#"mytest"#
              u.email = sreg_resp.data['email']#"mytestemail@linkeddata.co.uk"#
              u.save
              if u.login == oidresp.identity_url
                #self.current_user = u
                #session[:user_id] = u.id
                announce_invalid_user unless self.current_user = u
              end
            else
              u = User.create(:login => oidresp.display_identifier, :designer => true, :name => sreg_resp.data['nickname'], :email => sreg_resp.data['email'])
              #u.name = "mytest"#sreg_resp.data['nickname']
              #u.email = "mytestemail@linkeddata.co.uk"#sreg_resp.data['email']
              self.current_user = u
              #session[:user_id] = u.id
            end


            if current_user
              if params[:remember_me]
                current_user.remember_me
                set_session_cookie
              end
              redirect_to (session[:return_to] || welcome_url)
              session[:return_to] = nil
            else
              render :template => 'openid/login.html.haml'
            end

            flash[:success] = ("Verification of #{oidresp.display_identifier}"\
                         " succeeded.")
            if params[:did_sreg]
              sreg_resp = OpenID::SReg::Response.from_success_response(oidresp)
              sreg_message = "Simple Registration data was requested"
              if sreg_resp.empty?
                sreg_message << ", but none was returned."
              else
                sreg_message << ". The following data were sent:"
                sreg_resp.data.each {|k, v|
                  sreg_message << "<br/><b>#{k}</b>: #{v}"
                }
              end
              flash[:sreg_results] = sreg_message
            end
            if params[:did_pape]
              pape_resp = OpenID::PAPE::Response.from_success_response(oidresp)
              pape_message = "A phishing resistant authentication method was requested"
              if pape_resp.auth_policies.member? OpenID::PAPE::AUTH_PHISHING_RESISTANT
                pape_message << ", and the server reported one."
              else
                pape_message << ", but the server did not report one."
              end
              if pape_resp.auth_time
                pape_message << "<br><b>Authentication time:</b> #{pape_resp.auth_time} seconds"
              end
              if pape_resp.nist_auth_level
                pape_message << "<br><b>NIST Auth Level:</b> #{pape_resp.nist_auth_level}"
              end
              flash[:pape_results] = pape_message
            end
          when OpenID::Consumer::SETUP_NEEDED
            flash[:alert] = "Immediate request failed - Setup Needed"
          when OpenID::Consumer::CANCEL
            flash[:alert] = "OpenID transaction cancelled."
          else
        end
        #redirect_to :action => 'index'
      end

      private

      def consumer
        if @consumer.nil?
          dir = Pathname.new(RAILS_ROOT).join('db').join('cstore')
          store = OpenID::Store::Filesystem.new(dir)
          @consumer = OpenID::Consumer.new(session, store)
        end
        return @consumer
      end
    end

    #Admin::WelcomeController.class_eval do
    #alias_method :index_to_page, :index unless method_defined?(:index_to_profile)
    # alias_method :login_without_openid, :login unless method_defined?(:login_with_openid)

    #def index_to_profile
    #  redirect_to profile_admin_members_path
    #end

    #def login_with_openid
    #  if request.post?
    #    login = params[:user][:login]
    #    password = params[:user][:password]
    #    announce_invalid_user unless self.current_user = User.authenticate(login, password)
    #  end
    #  if current_user
    #    if params[:remember_me]
    #      current_user.remember_me
    #      set_session_cookie
    #    end
    #    redirect_to (session[:return_to] || welcome_url)
    #    session[:return_to] = nil
    #  else
    #    render :template => 'openid/login.html.haml'
    #  end
    #end


    #alias_method :index, :index_to_profile
    #alias_method :login, :login_with_openid

    #end
  end
end
