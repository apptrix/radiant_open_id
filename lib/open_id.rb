module OpenId
  
  module OpenIdUser
    def openid_authentication

    end

    def openid_authorize

    end
  end

  module OpenIdLogin

    protected

    def login_from_openid(openid)
      if u = User.find_by_login(openid)
        u
      else
        u = User.create(:openid => openid)
        u
      end
    end

    def current_user
      @current_user ||= (login_from_session || login_from_cookie || login_from_http || login_from_openid)
    end

    def login_from_openid

    end
  end

  module OpenIdLoginControl
    def login   # AKA start
      if request.post?
        begin
          identifier = params[:openid_identifier]     # This paramater is what our overriden form will submit
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
        if params[:use_sreg]
          sregreq = OpenID::SReg::Request.new
          # required fields
          sregreq.request_fields(['email', 'nickname'], true)
          # optional fields
          sregreq.request_fields(['dob', 'fullname'], false)
          oidreq.add_extension(sregreq)
          oidreq.return_to_args['did_sreg'] = 'y'
        end
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
           if u = User.find_by_login(oidresp.display_identifier)
           current_user = u
           else
           current_user = User.create(:login => oidresp.display_identifier)
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
      redirect_to :action => 'index'
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
end

#User.send :include, OpenId::OpenIdUser
#LoginSystem.send :extend, OpenId::OpenIdLogin
#Admin::WelcomeController.send :extend, OpenIdLoginControl