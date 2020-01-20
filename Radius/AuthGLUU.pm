# AuthGLUU.pm
# 
# Gluu Authentication module for Radiator 
# 
# Author: Rolain Djeumen (rolain@gluu.org)
#

# MIT License
#
# Copyright (c) 2020 Gluu Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


package Radius::AuthGLUU;
@ISA = qw(Radius::AuthGeneric);
use Radius::AuthGeneric;
use Data::UUID;
use Encode qw(encode_utf8);
use Crypt::JWT qw(decode_jwt encode_jwt);
use HTTP::Async;
use HTTP::Request;
use JSON;
use strict;

%Radius::AuthGLUU::ConfigKeywords = 
(
    'acrValue' => ['string','Optional custom scripts which will be invoked during authentication.'],
    'scopes' => ['stringarray','Optional scopes which will be used as openid scopes during authentication.'],
    'gluuServerUrl' => ['string','The url of your Gluu Server instance.',1],
    'clientId' => ['string','The username/client ID of the Gluu RO OpenID Client.',1],
    'signaturePkey' => ['string','The private key in PEM format used for authentication.',1],
    'signaturePkeyPassword' => ['string','The signature private key\'s password.',1],
    'signaturePkeyId' => ['string','This is the key Id of the authentication public key',1],
    'signatureAlgorithm' => ['enum','The algorithm used for authentication. Defaults to RS512',1,\@Radius::AuthGLUU::ALGORITHMS],
    'sslVerifyCert' => ['flag','Set to yes/no to enable/disable ssl certificate verification. Default is yes',1],
    'sslCAPath'  => ['string','Path of the directory containing CA certificates in PEM format.',1],
    'sslCAFile'  => ['string','Path to the file containing the Gluu Server instance CA cert in PEM format',1],
    'sslVerifyCnScheme' => ['string','Scheme used to perform certificate verification. See IO::Socket::SSL for details.',1],
    'sslVerifyCnName' => ['string','Set the name which is used in hostname verification. See IO::Socket::SSL for details.',1],
    'unreachableServerAction' => ['enum','Set the action to perform (accept/reject/ignore) when the server is unreachable.',1],
    'maxRequests' => ['integer','Maximum number of simultaneous requests to the Gluu server',1],
    'httpRequestTimeout' => ['integer','HTTP Request timeout in seconds'],
    'httpMaxRequestTime' => ['integer','Max time in seconds an http request can last'],
    'authTimeout' => ['integer','Authentication timeout in seconds'],
    'pollInterval' => ['integer','Number of seconds between checking replies from the Gluu Server.',1],
    'healthCheckInterval' => ['integer','Gluu Server health check interval in seconds.',1],
    'healthCheckTimeout' => ['integer','When a health check request is sent, the health check is assumed to have failed after this number of seconds',1],
    'retryInterval' => ['interval','If a configuration item download fails, wait for this amount of time before retrying'],
    'authScheme' => ['string','The authentication scheme to be used. Can be either onestep or twostep. Default is twostep',1]
,);

# RCS version number of this module
$Radius::AuthGLUU::VERSION = '4.0.0-SNAPSHOT';

# Grant Types 
$Radius::AuthGLUU::GRANT_TYPE::AUTHORIZATION_CODE = 'authorization_code';
$Radius::AuthGLUU::GRANT_TYPE::IMPLICIT = 'implicit';
$Radius::AuthGLUU::GRANT_TYPE::RO_PASSWORD_CREDENTIALS = 'password';
$Radius::AuthGLUU::GRANT_TYPE::CLIENT_CREDENTIALS = 'client_credentials';
$Radius::AuthGLUU::GRANT_TYPE::REFRESH_TOKEN = 'refresh_token';


# Default OpenID scopes 
@Radius::AuthGLUU::DEFAULT_SCOPES = qw(openid super_gluu_ro_session);

# Default acr values 
$Radius::AuthGLUU::DEFAULT_ACR = 'super_gluu_ro';

# Token endpoint request parameter names 
$Radius::AuthGLUU::TOKEN_PARAM::GRANT_TYPE = 'grant_type';
$Radius::AuthGLUU::TOKEN_PARAM::SCOPE = 'scope';
$Radius::AuthGLUU::TOKEN_PARAM::USERNAME = 'username';
$Radius::AuthGLUU::TOKEN_PARAM::PASSWORD = '__password';
$Radius::AuthGLUU::TOKEN_PARAM::CLIENT_ID = 'client_id';
$Radius::AuthGLUU::TOKEN_PARAM::REMOTE_IP = '__remote_ip';
$Radius::AuthGLUU::TOKEN_PARAM::STEP = '__step';
$Radius::AuthGLUU::TOKEN_PARAM::CLIENT_ASSERTION_TYPE = 'client_assertion_type';
$Radius::AuthGLUU::TOKEN_PARAM::CLIENT_ASSERTION = 'client_assertion';
$Radius::AuthGLUU::TOKEN_PARAM::ACR_VALUES = 'acr_values';
$Radius::AuthGLUU::TOKEN_PARAM::SESSION_ID = '__session_id';
$Radius::AuthGLUU::TOKEN_PARAM::AUTH_SCHEME = '__auth_scheme';

# client assertion type 
$Radius::AuthGLUU::CLIENT_ASSERTION_TYPE::JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

# Authentication steps 
$Radius::AuthGLUU::AUTH_STEP::INIT_AUTH = 'initiate_auth';
$Radius::AuthGLUU::AUTH_STEP::RESEND_NOTIFICATION = 'resend_notification';
$Radius::AuthGLUU::AUTH_STEP::VERIFY_AUTH = 'verify_auth';

# Allowed signature algorithms 
@Radius::AuthGLUU::ALGORITHMS = qw(RS512 RS256 RS384 PS256 PS384 PS512 ES256 ES384 ES512);

# OpenSSL SSL Cert verification constants 
$Radius::AuthGLUU::SSL::VERIFY_NONE = 0;
$Radius::AuthGLUU::SSL::VERIFY_PEER = 1;

# Gluu Server Health Status 
$Radius::AuthGLUU::SERVER_HEALTH_ERROR = 0; # Server health check failed
$Radius::AuthGLUU::SERVER_HEALTH_OK = 1; # Server is up and running

# Default values for parameters
$Radius::AuthGLUU::DEFAULT_MAX_REQUESTS = 20; # default max number of simultaneous requests of 20
$Radius::AuthGLUU::DEFAULT_AUTH_TIMEOUT = 30; # default authentication timeout of 30 seconds
$Radius::AuthGLUU::DEFAULT_POLL_INTERVAL = 1; # default auth poll interval of one second
$Radius::AuthGLUU::DEFAULT_HTTP_REQUEST_TIMEOUT = 30; # default http request timeout
$Radius::AuthGLUU::DEFAULT_HTTP_MAX_REQUEST_TIME = 60; # default max request time
$Radius::AuthGLUU::DEFAULT_RETRY_INTERVAL = 5; # 5 seconds retry interval
$Radius::AuthGLUU::DEFAULT_JWT_EXPIRY_TIME = 30; # 30 seconds for our token to expire

# Request context types 
$Radius::AuthGLUU::CONTEXT_TYPE::OPENID_REQUEST = 'openid_request_context';
$Radius::AuthGLUU::CONTEXT_TYPE::JWKS_DOWNLOAD_REQUEST = 'jwks_download_request_context';
$Radius::AuthGLUU::CONTEXT_TYPE::INIT_AUTH_REQUEST = 'init_auth_request_context';
$Radius::AuthGLUU::CONTEXT_TYPE::RESEND_NOTIFICATION_REQUEST = 'resend_notification_request_context';
$Radius::AuthGLUU::CONTEXT_TYPE::STATUS_REQUEST = 'status_request_context';
$Radius::AuthGLUU::CONTEXT_TYPE::VERIFY_AUTH_REQUEST = 'verify_auth_request_context';

# Request states
$Radius::AuthGLUU::REQUEST_STATE::IDLE = 0;
$Radius::AuthGLUU::REQUEST_STATE::IN_PROGRESS = 1;
$Radius::AuthGLUU::REQUEST_STATE::COMPLETE = 2;

# Session status 
$Radius::AuthGLUU::SESSION_STATUS::UNAUTHENTICATED = 0;
$Radius::AuthGLUU::SESSION_STATUS::AUTHENTICATED = 1;

# Auth schemes 
$Radius::AuthGLUU::TWOSTEP_DISABLED = 0;
$Radius::AuthGLUU::TWOSTEP_ENABLED  = 1;



# Just a name for useful printing
my $class = 'AuthGLUU';

# Can make sure we get reinitialized on sighup
#push(@main::reinitFns, \&reinitialize);

&main::log($main::LOG_DEBUG, "$class version $Radius::AuthGLUU::VERSION loaded");


#####################################################################
# Do per-instance configuration check
# This is called by Configurable just before activate.
sub check_config
{
    my ($self) = @_;

    if(!defined $self->{gluuServerUrl})
    {
        $self->log($main::LOG_ERROR,"Gluu Server url not Specified.");
        $self->{configError} = 1;
    }

    if(!defined $self->{clientId})
    {
        $self->log($main::LOG_ERROR,"ClientId configuration parameter missing.");
        $self->{configError} = 1;
    }

    if(!defined $self->{signaturePkey})
    {
        $self->log($main::LOG_ERROR,"Token auth signature private key missing.");
        $self->{configError} = 1;
    }

    if(!defined $self->{signaturePkeyPassword})
    {
        $self->log($main::LOG_WARNING,"Token auth signature private key password missing.");
    }

    if(!defined $self->{signaturePkeyId})
    {
        $self->log($main::LOG_ERROR,"Token auth signature private key Id missing.");
        $self->{configError} = 1;
    }

    if(!defined $self->{signatureAlgorithm})
    {
        $self->log($main::LOG_ERROR,"Token auth signature algorithm missing.");
        $self->{configError} = 1;
    }

    if (!defined $self->{sslVerifyCnScheme} && defined $self->{sslVerifyCnName})
    {
        $self->log($main::LOG_WARNING,"sslVerifyCnScheme not defined but sslVerifyCnName defined.");
    }

    if(defined $self->{sslVerifyCnScheme} && !defined $self->{sslVerifyCnName})
    {
        $self->log($main::LOG_WARNING,"sslVerifyCnScheme defined but sslVerifyCnName not defined.");
    }

    if(defined $self->{unreachableServerAction})
    {
        if($self->{unreachableServerAction} !~ /(accept|reject|ignore)/i)
        {
            $self->log($main::LOG_WARNING,"Unreachable server action '$self->{unreachableServerAction}' is invalid");
        }
    }
    
    if($self->{httpRequestTimeout} <= 0) 
    {
        $self->log($main::LOG_WARNING,"Config parameter 'httpRequestTimeout' should be greater than zero.");
        $self->{httpRequestTimeout} = $Radius::AuthGLUU::DEFAULT_HTTP_REQUEST_TIMEOUT;
    }

    if($self->{httpMaxRequestTime} <= 0)
    {
        $self->log($main::LOG_WARNING,"Config parameter 'httpMaxRequestTime' should be greater than zero.");
        $self->{httpMaxRequestTime} = $Radius::AuthGLUU::DEFAULT_HTTP_MAX_REQUEST_TIME;
    }

    if($self->{maxRequests} <= 0)
    {
        $self->log($main::LOG_WARNING,"Config parameter 'maxRequests' should be greater than zero.");
        $self->{maxRequests} = $Radius::AuthGLUU::DEFAULT_MAX_REQUESTS;
    }

    if($self->{authTimeout} <= 0)
    {
        $self->log($main::LOG_WARNING,"Config parameter 'authTimeout' should be greater than zero.");
        $self->{authTimeout} = $Radius::AuthGLUU::DEFAULT_AUTH_TIMEOUT;
    }

    if($self->{pollInterval} <= 0)
    {
        $self->log($main::LOG_WARNING,"Config parameter 'pollInterval' should be greater than zero.");
        $self->{pollInterval} = $Radius::AuthGLUU::DEFAULT_POLL_INTERVAL;
    }

    if($self->{retryInterval} <= 0)
    {
        $self->log($main::LOG_WARNING,"Config parameter 'retryInterval' should be greater than zero.");
        $self->retryInterval = $Radius::AuthGLUU::DEFAULT_RETRY_INTERVAL;
    }

    if($self->{configError})
    {
        $self->log($main::LOG_ERROR,"$class instance config check failed.");
        die("$class instance init failed due to configuration errors.");
    }


    if(defined $self->{authScheme})
    {
        if($self->{authScheme} !~ /(onestep|twostep)/i)
        {
            $self->log($main::LOG_WARNING,"Authentication scheme '$self->{authScheme}' is invalid");
            $self->{twoStepStatus} = $Radius::AuthGLUU::TWOSTEP_ENABLED;
        }
    }

    $self->log($main::LOG_DEBUG, "Configuration check for $class succeeded");
    $self->SUPER::check_config();
    return;
}

#####################################################################
# Do per-instance state (re)creation.
# This wil be called after the instance is created and after parameters have
# been changed during online reconfiguration.
# If it doesnt do anything, you can omit it.
sub activate
{
    my ($self) = @_;

    $self->SUPER::activate();
    if($self->{unreachableServerAction} && (lc $self->{unreachableServerAction} eq 'accept'))
    {
        $self->unreachableServerCode = $main::ACCEPT;
    }

    if($self->{unreachableServerAction} && (lc $self->{unreachableServerAction} eq 'reject'))
    {
        $self->unreachableServerCode = $main::REJECT;
    }

    if($self->{authScheme} && (lc $self->{authScheme} eq 'onestep'))
    {
        $self->{twoStepStatus} =  $Radius::AuthGLUU::TWOSTEP_DISABLED;
    }

    if($self->{authScheme} && (lc $self->{authScheme} eq 'twostep'))
    {
        $self->{twoStepStatus} = $Radius::AuthGLUU::TWOSTEP_ENABLED;
    }

    # Create http async request queue 
    $self->{async} = HTTP::Async->new(
        slots => $self->{maxRequests},
        timeout => $self->{httpRequestTimeout},
        max_request_time => $self->{httpMaxRequestTime} ,
    );

    my %ssl_opts = $self->build_ssl_options();
    $self->{async}->ssl_options(\%ssl_opts) if %ssl_opts;

    # Create hashmap containing id-to-request mapping
    %{$self->{requestMap}} = ();

    # starts the response processing timer 
    $self->start_http_response_processing_timer();

    # send initial openid configuration request 
    $self->log($main::LOG_INFO,"Activating $class plugin.");
    $self->send_openid_configuration_request();
    return;

}

#####################################################################
# Do per-instance default initialization
# This is called by Configurable during Configurable::new before
# the config file is parsed. Its a good place initialize instance 
# variables
# that might get overridden when the config file is parsed.
# If it doesnt do anything, you can omit it.
sub initialize
{
    my ($self) = @_;

    $self->SUPER::initialize;
    $self->{uuidGenerator} = Data::UUID->new();
    $self->{json} = JSON->new();
    $self->{configError} = 0;
    $self->{serverUnreachable} = 1;
    $self->{acrValue} = $Radius::AuthGLUU::DEFAULT_ACR;
    @{$self->{scopes}} = @Radius::AuthGLUU::DEFAULT_SCOPES;
    $self->{signatureAlgorithm} = $Radius::AuthGLUU::ALGORITHMS[0];
    $self->{sslVerifyCert} = $Radius::AuthGLUU::SSL::VERIFY_PEER;
    $self->{unreachableServerCode} = $main::IGNORE;
    $self->{maxRequests} = $Radius::AuthGLUU::DEFAULT_MAX_REQUESTS;
    $self->{httpRequestTimeout} = $Radius::AuthGLUU::DEFAULT_HTTP_REQUEST_TIMEOUT;
    $self->{httpMaxRequestTime} = $Radius::AuthGLUU::DEFAULT_HTTP_MAX_REQUEST_TIME;
    $self->{authTimeout} = $Radius::AuthGLUU::DEFAULT_AUTH_TIMEOUT;
    $self->{pollInterval} = $Radius::AuthGLUU::DEFAULT_POLL_INTERVAL;
    $self->{retryInterval} = $Radius::AuthGLUU::DEFAULT_RETRY_INTERVAL;
    $self->{jwtExpiryTime} = $Radius::AuthGLUU::DEFAULT_JWT_EXPIRY_TIME;
    $self->{twoStepStatus} = $Radius::AuthGLUU::TWOSTEP_ENABLED; 

    $self->{tokenEndpoint} = undef;
    $self->{jwksUri} = undef;
    $self->{jwksData} = undef;
    $self->{ready} = 0;

    return;

}

#####################################################################
# Handle a request
# This function is called for each packet. $p points to a Radius::
# packet containing the original request. $p->{rp} is a reply packet
# you can use to reply, or else fill with attributes and get
# the caller to reply for you.
# $extra_checks is an AttrVal containing check items that 
# we must check for, regardless what other check items we might 
# find for the user. This is most often used for cascading 
# authentication wuth Auth-Type .
# In this test module, Accounting is ignored
# It is expected to (eventually) reply to Access-Request packets
# with either Access-Accept or Access-Reject
# Accounting-Request will automatically be replied to by the 
# Realm object
# so there is no need to reply to them, although they might be forwarded
# logged in a site-specific fashion, or something else.
#
# The return value significant:
# If false, a generic reply will be constructed by Realm, else no reply will
# be sent to the requesting client. In general, you should always
# handle at least Access-Request and return 0
# Also returns an optional reason message for rejects
sub handle_request
{
    my ($self, $p, $dummy, $extra_checks) = @_;
    $self->log($main::LOG_DEBUG,"Handling with Radius::AuthGLUU.",$p);

    return ($main::IGNORE,'forked')
    if $self->{Fork} && !$self->handlerFork();

    return ($main::IGNORE,"Ignored due to IgnoreAuthentication")
    if $self->{IgnoreAuthentication} && $p->code eq 'Access-Request';

    return ($main::IGNORE,"Ignored due to IgnoreAccounting")
    if $self->{IgnoreAccounting} && $p->code eq 'Accounting-Request';

    if($p->code eq 'Access-Request')
    {
        unless($self->{ready})
        {
            return ($self->{unreachableServerCode},"Auth By GLUU plugin currently not ready.");
        }

        my $username  = $p->getUserName();
        my $password  = $p->decodedPassword();
        my $ipaddress = Radius::Util::inet_ntop($p->{RecvFromAddress});
        my $ctx = $self->perform_initial_authentication($username,$password,$ipaddress);

        if(!defined $ctx)
        {
            $self->log($main::LOG_DEBUG,'Error sending initial auth request to server.');
            return ($main::REJECT,'Error sending authentication request to Gluu server.');
        }

        $ctx->{'packet'} = $p;
        $ctx->{'start_time'} = time();

        # From AuthDUO. Let the caller know the reply will come in later.
        $p->{proxied}++;
        return ($main::IGNORE,'Sent initial auth response. Waiting for server reply.');
    }
    elsif ($p->code eq 'Accounting-Request')
    {
        return ($main::ACCEPT,'Accounting-Request accepted');
    }
    else
    {
        return ($main::REJECT,'Unknown request code: '. $p->code);
    }
}

#####################################################################
# This function will be called during SIGHUP
# Its class-specific, not object-specific
# Override it to do any module specific reinitialization
# it could reload any state, perhaps by rereading files, 
# reconnecting to a database or something like that.
# You usually dont need to do anything here, and can remove this function
#sub reinitialize
#{
#}

#####################################################################
# Optionally handle object destruction
# You usually dont need to do anything here, and can remove this function
#sub DESTROY
#{
#}



#####################################################################
# Builds ssl options based on configuration 
# which will be used to perform https requests
sub build_ssl_options
{
    my ($self) = @_;
    my %ssl_opts = ();

    $ssl_opts{SSL_ca_file} = Radius::util::format_special($self->{sslCAFile})
    if defined $self->{sslCAFile};

    $ssl_opts{SSL_ca_path} = Radius::util::format_special($self->{sslCAPath})
    if defined $self->{sslCAPath};

    $ssl_opts{SSL_verify_mode} = $self->{sslVerifyCert}
    if defined $self->{sslVerifyCert};

    $ssl_opts{SSL_verifycn_scheme} = $self->{sslVerifyCnScheme}
    if defined $self->{sslVerifyCnScheme};

    $ssl_opts{SSL_verifycn_name} = $self->{sslVerifyCnName}
    if defined $self->{sslVerifyCnName};

    return %ssl_opts;
}

######################################################################
# Parse and verify an id token 
sub parse_and_verify_id_token
{
    my ($self,$data) = @_;
    my $id_token;
    eval {$id_token = decode_jwt(token=>$data,kid_keys=>$self->{jwksData});};
    if(!defined $id_token)
    {
        $self->log($main::LOG_DEBUG,"id_token verification failed. $@.");
        return undef;        
    }
    return $id_token;
}


######################################################################
# Generates a jwt client assertion which will be used to authenticate
# Our requests to the server's OpenID token endpoint 
# 
sub generate_client_assertion 
{
    my ($self) = @_;

    # prepare claims
    my $issued_at = time();
    my $expires_at = $issued_at + $self->{jwtExpiryTime};
    my $algorithm = $self->{signatureAlgorithm};
    my %jwt_claims = (
        'iss' => $self->{clientId},
        'sub' => $self->{clientId},
        'aud' => $self->{tokenEndpoint},
        'jti' => lc $self->{uuidGenerator}->to_string($self->{uuidGenerator}->create()),
        'iat' => $issued_at,
        'exp' => $expires_at
    );

    # prepare extra headers 
    my %additional_headers = ();
    $additional_headers{'kid'} = $self->{signaturePkeyId} if $self->{signaturePkeyId};

    my %jwt_encode_params = (
        payload => \%jwt_claims,
        alg => $algorithm,
        key => \$self->{signaturePkey},
        extra_headers => \%additional_headers
    );
    
    $jwt_encode_params{keypass} = $self->{signaturePkeyPassword} 
    if defined $self->{signaturePkeyPassword};

    my $jwt_encoded_string;
    eval { $jwt_encoded_string = encode_jwt(%jwt_encode_params);};
    if($@) 
    {
        $self->log($main::LOG_DEBUG,"Could not generate client assertion. $@.");
        return undef;
    }
    else 
    {
        return $jwt_encoded_string;
    }
    
}

################################################################
# Creates an HTTP::Request object that can be used
# to perform an operation on the server's OpenID token endpoint 
# with the grant_type set to 'password'
sub build_ro_password_auth_request
{
    my ($self, $username, $password, $step, $scopes, $remoteip,$sessionid) = @_;

    return undef if (!$self->{tokenEndpoint});

    # create post param body
    my $grant_type = $Radius::AuthGLUU::GRANT_TYPE::RO_PASSWORD_CREDENTIALS;
    my $client_assertion_type = $Radius::AuthGLUU::CLIENT_ASSERTION_TYPE::JWT_BEARER;
    my $client_assertion = $self->generate_client_assertion();
    my $auth_scheme = "twostep";
    $auth_scheme = "onestep" if ($self->{twoStepStatus} == $Radius::AuthGLUU::TWOSTEP_DISABLED);
    return undef if (!defined $client_assertion);
    
    my %ro_params = (
        $Radius::AuthGLUU::TOKEN_PARAM::GRANT_TYPE => $grant_type,
        $Radius::AuthGLUU::TOKEN_PARAM::USERNAME => $username,
        $Radius::AuthGLUU::TOKEN_PARAM::PASSWORD => $password,
        $Radius::AuthGLUU::TOKEN_PARAM::CLIENT_ID => $self->{clientId},
        $Radius::AuthGLUU::TOKEN_PARAM::STEP => $step,
        $Radius::AuthGLUU::TOKEN_PARAM::CLIENT_ASSERTION_TYPE => $client_assertion_type,
        $Radius::AuthGLUU::TOKEN_PARAM::CLIENT_ASSERTION => $client_assertion,
        $Radius::AuthGLUU::TOKEN_PARAM::AUTH_SCHEME => $auth_scheme 
    );

    $ro_params{$Radius::AuthGLUU::TOKEN_PARAM::REMOTE_IP} = $remoteip 
    if defined $remoteip;
    $ro_params{$Radius::AuthGLUU::TOKEN_PARAM::SESSION_ID} = $sessionid;
    $ro_params{$Radius::AuthGLUU::TOKEN_PARAM::SCOPE} = join(" ",@$scopes) 
    if (defined $scopes &&  @$scopes);
    $ro_params{$Radius::AuthGLUU::TOKEN_PARAM::ACR_VALUES} = $self->{acrValues} 
    if defined $self->{acrValues};

    my @ro_params_array = map {"$_=" . URI::Escape::uri_escape_utf8($ro_params{$_})} sort keys %ro_params;
    my $request_body = encode_utf8(join("&",@ro_params_array));

    # request http headers 
    my $request_headers = [
        'Content-Type'=>'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept' => '*/*'
    ];
    
    return HTTP::Request->new('POST',$self->{tokenEndpoint},$request_headers,$request_body);
}

#############################################################
# Creates an HTTP::Request object which can be used to fetch 
# the server's OpenID configuration
#
sub build_openid_configuration_request
{
    my ($self) = @_;
    my $request_url = "$self->{gluuServerUrl}/.well-known/openid-configuration";
    return HTTP::Request->new('GET',$request_url);
}

##############################################################
# Creates an HTTP::Request object which can be used to fetch
# the server's jwks used for signature verification
#
sub build_server_keyset_download_request
{
    my ($self) = @_;
    return undef if(!$self->{jwksUri});
    return HTTP::Request->new('GET',$self->{jwksUri});
}

###############################################################
# Creates an HTTP::Request object which can be used to check 
# the authentication status of a session, given it's session id
#
sub build_session_status_check_request
{
    my ($self,$session_id) = @_;
    my $request_url = "$self->{gluuServerUrl}/oxauth/restv1/session_status";
    my $request_headers = [
        'Accept' => '*/*',
        "Cookie" =>  "session_id=$session_id" 
    ];
    return HTTP::Request->new('GET',$request_url,$request_headers);
}

########################################################################
# Associates a request context to a http request id 
# which can be eventually retried using the get_http_request_context
# method.
#
sub map_request_id_to_context
{
    my ($self, $id, $context) = @_;
    $self->{requestMap}{$id} = $context;
    return;
}

###########################################################################
# Retrieves the associated context for a request from our internal hashmap
# given it's request id. Returns undef if there is no request queued which 
# corresponds to the request id specified.
sub get_http_context_from_request_id
{
    my ($self,$id) = @_;
    my $context = delete $self->{requestMap}{$id};
    return $context;
}


############################################################################
# Submits an http request , and saves the request's context data for future
# access when the request completes or fails.
# 
sub submit_http_request
{
    my ($self,$request,$context,$opts) = @_;
    my $request_id;

    # log the request as a string 
    $self->log($main::LOG_EXTRA_DEBUG,$request->as_string());

    if($opts)
    {
        eval { $request_id = $self->{async}->add_with_opts($request,$opts); };
    }
    else
    {
        eval { $request_id = $self->{async}->add($request); };
    }
    if(defined $request_id) {
        $self->map_request_id_to_context($request_id,$context);
        return 1;
    }else {
        $self->log($main::LOG_WARNING,"Could not add http request to queue");
        return undef;
    }
}

###############################################################################
# Creates a http request context of a specific type 
#
sub create_http_request_context
{
    my ($self,$type,$context_data) = @_;
    my $context;
    if(defined $context_data)
    {
        $context = { context_type => $type, %{$context_data}};
    }
    else
    {
        $context = {context_type => $type};
    }

    return $context;
}

##################################################################
# Method used to perform various housekeeping functions
# Call it as often as possible.
#
sub perform_housekeeping
{
    my ($self) = @_;
    $self->{async}->poke();
    return;
}

##################################################################
# User authentication management methods  
#

##################################################################
# Method to perform an initial authentication 
sub perform_initial_authentication
{
    my ($self,$username,$password,$remoteip) = @_;
    my $step = $Radius::AuthGLUU::AUTH_STEP::INIT_AUTH;
    my $scopes = \@{$self->{scopes}};
    my $authrequest = $self->build_ro_password_auth_request($username,$password,$step,$scopes,$remoteip);
    if(!defined $authrequest) 
    {
        $self->log($main::LOG_WARNING,'Building the ro password authentication request failed.');
        return undef;
    }
    my $ctx_type = $Radius::AuthGLUU::CONTEXT_TYPE::INIT_AUTH_REQUEST;
    my $ctx = $self->create_http_request_context($ctx_type);
    $self->submit_http_request($authrequest,$ctx);
    return $ctx;
}

######################################################################
# Method to re-send a push notification , combined with authentication
sub perform_resend_notification
{
    my ($self,$username,$password,$remoteip,$sessionid) = @_;
    my $step = $Radius::AuthGLUU::AUTH_STEP::RESEND_NOTIFICATION;
    my $scopes = \@{$self->{scopes}};
    my $authrequest = $self->build_ro_password_auth_request($username,$password,$step,$scopes,$remoteip,$sessionid);
    if(!defined $authrequest)
    {
        $self->log($main::LOG_WARNING,'Building the ro password authentication request failed.');
        return undef;
    }
    my $ctx_type = $Radius::AuthGLUU::CONTEXT_TYPE::RESEND_NOTIFICATION_REQUEST;
    my $additional_context_data = {};
    my $ctx = $self->create_http_request_context($ctx_type,$additional_context_data);
    $self->submit_http_request($authrequest,$ctx);
    return $ctx;
}

#######################################################################
# Method to verify authentication status
sub perform_verify_authentication
{
    my ($self,$username,$password,$sessionid) = @_;
    my $step = $Radius::AuthGLUU::AUTH_STEP::VERIFY_AUTH;
    my $scopes = \@{$self->{scopes}};
    my $authrequest = $self->build_ro_password_auth_request($username,$password,$step,$scopes,undef,$sessionid);
    if(!defined $authrequest)
    {
        $self->log($main::LOG_WARNING,'Building the ro password authentication request failed.');
        return undef;
    }

    my $ctx_type = $Radius::AuthGLUU::CONTEXT_TYPE::VERIFY_AUTH_REQUEST;
    my $additional_context_data = {};
    my $ctx = $self->create_http_request_context($ctx_type,$additional_context_data);
    $self->submit_http_request($authrequest,$ctx);
    return $ctx;
}

####################################################################
# Method to perform a session status check 
#
sub perform_status_check
{
    my ($self,$session_id) = @_;
    my $statusrequest = $self->build_session_status_check_request($session_id);
    if(!defined $statusrequest)
    {
        $self->log($main::LOG_WARNING,'Building the session status request failed.');
        return undef;
    }
    my $ctx_type = $Radius::AuthGLUU::CONTEXT_TYPE::STATUS_REQUEST;
    my $additional_context_data = {};
    my $ctx = $self->create_http_request_context($ctx_type,$additional_context_data);
    $self->submit_http_request($statusrequest,$ctx);
    return $ctx;
}

####################################################################
# Sends an openid configuration request
#
sub send_openid_configuration_request
{
    my ($self) = @_;
    my $request = $self->build_openid_configuration_request();
    my $ctx_type = $Radius::AuthGLUU::CONTEXT_TYPE::OPENID_REQUEST;
    my $ctx = $self->create_http_request_context($ctx_type);
    $self->submit_http_request($request,$ctx);
    return $ctx;
}

####################################################################
# Schedules an openid configuration request 
sub schedule_openid_configuration_request
{
    my ($self,$delay) = @_;

    Radius::Select::remove_timeout($self->{openidTimer})
    if defined $self->{openidTimer};

    Radius::Select::add_timeout (
        time + $delay,
        \&openid_configuration_timer_elapsed,
        $self
    );

    return;
}

########################################################################
# Sends a jwks download request
sub send_jwks_download_request
{
    my ($self) = @_;

    my $request = $self->build_server_keyset_download_request();
    my $ctx_type = $Radius::AuthGLUU::CONTEXT_TYPE::JWKS_DOWNLOAD_REQUEST;
    my $ctx = $self->create_http_request_context($ctx_type);
    $self->submit_http_request($request,$ctx);

    return $ctx;
}

###########################################################################
# Schedules a jwks download request 
sub schedule_jwks_download_request
{
    my ($self,$delay) = @_;
    Radius::Select::remove_timeout($self->{jwksTimer})
    if defined $self->{jwksTimer};

    Radius::Select::add_timeout (
        time + $delay,
        \&jwks_download_timer_elapsed,
        $self
    );

    return;
}


#######################################################################
# called when the openid configuration timer elapses 
sub openid_configuration_timer_elapsed
{
    my ($handle,$self) = @_;
    $self->log($main::LOG_DEBUG,"Sending scheduled openid configuration request.");
    $self->send_openid_configuration_request();
}

######################################################
# Starts the thread used to process http responses 
#
sub start_http_response_processing_timer
{
    my ($self) = @_;
    Radius::Select::remove_timeout($self->{httpResponseTimer})
    if $self->{httpResponseTimer};

    $self->{httpResponseTimer} = Radius::Select::add_timeout(
        time + $self->{pollInterval},
        \&on_http_response_timer_elapsed,
        $self
    );
}

#############################################################
# subroutine called when http response timer elapses
#
sub on_http_response_timer_elapsed
{
    my ($handle,$self) = @_;
    $self->perform_housekeeping();
    $self->process_http_responses();
    $self->start_http_response_processing_timer();
}

#############################################################
# Process responses in the async queue from the Gluu server
# Gluu server.
#
sub process_http_responses
{
    my ($self) = @_;
    while(my ($response,$id) = $self->{async}->next_response)
    {
        $self->log($main::LOG_EXTRA_DEBUG,$response->as_string());

        my $context = $self->get_http_context_from_request_id($id);

        if($context->{context_type} eq $Radius::AuthGLUU::CONTEXT_TYPE::OPENID_REQUEST) 
        {
            $self->process_openid_configuration_response($response,$context);
        }
        elsif($context->{context_type} eq $Radius::AuthGLUU::CONTEXT_TYPE::JWKS_DOWNLOAD_REQUEST)
        {
            $self->process_jwks_download_response($response,$context);
        }
        elsif($context->{context_type} eq $Radius::AuthGLUU::CONTEXT_TYPE::INIT_AUTH_REQUEST)
        {
            my $ok_ref = $self->can('on_init_auth_success');
            my $error_ref = $self->can('on_init_auth_error');
            $self->process_ro_password_auth_response($response,$context,$ok_ref,$error_ref);
        }
        elsif($context->{context_type} eq $Radius::AuthGLUU::CONTEXT_TYPE::VERIFY_AUTH_REQUEST)
        {
            my $ok_ref = $self->can('on_verify_auth_success');
            my $error_ref = $self->can('on_verify_auth_error');
            $self->process_ro_password_auth_response($response,$context,$ok_ref,$error_ref);
        }
        elsif($context->{context_type} eq $Radius::AuthGLUU::CONTEXT_TYPE::RESEND_NOTIFICATION_REQUEST)
        {
            my $ok_ref = $self->can('on_resend_notification_success');
            my $error_ref = $self->can('on_resend_notification_error');
            $self->process_ro_password_auth_response($response,$context,$ok_ref,$error_ref);
        }
        elsif($context->{context_type} eq $Radius::AuthGLUU::CONTEXT_TYPE::STATUS_REQUEST)
        {
            $self->process_status_request_response($response,$context);

        }
    }
    return;
}

##############################################################
# Processes a single openid response from the server 
#
sub process_openid_configuration_response
{ 
   my ($self,$response) = @_;
   if($response->code() == 200)
   {
       my $content = $response->decoded_content();
       my $json_response;
       eval{ $json_response = $self->{json}->decode($content);};
       if($@)
       {
           $self->log($main::LOG_WARNING,"OpenId configuration response decoding failed. $@.");
           $self->log($main::LOG_DEBUG,"Scheduling openid configuration download.");
           $self->schedule_openid_configuration_request($self->{retryInterval});
       }
       else
       {
           if(exists $json_response->{'token_endpoint'} && exists $json_response->{'jwks_uri'})
           {
               $self->{tokenEndpoint} = $json_response->{'token_endpoint'};
               $self->{jwksUri} = $json_response->{'jwks_uri'};
               $self->log($main::LOG_DEBUG,"Downloading signing verification keys from server.");
               $self->send_jwks_download_request();
           }
           else
           {
               $self->log($main::LOG_WARNING,"OpenId configuration response does not contain configuration items.");
               $self->log($main::LOG_DEBUG,"Scheduling openid configuration download.");
               $self->schedule_openid_configuration_request($self->{retryInterval});
           }
       }
   }
   else
   {
       my $httpstatus = $response->status_line();
       $self->log($main::LOG_WARNING,"OpenId configuration download failed. ${httpstatus}.");
       $self->log($main::LOG_DEBUG,"Scheduling openid configuration download.");
       $self->schedule_openid_configuration_request($self->{retryInterval});
   }
}

#########################################################################
# Process a single jwks download request from the server 
#
sub process_jwks_download_response
{
    my ($self,$response) = @_;
    if($response->code() == 200)
    {
        my $content = $response->decoded_content();
        eval {$self->{jwksData} = $self->{json}->decode($content);};
        if($@)
        {
            $self->log($main::LOG_WARNING,"Signing verification keys download failed. $@.");
            $self->log($main::LOG_DEBUG,"Scheduling signing verification keys download.");
            $self->schedule_jwks_download_request($self->{retryInterval});
        }
        else
        {
            # in the future , we may verify if we in deed got jwks keys 
            $self->log($main::LOG_DEBUG,"JWKS verification keys download complete. Plugin ready.");
            $self->{ready} = 1;
            $self->log($main::LOG_INFO,"$class plugin active.");
        }
    }
    else
    {
       my $httpstatus = $response->status_line();
       $self->log($main::LOG_WARNING,"Signing verification keys download failed. ${httpstatus}.");
       $self->log($main::LOG_DEBUG,"Scheduling signing verification keys download.");
       $self->schedule_jwks_download_request($self->{retryInterval});
    }
}

########################################################################
# Process authentication init response 
#
sub process_ro_password_auth_response
{
    my ($self,$response,$context,$on_success,$on_failure) = @_;

    if($response->code() == 200) 
    {
        my $decoded_content = $response->decoded_content();
        my $json_response;

        eval {$json_response = $self->{json}->decode($decoded_content);};
        if(!defined $json_response)
        {
            $self->log($main::LOG_DEBUG_EXTRA,"Invalid server response: $decoded_content .");
            $on_failure->($self,$response,$context,'Malformed server response.');
            return;
        }

        # find out if this is an initiate auth response 
        # and if we're authenticating using one-step , return success right now 
        my $ctx_type = $context->{'context_type'};
        if($ctx_type == $Radius::AuthGLUU::CONTEXT_TYPE::INIT_AUTH_REQUEST)
        {
            if($self->{twoStepStatus} == $Radius::AuthGLUU::TWOSTEP_DISABLED)
            {
                $on_success->($self,undef,$context);
                return;
            }
        } 

        my $id_token_str = $json_response->{id_token};
        if(!defined $id_token_str)
        {
            $self->log($main::LOG_DEBUG_EXTRA,"Server response does not contain id_token.");
            $on_failure->($self,$response,$context,'Malformed server response.');
            return;
        }

        my $id_token = $self->parse_and_verify_id_token($id_token_str);
        $on_success->($self,$id_token,$context);
        return;

    }
    else
    {
        my $code = $response->code();
        $self->log($main::LOG_DEBUG,"Unknown server error (${code}).");
        $on_failure->($self,$response,$context,'Unknown server error.');
        return;
    }
}

#################################################################
# Process status request responses
#
sub process_status_request_response
{
    my ($self,$response,$context) = @_;
    if($response->code() == 200)
    {
        my $decoded_content = $response->decoded_content();
        my $json_status;
        eval {$json_status = $self->{json}->decode($decoded_content);};
        if(!defined $json_status)
        {
            $self->log($main::LOG_DEBUG_EXTRA,"Invalid server response: $decoded_content.");
            $self->on_session_status_error($response,$context,'Invalid auth status response.');
            return;
        }

        if(exists $json_status->{'state'} && exists $json_status->{'custom_state'})
        {
            my $state = $json_status->{'state'};
            my $custom_state = $json_status->{'custom_state'};
            my $session_status;
            if(($state eq 'unknown') || (($state eq 'unauthenticated') && ($custom_state =~/(declined|expired)/i)))
            {
                # unauthenticated session
                $session_status = $Radius::AuthGLUU::SESSION_STATUS::UNAUTHENTICATED;
            }
            elsif(($state eq 'authenticated') || (($state eq 'unauthenticated') && ($custom_state eq 'approved'))) 
            {
                # authenticated session
                $session_status = $Radius::AuthGLUU::SESSION_STATUS::AUTHENTICATED;
            }
            else
            {
                # we play it safe and set it to unauthenticated
                $session_status = $Radius::AuthGLUU::SESSION_STATUS::UNAUTHENTICATED;
            }

            $self->on_session_status_success($session_status,$context);
        }
        else
        {
            $self->log($main::LOG_DEBUG_EXTRA,"Unknown server response: $decoded_content.");
            $self->on_session_status_error($response,$context,'Unknown auth status response');
        }

        return;
    }
    else
    {
        my $code = $response->code();
        $self->log($main::LOG_DEBUG,"Unknown server error (${code}).");
        $self->on_session_status_error($response,$context,'Unknown auth status server error.');
    }
}

##############################################################
# Methods called when particular events happen

##############################################################
# Method called when init auth succeed
# 
sub on_init_auth_success
{
    my ($self,$id_token,$context) = @_;
    if($self->{twoStepStatus} == $Radius::AuthGLUU::TWOSTEP_DISABLED)
    {
        my $p = $context->{'packet'};
        $p->{Handler}->handlerResult($p,$main::ACCEPT,'User authenticated successfully');
        return;
    }
    my $sessionid = $id_token->{'__session_id'};
    my $username = $context->{'packet'}->getUserName();
    $self->log($main::LOG_DEBUG,"Init auth success ($username). Performing status check.");
    my $newcontext = $self->perform_status_check($sessionid);
    $newcontext->{'sessionid'} = $sessionid;
    $newcontext->{'packet'} = $context->{'packet'};
    $newcontext->{'start_time'} = $context->{'start_time'};
}

###############################################################
# Method called when init auth fails
# 
sub on_init_auth_error
{
    my ($self,$response,$context,$description) = @_;
    my $username = $context->{'packet'}->getUserName();
    $self->log($main::LOG_DEBUG,"Init auth failed ($username). $description");
    my $p = $context->{'packet'};

    my $replymessage;
    my $code = $response->code();
    if($code >=400 && $code < 500)
    {
        $replymessage = "Server authentication failed ($code). Check if you have an enrolled device.";
    }
    elsif($code >=500)
    {
        $replymessage = "A server error occured ($code). Please contact your administrator.";
    }
    else
    {
        $replymessage = "An error occured ($code). Please contact your administrator.";
    }

    $p->{Handler}->handlerResult($p,$main::REJECT,$replymessage);
}

###################################################################
# Method called when resend notification succeeds
#
sub on_resend_notification_success
{
    ...
}

###################################################################
# Method called when resend notification fails 
#
sub on_resend_notification_error
{
    ...
}


###################################################################
# Method called when verify auth succeeds 
#
sub on_verify_auth_success
{
    my ($self,$id_token,$context) = @_;
    my $p = $context->{'packet'};
    my $username = $p->getUserName();
    $self->log($main::LOG_DEBUG,"Authentication success ($username).");
    $p->{Handler}->handlerResult($p,$main::ACCEPT,'User authenticated successfully.');
    return;
}

####################################################################
# Method called when verify auth fails
sub on_verify_auth_error
{
    my ($self,$response,$context,$description) = @_;
    my $p = $context->{'packet'};
    my $username = $p->getUserName();
    $self->log($main::LOG_DEBUG,"Authentication verification failed ($username).");
    $p->{Handler}->handlerResult($p,$main::REJECT,'Authentication failed due to verification error.');
    return;
}

################################################################
# Method called when a session status check succeeds
#
sub on_session_status_success
{
    my ($self,$session_status,$context) = @_;
    my $p = $context->{'packet'};
    my $sessionid = $context->{'sessionid'};
    my $start_time = $context->{'start_time'};
     my $username = $p->getUserName();
    if($session_status == $Radius::AuthGLUU::SESSION_STATUS::AUTHENTICATED)
    {
        my $password = $p->decodedPassword();
        $self->log($main::LOG_DEBUG,"Session status authenticated ($username). Performing auth verification.");
        my $newcontext = $self->perform_verify_authentication($username,$password,$sessionid); 
        $newcontext->{'packet'} = $context->{packet};
        $newcontext->{'sessionid'} = $sessionid;
        return;
    }
    # from here on , we assume the session is not authenticated 
    # check if the authentication has timed out
    my $time_elapsed = time() - $start_time;
    if($self->{authTimeout} <= $time_elapsed)
    {
        $self->log($main::LOG_DEBUG,"Authentication request timeout ($username).");
        $p->{Handler}->handlerResult($p,$main::REJECT,'Authentication request timeout');
        return;
    }

    # re-send session status request
    $self->log($main::LOG_DEBUG,"Session unauthenticated ($username). Re-sending session status request."); 
    my $newcontext = $self->perform_status_check($sessionid);
    $newcontext->{'sessionid'} = $sessionid;
    $newcontext->{'packet'} = $context->{'packet'};
    $newcontext->{'start_time'} = $context->{'start_time'};
    return;
}

################################################################
# Method called when a session status check fails 
#
sub on_session_status_error
{
    my ($self,$response,$context,$description) = @_;
    # In order to increase our chances of success 
    # We will re-send a status check request , unless the authentication timeout
    # has elapsed
    my $start_time = $context->{'start_time'};
    my $sessionid = $context->{'sessionid'}; 
    my $p = $context->{'packet'};
    if($self->{authTimeout} >= (time() - $start_time))
    {
        $p->{Handler}->handlerResult($p,$main::REJECT,'Authentication request timeout');
        return;
    }

    my $newcontext = $self->perform_status_check($sessionid);
    $newcontext->{'sessionid'} = $sessionid;
    $newcontext->{'packet'} = $context->{'packet'};
    $newcontext->{'start_time'} = $context->{'start_time'};
    return;
}

1;

