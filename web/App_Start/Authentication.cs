using BrockAllen.IdentityReboot;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using web.Models;

namespace web
{
    public partial class ConfigureOwin
    {
        public static GoogleOAuth2AuthenticationOptions googleAuthOptions { get; private set; }
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }

        //public void ConfigureAuth(IAppBuilder app)
        //{
        //    var cookieOptions = new CookieAuthenticationOptions
        //    {
        //        LoginPath = new PathString("/api/Account/Login")
        //    };

        //    app.UseCookieAuthentication(cookieOptions);
        //    app.SetDefaultSignInAsAuthenticationType(cookieOptions.AuthenticationType);
            
        //    googleAuthOptions = new GoogleOAuth2AuthenticationOptions()
        //    {
        //        ClientId = "689994060053-m7o6obf8l89fgvj19p4u4kjtvvfrn47i.apps.googleusercontent.com",
        //        ClientSecret = "CRpFhh5JkKVTHXkgFeB3U0s4"
        //    };
        //    app.UseGoogleAuthentication(googleAuthOptions);
        //}


        public void ConfigureOAuth(IAppBuilder app)
        {

            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {

                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                Provider = new SimpleAuthorizationServerProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);

            //Configure Google External Login
            googleAuthOptions = new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "689994060053-m7o6obf8l89fgvj19p4u4kjtvvfrn47i.apps.googleusercontent.com",
                ClientSecret = "CRpFhh5JkKVTHXkgFeB3U0s4",
                Provider = new GoogleAuthProvider()
            };
            app.UseGoogleAuthentication(googleAuthOptions);            
        }
    }

    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            var usermanager = new IdentityRebootUserManager<User>(new UserStore());

            var user = await usermanager.FindAsync(context.UserName, context.Password);
            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim("role", "user"));

            context.Validated(identity);
        }
    }

    public class GoogleAuthProvider : IGoogleOAuth2AuthenticationProvider
    {
        public void ApplyRedirect(GoogleOAuth2ApplyRedirectContext context)
        {
            context.Response.Redirect(context.RedirectUri);
        }

        public Task Authenticated(GoogleOAuth2AuthenticatedContext context)
        {
            context.Identity.AddClaim(new Claim("ExternalAccessToken", context.AccessToken));
            return Task.FromResult<object>(null);
        }

        public Task ReturnEndpoint(GoogleOAuth2ReturnEndpointContext context)
        {
            return Task.FromResult<object>(null);
        }
    }
}
