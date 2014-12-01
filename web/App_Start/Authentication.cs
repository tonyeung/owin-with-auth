using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace web
{
    public partial class ConfigureOwin
    {
        public static GoogleOAuth2AuthenticationOptions googleAuthOptions { get; private set; }

        public void ConfigureAuth(IAppBuilder app)
        {
            var cookieOptions = new CookieAuthenticationOptions
            {
                LoginPath = new PathString("/api/Account/Login")
            };

            app.UseCookieAuthentication(cookieOptions);

            app.SetDefaultSignInAsAuthenticationType(cookieOptions.AuthenticationType);

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            {
                ClientId = "689994060053-m7o6obf8l89fgvj19p4u4kjtvvfrn47i.apps.googleusercontent.com",
                ClientSecret = "CRpFhh5JkKVTHXkgFeB3U0s4"
            });
        }
    }
}
