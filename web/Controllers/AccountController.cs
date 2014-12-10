using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using Microsoft.Owin.Security.OAuth;
using web.Models;
using BrockAllen.IdentityReboot;

namespace web.Controllers
{
    /// <summary>
    /// This class only contains methods to authenticate via google
    /// username/password authentication occurs in the SimpleAuthorizationServerProvider class in the /App_Start/Authentication.cs file
    /// the url for username/password authentication is /token
    /// </summary>
    public class AccountController : ApiController
    {


        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        public async Task<IHttpActionResult> GetGoogleLogin()
        {
            // Request a redirect to the external login provider
            if (User == null || !User.Identity.IsAuthenticated)
            {
                return new ChallengeResult("Google", this);
            }

            var usermanager = new IdentityRebootUserManager<User>(new UserStore());

            var idResult = await usermanager.CreateAsync(new User() { UserName = "User" }, "password");

            return Ok(GenerateLocalAccessTokenResponse("sumuser"));
        }

        private JObject GenerateLocalAccessTokenResponse(string userName)
        {
            var tokenExpiration = TimeSpan.FromDays(1);

            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            identity.AddClaim(new Claim("role", "user"));

            var props = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpiration),
            };

            var ticket = new AuthenticationTicket(identity, props);

            var accessToken = ConfigureOwin.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);

            JObject tokenResponse = new JObject(
                                        new JProperty("access_token", accessToken),
                                        new JProperty("token_type", "bearer"),
                                        new JProperty("expires_in", tokenExpiration.TotalSeconds.ToString()
                                        )
            );

            return tokenResponse;
        }

        public class ChallengeResult : IHttpActionResult 
        {
            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public HttpRequestMessage Request { get; set; }

            public ChallengeResult(string loginProvider, ApiController controller)
            {
                LoginProvider = loginProvider;
                Request = controller.Request;
            }

            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                Request.GetOwinContext().Authentication.Challenge(LoginProvider);

                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.RequestMessage = Request;
                return Task.FromResult(response);
            }
        }
    }
}