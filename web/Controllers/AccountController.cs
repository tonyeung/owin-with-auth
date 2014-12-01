using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;

namespace web.Controllers
{
    public class AccountController : ApiController
    {
        [HttpGet]
        [HttpPost]
        public async Task<IHttpActionResult> Login(string returnUrl = "")
        {
            // Request a redirect to the external login provider
            return new ChallengeResult("Google", this, returnUrl);
        }

        public HttpResponseMessage ExternalLoginCallback(string returnUrl)
        {
            var response = Request.CreateResponse(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = new Uri(returnUrl);
            return response;
        }

        public class ChallengeResult : IHttpActionResult 
        {
            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public HttpRequestMessage Request { get; set; }

            public ChallengeResult(string loginProvider, ApiController controller, string returnUrl)
            {
                LoginProvider = loginProvider;
                Request = controller.Request;
                RedirectUri = returnUrl;
            }

            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                var properties = new AuthenticationProperties() { RedirectUri = RedirectUri };
                Request.GetOwinContext().Authentication.Challenge(properties, LoginProvider);

                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.RequestMessage = Request;
                return Task.FromResult(response);
            }
        }
    }
}