using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace web.Controllers
{
    [Authorize]
    public class TestController : ApiController
    {
        private readonly ISample sample;

        public TestController(ISample Sample)
        {
            this.sample = Sample;
        }


        [HttpGet]
        public string Get()
        {
            return sample.GetDate();
        }
    }
}