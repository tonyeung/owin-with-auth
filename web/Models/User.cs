using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace web.Models
{
    public class User : IUser<string>
    {
        public string Id { get; set; }

        public string UserName { get; set; }
    }
}
