using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace web
{
    public class Sample : ISample
    {
        public string GetDate()
        {
            return DateTime.UtcNow.ToShortDateString();
        }
    }
}
