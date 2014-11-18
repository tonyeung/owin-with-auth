using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Topshelf;

namespace web
{
    public class Program
    {
        public static void Main()
        {
            HostFactory.Run(x =>
            {
                x.Service<StartUpOwin>
                (
                    s =>
                    {
                        s.ConstructUsing(() => new StartUpOwin());
                        s.WhenStarted((service, hostControl) => service.Start(hostControl));
                        s.WhenStopped((service, hostControl) => service.Stop(hostControl));
                    }
                );

                x.RunAsLocalSystem();
                x.SetDescription("owin self host web project");
                x.SetDisplayName("web-project");
                x.SetServiceName("web-project");
            });
        }
    }
}
