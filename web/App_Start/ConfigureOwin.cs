using Owin;
using StructureMap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Http;
using System.Web.Http.Dispatcher;

namespace web
{
    public class ConfigureOwin
    {
        public void Configure(IAppBuilder appBuilder)
        {
            HttpConfiguration config = new HttpConfiguration();

            IContainer container = IoC.Initialize();
            config.Services.Replace(typeof(IHttpControllerActivator), new StructureMapHttpControllerActivator(container));

            config.MapHttpAttributeRoutes();
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            appBuilder.UseWebApi(config);
        }
    }
}
