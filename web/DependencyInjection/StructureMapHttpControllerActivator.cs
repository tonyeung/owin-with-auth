using StructureMap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Web.Http.Controllers;
using System.Web.Http.Dispatcher;

namespace web
{
    public class StructureMapHttpControllerActivator : IHttpControllerActivator
    {
        IContainer container = null;
        public StructureMapHttpControllerActivator(IContainer Container)
        {
            container = Container;
        }

        public IHttpController Create(HttpRequestMessage request, HttpControllerDescriptor controllerDescriptor, Type controllerType)
        {
            var controller = container.GetInstance(controllerType) as IHttpController;
            return controller;
        }
    }
}
