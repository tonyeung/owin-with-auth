using StructureMap;
using StructureMap.Graph;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace web
{
    public static class IoC
    {
        public static IContainer Initialize()
        {
            return new Container(x =>
            {
                x.Scan(scan =>
                {
                    scan.AssembliesFromApplicationBaseDirectory();
                    scan.ExcludeNamespace("StructureMap");
                    scan.WithDefaultConventions();
                });
            });
        }
    }
}
