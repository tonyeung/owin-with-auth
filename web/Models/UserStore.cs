using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace web.Models
{
    public class UserStore : IUserStore<User>, IUserPasswordStore<User>
    {
        //private CustomDbContext database;

        public UserStore()
        {
            //this.database = new CustomDbContext();
        }

        public void Dispose()
        {
            //this.database.Dispose();
        }

        public async Task CreateAsync(User user)
        {
            // TODO 
            Console.WriteLine("CreateAsync user");
        }

        public async Task UpdateAsync(User user)
        {
            // TODO 
            Console.WriteLine("UpdateAsync user");
        }

        public async Task DeleteAsync(User user)
        {
            // TODO 
            Console.WriteLine("DeleteAsync user");
        }

        public async Task<User> FindByIdAsync(string userId)
        {
            User user = new User()
            {
                Id = Guid.NewGuid().ToString(),
                UserName = "Foo"
            };
            return user;
        }

        public async Task<User> FindByNameAsync(string userName)
        {
            if (userName == "foo")
            {
                return new User()
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = "Foo"
                };                
            }
            return null;
        }

        public async Task<string> GetPasswordHashAsync(User user)
        {
            Console.WriteLine("GetPasswordHashAsync user");
            return "1F400.AOcgsxDHtYNiyQIQ01JF0oqjw1JNwF5+ug/qng3VzgVEstu8JaAIIfIrlI4FoVinRw==";
        }

        public async Task<bool> HasPasswordAsync(User user)
        {
            Console.WriteLine("HasPasswordAsync user");
            return true;
        }

        public async Task SetPasswordHashAsync(User user, string passwordHash)
        {
            Console.WriteLine("SetPasswordHashAsync");
            Console.WriteLine(passwordHash);
        }
    }
}
