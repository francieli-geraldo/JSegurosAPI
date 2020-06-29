using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using JSegurosAPI.Entities;

namespace JSegurosAPI.Helpers
{
    public class DataContext : DbContext
    {
        protected readonly IConfiguration Configuration;

        public DataContext(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            options.UseSqlServer(Configuration.GetConnectionString("JSegurosDatabase"));
        }

        public DbSet<User> Users { get; set; }
    }
}