using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Glosslore_authorization.Web.Data.Entities;

namespace Glosslore_authorization.Web.Data;

public sealed class DataContext : IdentityDbContext<ApplicationUser, IdentityRole<long>, long>
{
    public DataContext (DbContextOptions<DataContext> options)
        : base(options)
    {
        Database.Migrate();
    }

    public DbSet<Application> Applications { get; set; } = null!;
    public DbSet<SampleData> SampleDatas { get; set; } = null!;
}