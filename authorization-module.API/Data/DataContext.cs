using authorization_module.API.Data.Entities;
using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.EntityFramework.Interfaces;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace authorization_module.API.Data;

public sealed class DataContext : IdentityDbContext<ApplicationUser>, IConfigurationDbContext, IPersistedGrantDbContext
{
    public DbSet<ApplicationUser> ApplicationUsers { get; set; } = null!;

    // Configuration store tables
    public DbSet<Client> Clients { get; set; } = null!;
    public DbSet<IdentityResource> IdentityResources { get; set; } = null!;
    public DbSet<ApiResource> ApiResources { get; set; } = null!;
    public DbSet<ApiScope> ApiScopes { get; set; } = null!;
    public DbSet<IdentityProvider> IdentityProviders { get; set; } = null!;
    public DbSet<ClientCorsOrigin> ClientCorsOrigins { get; set; } = null!;

    // Operational store tables
    public DbSet<PersistedGrant> PersistedGrants { get; set; } = null!;
    public DbSet<DeviceFlowCodes> DeviceFlowCodes { get; set; } = null!;
    public DbSet<Key> Keys { get; set; } = null!;
    public DbSet<ServerSideSession> ServerSideSessions { get; set; } = null!;
    public DbSet<PushedAuthorizationRequest> PushedAuthorizationRequests { get; set; } = null!;

    public DataContext(DbContextOptions<DataContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<PersistedGrant>(entity =>
        {
            entity.HasKey(e => e.Key);
            entity.HasIndex(e => e.SubjectId);
        });

        modelBuilder.Entity<DeviceFlowCodes>(entity =>
        {
            entity.HasKey(e => e.DeviceCode);
            entity.HasIndex(e => e.UserCode);
        });

        modelBuilder.Entity<Client>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<IdentityResource>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<ApiResource>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<ApiScope>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<IdentityProvider>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<ClientCorsOrigin>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<Key>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<ServerSideSession>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<PushedAuthorizationRequest>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<PersistedGrant>(entity =>
        {
            entity.HasKey(e => e.Key);
            entity.Property(e => e.Key).ValueGeneratedOnAdd(); // Ensure Key is auto-generated
            entity.HasIndex(e => e.SubjectId);
        });
    }
}