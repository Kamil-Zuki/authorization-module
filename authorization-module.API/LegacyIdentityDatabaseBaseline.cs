using authorization_module.API.Data;
using Microsoft.EntityFrameworkCore;

namespace authorization_module.API;

/// <summary>
/// Совместимость со старыми БД: схема создавалась через EnsureCreated без таблицы истории миграций.
/// Иначе Migrate() снова применяет начальную миграцию и падает с 42P07 (relation already exists).
/// </summary>
internal static class LegacyIdentityDatabaseBaseline
{
    private const string InitialMigrationId = "20241104103315_AddApplicationUser";

    // Совпадает с ProductVersion в Migrations/20241104103315_AddApplicationUser.Designer.cs
    private const string EfProductVersion = "8.0.10";

    public static void EnsureBaselineBeforeMigrate(DataContext db)
    {
        db.Database.ExecuteSqlRaw(
            """
            CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" (
                "MigrationId" character varying(150) NOT NULL,
                "ProductVersion" character varying(32) NOT NULL,
                CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
            );
            """);

        db.Database.ExecuteSqlRaw(
            $"""
            INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
            SELECT '{InitialMigrationId}', '{EfProductVersion}'
            WHERE EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'AspNetRoles'
            )
            AND NOT EXISTS (
                SELECT 1 FROM "__EFMigrationsHistory"
                WHERE "MigrationId" = '{InitialMigrationId}'
            );
            """);
    }
}
