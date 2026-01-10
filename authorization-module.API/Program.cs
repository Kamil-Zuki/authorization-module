using authorization_module.API.Api.Grpc;
using authorization_module.API.Data;
using authorization_module.API.Data.Entities;
using authorization_module.API.Dtos;
using authorization_module.API.Exceptions;
using authorization_module.API.Interfaces;
using authorization_module.API.Services;
using authorization_module.API.Validations;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

#if RELEASE
builder.WebHost.UseUrls("http://*:80");
#endif

builder.Services.AddControllers();

builder.Services.AddDbContext<DataContext>(opt =>
    opt.UseNpgsql(builder.Configuration.GetConnectionString("Db")));


builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<DataContext>()
        .AddDefaultTokenProviders();

builder.Services.AddCors(options => options.AddPolicy("cors", policy =>
{
    policy.AllowAnyHeader()
          .AllowAnyMethod()
          .AllowAnyOrigin();
}));



builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, authorization_module.API.Services.AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();

//validation
builder.Services.AddScoped<IValidator<UserRegistrationRequest>, UserRegistrationValidator>();
builder.Services.AddScoped<IValidator<UserLoginRequest>, UserLoginValidator>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Personal Vocabulary API", Version = "v1" });
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration.GetValue<string>("Jwt:Issuer"),
        ValidAudience = builder.Configuration.GetValue<string>("Jwt:Audience"),
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetValue<string>("Jwt:Secret")!))
    };
});


builder.Services.AddAuthorization();

// Add gRPC services
builder.Services.AddGrpc(options =>
{
    options.MaxSendMessageSize = 1000 * 1024 * 1024; // 1 GB
    options.MaxReceiveMessageSize = 1000 * 1024 * 1024; // 1 GB
    options.EnableDetailedErrors = true;
});

var app = builder.Build();

app.UseMiddleware<ExceptionHandlingMiddleware>();

app.UseCors("cors");

app.UseAuthentication();

app.UseAuthorization();

//app.UseHttpsRedirection();



app.UseSwagger(c =>
{
    c.RouteTemplate = "authorization-module/swagger/{documentname}/swagger.json";
});
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/authorization-module/swagger/v1/swagger.json", "Authorization API");
    c.RoutePrefix = "authorization-module/swagger";
});

app.Use(async (context, next) =>
{
    var authHeader = context.Request.Headers["Authorization"].ToString();
    app.Logger.LogInformation("Raw Authorization Header: '{Header}'", authHeader);
    await next(context);
});

// Map gRPC services
app.MapGrpcService<authorization_module.API.Api.Grpc.AuthService>();

app.MapControllers();

app.Run();
