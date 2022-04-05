using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Identity;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;
using OpenTelemetry;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using poc_minimal_api.Data;
using poc_minimal_api.Models;
using System.Diagnostics;

var builder = WebApplication.CreateBuilder(args);


#region Configure Service

var nome = "MinhaCompania.POC.Minimal-api";
var versao = "1.0.0";

using var tracerProvider = Sdk.CreateTracerProviderBuilder()
        .AddSource(nome)
        .SetResourceBuilder(
            ResourceBuilder.CreateDefault()
                .AddService(serviceName: nome, serviceVersion: versao))
        .AddZipkinExporter(c => c.Endpoint = new Uri("http://localhost:9411/api/v2/spans"))
        .Build();


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "POC-MINIMAL-API",
        Description = "Template para projetos futuros",

    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[]{ }
        }
    });
});

builder.Services.AddDbContext<MinimalContextDb>(opt =>
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityEntityFrameworkContextConfiguration(opt =>
opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
   b => b.MigrationsAssembly("poc-minimal-api")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");
builder.Services.AddSingleton(new ActivitySource(nome));

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("ExcluirFornecedor", p => p.RequireClaim("ExcluirFornecedor"));
});

#endregion

#region Configure Pipeline

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthConfiguration();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

MapActions(app);

app.Run();

#endregion

#region Actions
void MapActions(WebApplication app)
{
    app.MapPost("/registro", [AllowAnonymous] async (
    ActivitySource activitySource,
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    RegisterUser registerUser
    ) =>
    {
        using (var activity = activitySource.StartActivity("/registro", ActivityKind.Server))
        {
            activity?.SetTag("Criando um usuário Tag", registerUser.Email);

            if (registerUser == null)
                return Results.BadRequest("O Usuário não foi informado");


            if (!MiniValidator.TryValidate(registerUser, out var errors))
                return Results.ValidationProblem(errors);

            var user = new IdentityUser()
            {
                UserName = registerUser.Email,
                Email = registerUser.Email,
                EmailConfirmed = true
            };

            activity?.SetTag("Persisitindo no banco de dados", registerUser.Email);
            var result = await userManager.CreateAsync(user, registerUser.Password);

            if (!result.Succeeded)
                return Results.BadRequest(result.Errors);

            var jwt = new JwtBuilder()
                        .WithUserManager(userManager)
                        .WithJwtSettings(appJwtSettings.Value)
                        .WithEmail(user.Email)
                        .WithJwtClaims()
                        .WithUserClaims()
                        .WithUserRoles()
                        .BuildUserResponse();


            activity?.SetTag($"Retornando a requisicao JWT", jwt.ToString());
            return Results.Ok(jwt);

        }

    })
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("RegistroUsuario")
    .WithTags("Usuario");


    app.MapPost("/login", [AllowAnonymous] async (
        ActivitySource activitySource,
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        LoginUser loginUser
        ) =>
    {
        using (var activity = activitySource.StartActivity("/login", ActivityKind.Server))
        {
            if (loginUser == null)
                return Results.BadRequest("Usuário não informado");

            if (!MiniValidator.TryValidate(loginUser, out var errors))
                return Results.ValidationProblem(errors);

            var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, true, true);

            if (result.IsLockedOut)
                return Results.BadRequest("Usuário bloqueado");

            if (!result.Succeeded)
                return Results.BadRequest("Usuário ou senha inválidos");

            var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(loginUser.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

            activity?.SetTag("Usuário autenticado", jwt.ToString());

            return Results.Ok(jwt);
        }


    }).ProducesValidationProblem()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("LoginUsuario")
        .WithTags("Usuario");

    app.MapGet("/fornecedor", async (
        ActivitySource activitySource,
        MinimalContextDb context) =>
    {
        using (var activity = activitySource.CreateActivity("get-fornecedor", ActivityKind.Server))
        {
            var fornecedores = await context.Fornecedores.ToListAsync();

            activity?.SetTag("/get-fornecedores", fornecedores.Count);

            if (fornecedores.Count() == 0)
                return Results.NotFound();

            return Results.Ok(fornecedores);

        }
    })
            .WithName("GetFornecedor")
            .WithTags("Fornecedor");

    app.MapGet("/fornecedor/{id}", [Authorize] async (
        Guid id,
        ActivitySource activitySource,
        MinimalContextDb context) =>
        {
            using (var activity = activitySource.CreateActivity("/get-fornecedor-id", ActivityKind.Server))
            {
                var result = await context.Fornecedores.FindAsync(id)
                 is Fornecedor fornecedor
                        ? Results.Ok(fornecedor)
                        : Results.NotFound();

                activity?.SetTag("Registros extraidos do banco de dados", null);

                return result;
            }


        }).Produces<Fornecedor>(StatusCodes.Status200OK)
          .Produces(StatusCodes.Status404NotFound)
          .WithName("GetFornecedorPorId")
          .WithTags("Fornecedor");

    app.MapPost("/fornecedor", [Authorize] async (
        ActivitySource activitySource,
        MinimalContextDb context,
        Fornecedor fornecedor) =>
    {

        using (var activity = activitySource.StartActivity("/post-fornecedor", ActivityKind.Server))
        {
            if (!MiniValidator.TryValidate(fornecedor, out var errors))
                return Results.ValidationProblem(errors);

            context.Fornecedores.Add(fornecedor);
            var result = await context.SaveChangesAsync();

            activity?.SetTag("Registros criados no banco de dados", result);

            return result > 0
                ? Results.CreatedAtRoute("GetFornecedorPorId", new { id = fornecedor.Id })
                : Results.BadRequest("Houve um erro ao salvar o registro");

        }


    }).ProducesValidationProblem()
        .Produces<Fornecedor>(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("PostFornecedor")
        .WithTags("Fornecedor");

    app.MapPut("/fornecedor/{id}", [Authorize] async (
        Guid id,
        ActivitySource activitySource,
        MinimalContextDb context,
        Fornecedor fornecedor
        ) =>
    {
        using (var activity = activitySource.StartActivity("put-fornecedor", ActivityKind.Server))
        {
            var fornecedorBanco = await context.Fornecedores.AsNoTracking<Fornecedor>()
                                                .FirstOrDefaultAsync(f => f.Id == id);

            if (fornecedorBanco != null) return Results.NotFound();

            if (!MiniValidator.TryValidate(fornecedor, out var errors))
                return Results.ValidationProblem(errors);

            context.Fornecedores.Update(fornecedor);
            var result = await context.SaveChangesAsync();
            activity?.SetTag("Registros atualizados no banco de dados", result.ToString());

            return result > 0
               ? Results.NoContent()
               : Results.BadRequest("Houve um problema ao salvar o registro");

        }


    }).ProducesValidationProblem()
        .Produces<Fornecedor>(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("PutFornecedor")
        .WithTags("Fornecedor");

    app.MapDelete("/fornecedor/{id}", [Authorize] async (
        Guid id,
        ActivitySource activitySource,
        MinimalContextDb context
        ) =>
    {
        using (var activity = activitySource.StartActivity("/delete-fornecedor", ActivityKind.Server))
        {
            var fornecedor = await context.Fornecedores.FindAsync(id);
            if (fornecedor == null) return Results.NotFound();

            context.Fornecedores.Remove(fornecedor);
            var result = await context.SaveChangesAsync();

            activity?.SetTag("Registros removidos do banco de dados", result.ToString());

            return result >= 0
                ? Results.NoContent()
                : Results.BadRequest("Houve um problema ao remover o registro");



        }

    }).Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization("ExcluirFornecedor")
        .WithName("DeleteFornecedor")
        .WithTags("Fornecedor");
}
#endregion