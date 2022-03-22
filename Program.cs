using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Identity;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;
using poc_minimal_api.Data;
using poc_minimal_api.Models;

var builder = WebApplication.CreateBuilder(args);


#region Configure Service

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
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    RegisterUser registerUser
    ) =>
    {
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

        return Results.Ok(jwt);
    })
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("RegistroUsuario")
    .WithTags("Usuario");


    app.MapPost("/login", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        LoginUser loginUser
        ) =>
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

        return Results.Ok(jwt);
    }).ProducesValidationProblem()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("LoginUsuario")
        .WithTags("Usuario");

    app.MapGet("/fornecedor", async (
        MinimalContextDb context) =>
        await context.Fornecedores.ToListAsync())
            .WithName("GetFornecedor")
            .WithTags("Fornecedor");

    app.MapGet("/fornecedor/{id}", [Authorize] async (
        Guid id,
        MinimalContextDb context) =>
        await context.Fornecedores.FindAsync(id)
            is Fornecedor fornecedor
                ? Results.Ok(fornecedor)
                : Results.NotFound())
            .Produces<Fornecedor>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound)
            .WithName("GetFornecedorPorId")
            .WithTags("Fornecedor");

    app.MapPost("/fornecedor", [Authorize] async (
        MinimalContextDb context,
        Fornecedor fornecedor) =>
    {
        if (!MiniValidator.TryValidate(fornecedor, out var errors))
            return Results.ValidationProblem(errors);

        context.Fornecedores.Add(fornecedor);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.CreatedAtRoute("GetFornecedorPorId", new { id = fornecedor.Id })
            : Results.BadRequest("Houve um erro ao salvar o registro");

    }).ProducesValidationProblem()
        .Produces<Fornecedor>(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("PostFornecedor")
        .WithTags("Fornecedor");

    app.MapPut("/fornecedor/{id}", [Authorize] async (
        Guid id,
        MinimalContextDb context,
        Fornecedor fornecedor
        ) =>
    {
        var fornecedorBanco = await context.Fornecedores.AsNoTracking<Fornecedor>()
                                            .FirstOrDefaultAsync(f => f.Id == id);

        if (fornecedorBanco != null) return Results.NotFound();

        if (!MiniValidator.TryValidate(fornecedor, out var errors))
            return Results.ValidationProblem(errors);

        context.Fornecedores.Update(fornecedor);
        var result = await context.SaveChangesAsync();

        return result > 0
           ? Results.NoContent()
           : Results.BadRequest("Houve um problema ao salvar o registro");

    }).ProducesValidationProblem()
        .Produces<Fornecedor>(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("PutFornecedor")
        .WithTags("Fornecedor");

    app.MapDelete("/fornecedor/{id}", [Authorize] async (
        Guid id,
        MinimalContextDb context
        ) =>
    {
        var fornecedor = await context.Fornecedores.FindAsync(id);
        if (fornecedor == null) return Results.NotFound();

        context.Fornecedores.Remove(fornecedor);
        var result = await context.SaveChangesAsync();

        return result >= 0
            ? Results.NoContent()
            : Results.BadRequest("Houve um problema ao remover o registro");

    }).Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization("ExcluirFornecedor")
        .WithName("DeleteFornecedor")
        .WithTags("Fornecedor");
}
#endregion