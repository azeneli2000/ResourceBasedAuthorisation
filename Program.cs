using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
builder.Services.AddSingleton<IAuthorizationHandler, ResourceBasedAuthorizationHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanViewProduct", policy =>
        policy.Requirements.Add(new ResourceBasedRequirement("product_view")));
});
var app = builder.Build();





app.MapGet("/signout", async (ctx) =>
{
   await  ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); });

app.MapGet("/", () => "Hello World!").RequireAuthorization("CanViewProduct");
app.MapGet("/login", async( ctx) =>
{
    var claim = new Claim("resource", "product_view");
    ctx.User.Identities.First().AddClaim(claim);
    List<Claim> claims = new List<Claim>();
    claims.Add(claim);
    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await  ctx.SignInAsync(new ClaimsPrincipal(claimsIdentity));
    
}).AllowAnonymous();
app.UseAuthentication();
app.UseAuthorization();
app.Run();

public class ResourceBasedAuthorizationHandler :AuthorizationHandler<ResourceBasedRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ResourceBasedRequirement requirement)
    {
   
// TODO: Check if user is authorized to access the resource
        if (context.User.HasClaim(x => x.Type == "resource" && x.Value == requirement.ResourceId))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public class ResourceBasedRequirement : IAuthorizationRequirement
{
    public ResourceBasedRequirement(string resourceId)
    {
        ResourceId = resourceId;
    }
    public string ResourceId { get; set; }
}