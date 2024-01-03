using ApiCamScanner.Entities;
using ApiCamScanner.Manager;
using ApiCamScanner.Token;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
var configuration = builder.Configuration;
// Add services to the container.

var secretKey = configuration["JWTSetting:SecrectKey"];
var secrectKeyBytes = Encoding.UTF8.GetBytes(secretKey);


services.AddTransient<TokenManager>();
services.AddTransient<TokenGen>();

builder.Services.AddControllers();



// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            // tự cấp token
            ValidateIssuer = false, //Không xác thực nguồn phát hành (issuer) của token. 
            ValidateAudience = false,  //Không xác thực đối tượng chấp nhận (audience) của token
            ValidateLifetime = true,  // xđ time sống của token

            // ký vào token
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(secrectKeyBytes), // thuật toán đối xứng (tự động mã hóa)

            ClockSkew = TimeSpan.Zero
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
