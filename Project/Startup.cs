using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Project.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Project
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            //Swagger
            services.AddSwaggerGen(c =>
            {
                // configure SwaggerDoc and others

                // add JWT Authentication
                var securityScheme = new OpenApiSecurityScheme
                {
                    Name = "JWT Authentication",
                    Description = "Enter JWT Bearer token **_only_**",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer", // must be lower case
                    BearerFormat = "JWT",
                    Reference = new OpenApiReference
                    {
                        Id = JwtBearerDefaults.AuthenticationScheme,
                        Type = ReferenceType.SecurityScheme
                    }
                };
                c.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                        {securityScheme, new string[] { }}
                });

            });

            // Entity Framework
            services.AddDbContext<ApplicationDbContext>(x => x.UseSqlServer(Configuration.GetConnectionString("ConnectionString")));

            //For Identity
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            //Adding Authentication 
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                //Adding JWT BEARER
                .AddJwtBearer(X => {
                    X.SaveToken = true;
                    X.RequireHttpsMetadata = false;
                    X.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidAudience = Configuration["JWT:ValidAudience"],
                        ValidIssuer = Configuration["JWT:ValidIssuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:Secret"]))
                    };
                });

            /*
             SaveToken = true would save the token in the server, and the Authentication method should not accept any token 
             that was issued from any other server even if the other server is using the exact same JWT signing key since it
             is not saved on the server.

             
             RequireHttpsMetadata gets or sets if HTTPS is required for the metadata address or authority. The default is true.
             This should be disabled only in development environments.

             TokenValidationParameters contains a set of parameters that are used by a SecurityTokenHandler when validating a SecurityToken
                -Validation of the issuer mitigates forwarding attacks that can occur when an IdentityProvider represents multiple tenants
                 and signs tokens with the same keys.

                -Validation of the audience, mitigates forwarding attacks. For example, a site that receives a token, could not replay it to another side. 
                 A forwarded token would contain the audience of the original site. This boolean only applies to default audience validation.
                 If AudienceValidator is set, it will be called regardless of whether this property is true or false.
                
                -IssuerSigningKey gets or sets the SecurityKey that is to be used for signature validation.
             */ //Description for Jwt Bearer

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "TestAspCore v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            //Authentication comes before Authorization.
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
