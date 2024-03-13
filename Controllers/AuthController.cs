using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtToken.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {

        private readonly IConfiguration configuration;
        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpGet]
        [Route("token")]
        public ActionResult GetToken(string userName, string password)
        {
            if (String.IsNullOrEmpty(userName) || String.IsNullOrEmpty(password))
                return BadRequest("Username and password cannot be null");

            try
            {
                var signInKey = configuration["Jwt:SignInKey"];
                var issuer = configuration["Jwt:Issuer"];
                var audience = configuration["Jwt:Audience"];
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signInKey));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new[]
                {
                new Claim(ClaimTypes.Name, userName),
                new Claim(JwtRegisteredClaimNames.Email, userName),
            };
                var jwtSecurityToken = new JwtSecurityToken(
                    issuer: issuer,
                    audience: audience,
                    claims: claims,
                    expires: DateTime.Now.AddDays(5),
                    notBefore: DateTime.Now,
                    signingCredentials: credentials
                    );
                var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);


                return Ok(token);
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }
        }
    }
}
