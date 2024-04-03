using jwtAuthNet.Api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace jwtAuthNet.Api.Controllers
{
    public class AuthController : Controller
    {
        private static List<User> UserList = new List<User>();
        private readonly AppSettings _applicationSettings;
        public AuthController(IOptions<AppSettings> applicationSettings)
        {
            _applicationSettings = applicationSettings.Value;
        }

        [HttpPost("Login")]
        public IActionResult Login([FromBody] Login model)
        {
            var user = UserList.Where(u => u.UserName == model.UserName).FirstOrDefault();
            if (user == null)
            {
                return BadRequest("Username or password was invalid");
            }

            var match = CheckPassword(model.Password, user);

            if (!match)
            {
                return BadRequest("Username or password was invalid");
            }

            JWTGenarator(user);
            return Ok();
        }

        public dynamic JWTGenarator(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_applicationSettings.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("username", user.UserName) }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var encrypterToken = tokenHandler.WriteToken(token);

            SetJWT(encrypterToken);

            var refreshToken = GenerateRefreshToken();

            SetRefreshToken(refreshToken, user);

            return new { token = encrypterToken, username = user.UserName };
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken()
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(1),
                Created = DateTime.Now
            };
            return refreshToken;
        }

        [HttpGet("RefreshToken")]
        private async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["X-Refresh-Token"];
            var user = UserList.Where(u => u.Token == refreshToken).FirstOrDefault();

            if (user == null || user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token has expired");
            }

            JWTGenarator(user);
            return Ok();
        }

        public void SetRefreshToken(RefreshToken refreshToken, User user)
        {
            HttpContext.Response.Cookies.Append("X-Refresh-Token", refreshToken.Token,
                new CookieOptions
                {
                    Expires = refreshToken.Expires,
                    HttpOnly = true,
                    Secure = true,
                    IsEssential = true,
                    SameSite = SameSiteMode.None,
                });

            UserList.Where(u => u.UserName == user.UserName).First().Token = refreshToken.Token;
            UserList.Where(u => u.UserName == user.UserName).First().TokenCreated = refreshToken.Created;
            UserList.Where(u => u.UserName == user.UserName).First().TokenExpires = refreshToken.Expires;
        }

        public void SetJWT(string encrypterToken)
        {
            HttpContext.Response.Cookies.Append("X-Access-Token", encrypterToken,
                new CookieOptions
                {
                    Expires = DateTime.Now.AddMinutes(15),
                    HttpOnly = true,
                    Secure = true,
                    IsEssential = true,
                    SameSite = SameSiteMode.None
                });
        }

        [HttpDelete]
        public async Task<IActionResult> RevokeToken(string username)
        {
            UserList.Where(u => u.UserName == username).Select(t => t.Token = String.Empty);

            return Ok();
        }

        
        private bool CheckPassword(string password, User user)
        {
            bool result;

            using (HMACSHA512? hmac = new HMACSHA512(user.PasswordSalt))
            {
                var compute = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                result = compute.SequenceEqual(user.PasswordHash);
            }

            return result;
        }

        [HttpPost("Register")]
        public IActionResult Register([FromBody] Register model)
        {
            var user = new User { UserName = model.UserName };
            if (model.ConfirmPassword == model.Password)
            {
                using (HMACSHA512? hmac = new HMACSHA512())
                {
                    user.PasswordSalt = hmac.Key;
                    user.PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(model.Password));
                }

            }
            else
            {
                return BadRequest("Passwords don't match");
            }

            UserList.Add(user);

            return Ok("New user: " + user.UserName + " has been registered succesfully");
        }
    }
}
