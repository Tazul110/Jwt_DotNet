using Jwt_Demo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Jwt_Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IGetUserByEmailServ _userServ;
        private readonly TokenService _tokenService;

        // Store refresh tokens temporarily (or you can store them in a database)
        private static Dictionary<string, string> _refreshTokens = new();

        public LoginController(IConfiguration configuration, IGetUserByEmailServ user, TokenService tokenService)
        {
            _config = configuration;
            _userServ = user;
            _tokenService = tokenService;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(Users user)
        {
            SqlConnection connection = new SqlConnection(_config.GetConnectionString("CrudConnection"));
            IActionResult response = Unauthorized();

            var authenticatedUser = _userServ.AuthenticateUser(connection, user);

            if (authenticatedUser != null)
            {
                // Create claims for the authenticated user
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, authenticatedUser.userEmail),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    // Add additional claims if needed
                };

                // Generate access token
                var accessToken = _tokenService.CreateAccessToken(claims, false);
                var refreshToken = _tokenService.CreateRefreshToken();

                // Store the refresh token (you may want to implement a more secure storage)
                _refreshTokens[refreshToken] = authenticatedUser.userEmail;

                response = Ok(new { token = accessToken, refreshToken = refreshToken, message = "Valid credentials" });
            }
            else
            {
                response = BadRequest(new { message = "Try Again... Invalid user or Invalid password" });
            }

            return response;
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public IActionResult RefreshToken([FromBody] RefreshRequest request)
        {
            // Check if the refresh token is valid
            if (_refreshTokens.TryGetValue(request.RefreshToken, out var userEmail))
            {
                // Create claims for the refreshed user
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userEmail),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // New JTI for access token
                    // Add additional claims if needed
                };

                // Generate a new access token
                var newAccessToken = _tokenService.CreateAccessToken(claims, false);

                return Ok(new { token = newAccessToken });
            }

            return BadRequest(new { message = "Invalid refresh token" });
        }
    }
}