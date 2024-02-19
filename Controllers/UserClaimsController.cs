using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using JWTTokenAPI.Models;
using JWTTokenAPI.Services;

using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace JWTTokenAPI.Controllers
{ 
    [Route("api/userClaims")]
   [ApiController]
    //[Authorize(Roles = "SAdmin")]
    [Authorize]
    public class UserClaimsController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public UserClaimsController(IAuthService authService, ILogger<AuthenticationController> logger, UserManager<ApplicationUser> userManager)
        {
            _authService = authService;
            _logger = logger;
            _userManager = userManager;
        }

              
        [HttpGet("{id}")]
        public async Task<IActionResult> Get(string id)
        {
            
            var currentUserName = HttpContext.User.Identity.Name;            
            var user = await _userManager.FindByIdAsync(id);
            var currentUser = await _userManager.FindByNameAsync(currentUserName);
            var roles = await _userManager.GetRolesAsync(currentUser);
            if (user.UserName.Equals(currentUserName) || roles.IndexOf("SAdmin") != -1)
            {
                var (status, message) = await _authService.UserClaim(id);
                return Ok(message);
            }
            return NoContent();
        }

        [HttpPost]
        [Authorize(Roles = "SAdmin")]
        public async Task<IActionResult> Post(RolesModel id)
        {

            var (status, message) = await _authService.SetClaims(id);
            return Ok(message);
        }

        private Task<ApplicationUser> GetCurrentUserAsync() => _userManager.GetUserAsync(HttpContext.User);

    }
}

