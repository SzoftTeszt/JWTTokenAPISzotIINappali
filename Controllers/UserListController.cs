using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using JWTTokenAPI.Models;
using JWTTokenAPI.Services;

using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace JWTTokenAPI.Controllers
{
    [Route("api/userlist")]
    [ApiController]
    [Authorize(Roles = "SAdmin,Admin")]
    //[Authorize(Roles = "SAdmin")]
    //[Authorize]
    public class UserListController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        public UserListController(IAuthService authService, ILogger<AuthenticationController> logger, UserManager<ApplicationUser> userManager)
        {
            _authService = authService;
            _logger = logger;
            _userManager = userManager;

        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
           
            //var user = await _userManager.FindByIdAsync(u.id);
            var (status, message) = await _authService.UserList();
            return Ok(message);
        }
    }
}

