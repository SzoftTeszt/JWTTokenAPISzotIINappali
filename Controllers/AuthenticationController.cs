using JWTTokenAPI.Models;
using JWTTokenAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;


namespace JWTTokenAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthenticationController(IAuthService authService, ILogger<AuthenticationController> logger, UserManager<ApplicationUser> userManager)
        {
            _authService = authService;
            _userManager = userManager;
            _logger = logger;
        }


        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest("Invalid payload");
                var (status,user, message) = await _authService.Login(model);
                if (status == 0)
                    return BadRequest(message);
                return Ok(new LoggedUser(user, message));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        [HttpPost]
        [Route("deleteUser/{id}")]
        //[Authorize(Roles = "SAdmin")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var currentUserName = HttpContext.User.Identity.Name;
            var user = await _userManager.FindByIdAsync(id);
            var currentUser = await _userManager.FindByNameAsync(currentUserName);
            var roles = await _userManager.GetRolesAsync(currentUser);
            if (!user.UserName.Equals(currentUserName))
            {
                var (status, message) =
                 await _authService.DeleteUser(id);
                if (status == 0)
                {
                    return BadRequest(message);
                }
                return Ok(message);
            }
            return BadRequest("Unauthorized");

        }

        [HttpPost]
        [Route("register")]
       
        public async Task<IActionResult> Register(RegistrationModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest("Invalid payload");
                var (status, message) = 
                    await _authService.Register(model);
                if (status == 0)
                {
                    return BadRequest(message);
                }
                return CreatedAtAction(nameof(Register), model);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        } 
        
        [HttpPost]
        [Route("update")]
        [Authorize]
        public async Task<IActionResult> Update(UpdateModel model)
        {
            try
            {
                var currentUserName = HttpContext.User.Identity.Name;

                var user = await _userManager.FindByIdAsync(model.Id);
                var currentUser = await _userManager.FindByNameAsync(currentUserName);
                var roles = await _userManager.GetRolesAsync(currentUser);
                if (user.UserName.Equals(currentUserName) || roles.IndexOf("SAdmin") != -1)
                {
                    if (!ModelState.IsValid)
                        return BadRequest("Invalid payload");
                    var (status, message) =
                        await _authService.Update(model);
                    if (status == 0)
                    {
                        return BadRequest(message);
                    }
                    return Ok(message);
                }
                return BadRequest("Unauthorized");
               
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }  
        
        [HttpPost]
        [Route("change")]
        [Authorize]
        public async Task<IActionResult> Change(ChangePasswordModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest("Invalid payload");
                var currentUserName = HttpContext.User.Identity.Name;
               
                var user = await _userManager.FindByIdAsync(model.Id);
                var currentUser = await _userManager.FindByNameAsync(currentUserName);
                var roles = await _userManager.GetRolesAsync(currentUser);
                if (user.UserName.Equals(currentUserName) || roles.IndexOf("SAdmin") != -1)
                {

                    var (status, message) =
                    await _authService.ChangePassword(model);
                    if (status == 0)
                    {
                        return BadRequest(message);
                    }
                    return Ok(message);
                }
                return BadRequest("Unauthorized");
                //return CreatedAtAction(nameof(Register), model);

            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}
