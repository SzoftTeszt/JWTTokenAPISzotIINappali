using JWTTokenAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Microsoft.EntityFrameworkCore;

namespace JWTTokenAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
           

        }

        public async Task<(int, List<ApplicationUser>)> UserList()
        {
            var userList = await userManager.Users.ToListAsync();
            return (1, userList);
        }

      
        public async Task<(int, IList<string>)> UserClaim(string id)
        {
            var user = await userManager.FindByIdAsync(id);
            var roles = await userManager.GetRolesAsync(user);           
            return (1, roles);           
        }
        public async Task<(int, string)> SetClaims(RolesModel id)
        {
            var user = await userManager.FindByIdAsync(id.Id);
            var roles = await userManager.GetRolesAsync(user);
            await userManager.RemoveFromRolesAsync(user, roles);

           foreach (var role in id.Roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                    await roleManager.CreateAsync(new IdentityRole(role));

                if (await roleManager.RoleExistsAsync(role))
                    await userManager.AddToRoleAsync(user, role);

            }
            return (1, "");
        }

        public async Task<(int, string)> DeleteUser(string id) {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return (0, "User not found");
            var result = await userManager.DeleteAsync(user);
            if (!result.Succeeded)
                return (0, "Delete user failed! Please check user details and try again.");
            return (1, "Delete user successfully!");
        }
        public async Task<(int, string)> ChangePassword(ChangePasswordModel model) {
            var user = await userManager.FindByIdAsync(model.Id);
            //userManager.DeleteAsync(user)
            if (user == null)
                return (0, "User not found");
            var result = await userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!result.Succeeded)
                return (0, "Password update failed! Please check user details and try again.");
            return (1, "Password update successfully!");
        }
        public async Task<(int, string)> Update(UpdateModel model)
        {
            var user = await userManager.FindByIdAsync(model.Id);
            if (user == null)
                return (0, "User not found");
            user.Email=model.Email;
            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.UserName = model.Username;
            user.Address = model.Address;
            var result = await userManager.UpdateAsync(user);
                if (!result.Succeeded) 
                return (0, "User update failed! Please check user details and try again.");
            return (1, "User update successfully!");
        }
        public async Task<(int, string)> Register(RegistrationModel model)
        {
            
            
            
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return (0, "User already exists");

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                FirstName = model.FirstName,
                LastName = model.LastName,
                Address = model.Address,
            };
            var createUserResult = await userManager.CreateAsync(user, model.Password);
            if (!createUserResult.Succeeded)
                return (0, "User creation failed! Please check user details and try again.");

            /*if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));

            if (await roleManager.RoleExistsAsync(role))
                await userManager.AddToRoleAsync(user, role);*/

            if (user.UserName.Equals("Admin"))
            {
                if (!await roleManager.RoleExistsAsync(UserRoles.SAdmin))
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.SAdmin));
                if (await roleManager.RoleExistsAsync(UserRoles.SAdmin))
                    await userManager.AddToRoleAsync(user, UserRoles.SAdmin);
            }
            return (1, "User created successfully!");
        }

        public async Task<(int, ApplicationUser?, string)> Login(LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user == null)
                return (0, null, "Invalid username");
            if (!await userManager.CheckPasswordAsync(user, model.Password))
                return (0, null, "Invalid password");

            var userRoles = await userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
               new Claim(ClaimTypes.Name, user.UserName),
               new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            string token = GenerateToken(authClaims);
            return (1,user, token);
        }


        private string GenerateToken(IEnumerable<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWTKey:Secret"]));
            var _TokenExpiryTimeInHour = Convert.ToInt64(_configuration["JWTKey:TokenExpiryTimeInHour"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = _configuration["JWTKey:ValidIssuer"],
                Audience = _configuration["JWTKey:ValidAudience"],
                //Expires = DateTime.UtcNow.AddHours(_TokenExpiryTimeInHour),
                Expires = DateTime.UtcNow.AddMinutes(1),
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256),
                Subject = new ClaimsIdentity(claims)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}