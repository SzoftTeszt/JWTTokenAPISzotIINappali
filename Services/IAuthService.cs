using JWTTokenAPI.Models;
using System.Security.Claims;

namespace JWTTokenAPI.Services
{
    public interface IAuthService
    {
        Task<(int, string)> Register(RegistrationModel model);
        Task<(int, string)>Update(UpdateModel model); 
        Task<(int, string)>ChangePassword(ChangePasswordModel model);
        Task<(int, string)>DeleteUser(string id);
        Task<(int, ApplicationUser?, string)> Login(LoginModel model);

        Task<(int, List<ApplicationUser>)> UserList();
       
        Task<(int, IList<string>)> UserClaim(string id);

        Task<(int, string)> SetClaims(RolesModel id);



    }
}
