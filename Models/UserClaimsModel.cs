using System.Security.Claims;

namespace JWTTokenAPI.Models
{
    public class UserClaimsModel
    {
        public ApplicationUser User;
        public IList<Claim> Claims;
    }
}
