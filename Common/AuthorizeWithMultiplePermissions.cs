using Microsoft.AspNetCore.Authorization;

namespace WebApplication1.Common
{
    /// <summary>
    /// Authorize With Multiple Roles
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizeWithMultiplePermissionsAttribute : AuthorizeAttribute
    {
        /// <summary>
        /// Authorize With Multiple Roles
        /// </summary>
        /// <param name="roles">Roles</param>
        public AuthorizeWithMultiplePermissionsAttribute(params string[] roles)
        {
            Roles = string.Join(',', roles);
        }
    }
}
