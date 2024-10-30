using System.Text.Json.Serialization;
using WebApplication1.Common;

namespace WebApplication1.Commands
{
    public class DeleteUserCommand : IHasCurrentUserId, IRequest<GenericBaseResult<bool>>
    {
        public string Email { get; set; }
        [JsonIgnore]
        public string UserId { get; set; }
    }
}
