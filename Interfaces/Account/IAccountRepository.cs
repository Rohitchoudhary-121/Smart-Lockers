using Keynius.Backend.Contracts;
using Keynius.Backend.Contracts.Entity;
using Olssen.Slp.CommandResults;
using Olssen.Slp.Commands;
using Olssen.Slp.Commands.Account;
using Olssen.Slp.ViewModels.User;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Olssen.Slp.Repository
{
    public interface IAccountRepository
    {

        /// <summary>
        /// Get User Roles List
        /// </summary>
        /// <returns>List of string</returns>
        Task<IList<string>> GetUserWiseRolesResult(IList<string> rolesName);


        /// <summary>
        /// Update Refresh Token
        /// </summary>
        /// <returns>RefreshToken</returns>
        Task<RefreshToken> UpdateRefreshTokenResult(RefreshToken refreshToken, string userName);


        /// <summary>
        /// Update Refresh Token
        /// </summary>
        /// <returns>RefreshToken</returns>
        Task<RefreshToken> GetRefreshTokenResult(string refreshToken);


        /// <summary>
        /// Add User
        /// </summary>
        /// <returns>Registration Result</returns>
        Task<RegistrationResult> AddUser(RegisterCommand registerCommand, bool isExternalUser, bool isAnonymous, bool isAnonymousNFC, bool isReservationUser);

        /// <summary>
        /// Registers And Setup A User
        /// </summary>
        /// <returns></returns>
        Task<(ApplicationUser User, IQueryable<AssignedLocker> AssignedLockers)> RegisterAndSetupUser(RegisterAndSetupUserCommand registerAndSetupUser, bool isExternalUser);

        /// <summary>
        /// Updates and Sets Up A User
        /// </summary>
        /// <param name="updateAndSetupUser"></param>
        /// <returns></returns>
        Task<(ApplicationUser User, IQueryable<AssignedLocker> AssignedLockers)> UpdateAndSetupUser(UpdateAndSetupUserCommand updateAndSetupUser);


        /// <summary>
        /// Update User details
        /// </summary>
        /// <returns>true/false</returns>
        Task<bool> UpdateUser(UpdateUserApiModel updateUserApiModel);


        /// <summary>
        /// Update User details by user id
        /// </summary>
        /// <returns>true/false</returns>
        Task<bool> UpdateUser(UpdateUserByIdCommand updateUserCammand);


        /// <summary>
        /// Verify Registration Email
        /// </summary>
        /// <returns>true/false</returns>
        Task<BaseResult> VerifyRegistrationEmailResult(string userId, string token);


        /// <summary>
        /// Add Device for notification
        /// </summary>
        /// <returns>Base result</returns>
        Task AddDevice(string deviceId, string platform, string userId, string token);

        /// <summary>
        /// Get Devices bu user id
        /// </summary>
        /// <returns></returns>
        Task<List<Device>> GetDevicesByUserId(string userId);

        /// <summary>
        /// Synchronizes Smart Hub Users Of A Customer 
        /// </summary>
        /// <param name="customerId">Id Of The Customer</param>
        /// <param name="userNames">User Ids</param>
        /// <returns>Task</returns>
        Task SyncUsers(string customerId, IEnumerable<string> userNames);

        /// <summary>
        /// Adds Partner User 
        /// </summary>
        /// <param name="registerPartnerUser"></param>
        /// <returns></returns>
        Task<PartnerUserInfo> AddPartnerUser(AddPartnerUserCommand registerPartnerUser);

        /// <summary>
        /// Adds/Updates Keynius User
        /// </summary>
        /// <param name="registerKeyniusUser"></param>
        /// <returns></returns>
        Task<ApplicationUser> AddKeyniusUser(RegisterCommand registerKeyniusUser);

        /// <summary>
        /// Adds/Updates Keynius PIM User
        /// </summary>
        /// <param name="registerPimUser"></param>
        /// <returns></returns>
        Task<ApplicationUser> AddPIMUser(RegisterKeyniusPIMUserCommand registerPimUser);

        /// <summary>
        /// Block/UnBlock User
        /// </summary>
        /// <param name="request"></param> 
        /// <returns></returns>
        Task<bool> BlockUnblockUserByUserId(BlockUnblockUserByUserIdCommand request, string adminLanguage, bool isLockerAdmin);

        /// <summary>
        /// Registers And Setup A User
        /// </summary>
        /// <returns></returns>
        Task<int> GetDropOffPickUpUserCount(string customerId, string firstName, string lastName);

        /// <summary>
        /// Send email to admin that user has opened their OneTimeUse locker 
        /// </summary>
        /// <param name="assignedLocker">assignedLocker</param>
        /// <returns>Task</returns>
        Task SendEmailOneTimeLockerHasOpened(AssignedLocker assignedLocker);

        /// <summary>
        /// Send email to user that oneTimeLocker assigned
        /// </summary>
        /// <param name="assignment">assignment</param>
        /// <param name="user">user</param>
        /// <returns>Task</returns>
        Task SendOneTimeAssignmentEmailToUser(AssignLockerToUser assignment, ApplicationUser user);

        /// <summary>Sends the locker assigned email to user.</summary>
        /// <param name="assignedLockers">The assigned lockers.</param>
        /// <param name="userGroupAssignedLockerMappings">The user group assigned locker mappings.</param>
        /// <returns>
        ///   <br />
        /// </returns>
        Task SendLockerAssignedEmailToUser(List<AssignedLocker> assignedLockers, List<UserGroupAssignedLockerMapping> userGroupAssignedLockerMappings);

        Task<RegistrationResult> AddUserRentALocker(RegisterCommand registerCommand);
    }
}