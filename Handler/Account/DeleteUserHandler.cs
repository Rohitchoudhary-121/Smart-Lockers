using Microsoft.AspNetCore.Identity;
using System.Globalization;

namespace Olssen.Slp.Handlers.Account
{
    public class DeleteUserHandler : IRequestHandler<DeleteUserCommand, GenericBaseResult<bool>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IAuthenticationProvider _authenticationProvider;
        private readonly IDeviceRepository _deviceRepository;
        private readonly ILockerManagementRepository _lockerManagementRepository;
        private readonly IUserRepository _userRepositoryRepository;
        private readonly ILockerWallRepository _lockerWallRepository;
        private readonly ISiteAdminRepository _siteAdminRepository;
        private readonly ILogger<DeleteUserHandler> _logger;
        private readonly IAuditDataRepository _auditDataRepository;

        public DeleteUserHandler(UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IAuthenticationProvider authenticationProvider,
                                 ILogger<DeleteUserHandler> logger,
                                 IDeviceRepository deviceRepository,
                                 ILockerManagementRepository lockerManagementRepository,
                                 IUserRepository userRepositoryRepository,
                                 ILockerWallRepository lockerWallRepository,
                                 ISiteAdminRepository siteAdminRepository,
                                 IAuditDataRepository auditDataRepository)
            => (_userManager, _context, _authenticationProvider, _logger, _deviceRepository, _lockerManagementRepository, _userRepositoryRepository, _lockerWallRepository, _siteAdminRepository, _auditDataRepository)
            = (userManager, context, authenticationProvider, logger, deviceRepository, lockerManagementRepository, userRepositoryRepository, lockerWallRepository, siteAdminRepository, auditDataRepository);

        public async Task<GenericBaseResult<bool>> Handle(DeleteUserCommand request, CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogInformation("Handling Delete User Request");
                var user = await _userManager.FindByEmailAsync(request.Email);

                var culture = new CultureInfo(string.Empty);
                var adminuser = await _context.AspNetUsers.FirstOrDefaultAsync(x => x.Id == _authenticationProvider.UserId);

                culture = new CultureInfo(adminuser?.Language);

                if (user == null)
                    return new GenericBaseResult<bool>(false) { Message = Messages.ResourceManager.GetString(nameof(Messages.NoUserFoundWithThisEmail), culture), ResponseStatusCode = System.Net.HttpStatusCode.NotFound };

                //Cannot delete PCP user
                if (user.UserRoles.First().Role.NormalizedName == UserRoles.PrimaryContactPerson)
                    return new GenericBaseResult<bool>(false) { Message = Messages.ResourceManager.GetString(nameof(Messages.PCPUserCannotBeDeleted), culture), ResponseStatusCode = System.Net.HttpStatusCode.BadRequest };

                //Check user assigned locker
                if ((await _lockerManagementRepository.GetAssignedLockerCountByUserId(user.Id)) > 0)
                    return new GenericBaseResult<bool>(false) { Message = Messages.ResourceManager.GetString(nameof(Messages.UserHasLockerAssigned), culture), ResponseStatusCode = System.Net.HttpStatusCode.NotFound };

                //Delete Event Reservations
                await _userRepositoryRepository.DeleteEventReservationByUserId(user.Id);

                //Delete Attach lockerWall to user
                await _lockerWallRepository.DeleteLockerWallsByUserId(user.Id);

                //Delete site admin data
                await _siteAdminRepository.DeleteSites(user.Id);

                //Delete Attach Devices
                await _deviceRepository.DeleteDevice(new DeleteDeviceCommand { UserId = user.Id });

                if (await _context.Parcels.AnyAsync(x => x.ReceiverId == user.Id && x.ParcelStatus != ParcelStatus.Archived))
                    return new GenericBaseResult<bool>(false) { Message = Messages.ResourceManager.GetString(nameof(Messages.ParcelAssignedToThisUser), culture), ResponseStatusCode = System.Net.HttpStatusCode.BadRequest };

                //Add auditing for remove user
                await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                {
                    Event = EventNames.RemoveUser,
                    EndUserId = user.Id,
                    Description = "Delete user",
                    IsMainEvent = true
                }, true);

                await _userManager.DeleteAsync(user);

                return new GenericBaseResult<bool>(true) { Message = "User Deleted Successfully" };
            }
            catch (Exception ex)
            {
                _logger.LogInformation($"Error Handling Delete User Request: {ex.Message}");
                var result = new GenericBaseResult<bool>(false);
                result.AddExceptionLog(ex);
                return result;
            }
        }
    }
}
