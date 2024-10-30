using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Security.Claims;
using System.Web;

namespace Olssen.Slp.Repository
{
    /// <summary>
    /// Repository for Account
    /// </summary>
    public class AccountRepository : IAccountRepository
    {
        private readonly ApplicationDbContext _context;
        public readonly UserManager<ApplicationUser> _userManager;
        private readonly ILockerManagementRepository _lockerManagementRepository;
        private readonly IUserIdentificationRepository _userIdentificationRepository;
        private readonly IAuditDataRepository _auditDataRepository;
        private readonly SmartHubUserAuthOptions _hubUserAuthOptions;
        private readonly IMessageService _messageService;
        private readonly IConfiguration _configuration;
        private readonly IEmailTemplateHandler _emailTemplateHandler;
        private readonly ISmartHubUserRepository _smartHubUserRepository;
        private readonly ILockerAdminLockerWallRepository _lockerAdminLockerWallRepository;
        private readonly IAuthenticationProvider _authenticationProvider;
        private readonly CultureInfo _culture = new CultureInfo("nl");
        private readonly IServiceBusHelper _serviceBusHelper;
        private readonly ILockerModelRepository _lockerModelRepository;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AccountRepository(ApplicationDbContext context,
                                UserManager<ApplicationUser> userManager,
                                ILockerManagementRepository lockerManagementRepository,
                                IUserIdentificationRepository userIdentificationRepository,
                                IAuditDataRepository auditDataRepository,
                                IOptions<SmartHubUserAuthOptions> options,
                                IMessageService messageService,
                                IConfiguration configuration,
                                ISmartHubUserRepository smartHubUserRepository,
                                IEmailTemplateHandler emailTemplateHandler,
                                ILockerAdminLockerWallRepository lockerAdminLockerWallRepository,
                                IAuthenticationProvider authenticationProvider,
                                ILanguageOptionService languageOptionService,
                                IServiceBusHelper serviceBusHelper,
                                ILockerModelRepository lockerModelRepository,
                                IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _userManager = userManager;
            _lockerManagementRepository = lockerManagementRepository;
            _userIdentificationRepository = userIdentificationRepository;
            _auditDataRepository = auditDataRepository;
            _hubUserAuthOptions = options.Value;
            _messageService = messageService;
            _configuration = configuration;
            _smartHubUserRepository = smartHubUserRepository;
            _emailTemplateHandler = emailTemplateHandler;
            _lockerAdminLockerWallRepository = lockerAdminLockerWallRepository;
            _authenticationProvider = authenticationProvider;
            _culture = languageOptionService.UserCulture;
            _serviceBusHelper = serviceBusHelper;
            _lockerModelRepository = lockerModelRepository;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<IList<string>> GetUserWiseRolesResult(IList<string> rolesName)
        {
            var userAccessRoles = await (from role in _context.AspNetRoles.Where(m => rolesName.Contains(m.Name))
                                         join rra in _context.ResourceRoleAccess on role.Id equals rra.RoleId
                                         join rsa in _context.ResourceAccess on rra.ResourceAccessId equals rsa.Id
                                         join rs in _context.Resources on rsa.ResourceId equals rs.Id
                                         where rra.IsDeleted == false && rs.IsDeleted == false
                                         && rsa.IsDeleted == false
                                         select new
                                         {
                                             rs.Name,
                                             rsa.AccessLevel
                                         }).OrderByDescending(m => m.AccessLevel).ToListAsync();

            IList<string> listuserAccessRoles = new List<string>();

            foreach (var item in userAccessRoles)
            {
                listuserAccessRoles.Add($"{item.Name}{Constants.RoleSeparator}{(item.AccessLevel == 0 ? Constants.Read : Constants.Write)}");
            };

            return listuserAccessRoles;
        }

        public async Task<RegistrationResult> AddUser(RegisterCommand registerCommand, bool isExternalUser = false, bool isAnonymous = false, bool isAnonymousNFC = false, bool isReservationUser = false)
        {
            if (registerCommand == null)
                throw new ArgumentNullException(nameof(registerCommand), "Registration details are required.");

            var language = (await _context.Customers.FirstOrDefaultAsync(x => x.Id == registerCommand.CustomerId))?.Language;
            // default language should be customer language if we have
            if (string.IsNullOrEmpty(registerCommand.Language))
                registerCommand.Language = language;

            if (!isExternalUser && !isAnonymous && !isAnonymousNFC && !isReservationUser)
            {
                if (string.IsNullOrEmpty(registerCommand.FirstName))
                    throw new ArgumentNullException(nameof(registerCommand.FirstName), "First name is required.");

                if (string.IsNullOrEmpty(registerCommand.LastName))
                    throw new ArgumentNullException(nameof(registerCommand.LastName), "Last name is required.");

                if (string.IsNullOrEmpty(registerCommand.Email))
                    throw new ArgumentNullException(nameof(registerCommand.Email), "Email is required.");

                _ = new System.Net.Mail.MailAddress(registerCommand.Email);
            }

            var roles = await _context.AspNetRoles.ToListAsync();

            if (!isAnonymous && !isAnonymousNFC && !isReservationUser)
            {
                if (registerCommand.UserRoles.Count <= 0)
                    throw new ArgumentNullException(nameof(registerCommand.UserRoles), "Please enter user role value.");

                foreach (var userRole in registerCommand.UserRoles)
                {
                    if (!roles.Any(m => m.NormalizedName == userRole))
                        throw new ValidationException("This user role does not exists. Please verify user role value.");
                }
            }

            WaysOfIdentification wayOfIdentification = new WaysOfIdentification();
            if (registerCommand.WaysOfIdentifications == null)
            {
                wayOfIdentification = WaysOfIdentification.Pin;
                registerCommand.WaysOfIdentifications?.ForEach(x =>
                {
                    wayOfIdentification |= x;
                });
            }
            else
            {
                registerCommand.WaysOfIdentifications?.ForEach(x =>
                {
                    wayOfIdentification |= x;
                });
            }


            var newUser = new ApplicationUser();

            if (isExternalUser)
            {
                //Handling QrCode 
                if (!string.IsNullOrEmpty(registerCommand.QrCode) && registerCommand.WaysOfIdentifications.Contains(WaysOfIdentification.QrCode))
                    registerCommand.QrCode = AesCrypto.EncryptString(_hubUserAuthOptions.Key, _hubUserAuthOptions.Iv, registerCommand.QrCode, 16, true);


                newUser = new ApplicationUser
                {
                    FirstName = string.IsNullOrEmpty(registerCommand.FirstName) ? registerCommand.CustomerIdentificationId : registerCommand.FirstName,
                    // CustomerIdentificationId will the employee id. So we are putting it as first name
                    LastName = registerCommand.LastName,
                    UserName = string.IsNullOrEmpty(registerCommand.Email) ? $"{registerCommand.CustomerIdentificationId}@keynius.app" : registerCommand.Email,
                    Email = string.IsNullOrEmpty(registerCommand.Email) ? $"{registerCommand.CustomerIdentificationId}@keynius.app" : registerCommand.Email,
                    SubscriptionId = registerCommand.SubscriptionId,
                    PhoneNumber = registerCommand.Phone,
                    ForceChangePassword = registerCommand.AutoGenerate,
                    CustomerId = registerCommand.CustomerId,
                    Scenarios = registerCommand.Scenarios,
                    WaysOfIdentification = wayOfIdentification,
                    QrCode = registerCommand.QrCode,
                    Language = registerCommand.Language,
                    CustomerIdentificationId = registerCommand.CustomerIdentificationId,
                    IsImported = true,
                    HouseNumber = registerCommand.HouseNumber,
                    IsAzureADUser = registerCommand.IsAzureADUser,
                };
            }
            else if (isAnonymous)
            {
                var email = string.IsNullOrEmpty(registerCommand.Email)
                               ? string.Concat(registerCommand.CustomerId + "-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "@keynius.app")
                               : registerCommand.Email.Trim().ToLower();

                newUser = new ApplicationUser
                {
                    FirstName = registerCommand.FirstName,
                    LastName = registerCommand.LastName,
                    UserName = email,
                    Email = email,
                    PhoneNumber = registerCommand.Phone,
                    ForceChangePassword = registerCommand.AutoGenerate,
                    CustomerId = registerCommand.CustomerId,
                    Scenarios = registerCommand.Scenarios,
                    WaysOfIdentification = WaysOfIdentification.Pin,
                    Language = registerCommand.Language,
                    IsAnonymous = true,
                    HouseNumber = registerCommand.HouseNumber,
                };
            }
            else if (isAnonymousNFC)
            {
                newUser = new ApplicationUser
                {
                    FirstName = registerCommand.FirstName,
                    LastName = registerCommand.LastName,
                    UserName = string.Concat(registerCommand.CustomerId + "-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "@keynius.app"),
                    Email = string.Concat(registerCommand.CustomerId + "-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "@keynius.app"),
                    PhoneNumber = registerCommand.Phone,
                    ForceChangePassword = registerCommand.AutoGenerate,
                    CustomerId = registerCommand.CustomerId,
                    Scenarios = registerCommand.Scenarios,
                    WaysOfIdentification = string.IsNullOrEmpty(registerCommand.QrCode) ? WaysOfIdentification.Rfid : WaysOfIdentification.QrCode,
                    Language = registerCommand.Language,
                    IsAnonymous = true,
                    HouseNumber = registerCommand.HouseNumber,
                    QrCode = registerCommand.QrCode,
                };
            }
            else if (isReservationUser)
            {
                var email = string.IsNullOrEmpty(registerCommand.Email)
                                ? $"{registerCommand.CustomerId}-{DateTime.UtcNow.ToString("yyyyMMddHHmmss")}@keynius.app"
                                : registerCommand.Email.Trim().ToLower();

                var phone = string.IsNullOrEmpty(registerCommand.Phone)
                                ? string.Empty
                                : registerCommand.Phone;

                newUser = new ApplicationUser
                {
                    FirstName = registerCommand.FirstName,
                    LastName = registerCommand.LastName,
                    UserName = email,
                    Email = email,
                    PhoneNumber = phone,
                    ForceChangePassword = registerCommand.AutoGenerate,
                    CustomerId = registerCommand.CustomerId,
                    Scenarios = registerCommand.Scenarios,
                    WaysOfIdentification = wayOfIdentification,
                    Language = registerCommand.Language,
                    IsAnonymous = true,
                    QrCode = registerCommand.QrCode,
                    CleanupAction = CleanupAction.Purge,
                    HouseNumber = registerCommand.HouseNumber,
                };

                // qr code value is set from the handler and not in this repository for reservation user
            }
            else
            {
                //Handling QrCode 
                if (!string.IsNullOrEmpty(registerCommand.QrCode) && registerCommand.WaysOfIdentifications.Contains(WaysOfIdentification.QrCode))
                    registerCommand.QrCode = AesCrypto.EncryptString(_hubUserAuthOptions.Key, _hubUserAuthOptions.Iv, registerCommand.QrCode, 16, true);

                newUser = new ApplicationUser
                {
                    FirstName = registerCommand.FirstName,
                    LastName = registerCommand.LastName,
                    UserName = registerCommand.Email,
                    Email = registerCommand.Email,
                    SubscriptionId = registerCommand.SubscriptionId,
                    PhoneNumber = registerCommand.Phone,
                    ForceChangePassword = registerCommand.AutoGenerate,
                    CustomerId = registerCommand.CustomerId,
                    Scenarios = registerCommand.Scenarios,
                    WaysOfIdentification = wayOfIdentification,
                    QrCode = registerCommand.QrCode,
                    Language = registerCommand.Language,
                    HouseNumber = registerCommand.HouseNumber,
                    CustomerIdentificationId = registerCommand.CustomerIdentificationId,
                    ResetPin = registerCommand.ResetPin,
                    IsMarketingSelected = registerCommand.IsMarketingSelected,
                };
            }

            var userCreationResult = await _userManager.CreateAsync(newUser, registerCommand.Password);

            if (!userCreationResult.Succeeded)
                throw new Exception(userCreationResult.Errors.First().Description);

            if (!isAnonymous && !isAnonymousNFC && !isReservationUser)
            {
                foreach (Object userRole in registerCommand.UserRoles)
                {
                    await _userManager.AddToRoleAsync(newUser, userRole.ToString());
                }
            }

            return new RegistrationResult
            {
                Id = newUser.Id,
            };

        }

        public async Task<bool> UpdateUser(UpdateUserApiModel updateUserApiModel)
        {
            if (string.IsNullOrEmpty(updateUserApiModel.FirstName))
                throw new ArgumentNullException("Firstname");

            if (string.IsNullOrEmpty(updateUserApiModel.LastName))
                throw new ArgumentNullException("Lastname");

            var user = await _userManager.FindByEmailAsync(updateUserApiModel.Email);

            if (user == null)
            {
                throw new Exception("User not found with this email");
            }

            WaysOfIdentification wayOfIdentification = new WaysOfIdentification();
            if (updateUserApiModel.WaysOfIdentifications == null)
            {
                wayOfIdentification = WaysOfIdentification.Pin;
                updateUserApiModel.WaysOfIdentifications?.ForEach(x =>
                {
                    wayOfIdentification |= x;
                });
            }
            else
            {
                updateUserApiModel.WaysOfIdentifications?.ForEach(x =>
                {
                    wayOfIdentification |= x;
                });
            }

            user.WaysOfIdentification = wayOfIdentification;
            user.FirstName = updateUserApiModel.FirstName;
            user.LastName = updateUserApiModel.LastName;
            user.PhoneNumber = updateUserApiModel.Phone;
            user.HouseNumber = updateUserApiModel.HouseNumber;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new Exception("There is some issue while updating user. Please try again or contact administrator.");
            }
            return true;
        }

        public async Task<bool> UpdateUser(UpdateUserByIdCommand updateUserCommand)
        {
            if (updateUserCommand == null)
                throw new Exception("User details are required.");

            if (string.IsNullOrEmpty(updateUserCommand.FirstName))
                throw new ArgumentNullException("First name is are required.");

            if (string.IsNullOrEmpty(updateUserCommand.LastName))
                throw new ArgumentNullException("Last name is are required.");

            var user = await _userManager.FindByIdAsync(updateUserCommand.Id);

            if (user == null)
            {
                throw new Exception("User not found.");
            }

            if (!string.IsNullOrEmpty(updateUserCommand.CustomerIdentificationId))
                if (await _context.AspNetUsers.AnyAsync(x => x.CustomerId == user.CustomerId && x.CustomerIdentificationId == updateUserCommand.CustomerIdentificationId && x.Id != user.Id))
                    throw new Exception(Messages.ResourceManager.GetString(nameof(Messages.UserIdAlreadyExist), _culture));

            user.CustomerIdentificationId = updateUserCommand.CustomerIdentificationId;
            user.FirstName = updateUserCommand.FirstName;
            user.LastName = updateUserCommand.LastName;
            user.PhoneNumber = updateUserCommand.Phone;
            user.Scenarios = updateUserCommand.Scenarios;
            user.HouseNumber = updateUserCommand.HouseNumber;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                throw new Exception("There is some issue while updating user. Please try again or contact administrator.");
            }

            return true;
        }


        public async Task<(ApplicationUser User, IQueryable<AssignedLocker> AssignedLockers)> RegisterAndSetupUser(RegisterAndSetupUserCommand registerAndSetupUser, bool isExternalUser = false)
        {
            try
            {
                using var txn = await _context.Database.BeginTransactionAsync();

                if (!string.IsNullOrEmpty(registerAndSetupUser.CustomerIdentificationId))
                    if (await _context.AspNetUsers.AnyAsync(x => x.CustomerId == registerAndSetupUser.CustomerId && x.CustomerIdentificationId == registerAndSetupUser.CustomerIdentificationId))
                        throw new Exception(registerAndSetupUser.CustomerIdentificationId + " " + Messages.ResourceManager.GetString(nameof(Messages.UserIdAlreadyExist), _culture));

                var customer = await _context.Customers.FirstOrDefaultAsync(x => x.Id == registerAndSetupUser.CustomerId);
                if (customer != null && customer.EnableSecurePin)
                    registerAndSetupUser.ResetPin = true;

                // Register User
                var userResult = await AddUser(registerAndSetupUser, isExternalUser);

                await _context.SaveChangesAsync();

                var user = await _context.Users.Include(x => x.Customer).FirstOrDefaultAsync(x => x.Id == userResult.Id);

                await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                {
                    Event = EventNames.UserCreated,
                    EndUserId = user.Id,
                    IsMainEvent = true
                }, true);

                foreach (Scenarios scenario in Enum.GetValues(typeof(Scenarios)))
                {
                    if (user.Scenarios.HasFlag(scenario) && (scenario != Scenarios.None))
                        await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.ScenarioAdded,
                            Description = scenario.ToString(),
                            EndUserId = user.Id,
                            IsMainEvent = true
                        }, true);
                }

                foreach (WaysOfIdentification identification in Enum.GetValues(typeof(WaysOfIdentification)))
                {
                    if (user.WaysOfIdentification.HasFlag(identification))
                        await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.IdentificationAdded,
                            Description = identification.ToString(),
                            EndUserId = user.Id,
                            IsMainEvent = true
                        }, true);
                }

                if (registerAndSetupUser.LockerWallIds == null)
                {
                    throw new InvalidOperationException("Lockerwalls not configured, please contact administrator");
                }

                // Validate Locker Walls
                if (user.CustomerId != null && registerAndSetupUser.LockerWallIds != null && registerAndSetupUser
                        .LockerWallIds.Except(_context.LockerWalls.Where(x => x.Site.CustomerId == user.CustomerId)
                            .Select(x => x.Id)).Any())
                {
                    throw new InvalidOperationException("Some Locker Walls Do Not Belong To The Customer");
                }

                // Save Locker Walls
                if (registerAndSetupUser.LockerWallIds != null && registerAndSetupUser.LockerWallIds.Any())
                {
                    await _context.UserLockerWalls.AddRangeAsync(registerAndSetupUser.LockerWallIds.Select(x => new UserLockerWall { UserId = user.Id, LockerWallId = x }));
                    foreach (var userLockerwall in registerAndSetupUser.LockerWallIds.Select(x => new UserLockerWall { UserId = user.Id, LockerWallId = x }))
                    {
                        await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.LockerwallAssigned,
                            Description = "Assign LockerWall to user",
                            EndUserId = user.Id,
                            LockerWallId = userLockerwall?.LockerWallId,
                            IsMainEvent = true
                        }, true);
                    }
                }
                await _context.SaveChangesAsync();

                if (registerAndSetupUser.AssignedLockers != null)
                {
                    // Assign Lockers 
                    foreach (var assignment in registerAndSetupUser.AssignedLockers)
                    {
                        var assignedLocker = await _lockerManagementRepository.AssignLockerToUser(user.Id,
                                 assignment.LockerId,
                                 assignment.StartTimeUtc,
                                 assignment.EndTimeUtc,
                                 AssignmentMode.Assigned,
                                 assignment.AllocationMode,
                                 assignment.SizeLabelId,
                                 false,
                                 txn, assignment.OneTimeUse);



                        await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.AssignLocker,
                            Description = "Assign Locker to User",
                            EndUserId = user.Id,
                            AssignmentId = assignedLocker.Id,
                            IsMainEvent = true
                        }, true);
                    }
                }

                if (registerAndSetupUser.RfIds != null && registerAndSetupUser.RfIds.Any())
                {
                    // Save rfids for user
                    foreach (var rfid in registerAndSetupUser.RfIds)
                    {
                        var userRFID = await _userIdentificationRepository.AddUserIdentification(user.Id, rfid, UserIdentificationMode.RfId);
                        await _auditDataRepository.AddAuditData(new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.IdentificationAdded,
                            Description = "RFID",
                            EndUserId = user.Id,
                            IsMainEvent = true
                        }, true);
                    }
                }

                // If role is administrator and they selected setup then make user site administrator for that user
                if (registerAndSetupUser.Sites != null && registerAndSetupUser.UserRoles != null)
                {
                    if (registerAndSetupUser.UserRoles.Any(x => x.Equals("Administrator")) && registerAndSetupUser.Sites.Count > 0)
                    {
                        var sites = registerAndSetupUser.Sites.Select(x => new SiteAdministrator { SiteId = x, UserId = user.Id });
                        await _context.SiteAdministrators.AddRangeAsync(sites);
                        foreach (var site in sites)
                        {
                            await _auditDataRepository.AddAuditData(new MainEvent(user.Id, site.Id)
                            {
                                Event = EventNames.SiteAssigned,
                                EndUserId = user.Id,
                                SiteId = site.SiteId,
                                IsMainEvent = true
                            }, true);
                        }
                    }
                }

                // Locker Administrator?
                if (registerAndSetupUser.LockerWallIds.Any() && registerAndSetupUser.UserRoles != null && registerAndSetupUser.UserRoles.Contains(UserRoles.LockerAdministrator))
                    await _lockerAdminLockerWallRepository.AddLockerWalls(userResult.Id, registerAndSetupUser.LockerWallIds);

                await _context.SaveChangesAsync();

                await txn.CommitAsync();

                return (user, _context.AssignedLockers.Where(x => x.UserId == user.Id));
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Updates And Sets Up A User
        /// </summary>
        /// <param name="updateAndSetupUser"></param>
        /// <returns></returns>
        public async Task<(ApplicationUser User, IQueryable<AssignedLocker> AssignedLockers)> UpdateAndSetupUser(UpdateAndSetupUserCommand updateAndSetupUser)
        {
            using var txn = await _context.Database.BeginTransactionAsync();
            try
            {
                var auditDataCommandList = new List<AuditDataCommand>();
                string actionById = string.Empty;
                string actionByIdName = string.Empty;

                #region Update & Audit User

                var userResult = await UpdateUser(updateAndSetupUser);
                await _context.SaveChangesAsync();

                var user = await _context.Users.Include(x => x.Customer).FirstOrDefaultAsync(x => x.Id == updateAndSetupUser.Id);

                if (_authenticationProvider.UserId != user.Id)
                {
                    var adminUser = await _userManager.FindByIdAsync(_authenticationProvider.UserId);
                    actionById = adminUser.Id;
                    actionByIdName = adminUser.UserName;
                }
                else
                {
                    actionById = user.Id;
                    actionByIdName = user.UserName;
                }

                var auditCommand = new AuditDataCommand()
                {
                    AuditEvent = new MainEvent(user.Id, user.Id)
                    {
                        Event = EventNames.UpdateUser,
                        Description = "Update User",
                        EndUserId = user.Id,
                        ActionById = actionById,
                        ActionByIdName = actionByIdName,
                        Role = Constants.Administrator,
                        ActionByAdminId = actionById
                    }
                };

                auditDataCommandList.Add(auditCommand);

                #endregion

                #region Update Role, WaysofIdentification, QrCode, Validate Lockerwall
                //user.CustomerIdentificationId = updateAndSetupUser.CustomerIdentificationId;

                // do updated WaysOfIdentification only give on audit
                WaysOfIdentification wayOfIdentification = WaysOfIdentification.Pin;
                updateAndSetupUser.WaysOfIdentifications?.ForEach(x =>
                {
                    wayOfIdentification |= x;
                });

                user.WaysOfIdentification = wayOfIdentification;

                if (user.WaysOfIdentification != wayOfIdentification)
                    user.SessionKey = Guid.NewGuid().ToString();
                else
                {
                    var oldRoles = user.UserRoles.Select(x => x.Role.NormalizedName.ToUpper()).ToList();
                    if (updateAndSetupUser.UserRoles.Any(x => !oldRoles.Contains(x.ToUpper())))
                        user.SessionKey = Guid.NewGuid().ToString();
                }

                //Handling QrCode 
                if (!string.IsNullOrEmpty(updateAndSetupUser.QrCode) && updateAndSetupUser.WaysOfIdentifications.Contains(WaysOfIdentification.QrCode))
                    user.QrCode = AesCrypto.EncryptString(_hubUserAuthOptions.Key, _hubUserAuthOptions.Iv, updateAndSetupUser.QrCode, 16, true);

                if (string.IsNullOrEmpty(updateAndSetupUser.QrCode))
                    user.QrCode = string.Empty;

                await _userManager.UpdateAsync(user);

                //role update
                var roles = await _context.AspNetRoles.ToListAsync();

                if (updateAndSetupUser.UserRoles == null)
                    throw new ArgumentNullException(nameof(updateAndSetupUser.UserRoles), "User role is required.");

                if (updateAndSetupUser.UserRoles.Count <= 0)
                    throw new ArgumentNullException(nameof(updateAndSetupUser.UserRoles), "Please enter user role value.");

                foreach (var userRole in updateAndSetupUser.UserRoles)
                {
                    if (!roles.Any(m => m.NormalizedName == userRole))
                        throw new ValidationException("This user role does not exists. Please verify user role value.");
                }

                // Remove Old Roles
                await _userManager.RemoveFromRolesAsync(user, user.UserRoles.Select(x => x.Role.NormalizedName).ToList());
                await _context.SaveChangesAsync();

                // Save Roles
                foreach (var userRole in updateAndSetupUser.UserRoles)
                {
                    await _userManager.AddToRoleAsync(user, userRole);
                }

                await _context.SaveChangesAsync();

                // Validate Locker Walls
                if (user.CustomerId != null
                    && updateAndSetupUser.LockerWallIds != null
                    && updateAndSetupUser.LockerWallIds
                                         .Select(x => x)
                                         .Except(_context.LockerWalls
                                                         .Where(x => x.Site.CustomerId == user.CustomerId)
                                                         .Select(x => x.Id)).Any())
                    throw new InvalidOperationException("Some Locker Walls Do Not Belong To The Customer");

                #endregion

                #region Update & Audit LockerWalls 
                var userLockerWalls = await _context.UserLockerWalls.Where(x => x.UserId == updateAndSetupUser.Id).ToListAsync();

                // get remove lockerWall
                if (updateAndSetupUser.LockerWallIds != null && updateAndSetupUser.LockerWallIds.Any())
                {
                    var removeLockerwalls = userLockerWalls.Where(x => !updateAndSetupUser.LockerWallIds
                                                                        .Contains(x.LockerWallId))
                                                             .ToList();

                    if (removeLockerwalls != null && removeLockerwalls.Any())
                    {
                        // Remove Locker Walls            
                        _context.UserLockerWalls.RemoveRange(removeLockerwalls);
                        await _context.SaveChangesAsync();

                        //Add auditing for remove lockerWalls
                        var deAssignLockerwallAuditList = removeLockerwalls.Select(x => new AuditDataCommand
                        {
                            AuditEvent = new MainEvent(user.Id, user.Id)
                            {
                                Event = EventNames.LockerwallDeassigned,
                                Description = "Lockerwall Deassigned",
                                EndUserId = user.Id,
                                LockerWallId = x?.LockerWallId,
                                ActionById = actionById,
                                ActionByIdName = actionByIdName,
                                Role = Constants.Administrator,
                                ActionByAdminId = actionById
                            }
                        });

                        auditDataCommandList.AddRange(deAssignLockerwallAuditList);
                    }

                    var addLockerwalls = updateAndSetupUser.LockerWallIds.Where(x => !userLockerWalls.Select(y => y.LockerWallId)
                                                                                  .Contains(x))
                                                        .ToList();
                    if (addLockerwalls != null && addLockerwalls.Any())
                    {
                        // Save Locker Walls
                        if (addLockerwalls != null && addLockerwalls.Any())
                            await _context.UserLockerWalls.AddRangeAsync(
                                addLockerwalls.Select(x =>
                                    new UserLockerWall
                                    {
                                        UserId = user.Id,
                                        LockerWallId = x
                                    })
                            );

                        await _context.SaveChangesAsync();

                        //Add auditing for AssignLockerwalls
                        var assignLockerwalls = _context.UserLockerWalls.Where(x => x.UserId == updateAndSetupUser.Id && addLockerwalls.Select(x => x).Contains(x.LockerWallId));
                        var assignLockerwallAuditList = assignLockerwalls.Select(x => new AuditDataCommand
                        {
                            AuditEvent = new MainEvent(user.Id, user.Id)
                            {
                                Event = EventNames.LockerwallAssigned,
                                Description = "Lockerwall Assigned",
                                EndUserId = user.Id,
                                LockerWallId = x.LockerWallId,
                                ActionById = actionById,
                                ActionByIdName = actionByIdName,
                                Role = Constants.Administrator,
                                ActionByAdminId = actionById
                            }
                        });
                        auditDataCommandList.AddRange(assignLockerwallAuditList);
                    }
                }
                else
                {
                    // Remove all assigned Locker Walls
                    if (userLockerWalls != null && userLockerWalls.Any())
                    {
                        _context.UserLockerWalls.RemoveRange(userLockerWalls);
                        await _context.SaveChangesAsync();

                        //Add auditing for remove lockerWalls
                        var deAssignLockerwallAuditList = userLockerWalls.Select(x => new AuditDataCommand
                        {
                            AuditEvent = new MainEvent(user.Id, user.Id)
                            {
                                Event = EventNames.LockerwallDeassigned,
                                Description = "Lockerwall Deassigned",
                                EndUserId = user.Id,
                                LockerWallId = x.LockerWallId,
                                ActionById = actionById,
                                ActionByIdName = actionByIdName,
                                Role = Constants.Administrator,
                                ActionByAdminId = actionById
                            }
                        });
                        auditDataCommandList.AddRange(deAssignLockerwallAuditList);
                    }
                }

                #endregion

                #region Update & Audit Lockers

                var existingLockersWithUser = await _context.AssignedLockers.Where(x => x.UserId == updateAndSetupUser.Id).ToListAsync();

                List<AssignLockerToUser> lockersToAssign = new List<AssignLockerToUser>();

                if (updateAndSetupUser.AssignedLockers != null && updateAndSetupUser.AssignedLockers.Any())
                {
                    var lockersToRemoveAssignment = existingLockersWithUser.Where(x => !updateAndSetupUser.AssignedLockers
                                                                                      .Select(y => y.LockerId)
                                                                                      .Contains(x.LockerId))
                                                       .ToList();
                    if (lockersToRemoveAssignment != null && lockersToRemoveAssignment.Any())
                    {
                        // Remove Assignments
                        _context.AssignedLockers.RemoveRange(lockersToRemoveAssignment);
                        await _context.SaveChangesAsync();

                        //Add auditing for remove Assignments 
                        var lockerAssignmentRemovedAuditList = lockersToRemoveAssignment.Select(x => new AuditDataCommand
                        {
                            AuditEvent = new MainEvent(updateAndSetupUser.UserId, user.Id)
                            {
                                Event = EventNames.AssignmentRemoved,
                                Description = "Deassign Locker",
                                EndUserId = user.Id,
                                AssignmentId = x.Id,
                                ActionById = actionById,
                                ActionByIdName = actionByIdName,
                                Role = Constants.Administrator,
                                ActionByAdminId = actionById
                            }
                        });
                        auditDataCommandList.AddRange(lockerAssignmentRemovedAuditList);
                    }

                    lockersToAssign = updateAndSetupUser.AssignedLockers?.Where(x => !existingLockersWithUser
                                                                                         .Select(y => y.LockerId)
                                                                                         .Contains(x.LockerId))
                                                             .ToList();

                    if (lockersToAssign != null && lockersToAssign.Any())
                    {
                        // Assign Lockers 
                        foreach (var assignment in lockersToAssign)
                        {
                            var assignedLocker = await _lockerManagementRepository.AssignLockerToUser(user.Id,
                                    assignment.LockerId,
                                    assignment.StartTimeUtc,
                                    assignment.EndTimeUtc,
                                    AssignmentMode.Assigned,
                                    assignment.AllocationMode,
                                    assignment.SizeLabelId,
                                    false,
                                    txn, assignment.OneTimeUse);

                            if (assignedLocker != null)
                            {
                                assignment.LockerId = assignedLocker.LockerId;
                            }


                            //Add auditing for assign locker
                            var lockerAssignmentAudit = new AuditDataCommand
                            {
                                AuditEvent = new MainEvent(updateAndSetupUser.UserId, user.Id)
                                {
                                    Event = EventNames.AssignLocker,
                                    Description = "Assign Locker",
                                    EndUserId = user.Id,
                                    AssignmentId = assignedLocker.Id,
                                    ActionById = actionById,
                                    ActionByIdName = actionByIdName,
                                    Role = Constants.Administrator,
                                    ActionByAdminId = actionById
                                }
                            };
                            auditDataCommandList.Add(lockerAssignmentAudit);

                            //Send email to user that one time locker assigned
                            if (assignment.OneTimeUse)
                            {
                                await SendOneTimeAssignmentEmailToUser(assignment, user);
                            }

                            var isLockerAssignedEmailEnabled = await _context.CustomerConfigurations
                                .Where(w => w.CustomerId == user.CustomerId && w.Scenario.HasFlag(Scenarios.Assigned))
                                .Select(w => w.IsLockerAssignedEmailEnabled).FirstOrDefaultAsync();

                            if (isLockerAssignedEmailEnabled)
                            {
                                await SendLockerAssignedEmailToUser(new List<AssignedLocker>() { assignedLocker },
                                    new List<UserGroupAssignedLockerMapping>());
                            }
                        }
                    }
                    await _context.SaveChangesAsync();
                }


                #endregion

                #region Update & Audit RFID

                _context.RfIdIdentifications.RemoveRange(_context.RfIdIdentifications.Where(x => x.UserId == updateAndSetupUser.Id));
                _context.BatteryLockUserIdentifications.RemoveRange(_context.BatteryLockUserIdentifications.Where(x => x.UserId == updateAndSetupUser.Id));
                await _context.SaveChangesAsync();

                if (updateAndSetupUser.RfIds != null && updateAndSetupUser.RfIds.Any())
                {
                    // Assign rfids 
                    foreach (var rfid in updateAndSetupUser.RfIds)
                    {
                        var userRFID = await _userIdentificationRepository.AddUserIdentification(user.Id, rfid, UserIdentificationMode.RfId);
                    }

                    var identificationRFIDAudit = updateAndSetupUser.RfIds.Select(x => new AuditDataCommand
                    {
                        AuditEvent = new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.IdentificationAdded,
                            Description = "RFID",
                            EndUserId = user.Id,
                            ActionById = actionById,
                            ActionByIdName = actionByIdName,
                            Role = Constants.Administrator,
                            ActionByAdminId = actionById
                        }
                    });
                    auditDataCommandList.AddRange(identificationRFIDAudit);
                }

                if (updateAndSetupUser.BatteryLockRfids != null && updateAndSetupUser.BatteryLockRfids.Any())
                {
                    // Assign battery lock rfid
                    foreach (var rfid in updateAndSetupUser.BatteryLockRfids)
                    {
                        var userBatteryLockRFID = await _userIdentificationRepository.AddUserIdentification(user.Id, rfid, UserIdentificationMode.BatteryLockerRfId, BatteryLockIdentification.Rfid, user.CustomerId);
                    }

                    var identificationBatteryLockRFIDAudit = updateAndSetupUser.BatteryLockRfids.Select(x => new AuditDataCommand
                    {
                        AuditEvent = new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.IdentificationAdded,
                            Description = "Battery Lock RFID",
                            EndUserId = user.Id,
                            ActionById = actionById,
                            ActionByIdName = actionByIdName,
                            Role = Constants.Administrator,
                            ActionByAdminId = actionById
                        }
                    });
                    auditDataCommandList.AddRange(identificationBatteryLockRFIDAudit);
                }

                if (updateAndSetupUser.BatteryLockPins != null && updateAndSetupUser.BatteryLockPins.Any())
                {
                    // Assign battery lock pin
                    foreach (var rfid in updateAndSetupUser.BatteryLockPins)
                    {
                        var userBatteryPin = await _userIdentificationRepository.AddUserIdentification(user.Id, rfid, UserIdentificationMode.BatteryLockerPin, BatteryLockIdentification.Pin, user.CustomerId);
                    }

                    var identificationBatteryLockPINAudit = updateAndSetupUser.BatteryLockPins.Select(x => new AuditDataCommand
                    {
                        AuditEvent = new MainEvent(user.Id, user.Id)
                        {
                            Event = EventNames.IdentificationAdded,
                            Description = "Battery Lock PIN",
                            EndUserId = user.Id,
                            ActionById = actionById,
                            ActionByIdName = actionByIdName,
                            Role = Constants.Administrator,
                            ActionByAdminId = actionById
                        }
                    });
                    auditDataCommandList.AddRange(identificationBatteryLockPINAudit);
                }

                await _context.SaveChangesAsync();
                #endregion

                #region SHC_CHANGE_LOCKER_LED

                if (lockersToAssign != null && lockersToAssign.Any())
                {
                    var smartHomeLockersToAssign =
                    _context.Lockers.Join(_context.AssignedLockers
                        , locker => locker.Id,
                            assign => assign.LockerId, (locker, assign) => new
                            {
                                locker.Id,
                                locker.LockerWall.LockerType,
                                assign.UserId
                            })
                        .Where(x => lockersToAssign.Select(l => l.LockerId).Contains(x.Id) &&
                        (x.LockerType == LockerType.SmarthomeLock || x.LockerType == LockerType.SmarthomeLockV2)).ToList();

                    if (smartHomeLockersToAssign.Any())
                    {
                        var assignmentModes = await _lockerModelRepository
                                            .GetSmartHomeLockerAssignmentMode(smartHomeLockersToAssign.Select(a => a.Id).ToList());

                        // send command to hardware
                        for (int i = 0; i < smartHomeLockersToAssign.Count(); i++)
                        {

                            var sbCommand = new ChangeLedColorCommand
                            {
                                LockerId = smartHomeLockersToAssign[i].Id,
                                Status = SmartHomeLockerLedStatus.InUse,
                                UserRFID = (updateAndSetupUser.RfIds != null && updateAndSetupUser.RfIds?.Count > 0) ? updateAndSetupUser.RfIds.FirstOrDefault() : "00000000",
                                AssignMode = assignmentModes.FirstOrDefault(x => x.LockerID == smartHomeLockersToAssign[i].Id).AssignMode,
                            };

                            await _serviceBusHelper.ChangeSmarthomeLed(JsonConvert.SerializeObject(sbCommand,
                                Formatting.None, new JsonSerializerSettings
                                {
                                    ReferenceLoopHandling = ReferenceLoopHandling.Serialize
                                }));
                        }
                    }
                }

                #endregion

                #region Update & Audit Site
                var siteAdministrators = await _context.SiteAdministrators.Where(x => x.UserId == updateAndSetupUser.Id).ToListAsync();


                if (updateAndSetupUser.Sites != null && updateAndSetupUser.Sites.Any())
                {
                    var removeSiteAdministrators = siteAdministrators.Where(x => !updateAndSetupUser
                                                                                             .Sites
                                                                                             .Contains(x.SiteId))
                                                                                 .ToList();
                    if (removeSiteAdministrators != null && removeSiteAdministrators.Any())
                    {
                        //Remove sites
                        _context.SiteAdministrators.RemoveRange(removeSiteAdministrators);
                        await _context.SaveChangesAsync();

                        //Add audit for Deassign siteAdministrators
                        var sitesDeAssignedAudit = removeSiteAdministrators.Select(x => new AuditDataCommand
                        {
                            AuditEvent = new MainEvent(user.Id, user.Id)
                            {
                                Event = EventNames.SiteDeassigned,
                                Description = "Site Deassigned",
                                SiteId = x.SiteId,
                                EndUserId = user.Id,
                                ActionById = actionById,
                                ActionByIdName = actionByIdName,
                                Role = Constants.Administrator,
                                ActionByAdminId = actionById
                            }
                        });
                        auditDataCommandList.AddRange(sitesDeAssignedAudit);
                    }

                    var addsiteAdministrator = updateAndSetupUser.Sites?.Where(x => !siteAdministrators
                                                                                   .Select(y => y.SiteId)
                                                                                   .Contains(x))
                                                                   .ToList();

                    // If role is administrator and they selected setup then make user site administrator for that user
                    if ((addsiteAdministrator != null && addsiteAdministrator.Any()) && updateAndSetupUser.UserRoles != null)
                    {
                        if (updateAndSetupUser.UserRoles.Any(x => x.Equals("Administrator")) && addsiteAdministrator?.Count > 0)
                        {
                            var sites = addsiteAdministrator.Select(x => new SiteAdministrator { SiteId = x, UserId = user.Id });
                            await _context.SiteAdministrators.AddRangeAsync(sites);

                            var sitesAssignedAudit = sites.Select(x => new AuditDataCommand
                            {
                                AuditEvent = new MainEvent(user.Id, user.Id)
                                {
                                    Event = EventNames.SiteAssigned,
                                    Description = "Site Assigned",
                                    SiteId = x.SiteId,
                                    EndUserId = user.Id,
                                    ActionById = actionById,
                                    ActionByIdName = actionByIdName,
                                    Role = Constants.Administrator,
                                    ActionByAdminId = actionById
                                }
                            });
                            auditDataCommandList.AddRange(sitesAssignedAudit);
                        }
                    }
                }

                // Locker Administrator?
                await _lockerAdminLockerWallRepository.DeleteLockerWalls(updateAndSetupUser.Id);
                if (updateAndSetupUser.LockerWallIds.Any() && updateAndSetupUser.UserRoles != null && updateAndSetupUser.UserRoles.Contains(UserRoles.LockerAdministrator))
                    await _lockerAdminLockerWallRepository.AddLockerWalls(updateAndSetupUser.Id, updateAndSetupUser.LockerWallIds);

                await _context.SaveChangesAsync();
                #endregion;

                await txn.CommitAsync();

                await _serviceBusHelper.ServiceBusAsync<List<AuditDataCommand>>(auditDataCommandList, ConstantsModel.AUDITING_SERVICE_NAME);

                return (user, _context.AssignedLockers.Where(x => x.UserId == user.Id));
            }
            catch (Exception ex)
            {
                await txn.RollbackAsync();
                throw;
            }
        }

     

        /// <summary>
        /// Generate random password based on password option
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        public static string GeneratePassword(PasswordOptions options)
        {
            int length = options.RequiredLength;
            bool nonAlphanumeric = options.RequireNonAlphanumeric;
            bool digit = options.RequireDigit;
            bool lowercase = options.RequireLowercase;
            bool uppercase = options.RequireUppercase;

            string[] randomChars = new[] {
            "ABCDEFGHJKLMNOPQRSTUVWXYZ",    // uppercase 
            "abcdefghijkmnopqrstuvwxyz",    // lowercase
            "0123456789",                   // digits
            "!@$?_"                        // non-alphanumeric
            };

            Random rand = new Random(Environment.TickCount);
            List<char> password = new List<char>();

            if (options.RequireUppercase)
                password.Insert(rand.Next(0, password.Count), randomChars[0][rand.Next(0, randomChars[0].Length)]);

            if (options.RequireLowercase)
                password.Insert(rand.Next(0, password.Count), randomChars[1][rand.Next(0, randomChars[1].Length)]);

            if (options.RequireDigit)
                password.Insert(rand.Next(0, password.Count), randomChars[2][rand.Next(0, randomChars[2].Length)]);

            if (options.RequireNonAlphanumeric)
                password.Insert(rand.Next(0, password.Count), randomChars[3][rand.Next(0, randomChars[3].Length)]);

            for (int i = password.Count; i < options.RequiredLength || password.Distinct().Count() < options.RequiredUniqueChars; i++)
            {
                string rcs = randomChars[rand.Next(0, randomChars.Length)];
                password.Insert(rand.Next(0, password.Count), rcs[rand.Next(0, rcs.Length)]);
            }

            return new string(password.ToArray());
        }

        public async Task SyncUsers(string customerId, IEnumerable<string> userNames)
        {
            // All users of that customer
            var allUsers = _context.AspNetUsers.IgnoreQueryFilters().Where(x => x.CustomerId == customerId && !x.IsAnonymous);
            foreach (var user in allUsers)
            {
                if (user.UserRoles.Count == 1 && user.UserRoles.First().Role.NormalizedName == UserRoles.SmartHubUser)
                {
                    if (userNames.Contains(user.UserName))
                        user.BringBack();
                    else
                        user.Delete();
                }
            }
            await _context.SaveChangesAsync();
        }
       
        private async Task<bool> ResetUserPassword(ApplicationUser user, string newPassword)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetPasswordResult = await _userManager.ResetPasswordAsync(user, token, newPassword);
            return resetPasswordResult.Succeeded;
        }

        private async Task<(bool isExisting, ApplicationUser user)> UpsertUser(RegisterCommand register)
        {
            var user = await _userManager.Users.IgnoreQueryFilters().FirstOrDefaultAsync(x => x.UserName == register.Email);
            var isExisting = user != null;
            if (isExisting)
            {
                await UpdateUser(new UpdateUserApiModel { FirstName = register.FirstName, LastName = register.LastName, Phone = register.Phone, Email = register.Email, WaysOfIdentifications = register.WaysOfIdentifications });
            }
            else
            {
                var userId = (await AddUser(register)).Id;
                user = await _userManager.FindByIdAsync(userId);
                var pin = await _smartHubUserRepository.GetPin(userId);

                if (user.UserRoles.FirstOrDefault().Role.Name == ConstantsModel.AcademyMember)
                    await _emailTemplateHandler.SendAcademyUserEmailTemplate(user.Email, user.CustomerId, register.Password);
                else if (register.IsPIMUser)
                {// This case will be used to send email of Keynius, Entity, Partner backoffice and Entity, Partner Sales rep
                    await _emailTemplateHandler.PIMUserCreationEmailTemplateAsync(user.Email, user.CustomerId, register.Password);
                }
                else
                {
                    var registerEmailResult = await _emailTemplateHandler.PasswordAutoGenerateEmailTemplateAsync(register, pin, _configuration.GetSection(Constants.PortalUrlKey).Value);
                    await _messageService.SendEmailAsync(register.Email, registerEmailResult.subject, registerEmailResult.body);
                }
            }
            return (isExisting, user);
        }

        public class UserName
        {
            public string UserFullName { get; set; }
            public UserName(string firstName, string lastName)
            {
                UserFullName = firstName + " " + lastName;
            }
        }
        private async Task SendEmail<T>(T emailModel, string customerId, string userLanguage, string[] emailIds, EmailTemplate emailTemplate)
        {
            var emailNotificationCommands = new List<EmailNotificationCommand>();

            var notificationCommand = new NotificationCommand();
            notificationCommand.NotificationType = NotificationType.Email;

            var emailNotificationCommandModel = new EmailNotificationCommand
            {
                EmailTemplate = emailTemplate,
                Emails = emailIds,
                Model = JsonConvert.SerializeObject(emailModel),
                Language = userLanguage,
                CustomerId = customerId
            };

            emailNotificationCommands.Add(emailNotificationCommandModel);

            if (emailNotificationCommands != null && emailNotificationCommands.Any())
            {
                notificationCommand.Data = JsonConvert.SerializeObject(emailNotificationCommands);
                //send maill
                await _serviceBusHelper.ServiceBusAsync<NotificationCommand>(notificationCommand, null);
            }
        }

        public async Task SendLockerAssignedEmailToUser(List<AssignedLocker> assignedLockers, List<UserGroupAssignedLockerMapping> userGroupAssignedLockerMappings)
        {

            foreach (var assignedLocker in assignedLockers)
            {
                string[] emailIds;
                var userGroupAssignedLockerMapping = userGroupAssignedLockerMappings.FirstOrDefault(w => w.AssignedLockerId == assignedLocker.Id);
                ApplicationUser user;

                if (assignedLocker.User == null && userGroupAssignedLockerMapping != null)
                {
                    emailIds = userGroupAssignedLockerMapping.UserGroup.UserGroupUsers.Select(q => q.User.Email).ToArray();
                    user = userGroupAssignedLockerMapping.UserGroup.UserGroupUsers.Select(e => e.User).FirstOrDefault();
                }
                else
                {
                    emailIds = new string[] { assignedLocker?.User?.Email };
                    user = assignedLocker.User;
                }

                var model = new LockerAssignedToUserModel()
                {
                    LockerName = assignedLocker.Locker.InstallationInfo.Tag,
                    LockerWallName = assignedLocker.Locker.LockerWall.Name,
                    CustomerId = user?.CustomerId,
                    Language = user?.Language,
                    SiteName = assignedLocker.Locker.LockerWall.Site.Name
                };
                await SendEmail<LockerAssignedToUserModel>(model, model.CustomerId, model.Language, emailIds, EmailTemplate.LockerAssignedToUser);
            }
        }
    }
}

