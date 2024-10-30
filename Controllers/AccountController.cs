using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.VisualBasic;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using WebApplication1.Common;

namespace WebApplication1.Controllers
{
    /// <summary>
    /// Controller to handle account behaviour and bussiness logic
    /// </summary>
    [Route("api/[controller]")]
    public class AccountController : ApiBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JwtIssuerOptions _jwtOptions;
        private readonly IMessageService _messageService;
        private readonly TelemetryClient _telemetryClient;
        private readonly IConfiguration _configuration;
        private readonly INotificationManager _notificationManager;
        private readonly IEmailTemplate _emailTemplate;
        private readonly IKeyniusCustomerAdRepository _keyniusCustomerAdRepository;
        private readonly IMSGraphService _msGraphService;
        private readonly ITokenAcquisition _tokenAcquisition;
        private readonly GraphServiceClient _graphServiceClient;
        private readonly IInvalidTokenCacheHelper _cacheHelper;
        private readonly ApplicationDbContext _dbContext;
        private readonly string _hubUserAuthKey;
        private readonly string _hubUserAuthIv;
        private readonly IAccountRepository _accountRepository;
        private readonly IGenericRepository<UserFingerprintEnrollment> _userFingerprintEnrollmentRepository;
        private readonly IServiceBusHelper _serviceBusHelper;
        /// <summary>
        /// Constructor to initialize account controller
        /// </summary>
        /// <param name="mediator"></param>
        /// <param name="userManager"></param>
        /// <param name="roleManager"></param>
        /// <param name="signInManager"></param>
        /// <param name="jwtOptions"></param>
        /// <param name="messageService"></param>
        /// <param name="telemetryClient"></param>
        /// <param name="configuration"></param>
        /// <param name="notificationManager"></param>
        /// <param name="emailTemplate"></param>
        /// <param name="keyniusCustomerAdRepository"></param>
        /// <param name="msGraphS6ervice"></param>
        public AccountController(IMediator mediator,
                                  UserManager<ApplicationUser> userManager,
                                  RoleManager<ApplicationRole> roleManager,
                                  SignInManager<ApplicationUser> signInManager,
                                  IOptions<JwtIssuerOptions> jwtOptions,
                                  IMessageService messageService,
                                  TelemetryClient telemetryClient,
                                  IConfiguration configuration,
                                  INotificationManager notificationManager,
                                  IEmailTemplate emailTemplate,
                                  IKeyniusCustomerAdRepository keyniusCustomerAdRepository,
                                  IMSGraphService msGraphService,
                                  ITokenAcquisition tokenAcquisition,
                                  GraphServiceClient graphServiceClient,
                                  IInvalidTokenCacheHelper cacheHelper,
                                  ApplicationDbContext dbContext,
                                  IAccountRepository accountRepository,
                                  IGenericRepository<UserFingerprintEnrollment> userFingerprintEnrollmentRepository,
                                  IServiceBusHelper serviceBusHelper) : base(mediator)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _jwtOptions = jwtOptions.Value;
            _messageService = messageService;
            _telemetryClient = telemetryClient;
            _configuration = configuration;
            this._notificationManager = notificationManager;
            this._emailTemplate = emailTemplate;
            _keyniusCustomerAdRepository = keyniusCustomerAdRepository;
            _accountRepository = accountRepository;
            _msGraphService = msGraphService;
            _tokenAcquisition = tokenAcquisition;
            _graphServiceClient = graphServiceClient;
            _cacheHelper = cacheHelper;
            _dbContext = dbContext;
            _hubUserAuthKey = _configuration.GetSection("HubUserAuth:Key").Value;
            _hubUserAuthIv = _configuration.GetSection("HubUserAuth:Iv").Value;
            _userFingerprintEnrollmentRepository = userFingerprintEnrollmentRepository;
            _serviceBusHelper = serviceBusHelper;
        }

        /// <summary>
        /// Registers and Setup a new account.
        /// </summary>
        /// <returns>Registration Result</returns>
        /// <param name="command">Register Command</param>
        [HttpPost]
        [Route("RegisterAndSetup")]
        [HasCustomerId]
        [AuthorizeWithMultiplePermissions(UserRoles.Administrator, UserRoles.KeyniusConsultant)]
        [PublicApi]
        public async Task<ActionResult<GenericBaseResult<SetupUserResult>>> RegisterAndSetup([FromBody] RegisterAndSetupUserCommand command)
        {

            try
            {
                // handle auto generate at controller level
                if (command.AutoGenerate)
                    command.Password = AccountRepository.GeneratePassword(_userManager.Options.Password);
                else if (string.IsNullOrEmpty(command.Password))
                    throw new ArgumentNullException("Password is required.");

                command.UserId = HttpContext.User.GetUserId();

                var result = await GetResult(command);

                // handle sending email invite on register user
                if (result.IsSuccess)
                {
                    if (!(command.UserRoles.Contains(ConstantsModel.SmartHubUser) && (!command.HasAssignedUseSceneario && !command.HasDistributionUseSceneario && !command.HasFlexUseSceneario && !command.HasRentalUseSceneario) && (command.HasDropOffPickUpAnonymousSceneario || command.HasDropOffPickUpSceneario || command.HasFlexAnonymousUseSceneario)))
                        await _emailTemplate.RegisterAndSetupUserEmailFromFunction(command, result.Result, _configuration.GetSection(Constants.PortalUrlKey).Value);

                    var user = await _userManager.FindByEmailAsync(result.Result.Email);

                    if (user.WaysOfIdentification == WaysOfIdentification.MobileApp)
                    {
                        if (result.Result.Lockers != null)
                        {
                            if (result.Result.Lockers.Count > 0)
                            {
                                var culture = new CultureInfo(user.Language);
                                string title = Messages.ResourceManager.GetString(nameof(Messages.SubjectLockerAvailable), culture);
                                string body = string.Format(Messages.ResourceManager.GetString(nameof(Messages.LockerAvailable), culture), result.Result.Lockers[0].Locker.Tag);
                                await _notificationManager.SendNotificationByUserId(user.Id, title, body, new Dictionary<string, string>() { { "type", "assigned" }, { "tag", $"{result.Result.Lockers[0].Locker.Tag}" } });
                            }
                        }
                    }

                    //Send oneTime locker assignment email
                    var oneTimeAssignments = await _dbContext.AssignedLockers.Where(x => x.UserId == user.Id && x.OneTimeUse == true).ToListAsync();
                    if (oneTimeAssignments != null && oneTimeAssignments.Any())
                    {
                        foreach (var assignment in oneTimeAssignments)
                        {
                            await _accountRepository.SendOneTimeAssignmentEmailToUser(new AssignLockerToUser() { LockerId = assignment.LockerId, StartTimeUtc = assignment.StartTimeUtc, EndTimeUtc = assignment.EndTimeUtc, OneTimeUse = assignment.OneTimeUse }, user);
                        }
                    }

                }

                return result;
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackException(ex);

                return GetResponseFromResult(
                    new GenericBaseResult<SetupUserResult>(null)
                    {
                        ResponseStatusCode = System.Net.HttpStatusCode.Unauthorized,
                        Errors = new List<string> { ex.Message },
                        Message = ex.Message
                    });
            }
        }


        /// <summary>
        /// Updates and Setup a new account.
        /// </summary>
        /// <returns>Registration Result</returns>
        /// <param name="command">Update Command</param>
        [HttpPost]
        [Route("UpdateAndSetup")]
        [HasCustomerId]
        [AuthorizeWithMultiplePermissions(UserRoles.Administrator, UserRoles.KeyniusConsultant, UserRoles.LockerAdministrator)]
        [PublicApi]
        public async Task<ActionResult<GenericBaseResult<SetupUserResult>>> UpdateAndSetup([FromBody] UpdateAndSetupUserCommand command)
        {
            try
            {
                command.UserId = HttpContext.User.GetUserId();
                var user = await _userManager.FindByIdAsync(command.Id);

                if (user == null)
                {
                    return GetResponseFromResult(new GenericBaseResult<SetupUserResult>(null)
                    {
                        ResponseStatusCode = System.Net.HttpStatusCode.NotFound,
                        Errors = new List<string> { "User not found." },
                        Message = "User not found."
                    });
                }

                var oldWayOfIdentification = user.WaysOfIdentification;

                command.Email = user.Email;
                var result = await GetResult<GenericBaseResult<SetupUserResult>>(command);

                // handle sending email 
                if (result.IsSuccess)
                {
                    command.Language = user.Language;

                    if (!oldWayOfIdentification.HasFlag(WaysOfIdentification.MobileApp) && command.WaysOfIdentifications.Contains(WaysOfIdentification.MobileApp) && user.ForceChangePassword)
                    {
                        if (!user.IsAzureADUser)
                        {
                            var tempPassword = AccountRepository.GeneratePassword(_userManager.Options.Password);
                            command.Password = tempPassword;
                            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                            var resetPasswordResult = await _userManager.ResetPasswordAsync(user, token, command.Password);
                            await _emailTemplate.UpdateUserMobileAppEmailTemplate(command, result.Result, _configuration.GetSection(Constants.PortalUrlKey).Value);

                        }
                    }

                    if (oldWayOfIdentification.HasFlag(WaysOfIdentification.FingerPrint) && !command.WaysOfIdentifications.Contains(WaysOfIdentification.FingerPrint))
                    {
                        var removeFinger = await _userFingerprintEnrollmentRepository.GetQueryable().Where(a => a.UserId == user.Id).ToListAsync();
                        if (removeFinger != null)
                        {
                            await _userFingerprintEnrollmentRepository.DeleteRangeAsync(removeFinger);
                        }
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackException(ex);

                return GetResponseFromResult(
                    new GenericBaseResult<SetupUserResult>(null)
                    {
                        ResponseStatusCode = System.Net.HttpStatusCode.InternalServerError,
                        Errors = new List<string> { ex.Message },
                        Message = ex.Message
                    });
            }
        }

        /// <summary>
        /// Deletes an User by email
        /// </summary>
        /// <param name="email">Email Address of the user</param>
        /// <returns>Ok if succeeds</returns>
        [HttpDelete("{email}")]
        [AuthorizeWithMultiplePermissions(ResourcePrmissions.SmartHubUserWrite, ResourcePrmissions.CustomerWrite)]
        [HasCurrentUserId]
        public async Task<ActionResult<GenericBaseResult<bool>>> DeleteUser(DeleteUserCommand email)
            => GetResponseFromResult(await Mediator.Send(email));

        #region Login

        /// <summary>
        /// Login an account.
        /// </summary>
        /// <returns>Login Result</returns>
        /// <param name="command">Login Command</param>
        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        [PublicApi]
        public async Task<ActionResult<GenericBaseResult<AuthenticationResponse>>> Login([FromBody] LoginCommand command)
        {
            try
            {
                var context = this.HttpContext;
                var headerValues = context.Request.Headers["x-calling-platform"].FirstOrDefault();
                if (command == null)
                    throw new ArgumentNullException("Email and password is required.");

                if (string.IsNullOrEmpty(command.Email))
                    throw new ArgumentNullException("Email is required.");

                if (string.IsNullOrEmpty(command.Password))
                    throw new ArgumentNullException("Password is required.");

                if (string.IsNullOrEmpty(command.DeviceId))
                    throw new ArgumentNullException("DeviceId is required.");

                if (string.IsNullOrEmpty(command.Platform))
                    throw new ArgumentNullException("Platform is required.");


                var user = await _userManager.FindByNameAsync(command.Email);

                if (user == null)
                    throw new Exception("Invalid email.");

                if (user.IsBlocked)
                    throw new Exception(Messages.ResourceManager.GetString(nameof(Messages.UserIsBlockedContactAdmin), new CultureInfo(user.Language ?? "nl")));

                if (user.LockoutEnd.HasValue)
                {
                    throw new Exception(Messages.ResourceManager.GetString(nameof(Messages.UserIsLockedOut), new CultureInfo(user.Language ?? "nl")));
                }

                var result = await _signInManager.PasswordSignInAsync(user.Email, command.Password, true, lockoutOnFailure: true);
                if (result.IsLockedOut)
                {
                    List<AuditDataCommand> auditDataCommands = new List<AuditDataCommand>();
                    var auditCommand = new AuditDataCommand
                    {
                        AuditEvent = new AuditEvent
                        {
                            Event = EventNames.UserLoginLocked,
                            IsMainEvent = true,
                            Description = "Login locked after over 5 failed password attempts",
                            ActionById = user.Id,
                            EndUserId = user.Id,
                        }
                    };
                    auditDataCommands.Add(auditCommand);
                    if (auditDataCommands?.Count > 0)
                    {
                        await _serviceBusHelper.ServiceBusAsync<List<AuditDataCommand>>(auditDataCommands, ConstantsModel.AUDITING_SERVICE_NAME);
                    }
                    throw new Exception(Messages.ResourceManager.GetString(nameof(Messages.UserIsLockedOut), new CultureInfo(user.Language ?? "nl")));
                }

                //var isValid = await _userManager.CheckPasswordAsync(user, command.Password);
                if (!result.Succeeded)
                    throw new Exception("Invalid email or password.");

                if (!Enum.IsDefined(typeof(Keynius.Backend.Contracts.Enumerations.Platform), command.Platform))
                    throw new Exception("Invalid platform, verify and retry");

                if (((Keynius.Backend.Contracts.Enumerations.Platform)Enum.Parse(typeof(Keynius.Backend.Contracts.Enumerations.Platform), command.Platform) == Keynius.Backend.Contracts.Enumerations.Platform.Android && !user.WaysOfIdentification.HasFlag(WaysOfIdentification.MobileApp))
                    || ((Keynius.Backend.Contracts.Enumerations.Platform)Enum.Parse(typeof(Keynius.Backend.Contracts.Enumerations.Platform), command.Platform) == Keynius.Backend.Contracts.Enumerations.Platform.iOS && !user.WaysOfIdentification.HasFlag(WaysOfIdentification.MobileApp)))
                    throw new Exception("You do not have permission to use Keynius app, please contact your administrator.");

                await Mediator.Send(new AddDeviceCommand(command.DeviceId, command.Platform, user.Id, command.Token));

                var token = await GetToken(user);

                _telemetryClient.TrackEvent($"Login: {command.Email}");

                List<WaysOfIdentification> waysOfIdentifications = new List<WaysOfIdentification>()
                {
                    // pin is default way of identification for the user
                    WaysOfIdentification.Pin
                };
                if ((user.WaysOfIdentification & WaysOfIdentification.Rfid) != 0)
                    waysOfIdentifications.Add(WaysOfIdentification.Rfid);
                if ((user.WaysOfIdentification & WaysOfIdentification.MobileApp) != 0)
                    waysOfIdentifications.Add(WaysOfIdentification.MobileApp);

                AuthenticationResponse Authentication = new AuthenticationResponse
                {
                    UserId = user.Id,
                    AccessToken = token.AccessToken,
                    RefreshToken = token.RefreshToken,
                    ExpiresIn = (int)_jwtOptions.ValidFor.TotalSeconds,
                    SubscriptionId = user.SubscriptionId,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    ForceChangePassword = user.ForceChangePassword,
                    WaysOfIdentification = waysOfIdentifications,
                    Language = user.Language,
                    IsBlocked = user.IsBlocked,
                    Tenants = new List<Tenants>()
                    {
                        new Tenants()
                        {
                            Id = user.CustomerId,
                            Name = user.Customer?.BusinessAccountName,
                        }
                    },
                    Provider = AuthorizationProviderTypes.Azure
                };

                if (headerValues == "Smarty")
                {
                    List<string> allowedRoles = new List<string>();
                    allowedRoles.Add("Technician");
                    allowedRoles.Add("PartnerTechnician");
                    allowedRoles.Add("KeyniusTechnician");
                    var roles = user.UserRoles.Select(x => x.Role).Select(x => x.Name).ToList();
                    if (roles.Any(allowedRoles.Contains))
                    {
                        return GetResponseFromResult(new GenericBaseResult<AuthenticationResponse>(Authentication));
                    }
                    else
                    {
                        throw new Exception("You do not have permission to login");
                    }
                }
                else
                    return GetResponseFromResult(new GenericBaseResult<AuthenticationResponse>(Authentication));
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackException(ex);

                return GetResponseFromResult(
                    new GenericBaseResult<AuthenticationResponse>(null)
                    {
                        ResponseStatusCode = System.Net.HttpStatusCode.Unauthorized,
                        Errors = new List<string> { ex.Message },
                        Message = ex.Message
                    });
            }
        }

        #endregion

        #region Logout

        /// <summary>
        /// Logout this instance.
        /// </summary>
        /// <returns>Base Result</returns>
        [HttpPost]
        [Route("logout")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<BaseResult> Logout()
        {
            try
            {
                Request.Headers.TryGetValue(Constants.AuthorizationKey, out var accessToken);

                if (StringValues.IsNullOrEmpty(accessToken))
                    return new BaseResult
                    {
                        Errors = new List<string> { "Unauthorized" },
                        ResponseStatusCode = System.Net.HttpStatusCode.Unauthorized
                    };

                var token = accessToken.FirstOrDefault();

                token = token.Substring(token.IndexOf(" ", StringComparison.InvariantCulture) + 1);

                await _signInManager.SignOutAsync(); // We are not using cookie based auth now?

                // Delete the access token
                //await _authRepository.RemoveAccessTokenAsync(token);

                return new BaseResult
                {
                    Message = "You've been logged out successfully",
                    ResponseStatusCode = System.Net.HttpStatusCode.OK
                };
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackException(ex);

                return new BaseResult
                {
                    Message = ex.Message,
                    Errors = new List<string> { ex.Message },
                    ResponseStatusCode = System.Net.HttpStatusCode.BadRequest
                };
            }
        }

        #endregion

        #region Reset Password

        /// <summary>
        /// Send Email for Reset Password.
        /// </summary>
        /// <param name="email"></param>
        /// <returns>Base Result</returns>

        [HttpGet]
        [Route("resetpassword/{email}")]
        [AllowAnonymous]
        [PublicApi]
        public async Task<BaseResult> ResetPassword(string email)
        {
            try
            {
                if (string.IsNullOrEmpty(email))
                    throw new ArgumentNullException("email is required.");

                var user = await _userManager.FindByEmailAsync(email);

                if (user == null)
                    throw new Exception("Enter valid email.");

                if (user.IsAzureADUser)
                {
                    throw new Exception("Please manage your password via Microsoft Azure");
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                if (token == null)
                    throw new Exception("User is not valid.");

                var commonElement = await _dbContext.CommonEmailElements.FirstOrDefaultAsync(x => x.CustomerId == user.CustomerId);
                if (commonElement != null)
                    user.Language = commonElement.Language;

                var portalUrl = _configuration.GetSection(Constants.PortalUrlKey).Value;
                var callbackUrl = GetResetPasswordEmailRoute(token, user.Email, portalUrl);
                var sendMailResult = await _emailTemplate.ResetPasswordEmailTemplate(user, callbackUrl);

                var sendMessageResult = await _messageService.SendEmailAsync(user.Email, sendMailResult.subject, sendMailResult.body);

                return new BaseResult
                {
                    Message = "Reset Password Email sent Successfully.",
                    ResponseStatusCode = System.Net.HttpStatusCode.OK
                };
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackException(ex);

                return new BaseResult
                {
                    Message = ex.Message,
                    Errors = new List<string> { ex.Message },
                    ResponseStatusCode = System.Net.HttpStatusCode.BadRequest
                };
            }
        }


        #endregion

        #region Change Password

        /// <summary>
        /// Change Password
        /// </summary>
        /// <param name="command"></param>
        /// <returns>Base Result</returns>
        [HttpPost]
        [Authorize(AuthenticationSchemes = "Bearer")]
        [Route("changepassword")]
        [PublicApi]
        public async Task<BaseResult> ChangePassword([FromBody] ChangePasswordModel command)
        {
            try
            {
                if (string.IsNullOrEmpty(command.NewPassword))
                    throw new ArgumentNullException("password is required.");

                if (string.IsNullOrEmpty(command.OldPassword))
                    throw new ArgumentNullException("old password is required.");

                var userId = GetUserByClaimType(ClaimTypes.NameIdentifier);

                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                    throw new InvalidOperationException();

                if (user.ForceChangePassword == true)
                {
                    user.ForceChangePassword = false;
                    user.EmailConfirmed = true;

                    await _userManager.UpdateAsync(user);
                }

                var changePasswordResult = await _userManager.ChangePasswordAsync(user, command.OldPassword, command.NewPassword);

                if (!changePasswordResult.Succeeded)
                    throw new Exception(changePasswordResult.Errors.First().Description);

                return new BaseResult
                {
                    Message = "Password Changed Successfully.",
                    ResponseStatusCode = System.Net.HttpStatusCode.OK
                };
            }
            catch (Exception ex)
            {
                _telemetryClient.TrackException(ex);

                return new BaseResult
                {
                    Message = ex.Message,
                    Errors = new List<string> { ex.Message },
                    ResponseStatusCode = System.Net.HttpStatusCode.BadRequest
                };
            }
        }


        private async Task<Token> GetToken(ApplicationUser user, RefreshToken refreshToken = null)
        {
            var userRoles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var platform = HttpContext.Request.Headers[ConstantsModel.HeaderKeyPlatform].FirstOrDefault();
            bool isMobileOrSmarty = new[] { ConstantsModel.Mobile, ConstantsModel.Smarty }.Contains(platform);
            var smartHubIndex = userRoles.IndexOf(UserRoles.SmartHubUser);
            if (smartHubIndex != -1 && isMobileOrSmarty)
            {
                var isLockerAdmin = await _dbContext.UserGroupRoleMappings.Where(x =>
                    x.Role.Name == UserRoles.LockerAdministrator && x.UserGroup.UserGroupUsers.Any(y => y.UserId == user.Id)
                ).AnyAsync();
                if (isLockerAdmin)
                {
                    userRoles[smartHubIndex] = UserRoles.LockerAdministrator;
                }
            }
            var listuserAccessRoles = (await Mediator.Send(new GetUserWiseRolesQuery(userRoles))).Result;

            var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id),
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Sid, user.SessionKey ?? "Default"),
                        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                     };

            if (!string.IsNullOrEmpty(user.CustomerId))
            {
                claims.Add(new Claim("CustomerId", user.CustomerId));
            }

            foreach (var item in listuserAccessRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, item.ToString()));
            }

            foreach (var role in userRoles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var jwt = new JwtSecurityToken(
                        issuer: _jwtOptions.Issuer,
                        audience: _jwtOptions.Audience,
                        claims: claims,
                        notBefore: _jwtOptions.NotBefore,
                        expires: _jwtOptions.Expiration,
                        signingCredentials: _jwtOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var newRefreshToken = (await Mediator.Send(new UpdateRefreshTokenCommand(refreshToken, user.UserName))).Result;

            return new Token
            {
                AccessToken = encodedJwt,
                RefreshToken = newRefreshToken.Refreshtoken,
                Expires = (int)_jwtOptions.ValidFor.TotalSeconds
            };

        }

        #endregion


    }
}
