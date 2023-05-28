using System.Security.Claims;
using System;
using System.Data;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Dapper;
using Serilog;
using IdentityModel;

namespace IdentityServer.Pages.Register;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;
    private readonly IDbConnection _db;

    public ViewModel View { get; set; }
        
    [BindProperty]
    public InputModel Input { get; set; }
        
    public Index(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events,
        IDbConnection db,
        TestUserStore users = null)
    {
        // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
        _db = db;
        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _identityProviderStore = identityProviderStore;
        _events = events;
    }

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        await BuildModelAsync(returnUrl);
            
        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }

    async Task<UserDto> FindUserByLogin() => await FindUserByLoginOrDefault() ?? throw new NullReferenceException();
    #nullable enable
    
    
    async Task<UserDto?> FindUserByLoginOrDefault()
    {
        var user = await _db.QueryFirstOrDefaultAsync<UserDto>("SELECT * FROM [users] WHERE Login = @Login", new {
            Login = Input.Username
        });
        return user;
    }

    async Task<bool> UserIsExist()
    {
        var user = await FindUserByLoginOrDefault();
        return user is not null;
    }

    async Task<IActionResult?> GetCancellButtonResultOrDefault(AuthorizationRequest context)
    {
        var isCancellButton = Input.Button != "register";
        

        // since we don't have a valid context, then we just go back to the home page
        if (isCancellButton && context == null)
            return Redirect("~/");

        // if the user cancels, send a result back into IdentityServer as if they 
        // denied the consent (even if this client does not require consent).
        // this will send back an access denied OIDC error response to the client.
        if(isCancellButton)
            await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
        var isNativeClient = context?.IsNativeClient() ?? false;

        // The client is native, so this change in how to
        // return the response is for better UX for the end user.
        if(isCancellButton && isNativeClient)
            return this.LoadingPage(Input.ReturnUrl);

        if(isCancellButton && !isNativeClient)
            return Redirect(Input.ReturnUrl);

        return null;
    }

    bool InputModelPasswordsAreEquals() => Input.Password == Input.RepeatPassword;

    async Task BuildErrorModelAndRaiseFailureEvent(AuthorizationRequest context)
    {
        if(!InputModelPasswordsAreEquals())
            ModelState.AddModelError(nameof(InputModel.Password), "passwords are not equal");

        if(await UserIsExist())
            ModelState.AddModelError(string.Empty, "user is exists");

        if(ModelState.IsValid)
            return;
        
        await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, "invalid credentials", clientId:context?.Client.ClientId));
                                
        await BuildModelAsync(Input.ReturnUrl);
        
    }

    async Task SignIn(UserDto user)
    {
        // only set explicit expiration here if user chooses "remember me". 
        // otherwise we rely upon expiration configured in cookie middleware.
        AuthenticationProperties? props = null;
        if (LoginOptions.AllowRememberLogin && Input.RememberLogin)
            props = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.Add(LoginOptions.RememberMeLoginDuration)
            };

        // issue authentication cookie with subject ID and username
        var isuser = new IdentityServerUser(user.Id.ToString())
        {
            DisplayName = user.Login
        };
        isuser.AdditionalClaims = new List<Claim>() {
            new Claim(JwtClaimTypes.Name, user.Login),
            new Claim(JwtClaimTypes.Subject, user.Id.ToString()),
        };
        await HttpContext.SignInAsync(isuser, props);
    }
    #nullable disable

    IActionResult GetSignInResult(AuthorizationRequest context)
    {
        // The client is native, so this change in how to
        // return the response is for better UX for the end user.
        if (context != null && context.IsNativeClient())
            return this.LoadingPage(Input.ReturnUrl);

        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
        if(context != null && !context.IsNativeClient())
            return Redirect(Input.ReturnUrl);


        // request for a local page
        if (Url.IsLocalUrl(Input.ReturnUrl))
            return Redirect(Input.ReturnUrl);

        if (string.IsNullOrEmpty(Input.ReturnUrl))
            return Redirect("~/");
        
        // user might have clicked on a malicious link - should be logged
        throw new Exception("invalid return URL");
    }
    async Task CreateUser()
    {
        
        var res = await _db.ExecuteAsync("INSERT INTO [users] (Login, PasswordHash) VALUES(@Login, @PasswordHash)", new {
            PasswordHash = Input.Password,
            Login = Input.Username
        });
        
    }

    public async Task<IActionResult> OnPost()
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);

        var cancellButtonClickResult = await GetCancellButtonResultOrDefault(context);
        //clicked button is cancell button
        if(cancellButtonClickResult is not null)
            return cancellButtonClickResult;


            
        
        
        await BuildErrorModelAndRaiseFailureEvent(context);
        if(!ModelState.IsValid)
            return Page();

        await CreateUser();
        var userIdDb = await FindUserByLogin(); 
        await SignIn(userIdDb);

        await _events.RaiseAsync(new UserLoginSuccessEvent(userIdDb.Login, userIdDb.Id.ToString(), userIdDb.Login, clientId: context?.Client.ClientId));
        
        return GetSignInResult(context);
        
    }
        
    private async Task BuildModelAsync(string returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };
            
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            View = new ViewModel
            {
                EnableLocalRegister = local,
            };

            Input.Username = context?.LoginHint;

            if (!local)
            {
                View.ExternalProviders = new[] { new ViewModel.ExternalProvider { AuthenticationScheme = context.IdP } };
            }

            return;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name
            }).ToList();

        var dyanmicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            {
                AuthenticationScheme = x.Scheme,
                DisplayName = x.DisplayName
            });
        providers.AddRange(dyanmicSchemes);


        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalRegister = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }


}