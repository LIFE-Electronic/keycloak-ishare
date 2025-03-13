<#import "template.ftl" as layout>

<head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
</head>

<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "form">
        <div class="kc-form" id="kc-form">
          <div id="kc-form-wrapper" class="kc-form-wrapper">
            <img class="dmi-logo" src="${url.resourcesPath}/img/dmi-logo.png" alt="DMI Logo">
            <h2>
                Inloggen
            </h2>
            <#if realm.password>
                <form class="kc-form-login" id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                    <#if !usernameHidden??>
                        <div class="form-group">
                            <div class="input-container">
                                <span class="before-box">
                                    <i class="fa-regular fa-user"></i>
                                </span>
                                <input tabindex="2" id="username"  name="username" value="${(login.username!'')}"  type="text" autofocus
                                    aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                                    autocomplete="off"
                                    class="<#if messagesPerField.existsError('username','password')>errorInput</#if>"
                                    placeholder="<#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>"
                                />
                                <span class="before-box" />
                            </div>

                            <#if messagesPerField.existsError('username','password')>
                                <span id="input-error" class="errorMessage" aria-live="polite">
                                        ${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}
                                </span>
                            </#if>

                        </div>
                    </#if>

                    <div class="${properties.kcFormGroupClass!}">
                        <div class="password-container">
                            <div class="input-container">
                                <span class="before-box">
                                    <i class="fa fa-key"></i>
                                </span>

                                <input tabindex="3" id="password" class="${properties.kcInputClass!}" name="password" type="password" autocomplete="current-password"
                                    aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                                    placeholder="${msg("password")}"
                                />

                                <span class="before-box">
                                    <button class="password-visibility-button" type="button" aria-label="${msg("showPassword")}"
                                    aria-controls="password" data-password-toggle tabindex="4"
                                    data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}" data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                    data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                                        <i class="fa fa-eye" aria-hidden="true"></i>
                                    </button>
                                </span>
                            </div>
                        </div>

                        <#if usernameHidden?? && messagesPerField.existsError('username','password')>
                            <span id="input-error" class="errorMessage" aria-live="polite">
                                    ${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}
                            </span>
                        </#if>

                    </div>

                    <div class="form-settings">
                        <div id="kc-form-options">
                            <#if realm.rememberMe && !usernameHidden??>
                                <div class="checkbox">
                                    <label class="remember-me-label">
                                        <#if login.rememberMe??>
                                              <div class="check-container">
                                                <input tabindex="5" id="rememberMe" name="rememberMe" type="checkbox" checked>
                                                <i class="fa-solid fa-check checkmark"></i>
                                            </div>
                                            Onthoud mij
                                             

                                        <#else>
                                            <div class="check-container">
                                                <input tabindex="5" id="rememberMe" name="rememberMe" type="checkbox">
                                                <i class="fa-solid fa-check checkmark"></i>
                                            </div>
                                            
                                            <div>
                                                Onthoud mij
                                            </div>
                                        </#if>
                                    </label>
                                </div>
                            </#if>
                            </div>
                            <div class="${properties.kcFormOptionsWrapperClass!}">
                                <#if realm.resetPasswordAllowed>
                                    <span><a tabindex="6" href="${url.loginResetCredentialsUrl}">Wachtwoord vergeten?</a></span>
                                </#if>
                            </div>

                      </div>

                      <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                          <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                          <input tabindex="7" class="button" name="login" id="kc-login" type="submit" value="Login"/>
                      </div>
                </form>
                <div class="user-conditions-link-container">
                    <a class="user-conditions-link" href="https://dmi-ecosysteem.nl/wp-content/uploads/bb_documents/2024/11/2023.06.01-DMI-Afsprakenstelsel-v1.1-schoon-1.pdf" target="_blank">Gebruikers voorwaarden</a>
                </div>
            </#if>
            </div>
        </div>
        <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
    <#elseif section = "info" >
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration-container">
                <div id="kc-registration">
                    <span>${msg("noAccount")} <a tabindex="8"
                                                 href="${url.registrationUrl}">${msg("doRegister")}</a></span>
                </div>
            </div>
        </#if>
    <#elseif section = "socialProviders" >
        <#if realm.password && social.providers??>
            <div id="kc-social-providers" class="${properties.kcFormSocialAccountSectionClass!}">
                <hr/>
                <h2>${msg("identity-provider-login-label")}</h2>

                <ul class="${properties.kcFormSocialAccountListClass!} <#if social.providers?size gt 3>${properties.kcFormSocialAccountListGridClass!}</#if>">
                    <#list social.providers as p>
                        <li>
                            <a id="social-${p.alias}" class="${properties.kcFormSocialAccountListButtonClass!} <#if social.providers?size gt 3>${properties.kcFormSocialAccountGridItem!}</#if>"
                                    type="button" href="${p.loginUrl}">
                                <#if p.iconClasses?has_content>
                                    <i class="${properties.kcCommonLogoIdP!} ${p.iconClasses!}" aria-hidden="true"></i>
                                    <span class="${properties.kcFormSocialAccountNameClass!} kc-social-icon-text">${p.displayName!}</span>
                                <#else>
                                    <span class="${properties.kcFormSocialAccountNameClass!}">${p.displayName!}</span>
                                </#if>
                            </a>
                        </li>
                    </#list>
                </ul>
            </div>
        </#if>
    </#if>

</@layout.registrationLayout>
