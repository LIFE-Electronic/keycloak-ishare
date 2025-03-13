<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true displayMessage=!messagesPerField.existsError('username'); section>
    <div class="reset-password-container">
        <div class="reset-password-content">
            <#if section = "header">
                <img class="dmi-logo" src="${url.resourcesPath}/img/dmi-logo.png" alt="DMI Logo">
                <p class="reset-password-information">
                    Voer je gebruikersnaam of e-mailadres in. Je ontvangt een e-mailbericht met instructies hoe je je wachtwoord opnieuw kunt instellen.
                </p>
            <#elseif section = "form">
                <form id="kc-reset-password-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">

                    <div class="${properties.kcFormGroupClass!}">
                        <div class="${properties.kcInputWrapperClass!}">
                            <div class="input-container">
                                <span class="before-box"></span>

                                <input placeholder="Emailadres" type="text" id="username" name="username" class="${properties.kcInputClass!}" autofocus value="${(auth.attemptedUsername!'')}" aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"/>
                                                                <span class="before-box">

                            </div>
                            <#if messagesPerField.existsError('username')>
                                <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                            ${kcSanitize(messagesPerField.get('username'))?no_esc}
                                </span>
                            </#if>
                        </div>
                    </div>
                    <div class="form-actions-reset-password">
                        <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                            <input class="button" type="submit" value="Verzoek om reset link"/>
                        </div>
                        <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                            <div class="${properties.kcFormOptionsWrapperClass!}">
                                <span>
                                    <a class="back-to-login-link" href="${url.loginUrl}">
                                        Terug naar aanmelden
                                    </a>
                                </span>
                            </div>
                        </div>    
                    </div>
                </form>
            </#if>
        </div>
    </div>
</@layout.registrationLayout>
