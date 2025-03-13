<#macro logoutOtherSessions>
    <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
        <div class="logout-sessions">
            <div class="checkbox">
                <label class="logout-other-sessions-label">
                    <div class="check-container">
                        <input type="checkbox" id="logout-sessions" name="logout-sessions" value="on" checked>
                        <i class="fa-solid fa-check checkmark"></i>
                    </div>
                    ${msg("logoutOtherSessions")}
                </label>
            </div>
        </div>
    </div>
</#macro>
