use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::components::{Icon, IconName, Protected};
use crate::features::{BotSettings, VaultSettings};
use crate::state::{Density, Preferences, SessionState, Theme, ViewMode};

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! { <Protected><SettingsWorkspace/></Protected> }
}

#[component]
fn SettingsWorkspace() -> impl IntoView {
    let preferences = expect_context::<Preferences>();
    let session = expect_context::<SessionState>();

    view! {
        <div class="settings-page">
            <section class="settings-intro">
                <span class="eyebrow">"Make it yours"</span>
                <h2>"A drive that feels right."</h2>
                <p>"These choices affect only this browser. Your files and account settings stay unchanged."</p>
            </section>

            <div class="settings-layout">
                <div class="settings-main">
                    <BotSettings/>
                    <VaultSettings/>
                    <section class="settings-card" aria-labelledby="appearance-heading">
                        <div class="settings-card-heading">
                            <span class="settings-card-icon"><Icon icon=IconName::Sliders size=21/></span>
                            <div><h3 id="appearance-heading">"Appearance"</h3><p>"Choose a theme and a comfortable information density."</p></div>
                        </div>

                        <fieldset class="settings-fieldset">
                            <legend>"Color theme"</legend>
                            <div class="theme-options">
                                <ThemeOption value=Theme::System selected=move || preferences.value.get().theme == Theme::System label="System" description="Match your device" on_select=Callback::new(move |_| preferences.set_theme(Theme::System))/>
                                <ThemeOption value=Theme::Light selected=move || preferences.value.get().theme == Theme::Light label="Light" description="Bright and crisp" on_select=Callback::new(move |_| preferences.set_theme(Theme::Light))/>
                                <ThemeOption value=Theme::Dark selected=move || preferences.value.get().theme == Theme::Dark label="Dark" description="Easy on the eyes" on_select=Callback::new(move |_| preferences.set_theme(Theme::Dark))/>
                            </div>
                        </fieldset>

                        <div class="settings-control-row">
                            <div><label for="density">"Spacing"</label><p>"Adjust padding throughout your drive."</p></div>
                            <select id="density" on:change=move |event| {
                                let density = if event_target_value(&event) == "compact" { Density::Compact } else { Density::Comfortable };
                                preferences.set_density(density);
                            }>
                                <option value="comfortable" selected=move || preferences.value.get().density == Density::Comfortable>"Comfortable"</option>
                                <option value="compact" selected=move || preferences.value.get().density == Density::Compact>"Compact"</option>
                            </select>
                        </div>
                    </section>

                    <section class="settings-card" aria-labelledby="drive-view-heading">
                        <div class="settings-card-heading">
                            <span class="settings-card-icon"><Icon icon=IconName::Grid size=21/></span>
                            <div><h3 id="drive-view-heading">"Drive view"</h3><p>"Set the layout and details you see when browsing."</p></div>
                        </div>
                        <fieldset class="settings-fieldset">
                            <legend>"Default layout"</legend>
                            <div class="segmented-settings">
                                <label class=move || if preferences.value.get().view_mode == ViewMode::Grid { "is-selected" } else { "" }>
                                    <input type="radio" name="default-view" value="grid" checked=move || preferences.value.get().view_mode == ViewMode::Grid on:change=move |_| preferences.set_view_mode(ViewMode::Grid)/>
                                    <Icon icon=IconName::Grid size=18/>"Grid"
                                </label>
                                <label class=move || if preferences.value.get().view_mode == ViewMode::List { "is-selected" } else { "" }>
                                    <input type="radio" name="default-view" value="list" checked=move || preferences.value.get().view_mode == ViewMode::List on:change=move |_| preferences.set_view_mode(ViewMode::List)/>
                                    <Icon icon=IconName::List size=18/>"List"
                                </label>
                            </div>
                        </fieldset>
                        <label class="toggle-row">
                            <span><strong>"Show modified dates"</strong><small>"Include the last modified date beside each file size."</small></span>
                            <input class="switch" type="checkbox" role="switch" checked=move || preferences.value.get().show_file_details on:change=move |event| {
                                let checked = event.target().unwrap().unchecked_into::<web_sys::HtmlInputElement>().checked();
                                preferences.set_show_file_details(checked);
                            }/>
                        </label>
                    </section>
                </div>

                <aside class="settings-side" aria-label="Account and storage information">
                    <section class="settings-card account-settings-card">
                        <span class="settings-card-icon"><Icon icon=IconName::Shield size=21/></span>
                        <h3>"Signed in"</h3>
                        <p class="settings-account-name">{move || session.account().map(|account| account.display_name).unwrap_or_default()}</p>
                        <p>"Your authenticated session is held in memory. Signing out clears it from this tab."</p>
                        <button class="button button-secondary button-full" type="button" on:click=move |_| session.logout()><Icon icon=IconName::Logout size=18/>"Sign out"</button>
                    </section>
                    <section class="storage-notice">
                        <Icon icon=IconName::Lock size=18/>
                        <div><strong>"Preferences and encrypted containers"</strong><p>"Nonsecret preferences and plain-transfer metadata use local storage. Encrypted vault containers and name-free continuation journals use IndexedDB. Passphrases, keys, and plaintext are never persisted."</p></div>
                    </section>
                </aside>
            </div>
        </div>
    }
}

#[component]
fn ThemeOption(
    value: Theme,
    selected: impl Fn() -> bool + Clone + Send + Sync + 'static,
    label: &'static str,
    description: &'static str,
    on_select: Callback<()>,
) -> impl IntoView {
    let input_value = value.as_str();
    let input_name = format!("theme-{input_value}");
    let checked = selected.clone();
    view! {
        <label class=move || if selected() { "theme-option is-selected" } else { "theme-option" }>
            <input type="radio" name="color-theme" value=input_value checked=checked on:change=move |_| on_select.run(())/>
            <span class=format!("theme-preview theme-preview-{input_value}") aria-hidden="true"><i></i><b></b><em></em></span>
            <span><strong>{label}</strong><small>{description}</small></span>
            <span class="radio-indicator" id=input_name><Icon icon=IconName::Check size=13/></span>
        </label>
    }
}
