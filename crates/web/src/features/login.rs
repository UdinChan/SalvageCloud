use gloo_timers::future::TimeoutFuture;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;
use salvage_protocol::{LoginAttemptResponse, LoginOutcome, QrLoginAttemptResponse};

use crate::api;
use crate::components::{Brand, ErrorState, Icon, IconName, LoadingScreen, Spinner};
use crate::state::{SessionState, SessionStatus};

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginStep {
    Phone,
    Code,
    Password,
    Qr,
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let navigate = use_navigate();

    Effect::new(move |_| {
        if matches!(session.status.get(), SessionStatus::Authenticated(_)) {
            navigate("/drive", Default::default());
        }
    });

    view! {
        {move || match session.status.get() {
            SessionStatus::Loading | SessionStatus::Authenticated(_) => {
                view! { <LoadingScreen message="Opening Salvage Cloud"/> }.into_any()
            }
            SessionStatus::Error(message) => view! {
                <main id="main-content" class="standalone-page login-restore-error">
                    <div class="standalone-brand"><Brand/></div>
                    <ErrorState
                        title="We couldn’t check your session"
                        message=message
                        on_retry=Callback::new(move |_| session.restore_session())
                    />
                    <p class="standalone-help">"Your connection may be offline. Your saved browser preferences are unaffected."</p>
                </main>
            }.into_any(),
            SessionStatus::Anonymous => view! { <LoginExperience/> }.into_any(),
        }}
    }
}

#[component]
fn LoginExperience() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let step = RwSignal::new(LoginStep::Phone);
    let phone = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let password_visible = RwSignal::new(false);
    let attempt = RwSignal::new(Option::<LoginAttemptResponse>::None);
    let password_hint = RwSignal::new(Option::<String>::None);
    let pending = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);

    let submit_phone = move |_| {
        let value = phone.get_untracked().trim().to_owned();
        if value.is_empty() || pending.get_untracked() {
            return;
        }
        let generation = session.login_generation();
        pending.set(true);
        error.set(None);
        spawn_local(async move {
            let result = api::start_phone_login(&value).await;
            if session.login_generation() != generation {
                return;
            }
            pending.set(false);
            match result {
                Ok(login_attempt) => {
                    attempt.set(Some(login_attempt));
                    step.set(LoginStep::Code);
                }
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    };

    let submit_code = move |_| {
        let value = code.get_untracked().trim().to_owned();
        let Some(attempt_id) = attempt.get_untracked().map(|attempt| attempt.attempt_id) else {
            return;
        };
        if value.is_empty() || pending.get_untracked() {
            return;
        }
        let generation = session.login_generation();
        pending.set(true);
        error.set(None);
        code.set(String::new());
        spawn_local(async move {
            let result = api::verify_code(attempt_id, &value).await;
            if session.login_generation() != generation {
                return;
            }
            pending.set(false);
            match result {
                Ok(LoginOutcome::Authenticated {
                    session: authenticated,
                }) => {
                    session.authenticate(authenticated, generation);
                }
                Ok(LoginOutcome::PasswordRequired {
                    password_hint: hint,
                }) => {
                    password_hint.set(hint);
                    step.set(LoginStep::Password);
                }
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    };

    let submit_password = move |_| {
        let value = password.get_untracked();
        let Some(attempt_id) = attempt.get_untracked().map(|attempt| attempt.attempt_id) else {
            return;
        };
        if value.is_empty() || pending.get_untracked() {
            return;
        }
        let generation = session.login_generation();
        pending.set(true);
        error.set(None);
        password.set(String::new());
        spawn_local(async move {
            let result = api::verify_password(attempt_id, &value).await;
            if session.login_generation() != generation {
                return;
            }
            pending.set(false);
            match result {
                Ok(LoginOutcome::Authenticated {
                    session: authenticated,
                }) => {
                    session.authenticate(authenticated, generation);
                }
                Ok(LoginOutcome::PasswordRequired {
                    password_hint: hint,
                }) => {
                    password_hint.set(hint);
                    error.set(Some("Your cloud password is still required.".to_owned()));
                }
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    };

    let reset_to_phone = Callback::new(move |_| {
        if !pending.get_untracked() {
            step.set(LoginStep::Phone);
            code.set(String::new());
            password.set(String::new());
            error.set(None);
        }
    });

    view! {
        <main id="main-content" class="login-page">
            <section class="login-story" aria-label="About Salvage Cloud">
                <div class="login-story-top"><Brand/></div>
                <div class="story-content">
                    <span class="eyebrow eyebrow-light">"A calmer place for your files"</span>
                    <h1>"What matters,"<br/>"kept within reach."</h1>
                    <p>"Bring your Telegram-backed files into one focused, beautifully simple drive."</p>
                    <ul class="story-benefits">
                        <li><span><Icon icon=IconName::Folder size=19/></span><div><strong>"Find things faster"</strong><p>"Folders and search keep your drive organized."</p></div></li>
                        <li><span><Icon icon=IconName::Shield size=19/></span><div><strong>"Thoughtful session care"</strong><p>"Login secrets never enter local browser storage."</p></div></li>
                    </ul>
                </div>
                <div class="story-foot"><span class="status-dot"></span>"Salvage Cloud · Personal drive"</div>
                <div class="story-orb story-orb-one" aria-hidden="true"></div>
                <div class="story-orb story-orb-two" aria-hidden="true"></div>
            </section>

            <section class="login-workspace">
                <div class="login-mobile-brand"><Brand/></div>
                <div class="login-card">
                    {move || session.notice.get().map(|notice| view! {
                        <div class="inline-notice notice-warning" role="alert"><Icon icon=IconName::Alert size=18/><span>{notice}</span></div>
                    })}

                    <div class="login-progress" aria-label="Login progress">
                        <span class=move || match step.get() { LoginStep::Phone => "progress-step is-current", _ => "progress-step is-complete" }><i>"1"</i><b>"Phone"</b></span>
                        <span class="progress-line"></span>
                        <span class=move || match step.get() { LoginStep::Phone => "progress-step", LoginStep::Code => "progress-step is-current", LoginStep::Password => "progress-step is-complete", LoginStep::Qr => "progress-step" }><i>"2"</i><b>"Code"</b></span>
                        <span class="progress-line"></span>
                        <span class=move || if step.get() == LoginStep::Password { "progress-step is-current" } else { "progress-step" }><i>"3"</i><b>"Password"</b></span>
                    </div>

                    <Show when=move || step.get() == LoginStep::Phone>
                        <div class="login-heading">
                            <span class="eyebrow">"Welcome back"</span>
                            <h2>"Sign in to your drive"</h2>
                            <p>"Enter the phone number linked to your Telegram account. We’ll request a one-time login code."</p>
                        </div>
                        <p class="field-help hosted-consent">"This hosted service processes Telegram authentication and ordinary files on the server. Continue only if you consent to that processing."</p>
                        <form class="auth-form" on:submit=move |event| { event.prevent_default(); submit_phone(()); }>
                            <label for="phone">"Phone number"</label>
                            <div class="input-with-icon">
                                <span class="input-prefix" aria-hidden="true"><Icon icon=IconName::Cloud size=19/></span>
                                <input id="phone" name="phone" type="tel" autocomplete="tel" placeholder="+1 555 000 0000" required autofocus
                                    prop:value=move || phone.get()
                                    on:input=move |event| phone.set(event_target_value(&event))
                                />
                            </div>
                            <p class="field-help">"Include your country code. Standard Telegram login limits may apply."</p>
                            <FormError error=error/>
                            <button class="button button-primary button-full auth-submit" type="submit" disabled=move || pending.get()>
                                {move || if pending.get() { view! { <Spinner/> <span>"Requesting code…"</span> }.into_any() } else { view! { <span>"Continue securely"</span><Icon icon=IconName::ArrowRight size=19/> }.into_any() }}
                            </button>
                        </form>
                        <button class="button button-secondary button-full" type="button" disabled=move || pending.get() on:click=move |_| step.set(LoginStep::Qr)>
                            <Icon icon=IconName::Cloud size=18/>"Use QR code instead"
                        </button>
                    </Show>

                    <Show when=move || step.get() == LoginStep::Qr>
                        <QrLoginPanel session=session on_back=reset_to_phone/>
                    </Show>

                    <Show when=move || step.get() == LoginStep::Code>
                        <button class="back-button" type="button" disabled=move || pending.get() on:click=move |_| reset_to_phone.run(())><Icon icon=IconName::ArrowLeft size=17/>"Use another number"</button>
                        <div class="login-heading">
                            <span class="eyebrow">"One-time code"</span>
                            <h2>"Check your Telegram app"</h2>
                            <p>"Enter the login code sent to "<strong>{move || attempt.get().map(|attempt| attempt.phone_hint).unwrap_or_default()}</strong>"."</p>
                        </div>
                        <form class="auth-form" on:submit=move |event| { event.prevent_default(); submit_code(()); }>
                            <label for="login-code">"Login code"</label>
                            <input class="code-input" id="login-code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="•••••" required autofocus
                                prop:value=move || code.get()
                                on:input=move |event| code.set(event_target_value(&event))
                            />
                            <p class="field-help">{move || match attempt.get().and_then(|attempt| attempt.code_length) {
                                Some(length) => format!("Your code contains {length} digits. Never share it with anyone."),
                                None => "Never share this code with anyone.".to_owned(),
                            }}</p>
                            <FormError error=error/>
                            <button class="button button-primary button-full auth-submit" type="submit" disabled=move || pending.get()>
                                {move || if pending.get() { view! { <Spinner/> <span>"Checking code…"</span> }.into_any() } else { view! { <span>"Verify code"</span><Icon icon=IconName::ArrowRight size=19/> }.into_any() }}
                            </button>
                        </form>
                    </Show>

                    <Show when=move || step.get() == LoginStep::Password>
                        <div class="login-heading">
                            <span class="eyebrow">"Two-step verification"</span>
                            <h2>"Enter your cloud password"</h2>
                            <p>"This Telegram account has an extra password. It is used only for this login request."</p>
                        </div>
                        <form class="auth-form" on:submit=move |event| { event.prevent_default(); submit_password(()); }>
                            <label for="cloud-password">"Cloud password"</label>
                            <div class="password-input">
                                <input id="cloud-password" name="password" type=move || if password_visible.get() { "text" } else { "password" } autocomplete="current-password" placeholder="Your cloud password" required autofocus
                                    prop:value=move || password.get()
                                    on:input=move |event| password.set(event_target_value(&event))
                                />
                                <button class="icon-button" type="button" aria-label=move || if password_visible.get() { "Hide password" } else { "Show password" } on:click=move |_| password_visible.update(|visible| *visible = !*visible)>
                                    {move || if password_visible.get() { view! { <Icon icon=IconName::EyeOff/> }.into_any() } else { view! { <Icon icon=IconName::Eye/> }.into_any() }}
                                </button>
                            </div>
                            {move || password_hint.get().map(|hint| view! { <p class="field-help">"Password hint: "{hint}</p> })}
                            <FormError error=error/>
                            <button class="button button-primary button-full auth-submit" type="submit" disabled=move || pending.get()>
                                {move || if pending.get() { view! { <Spinner/> <span>"Unlocking your drive…"</span> }.into_any() } else { view! { <span>"Open my drive"</span><Icon icon=IconName::ArrowRight size=19/> }.into_any() }}
                            </button>
                        </form>
                    </Show>

                    <div class="login-security-note"><Icon icon=IconName::Lock size=15/><span>"Phone numbers, codes, passwords, and session tokens are kept in memory only."</span></div>
                </div>
                <footer class="login-footer">"Salvage Cloud" <span>"·"</span> "Your files, within reach."</footer>
            </section>
        </main>
    }
}

#[component]
fn QrLoginPanel(session: SessionState, on_back: Callback<()>) -> impl IntoView {
    let attempt = RwSignal::new(None::<QrLoginAttemptResponse>);
    let pending = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let generation = RwSignal::new(0_u64);
    let started = RwSignal::new(false);

    let start = Callback::new(move |_: ()| {
        if pending.get_untracked() {
            return;
        }
        let auth_generation = session.login_generation();
        let own_generation = generation.get_untracked().wrapping_add(1);
        generation.set(own_generation);
        pending.set(true);
        error.set(None);
        spawn_local(async move {
            match api::start_qr_login().await {
                Ok(login_attempt) => {
                    let attempt_id = login_attempt.attempt_id;
                    attempt.set(Some(login_attempt));
                    pending.set(false);
                    for _ in 0..150 {
                        TimeoutFuture::new(2_000).await;
                        if generation.get_untracked() != own_generation
                            || session.login_generation() != auth_generation
                        {
                            return;
                        }
                        match api::poll_qr_login(attempt_id).await {
                            Ok(poll) => {
                                if poll.complete {
                                    if let Some(authenticated) = poll.session {
                                        session.authenticate(authenticated, auth_generation);
                                    } else {
                                        error.set(Some(
                                            "Telegram did not return a complete login session."
                                                .to_string(),
                                        ));
                                    }
                                    return;
                                }
                                if let Some(qr_svg) = poll.qr_svg {
                                    attempt.update(|current| {
                                        if let Some(current) = current {
                                            current.qr_svg = qr_svg;
                                        }
                                    });
                                }
                            }
                            Err(api_error) => {
                                error.set(Some(api_error.message));
                                return;
                            }
                        }
                    }
                    error.set(Some(
                        "The QR login expired. Generate a new code.".to_string(),
                    ));
                }
                Err(api_error) => {
                    pending.set(false);
                    error.set(Some(api_error.message));
                }
            }
        });
    });

    Effect::new(move |_| {
        if !started.get_untracked() {
            started.set(true);
            start.run(());
        }
    });

    view! {
        <button class="back-button" type="button" on:click=move |_| {
            generation.update(|value| *value = value.wrapping_add(1));
            on_back.run(());
        }><Icon icon=IconName::ArrowLeft size=17/>"Use phone instead"</button>
        <div class="login-heading">
            <span class="eyebrow">"Telegram QR login"</span>
            <h2>"Scan with your Telegram app"</h2>
            <p>"Open Telegram on your phone, go to Settings → Devices → Link Desktop Device, and scan this code. Approval creates your normal secure web session."</p>
        </div>
        {move || attempt.get().map(|login_attempt| view! {
            <div class="qr-login-code" inner_html=login_attempt.qr_svg></div>
        })}
        {move || pending.get().then(|| view! { <div class="preview-loading" role="status"><Spinner size=22/><span>"Creating a secure QR login…"</span></div> })}
        <p class="field-help">"The code refreshes automatically. QR tokens are used only for this login attempt and are never saved in browser storage."</p>
        <FormError error=error/>
        <button class="button button-secondary button-full" type="button" disabled=move || pending.get() on:click=move |_| start.run(())>"Generate a new QR code"</button>
    }
}

#[component]
fn FormError(error: RwSignal<Option<String>>) -> impl IntoView {
    view! {
        {move || error.get().map(|message| view! {
            <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div>
        })}
    }
}
