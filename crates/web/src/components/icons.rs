use leptos::prelude::*;

#[derive(Clone, Copy)]
pub enum IconName {
    Alert,
    ArrowLeft,
    ArrowRight,
    Check,
    ChevronRight,
    Clock,
    Close,
    Cloud,
    Copy,
    Document,
    Download,
    Eye,
    EyeOff,
    File,
    Folder,
    Grid,
    Image,
    List,
    Lock,
    Logout,
    Menu,
    Pencil,
    Plus,
    Refresh,
    Search,
    Settings,
    Share,
    Shield,
    Sliders,
    Trash,
    Transfer,
    Upload,
    Video,
}

#[component]
pub fn Icon(icon: IconName, #[prop(default = 20)] size: u16) -> impl IntoView {
    let contents = match icon {
        IconName::Alert => view! {
            <path d="M10.3 3.7 2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.7a2 2 0 0 0-3.4 0Z"/>
            <path d="M12 9v4m0 4h.01"/>
        }.into_any(),
        IconName::ArrowLeft => view! { <path d="m15 18-6-6 6-6m-6 6h12"/> }.into_any(),
        IconName::ArrowRight => view! { <path d="m9 18 6-6-6-6m6 6H3"/> }.into_any(),
        IconName::Check => view! { <path d="m5 12 4 4L19 6"/> }.into_any(),
        IconName::ChevronRight => view! { <path d="m9 18 6-6-6-6"/> }.into_any(),
        IconName::Clock => view! { <circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/> }.into_any(),
        IconName::Close => view! { <path d="m6 6 12 12M18 6 6 18"/> }.into_any(),
        IconName::Cloud => view! { <path d="M6.5 18h11a4.5 4.5 0 0 0 .7-8.9A6.5 6.5 0 0 0 5.8 7.5 5.3 5.3 0 0 0 6.5 18Z"/> }.into_any(),
        IconName::Copy => view! { <rect x="8" y="8" width="12" height="13" rx="2"/><path d="M15 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h3"/> }.into_any(),
        IconName::Document => view! { <path d="M6 2h8l4 4v16H6z"/><path d="M14 2v5h5M9 12h6m-6 4h6"/> }.into_any(),
        IconName::Download => view! { <path d="M12 3v12m-5-5 5 5 5-5M4 18v3h16v-3"/> }.into_any(),
        IconName::Eye => view! { <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="2.5"/> }.into_any(),
        IconName::EyeOff => view! { <path d="m3 3 18 18M10.6 6.1A10.8 10.8 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-3.2 3.8M6.2 6.2C3.4 8.1 2 12 2 12s3.5 6 10 6c1.6 0 3-.4 4.2-1M9.9 9.9a3 3 0 0 0 4.2 4.2"/> }.into_any(),
        IconName::File => view! { <path d="M6 2h8l4 4v16H6z"/><path d="M14 2v5h5"/> }.into_any(),
        IconName::Folder => view! { <path d="M3 6a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/> }.into_any(),
        IconName::Grid => view! { <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/> }.into_any(),
        IconName::Image => view! { <rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/> }.into_any(),
        IconName::List => view! { <path d="M9 6h12M9 12h12M9 18h12M4 6h.01M4 12h.01M4 18h.01"/> }.into_any(),
        IconName::Lock => view! { <rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/> }.into_any(),
        IconName::Logout => view! { <path d="M10 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5m5-4 4-4-4-4m4 4H9"/> }.into_any(),
        IconName::Menu => view! { <path d="M4 6h16M4 12h16M4 18h16"/> }.into_any(),
        IconName::Pencil => view! { <path d="m14 5 5 5M4 20l4.5-1 11-11a2.1 2.1 0 0 0-3-3l-11 11zM13 20h8"/> }.into_any(),
        IconName::Plus => view! { <path d="M12 5v14M5 12h14"/> }.into_any(),
        IconName::Refresh => view! { <path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 8a7 7 0 0 1 11.8-1L20 12M4 12l2.1 5a7 7 0 0 0 11.8-1"/> }.into_any(),
        IconName::Search => view! { <circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/> }.into_any(),
        IconName::Settings => view! { <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/> }.into_any(),
        IconName::Share => view! { <circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.7 10.7 6.6-4.2m-6.6 6.8 6.6 4.2"/> }.into_any(),
        IconName::Shield => view! { <path d="M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6z"/><path d="m8.5 12 2.2 2.2 4.8-5"/> }.into_any(),
        IconName::Sliders => view! { <path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2" fill="currentColor" stroke="none"/><circle cx="16" cy="12" r="2" fill="currentColor" stroke="none"/><circle cx="10" cy="18" r="2" fill="currentColor" stroke="none"/> }.into_any(),
        IconName::Trash => view! { <path d="M4 7h16M9 3h6l1 4H8zM6 7l1 14h10l1-14M10 11v6m4-6v6"/> }.into_any(),
        IconName::Transfer => view! { <path d="m7 7-4 4 4 4m-4-4h14m0 6-4-4m4 4-4 4m4-4H7"/> }.into_any(),
        IconName::Upload => view! { <path d="M12 16V4m-5 5 5-5 5 5M4 17v4h16v-4"/> }.into_any(),
        IconName::Video => view! { <rect x="3" y="5" width="13" height="14" rx="2"/><path d="m16 10 5-3v10l-5-3"/> }.into_any(),
    };

    view! {
        <svg
            class="icon"
            width=size
            height=size
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
            focusable="false"
        >
            {contents}
        </svg>
    }
}
