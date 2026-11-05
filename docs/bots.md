# Channel bots and QR login

## Bot setup

1. Create a bot with **BotFather** and copy its token directly into **Salvage Cloud → Settings → Channel upload bots**. Do not send it in chat, tickets, screenshots, or logs.
2. Add the bot to each target channel or group and grant it administrator access with permission to post files.
3. Open the destination channel in Drive, then open **Upload files** and select the bot under **Upload identity**. Leave **Personal account** selected to publish as the normal user session.

Bot tokens and their MTProto sessions are encrypted with the server session key and stored only in the owning account's workspace. Token values are never returned by the list API or written to browser storage. Removing a bot deletes its Salvage Cloud records; revoking the token itself still requires BotFather.

Bots cannot publish to Saved Messages, cannot borrow another account's bot, and are checked for administrator rights before staging and again at publication. Permission checks use the official Bot API `getChatMember` endpoint; publication uses `sendDocument`. Publication is serialized per account and is not a rate-limit bypass. A bot losing admin rights stops future publication without changing existing files.

## Provisioning and rotation

Adding a bot resolves its public username and grants only posting rights in every current channel. New channels provision all existing bots automatically. **Sync access** repeats provisioning for an existing bot and is useful after creating channels outside Salvage Cloud or after changing channel permissions.

**Auto (least-loaded bot)** selects an eligible bot using the current in-flight load and a rotating starting offset. Manual selection remains available, and **Personal account** remains the default. Resumed uploads retain the bot selected when staging began, so a retry cannot silently change publication identity. This is a fairness mechanism, not a way to bypass Telegram flood waits or other limits.

## Active channel and rollover

Choose **Set active** on a channel card, then select **Active channel** as the upload destination. `SALVAGE_CHANNEL_PART_LIMIT` defaults to 500,000 file messages. When the active channel reaches that count, the next upload creates a new channel, provisions all bots, and makes it active. Existing files stay mapped to their original channels. An explicitly selected non-active channel never rolls over silently.

**Bot API uploads are limited to 50 MiB per file.** Larger files must use the personal account's Grammers/MTProto upload path. This limit is enforced before upload and cannot be bypassed by selecting multiple bots.

Plain and TDENC2 uploads retain the selected `bot_id` through resume state, so a resumed transfer cannot silently switch publication identities. Existing files remain visible through the owning user's normal channel history.

## QR login

Choose **Use QR code instead** on the login page, then open Telegram on your phone and go to **Settings → Devices → Link Desktop Device**. Scan the generated code and approve the login in Telegram.

The backend handles login-token refresh and DC migration. The QR is rendered as a generated SVG, is not persisted in browser storage, and only an approved login issues the normal Secure, HttpOnly, SameSite=Strict web-session cookie. Use **Generate a new QR code** after expiry or **Use phone instead** to cancel polling.

Real-bot and real-QR acceptance require the user's own BotFather token, administrator channel, and phone approval. Controlled fixtures cover the application flow but do not prove those live Telegram boundaries.
