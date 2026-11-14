# CashPilot Android companion

A small native Android client that imports only explicitly selected, locally parsed transaction alerts. It uses `NotificationListenerService`; it never requests SMS or phone permissions.

## Open and run

Open this directory in Android Studio (JDK 17 and Android SDK platform 35 required), let Gradle sync, then run the `app` configuration on a device with Android 8.0 (API 26) or later. No APK is included.

The default API base is `https://cashpilot-gs-e14e.vercel.app`. To use a development server, edit the base URL in the app. HTTPS is supported; cleartext HTTP is restricted by the client to `localhost`, `127.0.0.1`, and Android emulator host `10.0.2.2`.

## Pair and enable notifications

1. Sign in to CashPilot in the web app and create an Android pairing code.
2. Enter the 16-character code in the companion and pair. The bearer token is stored encrypted with AES/GCM using a key held in Android Keystore.
3. Tap **Notification access settings** and explicitly enable CashPilot in Android Settings. This permission can expose notification contents to the app.
4. Allow notifications from the intended bank/payment source apps to arrive. The app records only each observed source's package name and display name. Select only trusted sources in the list.
5. Turn on **Auto-import** only when ready. It defaults off. Text is considered only when both auto-import and that source's checkbox are enabled.

Parsing is deterministic and local. A clear INR debit/credit is accepted only when its transaction amount can be distinguished from any balance amount. OTPs, failed/pending alerts, unclear or ambiguous alerts, and unknown formats are skipped. The app does not retain or log notification text, account numbers, OTPs, balances, or credentials.

Only normalized transaction fields are placed in an AES-GCM encrypted, Android Keystore-backed local queue. WorkManager retries uploads when a network is available; queued events are removed only after the server accepts them. The queue contains no raw notification text. **Disconnect** revokes the paired device, removes the encrypted token, and clears the local queue. Disabling auto-import stops processing new alerts; Android notification access can also be revoked in system settings.

The parser cannot guarantee every bank's notification format. Unrecognized or combined notifications are deliberately skipped rather than guessed. Test the specific bank/payment app notifications on a real Android device before relying on imported transactions.