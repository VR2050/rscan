package im.uwrkaxlmjj.messenger;

import android.app.IntentService;
import android.content.Intent;

/* JADX INFO: loaded from: classes2.dex */
public class NotificationRepeat extends IntentService {
    public NotificationRepeat() {
        super("NotificationRepeat");
    }

    @Override // android.app.IntentService
    protected void onHandleIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        final int currentAccount = intent.getIntExtra("currentAccount", UserConfig.selectedAccount);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.NotificationRepeat.1
            @Override // java.lang.Runnable
            public void run() {
                NotificationsController.getInstance(currentAccount).repeatNotificationMaybe();
            }
        });
    }
}
