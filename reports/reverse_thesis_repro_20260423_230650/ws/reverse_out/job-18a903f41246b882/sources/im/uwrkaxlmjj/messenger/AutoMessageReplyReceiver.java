package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.core.app.RemoteInput;

/* JADX INFO: loaded from: classes2.dex */
public class AutoMessageReplyReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        CharSequence text;
        ApplicationLoader.postInitApplication();
        Bundle remoteInput = RemoteInput.getResultsFromIntent(intent);
        if (remoteInput != null && (text = remoteInput.getCharSequence(NotificationsController.EXTRA_VOICE_REPLY)) != null && text.length() != 0) {
            long dialog_id = intent.getLongExtra("dialog_id", 0L);
            int max_id = intent.getIntExtra("max_id", 0);
            int currentAccount = intent.getIntExtra("currentAccount", 0);
            if (dialog_id == 0 || max_id == 0) {
                return;
            }
            SendMessagesHelper.getInstance(currentAccount).sendMessage(text.toString(), dialog_id, null, null, true, null, null, null, true, 0);
            MessagesController.getInstance(currentAccount).markDialogAsRead(dialog_id, max_id, max_id, 0, false, 0, true, 0);
        }
    }
}
