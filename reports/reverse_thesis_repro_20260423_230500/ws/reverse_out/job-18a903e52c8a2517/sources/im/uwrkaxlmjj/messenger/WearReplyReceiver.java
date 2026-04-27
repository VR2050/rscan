package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.core.app.RemoteInput;
import im.uwrkaxlmjj.tgnet.TLRPC;

/* JADX INFO: loaded from: classes2.dex */
public class WearReplyReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        ApplicationLoader.postInitApplication();
        Bundle remoteInput = RemoteInput.getResultsFromIntent(intent);
        if (remoteInput == null) {
            return;
        }
        final CharSequence text = remoteInput.getCharSequence(NotificationsController.EXTRA_VOICE_REPLY);
        if (!TextUtils.isEmpty(text)) {
            final long dialog_id = intent.getLongExtra("dialog_id", 0L);
            final int max_id = intent.getIntExtra("max_id", 0);
            int currentAccount = intent.getIntExtra("currentAccount", 0);
            if (dialog_id != 0 && max_id != 0) {
                final int lowerId = (int) dialog_id;
                final AccountInstance accountInstance = AccountInstance.getInstance(currentAccount);
                if (lowerId > 0) {
                    TLRPC.User user = accountInstance.getMessagesController().getUser(Integer.valueOf(lowerId));
                    if (user == null) {
                        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearReplyReceiver$sHQ9Zs50HDKLzUWBI8EiHiWbtlU
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$onReceive$1$WearReplyReceiver(accountInstance, lowerId, text, dialog_id, max_id);
                            }
                        });
                        return;
                    }
                } else if (lowerId < 0) {
                    TLRPC.Chat chat = accountInstance.getMessagesController().getChat(Integer.valueOf(-lowerId));
                    if (chat == null) {
                        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearReplyReceiver$GlvesYtirhpjcfy9Tupek7nKH0g
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$onReceive$3$WearReplyReceiver(accountInstance, lowerId, text, dialog_id, max_id);
                            }
                        });
                        return;
                    }
                }
                sendMessage(accountInstance, text, dialog_id, max_id);
            }
        }
    }

    public /* synthetic */ void lambda$onReceive$1$WearReplyReceiver(final AccountInstance accountInstance, int lowerId, final CharSequence text, final long dialog_id, final int max_id) {
        final TLRPC.User user1 = accountInstance.getMessagesStorage().getUserSync(lowerId);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearReplyReceiver$5C4n39APdDGoVgXiWut61fgfXvc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$WearReplyReceiver(accountInstance, user1, text, dialog_id, max_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$WearReplyReceiver(AccountInstance accountInstance, TLRPC.User user1, CharSequence text, long dialog_id, int max_id) {
        accountInstance.getMessagesController().putUser(user1, true);
        sendMessage(accountInstance, text, dialog_id, max_id);
    }

    public /* synthetic */ void lambda$onReceive$3$WearReplyReceiver(final AccountInstance accountInstance, int lowerId, final CharSequence text, final long dialog_id, final int max_id) {
        final TLRPC.Chat chat1 = accountInstance.getMessagesStorage().getChatSync(-lowerId);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearReplyReceiver$2E58ekZ31Jbf9Vx6U68S5a3QtW4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$WearReplyReceiver(accountInstance, chat1, text, dialog_id, max_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$WearReplyReceiver(AccountInstance accountInstance, TLRPC.Chat chat1, CharSequence text, long dialog_id, int max_id) {
        accountInstance.getMessagesController().putChat(chat1, true);
        sendMessage(accountInstance, text, dialog_id, max_id);
    }

    private void sendMessage(AccountInstance accountInstance, CharSequence text, long dialog_id, int max_id) {
        accountInstance.getSendMessagesHelper().sendMessage(text.toString(), dialog_id, null, null, true, null, null, null, true, 0);
        accountInstance.getMessagesController().markDialogAsRead(dialog_id, max_id, max_id, 0, false, 0, true, 0);
    }
}
