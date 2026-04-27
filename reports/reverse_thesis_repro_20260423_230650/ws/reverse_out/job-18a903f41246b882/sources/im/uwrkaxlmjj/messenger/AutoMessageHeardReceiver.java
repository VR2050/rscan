package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import im.uwrkaxlmjj.tgnet.TLRPC;

/* JADX INFO: loaded from: classes2.dex */
public class AutoMessageHeardReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        ApplicationLoader.postInitApplication();
        final long dialog_id = intent.getLongExtra("dialog_id", 0L);
        final int max_id = intent.getIntExtra("max_id", 0);
        final int currentAccount = intent.getIntExtra("currentAccount", 0);
        if (dialog_id == 0 || max_id == 0) {
            return;
        }
        final int lowerId = (int) dialog_id;
        final AccountInstance accountInstance = AccountInstance.getInstance(currentAccount);
        if (lowerId > 0) {
            TLRPC.User user = accountInstance.getMessagesController().getUser(Integer.valueOf(lowerId));
            if (user == null) {
                Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AutoMessageHeardReceiver$uH_ji44SasxkbHok8UkQmOgDil4
                    @Override // java.lang.Runnable
                    public final void run() {
                        AutoMessageHeardReceiver.lambda$onReceive$1(accountInstance, lowerId, currentAccount, dialog_id, max_id);
                    }
                });
                return;
            }
        } else if (lowerId < 0) {
            TLRPC.Chat chat = accountInstance.getMessagesController().getChat(Integer.valueOf(-lowerId));
            if (chat == null) {
                Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AutoMessageHeardReceiver$7Pp0-W9HDRi6c4-5H6G2QWyszzs
                    @Override // java.lang.Runnable
                    public final void run() {
                        AutoMessageHeardReceiver.lambda$onReceive$3(accountInstance, lowerId, currentAccount, dialog_id, max_id);
                    }
                });
                return;
            }
        }
        MessagesController.getInstance(currentAccount).markDialogAsRead(dialog_id, max_id, max_id, 0, false, 0, true, 0);
    }

    static /* synthetic */ void lambda$onReceive$1(final AccountInstance accountInstance, int lowerId, final int currentAccount, final long dialog_id, final int max_id) {
        final TLRPC.User user1 = accountInstance.getMessagesStorage().getUserSync(lowerId);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AutoMessageHeardReceiver$1cx0J5ufNYamf3nN1x9g8vy7z4o
            @Override // java.lang.Runnable
            public final void run() {
                AutoMessageHeardReceiver.lambda$null$0(accountInstance, user1, currentAccount, dialog_id, max_id);
            }
        });
    }

    static /* synthetic */ void lambda$null$0(AccountInstance accountInstance, TLRPC.User user1, int currentAccount, long dialog_id, int max_id) {
        accountInstance.getMessagesController().putUser(user1, true);
        MessagesController.getInstance(currentAccount).markDialogAsRead(dialog_id, max_id, max_id, 0, false, 0, true, 0);
    }

    static /* synthetic */ void lambda$onReceive$3(final AccountInstance accountInstance, int lowerId, final int currentAccount, final long dialog_id, final int max_id) {
        final TLRPC.Chat chat1 = accountInstance.getMessagesStorage().getChatSync(-lowerId);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$AutoMessageHeardReceiver$Nwhp9RQyGjSL4Ya8HWXhvaeYxDY
            @Override // java.lang.Runnable
            public final void run() {
                AutoMessageHeardReceiver.lambda$null$2(accountInstance, chat1, currentAccount, dialog_id, max_id);
            }
        });
    }

    static /* synthetic */ void lambda$null$2(AccountInstance accountInstance, TLRPC.Chat chat1, int currentAccount, long dialog_id, int max_id) {
        accountInstance.getMessagesController().putChat(chat1, true);
        MessagesController.getInstance(currentAccount).markDialogAsRead(dialog_id, max_id, max_id, 0, false, 0, true, 0);
    }
}
