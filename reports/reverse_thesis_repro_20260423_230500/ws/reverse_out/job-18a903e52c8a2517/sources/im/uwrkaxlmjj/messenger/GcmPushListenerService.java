package im.uwrkaxlmjj.messenger;

import android.os.SystemClock;
import android.util.Log;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import org.json.JSONException;

/* JADX INFO: loaded from: classes2.dex */
public class GcmPushListenerService extends FirebaseMessagingService {
    public static final int NOTIFICATION_ID = 1;
    private CountDownLatch countDownLatch = new CountDownLatch(1);

    @Override // com.google.firebase.messaging.FirebaseMessagingService
    public void onMessageReceived(RemoteMessage message) {
        String from = message.getFrom();
        final Map<String, String> data = message.getData();
        final long time = message.getSentTime();
        long receiveTime = SystemClock.uptimeMillis();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("GCM received data: " + data + " from: " + from);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$7dN5Gx2sMytHw4dl4ec70aVqy0s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onMessageReceived$3$GcmPushListenerService(data, time);
            }
        });
        try {
            this.countDownLatch.await();
        } catch (Throwable th) {
        }
        if (BuildVars.DEBUG_VERSION) {
            FileLog.d("finished GCM service, time = " + (SystemClock.uptimeMillis() - receiveTime));
        }
    }

    public /* synthetic */ void lambda$onMessageReceived$3$GcmPushListenerService(final Map data, final long time) {
        ApplicationLoader.postInitApplication();
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$pj1TDtG09RE9Z7c3uGnPgCaI4lY
            @Override // java.lang.Runnable
            public final void run() throws JSONException {
                this.f$0.lambda$null$2$GcmPushListenerService(data, time);
            }
        });
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0213  */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0216  */
    /* JADX WARN: Removed duplicated region for block: B:555:0x09ee  */
    /* JADX WARN: Removed duplicated region for block: B:752:0x1b1c A[Catch: all -> 0x1c6b, TryCatch #4 {all -> 0x1c6b, blocks: (B:759:0x1b7f, B:748:0x1b05, B:752:0x1b1c, B:754:0x1b32, B:763:0x1bb1, B:767:0x1bb8, B:769:0x1c08, B:771:0x1c18, B:773:0x1c47, B:775:0x1c4d), top: B:807:0x0214 }] */
    /* JADX WARN: Removed duplicated region for block: B:771:0x1c18 A[Catch: all -> 0x1c6b, TryCatch #4 {all -> 0x1c6b, blocks: (B:759:0x1b7f, B:748:0x1b05, B:752:0x1b1c, B:754:0x1b32, B:763:0x1bb1, B:767:0x1bb8, B:769:0x1c08, B:771:0x1c18, B:773:0x1c47, B:775:0x1c4d), top: B:807:0x0214 }] */
    /* JADX WARN: Removed duplicated region for block: B:793:0x1cae  */
    /* JADX WARN: Removed duplicated region for block: B:794:0x1cbe  */
    /* JADX WARN: Removed duplicated region for block: B:797:0x1cc5  */
    /* JADX WARN: Removed duplicated region for block: B:808:0x1a3f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r3v23, types: [int] */
    /* JADX WARN: Type inference failed for: r3v26 */
    /* JADX WARN: Type inference failed for: r3v42 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$null$2$GcmPushListenerService(java.util.Map r65, long r66) throws org.json.JSONException {
        /*
            Method dump skipped, instruction units count: 7992
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.GcmPushListenerService.lambda$null$2$GcmPushListenerService(java.util.Map, long):void");
    }

    static /* synthetic */ void lambda$null$1(int accountFinal) {
        if (UserConfig.getInstance(accountFinal).getClientUserId() != 0) {
            UserConfig.getInstance(accountFinal).clearConfig();
            MessagesController.getInstance(accountFinal).performLogout(0);
        }
    }

    private void onDecryptError() {
        for (int a = 0; a < 3; a++) {
            if (UserConfig.getInstance(a).isClientActivated()) {
                ConnectionsManager.onInternalPushReceived(a);
                ConnectionsManager.getInstance(a).resumeNetworkMaybe();
            }
        }
        this.countDownLatch.countDown();
    }

    @Override // com.google.firebase.messaging.FirebaseMessagingService
    public void onNewToken(final String token) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$zYOeFnz8LaoWnZuRRRam6z7V0fM
            @Override // java.lang.Runnable
            public final void run() {
                GcmPushListenerService.lambda$onNewToken$4(token);
            }
        });
    }

    static /* synthetic */ void lambda$onNewToken$4(String token) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("Refreshed token: " + token);
        }
        ApplicationLoader.postInitApplication();
        sendRegistrationToServer(token);
    }

    public static void sendRegistrationToServer(final String token) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$CCIPOoRBm-eWa5-qe2lbzNon3Uk
            @Override // java.lang.Runnable
            public final void run() {
                GcmPushListenerService.lambda$sendRegistrationToServer$6(token);
            }
        });
    }

    static /* synthetic */ void lambda$sendRegistrationToServer$6(final String token) {
        ConnectionsManager.setRegId(token, SharedConfig.pushStringStatus);
        if (token == null) {
            return;
        }
        SharedConfig.pushString = token;
        for (int a = 0; a < 3; a++) {
            UserConfig userConfig = UserConfig.getInstance(a);
            userConfig.registeredForPush = false;
            userConfig.saveConfig(false);
            if (userConfig.getClientUserId() != 0) {
                final int currentAccount = a;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$pdKMWf6ynS4F55Ss_zsTYSIMiiE
                    @Override // java.lang.Runnable
                    public final void run() {
                        MessagesController.getInstance(currentAccount).registerForPush(token);
                    }
                });
            }
        }
    }

    public static void sendUPushRegistrationToServer(final String token) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$mtaierXZXU_NAaUmHqkmvV5PbUs
            @Override // java.lang.Runnable
            public final void run() {
                GcmPushListenerService.lambda$sendUPushRegistrationToServer$8(token);
            }
        });
    }

    static /* synthetic */ void lambda$sendUPushRegistrationToServer$8(final String token) {
        if (token == null) {
            return;
        }
        for (int a = 0; a < 3; a++) {
            UserConfig userConfig = UserConfig.getInstance(a);
            userConfig.registeredForPush = false;
            if (userConfig.getClientUserId() != 0) {
                final int currentAccount = a;
                Log.d("youmeng", "sendUPushRegistrationToServer = " + token);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$GcmPushListenerService$qm3q9E1AbA6KMkLr7CnDF-MrlUw
                    @Override // java.lang.Runnable
                    public final void run() {
                        MessagesController.getInstance(currentAccount).registerForUPush(token);
                    }
                });
            }
        }
    }
}
