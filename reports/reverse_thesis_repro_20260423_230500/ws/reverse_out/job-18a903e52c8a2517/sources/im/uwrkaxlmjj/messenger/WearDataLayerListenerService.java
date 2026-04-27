package im.uwrkaxlmjj.messenger;

import android.text.TextUtils;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.wearable.CapabilityInfo;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.MessageClient;
import com.google.android.gms.wearable.MessageEvent;
import com.google.android.gms.wearable.Node;
import com.google.android.gms.wearable.Wearable;
import com.google.android.gms.wearable.WearableListenerService;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes2.dex */
public class WearDataLayerListenerService extends WearableListenerService {
    private static boolean watchConnected;
    private int currentAccount = UserConfig.selectedAccount;

    @Override // com.google.android.gms.wearable.WearableListenerService, android.app.Service
    public void onCreate() {
        super.onCreate();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("WearableDataLayer service created");
        }
    }

    @Override // com.google.android.gms.wearable.WearableListenerService, android.app.Service
    public void onDestroy() {
        super.onDestroy();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("WearableDataLayer service destroyed");
        }
    }

    @Override // com.google.android.gms.wearable.WearableListenerService, com.google.android.gms.wearable.ChannelApi.ChannelListener
    public void onChannelOpened(Channel ch) {
        GoogleApiClient apiClient = new GoogleApiClient.Builder(this).addApi(Wearable.API).build();
        if (!apiClient.blockingConnect().isSuccess()) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("failed to connect google api client");
                return;
            }
            return;
        }
        String path = ch.getPath();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("wear channel path: " + path);
        }
        try {
            if ("/getCurrentUser".equals(path)) {
                DataOutputStream out = new DataOutputStream(new BufferedOutputStream(((Channel.GetOutputStreamResult) ch.getOutputStream(apiClient).await()).getOutputStream()));
                if (UserConfig.getInstance(this.currentAccount).isClientActivated()) {
                    final TLRPC.User user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                    out.writeInt(user.id);
                    out.writeUTF(user.first_name);
                    out.writeUTF(user.last_name);
                    out.writeUTF(user.phone);
                    if (user.photo != null) {
                        final File photo = FileLoader.getPathToAttach(user.photo.photo_small, true);
                        final CyclicBarrier barrier = new CyclicBarrier(2);
                        if (!photo.exists()) {
                            final NotificationCenter.NotificationCenterDelegate listener = new NotificationCenter.NotificationCenterDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$xDNv5Hht9sz17wk55CubgPPkUok
                                @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
                                public final void didReceivedNotification(int i, int i2, Object[] objArr) {
                                    WearDataLayerListenerService.lambda$onChannelOpened$0(photo, barrier, i, i2, objArr);
                                }
                            };
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$ya9ZOuuE0rQ5a6xb4MH57XMykug
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onChannelOpened$1$WearDataLayerListenerService(listener, user);
                                }
                            });
                            try {
                                barrier.await(10L, TimeUnit.SECONDS);
                            } catch (Exception e) {
                            }
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$cThQgyCsoAFS62brL5bo6g3CvS0
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onChannelOpened$2$WearDataLayerListenerService(listener);
                                }
                            });
                        }
                        if (photo.exists() && photo.length() <= 52428800) {
                            byte[] photoData = new byte[(int) photo.length()];
                            FileInputStream photoIn = new FileInputStream(photo);
                            new DataInputStream(photoIn).readFully(photoData);
                            photoIn.close();
                            out.writeInt(photoData.length);
                            out.write(photoData);
                        } else {
                            out.writeInt(0);
                        }
                    } else {
                        out.writeInt(0);
                    }
                } else {
                    out.writeInt(0);
                }
                out.flush();
                out.close();
            } else if ("/waitForAuthCode".equals(path)) {
                ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
                final String[] code = {null};
                final CyclicBarrier barrier2 = new CyclicBarrier(2);
                final NotificationCenter.NotificationCenterDelegate listener2 = new NotificationCenter.NotificationCenterDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$bdr25mUDSnAUnJD4gJSItIhP3pU
                    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
                    public final void didReceivedNotification(int i, int i2, Object[] objArr) {
                        WearDataLayerListenerService.lambda$onChannelOpened$3(code, barrier2, i, i2, objArr);
                    }
                };
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$a7GofazKMS6sEgyAb7wHjHk-eJI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onChannelOpened$4$WearDataLayerListenerService(listener2);
                    }
                });
                try {
                    barrier2.await(30L, TimeUnit.SECONDS);
                } catch (Exception e2) {
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$rEyYq4d7pZ3e5_mjBodkTPswkm8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onChannelOpened$5$WearDataLayerListenerService(listener2);
                    }
                });
                DataOutputStream out2 = new DataOutputStream(((Channel.GetOutputStreamResult) ch.getOutputStream(apiClient).await()).getOutputStream());
                if (code[0] != null) {
                    out2.writeUTF(code[0]);
                } else {
                    out2.writeUTF("");
                }
                out2.flush();
                out2.close();
                ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
            } else if ("/getChatPhoto".equals(path)) {
                try {
                    DataInputStream in = new DataInputStream(((Channel.GetInputStreamResult) ch.getInputStream(apiClient).await()).getInputStream());
                    try {
                        DataOutputStream out3 = new DataOutputStream(((Channel.GetOutputStreamResult) ch.getOutputStream(apiClient).await()).getOutputStream());
                        try {
                            String _req = in.readUTF();
                            JSONObject req = new JSONObject(_req);
                            int chatID = req.getInt("chat_id");
                            int accountID = req.getInt("account_id");
                            int currentAccount = -1;
                            int i = 0;
                            while (true) {
                                if (i >= UserConfig.getActivatedAccountsCount()) {
                                    break;
                                }
                                if (UserConfig.getInstance(i).getClientUserId() != accountID) {
                                    i++;
                                } else {
                                    currentAccount = i;
                                    break;
                                }
                            }
                            if (currentAccount != -1) {
                                TLRPC.FileLocation location = null;
                                if (chatID > 0) {
                                    TLRPC.User user2 = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(chatID));
                                    if (user2 != null && user2.photo != null) {
                                        location = user2.photo.photo_small;
                                    }
                                } else {
                                    TLRPC.Chat chat = MessagesController.getInstance(currentAccount).getChat(Integer.valueOf(-chatID));
                                    if (chat != null && chat.photo != null) {
                                        location = chat.photo.photo_small;
                                    }
                                }
                                if (location != null) {
                                    File file = FileLoader.getPathToAttach(location, true);
                                    if (file.exists() && file.length() < 102400) {
                                        out3.writeInt((int) file.length());
                                        FileInputStream fin = new FileInputStream(file);
                                        byte[] buf = new byte[10240];
                                        while (true) {
                                            int read = fin.read(buf);
                                            if (read <= 0) {
                                                break;
                                            }
                                            out3.write(buf, 0, read);
                                            _req = _req;
                                        }
                                        fin.close();
                                    } else {
                                        out3.writeInt(0);
                                    }
                                } else {
                                    out3.writeInt(0);
                                }
                            } else {
                                out3.writeInt(0);
                            }
                            out3.flush();
                            out3.close();
                            in.close();
                        } finally {
                        }
                    } finally {
                    }
                } catch (Exception e3) {
                }
            }
        } catch (Exception x) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("error processing wear request", x);
            }
        }
        ch.close(apiClient).await();
        apiClient.disconnect();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("WearableDataLayer channel thread exiting");
        }
    }

    static /* synthetic */ void lambda$onChannelOpened$0(File photo, CyclicBarrier barrier, int id, int account, Object[] args) {
        if (id == NotificationCenter.fileDidLoad) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("file loaded: " + args[0] + " " + args[0].getClass().getName());
            }
            if (args[0].equals(photo.getName())) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("LOADED USER PHOTO");
                }
                try {
                    barrier.await(10L, TimeUnit.MILLISECONDS);
                } catch (Exception e) {
                }
            }
        }
    }

    public /* synthetic */ void lambda$onChannelOpened$1$WearDataLayerListenerService(NotificationCenter.NotificationCenterDelegate listener, TLRPC.User user) {
        NotificationCenter.getInstance(this.currentAccount).addObserver(listener, NotificationCenter.fileDidLoad);
        FileLoader.getInstance(this.currentAccount).loadFile(ImageLocation.getForUser(user, false), user, null, 1, 1);
    }

    public /* synthetic */ void lambda$onChannelOpened$2$WearDataLayerListenerService(NotificationCenter.NotificationCenterDelegate listener) {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(listener, NotificationCenter.fileDidLoad);
    }

    static /* synthetic */ void lambda$onChannelOpened$3(String[] code, CyclicBarrier barrier, int id, int account, Object[] args) {
        if (id == NotificationCenter.didReceiveNewMessages) {
            long did = ((Long) args[0]).longValue();
            if (did == 777000) {
                ArrayList<MessageObject> arr = (ArrayList) args[1];
                if (arr.size() > 0) {
                    MessageObject msg = arr.get(0);
                    if (!TextUtils.isEmpty(msg.messageText)) {
                        Matcher matcher = Pattern.compile("[0-9]+").matcher(msg.messageText);
                        if (matcher.find()) {
                            code[0] = matcher.group();
                            try {
                                barrier.await(10L, TimeUnit.MILLISECONDS);
                            } catch (Exception e) {
                            }
                        }
                    }
                }
            }
        }
    }

    public /* synthetic */ void lambda$onChannelOpened$4$WearDataLayerListenerService(NotificationCenter.NotificationCenterDelegate listener) {
        NotificationCenter.getInstance(this.currentAccount).addObserver(listener, NotificationCenter.didReceiveNewMessages);
    }

    public /* synthetic */ void lambda$onChannelOpened$5$WearDataLayerListenerService(NotificationCenter.NotificationCenterDelegate listener) {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(listener, NotificationCenter.didReceiveNewMessages);
    }

    @Override // com.google.android.gms.wearable.WearableListenerService, com.google.android.gms.wearable.MessageApi.MessageListener
    public void onMessageReceived(final MessageEvent messageEvent) {
        if ("/reply".equals(messageEvent.getPath())) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$cJhmFitzy3AgQK7Kp0DgzFgiEJc
                @Override // java.lang.Runnable
                public final void run() {
                    WearDataLayerListenerService.lambda$onMessageReceived$6(messageEvent);
                }
            });
        }
    }

    static /* synthetic */ void lambda$onMessageReceived$6(MessageEvent messageEvent) {
        int currentAccount;
        try {
            ApplicationLoader.postInitApplication();
            String data = new String(messageEvent.getData(), "UTF-8");
            JSONObject r = new JSONObject(data);
            CharSequence text = r.getString("text");
            if (text != null && text.length() != 0) {
                long dialog_id = r.getLong("chat_id");
                int max_id = r.getInt("max_id");
                int accountID = r.getInt("account_id");
                int i = 0;
                while (true) {
                    if (i >= UserConfig.getActivatedAccountsCount()) {
                        currentAccount = -1;
                        break;
                    } else if (UserConfig.getInstance(i).getClientUserId() != accountID) {
                        i++;
                    } else {
                        int currentAccount2 = i;
                        currentAccount = currentAccount2;
                        break;
                    }
                }
                if (dialog_id == 0 || max_id == 0) {
                    return;
                }
                if (currentAccount == -1) {
                    return;
                }
                SendMessagesHelper.getInstance(currentAccount).sendMessage(text.toString(), dialog_id, null, null, true, null, null, null, true, 0);
                MessagesController.getInstance(currentAccount).markDialogAsRead(dialog_id, max_id, max_id, 0, false, 0, true, 0);
            }
        } catch (Exception x) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e(x);
            }
        }
    }

    public static void sendMessageToWatch(final String path, final byte[] data, String capability) {
        Wearable.getCapabilityClient(ApplicationLoader.applicationContext).getCapability(capability, 1).addOnCompleteListener(new OnCompleteListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$YSU0cIKAXPbZSTkQjsV9b-iU8qE
            @Override // com.google.android.gms.tasks.OnCompleteListener
            public final void onComplete(Task task) {
                WearDataLayerListenerService.lambda$sendMessageToWatch$7(path, data, task);
            }
        });
    }

    static /* synthetic */ void lambda$sendMessageToWatch$7(String path, byte[] data, Task task) {
        CapabilityInfo info = (CapabilityInfo) task.getResult();
        if (info != null) {
            MessageClient mc = Wearable.getMessageClient(ApplicationLoader.applicationContext);
            Set<Node> nodes = info.getNodes();
            for (Node node : nodes) {
                mc.sendMessage(node.getId(), path, data);
            }
        }
    }

    @Override // com.google.android.gms.wearable.WearableListenerService, com.google.android.gms.wearable.CapabilityApi.CapabilityListener
    public void onCapabilityChanged(CapabilityInfo capabilityInfo) {
        if ("remote_notifications".equals(capabilityInfo.getName())) {
            watchConnected = false;
            for (Node node : capabilityInfo.getNodes()) {
                if (node.isNearby()) {
                    watchConnected = true;
                }
            }
        }
    }

    public static void updateWatchConnectionState() {
        try {
            Wearable.getCapabilityClient(ApplicationLoader.applicationContext).getCapability("remote_notifications", 1).addOnCompleteListener(new OnCompleteListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$WearDataLayerListenerService$vNiSDhL-91y6YoPA2s075IX0MHc
                @Override // com.google.android.gms.tasks.OnCompleteListener
                public final void onComplete(Task task) {
                    WearDataLayerListenerService.lambda$updateWatchConnectionState$8(task);
                }
            });
        } catch (Throwable th) {
        }
    }

    static /* synthetic */ void lambda$updateWatchConnectionState$8(Task task) {
        watchConnected = false;
        try {
            CapabilityInfo capabilityInfo = (CapabilityInfo) task.getResult();
            if (capabilityInfo == null) {
                return;
            }
            for (Node node : capabilityInfo.getNodes()) {
                if (node.isNearby()) {
                    watchConnected = true;
                }
            }
        } catch (Exception e) {
        }
    }

    public static boolean isWatchConnected() {
        return watchConnected;
    }
}
