package im.uwrkaxlmjj.messenger;

import android.app.AlarmManager;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ImageDecoder;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Point;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.PostProcessor;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.SoundPool;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.util.SparseIntArray;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.app.Person;
import androidx.core.graphics.drawable.IconCompat;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.upstream.cache.ContentMetadata;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.support.SparseLongArray;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.ui.PopupNotificationActivity;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketBean;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketResponse;
import im.uwrkaxlmjj.ui.hui.transfer.bean.TransferResponse;
import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes2.dex */
public class NotificationsController extends BaseController {
    public static final String EXTRA_VOICE_REPLY = "extra_voice_reply";
    private static volatile NotificationsController[] Instance = null;
    public static final int SETTING_MUTE_2_DAYS = 2;
    public static final int SETTING_MUTE_8_HOURS = 1;
    public static final int SETTING_MUTE_FOREVER = 3;
    public static final int SETTING_MUTE_HOUR = 0;
    public static final int SETTING_MUTE_UNMUTE = 4;
    public static final int TYPE_CHANNEL = 2;
    public static final int TYPE_GROUP = 0;
    public static final int TYPE_PRIVATE = 1;
    protected static AudioManager audioManager;
    private static NotificationManagerCompat notificationManager;
    private static NotificationManager systemNotificationManager;
    private AlarmManager alarmManager;
    private ArrayList<MessageObject> delayedPushMessages;
    private LongSparseArray<MessageObject> fcmRandomMessagesDict;
    private boolean inChatSoundEnabled;
    private int lastBadgeCount;
    private int lastButtonId;
    private int lastOnlineFromOtherDevice;
    private long lastSoundOutPlay;
    private long lastSoundPlay;
    private LongSparseArray<Integer> lastWearNotifiedMessageId;
    private String launcherClassName;
    private Runnable notificationDelayRunnable;
    private PowerManager.WakeLock notificationDelayWakelock;
    private String notificationGroup;
    private int notificationId;
    private boolean notifyCheck;
    private long opened_dialog_id;
    private int personal_count;
    public ArrayList<MessageObject> popupMessages;
    public ArrayList<MessageObject> popupReplyMessages;
    private LongSparseArray<Integer> pushDialogs;
    private LongSparseArray<Integer> pushDialogsOverrideMention;
    private ArrayList<MessageObject> pushMessages;
    private LongSparseArray<MessageObject> pushMessagesDict;
    public boolean showBadgeMessages;
    public boolean showBadgeMuted;
    public boolean showBadgeNumber;
    private LongSparseArray<Point> smartNotificationsDialogs;
    private int soundIn;
    private boolean soundInLoaded;
    private int soundOut;
    private boolean soundOutLoaded;
    private SoundPool soundPool;
    private int soundRecord;
    private boolean soundRecordLoaded;
    private int total_unread_count;
    private LongSparseArray<Integer> wearNotificationsIds;
    public static String OTHER_NOTIFICATIONS_CHANNEL = null;
    private static DispatchQueue notificationsQueue = new DispatchQueue("notificationsQueue");
    public static long globalSecretChatId = -4294967296L;

    static {
        notificationManager = null;
        systemNotificationManager = null;
        if (Build.VERSION.SDK_INT >= 26 && ApplicationLoader.applicationContext != null) {
            notificationManager = NotificationManagerCompat.from(ApplicationLoader.applicationContext);
            systemNotificationManager = (NotificationManager) ApplicationLoader.applicationContext.getSystemService("notification");
            checkOtherNotificationsChannel();
        }
        audioManager = (AudioManager) ApplicationLoader.applicationContext.getSystemService("audio");
        Instance = new NotificationsController[3];
    }

    public static NotificationsController getInstance(int num) {
        NotificationsController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (NotificationsController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    NotificationsController[] notificationsControllerArr = Instance;
                    NotificationsController notificationsController = new NotificationsController(num);
                    localInstance = notificationsController;
                    notificationsControllerArr[num] = notificationsController;
                }
            }
        }
        return localInstance;
    }

    public NotificationManagerCompat getNotificationManager() {
        return notificationManager;
    }

    public NotificationsController(int instance) {
        super(instance);
        this.pushMessages = new ArrayList<>();
        this.delayedPushMessages = new ArrayList<>();
        this.pushMessagesDict = new LongSparseArray<>();
        this.fcmRandomMessagesDict = new LongSparseArray<>();
        this.smartNotificationsDialogs = new LongSparseArray<>();
        this.pushDialogs = new LongSparseArray<>();
        this.wearNotificationsIds = new LongSparseArray<>();
        this.lastWearNotifiedMessageId = new LongSparseArray<>();
        this.pushDialogsOverrideMention = new LongSparseArray<>();
        this.popupMessages = new ArrayList<>();
        this.popupReplyMessages = new ArrayList<>();
        this.opened_dialog_id = 0L;
        this.lastButtonId = 5000;
        this.total_unread_count = 0;
        this.personal_count = 0;
        this.notifyCheck = false;
        this.lastOnlineFromOtherDevice = 0;
        this.lastBadgeCount = -1;
        this.notificationId = this.currentAccount + 1;
        StringBuilder sb = new StringBuilder();
        sb.append("messages");
        sb.append(this.currentAccount == 0 ? "" : Integer.valueOf(this.currentAccount));
        this.notificationGroup = sb.toString();
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        this.inChatSoundEnabled = preferences.getBoolean("EnableInChatSound", true);
        this.showBadgeNumber = preferences.getBoolean("badgeNumber", true);
        this.showBadgeMuted = preferences.getBoolean("badgeNumberMuted", false);
        this.showBadgeMessages = preferences.getBoolean("badgeNumberMessages", true);
        notificationManager = NotificationManagerCompat.from(ApplicationLoader.applicationContext);
        systemNotificationManager = (NotificationManager) ApplicationLoader.applicationContext.getSystemService("notification");
        try {
            audioManager = (AudioManager) ApplicationLoader.applicationContext.getSystemService("audio");
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            this.alarmManager = (AlarmManager) ApplicationLoader.applicationContext.getSystemService(NotificationCompat.CATEGORY_ALARM);
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        try {
            PowerManager pm = (PowerManager) ApplicationLoader.applicationContext.getSystemService("power");
            PowerManager.WakeLock wakeLockNewWakeLock = pm.newWakeLock(1, "hchat:notification_delay_lock");
            this.notificationDelayWakelock = wakeLockNewWakeLock;
            wakeLockNewWakeLock.setReferenceCounted(false);
        } catch (Exception e3) {
            FileLog.e(e3);
        }
        this.notificationDelayRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$wxoXmw2SbFZnGaHS1q-JjIpkXRA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$0$NotificationsController();
            }
        };
    }

    public /* synthetic */ void lambda$new$0$NotificationsController() {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("delay reached");
        }
        if (!this.delayedPushMessages.isEmpty()) {
            showOrUpdateNotification(true);
            this.delayedPushMessages.clear();
        }
        try {
            if (this.notificationDelayWakelock.isHeld()) {
                this.notificationDelayWakelock.release();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void checkOtherNotificationsChannel() {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        SharedPreferences preferences = null;
        if (OTHER_NOTIFICATIONS_CHANNEL == null) {
            preferences = ApplicationLoader.applicationContext.getSharedPreferences("Notifications", 0);
            OTHER_NOTIFICATIONS_CHANNEL = preferences.getString("OtherKey", "Other3");
        }
        NotificationChannel notificationChannel = systemNotificationManager.getNotificationChannel(OTHER_NOTIFICATIONS_CHANNEL);
        if (notificationChannel != null && notificationChannel.getImportance() == 0) {
            systemNotificationManager.deleteNotificationChannel(OTHER_NOTIFICATIONS_CHANNEL);
            OTHER_NOTIFICATIONS_CHANNEL = null;
            notificationChannel = null;
        }
        if (OTHER_NOTIFICATIONS_CHANNEL == null) {
            if (preferences == null) {
                preferences = ApplicationLoader.applicationContext.getSharedPreferences("Notifications", 0);
            }
            OTHER_NOTIFICATIONS_CHANNEL = "Other" + Utilities.random.nextLong();
            preferences.edit().putString("OtherKey", OTHER_NOTIFICATIONS_CHANNEL).commit();
        }
        if (notificationChannel == null) {
            NotificationChannel notificationChannel2 = new NotificationChannel(OTHER_NOTIFICATIONS_CHANNEL, "Other", 2);
            notificationChannel2.enableLights(false);
            notificationChannel2.enableVibration(false);
            AudioAttributes.Builder builder = new AudioAttributes.Builder();
            builder.setContentType(4);
            builder.setUsage(5);
            notificationChannel2.setSound(Settings.System.DEFAULT_NOTIFICATION_URI, builder.build());
            try {
                systemNotificationManager.createNotificationChannel(notificationChannel2);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public void cleanup() {
        this.popupMessages.clear();
        this.popupReplyMessages.clear();
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$zVnm1MGGf5qq3lCW5uf2kM5NYUY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanup$1$NotificationsController();
            }
        });
    }

    public /* synthetic */ void lambda$cleanup$1$NotificationsController() {
        this.opened_dialog_id = 0L;
        this.total_unread_count = 0;
        this.personal_count = 0;
        this.pushMessages.clear();
        this.pushMessagesDict.clear();
        this.fcmRandomMessagesDict.clear();
        this.pushDialogs.clear();
        this.wearNotificationsIds.clear();
        this.lastWearNotifiedMessageId.clear();
        this.delayedPushMessages.clear();
        this.notifyCheck = false;
        this.lastBadgeCount = 0;
        try {
            if (this.notificationDelayWakelock.isHeld()) {
                this.notificationDelayWakelock.release();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        dismissNotification();
        setBadge(getTotalAllUnreadCount());
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.commit();
        if (Build.VERSION.SDK_INT >= 26) {
            try {
                String keyStart = this.currentAccount + "channel";
                List<NotificationChannel> list = systemNotificationManager.getNotificationChannels();
                int count = list.size();
                for (int a = 0; a < count; a++) {
                    NotificationChannel channel = list.get(a);
                    String id = channel.getId();
                    if (id.startsWith(keyStart)) {
                        systemNotificationManager.deleteNotificationChannel(id);
                    }
                }
            } catch (Throwable e2) {
                FileLog.e(e2);
            }
        }
    }

    public void setInChatSoundEnabled(boolean value) {
        this.inChatSoundEnabled = value;
    }

    public /* synthetic */ void lambda$setOpenedDialogId$2$NotificationsController(long dialog_id) {
        this.opened_dialog_id = dialog_id;
    }

    public void setOpenedDialogId(final long dialog_id) {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$6sIIQfVTv0xXiNSoWixXhFMxLUQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setOpenedDialogId$2$NotificationsController(dialog_id);
            }
        });
    }

    public void setLastOnlineFromOtherDevice(final int time) {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$wUr2pgun_6QbsSnHeL34tH9S5Ls
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setLastOnlineFromOtherDevice$3$NotificationsController(time);
            }
        });
    }

    public /* synthetic */ void lambda$setLastOnlineFromOtherDevice$3$NotificationsController(int time) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("set last online from other device = " + time);
        }
        this.lastOnlineFromOtherDevice = time;
    }

    public void removeNotificationsForDialog(long did) {
        processReadMessages(null, did, 0, Integer.MAX_VALUE, false);
        LongSparseArray<Integer> dialogsToUpdate = new LongSparseArray<>();
        dialogsToUpdate.put(did, 0);
        processDialogsUpdateRead(dialogsToUpdate);
    }

    public boolean hasMessagesToReply() {
        for (int a = 0; a < this.pushMessages.size(); a++) {
            MessageObject messageObject = this.pushMessages.get(a);
            long dialog_id = messageObject.getDialogId();
            if ((!messageObject.messageOwner.mentioned || !(messageObject.messageOwner.action instanceof TLRPC.TL_messageActionPinMessage)) && ((int) dialog_id) != 0 && (messageObject.messageOwner.to_id.channel_id == 0 || messageObject.isMegagroup())) {
                return true;
            }
        }
        return false;
    }

    protected void forceShowPopupForReply() {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$076LyHmzKCv_6MCAlIkwy6sGdHY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$forceShowPopupForReply$5$NotificationsController();
            }
        });
    }

    public /* synthetic */ void lambda$forceShowPopupForReply$5$NotificationsController() {
        final ArrayList<MessageObject> popupArray = new ArrayList<>();
        for (int a = 0; a < this.pushMessages.size(); a++) {
            MessageObject messageObject = this.pushMessages.get(a);
            long dialog_id = messageObject.getDialogId();
            if ((!messageObject.messageOwner.mentioned || !(messageObject.messageOwner.action instanceof TLRPC.TL_messageActionPinMessage)) && ((int) dialog_id) != 0 && (messageObject.messageOwner.to_id.channel_id == 0 || messageObject.isMegagroup())) {
                popupArray.add(0, messageObject);
            }
        }
        if (!popupArray.isEmpty() && !AndroidUtilities.needShowPasscode(false)) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$EyzoFKtlyFK2kaL5Zr0OUKLwp3c
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$NotificationsController(popupArray);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$4$NotificationsController(ArrayList popupArray) {
        this.popupReplyMessages = popupArray;
        Intent popupIntent = new Intent(ApplicationLoader.applicationContext, (Class<?>) PopupNotificationActivity.class);
        popupIntent.putExtra("force", true);
        popupIntent.putExtra("currentAccount", this.currentAccount);
        popupIntent.setFlags(268763140);
        ApplicationLoader.applicationContext.startActivity(popupIntent);
        Intent it = new Intent("android.intent.action.CLOSE_SYSTEM_DIALOGS");
        ApplicationLoader.applicationContext.sendBroadcast(it);
    }

    public void removeDeletedMessagesFromNotifications(final SparseArray<ArrayList<Integer>> deletedMessages) {
        final ArrayList<MessageObject> popupArrayRemove = new ArrayList<>(0);
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$3DACCClZk0JyJ8iG8RYUsHujN3c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeDeletedMessagesFromNotifications$8$NotificationsController(deletedMessages, popupArrayRemove);
            }
        });
    }

    public /* synthetic */ void lambda$removeDeletedMessagesFromNotifications$8$NotificationsController(SparseArray deletedMessages, final ArrayList popupArrayRemove) {
        int old_unread_count = this.total_unread_count;
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        int a = 0;
        while (a < deletedMessages.size()) {
            int key = deletedMessages.keyAt(a);
            long dialog_id = -key;
            ArrayList<Integer> mids = (ArrayList) deletedMessages.get(key);
            Integer currentCount = this.pushDialogs.get(dialog_id);
            if (currentCount == null) {
                currentCount = 0;
            }
            Integer newCount = currentCount;
            int b = 0;
            while (b < mids.size()) {
                int old_unread_count2 = old_unread_count;
                SharedPreferences preferences2 = preferences;
                long mid = (((long) key) << 32) | ((long) mids.get(b).intValue());
                MessageObject messageObject = this.pushMessagesDict.get(mid);
                if (messageObject != null) {
                    this.pushMessagesDict.remove(mid);
                    this.delayedPushMessages.remove(messageObject);
                    this.pushMessages.remove(messageObject);
                    if (isPersonalMessage(messageObject)) {
                        this.personal_count--;
                    }
                    popupArrayRemove.add(messageObject);
                    newCount = Integer.valueOf(newCount.intValue() - 1);
                }
                b++;
                old_unread_count = old_unread_count2;
                preferences = preferences2;
            }
            int old_unread_count3 = old_unread_count;
            SharedPreferences preferences3 = preferences;
            int old_unread_count4 = newCount.intValue();
            if (old_unread_count4 <= 0) {
                newCount = 0;
                this.smartNotificationsDialogs.remove(dialog_id);
            }
            if (!newCount.equals(currentCount)) {
                int iIntValue = this.total_unread_count - currentCount.intValue();
                this.total_unread_count = iIntValue;
                this.total_unread_count = iIntValue + newCount.intValue();
                this.pushDialogs.put(dialog_id, newCount);
            }
            if (newCount.intValue() == 0) {
                this.pushDialogs.remove(dialog_id);
                this.pushDialogsOverrideMention.remove(dialog_id);
            }
            a++;
            old_unread_count = old_unread_count3;
            preferences = preferences3;
        }
        int old_unread_count5 = old_unread_count;
        if (!popupArrayRemove.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$n2YPlpq5lMBdCX1tSkFRaV5zOqw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$6$NotificationsController(popupArrayRemove);
                }
            });
        }
        if (old_unread_count5 != this.total_unread_count) {
            if (this.notifyCheck) {
                scheduleNotificationDelay(this.lastOnlineFromOtherDevice > getConnectionsManager().getCurrentTime());
            } else {
                this.delayedPushMessages.clear();
                showOrUpdateNotification(this.notifyCheck);
            }
            final int pushDialogsCount = this.pushDialogs.size();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$cZJvNQverAmluehMt_NrjAND25g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$NotificationsController(pushDialogsCount);
                }
            });
        }
        this.notifyCheck = false;
        if (this.showBadgeNumber) {
            setBadge(getTotalAllUnreadCount());
        }
    }

    public /* synthetic */ void lambda$null$6$NotificationsController(ArrayList popupArrayRemove) {
        int size = popupArrayRemove.size();
        for (int a = 0; a < size; a++) {
            this.popupMessages.remove(popupArrayRemove.get(a));
        }
    }

    public /* synthetic */ void lambda$null$7$NotificationsController(int pushDialogsCount) {
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.notificationsCountUpdated, Integer.valueOf(this.currentAccount));
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsUnreadCounterChanged, Integer.valueOf(pushDialogsCount));
    }

    public void removeDeletedHisoryFromNotifications(final SparseIntArray deletedMessages) {
        final ArrayList<MessageObject> popupArrayRemove = new ArrayList<>(0);
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$6D06nJEYQeIVoCoyz4QyuQ5u-fI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeDeletedHisoryFromNotifications$11$NotificationsController(deletedMessages, popupArrayRemove);
            }
        });
    }

    public /* synthetic */ void lambda$removeDeletedHisoryFromNotifications$11$NotificationsController(SparseIntArray deletedMessages, final ArrayList popupArrayRemove) {
        long dialog_id;
        long dialog_id2;
        int i;
        int old_unread_count = this.total_unread_count;
        getAccountInstance().getNotificationsSettings();
        for (int a = 0; a < deletedMessages.size(); a++) {
            int key = deletedMessages.keyAt(a);
            long dialog_id3 = -key;
            int id = deletedMessages.get(key);
            Integer currentCount = this.pushDialogs.get(dialog_id3);
            if (currentCount == null) {
                currentCount = 0;
            }
            Integer newCount = currentCount;
            int c = 0;
            while (c < this.pushMessages.size()) {
                MessageObject messageObject = this.pushMessages.get(c);
                if (messageObject.getDialogId() != dialog_id3 || messageObject.getId() > id) {
                    dialog_id2 = dialog_id3;
                    i = 1;
                } else {
                    dialog_id2 = dialog_id3;
                    this.pushMessagesDict.remove(messageObject.getIdWithChannel());
                    this.delayedPushMessages.remove(messageObject);
                    this.pushMessages.remove(messageObject);
                    c--;
                    if (isPersonalMessage(messageObject)) {
                        i = 1;
                        this.personal_count--;
                    } else {
                        i = 1;
                    }
                    popupArrayRemove.add(messageObject);
                    newCount = Integer.valueOf(newCount.intValue() - i);
                }
                c += i;
                dialog_id3 = dialog_id2;
            }
            long dialog_id4 = dialog_id3;
            if (newCount.intValue() > 0) {
                dialog_id = dialog_id4;
            } else {
                newCount = 0;
                dialog_id = dialog_id4;
                this.smartNotificationsDialogs.remove(dialog_id);
            }
            if (!newCount.equals(currentCount)) {
                int iIntValue = this.total_unread_count - currentCount.intValue();
                this.total_unread_count = iIntValue;
                this.total_unread_count = iIntValue + newCount.intValue();
                this.pushDialogs.put(dialog_id, newCount);
            }
            if (newCount.intValue() == 0) {
                this.pushDialogs.remove(dialog_id);
                this.pushDialogsOverrideMention.remove(dialog_id);
            }
        }
        if (popupArrayRemove.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$f4_-jNinJ1EbrBG1JqrH8f-8F1A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$9$NotificationsController(popupArrayRemove);
                }
            });
        }
        if (old_unread_count != this.total_unread_count) {
            if (this.notifyCheck) {
                scheduleNotificationDelay(this.lastOnlineFromOtherDevice > getConnectionsManager().getCurrentTime());
            } else {
                this.delayedPushMessages.clear();
                showOrUpdateNotification(this.notifyCheck);
            }
            final int pushDialogsCount = this.pushDialogs.size();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$busGPlY4hTWJWmHLz0RVafA8rkk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$10$NotificationsController(pushDialogsCount);
                }
            });
        }
        this.notifyCheck = false;
        if (this.showBadgeNumber) {
            setBadge(getTotalAllUnreadCount());
        }
    }

    public /* synthetic */ void lambda$null$9$NotificationsController(ArrayList popupArrayRemove) {
        int size = popupArrayRemove.size();
        for (int a = 0; a < size; a++) {
            this.popupMessages.remove(popupArrayRemove.get(a));
        }
    }

    public /* synthetic */ void lambda$null$10$NotificationsController(int pushDialogsCount) {
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.notificationsCountUpdated, Integer.valueOf(this.currentAccount));
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsUnreadCounterChanged, Integer.valueOf(pushDialogsCount));
    }

    public void processReadMessages(final SparseLongArray inbox, final long dialog_id, final int max_date, final int max_id, final boolean isPopup) {
        final ArrayList<MessageObject> popupArrayRemove = new ArrayList<>(0);
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$myyrRW8vwtU8-NalFSsWzfB3yXA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processReadMessages$13$NotificationsController(inbox, popupArrayRemove, dialog_id, max_id, max_date, isPopup);
            }
        });
    }

    public /* synthetic */ void lambda$processReadMessages$13$NotificationsController(SparseLongArray inbox, final ArrayList popupArrayRemove, long dialog_id, int max_id, int max_date, boolean isPopup) {
        if (inbox != null) {
            for (int b = 0; b < inbox.size(); b++) {
                int key = inbox.keyAt(b);
                long messageId = inbox.get(key);
                int a = 0;
                while (a < this.pushMessages.size()) {
                    MessageObject messageObject = this.pushMessages.get(a);
                    if (!messageObject.messageOwner.from_scheduled && messageObject.getDialogId() == key && messageObject.getId() <= ((int) messageId)) {
                        if (isPersonalMessage(messageObject)) {
                            this.personal_count--;
                        }
                        popupArrayRemove.add(messageObject);
                        long mid = messageObject.getId();
                        if (messageObject.messageOwner.to_id.channel_id != 0) {
                            mid |= ((long) messageObject.messageOwner.to_id.channel_id) << 32;
                        }
                        this.pushMessagesDict.remove(mid);
                        this.delayedPushMessages.remove(messageObject);
                        this.pushMessages.remove(a);
                        a--;
                    }
                    a++;
                }
            }
        }
        if (dialog_id != 0 && (max_id != 0 || max_date != 0)) {
            int a2 = 0;
            while (a2 < this.pushMessages.size()) {
                MessageObject messageObject2 = this.pushMessages.get(a2);
                if (messageObject2.getDialogId() == dialog_id) {
                    boolean remove = false;
                    if (max_date != 0) {
                        if (messageObject2.messageOwner.date <= max_date) {
                            remove = true;
                        }
                    } else if (!isPopup) {
                        if (messageObject2.getId() <= max_id || max_id < 0) {
                            remove = true;
                        }
                    } else if (messageObject2.getId() == max_id || max_id < 0) {
                        remove = true;
                    }
                    if (remove) {
                        if (isPersonalMessage(messageObject2)) {
                            this.personal_count--;
                        }
                        this.pushMessages.remove(a2);
                        this.delayedPushMessages.remove(messageObject2);
                        popupArrayRemove.add(messageObject2);
                        long mid2 = messageObject2.getId();
                        if (messageObject2.messageOwner.to_id.channel_id != 0) {
                            mid2 |= ((long) messageObject2.messageOwner.to_id.channel_id) << 32;
                        }
                        this.pushMessagesDict.remove(mid2);
                        a2--;
                    }
                }
                a2++;
            }
        }
        if (!popupArrayRemove.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$x8IaTpmg_jDa0bnVlhiStRxcsqU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$NotificationsController(popupArrayRemove);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$12$NotificationsController(ArrayList popupArrayRemove) {
        int size = popupArrayRemove.size();
        for (int a = 0; a < size; a++) {
            this.popupMessages.remove(popupArrayRemove.get(a));
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.pushMessagesUpdated, new Object[0]);
    }

    private int addToPopupMessages(ArrayList<MessageObject> popupArrayAdd, MessageObject messageObject, int lower_id, long dialog_id, boolean isChannel, SharedPreferences preferences) {
        int popup = 0;
        if (lower_id != 0) {
            if (preferences.getBoolean(ContentMetadata.KEY_CUSTOM_PREFIX + dialog_id, false)) {
                popup = preferences.getInt("popup_" + dialog_id, 0);
            } else {
                popup = 0;
            }
            if (popup == 0) {
                if (isChannel) {
                    popup = preferences.getInt("popupChannel", 0);
                } else {
                    popup = preferences.getInt(((int) dialog_id) < 0 ? "popupGroup" : "popupAll", 0);
                }
            } else if (popup == 1) {
                popup = 3;
            } else if (popup == 2) {
                popup = 0;
            }
        }
        if (popup != 0 && messageObject.messageOwner.to_id.channel_id != 0 && !messageObject.isMegagroup()) {
            popup = 0;
        }
        if (popup != 0) {
            popupArrayAdd.add(0, messageObject);
        }
        return popup;
    }

    public void processNewMessages(final ArrayList<MessageObject> messageObjects, final boolean isLast, final boolean isFcm, final CountDownLatch countDownLatch) {
        if (messageObjects.isEmpty()) {
            if (countDownLatch != null) {
                countDownLatch.countDown();
            }
        } else {
            final ArrayList<MessageObject> popupArrayAdd = new ArrayList<>(0);
            notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$UFN9-Iz6tJFzJ2cdYdOI_o_eomo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processNewMessages$16$NotificationsController(messageObjects, popupArrayAdd, isFcm, isLast, countDownLatch);
                }
            });
        }
    }

    public /* synthetic */ void lambda$processNewMessages$16$NotificationsController(ArrayList messageObjects, final ArrayList popupArrayAdd, boolean isFcm, boolean isLast, CountDownLatch countDownLatch) {
        Integer override;
        int a;
        boolean allowPinned;
        long mid;
        boolean isChannel;
        int lower_id;
        long random_id;
        boolean value;
        LongSparseArray<Boolean> settingsCache;
        boolean added;
        boolean edited;
        int i;
        long original_dialog_id;
        MessageObject messageObject;
        ArrayList arrayList = messageObjects;
        LongSparseArray<Boolean> settingsCache2 = new LongSparseArray<>();
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        boolean allowPinned2 = preferences.getBoolean("PinnedMessages", true);
        boolean added2 = false;
        boolean edited2 = false;
        int popup = 0;
        boolean hasScheduled = false;
        int a2 = 0;
        while (a2 < messageObjects.size()) {
            MessageObject messageObject2 = (MessageObject) arrayList.get(a2);
            if (messageObject2.messageOwner != null && messageObject2.messageOwner.silent && ((messageObject2.messageOwner.action instanceof TLRPC.TL_messageActionContactSignUp) || (messageObject2.messageOwner.action instanceof TLRPC.TL_messageActionUserJoined))) {
                a = a2;
                allowPinned = allowPinned2;
            } else {
                a = a2;
                long mid2 = messageObject2.getId();
                long random_id2 = messageObject2.isFcmMessage() ? messageObject2.messageOwner.random_id : 0L;
                allowPinned = allowPinned2;
                long dialog_id = messageObject2.getDialogId();
                int lower_id2 = (int) dialog_id;
                if (messageObject2.messageOwner.to_id.channel_id != 0) {
                    mid = mid2 | (((long) messageObject2.messageOwner.to_id.channel_id) << 32);
                    isChannel = true;
                } else {
                    mid = mid2;
                    isChannel = false;
                }
                MessageObject oldMessageObject = this.pushMessagesDict.get(mid);
                if (oldMessageObject == null) {
                    random_id = random_id2;
                    if (messageObject2.messageOwner.random_id != 0) {
                        lower_id = lower_id2;
                        oldMessageObject = this.fcmRandomMessagesDict.get(messageObject2.messageOwner.random_id);
                        if (oldMessageObject != null) {
                            this.fcmRandomMessagesDict.remove(messageObject2.messageOwner.random_id);
                        }
                    } else {
                        lower_id = lower_id2;
                    }
                } else {
                    lower_id = lower_id2;
                    random_id = random_id2;
                }
                if (oldMessageObject == null) {
                    long mid3 = mid;
                    int lower_id3 = lower_id;
                    long random_id3 = random_id;
                    if (!edited2) {
                        if (isFcm) {
                            getMessagesStorage().putPushMessage(messageObject2);
                        }
                        if (dialog_id != this.opened_dialog_id || !ApplicationLoader.isScreenOn) {
                            if (messageObject2.messageOwner.mentioned) {
                                if (allowPinned || !(messageObject2.messageOwner.action instanceof TLRPC.TL_messageActionPinMessage)) {
                                    dialog_id = messageObject2.messageOwner.from_id;
                                }
                            }
                            if (isPersonalMessage(messageObject2)) {
                                this.personal_count++;
                            }
                            boolean z = lower_id3 < 0;
                            int index = settingsCache2.indexOfKey(dialog_id);
                            if (index >= 0) {
                                value = settingsCache2.valueAt(index).booleanValue();
                            } else {
                                int notifyOverride = getNotifyOverride(preferences, dialog_id);
                                boolean value2 = notifyOverride == -1 ? isGlobalNotificationsEnabled(dialog_id) : notifyOverride != 2;
                                settingsCache2.put(dialog_id, Boolean.valueOf(value2));
                                value = value2;
                            }
                            if (value) {
                                if (isFcm) {
                                    settingsCache = settingsCache2;
                                    added = true;
                                    edited = edited2;
                                    i = 0;
                                    original_dialog_id = dialog_id;
                                } else {
                                    added = true;
                                    edited = edited2;
                                    original_dialog_id = dialog_id;
                                    settingsCache = settingsCache2;
                                    i = 0;
                                    popup = addToPopupMessages(popupArrayAdd, messageObject2, lower_id3, dialog_id, isChannel, preferences);
                                }
                                if (!hasScheduled) {
                                    hasScheduled = messageObject2.messageOwner.from_scheduled;
                                }
                                this.delayedPushMessages.add(messageObject2);
                                this.pushMessages.add(i, messageObject2);
                                if (mid3 != 0) {
                                    this.pushMessagesDict.put(mid3, messageObject2);
                                } else if (random_id3 != 0) {
                                    this.fcmRandomMessagesDict.put(random_id3, messageObject2);
                                }
                                if (original_dialog_id != dialog_id) {
                                    Integer current = this.pushDialogsOverrideMention.get(original_dialog_id);
                                    this.pushDialogsOverrideMention.put(original_dialog_id, Integer.valueOf(current == null ? 1 : current.intValue() + 1));
                                }
                                edited2 = edited;
                                added2 = added;
                            } else {
                                settingsCache = settingsCache2;
                                edited2 = edited2;
                                added2 = true;
                            }
                        } else if (!isFcm) {
                            playInChatSound();
                        }
                    }
                } else if (oldMessageObject.isFcmMessage()) {
                    this.pushMessagesDict.put(mid, messageObject2);
                    int idxOld = this.pushMessages.indexOf(oldMessageObject);
                    if (idxOld >= 0) {
                        this.pushMessages.set(idxOld, messageObject2);
                        messageObject = messageObject2;
                        popup = addToPopupMessages(popupArrayAdd, messageObject2, lower_id, dialog_id, isChannel, preferences);
                    } else {
                        messageObject = messageObject2;
                    }
                    if (isFcm) {
                        boolean z2 = messageObject.localEdit;
                        edited2 = z2;
                        if (z2) {
                            getMessagesStorage().putPushMessage(messageObject);
                        }
                    }
                    settingsCache = settingsCache2;
                }
                a2 = a + 1;
                arrayList = messageObjects;
                allowPinned2 = allowPinned;
                settingsCache2 = settingsCache;
            }
            settingsCache = settingsCache2;
            a2 = a + 1;
            arrayList = messageObjects;
            allowPinned2 = allowPinned;
            settingsCache2 = settingsCache;
        }
        boolean edited3 = edited2;
        if (added2) {
            this.notifyCheck = isLast;
        }
        if (!popupArrayAdd.isEmpty() && !AndroidUtilities.needShowPasscode(false)) {
            final int popupFinal = popup;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$q7gnh0pa8gaSaQGDQMZ077_5B5k
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$14$NotificationsController(popupArrayAdd, popupFinal);
                }
            });
        }
        if (isFcm || hasScheduled) {
            if (edited3) {
                this.delayedPushMessages.clear();
                showOrUpdateNotification(this.notifyCheck);
            } else if (added2) {
                long dialog_id2 = ((MessageObject) messageObjects.get(0)).getDialogId();
                int old_unread_count = this.total_unread_count;
                int notifyOverride2 = getNotifyOverride(preferences, dialog_id2);
                boolean canAddValue = notifyOverride2 == -1 ? isGlobalNotificationsEnabled(dialog_id2) : notifyOverride2 != 2;
                Integer currentCount = this.pushDialogs.get(dialog_id2);
                Integer newCount = Integer.valueOf(currentCount != null ? currentCount.intValue() + 1 : 1);
                if (this.notifyCheck && !canAddValue && (override = this.pushDialogsOverrideMention.get(dialog_id2)) != null && override.intValue() != 0) {
                    canAddValue = true;
                    newCount = override;
                }
                if (canAddValue) {
                    if (currentCount != null) {
                        this.total_unread_count -= currentCount.intValue();
                    }
                    this.total_unread_count += newCount.intValue();
                    this.pushDialogs.put(dialog_id2, newCount);
                }
                if (old_unread_count != this.total_unread_count) {
                    this.delayedPushMessages.clear();
                    showOrUpdateNotification(this.notifyCheck);
                    final int pushDialogsCount = this.pushDialogs.size();
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$EB9wVqXPYhK4ImQlIfNZP2KIf_g
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$15$NotificationsController(pushDialogsCount);
                        }
                    });
                }
                this.notifyCheck = false;
                if (this.showBadgeNumber) {
                    setBadge(getTotalAllUnreadCount());
                }
            }
        }
        if (countDownLatch != null) {
            countDownLatch.countDown();
        }
    }

    public /* synthetic */ void lambda$null$14$NotificationsController(ArrayList popupArrayAdd, int popupFinal) {
        this.popupMessages.addAll(0, popupArrayAdd);
        if (ApplicationLoader.mainInterfacePaused || (!ApplicationLoader.isScreenOn && !SharedConfig.isWaitingForPasscodeEnter)) {
            if (popupFinal == 3 || ((popupFinal == 1 && ApplicationLoader.isScreenOn) || (popupFinal == 2 && !ApplicationLoader.isScreenOn))) {
                Intent popupIntent = new Intent(ApplicationLoader.applicationContext, (Class<?>) PopupNotificationActivity.class);
                popupIntent.setFlags(268763140);
                try {
                    ApplicationLoader.applicationContext.startActivity(popupIntent);
                } catch (Throwable th) {
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$15$NotificationsController(int pushDialogsCount) {
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.notificationsCountUpdated, Integer.valueOf(this.currentAccount));
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsUnreadCounterChanged, Integer.valueOf(pushDialogsCount));
    }

    public int getTotalUnreadCount() {
        return this.total_unread_count;
    }

    public void processDialogsUpdateRead(final LongSparseArray<Integer> dialogsToUpdate) {
        final ArrayList<MessageObject> popupArrayToRemove = new ArrayList<>();
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$DgropkV6mK1t6YgOAS7GuWQtV_4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processDialogsUpdateRead$19$NotificationsController(dialogsToUpdate, popupArrayToRemove);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0102  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$processDialogsUpdateRead$19$NotificationsController(android.util.LongSparseArray r21, final java.util.ArrayList r22) {
        /*
            Method dump skipped, instruction units count: 364
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.NotificationsController.lambda$processDialogsUpdateRead$19$NotificationsController(android.util.LongSparseArray, java.util.ArrayList):void");
    }

    public /* synthetic */ void lambda$null$17$NotificationsController(ArrayList popupArrayToRemove) {
        int size = popupArrayToRemove.size();
        for (int a = 0; a < size; a++) {
            this.popupMessages.remove(popupArrayToRemove.get(a));
        }
    }

    public /* synthetic */ void lambda$null$18$NotificationsController(int pushDialogsCount) {
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.notificationsCountUpdated, Integer.valueOf(this.currentAccount));
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsUnreadCounterChanged, Integer.valueOf(pushDialogsCount));
    }

    public void processLoadedUnreadMessages(final LongSparseArray<Integer> dialogs, final ArrayList<TLRPC.Message> messages, final ArrayList<MessageObject> push, ArrayList<TLRPC.User> users, ArrayList<TLRPC.Chat> chats, ArrayList<TLRPC.EncryptedChat> encryptedChats) {
        getMessagesController().putUsers(users, true);
        getMessagesController().putChats(chats, true);
        getMessagesController().putEncryptedChats(encryptedChats, true);
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$4bnw2IRhyoMAx65EbSVWYLO7QKc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedUnreadMessages$21$NotificationsController(messages, dialogs, push);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0055  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$processLoadedUnreadMessages$21$NotificationsController(java.util.ArrayList r24, android.util.LongSparseArray r25, java.util.ArrayList r26) {
        /*
            Method dump skipped, instruction units count: 717
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.NotificationsController.lambda$processLoadedUnreadMessages$21$NotificationsController(java.util.ArrayList, android.util.LongSparseArray, java.util.ArrayList):void");
    }

    public /* synthetic */ void lambda$null$20$NotificationsController(int pushDialogsCount) {
        if (this.total_unread_count == 0) {
            this.popupMessages.clear();
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.pushMessagesUpdated, new Object[0]);
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.notificationsCountUpdated, Integer.valueOf(this.currentAccount));
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsUnreadCounterChanged, Integer.valueOf(pushDialogsCount));
    }

    private int getTotalAllUnreadCount() {
        int count = 0;
        for (int a = 0; a < 3; a++) {
            if (UserConfig.getInstance(a).isClientActivated()) {
                NotificationsController controller = getInstance(a);
                if (controller.showBadgeNumber) {
                    if (controller.showBadgeMessages) {
                        if (controller.showBadgeMuted) {
                            try {
                                int N = MessagesController.getInstance(a).allDialogs.size();
                                for (int i = 0; i < N; i++) {
                                    TLRPC.Dialog dialog = MessagesController.getInstance(a).allDialogs.get(i);
                                    if (dialog.unread_count != 0) {
                                        count += dialog.unread_count;
                                    }
                                }
                            } catch (Exception e) {
                                FileLog.e(e);
                            }
                        } else {
                            count += controller.total_unread_count;
                        }
                    } else if (controller.showBadgeMuted) {
                        try {
                            int N2 = MessagesController.getInstance(a).allDialogs.size();
                            for (int i2 = 0; i2 < N2; i2++) {
                                if (MessagesController.getInstance(a).allDialogs.get(i2).unread_count != 0) {
                                    count++;
                                }
                            }
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                    } else {
                        count += controller.pushDialogs.size();
                    }
                }
            }
        }
        return count;
    }

    public /* synthetic */ void lambda$updateBadge$22$NotificationsController() {
        setBadge(getTotalAllUnreadCount());
    }

    public void updateBadge() {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$QCaAqOy9qMdjJzck9S37UYdvSnQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateBadge$22$NotificationsController();
            }
        });
    }

    private void setBadge(int count) {
        if (this.lastBadgeCount == count) {
            return;
        }
        this.lastBadgeCount = count;
        NotificationBadge.applyCount(count);
    }

    private String getShortStringForMessage(MessageObject messageObject, String[] userName, boolean[] preview) {
        int i;
        char c;
        char c2;
        if (AndroidUtilities.needShowPasscode(false) || SharedConfig.isWaitingForPasscodeEnter) {
            return LocaleController.getString("YouHaveNewMessage", mpEIGo.juqQQs.esbSDO.R.string.YouHaveNewMessage);
        }
        long dialog_id = messageObject.messageOwner.dialog_id;
        int chat_id = messageObject.messageOwner.to_id.chat_id != 0 ? messageObject.messageOwner.to_id.chat_id : messageObject.messageOwner.to_id.channel_id;
        int from_id = messageObject.messageOwner.to_id.user_id;
        if (preview != null) {
            preview[0] = true;
        }
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        boolean dialogPreviewEnabled = preferences.getBoolean("content_preview_" + dialog_id, true);
        if (messageObject.isFcmMessage()) {
            if (chat_id == 0 && from_id != 0) {
                if (Build.VERSION.SDK_INT > 27) {
                    userName[0] = messageObject.localName;
                }
                if (!dialogPreviewEnabled || !preferences.getBoolean("EnablePreviewAll", true)) {
                    if (preview != null) {
                        preview[0] = false;
                    }
                    return LocaleController.getString("Message", mpEIGo.juqQQs.esbSDO.R.string.Message);
                }
            } else if (chat_id != 0) {
                if (messageObject.messageOwner.to_id.channel_id == 0 || messageObject.isMegagroup()) {
                    userName[0] = messageObject.localUserName;
                } else if (Build.VERSION.SDK_INT > 27) {
                    userName[0] = messageObject.localName;
                }
                if (!dialogPreviewEnabled || ((!messageObject.localChannel && !preferences.getBoolean("EnablePreviewGroup", true)) || (messageObject.localChannel && !preferences.getBoolean("EnablePreviewChannel", true)))) {
                    if (preview != null) {
                        preview[0] = false;
                    }
                    if (!messageObject.isMegagroup() && messageObject.messageOwner.to_id.channel_id != 0) {
                        return LocaleController.formatString("ChannelMessageNoText", mpEIGo.juqQQs.esbSDO.R.string.ChannelMessageNoText, messageObject.localName);
                    }
                    return LocaleController.formatString("NotificationMessageGroupNoText", mpEIGo.juqQQs.esbSDO.R.string.NotificationMessageGroupNoText, messageObject.localUserName, messageObject.localName);
                }
            }
            return messageObject.messageOwner.message;
        }
        if (from_id == 0) {
            if (messageObject.isFromUser() || messageObject.getId() < 0) {
                from_id = messageObject.messageOwner.from_id;
            } else {
                from_id = -chat_id;
            }
        } else if (from_id == getUserConfig().getClientUserId()) {
            from_id = messageObject.messageOwner.from_id;
        }
        if (dialog_id == 0) {
            if (chat_id != 0) {
                dialog_id = -chat_id;
            } else if (from_id != 0) {
                dialog_id = from_id;
            }
        }
        String name = null;
        if (from_id > 0) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(from_id));
            if (user != null) {
                name = UserObject.getName(user);
                if (chat_id == 0 && Build.VERSION.SDK_INT <= 27) {
                    userName[0] = null;
                } else {
                    userName[0] = name;
                }
            }
        } else {
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(-from_id));
            if (chat != null) {
                name = chat.title;
                userName[0] = name;
            }
        }
        if (name == null) {
            return null;
        }
        TLRPC.Chat chat2 = null;
        if (chat_id != 0) {
            chat2 = getMessagesController().getChat(Integer.valueOf(chat_id));
            if (chat2 == null) {
                return null;
            }
            if (ChatObject.isChannel(chat2) && !chat2.megagroup && Build.VERSION.SDK_INT <= 27) {
                userName[0] = null;
            }
        }
        if (((int) dialog_id) == 0) {
            userName[0] = null;
            return LocaleController.getString("YouHaveNewMessage", mpEIGo.juqQQs.esbSDO.R.string.YouHaveNewMessage);
        }
        boolean isChannel = ChatObject.isChannel(chat2) && !chat2.megagroup;
        if (dialogPreviewEnabled && ((chat_id == 0 && from_id != 0 && preferences.getBoolean("EnablePreviewAll", true)) || (chat_id != 0 && ((!isChannel && preferences.getBoolean("EnablePreviewGroup", true)) || (isChannel && preferences.getBoolean("EnablePreviewChannel", true)))))) {
            if (messageObject.messageOwner instanceof TLRPC.TL_messageService) {
                userName[0] = null;
                if ((messageObject.messageOwner.action instanceof TLRPC.TL_messageActionUserJoined) || (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionContactSignUp)) {
                    return LocaleController.formatString("NotificationContactJoined", mpEIGo.juqQQs.esbSDO.R.string.NotificationContactJoined, name);
                }
                if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionUserUpdatedPhoto) {
                    return LocaleController.formatString("NotificationContactNewPhoto", mpEIGo.juqQQs.esbSDO.R.string.NotificationContactNewPhoto, name);
                }
                if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionLoginUnknownLocation) {
                    String date = LocaleController.formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, LocaleController.getInstance().formatterYear.format(((long) messageObject.messageOwner.date) * 1000), LocaleController.getInstance().formatterDay.format(((long) messageObject.messageOwner.date) * 1000));
                    return LocaleController.formatString("NotificationUnrecognizedDevice", mpEIGo.juqQQs.esbSDO.R.string.NotificationUnrecognizedDevice, getUserConfig().getCurrentUser().first_name, date, messageObject.messageOwner.action.title, messageObject.messageOwner.action.address);
                }
                if ((messageObject.messageOwner.action instanceof TLRPC.TL_messageActionGameScore) || (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionPaymentSent)) {
                    return messageObject.messageText.toString();
                }
                if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionPhoneCall) {
                    TLRPC.PhoneCallDiscardReason reason = messageObject.messageOwner.action.reason;
                    if (!messageObject.isOut() && (reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed)) {
                        return LocaleController.getString("CallMessageIncomingMissed", mpEIGo.juqQQs.esbSDO.R.string.CallMessageIncomingMissed);
                    }
                } else {
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatAddUser) {
                        int singleUserId = messageObject.messageOwner.action.user_id;
                        if (singleUserId == 0 && messageObject.messageOwner.action.users.size() == 1) {
                            singleUserId = messageObject.messageOwner.action.users.get(0).intValue();
                        }
                        if (singleUserId != 0) {
                            if (messageObject.messageOwner.to_id.channel_id != 0 && !chat2.megagroup) {
                                return LocaleController.formatString("ChannelAddedByNotification", mpEIGo.juqQQs.esbSDO.R.string.ChannelAddedByNotification, name, chat2.title);
                            }
                            if (singleUserId == getUserConfig().getClientUserId()) {
                                return LocaleController.formatString("NotificationInvitedToGroup", mpEIGo.juqQQs.esbSDO.R.string.NotificationInvitedToGroup, name, chat2.title);
                            }
                            TLRPC.User u2 = getMessagesController().getUser(Integer.valueOf(singleUserId));
                            if (u2 == null) {
                                return null;
                            }
                            return from_id == u2.id ? chat2.megagroup ? LocaleController.formatString("NotificationGroupAddSelfMega", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupAddSelfMega, name, chat2.title) : LocaleController.formatString("NotificationGroupAddSelf", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupAddSelf, name, chat2.title) : LocaleController.formatString("NotificationGroupAddMember", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupAddMember, name, chat2.title, UserObject.getName(u2));
                        }
                        StringBuilder names = new StringBuilder();
                        for (int a = 0; a < messageObject.messageOwner.action.users.size(); a++) {
                            TLRPC.User user2 = getMessagesController().getUser(messageObject.messageOwner.action.users.get(a));
                            if (user2 != null) {
                                String name2 = UserObject.getName(user2);
                                if (names.length() != 0) {
                                    names.append(", ");
                                }
                                names.append(name2);
                            }
                        }
                        return LocaleController.formatString("NotificationGroupAddMember", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupAddMember, name, chat2.title, names.toString());
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatJoinedByLink) {
                        return LocaleController.formatString("NotificationInvitedToGroupByLink", mpEIGo.juqQQs.esbSDO.R.string.NotificationInvitedToGroupByLink, name, chat2.title);
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatEditTitle) {
                        return LocaleController.formatString("NotificationEditedGroupName", mpEIGo.juqQQs.esbSDO.R.string.NotificationEditedGroupName, name, messageObject.messageOwner.action.title);
                    }
                    if ((messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatEditPhoto) || (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatDeletePhoto)) {
                        if (messageObject.messageOwner.to_id.channel_id != 0 && !chat2.megagroup) {
                            return LocaleController.formatString("ChannelPhotoEditNotification", mpEIGo.juqQQs.esbSDO.R.string.ChannelPhotoEditNotification, chat2.title);
                        }
                        return LocaleController.formatString("NotificationEditedGroupPhoto", mpEIGo.juqQQs.esbSDO.R.string.NotificationEditedGroupPhoto, name, chat2.title);
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatDeleteUser) {
                        if (messageObject.messageOwner.action.user_id == getUserConfig().getClientUserId()) {
                            return LocaleController.formatString("NotificationGroupKickYou", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupKickYou, name, chat2.title);
                        }
                        if (messageObject.messageOwner.action.user_id == from_id) {
                            return LocaleController.formatString("NotificationGroupLeftMember", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupLeftMember, name, chat2.title);
                        }
                        TLRPC.User u22 = getMessagesController().getUser(Integer.valueOf(messageObject.messageOwner.action.user_id));
                        if (u22 == null) {
                            return null;
                        }
                        return LocaleController.formatString("NotificationGroupKickMember", mpEIGo.juqQQs.esbSDO.R.string.NotificationGroupKickMember, name, chat2.title, UserObject.getName(u22));
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatCreate) {
                        return messageObject.messageText.toString();
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChannelCreate) {
                        return messageObject.messageText.toString();
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatMigrateTo) {
                        return LocaleController.formatString("ActionMigrateFromGroupNotify", mpEIGo.juqQQs.esbSDO.R.string.ActionMigrateFromGroupNotify, chat2.title);
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChannelMigrateFrom) {
                        return LocaleController.formatString("ActionMigrateFromGroupNotify", mpEIGo.juqQQs.esbSDO.R.string.ActionMigrateFromGroupNotify, messageObject.messageOwner.action.title);
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionScreenshotTaken) {
                        return messageObject.messageText.toString();
                    }
                    if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionPinMessage) {
                        if (chat2 == null) {
                            i = 1;
                        } else {
                            if (!ChatObject.isChannel(chat2) || chat2.megagroup) {
                                if (messageObject.replyMessageObject == null) {
                                    return LocaleController.formatString("NotificationActionPinnedNoText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedNoText, name, chat2.title);
                                }
                                MessageObject object = messageObject.replyMessageObject;
                                if (object.isMusic()) {
                                    return LocaleController.formatString("NotificationActionPinnedMusic", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedMusic, name, chat2.title);
                                }
                                if (object.isVideo()) {
                                    if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object.messageOwner.message)) {
                                        return LocaleController.formatString("NotificationActionPinnedText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedText, name, "📹 " + object.messageOwner.message, chat2.title);
                                    }
                                    return LocaleController.formatString("NotificationActionPinnedVideo", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedVideo, name, chat2.title);
                                }
                                if (object.isGif()) {
                                    if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object.messageOwner.message)) {
                                        return LocaleController.formatString("NotificationActionPinnedText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedText, name, "🎬 " + object.messageOwner.message, chat2.title);
                                    }
                                    return LocaleController.formatString("NotificationActionPinnedGif", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGif, name, chat2.title);
                                }
                                if (object.isVoice()) {
                                    return LocaleController.formatString("NotificationActionPinnedVoice", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedVoice, name, chat2.title);
                                }
                                if (object.isRoundVideo()) {
                                    return LocaleController.formatString("NotificationActionPinnedRound", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedRound, name, chat2.title);
                                }
                                if (object.isSticker() || object.isAnimatedSticker()) {
                                    String emoji = object.getStickerEmoji();
                                    return emoji != null ? LocaleController.formatString("NotificationActionPinnedStickerEmoji", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedStickerEmoji, name, chat2.title, emoji) : LocaleController.formatString("NotificationActionPinnedSticker", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedSticker, name, chat2.title);
                                }
                                if (object.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
                                    if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object.messageOwner.message)) {
                                        return LocaleController.formatString("NotificationActionPinnedText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedText, name, "📎 " + object.messageOwner.message, chat2.title);
                                    }
                                    return LocaleController.formatString("NotificationActionPinnedFile", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedFile, name, chat2.title);
                                }
                                if ((object.messageOwner.media instanceof TLRPC.TL_messageMediaGeo) || (object.messageOwner.media instanceof TLRPC.TL_messageMediaVenue)) {
                                    char c3 = 0;
                                    char c4 = 1;
                                    int i2 = 2;
                                    Object[] objArr = new Object[i2];
                                    objArr[c3] = name;
                                    objArr[c4] = chat2.title;
                                    return LocaleController.formatString("NotificationActionPinnedGeo", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGeo, objArr);
                                }
                                if (object.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive) {
                                    return LocaleController.formatString("NotificationActionPinnedGeoLive", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGeoLive, name, chat2.title);
                                }
                                if (object.messageOwner.media instanceof TLRPC.TL_messageMediaContact) {
                                    TLRPC.TL_messageMediaContact mediaContact = (TLRPC.TL_messageMediaContact) object.messageOwner.media;
                                    return LocaleController.formatString("NotificationActionPinnedContact2", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedContact2, name, chat2.title, ContactsController.formatName(mediaContact.first_name, mediaContact.last_name));
                                }
                                if (object.messageOwner.media instanceof TLRPC.TL_messageMediaPoll) {
                                    TLRPC.TL_messageMediaPoll mediaPoll = (TLRPC.TL_messageMediaPoll) object.messageOwner.media;
                                    return LocaleController.formatString("NotificationActionPinnedPoll2", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedPoll2, name, chat2.title, mediaPoll.poll.question);
                                }
                                if (object.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
                                    if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object.messageOwner.message)) {
                                        return LocaleController.formatString("NotificationActionPinnedText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedText, name, "🖼 " + object.messageOwner.message, chat2.title);
                                    }
                                    return LocaleController.formatString("NotificationActionPinnedPhoto", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedPhoto, name, chat2.title);
                                }
                                if (object.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                                    return LocaleController.formatString("NotificationActionPinnedGame", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGame, name, chat2.title);
                                }
                                if (object.messageText != null && object.messageText.length() > 0) {
                                    CharSequence message = object.messageText;
                                    if (message.length() <= 20) {
                                        c2 = 0;
                                    } else {
                                        StringBuilder sb = new StringBuilder();
                                        c2 = 0;
                                        sb.append((Object) message.subSequence(0, 20));
                                        sb.append("...");
                                        message = sb.toString();
                                    }
                                    Object[] objArr2 = new Object[3];
                                    objArr2[c2] = name;
                                    objArr2[1] = message;
                                    objArr2[2] = chat2.title;
                                    return LocaleController.formatString("NotificationActionPinnedText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedText, objArr2);
                                }
                                return LocaleController.formatString("NotificationActionPinnedNoText", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedNoText, name, chat2.title);
                            }
                            i = 1;
                        }
                        if (messageObject.replyMessageObject == null) {
                            Object[] objArr3 = new Object[i];
                            objArr3[0] = chat2.title;
                            return LocaleController.formatString("NotificationActionPinnedNoTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedNoTextChannel, objArr3);
                        }
                        MessageObject object2 = messageObject.replyMessageObject;
                        if (object2.isMusic()) {
                            return LocaleController.formatString("NotificationActionPinnedMusicChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedMusicChannel, chat2.title);
                        }
                        if (object2.isVideo()) {
                            if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object2.messageOwner.message)) {
                                return LocaleController.formatString("NotificationActionPinnedTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedTextChannel, chat2.title, "📹 " + object2.messageOwner.message);
                            }
                            return LocaleController.formatString("NotificationActionPinnedVideoChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedVideoChannel, chat2.title);
                        }
                        if (object2.isGif()) {
                            if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object2.messageOwner.message)) {
                                return LocaleController.formatString("NotificationActionPinnedTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedTextChannel, chat2.title, "🎬 " + object2.messageOwner.message);
                            }
                            return LocaleController.formatString("NotificationActionPinnedGifChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGifChannel, chat2.title);
                        }
                        if (object2.isVoice()) {
                            return LocaleController.formatString("NotificationActionPinnedVoiceChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedVoiceChannel, chat2.title);
                        }
                        if (object2.isRoundVideo()) {
                            return LocaleController.formatString("NotificationActionPinnedRoundChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedRoundChannel, chat2.title);
                        }
                        if (object2.isSticker() || object2.isAnimatedSticker()) {
                            String emoji2 = object2.getStickerEmoji();
                            return emoji2 != null ? LocaleController.formatString("NotificationActionPinnedStickerEmojiChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedStickerEmojiChannel, chat2.title, emoji2) : LocaleController.formatString("NotificationActionPinnedStickerChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedStickerChannel, chat2.title);
                        }
                        if (object2.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
                            if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object2.messageOwner.message)) {
                                return LocaleController.formatString("NotificationActionPinnedTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedTextChannel, chat2.title, "📎 " + object2.messageOwner.message);
                            }
                            return LocaleController.formatString("NotificationActionPinnedFileChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedFileChannel, chat2.title);
                        }
                        if ((object2.messageOwner.media instanceof TLRPC.TL_messageMediaGeo) || (object2.messageOwner.media instanceof TLRPC.TL_messageMediaVenue)) {
                            int i3 = 1;
                            char c5 = 0;
                            Object[] objArr4 = new Object[i3];
                            objArr4[c5] = chat2.title;
                            return LocaleController.formatString("NotificationActionPinnedGeoChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGeoChannel, objArr4);
                        }
                        if (object2.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive) {
                            return LocaleController.formatString("NotificationActionPinnedGeoLiveChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGeoLiveChannel, chat2.title);
                        }
                        if (object2.messageOwner.media instanceof TLRPC.TL_messageMediaContact) {
                            TLRPC.TL_messageMediaContact mediaContact2 = (TLRPC.TL_messageMediaContact) object2.messageOwner.media;
                            return LocaleController.formatString("NotificationActionPinnedContactChannel2", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedContactChannel2, chat2.title, ContactsController.formatName(mediaContact2.first_name, mediaContact2.last_name));
                        }
                        if (object2.messageOwner.media instanceof TLRPC.TL_messageMediaPoll) {
                            TLRPC.TL_messageMediaPoll mediaPoll2 = (TLRPC.TL_messageMediaPoll) object2.messageOwner.media;
                            return LocaleController.formatString("NotificationActionPinnedPollChannel2", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedPollChannel2, chat2.title, mediaPoll2.poll.question);
                        }
                        if (object2.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
                            if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(object2.messageOwner.message)) {
                                return LocaleController.formatString("NotificationActionPinnedTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedTextChannel, chat2.title, "🖼 " + object2.messageOwner.message);
                            }
                            return LocaleController.formatString("NotificationActionPinnedPhotoChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedPhotoChannel, chat2.title);
                        }
                        if (object2.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                            return LocaleController.formatString("NotificationActionPinnedGameChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedGameChannel, chat2.title);
                        }
                        if (object2.messageText != null && object2.messageText.length() > 0) {
                            CharSequence message2 = object2.messageText;
                            if (message2.length() <= 20) {
                                c = 0;
                            } else {
                                StringBuilder sb2 = new StringBuilder();
                                c = 0;
                                sb2.append((Object) message2.subSequence(0, 20));
                                sb2.append("...");
                                message2 = sb2.toString();
                            }
                            Object[] objArr5 = new Object[2];
                            objArr5[c] = chat2.title;
                            objArr5[1] = message2;
                            return LocaleController.formatString("NotificationActionPinnedTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedTextChannel, objArr5);
                        }
                        return LocaleController.formatString("NotificationActionPinnedNoTextChannel", mpEIGo.juqQQs.esbSDO.R.string.NotificationActionPinnedNoTextChannel, chat2.title);
                    }
                    if (messageObject.messageOwner.action instanceof TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer) {
                        TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer action = (TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer) messageObject.messageOwner.action;
                        if (action.trans == 0) {
                            TLRPC.User receiver = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(action.receiver.user_id));
                            TLRPC.User sender = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(action.sender.user_id));
                            TLApiModel<RedpacketResponse> parse = TLJsonResolve.parse(action.data, (Class<?>) RedpacketResponse.class);
                            RedpacketResponse bean = parse.model;
                            StringBuilder builder = new StringBuilder();
                            if (bean != null) {
                                if (messageObject.isOut()) {
                                    if (getUserConfig().clientUserId == action.sender.user_id) {
                                        builder.append(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouReceivedYourPacket));
                                    } else {
                                        builder.append(String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouReceivePacketFrom), UserObject.getName(sender)));
                                    }
                                } else if (getUserConfig().clientUserId == action.sender.user_id) {
                                    builder.append(UserObject.getName(receiver));
                                    builder.append(" ");
                                    builder.append(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.ReceivedYourPacket));
                                } else {
                                    builder.append(String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.WhoReceivePacketFrom), UserObject.getName(receiver), UserObject.getName(sender)));
                                }
                            }
                            return builder.toString();
                        }
                    }
                }
            } else {
                if (messageObject.isMediaEmpty()) {
                    if (!TextUtils.isEmpty(messageObject.messageText)) {
                        return messageObject.messageText.toString();
                    }
                    if (!TextUtils.isEmpty(messageObject.messageOwner.message)) {
                        return messageObject.messageOwner.message;
                    }
                    return LocaleController.getString("Message", mpEIGo.juqQQs.esbSDO.R.string.Message);
                }
                if (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) {
                    if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(messageObject.messageOwner.message)) {
                        return "🖼 " + messageObject.messageOwner.message;
                    }
                    if (messageObject.messageOwner.media.ttl_seconds != 0) {
                        return LocaleController.getString("AttachDestructingPhoto", mpEIGo.juqQQs.esbSDO.R.string.AttachDestructingPhoto);
                    }
                    return LocaleController.getString("AttachPhoto", mpEIGo.juqQQs.esbSDO.R.string.AttachPhoto);
                }
                if (messageObject.messageOwner.media instanceof TLRPCRedpacket.CL_messagesRpkTransferMedia) {
                    TLRPCRedpacket.CL_messagesRpkTransferMedia media = (TLRPCRedpacket.CL_messagesRpkTransferMedia) messageObject.messageOwner.media;
                    if (media.trans == 0) {
                        RedpacketResponse bean2 = null;
                        if (media.data != null) {
                            TLApiModel<RedpacketResponse> parse2 = TLJsonResolve.parse(media.data, (Class<?>) RedpacketResponse.class);
                            RedpacketResponse bean3 = parse2.model;
                            bean2 = bean3;
                        }
                        if (bean2 != null) {
                            RedpacketBean red = bean2.getRed();
                            TLRPC.User sender2 = getMessagesController().getUser(Integer.valueOf(red.getInitiatorUserIdInt()));
                            return String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.ReceiveRedPackFrom), UserObject.getName(sender2));
                        }
                        return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.ReceivePacketMessage);
                    }
                    if (media.trans == 1 || media.trans == 2) {
                        TransferResponse bean4 = null;
                        if (media.data != null) {
                            TLApiModel<TransferResponse> parse3 = TLJsonResolve.parse(media.data, (Class<?>) TransferResponse.class);
                            TransferResponse bean5 = parse3.model;
                            bean4 = bean5;
                        }
                        if (bean4 != null) {
                            TransferResponse.Status state = bean4.getState();
                            if (messageObject.isOutOwner()) {
                                if (state == TransferResponse.Status.WAITING) {
                                    return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferWaitingOtherCollect);
                                }
                                if (state == TransferResponse.Status.RECEIVED) {
                                    if (bean4.getInitiatorUserIdInt() == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                                        return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferOtherHasCollected);
                                    }
                                    return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouHaveConfirmedReceipt);
                                }
                                if (state == TransferResponse.Status.REFUSED) {
                                    if (bean4.getInitiatorUserIdInt() == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                                        return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferHasBeenReturned);
                                    }
                                    return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouHaveReturned);
                                }
                                if (state == TransferResponse.Status.TIMEOUT) {
                                    return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferHasReturned);
                                }
                            } else {
                                int sender_id = bean4.getInitiatorUserIdInt();
                                int receiver_id = Integer.parseInt(bean4.getRecipientUserId());
                                TLRPC.User sender3 = getMessagesController().getUser(Integer.valueOf(sender_id));
                                TLRPC.User receiver2 = getMessagesController().getUser(Integer.valueOf(receiver_id));
                                if (state == TransferResponse.Status.WAITING) {
                                    return String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferReceivedFromSomebody), UserObject.getName(sender3));
                                }
                                if (state == TransferResponse.Status.RECEIVED) {
                                    return sender_id == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId ? String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferReceivedBySomebody), UserObject.getName(receiver2)) : LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouHaveConfirmedReceipt);
                                }
                                if (state == TransferResponse.Status.REFUSED) {
                                    return sender_id == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId ? String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferReturnedBySomebody), UserObject.getName(receiver2)) : LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.YouHaveReturned);
                                }
                                if (state == TransferResponse.Status.TIMEOUT) {
                                    return String.format(LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferSendToSomebodyExpired), UserObject.getName(receiver2));
                                }
                            }
                        } else {
                            return LocaleController.getString(mpEIGo.juqQQs.esbSDO.R.string.TransferMessages);
                        }
                    }
                } else {
                    if (messageObject.isVideo()) {
                        if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(messageObject.messageOwner.message)) {
                            return "📹 " + messageObject.messageOwner.message;
                        }
                        if (messageObject.messageOwner.media.ttl_seconds != 0) {
                            return LocaleController.getString("AttachDestructingVideo", mpEIGo.juqQQs.esbSDO.R.string.AttachDestructingVideo);
                        }
                        return LocaleController.getString("AttachVideo", mpEIGo.juqQQs.esbSDO.R.string.AttachVideo);
                    }
                    if (messageObject.isGame()) {
                        return LocaleController.getString("AttachGame", mpEIGo.juqQQs.esbSDO.R.string.AttachGame);
                    }
                    if (messageObject.isVoice()) {
                        return LocaleController.getString("AttachAudio", mpEIGo.juqQQs.esbSDO.R.string.AttachAudio);
                    }
                    if (messageObject.isRoundVideo()) {
                        return LocaleController.getString("AttachRound", mpEIGo.juqQQs.esbSDO.R.string.AttachRound);
                    }
                    if (messageObject.isMusic()) {
                        return LocaleController.getString("AttachMusic", mpEIGo.juqQQs.esbSDO.R.string.AttachMusic);
                    }
                    if (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaContact) {
                        return LocaleController.getString("AttachContact", mpEIGo.juqQQs.esbSDO.R.string.AttachContact);
                    }
                    if (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaPoll) {
                        return LocaleController.getString("Poll", mpEIGo.juqQQs.esbSDO.R.string.Poll);
                    }
                    if ((messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGeo) || (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaVenue)) {
                        return LocaleController.getString("AttachLocation", mpEIGo.juqQQs.esbSDO.R.string.AttachLocation);
                    }
                    if (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive) {
                        return LocaleController.getString("AttachLiveLocation", mpEIGo.juqQQs.esbSDO.R.string.AttachLiveLocation);
                    }
                    if (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaDocument) {
                        if (messageObject.isSticker() || messageObject.isAnimatedSticker()) {
                            String emoji3 = messageObject.getStickerEmoji();
                            if (emoji3 != null) {
                                return emoji3 + " " + LocaleController.getString("AttachSticker", mpEIGo.juqQQs.esbSDO.R.string.AttachSticker);
                            }
                            return LocaleController.getString("AttachSticker", mpEIGo.juqQQs.esbSDO.R.string.AttachSticker);
                        }
                        if (messageObject.isGif()) {
                            if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(messageObject.messageOwner.message)) {
                                return "🎬 " + messageObject.messageOwner.message;
                            }
                            return LocaleController.getString("AttachGif", mpEIGo.juqQQs.esbSDO.R.string.AttachGif);
                        }
                        if (Build.VERSION.SDK_INT >= 19 && !TextUtils.isEmpty(messageObject.messageOwner.message)) {
                            return "📎 " + messageObject.messageOwner.message;
                        }
                        return LocaleController.getString("AttachDocument", mpEIGo.juqQQs.esbSDO.R.string.AttachDocument);
                    }
                }
            }
            return null;
        }
        if (preview != null) {
            preview[0] = false;
        }
        return LocaleController.getString("Message", mpEIGo.juqQQs.esbSDO.R.string.Message);
    }

    /* JADX WARN: Code restructure failed: missing block: B:331:0x08bb, code lost:
    
        if (r8.getBoolean("EnablePreviewChannel", true) != false) goto L332;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:324:0x08a2  */
    /* JADX WARN: Removed duplicated region for block: B:855:0x19b2  */
    /* JADX WARN: Removed duplicated region for block: B:857:0x19b6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private java.lang.String getStringForMessage(im.uwrkaxlmjj.messenger.MessageObject r24, boolean r25, boolean[] r26, boolean[] r27) {
        /*
            Method dump skipped, instruction units count: 6648
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.NotificationsController.getStringForMessage(im.uwrkaxlmjj.messenger.MessageObject, boolean, boolean[], boolean[]):java.lang.String");
    }

    private void scheduleNotificationRepeat() {
        try {
            Intent intent = new Intent(ApplicationLoader.applicationContext, (Class<?>) NotificationRepeat.class);
            intent.putExtra("currentAccount", this.currentAccount);
            PendingIntent pintent = PendingIntent.getService(ApplicationLoader.applicationContext, 0, intent, 0);
            SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
            int minutes = preferences.getInt("repeat_messages", 60);
            if (minutes > 0 && this.personal_count > 0) {
                this.alarmManager.set(2, SystemClock.elapsedRealtime() + ((long) (minutes * 60 * 1000)), pintent);
            } else {
                this.alarmManager.cancel(pintent);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private boolean isPersonalMessage(MessageObject messageObject) {
        return messageObject.messageOwner.to_id != null && messageObject.messageOwner.to_id.chat_id == 0 && messageObject.messageOwner.to_id.channel_id == 0 && (messageObject.messageOwner.action == null || (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionEmpty));
    }

    private int getNotifyOverride(SharedPreferences preferences, long dialog_id) {
        int notifyOverride = preferences.getInt("notify2_" + dialog_id, -1);
        if (notifyOverride == 3) {
            int muteUntil = preferences.getInt("notifyuntil_" + dialog_id, 0);
            if (muteUntil >= getConnectionsManager().getCurrentTime()) {
                return 2;
            }
            return notifyOverride;
        }
        return notifyOverride;
    }

    public /* synthetic */ void lambda$showNotifications$23$NotificationsController() {
        showOrUpdateNotification(false);
    }

    public void showNotifications() {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$FH1_c6TyRzktyXO2DoMX97nHAdA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$showNotifications$23$NotificationsController();
            }
        });
    }

    public void hideNotifications() {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$TP0c9Afor1JSAKNtZdlRrwdpllQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$hideNotifications$24$NotificationsController();
            }
        });
    }

    public /* synthetic */ void lambda$hideNotifications$24$NotificationsController() {
        notificationManager.cancel(this.notificationId);
        this.lastWearNotifiedMessageId.clear();
        for (int a = 0; a < this.wearNotificationsIds.size(); a++) {
            notificationManager.cancel(this.wearNotificationsIds.valueAt(a).intValue());
        }
        this.wearNotificationsIds.clear();
    }

    private void dismissNotification() {
        try {
            notificationManager.cancel(this.notificationId);
            this.pushMessages.clear();
            this.pushMessagesDict.clear();
            this.lastWearNotifiedMessageId.clear();
            for (int a = 0; a < this.wearNotificationsIds.size(); a++) {
                notificationManager.cancel(this.wearNotificationsIds.valueAt(a).intValue());
            }
            this.wearNotificationsIds.clear();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$qsmmMj6MDBL7fZIT74bxPWpneDY
                @Override // java.lang.Runnable
                public final void run() {
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.pushMessagesUpdated, new Object[0]);
                }
            });
            if (WearDataLayerListenerService.isWatchConnected()) {
                try {
                    JSONObject o = new JSONObject();
                    o.put(TtmlNode.ATTR_ID, getUserConfig().getClientUserId());
                    o.put("cancel_all", true);
                    WearDataLayerListenerService.sendMessageToWatch("/notify", o.toString().getBytes(), "remote_notifications");
                } catch (JSONException e) {
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    private void playInChatSound() {
        if (!this.inChatSoundEnabled || MediaController.getInstance().isRecordingAudio()) {
            return;
        }
        try {
            if (audioManager.getRingerMode() == 0) {
                return;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
            int notifyOverride = getNotifyOverride(preferences, this.opened_dialog_id);
            if (notifyOverride == 2) {
                return;
            }
            notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$0fTuDIbvGSQyJDA5SZhPVmJqqrk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$playInChatSound$27$NotificationsController();
                }
            });
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public /* synthetic */ void lambda$playInChatSound$27$NotificationsController() {
        if (Math.abs(System.currentTimeMillis() - this.lastSoundPlay) <= 500) {
            return;
        }
        try {
            if (this.soundPool == null) {
                SoundPool soundPool = new SoundPool(3, 1, 0);
                this.soundPool = soundPool;
                soundPool.setOnLoadCompleteListener(new SoundPool.OnLoadCompleteListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$vLaUO3R-s3vCu0i9TDfmeYVbhSc
                    @Override // android.media.SoundPool.OnLoadCompleteListener
                    public final void onLoadComplete(SoundPool soundPool2, int i, int i2) {
                        NotificationsController.lambda$null$26(soundPool2, i, i2);
                    }
                });
            }
            if (this.soundIn == 0 && !this.soundInLoaded) {
                this.soundInLoaded = true;
                this.soundIn = this.soundPool.load(ApplicationLoader.applicationContext, mpEIGo.juqQQs.esbSDO.R.raw.sound_in, 1);
            }
            if (this.soundIn != 0) {
                try {
                    this.soundPool.play(this.soundIn, 1.0f, 1.0f, 1, 0, 1.0f);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    static /* synthetic */ void lambda$null$26(SoundPool soundPool, int sampleId, int status) {
        if (status == 0) {
            try {
                soundPool.play(sampleId, 1.0f, 1.0f, 1, 0, 1.0f);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    private void scheduleNotificationDelay(boolean onlineReason) {
        try {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("delay notification start, onlineReason = " + onlineReason);
            }
            this.notificationDelayWakelock.acquire(OkHttpUtils.DEFAULT_MILLISECONDS);
            notificationsQueue.cancelRunnable(this.notificationDelayRunnable);
            notificationsQueue.postRunnable(this.notificationDelayRunnable, onlineReason ? 3000 : 1000);
        } catch (Exception e) {
            FileLog.e(e);
            showOrUpdateNotification(this.notifyCheck);
        }
    }

    protected void repeatNotificationMaybe() {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$p2v0FMbPowvnZHGS_FqwSYFBNtc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$repeatNotificationMaybe$28$NotificationsController();
            }
        });
    }

    public /* synthetic */ void lambda$repeatNotificationMaybe$28$NotificationsController() {
        int hour = Calendar.getInstance().get(11);
        if (hour >= 11 && hour <= 22) {
            notificationManager.cancel(this.notificationId);
            showOrUpdateNotification(true);
        } else {
            scheduleNotificationRepeat();
        }
    }

    private boolean isEmptyVibration(long[] pattern) {
        if (pattern == null || pattern.length == 0) {
            return false;
        }
        for (long j : pattern) {
            if (j != 0) {
                return false;
            }
        }
        return true;
    }

    public void deleteNotificationChannel(final long dialogId) {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$vRvTffZxcUOSeXEPF4xx-ekOPEk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteNotificationChannel$29$NotificationsController(dialogId);
            }
        });
    }

    public /* synthetic */ void lambda$deleteNotificationChannel$29$NotificationsController(long dialogId) {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        try {
            SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
            String key = "im.uwrkaxlmjj.key" + dialogId;
            String channelId = preferences.getString(key, null);
            if (channelId != null) {
                preferences.edit().remove(key).remove(key + "_s").commit();
                systemNotificationManager.deleteNotificationChannel(channelId);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void deleteAllNotificationChannels() {
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$3DOJ27aXMJEJ_YU8LZM4bPlALO0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteAllNotificationChannels$30$NotificationsController();
            }
        });
    }

    public /* synthetic */ void lambda$deleteAllNotificationChannels$30$NotificationsController() {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        try {
            SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
            Map<String, ?> values = preferences.getAll();
            SharedPreferences.Editor editor = preferences.edit();
            for (Map.Entry<String, ?> entry : values.entrySet()) {
                String key = entry.getKey();
                if (key.startsWith("im.uwrkaxlmjj.key")) {
                    if (!key.endsWith("_s")) {
                        systemNotificationManager.deleteNotificationChannel((String) entry.getValue());
                    }
                    editor.remove(key);
                }
            }
            editor.commit();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private String validateChannelId(long dialogId, String name, long[] vibrationPattern, int ledColor, Uri sound, int importance, long[] configVibrationPattern, Uri configSound, int configImportance) {
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        String key = "im.uwrkaxlmjj.key" + dialogId;
        String channelId = preferences.getString(key, null);
        String settings = preferences.getString(key + "_s", null);
        StringBuilder newSettings = new StringBuilder();
        for (long j : vibrationPattern) {
            newSettings.append(j);
        }
        newSettings.append(ledColor);
        if (sound != null) {
            newSettings.append(sound.toString());
        }
        newSettings.append(importance);
        String newSettingsHash = Utilities.MD5(newSettings.toString());
        if (channelId != null && !settings.equals(newSettingsHash)) {
            if (0 != 0) {
                preferences.edit().putString(key, channelId).putString(key + "_s", newSettingsHash).commit();
            } else {
                systemNotificationManager.deleteNotificationChannel(channelId);
                channelId = null;
            }
        }
        if (channelId == null) {
            channelId = this.currentAccount + "channel" + dialogId + "_" + Utilities.random.nextLong();
            NotificationChannel notificationChannel = new NotificationChannel(channelId, name, importance);
            if (ledColor != 0) {
                notificationChannel.enableLights(true);
                notificationChannel.setLightColor(ledColor);
            }
            if (!isEmptyVibration(vibrationPattern)) {
                notificationChannel.enableVibration(true);
                if (vibrationPattern != null && vibrationPattern.length > 0) {
                    notificationChannel.setVibrationPattern(vibrationPattern);
                }
            } else {
                notificationChannel.enableVibration(false);
            }
            AudioAttributes.Builder builder = new AudioAttributes.Builder();
            builder.setContentType(4);
            builder.setUsage(5);
            if (sound != null) {
                notificationChannel.setSound(sound, builder.build());
            } else {
                notificationChannel.setSound(null, builder.build());
            }
            systemNotificationManager.createNotificationChannel(notificationChannel);
            preferences.edit().putString(key, channelId).putString(key + "_s", newSettingsHash).commit();
        }
        return channelId;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:175:0x03c2  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x0444  */
    /* JADX WARN: Removed duplicated region for block: B:215:0x0451  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x048a A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:258:0x0524 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:267:0x055c A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:268:0x055e A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:274:0x0575 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:275:0x057a A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:278:0x0583 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:286:0x059e  */
    /* JADX WARN: Removed duplicated region for block: B:291:0x05ba A[Catch: Exception -> 0x0cd6, TRY_ENTER, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:295:0x05ed  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x05f9 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:302:0x0604 A[Catch: Exception -> 0x0cd6, TRY_LEAVE, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:305:0x060f A[Catch: Exception -> 0x0cd6, TRY_ENTER, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:306:0x0629 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:315:0x06d7  */
    /* JADX WARN: Removed duplicated region for block: B:318:0x06ea A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:330:0x0787 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:355:0x0883 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:378:0x08e2  */
    /* JADX WARN: Removed duplicated region for block: B:415:0x094d  */
    /* JADX WARN: Removed duplicated region for block: B:418:0x0953 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:469:0x0a57 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:470:0x0a61  */
    /* JADX WARN: Removed duplicated region for block: B:488:0x0abe A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:489:0x0ad1 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:514:0x0bfe  */
    /* JADX WARN: Removed duplicated region for block: B:517:0x0c10 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:525:0x0c38 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:526:0x0c51 A[Catch: Exception -> 0x0cd6, TryCatch #4 {Exception -> 0x0cd6, blocks: (B:66:0x0118, B:73:0x0168, B:75:0x0172, B:85:0x01d9, B:87:0x0214, B:93:0x0261, B:98:0x0272, B:118:0x0305, B:120:0x031e, B:143:0x035e, B:172:0x03ab, B:177:0x03c5, B:191:0x0403, B:193:0x0409, B:195:0x040f, B:196:0x0412, B:180:0x03d3, B:187:0x03ee, B:188:0x03fa, B:216:0x0457, B:218:0x048a, B:221:0x0495, B:223:0x049d, B:224:0x04a2, B:226:0x04a9, B:229:0x04af, B:231:0x04b8, B:234:0x04c0, B:236:0x04c4, B:238:0x04ca, B:240:0x04d4, B:242:0x04dc, B:265:0x0546, B:269:0x0560, B:271:0x0566, B:276:0x0580, B:278:0x0583, B:280:0x058e, B:282:0x0595, B:288:0x05ad, B:291:0x05ba, B:293:0x05c2, B:296:0x05ee, B:298:0x05f9, B:307:0x0661, B:310:0x06b2, B:312:0x06b6, B:314:0x06be, B:316:0x06d9, B:318:0x06ea, B:323:0x0712, B:329:0x0768, B:353:0x085b, B:355:0x0883, B:357:0x0892, B:413:0x0943, B:419:0x0955, B:430:0x099c, B:433:0x09a8, B:435:0x09b2, B:437:0x09b8, B:439:0x09c0, B:469:0x0a57, B:473:0x0a68, B:478:0x0a76, B:490:0x0aed, B:492:0x0af5, B:494:0x0af9, B:496:0x0b04, B:498:0x0b0a, B:501:0x0b1d, B:503:0x0b39, B:505:0x0b49, B:507:0x0b6a, B:508:0x0b71, B:510:0x0ba5, B:511:0x0bb9, B:517:0x0c10, B:519:0x0c16, B:521:0x0c1e, B:523:0x0c24, B:525:0x0c38, B:526:0x0c51, B:527:0x0c69, B:485:0x0a99, B:487:0x0ab0, B:488:0x0abe, B:440:0x09c8, B:441:0x09d2, B:443:0x09da, B:444:0x09e6, B:446:0x09ec, B:448:0x09f4, B:462:0x0a30, B:463:0x0a3a, B:425:0x0963, B:427:0x096b, B:429:0x0999, B:489:0x0ad1, B:401:0x0915, B:406:0x0925, B:409:0x0933, B:324:0x072d, B:326:0x0736, B:327:0x074d, B:330:0x0787, B:332:0x07b0, B:334:0x07c8, B:351:0x083e, B:339:0x07d9, B:340:0x07e0, B:344:0x07ef, B:345:0x0806, B:347:0x080b, B:348:0x0822, B:349:0x0838, B:352:0x084a, B:302:0x0604, B:305:0x060f, B:306:0x0629, B:294:0x05cf, B:287:0x05a0, B:274:0x0575, B:275:0x057a, B:245:0x04ed, B:247:0x04f1, B:249:0x04f7, B:251:0x0501, B:253:0x0509, B:258:0x0524, B:260:0x052d, B:262:0x0533, B:169:0x03a3, B:97:0x026b, B:101:0x0299, B:106:0x02aa, B:105:0x02a3, B:110:0x02d0, B:115:0x02e1, B:114:0x02da, B:76:0x018a, B:78:0x019e, B:79:0x01aa, B:81:0x01ae, B:159:0x038b), top: B:555:0x0118, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:530:0x0c6f  */
    /* JADX WARN: Removed duplicated region for block: B:532:0x0cad  */
    /* JADX WARN: Type inference failed for: r2v52, types: [androidx.core.app.NotificationCompat$Builder] */
    /* JADX WARN: Type inference failed for: r76v0, types: [im.uwrkaxlmjj.messenger.NotificationsController] */
    /* JADX WARN: Type inference failed for: r9v21 */
    /* JADX WARN: Type inference failed for: r9v22 */
    /* JADX WARN: Type inference failed for: r9v23 */
    /* JADX WARN: Type inference failed for: r9v24 */
    /* JADX WARN: Type inference failed for: r9v25 */
    /* JADX WARN: Type inference failed for: r9v49 */
    /* JADX WARN: Type inference failed for: r9v50 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void showOrUpdateNotification(boolean r77) {
        /*
            Method dump skipped, instruction units count: 3302
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.NotificationsController.showOrUpdateNotification(boolean):void");
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 10 */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 3 */
    /*  JADX ERROR: StackOverflowError in pass: DebugInfoApplyVisitor
        java.lang.StackOverflowError
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.verifyType(TypeUpdate.java:125)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:113)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.moveListener(TypeUpdate.java:454)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:202)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:480)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.runListeners(TypeUpdate.java:241)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.requestUpdate(TypeUpdate.java:225)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeForSsaVar(TypeUpdate.java:197)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.updateTypeChecked(TypeUpdate.java:119)
        	at jadx.core.dex.visitors.typeinference.TypeUpdate.allSameListener(TypeUpdate.java:473)
        */
    private void showExtraNotifications(androidx.core.app.NotificationCompat.Builder r72, boolean r73, java.lang.String r74) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException {
        /*
            Method dump skipped, instruction units count: 3697
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.NotificationsController.showExtraNotifications(androidx.core.app.NotificationCompat$Builder, boolean, java.lang.String):void");
    }

    private void loadRoundAvatar(File avatar, Person.Builder personBuilder) {
        if (avatar != null) {
            try {
                Bitmap bitmap = ImageDecoder.decodeBitmap(ImageDecoder.createSource(avatar), new ImageDecoder.OnHeaderDecodedListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$_tdtSCWLSMAxrc6TL2DFqraPCTA
                    @Override // android.graphics.ImageDecoder.OnHeaderDecodedListener
                    public final void onHeaderDecoded(ImageDecoder imageDecoder, ImageDecoder.ImageInfo imageInfo, ImageDecoder.Source source) {
                        imageDecoder.setPostProcessor(new PostProcessor() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$DM_XFJeJYTIdG75b4jcggcXyNYY
                            @Override // android.graphics.PostProcessor
                            public final int onPostProcess(Canvas canvas) {
                                return NotificationsController.lambda$null$32(canvas);
                            }
                        });
                    }
                });
                IconCompat icon = IconCompat.createWithBitmap(bitmap);
                personBuilder.setIcon(icon);
            } catch (Throwable th) {
            }
        }
    }

    static /* synthetic */ int lambda$null$32(Canvas canvas) {
        Path path = new Path();
        path.setFillType(Path.FillType.INVERSE_EVEN_ODD);
        int width = canvas.getWidth();
        int height = canvas.getHeight();
        path.addRoundRect(0.0f, 0.0f, width, height, width / 2, width / 2, Path.Direction.CW);
        Paint paint = new Paint();
        paint.setAntiAlias(true);
        paint.setColor(0);
        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC));
        canvas.drawPath(path, paint);
        return -3;
    }

    public void playOutChatSound() {
        if (!this.inChatSoundEnabled || MediaController.getInstance().isRecordingAudio()) {
            return;
        }
        try {
            if (audioManager.getRingerMode() == 0) {
                return;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        notificationsQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$8ir0WoJy4jXzHz6tN0Ko8phyN_Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$playOutChatSound$35$NotificationsController();
            }
        });
    }

    public /* synthetic */ void lambda$playOutChatSound$35$NotificationsController() {
        try {
            if (Math.abs(System.currentTimeMillis() - this.lastSoundOutPlay) <= 100) {
                return;
            }
            this.lastSoundOutPlay = System.currentTimeMillis();
            if (this.soundPool == null) {
                SoundPool soundPool = new SoundPool(3, 1, 0);
                this.soundPool = soundPool;
                soundPool.setOnLoadCompleteListener(new SoundPool.OnLoadCompleteListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$l7sbCw0iiiYX-2cWwmbEfG3G-kU
                    @Override // android.media.SoundPool.OnLoadCompleteListener
                    public final void onLoadComplete(SoundPool soundPool2, int i, int i2) {
                        NotificationsController.lambda$null$34(soundPool2, i, i2);
                    }
                });
            }
            if (this.soundOut == 0 && !this.soundOutLoaded) {
                this.soundOutLoaded = true;
                this.soundOut = this.soundPool.load(ApplicationLoader.applicationContext, mpEIGo.juqQQs.esbSDO.R.raw.sound_out, 1);
            }
            if (this.soundOut != 0) {
                try {
                    this.soundPool.play(this.soundOut, 1.0f, 1.0f, 1, 0, 1.0f);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    static /* synthetic */ void lambda$null$34(SoundPool soundPool, int sampleId, int status) {
        if (status == 0) {
            try {
                soundPool.play(sampleId, 1.0f, 1.0f, 1, 0, 1.0f);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public void setDialogNotificationsSettings(long dialog_id, int setting) {
        long flags;
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        SharedPreferences.Editor editor = preferences.edit();
        TLRPC.Dialog dialog = MessagesController.getInstance(UserConfig.selectedAccount).dialogs_dict.get(dialog_id);
        if (setting == 4) {
            boolean defaultEnabled = isGlobalNotificationsEnabled(dialog_id);
            if (defaultEnabled) {
                editor.remove("notify2_" + dialog_id);
            } else {
                editor.putInt("notify2_" + dialog_id, 0);
            }
            getMessagesStorage().setDialogFlags(dialog_id, 0L);
            if (dialog != null) {
                dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
            }
        } else {
            int untilTime = ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime();
            if (setting == 0) {
                untilTime += 3600;
            } else if (setting == 1) {
                untilTime += 28800;
            } else if (setting == 2) {
                untilTime += 172800;
            } else if (setting == 3) {
                untilTime = Integer.MAX_VALUE;
            }
            if (setting == 3) {
                editor.putInt("notify2_" + dialog_id, 2);
                flags = 1;
            } else {
                editor.putInt("notify2_" + dialog_id, 3);
                editor.putInt("notifyuntil_" + dialog_id, untilTime);
                flags = (((long) untilTime) << 32) | 1;
            }
            getInstance(UserConfig.selectedAccount).removeNotificationsForDialog(dialog_id);
            MessagesStorage.getInstance(UserConfig.selectedAccount).setDialogFlags(dialog_id, flags);
            if (dialog != null) {
                dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
                dialog.notify_settings.mute_until = untilTime;
            }
        }
        editor.commit();
        updateServerNotificationsSettings(dialog_id);
    }

    public void updateServerNotificationsSettings(long dialog_id) {
        updateServerNotificationsSettings(dialog_id, true);
    }

    public void updateServerNotificationsSettings(long dialog_id, boolean post) {
        if (post) {
            getNotificationCenter().postNotificationName(NotificationCenter.notificationsSettingsUpdated, new Object[0]);
        }
        if (((int) dialog_id) == 0) {
            return;
        }
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        TLRPC.TL_account_updateNotifySettings req = new TLRPC.TL_account_updateNotifySettings();
        req.settings = new TLRPC.TL_inputPeerNotifySettings();
        req.settings.flags |= 1;
        req.settings.show_previews = preferences.getBoolean("content_preview_" + dialog_id, true);
        TLRPC.TL_inputPeerNotifySettings tL_inputPeerNotifySettings = req.settings;
        tL_inputPeerNotifySettings.flags = tL_inputPeerNotifySettings.flags | 2;
        req.settings.silent = preferences.getBoolean("silent_" + dialog_id, false);
        int mute_type = preferences.getInt("notify2_" + dialog_id, -1);
        if (mute_type != -1) {
            req.settings.flags |= 4;
            if (mute_type == 3) {
                req.settings.mute_until = preferences.getInt("notifyuntil_" + dialog_id, 0);
            } else {
                req.settings.mute_until = mute_type == 2 ? Integer.MAX_VALUE : 0;
            }
        }
        req.peer = new TLRPC.TL_inputNotifyPeer();
        ((TLRPC.TL_inputNotifyPeer) req.peer).peer = getMessagesController().getInputPeer((int) dialog_id);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$mfutCYKGxlYydHlNvkHi5mBVpFU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                NotificationsController.lambda$updateServerNotificationsSettings$36(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$updateServerNotificationsSettings$36(TLObject response, TLRPC.TL_error error) {
    }

    public void updateServerNotificationsSettings(int type) {
        SharedPreferences preferences = getAccountInstance().getNotificationsSettings();
        TLRPC.TL_account_updateNotifySettings req = new TLRPC.TL_account_updateNotifySettings();
        req.settings = new TLRPC.TL_inputPeerNotifySettings();
        req.settings.flags = 5;
        if (type == 0) {
            req.peer = new TLRPC.TL_inputNotifyChats();
            req.settings.mute_until = preferences.getInt("EnableGroup2", 0);
            req.settings.show_previews = preferences.getBoolean("EnablePreviewGroup", true);
        } else if (type == 1) {
            req.peer = new TLRPC.TL_inputNotifyUsers();
            req.settings.mute_until = preferences.getInt("EnableAll2", 0);
            req.settings.show_previews = preferences.getBoolean("EnablePreviewAll", true);
        } else {
            req.peer = new TLRPC.TL_inputNotifyBroadcasts();
            req.settings.mute_until = preferences.getInt("EnableChannel2", 0);
            req.settings.show_previews = preferences.getBoolean("EnablePreviewChannel", true);
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$NotificationsController$BmnarN4JSUzvAWEqyzJNrvM0I_8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                NotificationsController.lambda$updateServerNotificationsSettings$37(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$updateServerNotificationsSettings$37(TLObject response, TLRPC.TL_error error) {
    }

    public boolean isGlobalNotificationsEnabled(long did) {
        int type;
        int lower_id = (int) did;
        if (lower_id < 0) {
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(-lower_id));
            if (ChatObject.isChannel(chat) && !chat.megagroup) {
                type = 2;
            } else {
                type = 0;
            }
        } else {
            type = 1;
        }
        return isGlobalNotificationsEnabled(type);
    }

    public boolean isGlobalNotificationsEnabled(int type) {
        return getAccountInstance().getNotificationsSettings().getInt(getGlobalNotificationsKey(type), 0) < getConnectionsManager().getCurrentTime();
    }

    public void setGlobalNotificationsEnabled(int type, int time) {
        getAccountInstance().getNotificationsSettings().edit().putInt(getGlobalNotificationsKey(type), time).commit();
        updateServerNotificationsSettings(type);
    }

    public String getGlobalNotificationsKey(int type) {
        if (type == 0) {
            return "EnableGroup2";
        }
        if (type == 1) {
            return "EnableAll2";
        }
        return "EnableChannel2";
    }
}
