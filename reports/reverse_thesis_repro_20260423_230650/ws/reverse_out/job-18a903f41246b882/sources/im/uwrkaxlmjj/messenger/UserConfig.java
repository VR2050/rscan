package im.uwrkaxlmjj.messenger;

import android.content.SharedPreferences;
import android.os.SystemClock;
import android.util.Base64;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.utils.AppUpdater;
import java.io.File;
import org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher;

/* JADX INFO: loaded from: classes2.dex */
public class UserConfig extends BaseController {
    private static volatile UserConfig[] Instance = new UserConfig[3];
    public static final int MAX_ACCOUNT_COUNT = 3;
    public static final int i_dialogsLoadOffsetAccess_1 = 5;
    public static final int i_dialogsLoadOffsetAccess_2 = 6;
    public static final int i_dialogsLoadOffsetChannelId = 4;
    public static final int i_dialogsLoadOffsetChatId = 3;
    public static final int i_dialogsLoadOffsetDate = 1;
    public static final int i_dialogsLoadOffsetId = 0;
    public static final int i_dialogsLoadOffsetUserId = 2;
    public static int selectedAccount;
    public long autoDownloadConfigLoadTime;
    public int botRatingLoadTime;
    public int clientUserId;
    private boolean configLoaded;
    public boolean contactsReimported;
    public int contactsSavedCount;
    private TLRPC.User currentUser;
    public boolean draftsLoaded;
    public boolean hasSecureData;
    public boolean hasValidDialogLoadIds;
    public int isCdnVip;
    public int lastBroadcastId;
    public int lastContactsSyncTime;
    public int lastHintsSyncTime;
    public int lastSendMessageId;
    public int loginTime;
    public long migrateOffsetAccess;
    public int migrateOffsetChannelId;
    public int migrateOffsetChatId;
    public int migrateOffsetDate;
    public int migrateOffsetId;
    public int migrateOffsetUserId;
    public boolean notificationsSettingsLoaded;
    public boolean notificationsSignUpSettingsLoaded;
    public int ratingLoadTime;
    public boolean registeredForPush;
    public volatile byte[] savedPasswordHash;
    public volatile long savedPasswordTime;
    public volatile byte[] savedSaltedPassword;
    public boolean suggestContacts;
    private final Object sync;
    public boolean syncContacts;
    public TLRPC.TL_account_tmpPassword tmpPassword;
    public TLRPC.TL_help_termsOfService unacceptedTermsOfService;
    public boolean unreadDialogsLoaded;

    public static UserConfig getInstance(int num) {
        UserConfig localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (UserConfig.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    UserConfig[] userConfigArr = Instance;
                    UserConfig userConfig = new UserConfig(num);
                    localInstance = userConfig;
                    userConfigArr[num] = userConfig;
                }
            }
        }
        return localInstance;
    }

    public UserConfig(int instance) {
        super(instance);
        this.sync = new Object();
        this.lastSendMessageId = -210000;
        this.lastBroadcastId = -1;
        this.unreadDialogsLoaded = true;
        this.migrateOffsetId = -1;
        this.migrateOffsetDate = -1;
        this.migrateOffsetUserId = -1;
        this.migrateOffsetChatId = -1;
        this.migrateOffsetChannelId = -1;
        this.migrateOffsetAccess = -1L;
        this.suggestContacts = true;
        this.syncContacts = true;
        this.isCdnVip = -1;
    }

    private SharedPreferences getPreferences() {
        if (this.currentAccount == 0) {
            return ApplicationLoader.applicationContext.getSharedPreferences("userconfing", 0);
        }
        return ApplicationLoader.applicationContext.getSharedPreferences("userconfig" + this.currentAccount, 0);
    }

    public static int getActivatedAccountsCount() {
        int count = 0;
        for (int a = 0; a < 3; a++) {
            if (AccountInstance.getInstance(a).getUserConfig().isClientActivated()) {
                count++;
            }
        }
        return count;
    }

    public int getNewMessageId() {
        int id;
        synchronized (this.sync) {
            id = this.lastSendMessageId;
            this.lastSendMessageId--;
        }
        return id;
    }

    public void saveConfig(boolean withFile) {
        saveConfig(withFile, null);
    }

    public void saveConfig(boolean withFile, File oldFile) {
        synchronized (this.sync) {
            try {
                SharedPreferences.Editor editor = getPreferences().edit();
                if (this.currentAccount == 0) {
                    editor.putInt("selectedAccount", selectedAccount);
                }
                editor.putBoolean("registeredForPush", this.registeredForPush);
                editor.putInt("lastSendMessageId", this.lastSendMessageId);
                editor.putInt("contactsSavedCount", this.contactsSavedCount);
                editor.putInt("lastBroadcastId", this.lastBroadcastId);
                editor.putInt("lastContactsSyncTime", this.lastContactsSyncTime);
                editor.putInt("lastHintsSyncTime", this.lastHintsSyncTime);
                editor.putBoolean("draftsLoaded", this.draftsLoaded);
                editor.putBoolean("unreadDialogsLoaded", this.unreadDialogsLoaded);
                editor.putInt("ratingLoadTime", this.ratingLoadTime);
                editor.putInt("botRatingLoadTime", this.botRatingLoadTime);
                editor.putBoolean("contactsReimported", this.contactsReimported);
                editor.putInt("loginTime", this.loginTime);
                editor.putBoolean("syncContacts", this.syncContacts);
                editor.putBoolean("suggestContacts", this.suggestContacts);
                editor.putBoolean("hasSecureData", this.hasSecureData);
                editor.putBoolean("notificationsSettingsLoaded3", this.notificationsSettingsLoaded);
                editor.putBoolean("notificationsSignUpSettingsLoaded", this.notificationsSignUpSettingsLoaded);
                editor.putLong("autoDownloadConfigLoadTime", this.autoDownloadConfigLoadTime);
                editor.putBoolean("hasValidDialogLoadIds", this.hasValidDialogLoadIds);
                editor.putInt("6migrateOffsetId", this.migrateOffsetId);
                if (this.migrateOffsetId != -1) {
                    editor.putInt("6migrateOffsetDate", this.migrateOffsetDate);
                    editor.putInt("6migrateOffsetUserId", this.migrateOffsetUserId);
                    editor.putInt("6migrateOffsetChatId", this.migrateOffsetChatId);
                    editor.putInt("6migrateOffsetChannelId", this.migrateOffsetChannelId);
                    editor.putLong("6migrateOffsetAccess", this.migrateOffsetAccess);
                }
                if (this.unacceptedTermsOfService != null) {
                    try {
                        SerializedData data = new SerializedData(this.unacceptedTermsOfService.getObjectSize());
                        this.unacceptedTermsOfService.serializeToStream(data);
                        String str = Base64.encodeToString(data.toByteArray(), 0);
                        editor.putString("terms", str);
                        data.cleanup();
                    } catch (Exception e) {
                    }
                } else {
                    editor.remove("terms");
                }
                SharedConfig.saveConfig();
                if (this.tmpPassword != null) {
                    SerializedData data2 = new SerializedData();
                    this.tmpPassword.serializeToStream(data2);
                    String string = Base64.encodeToString(data2.toByteArray(), 0);
                    editor.putString("tmpPassword", string);
                    data2.cleanup();
                } else {
                    editor.remove("tmpPassword");
                }
                if (this.currentUser != null) {
                    if (withFile) {
                        SerializedData data3 = new SerializedData();
                        this.currentUser.serializeToStream(data3);
                        String string2 = Base64.encodeToString(data3.toByteArray(), 0);
                        editor.putString(AudioDeviceSwitcher.AUDIO_DEVICE_SWITCH_SOURCE_USER, string2);
                        data3.cleanup();
                    }
                } else {
                    editor.remove(AudioDeviceSwitcher.AUDIO_DEVICE_SWITCH_SOURCE_USER);
                }
                editor.commit();
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            if (oldFile != null) {
                oldFile.delete();
            }
        }
    }

    public boolean isClientActivated() {
        boolean z;
        synchronized (this.sync) {
            z = this.currentUser != null;
        }
        return z;
    }

    public int getClientUserId() {
        int i;
        synchronized (this.sync) {
            i = this.currentUser != null ? this.currentUser.id : 0;
        }
        return i;
    }

    public String getClientPhone() {
        String str;
        synchronized (this.sync) {
            str = (this.currentUser == null || this.currentUser.phone == null) ? "" : this.currentUser.phone;
        }
        return str;
    }

    public TLRPC.User getCurrentUser() {
        TLRPC.User user;
        synchronized (this.sync) {
            user = this.currentUser;
        }
        return user;
    }

    public void setCurrentUser(TLRPC.User user) {
        synchronized (this.sync) {
            this.currentUser = user;
            this.clientUserId = user.id;
        }
    }

    public void loadConfig() {
        byte[] bytes;
        byte[] bytes2;
        byte[] arr;
        synchronized (this.sync) {
            if (this.configLoaded) {
                return;
            }
            SharedPreferences preferences = getPreferences();
            if (this.currentAccount == 0) {
                selectedAccount = preferences.getInt("selectedAccount", 0);
            }
            this.registeredForPush = preferences.getBoolean("registeredForPush", false);
            this.lastSendMessageId = preferences.getInt("lastSendMessageId", -210000);
            this.contactsSavedCount = preferences.getInt("contactsSavedCount", 0);
            this.lastBroadcastId = preferences.getInt("lastBroadcastId", -1);
            this.lastContactsSyncTime = preferences.getInt("lastContactsSyncTime", ((int) (System.currentTimeMillis() / 1000)) - 82800);
            this.lastHintsSyncTime = preferences.getInt("lastHintsSyncTime", ((int) (System.currentTimeMillis() / 1000)) - 90000);
            this.draftsLoaded = preferences.getBoolean("draftsLoaded", false);
            this.unreadDialogsLoaded = preferences.getBoolean("unreadDialogsLoaded", false);
            this.contactsReimported = preferences.getBoolean("contactsReimported", false);
            this.ratingLoadTime = preferences.getInt("ratingLoadTime", 0);
            this.botRatingLoadTime = preferences.getInt("botRatingLoadTime", 0);
            this.loginTime = preferences.getInt("loginTime", this.currentAccount);
            this.syncContacts = preferences.getBoolean("syncContacts", true);
            this.suggestContacts = preferences.getBoolean("suggestContacts", true);
            this.hasSecureData = preferences.getBoolean("hasSecureData", false);
            this.notificationsSettingsLoaded = preferences.getBoolean("notificationsSettingsLoaded3", false);
            this.notificationsSignUpSettingsLoaded = preferences.getBoolean("notificationsSignUpSettingsLoaded", false);
            this.autoDownloadConfigLoadTime = preferences.getLong("autoDownloadConfigLoadTime", 0L);
            this.hasValidDialogLoadIds = preferences.contains("2dialogsLoadOffsetId") || preferences.getBoolean("hasValidDialogLoadIds", false);
            try {
                String terms = preferences.getString("terms", null);
                if (terms != null && (arr = Base64.decode(terms, 0)) != null) {
                    SerializedData data = new SerializedData(arr);
                    this.unacceptedTermsOfService = TLRPC.TL_help_termsOfService.TLdeserialize(data, data.readInt32(false), false);
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            int i = preferences.getInt("6migrateOffsetId", 0);
            this.migrateOffsetId = i;
            if (i != -1) {
                this.migrateOffsetDate = preferences.getInt("6migrateOffsetDate", 0);
                this.migrateOffsetUserId = preferences.getInt("6migrateOffsetUserId", 0);
                this.migrateOffsetChatId = preferences.getInt("6migrateOffsetChatId", 0);
                this.migrateOffsetChannelId = preferences.getInt("6migrateOffsetChannelId", 0);
                this.migrateOffsetAccess = preferences.getLong("6migrateOffsetAccess", 0L);
            }
            String string = preferences.getString("tmpPassword", null);
            if (string != null && (bytes2 = Base64.decode(string, 0)) != null) {
                SerializedData data2 = new SerializedData(bytes2);
                this.tmpPassword = TLRPC.TL_account_tmpPassword.TLdeserialize(data2, data2.readInt32(false), false);
                data2.cleanup();
            }
            String string2 = preferences.getString(AudioDeviceSwitcher.AUDIO_DEVICE_SWITCH_SOURCE_USER, null);
            if (string2 != null && (bytes = Base64.decode(string2, 0)) != null) {
                SerializedData data3 = new SerializedData(bytes);
                this.currentUser = TLRPC.User.TLdeserialize(data3, data3.readInt32(false), false);
                data3.cleanup();
            }
            if (this.currentUser != null) {
                this.clientUserId = this.currentUser.id;
            }
            this.configLoaded = true;
        }
    }

    public void savePassword(byte[] hash, byte[] salted) {
        this.savedPasswordTime = SystemClock.elapsedRealtime();
        this.savedPasswordHash = hash;
        this.savedSaltedPassword = salted;
    }

    public void checkSavedPassword() {
        if ((this.savedSaltedPassword == null && this.savedPasswordHash == null) || Math.abs(SystemClock.elapsedRealtime() - this.savedPasswordTime) < 1800000) {
            return;
        }
        resetSavedPassword();
    }

    public void resetSavedPassword() {
        this.savedPasswordTime = 0L;
        if (this.savedPasswordHash != null) {
            for (int a = 0; a < this.savedPasswordHash.length; a++) {
                this.savedPasswordHash[a] = 0;
            }
            this.savedPasswordHash = null;
        }
        if (this.savedSaltedPassword != null) {
            for (int a2 = 0; a2 < this.savedSaltedPassword.length; a2++) {
                this.savedSaltedPassword[a2] = 0;
            }
            this.savedSaltedPassword = null;
        }
    }

    public void clearConfig() {
        getPreferences().edit().clear().commit();
        this.currentUser = null;
        this.clientUserId = 0;
        this.registeredForPush = false;
        this.contactsSavedCount = 0;
        this.lastSendMessageId = -210000;
        this.lastBroadcastId = -1;
        this.notificationsSettingsLoaded = false;
        this.notificationsSignUpSettingsLoaded = false;
        this.migrateOffsetId = -1;
        this.migrateOffsetDate = -1;
        this.migrateOffsetUserId = -1;
        this.migrateOffsetChatId = -1;
        this.migrateOffsetChannelId = -1;
        this.migrateOffsetAccess = -1L;
        this.ratingLoadTime = 0;
        this.botRatingLoadTime = 0;
        this.draftsLoaded = true;
        this.contactsReimported = true;
        this.syncContacts = true;
        this.suggestContacts = true;
        this.unreadDialogsLoaded = true;
        this.hasValidDialogLoadIds = true;
        this.unacceptedTermsOfService = null;
        this.hasSecureData = false;
        this.loginTime = (int) (System.currentTimeMillis() / 1000);
        this.lastContactsSyncTime = ((int) (System.currentTimeMillis() / 1000)) - 82800;
        this.lastHintsSyncTime = ((int) (System.currentTimeMillis() / 1000)) - 90000;
        AppUpdater.pendingAppUpdate = null;
        resetSavedPassword();
        boolean hasActivated = false;
        int a = 0;
        while (true) {
            if (a >= 3) {
                break;
            }
            if (!AccountInstance.getInstance(a).getUserConfig().isClientActivated()) {
                a++;
            } else {
                hasActivated = true;
                break;
            }
        }
        if (!hasActivated) {
            SharedConfig.clearConfig();
        }
        saveConfig(true);
    }

    public boolean isPinnedDialogsLoaded(int folderId) {
        return getPreferences().getBoolean("2pinnedDialogsLoaded" + folderId, false);
    }

    public void setPinnedDialogsLoaded(int folderId, boolean loaded) {
        getPreferences().edit().putBoolean("2pinnedDialogsLoaded" + folderId, loaded).commit();
    }

    public int getTotalDialogsCount(int folderId) {
        SharedPreferences preferences = getPreferences();
        StringBuilder sb = new StringBuilder();
        sb.append("2totalDialogsLoadCount");
        sb.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        return preferences.getInt(sb.toString(), 0);
    }

    public void setTotalDialogsCount(int folderId, int totalDialogsLoadCount) {
        SharedPreferences.Editor editorEdit = getPreferences().edit();
        StringBuilder sb = new StringBuilder();
        sb.append("2totalDialogsLoadCount");
        sb.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        editorEdit.putInt(sb.toString(), totalDialogsLoadCount).commit();
    }

    public int[] getDialogLoadOffsets(int folderId) {
        SharedPreferences preferences = getPreferences();
        StringBuilder sb = new StringBuilder();
        sb.append("2dialogsLoadOffsetId");
        sb.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        int dialogsLoadOffsetId = preferences.getInt(sb.toString(), this.hasValidDialogLoadIds ? 0 : -1);
        StringBuilder sb2 = new StringBuilder();
        sb2.append("2dialogsLoadOffsetDate");
        sb2.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        int dialogsLoadOffsetDate = preferences.getInt(sb2.toString(), this.hasValidDialogLoadIds ? 0 : -1);
        StringBuilder sb3 = new StringBuilder();
        sb3.append("2dialogsLoadOffsetUserId");
        sb3.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        int dialogsLoadOffsetUserId = preferences.getInt(sb3.toString(), this.hasValidDialogLoadIds ? 0 : -1);
        StringBuilder sb4 = new StringBuilder();
        sb4.append("2dialogsLoadOffsetChatId");
        sb4.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        int dialogsLoadOffsetChatId = preferences.getInt(sb4.toString(), this.hasValidDialogLoadIds ? 0 : -1);
        StringBuilder sb5 = new StringBuilder();
        sb5.append("2dialogsLoadOffsetChannelId");
        sb5.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        int dialogsLoadOffsetChannelId = preferences.getInt(sb5.toString(), this.hasValidDialogLoadIds ? 0 : -1);
        StringBuilder sb6 = new StringBuilder();
        sb6.append("2dialogsLoadOffsetAccess");
        sb6.append(folderId != 0 ? Integer.valueOf(folderId) : "");
        long dialogsLoadOffsetAccess = preferences.getLong(sb6.toString(), this.hasValidDialogLoadIds ? 0L : -1L);
        return new int[]{dialogsLoadOffsetId, dialogsLoadOffsetDate, dialogsLoadOffsetUserId, dialogsLoadOffsetChatId, dialogsLoadOffsetChannelId, (int) dialogsLoadOffsetAccess, (int) (dialogsLoadOffsetAccess >> 32)};
    }

    public void setDialogsLoadOffset(int folderId, int dialogsLoadOffsetId, int dialogsLoadOffsetDate, int dialogsLoadOffsetUserId, int dialogsLoadOffsetChatId, int dialogsLoadOffsetChannelId, long dialogsLoadOffsetAccess) {
        SharedPreferences.Editor editor = getPreferences().edit();
        StringBuilder sb = new StringBuilder();
        sb.append("2dialogsLoadOffsetId");
        sb.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        editor.putInt(sb.toString(), dialogsLoadOffsetId);
        StringBuilder sb2 = new StringBuilder();
        sb2.append("2dialogsLoadOffsetDate");
        sb2.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        editor.putInt(sb2.toString(), dialogsLoadOffsetDate);
        StringBuilder sb3 = new StringBuilder();
        sb3.append("2dialogsLoadOffsetUserId");
        sb3.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        editor.putInt(sb3.toString(), dialogsLoadOffsetUserId);
        StringBuilder sb4 = new StringBuilder();
        sb4.append("2dialogsLoadOffsetChatId");
        sb4.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        editor.putInt(sb4.toString(), dialogsLoadOffsetChatId);
        StringBuilder sb5 = new StringBuilder();
        sb5.append("2dialogsLoadOffsetChannelId");
        sb5.append(folderId == 0 ? "" : Integer.valueOf(folderId));
        editor.putInt(sb5.toString(), dialogsLoadOffsetChannelId);
        StringBuilder sb6 = new StringBuilder();
        sb6.append("2dialogsLoadOffsetAccess");
        sb6.append(folderId != 0 ? Integer.valueOf(folderId) : "");
        editor.putLong(sb6.toString(), dialogsLoadOffsetAccess);
        editor.putBoolean("hasValidDialogLoadIds", true);
        editor.commit();
    }
}
