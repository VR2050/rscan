package im.uwrkaxlmjj.messenger;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import android.util.SparseIntArray;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import com.just.agentweb.DefaultWebClient;
import com.king.zxing.util.CodeUtils;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.javaBean.fc.FollowedFcListBean;
import im.uwrkaxlmjj.javaBean.fc.HomeFcListBean;
import im.uwrkaxlmjj.javaBean.fc.RecommendFcListBean;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.support.SparseLongArray;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCChats;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.ProfileActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.FcDBHelper;
import im.uwrkaxlmjj.ui.hviews.helper.MryDeviceHelper;
import java.io.File;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes2.dex */
public class MessagesController extends BaseController implements NotificationCenter.NotificationCenterDelegate {
    private static volatile MessagesController[] Instance = new MessagesController[3];
    public static final int UPDATE_MASK_ALL = 1535;
    public static final int UPDATE_MASK_AVATAR = 2;
    public static final int UPDATE_MASK_CHAT = 8192;
    public static final int UPDATE_MASK_CHAT_AVATAR = 8;
    public static final int UPDATE_MASK_CHAT_MEMBERS = 32;
    public static final int UPDATE_MASK_CHAT_NAME = 16;
    public static final int UPDATE_MASK_CHECK = 65536;
    public static final int UPDATE_MASK_MESSAGE_TEXT = 32768;
    public static final int UPDATE_MASK_NAME = 1;
    public static final int UPDATE_MASK_NEW_MESSAGE = 2048;
    public static final int UPDATE_MASK_PHONE = 1024;
    public static final int UPDATE_MASK_READ_DIALOG_MESSAGE = 256;
    public static final int UPDATE_MASK_REORDER = 131072;
    public static final int UPDATE_MASK_SELECT_DIALOG = 512;
    public static final int UPDATE_MASK_SEND_STATE = 4096;
    public static final int UPDATE_MASK_STATUS = 4;
    public static final int UPDATE_MASK_USER_PHONE = 128;
    public static final int UPDATE_MASK_USER_PRINT = 64;
    private static volatile long lastPasswordCheckTime;
    private static volatile long lastThemeCheckTime;
    private int DIALOGS_LOAD_TYPE_CACHE;
    private int DIALOGS_LOAD_TYPE_CHANNEL;
    private int DIALOGS_LOAD_TYPE_UNKNOWN;
    protected ArrayList<TLRPC.Dialog> allDialogs;
    public float animatedEmojisZoom;
    public int availableMapProviders;
    public boolean blockedCountry;
    public boolean blockedEndReached;
    public SparseIntArray blockedUsers;
    public int callConnectTimeout;
    public int callPacketTimeout;
    public int callReceiveTimeout;
    public int callRingTimeout;
    public boolean canRevokePmInbox;
    private SparseArray<SparseArray<String>> channelAdmins;
    private SparseArray<ArrayList<Integer>> channelViewsToSend;
    private SparseIntArray channelsPts;
    private ConcurrentHashMap<Integer, TLRPC.Chat> chats;
    private SparseBooleanArray checkingLastMessagesDialogs;
    private boolean checkingProxyInfo;
    private int checkingProxyInfoRequestId;
    private boolean checkingTosUpdate;
    private LongSparseArray<TLRPC.Dialog> clearingHistoryDialogs;
    private boolean contactsGetDiff;
    private ArrayList<Long> createdDialogIds;
    private ArrayList<Long> createdDialogMainThreadIds;
    private ArrayList<Long> createdScheduledDialogIds;
    private Runnable currentDeleteTaskRunnable;
    private int currentDeletingTaskChannelId;
    private ArrayList<Integer> currentDeletingTaskMids;
    private int currentDeletingTaskTime;
    public String dcDomainName;
    public boolean defaultP2pContacts;
    public LongSparseArray<Integer> deletedHistory;
    private LongSparseArray<TLRPC.Dialog> deletingDialogs;
    private final Comparator<TLRPC.Dialog> dialogComparator;
    public LongSparseArray<MessageObject> dialogMessage;
    public SparseArray<MessageObject> dialogMessagesByIds;
    public LongSparseArray<MessageObject> dialogMessagesByRandomIds;
    private SparseArray<ArrayList<TLRPC.Dialog>> dialogsByFolder;
    public ArrayList<TLRPC.Dialog> dialogsCanAddUsers;
    public ArrayList<TLRPC.Dialog> dialogsChannelsOnly;
    private SparseBooleanArray dialogsEndReached;
    public ArrayList<TLRPC.Dialog> dialogsForward;
    public ArrayList<TLRPC.Dialog> dialogsGroupsOnly;
    private boolean dialogsInTransaction;
    public boolean dialogsLoaded;
    public ArrayList<TLRPC.Dialog> dialogsServerOnly;
    public ArrayList<TLRPC.Dialog> dialogsUnreadOnly;
    public ArrayList<TLRPC.Dialog> dialogsUsersOnly;
    public LongSparseArray<TLRPC.Dialog> dialogs_dict;
    public ConcurrentHashMap<Long, Integer> dialogs_read_inbox_max;
    public ConcurrentHashMap<Long, Integer> dialogs_read_outbox_max;
    private SharedPreferences emojiPreferences;
    public boolean enableDigitCoin;
    public boolean enableHub;
    public boolean enableJoined;
    public boolean enableWallet;
    private ConcurrentHashMap<Integer, TLRPC.EncryptedChat> encryptedChats;
    private SparseArray<TLRPC.ExportedChatInvite> exportedChats;
    public boolean firstGettingTask;
    private SparseArray<TLRPC.ChatFull> fullChats;
    private SparseArray<TLRPC.UserFull> fullUsers;
    private boolean getDifferenceFirstSync;
    public boolean gettingDifference;
    private SparseBooleanArray gettingDifferenceChannels;
    private boolean gettingNewDeleteTask;
    private SparseBooleanArray gettingUnknownChannels;
    private LongSparseArray<Boolean> gettingUnknownDialogs;
    public String gifSearchBot;
    public ArrayList<TLRPC.RecentMeUrl> hintDialogs;
    public String imageSearchBot;
    private String installReferer;
    private boolean isLeftProxyChannel;
    private ArrayList<Integer> joiningToChannels;
    private int lastCheckProxyId;
    private int lastPrintingStringCount;
    private long lastPushRegisterSendTime;
    private LongSparseArray<Long> lastScheduledServerQueryTime;
    private long lastStatusUpdateTime;
    private long lastViewsCheckTime;
    public String linkPrefix;
    private ArrayList<Integer> loadedFullChats;
    private ArrayList<Integer> loadedFullParticipants;
    private ArrayList<Integer> loadedFullUsers;
    private boolean loadingAppConfig;
    public boolean loadingBlockedUsers;
    private SparseIntArray loadingChannelAdmins;
    private SparseBooleanArray loadingDialogs;
    private ArrayList<Integer> loadingFullChats;
    private ArrayList<Integer> loadingFullParticipants;
    private ArrayList<Integer> loadingFullUsers;
    private int loadingNotificationSettings;
    private boolean loadingNotificationSignUpSettings;
    private LongSparseArray<Boolean> loadingPeerSettings;
    private SparseIntArray loadingPinnedDialogs;
    private boolean loadingUnreadDialogs;
    private SharedPreferences mainPreferences;
    public String mapKey;
    public int mapProvider;
    public int maxBroadcastCount;
    public int maxCaptionLength;
    public int maxEditTime;
    public int maxFaveStickersCount;
    public int maxFolderPinnedDialogsCount;
    public int maxGroupCount;
    public int maxMegagroupCount;
    public int maxMessageLength;
    public int maxPinnedDialogsCount;
    public int maxRecentGifsCount;
    public int maxRecentStickersCount;
    private SparseIntArray migratedChats;
    private boolean migratingDialogs;
    public int minGroupConvertSize;
    private SparseIntArray needShortPollChannels;
    private SparseIntArray needShortPollOnlines;
    private SparseIntArray nextDialogsCacheOffset;
    private int nextProxyInfoCheckTime;
    private int nextTosCheckTime;
    private SharedPreferences notificationsPreferences;
    private ConcurrentHashMap<String, TLObject> objectsByUsernames;
    private boolean offlineSent;
    public ConcurrentHashMap<Integer, Integer> onlinePrivacy;
    private Runnable passwordCheckRunnable;
    private LongSparseArray<SparseArray<MessageObject>> pollsToCheck;
    private int pollsToCheckSize;
    public boolean preloadFeaturedStickers;
    public LongSparseArray<CharSequence> printingStrings;
    public LongSparseArray<Integer> printingStringsTypes;
    public ConcurrentHashMap<Long, ArrayList<PrintingUser>> printingUsers;
    private TLRPC.Dialog proxyDialog;
    private String proxyDialogAddress;
    private long proxyDialogId;
    public int ratingDecay;
    private ArrayList<ReadTask> readTasks;
    private LongSparseArray<ReadTask> readTasksMap;
    public boolean registeringForPush;
    private LongSparseArray<ArrayList<Integer>> reloadingMessages;
    private HashMap<String, ArrayList<MessageObject>> reloadingScheduledWebpages;
    private LongSparseArray<ArrayList<MessageObject>> reloadingScheduledWebpagesPending;
    private HashMap<String, ArrayList<MessageObject>> reloadingWebpages;
    private LongSparseArray<ArrayList<MessageObject>> reloadingWebpagesPending;
    private TLRPC.messages_Dialogs resetDialogsAll;
    private TLRPC.TL_messages_peerDialogs resetDialogsPinned;
    private boolean resetingDialogs;
    public int revokeTimeLimit;
    public int revokeTimePmLimit;
    public int secretWebpagePreview;
    public SparseArray<LongSparseArray<Boolean>> sendingTypings;
    private SparseBooleanArray serverDialogsEndReached;
    public String sharePrefix;
    private SparseIntArray shortPollChannels;
    private SparseIntArray shortPollOnlines;
    private int statusRequest;
    private int statusSettingState;
    public boolean suggestContacts;
    public String suggestedLangCode;
    private Runnable themeCheckRunnable;
    public int totalBlockedCount;
    public int unreadUnmutedDialogs;
    private final Comparator<TLRPC.Update> updatesComparator;
    private SparseArray<ArrayList<TLRPC.Updates>> updatesQueueChannels;
    private ArrayList<TLRPC.Updates> updatesQueuePts;
    private ArrayList<TLRPC.Updates> updatesQueueQts;
    private ArrayList<TLRPC.Updates> updatesQueueSeq;
    private SparseLongArray updatesStartWaitTimeChannels;
    private long updatesStartWaitTimePts;
    private long updatesStartWaitTimeQts;
    private long updatesStartWaitTimeSeq;
    public boolean updatingState;
    private String uploadingAvatar;
    private HashMap<String, Theme.ThemeInfo> uploadingThemes;
    private String uploadingWallpaper;
    private boolean uploadingWallpaperBlurred;
    private boolean uploadingWallpaperMotion;
    private ConcurrentHashMap<Integer, TLRPC.User> users;
    public String venueSearchBot;
    private ArrayList<Long> visibleDialogMainThreadIds;
    private ArrayList<Long> visibleScheduledDialogMainThreadIds;
    public int webFileDatacenterId;

    public static class PrintingUser {
        public TLRPC.SendMessageAction action;
        public long lastTime;
        public int userId;
    }

    public /* synthetic */ void lambda$new$0$MessagesController() {
        getUserConfig().checkSavedPassword();
    }

    private static class UserActionUpdatesSeq extends TLRPC.Updates {
        private UserActionUpdatesSeq() {
        }
    }

    private static class UserActionUpdatesPts extends TLRPC.Updates {
        private UserActionUpdatesPts() {
        }
    }

    private class ReadTask {
        public long dialogId;
        public int maxDate;
        public int maxId;
        public long sendRequestTime;

        private ReadTask() {
        }
    }

    public /* synthetic */ int lambda$new$1$MessagesController(TLRPC.Dialog dialog1, TLRPC.Dialog dialog2) {
        if ((dialog1 instanceof TLRPC.TL_dialogFolder) && !(dialog2 instanceof TLRPC.TL_dialogFolder)) {
            return -1;
        }
        if (!(dialog1 instanceof TLRPC.TL_dialogFolder) && (dialog2 instanceof TLRPC.TL_dialogFolder)) {
            return 1;
        }
        if (!dialog1.pinned && dialog2.pinned) {
            return 1;
        }
        if (dialog1.pinned && !dialog2.pinned) {
            return -1;
        }
        if (dialog1.pinned && dialog2.pinned) {
            if (dialog1.pinnedNum < dialog2.pinnedNum) {
                return 1;
            }
            return dialog1.pinnedNum > dialog2.pinnedNum ? -1 : 0;
        }
        TLRPC.DraftMessage draftMessage = getMediaDataController().getDraft(dialog1.id);
        int date1 = (draftMessage == null || draftMessage.date < dialog1.last_message_date) ? dialog1.last_message_date : draftMessage.date;
        TLRPC.DraftMessage draftMessage2 = getMediaDataController().getDraft(dialog2.id);
        int date2 = (draftMessage2 == null || draftMessage2.date < dialog2.last_message_date) ? dialog2.last_message_date : draftMessage2.date;
        if (date1 < date2) {
            return 1;
        }
        return date1 > date2 ? -1 : 0;
    }

    public /* synthetic */ int lambda$new$2$MessagesController(TLRPC.Update lhs, TLRPC.Update rhs) {
        int ltype = getUpdateType(lhs);
        int rtype = getUpdateType(rhs);
        if (ltype != rtype) {
            return AndroidUtilities.compare(ltype, rtype);
        }
        if (ltype == 0) {
            return AndroidUtilities.compare(getUpdatePts(lhs), getUpdatePts(rhs));
        }
        if (ltype == 1) {
            return AndroidUtilities.compare(getUpdateQts(lhs), getUpdateQts(rhs));
        }
        if (ltype == 2) {
            int lChannel = getUpdateChannelId(lhs);
            int rChannel = getUpdateChannelId(rhs);
            if (lChannel == rChannel) {
                return AndroidUtilities.compare(getUpdatePts(lhs), getUpdatePts(rhs));
            }
            return AndroidUtilities.compare(lChannel, rChannel);
        }
        return 0;
    }

    public static MessagesController getInstance(int num) {
        MessagesController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (MessagesController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    MessagesController[] messagesControllerArr = Instance;
                    MessagesController messagesController = new MessagesController(num);
                    localInstance = messagesController;
                    messagesControllerArr[num] = messagesController;
                }
            }
        }
        return localInstance;
    }

    public static SharedPreferences getNotificationsSettings(int account) {
        return getInstance(account).notificationsPreferences;
    }

    public static SharedPreferences getGlobalNotificationsSettings() {
        return getInstance(0).notificationsPreferences;
    }

    public static SharedPreferences getMainSettings(int account) {
        return getInstance(account).mainPreferences;
    }

    public static SharedPreferences getGlobalMainSettings() {
        return getInstance(0).mainPreferences;
    }

    public static SharedPreferences getEmojiSettings(int account) {
        return getInstance(account).emojiPreferences;
    }

    public static SharedPreferences getGlobalEmojiSettings() {
        return getInstance(0).emojiPreferences;
    }

    public MessagesController(int num) {
        super(num);
        this.chats = new ConcurrentHashMap<>(100, 1.0f, 2);
        this.encryptedChats = new ConcurrentHashMap<>(10, 1.0f, 2);
        this.users = new ConcurrentHashMap<>(100, 1.0f, 2);
        this.objectsByUsernames = new ConcurrentHashMap<>(100, 1.0f, 2);
        this.joiningToChannels = new ArrayList<>();
        this.exportedChats = new SparseArray<>();
        this.hintDialogs = new ArrayList<>();
        this.dialogsByFolder = new SparseArray<>();
        this.allDialogs = new ArrayList<>();
        this.dialogsForward = new ArrayList<>();
        this.dialogsServerOnly = new ArrayList<>();
        this.dialogsCanAddUsers = new ArrayList<>();
        this.dialogsChannelsOnly = new ArrayList<>();
        this.dialogsUsersOnly = new ArrayList<>();
        this.dialogsGroupsOnly = new ArrayList<>();
        this.dialogsUnreadOnly = new ArrayList<>();
        this.dialogs_read_inbox_max = new ConcurrentHashMap<>(100, 1.0f, 2);
        this.dialogs_read_outbox_max = new ConcurrentHashMap<>(100, 1.0f, 2);
        this.dialogs_dict = new LongSparseArray<>();
        this.dialogMessage = new LongSparseArray<>();
        this.dialogMessagesByRandomIds = new LongSparseArray<>();
        this.deletedHistory = new LongSparseArray<>();
        this.dialogMessagesByIds = new SparseArray<>();
        this.printingUsers = new ConcurrentHashMap<>(20, 1.0f, 2);
        this.printingStrings = new LongSparseArray<>();
        this.printingStringsTypes = new LongSparseArray<>();
        this.sendingTypings = new SparseArray<>();
        this.onlinePrivacy = new ConcurrentHashMap<>(20, 1.0f, 2);
        this.loadingPeerSettings = new LongSparseArray<>();
        this.createdDialogIds = new ArrayList<>();
        this.createdScheduledDialogIds = new ArrayList<>();
        this.createdDialogMainThreadIds = new ArrayList<>();
        this.visibleDialogMainThreadIds = new ArrayList<>();
        this.visibleScheduledDialogMainThreadIds = new ArrayList<>();
        this.shortPollChannels = new SparseIntArray();
        this.needShortPollChannels = new SparseIntArray();
        this.shortPollOnlines = new SparseIntArray();
        this.needShortPollOnlines = new SparseIntArray();
        this.deletingDialogs = new LongSparseArray<>();
        this.clearingHistoryDialogs = new LongSparseArray<>();
        this.loadingBlockedUsers = false;
        this.blockedUsers = new SparseIntArray();
        this.totalBlockedCount = -1;
        this.channelViewsToSend = new SparseArray<>();
        this.pollsToCheck = new LongSparseArray<>();
        this.updatesQueueChannels = new SparseArray<>();
        this.updatesStartWaitTimeChannels = new SparseLongArray();
        this.channelsPts = new SparseIntArray();
        this.gettingDifferenceChannels = new SparseBooleanArray();
        this.gettingUnknownChannels = new SparseBooleanArray();
        this.gettingUnknownDialogs = new LongSparseArray<>();
        this.checkingLastMessagesDialogs = new SparseBooleanArray();
        this.updatesQueueSeq = new ArrayList<>();
        this.updatesQueuePts = new ArrayList<>();
        this.updatesQueueQts = new ArrayList<>();
        this.fullUsers = new SparseArray<>();
        this.fullChats = new SparseArray<>();
        this.loadingFullUsers = new ArrayList<>();
        this.loadedFullUsers = new ArrayList<>();
        this.loadingFullChats = new ArrayList<>();
        this.loadingFullParticipants = new ArrayList<>();
        this.loadedFullParticipants = new ArrayList<>();
        this.loadedFullChats = new ArrayList<>();
        this.channelAdmins = new SparseArray<>();
        this.loadingChannelAdmins = new SparseIntArray();
        this.migratedChats = new SparseIntArray();
        this.reloadingWebpages = new HashMap<>();
        this.reloadingWebpagesPending = new LongSparseArray<>();
        this.reloadingScheduledWebpages = new HashMap<>();
        this.reloadingScheduledWebpagesPending = new LongSparseArray<>();
        this.lastScheduledServerQueryTime = new LongSparseArray<>();
        this.reloadingMessages = new LongSparseArray<>();
        this.readTasks = new ArrayList<>();
        this.readTasksMap = new LongSparseArray<>();
        this.nextDialogsCacheOffset = new SparseIntArray();
        this.loadingDialogs = new SparseBooleanArray();
        this.dialogsEndReached = new SparseBooleanArray();
        this.serverDialogsEndReached = new SparseBooleanArray();
        this.getDifferenceFirstSync = true;
        this.loadingPinnedDialogs = new SparseIntArray();
        this.suggestContacts = true;
        this.themeCheckRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$bRse6ibcjE0rjB1ORE0rL4q_oI4
            @Override // java.lang.Runnable
            public final void run() {
                Theme.checkAutoNightThemeConditions();
            }
        };
        this.passwordCheckRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$on7Wfpjmtr6DEBbDHLrMZ3y6OA8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$0$MessagesController();
            }
        };
        this.uploadingThemes = new HashMap<>();
        this.maxBroadcastCount = 100;
        this.minGroupConvertSize = ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION;
        this.dialogComparator = new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$qIf3c1mQMUTzSQAq_m-SqR-FnVs
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return this.f$0.lambda$new$1$MessagesController((TLRPC.Dialog) obj, (TLRPC.Dialog) obj2);
            }
        };
        this.updatesComparator = new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$sAwqgpeXvFbNN-dK0atZm0x-H4g
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return this.f$0.lambda$new$2$MessagesController((TLRPC.Update) obj, (TLRPC.Update) obj2);
            }
        };
        this.DIALOGS_LOAD_TYPE_CACHE = 1;
        this.DIALOGS_LOAD_TYPE_CHANNEL = 2;
        this.DIALOGS_LOAD_TYPE_UNKNOWN = 3;
        this.contactsGetDiff = false;
        this.currentAccount = num;
        ImageLoader.getInstance();
        getMessagesStorage();
        getLocationController();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$MbScv0auAu-BsYqmtf_gG2Ywc8s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$3$MessagesController();
            }
        });
        addSupportUser();
        if (this.currentAccount == 0) {
            this.notificationsPreferences = ApplicationLoader.applicationContext.getSharedPreferences("Notifications", 0);
            this.mainPreferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0);
            this.emojiPreferences = ApplicationLoader.applicationContext.getSharedPreferences("emoji", 0);
        } else {
            this.notificationsPreferences = ApplicationLoader.applicationContext.getSharedPreferences("Notifications" + this.currentAccount, 0);
            this.mainPreferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig" + this.currentAccount, 0);
            this.emojiPreferences = ApplicationLoader.applicationContext.getSharedPreferences("emoji" + this.currentAccount, 0);
        }
        this.enableJoined = this.notificationsPreferences.getBoolean("EnableContactJoined", true);
        this.secretWebpagePreview = this.mainPreferences.getInt("secretWebpage2", 2);
        this.maxGroupCount = this.mainPreferences.getInt("maxGroupCount", ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        this.maxMegagroupCount = this.mainPreferences.getInt("maxMegagroupCount", 10000);
        this.maxRecentGifsCount = this.mainPreferences.getInt("maxRecentGifsCount", ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        this.maxRecentStickersCount = this.mainPreferences.getInt("maxRecentStickersCount", 30);
        this.maxFaveStickersCount = this.mainPreferences.getInt("maxFaveStickersCount", 5);
        this.maxEditTime = this.mainPreferences.getInt("maxEditTime", 3600);
        this.ratingDecay = this.mainPreferences.getInt("ratingDecay", 2419200);
        this.linkPrefix = "m12345.cc";
        String defaultValue = BuildVars.RELEASE_VERSION ? "https://m12345.cc/install.html?appkey=aa717156fa6e34325d3d4a7004a6647a" : "http://www.shareinstall.com.cn/js-test.html?appkey=aa717156fa6e34325d3d4a7004a6647a";
        this.sharePrefix = this.mainPreferences.getString("sharePrefix", defaultValue);
        this.callReceiveTimeout = this.mainPreferences.getInt("callReceiveTimeout", 20000);
        this.callRingTimeout = this.mainPreferences.getInt("callRingTimeout", 90000);
        this.callConnectTimeout = this.mainPreferences.getInt("callConnectTimeout", 30000);
        this.callPacketTimeout = this.mainPreferences.getInt("callPacketTimeout", 10000);
        this.maxPinnedDialogsCount = this.mainPreferences.getInt("maxPinnedDialogsCount", 5);
        this.maxFolderPinnedDialogsCount = this.mainPreferences.getInt("maxFolderPinnedDialogsCount", 100);
        this.maxMessageLength = this.mainPreferences.getInt("maxMessageLength", 4096);
        this.maxCaptionLength = this.mainPreferences.getInt("maxCaptionLength", 1024);
        this.mapProvider = this.mainPreferences.getInt("mapProvider", 0);
        this.availableMapProviders = this.mainPreferences.getInt("availableMapProviders", 3);
        this.mapKey = this.mainPreferences.getString("pk", null);
        this.installReferer = this.mainPreferences.getString("installReferer", null);
        this.defaultP2pContacts = this.mainPreferences.getBoolean("defaultP2pContacts", false);
        this.revokeTimeLimit = this.mainPreferences.getInt("revokeTimeLimit", this.revokeTimeLimit);
        this.revokeTimePmLimit = this.mainPreferences.getInt("revokeTimePmLimit", this.revokeTimePmLimit);
        this.canRevokePmInbox = this.mainPreferences.getBoolean("canRevokePmInbox", this.canRevokePmInbox);
        this.preloadFeaturedStickers = this.mainPreferences.getBoolean("preloadFeaturedStickers", false);
        this.proxyDialogId = this.mainPreferences.getLong("proxy_dialog", 0L);
        this.proxyDialogAddress = this.mainPreferences.getString("proxyDialogAddress", null);
        this.nextTosCheckTime = this.notificationsPreferences.getInt("nextTosCheckTime", 0);
        this.venueSearchBot = this.mainPreferences.getString("venueSearchBot", "foursquare");
        this.gifSearchBot = this.mainPreferences.getString("gifSearchBot", "gif");
        this.imageSearchBot = this.mainPreferences.getString("imageSearchBot", "pic");
        this.blockedCountry = this.mainPreferences.getBoolean("blockedCountry", false);
        this.dcDomainName = this.mainPreferences.getString("dcDomainName2", ConnectionsManager.native_isTestBackend(this.currentAccount) != 0 ? "tapv3.stel.com" : "apv3.stel.com");
        this.webFileDatacenterId = this.mainPreferences.getInt("webFileDatacenterId", ConnectionsManager.native_isTestBackend(this.currentAccount) == 0 ? 4 : 2);
        this.suggestedLangCode = this.mainPreferences.getString("suggestedLangCode", "en");
        this.animatedEmojisZoom = this.mainPreferences.getFloat("animatedEmojisZoom", 0.625f);
        this.enableHub = this.mainPreferences.getBoolean("enable_hub", false);
        this.enableWallet = this.mainPreferences.getBoolean("enable_wallet", false);
        this.enableDigitCoin = this.mainPreferences.getBoolean("enable_digit_coin", false);
    }

    public /* synthetic */ void lambda$new$3$MessagesController() {
        MessagesController messagesController = getMessagesController();
        getNotificationCenter().addObserver(messagesController, NotificationCenter.FileDidUpload);
        getNotificationCenter().addObserver(messagesController, NotificationCenter.FileDidFailUpload);
        getNotificationCenter().addObserver(messagesController, NotificationCenter.fileDidLoad);
        getNotificationCenter().addObserver(messagesController, NotificationCenter.fileDidFailToLoad);
        getNotificationCenter().addObserver(messagesController, NotificationCenter.messageReceivedByServer);
        getNotificationCenter().addObserver(messagesController, NotificationCenter.updateMessageMedia);
    }

    private void loadAppConfig() {
        if (this.loadingAppConfig) {
            return;
        }
        this.loadingAppConfig = true;
        TLRPC.TL_help_getAppConfig req = new TLRPC.TL_help_getAppConfig();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$LC0p8fZvJpttXXfoEXNcbOg3h5E
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadAppConfig$5$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadAppConfig$5$MessagesController(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$WvvJ7wLWqQSW6hGqR6ZXN0FnHPw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$MessagesController(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$MessagesController(TLObject response) {
        if (response instanceof TLRPC.TL_jsonObject) {
            SharedPreferences.Editor editor = this.mainPreferences.edit();
            boolean changed = false;
            TLRPC.TL_jsonObject object = (TLRPC.TL_jsonObject) response;
            int N = object.value.size();
            for (int a = 0; a < N; a++) {
                TLRPC.TL_jsonObjectValue value = object.value.get(a);
                if ("emojies_animated_zoom".equals(value.key) && (value.value instanceof TLRPC.TL_jsonNumber)) {
                    TLRPC.TL_jsonNumber number = (TLRPC.TL_jsonNumber) value.value;
                    if (this.animatedEmojisZoom != number.value) {
                        float f = (float) number.value;
                        this.animatedEmojisZoom = f;
                        editor.putFloat("animatedEmojisZoom", f);
                        changed = true;
                    }
                }
            }
            if (changed) {
                editor.commit();
            }
        }
        this.loadingAppConfig = false;
    }

    public void updateConfig(final TLRPC.TL_config config) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kmxoTiNK7OF7f4U0EP21a7xaPpY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$updateConfig$6$MessagesController(config);
            }
        });
    }

    public /* synthetic */ void lambda$updateConfig$6$MessagesController(TLRPC.TL_config config) {
        String str;
        getDownloadController().loadAutoDownloadConfig(false);
        loadAppConfig();
        this.maxMegagroupCount = config.megagroup_size_max;
        this.maxGroupCount = config.chat_size_max;
        this.maxEditTime = config.edit_time_limit;
        this.ratingDecay = config.rating_e_decay;
        this.maxRecentGifsCount = config.saved_gifs_limit;
        this.maxRecentStickersCount = config.stickers_recent_limit;
        this.maxFaveStickersCount = config.stickers_faved_limit;
        this.revokeTimeLimit = config.revoke_time_limit;
        this.revokeTimePmLimit = config.revoke_pm_time_limit;
        this.canRevokePmInbox = config.revoke_pm_inbox;
        this.linkPrefix = "m12345.cc";
        if ("m12345.cc".endsWith("/")) {
            String str2 = this.linkPrefix;
            this.linkPrefix = str2.substring(0, str2.length() - 1);
        }
        if (this.linkPrefix.startsWith(DefaultWebClient.HTTPS_SCHEME)) {
            this.linkPrefix = this.linkPrefix.substring(8);
        } else if (this.linkPrefix.startsWith(DefaultWebClient.HTTP_SCHEME)) {
            this.linkPrefix = this.linkPrefix.substring(7);
        }
        this.linkPrefix = "m12345.cc";
        this.sharePrefix = config.me_url_prefix;
        this.callReceiveTimeout = config.call_receive_timeout_ms;
        this.callRingTimeout = config.call_ring_timeout_ms;
        this.callConnectTimeout = config.call_connect_timeout_ms;
        this.callPacketTimeout = config.call_packet_timeout_ms;
        this.maxPinnedDialogsCount = config.pinned_dialogs_count_max;
        this.maxFolderPinnedDialogsCount = config.pinned_infolder_count_max;
        this.maxMessageLength = config.message_length_max;
        this.maxCaptionLength = config.caption_length_max;
        this.defaultP2pContacts = config.default_p2p_contacts;
        this.preloadFeaturedStickers = config.preload_featured_stickers;
        this.enableHub = ((config.flags >> 19) & 1) != 0;
        this.enableWallet = ((config.flags >> 20) & 1) != 0;
        this.enableDigitCoin = ((config.flags >> 21) & 1) != 0;
        if (config.venue_search_username != null) {
            this.venueSearchBot = config.venue_search_username;
        }
        if (config.gif_search_username != null) {
            this.gifSearchBot = config.gif_search_username;
        }
        if (this.imageSearchBot != null) {
            this.imageSearchBot = config.img_search_username;
        }
        this.blockedCountry = config.blocked_mode;
        this.dcDomainName = config.dc_txt_domain_name;
        this.webFileDatacenterId = config.webfile_dc_id;
        if (config.suggested_lang_code != null && ((str = this.suggestedLangCode) == null || !str.equals(config.suggested_lang_code))) {
            this.suggestedLangCode = config.suggested_lang_code;
            LocaleController.getInstance().loadRemoteLanguages(this.currentAccount);
        }
        Theme.loadRemoteThemes(this.currentAccount, false);
        Theme.checkCurrentRemoteTheme(false);
        if (config.static_maps_provider == null) {
            config.static_maps_provider = "google";
        }
        this.mapKey = null;
        this.mapProvider = 2;
        this.availableMapProviders = 0;
        String[] providers = config.static_maps_provider.split(",");
        for (int a = 0; a < providers.length; a++) {
            String[] mapArgs = providers[a].split("\\+");
            if (mapArgs.length > 0) {
                String[] typeAndKey = mapArgs[0].split(LogUtils.COLON);
                if (typeAndKey.length > 0) {
                    if ("yandex".equals(typeAndKey[0])) {
                        if (a == 0) {
                            if (mapArgs.length > 1) {
                                this.mapProvider = 3;
                            } else {
                                this.mapProvider = 1;
                            }
                        }
                        this.availableMapProviders |= 4;
                    } else if ("google".equals(typeAndKey[0])) {
                        if (a == 0 && mapArgs.length > 1) {
                            this.mapProvider = 4;
                        }
                        this.availableMapProviders |= 1;
                    } else if ("hchat".equals(typeAndKey[0])) {
                        if (a == 0) {
                            this.mapProvider = 2;
                        }
                        this.availableMapProviders |= 2;
                    }
                    if (typeAndKey.length > 1) {
                        this.mapKey = typeAndKey[1];
                    }
                }
            }
        }
        SharedPreferences.Editor editor = this.mainPreferences.edit();
        editor.putInt("maxGroupCount", this.maxGroupCount);
        editor.putInt("maxMegagroupCount", this.maxMegagroupCount);
        editor.putInt("maxEditTime", this.maxEditTime);
        editor.putInt("ratingDecay", this.ratingDecay);
        editor.putInt("maxRecentGifsCount", this.maxRecentGifsCount);
        editor.putInt("maxRecentStickersCount", this.maxRecentStickersCount);
        editor.putInt("maxFaveStickersCount", this.maxFaveStickersCount);
        editor.putInt("callReceiveTimeout", this.callReceiveTimeout);
        editor.putInt("callRingTimeout", this.callRingTimeout);
        editor.putInt("callConnectTimeout", this.callConnectTimeout);
        editor.putInt("callPacketTimeout", this.callPacketTimeout);
        editor.putString("linkPrefix", this.linkPrefix);
        editor.putString("sharePrefix", this.sharePrefix);
        editor.putInt("maxPinnedDialogsCount", this.maxPinnedDialogsCount);
        editor.putInt("maxFolderPinnedDialogsCount", this.maxFolderPinnedDialogsCount);
        editor.putInt("maxMessageLength", this.maxMessageLength);
        editor.putInt("maxCaptionLength", this.maxCaptionLength);
        editor.putBoolean("defaultP2pContacts", this.defaultP2pContacts);
        editor.putBoolean("preloadFeaturedStickers", this.preloadFeaturedStickers);
        editor.putInt("revokeTimeLimit", this.revokeTimeLimit);
        editor.putInt("revokeTimePmLimit", this.revokeTimePmLimit);
        editor.putInt("mapProvider", this.mapProvider);
        String str3 = this.mapKey;
        if (str3 != null) {
            editor.putString("pk", str3);
        } else {
            editor.remove("pk");
        }
        editor.putBoolean("canRevokePmInbox", this.canRevokePmInbox);
        editor.putBoolean("blockedCountry", this.blockedCountry);
        editor.putString("venueSearchBot", this.venueSearchBot);
        editor.putString("gifSearchBot", this.gifSearchBot);
        editor.putString("imageSearchBot", this.imageSearchBot);
        editor.putString("dcDomainName2", this.dcDomainName);
        editor.putInt("webFileDatacenterId", this.webFileDatacenterId);
        editor.putString("suggestedLangCode", this.suggestedLangCode);
        editor.putBoolean("enable_hub", this.enableHub);
        editor.putBoolean("enable_wallet", this.enableWallet);
        editor.putBoolean("enable_digit_coin", this.enableDigitCoin);
        editor.commit();
        LocaleController.getInstance().checkUpdateForCurrentRemoteLocale(this.currentAccount, config.lang_pack_version, config.base_lang_pack_version);
        getNotificationCenter().postNotificationName(NotificationCenter.configLoaded, new Object[0]);
    }

    public void addSupportUser() {
        TLRPC.TL_userForeign_old2 user = new TLRPC.TL_userForeign_old2();
        user.phone = "333";
        user.id = 333000;
        user.first_name = "Sbcc";
        user.last_name = "";
        user.status = null;
        user.photo = new TLRPC.TL_userProfilePhotoEmpty();
        putUser(user, true);
        TLRPC.TL_userForeign_old2 user2 = new TLRPC.TL_userForeign_old2();
        user2.phone = "42777";
        user2.id = 777000;
        user2.verified = true;
        user2.first_name = "Sbcc";
        user2.last_name = "Notifications";
        user2.status = null;
        user2.photo = new TLRPC.TL_userProfilePhotoEmpty();
        putUser(user2, true);
    }

    public TLRPC.InputUser getInputUser(TLRPC.User user) {
        if (user == null) {
            return new TLRPC.TL_inputUserEmpty();
        }
        if (user.id == getUserConfig().getClientUserId()) {
            return new TLRPC.TL_inputUserSelf();
        }
        TLRPC.InputUser inputUser = new TLRPC.TL_inputUser();
        inputUser.user_id = user.id;
        inputUser.access_hash = user.access_hash;
        return inputUser;
    }

    public TLRPC.InputUser getInputUser(int user_id) {
        TLRPC.User user = getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf(user_id));
        return getInputUser(user);
    }

    public static TLRPC.InputChannel getInputChannel(TLRPC.Chat chat) {
        if ((chat instanceof TLRPC.TL_channel) || (chat instanceof TLRPC.TL_channelForbidden)) {
            TLRPC.InputChannel inputChat = new TLRPC.TL_inputChannel();
            inputChat.channel_id = chat.id;
            inputChat.access_hash = chat.access_hash;
            return inputChat;
        }
        return new TLRPC.TL_inputChannelEmpty();
    }

    public TLRPC.InputChannel getInputChannel(int chatId) {
        return getInputChannel(getChat(Integer.valueOf(chatId)));
    }

    public TLRPC.InputPeer getInputPeer(int id) {
        if (id < 0) {
            TLRPC.Chat chat = getChat(Integer.valueOf(-id));
            if (ChatObject.isChannel(chat)) {
                TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerChannel();
                inputPeer.channel_id = -id;
                inputPeer.access_hash = chat.access_hash;
                return inputPeer;
            }
            TLRPC.InputPeer inputPeer2 = new TLRPC.TL_inputPeerChat();
            inputPeer2.chat_id = -id;
            return inputPeer2;
        }
        TLRPC.User user = getUser(Integer.valueOf(id));
        TLRPC.InputPeer inputPeer3 = new TLRPC.TL_inputPeerUser();
        inputPeer3.user_id = id;
        if (user != null) {
            inputPeer3.access_hash = user.access_hash;
            return inputPeer3;
        }
        return inputPeer3;
    }

    public TLRPC.Peer getPeer(int id) {
        if (id < 0) {
            TLRPC.Chat chat = getChat(Integer.valueOf(-id));
            if ((chat instanceof TLRPC.TL_channel) || (chat instanceof TLRPC.TL_channelForbidden)) {
                TLRPC.Peer inputPeer = new TLRPC.TL_peerChannel();
                inputPeer.channel_id = -id;
                return inputPeer;
            }
            TLRPC.Peer inputPeer2 = new TLRPC.TL_peerChat();
            inputPeer2.chat_id = -id;
            return inputPeer2;
        }
        getUser(Integer.valueOf(id));
        TLRPC.Peer inputPeer3 = new TLRPC.TL_peerUser();
        inputPeer3.user_id = id;
        return inputPeer3;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.FileDidUpload) {
            String location = (String) args[0];
            TLRPC.InputFile file = (TLRPC.InputFile) args[1];
            String str = this.uploadingAvatar;
            if (str != null && str.equals(location)) {
                TLRPC.TL_photos_uploadProfilePhoto req = new TLRPC.TL_photos_uploadProfilePhoto();
                req.file = file;
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$EAmQ4I8zyKsTMQcwTj745u8oIUQ
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$didReceivedNotification$8$MessagesController(tLObject, tL_error);
                    }
                });
                return;
            }
            String str2 = this.uploadingWallpaper;
            if (str2 != null && str2.equals(location)) {
                TLRPC.TL_account_uploadWallPaper req2 = new TLRPC.TL_account_uploadWallPaper();
                req2.file = file;
                req2.mime_type = "image/jpeg";
                final TLRPC.TL_wallPaperSettings settings = new TLRPC.TL_wallPaperSettings();
                settings.blur = this.uploadingWallpaperBlurred;
                settings.motion = this.uploadingWallpaperMotion;
                req2.settings = settings;
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$gm8jprKpCxfFbmn6xvIC7lo0ZjE
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$didReceivedNotification$10$MessagesController(settings, tLObject, tL_error);
                    }
                });
                return;
            }
            final Theme.ThemeInfo themeInfo = this.uploadingThemes.get(location);
            if (themeInfo != null) {
                if (location.equals(themeInfo.uploadingThumb)) {
                    themeInfo.uploadedThumb = file;
                    themeInfo.uploadingThumb = null;
                } else if (location.equals(themeInfo.uploadingFile)) {
                    themeInfo.uploadedFile = file;
                    themeInfo.uploadingFile = null;
                }
                if (themeInfo.uploadedFile != null && themeInfo.uploadedThumb != null) {
                    new File(location);
                    TLRPC.TL_account_uploadTheme req3 = new TLRPC.TL_account_uploadTheme();
                    req3.mime_type = "application/x-tgtheme-android";
                    req3.file_name = "theme.attheme";
                    req3.file = themeInfo.uploadedFile;
                    req3.file.name = "theme.attheme";
                    req3.thumb = themeInfo.uploadedThumb;
                    req3.thumb.name = "theme-preview.jpg";
                    req3.flags = 1 | req3.flags;
                    themeInfo.uploadedFile = null;
                    themeInfo.uploadedThumb = null;
                    getConnectionsManager().sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$xodKW6FWkBk7seMM16irGyV9Vqk
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$didReceivedNotification$16$MessagesController(themeInfo, tLObject, tL_error);
                        }
                    });
                }
                this.uploadingThemes.remove(location);
                return;
            }
            return;
        }
        if (id == NotificationCenter.FileDidFailUpload) {
            String location2 = (String) args[0];
            String str3 = this.uploadingAvatar;
            if (str3 != null && str3.equals(location2)) {
                this.uploadingAvatar = null;
                return;
            }
            String str4 = this.uploadingWallpaper;
            if (str4 != null && str4.equals(location2)) {
                this.uploadingWallpaper = null;
                return;
            }
            Theme.ThemeInfo themeInfo2 = this.uploadingThemes.remove(location2);
            if (themeInfo2 != null) {
                themeInfo2.uploadedFile = null;
                themeInfo2.uploadedThumb = null;
                return;
            }
            return;
        }
        if (id == NotificationCenter.messageReceivedByServer) {
            Boolean scheduled = (Boolean) args[6];
            if (scheduled.booleanValue()) {
                return;
            }
            Integer msgId = (Integer) args[0];
            Integer newMsgId = (Integer) args[1];
            Long did = (Long) args[3];
            MessageObject obj = this.dialogMessage.get(did.longValue());
            if (obj != null && (obj.getId() == msgId.intValue() || obj.messageOwner.local_id == msgId.intValue())) {
                obj.messageOwner.id = newMsgId.intValue();
                obj.messageOwner.send_state = 0;
            }
            TLRPC.Dialog dialog = this.dialogs_dict.get(did.longValue());
            if (dialog != null && dialog.top_message == msgId.intValue()) {
                dialog.top_message = newMsgId.intValue();
                getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            }
            MessageObject obj2 = this.dialogMessagesByIds.get(msgId.intValue());
            this.dialogMessagesByIds.remove(msgId.intValue());
            if (obj2 != null) {
                this.dialogMessagesByIds.put(newMsgId.intValue(), obj2);
            }
            int lowerId = (int) did.longValue();
            if (lowerId < 0) {
                TLRPC.ChatFull chatFull = this.fullChats.get(-lowerId);
                TLRPC.Chat chat = getChat(Integer.valueOf(-lowerId));
                if (chat != null && !ChatObject.hasAdminRights(chat) && chatFull != null && chatFull.slowmode_seconds != 0) {
                    chatFull.slowmode_next_send_date = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() + chatFull.slowmode_seconds;
                    chatFull.flags |= 262144;
                    getMessagesStorage().updateChatInfo(chatFull, false);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateMessageMedia) {
            TLRPC.Message message = (TLRPC.Message) args[0];
            MessageObject existMessageObject = this.dialogMessagesByIds.get(message.id);
            if (existMessageObject != null) {
                existMessageObject.messageOwner.media = message.media;
                if (message.media.ttl_seconds != 0) {
                    if ((message.media.photo instanceof TLRPC.TL_photoEmpty) || (message.media.document instanceof TLRPC.TL_documentEmpty)) {
                        existMessageObject.setType();
                        getNotificationCenter().postNotificationName(NotificationCenter.notificationsSettingsUpdated, new Object[0]);
                    }
                }
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$8$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.User user = getUser(Integer.valueOf(getUserConfig().getClientUserId()));
            if (user == null) {
                user = getUserConfig().getCurrentUser();
                putUser(user, true);
            } else {
                getUserConfig().setCurrentUser(user);
            }
            if (user == null) {
                return;
            }
            TLRPC.TL_photos_photo photo = (TLRPC.TL_photos_photo) response;
            ArrayList<TLRPC.PhotoSize> sizes = photo.photo.sizes;
            TLRPC.PhotoSize smallSize = FileLoader.getClosestPhotoSizeWithSize(sizes, 100);
            TLRPC.PhotoSize bigSize = FileLoader.getClosestPhotoSizeWithSize(sizes, 1000);
            user.photo = new TLRPC.TL_userProfilePhoto();
            user.photo.photo_id = photo.photo.id;
            if (smallSize != null) {
                user.photo.photo_small = smallSize.location;
            }
            if (bigSize != null) {
                user.photo.photo_big = bigSize.location;
            } else if (smallSize != null) {
                user.photo.photo_small = smallSize.location;
            }
            getMessagesStorage().clearUserPhotos(user.id);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user);
            getMessagesStorage().putUsersAndChats(users, null, false, true);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$BaF4p98jorDqVABbA_Yv7adfoFA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$MessagesController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$7$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 2);
        getUserConfig().saveConfig(true);
    }

    public /* synthetic */ void lambda$didReceivedNotification$10$MessagesController(final TLRPC.TL_wallPaperSettings settings, TLObject response, TLRPC.TL_error error) {
        final TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) response;
        final File path = new File(ApplicationLoader.getFilesDirFixed(), this.uploadingWallpaperBlurred ? "wallpaper_original.jpg" : "wallpaper.jpg");
        if (wallPaper != null) {
            try {
                AndroidUtilities.copyFile(path, FileLoader.getPathToAttach(wallPaper.document, true));
            } catch (Exception e) {
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$SNifMMGt2CF315ZzRmQrPvUHCGI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$9$MessagesController(wallPaper, settings, path);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$MessagesController(TLRPC.TL_wallPaper wallPaper, TLRPC.TL_wallPaperSettings settings, File path) {
        if (this.uploadingWallpaper != null && wallPaper != null) {
            wallPaper.settings = settings;
            wallPaper.flags |= 4;
            SharedPreferences preferences = getGlobalMainSettings();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putLong("selectedBackground2", wallPaper.id);
            editor.putString("selectedBackgroundSlug", wallPaper.slug);
            editor.commit();
            ArrayList<TLRPC.WallPaper> wallpapers = new ArrayList<>();
            wallpapers.add(wallPaper);
            getMessagesStorage().putWallpapers(wallpapers, 2);
            TLRPC.PhotoSize image = FileLoader.getClosestPhotoSizeWithSize(wallPaper.document.thumbs, 320);
            if (image != null) {
                String newKey = image.location.volume_id + "_" + image.location.local_id + "@100_100";
                String oldKey = Utilities.MD5(path.getAbsolutePath()) + "@100_100";
                ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForDocument(image, wallPaper.document), false);
            }
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.wallpapersNeedReload, Long.valueOf(wallPaper.id));
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$16$MessagesController(final Theme.ThemeInfo themeInfo, TLObject response, TLRPC.TL_error error) {
        int index = themeInfo.name.lastIndexOf(".attheme");
        String n = themeInfo.name;
        if (index > 0) {
            n = n.substring(0, index);
        }
        if (response != null) {
            TLRPC.Document document = (TLRPC.Document) response;
            TLRPC.TL_inputDocument inputDocument = new TLRPC.TL_inputDocument();
            inputDocument.access_hash = document.access_hash;
            inputDocument.id = document.id;
            inputDocument.file_reference = document.file_reference;
            if (themeInfo.info == null || !themeInfo.info.creator) {
                TLRPC.TL_account_createTheme req2 = new TLRPC.TL_account_createTheme();
                req2.document = inputDocument;
                req2.slug = (themeInfo.info == null || TextUtils.isEmpty(themeInfo.info.slug)) ? "" : themeInfo.info.slug;
                req2.title = n;
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Zsvej3uQYlHR9l5bJQDLJayVC70
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$12$MessagesController(themeInfo, tLObject, tL_error);
                    }
                });
                return;
            }
            TLRPC.TL_account_updateTheme req22 = new TLRPC.TL_account_updateTheme();
            TLRPC.TL_inputTheme inputTheme = new TLRPC.TL_inputTheme();
            inputTheme.id = themeInfo.info.id;
            inputTheme.access_hash = themeInfo.info.access_hash;
            req22.theme = inputTheme;
            req22.slug = themeInfo.info.slug;
            req22.flags |= 1;
            req22.title = n;
            req22.flags |= 2;
            req22.document = inputDocument;
            req22.flags |= 4;
            req22.format = "android";
            getConnectionsManager().sendRequest(req22, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Mpg9_MCIOJtudSpoefFaT1sdyM8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$14$MessagesController(themeInfo, tLObject, tL_error);
                }
            });
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$v9WsrYMfYgP1U8lQJB9yxuj_IGk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$15$MessagesController(themeInfo);
            }
        });
    }

    public /* synthetic */ void lambda$null$12$MessagesController(final Theme.ThemeInfo themeInfo, final TLObject response1, TLRPC.TL_error error1) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ueFwWLQgbRLA29qEL9hhM9VO3aU
            @Override // java.lang.Runnable
            public final void run() throws IOException {
                this.f$0.lambda$null$11$MessagesController(response1, themeInfo);
            }
        });
    }

    public /* synthetic */ void lambda$null$11$MessagesController(TLObject response1, Theme.ThemeInfo themeInfo) throws IOException {
        if (response1 instanceof TLRPC.TL_theme) {
            Theme.setThemeUploadInfo(themeInfo, (TLRPC.TL_theme) response1, false);
            installTheme(themeInfo, themeInfo == Theme.getCurrentNightTheme());
            getNotificationCenter().postNotificationName(NotificationCenter.themeUploadedToServer, themeInfo);
            return;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.themeUploadError, themeInfo);
    }

    public /* synthetic */ void lambda$null$14$MessagesController(final Theme.ThemeInfo themeInfo, final TLObject response1, TLRPC.TL_error error1) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$55OiPdCpZZBUvVgS-yccSja1N2k
            @Override // java.lang.Runnable
            public final void run() throws IOException {
                this.f$0.lambda$null$13$MessagesController(response1, themeInfo);
            }
        });
    }

    public /* synthetic */ void lambda$null$13$MessagesController(TLObject response1, Theme.ThemeInfo themeInfo) throws IOException {
        if (response1 instanceof TLRPC.TL_theme) {
            Theme.setThemeUploadInfo(themeInfo, (TLRPC.TL_theme) response1, false);
            getNotificationCenter().postNotificationName(NotificationCenter.themeUploadedToServer, themeInfo);
        } else {
            getNotificationCenter().postNotificationName(NotificationCenter.themeUploadError, themeInfo);
        }
    }

    public /* synthetic */ void lambda$null$15$MessagesController(Theme.ThemeInfo themeInfo) {
        getNotificationCenter().postNotificationName(NotificationCenter.themeUploadError, themeInfo);
    }

    public void cleanup() {
        getContactsController().cleanup();
        MediaController.getInstance().cleanup();
        getNotificationsController().cleanup();
        getSendMessagesHelper().cleanup();
        getSecretChatHelper().cleanup();
        getLocationController().cleanup();
        getMediaDataController().cleanup();
        DialogsActivity.dialogsLoaded[this.currentAccount] = false;
        SharedPreferences.Editor editor = this.notificationsPreferences.edit();
        editor.clear().commit();
        SharedPreferences.Editor editor2 = this.emojiPreferences.edit();
        editor2.putLong("lastGifLoadTime", 0L).putLong("lastStickersLoadTime", 0L).putLong("lastStickersLoadTimeMask", 0L).putLong("lastStickersLoadTimeFavs", 0L).commit();
        SharedPreferences.Editor editor3 = this.mainPreferences.edit();
        editor3.remove("archivehint").remove("archivehint_l").remove("gifhint").remove("soundHint").remove("dcDomainName2").remove("webFileDatacenterId").remove("last_contacts_get_diff").remove("contacts_apply_id").remove("contacts_apply_hash").remove("contacts_apply_count").commit();
        this.lastScheduledServerQueryTime.clear();
        this.reloadingWebpages.clear();
        this.reloadingWebpagesPending.clear();
        this.reloadingScheduledWebpages.clear();
        this.reloadingScheduledWebpagesPending.clear();
        this.dialogs_dict.clear();
        this.dialogs_read_inbox_max.clear();
        this.loadingPinnedDialogs.clear();
        this.dialogs_read_outbox_max.clear();
        this.exportedChats.clear();
        this.fullUsers.clear();
        this.fullChats.clear();
        this.dialogsByFolder.clear();
        this.unreadUnmutedDialogs = 0;
        this.joiningToChannels.clear();
        this.migratedChats.clear();
        this.channelViewsToSend.clear();
        this.pollsToCheck.clear();
        this.pollsToCheckSize = 0;
        this.dialogsServerOnly.clear();
        this.dialogsForward.clear();
        this.allDialogs.clear();
        this.dialogsCanAddUsers.clear();
        this.dialogsChannelsOnly.clear();
        this.dialogsGroupsOnly.clear();
        this.dialogsUnreadOnly.clear();
        this.dialogsUsersOnly.clear();
        this.dialogMessagesByIds.clear();
        this.dialogMessagesByRandomIds.clear();
        this.channelAdmins.clear();
        this.loadingChannelAdmins.clear();
        this.users.clear();
        this.objectsByUsernames.clear();
        this.chats.clear();
        this.dialogMessage.clear();
        this.deletedHistory.clear();
        this.printingUsers.clear();
        this.printingStrings.clear();
        this.printingStringsTypes.clear();
        this.onlinePrivacy.clear();
        this.loadingPeerSettings.clear();
        this.deletingDialogs.clear();
        this.clearingHistoryDialogs.clear();
        this.lastPrintingStringCount = 0;
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$82q5BpsxCULkU7Tg9d6BIsj5u7c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanup$17$MessagesController();
            }
        });
        this.createdDialogMainThreadIds.clear();
        this.visibleDialogMainThreadIds.clear();
        this.visibleScheduledDialogMainThreadIds.clear();
        this.blockedUsers.clear();
        this.sendingTypings.clear();
        this.loadingFullUsers.clear();
        this.loadedFullUsers.clear();
        this.reloadingMessages.clear();
        this.loadingFullChats.clear();
        this.loadingFullParticipants.clear();
        this.loadedFullParticipants.clear();
        this.loadedFullChats.clear();
        this.dialogsLoaded = false;
        this.nextDialogsCacheOffset.clear();
        this.loadingDialogs.clear();
        this.dialogsEndReached.clear();
        this.serverDialogsEndReached.clear();
        this.loadingAppConfig = false;
        this.checkingTosUpdate = false;
        this.nextTosCheckTime = 0;
        this.nextProxyInfoCheckTime = 0;
        this.checkingProxyInfo = false;
        this.loadingUnreadDialogs = false;
        this.currentDeletingTaskTime = 0;
        this.currentDeletingTaskMids = null;
        this.currentDeletingTaskChannelId = 0;
        this.gettingNewDeleteTask = false;
        this.loadingBlockedUsers = false;
        this.totalBlockedCount = -1;
        this.blockedEndReached = false;
        this.firstGettingTask = false;
        this.updatingState = false;
        this.resetingDialogs = false;
        this.lastStatusUpdateTime = 0L;
        this.offlineSent = false;
        this.registeringForPush = false;
        this.getDifferenceFirstSync = true;
        this.uploadingAvatar = null;
        this.uploadingWallpaper = null;
        this.uploadingThemes.clear();
        this.statusRequest = 0;
        this.statusSettingState = 0;
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$UCXUugwg5Q3D3WRKDBi2kaG2IQU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanup$18$MessagesController();
            }
        });
        if (this.currentDeleteTaskRunnable != null) {
            Utilities.stageQueue.cancelRunnable(this.currentDeleteTaskRunnable);
            this.currentDeleteTaskRunnable = null;
        }
        addSupportUser();
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        AppPreferenceUtil.putString("PublishFcBean", "");
        FcDBHelper.getInstance().deleteAll(HomeFcListBean.class);
        FcDBHelper.getInstance().deleteAll(RecommendFcListBean.class);
        FcDBHelper.getInstance().deleteAll(FollowedFcListBean.class);
    }

    public /* synthetic */ void lambda$cleanup$17$MessagesController() {
        this.readTasks.clear();
        this.readTasksMap.clear();
        this.updatesQueueSeq.clear();
        this.updatesQueuePts.clear();
        this.updatesQueueQts.clear();
        this.gettingUnknownChannels.clear();
        this.gettingUnknownDialogs.clear();
        this.updatesStartWaitTimeSeq = 0L;
        this.updatesStartWaitTimePts = 0L;
        this.updatesStartWaitTimeQts = 0L;
        this.createdDialogIds.clear();
        this.createdScheduledDialogIds.clear();
        this.gettingDifference = false;
        this.resetDialogsPinned = null;
        this.resetDialogsAll = null;
    }

    public /* synthetic */ void lambda$cleanup$18$MessagesController() {
        getConnectionsManager().setIsUpdating(false);
        this.updatesQueueChannels.clear();
        this.updatesStartWaitTimeChannels.clear();
        this.gettingDifferenceChannels.clear();
        this.channelsPts.clear();
        this.shortPollChannels.clear();
        this.needShortPollChannels.clear();
        this.shortPollOnlines.clear();
        this.needShortPollOnlines.clear();
    }

    public TLRPC.User getUser(Integer id) {
        return this.users.get(id);
    }

    public TLObject getUserOrChat(String username) {
        if (username == null || username.length() == 0) {
            return null;
        }
        return this.objectsByUsernames.get(username.toLowerCase());
    }

    public ConcurrentHashMap<Integer, TLRPC.User> getUsers() {
        return this.users;
    }

    public ConcurrentHashMap<Integer, TLRPC.Chat> getChats() {
        return this.chats;
    }

    public TLRPC.Chat getChat(Integer id) {
        return this.chats.get(id);
    }

    public TLRPC.EncryptedChat getEncryptedChat(Integer id) {
        return this.encryptedChats.get(id);
    }

    public TLRPC.EncryptedChat getEncryptedChatDB(int chat_id, boolean created) {
        TLRPC.EncryptedChat chat = this.encryptedChats.get(Integer.valueOf(chat_id));
        if (chat != null) {
            if (!created) {
                return chat;
            }
            if (!(chat instanceof TLRPC.TL_encryptedChatWaiting) && !(chat instanceof TLRPC.TL_encryptedChatRequested)) {
                return chat;
            }
        }
        CountDownLatch countDownLatch = new CountDownLatch(1);
        ArrayList<TLObject> result = new ArrayList<>();
        getMessagesStorage().getEncryptedChat(chat_id, countDownLatch, result);
        try {
            countDownLatch.await();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (result.size() == 2) {
            TLRPC.EncryptedChat chat2 = (TLRPC.EncryptedChat) result.get(0);
            TLRPC.User user = (TLRPC.User) result.get(1);
            putEncryptedChat(chat2, false);
            putUser(user, true);
            return chat2;
        }
        return chat;
    }

    public boolean isDialogVisible(long dialog_id, boolean scheduled) {
        return (scheduled ? this.visibleScheduledDialogMainThreadIds : this.visibleDialogMainThreadIds).contains(Long.valueOf(dialog_id));
    }

    public void setLastVisibleDialogId(long dialog_id, boolean scheduled, boolean set) {
        ArrayList<Long> arrayList = scheduled ? this.visibleScheduledDialogMainThreadIds : this.visibleDialogMainThreadIds;
        if (set) {
            if (arrayList.contains(Long.valueOf(dialog_id))) {
                return;
            }
            arrayList.add(Long.valueOf(dialog_id));
            return;
        }
        arrayList.remove(Long.valueOf(dialog_id));
    }

    public void setLastCreatedDialogId(final long dialogId, final boolean scheduled, final boolean set) {
        if (!scheduled) {
            ArrayList<Long> arrayList = this.createdDialogMainThreadIds;
            if (set) {
                if (arrayList.contains(Long.valueOf(dialogId))) {
                    return;
                } else {
                    arrayList.add(Long.valueOf(dialogId));
                }
            } else {
                arrayList.remove(Long.valueOf(dialogId));
                SparseArray<MessageObject> array = this.pollsToCheck.get(dialogId);
                if (array != null) {
                    int N = array.size();
                    for (int a = 0; a < N; a++) {
                        MessageObject object = array.valueAt(a);
                        object.pollVisibleOnScreen = false;
                    }
                }
            }
        }
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$UzCpp9aNDhwRIl9gsImGz2GYi5g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setLastCreatedDialogId$19$MessagesController(scheduled, set, dialogId);
            }
        });
    }

    public /* synthetic */ void lambda$setLastCreatedDialogId$19$MessagesController(boolean scheduled, boolean set, long dialogId) {
        ArrayList<Long> arrayList2 = scheduled ? this.createdScheduledDialogIds : this.createdDialogIds;
        if (set) {
            if (arrayList2.contains(Long.valueOf(dialogId))) {
                return;
            }
            arrayList2.add(Long.valueOf(dialogId));
            return;
        }
        arrayList2.remove(Long.valueOf(dialogId));
    }

    public TLRPC.ExportedChatInvite getExportedInvite(int chat_id) {
        return this.exportedChats.get(chat_id);
    }

    public boolean putUser(TLRPC.User user, boolean fromCache) {
        if (user == null) {
            return false;
        }
        boolean fromCache2 = (!fromCache || user.id / 1000 == 333 || user.id == 777000) ? false : true;
        TLRPC.User oldUser = this.users.get(Integer.valueOf(user.id));
        if (oldUser == user) {
            return false;
        }
        if (oldUser != null && !TextUtils.isEmpty(oldUser.username)) {
            this.objectsByUsernames.remove(oldUser.username.toLowerCase());
        }
        if (!TextUtils.isEmpty(user.username)) {
            this.objectsByUsernames.put(user.username.toLowerCase(), user);
        }
        if (user.min) {
            if (oldUser != null) {
                if (!fromCache2) {
                    if (user.bot) {
                        if (user.username != null) {
                            oldUser.username = user.username;
                            oldUser.flags |= 8;
                        } else {
                            oldUser.flags &= -9;
                            oldUser.username = null;
                        }
                    }
                    if (user.photo != null) {
                        oldUser.photo = user.photo;
                        oldUser.flags |= 32;
                    } else {
                        oldUser.flags &= -33;
                        oldUser.photo = null;
                    }
                }
            } else {
                this.users.put(Integer.valueOf(user.id), user);
            }
        } else if (!fromCache2) {
            this.users.put(Integer.valueOf(user.id), user);
            if (user.id == getUserConfig().getClientUserId()) {
                getUserConfig().setCurrentUser(user);
                getUserConfig().saveConfig(true);
            }
            if (oldUser != null && user.status != null && oldUser.status != null && user.status.expires != oldUser.status.expires) {
                return true;
            }
        } else if (oldUser == null) {
            this.users.put(Integer.valueOf(user.id), user);
        } else if (oldUser.min) {
            user.min = false;
            if (oldUser.bot) {
                if (oldUser.username != null) {
                    user.username = oldUser.username;
                    user.flags |= 8;
                } else {
                    user.flags &= -9;
                    user.username = null;
                }
            }
            if (oldUser.photo != null) {
                user.photo = oldUser.photo;
                user.flags |= 32;
            } else {
                user.flags &= -33;
                user.photo = null;
            }
            this.users.put(Integer.valueOf(user.id), user);
        }
        return false;
    }

    public void putUsers(ArrayList<TLRPC.User> users, boolean fromCache) {
        if (users == null || users.isEmpty()) {
            return;
        }
        boolean updateStatus = false;
        int count = users.size();
        for (int a = 0; a < count; a++) {
            TLRPC.User user = users.get(a);
            if (putUser(user, fromCache)) {
                updateStatus = true;
            }
        }
        if (updateStatus) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$oAHsVV6M_fcpO3Bg2EJQx4QbAIc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$putUsers$20$MessagesController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$putUsers$20$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 4);
    }

    public void putChat(final TLRPC.Chat chat, boolean fromCache) {
        TLRPC.Chat oldChat;
        if (chat == null || (oldChat = this.chats.get(Integer.valueOf(chat.id))) == chat) {
            return;
        }
        if (oldChat != null && !TextUtils.isEmpty(oldChat.username)) {
            this.objectsByUsernames.remove(oldChat.username.toLowerCase());
        }
        if (!TextUtils.isEmpty(chat.username)) {
            this.objectsByUsernames.put(chat.username.toLowerCase(), chat);
        }
        if (chat.min) {
            if (oldChat != null) {
                if (!fromCache) {
                    oldChat.title = chat.title;
                    oldChat.photo = chat.photo;
                    oldChat.broadcast = chat.broadcast;
                    oldChat.verified = chat.verified;
                    oldChat.megagroup = chat.megagroup;
                    if (chat.default_banned_rights != null) {
                        oldChat.default_banned_rights = chat.default_banned_rights;
                        oldChat.flags |= 262144;
                    }
                    if (chat.admin_rights != null) {
                        oldChat.admin_rights = chat.admin_rights;
                        oldChat.flags |= 16384;
                    }
                    if (chat.banned_rights != null) {
                        oldChat.banned_rights = chat.banned_rights;
                        oldChat.flags |= 32768;
                    }
                    if (chat.username != null) {
                        oldChat.username = chat.username;
                        oldChat.flags |= 64;
                    } else {
                        oldChat.flags &= -65;
                        oldChat.username = null;
                    }
                    if (chat.participants_count != 0) {
                        oldChat.participants_count = chat.participants_count;
                        return;
                    }
                    return;
                }
                return;
            }
            this.chats.put(Integer.valueOf(chat.id), chat);
            return;
        }
        if (!fromCache) {
            if (oldChat != null) {
                if (chat.version != oldChat.version) {
                    this.loadedFullChats.remove(Integer.valueOf(chat.id));
                }
                if (oldChat.participants_count != 0 && chat.participants_count == 0) {
                    chat.participants_count = oldChat.participants_count;
                    chat.flags = 131072 | chat.flags;
                }
                int oldFlags = oldChat.banned_rights != null ? oldChat.banned_rights.flags : 0;
                int newFlags = chat.banned_rights != null ? chat.banned_rights.flags : 0;
                int oldFlags2 = oldChat.default_banned_rights != null ? oldChat.default_banned_rights.flags : 0;
                int newFlags2 = chat.default_banned_rights != null ? chat.default_banned_rights.flags : 0;
                oldChat.default_banned_rights = chat.default_banned_rights;
                if (oldChat.default_banned_rights == null) {
                    oldChat.flags &= -262145;
                } else {
                    oldChat.flags = 262144 | oldChat.flags;
                }
                oldChat.banned_rights = chat.banned_rights;
                if (oldChat.banned_rights == null) {
                    oldChat.flags &= -32769;
                } else {
                    oldChat.flags = 32768 | oldChat.flags;
                }
                oldChat.admin_rights = chat.admin_rights;
                if (oldChat.admin_rights == null) {
                    oldChat.flags &= -16385;
                } else {
                    oldChat.flags |= 16384;
                }
                if (oldFlags != newFlags || oldFlags2 != newFlags2) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$9tuzIFKBtGP9T2bgcYnm9UvHV2s
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$putChat$21$MessagesController(chat);
                        }
                    });
                }
            }
            this.chats.put(Integer.valueOf(chat.id), chat);
            return;
        }
        if (oldChat == null) {
            this.chats.put(Integer.valueOf(chat.id), chat);
            return;
        }
        if (oldChat.min) {
            chat.min = false;
            chat.title = oldChat.title;
            chat.photo = oldChat.photo;
            chat.broadcast = oldChat.broadcast;
            chat.verified = oldChat.verified;
            chat.megagroup = oldChat.megagroup;
            if (oldChat.default_banned_rights != null) {
                chat.default_banned_rights = oldChat.default_banned_rights;
                chat.flags = 262144 | chat.flags;
            }
            if (oldChat.admin_rights != null) {
                chat.admin_rights = oldChat.admin_rights;
                chat.flags |= 16384;
            }
            if (oldChat.banned_rights != null) {
                chat.banned_rights = oldChat.banned_rights;
                chat.flags = 32768 | chat.flags;
            }
            if (oldChat.username != null) {
                chat.username = oldChat.username;
                chat.flags |= 64;
            } else {
                chat.flags &= -65;
                chat.username = null;
            }
            if (oldChat.participants_count != 0 && chat.participants_count == 0) {
                chat.participants_count = oldChat.participants_count;
                chat.flags = 131072 | chat.flags;
            }
            this.chats.put(Integer.valueOf(chat.id), chat);
        }
    }

    public /* synthetic */ void lambda$putChat$21$MessagesController(TLRPC.Chat chat) {
        getNotificationCenter().postNotificationName(NotificationCenter.channelRightsUpdated, chat);
    }

    public void putChats(ArrayList<TLRPC.Chat> chats, boolean fromCache) {
        if (chats == null || chats.isEmpty()) {
            return;
        }
        int count = chats.size();
        for (int a = 0; a < count; a++) {
            TLRPC.Chat chat = chats.get(a);
            putChat(chat, fromCache);
        }
    }

    public void setReferer(String referer) {
        if (referer == null) {
            return;
        }
        this.installReferer = referer;
        this.mainPreferences.edit().putString("installReferer", referer).commit();
    }

    public void putEncryptedChat(TLRPC.EncryptedChat encryptedChat, boolean fromCache) {
        if (encryptedChat == null) {
            return;
        }
        if (fromCache) {
            this.encryptedChats.putIfAbsent(Integer.valueOf(encryptedChat.id), encryptedChat);
        } else {
            this.encryptedChats.put(Integer.valueOf(encryptedChat.id), encryptedChat);
        }
    }

    public void putEncryptedChats(ArrayList<TLRPC.EncryptedChat> encryptedChats, boolean fromCache) {
        if (encryptedChats == null || encryptedChats.isEmpty()) {
            return;
        }
        int count = encryptedChats.size();
        for (int a = 0; a < count; a++) {
            TLRPC.EncryptedChat encryptedChat = encryptedChats.get(a);
            putEncryptedChat(encryptedChat, fromCache);
        }
    }

    public TLRPC.UserFull getUserFull(int uid) {
        return this.fullUsers.get(uid);
    }

    public TLRPC.ChatFull getChatFull(int chatId) {
        return this.fullChats.get(chatId);
    }

    public void cancelLoadFullUser(int uid) {
        this.loadingFullUsers.remove(Integer.valueOf(uid));
    }

    public void cancelLoadFullChat(int cid) {
        this.loadingFullChats.remove(Integer.valueOf(cid));
    }

    protected void clearFullUsers() {
        this.loadedFullUsers.clear();
        this.loadedFullChats.clear();
    }

    private void reloadDialogsReadValue(ArrayList<TLRPC.Dialog> dialogs, long did) {
        if (did == 0 && (dialogs == null || dialogs.isEmpty())) {
            return;
        }
        TLRPC.TL_messages_getPeerDialogs req = new TLRPC.TL_messages_getPeerDialogs();
        if (dialogs != null) {
            for (int a = 0; a < dialogs.size(); a++) {
                TLRPC.InputPeer inputPeer = getInputPeer((int) dialogs.get(a).id);
                if (!(inputPeer instanceof TLRPC.TL_inputPeerChannel) || inputPeer.access_hash != 0) {
                    TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
                    inputDialogPeer.peer = inputPeer;
                    req.peers.add(inputDialogPeer);
                }
            }
        } else {
            TLRPC.InputPeer inputPeer2 = getInputPeer((int) did);
            if ((inputPeer2 instanceof TLRPC.TL_inputPeerChannel) && inputPeer2.access_hash == 0) {
                return;
            }
            TLRPC.TL_inputDialogPeer inputDialogPeer2 = new TLRPC.TL_inputDialogPeer();
            inputDialogPeer2.peer = inputPeer2;
            req.peers.add(inputDialogPeer2);
        }
        if (req.peers.isEmpty()) {
            return;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$BeJus0Zq55IHSbuXAQjZ-q_x0I0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$reloadDialogsReadValue$22$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$reloadDialogsReadValue$22$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (response != null) {
            TLRPC.TL_messages_peerDialogs res = (TLRPC.TL_messages_peerDialogs) response;
            ArrayList<TLRPC.Update> arrayList = new ArrayList<>();
            for (int a = 0; a < res.dialogs.size(); a++) {
                TLRPC.Dialog dialog = res.dialogs.get(a);
                if (dialog.read_inbox_max_id == 0) {
                    dialog.read_inbox_max_id = 1;
                }
                if (dialog.read_outbox_max_id == 0) {
                    dialog.read_outbox_max_id = 1;
                }
                DialogObject.initDialog(dialog);
                Integer value = this.dialogs_read_inbox_max.get(Long.valueOf(dialog.id));
                if (value == null) {
                    value = 0;
                }
                this.dialogs_read_inbox_max.put(Long.valueOf(dialog.id), Integer.valueOf(Math.max(dialog.read_inbox_max_id, value.intValue())));
                if (value.intValue() == 0) {
                    if (dialog.peer.channel_id != 0) {
                        TLRPC.TL_updateReadChannelInbox update = new TLRPC.TL_updateReadChannelInbox();
                        update.channel_id = dialog.peer.channel_id;
                        update.max_id = dialog.read_inbox_max_id;
                        arrayList.add(update);
                    } else {
                        TLRPC.TL_updateReadHistoryInbox update2 = new TLRPC.TL_updateReadHistoryInbox();
                        update2.peer = dialog.peer;
                        update2.max_id = dialog.read_inbox_max_id;
                        arrayList.add(update2);
                    }
                }
                Integer value2 = this.dialogs_read_outbox_max.get(Long.valueOf(dialog.id));
                if (value2 == null) {
                    value2 = 0;
                }
                this.dialogs_read_outbox_max.put(Long.valueOf(dialog.id), Integer.valueOf(Math.max(dialog.read_outbox_max_id, value2.intValue())));
                if (value2.intValue() == 0) {
                    if (dialog.peer.channel_id != 0) {
                        TLRPC.TL_updateReadChannelOutbox update3 = new TLRPC.TL_updateReadChannelOutbox();
                        update3.channel_id = dialog.peer.channel_id;
                        update3.max_id = dialog.read_outbox_max_id;
                        arrayList.add(update3);
                    } else {
                        TLRPC.TL_updateReadHistoryOutbox update4 = new TLRPC.TL_updateReadHistoryOutbox();
                        update4.peer = dialog.peer;
                        update4.max_id = dialog.read_outbox_max_id;
                        arrayList.add(update4);
                    }
                }
            }
            if (!arrayList.isEmpty()) {
                processUpdateArray(arrayList, null, null, false, 0);
            }
        }
    }

    public String getAdminRank(int chatId, int uid) {
        SparseArray<String> array = this.channelAdmins.get(chatId);
        if (array == null) {
            return null;
        }
        return array.get(uid);
    }

    public boolean isChannelAdminsLoaded(int chatId) {
        return this.channelAdmins.get(chatId) != null;
    }

    public void loadChannelAdmins(final int chatId, boolean cache) {
        int loadTime = this.loadingChannelAdmins.get(chatId);
        if (SystemClock.uptimeMillis() - ((long) loadTime) < 60) {
            return;
        }
        this.loadingChannelAdmins.put(chatId, (int) (SystemClock.uptimeMillis() / 1000));
        if (cache) {
            getMessagesStorage().loadChannelAdmins(chatId);
            return;
        }
        TLRPC.TL_channels_getParticipants req = new TLRPC.TL_channels_getParticipants();
        req.channel = getInputChannel(chatId);
        req.limit = 100;
        req.filter = new TLRPC.TL_channelParticipantsAdmins();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$eJZAAh7I08J7fYWlLw98Jq-YlDg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadChannelAdmins$23$MessagesController(chatId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadChannelAdmins$23$MessagesController(int chatId, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_channels_channelParticipants) {
            processLoadedAdminsResponse(chatId, (TLRPC.TL_channels_channelParticipants) response);
        }
    }

    public void processLoadedAdminsResponse(int chatId, TLRPC.TL_channels_channelParticipants participants) {
        SparseArray<String> array1 = new SparseArray<>(participants.participants.size());
        for (int a = 0; a < participants.participants.size(); a++) {
            TLRPC.ChannelParticipant participant = participants.participants.get(a);
            array1.put(participant.user_id, participant.rank != null ? participant.rank : "");
        }
        processLoadedChannelAdmins(array1, chatId, false);
    }

    public void processLoadedChannelAdmins(final SparseArray<String> array, final int chatId, final boolean cache) {
        if (!cache) {
            getMessagesStorage().putChannelAdmins(chatId, array);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$M9AYPGpAxnbLGMFdyMnj5ZeMTTY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedChannelAdmins$24$MessagesController(chatId, array, cache);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedChannelAdmins$24$MessagesController(int chatId, SparseArray array, boolean cache) {
        this.channelAdmins.put(chatId, array);
        if (cache) {
            this.loadingChannelAdmins.delete(chatId);
            loadChannelAdmins(chatId, false);
        }
    }

    public void loadUsers(int[] userIds, long[] accessHashs, int classGuid) {
        if (userIds == null || accessHashs == null || userIds.length != accessHashs.length) {
            return;
        }
        ArrayList<Integer> emptyResult = new ArrayList<>();
        if (this.users != null) {
            for (int userId : userIds) {
                TLRPC.User user = this.users.get(Integer.valueOf(userId));
                if (user != null) {
                    getNotificationCenter().postNotificationName(NotificationCenter.userInfoDidLoad, Integer.valueOf(user.id), user);
                } else {
                    emptyResult.add(Integer.valueOf(userId));
                }
            }
            if (emptyResult.size() > 0) {
                loadUsers(emptyResult, accessHashs, classGuid);
            }
        }
    }

    public void loadUsers(ArrayList<Integer> idList, long[] accessHashs, int classGuid) {
        if (idList == null || accessHashs == null || idList.size() != accessHashs.length) {
            return;
        }
        ArrayList<TLRPC.InputUser> list = new ArrayList<>();
        for (int i = 0; i < idList.size(); i++) {
            TLRPC.InputUser user = new TLRPC.TL_inputUser();
            user.user_id = idList.get(i).intValue();
            user.access_hash = accessHashs[i];
            list.add(user);
        }
        loadUsers(list, classGuid);
    }

    public void loadUsers(ArrayList<TLRPC.InputUser> users, int classGuid) {
        if (users == null) {
            return;
        }
        TLRPC.TL_users_getUsers req = new TLRPC.TL_users_getUsers();
        req.id.addAll(users);
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$YguyZ9KDjGMmWEJ-mwL2uRKInpM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadUsers$26$MessagesController(tLObject, tL_error);
            }
        }), classGuid);
    }

    public /* synthetic */ void lambda$loadUsers$26$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.Vector) {
            TLRPC.Vector vector = (TLRPC.Vector) response;
            if (!vector.objects.isEmpty()) {
                for (int i = 0; i < vector.objects.size(); i++) {
                    ArrayList<TLRPC.User> arrayList1 = new ArrayList<>();
                    final TLRPC.User user = (TLRPC.User) vector.objects.get(i);
                    arrayList1.add(user);
                    getMessagesStorage().putUsersAndChats(arrayList1, null, false, true);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$gjbILHabzCdgNMD8zrMwWZCIe0I
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$25$MessagesController(user);
                        }
                    });
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$25$MessagesController(TLRPC.User user) {
        putUser(user, false);
        getNotificationCenter().postNotificationName(NotificationCenter.userInfoDidLoad, Integer.valueOf(user.id), user);
    }

    public void loadFullChat(final int chat_id, final int classGuid, boolean force) {
        TLObject request;
        boolean loaded = this.loadedFullChats.contains(Integer.valueOf(chat_id));
        if (this.loadingFullChats.contains(Integer.valueOf(chat_id))) {
            return;
        }
        if (!force && loaded) {
            return;
        }
        this.loadingFullChats.add(Integer.valueOf(chat_id));
        final long dialog_id = -chat_id;
        final TLRPC.Chat chat = getChat(Integer.valueOf(chat_id));
        if (ChatObject.isChannel(chat)) {
            TLRPC.TL_channels_getFullChannel req = new TLRPC.TL_channels_getFullChannel();
            req.channel = getInputChannel(chat);
            if (chat.megagroup) {
                loadChannelAdmins(chat_id, !loaded);
            }
            request = req;
        } else {
            TLRPC.TL_messages_getFullChat req2 = new TLRPC.TL_messages_getFullChat();
            req2.chat_id = chat_id;
            if (this.dialogs_read_inbox_max.get(Long.valueOf(dialog_id)) == null || this.dialogs_read_outbox_max.get(Long.valueOf(dialog_id)) == null) {
                reloadDialogsReadValue(null, dialog_id);
            }
            request = req2;
        }
        int reqId = getConnectionsManager().sendRequest(request, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$YXrpzVd5H_dlpFNqTNaBfWtREm4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$loadFullChat$29$MessagesController(chat, dialog_id, chat_id, classGuid, tLObject, tL_error);
            }
        });
        if (classGuid != 0) {
            getConnectionsManager().bindRequestToGuid(reqId, classGuid);
        }
    }

    public /* synthetic */ void lambda$loadFullChat$29$MessagesController(TLRPC.Chat chat, long dialog_id, final int chat_id, final int classGuid, TLObject response, final TLRPC.TL_error error) throws Exception {
        Integer value;
        Integer value2;
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$7VKkn2i1FAj1GF19RcZE-3MjNcY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$28$MessagesController(error, chat_id);
                }
            });
            return;
        }
        final TLRPC.TL_messages_chatFull res = (TLRPC.TL_messages_chatFull) response;
        getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
        getMessagesStorage().updateChatInfo(res.full_chat, false);
        if (ChatObject.isChannel(chat)) {
            Integer value3 = this.dialogs_read_inbox_max.get(Long.valueOf(dialog_id));
            if (value3 != null) {
                value = value3;
            } else {
                value = Integer.valueOf(getMessagesStorage().getDialogReadMax(false, dialog_id));
            }
            this.dialogs_read_inbox_max.put(Long.valueOf(dialog_id), Integer.valueOf(Math.max(res.full_chat.read_inbox_max_id, value.intValue())));
            if (value.intValue() == 0) {
                ArrayList<TLRPC.Update> arrayList = new ArrayList<>();
                TLRPC.TL_updateReadChannelInbox update = new TLRPC.TL_updateReadChannelInbox();
                update.channel_id = chat_id;
                update.max_id = res.full_chat.read_inbox_max_id;
                arrayList.add(update);
                processUpdateArray(arrayList, null, null, false, 0);
            }
            Integer value4 = this.dialogs_read_outbox_max.get(Long.valueOf(dialog_id));
            if (value4 != null) {
                value2 = value4;
            } else {
                value2 = Integer.valueOf(getMessagesStorage().getDialogReadMax(true, dialog_id));
            }
            this.dialogs_read_outbox_max.put(Long.valueOf(dialog_id), Integer.valueOf(Math.max(res.full_chat.read_outbox_max_id, value2.intValue())));
            if (value2.intValue() == 0) {
                ArrayList<TLRPC.Update> arrayList2 = new ArrayList<>();
                TLRPC.TL_updateReadChannelOutbox update2 = new TLRPC.TL_updateReadChannelOutbox();
                update2.channel_id = chat_id;
                update2.max_id = res.full_chat.read_outbox_max_id;
                arrayList2.add(update2);
                processUpdateArray(arrayList2, null, null, false, 0);
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ngzGcEC1dZa9bU2axK28RgXg-e8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$27$MessagesController(chat_id, res, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$null$27$MessagesController(int chat_id, TLRPC.TL_messages_chatFull res, int classGuid) {
        this.fullChats.put(chat_id, res.full_chat);
        applyDialogNotificationsSettings(-chat_id, res.full_chat.notify_settings);
        for (int a = 0; a < res.full_chat.bot_info.size(); a++) {
            TLRPC.BotInfo botInfo = res.full_chat.bot_info.get(a);
            getMediaDataController().putBotInfo(botInfo);
        }
        this.exportedChats.put(chat_id, res.full_chat.exported_invite);
        this.loadingFullChats.remove(Integer.valueOf(chat_id));
        this.loadedFullChats.add(Integer.valueOf(chat_id));
        putUsers(res.users, false);
        putChats(res.chats, false);
        if (res.full_chat.stickerset != null) {
            getMediaDataController().getGroupStickerSetById(res.full_chat.stickerset);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, res.full_chat, Integer.valueOf(classGuid), false, null);
    }

    public /* synthetic */ void lambda$null$28$MessagesController(TLRPC.TL_error error, int chat_id) {
        checkChannelError(error.text, chat_id);
        this.loadingFullChats.remove(Integer.valueOf(chat_id));
    }

    public void loadFullUser(TLRPC.User user, int classGuid, boolean force) {
        loadFullUser(user, 0, classGuid, force);
    }

    public void loadFullUser(int userId, int classGuid, boolean force) {
        loadFullUser(null, userId, classGuid, force);
    }

    public void loadFullUser(final TLRPC.User user, int userId, final int classGuid, boolean force) {
        if (user == null || this.loadingFullUsers.contains(Integer.valueOf(user.id)) || (!force && this.loadedFullUsers.contains(Integer.valueOf(user.id)))) {
            if (userId == 0 || this.loadingFullUsers.contains(Integer.valueOf(userId))) {
                return;
            }
            if (!force && this.loadedFullUsers.contains(Integer.valueOf(userId))) {
                return;
            }
        }
        final int searchId = user != null ? user.id : userId;
        this.loadingFullUsers.add(Integer.valueOf(searchId));
        TLRPCContacts.CL_user_getFulluser req = new TLRPCContacts.CL_user_getFulluser();
        req.inputUser = user != null ? getInputUser(user) : getInputUser(userId);
        long dialog_id = searchId;
        if (this.dialogs_read_inbox_max.get(Long.valueOf(dialog_id)) == null || this.dialogs_read_outbox_max.get(Long.valueOf(dialog_id)) == null) {
            reloadDialogsReadValue(null, dialog_id);
        }
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$tU8w0N1zhu3CTzWn-NkqcVHDpLo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadFullUser$32$MessagesController(searchId, user, classGuid, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, classGuid);
    }

    public /* synthetic */ void lambda$loadFullUser$32$MessagesController(final int searchId, final TLRPC.User user, final int classGuid, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.UserFull userFull = (TLRPC.UserFull) response;
            getMessagesStorage().updateUserInfo(userFull, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$WIAA9yPtgAbu9W_Gfwc0vHxgIPE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$30$MessagesController(userFull, searchId, user, classGuid);
                }
            });
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$BoDjSZU_ael8Z_vXFNVD-8hhU48
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$31$MessagesController(searchId);
            }
        });
    }

    public /* synthetic */ void lambda$null$30$MessagesController(TLRPC.UserFull userFull, int searchId, TLRPC.User user, int classGuid) {
        String names;
        savePeerSettings(userFull.user.id, userFull.settings, false);
        applyDialogNotificationsSettings(searchId, userFull.notify_settings);
        if (userFull.bot_info instanceof TLRPC.TL_botInfo) {
            getMediaDataController().putBotInfo(userFull.bot_info);
        }
        int index = this.blockedUsers.indexOfKey(searchId);
        if (userFull.blocked) {
            if (index < 0) {
                this.blockedUsers.put(searchId, 1);
                getNotificationCenter().postNotificationName(NotificationCenter.blockedUsersDidLoad, new Object[0]);
            }
        } else if (index >= 0) {
            this.blockedUsers.removeAt(index);
            getNotificationCenter().postNotificationName(NotificationCenter.blockedUsersDidLoad, new Object[0]);
        }
        this.fullUsers.put(searchId, userFull);
        this.loadingFullUsers.remove(Integer.valueOf(searchId));
        this.loadedFullUsers.add(Integer.valueOf(searchId));
        if (user != null) {
            names = user.first_name + user.last_name + user.username;
        } else {
            names = null;
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(userFull.user);
        putUsers(users, false);
        getMessagesStorage().putUsersAndChats(users, null, false, true);
        if (names != null) {
            if (!names.equals(userFull.user.first_name + userFull.user.last_name + userFull.user.username)) {
                getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 1);
            }
        }
        if (userFull.bot_info instanceof TLRPC.TL_botInfo) {
            getNotificationCenter().postNotificationName(NotificationCenter.botInfoDidLoad, userFull.bot_info, Integer.valueOf(classGuid));
        }
        getNotificationCenter().postNotificationName(NotificationCenter.userFullInfoDidLoad, Integer.valueOf(searchId), userFull, null);
    }

    public /* synthetic */ void lambda$null$31$MessagesController(int searchId) {
        this.loadingFullUsers.remove(Integer.valueOf(searchId));
    }

    private void reloadMessages(ArrayList<Integer> mids, final long dialog_id, final boolean scheduled) {
        TLObject request;
        ArrayList<Integer> arrayList;
        if (mids.isEmpty()) {
            return;
        }
        final ArrayList<Integer> result = new ArrayList<>();
        final TLRPC.Chat chat = ChatObject.getChatByDialog(dialog_id, this.currentAccount);
        if (ChatObject.isChannel(chat)) {
            TLRPC.TL_channels_getMessages req = new TLRPC.TL_channels_getMessages();
            req.channel = getInputChannel(chat);
            req.id = result;
            request = req;
        } else {
            TLRPC.TL_messages_getMessages req2 = new TLRPC.TL_messages_getMessages();
            req2.id = result;
            request = req2;
        }
        ArrayList<Integer> arrayList2 = this.reloadingMessages.get(dialog_id);
        for (int a = 0; a < mids.size(); a++) {
            Integer mid = mids.get(a);
            if (arrayList2 == null || !arrayList2.contains(mid)) {
                result.add(mid);
            }
        }
        if (result.isEmpty()) {
            return;
        }
        if (arrayList2 != null) {
            arrayList = arrayList2;
        } else {
            ArrayList<Integer> arrayList3 = new ArrayList<>();
            this.reloadingMessages.put(dialog_id, arrayList3);
            arrayList = arrayList3;
        }
        arrayList.addAll(result);
        getConnectionsManager().sendRequest(request, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$-GlbQkBiifMGL8qYnx1SxvoCEnI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$reloadMessages$34$MessagesController(dialog_id, chat, scheduled, result, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$reloadMessages$34$MessagesController(final long dialog_id, TLRPC.Chat chat, boolean scheduled, final ArrayList result, TLObject response, TLRPC.TL_error error) {
        Integer inboxValue;
        Integer outboxValue;
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            SparseArray<TLRPC.User> usersLocal = new SparseArray<>();
            for (int a = 0; a < messagesRes.users.size(); a++) {
                TLRPC.User u = messagesRes.users.get(a);
                usersLocal.put(u.id, u);
            }
            SparseArray<TLRPC.Chat> chatsLocal = new SparseArray<>();
            for (int a2 = 0; a2 < messagesRes.chats.size(); a2++) {
                TLRPC.Chat c = messagesRes.chats.get(a2);
                chatsLocal.put(c.id, c);
            }
            Integer inboxValue2 = this.dialogs_read_inbox_max.get(Long.valueOf(dialog_id));
            if (inboxValue2 == null) {
                Integer inboxValue3 = Integer.valueOf(getMessagesStorage().getDialogReadMax(false, dialog_id));
                this.dialogs_read_inbox_max.put(Long.valueOf(dialog_id), inboxValue3);
                inboxValue = inboxValue3;
            } else {
                inboxValue = inboxValue2;
            }
            Integer outboxValue2 = this.dialogs_read_outbox_max.get(Long.valueOf(dialog_id));
            if (outboxValue2 == null) {
                Integer outboxValue3 = Integer.valueOf(getMessagesStorage().getDialogReadMax(true, dialog_id));
                this.dialogs_read_outbox_max.put(Long.valueOf(dialog_id), outboxValue3);
                outboxValue = outboxValue3;
            } else {
                outboxValue = outboxValue2;
            }
            final ArrayList<MessageObject> objects = new ArrayList<>();
            for (int a3 = 0; a3 < messagesRes.messages.size(); a3++) {
                TLRPC.Message message = messagesRes.messages.get(a3);
                if (chat != null && chat.megagroup) {
                    message.flags |= Integer.MIN_VALUE;
                }
                message.dialog_id = dialog_id;
                if (!scheduled) {
                    message.unread = (message.out ? outboxValue : inboxValue).intValue() < message.id;
                }
                objects.add(new MessageObject(this.currentAccount, message, usersLocal, chatsLocal, true));
            }
            ImageLoader.saveMessagesThumbs(messagesRes.messages);
            getMessagesStorage().putMessages(messagesRes, dialog_id, -1, 0, false, scheduled);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$uKvNo80aQ5xngexekHqsjvv99QE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$33$MessagesController(dialog_id, result, objects);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$33$MessagesController(long dialog_id, ArrayList result, ArrayList objects) {
        ArrayList<Integer> arrayList1 = this.reloadingMessages.get(dialog_id);
        if (arrayList1 != null) {
            arrayList1.removeAll(result);
            if (arrayList1.isEmpty()) {
                this.reloadingMessages.remove(dialog_id);
            }
        }
        MessageObject dialogObj = this.dialogMessage.get(dialog_id);
        if (dialogObj != null) {
            int a = 0;
            while (true) {
                if (a >= objects.size()) {
                    break;
                }
                MessageObject obj = (MessageObject) objects.get(a);
                if (dialogObj == null || dialogObj.getId() != obj.getId()) {
                    a++;
                } else {
                    this.dialogMessage.put(dialog_id, obj);
                    if (obj.messageOwner.to_id.channel_id == 0) {
                        MessageObject obj2 = this.dialogMessagesByIds.get(obj.getId());
                        this.dialogMessagesByIds.remove(obj.getId());
                        if (obj2 != null) {
                            this.dialogMessagesByIds.put(obj2.getId(), obj2);
                        }
                    }
                    getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
                }
            }
        }
        getNotificationCenter().postNotificationName(NotificationCenter.replaceMessagesObjects, Long.valueOf(dialog_id), objects);
    }

    public void hidePeerSettingsBar(long dialogId, TLRPC.User currentUser, TLRPC.Chat currentChat) {
        if (currentUser == null && currentChat == null) {
            return;
        }
        SharedPreferences.Editor editor = this.notificationsPreferences.edit();
        editor.putInt("dialog_bar_vis3" + dialogId, 3);
        editor.commit();
        if (((int) dialogId) != 0) {
            TLRPC.TL_messages_hidePeerSettingsBar req = new TLRPC.TL_messages_hidePeerSettingsBar();
            if (currentUser != null) {
                req.peer = getInputPeer(currentUser.id);
            } else if (currentChat != null) {
                req.peer = getInputPeer(-currentChat.id);
            }
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$8PztytkoH0FF8sf7W4xbc80iFNc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$hidePeerSettingsBar$35(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$hidePeerSettingsBar$35(TLObject response, TLRPC.TL_error error) {
    }

    public void reportSpam(long dialogId, TLRPC.User currentUser, TLRPC.Chat currentChat, TLRPC.EncryptedChat currentEncryptedChat, boolean geo) {
        if (currentUser == null && currentChat == null && currentEncryptedChat == null) {
            return;
        }
        SharedPreferences.Editor editor = this.notificationsPreferences.edit();
        editor.putInt("dialog_bar_vis3" + dialogId, 3);
        editor.commit();
        if (((int) dialogId) == 0) {
            if (currentEncryptedChat == null || currentEncryptedChat.access_hash == 0) {
                return;
            }
            TLRPC.TL_messages_reportEncryptedSpam req = new TLRPC.TL_messages_reportEncryptedSpam();
            req.peer = new TLRPC.TL_inputEncryptedChat();
            req.peer.chat_id = currentEncryptedChat.id;
            req.peer.access_hash = currentEncryptedChat.access_hash;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$G0W1zovqJeSl6iltFKfbXCKZMnA
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$reportSpam$36(tLObject, tL_error);
                }
            }, 2);
            return;
        }
        TLRPC.TL_account_reportPeer req2 = new TLRPC.TL_account_reportPeer();
        if (currentChat != null) {
            req2.peer = getInputPeer(-currentChat.id);
        } else if (currentUser != null) {
            req2.peer = getInputPeer(currentUser.id);
        }
        if (geo) {
            req2.reason = new TLRPC.TL_inputReportReasonGeoIrrelevant();
        } else {
            req2.reason = new TLRPC.TL_inputReportReasonSpam();
        }
        getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$aPLFZJaLN9WFN_PhCmT1h6erfsA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MessagesController.lambda$reportSpam$37(tLObject, tL_error);
            }
        }, 2);
    }

    static /* synthetic */ void lambda$reportSpam$36(TLObject response, TLRPC.TL_error error) {
    }

    static /* synthetic */ void lambda$reportSpam$37(TLObject response, TLRPC.TL_error error) {
    }

    private void savePeerSettings(long dialogId, TLRPC.TL_peerSettings settings, boolean update) {
        if (settings != null) {
            if (this.notificationsPreferences.getInt("dialog_bar_vis3" + dialogId, 0) == 3) {
                return;
            }
            SharedPreferences.Editor editor = this.notificationsPreferences.edit();
            boolean bar_hidden = (settings.report_spam || settings.add_contact || settings.block_contact || settings.share_contact || settings.report_geo) ? false : true;
            editor.putInt("dialog_bar_vis3" + dialogId, bar_hidden ? 1 : 2);
            editor.putBoolean("dialog_bar_share" + dialogId, settings.share_contact);
            editor.putBoolean("dialog_bar_report" + dialogId, settings.report_spam);
            editor.putBoolean("dialog_bar_add" + dialogId, settings.add_contact);
            editor.putBoolean("dialog_bar_block" + dialogId, settings.block_contact);
            editor.putBoolean("dialog_bar_exception" + dialogId, settings.need_contacts_exception);
            editor.putBoolean("dialog_bar_location" + dialogId, settings.report_geo);
            editor.commit();
            getNotificationCenter().postNotificationName(NotificationCenter.peerSettingsDidLoad, Long.valueOf(dialogId));
        }
    }

    public void loadPeerSettings(TLRPC.User currentUser, TLRPC.Chat currentChat) {
        final long dialogId;
        if (currentUser == null && currentChat == null) {
            return;
        }
        if (currentUser != null) {
            dialogId = currentUser.id;
        } else {
            dialogId = -currentChat.id;
        }
        if (this.loadingPeerSettings.indexOfKey(dialogId) >= 0) {
            return;
        }
        this.loadingPeerSettings.put(dialogId, true);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("request spam button for " + dialogId);
        }
        int vis = this.notificationsPreferences.getInt("dialog_bar_vis3" + dialogId, 0);
        if (vis == 1 || vis == 3) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("dialog bar already hidden for " + dialogId);
                return;
            }
            return;
        }
        TLRPC.TL_messages_getPeerSettings req = new TLRPC.TL_messages_getPeerSettings();
        if (currentUser != null) {
            req.peer = getInputPeer(currentUser.id);
        } else if (currentChat != null) {
            req.peer = getInputPeer(-currentChat.id);
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$UYS_FXSAxWdfFOJl3ZweARJfiDc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPeerSettings$39$MessagesController(dialogId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadPeerSettings$39$MessagesController(final long dialogId, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$SlckNAtEk6PirxhTUCkY2SErvYg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$38$MessagesController(dialogId, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$38$MessagesController(long dialogId, TLObject response) {
        this.loadingPeerSettings.remove(dialogId);
        if (response != null) {
            savePeerSettings(dialogId, (TLRPC.TL_peerSettings) response, false);
        }
    }

    protected void processNewChannelDifferenceParams(int pts, int pts_count, int channelId) {
        int channelPts = this.channelsPts.get(channelId);
        if (channelPts == 0) {
            channelPts = getMessagesStorage().getChannelPtsSync(channelId);
            if (channelPts == 0) {
                channelPts = 1;
            }
            this.channelsPts.put(channelId, channelPts);
        }
        if (channelPts + pts_count == pts) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("APPLY CHANNEL PTS");
            }
            this.channelsPts.put(channelId, pts);
            getMessagesStorage().saveChannelPts(channelId, pts);
            return;
        }
        if (channelPts != pts) {
            long updatesStartWaitTime = this.updatesStartWaitTimeChannels.get(channelId);
            boolean gettingDifferenceChannel = this.gettingDifferenceChannels.get(channelId);
            if (gettingDifferenceChannel || updatesStartWaitTime == 0 || Math.abs(System.currentTimeMillis() - updatesStartWaitTime) <= 1500) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("ADD CHANNEL UPDATE TO QUEUE pts = " + pts + " pts_count = " + pts_count);
                }
                if (updatesStartWaitTime == 0) {
                    this.updatesStartWaitTimeChannels.put(channelId, System.currentTimeMillis());
                }
                UserActionUpdatesPts updates = new UserActionUpdatesPts();
                updates.pts = pts;
                updates.pts_count = pts_count;
                updates.chat_id = channelId;
                ArrayList<TLRPC.Updates> arrayList = this.updatesQueueChannels.get(channelId);
                if (arrayList == null) {
                    arrayList = new ArrayList<>();
                    this.updatesQueueChannels.put(channelId, arrayList);
                }
                arrayList.add(updates);
                return;
            }
            getChannelDifference(channelId);
        }
    }

    protected void processNewDifferenceParams(int seq, int pts, int date, int pts_count) {
        if (pts != -1) {
            if (getMessagesStorage().getLastPtsValue() + pts_count == pts) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("APPLY PTS");
                }
                getMessagesStorage().setLastPtsValue(pts);
                getMessagesStorage().saveDiffParams(getMessagesStorage().getLastSeqValue(), getMessagesStorage().getLastPtsValue(), getMessagesStorage().getLastDateValue(), getMessagesStorage().getLastQtsValue());
            } else if (getMessagesStorage().getLastPtsValue() != pts) {
                if (this.gettingDifference || this.updatesStartWaitTimePts == 0 || Math.abs(System.currentTimeMillis() - this.updatesStartWaitTimePts) <= 1500) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("ADD UPDATE TO QUEUE pts = " + pts + " pts_count = " + pts_count);
                    }
                    if (this.updatesStartWaitTimePts == 0) {
                        this.updatesStartWaitTimePts = System.currentTimeMillis();
                    }
                    UserActionUpdatesPts updates = new UserActionUpdatesPts();
                    updates.pts = pts;
                    updates.pts_count = pts_count;
                    this.updatesQueuePts.add(updates);
                } else {
                    getDifference();
                }
            }
        }
        if (seq != -1) {
            if (getMessagesStorage().getLastSeqValue() + 1 == seq) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("APPLY SEQ");
                }
                getMessagesStorage().setLastSeqValue(seq);
                if (date != -1) {
                    getMessagesStorage().setLastDateValue(date);
                }
                getMessagesStorage().saveDiffParams(getMessagesStorage().getLastSeqValue(), getMessagesStorage().getLastPtsValue(), getMessagesStorage().getLastDateValue(), getMessagesStorage().getLastQtsValue());
                return;
            }
            if (getMessagesStorage().getLastSeqValue() != seq) {
                if (this.gettingDifference || this.updatesStartWaitTimeSeq == 0 || Math.abs(System.currentTimeMillis() - this.updatesStartWaitTimeSeq) <= 1500) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("ADD UPDATE TO QUEUE seq = " + seq);
                    }
                    if (this.updatesStartWaitTimeSeq == 0) {
                        this.updatesStartWaitTimeSeq = System.currentTimeMillis();
                    }
                    UserActionUpdatesSeq updates2 = new UserActionUpdatesSeq();
                    updates2.seq = seq;
                    this.updatesQueueSeq.add(updates2);
                    return;
                }
                getDifference();
            }
        }
    }

    public void didAddedNewTask(final int minDate, final SparseArray<ArrayList<Long>> mids) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Ba7iPuQLurNXSjv1CK6t6fD69Pg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didAddedNewTask$40$MessagesController(minDate);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$AHOqf9o-f3SX_SROksNwmirzVSU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didAddedNewTask$41$MessagesController(mids);
            }
        });
    }

    public /* synthetic */ void lambda$didAddedNewTask$40$MessagesController(int minDate) {
        int i;
        if ((this.currentDeletingTaskMids == null && !this.gettingNewDeleteTask) || ((i = this.currentDeletingTaskTime) != 0 && minDate < i)) {
            getNewDeleteTask(null, 0);
        }
    }

    public /* synthetic */ void lambda$didAddedNewTask$41$MessagesController(SparseArray mids) {
        getNotificationCenter().postNotificationName(NotificationCenter.didCreatedNewDeleteTask, mids);
    }

    public void getNewDeleteTask(final ArrayList<Integer> oldTask, final int channelId) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HVyL9AE10SdqolqwNW9-uW2ye8w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getNewDeleteTask$42$MessagesController(oldTask, channelId);
            }
        });
    }

    public /* synthetic */ void lambda$getNewDeleteTask$42$MessagesController(ArrayList oldTask, int channelId) {
        this.gettingNewDeleteTask = true;
        getMessagesStorage().getNewTask(oldTask, channelId);
    }

    private boolean checkDeletingTask(boolean runnable) {
        int i;
        int currentServerTime = getConnectionsManager().getCurrentTime();
        if (this.currentDeletingTaskMids == null || (!runnable && ((i = this.currentDeletingTaskTime) == 0 || i > currentServerTime))) {
            return false;
        }
        this.currentDeletingTaskTime = 0;
        if (this.currentDeleteTaskRunnable != null && !runnable) {
            Utilities.stageQueue.cancelRunnable(this.currentDeleteTaskRunnable);
        }
        this.currentDeleteTaskRunnable = null;
        final ArrayList<Integer> mids = new ArrayList<>(this.currentDeletingTaskMids);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$w7XIgDqlozvjD4EZSl4o_TlXdS8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkDeletingTask$44$MessagesController(mids);
            }
        });
        return true;
    }

    public /* synthetic */ void lambda$checkDeletingTask$44$MessagesController(final ArrayList mids) {
        if (!mids.isEmpty() && ((Integer) mids.get(0)).intValue() > 0) {
            getMessagesStorage().emptyMessagesMedia(mids);
        } else {
            deleteMessages(mids, null, null, 0L, 0, false, false);
        }
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$xjQwS6ppJCjk4MvwyWTvwV8VUSM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$43$MessagesController(mids);
            }
        });
    }

    public /* synthetic */ void lambda$null$43$MessagesController(ArrayList mids) {
        getNewDeleteTask(mids, this.currentDeletingTaskChannelId);
        this.currentDeletingTaskTime = 0;
        this.currentDeletingTaskMids = null;
    }

    public void processLoadedDeleteTask(final int taskTime, final ArrayList<Integer> messages, int channelId) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$GOcwDQODCcmnwXDq5LXUSdfNc34
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedDeleteTask$46$MessagesController(messages, taskTime);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedDeleteTask$46$MessagesController(ArrayList messages, int taskTime) {
        this.gettingNewDeleteTask = false;
        if (messages != null) {
            this.currentDeletingTaskTime = taskTime;
            this.currentDeletingTaskMids = messages;
            if (this.currentDeleteTaskRunnable != null) {
                Utilities.stageQueue.cancelRunnable(this.currentDeleteTaskRunnable);
                this.currentDeleteTaskRunnable = null;
            }
            if (!checkDeletingTask(false)) {
                this.currentDeleteTaskRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Sg9B_lQHbQXzS7-a1aa9KOcJVk4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$45$MessagesController();
                    }
                };
                int currentServerTime = getConnectionsManager().getCurrentTime();
                Utilities.stageQueue.postRunnable(this.currentDeleteTaskRunnable, ((long) Math.abs(currentServerTime - this.currentDeletingTaskTime)) * 1000);
                return;
            }
            return;
        }
        this.currentDeletingTaskTime = 0;
        this.currentDeletingTaskMids = null;
    }

    public /* synthetic */ void lambda$null$45$MessagesController() {
        checkDeletingTask(true);
    }

    public void loadDialogPhotos(final int did, final int count, final long max_id, boolean fromCache, final int classGuid) {
        if (fromCache) {
            getMessagesStorage().getDialogPhotos(did, count, max_id, classGuid);
            return;
        }
        if (did > 0) {
            TLRPC.User user = getUser(Integer.valueOf(did));
            if (user == null) {
                return;
            }
            TLRPC.TL_photos_getUserPhotos req = new TLRPC.TL_photos_getUserPhotos();
            req.limit = count;
            req.offset = 0;
            req.max_id = (int) max_id;
            req.user_id = getInputUser(user);
            int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$GKFg6CSUbqruGe5J8K7aKcgjSNs
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadDialogPhotos$47$MessagesController(did, count, max_id, classGuid, tLObject, tL_error);
                }
            });
            getConnectionsManager().bindRequestToGuid(reqId, classGuid);
            return;
        }
        if (did < 0) {
            TLRPC.TL_messages_search req2 = new TLRPC.TL_messages_search();
            req2.filter = new TLRPC.TL_inputMessagesFilterChatPhotos();
            req2.limit = count;
            req2.offset_id = (int) max_id;
            req2.q = "";
            req2.peer = getInputPeer(did);
            int reqId2 = getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$qoYTERJ7WNCLj2thPBcy9tTL2A4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadDialogPhotos$48$MessagesController(did, count, max_id, classGuid, tLObject, tL_error);
                }
            });
            getConnectionsManager().bindRequestToGuid(reqId2, classGuid);
        }
    }

    public /* synthetic */ void lambda$loadDialogPhotos$47$MessagesController(int did, int count, long max_id, int classGuid, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.photos_Photos res = (TLRPC.photos_Photos) response;
            processLoadedUserPhotos(res, did, count, max_id, false, classGuid);
        }
    }

    public /* synthetic */ void lambda$loadDialogPhotos$48$MessagesController(int did, int count, long max_id, int classGuid, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages messages = (TLRPC.messages_Messages) response;
            TLRPC.TL_photos_photos res = new TLRPC.TL_photos_photos();
            res.count = messages.count;
            res.users.addAll(messages.users);
            for (int a = 0; a < messages.messages.size(); a++) {
                TLRPC.Message message = messages.messages.get(a);
                if (message.action != null && message.action.photo != null) {
                    res.photos.add(message.action.photo);
                }
            }
            processLoadedUserPhotos(res, did, count, max_id, false, classGuid);
        }
    }

    public void blockUser(int user_id) {
        TLRPC.User user = getUser(Integer.valueOf(user_id));
        if (user == null || this.blockedUsers.indexOfKey(user_id) >= 0) {
            return;
        }
        this.blockedUsers.put(user_id, 1);
        if (user.bot) {
            getMediaDataController().removeInline(user_id);
        } else {
            getMediaDataController().removePeer(user_id);
        }
        int i = this.totalBlockedCount;
        if (i >= 0) {
            this.totalBlockedCount = i + 1;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.blockedUsersDidLoad, new Object[0]);
        TLRPC.TL_contacts_block req = new TLRPC.TL_contacts_block();
        req.id = getInputUser(user);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$vdcCtL9u8d3OR8Kx_p8U1u_SZjI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MessagesController.lambda$blockUser$49(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$blockUser$49(TLObject response, TLRPC.TL_error error) {
    }

    public void setUserBannedRole(final int chatId, TLRPC.User user, TLRPC.TL_chatBannedRights rights, final boolean isChannel, final BaseFragment parentFragment) {
        if (user == null || rights == null) {
            return;
        }
        final TLRPC.TL_channels_editBanned req = new TLRPC.TL_channels_editBanned();
        req.channel = getInputChannel(chatId);
        req.user_id = getInputUser(user);
        req.banned_rights = rights;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$BHguzhqq_dttONL1Bzg638klJLs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$setUserBannedRole$52$MessagesController(chatId, parentFragment, req, isChannel, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$setUserBannedRole$52$MessagesController(final int chatId, final BaseFragment parentFragment, final TLRPC.TL_channels_editBanned req, final boolean isChannel, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error == null) {
            processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$pFiu5OR9ZeUQZ6vTKD-rupQhmCw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$50$MessagesController(chatId);
                }
            }, 1000L);
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$v51gjsq5ejL540hAzhZ6Cpc4CIo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$51$MessagesController(error, parentFragment, req, isChannel);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$50$MessagesController(int chatId) {
        loadFullChat(chatId, 0, true);
    }

    public /* synthetic */ void lambda$null$51$MessagesController(TLRPC.TL_error error, BaseFragment parentFragment, TLRPC.TL_channels_editBanned req, boolean isChannel) {
        AlertsCreator.processError(this.currentAccount, error, parentFragment, req, Boolean.valueOf(isChannel));
    }

    public void setChannelSlowMode(final int chatId, int seconds) {
        TLRPC.TL_channels_toggleSlowMode req = new TLRPC.TL_channels_toggleSlowMode();
        req.seconds = seconds;
        req.channel = getInputChannel(chatId);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$5-uhPwmBDgCgqsbJWbytSkpiBPs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$setChannelSlowMode$54$MessagesController(chatId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$setChannelSlowMode$54$MessagesController(final int chatId, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$v75j3NHK_GMKjmqznQiP49KsSxo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$53$MessagesController(chatId);
                }
            }, 1000L);
        }
    }

    public /* synthetic */ void lambda$null$53$MessagesController(int chatId) {
        loadFullChat(chatId, 0, true);
    }

    public void setDefaultBannedRole(final int chatId, TLRPC.TL_chatBannedRights rights, final boolean isChannel, final BaseFragment parentFragment) {
        if (rights == null) {
            return;
        }
        final TLRPC.TL_messages_editChatDefaultBannedRights req = new TLRPC.TL_messages_editChatDefaultBannedRights();
        req.peer = getInputPeer(-chatId);
        req.banned_rights = rights;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$sLFOjIuJkbf8m7xFFThmTsIpzTs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$setDefaultBannedRole$57$MessagesController(chatId, parentFragment, req, isChannel, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$setDefaultBannedRole$57$MessagesController(final int chatId, final BaseFragment parentFragment, final TLRPC.TL_messages_editChatDefaultBannedRights req, final boolean isChannel, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error == null) {
            processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kqz32rFHHheQBHrwvenTpoD9FvI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$55$MessagesController(chatId);
                }
            }, 1000L);
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$IaCkvpDg2t4pkXzv4ce888H7UnM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$56$MessagesController(error, parentFragment, req, isChannel);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$55$MessagesController(int chatId) {
        loadFullChat(chatId, 0, true);
    }

    public /* synthetic */ void lambda$null$56$MessagesController(TLRPC.TL_error error, BaseFragment parentFragment, TLRPC.TL_messages_editChatDefaultBannedRights req, boolean isChannel) {
        AlertsCreator.processError(this.currentAccount, error, parentFragment, req, Boolean.valueOf(isChannel));
    }

    public void setUserAdminRole(final int chatId, TLRPC.User user, TLRPC.TL_chatAdminRights rights, String rank, final boolean isChannel, final BaseFragment parentFragment, boolean addingNew) {
        if (user != null && rights != null) {
            TLRPC.Chat chat = getChat(Integer.valueOf(chatId));
            if (ChatObject.isChannel(chat)) {
                final TLRPC.TL_channels_editAdmin req = new TLRPC.TL_channels_editAdmin();
                req.channel = getInputChannel(chat);
                req.user_id = getInputUser(user);
                req.admin_rights = rights;
                req.rank = rank;
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$JdGi-HXQGKVZJm5aS73Eu6X0ihQ
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                        this.f$0.lambda$setUserAdminRole$60$MessagesController(chatId, parentFragment, req, isChannel, tLObject, tL_error);
                    }
                });
                return;
            }
            final TLRPC.TL_messages_editChatAdmin req2 = new TLRPC.TL_messages_editChatAdmin();
            req2.chat_id = chatId;
            req2.user_id = getInputUser(user);
            req2.is_admin = rights.change_info || rights.delete_messages || rights.ban_users || rights.invite_users || rights.pin_messages || rights.add_admins;
            final RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$jN1dE2osefVMQZU_Z_Qcoh2ywIE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$setUserAdminRole$63$MessagesController(chatId, parentFragment, req2, tLObject, tL_error);
                }
            };
            if (req2.is_admin && addingNew) {
                addUserToChat(chatId, user, null, 0, null, parentFragment, new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$3mnGempqNSKOToEKJUKskxAJ_dE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$setUserAdminRole$64$MessagesController(req2, requestDelegate);
                    }
                });
            } else {
                getConnectionsManager().sendRequest(req2, requestDelegate);
            }
        }
    }

    public /* synthetic */ void lambda$setUserAdminRole$60$MessagesController(final int chatId, final BaseFragment parentFragment, final TLRPC.TL_channels_editAdmin req, final boolean isChannel, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error == null) {
            processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$zCEJGaq4OsMbrsSB2xrWleO7GfI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$58$MessagesController(chatId);
                }
            }, 1000L);
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HUsrX6G_i0R0Rw0BmdQMPTPYGB0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$59$MessagesController(error, parentFragment, req, isChannel);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$58$MessagesController(int chatId) {
        loadFullChat(chatId, 0, true);
    }

    public /* synthetic */ void lambda$null$59$MessagesController(TLRPC.TL_error error, BaseFragment parentFragment, TLRPC.TL_channels_editAdmin req, boolean isChannel) {
        AlertsCreator.processError(this.currentAccount, error, parentFragment, req, Boolean.valueOf(isChannel));
    }

    public /* synthetic */ void lambda$setUserAdminRole$63$MessagesController(final int chatId, final BaseFragment parentFragment, final TLRPC.TL_messages_editChatAdmin req, TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$yMfGXowOI9_MQ5g0s875LDelJc4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$61$MessagesController(chatId);
                }
            }, 1000L);
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$LgQXvKlpIMQsOGR_D-a_6YF4gqY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$62$MessagesController(error, parentFragment, req);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$61$MessagesController(int chatId) {
        loadFullChat(chatId, 0, true);
    }

    public /* synthetic */ void lambda$null$62$MessagesController(TLRPC.TL_error error, BaseFragment parentFragment, TLRPC.TL_messages_editChatAdmin req) {
        AlertsCreator.processError(this.currentAccount, error, parentFragment, req, false);
    }

    public /* synthetic */ void lambda$setUserAdminRole$64$MessagesController(TLRPC.TL_messages_editChatAdmin req, RequestDelegate requestDelegate) {
        getConnectionsManager().sendRequest(req, requestDelegate);
    }

    public void unblockUser(int user_id) {
        TLRPC.TL_contacts_unblock req = new TLRPC.TL_contacts_unblock();
        TLRPC.User user = getUser(Integer.valueOf(user_id));
        if (user == null) {
            return;
        }
        this.totalBlockedCount--;
        this.blockedUsers.delete(user.id);
        req.id = getInputUser(user);
        getNotificationCenter().postNotificationName(NotificationCenter.blockedUsersDidLoad, new Object[0]);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$AlfHwPv774-eSAOSO69oX5Ik8-M
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MessagesController.lambda$unblockUser$65(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$unblockUser$65(TLObject response, TLRPC.TL_error error) {
    }

    public void getBlockedUsers(final boolean reset) {
        if (!getUserConfig().isClientActivated() || this.loadingBlockedUsers) {
            return;
        }
        this.loadingBlockedUsers = true;
        final TLRPC.TL_contacts_getBlocked req = new TLRPC.TL_contacts_getBlocked();
        req.offset = reset ? 0 : this.blockedUsers.size();
        req.limit = reset ? 20 : 100;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$bdwI61fynprx_j_VF4bBHmqCMHo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getBlockedUsers$67$MessagesController(reset, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$getBlockedUsers$67$MessagesController(final boolean reset, final TLRPC.TL_contacts_getBlocked req, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$tom-WiCPKcdv1_wcHucO1ZR6xx0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$66$MessagesController(response, reset, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$66$MessagesController(TLObject response, boolean reset, TLRPC.TL_contacts_getBlocked req) {
        if (response != null) {
            TLRPC.contacts_Blocked res = (TLRPC.contacts_Blocked) response;
            putUsers(res.users, false);
            getMessagesStorage().putUsersAndChats(res.users, null, true, true);
            if (reset) {
                this.blockedUsers.clear();
            }
            this.totalBlockedCount = Math.max(res.count, res.blocked.size());
            this.blockedEndReached = res.blocked.size() < req.limit;
            int N = res.blocked.size();
            for (int a = 0; a < N; a++) {
                TLRPC.TL_contactBlocked blocked = res.blocked.get(a);
                this.blockedUsers.put(blocked.user_id, 1);
            }
            this.loadingBlockedUsers = false;
            getNotificationCenter().postNotificationName(NotificationCenter.blockedUsersDidLoad, new Object[0]);
        }
    }

    public void deleteUserPhoto(TLRPC.InputPhoto photo) {
        if (photo == null) {
            TLRPC.TL_photos_updateProfilePhoto req = new TLRPC.TL_photos_updateProfilePhoto();
            req.id = new TLRPC.TL_inputPhotoEmpty();
            getUserConfig().getCurrentUser().photo = new TLRPC.TL_userProfilePhotoEmpty();
            TLRPC.User user = getUser(Integer.valueOf(getUserConfig().getClientUserId()));
            if (user == null) {
                user = getUserConfig().getCurrentUser();
            }
            if (user == null) {
                return;
            }
            user.photo = getUserConfig().getCurrentUser().photo;
            getNotificationCenter().postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(UPDATE_MASK_ALL));
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HYdylcsw2MUJP-nyrM7H-v7pMkk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$deleteUserPhoto$69$MessagesController(tLObject, tL_error);
                }
            });
            return;
        }
        TLRPC.TL_photos_deletePhotos req2 = new TLRPC.TL_photos_deletePhotos();
        req2.id.add(photo);
        getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$IBaBqdM-dU9B7A3ITbVO5SsGx1g
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MessagesController.lambda$deleteUserPhoto$70(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteUserPhoto$69$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.User user1 = getUser(Integer.valueOf(getUserConfig().getClientUserId()));
            if (user1 == null) {
                user1 = getUserConfig().getCurrentUser();
                putUser(user1, false);
            } else {
                getUserConfig().setCurrentUser(user1);
            }
            if (user1 == null) {
                return;
            }
            getMessagesStorage().clearUserPhotos(user1.id);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user1);
            getMessagesStorage().putUsersAndChats(users, null, false, true);
            user1.photo = (TLRPC.UserProfilePhoto) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$G4xD_d8RpUnBNQUEBqrOLzsKcR0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$68$MessagesController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$68$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(UPDATE_MASK_ALL));
        getUserConfig().saveConfig(true);
    }

    static /* synthetic */ void lambda$deleteUserPhoto$70(TLObject response, TLRPC.TL_error error) {
    }

    public void processLoadedUserPhotos(final TLRPC.photos_Photos res, final int did, final int count, long max_id, final boolean fromCache, final int classGuid) {
        if (!fromCache) {
            getMessagesStorage().putUsersAndChats(res.users, null, true, true);
            getMessagesStorage().putDialogPhotos(did, res);
        } else if (res == null || res.photos.isEmpty()) {
            loadDialogPhotos(did, count, max_id, false, classGuid);
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$iTXnddr2twslN9MvMEAunQypBWw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedUserPhotos$71$MessagesController(res, fromCache, did, count, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedUserPhotos$71$MessagesController(TLRPC.photos_Photos res, boolean fromCache, int did, int count, int classGuid) {
        putUsers(res.users, fromCache);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogPhotosLoaded, Integer.valueOf(did), Integer.valueOf(count), Boolean.valueOf(fromCache), Integer.valueOf(classGuid), res.photos);
    }

    public void uploadAndApplyUserAvatar(TLRPC.FileLocation location) {
        if (location == null) {
            return;
        }
        this.uploadingAvatar = FileLoader.getDirectory(4) + "/" + location.volume_id + "_" + location.local_id + ".jpg";
        getFileLoader().uploadFile(this.uploadingAvatar, false, true, 16777216);
    }

    public void uploadAvatar(TLRPC.FileLocation location) {
        if (location == null) {
            return;
        }
        this.uploadingAvatar = FileLoader.getDirectory(4) + "/" + location.volume_id + "_" + location.local_id + ".jpg";
        getFileLoader().uploadFile(this.uploadingAvatar, false, true, 16777216, false);
    }

    public void saveTheme(Theme.ThemeInfo themeInfo, boolean night, boolean unsave) {
        if (themeInfo.info != null) {
            TLRPC.TL_account_saveTheme req = new TLRPC.TL_account_saveTheme();
            TLRPC.TL_inputTheme inputTheme = new TLRPC.TL_inputTheme();
            inputTheme.id = themeInfo.info.id;
            inputTheme.access_hash = themeInfo.info.access_hash;
            req.theme = inputTheme;
            req.unsave = unsave;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$2KVY-ZMjE9wuQU6x1c3ROvoNpcc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$saveTheme$72(tLObject, tL_error);
                }
            });
        }
        if (!unsave) {
            installTheme(themeInfo, night);
        }
    }

    static /* synthetic */ void lambda$saveTheme$72(TLObject response, TLRPC.TL_error error) {
    }

    public void installTheme(Theme.ThemeInfo themeInfo, boolean night) {
        TLRPC.TL_account_installTheme req = new TLRPC.TL_account_installTheme();
        req.dark = night;
        if (themeInfo.info != null) {
            req.format = "android";
            TLRPC.TL_inputTheme inputTheme = new TLRPC.TL_inputTheme();
            inputTheme.id = themeInfo.info.id;
            inputTheme.access_hash = themeInfo.info.access_hash;
            req.theme = inputTheme;
            req.flags |= 2;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$aUxbZ-a-imaPvGrGoh06VNxsAi4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MessagesController.lambda$installTheme$73(tLObject, tL_error);
            }
        });
        if (!TextUtils.isEmpty(themeInfo.slug)) {
            TLRPC.TL_account_installWallPaper req2 = new TLRPC.TL_account_installWallPaper();
            TLRPC.TL_inputWallPaperSlug inputWallPaperSlug = new TLRPC.TL_inputWallPaperSlug();
            inputWallPaperSlug.slug = themeInfo.slug;
            req2.wallpaper = inputWallPaperSlug;
            req2.settings = new TLRPC.TL_wallPaperSettings();
            req2.settings.blur = themeInfo.isBlured;
            req2.settings.motion = themeInfo.isMotion;
            getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$NedXDG-jGdQd5cChMzKqnQR5z5g
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$installTheme$74(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$installTheme$73(TLObject response, TLRPC.TL_error error) {
    }

    static /* synthetic */ void lambda$installTheme$74(TLObject response, TLRPC.TL_error error) {
    }

    public void saveThemeToServer(final Theme.ThemeInfo themeInfo) {
        if (themeInfo == null || this.uploadingThemes.containsKey(themeInfo.pathToFile)) {
            return;
        }
        this.uploadingThemes.put(themeInfo.pathToFile, themeInfo);
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Y46XIx_XV0ESMe9xRo2zrr0NETs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveThemeToServer$76$MessagesController(themeInfo);
            }
        });
    }

    public /* synthetic */ void lambda$saveThemeToServer$76$MessagesController(final Theme.ThemeInfo themeInfo) {
        final String thumbPath = Theme.createThemePreviewImage(themeInfo);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$U__BqS6fuziKVxSvDIhdlSO_9Hw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$75$MessagesController(thumbPath, themeInfo);
            }
        });
    }

    public /* synthetic */ void lambda$null$75$MessagesController(String thumbPath, Theme.ThemeInfo themeInfo) {
        if (thumbPath == null) {
            this.uploadingThemes.remove(themeInfo.pathToFile);
            return;
        }
        themeInfo.uploadingFile = themeInfo.pathToFile;
        themeInfo.uploadingThumb = thumbPath;
        this.uploadingThemes.put(thumbPath, themeInfo);
        File f = new File(themeInfo.pathToFile);
        f.length();
        File f2 = new File(thumbPath);
        f2.length();
        getFileLoader().uploadFile(themeInfo.pathToFile, false, true, ConnectionsManager.FileTypeFile);
        getFileLoader().uploadFile(thumbPath, false, true, 16777216);
    }

    public void saveWallpaperToServer(File path, final long wallPaperId, final String slug, long accessHash, boolean isBlurred, boolean isMotion, int backgroundColor, float intesity, final boolean install, long taskId) {
        TLObject req;
        long newTaskId;
        if (this.uploadingWallpaper != null) {
            File finalPath = new File(ApplicationLoader.getFilesDirFixed(), this.uploadingWallpaperBlurred ? "wallpaper_original.jpg" : "wallpaper.jpg");
            if (path == null || (!path.getAbsolutePath().equals(this.uploadingWallpaper) && !path.equals(finalPath))) {
                getFileLoader().cancelUploadFile(this.uploadingWallpaper, false);
                this.uploadingWallpaper = null;
            } else {
                this.uploadingWallpaperMotion = isMotion;
                this.uploadingWallpaperBlurred = isBlurred;
                return;
            }
        }
        if (path != null) {
            this.uploadingWallpaper = path.getAbsolutePath();
            this.uploadingWallpaperMotion = isMotion;
            this.uploadingWallpaperBlurred = isBlurred;
            getFileLoader().uploadFile(this.uploadingWallpaper, false, true, 16777216);
            return;
        }
        if (accessHash != 0) {
            TLRPC.TL_inputWallPaper inputWallPaper = new TLRPC.TL_inputWallPaper();
            inputWallPaper.id = wallPaperId;
            inputWallPaper.access_hash = accessHash;
            TLRPC.TL_wallPaperSettings settings = new TLRPC.TL_wallPaperSettings();
            settings.blur = isBlurred;
            settings.motion = isMotion;
            if (backgroundColor != 0) {
                settings.background_color = backgroundColor;
                settings.flags = 1 | settings.flags;
                settings.intensity = (int) (100.0f * intesity);
                settings.flags |= 8;
            }
            if (install) {
                TLRPC.TL_account_installWallPaper request = new TLRPC.TL_account_installWallPaper();
                request.wallpaper = inputWallPaper;
                request.settings = settings;
                req = request;
            } else {
                TLRPC.TL_account_saveWallPaper request2 = new TLRPC.TL_account_saveWallPaper();
                request2.wallpaper = inputWallPaper;
                request2.settings = settings;
                req = request2;
            }
            if (taskId != 0) {
                newTaskId = taskId;
            } else {
                NativeByteBuffer data = null;
                try {
                    try {
                        data = new NativeByteBuffer(1024);
                    } catch (Exception e) {
                        e = e;
                        data = null;
                    }
                } catch (Exception e2) {
                    e = e2;
                }
                try {
                    data.writeInt32(19);
                    data.writeInt64(wallPaperId);
                    data.writeInt64(accessHash);
                    data.writeBool(isBlurred);
                    data.writeBool(isMotion);
                    data.writeInt32(backgroundColor);
                    data.writeDouble(intesity);
                    data.writeBool(install);
                    if (slug != null) {
                        data.writeString(slug);
                    } else {
                        data.writeString("");
                    }
                    data.limit(data.position());
                } catch (Exception e3) {
                    e = e3;
                    FileLog.e(e);
                }
                newTaskId = getMessagesStorage().createPendingTask(data);
            }
            final long j = newTaskId;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$egDNK2r2uDKuiFDnR7vw-IXXfV0
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$saveWallpaperToServer$77$MessagesController(j, install, wallPaperId, slug, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$saveWallpaperToServer$77$MessagesController(long newTaskId, boolean install, long wallPaperId, String slug, TLObject response, TLRPC.TL_error error) {
        getMessagesStorage().removePendingTask(newTaskId);
        if (!install && this.uploadingWallpaper != null) {
            SharedPreferences preferences = getGlobalMainSettings();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putLong("selectedBackground2", wallPaperId);
            if (!TextUtils.isEmpty(slug)) {
                editor.putString("selectedBackgroundSlug", slug);
            } else {
                editor.remove("selectedBackgroundSlug");
            }
            editor.commit();
        }
    }

    public void markChannelDialogMessageAsDeleted(ArrayList<Integer> messages, int channelId) {
        MessageObject obj = this.dialogMessage.get(-channelId);
        if (obj != null) {
            for (int a = 0; a < messages.size(); a++) {
                Integer id = messages.get(a);
                if (obj.getId() == id.intValue()) {
                    obj.deleted = true;
                    return;
                }
            }
        }
    }

    public void deleteMessages(ArrayList<Integer> messages, ArrayList<Long> randoms, TLRPC.EncryptedChat encryptedChat, long dialogId, int channelId, boolean forAll, boolean scheduled) {
        deleteMessages(messages, randoms, encryptedChat, dialogId, channelId, forAll, scheduled, 0L, null);
    }

    public void deleteMessages(ArrayList<Integer> messages, ArrayList<Long> randoms, TLRPC.EncryptedChat encryptedChat, long dialogId, final int channelId, boolean forAll, boolean scheduled, long taskId, TLObject taskRequest) {
        ArrayList<Integer> toSend;
        final long newTaskId;
        TLRPC.TL_messages_deleteMessages req;
        TLRPC.TL_channels_deleteMessages req2;
        final long newTaskId2;
        TLRPC.TL_messages_deleteScheduledMessages req3;
        final long newTaskId3;
        if ((messages == null || messages.isEmpty()) && taskRequest == null) {
            return;
        }
        if (taskId != 0) {
            toSend = null;
        } else {
            ArrayList<Integer> toSend2 = new ArrayList<>();
            for (int a = 0; a < messages.size(); a++) {
                Integer mid = messages.get(a);
                if (mid.intValue() > 0) {
                    toSend2.add(mid);
                }
            }
            if (scheduled) {
                getMessagesStorage().markMessagesAsDeleted(messages, true, channelId, false, true);
            } else {
                if (channelId == 0) {
                    for (int a2 = 0; a2 < messages.size(); a2++) {
                        Integer id = messages.get(a2);
                        MessageObject obj = this.dialogMessagesByIds.get(id.intValue());
                        if (obj != null) {
                            obj.deleted = true;
                        }
                    }
                } else {
                    markChannelDialogMessageAsDeleted(messages, channelId);
                }
                getMessagesStorage().markMessagesAsDeleted(messages, true, channelId, forAll, false);
                getMessagesStorage().updateDialogsWithDeletedMessages(messages, null, true, channelId);
            }
            getNotificationCenter().postNotificationName(NotificationCenter.messagesDeleted, messages, Integer.valueOf(channelId), Boolean.valueOf(scheduled));
            toSend = toSend2;
        }
        if (scheduled) {
            if (taskRequest != null) {
                req3 = (TLRPC.TL_messages_deleteScheduledMessages) taskRequest;
                newTaskId3 = taskId;
            } else {
                TLRPC.TL_messages_deleteScheduledMessages req4 = new TLRPC.TL_messages_deleteScheduledMessages();
                req4.id = toSend;
                req4.peer = getInputPeer((int) dialogId);
                NativeByteBuffer data = null;
                try {
                    data = new NativeByteBuffer(req4.getObjectSize() + 16);
                    data.writeInt32(18);
                    data.writeInt64(dialogId);
                    data.writeInt32(channelId);
                    req4.serializeToStream(data);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                req3 = req4;
                newTaskId3 = MessagesStorage.getInstance(this.currentAccount).createPendingTask(data);
            }
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$8UCT1VV43lSTBOCkklkBZg8H3Bw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                    this.f$0.lambda$deleteMessages$78$MessagesController(newTaskId3, tLObject, tL_error);
                }
            });
            return;
        }
        if (channelId != 0) {
            if (taskRequest != null) {
                req2 = (TLRPC.TL_channels_deleteMessages) taskRequest;
                newTaskId2 = taskId;
            } else {
                TLRPC.TL_channels_deleteMessages req5 = new TLRPC.TL_channels_deleteMessages();
                req5.id = toSend;
                req5.channel = getInputChannel(channelId);
                NativeByteBuffer data2 = null;
                try {
                    data2 = new NativeByteBuffer(req5.getObjectSize() + 8);
                    data2.writeInt32(7);
                    data2.writeInt32(channelId);
                    req5.serializeToStream(data2);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                req2 = req5;
                newTaskId2 = getMessagesStorage().createPendingTask(data2);
            }
            getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$RNquOvW5I1e-9ugKvr2XMEOdoAI
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$deleteMessages$79$MessagesController(channelId, newTaskId2, tLObject, tL_error);
                }
            });
            return;
        }
        if (randoms != null && encryptedChat != null && !randoms.isEmpty()) {
            getSecretChatHelper().sendMessagesDeleteMessage(encryptedChat, randoms, null);
        }
        if (taskRequest != null) {
            req = (TLRPC.TL_messages_deleteMessages) taskRequest;
            newTaskId = taskId;
        } else {
            TLRPC.TL_messages_deleteMessages req6 = new TLRPC.TL_messages_deleteMessages();
            req6.id = toSend;
            req6.revoke = forAll;
            NativeByteBuffer data3 = null;
            try {
                data3 = new NativeByteBuffer(req6.getObjectSize() + 8);
                data3.writeInt32(7);
                data3.writeInt32(channelId);
                req6.serializeToStream(data3);
            } catch (Exception e3) {
                FileLog.e(e3);
            }
            newTaskId = getMessagesStorage().createPendingTask(data3);
            req = req6;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$pwKqpRKjdVAfKEv9mS_V7DPeBLY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$deleteMessages$80$MessagesController(newTaskId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteMessages$78$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            processUpdates(updates, false);
        }
        if (newTaskId != 0) {
            MessagesStorage.getInstance(this.currentAccount).removePendingTask(newTaskId);
        }
    }

    public /* synthetic */ void lambda$deleteMessages$79$MessagesController(int channelId, long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_affectedMessages res = (TLRPC.TL_messages_affectedMessages) response;
            processNewChannelDifferenceParams(res.pts, res.pts_count, channelId);
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public /* synthetic */ void lambda$deleteMessages$80$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_affectedMessages res = (TLRPC.TL_messages_affectedMessages) response;
            processNewDifferenceParams(-1, res.pts, -1, res.pts_count);
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public void pinMessage(TLRPC.Chat chat, TLRPC.User user, int id, boolean notify) {
        if (chat == null && user == null) {
            return;
        }
        TLRPC.TL_messages_updatePinnedMessage req = new TLRPC.TL_messages_updatePinnedMessage();
        req.peer = getInputPeer(chat != null ? -chat.id : user.id);
        req.id = id;
        req.silent = !notify;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$rQvzd4pwDPvmQxbr_hKTl46Xs2c
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$pinMessage$81$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$pinMessage$81$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            processUpdates(updates, false);
        }
    }

    public void deleteUserChannelHistory(final TLRPC.Chat chat, final TLRPC.User user, int offset) {
        if (offset == 0) {
            getMessagesStorage().deleteUserChannelHistory(chat.id, user.id);
        }
        TLRPC.TL_channels_deleteUserHistory req = new TLRPC.TL_channels_deleteUserHistory();
        req.channel = getInputChannel(chat);
        req.user_id = getInputUser(user);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Lob2cxUnVMZDwtsDRkrhiHXSMeo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$deleteUserChannelHistory$82$MessagesController(chat, user, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteUserChannelHistory$82$MessagesController(TLRPC.Chat chat, TLRPC.User user, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_affectedHistory res = (TLRPC.TL_messages_affectedHistory) response;
            if (res.offset > 0) {
                deleteUserChannelHistory(chat, user, res.offset);
            }
            processNewChannelDifferenceParams(res.pts, res.pts_count, chat.id);
        }
    }

    public ArrayList<TLRPC.Dialog> getAllDialogs() {
        return this.allDialogs;
    }

    public boolean isDialogsEndReached(int folderId) {
        return this.dialogsEndReached.get(folderId);
    }

    public boolean isLoadingDialogs(int folderId) {
        return this.loadingDialogs.get(folderId);
    }

    public boolean isServerDialogsEndReached(int folderId) {
        return this.serverDialogsEndReached.get(folderId);
    }

    public boolean hasHiddenArchive() {
        return SharedConfig.archiveHidden && this.dialogs_dict.get(DialogObject.makeFolderDialogId(1)) != null;
    }

    public ArrayList<TLRPC.Dialog> getDialogs(int folderId) {
        ArrayList<TLRPC.Dialog> dialogs = this.dialogsByFolder.get(folderId);
        if (dialogs == null) {
            return new ArrayList<>();
        }
        return dialogs;
    }

    private void removeDialog(TLRPC.Dialog dialog) {
        if (dialog == null) {
            return;
        }
        final long did = dialog.id;
        if (this.dialogsServerOnly.remove(dialog) && DialogObject.isChannel(dialog)) {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$GAsAERmlyeJkXUA7py-CdN3hEdw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$removeDialog$83$MessagesController(did);
                }
            });
        }
        this.allDialogs.remove(dialog);
        this.dialogsCanAddUsers.remove(dialog);
        this.dialogsChannelsOnly.remove(dialog);
        this.dialogsGroupsOnly.remove(dialog);
        this.dialogsUnreadOnly.remove(dialog);
        this.dialogsUsersOnly.remove(dialog);
        this.dialogsForward.remove(dialog);
        this.dialogs_dict.remove(did);
        this.dialogs_read_inbox_max.remove(Long.valueOf(did));
        this.dialogs_read_outbox_max.remove(Long.valueOf(did));
        ArrayList<TLRPC.Dialog> dialogs = this.dialogsByFolder.get(dialog.folder_id);
        if (dialogs != null) {
            dialogs.remove(dialog);
        }
    }

    public /* synthetic */ void lambda$removeDialog$83$MessagesController(long did) {
        this.channelsPts.delete(-((int) did));
        this.shortPollChannels.delete(-((int) did));
        this.needShortPollChannels.delete(-((int) did));
        this.shortPollOnlines.delete(-((int) did));
        this.needShortPollOnlines.delete(-((int) did));
    }

    public void deleteDialog(long did, int onlyHistory) {
        deleteDialog(did, onlyHistory, false);
    }

    public void deleteDialog(long did, int onlyHistory, boolean revoke) {
        deleteDialog(did, true, onlyHistory, 0, revoke, null, 0L);
    }

    public void setDialogsInTransaction(boolean transaction) {
        this.dialogsInTransaction = transaction;
        if (!transaction) {
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, true);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00a1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void deleteDialog(final long r34, boolean r36, final int r37, int r38, final boolean r39, im.uwrkaxlmjj.tgnet.TLRPC.InputPeer r40, long r41) {
        /*
            Method dump skipped, instruction units count: 840
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.deleteDialog(long, boolean, int, int, boolean, im.uwrkaxlmjj.tgnet.TLRPC$InputPeer, long):void");
    }

    public /* synthetic */ void lambda$deleteDialog$85$MessagesController(final long did) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$fUfZ0EJpLwvLnjeaFOfQQdP5Ajs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$84$MessagesController(did);
            }
        });
    }

    public /* synthetic */ void lambda$null$84$MessagesController(long did) {
        getNotificationsController().removeNotificationsForDialog(did);
    }

    public /* synthetic */ void lambda$deleteDialog$87$MessagesController(long newTaskId, final long did, TLObject response, TLRPC.TL_error error) {
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HvOHtgX1B7cVWY9ut4n28h46Vuw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$86$MessagesController(did);
            }
        });
    }

    public /* synthetic */ void lambda$null$86$MessagesController(long did) {
        this.deletedHistory.remove(did);
    }

    public /* synthetic */ void lambda$deleteDialog$88$MessagesController(long newTaskId, long did, int onlyHistory, int max_id_delete_final, boolean revoke, TLRPC.InputPeer peerFinal, TLObject response, TLRPC.TL_error error) {
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
        if (error == null) {
            TLRPC.TL_messages_affectedHistory res = (TLRPC.TL_messages_affectedHistory) response;
            if (res.offset > 0) {
                deleteDialog(did, false, onlyHistory, max_id_delete_final, revoke, peerFinal, 0L);
            }
            processNewDifferenceParams(-1, res.pts, -1, res.pts_count);
            getMessagesStorage().onDeleteQueryComplete(did);
        }
    }

    public void saveGif(final Object parentObject, TLRPC.Document document) {
        if (parentObject == null || !MessageObject.isGifDocument(document)) {
            return;
        }
        final TLRPC.TL_messages_saveGif req = new TLRPC.TL_messages_saveGif();
        req.id = new TLRPC.TL_inputDocument();
        req.id.id = document.id;
        req.id.access_hash = document.access_hash;
        req.id.file_reference = document.file_reference;
        if (req.id.file_reference == null) {
            req.id.file_reference = new byte[0];
        }
        req.unsave = false;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$O833rIKMNftrE-gjU7liCl6VZKY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveGif$89$MessagesController(parentObject, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$saveGif$89$MessagesController(Object parentObject, TLRPC.TL_messages_saveGif req, TLObject response, TLRPC.TL_error error) {
        if (error != null && FileRefController.isFileRefError(error.text) && parentObject != null) {
            getFileRefController().requestReference(parentObject, req);
        }
    }

    public void saveRecentSticker(final Object parentObject, TLRPC.Document document, boolean asMask) {
        if (parentObject == null || document == null) {
            return;
        }
        final TLRPC.TL_messages_saveRecentSticker req = new TLRPC.TL_messages_saveRecentSticker();
        req.id = new TLRPC.TL_inputDocument();
        req.id.id = document.id;
        req.id.access_hash = document.access_hash;
        req.id.file_reference = document.file_reference;
        if (req.id.file_reference == null) {
            req.id.file_reference = new byte[0];
        }
        req.unsave = false;
        req.attached = asMask;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$JdT5wBsh1hx38KhDYVExjulu6TY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveRecentSticker$90$MessagesController(parentObject, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$saveRecentSticker$90$MessagesController(Object parentObject, TLRPC.TL_messages_saveRecentSticker req, TLObject response, TLRPC.TL_error error) {
        if (error != null && FileRefController.isFileRefError(error.text) && parentObject != null) {
            getFileRefController().requestReference(parentObject, req);
        }
    }

    public void loadChannelParticipants(final Integer chat_id) {
        if (this.loadingFullParticipants.contains(chat_id) || this.loadedFullParticipants.contains(chat_id)) {
            return;
        }
        this.loadingFullParticipants.add(chat_id);
        TLRPC.TL_channels_getParticipants req = new TLRPC.TL_channels_getParticipants();
        req.channel = getInputChannel(chat_id.intValue());
        req.filter = new TLRPC.TL_channelParticipantsRecent();
        req.offset = 0;
        req.limit = 32;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$zlVh14iOUJnoegkiZmlmmZNWgzc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadChannelParticipants$92$MessagesController(chat_id, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadChannelParticipants$92$MessagesController(final Integer chat_id, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$PjyGvO_sZUt5y9D2B9DafINpRS4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$91$MessagesController(error, response, chat_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$91$MessagesController(TLRPC.TL_error error, TLObject response, Integer chat_id) {
        if (error == null && (response instanceof TLRPC.TL_channels_channelParticipants)) {
            TLRPC.TL_channels_channelParticipants res = (TLRPC.TL_channels_channelParticipants) response;
            putUsers(res.users, false);
            getMessagesStorage().putUsersAndChats(res.users, null, true, true);
            getMessagesStorage().updateChannelUsers(chat_id.intValue(), res.participants);
            this.loadedFullParticipants.add(chat_id);
        }
        this.loadingFullParticipants.remove(chat_id);
    }

    public void processChatInfo(final int chat_id, final TLRPC.ChatFull info, final ArrayList<TLRPC.User> usersArr, final boolean fromCache, final boolean force, final boolean byChannelUsers, final MessageObject pinnedMessageObject) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$sKNAZ42O5JM9UoyGVb8yl4i_gLY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processChatInfo$93$MessagesController(fromCache, chat_id, byChannelUsers, force, info, usersArr, pinnedMessageObject);
            }
        });
    }

    public /* synthetic */ void lambda$processChatInfo$93$MessagesController(boolean fromCache, int chat_id, boolean byChannelUsers, boolean force, TLRPC.ChatFull info, ArrayList usersArr, MessageObject pinnedMessageObject) {
        if (fromCache && chat_id > 0 && !byChannelUsers) {
            loadFullChat(chat_id, 0, force);
        }
        if (info != null) {
            if (this.fullChats.get(chat_id) == null) {
                this.fullChats.put(chat_id, info);
            }
            putUsers(usersArr, fromCache);
            if (info.stickerset != null) {
                getMediaDataController().getGroupStickerSetById(info.stickerset);
            }
            getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, info, 0, Boolean.valueOf(byChannelUsers), pinnedMessageObject);
        }
    }

    public void loadUserInfo(TLRPC.User user, boolean force, int classGuid) {
        getMessagesStorage().loadUserInfo(user, force, classGuid);
    }

    public void processUserInfo(final TLRPC.User user, final TLRPC.UserFull info, final boolean fromCache, final boolean force, final MessageObject pinnedMessageObject, final int classGuid) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$1SBTd-x5JwQqvos37R9KIhK8Ohs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processUserInfo$94$MessagesController(fromCache, user, classGuid, force, info, pinnedMessageObject);
            }
        });
    }

    public /* synthetic */ void lambda$processUserInfo$94$MessagesController(boolean fromCache, TLRPC.User user, int classGuid, boolean force, TLRPC.UserFull info, MessageObject pinnedMessageObject) {
        if (fromCache) {
            loadFullUser(user, classGuid, force);
        }
        if (info != null) {
            if (this.fullUsers.get(user.id) == null) {
                this.fullUsers.put(user.id, info);
                if (info.blocked) {
                    this.blockedUsers.put(user.id, 1);
                } else {
                    this.blockedUsers.delete(user.id);
                }
            }
            getNotificationCenter().postNotificationName(NotificationCenter.userFullInfoDidLoad, Integer.valueOf(user.id), info, pinnedMessageObject);
        }
    }

    public void updateTimerProc() throws Exception {
        int timeToRemove;
        long currentTime = System.currentTimeMillis();
        checkDeletingTask(false);
        checkReadTasks();
        if (getUserConfig().isClientActivated()) {
            if (getConnectionsManager().getPauseTime() == 0 && ApplicationLoader.isScreenOn && !ApplicationLoader.mainInterfacePausedStageQueue) {
                if (ApplicationLoader.mainInterfacePausedStageQueueTime != 0 && Math.abs(ApplicationLoader.mainInterfacePausedStageQueueTime - System.currentTimeMillis()) > 1000 && this.statusSettingState != 1 && (this.lastStatusUpdateTime == 0 || Math.abs(System.currentTimeMillis() - this.lastStatusUpdateTime) >= 55000 || this.offlineSent)) {
                    this.statusSettingState = 1;
                    if (this.statusRequest != 0) {
                        getConnectionsManager().cancelRequest(this.statusRequest, true);
                    }
                    TLRPC.TL_account_updateStatus req = new TLRPC.TL_account_updateStatus();
                    req.offline = false;
                    this.statusRequest = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Pyad5my4LX0SF7Odc6N4UqjzsC8
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$updateTimerProc$95$MessagesController(tLObject, tL_error);
                        }
                    });
                }
            } else if (this.statusSettingState != 2 && !this.offlineSent && Math.abs(System.currentTimeMillis() - getConnectionsManager().getPauseTime()) >= AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                this.statusSettingState = 2;
                if (this.statusRequest != 0) {
                    getConnectionsManager().cancelRequest(this.statusRequest, true);
                }
                TLRPC.TL_account_updateStatus req2 = new TLRPC.TL_account_updateStatus();
                req2.offline = true;
                this.statusRequest = getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$dzb4c8jEvVVs1gxAatS6u0aDY2U
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$updateTimerProc$96$MessagesController(tLObject, tL_error);
                    }
                });
            }
            if (this.updatesQueueChannels.size() != 0) {
                for (int a = 0; a < this.updatesQueueChannels.size(); a++) {
                    int key = this.updatesQueueChannels.keyAt(a);
                    long updatesStartWaitTime = this.updatesStartWaitTimeChannels.valueAt(a);
                    if (updatesStartWaitTime + 1500 < currentTime) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("QUEUE CHANNEL " + key + " UPDATES WAIT TIMEOUT - CHECK QUEUE");
                        }
                        processChannelsUpdatesQueue(key, 0);
                    }
                }
            }
            for (int a2 = 0; a2 < 3; a2++) {
                if (getUpdatesStartTime(a2) != 0 && getUpdatesStartTime(a2) + 1500 < currentTime) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d(a2 + " QUEUE UPDATES WAIT TIMEOUT - CHECK QUEUE");
                    }
                    processUpdatesQueue(a2, 0);
                }
            }
        }
        if (Math.abs(System.currentTimeMillis() - this.lastViewsCheckTime) >= DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS) {
            this.lastViewsCheckTime = System.currentTimeMillis();
            if (this.channelViewsToSend.size() != 0) {
                int a3 = 0;
                while (a3 < this.channelViewsToSend.size()) {
                    final int key2 = this.channelViewsToSend.keyAt(a3);
                    final TLRPC.TL_messages_getMessagesViews req3 = new TLRPC.TL_messages_getMessagesViews();
                    req3.peer = getInputPeer(key2);
                    req3.id = this.channelViewsToSend.valueAt(a3);
                    req3.increment = a3 == 0;
                    getConnectionsManager().sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Nu_PAGu1draRKbx1BPrvVOsm9BY
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$updateTimerProc$98$MessagesController(key2, req3, tLObject, tL_error);
                        }
                    });
                    a3++;
                }
                this.channelViewsToSend.clear();
            }
            if (this.pollsToCheckSize > 0) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$_GX4ANFBhTlH7PYbhqz3iLmdgAk
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$updateTimerProc$100$MessagesController();
                    }
                });
            }
        }
        if (!this.onlinePrivacy.isEmpty()) {
            ArrayList<Integer> toRemove = null;
            int currentServerTime = getConnectionsManager().getCurrentTime();
            for (Map.Entry<Integer, Integer> entry : this.onlinePrivacy.entrySet()) {
                if (entry.getValue().intValue() < currentServerTime - 30) {
                    if (toRemove == null) {
                        toRemove = new ArrayList<>();
                    }
                    toRemove.add(entry.getKey());
                }
            }
            if (toRemove != null) {
                for (Integer uid : toRemove) {
                    this.onlinePrivacy.remove(uid);
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$roukq0RgY0lDSfS9k1HoQOZdtDw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$updateTimerProc$101$MessagesController();
                    }
                });
            }
        }
        if (this.shortPollChannels.size() != 0) {
            int a4 = 0;
            while (a4 < this.shortPollChannels.size()) {
                int key3 = this.shortPollChannels.keyAt(a4);
                int timeout = this.shortPollChannels.valueAt(a4);
                if (timeout < System.currentTimeMillis() / 1000) {
                    this.shortPollChannels.delete(key3);
                    a4--;
                    if (this.needShortPollChannels.indexOfKey(key3) >= 0) {
                        getChannelDifference(key3);
                    }
                }
                a4++;
            }
        }
        if (this.shortPollOnlines.size() != 0) {
            long time = SystemClock.uptimeMillis() / 1000;
            int a5 = 0;
            while (a5 < this.shortPollOnlines.size()) {
                final int key4 = this.shortPollOnlines.keyAt(a5);
                int timeout2 = this.shortPollOnlines.valueAt(a5);
                if (timeout2 < time) {
                    if (this.needShortPollChannels.indexOfKey(key4) >= 0) {
                        this.shortPollOnlines.put(key4, (int) (300 + time));
                    } else {
                        this.shortPollOnlines.delete(key4);
                        a5--;
                    }
                    TLRPC.TL_messages_getOnlines req4 = new TLRPC.TL_messages_getOnlines();
                    req4.peer = getInputPeer(-key4);
                    getConnectionsManager().sendRequest(req4, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$NSI2YjPsqtl1fMV3wZ15EYjzp0s
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$updateTimerProc$103$MessagesController(key4, tLObject, tL_error);
                        }
                    });
                }
                a5++;
            }
        }
        if (!this.printingUsers.isEmpty() || this.lastPrintingStringCount != this.printingUsers.size()) {
            boolean updated = false;
            ArrayList<Long> keys = new ArrayList<>(this.printingUsers.keySet());
            int b = 0;
            while (b < keys.size()) {
                long key5 = keys.get(b).longValue();
                ArrayList<PrintingUser> arr = this.printingUsers.get(Long.valueOf(key5));
                if (arr != null) {
                    int a6 = 0;
                    while (a6 < arr.size()) {
                        PrintingUser user = arr.get(a6);
                        if (user.action instanceof TLRPC.TL_sendMessageGamePlayAction) {
                            timeToRemove = 30000;
                        } else {
                            timeToRemove = 5900;
                        }
                        boolean updated2 = updated;
                        if (user.lastTime + ((long) timeToRemove) >= currentTime) {
                            updated = updated2;
                        } else {
                            arr.remove(user);
                            a6--;
                            updated = true;
                        }
                        a6++;
                    }
                }
                if (arr == null || arr.isEmpty()) {
                    this.printingUsers.remove(Long.valueOf(key5));
                    keys.remove(b);
                    b--;
                }
                b++;
            }
            updatePrintingStrings();
            if (updated) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$rDXSfjZfvgluge1cDPlWv37X6kU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$updateTimerProc$104$MessagesController();
                    }
                });
            }
        }
        if (Theme.selectedAutoNightType == 1 && Math.abs(currentTime - lastThemeCheckTime) >= 60) {
            AndroidUtilities.runOnUIThread(this.themeCheckRunnable);
            lastThemeCheckTime = currentTime;
        }
        if (getUserConfig().savedPasswordHash != null && Math.abs(currentTime - lastPasswordCheckTime) >= 60) {
            AndroidUtilities.runOnUIThread(this.passwordCheckRunnable);
            lastPasswordCheckTime = currentTime;
        }
        if (this.lastPushRegisterSendTime != 0 && Math.abs(SystemClock.elapsedRealtime() - this.lastPushRegisterSendTime) >= 10800000) {
            GcmPushListenerService.sendRegistrationToServer(SharedConfig.pushString);
        }
        getLocationController().update();
        lambda$checkProxyInfo$107$MessagesController(false);
        checkTosUpdate();
    }

    public /* synthetic */ void lambda$updateTimerProc$95$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            this.lastStatusUpdateTime = System.currentTimeMillis();
            this.offlineSent = false;
            this.statusSettingState = 0;
        } else {
            long j = this.lastStatusUpdateTime;
            if (j != 0) {
                this.lastStatusUpdateTime = j + DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS;
            }
        }
        this.statusRequest = 0;
    }

    public /* synthetic */ void lambda$updateTimerProc$96$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            this.offlineSent = true;
        } else {
            long j = this.lastStatusUpdateTime;
            if (j != 0) {
                this.lastStatusUpdateTime = j + DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS;
            }
        }
        this.statusRequest = 0;
    }

    public /* synthetic */ void lambda$updateTimerProc$98$MessagesController(int key, TLRPC.TL_messages_getMessagesViews req, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.Vector vector = (TLRPC.Vector) response;
            final SparseArray<SparseIntArray> channelViews = new SparseArray<>();
            SparseIntArray array = channelViews.get(key);
            if (array == null) {
                array = new SparseIntArray();
                channelViews.put(key, array);
            }
            for (int a1 = 0; a1 < req.id.size() && a1 < vector.objects.size(); a1++) {
                array.put(req.id.get(a1).intValue(), ((Integer) vector.objects.get(a1)).intValue());
            }
            getMessagesStorage().putChannelViews(channelViews, req.peer instanceof TLRPC.TL_inputPeerChannel);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$fo8b3y20Ttizd4IerV9tFXgDGtE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$97$MessagesController(channelViews);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$97$MessagesController(SparseArray channelViews) {
        getNotificationCenter().postNotificationName(NotificationCenter.didUpdatedMessagesViews, channelViews);
    }

    public /* synthetic */ void lambda$updateTimerProc$100$MessagesController() {
        long time = SystemClock.uptimeMillis();
        int a = 0;
        int N = this.pollsToCheck.size();
        while (a < N) {
            SparseArray<MessageObject> array = this.pollsToCheck.valueAt(a);
            if (array != null) {
                int b = 0;
                int N2 = array.size();
                while (b < N2) {
                    MessageObject messageObject = array.valueAt(b);
                    if (Math.abs(time - messageObject.pollLastCheckTime) < 30000) {
                        if (!messageObject.pollVisibleOnScreen) {
                            array.remove(messageObject.getId());
                            N2--;
                            b--;
                        }
                    } else {
                        messageObject.pollLastCheckTime = time;
                        TLRPC.TL_messages_getPollResults req = new TLRPC.TL_messages_getPollResults();
                        req.peer = getInputPeer((int) messageObject.getDialogId());
                        req.msg_id = messageObject.getId();
                        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$NijXFRXx5Ij-wnijQKp9lgVy5tg
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                                this.f$0.lambda$null$99$MessagesController(tLObject, tL_error);
                            }
                        });
                    }
                    b++;
                }
                int b2 = array.size();
                if (b2 == 0) {
                    LongSparseArray<SparseArray<MessageObject>> longSparseArray = this.pollsToCheck;
                    longSparseArray.remove(longSparseArray.keyAt(a));
                    N--;
                    a--;
                }
            }
            a++;
        }
        this.pollsToCheckSize = this.pollsToCheck.size();
    }

    public /* synthetic */ void lambda$null$99$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            processUpdates((TLRPC.Updates) response, false);
        }
    }

    public /* synthetic */ void lambda$updateTimerProc$101$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 4);
    }

    public /* synthetic */ void lambda$updateTimerProc$103$MessagesController(final int key, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            final TLRPC.TL_chatOnlines res = (TLRPC.TL_chatOnlines) response;
            getMessagesStorage().updateChatOnlineCount(key, res.onlines);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HT1fu26wX_ET0Hq6iMgD5S6odO0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$102$MessagesController(key, res);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$102$MessagesController(int key, TLRPC.TL_chatOnlines res) {
        getNotificationCenter().postNotificationName(NotificationCenter.chatOnlineCountDidLoad, Integer.valueOf(key), Integer.valueOf(res.onlines));
    }

    public /* synthetic */ void lambda$updateTimerProc$104$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 64);
    }

    private void checkTosUpdate() {
        if (this.nextTosCheckTime > getConnectionsManager().getCurrentTime() || this.checkingTosUpdate || !getUserConfig().isClientActivated()) {
            return;
        }
        this.checkingTosUpdate = true;
        TLRPC.TL_help_getTermsOfServiceUpdate req = new TLRPC.TL_help_getTermsOfServiceUpdate();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$cdU_E-yWKCPUEGITkzxitj5qTKU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkTosUpdate$106$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$checkTosUpdate$106$MessagesController(TLObject response, TLRPC.TL_error error) {
        this.checkingTosUpdate = false;
        if (response instanceof TLRPC.TL_help_termsOfServiceUpdateEmpty) {
            this.nextTosCheckTime = ((TLRPC.TL_help_termsOfServiceUpdateEmpty) response).expires;
        } else if (response instanceof TLRPC.TL_help_termsOfServiceUpdate) {
            final TLRPC.TL_help_termsOfServiceUpdate res = (TLRPC.TL_help_termsOfServiceUpdate) response;
            this.nextTosCheckTime = res.expires;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$vsZNuPmkb_aTLmVAgMvt2ACBXpI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$105$MessagesController(res);
                }
            });
        } else {
            this.nextTosCheckTime = getConnectionsManager().getCurrentTime() + 3600;
        }
        this.notificationsPreferences.edit().putInt("nextTosCheckTime", this.nextTosCheckTime).commit();
    }

    public /* synthetic */ void lambda$null$105$MessagesController(TLRPC.TL_help_termsOfServiceUpdate res) {
        getNotificationCenter().postNotificationName(NotificationCenter.needShowAlert, 4, res.terms_of_service);
    }

    public void checkProxyInfo(final boolean reset) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Baj496APXG-_AwHITArqyj2Fwyk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkProxyInfo$107$MessagesController(reset);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: checkProxyInfoInternal, reason: merged with bridge method [inline-methods] */
    public void lambda$checkProxyInfo$107$MessagesController(boolean reset) {
        String str;
        if (reset && this.checkingProxyInfo) {
            this.checkingProxyInfo = false;
        }
        if ((!reset && this.nextProxyInfoCheckTime > getConnectionsManager().getCurrentTime()) || this.checkingProxyInfo) {
            return;
        }
        if (this.checkingProxyInfoRequestId != 0) {
            getConnectionsManager().cancelRequest(this.checkingProxyInfoRequestId, true);
            this.checkingProxyInfoRequestId = 0;
        }
        SharedPreferences preferences = getGlobalMainSettings();
        boolean enabled = preferences.getBoolean("proxy_enabled", false);
        final String proxyAddress = preferences.getString("proxy_ip", "");
        final String proxySecret = preferences.getString("proxy_secret", "");
        int removeCurrent = 0;
        if (this.proxyDialogId != 0 && (str = this.proxyDialogAddress) != null) {
            if (!str.equals(proxyAddress + proxySecret)) {
                removeCurrent = 1;
            }
        }
        this.lastCheckProxyId++;
        if (enabled && !TextUtils.isEmpty(proxyAddress) && !TextUtils.isEmpty(proxySecret)) {
            this.checkingProxyInfo = true;
            final int checkProxyId = this.lastCheckProxyId;
            TLRPC.TL_help_getProxyData req = new TLRPC.TL_help_getProxyData();
            this.checkingProxyInfoRequestId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$oAL3uFgtYbONNbhVu5D5jIvr6RM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$checkProxyInfoInternal$112$MessagesController(checkProxyId, proxyAddress, proxySecret, tLObject, tL_error);
                }
            });
        } else {
            removeCurrent = 2;
        }
        if (removeCurrent != 0) {
            this.proxyDialogId = 0L;
            this.proxyDialogAddress = null;
            getGlobalMainSettings().edit().putLong("proxy_dialog", this.proxyDialogId).remove("proxyDialogAddress").commit();
            this.nextProxyInfoCheckTime = getConnectionsManager().getCurrentTime() + 3600;
            if (removeCurrent == 2) {
                this.checkingProxyInfo = false;
                if (this.checkingProxyInfoRequestId != 0) {
                    getConnectionsManager().cancelRequest(this.checkingProxyInfoRequestId, true);
                    this.checkingProxyInfoRequestId = 0;
                }
            }
            AndroidUtilities.runOnUIThread(new $$Lambda$MessagesController$d6zltpcX4zlOIu0jQICiA65H4qA(this));
        }
    }

    public /* synthetic */ void lambda$checkProxyInfoInternal$112$MessagesController(final int checkProxyId, String proxyAddress, String proxySecret, TLObject response, TLRPC.TL_error error) {
        boolean noDialog;
        boolean noDialog2;
        long did;
        if (checkProxyId != this.lastCheckProxyId) {
            return;
        }
        boolean noDialog3 = false;
        if (response instanceof TLRPC.TL_help_proxyDataEmpty) {
            this.nextProxyInfoCheckTime = ((TLRPC.TL_help_proxyDataEmpty) response).expires;
            noDialog = true;
        } else if (!(response instanceof TLRPC.TL_help_proxyDataPromo)) {
            this.nextProxyInfoCheckTime = getConnectionsManager().getCurrentTime() + 3600;
            noDialog = true;
        } else {
            final TLRPC.TL_help_proxyDataPromo res = (TLRPC.TL_help_proxyDataPromo) response;
            if (res.peer.user_id != 0) {
                noDialog2 = false;
                did = res.peer.user_id;
            } else if (res.peer.chat_id != 0) {
                long did2 = -res.peer.chat_id;
                int a = 0;
                while (true) {
                    if (a >= res.chats.size()) {
                        break;
                    }
                    TLRPC.Chat chat = res.chats.get(a);
                    if (chat.id != res.peer.chat_id) {
                        a++;
                    } else if (chat.kicked || chat.restricted) {
                        noDialog3 = true;
                    }
                }
                noDialog2 = noDialog3;
                did = did2;
            } else {
                long did3 = -res.peer.channel_id;
                int a2 = 0;
                while (true) {
                    if (a2 >= res.chats.size()) {
                        break;
                    }
                    TLRPC.Chat chat2 = res.chats.get(a2);
                    if (chat2.id != res.peer.channel_id) {
                        a2++;
                    } else if (chat2.kicked || chat2.restricted) {
                        noDialog2 = true;
                        did = did3;
                    }
                }
                noDialog2 = false;
                did = did3;
            }
            this.proxyDialogId = did;
            this.proxyDialogAddress = proxyAddress + proxySecret;
            getGlobalMainSettings().edit().putLong("proxy_dialog", this.proxyDialogId).putString("proxyDialogAddress", this.proxyDialogAddress).commit();
            this.nextProxyInfoCheckTime = res.expires;
            if (!noDialog2) {
                final long j = did;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$adV9Gjm6zPxeWn_wxpfDLvlbls8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$111$MessagesController(j, res, checkProxyId);
                    }
                });
            }
            noDialog = noDialog2;
        }
        if (noDialog) {
            this.proxyDialogId = 0L;
            getGlobalMainSettings().edit().putLong("proxy_dialog", this.proxyDialogId).remove("proxyDialogAddress").commit();
            this.checkingProxyInfoRequestId = 0;
            this.checkingProxyInfo = false;
            AndroidUtilities.runOnUIThread(new $$Lambda$MessagesController$d6zltpcX4zlOIu0jQICiA65H4qA(this));
        }
    }

    public /* synthetic */ void lambda$null$111$MessagesController(final long did, final TLRPC.TL_help_proxyDataPromo res, final int checkProxyId) {
        TLRPC.Dialog dialog = this.proxyDialog;
        if (dialog != null && did != dialog.id) {
            removeProxyDialog();
        }
        TLRPC.Dialog dialog2 = this.dialogs_dict.get(did);
        this.proxyDialog = dialog2;
        if (dialog2 != null) {
            this.checkingProxyInfo = false;
            sortDialogs(null);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, true);
            return;
        }
        SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        SparseArray<TLRPC.Chat> chatsDict = new SparseArray<>();
        for (int a = 0; a < res.users.size(); a++) {
            TLRPC.User u = res.users.get(a);
            usersDict.put(u.id, u);
        }
        for (int a2 = 0; a2 < res.chats.size(); a2++) {
            TLRPC.Chat c = res.chats.get(a2);
            chatsDict.put(c.id, c);
        }
        TLRPC.TL_messages_getPeerDialogs req1 = new TLRPC.TL_messages_getPeerDialogs();
        TLRPC.TL_inputDialogPeer peer = new TLRPC.TL_inputDialogPeer();
        if (res.peer.user_id != 0) {
            peer.peer = new TLRPC.TL_inputPeerUser();
            peer.peer.user_id = res.peer.user_id;
            TLRPC.User user = usersDict.get(res.peer.user_id);
            if (user != null) {
                peer.peer.access_hash = user.access_hash;
            }
        } else if (res.peer.chat_id != 0) {
            peer.peer = new TLRPC.TL_inputPeerChat();
            peer.peer.chat_id = res.peer.chat_id;
            TLRPC.Chat chat = chatsDict.get(res.peer.chat_id);
            if (chat != null) {
                peer.peer.access_hash = chat.access_hash;
            }
        } else {
            peer.peer = new TLRPC.TL_inputPeerChannel();
            peer.peer.channel_id = res.peer.channel_id;
            TLRPC.Chat chat2 = chatsDict.get(res.peer.channel_id);
            if (chat2 != null) {
                peer.peer.access_hash = chat2.access_hash;
            }
        }
        req1.peers.add(peer);
        this.checkingProxyInfoRequestId = getConnectionsManager().sendRequest(req1, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$5VcedFmnGIVt0VG4b3gcxeLRI8w
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$110$MessagesController(checkProxyId, res, did, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$110$MessagesController(int checkProxyId, final TLRPC.TL_help_proxyDataPromo res, final long did, TLObject response1, TLRPC.TL_error error1) {
        if (checkProxyId == this.lastCheckProxyId) {
            this.checkingProxyInfoRequestId = 0;
            final TLRPC.TL_messages_peerDialogs res2 = (TLRPC.TL_messages_peerDialogs) response1;
            if (res2 != null && !res2.dialogs.isEmpty()) {
                getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
                TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
                dialogs.chats = res2.chats;
                dialogs.users = res2.users;
                dialogs.dialogs = res2.dialogs;
                dialogs.messages = res2.messages;
                getMessagesStorage().putDialogs(dialogs, 2);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$yQnzxoUuKpLQMRkC1kPlfn2uB5A
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$108$MessagesController(res, res2, did);
                    }
                });
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$IHjXpjER5WHn6XT0cRp4XnVMrj4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$109$MessagesController();
                    }
                });
            }
            this.checkingProxyInfo = false;
        }
    }

    public /* synthetic */ void lambda$null$108$MessagesController(TLRPC.TL_help_proxyDataPromo res, TLRPC.TL_messages_peerDialogs res2, long did) {
        putUsers(res.users, false);
        putChats(res.chats, false);
        putUsers(res2.users, false);
        putChats(res2.chats, false);
        TLRPC.Dialog dialog = this.proxyDialog;
        if (dialog != null) {
            int lowerId = (int) dialog.id;
            if (lowerId < 0) {
                TLRPC.Chat chat = getChat(Integer.valueOf(-lowerId));
                if (ChatObject.isNotInChat(chat) || chat.restricted) {
                    removeDialog(this.proxyDialog);
                }
            } else {
                removeDialog(this.proxyDialog);
            }
        }
        TLRPC.Dialog dialog2 = res2.dialogs.get(0);
        this.proxyDialog = dialog2;
        dialog2.id = did;
        this.proxyDialog.folder_id = 0;
        if (DialogObject.isChannel(this.proxyDialog)) {
            this.channelsPts.put(-((int) this.proxyDialog.id), this.proxyDialog.pts);
        }
        Integer value = this.dialogs_read_inbox_max.get(Long.valueOf(this.proxyDialog.id));
        if (value == null) {
            value = 0;
        }
        this.dialogs_read_inbox_max.put(Long.valueOf(this.proxyDialog.id), Integer.valueOf(Math.max(value.intValue(), this.proxyDialog.read_inbox_max_id)));
        Integer value2 = this.dialogs_read_outbox_max.get(Long.valueOf(this.proxyDialog.id));
        if (value2 == null) {
            value2 = 0;
        }
        this.dialogs_read_outbox_max.put(Long.valueOf(this.proxyDialog.id), Integer.valueOf(Math.max(value2.intValue(), this.proxyDialog.read_outbox_max_id)));
        this.dialogs_dict.put(did, this.proxyDialog);
        if (!res2.messages.isEmpty()) {
            SparseArray<TLRPC.User> usersDict1 = new SparseArray<>();
            SparseArray<TLRPC.Chat> chatsDict1 = new SparseArray<>();
            for (int a = 0; a < res2.users.size(); a++) {
                TLRPC.User u = res2.users.get(a);
                usersDict1.put(u.id, u);
            }
            for (int a2 = 0; a2 < res2.chats.size(); a2++) {
                TLRPC.Chat c = res2.chats.get(a2);
                chatsDict1.put(c.id, c);
            }
            MessageObject messageObject = new MessageObject(this.currentAccount, res2.messages.get(0), usersDict1, chatsDict1, false);
            this.dialogMessage.put(did, messageObject);
            if (this.proxyDialog.last_message_date == 0) {
                this.proxyDialog.last_message_date = messageObject.messageOwner.date;
            }
        }
        sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, true);
    }

    public /* synthetic */ void lambda$null$109$MessagesController() {
        TLRPC.Dialog dialog = this.proxyDialog;
        if (dialog != null) {
            int lowerId = (int) dialog.id;
            if (lowerId < 0) {
                TLRPC.Chat chat = getChat(Integer.valueOf(-lowerId));
                if (ChatObject.isNotInChat(chat) || chat.restricted) {
                    removeDialog(this.proxyDialog);
                }
            } else {
                removeDialog(this.proxyDialog);
            }
            this.proxyDialog = null;
            sortDialogs(null);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeProxyDialog() {
        TLRPC.Dialog dialog = this.proxyDialog;
        if (dialog == null) {
            return;
        }
        int lowerId = (int) dialog.id;
        if (lowerId < 0) {
            TLRPC.Chat chat = getChat(Integer.valueOf(-lowerId));
            if (ChatObject.isNotInChat(chat) || chat.restricted) {
                removeDialog(this.proxyDialog);
            }
        } else {
            removeDialog(this.proxyDialog);
        }
        this.proxyDialog = null;
        sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public boolean isProxyDialog(long did, boolean checkLeft) {
        TLRPC.Dialog dialog = this.proxyDialog;
        return dialog != null && dialog.id == did && (!checkLeft || this.isLeftProxyChannel);
    }

    private String getUserNameForTyping(TLRPC.User user) {
        if (user == null) {
            return "";
        }
        if (user.first_name != null && user.first_name.length() > 0) {
            return user.first_name;
        }
        if (user.last_name == null || user.last_name.length() <= 0) {
            return "";
        }
        return user.last_name;
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x010d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0018 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void updatePrintingStrings() {
        /*
            Method dump skipped, instruction units count: 712
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.updatePrintingStrings():void");
    }

    public /* synthetic */ void lambda$updatePrintingStrings$113$MessagesController(LongSparseArray newPrintingStrings, LongSparseArray newPrintingStringsTypes) {
        this.printingStrings = newPrintingStrings;
        this.printingStringsTypes = newPrintingStringsTypes;
    }

    public void cancelTyping(int action, long dialog_id) {
        LongSparseArray<Boolean> typings = this.sendingTypings.get(action);
        if (typings != null) {
            typings.remove(dialog_id);
        }
    }

    public void sendTyping(final long dialog_id, final int action, int classGuid) {
        TLRPC.Chat chat;
        if (dialog_id == 0) {
            return;
        }
        LongSparseArray<Boolean> typings = this.sendingTypings.get(action);
        if (typings != null && typings.get(dialog_id) != null) {
            return;
        }
        if (typings == null) {
            typings = new LongSparseArray<>();
            this.sendingTypings.put(action, typings);
        }
        int lower_part = (int) dialog_id;
        int high_id = (int) (dialog_id >> 32);
        if (lower_part != 0) {
            TLRPC.TL_messages_setTyping req = new TLRPC.TL_messages_setTyping();
            req.peer = getInputPeer(lower_part);
            if (((req.peer instanceof TLRPC.TL_inputPeerChannel) && ((chat = getChat(Integer.valueOf(req.peer.channel_id))) == null || !chat.megagroup)) || req.peer == null) {
                return;
            }
            if (action == 0) {
                req.action = new TLRPC.TL_sendMessageTypingAction();
            } else if (action == 1) {
                req.action = new TLRPC.TL_sendMessageRecordAudioAction();
            } else if (action == 2) {
                req.action = new TLRPC.TL_sendMessageCancelAction();
            } else if (action == 3) {
                req.action = new TLRPC.TL_sendMessageUploadDocumentAction();
            } else if (action == 4) {
                req.action = new TLRPC.TL_sendMessageUploadPhotoAction();
            } else if (action == 5) {
                req.action = new TLRPC.TL_sendMessageUploadVideoAction();
            } else if (action == 6) {
                req.action = new TLRPC.TL_sendMessageGamePlayAction();
            } else if (action == 7) {
                req.action = new TLRPC.TL_sendMessageRecordRoundAction();
            } else if (action == 8) {
                req.action = new TLRPC.TL_sendMessageUploadRoundAction();
            } else if (action == 9) {
                req.action = new TLRPC.TL_sendMessageUploadAudioAction();
            }
            typings.put(dialog_id, true);
            int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$v0QCdIWmcSwEGEhy4WpywrEi-3k
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$sendTyping$115$MessagesController(action, dialog_id, tLObject, tL_error);
                }
            }, 2);
            if (classGuid != 0) {
                getConnectionsManager().bindRequestToGuid(reqId, classGuid);
                return;
            }
            return;
        }
        if (action != 0) {
            return;
        }
        TLRPC.EncryptedChat chat2 = getEncryptedChat(Integer.valueOf(high_id));
        if (chat2.auth_key != null && chat2.auth_key.length > 1 && (chat2 instanceof TLRPC.TL_encryptedChat)) {
            TLRPC.TL_messages_setEncryptedTyping req2 = new TLRPC.TL_messages_setEncryptedTyping();
            req2.peer = new TLRPC.TL_inputEncryptedChat();
            req2.peer.chat_id = chat2.id;
            req2.peer.access_hash = chat2.access_hash;
            req2.typing = true;
            typings.put(dialog_id, true);
            int reqId2 = getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$85rhis3m64QIogfK55By-Cphsp8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$sendTyping$117$MessagesController(action, dialog_id, tLObject, tL_error);
                }
            }, 2);
            if (classGuid != 0) {
                getConnectionsManager().bindRequestToGuid(reqId2, classGuid);
            }
        }
    }

    public /* synthetic */ void lambda$sendTyping$115$MessagesController(final int action, final long dialog_id, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$YaP7EHUjgQpaBqsdzA29o223uNM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$114$MessagesController(action, dialog_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$114$MessagesController(int action, long dialog_id) {
        LongSparseArray<Boolean> typings1 = this.sendingTypings.get(action);
        if (typings1 != null) {
            typings1.remove(dialog_id);
        }
    }

    public /* synthetic */ void lambda$sendTyping$117$MessagesController(final int action, final long dialog_id, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kuqM5CzbQ9xpiwvWC8zJZzpW8o4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$116$MessagesController(action, dialog_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$116$MessagesController(int action, long dialog_id) {
        LongSparseArray<Boolean> typings12 = this.sendingTypings.get(action);
        if (typings12 != null) {
            typings12.remove(dialog_id);
        }
    }

    protected void removeDeletedMessagesFromArray(long dialog_id, ArrayList<TLRPC.Message> messages) {
        int maxDeletedId = this.deletedHistory.get(dialog_id, 0).intValue();
        if (maxDeletedId == 0) {
            return;
        }
        int a = 0;
        int N = messages.size();
        while (a < N) {
            TLRPC.Message message = messages.get(a);
            if (message.id <= maxDeletedId) {
                messages.remove(a);
                a--;
                N--;
            }
            a++;
        }
    }

    public void loadMessages(long dialog_id, int count, int max_id, int offset_date, boolean fromCache, int midDate, int classGuid, int load_type, int last_message_id, boolean isChannel, boolean scheduled, int loadIndex) {
        loadMessages(dialog_id, count, max_id, offset_date, fromCache, midDate, classGuid, load_type, last_message_id, isChannel, scheduled, loadIndex, 0, 0, 0, false, 0);
    }

    public void loadMessages(long dialog_id, int count, int max_id, int offset_date, boolean fromCache, int midDate, int classGuid, int load_type, int last_message_id, boolean isChannel, boolean scheduled, int loadIndex, int first_unread, int unread_count, int last_date, boolean queryFromServer, int mentionsCount) {
        loadMessagesInternal(dialog_id, count, max_id, offset_date, fromCache, midDate, classGuid, load_type, last_message_id, isChannel, scheduled, loadIndex, first_unread, unread_count, last_date, queryFromServer, mentionsCount, true);
    }

    private void loadMessagesInternal(final long dialog_id, final int count, final int max_id, final int offset_date, boolean fromCache, final int minDate, final int classGuid, final int load_type, final int last_message_id, final boolean isChannel, boolean scheduled, final int loadIndex, final int first_unread, final int unread_count, final int last_date, final boolean queryFromServer, final int mentionsCount, boolean loadDialog) {
        int i;
        int i2;
        int lower_part = (int) dialog_id;
        if (fromCache || lower_part == 0) {
            getMessagesStorage().getMessages(dialog_id, count, max_id, offset_date, minDate, classGuid, load_type, isChannel, scheduled, loadIndex);
            return;
        }
        if (scheduled) {
            TLRPC.TL_messages_getScheduledHistory req = new TLRPC.TL_messages_getScheduledHistory();
            req.peer = getInputPeer(lower_part);
            req.hash = minDate;
            int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$z9R-LnR0ShkIo1U54SYmIn8uf4I
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadMessagesInternal$118$MessagesController(max_id, offset_date, dialog_id, count, classGuid, first_unread, last_message_id, unread_count, last_date, load_type, isChannel, loadIndex, queryFromServer, mentionsCount, tLObject, tL_error);
                }
            });
            ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, classGuid);
            return;
        }
        if (loadDialog && ((load_type == 3 || load_type == 2) && last_message_id == 0)) {
            TLRPC.TL_messages_getPeerDialogs req2 = new TLRPC.TL_messages_getPeerDialogs();
            TLRPC.InputPeer inputPeer = getInputPeer((int) dialog_id);
            TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
            inputDialogPeer.peer = inputPeer;
            req2.peers.add(inputDialogPeer);
            getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$DWL_O1VoetRxewXZqBw1Z5Yjk-g
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadMessagesInternal$119$MessagesController(dialog_id, count, max_id, offset_date, minDate, classGuid, load_type, isChannel, loadIndex, first_unread, last_date, queryFromServer, tLObject, tL_error);
                }
            });
            return;
        }
        TLRPC.TL_messages_getHistory req3 = new TLRPC.TL_messages_getHistory();
        req3.peer = getInputPeer(lower_part);
        if (load_type == 4) {
            i = count;
            req3.add_offset = (-i) + 5;
            i2 = max_id;
        } else {
            i = count;
            if (load_type == 3) {
                req3.add_offset = (-i) / 2;
                i2 = max_id;
            } else if (load_type == 1) {
                req3.add_offset = (-i) - 1;
                i2 = max_id;
            } else {
                if (load_type == 2) {
                    i2 = max_id;
                    if (i2 != 0) {
                        req3.add_offset = (-i) + 6;
                    }
                } else {
                    i2 = max_id;
                }
                if (lower_part < 0 && i2 != 0) {
                    TLRPC.Chat chat = getChat(Integer.valueOf(-lower_part));
                    if (ChatObject.isChannel(chat)) {
                        req3.add_offset = -1;
                        req3.limit++;
                    }
                }
            }
        }
        req3.limit = i;
        req3.offset_id = i2;
        req3.offset_date = offset_date;
        int reqId2 = getConnectionsManager().sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$qnE0wStxsFKyRZOpvhABeD5QKto
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadMessagesInternal$120$MessagesController(dialog_id, count, max_id, offset_date, classGuid, first_unread, last_message_id, unread_count, last_date, load_type, isChannel, loadIndex, queryFromServer, mentionsCount, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId2, classGuid);
    }

    public /* synthetic */ void lambda$loadMessagesInternal$118$MessagesController(int max_id, int offset_date, long dialog_id, int count, int classGuid, int first_unread, int last_message_id, int unread_count, int last_date, int load_type, boolean isChannel, int loadIndex, boolean queryFromServer, int mentionsCount, TLObject response, TLRPC.TL_error error) {
        int mid;
        if (response != null) {
            TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            if (res instanceof TLRPC.TL_messages_messagesNotModified) {
                return;
            }
            if (offset_date != 0 && !res.messages.isEmpty()) {
                int mid2 = res.messages.get(res.messages.size() - 1).id;
                int a = res.messages.size() - 1;
                while (true) {
                    if (a < 0) {
                        mid = mid2;
                        break;
                    }
                    TLRPC.Message message = res.messages.get(a);
                    if (message.date <= offset_date) {
                        a--;
                    } else {
                        int mid3 = message.id;
                        mid = mid3;
                        break;
                    }
                }
            } else {
                mid = max_id;
            }
            processLoadedMessages(res, dialog_id, count, mid, offset_date, false, classGuid, first_unread, last_message_id, unread_count, last_date, load_type, isChannel, false, true, loadIndex, queryFromServer, mentionsCount);
        }
    }

    public /* synthetic */ void lambda$loadMessagesInternal$119$MessagesController(long dialog_id, int count, int max_id, int offset_date, int minDate, int classGuid, int load_type, boolean isChannel, int loadIndex, int first_unread, int last_date, boolean queryFromServer, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.TL_messages_peerDialogs res = (TLRPC.TL_messages_peerDialogs) response;
            if (!res.dialogs.isEmpty()) {
                TLRPC.Dialog dialog = res.dialogs.get(0);
                if (dialog.top_message != 0) {
                    TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
                    dialogs.chats = res.chats;
                    dialogs.users = res.users;
                    dialogs.dialogs = res.dialogs;
                    dialogs.messages = res.messages;
                    getMessagesStorage().putDialogs(dialogs, 0);
                }
                loadMessagesInternal(dialog_id, count, max_id, offset_date, false, minDate, classGuid, load_type, dialog.top_message, isChannel, false, loadIndex, first_unread, dialog.unread_count, last_date, queryFromServer, dialog.unread_mentions_count, false);
                return;
            }
            loadMessagesInternal(dialog_id, count, max_id, offset_date, false, minDate, classGuid, load_type, -1, isChannel, false, loadIndex, first_unread, res.state.unread_count, last_date, queryFromServer, 0, false);
        }
    }

    public /* synthetic */ void lambda$loadMessagesInternal$120$MessagesController(long dialog_id, int count, int max_id, int offset_date, int classGuid, int first_unread, int last_message_id, int unread_count, int last_date, int load_type, boolean isChannel, int loadIndex, boolean queryFromServer, int mentionsCount, TLObject response, TLRPC.TL_error error) {
        int mid;
        if (response != null) {
            TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            removeDeletedMessagesFromArray(dialog_id, res.messages);
            if (res.messages.size() > count) {
                res.messages.remove(0);
            }
            if (offset_date != 0 && !res.messages.isEmpty()) {
                int mid2 = res.messages.get(res.messages.size() - 1).id;
                int a = res.messages.size() - 1;
                while (true) {
                    if (a < 0) {
                        mid = mid2;
                        break;
                    }
                    TLRPC.Message message = res.messages.get(a);
                    if (message.date <= offset_date) {
                        a--;
                    } else {
                        int mid3 = message.id;
                        mid = mid3;
                        break;
                    }
                }
            } else {
                mid = max_id;
            }
            processLoadedMessages(res, dialog_id, count, mid, offset_date, false, classGuid, first_unread, last_message_id, unread_count, last_date, load_type, isChannel, false, false, loadIndex, queryFromServer, mentionsCount);
        }
    }

    public void reloadWebPages(final long dialog_id, HashMap<String, ArrayList<MessageObject>> webpagesToReload, final boolean scheduled) {
        HashMap<String, ArrayList<MessageObject>> map = scheduled ? this.reloadingScheduledWebpages : this.reloadingWebpages;
        final LongSparseArray<ArrayList<MessageObject>> array = scheduled ? this.reloadingScheduledWebpagesPending : this.reloadingWebpagesPending;
        for (Map.Entry<String, ArrayList<MessageObject>> entry : webpagesToReload.entrySet()) {
            final String url = entry.getKey();
            ArrayList<MessageObject> messages = entry.getValue();
            ArrayList<MessageObject> arrayList = map.get(url);
            if (arrayList == null) {
                arrayList = new ArrayList<>();
                map.put(url, arrayList);
            }
            arrayList.addAll(messages);
            TLRPC.TL_messages_getWebPagePreview req = new TLRPC.TL_messages_getWebPagePreview();
            req.message = url;
            final HashMap<String, ArrayList<MessageObject>> map2 = map;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$yP7OOtD3Ab8tTZkGs14vWQWvVeM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$reloadWebPages$122$MessagesController(map2, url, array, dialog_id, scheduled, tLObject, tL_error);
                }
            });
            map = map;
        }
    }

    public /* synthetic */ void lambda$reloadWebPages$122$MessagesController(final HashMap map, final String url, final LongSparseArray array, final long dialog_id, final boolean scheduled, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Q1WdFRq99QanjV-lqgJ507R8ieg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$121$MessagesController(map, url, response, array, dialog_id, scheduled);
            }
        });
    }

    public /* synthetic */ void lambda$null$121$MessagesController(HashMap map, String url, TLObject response, LongSparseArray array, long dialog_id, boolean scheduled) {
        ArrayList<MessageObject> arrayList1 = (ArrayList) map.remove(url);
        if (arrayList1 == null) {
            return;
        }
        TLRPC.TL_messages_messages messagesRes = new TLRPC.TL_messages_messages();
        if (!(response instanceof TLRPC.TL_messageMediaWebPage)) {
            for (int a = 0; a < arrayList1.size(); a++) {
                arrayList1.get(a).messageOwner.media.webpage = new TLRPC.TL_webPageEmpty();
                messagesRes.messages.add(arrayList1.get(a).messageOwner);
            }
        } else {
            TLRPC.TL_messageMediaWebPage media = (TLRPC.TL_messageMediaWebPage) response;
            if ((media.webpage instanceof TLRPC.TL_webPage) || (media.webpage instanceof TLRPC.TL_webPageEmpty)) {
                for (int a2 = 0; a2 < arrayList1.size(); a2++) {
                    arrayList1.get(a2).messageOwner.media.webpage = media.webpage;
                    if (a2 == 0) {
                        ImageLoader.saveMessageThumbs(arrayList1.get(a2).messageOwner);
                    }
                    messagesRes.messages.add(arrayList1.get(a2).messageOwner);
                }
            } else {
                array.put(media.webpage.id, arrayList1);
            }
        }
        if (!messagesRes.messages.isEmpty()) {
            getMessagesStorage().putMessages((TLRPC.messages_Messages) messagesRes, dialog_id, -2, 0, false, scheduled);
            getNotificationCenter().postNotificationName(NotificationCenter.replaceMessagesObjects, Long.valueOf(dialog_id), arrayList1);
        }
    }

    public void processLoadedMessages(final TLRPC.messages_Messages messagesRes, final long dialog_id, final int count, final int max_id, final int offset_date, final boolean isCache, final int classGuid, final int first_unread, final int last_message_id, final int unread_count, final int last_date, final int load_type, final boolean isChannel, final boolean isEnd, final boolean scheduled, final int loadIndex, final boolean queryFromServer, final int mentionsCount) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$UBlGVCPkt5ohudnHJ4EFsDLvVsA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedMessages$125$MessagesController(messagesRes, dialog_id, scheduled, isCache, count, load_type, queryFromServer, first_unread, max_id, offset_date, classGuid, last_message_id, isChannel, loadIndex, unread_count, last_date, mentionsCount, isEnd);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedMessages$125$MessagesController(final TLRPC.messages_Messages messagesRes, final long dialog_id, final boolean scheduled, final boolean isCache, final int count, final int load_type, final boolean queryFromServer, final int first_unread, final int max_id, final int offset_date, final int classGuid, final int last_message_id, final boolean isChannel, final int loadIndex, final int unread_count, final int last_date, final int mentionsCount, final boolean isEnd) {
        boolean createDialog;
        boolean isMegagroup;
        TLRPC.messages_Messages messages_messages;
        MessagesController messagesController;
        long j;
        boolean z;
        Integer inboxValue;
        Integer outboxValue;
        TLRPC.User user;
        int high_id;
        int hash;
        int high_id2;
        boolean createDialog2 = false;
        if (!(messagesRes instanceof TLRPC.TL_messages_channelMessages)) {
            createDialog = false;
            isMegagroup = false;
        } else {
            int channelId = -((int) dialog_id);
            if (!scheduled) {
                int channelPts = this.channelsPts.get(channelId);
                if (channelPts == 0) {
                    int channelPts2 = getMessagesStorage().getChannelPtsSync(channelId);
                    if (channelPts2 == 0) {
                        this.channelsPts.put(channelId, messagesRes.pts);
                        if (this.needShortPollChannels.indexOfKey(channelId) >= 0 && this.shortPollChannels.indexOfKey(channelId) < 0) {
                            getChannelDifference(channelId, 2, 0L, null);
                        } else {
                            getChannelDifference(channelId);
                        }
                        createDialog2 = true;
                    }
                }
            }
            int a = 0;
            while (true) {
                if (a >= messagesRes.chats.size()) {
                    createDialog = createDialog2;
                    isMegagroup = false;
                    break;
                }
                TLRPC.Chat chat = messagesRes.chats.get(a);
                if (chat.id != channelId) {
                    a++;
                } else {
                    boolean isMegagroup2 = chat.megagroup;
                    createDialog = createDialog2;
                    isMegagroup = isMegagroup2;
                    break;
                }
            }
        }
        int lower_id = (int) dialog_id;
        int high_id3 = (int) (dialog_id >> 32);
        if (!isCache) {
            ImageLoader.saveMessagesThumbs(messagesRes.messages);
        }
        if (high_id3 == 1 || lower_id == 0 || !isCache) {
            messages_messages = messagesRes;
        } else if (messagesRes.messages.size() == 0 || (scheduled && SystemClock.uptimeMillis() - this.lastScheduledServerQueryTime.get(dialog_id, 0L).longValue() > DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS)) {
            if (scheduled) {
                this.lastScheduledServerQueryTime.put(dialog_id, Long.valueOf(SystemClock.uptimeMillis()));
                long h = 0;
                int a2 = 0;
                int N = messagesRes.messages.size();
                while (a2 < N) {
                    TLRPC.Message message = messagesRes.messages.get(a2);
                    if (message.id < 0) {
                        high_id2 = high_id3;
                    } else {
                        high_id2 = high_id3;
                        h = (((20261 * ((((((((h * 20261) + 2147483648L) + ((long) message.id)) % 2147483648L) * 20261) + 2147483648L) + ((long) message.edit_date)) % 2147483648L)) + 2147483648L) + ((long) message.date)) % 2147483648L;
                    }
                    a2++;
                    high_id3 = high_id2;
                }
                high_id = high_id3;
                int a3 = (int) h;
                int hash2 = a3 - 1;
                hash = hash2;
            } else {
                high_id = high_id3;
                hash = 0;
            }
            final int lower_id2 = hash;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Mb1LXajfTRinve9f4epmYtx6qHc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$123$MessagesController(dialog_id, count, load_type, queryFromServer, first_unread, max_id, offset_date, lower_id2, classGuid, last_message_id, isChannel, scheduled, loadIndex, unread_count, last_date, mentionsCount);
                }
            });
            messages_messages = messagesRes;
            if (messages_messages.messages.isEmpty()) {
                return;
            }
        } else {
            messages_messages = messagesRes;
        }
        SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        SparseArray<TLRPC.Chat> chatsDict = new SparseArray<>();
        for (int a4 = 0; a4 < messages_messages.users.size(); a4++) {
            TLRPC.User u = messages_messages.users.get(a4);
            usersDict.put(u.id, u);
        }
        for (int a5 = 0; a5 < messages_messages.chats.size(); a5++) {
            TLRPC.Chat c = messages_messages.chats.get(a5);
            chatsDict.put(c.id, c);
        }
        int size = messages_messages.messages.size();
        if (isCache) {
            messagesController = this;
            j = dialog_id;
            z = scheduled;
        } else {
            messagesController = this;
            Integer inboxValue2 = messagesController.dialogs_read_inbox_max.get(Long.valueOf(dialog_id));
            if (inboxValue2 == null) {
                j = dialog_id;
                Integer inboxValue3 = Integer.valueOf(getMessagesStorage().getDialogReadMax(false, j));
                messagesController.dialogs_read_inbox_max.put(Long.valueOf(dialog_id), inboxValue3);
                inboxValue = inboxValue3;
            } else {
                j = dialog_id;
                inboxValue = inboxValue2;
            }
            Integer outboxValue2 = messagesController.dialogs_read_outbox_max.get(Long.valueOf(dialog_id));
            if (outboxValue2 == null) {
                Integer outboxValue3 = Integer.valueOf(getMessagesStorage().getDialogReadMax(true, j));
                messagesController.dialogs_read_outbox_max.put(Long.valueOf(dialog_id), outboxValue3);
                outboxValue = outboxValue3;
            } else {
                outboxValue = outboxValue2;
            }
            for (int a6 = 0; a6 < size; a6++) {
                TLRPC.Message message2 = messages_messages.messages.get(a6);
                if (isMegagroup) {
                    message2.flags |= Integer.MIN_VALUE;
                }
                if (!scheduled) {
                    if ((message2.action instanceof TLRPC.TL_messageActionChatDeleteUser) && (user = usersDict.get(message2.action.user_id)) != null && user.bot) {
                        message2.reply_markup = new TLRPC.TL_replyKeyboardHide();
                        message2.flags |= 64;
                    }
                    if ((message2.action instanceof TLRPC.TL_messageActionChatMigrateTo) || (message2.action instanceof TLRPC.TL_messageActionChannelCreate)) {
                        message2.unread = false;
                        message2.media_unread = false;
                    } else {
                        message2.unread = (message2.out ? outboxValue : inboxValue).intValue() < message2.id;
                    }
                }
            }
            z = scheduled;
            getMessagesStorage().putMessages(messagesRes, dialog_id, load_type, max_id, createDialog, scheduled);
        }
        final ArrayList<MessageObject> objects = new ArrayList<>();
        final ArrayList<Integer> messagesToReload = new ArrayList<>();
        HashMap<String, ArrayList<MessageObject>> webpagesToReload = new HashMap<>();
        int a7 = 0;
        while (a7 < size) {
            TLRPC.Message message3 = messages_messages.messages.get(a7);
            message3.dialog_id = j;
            int a8 = a7;
            HashMap<String, ArrayList<MessageObject>> webpagesToReload2 = webpagesToReload;
            MessageObject messageObject = new MessageObject(messagesController.currentAccount, message3, usersDict, chatsDict, true);
            messageObject.scheduled = z;
            objects.add(messageObject);
            if (isCache) {
                if (message3.legacy && message3.layer < 105) {
                    messagesToReload.add(Integer.valueOf(message3.id));
                } else if (message3.media instanceof TLRPC.TL_messageMediaUnsupported) {
                    if (message3.media.bytes != null) {
                        if (message3.media.bytes.length != 0) {
                            if (message3.media.bytes.length == 1) {
                                if (message3.media.bytes[0] < 105) {
                                }
                            }
                        }
                        messagesToReload.add(Integer.valueOf(message3.id));
                    }
                }
                if (message3.media instanceof TLRPC.TL_messageMediaWebPage) {
                    if ((message3.media.webpage instanceof TLRPC.TL_webPagePending) && message3.media.webpage.date <= getConnectionsManager().getCurrentTime()) {
                        messagesToReload.add(Integer.valueOf(message3.id));
                    } else if (message3.media.webpage instanceof TLRPC.TL_webPageUrlPending) {
                        ArrayList<MessageObject> arrayList = webpagesToReload2.get(message3.media.webpage.url);
                        if (arrayList == null) {
                            arrayList = new ArrayList<>();
                            webpagesToReload2.put(message3.media.webpage.url, arrayList);
                        }
                        arrayList.add(messageObject);
                    }
                }
            }
            a7 = a8 + 1;
            webpagesToReload = webpagesToReload2;
            messages_messages = messagesRes;
        }
        final HashMap<String, ArrayList<MessageObject>> webpagesToReload3 = webpagesToReload;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$cS0veguAFOYrBtYxJwCq5kgFVRs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$124$MessagesController(messagesRes, isCache, scheduled, queryFromServer, load_type, first_unread, count, dialog_id, objects, last_message_id, unread_count, last_date, isEnd, classGuid, loadIndex, max_id, mentionsCount, messagesToReload, webpagesToReload3);
            }
        });
    }

    public /* synthetic */ void lambda$null$123$MessagesController(long dialog_id, int count, int load_type, boolean queryFromServer, int first_unread, int max_id, int offset_date, int hash, int classGuid, int last_message_id, boolean isChannel, boolean scheduled, int loadIndex, int unread_count, int last_date, int mentionsCount) {
        loadMessages(dialog_id, count, (load_type == 2 && queryFromServer) ? first_unread : max_id, offset_date, false, hash, classGuid, load_type, last_message_id, isChannel, scheduled, loadIndex, first_unread, unread_count, last_date, queryFromServer, mentionsCount);
    }

    public /* synthetic */ void lambda$null$124$MessagesController(TLRPC.messages_Messages messagesRes, boolean isCache, boolean scheduled, boolean queryFromServer, int load_type, int first_unread, int count, long dialog_id, ArrayList objects, int last_message_id, int unread_count, int last_date, boolean isEnd, int classGuid, int loadIndex, int max_id, int mentionsCount, ArrayList messagesToReload, HashMap webpagesToReload) {
        int first_unread_final;
        putUsers(messagesRes.users, isCache);
        putChats(messagesRes.chats, isCache);
        if (scheduled) {
            first_unread_final = 0;
        } else {
            first_unread_final = Integer.MAX_VALUE;
            if (queryFromServer && load_type == 2) {
                for (int a = 0; a < messagesRes.messages.size(); a++) {
                    TLRPC.Message message = messagesRes.messages.get(a);
                    if ((!message.out || message.from_scheduled) && message.id > first_unread && message.id < first_unread_final) {
                        first_unread_final = message.id;
                    }
                }
            }
            if (first_unread_final == Integer.MAX_VALUE) {
                first_unread_final = first_unread;
            }
        }
        if (scheduled && count == 1) {
            getNotificationCenter().postNotificationName(NotificationCenter.scheduledMessagesUpdated, Long.valueOf(dialog_id), Integer.valueOf(objects.size()));
        }
        getNotificationCenter().postNotificationName(NotificationCenter.messagesDidLoad, Long.valueOf(dialog_id), Integer.valueOf(count), objects, Boolean.valueOf(isCache), Integer.valueOf(first_unread_final), Integer.valueOf(last_message_id), Integer.valueOf(unread_count), Integer.valueOf(last_date), Integer.valueOf(load_type), Boolean.valueOf(isEnd), Integer.valueOf(classGuid), Integer.valueOf(loadIndex), Integer.valueOf(max_id), Integer.valueOf(mentionsCount), Boolean.valueOf(scheduled));
        if (!messagesToReload.isEmpty()) {
            reloadMessages(messagesToReload, dialog_id, scheduled);
        }
        if (!webpagesToReload.isEmpty()) {
            reloadWebPages(dialog_id, webpagesToReload, scheduled);
        }
    }

    public void loadHintDialogs() {
        if (!this.hintDialogs.isEmpty() || TextUtils.isEmpty(this.installReferer)) {
            return;
        }
        TLRPC.TL_help_getRecentMeUrls req = new TLRPC.TL_help_getRecentMeUrls();
        req.referer = this.installReferer;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Yq-xH3Uho3zKNUA7AXEFXurzGjo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadHintDialogs$127$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadHintDialogs$127$MessagesController(final TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$FA6InJMpcfKT3nnjB-PLwTesjmU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$126$MessagesController(response);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$126$MessagesController(TLObject response) {
        TLRPC.TL_help_recentMeUrls res = (TLRPC.TL_help_recentMeUrls) response;
        putUsers(res.users, false);
        putChats(res.chats, false);
        this.hintDialogs.clear();
        this.hintDialogs.addAll(res.urls);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    private TLRPC.TL_dialogFolder ensureFolderDialogExists(int folderId, boolean[] folderCreated) {
        if (folderId == 0) {
            return null;
        }
        long folderDialogId = DialogObject.makeFolderDialogId(folderId);
        TLRPC.Dialog dialog = this.dialogs_dict.get(folderDialogId);
        if (dialog instanceof TLRPC.TL_dialogFolder) {
            if (folderCreated != null) {
                folderCreated[0] = false;
            }
            return (TLRPC.TL_dialogFolder) dialog;
        }
        if (folderCreated != null) {
            folderCreated[0] = true;
        }
        TLRPC.TL_dialogFolder dialogFolder = new TLRPC.TL_dialogFolder();
        dialogFolder.id = folderDialogId;
        dialogFolder.peer = new TLRPC.TL_peerUser();
        dialogFolder.folder = new TLRPC.TL_folder();
        dialogFolder.folder.id = folderId;
        dialogFolder.folder.title = LocaleController.getString("ArchivedChats", mpEIGo.juqQQs.esbSDO.R.string.ArchivedChats);
        dialogFolder.pinned = true;
        int maxPinnedNum = 0;
        for (int a = 0; a < this.allDialogs.size(); a++) {
            TLRPC.Dialog d = this.allDialogs.get(a);
            if (!d.pinned) {
                break;
            }
            maxPinnedNum = Math.max(d.pinnedNum, maxPinnedNum);
        }
        int a2 = maxPinnedNum + 1;
        dialogFolder.pinnedNum = a2;
        TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
        dialogs.dialogs.add(dialogFolder);
        getMessagesStorage().putDialogs(dialogs, 1);
        this.dialogs_dict.put(folderDialogId, dialogFolder);
        this.allDialogs.add(0, dialogFolder);
        return dialogFolder;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: removeFolder, reason: merged with bridge method [inline-methods] */
    public void lambda$onFolderEmpty$128$MessagesController(int folderId) {
        long dialogId = DialogObject.makeFolderDialogId(folderId);
        TLRPC.Dialog dialog = this.dialogs_dict.get(dialogId);
        if (dialog == null) {
            return;
        }
        this.dialogs_dict.remove(dialogId);
        this.allDialogs.remove(dialog);
        sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.folderBecomeEmpty, Integer.valueOf(folderId));
    }

    protected void onFolderEmpty(final int folderId) {
        int[] dialogsLoadOffset = getUserConfig().getDialogLoadOffsets(folderId);
        if (dialogsLoadOffset[0] == Integer.MAX_VALUE) {
            lambda$onFolderEmpty$128$MessagesController(folderId);
        } else {
            loadDialogs(folderId, 0, 10, false, new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$XAigfVThtb9B3phj9O53H0upEK0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onFolderEmpty$128$MessagesController(folderId);
                }
            });
        }
    }

    public void checkIfFolderEmpty(int folderId) {
        if (folderId == 0) {
            return;
        }
        getMessagesStorage().checkIfFolderEmpty(folderId);
    }

    public int addDialogToFolder(long dialogId, int folderId, int pinnedNum, long taskId) {
        ArrayList<Long> arrayList = new ArrayList<>(1);
        arrayList.add(Long.valueOf(dialogId));
        return addDialogToFolder(arrayList, folderId, pinnedNum, null, taskId);
    }

    public int addDialogToFolder(ArrayList<Long> dialogIds, int folderId, int pinnedNum, ArrayList<TLRPC.TL_inputFolderPeer> peers, long taskId) {
        final long newTaskId;
        long newTaskId2;
        TLRPC.Dialog dialog;
        boolean[] folderCreated;
        TLRPC.TL_folders_editPeerFolders req = new TLRPC.TL_folders_editPeerFolders();
        boolean[] folderCreated2 = null;
        int i = 1;
        if (taskId == 0) {
            int selfUserId = getUserConfig().getClientUserId();
            int N = dialogIds.size();
            int size = 0;
            int size2 = 0;
            boolean[] folderCreated3 = null;
            int a = 0;
            while (a < N) {
                long dialogId = dialogIds.get(a).longValue();
                if ((DialogObject.isPeerDialogId(dialogId) || DialogObject.isSecretDialogId(dialogId)) && ((folderId != i || (dialogId != selfUserId && dialogId != 777000 && !isProxyDialog(dialogId, false))) && (dialog = this.dialogs_dict.get(dialogId)) != null)) {
                    dialog.folder_id = folderId;
                    if (pinnedNum > 0) {
                        dialog.pinned = true;
                        dialog.pinnedNum = pinnedNum;
                    } else {
                        dialog.pinned = false;
                        dialog.pinnedNum = 0;
                    }
                    if (folderCreated3 == null) {
                        boolean[] folderCreated4 = new boolean[1];
                        ensureFolderDialogExists(folderId, folderCreated4);
                        folderCreated = folderCreated4;
                    } else {
                        folderCreated = folderCreated3;
                    }
                    if (DialogObject.isSecretDialogId(dialogId)) {
                        getMessagesStorage().setDialogsFolderId(null, null, dialogId, folderId);
                        size2 = 1;
                        folderCreated3 = folderCreated;
                    } else {
                        TLRPC.TL_inputFolderPeer folderPeer = new TLRPC.TL_inputFolderPeer();
                        folderPeer.folder_id = folderId;
                        folderPeer.peer = getInputPeer((int) dialogId);
                        req.folder_peers.add(folderPeer);
                        size += folderPeer.getObjectSize();
                        size2 = 1;
                        folderCreated3 = folderCreated;
                    }
                }
                a++;
                i = 1;
            }
            if (size2 != 0) {
                sortDialogs(null);
                getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
                if (size != 0) {
                    NativeByteBuffer data = null;
                    try {
                        data = new NativeByteBuffer(size + 12);
                        data.writeInt32(17);
                        data.writeInt32(folderId);
                        data.writeInt32(req.folder_peers.size());
                        int N2 = req.folder_peers.size();
                        for (int a2 = 0; a2 < N2; a2++) {
                            req.folder_peers.get(a2).serializeToStream(data);
                        }
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                    newTaskId2 = getMessagesStorage().createPendingTask(data);
                } else {
                    newTaskId2 = 0;
                }
                folderCreated2 = folderCreated3;
                newTaskId = newTaskId2;
            } else {
                return 0;
            }
        } else {
            req.folder_peers = peers;
            newTaskId = taskId;
        }
        if (!req.folder_peers.isEmpty()) {
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$7PKO1Udxw2bbBZvSUEkL6T_zwko
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                    this.f$0.lambda$addDialogToFolder$129$MessagesController(newTaskId, tLObject, tL_error);
                }
            });
            getMessagesStorage().setDialogsFolderId(null, req.folder_peers, 0L, folderId);
        }
        if (folderCreated2 == null) {
            return 0;
        }
        return folderCreated2[0] ? 2 : 1;
    }

    public /* synthetic */ void lambda$addDialogToFolder$129$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            processUpdates((TLRPC.Updates) response, false);
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public void loadDialogs(int folderId, int offset, int count, boolean fromCache) {
        loadDialogs(folderId, offset, count, fromCache, null);
    }

    public void loadDialogs(final int folderId, int offset, final int count, boolean fromCache, final Runnable onEmptyCallback) {
        MessageObject message;
        int id;
        if (!this.loadingDialogs.get(folderId) && !this.resetingDialogs) {
            this.loadingDialogs.put(folderId, true);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            if (fromCache) {
                getMessagesStorage().getDialogs(folderId, offset != 0 ? this.nextDialogsCacheOffset.get(folderId, 0) : 0, count);
                return;
            }
            TLRPC.TL_messages_getDialogs req = new TLRPC.TL_messages_getDialogs();
            req.limit = count;
            req.exclude_pinned = true;
            if (folderId != 0) {
                req.flags |= 2;
                req.folder_id = folderId;
            }
            int[] dialogsLoadOffset = getUserConfig().getDialogLoadOffsets(folderId);
            if (dialogsLoadOffset[0] != -1) {
                if (dialogsLoadOffset[0] == Integer.MAX_VALUE) {
                    this.dialogsEndReached.put(folderId, true);
                    this.serverDialogsEndReached.put(folderId, true);
                    this.loadingDialogs.put(folderId, false);
                    getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
                    return;
                }
                req.offset_id = dialogsLoadOffset[0];
                req.offset_date = dialogsLoadOffset[1];
                if (req.offset_id == 0) {
                    req.offset_peer = new TLRPC.TL_inputPeerEmpty();
                } else {
                    if (dialogsLoadOffset[4] != 0) {
                        req.offset_peer = new TLRPC.TL_inputPeerChannel();
                        req.offset_peer.channel_id = dialogsLoadOffset[4];
                    } else if (dialogsLoadOffset[2] != 0) {
                        req.offset_peer = new TLRPC.TL_inputPeerUser();
                        req.offset_peer.user_id = dialogsLoadOffset[2];
                    } else {
                        req.offset_peer = new TLRPC.TL_inputPeerChat();
                        req.offset_peer.chat_id = dialogsLoadOffset[3];
                    }
                    req.offset_peer.access_hash = (((long) dialogsLoadOffset[5]) << 32) | ((long) dialogsLoadOffset[5]);
                }
            } else {
                boolean found = false;
                ArrayList<TLRPC.Dialog> dialogs = getDialogs(folderId);
                int a = dialogs.size() - 1;
                while (true) {
                    if (a < 0) {
                        break;
                    }
                    TLRPC.Dialog dialog = dialogs.get(a);
                    if (!dialog.pinned) {
                        int lower_id = (int) dialog.id;
                        int high_id = (int) (dialog.id >> 32);
                        if (lower_id != 0 && high_id != 1 && dialog.top_message > 0 && (message = this.dialogMessage.get(dialog.id)) != null && message.getId() > 0) {
                            req.offset_date = message.messageOwner.date;
                            req.offset_id = message.messageOwner.id;
                            if (message.messageOwner.to_id.channel_id != 0) {
                                id = -message.messageOwner.to_id.channel_id;
                            } else if (message.messageOwner.to_id.chat_id != 0) {
                                id = -message.messageOwner.to_id.chat_id;
                            } else {
                                id = message.messageOwner.to_id.user_id;
                            }
                            req.offset_peer = getInputPeer(id);
                            found = true;
                        }
                    }
                    a--;
                }
                if (!found) {
                    req.offset_peer = new TLRPC.TL_inputPeerEmpty();
                }
            }
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$mnwQ_02kalvh23URN7lCmO6Uln4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadDialogs$130$MessagesController(folderId, count, onEmptyCallback, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$loadDialogs$130$MessagesController(int folderId, int count, Runnable onEmptyCallback, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Dialogs dialogsRes = (TLRPC.messages_Dialogs) response;
            processLoadedDialogs(dialogsRes, null, folderId, 0, count, 0, false, false, false);
            if (onEmptyCallback != null && dialogsRes.dialogs.isEmpty()) {
                AndroidUtilities.runOnUIThread(onEmptyCallback);
            }
        }
    }

    public void loadGlobalNotificationsSettings() {
        if (this.loadingNotificationSettings == 0 && !getUserConfig().notificationsSettingsLoaded) {
            SharedPreferences preferences = getNotificationsSettings(this.currentAccount);
            SharedPreferences.Editor editor1 = null;
            if (preferences.contains("EnableGroup")) {
                boolean enabled = preferences.getBoolean("EnableGroup", true);
                if (0 == 0) {
                    editor1 = preferences.edit();
                }
                if (!enabled) {
                    editor1.putInt("EnableGroup2", Integer.MAX_VALUE);
                    editor1.putInt("EnableChannel2", Integer.MAX_VALUE);
                }
                editor1.remove("EnableGroup").commit();
            }
            if (preferences.contains("EnableAll")) {
                boolean enabled2 = preferences.getBoolean("EnableAll", true);
                if (editor1 == null) {
                    editor1 = preferences.edit();
                }
                if (!enabled2) {
                    editor1.putInt("EnableAll2", Integer.MAX_VALUE);
                }
                editor1.remove("EnableAll").commit();
            }
            if (editor1 != null) {
                editor1.commit();
            }
            this.loadingNotificationSettings = 3;
            for (int a = 0; a < 3; a++) {
                TLRPC.TL_account_getNotifySettings req = new TLRPC.TL_account_getNotifySettings();
                if (a == 0) {
                    req.peer = new TLRPC.TL_inputNotifyChats();
                } else if (a == 1) {
                    req.peer = new TLRPC.TL_inputNotifyUsers();
                } else if (a == 2) {
                    req.peer = new TLRPC.TL_inputNotifyBroadcasts();
                }
                final int type = a;
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$aRhjivnAA2DPzRio8JHJ0a7lOzE
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$loadGlobalNotificationsSettings$132$MessagesController(type, tLObject, tL_error);
                    }
                });
            }
        }
        if (!getUserConfig().notificationsSignUpSettingsLoaded) {
            loadSignUpNotificationsSettings();
        }
    }

    public /* synthetic */ void lambda$loadGlobalNotificationsSettings$132$MessagesController(final int type, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$BFZxv1z5r_1DoAsOvL6v_9Koo9w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$131$MessagesController(response, type);
            }
        });
    }

    public /* synthetic */ void lambda$null$131$MessagesController(TLObject response, int type) {
        if (response != null) {
            this.loadingNotificationSettings--;
            TLRPC.TL_peerNotifySettings notify_settings = (TLRPC.TL_peerNotifySettings) response;
            SharedPreferences.Editor editor = this.notificationsPreferences.edit();
            if (type == 0) {
                if ((notify_settings.flags & 1) != 0) {
                    editor.putBoolean("EnablePreviewGroup", notify_settings.show_previews);
                }
                int i = notify_settings.flags;
                if ((notify_settings.flags & 4) != 0) {
                    editor.putInt("EnableGroup2", notify_settings.mute_until);
                }
            } else if (type == 1) {
                if ((notify_settings.flags & 1) != 0) {
                    editor.putBoolean("EnablePreviewAll", notify_settings.show_previews);
                }
                int i2 = notify_settings.flags;
                if ((notify_settings.flags & 4) != 0) {
                    editor.putInt("EnableAll2", notify_settings.mute_until);
                }
            } else if (type == 2) {
                if ((notify_settings.flags & 1) != 0) {
                    editor.putBoolean("EnablePreviewChannel", notify_settings.show_previews);
                }
                int i3 = notify_settings.flags;
                if ((notify_settings.flags & 4) != 0) {
                    editor.putInt("EnableChannel2", notify_settings.mute_until);
                }
            }
            editor.commit();
            if (this.loadingNotificationSettings == 0) {
                getUserConfig().notificationsSettingsLoaded = true;
                getUserConfig().saveConfig(false);
            }
        }
    }

    public void loadSignUpNotificationsSettings() {
        if (!this.loadingNotificationSignUpSettings) {
            this.loadingNotificationSignUpSettings = true;
            TLRPC.TL_account_getContactSignUpNotification req = new TLRPC.TL_account_getContactSignUpNotification();
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$n-WnQ9-6bTQQtN1vdW_Cn9vYqSk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadSignUpNotificationsSettings$134$MessagesController(tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$loadSignUpNotificationsSettings$134$MessagesController(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$VfAgMtzwn4FSS1a316kYeM33Evs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$133$MessagesController(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$133$MessagesController(TLObject response) {
        this.loadingNotificationSignUpSettings = false;
        SharedPreferences.Editor editor = this.notificationsPreferences.edit();
        boolean z = response instanceof TLRPC.TL_boolFalse;
        this.enableJoined = z;
        editor.putBoolean("EnableContactJoined", z);
        editor.commit();
        getUserConfig().notificationsSignUpSettingsLoaded = true;
        getUserConfig().saveConfig(false);
    }

    public void forceResetDialogs() {
        resetDialogs(true, getMessagesStorage().getLastSeqValue(), getMessagesStorage().getLastPtsValue(), getMessagesStorage().getLastDateValue(), getMessagesStorage().getLastQtsValue());
        getNotificationsController().deleteAllNotificationChannels();
    }

    protected void loadUnknownDialog(TLRPC.InputPeer peer, long taskId) {
        long newTaskId;
        if (peer == null) {
            return;
        }
        final long dialogId = DialogObject.getPeerDialogId(peer);
        if (this.gettingUnknownDialogs.indexOfKey(dialogId) >= 0) {
            return;
        }
        this.gettingUnknownDialogs.put(dialogId, true);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("load unknown dialog " + dialogId);
        }
        TLRPC.TL_messages_getPeerDialogs req = new TLRPC.TL_messages_getPeerDialogs();
        TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
        inputDialogPeer.peer = peer;
        req.peers.add(inputDialogPeer);
        if (taskId == 0) {
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(peer.getObjectSize() + 4);
                data.writeInt32(15);
                peer.serializeToStream(data);
            } catch (Exception e) {
                FileLog.e(e);
            }
            long newTaskId2 = getMessagesStorage().createPendingTask(data);
            newTaskId = newTaskId2;
        } else {
            newTaskId = taskId;
        }
        final long j = newTaskId;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$LH1_JDkqTIMKLr8nCYtL4n96LcA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadUnknownDialog$135$MessagesController(j, dialogId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadUnknownDialog$135$MessagesController(long newTaskId, long dialogId, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.TL_messages_peerDialogs res = (TLRPC.TL_messages_peerDialogs) response;
            if (!res.dialogs.isEmpty() && !(res.dialogs.get(0) instanceof TLRPC.TL_dialogFolder)) {
                TLRPC.TL_dialog dialog = (TLRPC.TL_dialog) res.dialogs.get(0);
                TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
                dialogs.dialogs.addAll(res.dialogs);
                dialogs.messages.addAll(res.messages);
                dialogs.users.addAll(res.users);
                dialogs.chats.addAll(res.chats);
                processLoadedDialogs(dialogs, null, dialog.folder_id, 0, 1, this.DIALOGS_LOAD_TYPE_UNKNOWN, false, false, false);
            }
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
        this.gettingUnknownDialogs.delete(dialogId);
    }

    private void fetchFolderInLoadedPinnedDialogs(TLRPC.TL_messages_peerDialogs res) {
        int N;
        TLRPC.InputPeer inputPeer;
        int a = 0;
        int N2 = res.dialogs.size();
        while (a < N2) {
            TLRPC.Dialog dialog = res.dialogs.get(a);
            if (!(dialog instanceof TLRPC.TL_dialogFolder)) {
                N = N2;
            } else {
                TLRPC.TL_dialogFolder dialogFolder = (TLRPC.TL_dialogFolder) dialog;
                long folderTopDialogId = DialogObject.getPeerDialogId(dialog.peer);
                if (dialogFolder.top_message != 0) {
                    long folderTopDialogId2 = 0;
                    if (folderTopDialogId != 0) {
                        int b = 0;
                        int N22 = res.messages.size();
                        while (b < N22) {
                            TLRPC.Message message = res.messages.get(b);
                            long messageDialogId = MessageObject.getDialogId(message);
                            if (folderTopDialogId != messageDialogId || dialog.top_message != message.id) {
                                b++;
                                folderTopDialogId2 = folderTopDialogId2;
                                N2 = N2;
                                folderTopDialogId = folderTopDialogId;
                            } else {
                                TLRPC.TL_dialog newDialog = new TLRPC.TL_dialog();
                                newDialog.peer = dialog.peer;
                                newDialog.top_message = dialog.top_message;
                                newDialog.folder_id = dialogFolder.folder.id;
                                newDialog.flags |= 16;
                                res.dialogs.add(newDialog);
                                if (!(dialog.peer instanceof TLRPC.TL_peerChannel)) {
                                    if (dialog.peer instanceof TLRPC.TL_peerChat) {
                                        inputPeer = new TLRPC.TL_inputPeerChat();
                                        inputPeer.chat_id = dialog.peer.chat_id;
                                    } else {
                                        inputPeer = new TLRPC.TL_inputPeerUser();
                                        inputPeer.user_id = dialog.peer.user_id;
                                        int c = 0;
                                        int N3 = res.users.size();
                                        while (true) {
                                            if (c >= N3) {
                                                break;
                                            }
                                            TLRPC.User user = res.users.get(c);
                                            if (user.id != inputPeer.user_id) {
                                                c++;
                                            } else {
                                                inputPeer.access_hash = user.access_hash;
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    inputPeer = new TLRPC.TL_inputPeerChannel();
                                    inputPeer.channel_id = dialog.peer.channel_id;
                                    int c2 = 0;
                                    int N32 = res.chats.size();
                                    while (true) {
                                        if (c2 >= N32) {
                                            break;
                                        }
                                        int N4 = N2;
                                        TLRPC.Chat chat = res.chats.get(c2);
                                        long folderTopDialogId3 = folderTopDialogId;
                                        if (chat.id != inputPeer.channel_id) {
                                            c2++;
                                            N2 = N4;
                                            folderTopDialogId = folderTopDialogId3;
                                        } else {
                                            inputPeer.access_hash = chat.access_hash;
                                            break;
                                        }
                                    }
                                }
                                loadUnknownDialog(inputPeer, 0L);
                                return;
                            }
                        }
                        return;
                    }
                    N = N2;
                } else {
                    N = N2;
                }
                res.dialogs.remove(dialogFolder);
            }
            a++;
            N2 = N;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:79:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0222  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void resetDialogs(boolean r21, final int r22, final int r23, final int r24, final int r25) {
        /*
            Method dump skipped, instruction units count: 777
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.resetDialogs(boolean, int, int, int, int):void");
    }

    public /* synthetic */ void lambda$resetDialogs$136$MessagesController(int seq, int newPts, int date, int qts, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            this.resetDialogsPinned = (TLRPC.TL_messages_peerDialogs) response;
            for (int a = 0; a < this.resetDialogsPinned.dialogs.size(); a++) {
                TLRPC.Dialog d = this.resetDialogsPinned.dialogs.get(a);
                d.pinned = true;
            }
            resetDialogs(false, seq, newPts, date, qts);
        }
    }

    public /* synthetic */ void lambda$resetDialogs$137$MessagesController(int seq, int newPts, int date, int qts, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            this.resetDialogsAll = (TLRPC.messages_Dialogs) response;
            resetDialogs(false, seq, newPts, date, qts);
        }
    }

    protected void completeDialogsReset(final TLRPC.messages_Dialogs dialogsRes, int messagesCount, int seq, final int newPts, final int date, final int qts, final LongSparseArray<TLRPC.Dialog> new_dialogs_dict, final LongSparseArray<MessageObject> new_dialogMessage, TLRPC.Message lastMessage) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$-eSd-BvvGngkbyB7nomoqG1Ff_U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$completeDialogsReset$139$MessagesController(newPts, date, qts, dialogsRes, new_dialogs_dict, new_dialogMessage);
            }
        });
    }

    public /* synthetic */ void lambda$completeDialogsReset$139$MessagesController(int newPts, int date, int qts, final TLRPC.messages_Dialogs dialogsRes, final LongSparseArray new_dialogs_dict, final LongSparseArray new_dialogMessage) {
        this.gettingDifference = false;
        getMessagesStorage().setLastPtsValue(newPts);
        getMessagesStorage().setLastDateValue(date);
        getMessagesStorage().setLastQtsValue(qts);
        getDifference();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$rMnHzxgHJRGM8BpH1moWUcDX27M
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$138$MessagesController(dialogsRes, new_dialogs_dict, new_dialogMessage);
            }
        });
    }

    public /* synthetic */ void lambda$null$138$MessagesController(TLRPC.messages_Dialogs dialogsRes, LongSparseArray new_dialogs_dict, LongSparseArray new_dialogMessage) {
        this.resetingDialogs = false;
        applyDialogsNotificationsSettings(dialogsRes.dialogs);
        if (!getUserConfig().draftsLoaded) {
            getMediaDataController().loadDrafts();
        }
        putUsers(dialogsRes.users, false);
        putChats(dialogsRes.chats, false);
        for (int a = 0; a < this.allDialogs.size(); a++) {
            TLRPC.Dialog oldDialog = this.allDialogs.get(a);
            if (!DialogObject.isSecretDialogId(oldDialog.id)) {
                this.dialogs_dict.remove(oldDialog.id);
                MessageObject messageObject = this.dialogMessage.get(oldDialog.id);
                this.dialogMessage.remove(oldDialog.id);
                if (messageObject != null) {
                    this.dialogMessagesByIds.remove(messageObject.getId());
                    if (messageObject.messageOwner.random_id != 0) {
                        this.dialogMessagesByRandomIds.remove(messageObject.messageOwner.random_id);
                    }
                }
            }
        }
        for (int a2 = 0; a2 < new_dialogs_dict.size(); a2++) {
            long key = new_dialogs_dict.keyAt(a2);
            TLRPC.Dialog value = (TLRPC.Dialog) new_dialogs_dict.valueAt(a2);
            if (value.draft instanceof TLRPC.TL_draftMessage) {
                getMediaDataController().saveDraft(value.id, value.draft, null, false);
            }
            this.dialogs_dict.put(key, value);
            MessageObject messageObject2 = (MessageObject) new_dialogMessage.get(value.id);
            this.dialogMessage.put(key, messageObject2);
            if (messageObject2 != null && messageObject2.messageOwner.to_id.channel_id == 0) {
                this.dialogMessagesByIds.put(messageObject2.getId(), messageObject2);
                if (messageObject2.messageOwner.random_id != 0) {
                    this.dialogMessagesByRandomIds.put(messageObject2.messageOwner.random_id, messageObject2);
                }
            }
        }
        this.allDialogs.clear();
        int size = this.dialogs_dict.size();
        for (int a3 = 0; a3 < size; a3++) {
            this.allDialogs.add(this.dialogs_dict.valueAt(a3));
        }
        sortDialogs(null);
        this.dialogsEndReached.put(0, true);
        this.serverDialogsEndReached.put(0, false);
        this.dialogsEndReached.put(1, true);
        this.serverDialogsEndReached.put(1, false);
        int totalDialogsLoadCount = getUserConfig().getTotalDialogsCount(0);
        int[] dialogsLoadOffset = getUserConfig().getDialogLoadOffsets(0);
        if (totalDialogsLoadCount < 400 && dialogsLoadOffset[0] != -1 && dialogsLoadOffset[0] != Integer.MAX_VALUE) {
            loadDialogs(0, 100, 0, false);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    private void migrateDialogs(final int offset, int offsetDate, int offsetUser, int offsetChat, int offsetChannel, long accessPeer) {
        if (this.migratingDialogs || offset == -1) {
            return;
        }
        this.migratingDialogs = true;
        TLRPC.TL_messages_getDialogs req = new TLRPC.TL_messages_getDialogs();
        req.exclude_pinned = true;
        req.limit = 100;
        req.offset_id = offset;
        req.offset_date = offsetDate;
        if (offset == 0) {
            req.offset_peer = new TLRPC.TL_inputPeerEmpty();
        } else {
            if (offsetChannel != 0) {
                req.offset_peer = new TLRPC.TL_inputPeerChannel();
                req.offset_peer.channel_id = offsetChannel;
            } else if (offsetUser != 0) {
                req.offset_peer = new TLRPC.TL_inputPeerUser();
                req.offset_peer.user_id = offsetUser;
            } else {
                req.offset_peer = new TLRPC.TL_inputPeerChat();
                req.offset_peer.chat_id = offsetChat;
            }
            req.offset_peer.access_hash = accessPeer;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$vdnJKfvith-exf3ZQIied9VTH50
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$migrateDialogs$143$MessagesController(offset, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$migrateDialogs$143$MessagesController(final int offset, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.messages_Dialogs dialogsRes = (TLRPC.messages_Dialogs) response;
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$REiNl3pVAyWxhge-9dm7GyZlLaM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$141$MessagesController(dialogsRes, offset);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Yq4FgQSnfQ-YKm7KmlPxAPPm1as
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$142$MessagesController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$141$MessagesController(TLRPC.messages_Dialogs dialogsRes, int offset) {
        int offsetId;
        int offsetId2;
        int totalDialogsLoadCount;
        TLRPC.Message lastMessage;
        StringBuilder dids;
        int i = offset;
        try {
            int i2 = 0;
            int totalDialogsLoadCount2 = getUserConfig().getTotalDialogsCount(0);
            getUserConfig().setTotalDialogsCount(0, dialogsRes.dialogs.size() + totalDialogsLoadCount2);
            TLRPC.Message lastMessage2 = null;
            for (int a = 0; a < dialogsRes.messages.size(); a++) {
                TLRPC.Message message = dialogsRes.messages.get(a);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("search migrate id " + message.id + " date " + LocaleController.getInstance().formatterStats.format(((long) message.date) * 1000));
                }
                if (lastMessage2 == null || message.date < lastMessage2.date) {
                    lastMessage2 = message;
                }
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("migrate step with id " + lastMessage2.id + " date " + LocaleController.getInstance().formatterStats.format(((long) lastMessage2.date) * 1000));
            }
            if (dialogsRes.dialogs.size() >= 100) {
                offsetId = lastMessage2.id;
            } else {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("migrate stop due to not 100 dialogs");
                }
                for (int i3 = 0; i3 < 2; i3++) {
                    getUserConfig().setDialogsLoadOffset(i3, Integer.MAX_VALUE, getUserConfig().migrateOffsetDate, getUserConfig().migrateOffsetUserId, getUserConfig().migrateOffsetChatId, getUserConfig().migrateOffsetChannelId, getUserConfig().migrateOffsetAccess);
                }
                offsetId = -1;
            }
            StringBuilder dids2 = new StringBuilder(dialogsRes.dialogs.size() * 12);
            LongSparseArray<TLRPC.Dialog> dialogHashMap = new LongSparseArray<>();
            for (int a2 = 0; a2 < dialogsRes.dialogs.size(); a2++) {
                TLRPC.Dialog dialog = dialogsRes.dialogs.get(a2);
                DialogObject.initDialog(dialog);
                if (dids2.length() > 0) {
                    dids2.append(",");
                }
                dids2.append(dialog.id);
                dialogHashMap.put(dialog.id, dialog);
            }
            int i4 = 1;
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT did, folder_id FROM dialogs WHERE did IN (%s)", dids2.toString()), new Object[0]);
            while (cursor.next()) {
                long did = cursor.longValue(i2);
                int folder_id = cursor.intValue(i4);
                TLRPC.Dialog dialog2 = dialogHashMap.get(did);
                if (dialog2.folder_id == folder_id) {
                    dialogHashMap.remove(did);
                    if (dialog2 != null) {
                        dialogsRes.dialogs.remove(dialog2);
                        int a3 = 0;
                        while (true) {
                            if (a3 >= dialogsRes.messages.size()) {
                                break;
                            }
                            TLRPC.Message message2 = dialogsRes.messages.get(a3);
                            if (MessageObject.getDialogId(message2) == did) {
                                dialogsRes.messages.remove(a3);
                                a3--;
                                if (message2.id == dialog2.top_message) {
                                    dialog2.top_message = 0;
                                    break;
                                }
                            }
                            a3++;
                        }
                    }
                    i2 = 0;
                    i4 = 1;
                }
            }
            cursor.dispose();
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("migrate found missing dialogs " + dialogsRes.dialogs.size());
            }
            SQLiteCursor cursor2 = getMessagesStorage().getDatabase().queryFinalized("SELECT min(date) FROM dialogs WHERE date != 0 AND did >> 32 IN (0, -1)", new Object[0]);
            if (cursor2.next()) {
                int date = Math.max(1441062000, cursor2.intValue(0));
                int a4 = 0;
                while (a4 < dialogsRes.messages.size()) {
                    try {
                        TLRPC.Message message3 = dialogsRes.messages.get(a4);
                        if (message3.date >= date) {
                            totalDialogsLoadCount = totalDialogsLoadCount2;
                            lastMessage = lastMessage2;
                            dids = dids2;
                        } else {
                            if (i == -1) {
                                totalDialogsLoadCount = totalDialogsLoadCount2;
                                lastMessage = lastMessage2;
                                dids = dids2;
                            } else {
                                int i5 = 0;
                                while (i5 < 2) {
                                    getUserConfig().setDialogsLoadOffset(i5, getUserConfig().migrateOffsetId, getUserConfig().migrateOffsetDate, getUserConfig().migrateOffsetUserId, getUserConfig().migrateOffsetChatId, getUserConfig().migrateOffsetChannelId, getUserConfig().migrateOffsetAccess);
                                    i5++;
                                    totalDialogsLoadCount2 = totalDialogsLoadCount2;
                                    offsetId = offsetId;
                                    dids2 = dids2;
                                    lastMessage2 = lastMessage2;
                                }
                                totalDialogsLoadCount = totalDialogsLoadCount2;
                                lastMessage = lastMessage2;
                                dids = dids2;
                                offsetId = -1;
                                if (BuildVars.LOGS_ENABLED) {
                                    FileLog.d("migrate stop due to reached loaded dialogs " + LocaleController.getInstance().formatterStats.format(((long) date) * 1000));
                                }
                            }
                            dialogsRes.messages.remove(a4);
                            a4--;
                            long did2 = MessageObject.getDialogId(message3);
                            TLRPC.Dialog dialog3 = dialogHashMap.get(did2);
                            dialogHashMap.remove(did2);
                            if (dialog3 != null) {
                                dialogsRes.dialogs.remove(dialog3);
                            }
                        }
                        a4++;
                        i = offset;
                        totalDialogsLoadCount2 = totalDialogsLoadCount;
                        dids2 = dids;
                        lastMessage2 = lastMessage;
                    } catch (Exception e) {
                        e = e;
                        FileLog.e(e);
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$yYYWrBNGTi2flkSkW-lfc8zC0rs
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$null$140$MessagesController();
                            }
                        });
                        return;
                    }
                }
                offsetId2 = offsetId;
                TLRPC.Message lastMessage3 = lastMessage2;
                if (lastMessage3 != null) {
                    lastMessage2 = lastMessage3;
                    if (lastMessage2.date < date && offset != -1) {
                        for (int i6 = 0; i6 < 2; i6++) {
                            getUserConfig().setDialogsLoadOffset(i6, getUserConfig().migrateOffsetId, getUserConfig().migrateOffsetDate, getUserConfig().migrateOffsetUserId, getUserConfig().migrateOffsetChatId, getUserConfig().migrateOffsetChannelId, getUserConfig().migrateOffsetAccess);
                        }
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("migrate stop due to reached loaded dialogs " + LocaleController.getInstance().formatterStats.format(((long) date) * 1000));
                        }
                        offsetId2 = -1;
                    }
                } else {
                    lastMessage2 = lastMessage3;
                }
            } else {
                offsetId2 = offsetId;
            }
            cursor2.dispose();
            getUserConfig().migrateOffsetDate = lastMessage2.date;
            if (lastMessage2.to_id.channel_id != 0) {
                getUserConfig().migrateOffsetChannelId = lastMessage2.to_id.channel_id;
                getUserConfig().migrateOffsetChatId = 0;
                getUserConfig().migrateOffsetUserId = 0;
                int a5 = 0;
                while (true) {
                    if (a5 >= dialogsRes.chats.size()) {
                        break;
                    }
                    TLRPC.Chat chat = dialogsRes.chats.get(a5);
                    if (chat.id != getUserConfig().migrateOffsetChannelId) {
                        a5++;
                    } else {
                        getUserConfig().migrateOffsetAccess = chat.access_hash;
                        break;
                    }
                }
            } else if (lastMessage2.to_id.chat_id != 0) {
                getUserConfig().migrateOffsetChatId = lastMessage2.to_id.chat_id;
                getUserConfig().migrateOffsetChannelId = 0;
                getUserConfig().migrateOffsetUserId = 0;
                int a6 = 0;
                while (true) {
                    if (a6 >= dialogsRes.chats.size()) {
                        break;
                    }
                    TLRPC.Chat chat2 = dialogsRes.chats.get(a6);
                    if (chat2.id != getUserConfig().migrateOffsetChatId) {
                        a6++;
                    } else {
                        getUserConfig().migrateOffsetAccess = chat2.access_hash;
                        break;
                    }
                }
            } else if (lastMessage2.to_id.user_id != 0) {
                getUserConfig().migrateOffsetUserId = lastMessage2.to_id.user_id;
                getUserConfig().migrateOffsetChatId = 0;
                getUserConfig().migrateOffsetChannelId = 0;
                int a7 = 0;
                while (true) {
                    if (a7 >= dialogsRes.users.size()) {
                        break;
                    }
                    TLRPC.User user = dialogsRes.users.get(a7);
                    if (user.id != getUserConfig().migrateOffsetUserId) {
                        a7++;
                    } else {
                        getUserConfig().migrateOffsetAccess = user.access_hash;
                        break;
                    }
                }
            }
            processLoadedDialogs(dialogsRes, null, 0, offsetId2, 0, 0, false, true, false);
        } catch (Exception e2) {
            e = e2;
        }
    }

    public /* synthetic */ void lambda$null$140$MessagesController() {
        this.migratingDialogs = false;
    }

    public /* synthetic */ void lambda$null$142$MessagesController() {
        this.migratingDialogs = false;
    }

    public void processLoadedDialogs(final TLRPC.messages_Dialogs dialogsRes, final ArrayList<TLRPC.EncryptedChat> encChats, final int folderId, final int offset, final int count, final int loadType, final boolean resetEnd, final boolean migrate, final boolean fromCache) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$7S7zlYy9o1eeQpoW35OTF9lZOpA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedDialogs$146$MessagesController(folderId, loadType, dialogsRes, resetEnd, count, encChats, offset, fromCache, migrate);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:161:0x0370  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0388  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x039c  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x03cb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$processLoadedDialogs$146$MessagesController(final int r32, final int r33, final im.uwrkaxlmjj.tgnet.TLRPC.messages_Dialogs r34, final boolean r35, final int r36, final java.util.ArrayList r37, final int r38, final boolean r39, final boolean r40) {
        /*
            Method dump skipped, instruction units count: 1253
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.lambda$processLoadedDialogs$146$MessagesController(int, int, im.uwrkaxlmjj.tgnet.TLRPC$messages_Dialogs, boolean, int, java.util.ArrayList, int, boolean, boolean):void");
    }

    public /* synthetic */ void lambda$null$144$MessagesController(TLRPC.messages_Dialogs dialogsRes, int folderId, boolean resetEnd, int[] dialogsLoadOffset, int count) {
        putUsers(dialogsRes.users, true);
        this.loadingDialogs.put(folderId, false);
        if (resetEnd) {
            this.dialogsEndReached.put(folderId, false);
            this.serverDialogsEndReached.put(folderId, false);
        } else if (dialogsLoadOffset[0] == Integer.MAX_VALUE) {
            this.dialogsEndReached.put(folderId, true);
            this.serverDialogsEndReached.put(folderId, true);
        } else {
            loadDialogs(folderId, 0, count, false);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$null$145$MessagesController(int loadType, TLRPC.messages_Dialogs dialogsRes, ArrayList encChats, boolean migrate, int folderId, LongSparseArray new_dialogs_dict, LongSparseArray new_dialogMessage, SparseArray chatsDict, int count, boolean fromCache, int offset, ArrayList dialogsToReload) {
        int i;
        boolean z;
        TLRPC.Dialog currentDialog;
        int lastDialogDate;
        int lastDialogDate2;
        int archivedDialogsCount;
        if (loadType != this.DIALOGS_LOAD_TYPE_CACHE) {
            applyDialogsNotificationsSettings(dialogsRes.dialogs);
            if (!getUserConfig().draftsLoaded) {
                getMediaDataController().loadDrafts();
            }
        }
        putUsers(dialogsRes.users, loadType == this.DIALOGS_LOAD_TYPE_CACHE);
        putChats(dialogsRes.chats, loadType == this.DIALOGS_LOAD_TYPE_CACHE);
        if (encChats != null) {
            for (int a = 0; a < encChats.size(); a++) {
                TLRPC.EncryptedChat encryptedChat = (TLRPC.EncryptedChat) encChats.get(a);
                if ((encryptedChat instanceof TLRPC.TL_encryptedChat) && AndroidUtilities.getMyLayerVersion(encryptedChat.layer) < 101) {
                    getSecretChatHelper().sendNotifyLayerMessage(encryptedChat, null);
                }
                putEncryptedChat(encryptedChat, true);
            }
        }
        if (!migrate && loadType != this.DIALOGS_LOAD_TYPE_UNKNOWN && loadType != this.DIALOGS_LOAD_TYPE_CHANNEL) {
            this.loadingDialogs.put(folderId, false);
        }
        this.dialogsLoaded = true;
        if (!migrate || this.allDialogs.isEmpty()) {
            i = 0;
        } else {
            ArrayList<TLRPC.Dialog> arrayList = this.allDialogs;
            i = arrayList.get(arrayList.size() - 1).last_message_date;
        }
        int lastDialogDate3 = i;
        int a2 = 0;
        boolean added = false;
        int archivedDialogsCount2 = 0;
        while (a2 < new_dialogs_dict.size()) {
            long key = new_dialogs_dict.keyAt(a2);
            TLRPC.Dialog value = (TLRPC.Dialog) new_dialogs_dict.valueAt(a2);
            if (loadType != this.DIALOGS_LOAD_TYPE_UNKNOWN) {
                currentDialog = this.dialogs_dict.get(key);
            } else {
                currentDialog = null;
            }
            if (migrate && currentDialog != null) {
                currentDialog.folder_id = value.folder_id;
            }
            if (migrate && lastDialogDate3 != 0 && value.last_message_date < lastDialogDate3) {
                lastDialogDate = lastDialogDate3;
            } else {
                if (loadType != this.DIALOGS_LOAD_TYPE_CACHE && (value.draft instanceof TLRPC.TL_draftMessage)) {
                    getMediaDataController().saveDraft(value.id, value.draft, null, false);
                }
                if (value.folder_id != folderId) {
                    archivedDialogsCount2++;
                }
                if (currentDialog == null) {
                    this.dialogs_dict.put(key, value);
                    MessageObject messageObject = (MessageObject) new_dialogMessage.get(value.id);
                    this.dialogMessage.put(key, messageObject);
                    if (messageObject != null && messageObject.messageOwner.to_id.channel_id == 0) {
                        added = true;
                        this.dialogMessagesByIds.put(messageObject.getId(), messageObject);
                        lastDialogDate2 = lastDialogDate3;
                        archivedDialogsCount = archivedDialogsCount2;
                        if (messageObject.messageOwner.random_id != 0) {
                            this.dialogMessagesByRandomIds.put(messageObject.messageOwner.random_id, messageObject);
                        }
                    } else {
                        added = true;
                        lastDialogDate2 = lastDialogDate3;
                        archivedDialogsCount = archivedDialogsCount2;
                    }
                    lastDialogDate = lastDialogDate2;
                    archivedDialogsCount2 = archivedDialogsCount;
                } else {
                    int lastDialogDate4 = lastDialogDate3;
                    int archivedDialogsCount3 = archivedDialogsCount2;
                    if (loadType != this.DIALOGS_LOAD_TYPE_CACHE) {
                        currentDialog.notify_settings = value.notify_settings;
                    }
                    currentDialog.pinned = value.pinned;
                    currentDialog.pinnedNum = value.pinnedNum;
                    MessageObject oldMsg = this.dialogMessage.get(key);
                    if ((oldMsg != null && oldMsg.deleted) || oldMsg == null || currentDialog.top_message > 0) {
                        lastDialogDate = lastDialogDate4;
                        if (value.top_message >= currentDialog.top_message) {
                            this.dialogs_dict.put(key, value);
                            MessageObject messageObject2 = (MessageObject) new_dialogMessage.get(value.id);
                            this.dialogMessage.put(key, messageObject2);
                            if (messageObject2 != null && messageObject2.messageOwner.to_id.channel_id == 0) {
                                this.dialogMessagesByIds.put(messageObject2.getId(), messageObject2);
                                if (messageObject2 != null && messageObject2.messageOwner.random_id != 0) {
                                    this.dialogMessagesByRandomIds.put(messageObject2.messageOwner.random_id, messageObject2);
                                }
                            }
                            if (oldMsg != null) {
                                this.dialogMessagesByIds.remove(oldMsg.getId());
                                if (oldMsg.messageOwner.random_id != 0) {
                                    this.dialogMessagesByRandomIds.remove(oldMsg.messageOwner.random_id);
                                }
                            }
                        }
                        archivedDialogsCount2 = archivedDialogsCount3;
                    } else {
                        MessageObject newMsg = (MessageObject) new_dialogMessage.get(value.id);
                        if (oldMsg.deleted || newMsg == null || newMsg.messageOwner.date > oldMsg.messageOwner.date) {
                            this.dialogs_dict.put(key, value);
                            this.dialogMessage.put(key, newMsg);
                            if (newMsg == null || newMsg.messageOwner.to_id.channel_id != 0) {
                                lastDialogDate = lastDialogDate4;
                            } else {
                                this.dialogMessagesByIds.put(newMsg.getId(), newMsg);
                                if (newMsg != null) {
                                    lastDialogDate = lastDialogDate4;
                                    if (newMsg.messageOwner.random_id != 0) {
                                        this.dialogMessagesByRandomIds.put(newMsg.messageOwner.random_id, newMsg);
                                    }
                                } else {
                                    lastDialogDate = lastDialogDate4;
                                }
                            }
                            this.dialogMessagesByIds.remove(oldMsg.getId());
                            if (oldMsg.messageOwner.random_id != 0) {
                                this.dialogMessagesByRandomIds.remove(oldMsg.messageOwner.random_id);
                            }
                        } else {
                            lastDialogDate = lastDialogDate4;
                        }
                        archivedDialogsCount2 = archivedDialogsCount3;
                    }
                }
            }
            a2++;
            lastDialogDate3 = lastDialogDate;
        }
        this.allDialogs.clear();
        int size = this.dialogs_dict.size();
        for (int a3 = 0; a3 < size; a3++) {
            this.allDialogs.add(this.dialogs_dict.valueAt(a3));
        }
        sortDialogs(migrate ? chatsDict : null);
        if (loadType != this.DIALOGS_LOAD_TYPE_CHANNEL && loadType != this.DIALOGS_LOAD_TYPE_UNKNOWN && !migrate) {
            this.dialogsEndReached.put(folderId, (dialogsRes.dialogs.size() == 0 || dialogsRes.dialogs.size() != count) && loadType == 0);
            if (archivedDialogsCount2 <= 0 || archivedDialogsCount2 >= 20 || folderId != 0) {
                z = true;
            } else {
                z = true;
                this.dialogsEndReached.put(1, true);
                int[] dialogsLoadOffsetArchived = getUserConfig().getDialogLoadOffsets(folderId);
                if (dialogsLoadOffsetArchived[0] == Integer.MAX_VALUE) {
                    this.serverDialogsEndReached.put(1, true);
                }
            }
            if (!fromCache) {
                SparseBooleanArray sparseBooleanArray = this.serverDialogsEndReached;
                if ((dialogsRes.dialogs.size() != 0 && dialogsRes.dialogs.size() == count) || loadType != 0) {
                    z = false;
                }
                sparseBooleanArray.put(folderId, z);
            }
        }
        int totalDialogsLoadCount = getUserConfig().getTotalDialogsCount(folderId);
        int[] dialogsLoadOffset2 = getUserConfig().getDialogLoadOffsets(folderId);
        if (!fromCache && !migrate && totalDialogsLoadCount < 400 && dialogsLoadOffset2[0] != -1 && dialogsLoadOffset2[0] != Integer.MAX_VALUE) {
            loadDialogs(0, 100, folderId, false);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        if (migrate) {
            getUserConfig().migrateOffsetId = offset;
            getUserConfig().saveConfig(false);
            this.migratingDialogs = false;
            getNotificationCenter().postNotificationName(NotificationCenter.needReloadRecentDialogsSearch, new Object[0]);
        } else {
            generateUpdateMessage();
            if (!added && loadType == this.DIALOGS_LOAD_TYPE_CACHE) {
                loadDialogs(folderId, 0, count, false);
            }
        }
        migrateDialogs(getUserConfig().migrateOffsetId, getUserConfig().migrateOffsetDate, getUserConfig().migrateOffsetUserId, getUserConfig().migrateOffsetChatId, getUserConfig().migrateOffsetChannelId, getUserConfig().migrateOffsetAccess);
        if (!dialogsToReload.isEmpty()) {
            reloadDialogsReadValue(dialogsToReload, 0L);
        }
        loadUnreadDialogs();
    }

    private void applyDialogNotificationsSettings(long dialog_id, TLRPC.PeerNotifySettings notify_settings) {
        boolean updated;
        int i;
        if (notify_settings == null) {
            return;
        }
        int currentValue = this.notificationsPreferences.getInt("notify2_" + dialog_id, -1);
        int currentValue2 = this.notificationsPreferences.getInt("notifyuntil_" + dialog_id, 0);
        SharedPreferences.Editor editor = this.notificationsPreferences.edit();
        TLRPC.Dialog dialog = this.dialogs_dict.get(dialog_id);
        if (dialog != null) {
            dialog.notify_settings = notify_settings;
        }
        if ((notify_settings.flags & 2) != 0) {
            editor.putBoolean("silent_" + dialog_id, notify_settings.silent);
        } else {
            editor.remove("silent_" + dialog_id);
        }
        boolean updated2 = false;
        if ((notify_settings.flags & 4) != 0) {
            if (notify_settings.mute_until > getConnectionsManager().getCurrentTime()) {
                int until = 0;
                if (notify_settings.mute_until > getConnectionsManager().getCurrentTime() + 31536000) {
                    if (currentValue == 2) {
                        updated = false;
                    } else {
                        updated = true;
                        editor.putInt("notify2_" + dialog_id, 2);
                        if (dialog != null) {
                            dialog.notify_settings.mute_until = Integer.MAX_VALUE;
                        }
                    }
                } else {
                    if (currentValue == 3 && currentValue2 == notify_settings.mute_until) {
                        updated = false;
                    } else {
                        updated = true;
                        editor.putInt("notify2_" + dialog_id, 3);
                        editor.putInt("notifyuntil_" + dialog_id, notify_settings.mute_until);
                        if (dialog != null) {
                            dialog.notify_settings.mute_until = 0;
                        }
                    }
                    until = notify_settings.mute_until;
                }
                getMessagesStorage().setDialogFlags(dialog_id, (((long) until) << 32) | 1);
                getNotificationsController().removeNotificationsForDialog(dialog_id);
            } else {
                if (currentValue != 0 && currentValue != 1) {
                    if (dialog == null) {
                        i = 0;
                    } else {
                        i = 0;
                        dialog.notify_settings.mute_until = 0;
                    }
                    editor.putInt("notify2_" + dialog_id, i);
                    updated2 = true;
                }
                getMessagesStorage().setDialogFlags(dialog_id, 0L);
                updated = updated2;
            }
        } else {
            if (currentValue != -1) {
                if (dialog != null) {
                    dialog.notify_settings.mute_until = 0;
                }
                editor.remove("notify2_" + dialog_id);
                updated2 = true;
            }
            getMessagesStorage().setDialogFlags(dialog_id, 0L);
            updated = updated2;
        }
        editor.commit();
        if (updated) {
            getNotificationCenter().postNotificationName(NotificationCenter.notificationsSettingsUpdated, new Object[0]);
        }
    }

    private void applyDialogsNotificationsSettings(ArrayList<TLRPC.Dialog> dialogs) {
        int dialog_id;
        SharedPreferences.Editor editor = null;
        for (int a = 0; a < dialogs.size(); a++) {
            TLRPC.Dialog dialog = dialogs.get(a);
            if (dialog.peer != null && (dialog.notify_settings instanceof TLRPC.TL_peerNotifySettings)) {
                if (editor == null) {
                    editor = this.notificationsPreferences.edit();
                }
                if (dialog.peer.user_id != 0) {
                    dialog_id = dialog.peer.user_id;
                } else if (dialog.peer.chat_id != 0) {
                    dialog_id = -dialog.peer.chat_id;
                } else {
                    dialog_id = -dialog.peer.channel_id;
                }
                if ((dialog.notify_settings.flags & 2) != 0) {
                    editor.putBoolean("silent_" + dialog_id, dialog.notify_settings.silent);
                } else {
                    editor.remove("silent_" + dialog_id);
                }
                if ((dialog.notify_settings.flags & 4) == 0) {
                    editor.remove("notify2_" + dialog_id);
                } else if (dialog.notify_settings.mute_until <= getConnectionsManager().getCurrentTime()) {
                    editor.putInt("notify2_" + dialog_id, 0);
                } else if (dialog.notify_settings.mute_until > getConnectionsManager().getCurrentTime() + 31536000) {
                    editor.putInt("notify2_" + dialog_id, 2);
                    dialog.notify_settings.mute_until = Integer.MAX_VALUE;
                } else {
                    editor.putInt("notify2_" + dialog_id, 3);
                    editor.putInt("notifyuntil_" + dialog_id, dialog.notify_settings.mute_until);
                }
            }
        }
        if (editor != null) {
            editor.commit();
        }
    }

    public void reloadMentionsCountForChannels(final ArrayList<Integer> arrayList) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$oIY3fILuVHP9hHCUq23fQxX2Ylw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$reloadMentionsCountForChannels$149$MessagesController(arrayList);
            }
        });
    }

    public /* synthetic */ void lambda$reloadMentionsCountForChannels$149$MessagesController(ArrayList arrayList) {
        for (int a = 0; a < arrayList.size(); a++) {
            final long dialog_id = -((Integer) arrayList.get(a)).intValue();
            TLRPC.TL_messages_getUnreadMentions req = new TLRPC.TL_messages_getUnreadMentions();
            req.peer = getInputPeer((int) dialog_id);
            req.limit = 1;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$FpCmCQ1PvmH9pMReFNM_eMXpd8I
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$148$MessagesController(dialog_id, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$148$MessagesController(final long dialog_id, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kxF1hQgJhU4Y_rkQ2Mr3mISytJs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$147$MessagesController(response, dialog_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$147$MessagesController(TLObject response, long dialog_id) {
        int newCount;
        TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
        if (res != null) {
            if (res.count != 0) {
                newCount = res.count;
            } else {
                newCount = res.messages.size();
            }
            getMessagesStorage().resetMentionsCount(dialog_id, newCount);
        }
    }

    public void processDialogsUpdateRead(final LongSparseArray<Integer> dialogsToUpdate, final LongSparseArray<Integer> dialogsMentionsToUpdate) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$iAvDVDXVyZcxLyEHhUDGWxvBiBk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processDialogsUpdateRead$150$MessagesController(dialogsToUpdate, dialogsMentionsToUpdate);
            }
        });
    }

    public /* synthetic */ void lambda$processDialogsUpdateRead$150$MessagesController(LongSparseArray dialogsToUpdate, LongSparseArray dialogsMentionsToUpdate) {
        if (dialogsToUpdate != null) {
            for (int a = 0; a < dialogsToUpdate.size(); a++) {
                long dialogId = dialogsToUpdate.keyAt(a);
                TLRPC.Dialog currentDialog = this.dialogs_dict.get(dialogId);
                if (currentDialog != null) {
                    int prevCount = currentDialog.unread_count;
                    currentDialog.unread_count = ((Integer) dialogsToUpdate.valueAt(a)).intValue();
                    if (prevCount != 0 && currentDialog.unread_count == 0 && !isDialogMuted(dialogId)) {
                        this.unreadUnmutedDialogs--;
                    } else if (prevCount == 0 && !currentDialog.unread_mark && currentDialog.unread_count != 0) {
                        this.dialogsUnreadOnly.add(currentDialog);
                        if (!isDialogMuted(dialogId)) {
                            this.unreadUnmutedDialogs++;
                        }
                    }
                }
            }
        }
        if (dialogsMentionsToUpdate != null) {
            for (int a2 = 0; a2 < dialogsMentionsToUpdate.size(); a2++) {
                TLRPC.Dialog currentDialog2 = this.dialogs_dict.get(dialogsMentionsToUpdate.keyAt(a2));
                if (currentDialog2 != null) {
                    currentDialog2.unread_mentions_count = ((Integer) dialogsMentionsToUpdate.valueAt(a2)).intValue();
                    if (this.createdDialogMainThreadIds.contains(Long.valueOf(currentDialog2.id))) {
                        getNotificationCenter().postNotificationName(NotificationCenter.updateMentionsCount, Long.valueOf(currentDialog2.id), Integer.valueOf(currentDialog2.unread_mentions_count));
                    }
                }
            }
        }
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 256);
        if (dialogsToUpdate != null) {
            getNotificationsController().processDialogsUpdateRead(dialogsToUpdate);
        }
    }

    protected void checkLastDialogMessage(final TLRPC.Dialog dialog, TLRPC.InputPeer peer, long taskId) {
        long newTaskId;
        final int lower_id = (int) dialog.id;
        if (lower_id == 0 || this.checkingLastMessagesDialogs.indexOfKey(lower_id) >= 0) {
            return;
        }
        TLRPC.TL_messages_getHistory req = new TLRPC.TL_messages_getHistory();
        req.peer = peer == null ? getInputPeer(lower_id) : peer;
        if (req.peer == null) {
            return;
        }
        req.limit = 1;
        this.checkingLastMessagesDialogs.put(lower_id, true);
        if (taskId == 0) {
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(req.peer.getObjectSize() + 60);
                data.writeInt32(14);
                data.writeInt64(dialog.id);
                data.writeInt32(dialog.top_message);
                data.writeInt32(dialog.read_inbox_max_id);
                data.writeInt32(dialog.read_outbox_max_id);
                data.writeInt32(dialog.unread_count);
                data.writeInt32(dialog.last_message_date);
                data.writeInt32(dialog.pts);
                data.writeInt32(dialog.flags);
                data.writeBool(dialog.pinned);
                data.writeInt32(dialog.pinnedNum);
                data.writeInt32(dialog.unread_mentions_count);
                data.writeBool(dialog.unread_mark);
                data.writeInt32(dialog.folder_id);
                peer.serializeToStream(data);
            } catch (Exception e) {
                FileLog.e(e);
            }
            long newTaskId2 = getMessagesStorage().createPendingTask(data);
            newTaskId = newTaskId2;
        } else {
            newTaskId = taskId;
        }
        final long j = newTaskId;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ZcMXm3Bj3oFAjpgTYi1SK05zTD8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkLastDialogMessage$153$MessagesController(lower_id, dialog, j, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$checkLastDialogMessage$153$MessagesController(final int lower_id, final TLRPC.Dialog dialog, long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            removeDeletedMessagesFromArray(lower_id, res.messages);
            if (res.messages.isEmpty()) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$I2jNnoX0pyktBbJy89XeOEeo1KY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$151$MessagesController(dialog);
                    }
                });
            } else {
                TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
                TLRPC.Message newMessage = res.messages.get(0);
                TLRPC.Dialog newDialog = new TLRPC.TL_dialog();
                newDialog.flags = dialog.flags;
                newDialog.top_message = newMessage.id;
                newDialog.last_message_date = newMessage.date;
                newDialog.notify_settings = dialog.notify_settings;
                newDialog.pts = dialog.pts;
                newDialog.unread_count = dialog.unread_count;
                newDialog.unread_mark = dialog.unread_mark;
                newDialog.unread_mentions_count = dialog.unread_mentions_count;
                newDialog.read_inbox_max_id = dialog.read_inbox_max_id;
                newDialog.read_outbox_max_id = dialog.read_outbox_max_id;
                newDialog.pinned = dialog.pinned;
                newDialog.pinnedNum = dialog.pinnedNum;
                newDialog.folder_id = dialog.folder_id;
                long j = dialog.id;
                newDialog.id = j;
                newMessage.dialog_id = j;
                dialogs.users.addAll(res.users);
                dialogs.chats.addAll(res.chats);
                dialogs.dialogs.add(newDialog);
                dialogs.messages.addAll(res.messages);
                dialogs.count = 1;
                processDialogsUpdate(dialogs, null);
                getMessagesStorage().putMessages(res.messages, true, true, false, getDownloadController().getAutodownloadMask(), true);
            }
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$azlAJbJ9IaGtx7uuOP_jlO2-6jw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$152$MessagesController(lower_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$151$MessagesController(TLRPC.Dialog dialog) {
        TLRPC.Dialog currentDialog = this.dialogs_dict.get(dialog.id);
        if (currentDialog != null && currentDialog.top_message == 0) {
            deleteDialog(dialog.id, 3);
        }
    }

    public /* synthetic */ void lambda$null$152$MessagesController(int lower_id) {
        this.checkingLastMessagesDialogs.delete(lower_id);
    }

    public void processDialogsUpdate(final TLRPC.messages_Dialogs dialogsRes, ArrayList<TLRPC.EncryptedChat> encChats) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$DyTJRCD5wbNpzHsmuTOWafftss0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processDialogsUpdate$155$MessagesController(dialogsRes);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0114  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$processDialogsUpdate$155$MessagesController(final im.uwrkaxlmjj.tgnet.TLRPC.messages_Dialogs r17) {
        /*
            Method dump skipped, instruction units count: 430
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.lambda$processDialogsUpdate$155$MessagesController(im.uwrkaxlmjj.tgnet.TLRPC$messages_Dialogs):void");
    }

    public /* synthetic */ void lambda$null$154$MessagesController(TLRPC.messages_Dialogs dialogsRes, LongSparseArray new_dialogs_dict, LongSparseArray new_dialogMessage, LongSparseArray dialogsToUpdate) {
        TLRPC.Dialog value;
        int i = 1;
        putUsers(dialogsRes.users, true);
        putChats(dialogsRes.chats, true);
        int a = 0;
        while (a < new_dialogs_dict.size()) {
            long key = new_dialogs_dict.keyAt(a);
            TLRPC.Dialog value2 = (TLRPC.Dialog) new_dialogs_dict.valueAt(a);
            TLRPC.Dialog currentDialog = this.dialogs_dict.get(key);
            if (currentDialog == null) {
                int offset = this.nextDialogsCacheOffset.get(value2.folder_id, 0) + i;
                this.nextDialogsCacheOffset.put(value2.folder_id, offset);
                this.dialogs_dict.put(key, value2);
                MessageObject messageObject = (MessageObject) new_dialogMessage.get(value2.id);
                this.dialogMessage.put(key, messageObject);
                if (messageObject != null && messageObject.messageOwner.to_id.channel_id == 0) {
                    this.dialogMessagesByIds.put(messageObject.getId(), messageObject);
                    if (messageObject.messageOwner.random_id != 0) {
                        this.dialogMessagesByRandomIds.put(messageObject.messageOwner.random_id, messageObject);
                    }
                }
            } else {
                currentDialog.unread_count = value2.unread_count;
                if (currentDialog.unread_mentions_count == value2.unread_mentions_count) {
                    value = value2;
                } else {
                    currentDialog.unread_mentions_count = value2.unread_mentions_count;
                    if (!this.createdDialogMainThreadIds.contains(Long.valueOf(currentDialog.id))) {
                        value = value2;
                    } else {
                        value = value2;
                        getNotificationCenter().postNotificationName(NotificationCenter.updateMentionsCount, Long.valueOf(currentDialog.id), Integer.valueOf(currentDialog.unread_mentions_count));
                    }
                }
                MessageObject oldMsg = this.dialogMessage.get(key);
                if (oldMsg == null || currentDialog.top_message > 0) {
                    TLRPC.Dialog value3 = value;
                    if ((oldMsg != null && oldMsg.deleted) || value3.top_message > currentDialog.top_message) {
                        this.dialogs_dict.put(key, value3);
                        MessageObject messageObject2 = (MessageObject) new_dialogMessage.get(value3.id);
                        this.dialogMessage.put(key, messageObject2);
                        if (messageObject2 != null && messageObject2.messageOwner.to_id.channel_id == 0) {
                            this.dialogMessagesByIds.put(messageObject2.getId(), messageObject2);
                            if (messageObject2.messageOwner.random_id != 0) {
                                this.dialogMessagesByRandomIds.put(messageObject2.messageOwner.random_id, messageObject2);
                            }
                        }
                        if (oldMsg != null) {
                            this.dialogMessagesByIds.remove(oldMsg.getId());
                            if (oldMsg.messageOwner.random_id != 0) {
                                this.dialogMessagesByRandomIds.remove(oldMsg.messageOwner.random_id);
                            }
                        }
                        if (messageObject2 == null) {
                            checkLastDialogMessage(value3, null, 0L);
                        }
                    }
                } else {
                    TLRPC.Dialog value4 = value;
                    MessageObject newMsg = (MessageObject) new_dialogMessage.get(value4.id);
                    if (oldMsg.deleted || newMsg == null || newMsg.messageOwner.date > oldMsg.messageOwner.date) {
                        this.dialogs_dict.put(key, value4);
                        this.dialogMessage.put(key, newMsg);
                        if (newMsg != null && newMsg.messageOwner.to_id.channel_id == 0) {
                            this.dialogMessagesByIds.put(newMsg.getId(), newMsg);
                            if (newMsg.messageOwner.random_id != 0) {
                                this.dialogMessagesByRandomIds.put(newMsg.messageOwner.random_id, newMsg);
                            }
                        }
                        this.dialogMessagesByIds.remove(oldMsg.getId());
                        if (oldMsg.messageOwner.random_id != 0) {
                            this.dialogMessagesByRandomIds.remove(oldMsg.messageOwner.random_id);
                        }
                    }
                }
            }
            a++;
            i = 1;
        }
        this.allDialogs.clear();
        int size = this.dialogs_dict.size();
        for (int a2 = 0; a2 < size; a2++) {
            this.allDialogs.add(this.dialogs_dict.valueAt(a2));
        }
        sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        getNotificationsController().processDialogsUpdateRead(dialogsToUpdate);
    }

    public void addToViewsQueue(final MessageObject messageObject) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$qx3MFpwb5t4-hVLH3faB0_Owr7U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$addToViewsQueue$156$MessagesController(messageObject);
            }
        });
    }

    public /* synthetic */ void lambda$addToViewsQueue$156$MessagesController(MessageObject messageObject) {
        int peer = (int) messageObject.getDialogId();
        int id = messageObject.getId();
        ArrayList<Integer> ids = this.channelViewsToSend.get(peer);
        if (ids == null) {
            ids = new ArrayList<>();
            this.channelViewsToSend.put(peer, ids);
        }
        if (!ids.contains(Integer.valueOf(id))) {
            ids.add(Integer.valueOf(id));
        }
    }

    public void addToPollsQueue(long dialogId, ArrayList<MessageObject> visibleObjects) {
        SparseArray<MessageObject> array = this.pollsToCheck.get(dialogId);
        if (array == null) {
            array = new SparseArray<>();
            this.pollsToCheck.put(dialogId, array);
            this.pollsToCheckSize++;
        }
        int N = array.size();
        for (int a = 0; a < N; a++) {
            array.valueAt(a).pollVisibleOnScreen = false;
        }
        int N2 = visibleObjects.size();
        for (int a2 = 0; a2 < N2; a2++) {
            MessageObject messageObject = visibleObjects.get(a2);
            if (messageObject.type == 17) {
                int id = messageObject.getId();
                MessageObject object = array.get(id);
                if (object != null) {
                    object.pollVisibleOnScreen = true;
                } else {
                    array.put(id, messageObject);
                }
            }
        }
    }

    public void markMessageContentAsRead(MessageObject messageObject) {
        if (messageObject.scheduled) {
            return;
        }
        ArrayList<Long> arrayList = new ArrayList<>();
        long messageId = messageObject.getId();
        if (messageObject.messageOwner.to_id.channel_id != 0) {
            messageId |= ((long) messageObject.messageOwner.to_id.channel_id) << 32;
        }
        if (messageObject.messageOwner.mentioned) {
            getMessagesStorage().markMentionMessageAsRead(messageObject.getId(), messageObject.messageOwner.to_id.channel_id, messageObject.getDialogId());
        }
        arrayList.add(Long.valueOf(messageId));
        getMessagesStorage().markMessagesContentAsRead(arrayList, 0);
        getNotificationCenter().postNotificationName(NotificationCenter.messagesReadContent, arrayList);
        if (messageObject.getId() < 0) {
            markMessageAsRead(messageObject.getDialogId(), messageObject.messageOwner.random_id, Integer.MIN_VALUE);
            return;
        }
        if (messageObject.messageOwner.to_id.channel_id != 0) {
            TLRPC.TL_channels_readMessageContents req = new TLRPC.TL_channels_readMessageContents();
            req.channel = getInputChannel(messageObject.messageOwner.to_id.channel_id);
            if (req.channel == null) {
                return;
            }
            req.id.add(Integer.valueOf(messageObject.getId()));
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$avLHvPSueCJP5cgQdpqleuXuRuU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$markMessageContentAsRead$157(tLObject, tL_error);
                }
            });
            return;
        }
        TLRPC.TL_messages_readMessageContents req2 = new TLRPC.TL_messages_readMessageContents();
        req2.id.add(Integer.valueOf(messageObject.getId()));
        getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$A4uiVPa_Otgham0o45__7SRs0CM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$markMessageContentAsRead$158$MessagesController(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$markMessageContentAsRead$157(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ void lambda$markMessageContentAsRead$158$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_affectedMessages res = (TLRPC.TL_messages_affectedMessages) response;
            processNewDifferenceParams(-1, res.pts, -1, res.pts_count);
        }
    }

    public void markMentionMessageAsRead(int mid, int channelId, long did) {
        getMessagesStorage().markMentionMessageAsRead(mid, channelId, did);
        if (channelId != 0) {
            TLRPC.TL_channels_readMessageContents req = new TLRPC.TL_channels_readMessageContents();
            req.channel = getInputChannel(channelId);
            if (req.channel == null) {
                return;
            }
            req.id.add(Integer.valueOf(mid));
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$FzZvSnPSudLpNrS4of8Af0RJLZU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$markMentionMessageAsRead$159(tLObject, tL_error);
                }
            });
            return;
        }
        TLRPC.TL_messages_readMessageContents req2 = new TLRPC.TL_messages_readMessageContents();
        req2.id.add(Integer.valueOf(mid));
        getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$JuA5HGWhfkW_iL0dbRAfTzNET0U
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$markMentionMessageAsRead$160$MessagesController(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$markMentionMessageAsRead$159(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ void lambda$markMentionMessageAsRead$160$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_affectedMessages res = (TLRPC.TL_messages_affectedMessages) response;
            processNewDifferenceParams(-1, res.pts, -1, res.pts_count);
        }
    }

    public void markMessageAsRead(int mid, int channelId, TLRPC.InputChannel inputChannel, int ttl, long taskId) {
        TLRPC.InputChannel inputChannel2;
        final long newTaskId;
        if (mid == 0 || ttl <= 0) {
            return;
        }
        if (channelId != 0 && inputChannel == null) {
            TLRPC.InputChannel inputChannel3 = getInputChannel(channelId);
            if (inputChannel3 != null) {
                inputChannel2 = inputChannel3;
            } else {
                return;
            }
        } else {
            inputChannel2 = inputChannel;
        }
        if (taskId == 0) {
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(16 + (inputChannel2 != null ? inputChannel2.getObjectSize() : 0));
                data.writeInt32(11);
                data.writeInt32(mid);
                data.writeInt32(channelId);
                data.writeInt32(ttl);
                if (channelId != 0) {
                    inputChannel2.serializeToStream(data);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            long newTaskId2 = getMessagesStorage().createPendingTask(data);
            newTaskId = newTaskId2;
        } else {
            newTaskId = taskId;
        }
        int time = getConnectionsManager().getCurrentTime();
        getMessagesStorage().createTaskForMid(mid, channelId, time, time, ttl, false);
        if (channelId != 0) {
            TLRPC.TL_channels_readMessageContents req = new TLRPC.TL_channels_readMessageContents();
            req.channel = inputChannel2;
            req.id.add(Integer.valueOf(mid));
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$F-FC1D6cqlHN41dL_28NjHJOoRI
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$markMessageAsRead$161$MessagesController(newTaskId, tLObject, tL_error);
                }
            });
            return;
        }
        TLRPC.TL_messages_readMessageContents req2 = new TLRPC.TL_messages_readMessageContents();
        req2.id.add(Integer.valueOf(mid));
        getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$CLY4Y63r6cKhVIkOD9KxYcyRVQs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$markMessageAsRead$162$MessagesController(newTaskId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$markMessageAsRead$161$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public /* synthetic */ void lambda$markMessageAsRead$162$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_affectedMessages res = (TLRPC.TL_messages_affectedMessages) response;
            processNewDifferenceParams(-1, res.pts, -1, res.pts_count);
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public void markMessageAsRead(long dialog_id, long random_id, int ttl) {
        TLRPC.EncryptedChat chat;
        if (random_id == 0 || dialog_id == 0) {
            return;
        }
        if (ttl <= 0 && ttl != Integer.MIN_VALUE) {
            return;
        }
        int lower_part = (int) dialog_id;
        int high_id = (int) (dialog_id >> 32);
        if (lower_part != 0 || (chat = getEncryptedChat(Integer.valueOf(high_id))) == null) {
            return;
        }
        ArrayList<Long> random_ids = new ArrayList<>();
        random_ids.add(Long.valueOf(random_id));
        getSecretChatHelper().sendMessagesReadMessage(chat, random_ids, null);
        if (ttl > 0) {
            int time = getConnectionsManager().getCurrentTime();
            getMessagesStorage().createTaskForSecretChat(chat.id, time, time, 0, random_ids);
        }
    }

    private void completeReadTask(ReadTask readTask) {
        TLObject tLObject;
        int i = (int) readTask.dialogId;
        int i2 = (int) (readTask.dialogId >> 32);
        if (i != 0) {
            TLRPC.InputPeer inputPeer = getInputPeer(i);
            if (inputPeer instanceof TLRPC.TL_inputPeerChannel) {
                TLRPC.TL_channels_readHistory tL_channels_readHistory = new TLRPC.TL_channels_readHistory();
                tL_channels_readHistory.channel = getInputChannel(-i);
                tL_channels_readHistory.max_id = readTask.maxId;
                tLObject = tL_channels_readHistory;
            } else {
                TLRPC.TL_messages_readHistory tL_messages_readHistory = new TLRPC.TL_messages_readHistory();
                tL_messages_readHistory.peer = inputPeer;
                tL_messages_readHistory.max_id = readTask.maxId;
                tLObject = tL_messages_readHistory;
            }
            getConnectionsManager().sendRequest(tLObject, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$_pRN6Cbh2uEBR4PiNkBVknj7zZM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$completeReadTask$163$MessagesController(tLObject2, tL_error);
                }
            });
            return;
        }
        TLRPC.EncryptedChat encryptedChat = getEncryptedChat(Integer.valueOf(i2));
        if (encryptedChat.auth_key != null && encryptedChat.auth_key.length > 1 && (encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            TLRPC.TL_messages_readEncryptedHistory tL_messages_readEncryptedHistory = new TLRPC.TL_messages_readEncryptedHistory();
            tL_messages_readEncryptedHistory.peer = new TLRPC.TL_inputEncryptedChat();
            tL_messages_readEncryptedHistory.peer.chat_id = encryptedChat.id;
            tL_messages_readEncryptedHistory.peer.access_hash = encryptedChat.access_hash;
            tL_messages_readEncryptedHistory.max_date = readTask.maxDate;
            getConnectionsManager().sendRequest(tL_messages_readEncryptedHistory, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$OhSSSQkey4rvTT3S85wCBHebNTc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$completeReadTask$164(tLObject2, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$completeReadTask$163$MessagesController(TLObject response, TLRPC.TL_error error) {
        if (error == null && (response instanceof TLRPC.TL_messages_affectedMessages)) {
            TLRPC.TL_messages_affectedMessages res = (TLRPC.TL_messages_affectedMessages) response;
            processNewDifferenceParams(-1, res.pts, -1, res.pts_count);
        }
    }

    static /* synthetic */ void lambda$completeReadTask$164(TLObject response, TLRPC.TL_error error) {
    }

    private void checkReadTasks() {
        long time = SystemClock.elapsedRealtime();
        int a = 0;
        int size = this.readTasks.size();
        while (a < size) {
            ReadTask task = this.readTasks.get(a);
            if (task.sendRequestTime <= time) {
                completeReadTask(task);
                this.readTasks.remove(a);
                this.readTasksMap.remove(task.dialogId);
                a--;
                size--;
            }
            a++;
        }
    }

    public void markDialogAsReadNow(final long dialogId) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$2uKpHBn4wJ_en6seUpPNUl9yfhs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markDialogAsReadNow$165$MessagesController(dialogId);
            }
        });
    }

    public /* synthetic */ void lambda$markDialogAsReadNow$165$MessagesController(long dialogId) {
        ReadTask currentReadTask = this.readTasksMap.get(dialogId);
        if (currentReadTask == null) {
            return;
        }
        completeReadTask(currentReadTask);
        this.readTasks.remove(currentReadTask);
        this.readTasksMap.remove(dialogId);
    }

    public void markMentionsAsRead(long dialogId) {
        if (((int) dialogId) == 0) {
            return;
        }
        getMessagesStorage().resetMentionsCount(dialogId, 0);
        TLRPC.TL_messages_readMentions req = new TLRPC.TL_messages_readMentions();
        req.peer = getInputPeer((int) dialogId);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ztIqYgt7JBs6k9kC9NcT9lczvcY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MessagesController.lambda$markMentionsAsRead$166(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$markMentionsAsRead$166(TLObject response, TLRPC.TL_error error) {
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x00b6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void markDialogAsRead(final long r26, final int r28, final int r29, final int r30, final boolean r31, final int r32, final boolean r33, int r34) {
        /*
            Method dump skipped, instruction units count: 309
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.markDialogAsRead(long, int, int, int, boolean, int, boolean, int):void");
    }

    public /* synthetic */ void lambda$markDialogAsRead$168$MessagesController(final long dialogId, final int countDiff, final int maxPositiveId, final boolean countMessages, final boolean popup) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$GknpVTpsJEFiyBj_aYhKRP5nk0I
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$167$MessagesController(dialogId, countDiff, maxPositiveId, countMessages, popup);
            }
        });
    }

    public /* synthetic */ void lambda$null$167$MessagesController(long dialogId, int countDiff, int maxPositiveId, boolean countMessages, boolean popup) {
        TLRPC.Dialog folder;
        TLRPC.Dialog dialog = this.dialogs_dict.get(dialogId);
        if (dialog != null) {
            int prevCount = dialog.unread_count;
            if (countDiff != 0 && maxPositiveId < dialog.top_message) {
                dialog.unread_count = Math.max(dialog.unread_count - countDiff, 0);
                if (maxPositiveId != Integer.MIN_VALUE && dialog.unread_count > dialog.top_message - maxPositiveId) {
                    dialog.unread_count = dialog.top_message - maxPositiveId;
                }
            } else {
                dialog.unread_count = 0;
            }
            if (dialog.folder_id != 0 && (folder = this.dialogs_dict.get(DialogObject.makeFolderDialogId(dialog.folder_id))) != null) {
                if (countMessages) {
                    if (isDialogMuted(dialog.id)) {
                        folder.unread_count -= prevCount - dialog.unread_count;
                    } else {
                        folder.unread_mentions_count -= prevCount - dialog.unread_count;
                    }
                } else if (dialog.unread_count == 0) {
                    if (isDialogMuted(dialog.id)) {
                        folder.unread_count--;
                    } else {
                        folder.unread_mentions_count--;
                    }
                }
            }
            if ((prevCount != 0 || dialog.unread_mark) && dialog.unread_count == 0 && !isDialogMuted(dialogId)) {
                this.unreadUnmutedDialogs--;
            }
            if (dialog.unread_mark) {
                dialog.unread_mark = false;
                getMessagesStorage().setDialogUnread(dialog.id, false);
            }
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 256);
        }
        if (!popup) {
            getNotificationsController().processReadMessages(null, dialogId, 0, maxPositiveId, false);
            LongSparseArray<Integer> dialogsToUpdate = new LongSparseArray<>(1);
            dialogsToUpdate.put(dialogId, 0);
            getNotificationsController().processDialogsUpdateRead(dialogsToUpdate);
            return;
        }
        getNotificationsController().processReadMessages(null, dialogId, 0, maxPositiveId, true);
        LongSparseArray<Integer> dialogsToUpdate2 = new LongSparseArray<>(1);
        dialogsToUpdate2.put(dialogId, -1);
        getNotificationsController().processDialogsUpdateRead(dialogsToUpdate2);
    }

    public /* synthetic */ void lambda$markDialogAsRead$170$MessagesController(final long dialogId, final int maxDate, final boolean popup, final int countDiff, final int maxNegativeId, final boolean countMessages) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$rl6GEZKw_pntmB17B4WIvWQwKrI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$169$MessagesController(dialogId, maxDate, popup, countDiff, maxNegativeId, countMessages);
            }
        });
    }

    public /* synthetic */ void lambda$null$169$MessagesController(long dialogId, int maxDate, boolean popup, int countDiff, int maxNegativeId, boolean countMessages) {
        TLRPC.Dialog folder;
        getNotificationsController().processReadMessages(null, dialogId, maxDate, 0, popup);
        TLRPC.Dialog dialog = this.dialogs_dict.get(dialogId);
        if (dialog != null) {
            int prevCount = dialog.unread_count;
            if (countDiff == 0 || maxNegativeId <= dialog.top_message) {
                dialog.unread_count = 0;
            } else {
                dialog.unread_count = Math.max(dialog.unread_count - countDiff, 0);
                if (maxNegativeId != Integer.MAX_VALUE && dialog.unread_count > maxNegativeId - dialog.top_message) {
                    dialog.unread_count = maxNegativeId - dialog.top_message;
                }
            }
            if (dialog.folder_id != 0 && (folder = this.dialogs_dict.get(DialogObject.makeFolderDialogId(dialog.folder_id))) != null) {
                if (countMessages) {
                    if (isDialogMuted(dialog.id)) {
                        folder.unread_count -= prevCount - dialog.unread_count;
                    } else {
                        folder.unread_mentions_count -= prevCount - dialog.unread_count;
                    }
                } else if (dialog.unread_count == 0) {
                    if (isDialogMuted(dialog.id)) {
                        folder.unread_count--;
                    } else {
                        folder.unread_mentions_count--;
                    }
                }
            }
            if ((prevCount != 0 || dialog.unread_mark) && dialog.unread_count == 0 && !isDialogMuted(dialogId)) {
                this.unreadUnmutedDialogs--;
            }
            if (dialog.unread_mark) {
                dialog.unread_mark = false;
                getMessagesStorage().setDialogUnread(dialog.id, false);
            }
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 256);
        }
        LongSparseArray<Integer> dialogsToUpdate = new LongSparseArray<>(1);
        dialogsToUpdate.put(dialogId, 0);
        getNotificationsController().processDialogsUpdateRead(dialogsToUpdate);
    }

    public /* synthetic */ void lambda$markDialogAsRead$171$MessagesController(long dialogId, boolean readNow, int maxDate, int maxPositiveId) {
        ReadTask currentReadTask = this.readTasksMap.get(dialogId);
        if (currentReadTask == null) {
            currentReadTask = new ReadTask();
            currentReadTask.dialogId = dialogId;
            currentReadTask.sendRequestTime = SystemClock.elapsedRealtime() + DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS;
            if (!readNow) {
                this.readTasksMap.put(dialogId, currentReadTask);
                this.readTasks.add(currentReadTask);
            }
        }
        currentReadTask.maxDate = maxDate;
        currentReadTask.maxId = maxPositiveId;
        if (readNow) {
            completeReadTask(currentReadTask);
        }
    }

    public int createChat(String title, ArrayList<Integer> selectedContacts, String about, int type, final BaseFragment fragment) {
        if (type != 0) {
            if (type == 2 || type == 4) {
                final TLRPC.TL_channels_createChannel req = new TLRPC.TL_channels_createChannel();
                req.title = title;
                req.about = about != null ? about : "";
                if (type == 4) {
                    req.megagroup = true;
                } else {
                    req.broadcast = true;
                }
                return getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$jRIDGuZL_POkHlOGZ0xTm0J3Avw
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                        this.f$0.lambda$createChat$177$MessagesController(fragment, req, tLObject, tL_error);
                    }
                }, 2);
            }
            return 0;
        }
        final TLRPC.TL_messages_createChat req2 = new TLRPC.TL_messages_createChat();
        req2.title = title;
        for (int a = 0; a < selectedContacts.size(); a++) {
            TLRPC.User user = getUser(selectedContacts.get(a));
            if (user != null) {
                req2.users.add(getInputUser(user));
            }
        }
        return getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HOeLi8-Dh0gPV53yoHk_wnyHzvg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$createChat$174$MessagesController(fragment, req2, tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$createChat$174$MessagesController(final BaseFragment fragment, final TLRPC.TL_messages_createChat req, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$z9M3eMhfhOxdaIc6GFbtqpqi8CQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$172$MessagesController(error, fragment, req);
                }
            });
            return;
        }
        final TLRPC.Updates updates = (TLRPC.Updates) response;
        processUpdates(updates, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kqKZ1IlYpjuTkNMdmeS9JZYAFQM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$173$MessagesController(updates);
            }
        });
    }

    public /* synthetic */ void lambda$null$172$MessagesController(TLRPC.TL_error error, BaseFragment fragment, TLRPC.TL_messages_createChat req) {
        AlertsCreator.processError(this.currentAccount, error, fragment, req, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.chatDidFailCreate, new Object[0]);
    }

    public /* synthetic */ void lambda$null$173$MessagesController(TLRPC.Updates updates) {
        putUsers(updates.users, false);
        putChats(updates.chats, false);
        if (updates.chats != null && !updates.chats.isEmpty()) {
            getNotificationCenter().postNotificationName(NotificationCenter.chatDidCreated, Integer.valueOf(updates.chats.get(0).id));
        } else {
            getNotificationCenter().postNotificationName(NotificationCenter.chatDidFailCreate, new Object[0]);
        }
    }

    public /* synthetic */ void lambda$createChat$177$MessagesController(final BaseFragment fragment, final TLRPC.TL_channels_createChannel req, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$gkFqjC31WnY_O35gXqULHQ3sZeA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$175$MessagesController(error, fragment, req);
                }
            });
            return;
        }
        final TLRPC.Updates updates = (TLRPC.Updates) response;
        processUpdates(updates, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$VqrDy0E3zpilW-BYBNCGGvWYEPU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$176$MessagesController(updates);
            }
        });
    }

    public /* synthetic */ void lambda$null$175$MessagesController(TLRPC.TL_error error, BaseFragment fragment, TLRPC.TL_channels_createChannel req) {
        AlertsCreator.processError(this.currentAccount, error, fragment, req, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.chatDidFailCreate, new Object[0]);
    }

    public /* synthetic */ void lambda$null$176$MessagesController(TLRPC.Updates updates) {
        putUsers(updates.users, false);
        putChats(updates.chats, false);
        if (updates.chats != null && !updates.chats.isEmpty()) {
            getNotificationCenter().postNotificationName(NotificationCenter.chatDidCreated, Integer.valueOf(updates.chats.get(0).id));
        } else {
            getNotificationCenter().postNotificationName(NotificationCenter.chatDidFailCreate, new Object[0]);
        }
    }

    public int createMegaGroup(String title, final ArrayList<Integer> selectedContacts, String about, int type, final BaseFragment fragment, boolean forbidContact) {
        if (type == 2 || type == 4) {
            final TLRPCChats.TL_channels_createChannel_v1 req = new TLRPCChats.TL_channels_createChannel_v1();
            req.title = title;
            req.about = about != null ? about : "";
            req.ban_add_contact = forbidContact;
            if (type == 4) {
                req.megagroup = true;
            } else {
                req.broadcast = true;
            }
            return getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$-kJpXd1BONCkzMYm9WB0g88HI48
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                    this.f$0.lambda$createMegaGroup$180$MessagesController(fragment, req, selectedContacts, tLObject, tL_error);
                }
            }, 2);
        }
        return 0;
    }

    public /* synthetic */ void lambda$createMegaGroup$180$MessagesController(final BaseFragment fragment, final TLRPCChats.TL_channels_createChannel_v1 req, ArrayList selectedContacts, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$nuov5ueDOqB7Knm8X-OwnSHik0I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$178$MessagesController(error, fragment, req);
                }
            });
            return;
        }
        final TLRPC.Updates updates = (TLRPC.Updates) response;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$d7s4gFjxkGUTJa-TcIXmSv1Qvt0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$179$MessagesController(updates);
            }
        });
        ArrayList<TLRPC.InputUser> result = new ArrayList<>();
        for (int a = 0; a < selectedContacts.size(); a++) {
            TLRPC.InputUser user = getInstance(this.currentAccount).getInputUser(getInstance(this.currentAccount).getUser((Integer) selectedContacts.get(a)));
            if (user != null) {
                result.add(user);
            }
        }
        int a2 = this.currentAccount;
        getInstance(a2).addUsersToChannelWithCreate(updates.chats.get(0), result, null);
        processUpdates(updates, false);
    }

    public /* synthetic */ void lambda$null$178$MessagesController(TLRPC.TL_error error, BaseFragment fragment, TLRPCChats.TL_channels_createChannel_v1 req) {
        AlertsCreator.processError(this.currentAccount, error, fragment, req, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.chatDidFailCreate, new Object[0]);
    }

    public /* synthetic */ void lambda$null$179$MessagesController(TLRPC.Updates updates) {
        putUsers(updates.users, false);
        putChats(updates.chats, false);
        if (updates.chats != null && !updates.chats.isEmpty()) {
            getNotificationCenter().postNotificationName(NotificationCenter.chatDidCreated, Integer.valueOf(updates.chats.get(0).id));
        } else {
            getNotificationCenter().postNotificationName(NotificationCenter.chatDidFailCreate, new Object[0]);
        }
    }

    public void addUsersToChannelWithCreate(TLRPC.Chat chat, ArrayList<TLRPC.InputUser> users, final BaseFragment fragment) {
        if (users == null || users.isEmpty()) {
            return;
        }
        final TLRPC.TL_channels_inviteToChannel req = new TLRPC.TL_channels_inviteToChannel();
        req.channel = getInputChannel(chat);
        req.users = users;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$0D5Lb6S-PNOuDCD_iUg28PyE3wc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$addUsersToChannelWithCreate$182$MessagesController(fragment, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$addUsersToChannelWithCreate$182$MessagesController(final BaseFragment fragment, final TLRPC.TL_channels_inviteToChannel req, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$TSRwT0nT58HJxPxbFtXQLeNrs4A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$181$MessagesController(error, fragment, req);
                }
            });
        } else {
            processUpdates((TLRPC.Updates) response, false);
        }
    }

    public /* synthetic */ void lambda$null$181$MessagesController(TLRPC.TL_error error, BaseFragment fragment, TLRPC.TL_channels_inviteToChannel req) {
        AlertsCreator.processError(this.currentAccount, error, fragment, req, true);
    }

    public void convertToMegaGroup(final Context context, int chat_id, final BaseFragment fragment, final MessagesStorage.IntCallback convertRunnable) {
        final TLRPC.TL_messages_migrateChat req = new TLRPC.TL_messages_migrateChat();
        req.chat_id = chat_id;
        final AlertDialog progressDialog = new AlertDialog(context, 3);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Nd6p_ql5bBsUj5fNp5QNYNldNvY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$convertToMegaGroup$186$MessagesController(context, progressDialog, convertRunnable, fragment, req, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$KhGaN8Vfeu1BcZzdzmm_u3ANyOw
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$convertToMegaGroup$187$MessagesController(reqId, dialogInterface);
            }
        });
        try {
            progressDialog.show();
        } catch (Exception e) {
        }
    }

    public /* synthetic */ void lambda$convertToMegaGroup$186$MessagesController(final Context context, final AlertDialog progressDialog, final MessagesStorage.IntCallback convertRunnable, final BaseFragment fragment, final TLRPC.TL_messages_migrateChat req, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$oI4NVPHvNzoQPoN0DlVywZoH5oQ
                @Override // java.lang.Runnable
                public final void run() {
                    MessagesController.lambda$null$183(context, progressDialog);
                }
            });
            final TLRPC.Updates updates = (TLRPC.Updates) response;
            processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$4SzFObcfMQY6C-QQg82hsB0Lz8E
                @Override // java.lang.Runnable
                public final void run() {
                    MessagesController.lambda$null$184(convertRunnable, updates);
                }
            });
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$lMRe2rIJm9ERt6CxTYfQqyOk9EI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$185$MessagesController(convertRunnable, context, progressDialog, error, fragment, req);
            }
        });
    }

    static /* synthetic */ void lambda$null$183(Context context, AlertDialog progressDialog) {
        if (!((Activity) context).isFinishing()) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    static /* synthetic */ void lambda$null$184(MessagesStorage.IntCallback convertRunnable, TLRPC.Updates updates) {
        if (convertRunnable != null) {
            for (int a = 0; a < updates.chats.size(); a++) {
                TLRPC.Chat chat = updates.chats.get(a);
                if (ChatObject.isChannel(chat)) {
                    convertRunnable.run(chat.id);
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$185$MessagesController(MessagesStorage.IntCallback convertRunnable, Context context, AlertDialog progressDialog, TLRPC.TL_error error, BaseFragment fragment, TLRPC.TL_messages_migrateChat req) {
        if (convertRunnable != null) {
            convertRunnable.run(0);
        }
        if (!((Activity) context).isFinishing()) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            AlertsCreator.processError(this.currentAccount, error, fragment, req, false);
        }
    }

    public /* synthetic */ void lambda$convertToMegaGroup$187$MessagesController(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    public void addUsersToChannel(int chat_id, ArrayList<TLRPC.InputUser> users, final BaseFragment fragment) {
        if (users == null || users.isEmpty()) {
            return;
        }
        final TLRPC.TL_channels_inviteToChannel req = new TLRPC.TL_channels_inviteToChannel();
        req.channel = getInputChannel(chat_id);
        req.users = users;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$d1aCG5azf9iTRoQTDSPWrB35SQw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$addUsersToChannel$189$MessagesController(fragment, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$addUsersToChannel$189$MessagesController(final BaseFragment fragment, final TLRPC.TL_channels_inviteToChannel req, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$O5o_Xy4a31oaIMXs88cROfS84Ig
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$188$MessagesController(error, fragment, req);
                }
            });
        } else {
            processUpdates((TLRPC.Updates) response, false);
        }
    }

    public /* synthetic */ void lambda$null$188$MessagesController(TLRPC.TL_error error, BaseFragment fragment, TLRPC.TL_channels_inviteToChannel req) {
        AlertsCreator.processError(this.currentAccount, error, fragment, req, true);
    }

    public void toogleChannelSignatures(int chat_id, boolean enabled) {
        TLRPC.TL_channels_toggleSignatures req = new TLRPC.TL_channels_toggleSignatures();
        req.channel = getInputChannel(chat_id);
        req.enabled = enabled;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$jDOsKDYGaGFAHz79jsrH6t6w1lw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$toogleChannelSignatures$191$MessagesController(tLObject, tL_error);
            }
        }, 64);
    }

    public /* synthetic */ void lambda$toogleChannelSignatures$191$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (response != null) {
            processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$JQg6OTRwPsF9cNmJsJx_sc7ufUc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$190$MessagesController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$190$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 8192);
    }

    public void toogleChannelInvitesHistory(int chat_id, boolean enabled) {
        TLRPC.TL_channels_togglePreHistoryHidden req = new TLRPC.TL_channels_togglePreHistoryHidden();
        req.channel = getInputChannel(chat_id);
        req.enabled = enabled;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$zAl-qY_hgEXiAOMwnolRl0G1ONU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$toogleChannelInvitesHistory$193$MessagesController(tLObject, tL_error);
            }
        }, 64);
    }

    public /* synthetic */ void lambda$toogleChannelInvitesHistory$193$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (response != null) {
            processUpdates((TLRPC.Updates) response, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$VLWL21ng6Kv5K-0oqvrAMHtVz-M
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$192$MessagesController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$192$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 8192);
    }

    public void updateChatAbout(int chat_id, final String about, final TLRPC.ChatFull info) {
        if (info == null) {
            return;
        }
        TLRPC.TL_messages_editChatAbout req = new TLRPC.TL_messages_editChatAbout();
        req.peer = getInputPeer(-chat_id);
        req.about = about;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$nndA9V2cA_4gy1kLa-t1fXh-dIY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$updateChatAbout$195$MessagesController(info, about, tLObject, tL_error);
            }
        }, 64);
    }

    public /* synthetic */ void lambda$updateChatAbout$195$MessagesController(final TLRPC.ChatFull info, final String about, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_boolTrue) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$QsRAYeh1rXIG17OVI14I4x2eEJ8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$194$MessagesController(info, about);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$194$MessagesController(TLRPC.ChatFull info, String about) {
        info.about = about;
        getMessagesStorage().updateChatInfo(info, false);
        getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, info, 0, false, null);
    }

    public void updateChannelUserName(final int chat_id, final String userName) {
        TLRPC.TL_channels_updateUsername req = new TLRPC.TL_channels_updateUsername();
        req.channel = getInputChannel(chat_id);
        req.username = userName;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$67I-xCB3C6VgO11GenT4XmV8Mk0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$updateChannelUserName$197$MessagesController(chat_id, userName, tLObject, tL_error);
            }
        }, 64);
    }

    public /* synthetic */ void lambda$updateChannelUserName$197$MessagesController(final int chat_id, final String userName, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_boolTrue) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$9c2_Q9-svOaxfWBzw0_yAHSqQaY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$196$MessagesController(chat_id, userName);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$196$MessagesController(int chat_id, String userName) {
        TLRPC.Chat chat = getChat(Integer.valueOf(chat_id));
        if (userName.length() != 0) {
            chat.flags |= 64;
        } else {
            chat.flags &= -65;
        }
        chat.username = userName;
        ArrayList<TLRPC.Chat> arrayList = new ArrayList<>();
        arrayList.add(chat);
        getMessagesStorage().putUsersAndChats(null, arrayList, true, true);
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 8192);
    }

    public void sendBotStart(TLRPC.User user, String botHash) {
        if (user == null) {
            return;
        }
        TLRPC.TL_messages_startBot req = new TLRPC.TL_messages_startBot();
        req.bot = getInputUser(user);
        req.peer = getInputPeer(user.id);
        req.start_param = botHash;
        req.random_id = Utilities.random.nextLong();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$WYHzG5ttEUL0PnsiAiXmh6UASrs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$sendBotStart$198$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$sendBotStart$198$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            return;
        }
        processUpdates((TLRPC.Updates) response, false);
    }

    public boolean isJoiningChannel(int chat_id) {
        return this.joiningToChannels.contains(Integer.valueOf(chat_id));
    }

    public void addUserToChat(final int chat_id, TLRPC.User user, TLRPC.ChatFull info, int count_fwd, String botHash, final BaseFragment fragment, final Runnable onFinishRunnable) {
        final TLObject request;
        if (user == null) {
            return;
        }
        boolean z = false;
        if (chat_id > 0) {
            final boolean isChannel = ChatObject.isChannel(chat_id, this.currentAccount);
            if (isChannel && getChat(Integer.valueOf(chat_id)).megagroup) {
                z = true;
            }
            final boolean isMegagroup = z;
            final TLRPC.InputUser inputUser = getInputUser(user);
            if (botHash == null || (isChannel && !isMegagroup)) {
                if (isChannel) {
                    if (inputUser instanceof TLRPC.TL_inputUserSelf) {
                        if (this.joiningToChannels.contains(Integer.valueOf(chat_id))) {
                            return;
                        }
                        TLRPC.TL_channels_joinChannel req = new TLRPC.TL_channels_joinChannel();
                        req.channel = getInputChannel(chat_id);
                        this.joiningToChannels.add(Integer.valueOf(chat_id));
                        request = req;
                    } else {
                        TLRPC.TL_channels_inviteToChannel req2 = new TLRPC.TL_channels_inviteToChannel();
                        req2.channel = getInputChannel(chat_id);
                        req2.users.add(inputUser);
                        request = req2;
                    }
                } else {
                    TLRPC.TL_messages_addChatUser req3 = new TLRPC.TL_messages_addChatUser();
                    req3.chat_id = chat_id;
                    req3.fwd_limit = count_fwd;
                    req3.user_id = inputUser;
                    request = req3;
                }
            } else {
                TLRPC.TL_messages_startBot req4 = new TLRPC.TL_messages_startBot();
                req4.bot = inputUser;
                if (isChannel) {
                    req4.peer = getInputPeer(-chat_id);
                } else {
                    req4.peer = new TLRPC.TL_inputPeerChat();
                    req4.peer.chat_id = chat_id;
                }
                req4.start_param = botHash;
                req4.random_id = Utilities.random.nextLong();
                request = req4;
            }
            getConnectionsManager().sendRequest(request, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$e1bxzSq7KRi3ndfJ_vKPQQsD8xs
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                    this.f$0.lambda$addUserToChat$202$MessagesController(isChannel, inputUser, chat_id, fragment, request, isMegagroup, onFinishRunnable, tLObject, tL_error);
                }
            });
            return;
        }
        if (info instanceof TLRPC.TL_chatFull) {
            for (int a = 0; a < info.participants.participants.size(); a++) {
                if (info.participants.participants.get(a).user_id == user.id) {
                    return;
                }
            }
            TLRPC.Chat chat = getChat(Integer.valueOf(chat_id));
            chat.participants_count++;
            ArrayList<TLRPC.Chat> chatArrayList = new ArrayList<>();
            chatArrayList.add(chat);
            getMessagesStorage().putUsersAndChats(null, chatArrayList, true, true);
            TLRPC.TL_chatParticipant newPart = new TLRPC.TL_chatParticipant();
            newPart.user_id = user.id;
            newPart.inviter_id = getUserConfig().getClientUserId();
            newPart.date = getConnectionsManager().getCurrentTime();
            info.participants.participants.add(0, newPart);
            getMessagesStorage().updateChatInfo(info, true);
            getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, info, 0, false, null);
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 32);
        }
    }

    public /* synthetic */ void lambda$addUserToChat$202$MessagesController(final boolean isChannel, final TLRPC.InputUser inputUser, final int chat_id, final BaseFragment fragment, final TLObject request, final boolean isMegagroup, Runnable onFinishRunnable, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (isChannel && (inputUser instanceof TLRPC.TL_inputUserSelf)) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ZdsGajV0rpsC-iHhy8GOsHfPDl8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$199$MessagesController(chat_id);
                }
            });
        }
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$PHlKx6WjDDMAkcgZkjRAvdsVUKQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$200$MessagesController(error, fragment, request, isChannel, isMegagroup, inputUser);
                }
            });
            return;
        }
        boolean hasJoinMessage = false;
        TLRPC.Updates updates = (TLRPC.Updates) response;
        int a = 0;
        while (true) {
            if (a >= updates.updates.size()) {
                break;
            }
            TLRPC.Update update = updates.updates.get(a);
            if (!(update instanceof TLRPC.TL_updateNewChannelMessage) || !(((TLRPC.TL_updateNewChannelMessage) update).message.action instanceof TLRPC.TL_messageActionChatAddUser)) {
                a++;
            } else {
                hasJoinMessage = true;
                break;
            }
        }
        processUpdates(updates, false);
        if (isChannel) {
            if (!hasJoinMessage && (inputUser instanceof TLRPC.TL_inputUserSelf)) {
                generateJoinMessage(chat_id, true);
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$6dOJHJzE1WFR7ENSBYxad7dLPNE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$201$MessagesController(chat_id);
                }
            }, 1000L);
        }
        if (isChannel && (inputUser instanceof TLRPC.TL_inputUserSelf)) {
            getMessagesStorage().updateDialogsWithDeletedMessages(new ArrayList<>(), null, true, chat_id);
        }
        if (onFinishRunnable != null) {
            AndroidUtilities.runOnUIThread(onFinishRunnable);
        }
    }

    public /* synthetic */ void lambda$null$199$MessagesController(int chat_id) {
        this.joiningToChannels.remove(Integer.valueOf(chat_id));
    }

    public /* synthetic */ void lambda$null$200$MessagesController(TLRPC.TL_error error, BaseFragment fragment, TLObject request, boolean isChannel, boolean isMegagroup, TLRPC.InputUser inputUser) {
        int i = this.currentAccount;
        Object[] objArr = new Object[1];
        objArr[0] = Boolean.valueOf(isChannel && !isMegagroup);
        AlertsCreator.processError(i, error, fragment, request, objArr);
        if (isChannel && (inputUser instanceof TLRPC.TL_inputUserSelf)) {
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 8192);
        }
    }

    public /* synthetic */ void lambda$null$201$MessagesController(int chat_id) {
        loadFullChat(chat_id, 0, true);
    }

    public void deleteUserFromChat(int chat_id, TLRPC.User user, TLRPC.ChatFull info) {
        deleteUserFromChat(chat_id, user, info, false, false);
    }

    public void deleteUserFromChat(final int i, TLRPC.User user, TLRPC.ChatFull chatFull, boolean z, boolean z2) {
        TLObject tLObject;
        if (user == null) {
            return;
        }
        if (i <= 0) {
            if (chatFull instanceof TLRPC.TL_chatFull) {
                TLRPC.Chat chat = getChat(Integer.valueOf(i));
                chat.participants_count--;
                ArrayList<TLRPC.Chat> arrayList = new ArrayList<>();
                arrayList.add(chat);
                getMessagesStorage().putUsersAndChats(null, arrayList, true, true);
                boolean z3 = false;
                int i2 = 0;
                while (true) {
                    if (i2 >= chatFull.participants.participants.size()) {
                        break;
                    }
                    if (chatFull.participants.participants.get(i2).user_id != user.id) {
                        i2++;
                    } else {
                        chatFull.participants.participants.remove(i2);
                        z3 = true;
                        break;
                    }
                }
                if (z3) {
                    getMessagesStorage().updateChatInfo(chatFull, true);
                    getNotificationCenter().postNotificationName(NotificationCenter.chatInfoDidLoad, chatFull, 0, false, null);
                }
                getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 32);
                return;
            }
            return;
        }
        final TLRPC.InputUser inputUser = getInputUser(user);
        TLRPC.Chat chat2 = getChat(Integer.valueOf(i));
        final boolean zIsChannel = ChatObject.isChannel(chat2);
        if (zIsChannel) {
            if (inputUser instanceof TLRPC.TL_inputUserSelf) {
                if (chat2.creator && z) {
                    TLRPC.TL_channels_deleteChannel tL_channels_deleteChannel = new TLRPC.TL_channels_deleteChannel();
                    tL_channels_deleteChannel.channel = getInputChannel(chat2);
                    tLObject = tL_channels_deleteChannel;
                } else {
                    TLRPC.TL_channels_leaveChannel tL_channels_leaveChannel = new TLRPC.TL_channels_leaveChannel();
                    tL_channels_leaveChannel.channel = getInputChannel(chat2);
                    tLObject = tL_channels_leaveChannel;
                }
            } else {
                TLRPC.TL_channels_editBanned tL_channels_editBanned = new TLRPC.TL_channels_editBanned();
                tL_channels_editBanned.channel = getInputChannel(chat2);
                tL_channels_editBanned.user_id = inputUser;
                tL_channels_editBanned.banned_rights = new TLRPC.TL_chatBannedRights();
                tL_channels_editBanned.banned_rights.view_messages = true;
                tL_channels_editBanned.banned_rights.send_media = true;
                tL_channels_editBanned.banned_rights.send_messages = true;
                tL_channels_editBanned.banned_rights.send_stickers = true;
                tL_channels_editBanned.banned_rights.send_gifs = true;
                tL_channels_editBanned.banned_rights.send_games = true;
                tL_channels_editBanned.banned_rights.send_inline = true;
                tL_channels_editBanned.banned_rights.embed_links = true;
                tL_channels_editBanned.banned_rights.pin_messages = true;
                tL_channels_editBanned.banned_rights.send_polls = true;
                tL_channels_editBanned.banned_rights.invite_users = true;
                tL_channels_editBanned.banned_rights.change_info = true;
                tLObject = tL_channels_editBanned;
            }
        } else {
            TLRPC.TL_messages_deleteChatUser tL_messages_deleteChatUser = new TLRPC.TL_messages_deleteChatUser();
            tL_messages_deleteChatUser.chat_id = i;
            tL_messages_deleteChatUser.user_id = getInputUser(user);
            tLObject = tL_messages_deleteChatUser;
        }
        if (user.id == getUserConfig().getClientUserId()) {
            deleteDialog(-i, 0, z2);
        }
        getConnectionsManager().sendRequest(tLObject, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$jfA0djbSYYr5aQeQj4cvhNyX8-Y
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$deleteUserFromChat$204$MessagesController(zIsChannel, inputUser, i, tLObject2, tL_error);
            }
        }, 64);
    }

    public /* synthetic */ void lambda$deleteUserFromChat$204$MessagesController(boolean isChannel, TLRPC.InputUser inputUser, final int chat_id, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            return;
        }
        TLRPC.Updates updates = (TLRPC.Updates) response;
        processUpdates(updates, false);
        if (isChannel && !(inputUser instanceof TLRPC.TL_inputUserSelf)) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$VYgWYQ9idBPUtiR3U6fEqPTC23E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$203$MessagesController(chat_id);
                }
            }, 1000L);
        }
    }

    public /* synthetic */ void lambda$null$203$MessagesController(int chat_id) {
        loadFullChat(chat_id, 0, true);
    }

    public void changeChatTitle(int i, String str) {
        TLObject tLObject;
        if (i > 0) {
            if (ChatObject.isChannel(i, this.currentAccount)) {
                TLRPC.TL_channels_editTitle tL_channels_editTitle = new TLRPC.TL_channels_editTitle();
                tL_channels_editTitle.channel = getInputChannel(i);
                tL_channels_editTitle.title = str;
                tLObject = tL_channels_editTitle;
            } else {
                TLRPC.TL_messages_editChatTitle tL_messages_editChatTitle = new TLRPC.TL_messages_editChatTitle();
                tL_messages_editChatTitle.chat_id = i;
                tL_messages_editChatTitle.title = str;
                tLObject = tL_messages_editChatTitle;
            }
            getConnectionsManager().sendRequest(tLObject, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$wNdYAHdHgopa7GH6FY8PddtjuNo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) throws Exception {
                    this.f$0.lambda$changeChatTitle$205$MessagesController(tLObject2, tL_error);
                }
            }, 64);
            return;
        }
        TLRPC.Chat chat = getChat(Integer.valueOf(i));
        chat.title = str;
        ArrayList<TLRPC.Chat> arrayList = new ArrayList<>();
        arrayList.add(chat);
        getMessagesStorage().putUsersAndChats(null, arrayList, true, true);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 16);
    }

    public /* synthetic */ void lambda$changeChatTitle$205$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            return;
        }
        processUpdates((TLRPC.Updates) response, false);
    }

    public void changeChatAvatar(int i, TLRPC.InputFile inputFile, final TLRPC.FileLocation fileLocation, final TLRPC.FileLocation fileLocation2) {
        TLObject tLObject;
        if (ChatObject.isChannel(i, this.currentAccount)) {
            TLRPC.TL_channels_editPhoto tL_channels_editPhoto = new TLRPC.TL_channels_editPhoto();
            tL_channels_editPhoto.channel = getInputChannel(i);
            if (inputFile != null) {
                tL_channels_editPhoto.photo = new TLRPC.TL_inputChatUploadedPhoto();
                tL_channels_editPhoto.photo.file = inputFile;
                tLObject = tL_channels_editPhoto;
            } else {
                tL_channels_editPhoto.photo = new TLRPC.TL_inputChatPhotoEmpty();
                tLObject = tL_channels_editPhoto;
            }
        } else {
            TLRPC.TL_messages_editChatPhoto tL_messages_editChatPhoto = new TLRPC.TL_messages_editChatPhoto();
            tL_messages_editChatPhoto.chat_id = i;
            if (inputFile != null) {
                tL_messages_editChatPhoto.photo = new TLRPC.TL_inputChatUploadedPhoto();
                tL_messages_editChatPhoto.photo.file = inputFile;
            } else {
                tL_messages_editChatPhoto.photo = new TLRPC.TL_inputChatPhotoEmpty();
            }
            tLObject = tL_messages_editChatPhoto;
        }
        getConnectionsManager().sendRequest(tLObject, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$mKg0Liq7UxJsdgPo-x5_ZCcM5Us
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$changeChatAvatar$206$MessagesController(fileLocation, fileLocation2, tLObject2, tL_error);
            }
        }, 64);
    }

    public /* synthetic */ void lambda$changeChatAvatar$206$MessagesController(TLRPC.FileLocation smallSize, TLRPC.FileLocation bigSize, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            return;
        }
        TLRPC.Updates updates = (TLRPC.Updates) response;
        TLRPC.Photo photo = null;
        int a = 0;
        int N = updates.updates.size();
        while (true) {
            if (a >= N) {
                break;
            }
            TLRPC.Update update = updates.updates.get(a);
            if (update instanceof TLRPC.TL_updateNewChannelMessage) {
                TLRPC.Message message = ((TLRPC.TL_updateNewChannelMessage) update).message;
                if (!(message.action instanceof TLRPC.TL_messageActionChatEditPhoto) || !(message.action.photo instanceof TLRPC.TL_photo)) {
                    a++;
                } else {
                    photo = message.action.photo;
                    break;
                }
            } else {
                if (update instanceof TLRPC.TL_updateNewMessage) {
                    TLRPC.Message message2 = ((TLRPC.TL_updateNewMessage) update).message;
                    if ((message2.action instanceof TLRPC.TL_messageActionChatEditPhoto) && (message2.action.photo instanceof TLRPC.TL_photo)) {
                        photo = message2.action.photo;
                        break;
                    }
                } else {
                    continue;
                }
                a++;
            }
        }
        if (photo != null) {
            TLRPC.PhotoSize small = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 150);
            if (small != null && smallSize != null) {
                File destFile = FileLoader.getPathToAttach(small, true);
                File src = FileLoader.getPathToAttach(smallSize, true);
                src.renameTo(destFile);
                String oldKey = smallSize.volume_id + "_" + smallSize.local_id + "@50_50";
                String newKey = small.location.volume_id + "_" + small.location.local_id + "@50_50";
                ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForPhoto(small, photo), true);
            }
            TLRPC.PhotoSize big = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, CodeUtils.DEFAULT_REQ_HEIGHT);
            if (big != null && bigSize != null) {
                File destFile2 = FileLoader.getPathToAttach(big, true);
                File src2 = FileLoader.getPathToAttach(bigSize, true);
                src2.renameTo(destFile2);
            }
        }
        processUpdates(updates, false);
    }

    public void unregistedPush() {
        if (getUserConfig().registeredForPush && SharedConfig.pushString.length() == 0) {
            TLRPC.TL_account_unregisterDevice req = new TLRPC.TL_account_unregisterDevice();
            req.token = SharedConfig.pushString;
            req.token_type = 2;
            for (int a = 0; a < 3; a++) {
                UserConfig userConfig = UserConfig.getInstance(a);
                if (a != this.currentAccount && userConfig.isClientActivated()) {
                    req.other_uids.add(Integer.valueOf(userConfig.getClientUserId()));
                }
            }
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$U0ZEwxbC6yYQe5HYfzDE_3XNwmQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MessagesController.lambda$unregistedPush$207(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$unregistedPush$207(TLObject response, TLRPC.TL_error error) {
    }

    public void generateUpdateMessage() {
        if (BuildVars.DEBUG_VERSION || SharedConfig.lastUpdateVersion == null || SharedConfig.lastUpdateVersion.equals(BuildVars.BUILD_VERSION_STRING)) {
            return;
        }
        TLRPC.TL_help_getAppChangelog req = new TLRPC.TL_help_getAppChangelog();
        req.prev_app_version = SharedConfig.lastUpdateVersion;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$B2F4_1K19vjz5r1ICVLjTt8lXm4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$generateUpdateMessage$208$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$generateUpdateMessage$208$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            SharedConfig.lastUpdateVersion = BuildVars.BUILD_VERSION_STRING;
            SharedConfig.saveConfig();
        }
        if (response instanceof TLRPC.Updates) {
            processUpdates((TLRPC.Updates) response, false);
        }
    }

    public void performLogout(int type) {
        if (type == 1) {
            unregistedPush();
            TLRPC.TL_auth_logOut req = new TLRPC.TL_auth_logOut();
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$nlKA5YzwclB8SgLPQau4kvRKEfk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$performLogout$209$MessagesController(tLObject, tL_error);
                }
            });
        } else {
            getConnectionsManager().cleanup(type == 2);
        }
        getUserConfig().clearConfig();
        getNotificationCenter().postNotificationName(NotificationCenter.appDidLogout, new Object[0]);
        getMessagesStorage().cleanup(false);
        cleanup();
        getContactsController().deleteUnknownAppAccounts();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$cloKvchLwHbFq0rabyqAm0Zk_I0
            @Override // java.lang.Runnable
            public final void run() {
                GcmPushListenerService.sendUPushRegistrationToServer("");
            }
        });
    }

    public /* synthetic */ void lambda$performLogout$209$MessagesController(TLObject response, TLRPC.TL_error error) {
        getConnectionsManager().cleanup(false);
    }

    public void registerForPush(final String regid) {
        if (TextUtils.isEmpty(regid) || this.registeringForPush || getUserConfig().getClientUserId() == 0) {
            return;
        }
        if (getUserConfig().registeredForPush && regid.equals(SharedConfig.pushString)) {
            return;
        }
        this.registeringForPush = true;
        this.lastPushRegisterSendTime = SystemClock.elapsedRealtime();
        if (SharedConfig.pushAuthKey == null) {
            SharedConfig.pushAuthKey = new byte[256];
            Utilities.random.nextBytes(SharedConfig.pushAuthKey);
            SharedConfig.saveConfig();
        }
        TLRPC.TL_account_registerDevice req = new TLRPC.TL_account_registerDevice();
        req.token_type = 2;
        req.token = regid;
        req.no_muted = false;
        req.secret = SharedConfig.pushAuthKey;
        for (int a = 0; a < 3; a++) {
            UserConfig userConfig = UserConfig.getInstance(a);
            if (a != this.currentAccount && userConfig.isClientActivated()) {
                int uid = userConfig.getClientUserId();
                req.other_uids.add(Integer.valueOf(uid));
            }
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$78Y98GYQtWlNzIfWxsk-sKAXTTc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$registerForPush$212$MessagesController(regid, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$registerForPush$212$MessagesController(String regid, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_boolTrue) {
            getUserConfig().registeredForPush = true;
            SharedConfig.pushString = regid;
            getUserConfig().saveConfig(false);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$T5VpiYfm0ufiRSahkueWL36Xlhc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$211$MessagesController();
            }
        });
    }

    public /* synthetic */ void lambda$null$211$MessagesController() {
        this.registeringForPush = false;
    }

    public void registerForUPush(final String regid) {
        if (TextUtils.isEmpty(regid) || this.registeringForPush || getUserConfig().getClientUserId() == 0) {
            return;
        }
        if (getUserConfig().registeredForPush && regid.equals(SharedConfig.pushString)) {
            return;
        }
        this.registeringForPush = true;
        this.lastPushRegisterSendTime = SystemClock.elapsedRealtime();
        if (SharedConfig.pushAuthKey == null) {
            SharedConfig.pushAuthKey = new byte[256];
            Utilities.random.nextBytes(SharedConfig.pushAuthKey);
            SharedConfig.saveConfig();
        }
        TLRPC.TL_account_registerDevice req = new TLRPC.TL_account_registerDevice();
        req.token_type = getPushDeviceType();
        req.token = regid;
        req.no_muted = false;
        req.secret = SharedConfig.pushAuthKey;
        for (int a = 0; a < 3; a++) {
            UserConfig userConfig = UserConfig.getInstance(a);
            if (a != this.currentAccount && userConfig.isClientActivated()) {
                int uid = userConfig.getClientUserId();
                req.other_uids.add(Integer.valueOf(uid));
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("add other uid = " + uid + " for account " + this.currentAccount);
                }
            }
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$x0R48yMIqM6ROELEZDaj4i2Uhik
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$registerForUPush$214$MessagesController(regid, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$registerForUPush$214$MessagesController(String regid, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_boolTrue) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("account " + this.currentAccount + " registered for push");
            }
            getUserConfig().registeredForPush = true;
            SharedConfig.pushString = regid;
            getUserConfig().saveConfig(false);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$v5ijAJlBjWWWgtDSg1RCYeoWRhI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$213$MessagesController();
            }
        });
    }

    public /* synthetic */ void lambda$null$213$MessagesController() {
        this.registeringForPush = false;
    }

    private int getPushDeviceType() {
        if (MryDeviceHelper.isHuawei()) {
            return 5;
        }
        if (MryDeviceHelper.isXiaomi()) {
            return 6;
        }
        if (MryDeviceHelper.isOppo()) {
            return 7;
        }
        return 8;
    }

    public void loadCurrentState() {
        if (this.updatingState) {
            return;
        }
        this.updatingState = true;
        TLRPC.TL_updates_getState req = new TLRPC.TL_updates_getState();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$52-D2Us26PVq0hE7-gWouwQV_is
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$loadCurrentState$215$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadCurrentState$215$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        this.updatingState = false;
        if (error == null) {
            TLRPC.TL_updates_state res = (TLRPC.TL_updates_state) response;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("loadCurrentState ===> response = " + res.toString());
            }
            getMessagesStorage().setLastDateValue(res.date);
            getMessagesStorage().setLastPtsValue(res.pts);
            getMessagesStorage().setLastSeqValue(res.seq);
            getMessagesStorage().setLastQtsValue(res.qts);
            for (int a = 0; a < 3; a++) {
                processUpdatesQueue(a, 2);
            }
            getMessagesStorage().saveDiffParams(getMessagesStorage().getLastSeqValue(), getMessagesStorage().getLastPtsValue(), getMessagesStorage().getLastDateValue(), getMessagesStorage().getLastQtsValue());
            return;
        }
        if (error.code != 401) {
            loadCurrentState();
        }
    }

    private int getUpdateSeq(TLRPC.Updates updates) {
        if (updates instanceof TLRPC.TL_updatesCombined) {
            return updates.seq_start;
        }
        return updates.seq;
    }

    private void setUpdatesStartTime(int type, long time) {
        if (type == 0) {
            this.updatesStartWaitTimeSeq = time;
        } else if (type == 1) {
            this.updatesStartWaitTimePts = time;
        } else if (type == 2) {
            this.updatesStartWaitTimeQts = time;
        }
    }

    public long getUpdatesStartTime(int type) {
        if (type == 0) {
            return this.updatesStartWaitTimeSeq;
        }
        if (type == 1) {
            return this.updatesStartWaitTimePts;
        }
        if (type == 2) {
            return this.updatesStartWaitTimeQts;
        }
        return 0L;
    }

    private int isValidUpdate(TLRPC.Updates updates, int type) {
        if (type == 0) {
            int seq = getUpdateSeq(updates);
            if (getMessagesStorage().getLastSeqValue() + 1 == seq || getMessagesStorage().getLastSeqValue() == seq) {
                return 0;
            }
            return getMessagesStorage().getLastSeqValue() < seq ? 1 : 2;
        }
        if (type == 1) {
            if (updates.pts <= getMessagesStorage().getLastPtsValue()) {
                return 2;
            }
            return getMessagesStorage().getLastPtsValue() + updates.pts_count == updates.pts ? 0 : 1;
        }
        if (type != 2) {
            return 0;
        }
        if (updates.pts <= getMessagesStorage().getLastQtsValue()) {
            return 2;
        }
        return getMessagesStorage().getLastQtsValue() + updates.updates.size() == updates.pts ? 0 : 1;
    }

    private void processChannelsUpdatesQueue(int channelId, int state) throws Exception {
        int updateState;
        ArrayList<TLRPC.Updates> updatesQueue = this.updatesQueueChannels.get(channelId);
        if (updatesQueue == null) {
            return;
        }
        int channelPts = this.channelsPts.get(channelId);
        if (updatesQueue.isEmpty() || channelPts == 0) {
            this.updatesQueueChannels.remove(channelId);
            return;
        }
        Collections.sort(updatesQueue, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$I6hzQtqWBtqVR4Lw_ezZczCwkUs
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return AndroidUtilities.compare(((TLRPC.Updates) obj).pts, ((TLRPC.Updates) obj2).pts);
            }
        });
        boolean anyProceed = false;
        if (state == 2) {
            this.channelsPts.put(channelId, updatesQueue.get(0).pts);
        }
        for (int a = 0; a < updatesQueue.size(); a = (a - 1) + 1) {
            TLRPC.Updates updates = updatesQueue.get(a);
            if (updates.pts <= channelPts) {
                updateState = 2;
            } else {
                int updateState2 = updates.pts_count;
                if (updateState2 + channelPts == updates.pts) {
                    updateState = 0;
                } else {
                    updateState = 1;
                }
            }
            if (updateState == 0) {
                processUpdates(updates, true);
                anyProceed = true;
                updatesQueue.remove(a);
            } else {
                if (updateState == 1) {
                    long updatesStartWaitTime = this.updatesStartWaitTimeChannels.get(channelId);
                    if (updatesStartWaitTime != 0 && (anyProceed || Math.abs(System.currentTimeMillis() - updatesStartWaitTime) <= 1500)) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("HOLE IN CHANNEL " + channelId + " UPDATES QUEUE - will wait more time");
                        }
                        if (anyProceed) {
                            this.updatesStartWaitTimeChannels.put(channelId, System.currentTimeMillis());
                            return;
                        }
                        return;
                    }
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("HOLE IN CHANNEL " + channelId + " UPDATES QUEUE - getChannelDifference ");
                    }
                    this.updatesStartWaitTimeChannels.delete(channelId);
                    this.updatesQueueChannels.remove(channelId);
                    getChannelDifference(channelId);
                    return;
                }
                updatesQueue.remove(a);
            }
        }
        this.updatesQueueChannels.remove(channelId);
        this.updatesStartWaitTimeChannels.delete(channelId);
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("UPDATES CHANNEL " + channelId + " QUEUE PROCEED - OK");
        }
    }

    private void processUpdatesQueue(int type, int state) throws Exception {
        ArrayList<TLRPC.Updates> updatesQueue = null;
        if (type == 0) {
            updatesQueue = this.updatesQueueSeq;
            Collections.sort(updatesQueue, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$S5P_clUFfzMeZPXTIrhz4JqBjQ4
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return this.f$0.lambda$processUpdatesQueue$217$MessagesController((TLRPC.Updates) obj, (TLRPC.Updates) obj2);
                }
            });
        } else if (type == 1) {
            updatesQueue = this.updatesQueuePts;
            Collections.sort(updatesQueue, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$3lQMgFMHA0XYXYjykHY2CEp5R-U
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return AndroidUtilities.compare(((TLRPC.Updates) obj).pts, ((TLRPC.Updates) obj2).pts);
                }
            });
        } else if (type == 2) {
            updatesQueue = this.updatesQueueQts;
            Collections.sort(updatesQueue, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$h08DE1cIMmDov5Ansk3vF8tnsmI
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return AndroidUtilities.compare(((TLRPC.Updates) obj).pts, ((TLRPC.Updates) obj2).pts);
                }
            });
        }
        if (updatesQueue != null && !updatesQueue.isEmpty()) {
            boolean anyProceed = false;
            if (state == 2) {
                TLRPC.Updates updates = updatesQueue.get(0);
                if (type == 0) {
                    getMessagesStorage().setLastSeqValue(getUpdateSeq(updates));
                } else if (type == 1) {
                    getMessagesStorage().setLastPtsValue(updates.pts);
                } else {
                    getMessagesStorage().setLastQtsValue(updates.pts);
                }
            }
            for (int a = 0; a < updatesQueue.size(); a = (a - 1) + 1) {
                TLRPC.Updates updates2 = updatesQueue.get(a);
                int updateState = isValidUpdate(updates2, type);
                if (updateState == 0) {
                    processUpdates(updates2, true);
                    anyProceed = true;
                    updatesQueue.remove(a);
                } else {
                    if (updateState == 1) {
                        if (getUpdatesStartTime(type) != 0 && (anyProceed || Math.abs(System.currentTimeMillis() - getUpdatesStartTime(type)) <= 1500)) {
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("HOLE IN UPDATES QUEUE - will wait more time");
                            }
                            if (anyProceed) {
                                setUpdatesStartTime(type, System.currentTimeMillis());
                                return;
                            }
                            return;
                        }
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("HOLE IN UPDATES QUEUE - getDifference");
                        }
                        setUpdatesStartTime(type, 0L);
                        updatesQueue.clear();
                        getDifference();
                        return;
                    }
                    updatesQueue.remove(a);
                }
            }
            updatesQueue.clear();
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("UPDATES QUEUE PROCEED - OK");
            }
        }
        setUpdatesStartTime(type, 0L);
    }

    public /* synthetic */ int lambda$processUpdatesQueue$217$MessagesController(TLRPC.Updates updates, TLRPC.Updates updates2) {
        return AndroidUtilities.compare(getUpdateSeq(updates), getUpdateSeq(updates2));
    }

    protected void loadUnknownChannel(final TLRPC.Chat channel, long taskId) throws Exception {
        final long newTaskId;
        if (!(channel instanceof TLRPC.TL_channel) || this.gettingUnknownChannels.indexOfKey(channel.id) >= 0) {
            return;
        }
        if (channel.access_hash == 0) {
            if (taskId != 0) {
                getMessagesStorage().removePendingTask(taskId);
                return;
            }
            return;
        }
        TLRPC.TL_inputPeerChannel inputPeer = new TLRPC.TL_inputPeerChannel();
        inputPeer.channel_id = channel.id;
        inputPeer.access_hash = channel.access_hash;
        this.gettingUnknownChannels.put(channel.id, true);
        TLRPC.TL_messages_getPeerDialogs req = new TLRPC.TL_messages_getPeerDialogs();
        TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
        inputDialogPeer.peer = inputPeer;
        req.peers.add(inputDialogPeer);
        if (taskId == 0) {
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(channel.getObjectSize() + 4);
                data.writeInt32(0);
                channel.serializeToStream(data);
            } catch (Exception e) {
                FileLog.e(e);
            }
            newTaskId = getMessagesStorage().createPendingTask(data);
        } else {
            newTaskId = taskId;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HpaSz6T3lxxqnhBTc6NZW3mdQ1M
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadUnknownChannel$220$MessagesController(newTaskId, channel, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadUnknownChannel$220$MessagesController(long newTaskId, TLRPC.Chat channel, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.TL_messages_peerDialogs res = (TLRPC.TL_messages_peerDialogs) response;
            if (!res.dialogs.isEmpty() && !res.chats.isEmpty() && !(res.dialogs.get(0) instanceof TLRPC.TL_dialogFolder)) {
                TLRPC.TL_dialog dialog = (TLRPC.TL_dialog) res.dialogs.get(0);
                TLRPC.TL_messages_dialogs dialogs = new TLRPC.TL_messages_dialogs();
                dialogs.dialogs.addAll(res.dialogs);
                dialogs.messages.addAll(res.messages);
                dialogs.users.addAll(res.users);
                dialogs.chats.addAll(res.chats);
                processLoadedDialogs(dialogs, null, dialog.folder_id, 0, 1, this.DIALOGS_LOAD_TYPE_CHANNEL, false, false, false);
            }
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
        this.gettingUnknownChannels.delete(channel.id);
    }

    public void startShortPoll(final TLRPC.Chat chat, final boolean stop) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$lojrZaBZ4EUot15-m19a29rhyCU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startShortPoll$221$MessagesController(stop, chat);
            }
        });
    }

    public /* synthetic */ void lambda$startShortPoll$221$MessagesController(boolean stop, TLRPC.Chat chat) {
        if (stop) {
            this.needShortPollChannels.delete(chat.id);
            if (chat.megagroup) {
                this.needShortPollOnlines.delete(chat.id);
                return;
            }
            return;
        }
        this.needShortPollChannels.put(chat.id, 0);
        if (this.shortPollChannels.indexOfKey(chat.id) < 0) {
            getChannelDifference(chat.id, 3, 0L, null);
        }
        if (chat.megagroup) {
            this.needShortPollOnlines.put(chat.id, 0);
            if (this.shortPollOnlines.indexOfKey(chat.id) < 0) {
                this.shortPollOnlines.put(chat.id, 0);
            }
        }
    }

    private void getChannelDifference(int channelId) {
        getChannelDifference(channelId, 0, 0L, null);
    }

    public static boolean isSupportUser(TLRPC.User user) {
        return user != null && (user.support || user.id == 777000 || user.id == 333000 || user.id == 4240000 || user.id == 4244000 || user.id == 4245000 || user.id == 4246000 || user.id == 410000 || user.id == 420000 || user.id == 431000 || user.id == 431415000 || user.id == 434000 || user.id == 4243000 || user.id == 439000 || user.id == 449000 || user.id == 450000 || user.id == 452000 || user.id == 454000 || user.id == 4254000 || user.id == 455000 || user.id == 460000 || user.id == 470000 || user.id == 479000 || user.id == 796000 || user.id == 482000 || user.id == 490000 || user.id == 496000 || user.id == 497000 || user.id == 498000 || user.id == 4298000);
    }

    protected void getChannelDifference(final int channelId, final int newDialogType, long taskId, TLRPC.InputChannel inputChannel) {
        int limit;
        int channelPts;
        TLRPC.InputChannel inputChannel2;
        long newTaskId;
        boolean gettingDifferenceChannel = this.gettingDifferenceChannels.get(channelId);
        if (gettingDifferenceChannel) {
            return;
        }
        if (newDialogType == 1) {
            if (this.channelsPts.get(channelId) != 0) {
                return;
            }
            limit = 1;
            channelPts = 1;
        } else {
            int channelPts2 = this.channelsPts.get(channelId);
            if (channelPts2 == 0) {
                channelPts2 = getMessagesStorage().getChannelPtsSync(channelId);
                if (channelPts2 != 0) {
                    this.channelsPts.put(channelId, channelPts2);
                }
                if (channelPts2 == 0 && (newDialogType == 2 || newDialogType == 3)) {
                    return;
                }
            }
            if (channelPts2 != 0) {
                limit = 100;
                channelPts = channelPts2;
            } else {
                return;
            }
        }
        if (inputChannel == null) {
            TLRPC.Chat chat = getChat(Integer.valueOf(channelId));
            if (chat == null && (chat = getMessagesStorage().getChatSync(channelId)) != null) {
                putChat(chat, true);
            }
            inputChannel2 = getInputChannel(chat);
        } else {
            inputChannel2 = inputChannel;
        }
        if (inputChannel2 == null || inputChannel2.access_hash == 0) {
            if (taskId != 0) {
                getMessagesStorage().removePendingTask(taskId);
                return;
            }
            return;
        }
        if (taskId == 0) {
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(inputChannel2.getObjectSize() + 12);
                data.writeInt32(6);
                data.writeInt32(channelId);
                data.writeInt32(newDialogType);
                inputChannel2.serializeToStream(data);
            } catch (Exception e) {
                FileLog.e(e);
            }
            long newTaskId2 = getMessagesStorage().createPendingTask(data);
            newTaskId = newTaskId2;
        } else {
            newTaskId = taskId;
        }
        this.gettingDifferenceChannels.put(channelId, true);
        TLRPC.TL_updates_getChannelDifference req = new TLRPC.TL_updates_getChannelDifference();
        req.channel = inputChannel2;
        req.filter = new TLRPC.TL_channelMessagesFilterEmpty();
        req.pts = channelPts;
        req.limit = limit;
        req.force = newDialogType != 3;
        final long j = newTaskId;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$NtYeyvghOJzHdKganE786n31sIQ
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getChannelDifference$230$MessagesController(channelId, newDialogType, j, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$getChannelDifference$230$MessagesController(final int channelId, final int newDialogType, final long newTaskId, TLObject response, final TLRPC.TL_error error) {
        TLRPC.Chat channel;
        if (response == null) {
            if (error != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$sGTKbRuPrsH9GZH4oZ7yZz51nr8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$229$MessagesController(error, channelId);
                    }
                });
                this.gettingDifferenceChannels.delete(channelId);
                if (newTaskId != 0) {
                    getMessagesStorage().removePendingTask(newTaskId);
                    return;
                }
                return;
            }
            return;
        }
        final TLRPC.updates_ChannelDifference res = (TLRPC.updates_ChannelDifference) response;
        final SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        for (int a = 0; a < res.users.size(); a++) {
            TLRPC.User user = res.users.get(a);
            usersDict.put(user.id, user);
        }
        int a2 = 0;
        while (true) {
            if (a2 >= res.chats.size()) {
                channel = null;
                break;
            }
            TLRPC.Chat chat = res.chats.get(a2);
            if (chat.id != channelId) {
                a2++;
            } else {
                channel = chat;
                break;
            }
        }
        final TLRPC.Chat channelFinal = channel;
        final ArrayList<TLRPC.TL_updateMessageID> msgUpdates = new ArrayList<>();
        if (!res.other_updates.isEmpty()) {
            int a3 = 0;
            while (a3 < res.other_updates.size()) {
                TLRPC.Update upd = res.other_updates.get(a3);
                if (upd instanceof TLRPC.TL_updateMessageID) {
                    msgUpdates.add((TLRPC.TL_updateMessageID) upd);
                    res.other_updates.remove(a3);
                    a3--;
                }
                a3++;
            }
        }
        getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$19Ey1Xp8r-tmssFLi8t8QsAaklA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$222$MessagesController(res);
            }
        });
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Cv9lgdgyrmsYRBxzd9fHvTcRfNA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$228$MessagesController(msgUpdates, channelId, res, channelFinal, usersDict, newDialogType, newTaskId);
            }
        });
    }

    public /* synthetic */ void lambda$null$222$MessagesController(TLRPC.updates_ChannelDifference res) {
        putUsers(res.users, false);
        putChats(res.chats, false);
    }

    public /* synthetic */ void lambda$null$228$MessagesController(ArrayList msgUpdates, final int channelId, final TLRPC.updates_ChannelDifference res, final TLRPC.Chat channelFinal, final SparseArray usersDict, final int newDialogType, final long newTaskId) {
        if (!msgUpdates.isEmpty()) {
            final SparseArray<long[]> corrected = new SparseArray<>();
            Iterator it = msgUpdates.iterator();
            while (it.hasNext()) {
                TLRPC.TL_updateMessageID update = (TLRPC.TL_updateMessageID) it.next();
                long[] ids = getMessagesStorage().updateMessageStateAndId(update.random_id, null, update.id, 0, false, channelId, -1);
                if (ids != null) {
                    corrected.put(update.id, ids);
                }
            }
            if (corrected.size() != 0) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ZwLvscPpG6Scs14LTpcodwVXwJU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$223$MessagesController(corrected);
                    }
                });
            }
        }
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$e1pk5aUSJtYevcKOWFpDtMWRQz0
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$227$MessagesController(res, channelId, channelFinal, usersDict, newDialogType, newTaskId);
            }
        });
    }

    public /* synthetic */ void lambda$null$223$MessagesController(SparseArray corrected) {
        for (int a = 0; a < corrected.size(); a++) {
            int newId = corrected.keyAt(a);
            long[] ids = (long[]) corrected.valueAt(a);
            int oldId = (int) ids[1];
            getSendMessagesHelper().processSentMessage(oldId);
            getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(oldId), Integer.valueOf(newId), null, Long.valueOf(ids[0]), 0L, -1, false);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0251  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x01ac A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:110:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x016d  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01a3  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0212  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x022d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$null$227$MessagesController(final im.uwrkaxlmjj.tgnet.TLRPC.updates_ChannelDifference r22, int r23, im.uwrkaxlmjj.tgnet.TLRPC.Chat r24, android.util.SparseArray r25, int r26, long r27) throws java.lang.Exception {
        /*
            Method dump skipped, instruction units count: 601
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.lambda$null$227$MessagesController(im.uwrkaxlmjj.tgnet.TLRPC$updates_ChannelDifference, int, im.uwrkaxlmjj.tgnet.TLRPC$Chat, android.util.SparseArray, int, long):void");
    }

    public /* synthetic */ void lambda$null$224$MessagesController(LongSparseArray messages) {
        for (int a = 0; a < messages.size(); a++) {
            long key = messages.keyAt(a);
            ArrayList<MessageObject> value = (ArrayList) messages.valueAt(a);
            updateInterfaceWithMessages(key, value, false);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public /* synthetic */ void lambda$null$226$MessagesController(final ArrayList pushMessages, TLRPC.updates_ChannelDifference res) {
        if (!pushMessages.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$gpedcGmub6xI7Gvj3LcLev9OEko
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$225$MessagesController(pushMessages);
                }
            });
        }
        getMessagesStorage().putMessages(res.new_messages, true, true, false, getDownloadController().getAutodownloadMask(), false);
    }

    public /* synthetic */ void lambda$null$225$MessagesController(ArrayList pushMessages) {
        getNotificationsController().processNewMessages(pushMessages, true, false, null);
    }

    public /* synthetic */ void lambda$null$229$MessagesController(TLRPC.TL_error error, int channelId) {
        checkChannelError(error.text, channelId);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0035  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void checkChannelError(java.lang.String r8, int r9) {
        /*
            r7 = this;
            int r0 = r8.hashCode()
            r1 = -1809401834(0xffffffff9426b816, float:-8.417163E-27)
            r2 = 0
            r3 = 2
            r4 = 1
            if (r0 == r1) goto L2b
            r1 = -795226617(0xffffffffd099ce07, float:-2.064333E10)
            if (r0 == r1) goto L21
            r1 = -471086771(0xffffffffe3ebc94d, float:-8.69898E21)
            if (r0 == r1) goto L17
        L16:
            goto L35
        L17:
            java.lang.String r0 = "CHANNEL_PUBLIC_GROUP_NA"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L16
            r0 = 1
            goto L36
        L21:
            java.lang.String r0 = "CHANNEL_PRIVATE"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L16
            r0 = 0
            goto L36
        L2b:
            java.lang.String r0 = "USER_BANNED_IN_CHANNEL"
            boolean r0 = r8.equals(r0)
            if (r0 == 0) goto L16
            r0 = 2
            goto L36
        L35:
            r0 = -1
        L36:
            if (r0 == 0) goto L6d
            if (r0 == r4) goto L55
            if (r0 == r3) goto L3d
            goto L85
        L3d:
            im.uwrkaxlmjj.messenger.NotificationCenter r0 = r7.getNotificationCenter()
            int r1 = im.uwrkaxlmjj.messenger.NotificationCenter.chatInfoCantLoad
            java.lang.Object[] r5 = new java.lang.Object[r3]
            java.lang.Integer r6 = java.lang.Integer.valueOf(r9)
            r5[r2] = r6
            java.lang.Integer r2 = java.lang.Integer.valueOf(r3)
            r5[r4] = r2
            r0.postNotificationName(r1, r5)
            goto L85
        L55:
            im.uwrkaxlmjj.messenger.NotificationCenter r0 = r7.getNotificationCenter()
            int r1 = im.uwrkaxlmjj.messenger.NotificationCenter.chatInfoCantLoad
            java.lang.Object[] r3 = new java.lang.Object[r3]
            java.lang.Integer r5 = java.lang.Integer.valueOf(r9)
            r3[r2] = r5
            java.lang.Integer r2 = java.lang.Integer.valueOf(r4)
            r3[r4] = r2
            r0.postNotificationName(r1, r3)
            goto L85
        L6d:
            im.uwrkaxlmjj.messenger.NotificationCenter r0 = r7.getNotificationCenter()
            int r1 = im.uwrkaxlmjj.messenger.NotificationCenter.chatInfoCantLoad
            java.lang.Object[] r3 = new java.lang.Object[r3]
            java.lang.Integer r5 = java.lang.Integer.valueOf(r9)
            r3[r2] = r5
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            r3[r4] = r2
            r0.postNotificationName(r1, r3)
        L85:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.checkChannelError(java.lang.String, int):void");
    }

    public void getDifference() {
        getDifference(getMessagesStorage().getLastPtsValue(), getMessagesStorage().getLastDateValue(), getMessagesStorage().getLastQtsValue(), false);
    }

    public void getDifference(int pts, final int date, final int qts, boolean slice) {
        registerForPush(SharedConfig.pushString);
        if (getMessagesStorage().getLastPtsValue() == 0) {
            loadCurrentState();
            return;
        }
        if (!slice && this.gettingDifference) {
            return;
        }
        this.gettingDifference = true;
        TLRPC.TL_updates_getDifference req = new TLRPC.TL_updates_getDifference();
        req.pts = pts;
        req.date = date;
        req.qts = qts;
        if (this.getDifferenceFirstSync) {
            req.flags |= 1;
            if (ApplicationLoader.isConnectedOrConnectingToWiFi()) {
                req.pts_total_limit = 5000;
            } else {
                req.pts_total_limit = 1000;
            }
            this.getDifferenceFirstSync = false;
        }
        if (req.date == 0) {
            req.date = getConnectionsManager().getCurrentTime();
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("getDiff start ===> act=" + this.currentAccount + " ,date=" + date + " ,pts=" + pts + " ,qts=" + qts);
        }
        getConnectionsManager().setIsUpdating(true);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$WFoSdPlV4NQ48MT71Sk17WBG6jo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getDifference$239$MessagesController(date, qts, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$getDifference$239$MessagesController(final int date, final int qts, TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            this.gettingDifference = false;
            getConnectionsManager().setIsUpdating(false);
            return;
        }
        final TLRPC.updates_Difference res = (TLRPC.updates_Difference) response;
        if (BuildVars.DEBUG_VERSION) {
            FileLog.d("getDiff success ===> act=" + this.currentAccount + " ,date=" + date + " ,res=" + res.toString());
        }
        if (res instanceof TLRPC.TL_updates_differenceTooLong) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$TH_nBVhXSuNXK1CjhUy_ibaMUwM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$231$MessagesController(res, date, qts);
                }
            });
            return;
        }
        if (res instanceof TLRPC.TL_updates_differenceSlice) {
            getDifference(res.intermediate_state.pts, res.intermediate_state.date, res.intermediate_state.qts, true);
        }
        final SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        final SparseArray<TLRPC.Chat> chatsDict = new SparseArray<>();
        for (int a = 0; a < res.users.size(); a++) {
            TLRPC.User user = res.users.get(a);
            usersDict.put(user.id, user);
        }
        for (int a2 = 0; a2 < res.chats.size(); a2++) {
            TLRPC.Chat chat = res.chats.get(a2);
            chatsDict.put(chat.id, chat);
        }
        final ArrayList<TLRPC.TL_updateMessageID> msgUpdates = new ArrayList<>();
        if (!res.other_updates.isEmpty()) {
            int a3 = 0;
            while (a3 < res.other_updates.size()) {
                TLRPC.Update upd = res.other_updates.get(a3);
                if (upd instanceof TLRPC.TL_updateMessageID) {
                    msgUpdates.add((TLRPC.TL_updateMessageID) upd);
                    res.other_updates.remove(a3);
                    a3--;
                } else if (getUpdateType(upd) == 2) {
                    int channelId = getUpdateChannelId(upd);
                    int channelPts = this.channelsPts.get(channelId);
                    if (channelPts == 0 && (channelPts = getMessagesStorage().getChannelPtsSync(channelId)) != 0) {
                        this.channelsPts.put(channelId, channelPts);
                    }
                    if (channelPts != 0 && getUpdatePts(upd) <= channelPts) {
                        res.other_updates.remove(a3);
                        a3--;
                    }
                }
                a3++;
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$C1qqhmLkQ0SW73g2jRNFYf_5_0g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$232$MessagesController(res);
            }
        });
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$znu334ueVUlbdfj51HqycAYz27U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$238$MessagesController(res, msgUpdates, usersDict, chatsDict);
            }
        });
    }

    public /* synthetic */ void lambda$null$231$MessagesController(TLRPC.updates_Difference res, int date, int qts) {
        this.loadedFullUsers.clear();
        this.loadedFullChats.clear();
        resetDialogs(true, getMessagesStorage().getLastSeqValue(), res.pts, date, qts);
    }

    public /* synthetic */ void lambda$null$232$MessagesController(TLRPC.updates_Difference res) {
        this.loadedFullUsers.clear();
        this.loadedFullChats.clear();
        putUsers(res.users, false);
        putChats(res.chats, false);
    }

    public /* synthetic */ void lambda$null$238$MessagesController(final TLRPC.updates_Difference res, ArrayList msgUpdates, final SparseArray usersDict, final SparseArray chatsDict) {
        getMessagesStorage().putUsersAndChats(res.users, res.chats, true, false);
        if (!msgUpdates.isEmpty()) {
            final SparseArray<long[]> corrected = new SparseArray<>();
            for (int a = 0; a < msgUpdates.size(); a++) {
                TLRPC.TL_updateMessageID update = (TLRPC.TL_updateMessageID) msgUpdates.get(a);
                long[] ids = getMessagesStorage().updateMessageStateAndId(update.random_id, null, update.id, 0, false, 0, -1);
                if (ids != null) {
                    corrected.put(update.id, ids);
                }
            }
            int a2 = corrected.size();
            if (a2 != 0) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$9DcorgXvDsC7_iTui0Y_3R3j0oA
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$233$MessagesController(corrected);
                    }
                });
            }
        }
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$SAMqrJjCQfI9k0GSqPHntq1AgCc
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$237$MessagesController(res, usersDict, chatsDict);
            }
        });
    }

    public /* synthetic */ void lambda$null$233$MessagesController(SparseArray corrected) {
        for (int a = 0; a < corrected.size(); a++) {
            int newId = corrected.keyAt(a);
            long[] ids = (long[]) corrected.valueAt(a);
            int oldId = (int) ids[1];
            getSendMessagesHelper().processSentMessage(oldId);
            getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(oldId), Integer.valueOf(newId), null, Long.valueOf(ids[0]), 0L, -1, false);
        }
    }

    public /* synthetic */ void lambda$null$237$MessagesController(final TLRPC.updates_Difference res, SparseArray usersDict, SparseArray chatsDict) throws Exception {
        TLRPC.User user;
        if (!res.new_messages.isEmpty() || !res.new_encrypted_messages.isEmpty()) {
            final LongSparseArray<ArrayList<MessageObject>> messages = new LongSparseArray<>();
            for (int b = 0; b < res.new_encrypted_messages.size(); b++) {
                TLRPC.EncryptedMessage encryptedMessage = res.new_encrypted_messages.get(b);
                ArrayList<TLRPC.Message> decryptedMessages = getSecretChatHelper().decryptMessage(encryptedMessage);
                if (decryptedMessages != null && !decryptedMessages.isEmpty()) {
                    res.new_messages.addAll(decryptedMessages);
                }
            }
            ImageLoader.saveMessagesThumbs(res.new_messages);
            final ArrayList<MessageObject> pushMessages = new ArrayList<>();
            int clientUserId = getUserConfig().getClientUserId();
            for (int a = 0; a < res.new_messages.size(); a++) {
                TLRPC.Message message = res.new_messages.get(a);
                if (message.dialog_id == 0) {
                    if (message.to_id.chat_id != 0) {
                        message.dialog_id = -message.to_id.chat_id;
                    } else {
                        if (message.to_id.user_id == getUserConfig().getClientUserId()) {
                            message.to_id.user_id = message.from_id;
                        }
                        message.dialog_id = message.to_id.user_id;
                    }
                }
                if (((int) message.dialog_id) != 0) {
                    if ((message.action instanceof TLRPC.TL_messageActionChatDeleteUser) && (user = (TLRPC.User) usersDict.get(message.action.user_id)) != null && user.bot) {
                        message.reply_markup = new TLRPC.TL_replyKeyboardHide();
                        message.flags |= 64;
                    }
                    if ((message.action instanceof TLRPC.TL_messageActionChatMigrateTo) || (message.action instanceof TLRPC.TL_messageActionChannelCreate)) {
                        message.unread = false;
                        message.media_unread = false;
                    } else {
                        ConcurrentHashMap<Long, Integer> read_max = message.out ? this.dialogs_read_outbox_max : this.dialogs_read_inbox_max;
                        Integer value = read_max.get(Long.valueOf(message.dialog_id));
                        if (value == null) {
                            value = Integer.valueOf(getMessagesStorage().getDialogReadMax(message.out, message.dialog_id));
                            read_max.put(Long.valueOf(message.dialog_id), value);
                        }
                        message.unread = value.intValue() < message.id;
                    }
                }
                if (message.dialog_id == clientUserId) {
                    message.unread = false;
                    message.media_unread = false;
                    message.out = true;
                }
                MessageObject obj = new MessageObject(this.currentAccount, message, (SparseArray<TLRPC.User>) usersDict, (SparseArray<TLRPC.Chat>) chatsDict, this.createdDialogIds.contains(Long.valueOf(message.dialog_id)));
                if ((!obj.isOut() || obj.messageOwner.from_scheduled) && obj.isUnread()) {
                    pushMessages.add(obj);
                }
                ArrayList<MessageObject> arr = messages.get(message.dialog_id);
                if (arr == null) {
                    arr = new ArrayList<>();
                    messages.put(message.dialog_id, arr);
                }
                arr.add(obj);
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$sjdTVjjJCYsToGTKoCNQH3urieo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$234$MessagesController(messages);
                }
            });
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$OB79qOjlPPZNstHYHHjPuEQkXIo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$236$MessagesController(pushMessages, res);
                }
            });
            getSecretChatHelper().processPendingEncMessages();
        }
        if (!res.other_updates.isEmpty()) {
            processUpdateArray(res.other_updates, res.users, res.chats, true, 0);
        }
        if (res instanceof TLRPC.TL_updates_difference) {
            this.gettingDifference = false;
            getMessagesStorage().setLastSeqValue(res.state.seq);
            getMessagesStorage().setLastDateValue(res.state.date);
            getMessagesStorage().setLastPtsValue(res.state.pts);
            getMessagesStorage().setLastQtsValue(res.state.qts);
            getConnectionsManager().setIsUpdating(false);
            for (int a2 = 0; a2 < 3; a2++) {
                processUpdatesQueue(a2, 1);
            }
        } else if (res instanceof TLRPC.TL_updates_differenceSlice) {
            getMessagesStorage().setLastDateValue(res.intermediate_state.date);
            getMessagesStorage().setLastPtsValue(res.intermediate_state.pts);
            getMessagesStorage().setLastQtsValue(res.intermediate_state.qts);
        } else if (res instanceof TLRPC.TL_updates_differenceEmpty) {
            this.gettingDifference = false;
            getMessagesStorage().setLastSeqValue(res.seq);
            getMessagesStorage().setLastDateValue(res.date);
            getConnectionsManager().setIsUpdating(false);
            for (int a3 = 0; a3 < 3; a3++) {
                processUpdatesQueue(a3, 1);
            }
        }
        getMessagesStorage().saveDiffParams(getMessagesStorage().getLastSeqValue(), getMessagesStorage().getLastPtsValue(), getMessagesStorage().getLastDateValue(), getMessagesStorage().getLastQtsValue());
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("getDiff save last diff value ===> act=" + this.currentAccount + " ,date=" + getMessagesStorage().getLastDateValue() + " ,pts=" + getMessagesStorage().getLastPtsValue() + " ,seq=" + getMessagesStorage().getLastSeqValue() + " ,qts=" + getMessagesStorage().getLastQtsValue());
        }
    }

    public /* synthetic */ void lambda$null$234$MessagesController(LongSparseArray messages) {
        for (int a = 0; a < messages.size(); a++) {
            long key = messages.keyAt(a);
            ArrayList<MessageObject> value = (ArrayList) messages.valueAt(a);
            updateInterfaceWithMessages(key, value, false);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public /* synthetic */ void lambda$null$236$MessagesController(final ArrayList pushMessages, final TLRPC.updates_Difference res) {
        if (!pushMessages.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$pIqKxK_DDR5tJ3SyT3yPkKFs6iA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$235$MessagesController(pushMessages, res);
                }
            });
        }
        getMessagesStorage().putMessages(res.new_messages, true, true, false, getDownloadController().getAutodownloadMask(), false);
    }

    public /* synthetic */ void lambda$null$235$MessagesController(ArrayList pushMessages, TLRPC.updates_Difference res) {
        getNotificationsController().processNewMessages(pushMessages, !(res instanceof TLRPC.TL_updates_differenceSlice), false, null);
    }

    public void markDialogAsUnread(long did, TLRPC.InputPeer peer, long taskId) {
        final long newTaskId;
        TLRPC.Dialog dialog = this.dialogs_dict.get(did);
        if (dialog != null) {
            dialog.unread_mark = true;
            if (dialog.unread_count == 0) {
                this.dialogsUnreadOnly.add(dialog);
                if (!isDialogMuted(did)) {
                    this.unreadUnmutedDialogs++;
                }
            }
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 256);
            getMessagesStorage().setDialogUnread(did, true);
        }
        int lower_id = (int) did;
        if (lower_id != 0) {
            TLRPC.TL_messages_markDialogUnread req = new TLRPC.TL_messages_markDialogUnread();
            req.unread = true;
            if (peer == null) {
                peer = getInputPeer(lower_id);
            }
            if (peer instanceof TLRPC.TL_inputPeerEmpty) {
                return;
            }
            TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
            inputDialogPeer.peer = peer;
            req.peer = inputDialogPeer;
            if (taskId == 0) {
                NativeByteBuffer data = null;
                try {
                    data = new NativeByteBuffer(peer.getObjectSize() + 12);
                    data.writeInt32(9);
                    data.writeInt64(did);
                    peer.serializeToStream(data);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                newTaskId = getMessagesStorage().createPendingTask(data);
            } else {
                newTaskId = taskId;
            }
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$wYOHhAUHFhhuxfehwv9wJOjtysI
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$markDialogAsUnread$240$MessagesController(newTaskId, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$markDialogAsUnread$240$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public void loadUnreadDialogs() {
        if (this.loadingUnreadDialogs || getUserConfig().unreadDialogsLoaded) {
            return;
        }
        this.loadingUnreadDialogs = true;
        TLRPC.TL_messages_getDialogUnreadMarks req = new TLRPC.TL_messages_getDialogUnreadMarks();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$m137Dn_a_0mywKUgpmG__TG_w0o
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadUnreadDialogs$242$MessagesController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadUnreadDialogs$242$MessagesController(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$WNGzcRE8fLFG4r1eTGeg0yr0DcI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$241$MessagesController(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$241$MessagesController(TLObject response) {
        long did;
        if (response != null) {
            TLRPC.Vector vector = (TLRPC.Vector) response;
            int size = vector.objects.size();
            for (int a = 0; a < size; a++) {
                TLRPC.DialogPeer peer = (TLRPC.DialogPeer) vector.objects.get(a);
                if (peer instanceof TLRPC.TL_dialogPeer) {
                    TLRPC.TL_dialogPeer dialogPeer = (TLRPC.TL_dialogPeer) peer;
                    if (dialogPeer.peer.user_id != 0) {
                        if (dialogPeer.peer.user_id != 0) {
                            did = dialogPeer.peer.user_id;
                        } else if (dialogPeer.peer.chat_id != 0) {
                            did = -dialogPeer.peer.chat_id;
                        } else {
                            did = -dialogPeer.peer.channel_id;
                        }
                    } else {
                        did = 0;
                    }
                    getMessagesStorage().setDialogUnread(did, true);
                    TLRPC.Dialog dialog = this.dialogs_dict.get(did);
                    if (dialog != null && !dialog.unread_mark) {
                        dialog.unread_mark = true;
                        if (dialog.unread_count == 0) {
                            this.dialogsUnreadOnly.add(dialog);
                            if (!isDialogMuted(did)) {
                                this.unreadUnmutedDialogs++;
                            }
                        }
                    }
                }
            }
            getUserConfig().unreadDialogsLoaded = true;
            getUserConfig().saveConfig(false);
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 256);
            this.loadingUnreadDialogs = false;
        }
    }

    public void reorderPinnedDialogs(int folderId, ArrayList<TLRPC.InputDialogPeer> order, long taskId) {
        final long newTaskId;
        TLRPC.TL_messages_reorderPinnedDialogs req = new TLRPC.TL_messages_reorderPinnedDialogs();
        req.folder_id = folderId;
        req.force = true;
        if (taskId == 0) {
            ArrayList<TLRPC.Dialog> dialogs = getDialogs(folderId);
            if (dialogs.isEmpty()) {
                return;
            }
            int size = 0;
            int N = dialogs.size();
            for (int a = 0; a < N; a++) {
                TLRPC.Dialog dialog = dialogs.get(a);
                if (!(dialog instanceof TLRPC.TL_dialogFolder)) {
                    if (!dialog.pinned) {
                        break;
                    }
                    getMessagesStorage().setDialogPinned(dialog.id, dialog.pinnedNum);
                    if (((int) dialog.id) != 0) {
                        TLRPC.InputPeer inputPeer = getInputPeer((int) dialogs.get(a).id);
                        TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
                        inputDialogPeer.peer = inputPeer;
                        req.order.add(inputDialogPeer);
                        size += inputDialogPeer.getObjectSize();
                    }
                }
            }
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(size + 12);
                data.writeInt32(16);
                data.writeInt32(folderId);
                data.writeInt32(req.order.size());
                int N2 = req.order.size();
                for (int a2 = 0; a2 < N2; a2++) {
                    req.order.get(a2).serializeToStream(data);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            newTaskId = getMessagesStorage().createPendingTask(data);
        } else {
            req.order = order;
            newTaskId = taskId;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$mcrmFP_Bp6za4apay9PxQG_MhNY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$reorderPinnedDialogs$243$MessagesController(newTaskId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$reorderPinnedDialogs$243$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public boolean pinDialog(long did, boolean pin, TLRPC.InputPeer peer, long taskId) {
        TLRPC.InputPeer peer2;
        final long newTaskId;
        int lower_id = (int) did;
        TLRPC.Dialog dialog = this.dialogs_dict.get(did);
        if (dialog == null || dialog.pinned == pin) {
            return dialog != null;
        }
        int folderId = dialog.folder_id;
        ArrayList<TLRPC.Dialog> dialogs = getDialogs(folderId);
        dialog.pinned = pin;
        if (pin) {
            int maxPinnedNum = 0;
            for (int a = 0; a < dialogs.size(); a++) {
                TLRPC.Dialog d = dialogs.get(a);
                if (!(d instanceof TLRPC.TL_dialogFolder)) {
                    if (!d.pinned) {
                        break;
                    }
                    maxPinnedNum = Math.max(d.pinnedNum, maxPinnedNum);
                }
            }
            int a2 = maxPinnedNum + 1;
            dialog.pinnedNum = a2;
        } else {
            dialog.pinnedNum = 0;
        }
        sortDialogs(null);
        if (!pin && dialogs.get(dialogs.size() - 1) == dialog && !this.dialogsEndReached.get(folderId)) {
            dialogs.remove(dialogs.size() - 1);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        if (lower_id != 0 && taskId != -1) {
            TLRPC.TL_messages_toggleDialogPin req = new TLRPC.TL_messages_toggleDialogPin();
            req.pinned = pin;
            if (peer != null) {
                peer2 = peer;
            } else {
                peer2 = getInputPeer(lower_id);
            }
            if (peer2 instanceof TLRPC.TL_inputPeerEmpty) {
                return false;
            }
            TLRPC.TL_inputDialogPeer inputDialogPeer = new TLRPC.TL_inputDialogPeer();
            inputDialogPeer.peer = peer2;
            req.peer = inputDialogPeer;
            if (taskId == 0) {
                NativeByteBuffer data = null;
                try {
                    data = new NativeByteBuffer(peer2.getObjectSize() + 16);
                    data.writeInt32(4);
                    data.writeInt64(did);
                    data.writeBool(pin);
                    peer2.serializeToStream(data);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                newTaskId = getMessagesStorage().createPendingTask(data);
            } else {
                newTaskId = taskId;
            }
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$oywEgKBY-W-hkaSOHxKQ2zw4Hjs
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$pinDialog$244$MessagesController(newTaskId, tLObject, tL_error);
                }
            });
        }
        getMessagesStorage().setDialogPinned(did, dialog.pinnedNum);
        return true;
    }

    public /* synthetic */ void lambda$pinDialog$244$MessagesController(long newTaskId, TLObject response, TLRPC.TL_error error) {
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public void loadPinnedDialogs(final int folderId, long newDialogId, ArrayList<Long> order) {
        if (this.loadingPinnedDialogs.indexOfKey(folderId) >= 0 || getUserConfig().isPinnedDialogsLoaded(folderId)) {
            return;
        }
        this.loadingPinnedDialogs.put(folderId, 1);
        TLRPC.TL_messages_getPinnedDialogs req = new TLRPC.TL_messages_getPinnedDialogs();
        req.folder_id = folderId;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$uQcc0r2W6qfuR1tgdYA_VudNYqU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPinnedDialogs$247$MessagesController(folderId, tLObject, tL_error);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00ba  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0126  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadPinnedDialogs$247$MessagesController(final int r17, im.uwrkaxlmjj.tgnet.TLObject r18, im.uwrkaxlmjj.tgnet.TLRPC.TL_error r19) {
        /*
            Method dump skipped, instruction units count: 443
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.lambda$loadPinnedDialogs$247$MessagesController(int, im.uwrkaxlmjj.tgnet.TLObject, im.uwrkaxlmjj.tgnet.TLRPC$TL_error):void");
    }

    public /* synthetic */ void lambda$null$246$MessagesController(final int folderId, final ArrayList newPinnedDialogs, final boolean firstIsFolder, final TLRPC.TL_messages_peerDialogs res, final LongSparseArray new_dialogMessage, final TLRPC.TL_messages_dialogs toCache) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$NdTZjga4uDz4fZ5NKfbRlWlgRWM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$245$MessagesController(folderId, newPinnedDialogs, firstIsFolder, res, new_dialogMessage, toCache);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r18v0, types: [im.uwrkaxlmjj.messenger.MessagesController] */
    /* JADX WARN: Type inference failed for: r2v0, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r2v11, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r2v23 */
    /* JADX WARN: Type inference failed for: r2v24 */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1, types: [int] */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v3, types: [int] */
    /* JADX WARN: Type inference failed for: r8v4, types: [int] */
    /* JADX WARN: Type inference failed for: r8v5 */
    public /* synthetic */ void lambda$null$245$MessagesController(int i, ArrayList arrayList, boolean z, TLRPC.TL_messages_peerDialogs tL_messages_peerDialogs, LongSparseArray longSparseArray, TLRPC.TL_messages_dialogs tL_messages_dialogs) {
        ?? r2 = arrayList;
        this.loadingPinnedDialogs.delete(i);
        applyDialogsNotificationsSettings(r2);
        boolean z2 = false;
        boolean z3 = false;
        int iMax = 0;
        ArrayList<TLRPC.Dialog> dialogs = getDialogs(i);
        ?? r8 = z;
        int i2 = 0;
        while (i2 < dialogs.size()) {
            TLRPC.Dialog dialog = dialogs.get(i2);
            if (!(dialog instanceof TLRPC.TL_dialogFolder)) {
                if (((int) dialog.id) == 0) {
                    if (r8 < arrayList.size()) {
                        r2.add(r8, dialog);
                    } else {
                        r2.add(dialog);
                    }
                    r8++;
                } else {
                    if (!dialog.pinned) {
                        break;
                    }
                    iMax = Math.max(dialog.pinnedNum, iMax);
                    dialog.pinned = false;
                    dialog.pinnedNum = 0;
                    z2 = true;
                    r8++;
                }
            }
            i2++;
            r8 = r8;
        }
        ArrayList<Long> arrayList2 = new ArrayList<>();
        if (!arrayList.isEmpty()) {
            putUsers(tL_messages_peerDialogs.users, false);
            putChats(tL_messages_peerDialogs.chats, false);
            int i3 = 0;
            int size = arrayList.size();
            ?? r22 = r2;
            while (i3 < size) {
                TLRPC.Dialog dialog2 = (TLRPC.Dialog) r22.get(i3);
                dialog2.pinnedNum = (size - i3) + iMax;
                arrayList2.add(Long.valueOf(dialog2.id));
                TLRPC.Dialog dialog3 = this.dialogs_dict.get(dialog2.id);
                if (dialog3 != null) {
                    dialog3.pinned = true;
                    dialog3.pinnedNum = dialog2.pinnedNum;
                    getMessagesStorage().setDialogPinned(dialog2.id, dialog2.pinnedNum);
                } else {
                    z3 = true;
                    this.dialogs_dict.put(dialog2.id, dialog2);
                    MessageObject messageObject = (MessageObject) longSparseArray.get(dialog2.id);
                    this.dialogMessage.put(dialog2.id, messageObject);
                    if (messageObject != null && messageObject.messageOwner.to_id.channel_id == 0) {
                        this.dialogMessagesByIds.put(messageObject.getId(), messageObject);
                        if (messageObject.messageOwner.random_id != 0) {
                            this.dialogMessagesByRandomIds.put(messageObject.messageOwner.random_id, messageObject);
                        }
                    }
                }
                z2 = true;
                i3++;
                r22 = arrayList;
            }
        }
        if (z2) {
            if (z3) {
                this.allDialogs.clear();
                int size2 = this.dialogs_dict.size();
                for (int i4 = 0; i4 < size2; i4++) {
                    this.allDialogs.add(this.dialogs_dict.valueAt(i4));
                }
            }
            sortDialogs(null);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        }
        getMessagesStorage().unpinAllDialogsExceptNew(arrayList2, i);
        getMessagesStorage().putDialogs(tL_messages_dialogs, 1);
        getUserConfig().setPinnedDialogsLoaded(i, true);
        getUserConfig().saveConfig(false);
    }

    public void generateJoinMessage(final int chat_id, boolean ignoreLeft) {
        TLRPC.Chat chat = getChat(Integer.valueOf(chat_id));
        if (chat == null || !ChatObject.isChannel(chat_id, this.currentAccount)) {
            return;
        }
        if ((chat.left || chat.kicked) && !ignoreLeft) {
            return;
        }
        TLRPC.TL_messageService message = new TLRPC.TL_messageService();
        message.flags = 256;
        int newMessageId = getUserConfig().getNewMessageId();
        message.id = newMessageId;
        message.local_id = newMessageId;
        message.date = getConnectionsManager().getCurrentTime();
        message.from_id = getUserConfig().getClientUserId();
        message.to_id = new TLRPC.TL_peerChannel();
        message.to_id.channel_id = chat_id;
        message.dialog_id = -chat_id;
        message.post = true;
        message.action = new TLRPC.TL_messageActionChatAddUser();
        message.action.users.add(Integer.valueOf(getUserConfig().getClientUserId()));
        if (chat.megagroup) {
            message.flags |= Integer.MIN_VALUE;
        }
        getUserConfig().saveConfig(false);
        final ArrayList<MessageObject> pushMessages = new ArrayList<>();
        ArrayList<TLRPC.Message> messagesArr = new ArrayList<>();
        messagesArr.add(message);
        MessageObject obj = new MessageObject(this.currentAccount, message, true);
        pushMessages.add(obj);
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$9YCXpR3awOEBHBM1OBumIT9higo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$generateJoinMessage$249$MessagesController(pushMessages);
            }
        });
        getMessagesStorage().putMessages(messagesArr, true, true, false, 0, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$EekQap-3BPjEbU6ctWlX4SGWPkc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$generateJoinMessage$250$MessagesController(chat_id, pushMessages);
            }
        });
    }

    public /* synthetic */ void lambda$generateJoinMessage$249$MessagesController(final ArrayList pushMessages) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$mKTV5HcGOpp2WN-36d_r358tcMY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$248$MessagesController(pushMessages);
            }
        });
    }

    public /* synthetic */ void lambda$null$248$MessagesController(ArrayList pushMessages) {
        getNotificationsController().processNewMessages(pushMessages, true, false, null);
    }

    public /* synthetic */ void lambda$generateJoinMessage$250$MessagesController(int chat_id, ArrayList pushMessages) {
        updateInterfaceWithMessages(-chat_id, pushMessages, false);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    protected void deleteMessagesByPush(final long dialogId, final ArrayList<Integer> ids, final int channelId) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$ynz-Vtgrwno9hJU2NnNNU-TaUWM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deleteMessagesByPush$252$MessagesController(ids, channelId, dialogId);
            }
        });
    }

    public /* synthetic */ void lambda$deleteMessagesByPush$252$MessagesController(final ArrayList ids, final int channelId, long dialogId) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Gmp9M7I4OW4i3w8LBIgYV3W7Z5k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$251$MessagesController(ids, channelId);
            }
        });
        getMessagesStorage().deletePushMessages(dialogId, ids);
        ArrayList<Long> dialogIds = getMessagesStorage().markMessagesAsDeleted(ids, false, channelId, true, false);
        getMessagesStorage().updateDialogsWithDeletedMessages(ids, dialogIds, false, channelId);
    }

    public /* synthetic */ void lambda$null$251$MessagesController(ArrayList ids, int channelId) {
        getNotificationCenter().postNotificationName(NotificationCenter.messagesDeleted, ids, Integer.valueOf(channelId), false);
        if (channelId == 0) {
            int size2 = ids.size();
            for (int b = 0; b < size2; b++) {
                Integer id = (Integer) ids.get(b);
                MessageObject obj = this.dialogMessagesByIds.get(id.intValue());
                if (obj != null) {
                    obj.deleted = true;
                }
            }
            return;
        }
        MessageObject obj2 = this.dialogMessage.get(-channelId);
        if (obj2 != null) {
            int size22 = ids.size();
            for (int b2 = 0; b2 < size22; b2++) {
                if (obj2.getId() == ((Integer) ids.get(b2)).intValue()) {
                    obj2.deleted = true;
                    return;
                }
            }
        }
    }

    public void checkChannelInviter(final int chat_id) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$uYTNfJW-Dzniz4-tLWoNjcIP3dg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkChannelInviter$258$MessagesController(chat_id);
            }
        });
    }

    public /* synthetic */ void lambda$checkChannelInviter$258$MessagesController(final int chat_id) {
        final TLRPC.Chat chat = getChat(Integer.valueOf(chat_id));
        if (chat == null || !ChatObject.isChannel(chat_id, this.currentAccount) || chat.creator) {
            return;
        }
        TLRPC.TL_channels_getParticipant req = new TLRPC.TL_channels_getParticipant();
        req.channel = getInputChannel(chat_id);
        req.user_id = new TLRPC.TL_inputUserSelf();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$4fM15G2ZmQnLQJ34q8Rbtku5mns
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$257$MessagesController(chat, chat_id, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$257$MessagesController(TLRPC.Chat chat, final int chat_id, TLObject response, TLRPC.TL_error error) {
        final TLRPC.TL_channels_channelParticipant res = (TLRPC.TL_channels_channelParticipant) response;
        if (res != null && (res.participant instanceof TLRPC.TL_channelParticipantSelf) && res.participant.inviter_id != getUserConfig().getClientUserId()) {
            if (!chat.megagroup || !getMessagesStorage().isMigratedChat(chat.id)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$CZLfT2CxvJ1LpzAb2vhhdX6zoEU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$253$MessagesController(res);
                    }
                });
                getMessagesStorage().putUsersAndChats(res.users, null, true, true);
                TLRPC.TL_messageService message = new TLRPC.TL_messageService();
                message.media_unread = true;
                message.unread = true;
                message.flags = 256;
                message.post = true;
                if (chat.megagroup) {
                    message.flags |= Integer.MIN_VALUE;
                }
                int newMessageId = getUserConfig().getNewMessageId();
                message.id = newMessageId;
                message.local_id = newMessageId;
                message.date = res.participant.date;
                message.action = new TLRPC.TL_messageActionChatAddUser();
                message.from_id = res.participant.inviter_id;
                message.action.users.add(Integer.valueOf(getUserConfig().getClientUserId()));
                message.to_id = new TLRPC.TL_peerChannel();
                message.to_id.channel_id = chat_id;
                message.dialog_id = -chat_id;
                getUserConfig().saveConfig(false);
                final ArrayList<MessageObject> pushMessages = new ArrayList<>();
                ArrayList<TLRPC.Message> messagesArr = new ArrayList<>();
                ConcurrentHashMap<Integer, TLRPC.User> usersDict = new ConcurrentHashMap<>();
                for (int a = 0; a < res.users.size(); a++) {
                    TLRPC.User user = res.users.get(a);
                    usersDict.put(Integer.valueOf(user.id), user);
                }
                messagesArr.add(message);
                MessageObject obj = new MessageObject(this.currentAccount, (TLRPC.Message) message, (AbstractMap<Integer, TLRPC.User>) usersDict, true);
                pushMessages.add(obj);
                getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kZB0nsv0b0TKgGGUmvKiFQofIYw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$255$MessagesController(pushMessages);
                    }
                });
                getMessagesStorage().putMessages(messagesArr, true, true, false, 0, false);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$sky4Z88dg73seE8m7mO7MQ_02a8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$256$MessagesController(chat_id, pushMessages);
                    }
                });
            }
        }
    }

    public /* synthetic */ void lambda$null$253$MessagesController(TLRPC.TL_channels_channelParticipant res) {
        putUsers(res.users, false);
    }

    public /* synthetic */ void lambda$null$254$MessagesController(ArrayList pushMessages) {
        getNotificationsController().processNewMessages(pushMessages, true, false, null);
    }

    public /* synthetic */ void lambda$null$255$MessagesController(final ArrayList pushMessages) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$Ku_A2_ZUQX2RrP5hUxWYc61sBLg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$254$MessagesController(pushMessages);
            }
        });
    }

    public /* synthetic */ void lambda$null$256$MessagesController(int chat_id, ArrayList pushMessages) {
        updateInterfaceWithMessages(-chat_id, pushMessages, false);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    private int getUpdateType(TLRPC.Update update) {
        if ((update instanceof TLRPC.TL_updateNewMessage) || (update instanceof TLRPC.TL_updateReadMessagesContents) || (update instanceof TLRPC.TL_updateReadHistoryInbox) || (update instanceof TLRPC.TL_updateReadHistoryOutbox) || (update instanceof TLRPC.TL_updateDeleteMessages) || (update instanceof TLRPC.TL_updateWebPage) || (update instanceof TLRPC.TL_updateEditMessage) || (update instanceof TLRPC.TL_updateFolderPeers)) {
            return 0;
        }
        if (update instanceof TLRPC.TL_updateNewEncryptedMessage) {
            return 1;
        }
        if ((update instanceof TLRPC.TL_updateNewChannelMessage) || (update instanceof TLRPC.TL_updateDeleteChannelMessages) || (update instanceof TLRPC.TL_updateEditChannelMessage) || (update instanceof TLRPC.TL_updateChannelWebPage)) {
            return 2;
        }
        return 3;
    }

    private static int getUpdatePts(TLRPC.Update update) {
        if (update instanceof TLRPC.TL_updateDeleteMessages) {
            return ((TLRPC.TL_updateDeleteMessages) update).pts;
        }
        if (update instanceof TLRPC.TL_updateNewChannelMessage) {
            return ((TLRPC.TL_updateNewChannelMessage) update).pts;
        }
        if (update instanceof TLRPC.TL_updateReadHistoryOutbox) {
            return ((TLRPC.TL_updateReadHistoryOutbox) update).pts;
        }
        if (update instanceof TLRPC.TL_updateNewMessage) {
            return ((TLRPC.TL_updateNewMessage) update).pts;
        }
        if (update instanceof TLRPC.TL_updateEditMessage) {
            return ((TLRPC.TL_updateEditMessage) update).pts;
        }
        if (update instanceof TLRPC.TL_updateWebPage) {
            return ((TLRPC.TL_updateWebPage) update).pts;
        }
        if (update instanceof TLRPC.TL_updateReadHistoryInbox) {
            return ((TLRPC.TL_updateReadHistoryInbox) update).pts;
        }
        if (update instanceof TLRPC.TL_updateChannelWebPage) {
            return ((TLRPC.TL_updateChannelWebPage) update).pts;
        }
        if (update instanceof TLRPC.TL_updateDeleteChannelMessages) {
            return ((TLRPC.TL_updateDeleteChannelMessages) update).pts;
        }
        if (update instanceof TLRPC.TL_updateEditChannelMessage) {
            return ((TLRPC.TL_updateEditChannelMessage) update).pts;
        }
        if (update instanceof TLRPC.TL_updateReadMessagesContents) {
            return ((TLRPC.TL_updateReadMessagesContents) update).pts;
        }
        if (update instanceof TLRPC.TL_updateChannelTooLong) {
            return ((TLRPC.TL_updateChannelTooLong) update).pts;
        }
        if (update instanceof TLRPC.TL_updateFolderPeers) {
            return ((TLRPC.TL_updateFolderPeers) update).pts;
        }
        return 0;
    }

    private static int getUpdatePtsCount(TLRPC.Update update) {
        if (update instanceof TLRPC.TL_updateDeleteMessages) {
            return ((TLRPC.TL_updateDeleteMessages) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateNewChannelMessage) {
            return ((TLRPC.TL_updateNewChannelMessage) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateReadHistoryOutbox) {
            return ((TLRPC.TL_updateReadHistoryOutbox) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateNewMessage) {
            return ((TLRPC.TL_updateNewMessage) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateEditMessage) {
            return ((TLRPC.TL_updateEditMessage) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateWebPage) {
            return ((TLRPC.TL_updateWebPage) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateReadHistoryInbox) {
            return ((TLRPC.TL_updateReadHistoryInbox) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateChannelWebPage) {
            return ((TLRPC.TL_updateChannelWebPage) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateDeleteChannelMessages) {
            return ((TLRPC.TL_updateDeleteChannelMessages) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateEditChannelMessage) {
            return ((TLRPC.TL_updateEditChannelMessage) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateReadMessagesContents) {
            return ((TLRPC.TL_updateReadMessagesContents) update).pts_count;
        }
        if (update instanceof TLRPC.TL_updateFolderPeers) {
            return ((TLRPC.TL_updateFolderPeers) update).pts_count;
        }
        return 0;
    }

    private static int getUpdateQts(TLRPC.Update update) {
        if (update instanceof TLRPC.TL_updateNewEncryptedMessage) {
            return ((TLRPC.TL_updateNewEncryptedMessage) update).qts;
        }
        return 0;
    }

    private static int getUpdateChannelId(TLRPC.Update update) {
        if (update instanceof TLRPC.TL_updateNewChannelMessage) {
            return ((TLRPC.TL_updateNewChannelMessage) update).message.to_id.channel_id;
        }
        if (update instanceof TLRPC.TL_updateEditChannelMessage) {
            return ((TLRPC.TL_updateEditChannelMessage) update).message.to_id.channel_id;
        }
        if (update instanceof TLRPC.TL_updateReadChannelOutbox) {
            return ((TLRPC.TL_updateReadChannelOutbox) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannelMessageViews) {
            return ((TLRPC.TL_updateChannelMessageViews) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannelTooLong) {
            return ((TLRPC.TL_updateChannelTooLong) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannelPinnedMessage) {
            return ((TLRPC.TL_updateChannelPinnedMessage) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannelReadMessagesContents) {
            return ((TLRPC.TL_updateChannelReadMessagesContents) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannelAvailableMessages) {
            return ((TLRPC.TL_updateChannelAvailableMessages) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannel) {
            return ((TLRPC.TL_updateChannel) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateChannelWebPage) {
            return ((TLRPC.TL_updateChannelWebPage) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateDeleteChannelMessages) {
            return ((TLRPC.TL_updateDeleteChannelMessages) update).channel_id;
        }
        if (update instanceof TLRPC.TL_updateReadChannelInbox) {
            return ((TLRPC.TL_updateReadChannelInbox) update).channel_id;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.e("trying to get unknown update channel_id for " + update);
            return 0;
        }
        return 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:128:0x02ce  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void processUpdates(final im.uwrkaxlmjj.tgnet.TLRPC.Updates r34, boolean r35) throws java.lang.Exception {
        /*
            Method dump skipped, instruction units count: 2569
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.processUpdates(im.uwrkaxlmjj.tgnet.TLRPC$Updates, boolean):void");
    }

    public /* synthetic */ void lambda$processUpdates$259$MessagesController(boolean printUpdate, int user_id, ArrayList objArr) {
        if (printUpdate) {
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 64);
        }
        updateInterfaceWithMessages(user_id, objArr, false);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public /* synthetic */ void lambda$processUpdates$260$MessagesController(boolean printUpdate, TLRPC.Updates updates, ArrayList objArr) {
        if (printUpdate) {
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 64);
        }
        updateInterfaceWithMessages(-updates.chat_id, objArr, false);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public /* synthetic */ void lambda$null$261$MessagesController(ArrayList objArr) {
        getNotificationsController().processNewMessages(objArr, true, false, null);
    }

    public /* synthetic */ void lambda$processUpdates$262$MessagesController(final ArrayList objArr) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$F4gp_k6THBvmNJLhtbO9ocJKYkw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$261$MessagesController(objArr);
            }
        });
    }

    static /* synthetic */ void lambda$processUpdates$263(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ void lambda$processUpdates$264$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, 4);
    }

    public void ensureMessagesLoaded(final long dialog_id, boolean isChannel, int messageId, final Runnable callback) {
        int messageId2;
        SharedPreferences sharedPreferences = getNotificationsSettings(this.currentAccount);
        if (messageId == 0) {
            messageId2 = sharedPreferences.getInt("diditem" + dialog_id, 0);
        } else {
            messageId2 = messageId;
        }
        int finalMessageId = messageId2;
        final int classGuid = ConnectionsManager.generateClassGuid();
        getNotificationCenter().addObserver(new NotificationCenter.NotificationCenterDelegate() { // from class: im.uwrkaxlmjj.messenger.MessagesController.1
            @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
            public void didReceivedNotification(int id, int account, Object... args) {
                if (id == NotificationCenter.messagesDidLoad && ((Integer) args[10]).intValue() == classGuid) {
                    ArrayList<MessageObject> messArr = (ArrayList) args[2];
                    boolean isCache = ((Boolean) args[3]).booleanValue();
                    if (!messArr.isEmpty() || !isCache) {
                        MessagesController.this.getNotificationCenter().removeObserver(this, NotificationCenter.didReceiveNewMessages);
                        callback.run();
                    } else {
                        MessagesController.this.loadMessages(dialog_id, 20, 3, 0, false, 0, classGuid, 3, 0, false, false, 0);
                    }
                }
            }
        }, NotificationCenter.messagesDidLoad);
        loadMessages(dialog_id, 1, finalMessageId, 0, true, 0, classGuid, 3, 0, false, false, 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:1044:0x19bd  */
    /* JADX WARN: Removed duplicated region for block: B:1047:0x19d0  */
    /* JADX WARN: Removed duplicated region for block: B:1051:0x1a15  */
    /* JADX WARN: Removed duplicated region for block: B:1054:0x1a21  */
    /* JADX WARN: Removed duplicated region for block: B:1058:0x1a4f  */
    /* JADX WARN: Removed duplicated region for block: B:1061:0x1a55  */
    /* JADX WARN: Removed duplicated region for block: B:1065:0x1a84  */
    /* JADX WARN: Removed duplicated region for block: B:1067:0x1a88  */
    /* JADX WARN: Removed duplicated region for block: B:1082:0x11e2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:1151:0x11e8 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:1166:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:608:0x0fc2  */
    /* JADX WARN: Removed duplicated region for block: B:609:0x0fc5  */
    /* JADX WARN: Removed duplicated region for block: B:696:0x11cd  */
    /* JADX WARN: Removed duplicated region for block: B:912:0x162b  */
    /* JADX WARN: Removed duplicated region for block: B:913:0x1634  */
    /* JADX WARN: Removed duplicated region for block: B:924:0x1662  */
    /* JADX WARN: Removed duplicated region for block: B:935:0x16bf  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean processUpdateArray(java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.Update> r62, final java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.User> r63, final java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.Chat> r64, boolean r65, int r66) throws java.lang.Exception {
        /*
            Method dump skipped, instruction units count: 6839
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.processUpdateArray(java.util.ArrayList, java.util.ArrayList, java.util.ArrayList, boolean, int):boolean");
    }

    public /* synthetic */ void lambda$processUpdateArray$265$MessagesController(ArrayList usersArr, ArrayList chatsArr) {
        putUsers(usersArr, false);
        putChats(chatsArr, false);
    }

    public /* synthetic */ void lambda$processUpdateArray$266$MessagesController(ArrayList usersArr, ArrayList chatsArr) {
        putUsers(usersArr, false);
        putChats(chatsArr, false);
    }

    public /* synthetic */ void lambda$processUpdateArray$268$MessagesController(final TLRPC.TL_updateUserBlocked finalUpdate) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$hOa-vpgKAyoCrqJpMSlVhdoKlPY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$267$MessagesController(finalUpdate);
            }
        });
    }

    public /* synthetic */ void lambda$null$267$MessagesController(TLRPC.TL_updateUserBlocked finalUpdate) {
        if (finalUpdate.blocked) {
            if (this.blockedUsers.indexOfKey(finalUpdate.user_id) < 0) {
                this.blockedUsers.put(finalUpdate.user_id, 1);
            }
        } else {
            this.blockedUsers.delete(finalUpdate.user_id);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.blockedUsersDidLoad, new Object[0]);
    }

    public /* synthetic */ void lambda$processUpdateArray$269$MessagesController(TLRPC.TL_updateServiceNotification update) {
        getNotificationCenter().postNotificationName(NotificationCenter.needShowAlert, 2, update.message, update.type);
    }

    public /* synthetic */ void lambda$processUpdateArray$270$MessagesController(TLRPC.Message message) {
        getNotificationCenter().postNotificationName(NotificationCenter.livestatechange, message.media);
    }

    public /* synthetic */ void lambda$processUpdateArray$271$MessagesController(TLRPC.TL_updateLangPack update) {
        LocaleController.getInstance().saveRemoteLocaleStringsForCurrentLocale(update.difference, this.currentAccount);
    }

    public /* synthetic */ void lambda$processUpdateArray$272$MessagesController(TLRPC.TL_updateUserMomentStateV1 userMomentStateV1) {
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.userFriendsCircleUpdate, userMomentStateV1);
    }

    public /* synthetic */ void lambda$processUpdateArray$276$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, 0);
    }

    public /* synthetic */ void lambda$processUpdateArray$279$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.groupingChanged, new Object[0]);
    }

    public /* synthetic */ void lambda$null$280$MessagesController(ArrayList pushMessagesFinal) {
        getNotificationsController().processNewMessages(pushMessagesFinal, true, false, null);
    }

    public /* synthetic */ void lambda$processUpdateArray$281$MessagesController(final ArrayList pushMessagesFinal) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$uaNwKtm1NeBjvarv2HBjf43f9Lg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$280$MessagesController(pushMessagesFinal);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:418:0x0a06  */
    /* JADX WARN: Removed duplicated region for block: B:423:0x0a3f  */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v105 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$processUpdateArray$286$MessagesController(int r32, java.util.ArrayList r33, android.util.LongSparseArray r34, android.util.LongSparseArray r35, android.util.LongSparseArray r36, android.util.LongSparseArray r37, boolean r38, java.util.ArrayList r39, java.util.ArrayList r40, android.util.SparseArray r41) throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 3023
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.lambda$processUpdateArray$286$MessagesController(int, java.util.ArrayList, android.util.LongSparseArray, android.util.LongSparseArray, android.util.LongSparseArray, android.util.LongSparseArray, boolean, java.util.ArrayList, java.util.ArrayList, android.util.SparseArray):void");
    }

    public /* synthetic */ void lambda$null$282$MessagesController(TLRPC.User currentUser) {
        getContactsController().addContactToPhoneBook(currentUser, true);
    }

    public /* synthetic */ void lambda$null$283$MessagesController(TLRPC.TL_updateChannel update) {
        getChannelDifference(update.channel_id, 1, 0L, null);
    }

    public /* synthetic */ void lambda$null$284$MessagesController(TLRPC.Chat chat) {
        getNotificationCenter().postNotificationName(NotificationCenter.channelRightsUpdated, chat);
    }

    public /* synthetic */ void lambda$null$285$MessagesController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (response != null) {
            TLRPC.Updates updates1 = (TLRPC.Updates) response;
            processUpdates(updates1, false);
        }
    }

    public /* synthetic */ void lambda$processUpdateArray$288$MessagesController(final SparseLongArray markAsReadMessagesInboxFinal, final SparseLongArray markAsReadMessagesOutboxFinal, final SparseIntArray markAsReadEncryptedFinal, final ArrayList markAsReadMessagesFinal, final SparseArray deletedMessagesFinal, final SparseArray scheduledDeletedMessagesFinal, final SparseIntArray clearHistoryMessagesFinal) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$jMWZieMLsJYuvoww1fABFpTaxmc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$287$MessagesController(markAsReadMessagesInboxFinal, markAsReadMessagesOutboxFinal, markAsReadEncryptedFinal, markAsReadMessagesFinal, deletedMessagesFinal, scheduledDeletedMessagesFinal, clearHistoryMessagesFinal);
            }
        });
    }

    /* JADX WARN: Type inference failed for: r12v3 */
    /* JADX WARN: Type inference failed for: r12v8 */
    public /* synthetic */ void lambda$null$287$MessagesController(SparseLongArray markAsReadMessagesInboxFinal, SparseLongArray markAsReadMessagesOutboxFinal, SparseIntArray markAsReadEncryptedFinal, ArrayList markAsReadMessagesFinal, SparseArray deletedMessagesFinal, SparseArray scheduledDeletedMessagesFinal, SparseIntArray clearHistoryMessagesFinal) {
        MessageObject obj;
        MessageObject obj2;
        int i;
        MessageObject message;
        SparseLongArray sparseLongArray = markAsReadMessagesInboxFinal;
        int updateMask = 0;
        char c = 2;
        if (sparseLongArray != null || markAsReadMessagesOutboxFinal != null) {
            getNotificationCenter().postNotificationName(NotificationCenter.messagesRead, sparseLongArray, markAsReadMessagesOutboxFinal);
            if (sparseLongArray != null) {
                getNotificationsController().processReadMessages(markAsReadMessagesInboxFinal, 0L, 0, 0, false);
                SharedPreferences.Editor editor = this.notificationsPreferences.edit();
                int b = 0;
                int size = markAsReadMessagesInboxFinal.size();
                while (b < size) {
                    int key = sparseLongArray.keyAt(b);
                    int messageId = (int) sparseLongArray.valueAt(b);
                    TLRPC.Dialog dialog = this.dialogs_dict.get(key);
                    if (dialog != null && dialog.top_message > 0 && dialog.top_message <= messageId && (obj2 = this.dialogMessage.get(dialog.id)) != null && !obj2.isOut()) {
                        obj2.setIsRead();
                        updateMask |= 256;
                    }
                    if (key != getUserConfig().getClientUserId()) {
                        editor.remove("diditem" + key);
                        editor.remove("diditemo" + key);
                    }
                    b++;
                    sparseLongArray = markAsReadMessagesInboxFinal;
                }
                editor.commit();
            }
            if (markAsReadMessagesOutboxFinal != null) {
                int size2 = markAsReadMessagesOutboxFinal.size();
                for (int b2 = 0; b2 < size2; b2++) {
                    int key2 = markAsReadMessagesOutboxFinal.keyAt(b2);
                    int messageId2 = (int) markAsReadMessagesOutboxFinal.valueAt(b2);
                    TLRPC.Dialog dialog2 = this.dialogs_dict.get(key2);
                    if (dialog2 != null && dialog2.top_message > 0 && dialog2.top_message <= messageId2 && (obj = this.dialogMessage.get(dialog2.id)) != null && obj.isOut()) {
                        obj.setIsRead();
                        updateMask |= 256;
                    }
                }
            }
        }
        if (markAsReadEncryptedFinal == null) {
            i = 1;
        } else {
            int size3 = markAsReadEncryptedFinal.size();
            for (int a = 0; a < size3; a++) {
                int key3 = markAsReadEncryptedFinal.keyAt(a);
                int value = markAsReadEncryptedFinal.valueAt(a);
                getNotificationCenter().postNotificationName(NotificationCenter.messagesReadEncrypted, Integer.valueOf(key3), Integer.valueOf(value));
                long dialog_id = ((long) key3) << 32;
                if (this.dialogs_dict.get(dialog_id) != null && (message = this.dialogMessage.get(dialog_id)) != null && message.messageOwner.date <= value) {
                    message.setIsRead();
                    updateMask |= 256;
                }
            }
            i = 1;
        }
        if (markAsReadMessagesFinal != null) {
            NotificationCenter notificationCenter = getNotificationCenter();
            int i2 = NotificationCenter.messagesReadContent;
            Object[] objArr = new Object[i];
            objArr[0] = markAsReadMessagesFinal;
            notificationCenter.postNotificationName(i2, objArr);
        }
        if (deletedMessagesFinal != null) {
            int a2 = 0;
            int size4 = deletedMessagesFinal.size();
            while (a2 < size4) {
                int key4 = deletedMessagesFinal.keyAt(a2);
                ArrayList<Integer> arrayList = (ArrayList) deletedMessagesFinal.valueAt(a2);
                if (arrayList != null) {
                    NotificationCenter notificationCenter2 = getNotificationCenter();
                    int i3 = NotificationCenter.messagesDeleted;
                    Object[] objArr2 = new Object[3];
                    objArr2[0] = arrayList;
                    objArr2[i] = Integer.valueOf(key4);
                    objArr2[c] = false;
                    notificationCenter2.postNotificationName(i3, objArr2);
                    if (key4 == 0) {
                        int size22 = arrayList.size();
                        for (int b3 = 0; b3 < size22; b3++) {
                            MessageObject obj3 = this.dialogMessagesByIds.get(arrayList.get(b3).intValue());
                            if (obj3 != null) {
                                obj3.deleted = i;
                            }
                        }
                    } else {
                        MessageObject obj4 = this.dialogMessage.get(-key4);
                        if (obj4 != null) {
                            int b4 = 0;
                            int size23 = arrayList.size();
                            while (true) {
                                if (b4 >= size23) {
                                    break;
                                }
                                if (obj4.getId() != arrayList.get(b4).intValue()) {
                                    b4++;
                                } else {
                                    obj4.deleted = i;
                                    break;
                                }
                            }
                        }
                    }
                }
                a2++;
                c = 2;
            }
            getNotificationsController().removeDeletedMessagesFromNotifications(deletedMessagesFinal);
        }
        if (scheduledDeletedMessagesFinal != null) {
            int size5 = scheduledDeletedMessagesFinal.size();
            for (int a3 = 0; a3 < size5; a3++) {
                int key5 = scheduledDeletedMessagesFinal.keyAt(a3);
                ArrayList<Integer> arrayList2 = (ArrayList) scheduledDeletedMessagesFinal.valueAt(a3);
                if (arrayList2 != null) {
                    NotificationCenter notificationCenter3 = NotificationCenter.getInstance(this.currentAccount);
                    int i4 = NotificationCenter.messagesDeleted;
                    Object[] objArr3 = new Object[3];
                    objArr3[0] = arrayList2;
                    objArr3[i] = Integer.valueOf(key5);
                    objArr3[2] = Boolean.valueOf((boolean) i);
                    notificationCenter3.postNotificationName(i4, objArr3);
                }
            }
        }
        if (clearHistoryMessagesFinal != null) {
            int a4 = 0;
            int size6 = clearHistoryMessagesFinal.size();
            while (true) {
                if (a4 >= size6) {
                    break;
                }
                int key6 = clearHistoryMessagesFinal.keyAt(a4);
                int id = clearHistoryMessagesFinal.valueAt(a4);
                long did = -key6;
                getNotificationCenter().postNotificationName(NotificationCenter.historyCleared, Long.valueOf(did), Integer.valueOf(id));
                MessageObject obj5 = this.dialogMessage.get(did);
                if (obj5 == null || obj5.getId() > id) {
                    a4++;
                } else {
                    obj5.deleted = true;
                    break;
                }
            }
            getNotificationsController().removeDeletedHisoryFromNotifications(clearHistoryMessagesFinal);
        }
        if (updateMask != 0) {
            getNotificationCenter().postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(updateMask));
        }
    }

    public /* synthetic */ void lambda$processUpdateArray$289$MessagesController(ArrayList arrayList, int key) {
        ArrayList<Long> dialogIds = getMessagesStorage().markMessagesAsDeleted(arrayList, false, key, true, false);
        getMessagesStorage().updateDialogsWithDeletedMessages(arrayList, dialogIds, false, key);
    }

    public /* synthetic */ void lambda$processUpdateArray$290$MessagesController(int key, int id) {
        ArrayList<Long> dialogIds = getMessagesStorage().markMessagesAsDeleted(key, id, false, true);
        getMessagesStorage().updateDialogsWithDeletedMessages(new ArrayList<>(), dialogIds, false, key);
    }

    public boolean isDialogMuted(long dialog_id) {
        int mute_type = this.notificationsPreferences.getInt("notify2_" + dialog_id, -1);
        if (mute_type == -1) {
            return true ^ getNotificationsController().isGlobalNotificationsEnabled(dialog_id);
        }
        if (mute_type == 2) {
            return true;
        }
        if (mute_type == 3) {
            int mute_until = this.notificationsPreferences.getInt("notifyuntil_" + dialog_id, 0);
            if (mute_until >= getConnectionsManager().getCurrentTime()) {
                return true;
            }
        }
        return false;
    }

    private boolean updatePrintingUsersWithNewMessages(long uid, ArrayList<MessageObject> messages) {
        if (uid > 0) {
            if (this.printingUsers.get(Long.valueOf(uid)) != null) {
                this.printingUsers.remove(Long.valueOf(uid));
                return true;
            }
            return false;
        }
        if (uid < 0) {
            ArrayList<Integer> messagesUsers = new ArrayList<>();
            for (MessageObject message : messages) {
                if (!messagesUsers.contains(Integer.valueOf(message.messageOwner.from_id))) {
                    messagesUsers.add(Integer.valueOf(message.messageOwner.from_id));
                }
            }
            ArrayList<PrintingUser> arr = this.printingUsers.get(Long.valueOf(uid));
            boolean changed = false;
            if (arr != null) {
                int a = 0;
                while (a < arr.size()) {
                    PrintingUser user = arr.get(a);
                    if (messagesUsers.contains(Integer.valueOf(user.userId))) {
                        arr.remove(a);
                        a--;
                        if (arr.isEmpty()) {
                            this.printingUsers.remove(Long.valueOf(uid));
                        }
                        changed = true;
                    }
                    a++;
                }
            }
            return changed;
        }
        return false;
    }

    protected void updateInterfaceWithMessages(final long j, ArrayList<MessageObject> arrayList, boolean z) {
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        boolean z2 = ((int) j) == 0;
        MessageObject messageObject = null;
        int i = 0;
        boolean z3 = false;
        boolean z4 = false;
        if (!z) {
            for (int i2 = 0; i2 < arrayList.size(); i2++) {
                MessageObject messageObject2 = arrayList.get(i2);
                if (messageObject == null || ((!z2 && messageObject2.getId() > messageObject.getId()) || (((z2 || (messageObject2.getId() < 0 && messageObject.getId() < 0)) && messageObject2.getId() < messageObject.getId()) || messageObject2.messageOwner.date > messageObject.messageOwner.date))) {
                    messageObject = messageObject2;
                    if (messageObject2.messageOwner.to_id.channel_id != 0) {
                        i = messageObject2.messageOwner.to_id.channel_id;
                    }
                }
                if (!z4 && !messageObject2.isOut()) {
                    z4 = true;
                }
                if (messageObject2.isOut() && !messageObject2.isSending() && !messageObject2.isForwarded()) {
                    if (messageObject2.isNewGif()) {
                        getMediaDataController().addRecentGif(messageObject2.messageOwner.media.document, messageObject2.messageOwner.date);
                    } else if (!messageObject2.isAnimatedEmoji() && (messageObject2.isSticker() || messageObject2.isAnimatedSticker())) {
                        getMediaDataController().addRecentSticker(0, messageObject2, messageObject2.messageOwner.media.document, messageObject2.messageOwner.date, false);
                    }
                }
                if (messageObject2.isOut() && messageObject2.isSent()) {
                    z3 = true;
                }
            }
        }
        getMediaDataController().loadReplyMessagesForMessages(arrayList, j, z);
        getNotificationCenter().postNotificationName(NotificationCenter.didReceiveNewMessages, Long.valueOf(j), arrayList, Boolean.valueOf(z));
        if (messageObject == null || z) {
            return;
        }
        TLRPC.TL_dialog tL_dialog = (TLRPC.TL_dialog) this.dialogs_dict.get(j);
        if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionChatMigrateTo) {
            if (tL_dialog != null) {
                this.allDialogs.remove(tL_dialog);
                this.dialogsServerOnly.remove(tL_dialog);
                this.dialogsCanAddUsers.remove(tL_dialog);
                this.dialogsChannelsOnly.remove(tL_dialog);
                this.dialogsGroupsOnly.remove(tL_dialog);
                this.dialogsUnreadOnly.remove(tL_dialog);
                this.dialogsUsersOnly.remove(tL_dialog);
                this.dialogsForward.remove(tL_dialog);
                this.dialogs_dict.remove(tL_dialog.id);
                this.dialogs_read_inbox_max.remove(Long.valueOf(tL_dialog.id));
                this.dialogs_read_outbox_max.remove(Long.valueOf(tL_dialog.id));
                int i3 = this.nextDialogsCacheOffset.get(tL_dialog.folder_id, 0);
                if (i3 > 0) {
                    this.nextDialogsCacheOffset.put(tL_dialog.folder_id, i3 - 1);
                }
                this.dialogMessage.remove(tL_dialog.id);
                ArrayList<TLRPC.Dialog> arrayList2 = this.dialogsByFolder.get(tL_dialog.folder_id);
                if (arrayList2 != null) {
                    arrayList2.remove(tL_dialog);
                }
                MessageObject messageObject3 = this.dialogMessagesByIds.get(tL_dialog.top_message);
                this.dialogMessagesByIds.remove(tL_dialog.top_message);
                if (messageObject3 != null && messageObject3.messageOwner.random_id != 0) {
                    this.dialogMessagesByRandomIds.remove(messageObject3.messageOwner.random_id);
                }
                tL_dialog.top_message = 0;
                getNotificationsController().removeNotificationsForDialog(tL_dialog.id);
                getNotificationCenter().postNotificationName(NotificationCenter.needReloadRecentDialogsSearch, new Object[0]);
                return;
            }
            return;
        }
        boolean z5 = false;
        if (tL_dialog == null) {
            TLRPC.Chat chat = getChat(Integer.valueOf(i));
            if (i != 0 && chat == null) {
                return;
            }
            if (chat != null && ChatObject.isNotInChat(chat)) {
                return;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("not found dialog with id " + j + " dictCount = " + this.dialogs_dict.size() + " allCount = " + this.allDialogs.size());
            }
            final TLRPC.TL_dialog tL_dialog2 = new TLRPC.TL_dialog();
            tL_dialog2.id = j;
            tL_dialog2.unread_count = 0;
            tL_dialog2.top_message = messageObject.getId();
            tL_dialog2.last_message_date = messageObject.messageOwner.date;
            tL_dialog2.flags = ChatObject.isChannel(chat) ? 1 : 0;
            this.dialogs_dict.put(j, tL_dialog2);
            this.allDialogs.add(tL_dialog2);
            this.dialogMessage.put(j, messageObject);
            if (messageObject.messageOwner.to_id.channel_id == 0) {
                this.dialogMessagesByIds.put(messageObject.getId(), messageObject);
                if (messageObject.messageOwner.random_id != 0) {
                    this.dialogMessagesByRandomIds.put(messageObject.messageOwner.random_id, messageObject);
                }
            }
            z5 = true;
            getMessagesStorage().getDialogFolderId(j, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$mIhYCUiAMH9k9d_pilPp0g5Ig1A
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i4) {
                    this.f$0.lambda$updateInterfaceWithMessages$291$MessagesController(tL_dialog2, j, i4);
                }
            });
        } else {
            if (z4 && tL_dialog.folder_id == 1 && !isDialogMuted(tL_dialog.id)) {
                tL_dialog.folder_id = 0;
                tL_dialog.pinned = false;
                tL_dialog.pinnedNum = 0;
                getMessagesStorage().setDialogsFolderId(null, null, tL_dialog.id, 0);
                z5 = true;
            }
            if ((tL_dialog.top_message > 0 && messageObject.getId() > 0 && messageObject.getId() > tL_dialog.top_message) || ((tL_dialog.top_message < 0 && messageObject.getId() < 0 && messageObject.getId() < tL_dialog.top_message) || this.dialogMessage.indexOfKey(j) < 0 || tL_dialog.top_message < 0 || tL_dialog.last_message_date <= messageObject.messageOwner.date)) {
                MessageObject messageObject4 = this.dialogMessagesByIds.get(tL_dialog.top_message);
                this.dialogMessagesByIds.remove(tL_dialog.top_message);
                if (messageObject4 != null && messageObject4.messageOwner.random_id != 0) {
                    this.dialogMessagesByRandomIds.remove(messageObject4.messageOwner.random_id);
                }
                tL_dialog.top_message = messageObject.getId();
                tL_dialog.last_message_date = messageObject.messageOwner.date;
                z5 = true;
                this.dialogMessage.put(j, messageObject);
                if (messageObject.messageOwner.to_id.channel_id == 0) {
                    this.dialogMessagesByIds.put(messageObject.getId(), messageObject);
                    if (messageObject.messageOwner.random_id != 0) {
                        this.dialogMessagesByRandomIds.put(messageObject.messageOwner.random_id, messageObject);
                    }
                }
            }
        }
        if (z5) {
            sortDialogs(null);
        }
        if (z3) {
            getMediaDataController().increasePeerRaiting(j);
        }
    }

    public /* synthetic */ void lambda$updateInterfaceWithMessages$291$MessagesController(TLRPC.Dialog dialogFinal, long uid, int param) {
        if (param != -1) {
            if (param != 0) {
                dialogFinal.folder_id = param;
                sortDialogs(null);
                getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, true);
                return;
            }
            return;
        }
        int lowerId = (int) uid;
        if (lowerId != 0) {
            loadUnknownDialog(getInputPeer(lowerId), 0L);
        }
    }

    public void addDialogAction(long did, boolean clean) {
        TLRPC.Dialog dialog = this.dialogs_dict.get(did);
        if (dialog == null) {
            return;
        }
        if (clean) {
            this.clearingHistoryDialogs.put(did, dialog);
        } else {
            this.deletingDialogs.put(did, dialog);
            this.allDialogs.remove(dialog);
            sortDialogs(null);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, true);
    }

    public void removeDialogAction(long did, boolean clean, boolean apply) {
        TLRPC.Dialog dialog = this.dialogs_dict.get(did);
        if (dialog == null) {
            return;
        }
        if (clean) {
            this.clearingHistoryDialogs.remove(did);
        } else {
            this.deletingDialogs.remove(did);
            if (!apply) {
                this.allDialogs.add(dialog);
                sortDialogs(null);
            }
        }
        if (!apply) {
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, true);
        }
    }

    public boolean isClearingDialog(long did) {
        return this.clearingHistoryDialogs.get(did) != null;
    }

    /* JADX WARN: Removed duplicated region for block: B:83:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0178  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void sortDialogs(android.util.SparseArray<im.uwrkaxlmjj.tgnet.TLRPC.Chat> r18) {
        /*
            Method dump skipped, instruction units count: 487
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MessagesController.sortDialogs(android.util.SparseArray):void");
    }

    private void addDialogToItsFolder(int index, TLRPC.Dialog dialog, boolean countMessages) {
        int folderId;
        TLRPC.Dialog folder;
        if (dialog instanceof TLRPC.TL_dialogFolder) {
            folderId = 0;
            dialog.unread_count = 0;
            dialog.unread_mentions_count = 0;
        } else {
            folderId = dialog.folder_id;
        }
        ArrayList<TLRPC.Dialog> dialogs = this.dialogsByFolder.get(folderId);
        if (dialogs == null) {
            dialogs = new ArrayList<>();
            this.dialogsByFolder.put(folderId, dialogs);
        }
        if (folderId != 0 && dialog.unread_count != 0 && (folder = this.dialogs_dict.get(DialogObject.makeFolderDialogId(folderId))) != null) {
            if (countMessages) {
                if (isDialogMuted(dialog.id)) {
                    folder.unread_count += dialog.unread_count;
                } else {
                    folder.unread_mentions_count += dialog.unread_count;
                }
            } else if (isDialogMuted(dialog.id)) {
                folder.unread_count++;
            } else {
                folder.unread_mentions_count++;
            }
        }
        if (index == -1) {
            dialogs.add(dialog);
            return;
        }
        if (index == -2) {
            if (dialogs.isEmpty() || !(dialogs.get(0) instanceof TLRPC.TL_dialogFolder)) {
                dialogs.add(0, dialog);
                return;
            } else {
                dialogs.add(1, dialog);
                return;
            }
        }
        dialogs.add(index, dialog);
    }

    public static String getRestrictionReason(ArrayList<TLRPC.TL_restrictionReason> reasons) {
        if (reasons.isEmpty()) {
            return null;
        }
        int N = reasons.size();
        for (int a = 0; a < N; a++) {
            TLRPC.TL_restrictionReason reason = reasons.get(a);
            if ("all".equals(reason.platform) || "android".equals(reason.platform)) {
                return reason.text;
            }
        }
        return null;
    }

    public static void showCantOpenAlert(BaseFragment fragment, String reason) {
        if (fragment == null || fragment.getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", mpEIGo.juqQQs.esbSDO.R.string.OK), null);
        builder.setMessage(reason);
        fragment.showDialog(builder.create());
    }

    public static void showCantOpenAlert2(final BaseFragment fragment, String reason) {
        if (fragment == null || fragment.getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(fragment.getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", mpEIGo.juqQQs.esbSDO.R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.messenger.MessagesController.2
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                fragment.finishFragment();
            }
        });
        builder.setMessage(reason);
        fragment.showDialog(builder.create());
    }

    public boolean checkCanOpenChat(Bundle bundle, BaseFragment fragment) {
        return checkCanOpenChat(bundle, fragment, null);
    }

    public boolean checkCanOpenChat2(Bundle bundle, BaseFragment fragment) {
        return checkCanOpenChat2(bundle, fragment, null);
    }

    public boolean checkCanOpenChat(final Bundle bundle, final BaseFragment fragment, MessageObject originalMessage) {
        int did;
        TLObject req;
        if (bundle == null || fragment == null) {
            return true;
        }
        TLRPC.User user = null;
        TLRPC.Chat chat = null;
        int user_id = bundle.getInt("user_id", 0);
        int chat_id = bundle.getInt("chat_id", 0);
        int messageId = bundle.getInt("message_id", 0);
        if (user_id != 0) {
            user = getUser(Integer.valueOf(user_id));
        } else if (chat_id != 0) {
            chat = getChat(Integer.valueOf(chat_id));
        }
        if (user == null && chat == null) {
            return true;
        }
        String reason = null;
        if (chat != null) {
            reason = getRestrictionReason(chat.restriction_reason);
        } else if (user != null) {
            reason = getRestrictionReason(user.restriction_reason);
        }
        if (reason != null) {
            showCantOpenAlert(fragment, reason);
            return false;
        }
        if (messageId == 0 || originalMessage == null || chat == null || chat.access_hash != 0 || (did = (int) originalMessage.getDialogId()) == 0) {
            return true;
        }
        final AlertDialog progressDialog = new AlertDialog(fragment.getParentActivity(), 3);
        if (did < 0) {
            chat = getChat(Integer.valueOf(-did));
        }
        if (did <= 0 && ChatObject.isChannel(chat)) {
            TLRPC.Chat chat2 = getChat(Integer.valueOf(-did));
            TLRPC.TL_channels_getMessages request = new TLRPC.TL_channels_getMessages();
            request.channel = getInputChannel(chat2);
            request.id.add(Integer.valueOf(originalMessage.getId()));
            req = request;
        } else {
            TLRPC.TL_messages_getMessages request2 = new TLRPC.TL_messages_getMessages();
            request2.id.add(Integer.valueOf(originalMessage.getId()));
            req = request2;
        }
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$YGm_hvQzeDQwPH4MOptSA7Z8v-Y
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkCanOpenChat$293$MessagesController(progressDialog, fragment, bundle, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$IpKrhMSKbyXhdAFew615ikBcZ9s
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$checkCanOpenChat$294$MessagesController(reqId, fragment, dialogInterface);
            }
        });
        fragment.setVisibleDialog(progressDialog);
        progressDialog.show();
        return false;
    }

    public /* synthetic */ void lambda$checkCanOpenChat$293$MessagesController(final AlertDialog progressDialog, final BaseFragment fragment, final Bundle bundle, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$kCI5HayaHMIfW6qSl-X3LzZfZzk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$292$MessagesController(progressDialog, response, fragment, bundle);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$292$MessagesController(AlertDialog progressDialog, TLObject response, BaseFragment fragment, Bundle bundle) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
        putUsers(res.users, false);
        putChats(res.chats, false);
        getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
        fragment.presentFragment(new ChatActivity(bundle), true);
    }

    public /* synthetic */ void lambda$checkCanOpenChat$294$MessagesController(int reqId, BaseFragment fragment, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
        if (fragment != null) {
            fragment.setVisibleDialog(null);
        }
    }

    public boolean checkCanOpenChat2(final Bundle bundle, final BaseFragment fragment, MessageObject originalMessage) {
        int did;
        TLObject req;
        if (bundle == null || fragment == null) {
            return true;
        }
        TLRPC.User user = null;
        TLRPC.Chat chat = null;
        int user_id = bundle.getInt("user_id", 0);
        int chat_id = bundle.getInt("chat_id", 0);
        int messageId = bundle.getInt("message_id", 0);
        if (user_id != 0) {
            user = getUser(Integer.valueOf(user_id));
        } else if (chat_id != 0) {
            chat = getChat(Integer.valueOf(chat_id));
        }
        if (user == null && chat == null) {
            return true;
        }
        String reason = null;
        if (chat != null) {
            reason = getRestrictionReason(chat.restriction_reason);
        } else if (user != null) {
            reason = getRestrictionReason(user.restriction_reason);
        }
        if (reason != null) {
            showCantOpenAlert2(fragment, reason);
            return false;
        }
        if (messageId == 0 || originalMessage == null || chat == null || chat.access_hash != 0 || (did = (int) originalMessage.getDialogId()) == 0) {
            return true;
        }
        final AlertDialog progressDialog = new AlertDialog(fragment.getParentActivity(), 3);
        if (did < 0) {
            chat = getChat(Integer.valueOf(-did));
        }
        if (did <= 0 && ChatObject.isChannel(chat)) {
            TLRPC.Chat chat2 = getChat(Integer.valueOf(-did));
            TLRPC.TL_channels_getMessages request = new TLRPC.TL_channels_getMessages();
            request.channel = getInputChannel(chat2);
            request.id.add(Integer.valueOf(originalMessage.getId()));
            req = request;
        } else {
            TLRPC.TL_messages_getMessages request2 = new TLRPC.TL_messages_getMessages();
            request2.id.add(Integer.valueOf(originalMessage.getId()));
            req = request2;
        }
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$to6ZXgbZM30_OkvzipDwO6CfmNU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkCanOpenChat2$296$MessagesController(progressDialog, fragment, bundle, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$hpSBGwZQowN8ik33o8suR12mUDU
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$checkCanOpenChat2$297$MessagesController(reqId, fragment, dialogInterface);
            }
        });
        fragment.setVisibleDialog(progressDialog);
        progressDialog.show();
        return false;
    }

    public /* synthetic */ void lambda$checkCanOpenChat2$296$MessagesController(final AlertDialog progressDialog, final BaseFragment fragment, final Bundle bundle, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$BnnfgT86wA-bpMnzz-gCIM9LvgA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$295$MessagesController(progressDialog, response, fragment, bundle);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$295$MessagesController(AlertDialog progressDialog, TLObject response, BaseFragment fragment, Bundle bundle) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
        putUsers(res.users, false);
        putChats(res.chats, false);
        getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
        fragment.presentFragment(new ChatActivity(bundle), true);
    }

    public /* synthetic */ void lambda$checkCanOpenChat2$297$MessagesController(int reqId, BaseFragment fragment, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
        if (fragment != null) {
            fragment.setVisibleDialog(null);
        }
    }

    public static void openChatOrProfileWith(TLRPC.User user, TLRPC.Chat chat, BaseFragment fragment, int type, boolean closeLast) {
        if ((user == null && chat == null) || fragment == null) {
            return;
        }
        String reason = null;
        if (chat != null) {
            reason = getRestrictionReason(chat.restriction_reason);
        } else if (user != null) {
            reason = getRestrictionReason(user.restriction_reason);
            if (user.bot) {
                type = 1;
                closeLast = true;
            }
        }
        if (reason != null) {
            showCantOpenAlert(fragment, reason);
            return;
        }
        Bundle args = new Bundle();
        if (chat != null) {
            args.putInt("chat_id", chat.id);
        } else {
            args.putInt("user_id", user.id);
        }
        if (type == 0) {
            fragment.presentFragment(new ProfileActivity(args));
        } else if (type == 2) {
            fragment.presentFragment(new ChatActivity(args), true, true);
        } else {
            fragment.presentFragment(new ChatActivity(args), closeLast);
        }
    }

    public void openByUserName(String username, BaseFragment fragment, int type) {
        openByUserName(username, fragment, type, false);
    }

    public void openByUserName(String username, final BaseFragment fragment, final int type, final boolean closeLast) {
        TLRPC.User user;
        TLRPC.Chat chat;
        if (username != null && fragment != null) {
            TLObject object = getUserOrChat(username);
            if (object instanceof TLRPC.User) {
                TLRPC.User user2 = (TLRPC.User) object;
                if (!user2.min) {
                    user = user2;
                    chat = null;
                } else {
                    user = null;
                    chat = null;
                }
            } else if (!(object instanceof TLRPC.Chat)) {
                user = null;
                chat = null;
            } else {
                TLRPC.Chat chat2 = (TLRPC.Chat) object;
                if (chat2.min) {
                    user = null;
                    chat = null;
                } else {
                    user = null;
                    chat = chat2;
                }
            }
            if (user != null) {
                openChatOrProfileWith(user, null, fragment, type, closeLast);
                return;
            }
            if (chat != null) {
                openChatOrProfileWith(null, chat, fragment, 1, closeLast);
                return;
            }
            if (fragment.getParentActivity() == null) {
                return;
            }
            final AlertDialog[] progressDialog = {new AlertDialog(fragment.getParentActivity(), 3)};
            TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
            req.username = username;
            final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$W0NOOCY8vIG2TO-JbnWorASoWTM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$openByUserName$299$MessagesController(progressDialog, fragment, closeLast, type, tLObject, tL_error);
                }
            });
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$GSNlSgtG069joF5JixbfxGbwzdk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$openByUserName$301$MessagesController(progressDialog, reqId, fragment);
                }
            }, 500L);
        }
    }

    public /* synthetic */ void lambda$openByUserName$299$MessagesController(final AlertDialog[] progressDialog, final BaseFragment fragment, final boolean closeLast, final int type, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$i9nIYVF9X21O-bOxUnHCWP6CJvQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$298$MessagesController(progressDialog, fragment, error, response, closeLast, type);
            }
        });
    }

    public /* synthetic */ void lambda$null$298$MessagesController(AlertDialog[] progressDialog, BaseFragment fragment, TLRPC.TL_error error, TLObject response, boolean closeLast, int type) {
        try {
            progressDialog[0].dismiss();
        } catch (Exception e) {
        }
        progressDialog[0] = null;
        fragment.setVisibleDialog(null);
        if (error == null) {
            TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
            putUsers(res.users, false);
            putChats(res.chats, false);
            getMessagesStorage().putUsersAndChats(res.users, res.chats, false, true);
            if (!res.chats.isEmpty()) {
                openChatOrProfileWith(null, res.chats.get(0), fragment, 1, closeLast);
                return;
            } else {
                if (!res.users.isEmpty()) {
                    if (res.users.get(0).contact) {
                        openChatOrProfileWith(res.users.get(0), null, fragment, type, closeLast);
                        return;
                    } else {
                        fragment.presentFragment(new AddContactsInfoActivity(null, res.users.get(0)));
                        return;
                    }
                }
                return;
            }
        }
        if (fragment != null && fragment.getParentActivity() != null) {
            if (type == 0) {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.NoUsernameFound);
            } else {
                AlertsCreator.createSimpleAlert(fragment.getParentActivity(), LocaleController.getString("JoinToGroupErrorNotExist", mpEIGo.juqQQs.esbSDO.R.string.JoinToGroupErrorNotExist)).show();
            }
        }
    }

    public /* synthetic */ void lambda$openByUserName$301$MessagesController(AlertDialog[] progressDialog, final int reqId, BaseFragment fragment) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$YR9S3D2LrutPGkJD5Ss6YFP6-TI
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$300$MessagesController(reqId, dialogInterface);
            }
        });
        fragment.showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$300$MessagesController(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    public void openByUserName(String username, final BaseFragment fragment, final TLRPC.Chat currentChat, final boolean closeLast) {
        TLRPC.User user;
        TLRPC.Chat chat;
        if (username != null && fragment != null) {
            if (!ChatObject.canSendEmbed(currentChat)) {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.ForbidViewUserAndGroupInfoTips);
                return;
            }
            TLObject object = getUserOrChat(username);
            if (object instanceof TLRPC.User) {
                TLRPC.User user2 = (TLRPC.User) object;
                if (!user2.min) {
                    user = user2;
                    chat = null;
                } else {
                    user = null;
                    chat = null;
                }
            } else if (!(object instanceof TLRPC.Chat)) {
                user = null;
                chat = null;
            } else {
                TLRPC.Chat chat2 = (TLRPC.Chat) object;
                if (chat2.min) {
                    user = null;
                    chat = null;
                } else {
                    user = null;
                    chat = chat2;
                }
            }
            boolean z = false;
            if (user != null) {
                if (!user.self && currentChat != null && !ChatObject.hasAdminRights(currentChat) && currentChat.megagroup && (currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user.mutual_contact) {
                    ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.ForbidViewUserInfoTips);
                    return;
                }
                if (user.contact) {
                    Bundle args = new Bundle();
                    args.putInt("user_id", user.id);
                    if (currentChat != null) {
                        if (currentChat.megagroup && (33554432 & currentChat.flags) != 0) {
                            z = true;
                        }
                        args.putBoolean("forbid_add_contact", z);
                        args.putBoolean("has_admin_right", ChatObject.hasAdminRights(currentChat));
                    }
                    fragment.presentFragment(new NewProfileActivity(args));
                    return;
                }
                Bundle args2 = new Bundle();
                args2.putInt("user_id", user.id);
                if (currentChat != null) {
                    if (currentChat.megagroup && (33554432 & currentChat.flags) != 0) {
                        z = true;
                    }
                    args2.putBoolean("forbid_add_contact", z);
                    args2.putBoolean("has_admin_right", ChatObject.hasAdminRights(currentChat));
                }
                args2.putInt("from_type", 2);
                fragment.presentFragment(new NewProfileActivity(args2));
                return;
            }
            if (chat != null) {
                openChatOrProfileWith(null, chat, fragment, 1, closeLast);
                return;
            }
            if (fragment.getParentActivity() == null) {
                return;
            }
            final AlertDialog[] progressDialog = {new AlertDialog(fragment.getParentActivity(), 3)};
            TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
            req.username = username;
            final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$oEyqEsbHU3-nffe47npbMkuHZ18
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$openByUserName$303$MessagesController(progressDialog, fragment, closeLast, currentChat, tLObject, tL_error);
                }
            });
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$REjfy6hV8X3JrE3m3BEspr_4rkg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$openByUserName$305$MessagesController(progressDialog, reqId, fragment);
                }
            }, 500L);
        }
    }

    public /* synthetic */ void lambda$openByUserName$303$MessagesController(final AlertDialog[] progressDialog, final BaseFragment fragment, final boolean closeLast, final TLRPC.Chat currentChat, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$gmE7-wUtUeT7QKkkneKCK-ndHyo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$302$MessagesController(progressDialog, fragment, error, response, closeLast, currentChat);
            }
        });
    }

    public /* synthetic */ void lambda$null$302$MessagesController(AlertDialog[] progressDialog, BaseFragment fragment, TLRPC.TL_error error, TLObject response, boolean closeLast, TLRPC.Chat currentChat) {
        boolean z = false;
        try {
            progressDialog[0].dismiss();
        } catch (Exception e) {
        }
        progressDialog[0] = null;
        fragment.setVisibleDialog(null);
        if (error == null) {
            TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
            putUsers(res.users, false);
            putChats(res.chats, false);
            getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
            if (!res.chats.isEmpty()) {
                openChatOrProfileWith(null, res.chats.get(0), fragment, 1, closeLast);
                return;
            }
            if (!res.users.isEmpty()) {
                TLRPC.User user1 = res.users.get(0);
                if (!user1.self && currentChat != null && !ChatObject.hasAdminRights(currentChat) && currentChat.megagroup && (currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user1.mutual_contact) {
                    ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.ForbidViewUserInfoTips);
                    return;
                }
                Bundle args = new Bundle();
                args.putInt("user_id", user1.id);
                if (currentChat != null) {
                    if (currentChat.megagroup && (33554432 & currentChat.flags) != 0) {
                        z = true;
                    }
                    args.putBoolean("forbid_add_contact", z);
                    args.putBoolean("has_admin_right", ChatObject.hasAdminRights(currentChat));
                }
                args.putInt("from_type", 2);
                fragment.presentFragment(new NewProfileActivity(args));
                return;
            }
            return;
        }
        if (fragment != null && fragment.getParentActivity() != null) {
            try {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.NoUsernameFound);
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
    }

    public /* synthetic */ void lambda$openByUserName$305$MessagesController(AlertDialog[] progressDialog, final int reqId, BaseFragment fragment) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$HkfNY2GC-fFH2k69mJ5aS7I_UgY
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$304$MessagesController(reqId, dialogInterface);
            }
        });
        fragment.showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$304$MessagesController(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    public void saveContactsAppliesId(int applyId) {
        this.mainPreferences.edit().putInt("contacts_apply_id", applyId).apply();
    }

    public void saveContactsAppliesDate(int date) {
        this.mainPreferences.edit().putInt("last_contacts_get_diff", date).apply();
    }

    public void saveContactsAppliesHash(long hash) {
        this.mainPreferences.edit().putLong("contacts_apply_hash", hash).apply();
    }

    public void handleUpdatesContactsApply(int count) {
        if (count <= 0) {
            this.mainPreferences.edit().putInt("contacts_apply_count", 0).apply();
        } else {
            this.mainPreferences.edit().putInt("contacts_apply_count", count).apply();
        }
    }

    public void getContactsApplyDifferenceV2(boolean reget, boolean slice) {
        getContactsApplyDifferenceV2(reget, false, slice);
    }

    public void getContactsApplyDifferenceV2(final boolean reget, boolean reset, boolean slice) {
        if (this.contactsGetDiff) {
            return;
        }
        this.contactsGetDiff = true;
        int applyId = this.mainPreferences.getInt("contacts_apply_id", -1);
        int needTime = this.mainPreferences.getInt("last_contacts_get_diff", 0);
        long applyHash = this.mainPreferences.getLong("contacts_apply_hash", 0L);
        TLRPCContacts.GetContactAppliesDifferenceV2 req = new TLRPCContacts.GetContactAppliesDifferenceV2();
        req.apply_id = reget ? -1 : applyId;
        req.total_limit = 100;
        req.date = needTime;
        req.hash = reset ? 0L : applyHash;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$nyn-Hmqzz04HUIBZnYmJGUJ5qDs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getContactsApplyDifferenceV2$309$MessagesController(reget, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$getContactsApplyDifferenceV2$309$MessagesController(boolean reget, TLObject response, TLRPC.TL_error error) {
        this.contactsGetDiff = false;
        if (error == null) {
            final TLRPCContacts.ContactsAppiesDifferenceV2 res = (TLRPCContacts.ContactsAppiesDifferenceV2) response;
            if (res instanceof TLRPCContacts.HC_contacts_apply_notModified) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$moXnNMEhLYLlZ40ycPOnVrEavlo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$306$MessagesController();
                    }
                });
                return;
            }
            if (res instanceof TLRPCContacts.HC_contacts_apply_differenceSlice_v2) {
                getMessagesController().putUsers(res.users, false);
                ArrayList<TLRPCContacts.ContactApplyInfo> infos = new ArrayList<>();
                for (int i = 0; i < res.otherUpdates.size(); i++) {
                    TLRPC.Update update = res.otherUpdates.get(i);
                    if (update instanceof TLRPCContacts.UpdateContactApplyRequested) {
                        TLRPCContacts.UpdateContactApplyRequested obj = (TLRPCContacts.UpdateContactApplyRequested) update;
                        if (obj.apply_info.from_peer.user_id != getUserConfig().clientUserId) {
                            infos.add(obj.apply_info);
                        }
                    }
                }
                getContactsApplyDifferenceV2(false, true);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("------------> slice response");
                }
                if (infos.size() > 0 && BuildVars.LOGS_ENABLED) {
                    FileLog.e("------------> infos.size() :" + infos.size());
                    return;
                }
                return;
            }
            final ArrayList<TLRPCContacts.ContactApplyInfo> infos2 = new ArrayList<>();
            getMessagesController().putUsers(res.users, false);
            for (int i2 = 0; i2 < res.otherUpdates.size(); i2++) {
                TLRPC.Update update2 = res.otherUpdates.get(i2);
                if (update2 instanceof TLRPCContacts.UpdateContactApplyRequested) {
                    TLRPCContacts.UpdateContactApplyRequested obj2 = (TLRPCContacts.UpdateContactApplyRequested) update2;
                    if (obj2.apply_info.from_peer.user_id != getUserConfig().clientUserId) {
                        infos2.add(obj2.apply_info);
                    }
                }
            }
            if (infos2.size() > 0) {
                handleUpdatesContactsApply(res.state.unread_count);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$IGrIRnaNF6XKKxZcSphUKoA89EM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$307$MessagesController(res, infos2);
                    }
                });
            } else {
                handleUpdatesContactsApply(res.state.unread_count);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$G4ry1-OEsuafOws2cA0vLE5YSQc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$308$MessagesController(res);
                    }
                });
            }
            saveContactsAppliesId(res.state.apply_id);
            saveContactsAppliesHash(res.hash);
        }
    }

    public /* synthetic */ void lambda$null$306$MessagesController() {
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, 0);
    }

    public /* synthetic */ void lambda$null$307$MessagesController(TLRPCContacts.ContactsAppiesDifferenceV2 res, ArrayList infos) {
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, Integer.valueOf(res.state.unread_count));
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplieReceived, infos, res.users);
    }

    public /* synthetic */ void lambda$null$308$MessagesController(TLRPCContacts.ContactsAppiesDifferenceV2 res) {
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, Integer.valueOf(res.state.unread_count));
    }
}
