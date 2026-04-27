package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.location.Location;
import android.os.Build;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper;
import im.uwrkaxlmjj.ui.cells.BotSwitchCell;
import im.uwrkaxlmjj.ui.cells.ContextLinkCell;
import im.uwrkaxlmjj.ui.cells.MentionCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MentionsAdapter extends RecyclerListView.SelectionAdapter {
    private static final String punctuationsChars = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n";
    private SparseArray<TLRPC.BotInfo> botInfo;
    private int botsCount;
    private Runnable cancelDelayRunnable;
    private int channelLastReqId;
    private int channelReqId;
    private boolean contextMedia;
    private int contextQueryReqid;
    private Runnable contextQueryRunnable;
    private int contextUsernameReqid;
    private MentionsAdapterDelegate delegate;
    private long dialog_id;
    private TLRPC.User foundContextBot;
    private TLRPC.ChatFull info;
    private boolean isDarkTheme;
    private boolean isSearchingMentions;
    private Location lastKnownLocation;
    private int lastPosition;
    private String[] lastSearchKeyboardLanguage;
    private String lastText;
    private boolean lastUsernameOnly;
    private Context mContext;
    private ArrayList<MessageObject> messages;
    private String nextQueryOffset;
    private boolean noUserName;
    private ChatActivity parentFragment;
    private int resultLength;
    private int resultStartPosition;
    private SearchAdapterHelper searchAdapterHelper;
    private Runnable searchGlobalRunnable;
    private ArrayList<TLRPC.BotInlineResult> searchResultBotContext;
    private TLRPC.TL_inlineBotSwitchPM searchResultBotContextSwitch;
    private ArrayList<String> searchResultCommands;
    private ArrayList<String> searchResultCommandsHelp;
    private ArrayList<TLRPC.User> searchResultCommandsUsers;
    private ArrayList<String> searchResultHashtags;
    private ArrayList<MediaDataController.KeywordResult> searchResultSuggestions;
    private ArrayList<TLRPC.User> searchResultUsernames;
    private SparseArray<TLRPC.User> searchResultUsernamesMap;
    private String searchingContextQuery;
    private String searchingContextUsername;
    private int currentAccount = UserConfig.selectedAccount;
    private boolean needUsernames = true;
    private boolean needBotContext = true;
    private boolean inlineMediaEnabled = true;
    private SendMessagesHelper.LocationProvider locationProvider = new SendMessagesHelper.LocationProvider(new SendMessagesHelper.LocationProvider.LocationProviderDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.MentionsAdapter.1
        @Override // im.uwrkaxlmjj.messenger.SendMessagesHelper.LocationProvider.LocationProviderDelegate
        public void onLocationAcquired(Location location) {
            if (MentionsAdapter.this.foundContextBot != null && MentionsAdapter.this.foundContextBot.bot_inline_geo) {
                MentionsAdapter.this.lastKnownLocation = location;
                MentionsAdapter mentionsAdapter = MentionsAdapter.this;
                mentionsAdapter.searchForContextBotResults(true, mentionsAdapter.foundContextBot, MentionsAdapter.this.searchingContextQuery, "");
            }
        }

        @Override // im.uwrkaxlmjj.messenger.SendMessagesHelper.LocationProvider.LocationProviderDelegate
        public void onUnableLocationAcquire() {
            MentionsAdapter.this.onLocationUnavailable();
        }
    }) { // from class: im.uwrkaxlmjj.ui.adapters.MentionsAdapter.2
        @Override // im.uwrkaxlmjj.messenger.SendMessagesHelper.LocationProvider
        public void stop() {
            super.stop();
            MentionsAdapter.this.lastKnownLocation = null;
        }
    };
    private boolean needPannel = true;

    public interface MentionsAdapterDelegate {
        void needChangePanelVisibility(boolean z);

        void onContextClick(TLRPC.BotInlineResult botInlineResult);

        void onContextSearch(boolean z);
    }

    static /* synthetic */ int access$1604(MentionsAdapter x0) {
        int i = x0.channelLastReqId + 1;
        x0.channelLastReqId = i;
        return i;
    }

    public MentionsAdapter(Context context, boolean darkTheme, long did, MentionsAdapterDelegate mentionsAdapterDelegate) {
        this.mContext = context;
        this.delegate = mentionsAdapterDelegate;
        this.isDarkTheme = darkTheme;
        this.dialog_id = did;
        SearchAdapterHelper searchAdapterHelper = new SearchAdapterHelper(true);
        this.searchAdapterHelper = searchAdapterHelper;
        searchAdapterHelper.setDelegate(new SearchAdapterHelper.SearchAdapterHelperDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.MentionsAdapter.3
            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public /* synthetic */ SparseArray<TLRPC.User> getExcludeUsers() {
                return SearchAdapterHelper.SearchAdapterHelperDelegate.CC.$default$getExcludeUsers(this);
            }

            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public void onDataSetChanged() {
                MentionsAdapter.this.notifyDataSetChanged();
            }

            @Override // im.uwrkaxlmjj.ui.adapters.SearchAdapterHelper.SearchAdapterHelperDelegate
            public void onSetHashtags(ArrayList<SearchAdapterHelper.HashtagObject> arrayList, HashMap<String, SearchAdapterHelper.HashtagObject> hashMap) {
                if (MentionsAdapter.this.lastText != null) {
                    MentionsAdapter mentionsAdapter = MentionsAdapter.this;
                    mentionsAdapter.searchUsernameOrHashtag(mentionsAdapter.lastText, MentionsAdapter.this.lastPosition, MentionsAdapter.this.messages, MentionsAdapter.this.lastUsernameOnly);
                }
            }
        });
    }

    public void onDestroy() {
        SendMessagesHelper.LocationProvider locationProvider = this.locationProvider;
        if (locationProvider != null) {
            locationProvider.stop();
        }
        Runnable runnable = this.contextQueryRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.contextQueryRunnable = null;
        }
        if (this.contextUsernameReqid != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.contextUsernameReqid, true);
            this.contextUsernameReqid = 0;
        }
        if (this.contextQueryReqid != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.contextQueryReqid, true);
            this.contextQueryReqid = 0;
        }
        this.foundContextBot = null;
        this.inlineMediaEnabled = true;
        this.searchingContextUsername = null;
        this.searchingContextQuery = null;
        this.noUserName = false;
    }

    public void setParentFragment(ChatActivity fragment) {
        this.parentFragment = fragment;
    }

    public void setChatInfo(TLRPC.ChatFull chatInfo) {
        ChatActivity chatActivity;
        TLRPC.Chat chat;
        this.currentAccount = UserConfig.selectedAccount;
        this.info = chatInfo;
        if (!this.inlineMediaEnabled && this.foundContextBot != null && (chatActivity = this.parentFragment) != null && (chat = chatActivity.getCurrentChat()) != null) {
            boolean zCanSendStickers = ChatObject.canSendStickers(chat);
            this.inlineMediaEnabled = zCanSendStickers;
            if (zCanSendStickers) {
                this.searchResultUsernames = null;
                notifyDataSetChanged();
                this.delegate.needChangePanelVisibility(false);
                processFoundUser(this.foundContextBot);
            }
        }
        String str = this.lastText;
        if (str != null) {
            searchUsernameOrHashtag(str, this.lastPosition, this.messages, this.lastUsernameOnly);
        }
    }

    public void setNeedUsernames(boolean value) {
        this.needUsernames = value;
    }

    public void setNeedBotContext(boolean value) {
        this.needBotContext = value;
    }

    public void setBotInfo(SparseArray<TLRPC.BotInfo> info) {
        this.botInfo = info;
    }

    public void setBotsCount(int count) {
        this.botsCount = count;
    }

    public void clearRecentHashtags() {
        this.searchAdapterHelper.clearRecentHashtags();
        this.searchResultHashtags.clear();
        notifyDataSetChanged();
        MentionsAdapterDelegate mentionsAdapterDelegate = this.delegate;
        if (mentionsAdapterDelegate != null) {
            mentionsAdapterDelegate.needChangePanelVisibility(false);
        }
    }

    public TLRPC.TL_inlineBotSwitchPM getBotContextSwitch() {
        return this.searchResultBotContextSwitch;
    }

    public int getContextBotId() {
        TLRPC.User user = this.foundContextBot;
        if (user != null) {
            return user.id;
        }
        return 0;
    }

    public TLRPC.User getContextBotUser() {
        return this.foundContextBot;
    }

    public String getContextBotName() {
        TLRPC.User user = this.foundContextBot;
        return user != null ? user.username : "";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processFoundUser(TLRPC.User user) {
        ChatActivity chatActivity;
        TLRPC.Chat chat;
        this.contextUsernameReqid = 0;
        this.locationProvider.stop();
        if (user != null && user.bot && user.bot_inline_placeholder != null) {
            this.foundContextBot = user;
            ChatActivity chatActivity2 = this.parentFragment;
            if (chatActivity2 != null && (chat = chatActivity2.getCurrentChat()) != null) {
                boolean zCanSendStickers = ChatObject.canSendStickers(chat);
                this.inlineMediaEnabled = zCanSendStickers;
                if (!zCanSendStickers) {
                    notifyDataSetChanged();
                    this.delegate.needChangePanelVisibility(true);
                    return;
                }
            }
            if (this.foundContextBot.bot_inline_geo) {
                SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
                boolean allowGeo = preferences.getBoolean("inlinegeo_" + this.foundContextBot.id, false);
                if (!allowGeo && (chatActivity = this.parentFragment) != null && chatActivity.getParentActivity() != null) {
                    final TLRPC.User foundContextBotFinal = this.foundContextBot;
                    AlertDialog.Builder builder = new AlertDialog.Builder(this.parentFragment.getParentActivity());
                    builder.setTitle(LocaleController.getString("ShareYouLocationTitle", R.string.ShareYouLocationTitle));
                    builder.setMessage(LocaleController.getString("ShareYouLocationInline", R.string.ShareYouLocationInline));
                    final boolean[] buttonClicked = new boolean[1];
                    builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$ZxNBqPcUMnEzlGXKD42JGwRaXt0
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$processFoundUser$0$MentionsAdapter(buttonClicked, foundContextBotFinal, dialogInterface, i);
                        }
                    });
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$yZe1WooWjVxq-BFYJXdPPTF_8jw
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$processFoundUser$1$MentionsAdapter(buttonClicked, dialogInterface, i);
                        }
                    });
                    this.parentFragment.showDialog(builder.create(), new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$DCiY3d1JX3yho1toQsaxx51q9Yg
                        @Override // android.content.DialogInterface.OnDismissListener
                        public final void onDismiss(DialogInterface dialogInterface) {
                            this.f$0.lambda$processFoundUser$2$MentionsAdapter(buttonClicked, dialogInterface);
                        }
                    });
                } else {
                    checkLocationPermissionsOrStart();
                }
            }
        } else {
            this.foundContextBot = null;
            this.inlineMediaEnabled = true;
        }
        if (this.foundContextBot == null) {
            this.noUserName = true;
            return;
        }
        MentionsAdapterDelegate mentionsAdapterDelegate = this.delegate;
        if (mentionsAdapterDelegate != null) {
            mentionsAdapterDelegate.onContextSearch(true);
        }
        searchForContextBotResults(true, this.foundContextBot, this.searchingContextQuery, "");
    }

    public /* synthetic */ void lambda$processFoundUser$0$MentionsAdapter(boolean[] buttonClicked, TLRPC.User foundContextBotFinal, DialogInterface dialogInterface, int i) {
        buttonClicked[0] = true;
        if (foundContextBotFinal != null) {
            SharedPreferences preferences1 = MessagesController.getNotificationsSettings(this.currentAccount);
            preferences1.edit().putBoolean("inlinegeo_" + foundContextBotFinal.id, true).commit();
            checkLocationPermissionsOrStart();
        }
    }

    public /* synthetic */ void lambda$processFoundUser$1$MentionsAdapter(boolean[] buttonClicked, DialogInterface dialog, int which) {
        buttonClicked[0] = true;
        onLocationUnavailable();
    }

    public /* synthetic */ void lambda$processFoundUser$2$MentionsAdapter(boolean[] buttonClicked, DialogInterface dialog) {
        if (!buttonClicked[0]) {
            onLocationUnavailable();
        }
    }

    private void searchForContextBot(String username, String query) {
        String str;
        String str2;
        TLRPC.User user = this.foundContextBot;
        if (user != null && user.username != null && this.foundContextBot.username.equals(username) && (str2 = this.searchingContextQuery) != null && str2.equals(query)) {
            return;
        }
        this.searchResultBotContext = null;
        this.searchResultBotContextSwitch = null;
        notifyDataSetChanged();
        if (this.foundContextBot != null) {
            if (!this.inlineMediaEnabled && username != null && query != null) {
                return;
            } else {
                this.delegate.needChangePanelVisibility(false);
            }
        }
        Runnable runnable = this.contextQueryRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.contextQueryRunnable = null;
        }
        if (TextUtils.isEmpty(username) || ((str = this.searchingContextUsername) != null && !str.equals(username))) {
            if (this.contextUsernameReqid != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.contextUsernameReqid, true);
                this.contextUsernameReqid = 0;
            }
            if (this.contextQueryReqid != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.contextQueryReqid, true);
                this.contextQueryReqid = 0;
            }
            this.foundContextBot = null;
            this.inlineMediaEnabled = true;
            this.searchingContextUsername = null;
            this.searchingContextQuery = null;
            this.locationProvider.stop();
            this.noUserName = false;
            MentionsAdapterDelegate mentionsAdapterDelegate = this.delegate;
            if (mentionsAdapterDelegate != null) {
                mentionsAdapterDelegate.onContextSearch(false);
            }
            if (username == null || username.length() == 0) {
                return;
            }
        }
        if (query == null) {
            if (this.contextQueryReqid != 0) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.contextQueryReqid, true);
                this.contextQueryReqid = 0;
            }
            this.searchingContextQuery = null;
            MentionsAdapterDelegate mentionsAdapterDelegate2 = this.delegate;
            if (mentionsAdapterDelegate2 != null) {
                mentionsAdapterDelegate2.onContextSearch(false);
                return;
            }
            return;
        }
        MentionsAdapterDelegate mentionsAdapterDelegate3 = this.delegate;
        if (mentionsAdapterDelegate3 != null) {
            if (this.foundContextBot != null) {
                mentionsAdapterDelegate3.onContextSearch(true);
            } else if (username.equals("gif")) {
                this.searchingContextUsername = "gif";
                this.delegate.onContextSearch(false);
            }
        }
        MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
        MessagesStorage messagesStorage = MessagesStorage.getInstance(this.currentAccount);
        this.searchingContextQuery = query;
        AnonymousClass4 anonymousClass4 = new AnonymousClass4(query, username, messagesController, messagesStorage);
        this.contextQueryRunnable = anonymousClass4;
        AndroidUtilities.runOnUIThread(anonymousClass4, 400L);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.adapters.MentionsAdapter$4, reason: invalid class name */
    class AnonymousClass4 implements Runnable {
        final /* synthetic */ MessagesController val$messagesController;
        final /* synthetic */ MessagesStorage val$messagesStorage;
        final /* synthetic */ String val$query;
        final /* synthetic */ String val$username;

        AnonymousClass4(String str, String str2, MessagesController messagesController, MessagesStorage messagesStorage) {
            this.val$query = str;
            this.val$username = str2;
            this.val$messagesController = messagesController;
            this.val$messagesStorage = messagesStorage;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (MentionsAdapter.this.contextQueryRunnable == this) {
                MentionsAdapter.this.contextQueryRunnable = null;
                if (MentionsAdapter.this.foundContextBot != null || MentionsAdapter.this.noUserName) {
                    if (MentionsAdapter.this.noUserName) {
                        return;
                    }
                    MentionsAdapter mentionsAdapter = MentionsAdapter.this;
                    mentionsAdapter.searchForContextBotResults(true, mentionsAdapter.foundContextBot, this.val$query, "");
                    return;
                }
                MentionsAdapter.this.searchingContextUsername = this.val$username;
                TLObject object = this.val$messagesController.getUserOrChat(MentionsAdapter.this.searchingContextUsername);
                if (object instanceof TLRPC.User) {
                    MentionsAdapter.this.processFoundUser((TLRPC.User) object);
                    return;
                }
                TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
                req.username = MentionsAdapter.this.searchingContextUsername;
                MentionsAdapter mentionsAdapter2 = MentionsAdapter.this;
                ConnectionsManager connectionsManager = ConnectionsManager.getInstance(mentionsAdapter2.currentAccount);
                final String str = this.val$username;
                final MessagesController messagesController = this.val$messagesController;
                final MessagesStorage messagesStorage = this.val$messagesStorage;
                mentionsAdapter2.contextUsernameReqid = connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$4$NdHWdEpfjURNMiemIhtHMKIbXMo
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$run$1$MentionsAdapter$4(str, messagesController, messagesStorage, tLObject, tL_error);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$run$1$MentionsAdapter$4(final String username, final MessagesController messagesController, final MessagesStorage messagesStorage, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$4$b9eFn4NzwyM7nRlEv1KfxdNsNX4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$MentionsAdapter$4(username, error, response, messagesController, messagesStorage);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$MentionsAdapter$4(String username, TLRPC.TL_error error, TLObject response, MessagesController messagesController, MessagesStorage messagesStorage) {
            if (MentionsAdapter.this.searchingContextUsername == null || !MentionsAdapter.this.searchingContextUsername.equals(username)) {
                return;
            }
            TLRPC.User user = null;
            if (error == null) {
                TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
                if (!res.users.isEmpty()) {
                    user = res.users.get(0);
                    messagesController.putUser(user, false);
                    messagesStorage.putUsersAndChats(res.users, null, true, true);
                }
            }
            MentionsAdapter.this.processFoundUser(user);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onLocationUnavailable() {
        TLRPC.User user = this.foundContextBot;
        if (user != null && user.bot_inline_geo) {
            Location location = new Location("network");
            this.lastKnownLocation = location;
            location.setLatitude(-1000.0d);
            this.lastKnownLocation.setLongitude(-1000.0d);
            searchForContextBotResults(true, this.foundContextBot, this.searchingContextQuery, "");
        }
    }

    private void checkLocationPermissionsOrStart() {
        ChatActivity chatActivity = this.parentFragment;
        if (chatActivity == null || chatActivity.getParentActivity() == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 23 && this.parentFragment.getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            this.parentFragment.getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"}, 2);
            return;
        }
        TLRPC.User user = this.foundContextBot;
        if (user != null && user.bot_inline_geo) {
            this.locationProvider.start();
        }
    }

    public void setSearchingMentions(boolean value) {
        this.isSearchingMentions = value;
    }

    public String getBotCaption() {
        TLRPC.User user = this.foundContextBot;
        if (user != null) {
            return user.bot_inline_placeholder;
        }
        String str = this.searchingContextUsername;
        if (str != null && str.equals("gif")) {
            return "Search GIFs";
        }
        return null;
    }

    public void searchForContextBotForNextOffset() {
        String str;
        TLRPC.User user;
        String str2;
        if (this.contextQueryReqid != 0 || (str = this.nextQueryOffset) == null || str.length() == 0 || (user = this.foundContextBot) == null || (str2 = this.searchingContextQuery) == null) {
            return;
        }
        searchForContextBotResults(true, user, str2, this.nextQueryOffset);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void searchForContextBotResults(final boolean cache, final TLRPC.User user, final String query, final String offset) {
        Location location;
        Location location2;
        if (this.contextQueryReqid != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.contextQueryReqid, true);
            this.contextQueryReqid = 0;
        }
        if (!this.inlineMediaEnabled) {
            MentionsAdapterDelegate mentionsAdapterDelegate = this.delegate;
            if (mentionsAdapterDelegate != null) {
                mentionsAdapterDelegate.onContextSearch(false);
                return;
            }
            return;
        }
        if (query == null || user == null) {
            this.searchingContextQuery = null;
            return;
        }
        if (user.bot_inline_geo && this.lastKnownLocation == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(this.dialog_id);
        sb.append("_");
        sb.append(query);
        sb.append("_");
        sb.append(offset);
        sb.append("_");
        sb.append(this.dialog_id);
        sb.append("_");
        sb.append(user.id);
        sb.append("_");
        sb.append((!user.bot_inline_geo || (location2 = this.lastKnownLocation) == null || location2.getLatitude() == -1000.0d) ? "" : Double.valueOf(this.lastKnownLocation.getLatitude() + this.lastKnownLocation.getLongitude()));
        final String key = sb.toString();
        final MessagesStorage messagesStorage = MessagesStorage.getInstance(this.currentAccount);
        RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$zwxJAI1sKdw3Y0JRgoA11H4Hstc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$searchForContextBotResults$4$MentionsAdapter(query, cache, user, offset, messagesStorage, key, tLObject, tL_error);
            }
        };
        if (cache) {
            messagesStorage.getBotCache(key, requestDelegate);
            return;
        }
        TLRPC.TL_messages_getInlineBotResults req = new TLRPC.TL_messages_getInlineBotResults();
        req.bot = MessagesController.getInstance(this.currentAccount).getInputUser(user);
        req.query = query;
        req.offset = offset;
        if (user.bot_inline_geo && (location = this.lastKnownLocation) != null && location.getLatitude() != -1000.0d) {
            req.flags |= 1;
            req.geo_point = new TLRPC.TL_inputGeoPoint();
            req.geo_point.lat = AndroidUtilities.fixLocationCoord(this.lastKnownLocation.getLatitude());
            req.geo_point._long = AndroidUtilities.fixLocationCoord(this.lastKnownLocation.getLongitude());
        }
        long j = this.dialog_id;
        int lower_id = (int) j;
        if (lower_id != 0) {
            req.peer = MessagesController.getInstance(this.currentAccount).getInputPeer(lower_id);
        } else {
            req.peer = new TLRPC.TL_inputPeerEmpty();
        }
        this.contextQueryReqid = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, requestDelegate, 2);
    }

    public /* synthetic */ void lambda$searchForContextBotResults$4$MentionsAdapter(final String query, final boolean cache, final TLRPC.User user, final String offset, final MessagesStorage messagesStorage, final String key, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$NUg_R8x3TMAeuPh7rR31ESKGE7k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$MentionsAdapter(query, cache, response, user, offset, messagesStorage, key);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$MentionsAdapter(String query, boolean cache, TLObject response, TLRPC.User user, String offset, MessagesStorage messagesStorage, String key) {
        if (!query.equals(this.searchingContextQuery)) {
            return;
        }
        this.contextQueryReqid = 0;
        if (cache && response == null) {
            searchForContextBotResults(false, user, query, offset);
        } else {
            MentionsAdapterDelegate mentionsAdapterDelegate = this.delegate;
            if (mentionsAdapterDelegate != null) {
                mentionsAdapterDelegate.onContextSearch(false);
            }
        }
        if (response instanceof TLRPC.TL_messages_botResults) {
            TLRPC.TL_messages_botResults res = (TLRPC.TL_messages_botResults) response;
            if (!cache && res.cache_time != 0) {
                messagesStorage.saveBotCache(key, res);
            }
            this.nextQueryOffset = res.next_offset;
            if (this.searchResultBotContextSwitch == null) {
                this.searchResultBotContextSwitch = res.switch_pm;
            }
            int a = 0;
            while (a < res.results.size()) {
                TLRPC.BotInlineResult result = res.results.get(a);
                if (!(result.document instanceof TLRPC.TL_document) && !(result.photo instanceof TLRPC.TL_photo) && !"game".equals(result.type) && result.content == null && (result.send_message instanceof TLRPC.TL_botInlineMessageMediaAuto)) {
                    res.results.remove(a);
                    a--;
                }
                result.query_id = res.query_id;
                a++;
            }
            int a2 = 0;
            if (this.searchResultBotContext == null || offset.length() == 0) {
                this.searchResultBotContext = res.results;
                this.contextMedia = res.gallery;
            } else {
                a2 = 1;
                this.searchResultBotContext.addAll(res.results);
                if (res.results.isEmpty()) {
                    this.nextQueryOffset = "";
                }
            }
            Runnable runnable = this.cancelDelayRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.cancelDelayRunnable = null;
            }
            this.searchResultHashtags = null;
            this.searchResultUsernames = null;
            this.searchResultUsernamesMap = null;
            this.searchResultCommands = null;
            this.searchResultSuggestions = null;
            this.searchResultCommandsHelp = null;
            this.searchResultCommandsUsers = null;
            if (a2 != 0) {
                boolean hasTop = this.searchResultBotContextSwitch != null;
                notifyItemChanged(((this.searchResultBotContext.size() - res.results.size()) + (hasTop ? 1 : 0)) - 1);
                notifyItemRangeInserted((this.searchResultBotContext.size() - res.results.size()) + (hasTop ? 1 : 0), res.results.size());
            } else {
                notifyDataSetChanged();
            }
            this.delegate.needChangePanelVisibility((this.searchResultBotContext.isEmpty() && this.searchResultBotContextSwitch == null) ? false : true);
        }
    }

    public void setNeedPannel(boolean need) {
        this.needPannel = need;
    }

    public void searchUsernameOrHashtag(String text, int position, ArrayList<MessageObject> messageObjects, boolean usernameOnly) {
        int searchPostion;
        int foundType;
        int dogPostion;
        ArrayList<TLRPC.TL_topPeer> inlineBots;
        TLRPC.Chat chat;
        SparseArray<TLRPC.User> newResultsHashMap;
        TLRPC.ChatFull chatFull;
        SparseArray<TLRPC.User> newResultsHashMap2;
        String query;
        Runnable runnable = this.cancelDelayRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.cancelDelayRunnable = null;
        }
        if (this.channelReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.channelReqId, true);
            this.channelReqId = 0;
        }
        Runnable runnable2 = this.searchGlobalRunnable;
        if (runnable2 != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable2);
            this.searchGlobalRunnable = null;
        }
        if (TextUtils.isEmpty(text)) {
            searchForContextBot(null, null);
            this.delegate.needChangePanelVisibility(false);
            this.lastText = null;
            return;
        }
        if (text.length() <= 0) {
            searchPostion = position;
        } else {
            int searchPostion2 = position - 1;
            searchPostion = searchPostion2;
        }
        this.lastText = null;
        this.lastUsernameOnly = usernameOnly;
        StringBuilder result = new StringBuilder();
        if (!usernameOnly && this.needBotContext && text.charAt(0) == '@') {
            int index = text.indexOf(32);
            int len = text.length();
            String username = null;
            if (index > 0) {
                username = text.substring(1, index);
                String query2 = text.substring(index + 1);
                query = query2;
            } else if (text.charAt(len - 1) == 't' && text.charAt(len - 2) == 'o' && text.charAt(len - 3) == 'b') {
                username = text.substring(1);
                query = "";
            } else {
                searchForContextBot(null, null);
                query = null;
            }
            if (username != null && username.length() >= 1) {
                int a = 1;
                while (true) {
                    if (a >= username.length()) {
                        break;
                    }
                    char ch = username.charAt(a);
                    if ((ch >= '0' && ch <= '9') || ((ch >= 'a' && ch <= 'z') || ((ch >= 'A' && ch <= 'Z') || ch == '_'))) {
                        a++;
                    } else {
                        username = "";
                        break;
                    }
                }
            } else {
                username = "";
            }
            searchForContextBot(username, query);
        } else {
            searchForContextBot(null, null);
        }
        if (this.foundContextBot != null) {
            return;
        }
        MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
        if (usernameOnly) {
            result.append(text.substring(1));
            this.resultStartPosition = 0;
            this.resultLength = result.length();
            foundType = 0;
            dogPostion = -1;
        } else {
            for (int a2 = searchPostion; a2 >= 0; a2--) {
                if (a2 < text.length()) {
                    char ch2 = text.charAt(a2);
                    if (a2 == 0 || text.charAt(a2 - 1) == ' ' || text.charAt(a2 - 1) == '\n') {
                        if (ch2 == '@') {
                            if (this.needUsernames || (this.needBotContext && a2 == 0)) {
                                if (this.info == null && a2 != 0) {
                                    this.lastText = text;
                                    this.lastPosition = position;
                                    this.messages = messageObjects;
                                    this.delegate.needChangePanelVisibility(false);
                                    return;
                                }
                                int dogPostion2 = a2;
                                this.resultStartPosition = a2;
                                this.resultLength = result.length() + 1;
                                foundType = 0;
                                dogPostion = dogPostion2;
                            }
                        } else if (ch2 == '#') {
                            if (!this.searchAdapterHelper.loadRecentHashtags()) {
                                this.lastText = text;
                                this.lastPosition = position;
                                this.messages = messageObjects;
                                this.delegate.needChangePanelVisibility(false);
                                return;
                            }
                            this.resultStartPosition = a2;
                            this.resultLength = result.length() + 1;
                            result.insert(0, ch2);
                            foundType = 1;
                            dogPostion = -1;
                        } else {
                            if (a2 == 0 && this.botInfo != null && ch2 == '/') {
                                this.resultStartPosition = a2;
                                this.resultLength = result.length() + 1;
                                foundType = 2;
                                dogPostion = -1;
                                break;
                            }
                            if (ch2 == ':' && result.length() > 0) {
                                boolean isNextPunctiationChar = punctuationsChars.indexOf(result.charAt(0)) >= 0;
                                if (!isNextPunctiationChar || result.length() > 1) {
                                    this.resultStartPosition = a2;
                                    this.resultLength = result.length() + 1;
                                    foundType = 3;
                                    dogPostion = -1;
                                    break;
                                }
                            }
                        }
                    }
                    if (ch2 == ' ') {
                        break;
                    } else {
                        result.insert(0, ch2);
                    }
                }
            }
            foundType = -1;
            dogPostion = -1;
        }
        if (!this.needPannel) {
            return;
        }
        if (foundType == -1) {
            this.delegate.needChangePanelVisibility(false);
            return;
        }
        if (foundType != 0) {
            if (foundType == 1) {
                ArrayList<String> newResult = new ArrayList<>();
                String hashtagString = result.toString().toLowerCase();
                ArrayList<SearchAdapterHelper.HashtagObject> hashtags = this.searchAdapterHelper.getHashtags();
                for (int a3 = 0; a3 < hashtags.size(); a3++) {
                    SearchAdapterHelper.HashtagObject hashtagObject = hashtags.get(a3);
                    if (hashtagObject != null && hashtagObject.hashtag != null && hashtagObject.hashtag.startsWith(hashtagString)) {
                        newResult.add(hashtagObject.hashtag);
                    }
                }
                this.searchResultHashtags = newResult;
                this.searchResultUsernames = null;
                this.searchResultUsernamesMap = null;
                this.searchResultCommands = null;
                this.searchResultCommandsHelp = null;
                this.searchResultCommandsUsers = null;
                this.searchResultSuggestions = null;
                notifyDataSetChanged();
                this.delegate.needChangePanelVisibility(!newResult.isEmpty());
                return;
            }
            if (foundType == 2) {
                ArrayList<String> newResult2 = new ArrayList<>();
                ArrayList<String> newResultHelp = new ArrayList<>();
                ArrayList<TLRPC.User> newResultUsers = new ArrayList<>();
                String command = result.toString().toLowerCase();
                for (int b = 0; b < this.botInfo.size(); b++) {
                    TLRPC.BotInfo info = this.botInfo.valueAt(b);
                    for (int a4 = 0; a4 < info.commands.size(); a4++) {
                        TLRPC.TL_botCommand botCommand = info.commands.get(a4);
                        if (botCommand != null && botCommand.command != null && botCommand.command.startsWith(command)) {
                            newResult2.add("/" + botCommand.command);
                            newResultHelp.add(botCommand.description);
                            newResultUsers.add(messagesController.getUser(Integer.valueOf(info.user_id)));
                        }
                    }
                }
                this.searchResultHashtags = null;
                this.searchResultUsernames = null;
                this.searchResultUsernamesMap = null;
                this.searchResultSuggestions = null;
                this.searchResultCommands = newResult2;
                this.searchResultCommandsHelp = newResultHelp;
                this.searchResultCommandsUsers = newResultUsers;
                notifyDataSetChanged();
                this.delegate.needChangePanelVisibility(!newResult2.isEmpty());
                return;
            }
            if (foundType == 3) {
                String[] newLanguage = AndroidUtilities.getCurrentKeyboardLanguage();
                if (!Arrays.equals(newLanguage, this.lastSearchKeyboardLanguage)) {
                    MediaDataController.getInstance(this.currentAccount).fetchNewEmojiKeywords(newLanguage);
                }
                this.lastSearchKeyboardLanguage = newLanguage;
                MediaDataController.getInstance(this.currentAccount).getEmojiSuggestions(this.lastSearchKeyboardLanguage, result.toString(), false, new MediaDataController.KeywordResultCallback() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$IiRdFXmMxMFWwA6ADFhmoSeJmH0
                    @Override // im.uwrkaxlmjj.messenger.MediaDataController.KeywordResultCallback
                    public final void run(ArrayList arrayList, String str) {
                        this.f$0.lambda$searchUsernameOrHashtag$7$MentionsAdapter(arrayList, str);
                    }
                });
                return;
            }
            return;
        }
        final ArrayList<Integer> users = new ArrayList<>();
        for (int a5 = 0; a5 < Math.min(100, messageObjects.size()); a5++) {
            int from_id = messageObjects.get(a5).messageOwner.from_id;
            if (!users.contains(Integer.valueOf(from_id))) {
                users.add(Integer.valueOf(from_id));
            }
        }
        String usernameString = result.toString().toLowerCase();
        boolean hasSpace = usernameString.indexOf(32) >= 0;
        final ArrayList<TLRPC.User> newResult3 = new ArrayList<>();
        SparseArray<TLRPC.User> newResultsHashMap3 = new SparseArray<>();
        final SparseArray<TLRPC.User> newMap = new SparseArray<>();
        ArrayList<TLRPC.TL_topPeer> inlineBots2 = MediaDataController.getInstance(this.currentAccount).inlineBots;
        if (usernameOnly || !this.needBotContext || dogPostion != 0 || inlineBots2.isEmpty()) {
            inlineBots = inlineBots2;
        } else {
            int count = 0;
            int a6 = 0;
            while (true) {
                if (a6 >= inlineBots2.size()) {
                    inlineBots = inlineBots2;
                    break;
                }
                TLRPC.User user = messagesController.getUser(Integer.valueOf(inlineBots2.get(a6).peer.user_id));
                if (user == null) {
                    inlineBots = inlineBots2;
                } else {
                    inlineBots = inlineBots2;
                    if (user.username != null && user.username.length() > 0 && ((usernameString.length() > 0 && user.username.toLowerCase().startsWith(usernameString)) || usernameString.length() == 0)) {
                        newResult3.add(user);
                        newResultsHashMap3.put(user.id, user);
                        count++;
                    }
                    if (count == 5) {
                        break;
                    }
                }
                a6++;
                inlineBots2 = inlineBots;
            }
        }
        ChatActivity chatActivity = this.parentFragment;
        if (chatActivity != null) {
            chat = chatActivity.getCurrentChat();
        } else {
            TLRPC.ChatFull chatFull2 = this.info;
            if (chatFull2 != null) {
                chat = messagesController.getChat(Integer.valueOf(chatFull2.id));
            } else {
                chat = null;
            }
        }
        if (chat == null || (chatFull = this.info) == null || chatFull.participants == null) {
            newResultsHashMap = newResultsHashMap3;
        } else if (!ChatObject.isChannel(chat) || chat.megagroup) {
            if (this.info.participants.participants.size() > 1) {
                TLRPC.User forAll = new TLRPC.TL_user();
                forAll.first_name = "all";
                forAll.last_name = "all";
                forAll.id = -1;
                newResult3.add(forAll);
                newMap.put(forAll.id, forAll);
            }
            int a7 = 0;
            while (a7 < this.info.participants.participants.size()) {
                TLRPC.ChatParticipant chatParticipant = this.info.participants.participants.get(a7);
                TLRPC.User user2 = messagesController.getUser(Integer.valueOf(chatParticipant.user_id));
                if (user2 == null) {
                    newResultsHashMap2 = newResultsHashMap3;
                } else if (!usernameOnly && UserObject.isUserSelf(user2)) {
                    newResultsHashMap2 = newResultsHashMap3;
                } else if (newResultsHashMap3.indexOfKey(user2.id) >= 0) {
                    newResultsHashMap2 = newResultsHashMap3;
                } else if (usernameString.length() == 0) {
                    if (user2.deleted) {
                        newResultsHashMap2 = newResultsHashMap3;
                    } else {
                        newResult3.add(user2);
                        newResultsHashMap2 = newResultsHashMap3;
                    }
                } else if (user2.username != null && user2.username.length() > 0 && user2.username.toLowerCase().startsWith(usernameString)) {
                    newResult3.add(user2);
                    newMap.put(user2.id, user2);
                    newResultsHashMap2 = newResultsHashMap3;
                } else if (user2.first_name != null && user2.first_name.length() > 0 && user2.first_name.toLowerCase().startsWith(usernameString)) {
                    newResult3.add(user2);
                    newMap.put(user2.id, user2);
                    newResultsHashMap2 = newResultsHashMap3;
                } else if (user2.last_name != null && user2.last_name.length() > 0 && user2.last_name.toLowerCase().startsWith(usernameString)) {
                    newResult3.add(user2);
                    newMap.put(user2.id, user2);
                    newResultsHashMap2 = newResultsHashMap3;
                } else if (hasSpace) {
                    newResultsHashMap2 = newResultsHashMap3;
                    if (ContactsController.formatName(user2.first_name, user2.last_name).toLowerCase().startsWith(usernameString)) {
                        newResult3.add(user2);
                        newMap.put(user2.id, user2);
                    }
                } else {
                    newResultsHashMap2 = newResultsHashMap3;
                }
                a7++;
                newResultsHashMap3 = newResultsHashMap2;
            }
            newResultsHashMap = newResultsHashMap3;
        } else {
            newResultsHashMap = newResultsHashMap3;
        }
        Collections.sort(newResult3, new Comparator() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$Bn2yBNQYanrCRteRauH0r3Zb5wA
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MentionsAdapter.lambda$searchUsernameOrHashtag$5(newMap, users, (TLRPC.User) obj, (TLRPC.User) obj2);
            }
        });
        this.searchResultHashtags = null;
        this.searchResultCommands = null;
        this.searchResultCommandsHelp = null;
        this.searchResultCommandsUsers = null;
        this.searchResultSuggestions = null;
        if (chat == null || !chat.megagroup || usernameString.length() <= 0) {
            showUsersResult(newResult3, newMap, true);
            return;
        }
        if (newResult3.size() < 5) {
            Runnable runnable3 = new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$500eH-lOVVoEhBwgWi_l4BwrC34
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$searchUsernameOrHashtag$6$MentionsAdapter(newResult3, newMap);
                }
            };
            this.cancelDelayRunnable = runnable3;
            AndroidUtilities.runOnUIThread(runnable3, 1000L);
        } else {
            showUsersResult(newResult3, newMap, true);
        }
        AnonymousClass5 anonymousClass5 = new AnonymousClass5(chat, usernameString, newResult3, newMap, messagesController);
        this.searchGlobalRunnable = anonymousClass5;
        AndroidUtilities.runOnUIThread(anonymousClass5, 200L);
    }

    static /* synthetic */ int lambda$searchUsernameOrHashtag$5(SparseArray newMap, ArrayList users, TLRPC.User lhs, TLRPC.User rhs) {
        if (newMap.indexOfKey(lhs.id) >= 0 && newMap.indexOfKey(rhs.id) >= 0) {
            return 0;
        }
        if (newMap.indexOfKey(lhs.id) >= 0) {
            return -1;
        }
        if (newMap.indexOfKey(rhs.id) >= 0) {
            return 1;
        }
        int lhsNum = users.indexOf(Integer.valueOf(lhs.id));
        int rhsNum = users.indexOf(Integer.valueOf(rhs.id));
        if (lhsNum != -1 && rhsNum != -1) {
            if (lhsNum < rhsNum) {
                return -1;
            }
            return lhsNum == rhsNum ? 0 : 1;
        }
        if (lhsNum == -1 || rhsNum != -1) {
            return (lhsNum != -1 || rhsNum == -1) ? 0 : 1;
        }
        return -1;
    }

    public /* synthetic */ void lambda$searchUsernameOrHashtag$6$MentionsAdapter(ArrayList newResult, SparseArray newMap) {
        this.cancelDelayRunnable = null;
        showUsersResult(newResult, newMap, true);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.adapters.MentionsAdapter$5, reason: invalid class name */
    class AnonymousClass5 implements Runnable {
        final /* synthetic */ TLRPC.Chat val$chat;
        final /* synthetic */ MessagesController val$messagesController;
        final /* synthetic */ SparseArray val$newMap;
        final /* synthetic */ ArrayList val$newResult;
        final /* synthetic */ String val$usernameString;

        AnonymousClass5(TLRPC.Chat chat, String str, ArrayList arrayList, SparseArray sparseArray, MessagesController messagesController) {
            this.val$chat = chat;
            this.val$usernameString = str;
            this.val$newResult = arrayList;
            this.val$newMap = sparseArray;
            this.val$messagesController = messagesController;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (MentionsAdapter.this.searchGlobalRunnable != this) {
                return;
            }
            TLRPC.TL_channels_getParticipants req = new TLRPC.TL_channels_getParticipants();
            req.channel = MessagesController.getInputChannel(this.val$chat);
            req.limit = 20;
            req.offset = 0;
            TLRPC.TL_channelParticipantsSearch channelParticipantsSearch = new TLRPC.TL_channelParticipantsSearch();
            channelParticipantsSearch.q = this.val$usernameString;
            req.filter = channelParticipantsSearch;
            final int currentReqId = MentionsAdapter.access$1604(MentionsAdapter.this);
            MentionsAdapter mentionsAdapter = MentionsAdapter.this;
            ConnectionsManager connectionsManager = ConnectionsManager.getInstance(mentionsAdapter.currentAccount);
            final ArrayList arrayList = this.val$newResult;
            final SparseArray sparseArray = this.val$newMap;
            final MessagesController messagesController = this.val$messagesController;
            mentionsAdapter.channelReqId = connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$5$VwUHGO5DL8h5H_zb1i-PNVb0yec
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$run$1$MentionsAdapter$5(currentReqId, arrayList, sparseArray, messagesController, tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$run$1$MentionsAdapter$5(final int currentReqId, final ArrayList newResult, final SparseArray newMap, final MessagesController messagesController, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$5$d_hR4iw-8RnMGhoEI1ZGMnQsQ8w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$MentionsAdapter$5(currentReqId, newResult, newMap, error, response, messagesController);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$MentionsAdapter$5(int currentReqId, ArrayList newResult, SparseArray newMap, TLRPC.TL_error error, TLObject response, MessagesController messagesController) {
            if (MentionsAdapter.this.channelReqId != 0 && currentReqId == MentionsAdapter.this.channelLastReqId && MentionsAdapter.this.searchResultUsernamesMap != null && MentionsAdapter.this.searchResultUsernames != null) {
                MentionsAdapter.this.showUsersResult(newResult, newMap, false);
                if (error == null) {
                    TLRPC.TL_channels_channelParticipants res = (TLRPC.TL_channels_channelParticipants) response;
                    messagesController.putUsers(res.users, false);
                    boolean z = !MentionsAdapter.this.searchResultUsernames.isEmpty();
                    if (!res.participants.isEmpty()) {
                        int currentUserId = UserConfig.getInstance(MentionsAdapter.this.currentAccount).getClientUserId();
                        for (int a = 0; a < res.participants.size(); a++) {
                            TLRPC.ChannelParticipant participant = res.participants.get(a);
                            if (MentionsAdapter.this.searchResultUsernamesMap.indexOfKey(participant.user_id) < 0 && (MentionsAdapter.this.isSearchingMentions || participant.user_id != currentUserId)) {
                                TLRPC.User user = messagesController.getUser(Integer.valueOf(participant.user_id));
                                if (user != null) {
                                    MentionsAdapter.this.searchResultUsernames.add(user);
                                } else {
                                    return;
                                }
                            }
                        }
                    }
                }
                MentionsAdapter.this.notifyDataSetChanged();
                MentionsAdapter.this.delegate.needChangePanelVisibility(!MentionsAdapter.this.searchResultUsernames.isEmpty());
            }
            MentionsAdapter.this.channelReqId = 0;
        }
    }

    public /* synthetic */ void lambda$searchUsernameOrHashtag$7$MentionsAdapter(ArrayList param, String alias) {
        this.searchResultSuggestions = param;
        this.searchResultHashtags = null;
        this.searchResultUsernames = null;
        this.searchResultUsernamesMap = null;
        this.searchResultCommands = null;
        this.searchResultCommandsHelp = null;
        this.searchResultCommandsUsers = null;
        notifyDataSetChanged();
        MentionsAdapterDelegate mentionsAdapterDelegate = this.delegate;
        ArrayList<MediaDataController.KeywordResult> arrayList = this.searchResultSuggestions;
        mentionsAdapterDelegate.needChangePanelVisibility((arrayList == null || arrayList.isEmpty()) ? false : true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showUsersResult(ArrayList<TLRPC.User> newResult, SparseArray<TLRPC.User> newMap, boolean notify) {
        this.searchResultUsernames = newResult;
        this.searchResultUsernamesMap = newMap;
        Runnable runnable = this.cancelDelayRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.cancelDelayRunnable = null;
        }
        if (notify) {
            notifyDataSetChanged();
            this.delegate.needChangePanelVisibility(!this.searchResultUsernames.isEmpty());
        }
    }

    public int getResultStartPosition() {
        return this.resultStartPosition;
    }

    public int getResultLength() {
        return this.resultLength;
    }

    public ArrayList<TLRPC.BotInlineResult> getSearchResultBotContext() {
        return this.searchResultBotContext;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        if (this.foundContextBot != null && !this.inlineMediaEnabled) {
            return 1;
        }
        ArrayList<TLRPC.BotInlineResult> arrayList = this.searchResultBotContext;
        if (arrayList != null) {
            return arrayList.size() + (this.searchResultBotContextSwitch == null ? 0 : 1);
        }
        ArrayList<TLRPC.User> arrayList2 = this.searchResultUsernames;
        if (arrayList2 != null) {
            return arrayList2.size();
        }
        ArrayList<String> arrayList3 = this.searchResultHashtags;
        if (arrayList3 != null) {
            return arrayList3.size();
        }
        ArrayList<String> arrayList4 = this.searchResultCommands;
        if (arrayList4 != null) {
            return arrayList4.size();
        }
        ArrayList<MediaDataController.KeywordResult> arrayList5 = this.searchResultSuggestions;
        if (arrayList5 != null) {
            return arrayList5.size();
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        if (this.foundContextBot != null && !this.inlineMediaEnabled) {
            return 3;
        }
        if (this.searchResultBotContext != null) {
            if (position == 0 && this.searchResultBotContextSwitch != null) {
                return 2;
            }
            return 1;
        }
        return 0;
    }

    public void addHashtagsFromMessage(CharSequence message) {
        this.searchAdapterHelper.addHashtagsFromMessage(message);
    }

    public int getItemPosition(int i) {
        if (this.searchResultBotContext != null && this.searchResultBotContextSwitch != null) {
            return i - 1;
        }
        return i;
    }

    public Object getItem(int i) {
        if (this.searchResultBotContext != null) {
            TLRPC.TL_inlineBotSwitchPM tL_inlineBotSwitchPM = this.searchResultBotContextSwitch;
            if (tL_inlineBotSwitchPM != null) {
                if (i == 0) {
                    return tL_inlineBotSwitchPM;
                }
                i--;
            }
            if (i < 0 || i >= this.searchResultBotContext.size()) {
                return null;
            }
            return this.searchResultBotContext.get(i);
        }
        ArrayList<TLRPC.User> arrayList = this.searchResultUsernames;
        if (arrayList != null) {
            if (i < 0 || i >= arrayList.size()) {
                return null;
            }
            return this.searchResultUsernames.get(i);
        }
        ArrayList<String> arrayList2 = this.searchResultHashtags;
        if (arrayList2 != null) {
            if (i < 0 || i >= arrayList2.size()) {
                return null;
            }
            return this.searchResultHashtags.get(i);
        }
        ArrayList<MediaDataController.KeywordResult> arrayList3 = this.searchResultSuggestions;
        if (arrayList3 != null) {
            if (i < 0 || i >= arrayList3.size()) {
                return null;
            }
            return this.searchResultSuggestions.get(i);
        }
        ArrayList<String> arrayList4 = this.searchResultCommands;
        if (arrayList4 == null || i < 0 || i >= arrayList4.size()) {
            return null;
        }
        if (this.searchResultCommandsUsers != null && (this.botsCount != 1 || (this.info instanceof TLRPC.TL_channelFull))) {
            if (this.searchResultCommandsUsers.get(i) == null) {
                return String.format("%s", this.searchResultCommands.get(i));
            }
            Object[] objArr = new Object[2];
            objArr[0] = this.searchResultCommands.get(i);
            objArr[1] = this.searchResultCommandsUsers.get(i) != null ? this.searchResultCommandsUsers.get(i).username : "";
            return String.format("%s@%s", objArr);
        }
        return this.searchResultCommands.get(i);
    }

    public boolean isLongClickEnabled() {
        return (this.searchResultHashtags == null && this.searchResultCommands == null) ? false : true;
    }

    public boolean isBotCommands() {
        return this.searchResultCommands != null;
    }

    public boolean isBotContext() {
        return this.searchResultBotContext != null;
    }

    public boolean isBannedInline() {
        return (this.foundContextBot == null || this.inlineMediaEnabled) ? false : true;
    }

    public boolean isMediaLayout() {
        return this.contextMedia;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        return this.foundContextBot == null || this.inlineMediaEnabled;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType == 0) {
            view = new MentionCell(this.mContext);
            ((MentionCell) view).setIsDarkTheme(this.isDarkTheme);
        } else if (viewType == 1) {
            view = new ContextLinkCell(this.mContext);
            ((ContextLinkCell) view).setDelegate(new ContextLinkCell.ContextLinkCellDelegate() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$MentionsAdapter$hsoiPYInTxQQwNiv7S-IRg0Wdos
                @Override // im.uwrkaxlmjj.ui.cells.ContextLinkCell.ContextLinkCellDelegate
                public final void didPressedImage(ContextLinkCell contextLinkCell) {
                    this.f$0.lambda$onCreateViewHolder$8$MentionsAdapter(contextLinkCell);
                }
            });
        } else if (viewType == 2) {
            view = new BotSwitchCell(this.mContext);
        } else {
            TextView textView = new TextView(this.mContext);
            textView.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
            textView.setTextSize(1, 14.0f);
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
            view = textView;
        }
        return new RecyclerListView.Holder(view);
    }

    public /* synthetic */ void lambda$onCreateViewHolder$8$MentionsAdapter(ContextLinkCell cell) {
        this.delegate.onContextClick(cell.getResult());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        boolean z = false;
        if (holder.getItemViewType() == 3) {
            TextView textView = (TextView) holder.itemView;
            TLRPC.Chat chat = this.parentFragment.getCurrentChat();
            if (chat != null) {
                if (!ChatObject.hasAdminRights(chat) && chat.default_banned_rights != null && chat.default_banned_rights.send_inline) {
                    textView.setText(LocaleController.getString("GlobalAttachInlineRestricted", R.string.GlobalAttachInlineRestricted));
                    return;
                } else if (AndroidUtilities.isBannedForever(chat.banned_rights)) {
                    textView.setText(LocaleController.getString("AttachInlineRestrictedForever", R.string.AttachInlineRestrictedForever));
                    return;
                } else {
                    textView.setText(LocaleController.formatString("AttachInlineRestricted", R.string.AttachInlineRestricted, LocaleController.formatDateForBan(chat.banned_rights.until_date)));
                    return;
                }
            }
            return;
        }
        if (this.searchResultBotContext != null) {
            boolean hasTop = this.searchResultBotContextSwitch != null;
            if (holder.getItemViewType() == 2) {
                if (hasTop) {
                    ((BotSwitchCell) holder.itemView).setText(this.searchResultBotContextSwitch.text);
                    return;
                }
                return;
            }
            if (hasTop) {
                position--;
            }
            ContextLinkCell contextLinkCell = (ContextLinkCell) holder.itemView;
            TLRPC.BotInlineResult botInlineResult = this.searchResultBotContext.get(position);
            boolean z2 = this.contextMedia;
            boolean z3 = position != this.searchResultBotContext.size() - 1;
            if (hasTop && position == 0) {
                z = true;
            }
            contextLinkCell.setLink(botInlineResult, z2, z3, z);
            return;
        }
        if (this.searchResultUsernames != null) {
            ((MentionCell) holder.itemView).setUser(this.searchResultUsernames.get(position));
            return;
        }
        if (this.searchResultHashtags != null) {
            ((MentionCell) holder.itemView).setText(this.searchResultHashtags.get(position));
            return;
        }
        if (this.searchResultSuggestions != null) {
            ((MentionCell) holder.itemView).setEmojiSuggestion(this.searchResultSuggestions.get(position));
            return;
        }
        if (this.searchResultCommands != null) {
            MentionCell mentionCell = (MentionCell) holder.itemView;
            String str = this.searchResultCommands.get(position);
            String str2 = this.searchResultCommandsHelp.get(position);
            ArrayList<TLRPC.User> arrayList = this.searchResultCommandsUsers;
            mentionCell.setBotCommand(str, str2, arrayList != null ? arrayList.get(position) : null);
        }
    }

    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        TLRPC.User user;
        if (requestCode == 2 && (user = this.foundContextBot) != null && user.bot_inline_geo) {
            if (grantResults.length > 0 && grantResults[0] == 0) {
                this.locationProvider.start();
            } else {
                onLocationUnavailable();
            }
        }
    }
}
