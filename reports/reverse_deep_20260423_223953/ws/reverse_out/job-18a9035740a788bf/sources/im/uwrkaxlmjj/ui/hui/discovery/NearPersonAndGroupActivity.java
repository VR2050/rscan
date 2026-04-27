package im.uwrkaxlmjj.ui.hui.discovery;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Property;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.LocationController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ManageChatUserCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.ShareLocationDrawable;
import im.uwrkaxlmjj.ui.dialogs.DialogNearPersonFilter;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.utils.NetworkUtils;
import im.uwrkaxlmjj.ui.utils.SimulatorUtil;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NearPersonAndGroupActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, LocationController.LocationFetchCallback {
    private static final int SHORT_POLL_TIMEOUT = 25000;
    private AvatarDrawable avatarDrawable;
    private boolean canCreateGroup;
    private int chatsCreateRow;
    private int chatsEndRow;
    private int chatsHeaderRow;
    private int chatsSectionRow;
    private int chatsStartRow;
    private Runnable checkExpiredRunnable;
    private boolean checkingCanCreate;
    private int currentChatId;
    private CharSequence currentName;
    private CharSequence currrntStatus;
    private boolean firstLoaded;
    private ActionIntroActivity groupCreateActivity;
    private int helpRow;
    private boolean isAdmin;
    private TLRPC.FileLocation lastAvatar;
    private long lastLoadedLocationTime;
    private String lastName;
    private int lastStatus;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private AlertDialog loadingDialog;
    private TextView m_tvCurrent;
    private TextView m_tvNearGroup;
    private TextView m_tvNearPerson;
    private int reqId;
    private int rowCount;
    private AnimatorSet showProgressAnimation;
    private Runnable showProgressRunnable;
    private boolean showingLoadingProgress;
    private int statusColor;
    private int statusOnlineColor;
    private int usersEmptyRow;
    private int usersEndRow;
    private int usersHeaderRow;
    private int usersSectionRow;
    private int usersStartRow;
    private ListAdapterGroup listAdapterGroup = null;
    private ArrayList<View> animatingViews = new ArrayList<>();
    private Runnable shortPollRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.1
        @Override // java.lang.Runnable
        public void run() {
            if (NearPersonAndGroupActivity.this.shortPollRunnable != null) {
                NearPersonAndGroupActivity.this.sendRequest(true);
                AndroidUtilities.cancelRunOnUIThread(NearPersonAndGroupActivity.this.shortPollRunnable);
                AndroidUtilities.runOnUIThread(NearPersonAndGroupActivity.this.shortPollRunnable, 25000L);
            }
        }
    };
    private int groupRowCount = 1;
    private ArrayList<TLRPC.TL_peerLocated> users = new ArrayList<>(getLocationController().getCachedNearbyUsers());
    private ArrayList<TLRPC.TL_peerLocated> chats = new ArrayList<>(getLocationController().getCachedNearbyChats());

    private void initView(Context context) {
        FrameLayout flContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) this.fragmentView.findViewById(R.attr.rl_title_bar).getLayoutParams();
        layoutParams.topMargin = AndroidUtilities.statusBarHeight;
        this.fragmentView.findViewById(R.attr.rl_title_bar).setLayoutParams(layoutParams);
        this.m_tvNearPerson = (TextView) this.fragmentView.findViewById(R.attr.tv_near_person);
        this.m_tvNearGroup = (TextView) this.fragmentView.findViewById(R.attr.tv_near_group);
        TextView textView = this.m_tvNearPerson;
        this.m_tvCurrent = textView;
        textView.setText(LocaleController.getString("PeopleNearbyHeader", R.string.PeopleNearbyHeader));
        this.m_tvNearGroup.setText(LocaleController.getString("ChatsNearbyHeader", R.string.ChatsNearbyHeader));
        ((ImageView) this.fragmentView.findViewById(R.attr.iv_back)).setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.MULTIPLY));
        this.fragmentView.findViewById(R.attr.iv_back).setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarDefaultSelector)));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listViewAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.2
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        this.listView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        flContainer.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        initListener(context);
    }

    private void initListener(final Context context) {
        this.m_tvNearPerson.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (NearPersonAndGroupActivity.this.m_tvCurrent.getId() != view.getId()) {
                    NearPersonAndGroupActivity.this.m_tvNearPerson.setTextColor(-1);
                    NearPersonAndGroupActivity.this.m_tvNearPerson.setBackground(context.getResources().getDrawable(R.drawable.near_person_tab1_bg));
                    NearPersonAndGroupActivity.this.m_tvCurrent.setTextColor(context.getResources().getColor(R.color.new_call_tab_text_color_unseled));
                    NearPersonAndGroupActivity.this.m_tvCurrent.setBackground(context.getResources().getDrawable(R.drawable.near_person_tab2_bg));
                    NearPersonAndGroupActivity nearPersonAndGroupActivity = NearPersonAndGroupActivity.this;
                    nearPersonAndGroupActivity.m_tvCurrent = nearPersonAndGroupActivity.m_tvNearPerson;
                    NearPersonAndGroupActivity.this.listView.setAdapter(NearPersonAndGroupActivity.this.listViewAdapter);
                }
            }
        });
        this.m_tvNearGroup.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.4
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (NearPersonAndGroupActivity.this.m_tvCurrent.getId() != view.getId()) {
                    NearPersonAndGroupActivity.this.m_tvNearGroup.setTextColor(-1);
                    NearPersonAndGroupActivity.this.m_tvNearGroup.setBackground(context.getResources().getDrawable(R.drawable.near_person_tab2_unseled_bg));
                    NearPersonAndGroupActivity.this.m_tvCurrent.setTextColor(context.getResources().getColor(R.color.new_call_tab_text_color_unseled));
                    NearPersonAndGroupActivity.this.m_tvCurrent.setBackground(context.getResources().getDrawable(R.drawable.near_person_tab1_unseled_bg));
                    NearPersonAndGroupActivity nearPersonAndGroupActivity = NearPersonAndGroupActivity.this;
                    nearPersonAndGroupActivity.m_tvCurrent = nearPersonAndGroupActivity.m_tvNearGroup;
                    if (NearPersonAndGroupActivity.this.listAdapterGroup == null) {
                        NearPersonAndGroupActivity nearPersonAndGroupActivity2 = NearPersonAndGroupActivity.this;
                        nearPersonAndGroupActivity2.listAdapterGroup = nearPersonAndGroupActivity2.new ListAdapterGroup(context);
                    }
                    NearPersonAndGroupActivity.this.listView.setAdapter(NearPersonAndGroupActivity.this.listAdapterGroup);
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_back).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                NearPersonAndGroupActivity.this.finishFragment();
            }
        });
        this.fragmentView.findViewById(R.attr.rl_more).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.6
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                DialogNearPersonFilter dialogNearPersonFilter = new DialogNearPersonFilter(NearPersonAndGroupActivity.this.getParentActivity());
                dialogNearPersonFilter.show();
            }
        });
    }

    public NearPersonAndGroupActivity() {
        checkForExpiredLocations(false);
        this.statusColor = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText);
        this.statusOnlineColor = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText);
        this.avatarDrawable = new AvatarDrawable();
        updateRows();
    }

    private void updateRows() {
        this.rowCount = 0;
        this.groupRowCount = 1;
        this.usersStartRow = -1;
        this.usersEndRow = -1;
        this.usersEmptyRow = -1;
        this.chatsStartRow = -1;
        this.chatsEndRow = -1;
        this.chatsCreateRow = -1;
        int i = 0 + 1;
        this.rowCount = i;
        this.helpRow = 0;
        this.rowCount = i + 1;
        this.usersHeaderRow = i;
        if (this.users.isEmpty()) {
            int i2 = this.rowCount;
            this.rowCount = i2 + 1;
            this.usersEmptyRow = i2;
        } else {
            int i3 = this.rowCount;
            this.usersStartRow = i3;
            int size = i3 + this.users.size();
            this.rowCount = size;
            this.usersEndRow = size;
        }
        int i4 = this.rowCount;
        int i5 = i4 + 1;
        this.rowCount = i5;
        this.usersSectionRow = i4;
        int i6 = i5 + 1;
        this.rowCount = i6;
        this.chatsHeaderRow = i5;
        this.rowCount = i6 + 1;
        this.chatsCreateRow = i6;
        if (!this.chats.isEmpty()) {
            int i7 = this.rowCount;
            this.chatsStartRow = i7;
            int size2 = i7 + this.chats.size();
            this.rowCount = size2;
            this.chatsEndRow = size2;
        }
        int i8 = this.rowCount;
        this.rowCount = i8 + 1;
        this.chatsSectionRow = i8;
        this.rowCount = this.users.size();
        this.groupRowCount = this.chats.size() + 1;
        if (this.m_tvCurrent == this.m_tvNearPerson) {
            ListAdapter listAdapter = this.listViewAdapter;
            if (listAdapter != null) {
                listAdapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        ListAdapterGroup listAdapterGroup = this.listAdapterGroup;
        if (listAdapterGroup != null) {
            listAdapterGroup.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.newLocationAvailable);
        getNotificationCenter().addObserver(this, NotificationCenter.newPeopleNearbyAvailable);
        getNotificationCenter().addObserver(this, NotificationCenter.needDeleteDialog);
        checkCanCreateGroup();
        sendRequest(false);
        AndroidUtilities.runOnUIThread(this.shortPollRunnable, 25000L);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.newLocationAvailable);
        getNotificationCenter().removeObserver(this, NotificationCenter.newPeopleNearbyAvailable);
        getNotificationCenter().removeObserver(this, NotificationCenter.needDeleteDialog);
        Runnable runnable = this.shortPollRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.shortPollRunnable = null;
        }
        Runnable runnable2 = this.checkExpiredRunnable;
        if (runnable2 != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable2);
            this.checkExpiredRunnable = null;
        }
        Runnable runnable3 = this.showProgressRunnable;
        if (runnable3 != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable3);
            this.showProgressRunnable = null;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setAddToContainer(false);
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_nearperson_and_group, (ViewGroup) null, false);
        initView(context);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$NearPersonAndGroupActivity$8BENkK6Zhc8DL6pEhwkMw0HgjP0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$0$NearPersonAndGroupActivity(view, i);
            }
        });
        updateRows();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$NearPersonAndGroupActivity(View view, int position) {
        int chatId;
        if (this.m_tvCurrent == this.m_tvNearPerson) {
            if (!this.users.isEmpty()) {
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.users.get(position).peer.user_id));
                if (user != null) {
                    Bundle args = new Bundle();
                    args.putInt("from_type", 5);
                    presentFragment(new AddContactsInfoActivity(args, user));
                    return;
                }
                return;
            }
            return;
        }
        if (position != 0) {
            TLRPC.TL_peerLocated peerLocated = this.chats.get(position - 1);
            Bundle args1 = new Bundle();
            if (peerLocated.peer instanceof TLRPC.TL_peerChat) {
                chatId = peerLocated.peer.chat_id;
            } else {
                chatId = peerLocated.peer.channel_id;
            }
            args1.putInt("chat_id", chatId);
            ChatActivity chatActivity = new ChatActivity(args1);
            presentFragment(chatActivity);
        }
    }

    private void openGroupCreate() {
        if (!this.canCreateGroup) {
            AlertsCreator.showSimpleAlert(this, LocaleController.getString("YourLocatedChannelsTooMuch", R.string.YourLocatedChannelsTooMuch));
            return;
        }
        ActionIntroActivity actionIntroActivity = new ActionIntroActivity(2);
        this.groupCreateActivity = actionIntroActivity;
        presentFragment(actionIntroActivity);
    }

    private void checkCanCreateGroup() {
        if (this.checkingCanCreate) {
            return;
        }
        this.checkingCanCreate = true;
        TLRPC.TL_channels_getAdminedPublicChannels req = new TLRPC.TL_channels_getAdminedPublicChannels();
        req.by_location = true;
        req.check_limit = true;
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$NearPersonAndGroupActivity$MGAsBzX4OWWv6qfKxP5X-PfQBnE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkCanCreateGroup$2$NearPersonAndGroupActivity(tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$checkCanCreateGroup$2$NearPersonAndGroupActivity(TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$NearPersonAndGroupActivity$1b7tIoInZwhFm3utpzyaHMPdOeQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$NearPersonAndGroupActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$NearPersonAndGroupActivity(TLRPC.TL_error error) {
        this.canCreateGroup = error == null;
        this.checkingCanCreate = false;
    }

    private void showLoadingProgress(boolean show) {
        if (this.showingLoadingProgress == show) {
            return;
        }
        this.showingLoadingProgress = show;
        AnimatorSet animatorSet = this.showProgressAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.showProgressAnimation = null;
        }
        if (this.listView == null) {
            return;
        }
        ArrayList<Animator> animators = new ArrayList<>();
        int count = this.listView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof HeaderCellProgress) {
                HeaderCellProgress cell = (HeaderCellProgress) child;
                this.animatingViews.add(cell);
                RadialProgressView radialProgressView = cell.progressView;
                Property property = View.ALPHA;
                float[] fArr = new float[1];
                fArr[0] = show ? 1.0f : 0.0f;
                animators.add(ObjectAnimator.ofFloat(radialProgressView, (Property<RadialProgressView, Float>) property, fArr));
            }
        }
        if (animators.isEmpty()) {
            return;
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.showProgressAnimation = animatorSet2;
        animatorSet2.playTogether(animators);
        this.showProgressAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity.7
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                NearPersonAndGroupActivity.this.showProgressAnimation = null;
                NearPersonAndGroupActivity.this.animatingViews.clear();
            }
        });
        this.showProgressAnimation.setDuration(180L);
        this.showProgressAnimation.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendRequest(boolean shortpoll) {
        if (!this.firstLoaded) {
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$NearPersonAndGroupActivity$4iJnx_YS70rA5S1UxKn0lhdLrKY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$sendRequest$3$NearPersonAndGroupActivity();
                }
            };
            this.showProgressRunnable = runnable;
            AndroidUtilities.runOnUIThread(runnable, 1000L);
            this.firstLoaded = true;
        }
        if (!NetworkUtils.hasSimCard(ApplicationLoader.applicationContext)) {
            FileLog.d("--------->no sim card:");
        } else if (SimulatorUtil.isSimulator(ApplicationLoader.applicationContext)) {
            FileLog.d("--------->is simulator");
        } else if (this.reqId != 0) {
        }
    }

    public /* synthetic */ void lambda$sendRequest$3$NearPersonAndGroupActivity() {
        showLoadingProgress(true);
        this.showProgressRunnable = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        Activity activity;
        super.onResume();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        if (Build.VERSION.SDK_INT >= 23 && (activity = getParentActivity()) != null && activity.checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            return;
        }
        getLocationController().startLocationLookupForPeopleNearby(false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        getLocationController().startLocationLookupForPeopleNearby(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onBecomeFullyVisible() {
        super.onBecomeFullyVisible();
        this.groupCreateActivity = null;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        ArrayList<TLRPC.TL_peerLocated> arrayList;
        if (id == NotificationCenter.newLocationAvailable) {
            sendRequest(false);
            return;
        }
        if (id == NotificationCenter.newPeopleNearbyAvailable) {
            TLRPC.TL_updatePeerLocated update = (TLRPC.TL_updatePeerLocated) args[0];
            int N2 = update.peers.size();
            for (int b = 0; b < N2; b++) {
                TLRPC.TL_peerLocated peerLocated = update.peers.get(b);
                boolean found = false;
                if (peerLocated.peer instanceof TLRPC.TL_peerUser) {
                    arrayList = this.users;
                } else {
                    arrayList = this.chats;
                }
                int N = arrayList.size();
                for (int a = 0; a < N; a++) {
                    TLRPC.TL_peerLocated old = arrayList.get(a);
                    if ((old.peer.user_id != 0 && old.peer.user_id == peerLocated.peer.user_id) || ((old.peer.chat_id != 0 && old.peer.chat_id == peerLocated.peer.chat_id) || (old.peer.channel_id != 0 && old.peer.channel_id == peerLocated.peer.channel_id))) {
                        arrayList.set(a, peerLocated);
                        found = true;
                    }
                }
                if (!found) {
                    arrayList.add(peerLocated);
                }
            }
            checkForExpiredLocations(true);
            updateRows();
            return;
        }
        if (id != NotificationCenter.needDeleteDialog || this.fragmentView == null || this.isPaused) {
            return;
        }
        final long dialogId = ((Long) args[0]).longValue();
        final TLRPC.Chat chat = (TLRPC.Chat) args[2];
        final boolean revoke = ((Boolean) args[3]).booleanValue();
        Runnable deleteRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$NearPersonAndGroupActivity$_7p-rOyz95YMTrqoBagr7iGiJsQ
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$didReceivedNotification$4$NearPersonAndGroupActivity(chat, dialogId, revoke);
            }
        };
        deleteRunnable.run();
    }

    public /* synthetic */ void lambda$didReceivedNotification$4$NearPersonAndGroupActivity(TLRPC.Chat chat, long dialogId, boolean revoke) throws Exception {
        if (chat == null) {
            getMessagesController().deleteDialog(dialogId, 0, revoke);
        } else if (ChatObject.isNotInChat(chat)) {
            getMessagesController().deleteDialog(dialogId, 0, revoke);
        } else {
            getMessagesController().deleteUserFromChat((int) (-dialogId), getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId())), null, false, revoke);
        }
    }

    private void checkForExpiredLocations(boolean cache) {
        Runnable runnable = this.checkExpiredRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.checkExpiredRunnable = null;
        }
        int currentTime = getConnectionsManager().getCurrentTime();
        int minExpired = Integer.MAX_VALUE;
        boolean changed = false;
        int a = 0;
        while (a < 2) {
            ArrayList<TLRPC.TL_peerLocated> arrayList = a == 0 ? this.users : this.chats;
            int b = 0;
            int N = arrayList.size();
            while (b < N) {
                TLRPC.TL_peerLocated peer = arrayList.get(b);
                if (peer.expires <= currentTime) {
                    arrayList.remove(b);
                    b--;
                    N--;
                    changed = true;
                } else {
                    minExpired = Math.min(minExpired, peer.expires);
                }
                b++;
            }
            a++;
        }
        if (changed && this.listViewAdapter != null) {
            updateRows();
        }
        if (changed || cache) {
            getLocationController().setCachedNearbyUsersAndChats(this.users, this.chats);
        }
        if (minExpired != Integer.MAX_VALUE) {
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.discovery.-$$Lambda$NearPersonAndGroupActivity$IKJ4Qlout_cRS935TlvdYhlaICM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$checkForExpiredLocations$5$NearPersonAndGroupActivity();
                }
            };
            this.checkExpiredRunnable = runnable2;
            AndroidUtilities.runOnUIThread(runnable2, (minExpired - currentTime) * 1000);
        }
    }

    public /* synthetic */ void lambda$checkForExpiredLocations$5$NearPersonAndGroupActivity() {
        this.checkExpiredRunnable = null;
        checkForExpiredLocations(false);
    }

    public class HeaderCellProgress extends HeaderCell {
        private RadialProgressView progressView;

        public HeaderCellProgress(Context context) {
            super(context);
            setClipChildren(false);
            RadialProgressView radialProgressView = new RadialProgressView(context);
            this.progressView = radialProgressView;
            radialProgressView.setSize(AndroidUtilities.dp(14.0f));
            this.progressView.setStrokeWidth(2.0f);
            this.progressView.setAlpha(0.0f);
            this.progressView.setProgressColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
            addView(this.progressView, LayoutHelper.createFrame(50.0f, 40.0f, (LocaleController.isRTL ? 3 : 5) | 48, LocaleController.isRTL ? 2.0f : 0.0f, 3.0f, LocaleController.isRTL ? 0.0f : 2.0f, 0.0f));
        }
    }

    public class HintInnerCell extends FrameLayout {
        private ImageView imageView;
        private TextView messageTextView;

        public HintInnerCell(Context context) {
            super(context);
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setBackgroundDrawable(Theme.createCircleDrawable(AndroidUtilities.dp(74.0f), Theme.getColor(Theme.key_chats_archiveBackground)));
            this.imageView.setImageDrawable(new ShareLocationDrawable(context, 2));
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            addView(this.imageView, LayoutHelper.createFrame(74.0f, 74.0f, 49, 0.0f, 27.0f, 0.0f, 0.0f));
            TextView textView = new TextView(context);
            this.messageTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_chats_message));
            this.messageTextView.setTextSize(1, 14.0f);
            this.messageTextView.setGravity(17);
            this.messageTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("PeopleNearbyInfo", R.string.PeopleNearbyInfo, new Object[0])));
            addView(this.messageTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 52.0f, 125.0f, 52.0f, 27.0f));
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (NearPersonAndGroupActivity.this.rowCount != 0) {
                return NearPersonAndGroupActivity.this.rowCount;
            }
            return 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(this.mContext).inflate(R.layout.item_near_person, (ViewGroup) null, false);
            view.setTag(Integer.valueOf(viewType));
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(70.0f)));
            return new RecyclerListView.Holder(view);
        }

        private String formatDistance(TLRPC.TL_peerLocated located) {
            return LocaleController.formatDistance(located.distance);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (!NearPersonAndGroupActivity.this.users.isEmpty() && position < NearPersonAndGroupActivity.this.users.size()) {
                TLRPC.TL_peerLocated peerLocated = (TLRPC.TL_peerLocated) NearPersonAndGroupActivity.this.users.get(position);
                MessagesController.getInstance(NearPersonAndGroupActivity.this.currentAccount).getUserFull(peerLocated.peer.user_id);
                TLRPC.User user = NearPersonAndGroupActivity.this.getMessagesController().getUser(Integer.valueOf(peerLocated.peer.user_id));
                if (user != null) {
                    if (position == 0) {
                        holder.itemView.findViewById(R.attr.tv_no_data).setVisibility(8);
                        holder.itemView.findViewById(R.attr.iv_head_img).setVisibility(0);
                        holder.itemView.findViewById(R.attr.tv_nick_name).setVisibility(0);
                        holder.itemView.findViewById(R.attr.tv_distance).setVisibility(0);
                    }
                    NearPersonAndGroupActivity.this.currrntStatus = formatDistance(peerLocated);
                    NearPersonAndGroupActivity.this.currentName = null;
                    NearPersonAndGroupActivity.this.update(user, 0, holder.itemView);
                    return;
                }
                return;
            }
            holder.itemView.findViewById(R.attr.tv_no_data).setVisibility(0);
            holder.itemView.findViewById(R.attr.iv_head_img).setVisibility(8);
            holder.itemView.findViewById(R.attr.tv_nick_name).setVisibility(8);
            holder.itemView.findViewById(R.attr.tv_distance).setVisibility(8);
            ((TextView) holder.itemView.findViewById(R.attr.tv_no_data)).setText(AndroidUtilities.replaceTags(LocaleController.getString("PeopleNearbyEmpty", R.string.PeopleNearbyEmpty)));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position;
        }
    }

    public void update(TLObject currentObject, int mask, View v) {
        TLRPC.FileLocation fileLocation;
        TextView tv_nick = (TextView) v.findViewById(R.attr.tv_nick_name);
        TextView tv_distance = (TextView) v.findViewById(R.attr.tv_distance);
        BackupImageView iv_head_img = (BackupImageView) v.findViewById(R.attr.iv_head_img);
        if (currentObject == null) {
            this.currrntStatus = null;
            this.currentName = null;
            tv_nick.setText("");
            tv_distance.setText("");
            iv_head_img.setImageDrawable(null);
            return;
        }
        if (currentObject instanceof TLRPC.User) {
            TLRPC.User currentUser = (TLRPC.User) currentObject;
            TLRPC.FileLocation photo = null;
            String newName = null;
            if (currentUser.photo != null) {
                photo = currentUser.photo.photo_small;
            }
            if (mask != 0) {
                boolean continueUpdate = false;
                if ((mask & 2) != 0 && ((this.lastAvatar != null && photo == null) || ((this.lastAvatar == null && photo != null) || ((fileLocation = this.lastAvatar) != null && photo != null && (fileLocation.volume_id != photo.volume_id || this.lastAvatar.local_id != photo.local_id))))) {
                    continueUpdate = true;
                }
                if (currentUser != null && !continueUpdate && (mask & 4) != 0) {
                    int newStatus = 0;
                    if (currentUser.status != null) {
                        newStatus = currentUser.status.expires;
                    }
                    if (newStatus != this.lastStatus) {
                        continueUpdate = true;
                    }
                }
                if (!continueUpdate && this.currentName == null && this.lastName != null && (mask & 1) != 0) {
                    newName = UserObject.getName(currentUser);
                    if (!newName.equals(this.lastName)) {
                        continueUpdate = true;
                    }
                }
                if (!continueUpdate) {
                    return;
                }
            }
            AvatarDrawable avatarDrawableNew = new AvatarDrawable();
            avatarDrawableNew.setInfo(currentUser);
            if (currentUser.status != null) {
                this.lastStatus = currentUser.status.expires;
            } else {
                this.lastStatus = 0;
            }
            CharSequence charSequence = this.currentName;
            if (charSequence != null) {
                this.lastName = null;
                tv_nick.setText(charSequence);
            } else {
                String name = newName == null ? UserObject.getName(currentUser) : newName;
                this.lastName = name;
                tv_nick.setText(name);
            }
            if (this.currrntStatus != null) {
                tv_distance.setTextColor(this.statusColor);
                tv_distance.setText(this.currrntStatus);
            } else if (!currentUser.bot) {
                if (currentUser.id == UserConfig.getInstance(this.currentAccount).getClientUserId() || ((currentUser.status != null && currentUser.status.expires > ConnectionsManager.getInstance(this.currentAccount).getCurrentTime()) || MessagesController.getInstance(this.currentAccount).onlinePrivacy.containsKey(Integer.valueOf(currentUser.id)))) {
                    tv_distance.setTextColor(this.statusOnlineColor);
                    tv_distance.setText(LocaleController.getString("Online", R.string.Online));
                } else {
                    tv_distance.setTextColor(this.statusColor);
                    tv_distance.setText(LocaleController.formatUserStatus(this.currentAccount, currentUser));
                }
            } else {
                tv_distance.setTextColor(this.statusColor);
                if (currentUser.bot_chat_history || this.isAdmin) {
                    tv_distance.setText(LocaleController.getString("BotStatusRead", R.string.BotStatusRead));
                } else {
                    tv_distance.setText(LocaleController.getString("BotStatusCantRead", R.string.BotStatusCantRead));
                }
            }
            this.lastAvatar = photo;
            iv_head_img.setRoundRadius(AndroidUtilities.dp(25.0f));
            iv_head_img.setImage(ImageLocation.getForUser(currentUser, false), "50_50", avatarDrawableNew, currentUser);
        }
    }

    private class ListAdapterGroup extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapterGroup(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return NearPersonAndGroupActivity.this.groupRowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(this.mContext).inflate(R.layout.item_near_group, (ViewGroup) null, false);
            view.setTag(Integer.valueOf(viewType));
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(70.0f)));
            return new RecyclerListView.Holder(view);
        }

        private String formatDistance(TLRPC.TL_peerLocated located) {
            return LocaleController.formatDistance(located.distance);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int chatId;
            if (position == 0) {
                holder.itemView.findViewById(R.attr.tv_create_group).setVisibility(0);
                ((BackupImageView) holder.itemView.findViewById(R.attr.iv_group_head_img)).setRoundRadius(AndroidUtilities.dp(25.0f));
                ((BackupImageView) holder.itemView.findViewById(R.attr.iv_group_head_img)).setImageDrawable(this.mContext.getResources().getDrawable(R.id.ic_create_group));
                return;
            }
            holder.itemView.findViewById(R.attr.tv_create_group).setVisibility(8);
            if (!NearPersonAndGroupActivity.this.chats.isEmpty() && position - 1 < NearPersonAndGroupActivity.this.chats.size()) {
                TLRPC.TL_peerLocated peerLocated = (TLRPC.TL_peerLocated) NearPersonAndGroupActivity.this.chats.get(position - 1);
                if (peerLocated.peer instanceof TLRPC.TL_peerChat) {
                    chatId = peerLocated.peer.chat_id;
                } else {
                    chatId = peerLocated.peer.channel_id;
                }
                TLRPC.Chat chat = NearPersonAndGroupActivity.this.getMessagesController().getChat(Integer.valueOf(chatId));
                if (chat != null) {
                    String subtitle = formatDistance(peerLocated);
                    if (chat.participants_count != 0) {
                        subtitle = String.format("%1$s, %2$s", subtitle, LocaleController.formatPluralString("Members", chat.participants_count));
                    }
                    NearPersonAndGroupActivity.this.currrntStatus = subtitle;
                    NearPersonAndGroupActivity.this.currentName = null;
                    NearPersonAndGroupActivity.this.updateGroup(chat, 0, holder.itemView);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewRecycled(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ManageChatUserCell) {
                ((ManageChatUserCell) holder.itemView).recycle();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateGroup(TLObject currentObject, int mask, View v) {
        TLRPC.FileLocation fileLocation;
        TextView tv_nick = (TextView) v.findViewById(R.attr.tv_nick_name);
        TextView tv_distance = (TextView) v.findViewById(R.attr.tv_distance);
        BackupImageView iv_head_img = (BackupImageView) v.findViewById(R.attr.iv_group_head_img);
        if (currentObject == null) {
            this.currrntStatus = null;
            this.currentName = null;
            tv_nick.setText("");
            tv_distance.setText("");
            iv_head_img.setImageDrawable(null);
            return;
        }
        iv_head_img.setImageDrawable(null);
        TLRPC.Chat currentChat = (TLRPC.Chat) currentObject;
        TLRPC.FileLocation photo = null;
        String newName = null;
        if (currentChat.photo != null) {
            photo = currentChat.photo.photo_small;
        }
        if (mask != 0) {
            boolean continueUpdate = false;
            if ((mask & 2) != 0 && ((this.lastAvatar != null && photo == null) || ((this.lastAvatar == null && photo != null) || ((fileLocation = this.lastAvatar) != null && photo != null && (fileLocation.volume_id != photo.volume_id || this.lastAvatar.local_id != photo.local_id))))) {
                continueUpdate = true;
            }
            if (!continueUpdate && this.currentName == null && this.lastName != null && (mask & 1) != 0) {
                newName = currentChat.title;
                if (!newName.equals(this.lastName)) {
                    continueUpdate = true;
                }
            }
            if (!continueUpdate) {
                return;
            }
        }
        AvatarDrawable avatarDrawableNew = new AvatarDrawable();
        avatarDrawableNew.setInfo(currentChat);
        CharSequence charSequence = this.currentName;
        if (charSequence != null) {
            this.lastName = null;
            tv_nick.setText(charSequence);
        } else {
            String str = newName == null ? currentChat.title : newName;
            this.lastName = str;
            tv_nick.setText(str);
        }
        if (this.currrntStatus != null) {
            tv_distance.setTextColor(this.statusColor);
            tv_distance.setText(this.currrntStatus);
        } else {
            tv_distance.setTextColor(this.statusColor);
            if (currentChat.participants_count != 0) {
                tv_distance.setText(LocaleController.formatPluralString("Members", currentChat.participants_count));
            } else if (currentChat.has_geo) {
                tv_distance.setText(LocaleController.getString("MegaLocation", R.string.MegaLocation));
            } else if (TextUtils.isEmpty(currentChat.username)) {
                tv_distance.setText(LocaleController.getString("MegaPrivate", R.string.MegaPrivate));
            } else {
                tv_distance.setText(LocaleController.getString("MegaPublic", R.string.MegaPublic));
            }
        }
        this.lastAvatar = photo;
        iv_head_img.setRoundRadius(AndroidUtilities.dp(25.0f));
        iv_head_img.setImage(ImageLocation.getForChat(currentChat, false), "50_50", avatarDrawableNew, currentChat);
    }
}
