package im.uwrkaxlmjj.ui.fragments;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.util.Property;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.core.view.GravityCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSmoothScrollerMiddle;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DialogObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.XiaomiUtilities;
import im.uwrkaxlmjj.network.NetWorkManager;
import im.uwrkaxlmjj.network.OSSChat;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChannelCreateActivity;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.NewContactActivity;
import im.uwrkaxlmjj.ui.ProxyListActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BackDrawable;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.MenuDrawable;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter;
import im.uwrkaxlmjj.ui.cell.FmtDialogCell;
import im.uwrkaxlmjj.ui.cells.AccountSelectCell;
import im.uwrkaxlmjj.ui.cells.HintDialogCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ChatActivityEnterView;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.DialogsItemAnimator;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.JoinGroupAlert;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberTextView;
import im.uwrkaxlmjj.ui.components.PacmanAnimation;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.UndoView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.BottomDialog;
import im.uwrkaxlmjj.ui.dialogs.ReStartTipDialog;
import im.uwrkaxlmjj.ui.fragments.adapter.FmtDialogsAdapter;
import im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity;
import im.uwrkaxlmjj.ui.hui.chats.NewChatActivity;
import im.uwrkaxlmjj.ui.hui.chats.StartChatActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.discovery.QrScanActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.ThreadUtils;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DialogsFragment extends BaseFmts implements NotificationCenter.NotificationCenterDelegate {
    private static final String TAG = "****** J ****** DialogsFragment **** : ";
    private static final int create_new_chat = 11;
    public static boolean[] dialogsLoaded = new boolean[3];
    private static ArrayList<TLRPC.Dialog> frozenDialogsList = null;
    private static final int item_add_contact = 1003;
    private static final int item_camera_scan = 1004;
    private static final int item_edit_chat = 9999;
    private static final int item_edit_chat_completed = 9997;
    private static final int item_login_on_computer = 9998;
    private static final int item_server = 1005;
    private static final int item_start_channel = 1002;
    private static final int item_start_chat = 1000;
    private static final int item_start_group = 1001;
    private static final int refresh_line = 5;
    private String addToGroupAlertString;
    private boolean allowMoving;
    private boolean allowScrollToHiddenView;
    private boolean allowSwipeDuringCurrentTouch;
    private boolean allowSwitchAccount;
    private ActionBarMenuSubItem archiveItem;
    private BackDrawable backDrawable;
    private int canClearCacheCount;
    private int canMuteCount;
    private int canPinCount;
    private int canReadCount;
    private int canUnmuteCount;
    private boolean cantSendToChannels;
    private boolean checkCanWrite;
    private ActionBarMenuSubItem clearItem;
    private ChatActivityEnterView commentView;
    private FrameLayout containerLayout;
    private ContentView contentView;
    private ActionBarMenuItem createNewChat;
    private int currentConnectionState;
    private FmtConsumDelegate delegate;
    private ActionBarMenuItem deleteItem;
    private int dialogChangeFinished;
    private int dialogInsertFinished;
    private int dialogRemoveFinished;
    private FmtDialogsAdapter dialogsAdapter;
    private DialogsItemAnimator dialogsItemAnimator;
    private boolean dialogsListFrozen;
    private DialogsSearchAdapter dialogsSearchAdapter;
    private int dialogsType;
    private View divider;
    private int folderId;
    private int lastItemsCount;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private onRefreshMainInterface mainInterface;
    private MenuDrawable menuDrawable;
    private int messagesCount;
    private FmtDialogCell movingView;
    private boolean movingWas;
    private ActionBarMenuItem muteItem;
    private SharedPreferences notificationsSettingsSP;
    private long openedDialogId;
    private PacmanAnimation pacmanAnimation;
    private ActionBarMenuItem passcodeItem;
    private AlertDialog permissionDialog;
    private ActionBarMenuItem pinItem;
    private RadialProgressView progressView;
    private ActionBarMenuSubItem readItem;
    private long searchDialogId;
    private EmptyTextProgressView searchEmptyView;
    private FrameLayout searchLayout;
    private TLObject searchObject;
    private String searchString;
    private MrySearchView searchView;
    private boolean searchWas;
    private boolean searching;
    private String selectAlertString;
    private String selectAlertStringGroup;
    private NumberTextView selectedDialogsCountTextView;
    private RecyclerView sideMenu;
    private FmtDialogCell slidingView;
    private boolean startedScrollAtTop;
    private ActionBarMenuItem switchItem;
    private int totalConsumedAmount;
    private boolean waitingForScrollFinished;
    private UndoView[] undoView = new UndoView[2];
    private ArrayList<View> actionModeViews = new ArrayList<>();
    private boolean askAboutContacts = true;
    private boolean checkPermission = true;
    private boolean resetDelegate = true;
    private int refreshNum = 0;
    boolean isEditModel = false;

    public interface FmtConsumDelegate {
        void changeUnreadCount(int i);

        void onEditModelChange(boolean z, boolean z2);

        void onUpdateState(boolean z, int i, int i2);
    }

    public DialogsFragment(onRefreshMainInterface mainInterface) {
        this.mainInterface = mainInterface;
    }

    public void setDilogsType(int dialogsType) {
        this.dialogsType = dialogsType;
        FmtDialogsAdapter fmtDialogsAdapter = this.dialogsAdapter;
        if (fmtDialogsAdapter != null) {
            fmtDialogsAdapter.setDialogsType(dialogsType);
            this.dialogsAdapter.notifyDataSetChanged();
        }
    }

    public void setDelegate(FmtConsumDelegate delegate) {
        this.delegate = delegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        FmtConsumDelegate fmtConsumDelegate;
        if ((key.equals("badgeNumberMuted") || key.equals("badgeNumberMessages")) && (fmtConsumDelegate = this.delegate) != null) {
            fmtConsumDelegate.changeUnreadCount(getUnreadCount());
        }
    }

    private class ContentView extends SizeNotifierFrameLayout {
        private int inputFieldHeight;

        public ContentView(Context context) {
            super(context);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, heightSize);
            int heightSize2 = heightSize - getPaddingTop();
            measureChildWithMargins(DialogsFragment.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
            int keyboardSize = getKeyboardHeight();
            int childCount = getChildCount();
            if (DialogsFragment.this.commentView != null) {
                measureChildWithMargins(DialogsFragment.this.commentView, widthMeasureSpec, 0, heightMeasureSpec, 0);
                Object tag = DialogsFragment.this.commentView.getTag();
                if (tag != null && tag.equals(2)) {
                    if (keyboardSize <= AndroidUtilities.dp(20.0f) && !AndroidUtilities.isInMultiwindow) {
                        heightSize2 -= DialogsFragment.this.commentView.getEmojiPadding();
                    }
                    this.inputFieldHeight = DialogsFragment.this.commentView.getMeasuredHeight();
                } else {
                    this.inputFieldHeight = 0;
                }
            }
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8 && child != DialogsFragment.this.commentView && child != DialogsFragment.this.actionBar) {
                    if (child == DialogsFragment.this.listView || child == DialogsFragment.this.progressView || child == DialogsFragment.this.searchEmptyView) {
                        if (DialogsFragment.this.searchView != null && DialogsFragment.this.searchView.isSearchFieldVisible()) {
                            int contentWidthSpec = View.MeasureSpec.makeMeasureSpec(widthSize, Integer.MIN_VALUE);
                            int contentHeightSpec = View.MeasureSpec.makeMeasureSpec(Math.max(AndroidUtilities.dp(10.0f), (heightSize2 - this.inputFieldHeight) + AndroidUtilities.dp(2.0f)), Integer.MIN_VALUE);
                            child.measure(contentWidthSpec, contentHeightSpec);
                        } else {
                            measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                        }
                    } else if (DialogsFragment.this.commentView != null && DialogsFragment.this.commentView.isPopupView(child)) {
                        if (AndroidUtilities.isInMultiwindow) {
                            if (AndroidUtilities.isTablet()) {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(320.0f), ((heightSize2 - this.inputFieldHeight) - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(((heightSize2 - this.inputFieldHeight) - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
                            }
                        } else {
                            child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                        }
                    } else {
                        measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int childLeft;
            int childTop;
            int count = getChildCount();
            Object tag = DialogsFragment.this.commentView != null ? DialogsFragment.this.commentView.getTag() : null;
            int i = 2;
            int paddingBottom = (tag == null || !tag.equals(2) || getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : DialogsFragment.this.commentView.getEmojiPadding();
            setBottomClip(paddingBottom);
            int i2 = 0;
            while (i2 < count) {
                View child = getChildAt(i2);
                if (child.getVisibility() != 8) {
                    FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                    int width = child.getMeasuredWidth();
                    int height = child.getMeasuredHeight();
                    int gravity = lp.gravity;
                    if (gravity == -1) {
                        gravity = 51;
                    }
                    int absoluteGravity = gravity & 7;
                    int verticalGravity = gravity & 112;
                    int i3 = absoluteGravity & 7;
                    if (i3 == 1) {
                        int childLeft2 = r - l;
                        childLeft = (((childLeft2 - width) / i) + lp.leftMargin) - lp.rightMargin;
                    } else if (i3 == 5) {
                        int childLeft3 = r - width;
                        childLeft = childLeft3 - lp.rightMargin;
                    } else {
                        childLeft = lp.leftMargin;
                    }
                    if (verticalGravity == 16) {
                        int childTop2 = b - paddingBottom;
                        childTop = ((((childTop2 - t) - height) / i) + lp.topMargin) - lp.bottomMargin;
                    } else if (verticalGravity == 48) {
                        int childTop3 = lp.topMargin;
                        childTop = childTop3 + getPaddingTop();
                    } else if (verticalGravity == 80) {
                        int childTop4 = b - paddingBottom;
                        childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (DialogsFragment.this.commentView != null && DialogsFragment.this.commentView.isPopupView(child)) {
                        childTop = AndroidUtilities.isInMultiwindow ? (DialogsFragment.this.commentView.getTop() - child.getMeasuredHeight()) + AndroidUtilities.dp(1.0f) : DialogsFragment.this.commentView.getBottom();
                    }
                    if (child == DialogsFragment.this.listView) {
                        child.layout(childLeft, childTop, childLeft + width, childTop + height);
                    } else {
                        child.layout(childLeft, childTop, childLeft + width, childTop + height);
                    }
                }
                i2++;
                i = 2;
            }
            notifyHeightChanged();
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            int action = ev.getActionMasked();
            if (action == 0 || action == 1 || action == 3) {
                if (action == 0) {
                    int currentPosition = DialogsFragment.this.layoutManager.findFirstVisibleItemPosition();
                    DialogsFragment.this.startedScrollAtTop = currentPosition <= 1;
                } else if (DialogsFragment.this.actionBar.isActionModeShowed()) {
                    DialogsFragment.this.allowMoving = true;
                }
                DialogsFragment.this.totalConsumedAmount = 0;
                DialogsFragment.this.allowScrollToHiddenView = false;
            }
            return super.onInterceptTouchEvent(ev);
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            this.cantSendToChannels = this.arguments.getBoolean("cantSendToChannels", false);
            this.selectAlertString = this.arguments.getString("selectAlertString");
            this.selectAlertStringGroup = this.arguments.getString("selectAlertStringGroup");
            this.addToGroupAlertString = this.arguments.getString("addToGroupAlertString");
            this.allowSwitchAccount = this.arguments.getBoolean("allowSwitchAccount");
            this.checkCanWrite = this.arguments.getBoolean("checkCanWrite", true);
            this.folderId = this.arguments.getInt("folderId", 0);
            this.resetDelegate = this.arguments.getBoolean("resetDelegate", true);
            this.messagesCount = this.arguments.getInt("messagesCount", 0);
        }
        this.askAboutContacts = MessagesController.getGlobalNotificationsSettings().getBoolean("askAboutContacts", true);
        SharedConfig.loadProxyList();
        if (this.searchString == null) {
            this.currentConnectionState = getConnectionsManager().getConnectionState();
            getNotificationCenter().addObserver(this, NotificationCenter.dialogsNeedReload);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.closeSearchByActiveAction);
            getNotificationCenter().addObserver(this, NotificationCenter.updateInterfaces);
            getNotificationCenter().addObserver(this, NotificationCenter.encryptedChatUpdated);
            getNotificationCenter().addObserver(this, NotificationCenter.contactsDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.appDidLogout);
            getNotificationCenter().addObserver(this, NotificationCenter.openedChatChanged);
            getNotificationCenter().addObserver(this, NotificationCenter.notificationsSettingsUpdated);
            getNotificationCenter().addObserver(this, NotificationCenter.messageReceivedByAck);
            getNotificationCenter().addObserver(this, NotificationCenter.messageReceivedByServer);
            getNotificationCenter().addObserver(this, NotificationCenter.messageSendError);
            getNotificationCenter().addObserver(this, NotificationCenter.needReloadRecentDialogsSearch);
            getNotificationCenter().addObserver(this, NotificationCenter.replyMessagesDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.reloadHints);
            getNotificationCenter().addObserver(this, NotificationCenter.didUpdateConnectionState);
            getNotificationCenter().addObserver(this, NotificationCenter.dialogsUnreadCounterChanged);
            getNotificationCenter().addObserver(this, NotificationCenter.needDeleteDialog);
            getNotificationCenter().addObserver(this, NotificationCenter.folderBecomeEmpty);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.pushRemoteOpenChat);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetPasscode);
            ApplicationLoader.mbytMessageReged = (byte) 1;
        }
        if (!dialogsLoaded[this.currentAccount]) {
            getMessagesController().loadGlobalNotificationsSettings();
            getMessagesController().loadDialogs(this.folderId, 0, 100, true);
            getMessagesController().loadHintDialogs();
            getContactsController().checkInviteText();
            getMediaDataController().loadRecents(2, false, true, false);
            getMediaDataController().checkFeaturedStickers();
            dialogsLoaded[this.currentAccount] = true;
        }
        getMessagesController().loadPinnedDialogs(this.folderId, 0L, null);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        initData();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
        initData();
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onResumeForBaseFragment() {
        super.onResumeForBaseFragment();
        this.isPaused = false;
        FmtDialogsAdapter fmtDialogsAdapter = this.dialogsAdapter;
        if (fmtDialogsAdapter != null && !this.dialogsListFrozen) {
            fmtDialogsAdapter.notifyDataSetChanged();
        }
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onResume();
        }
        if (this.folderId == 0) {
            getMediaDataController().checkStickers(4);
        }
        DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
        if (dialogsSearchAdapter != null) {
            dialogsSearchAdapter.notifyDataSetChanged();
        }
        if (this.checkPermission && Build.VERSION.SDK_INT >= 23) {
            Activity activity = getParentActivity();
            if (activity != null) {
                this.checkPermission = false;
                boolean hasNotStoragePermission = activity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0;
                if (hasNotStoragePermission) {
                    if (hasNotStoragePermission && activity.shouldShowRequestPermissionRationale("android.permission.WRITE_EXTERNAL_STORAGE")) {
                        AlertDialog.Builder builder = new AlertDialog.Builder(activity);
                        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                        builder.setMessage(LocaleController.getString("PermissionStorage", R.string.PermissionStorage));
                        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$FlRCB7po8Hm-5DUZnvL-kaEethw
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                this.f$0.lambda$onResumeForBaseFragment$0$DialogsFragment(dialogInterface, i);
                            }
                        });
                        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                        AlertDialog alertDialogCreate = builder.create();
                        this.permissionDialog = alertDialogCreate;
                        showDialog(alertDialogCreate);
                        return;
                    }
                    askForPermissons(true);
                    return;
                }
                return;
            }
            return;
        }
        if (!XiaomiUtilities.isMIUI() || Build.VERSION.SDK_INT < 19 || XiaomiUtilities.isCustomPermissionGranted(XiaomiUtilities.OP_SHOW_WHEN_LOCKED) || getActivity() == null || MessagesController.getGlobalNotificationsSettings().getBoolean("askedAboutMiuiLockscreen", false)) {
            return;
        }
        showDialog(new AlertDialog.Builder(getActivity()).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("PermissionXiaomiLockscreen", R.string.PermissionXiaomiLockscreen)).setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$GsWJ3SRfHcmvRxQnbU2TmvY0yt0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$onResumeForBaseFragment$1$DialogsFragment(dialogInterface, i);
            }
        }).setNegativeButton(LocaleController.getString("ContactsPermissionAlertNotNow", R.string.ContactsPermissionAlertNotNow), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$5_DSw2czWfFS4PvJgVRqL9mQUSg
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                MessagesController.getGlobalNotificationsSettings().edit().putBoolean("askedAboutMiuiLockscreen", true).commit();
            }
        }).create());
    }

    public /* synthetic */ void lambda$onResumeForBaseFragment$0$DialogsFragment(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$onResumeForBaseFragment$1$DialogsFragment(DialogInterface dialog, int which) {
        Intent intent = XiaomiUtilities.getPermissionManagerIntent();
        if (intent != null) {
            try {
                getActivity().startActivity(intent);
            } catch (Exception e) {
                try {
                    Intent intent2 = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
                    intent2.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
                    getActivity().startActivity(intent2);
                } catch (Exception xx) {
                    FileLog.e(xx);
                }
            }
        }
    }

    private void askForPermissons(boolean alert) {
        Activity activity = getParentActivity();
        if (activity == null) {
            return;
        }
        ArrayList<String> permissons = new ArrayList<>();
        if (activity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            permissons.add(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE);
            permissons.add("android.permission.WRITE_EXTERNAL_STORAGE");
        }
        if (permissons.isEmpty()) {
            return;
        }
        String[] items = (String[]) permissons.toArray(new String[0]);
        try {
            activity.requestPermissions(items, 1);
        } catch (Exception e) {
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        this.isPaused = true;
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onResume();
        }
        UndoView[] undoViewArr = this.undoView;
        if (undoViewArr[0] != null) {
            undoViewArr[0].hide(true, 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        if (this.searchString == null) {
            getNotificationCenter().removeObserver(this, NotificationCenter.dialogsNeedReload);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.closeSearchByActiveAction);
            getNotificationCenter().removeObserver(this, NotificationCenter.updateInterfaces);
            getNotificationCenter().removeObserver(this, NotificationCenter.encryptedChatUpdated);
            getNotificationCenter().removeObserver(this, NotificationCenter.contactsDidLoad);
            getNotificationCenter().removeObserver(this, NotificationCenter.appDidLogout);
            getNotificationCenter().removeObserver(this, NotificationCenter.openedChatChanged);
            getNotificationCenter().removeObserver(this, NotificationCenter.notificationsSettingsUpdated);
            getNotificationCenter().removeObserver(this, NotificationCenter.messageReceivedByAck);
            getNotificationCenter().removeObserver(this, NotificationCenter.messageReceivedByServer);
            getNotificationCenter().removeObserver(this, NotificationCenter.messageSendError);
            getNotificationCenter().removeObserver(this, NotificationCenter.needReloadRecentDialogsSearch);
            getNotificationCenter().removeObserver(this, NotificationCenter.replyMessagesDidLoad);
            getNotificationCenter().removeObserver(this, NotificationCenter.reloadHints);
            getNotificationCenter().removeObserver(this, NotificationCenter.didUpdateConnectionState);
            getNotificationCenter().removeObserver(this, NotificationCenter.dialogsUnreadCounterChanged);
            getNotificationCenter().removeObserver(this, NotificationCenter.needDeleteDialog);
            getNotificationCenter().removeObserver(this, NotificationCenter.folderBecomeEmpty);
            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetPasscode);
        }
        ChatActivityEnterView chatActivityEnterView = this.commentView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onDestroy();
        }
        UndoView[] undoViewArr = this.undoView;
        if (undoViewArr[0] != null) {
            undoViewArr[0].hide(true, 0);
        }
        SharedPreferences sharedPreferences = this.notificationsSettingsSP;
        if (sharedPreferences != null) {
            sharedPreferences.unregisterOnSharedPreferenceChangeListener(new $$Lambda$DialogsFragment$hLYS5Ja9fYXztObkZDHxHtfloQc(this));
            this.notificationsSettingsSP = null;
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.searching = false;
        this.searchWas = false;
        this.pacmanAnimation = null;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$gHCoLbyYLmwBk5TEdwbULZhB9Yc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onCreateView$3$DialogsFragment();
            }
        });
        FrameLayout frameLayout = new FrameLayout(this.context);
        this.containerLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView = this.containerLayout;
        initActionBar(this.containerLayout);
        initView(this.containerLayout);
        initSearchView(this.containerLayout);
        initListener();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$onCreateView$3$DialogsFragment() {
        Theme.createChatResources(this.context, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void toggleEditModel() {
        this.isEditModel = !this.isEditModel;
        this.actionBar.showActionMode();
        if (this.isEditModel) {
            this.actionBar.setBackTitle(LocaleController.getString(R.string.Done));
        } else {
            this.actionBar.setBackButtonImage(R.id.ic_edit);
        }
        AndroidUtilities.clearDrawableAnimation(this.actionBar.getBackButton());
        AndroidUtilities.clearDrawableAnimation(this.actionBar.getBackTitleTextView());
        AndroidUtilities.clearDrawableAnimation(this.createNewChat);
        int pivotY = ActionBar.getCurrentActionBarHeight() / 2;
        AnimatorSet animatorSet = new AnimatorSet();
        ArrayList<Animator> animators = new ArrayList<>();
        AnimatorListenerAdapter listener = new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                if (DialogsFragment.this.isEditModel) {
                    if (DialogsFragment.this.actionBar.getBackTitleTextView() != null) {
                        DialogsFragment.this.actionBar.getBackTitleTextView().setVisibility(0);
                    }
                } else {
                    if (DialogsFragment.this.actionBar.getBackButton() != null) {
                        DialogsFragment.this.actionBar.getBackButton().setVisibility(0);
                    }
                    if (DialogsFragment.this.createNewChat != null) {
                        DialogsFragment.this.createNewChat.setVisibility(0);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!DialogsFragment.this.isEditModel) {
                    if (DialogsFragment.this.actionBar.getBackTitleTextView() != null) {
                        DialogsFragment.this.actionBar.getBackTitleTextView().setVisibility(8);
                    }
                } else {
                    if (DialogsFragment.this.actionBar.getBackButton() != null) {
                        DialogsFragment.this.actionBar.getBackButton().setVisibility(8);
                    }
                    if (DialogsFragment.this.createNewChat != null) {
                        DialogsFragment.this.createNewChat.setVisibility(8);
                    }
                }
            }
        };
        if (this.actionBar.getBackButton() != null) {
            this.actionBar.getBackButton().setTag(-1);
            this.actionBar.getBackButton().setPivotY(pivotY);
            View backButton = this.actionBar.getBackButton();
            Property property = View.SCALE_Y;
            float[] fArr = new float[2];
            fArr[0] = this.isEditModel ? 1.0f : 0.1f;
            fArr[1] = this.isEditModel ? 0.1f : 1.0f;
            Animator animator = ObjectAnimator.ofFloat(backButton, (Property<View, Float>) property, fArr);
            animator.addListener(listener);
            animators.add(animator);
        }
        if (this.actionBar.getBackTitleTextView() != null) {
            this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$We3GyoDnnqKi1AnYcEjByjPvCgk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$toggleEditModel$4$DialogsFragment(view);
                }
            });
            this.actionBar.getBackTitleTextView().setPivotY(pivotY);
            TextView backTitleTextView = this.actionBar.getBackTitleTextView();
            Property property2 = View.SCALE_Y;
            float[] fArr2 = new float[2];
            fArr2[0] = this.isEditModel ? 0.1f : 1.0f;
            fArr2[1] = this.isEditModel ? 1.0f : 0.1f;
            Animator animator2 = ObjectAnimator.ofFloat(backTitleTextView, (Property<TextView, Float>) property2, fArr2);
            animator2.addListener(listener);
            animators.add(animator2);
        }
        ActionBarMenuItem actionBarMenuItem = this.createNewChat;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.setPivotY(pivotY);
            ActionBarMenuItem actionBarMenuItem2 = this.createNewChat;
            Property property3 = View.SCALE_Y;
            float[] fArr3 = new float[2];
            fArr3[0] = this.isEditModel ? 1.0f : 0.1f;
            fArr3[1] = this.isEditModel ? 0.1f : 1.0f;
            Animator animator3 = ObjectAnimator.ofFloat(actionBarMenuItem2, (Property<ActionBarMenuItem, Float>) property3, fArr3);
            animator3.addListener(listener);
            animators.add(animator3);
        }
        animatorSet.playTogether(animators);
        animatorSet.setDuration(250L);
        animatorSet.start();
        if (this.isEditModel) {
            updateCounters(false, false);
        } else {
            hideActionPanel();
        }
        this.dialogsAdapter.setEdit(this.isEditModel);
        this.dialogsAdapter.notifyDataSetChanged();
        FmtConsumDelegate fmtConsumDelegate = this.delegate;
        if (fmtConsumDelegate != null) {
            fmtConsumDelegate.onEditModelChange(this.isEditModel, getCanReadCountInAllDialogs() > 0);
        }
    }

    public /* synthetic */ void lambda$toggleEditModel$4$DialogsFragment(View v) {
        toggleEditModel();
    }

    private void initActionBar(FrameLayout containerLayout) {
        this.actionBar = createActionBar();
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("Chats", R.string.Chats));
        this.actionBar.setCastShadows(true);
        containerLayout.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        ActionBarMenu menu = this.actionBar.createMenu();
        if (this.searchString == null && this.folderId == 0) {
            this.passcodeItem = menu.addItem(1, R.drawable.lock_close);
            updatePasscodeButton();
        }
        this.actionBar.setBackButtonImage(R.id.ic_edit);
        menu.addItem(5, LocaleController.getString("SwitchLine", R.string.SwitchLine));
        ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(11, R.id.ic_add_circle);
        this.createNewChat = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.addSubItem(1000, R.id.fmt_dialog_menu_chat, LocaleController.getString("StartChats", R.string.StartChats));
        this.createNewChat.addSubItem(1003, R.id.fmt_dialog_menu_add, LocaleController.getString("AddFriends", R.string.AddFriends));
        this.createNewChat.addSubItem(1004, R.id.fmt_dialog_menu_scan, LocaleController.getString("Scan", R.string.Scan));
        if (BuildVars.ENABLE_ME_ONLINE_SERVICE) {
            this.createNewChat.addSubItem(item_server, R.drawable.fmt_mev2_service, LocaleController.getString("OnlineService", R.string.OnlineService));
        }
        if (this.folderId != 0) {
            this.actionBar.setTitle(LocaleController.getString("ArchivedChats", R.string.ArchivedChats));
        }
        this.actionBar.setSupportsHolidayImage(true);
        this.actionBar.setTitleActionRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$UdwttnuZScYlVlgNUKlPJ0U2WwY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$initActionBar$5$DialogsFragment();
            }
        });
        if (this.allowSwitchAccount && UserConfig.getActivatedAccountsCount() > 1) {
            this.switchItem = menu.addItemWithWidth(1, 0, AndroidUtilities.dp(56.0f));
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(12.0f));
            BackupImageView imageView = new BackupImageView(this.context);
            imageView.setRoundRadius(AndroidUtilities.dp(18.0f));
            this.switchItem.addView(imageView, LayoutHelper.createFrame(36, 36, 17));
            TLRPC.User user = getUserConfig().getCurrentUser();
            avatarDrawable.setInfo(user);
            imageView.getImageReceiver().setCurrentAccount(this.currentAccount);
            imageView.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
            for (int a = 0; a < 3; a++) {
                TLRPC.User u = AccountInstance.getInstance(a).getUserConfig().getCurrentUser();
                if (u != null) {
                    AccountSelectCell cell = new AccountSelectCell(this.context);
                    cell.setAccount(a, true);
                    this.switchItem.addSubItem(a + 10, cell, AndroidUtilities.dp(230.0f), AndroidUtilities.dp(48.0f));
                }
            }
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    DialogsFragment.this.toggleEditModel();
                    return;
                }
                if (id == 1) {
                    SharedConfig.appLocked = true ^ SharedConfig.appLocked;
                    SharedConfig.saveConfig();
                    DialogsFragment.this.updatePasscodeButton();
                    return;
                }
                if (id == 2) {
                    DialogsFragment.this.presentFragment(new ProxyListActivity());
                    return;
                }
                if (id == 11) {
                    DialogsFragment.this.presentFragment(new NewChatActivity(null));
                    return;
                }
                if (id >= 10 && id < 13) {
                    if (DialogsFragment.this.getParentActivity() == null) {
                        return;
                    } else {
                        return;
                    }
                }
                if (id == 1000) {
                    DialogsFragment.this.presentFragment(new StartChatActivity(null));
                    return;
                }
                if (id == 1001) {
                    DialogsFragment.this.presentFragment(new CreateGroupActivity(new Bundle()));
                    return;
                }
                if (id == 1002) {
                    Bundle args = new Bundle();
                    args.putInt("step", 0);
                    DialogsFragment.this.presentFragment(new ChannelCreateActivity(args));
                } else {
                    if (id == 1003) {
                        DialogsFragment.this.presentFragment(new AddContactsActivity());
                        return;
                    }
                    if (id == 1004) {
                        DialogsFragment.this.presentFragment(new QrScanActivity());
                    } else if (id == 5) {
                        DialogsFragment.this.restartApplication();
                    } else if (id == DialogsFragment.item_server) {
                        DialogsFragment.this.getServerUrl();
                    }
                }
            }
        });
    }

    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public /* synthetic */ void lambda$initActionBar$5$DialogsFragment() {
        if (this.isEditModel) {
            return;
        }
        LinearLayoutManager linearLayoutManager = this.layoutManager;
        boolean zHasHiddenArchive = hasHiddenArchive();
        linearLayoutManager.scrollToPositionWithOffset(zHasHiddenArchive ? 1 : 0, AndroidUtilities.dp(55.0f));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getServerUrl() {
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
        OSSChat.getInstance().sendOSSRequest(new OSSChat.OSSChatCallback() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.3
            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onSuccess(String url) {
                progressDialog.dismiss();
                Log.d("bond", "客服链接 = " + url);
                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(url));
                intent.putExtra("create_new_tab", true);
                intent.putExtra("com.android.browser.application_id", DialogsFragment.this.getParentActivity().getPackageName());
                DialogsFragment.this.getParentActivity().startActivity(intent);
            }

            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onFail() {
                progressDialog.dismiss();
                ToastUtils.show((CharSequence) "获取客服链接失败");
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void restartApplication() {
        this.refreshNum++;
        Log.d("bond", "点击次数 = " + this.refreshNum);
        if (this.refreshNum >= 3) {
            this.refreshNum = 0;
            showReStartTipDialog();
        } else {
            showProgressDialog();
            ThreadUtils.runOnSubThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$C1j7vuQOrPMz0qLxaAmRKSE_a8g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$restartApplication$6$DialogsFragment();
                }
            });
            NetWorkManager.getInstance().restartApplication();
        }
    }

    public /* synthetic */ void lambda$restartApplication$6$DialogsFragment() {
        try {
            Thread.sleep(1000L);
        } catch (InterruptedException e) {
            disDialig();
        }
        disDialig();
    }

    private void showReStartTipDialog() {
        new ReStartTipDialog((FragmentActivity) this.context, new ReStartTipDialog.OnReStartListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$QRCFQoEoFPYOu-WNdNz45LO7sYE
            @Override // im.uwrkaxlmjj.ui.dialogs.ReStartTipDialog.OnReStartListener
            public final void onReStart() {
                this.f$0.lambda$showReStartTipDialog$7$DialogsFragment();
            }
        }).show();
    }

    public /* synthetic */ void lambda$showReStartTipDialog$7$DialogsFragment() {
        ToastUtils.show((CharSequence) "重启应用");
        restartApp();
    }

    private void disDialig() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$5TwI7obo4vYM7679_frW-ZBJOdw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.dismissCurrentDialog();
            }
        });
    }

    private void showProgressDialog() {
        AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
    }

    private void restartApp() {
        FragmentActivity activity = (FragmentActivity) getParentActivity();
        if (activity == null) {
            return;
        }
        Context context = activity.getApplicationContext();
        PackageManager packageManager = context.getPackageManager();
        String packageName = context.getPackageName();
        Intent intent = packageManager.getLaunchIntentForPackage(packageName);
        if (intent == null) {
            return;
        }
        intent.addFlags(268468224);
        context.startActivity(intent);
        Process.killProcess(Process.myPid());
    }

    private void initSearchView(FrameLayout containerLayout) {
        FrameLayout frameLayout = new FrameLayout(this.context);
        this.searchLayout = frameLayout;
        containerLayout.addView(frameLayout, LayoutHelper.createFrameWithActionBar(-1, 55));
        MrySearchView mrySearchView = new MrySearchView(this.context);
        this.searchView = mrySearchView;
        mrySearchView.setHintText(LocaleController.getString("SearchMessageOrUser", R.string.SearchMessageOrUser));
        this.searchLayout.addView(this.searchView, LayoutHelper.createFrame(-1.0f, 35.0f, GravityCompat.START, 10.0f, 10.0f, 10.0f, 10.0f));
        this.searchLayout.setBackgroundColor(Theme.getColor(Theme.key_searchview_solidColor));
        this.searchView.setEditTextBackground(getParentActivity().getDrawable(R.drawable.shape_edit_bg));
        View view = new View(this.context);
        this.divider = view;
        view.setBackground(getResources().getDrawable(R.drawable.header_shadow).mutate());
        containerLayout.addView(this.divider, LayoutHelper.createFrameWithActionBar(-1, 1));
        this.searchView.setiSearchViewDelegate(new MrySearchView.ISearchViewDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.4
            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onStart(boolean focus) {
                if (focus) {
                    DialogsFragment.this.hideTitle();
                } else {
                    DialogsFragment.this.showTitle();
                }
                if (DialogsFragment.this.contentView != null) {
                    DialogsFragment.this.contentView.requestLayout();
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchExpand() {
                DialogsFragment.this.searchLayout.setBackgroundColor(Theme.getColor(Theme.key_searchview_solidColor));
                DialogsFragment.this.searching = true;
                if (DialogsFragment.this.switchItem != null) {
                    DialogsFragment.this.switchItem.setVisibility(8);
                }
                if (DialogsFragment.this.listView != null && DialogsFragment.this.searchString != null) {
                    DialogsFragment.this.listView.setEmptyView(DialogsFragment.this.searchEmptyView);
                    DialogsFragment.this.progressView.setVisibility(8);
                }
                DialogsFragment.this.updatePasscodeButton();
                DialogsFragment.this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrGoBack", R.string.AccDescrGoBack));
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public boolean canCollapseSearch() {
                if (DialogsFragment.this.switchItem != null) {
                    DialogsFragment.this.switchItem.setVisibility(0);
                }
                return DialogsFragment.this.searchString == null;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchCollapse() {
                DialogsFragment.this.searchLayout.setBackgroundColor(Theme.getColor(Theme.key_searchview_solidColor));
                DialogsFragment.this.searching = false;
                DialogsFragment.this.searchWas = false;
                if (DialogsFragment.this.listView != null) {
                    DialogsFragment.this.listView.setEmptyView(DialogsFragment.this.folderId == 0 ? DialogsFragment.this.progressView : null);
                    DialogsFragment.this.searchEmptyView.setVisibility(8);
                    if (DialogsFragment.this.listView.getAdapter() != DialogsFragment.this.dialogsAdapter) {
                        DialogsFragment.this.listView.setAdapter(DialogsFragment.this.dialogsAdapter);
                        DialogsFragment.this.dialogsAdapter.notifyDataSetChanged();
                    }
                }
                if (DialogsFragment.this.dialogsSearchAdapter != null) {
                    DialogsFragment.this.dialogsSearchAdapter.searchDialogs(null);
                }
                DialogsFragment.this.updatePasscodeButton();
                if (DialogsFragment.this.menuDrawable != null) {
                    DialogsFragment.this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrOpenMenu", R.string.AccDescrOpenMenu));
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onTextChange(String text) {
                if (text.length() != 0 || (DialogsFragment.this.dialogsSearchAdapter != null && DialogsFragment.this.dialogsSearchAdapter.hasRecentRearch())) {
                    DialogsFragment.this.searchWas = true;
                    if (DialogsFragment.this.dialogsSearchAdapter != null && DialogsFragment.this.listView.getAdapter() != DialogsFragment.this.dialogsSearchAdapter) {
                        DialogsFragment.this.listView.setAdapter(DialogsFragment.this.dialogsSearchAdapter);
                        DialogsFragment.this.dialogsSearchAdapter.notifyDataSetChanged();
                    }
                    if (DialogsFragment.this.searchEmptyView != null && DialogsFragment.this.listView.getEmptyView() != DialogsFragment.this.searchEmptyView) {
                        DialogsFragment.this.progressView.setVisibility(8);
                        DialogsFragment.this.listView.setEmptyView(DialogsFragment.this.searchEmptyView);
                    }
                    DialogsFragment.this.dialogsSearchAdapter.searchDialogs(text);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onActionSearch(String trim) {
            }
        });
    }

    private void initView(FrameLayout containerLayout) {
        ContentView contentView = new ContentView(this.context);
        this.contentView = contentView;
        containerLayout.addView(contentView, LayoutHelper.createFrameWithActionBar(-1, -2));
        this.contentView.setBackgroundColor(0);
        this.dialogsItemAnimator = new DialogsItemAnimator() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.5
            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onRemoveFinished(RecyclerView.ViewHolder item) {
                if (DialogsFragment.this.dialogRemoveFinished == 2) {
                    DialogsFragment.this.dialogRemoveFinished = 1;
                }
            }

            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onAddFinished(RecyclerView.ViewHolder item) {
                if (DialogsFragment.this.dialogInsertFinished == 2) {
                    DialogsFragment.this.dialogInsertFinished = 1;
                }
            }

            @Override // androidx.recyclerview.widget.SimpleItemAnimator
            public void onChangeFinished(RecyclerView.ViewHolder item, boolean oldItem) {
                if (DialogsFragment.this.dialogChangeFinished == 2) {
                    DialogsFragment.this.dialogChangeFinished = 1;
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.DialogsItemAnimator
            protected void onAllAnimationsDone() {
                if (DialogsFragment.this.dialogRemoveFinished == 1 || DialogsFragment.this.dialogInsertFinished == 1 || DialogsFragment.this.dialogChangeFinished == 1) {
                    DialogsFragment.this.onDialogAnimationFinished();
                }
            }
        };
        RecyclerListView recyclerListView = new RecyclerListView(this.context) { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.6
            private boolean firstLayout = true;
            private boolean ignoreLayout;

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.ViewGroup, android.view.View
            protected void dispatchDraw(Canvas canvas) {
                super.dispatchDraw(canvas);
                if (DialogsFragment.this.slidingView != null && DialogsFragment.this.pacmanAnimation != null) {
                    DialogsFragment.this.pacmanAnimation.draw(canvas, DialogsFragment.this.slidingView.getTop() + (DialogsFragment.this.slidingView.getMeasuredHeight() / 2));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView
            public void setAdapter(RecyclerView.Adapter adapter) {
                super.setAdapter(adapter);
                this.firstLayout = true;
            }

            private void checkIfAdapterValid() {
                if (DialogsFragment.this.listView != null && DialogsFragment.this.dialogsAdapter != null && DialogsFragment.this.listView.getAdapter() == DialogsFragment.this.dialogsAdapter && DialogsFragment.this.lastItemsCount != DialogsFragment.this.dialogsAdapter.getItemCount()) {
                    this.ignoreLayout = true;
                    DialogsFragment.this.dialogsAdapter.notifyDataSetChanged();
                    this.ignoreLayout = false;
                }
            }

            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (DialogsFragment.this.searchEmptyView != null) {
                    DialogsFragment.this.searchEmptyView.setPadding(left, top, right, bottom);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.View
            protected void onMeasure(int widthSpec, int heightSpec) {
                if (this.firstLayout && DialogsFragment.this.getMessagesController().dialogsLoaded) {
                    if (DialogsFragment.this.hasHiddenArchive()) {
                        this.ignoreLayout = true;
                        DialogsFragment.this.layoutManager.scrollToPositionWithOffset(1, AndroidUtilities.dp(55.0f));
                        this.ignoreLayout = false;
                    }
                    this.firstLayout = false;
                }
                checkIfAdapterValid();
                super.onMeasure(widthSpec, heightSpec);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                super.onLayout(changed, l, t, r, b);
                if ((DialogsFragment.this.dialogRemoveFinished != 0 || DialogsFragment.this.dialogInsertFinished != 0 || DialogsFragment.this.dialogChangeFinished != 0) && !DialogsFragment.this.dialogsItemAnimator.isRunning()) {
                    DialogsFragment.this.onDialogAnimationFinished();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean drawChild(Canvas canvas, View child, long drawingTime) {
                return super.drawChild(canvas, child, drawingTime);
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                if (DialogsFragment.this.waitingForScrollFinished || DialogsFragment.this.dialogRemoveFinished != 0 || DialogsFragment.this.dialogInsertFinished != 0 || DialogsFragment.this.dialogChangeFinished != 0) {
                    return false;
                }
                int action = e.getAction();
                boolean result = super.onTouchEvent(e);
                if ((action == 1 || action == 3) && DialogsFragment.this.allowScrollToHiddenView) {
                    int currentPosition = DialogsFragment.this.layoutManager.findFirstVisibleItemPosition();
                    if (currentPosition == 1) {
                        View view = DialogsFragment.this.layoutManager.findViewByPosition(currentPosition);
                        int height = (AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 77.0f : 71.0f) / 4) * 3;
                        int diff = view.getTop() + view.getMeasuredHeight();
                        if (view != null) {
                            if (diff < height) {
                                DialogsFragment.this.listView.smoothScrollBy(0, AndroidUtilities.dp(55.0f) + diff, CubicBezierInterpolator.EASE_OUT_QUINT);
                            } else {
                                DialogsFragment.this.listView.smoothScrollBy(0, view.getTop() + AndroidUtilities.dp(55.0f), CubicBezierInterpolator.EASE_OUT_QUINT);
                            }
                        }
                    }
                    DialogsFragment.this.allowScrollToHiddenView = false;
                }
                return result;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent e) {
                if (DialogsFragment.this.waitingForScrollFinished || DialogsFragment.this.dialogRemoveFinished != 0 || DialogsFragment.this.dialogInsertFinished != 0 || DialogsFragment.this.dialogChangeFinished != 0) {
                    return false;
                }
                if (e.getAction() == 0) {
                    DialogsFragment.this.allowSwipeDuringCurrentTouch = !r0.actionBar.isActionModeShowed();
                    checkIfAdapterValid();
                }
                if (e.getAction() == 2 && (DialogsFragment.this.isEditModel || getLongPressCalled())) {
                    return true;
                }
                return super.onInterceptTouchEvent(e);
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setOverScrollMode(2);
        this.listView.setItemAnimator(this.dialogsItemAnimator);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setInstantClick(true);
        this.listView.setTag(4);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.context) { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.7
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public void smoothScrollToPosition(RecyclerView recyclerView, RecyclerView.State state, int position) {
                if (DialogsFragment.this.hasHiddenArchive() && position == 1) {
                    super.smoothScrollToPosition(recyclerView, state, position);
                    return;
                }
                LinearSmoothScrollerMiddle linearSmoothScroller = new LinearSmoothScrollerMiddle(recyclerView.getContext());
                linearSmoothScroller.setTargetPosition(position);
                startSmoothScroll(linearSmoothScroller);
            }

            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public int scrollVerticallyBy(int dy, RecyclerView.Recycler recycler, RecyclerView.State state) {
                View view;
                View view2;
                if (DialogsFragment.this.listView.getAdapter() == DialogsFragment.this.dialogsAdapter && !DialogsFragment.this.allowScrollToHiddenView && DialogsFragment.this.folderId == 0 && dy < 0 && DialogsFragment.this.getMessagesController().hasHiddenArchive()) {
                    int currentPosition = DialogsFragment.this.layoutManager.findFirstVisibleItemPosition();
                    computeVerticalScrollOffset(state);
                    if (currentPosition == 0 && (view2 = DialogsFragment.this.layoutManager.findViewByPosition(currentPosition)) != null && view2.getBottom() <= AndroidUtilities.dp(63.0f)) {
                        currentPosition = 1;
                    }
                    if (currentPosition != 0 && currentPosition != -1 && (view = DialogsFragment.this.layoutManager.findViewByPosition(currentPosition)) != null) {
                        int dialogHeight = AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 77.0f : 71.0f) + 1;
                        int canScrollDy = (-view.getTop()) + ((currentPosition - 1) * dialogHeight) + AndroidUtilities.dp(55.0f);
                        int positiveDy = Math.abs(dy);
                        if (canScrollDy < positiveDy) {
                            DialogsFragment.this.totalConsumedAmount += Math.abs(dy);
                            dy = -canScrollDy;
                            if (DialogsFragment.this.startedScrollAtTop && DialogsFragment.this.totalConsumedAmount >= AndroidUtilities.dp(150.0f)) {
                                DialogsFragment.this.allowScrollToHiddenView = true;
                                try {
                                    DialogsFragment.this.listView.performHapticFeedback(3, 2);
                                } catch (Exception e) {
                                }
                            }
                        }
                    }
                }
                return super.scrollVerticallyBy(dy, recycler, state);
            }
        };
        this.layoutManager = linearLayoutManager;
        linearLayoutManager.setOrientation(1);
        this.listView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.8
            @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
            public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
                super.getItemOffsets(outRect, view, parent, state);
                int position = parent.getChildAdapterPosition(view);
                if (position == 0) {
                    outRect.top = AndroidUtilities.dp(55.0f);
                }
                RecyclerView.Adapter adapter = parent.getAdapter();
                if ((adapter instanceof FmtDialogsAdapter) && position == adapter.getItemCount() - 1) {
                    outRect.bottom = AndroidUtilities.dp(10.0f);
                }
            }
        });
        this.listView.setLayoutManager(this.layoutManager);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.contentView.addView(this.listView, LayoutHelper.createFrame(-1, -2, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(this.context);
        this.searchEmptyView = emptyTextProgressView;
        emptyTextProgressView.setVisibility(8);
        this.searchEmptyView.setShowAtCenter(true);
        this.searchEmptyView.setTopImage(R.drawable.settings_noresults);
        this.searchEmptyView.setText(LocaleController.getString("SettingsNoResults", R.string.SettingsNoResults));
        this.contentView.addView(this.searchEmptyView, LayoutHelper.createFrame(-1, -1.0f));
        RadialProgressView radialProgressView = new RadialProgressView(this.context);
        this.progressView = radialProgressView;
        radialProgressView.setVisibility(8);
        this.contentView.addView(this.progressView, LayoutHelper.createFrame(-2, -2, 17));
    }

    private void initListener() {
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$C0YrmYgq1K5zAuX1rIZLuTgJE6A
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initListener$8$DialogsFragment(view, i);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.9
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public boolean onItemClick(View clickView, int position, float x, float y) {
                TLRPC.Chat chat;
                if (DialogsFragment.this.getParentActivity() != null && !DialogsFragment.this.isEditModel) {
                    RecyclerView.Adapter adapter = DialogsFragment.this.listView.getAdapter();
                    if (adapter == DialogsFragment.this.dialogsSearchAdapter) {
                        return false;
                    }
                    ArrayList<TLRPC.Dialog> dialogs = DialogsFragment.getDialogsArray(DialogsFragment.this.currentAccount, DialogsFragment.this.dialogsType, DialogsFragment.this.folderId, DialogsFragment.this.dialogsListFrozen);
                    int position2 = DialogsFragment.this.dialogsAdapter.fixPosition(position);
                    if (position2 >= 0 && position2 < dialogs.size()) {
                        TLRPC.Dialog dialog = dialogs.get(position2);
                        if (dialog instanceof TLRPC.TL_dialogFolder) {
                            return false;
                        }
                        SwipeLayout swipeLayout = (SwipeLayout) clickView;
                        View view = swipeLayout.getMainLayout();
                        if (!AndroidUtilities.isTablet() && (view instanceof FmtDialogCell)) {
                            FmtDialogCell cell = (FmtDialogCell) view;
                            long dialog_id = cell.getDialogId();
                            Bundle args = new Bundle();
                            int lower_part = (int) dialog_id;
                            int message_id = cell.getMessageId();
                            if (lower_part == 0) {
                                return false;
                            }
                            if (lower_part > 0) {
                                args.putInt("user_id", lower_part);
                            } else if (lower_part < 0) {
                                if (message_id != 0 && (chat = DialogsFragment.this.getMessagesController().getChat(Integer.valueOf(-lower_part))) != null && chat.migrated_to != null) {
                                    args.putInt("migrated_to", lower_part);
                                    lower_part = -chat.migrated_to.channel_id;
                                }
                                args.putInt("chat_id", -lower_part);
                            }
                            if (message_id != 0) {
                                args.putInt("message_id", message_id);
                            }
                            if (DialogsFragment.this.searchString != null) {
                                if (DialogsFragment.this.getMessagesController().checkCanOpenChat(args, DialogsFragment.this.getCurrentFragment())) {
                                    DialogsFragment.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                                    DialogsFragment.this.presentFragmentAsPreview(new ChatActivity(args));
                                    return true;
                                }
                                return true;
                            }
                            if (DialogsFragment.this.getMessagesController().checkCanOpenChat(args, DialogsFragment.this.getCurrentFragment())) {
                                DialogsFragment.this.presentFragmentAsPreview(new ChatActivity(args));
                                return true;
                            }
                            return true;
                        }
                        return true;
                    }
                    return false;
                }
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onLongClickRelease() {
                DialogsFragment.this.finishPreviewFragment();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onMove(float dx, float dy) {
                DialogsFragment.this.movePreviewFragment(dy);
            }
        });
        this.listView.addOnScrollListener(new AnonymousClass10());
        SharedPreferences notificationsSettings = MessagesController.getNotificationsSettings(this.currentAccount);
        this.notificationsSettingsSP = notificationsSettings;
        notificationsSettings.registerOnSharedPreferenceChangeListener(new $$Lambda$DialogsFragment$hLYS5Ja9fYXztObkZDHxHtfloQc(this));
    }

    public /* synthetic */ void lambda$initListener$8$DialogsFragment(View clickView, int position) {
        long dialog_id;
        TLRPC.Chat chat;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || recyclerListView.getAdapter() == null || getParentActivity() == null) {
            return;
        }
        int message_id = 0;
        boolean isGlobalSearch = false;
        RecyclerView.Adapter adapter = this.listView.getAdapter();
        FmtDialogsAdapter fmtDialogsAdapter = this.dialogsAdapter;
        if (adapter != fmtDialogsAdapter) {
            DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
            if (adapter != dialogsSearchAdapter) {
                dialog_id = 0;
            } else {
                Object obj = dialogsSearchAdapter.getItem(position);
                isGlobalSearch = this.dialogsSearchAdapter.isGlobalSearch(position);
                if (obj instanceof TLRPC.User) {
                    long dialog_id2 = ((TLRPC.User) obj).id;
                    this.searchDialogId = dialog_id2;
                    this.searchObject = (TLRPC.User) obj;
                    dialog_id = dialog_id2;
                } else if (obj instanceof TLRPC.Chat) {
                    long dialog_id3 = -((TLRPC.Chat) obj).id;
                    this.searchDialogId = dialog_id3;
                    this.searchObject = (TLRPC.Chat) obj;
                    dialog_id = dialog_id3;
                } else if (obj instanceof TLRPC.EncryptedChat) {
                    long dialog_id4 = ((long) ((TLRPC.EncryptedChat) obj).id) << 32;
                    this.searchDialogId = dialog_id4;
                    this.searchObject = (TLRPC.EncryptedChat) obj;
                    dialog_id = dialog_id4;
                } else if (obj instanceof MessageObject) {
                    MessageObject messageObject = (MessageObject) obj;
                    long dialog_id5 = messageObject.getDialogId();
                    message_id = messageObject.getId();
                    DialogsSearchAdapter dialogsSearchAdapter2 = this.dialogsSearchAdapter;
                    dialogsSearchAdapter2.addHashtagsFromMessage(dialogsSearchAdapter2.getLastSearchString());
                    dialog_id = dialog_id5;
                } else {
                    if (obj instanceof String) {
                        String str = (String) obj;
                        if (this.dialogsSearchAdapter.isHashtagSearch()) {
                            this.searchView.openSearchField(str);
                        } else if (!str.equals("section")) {
                            NewContactActivity activity = new NewContactActivity();
                            activity.setInitialPhoneNumber(str);
                            presentFragment(activity);
                        }
                    }
                    dialog_id = 0;
                }
            }
        } else {
            TLObject object = fmtDialogsAdapter.getItem(position);
            if (object instanceof TLRPC.User) {
                dialog_id = ((TLRPC.User) object).id;
            } else if (object instanceof TLRPC.Dialog) {
                TLRPC.Dialog dialog = (TLRPC.Dialog) object;
                if (dialog instanceof TLRPC.TL_dialogFolder) {
                    if (this.actionBar.isActionModeShowed()) {
                        return;
                    }
                    TLRPC.TL_dialogFolder dialogFolder = (TLRPC.TL_dialogFolder) dialog;
                    Bundle args = new Bundle();
                    args.putInt("folderId", dialogFolder.folder.id);
                    presentFragment(new DialogsActivity(args));
                    return;
                }
                dialog_id = dialog.id;
                if (this.isEditModel) {
                    SwipeLayout swipeLayout = (SwipeLayout) clickView;
                    View view = swipeLayout.getMainLayout();
                    showOrUpdateActionMode(dialog, view);
                    return;
                } else if (this.dialogsType == 9) {
                    getMessagesController().dialogsUnreadOnly.remove(dialog);
                    this.dialogsAdapter.notifyItemRemoved(position);
                } else {
                    getMessagesController().dialogsUnreadOnly.remove(dialog);
                }
            } else if (object instanceof TLRPC.TL_recentMeUrlChat) {
                dialog_id = -((TLRPC.TL_recentMeUrlChat) object).chat_id;
            } else if (object instanceof TLRPC.TL_recentMeUrlUser) {
                dialog_id = ((TLRPC.TL_recentMeUrlUser) object).user_id;
            } else if (object instanceof TLRPC.TL_recentMeUrlChatInvite) {
                TLRPC.TL_recentMeUrlChatInvite chatInvite = (TLRPC.TL_recentMeUrlChatInvite) object;
                TLRPC.ChatInvite invite = chatInvite.chat_invite;
                if ((invite.chat == null && (!invite.channel || invite.megagroup)) || (invite.chat != null && (!ChatObject.isChannel(invite.chat) || invite.chat.megagroup))) {
                    String hash = chatInvite.url;
                    int index = hash.indexOf(47);
                    if (index > 0) {
                        hash = hash.substring(index + 1);
                    }
                    showDialog(new JoinGroupAlert(getParentActivity(), invite, hash, getCurrentFragment()));
                    return;
                }
                if (invite.chat != null) {
                    dialog_id = -invite.chat.id;
                } else {
                    return;
                }
            } else {
                if (!(object instanceof TLRPC.TL_recentMeUrlStickerSet)) {
                    if (object instanceof TLRPC.TL_recentMeUrlUnknown) {
                        return;
                    } else {
                        return;
                    }
                }
                TLRPC.StickerSet stickerSet = ((TLRPC.TL_recentMeUrlStickerSet) object).set.set;
                TLRPC.TL_inputStickerSetID set = new TLRPC.TL_inputStickerSetID();
                set.id = stickerSet.id;
                set.access_hash = stickerSet.access_hash;
                showDialog(new StickersAlert(getParentActivity(), getCurrentFragment(), set, null, null));
                return;
            }
        }
        if (dialog_id == 0) {
            return;
        }
        Bundle args2 = new Bundle();
        int lower_part = (int) dialog_id;
        int high_id = (int) (dialog_id >> 32);
        if (lower_part != 0) {
            if (lower_part > 0) {
                args2.putInt("user_id", lower_part);
                if (this.searching || this.searchWas) {
                    TLRPC.User user = getMessagesController().getUser(Integer.valueOf(lower_part));
                    if (!user.contact && !user.bot) {
                        getMessagesController();
                        if (!MessagesController.isSupportUser(user)) {
                            presentFragment(new AddContactsInfoActivity(null, user));
                            return;
                        }
                    }
                }
            } else if (lower_part < 0) {
                if (message_id != 0 && (chat = getMessagesController().getChat(Integer.valueOf(-lower_part))) != null && chat.migrated_to != null) {
                    args2.putInt("migrated_to", lower_part);
                    lower_part = -chat.migrated_to.channel_id;
                }
                args2.putInt("chat_id", -lower_part);
            }
        } else {
            args2.putInt("enc_id", high_id);
        }
        if (message_id != 0) {
            args2.putInt("message_id", message_id);
        } else if (!isGlobalSearch) {
            closeSearch();
        } else {
            TLObject tLObject = this.searchObject;
            if (tLObject != null) {
                this.dialogsSearchAdapter.putRecentSearch(this.searchDialogId, tLObject);
                this.searchObject = null;
            }
        }
        if (AndroidUtilities.isTablet()) {
            if (this.openedDialogId == dialog_id && adapter != this.dialogsSearchAdapter) {
                return;
            }
            FmtDialogsAdapter fmtDialogsAdapter2 = this.dialogsAdapter;
            if (fmtDialogsAdapter2 != null) {
                this.openedDialogId = dialog_id;
                fmtDialogsAdapter2.setOpenedDialogId(dialog_id);
                updateVisibleRows(512);
            }
        }
        if (this.searchString != null) {
            if (getMessagesController().checkCanOpenChat(args2, getCurrentFragment())) {
                getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                presentFragment(new ChatActivity(args2));
                return;
            }
            return;
        }
        if (getMessagesController().checkCanOpenChat(args2, getCurrentFragment())) {
            presentFragment(new ChatActivity(args2));
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.fragments.DialogsFragment$10, reason: invalid class name */
    class AnonymousClass10 extends RecyclerView.OnScrollListener {
        AnonymousClass10() {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
            if (newState == 1 && DialogsFragment.this.searching && DialogsFragment.this.searchWas) {
                AndroidUtilities.hideKeyboard(DialogsFragment.this.getParentActivity().getCurrentFocus());
            }
            if (DialogsFragment.this.waitingForScrollFinished && newState == 0) {
                DialogsFragment.this.waitingForScrollFinished = false;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            final boolean fromCache;
            int firstVisibleItem = DialogsFragment.this.layoutManager.findFirstVisibleItemPosition();
            int visibleItemCount = Math.abs(DialogsFragment.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
            int totalItemCount = recyclerView.getAdapter().getItemCount();
            DialogsFragment.this.dialogsItemAnimator.onListScroll(-dy);
            if (DialogsFragment.this.searching && DialogsFragment.this.searchWas) {
                if (visibleItemCount > 0 && DialogsFragment.this.layoutManager.findLastVisibleItemPosition() == totalItemCount - 1 && !DialogsFragment.this.dialogsSearchAdapter.isMessagesSearchEndReached()) {
                    DialogsFragment.this.dialogsSearchAdapter.loadMoreSearchMessages();
                    return;
                }
                return;
            }
            if (visibleItemCount > 0 && DialogsFragment.this.layoutManager.findLastVisibleItemPosition() >= DialogsFragment.getDialogsArray(DialogsFragment.this.currentAccount, DialogsFragment.this.dialogsType, DialogsFragment.this.folderId, DialogsFragment.this.dialogsListFrozen).size() - 10 && ((!DialogsFragment.this.getMessagesController().isDialogsEndReached(DialogsFragment.this.folderId)) || !DialogsFragment.this.getMessagesController().isServerDialogsEndReached(DialogsFragment.this.folderId))) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$10$a16YcpBOs8nPcksebiPPg9HB5rk
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onScrolled$0$DialogsFragment$10(fromCache);
                    }
                });
            }
            boolean hasHiddenArchive = DialogsFragment.this.hasHiddenArchive();
            int off = recyclerView.computeVerticalScrollOffset();
            DialogsFragment.this.divider.setVisibility(off > AndroidUtilities.dp(55.0f) ? 0 : 8);
            if (off >= 0) {
                if (!hasHiddenArchive || firstVisibleItem == 1) {
                    DialogsFragment.this.searchLayout.setScrollY(Math.min(off, AndroidUtilities.dp(55.0f)));
                    return;
                }
                int m = off - AndroidUtilities.dp(55.0f);
                if (m >= 0) {
                    DialogsFragment.this.searchLayout.setScrollY(Math.min(m, AndroidUtilities.dp(55.0f)));
                } else {
                    DialogsFragment.this.searchLayout.setScrollY(0);
                }
            }
        }

        public /* synthetic */ void lambda$onScrolled$0$DialogsFragment$10(boolean fromCache) {
            DialogsFragment.this.getMessagesController().loadDialogs(DialogsFragment.this.folderId, -1, 100, fromCache);
        }
    }

    private void initData() {
        if (this.searchString == null) {
            FmtDialogsAdapter fmtDialogsAdapter = new FmtDialogsAdapter(this.context, this.dialogsType, this.folderId) { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.11
                @Override // im.uwrkaxlmjj.ui.fragments.adapter.FmtDialogsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
                public void notifyDataSetChanged() {
                    DialogsFragment.this.lastItemsCount = getItemCount();
                    super.notifyDataSetChanged();
                }
            };
            this.dialogsAdapter = fmtDialogsAdapter;
            fmtDialogsAdapter.setDelegate(new FmtDialogsAdapter.FmtDialogDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.12
                @Override // im.uwrkaxlmjj.ui.fragments.adapter.FmtDialogsAdapter.FmtDialogDelegate
                public void onItemMenuClick(boolean left, int index, long dialog_id, int i) throws Exception {
                    DialogsFragment.this.performMenuClick(left, index, dialog_id, i);
                }
            });
            if (AndroidUtilities.isTablet()) {
                long j = this.openedDialogId;
                if (j != 0) {
                    this.dialogsAdapter.setOpenedDialogId(j);
                }
            }
            this.listView.setAdapter(this.dialogsAdapter);
        }
        int type = 1;
        if (this.searchString != null) {
            type = 2;
        }
        DialogsSearchAdapter dialogsSearchAdapter = new DialogsSearchAdapter(this.context, type, 0, AndroidUtilities.dp(20.0f));
        this.dialogsSearchAdapter = dialogsSearchAdapter;
        dialogsSearchAdapter.setDelegate(new AnonymousClass13());
        this.listView.setEmptyView(this.folderId == 0 ? this.progressView : null);
        String str = this.searchString;
        if (str != null) {
            this.searchView.openSearchField(str);
        }
        for (int a = 0; a < 2; a++) {
            this.undoView[a] = new UndoView(this.context) { // from class: im.uwrkaxlmjj.ui.fragments.DialogsFragment.14
                @Override // android.view.View
                public void setTranslationY(float translationY) {
                    super.setTranslationY(translationY);
                    if (this == DialogsFragment.this.undoView[0] && DialogsFragment.this.undoView[1].getVisibility() != 0) {
                        getMeasuredHeight();
                        AndroidUtilities.dp(8.0f);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.UndoView
                protected boolean canUndo() {
                    return !DialogsFragment.this.dialogsItemAnimator.isRunning();
                }
            };
            this.contentView.addView(this.undoView[a], LayoutHelper.createFrame(-1.0f, -2.0f, 83, 8.0f, 0.0f, 8.0f, 8.0f));
        }
        int a2 = this.folderId;
        if (a2 != 0) {
            this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultArchived));
            this.listView.setGlowColor(Theme.getColor(Theme.key_actionBarDefaultArchived));
            this.actionBar.setTitleColor(Theme.getColor(Theme.key_actionBarDefaultArchivedTitle));
            this.actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarDefaultArchivedIcon), false);
            this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultArchivedSelector), false);
            this.actionBar.setSearchTextColor(Theme.getColor(Theme.key_actionBarDefaultArchivedSearch), false);
            this.actionBar.setSearchTextColor(Theme.getColor(Theme.key_actionBarDefaultArchivedSearchPlaceholder), true);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.fragments.DialogsFragment$13, reason: invalid class name */
    class AnonymousClass13 implements DialogsSearchAdapter.DialogsSearchAdapterDelegate {
        AnonymousClass13() {
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void searchStateChanged(boolean search) {
            if (DialogsFragment.this.searching && DialogsFragment.this.searchWas && DialogsFragment.this.searchEmptyView != null) {
                if (search) {
                    DialogsFragment.this.searchEmptyView.showProgress();
                } else {
                    DialogsFragment.this.searchEmptyView.showTextView();
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void didPressedOnSubDialog(long did) {
            int lower_id = (int) did;
            Bundle args = new Bundle();
            if (lower_id > 0) {
                args.putInt("user_id", lower_id);
            } else {
                args.putInt("chat_id", -lower_id);
            }
            DialogsFragment.this.closeSearch();
            if (AndroidUtilities.isTablet() && DialogsFragment.this.dialogsAdapter != null) {
                DialogsFragment.this.dialogsAdapter.setOpenedDialogId(DialogsFragment.this.openedDialogId = did);
                DialogsFragment.this.updateVisibleRows(512);
            }
            if (DialogsFragment.this.searchString != null) {
                if (DialogsFragment.this.getMessagesController().checkCanOpenChat(args, DialogsFragment.this.getCurrentFragment())) {
                    DialogsFragment.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
                    DialogsFragment.this.presentFragment(new ChatActivity(args));
                    return;
                }
                return;
            }
            TLRPC.User user = DialogsFragment.this.getMessagesController().getUser(Integer.valueOf(lower_id));
            if (user != null && !user.contact && !user.bot) {
                DialogsFragment.this.getMessagesController();
                if (!MessagesController.isSupportUser(user)) {
                    DialogsFragment.this.presentFragment(new AddContactsInfoActivity(null, user));
                    return;
                }
            }
            if (DialogsFragment.this.getMessagesController().checkCanOpenChat(args, DialogsFragment.this.getCurrentFragment())) {
                DialogsFragment.this.presentFragment(new ChatActivity(args));
            }
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void needRemoveHint(final int did) {
            TLRPC.User user;
            if (DialogsFragment.this.getParentActivity() == null || (user = DialogsFragment.this.getMessagesController().getUser(Integer.valueOf(did))) == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(DialogsFragment.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ChatHintsDeleteAlertTitle", R.string.ChatHintsDeleteAlertTitle));
            builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("ChatHintsDeleteAlert", R.string.ChatHintsDeleteAlert, ContactsController.formatName(user.first_name, user.last_name))));
            builder.setPositiveButton(LocaleController.getString("StickersRemove", R.string.StickersRemove), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$13$witaez6LNSDKqBPKFUFK2URZNXQ
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$needRemoveHint$0$DialogsFragment$13(did, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            DialogsFragment.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$needRemoveHint$0$DialogsFragment$13(int did, DialogInterface dialogInterface, int i) {
            DialogsFragment.this.getMediaDataController().removePeer(did);
        }

        @Override // im.uwrkaxlmjj.ui.adapters.DialogsSearchAdapter.DialogsSearchAdapterDelegate
        public void needClearList() {
            AlertDialog.Builder builder = new AlertDialog.Builder(DialogsFragment.this.getParentActivity());
            builder.setTitle(LocaleController.getString("ClearSearchAlertTitle", R.string.ClearSearchAlertTitle));
            builder.setMessage(LocaleController.getString("ClearSearchAlert", R.string.ClearSearchAlert));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$13$efoNvMCN-aXll9gkhEx_bzugwPM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$needClearList$1$DialogsFragment$13(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            AlertDialog dialog = builder.create();
            DialogsFragment.this.showDialog(dialog);
            TextView button = (TextView) dialog.getButton(-1);
            if (button != null) {
                button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
            }
        }

        public /* synthetic */ void lambda$needClearList$1$DialogsFragment$13(DialogInterface dialogInterface, int i) {
            if (DialogsFragment.this.dialogsSearchAdapter.isRecentSearchDisplayed()) {
                DialogsFragment.this.dialogsSearchAdapter.clearRecentSearch();
            } else {
                DialogsFragment.this.dialogsSearchAdapter.clearRecentHashtags();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideTitle() {
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.containerLayout, "translationY", 0.0f, -ActionBar.getCurrentActionBarHeight());
        animator.setDuration(300L);
        animator.start();
        this.actionBar.setVisibility(4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showTitle() {
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.containerLayout, "translationY", -ActionBar.getCurrentActionBarHeight(), 0.0f);
        animator.start();
        this.actionBar.setVisibility(0);
    }

    public NotificationCenter getNotificationCenter() {
        return getAccountInstance().getNotificationCenter();
    }

    private boolean waitingForDialogsAnimationEnd() {
        return (!this.dialogsItemAnimator.isRunning() && this.dialogRemoveFinished == 0 && this.dialogInsertFinished == 0 && this.dialogChangeFinished == 0) ? false : true;
    }

    protected RecyclerListView getListView() {
        return this.listView;
    }

    private UndoView getUndoView() {
        if (this.undoView[0].getVisibility() == 0) {
            UndoView[] undoViewArr = this.undoView;
            UndoView old = undoViewArr[0];
            undoViewArr[0] = undoViewArr[1];
            undoViewArr[1] = old;
            old.hide(true, 2);
            if (this.undoView[0].getParent() != null) {
                ((ViewGroup) this.undoView[0].getParent()).removeView(this.undoView[0]);
            }
            this.contentView.addView(this.undoView[0]);
        }
        return this.undoView[0];
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, final Object... args) {
        if (id == NotificationCenter.dialogsNeedReload) {
            if (this.dialogsListFrozen) {
                return;
            }
            FmtDialogsAdapter fmtDialogsAdapter = this.dialogsAdapter;
            if (fmtDialogsAdapter != null) {
                if (!fmtDialogsAdapter.isDataSetChanged() && args.length <= 0) {
                    updateVisibleRows(2048);
                } else {
                    this.dialogsAdapter.notifyDataSetChanged();
                }
            }
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                try {
                    if (recyclerListView.getAdapter() == this.dialogsAdapter) {
                        this.searchEmptyView.setVisibility(8);
                        this.listView.setEmptyView(this.folderId == 0 ? this.progressView : null);
                    } else {
                        if (this.searching && this.searchWas) {
                            this.listView.setEmptyView(this.searchEmptyView);
                        } else {
                            this.searchEmptyView.setVisibility(8);
                            this.listView.setEmptyView(null);
                        }
                        this.progressView.setVisibility(8);
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            FmtConsumDelegate fmtConsumDelegate = this.delegate;
            if (fmtConsumDelegate != null) {
                fmtConsumDelegate.changeUnreadCount(getUnreadCount());
                return;
            }
            return;
        }
        if (id == NotificationCenter.emojiDidLoad) {
            updateVisibleRows(0);
            return;
        }
        if (id == NotificationCenter.closeSearchByActiveAction) {
            if (this.actionBar != null) {
                this.searchView.closeSearchField();
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            Integer mask = (Integer) args[0];
            updateVisibleRows(mask.intValue());
            FmtConsumDelegate fmtConsumDelegate2 = this.delegate;
            if (fmtConsumDelegate2 != null) {
                fmtConsumDelegate2.changeUnreadCount(getUnreadCount());
                return;
            }
            return;
        }
        if (id == NotificationCenter.appDidLogout) {
            dialogsLoaded[this.currentAccount] = false;
            return;
        }
        if (id == NotificationCenter.encryptedChatUpdated) {
            updateVisibleRows(0);
            return;
        }
        if (id == NotificationCenter.contactsDidLoad) {
            if (!this.dialogsListFrozen) {
                if (getMessagesController().getDialogs(this.folderId).isEmpty()) {
                    FmtDialogsAdapter fmtDialogsAdapter2 = this.dialogsAdapter;
                    if (fmtDialogsAdapter2 != null) {
                        fmtDialogsAdapter2.notifyDataSetChanged();
                        return;
                    }
                    return;
                }
                updateVisibleRows(0);
                return;
            }
            return;
        }
        if (id == NotificationCenter.openedChatChanged) {
            if (AndroidUtilities.isTablet()) {
                boolean close = ((Boolean) args[1]).booleanValue();
                long dialog_id = ((Long) args[0]).longValue();
                if (!close) {
                    this.openedDialogId = dialog_id;
                } else if (dialog_id == this.openedDialogId) {
                    this.openedDialogId = 0L;
                }
                FmtDialogsAdapter fmtDialogsAdapter3 = this.dialogsAdapter;
                if (fmtDialogsAdapter3 != null) {
                    fmtDialogsAdapter3.setOpenedDialogId(this.openedDialogId);
                }
                updateVisibleRows(512);
                return;
            }
            return;
        }
        if (id == NotificationCenter.notificationsSettingsUpdated) {
            updateVisibleRows(0);
            FmtConsumDelegate fmtConsumDelegate3 = this.delegate;
            if (fmtConsumDelegate3 != null) {
                fmtConsumDelegate3.changeUnreadCount(getUnreadCount());
                return;
            }
            return;
        }
        if (id == NotificationCenter.messageReceivedByAck || id == NotificationCenter.messageReceivedByServer || id == NotificationCenter.messageSendError) {
            updateVisibleRows(4096);
            return;
        }
        if (id == NotificationCenter.didSetPasscode) {
            updatePasscodeButton();
            return;
        }
        if (id == NotificationCenter.needReloadRecentDialogsSearch) {
            DialogsSearchAdapter dialogsSearchAdapter = this.dialogsSearchAdapter;
            if (dialogsSearchAdapter != null) {
                dialogsSearchAdapter.loadRecentSearch();
                return;
            }
            return;
        }
        if (id == NotificationCenter.replyMessagesDidLoad) {
            updateVisibleRows(32768);
            return;
        }
        if (id == NotificationCenter.reloadHints) {
            DialogsSearchAdapter dialogsSearchAdapter2 = this.dialogsSearchAdapter;
            if (dialogsSearchAdapter2 != null) {
                dialogsSearchAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.didUpdateConnectionState) {
            int state = AccountInstance.getInstance(account).getConnectionsManager().getConnectionState();
            if (this.currentConnectionState != state) {
                this.currentConnectionState = state;
                return;
            }
            return;
        }
        if (id != NotificationCenter.dialogsUnreadCounterChanged) {
            if (id == NotificationCenter.needDeleteDialog) {
                if (this.fragmentView == null || this.isPaused) {
                    return;
                }
                final long dialogId = ((Long) args[0]).longValue();
                final TLRPC.Chat chat = (TLRPC.Chat) args[2];
                final boolean revoke = ((Boolean) args[3]).booleanValue();
                Runnable deleteRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$AGYCwVj3n1HXChTE2J75CgWw_4I
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        this.f$0.lambda$didReceivedNotification$9$DialogsFragment(chat, dialogId, revoke);
                    }
                };
                if (this.undoView[0] != null) {
                    getUndoView().showWithAction(dialogId, 1, deleteRunnable);
                    return;
                } else {
                    deleteRunnable.run();
                    return;
                }
            }
            if (id == NotificationCenter.folderBecomeEmpty) {
                ((Integer) args[0]).intValue();
                int i = this.folderId;
                return;
            }
            int fid = NotificationCenter.pushRemoteOpenChat;
            if (id == fid) {
                if (getActivity() != null) {
                    jumpToChatWindow(Integer.parseInt(String.valueOf(args[0])));
                } else {
                    new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$R9A5WSRm4zVhjXNc5BAIUqyBF1g
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$didReceivedNotification$11$DialogsFragment(args);
                        }
                    }).start();
                }
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$9$DialogsFragment(TLRPC.Chat chat, long dialogId, boolean revoke) throws Exception {
        if (chat == null || ChatObject.isNotInChat(chat)) {
            getMessagesController().deleteDialog(dialogId, 0, revoke);
        } else {
            getMessagesController().deleteUserFromChat((int) (-dialogId), getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId())), null, false, revoke);
        }
        MessagesController.getInstance(this.currentAccount).checkIfFolderEmpty(this.folderId);
    }

    public /* synthetic */ void lambda$didReceivedNotification$11$DialogsFragment(final Object[] args) {
        while (getActivity() == null) {
            try {
                Thread.sleep(50L);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$nRTLyPE5jtO1xZLSU473gH-am7Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$10$DialogsFragment(args);
            }
        });
    }

    public /* synthetic */ void lambda$null$10$DialogsFragment(Object[] args) {
        jumpToChatWindow(Integer.parseInt(String.valueOf(args[0])));
    }

    private void jumpToChatWindow(int dialog_id) {
        Bundle args = new Bundle();
        int high_id = dialog_id >> 32;
        if (dialog_id != 0) {
            if (dialog_id > 0) {
                args.putInt("user_id", dialog_id);
            } else if (dialog_id < 0) {
                args.putInt("chat_id", -dialog_id);
            }
        } else {
            args.putInt("enc_id", high_id);
        }
        if (getMessagesController().checkCanOpenChat(args, getCurrentFragment())) {
            presentFragment(new ChatActivity(args));
        }
    }

    private void setDialogsListFrozen(boolean frozen) {
        if (this.dialogsListFrozen == frozen) {
            return;
        }
        if (frozen) {
            frozenDialogsList = new ArrayList<>(getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false));
        } else {
            frozenDialogsList = null;
        }
        this.dialogsListFrozen = frozen;
        this.dialogsAdapter.setDialogsListFrozen(frozen);
        if (!frozen) {
            this.dialogsAdapter.notifyDataSetChanged();
        }
    }

    private int getUnreadCount() {
        int count = 0;
        ArrayList<TLRPC.Dialog> dialogsArray = getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false);
        if (dialogsArray == null) {
            return 0;
        }
        NotificationsController controller = getNotificationsController();
        for (TLRPC.Dialog dialog : dialogsArray) {
            if (controller.showBadgeNumber) {
                if (controller.showBadgeMessages) {
                    if (controller.showBadgeMuted || dialog.notify_settings == null || (!dialog.notify_settings.silent && dialog.notify_settings.mute_until <= getConnectionsManager().getCurrentTime())) {
                        count += dialog.unread_count;
                    }
                } else if (controller.showBadgeMuted || dialog.notify_settings == null || (!dialog.notify_settings.silent && dialog.notify_settings.mute_until <= getConnectionsManager().getCurrentTime())) {
                    if (dialog.unread_count != 0) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    public static ArrayList<TLRPC.Dialog> getDialogsArray(int currentAccount, int dialogsType, int folderId, boolean frozen) {
        ArrayList<TLRPC.Dialog> arrayList;
        if (frozen && (arrayList = frozenDialogsList) != null) {
            return arrayList;
        }
        MessagesController messagesController = AccountInstance.getInstance(currentAccount).getMessagesController();
        if (dialogsType == 0) {
            return messagesController.getDialogs(folderId);
        }
        if (dialogsType == 1) {
            return messagesController.dialogsServerOnly;
        }
        if (dialogsType == 2) {
            return messagesController.dialogsCanAddUsers;
        }
        if (dialogsType == 3) {
            return messagesController.dialogsForward;
        }
        if (dialogsType == 4) {
            return messagesController.dialogsUsersOnly;
        }
        if (dialogsType == 5) {
            return messagesController.dialogsChannelsOnly;
        }
        if (dialogsType == 6) {
            return messagesController.dialogsGroupsOnly;
        }
        if (dialogsType == 9) {
            return messagesController.dialogsUnreadOnly;
        }
        if (dialogsType == 7) {
            ArrayList<TLRPC.Dialog> dialogs = new ArrayList<>();
            for (TLRPC.Dialog dialog : messagesController.dialogsForward) {
                long dialogId = dialog.id;
                if (dialogId != 0) {
                    int lower_id = (int) dialogId;
                    if (lower_id != 0) {
                        dialogs.add(dialog);
                    }
                }
            }
            return dialogs;
        }
        if (dialogsType == 8) {
            ArrayList<TLRPC.Dialog> dialogs2 = new ArrayList<>();
            ArrayList<TLRPC.Dialog> dialogsTemp = messagesController.getDialogs(folderId);
            for (TLRPC.Dialog dialog2 : dialogsTemp) {
                if (dialog2.unread_mentions_count != 0 || dialog2.unread_count != 0) {
                    dialogs2.add(dialog2);
                }
            }
            return dialogs2;
        }
        return null;
    }

    public void setSideMenu(RecyclerView recyclerView) {
        this.sideMenu = recyclerView;
        recyclerView.setBackgroundColor(Theme.getColor(Theme.key_chats_menuBackground));
        this.sideMenu.setGlowColor(Theme.getColor(Theme.key_chats_menuBackground));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePasscodeButton() {
        if (this.passcodeItem == null) {
            return;
        }
        if (SharedConfig.passcodeHash.length() != 0 && !this.searching) {
            this.passcodeItem.setVisibility(0);
            if (SharedConfig.appLocked) {
                this.passcodeItem.setIcon(R.drawable.lock_close);
                this.passcodeItem.setContentDescription(LocaleController.getString("AccDescrPasscodeUnlock", R.string.AccDescrPasscodeUnlock));
                return;
            } else {
                this.passcodeItem.setIcon(R.drawable.lock_open);
                this.passcodeItem.setContentDescription(LocaleController.getString("AccDescrPasscodeLock", R.string.AccDescrPasscodeLock));
                return;
            }
        }
        this.passcodeItem.setVisibility(8);
    }

    private void updateDialogIndices() {
        int index;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || recyclerListView.getAdapter() != this.dialogsAdapter) {
            return;
        }
        ArrayList<TLRPC.Dialog> dialogs = getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false);
        int count = this.listView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof SwipeLayout) {
                SwipeLayout swipeLayout = (SwipeLayout) child;
                FmtDialogCell dialogCell = (FmtDialogCell) swipeLayout.getMainLayout();
                TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(dialogCell.getDialogId());
                if (dialog != null && (index = dialogs.indexOf(dialog)) >= 0) {
                    dialogCell.setDialogIndex(index);
                }
            }
        }
    }

    private void updateSwipeLayout(SwipeLayout swipeLayout, long dialog_id) {
        TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(dialog_id);
        if (dialog != null && !(dialog instanceof TLRPC.TL_dialogFolder)) {
            swipeLayout.setTextAtIndex(true, 1, LocaleController.getString(dialog.pinned ? R.string.UnpinFromTop : R.string.PinToTop));
            swipeLayout.setIconAtIndex(true, 1, dialog.pinned ? R.drawable.msg_unpin : R.drawable.msg_pin);
            swipeLayout.setbackgroudAtIndex(true, 1, Theme.getColor(Theme.key_accentSuccess));
            boolean isDialogMuted = MessagesController.getInstance(UserConfig.selectedAccount).isDialogMuted(dialog.id);
            swipeLayout.setTextAtIndex(false, 0, LocaleController.getString(isDialogMuted ? R.string.ChatsUnmute : R.string.ChatsMute));
            swipeLayout.setIconAtIndex(false, 0, isDialogMuted ? R.drawable.msg_unmute : R.drawable.msg_mute);
            swipeLayout.setbackgroudAtIndex(false, 0, Theme.getColor(Theme.key_accentOrange));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVisibleRows(int mask) {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView == null || this.dialogsListFrozen) {
            return;
        }
        int count = recyclerListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.listView.getChildAt(a);
            if (child instanceof SwipeLayout) {
                if (this.listView.getAdapter() != this.dialogsSearchAdapter) {
                    SwipeLayout swipeLayout = (SwipeLayout) child;
                    FmtDialogCell cell = (FmtDialogCell) swipeLayout.getMainLayout();
                    if ((131072 & mask) != 0) {
                        cell.onReorderStateChanged(this.actionBar.isActionModeShowed(), true);
                    }
                    if ((65536 & mask) != 0) {
                        cell.setChecked(false, (mask & 8192) != 0);
                    } else {
                        if ((mask & 2048) != 0) {
                            cell.checkCurrentDialogIndex(this.dialogsListFrozen);
                            if (AndroidUtilities.isTablet()) {
                                cell.setDialogSelected(cell.getDialogId() == this.openedDialogId);
                            }
                            updateSwipeLayout(swipeLayout, cell.getDialogId());
                        } else if ((mask & 512) != 0) {
                            if (AndroidUtilities.isTablet()) {
                                cell.setDialogSelected(cell.getDialogId() == this.openedDialogId);
                            }
                        } else {
                            cell.update(mask);
                            updateSwipeLayout(swipeLayout, cell.getDialogId());
                        }
                        ArrayList<Long> selectedDialogs = this.dialogsAdapter.getSelectedDialogs();
                        if (selectedDialogs != null) {
                            cell.setChecked(selectedDialogs.contains(Long.valueOf(cell.getDialogId())), false);
                        }
                    }
                }
            } else if (child instanceof UserCell) {
                ((UserCell) child).update(mask);
            } else if (child instanceof ProfileSearchCell) {
                ((ProfileSearchCell) child).update(mask);
            } else if (child instanceof RecyclerListView) {
                RecyclerListView innerListView = (RecyclerListView) child;
                int count2 = innerListView.getChildCount();
                for (int b = 0; b < count2; b++) {
                    View child2 = innerListView.getChildAt(b);
                    if (child2 instanceof HintDialogCell) {
                        ((HintDialogCell) child2).update(mask);
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean hasHiddenArchive() {
        return this.listView.getAdapter() == this.dialogsAdapter && this.folderId == 0 && getMessagesController().hasHiddenArchive();
    }

    public void setSearchString(String string) {
        this.searchString = string;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onDialogAnimationFinished() {
        this.dialogRemoveFinished = 0;
        this.dialogInsertFinished = 0;
        this.dialogChangeFinished = 0;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$xDb12bMCf-JETkJZy8xwjURp5Kg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onDialogAnimationFinished$12$DialogsFragment();
            }
        });
    }

    public /* synthetic */ void lambda$onDialogAnimationFinished$12$DialogsFragment() {
        if (this.folderId != 0 && frozenDialogsList.isEmpty()) {
            this.listView.setEmptyView(null);
            this.progressView.setVisibility(4);
        }
        setDialogsListFrozen(false);
        updateDialogIndices();
    }

    private boolean validateSlowModeDialog(long dialogId) {
        int lowerId;
        TLRPC.Chat chat;
        ChatActivityEnterView chatActivityEnterView;
        if ((this.messagesCount <= 1 && ((chatActivityEnterView = this.commentView) == null || chatActivityEnterView.getVisibility() != 0 || TextUtils.isEmpty(this.commentView.getFieldText()))) || (lowerId = (int) dialogId) >= 0 || (chat = getMessagesController().getChat(Integer.valueOf(-lowerId))) == null || ChatObject.hasAdminRights(chat) || !chat.slowmode_enabled) {
            return true;
        }
        AlertsCreator.showSimpleAlert(getCurrentFragment(), LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSendError", R.string.SlowmodeSendError));
        return false;
    }

    public void movePreviewFragment(float dy) {
        this.parentLayout.movePreviewFragment(dy);
    }

    public void finishPreviewFragment() {
        this.parentLayout.finishPreviewFragment();
    }

    public boolean presentFragmentAsPreview(BaseFragment fragment) {
        return this.parentLayout != null && this.parentLayout.presentFragmentAsPreview(fragment);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public void performMenuClick(boolean z, int i, long j, int i2) throws Exception {
        int i3;
        TLRPC.User tL_userEmpty;
        TLRPC.Chat chat;
        int i4;
        int i5;
        String str;
        if (getParentActivity() == null) {
            return;
        }
        if (z) {
            if (i == 0) {
                TLRPC.Dialog dialog = (TLRPC.Dialog) this.dialogsAdapter.getItem(i2);
                getMessagesController().dialogs_dict.get(j);
                View viewFindViewByPosition = this.layoutManager.findViewByPosition(i2);
                if (viewFindViewByPosition instanceof SwipeLayout) {
                    SwipeLayout swipeLayout = (SwipeLayout) viewFindViewByPosition;
                    boolean z2 = dialog.unread_count != 0 || dialog.unread_mark;
                    if (z2) {
                        i5 = R.string.MarkAsUnread;
                        str = "MarkAsUnread";
                    } else {
                        i5 = R.string.MarkAsRead;
                        str = "MarkAsRead";
                    }
                    String string = LocaleController.getString(str, i5);
                    int i6 = !z2 ? R.drawable.msg_markread : R.drawable.msg_markunread;
                    swipeLayout.setTextAtIndex(z, i, string);
                    swipeLayout.setIconAtIndex(z, i, i6);
                    swipeLayout.setbackgroudAtIndex(z, i, Theme.getColor(!z2 ? Theme.key_accentBlue : Theme.key_neutralWeak));
                    swipeLayout.setItemState(2, true);
                }
                if (dialog.unread_count != 0 || dialog.unread_mark) {
                    getMessagesController().markMentionsAsRead(dialog.id);
                    getMessagesController().markDialogAsRead(dialog.id, dialog.top_message, dialog.top_message, dialog.last_message_date, false, 0, true, 0);
                    return;
                } else {
                    getMessagesController().markDialogAsUnread(dialog.id, null, 0L);
                    return;
                }
            }
            if (i == 1) {
                SwipeLayout swipeLayout2 = (SwipeLayout) this.layoutManager.findViewByPosition(i2);
                boolean z3 = false;
                TLRPC.Dialog dialog2 = (TLRPC.Dialog) this.dialogsAdapter.getItem(i2);
                if (!dialog2.pinned) {
                    int i7 = 0;
                    int i8 = 0;
                    int i9 = 0;
                    int i10 = 0;
                    ArrayList<TLRPC.Dialog> dialogs = getMessagesController().getDialogs(this.folderId);
                    int i11 = 0;
                    int size = dialogs.size();
                    while (i11 < size) {
                        TLRPC.Dialog dialog3 = dialogs.get(i11);
                        ArrayList<TLRPC.Dialog> arrayList = dialogs;
                        if (!(dialog3 instanceof TLRPC.TL_dialogFolder)) {
                            int i12 = (int) dialog2.id;
                            if (!dialog3.pinned) {
                                break;
                            } else if (i12 == 0) {
                                i8++;
                            } else {
                                i7++;
                            }
                        }
                        i11++;
                        dialogs = arrayList;
                    }
                    if (((int) dialog2.id) == 0) {
                        i10 = 0 + 1;
                    } else {
                        i9 = 0 + 1;
                    }
                    if (this.folderId != 0) {
                        i4 = getMessagesController().maxFolderPinnedDialogsCount;
                    } else {
                        i4 = getMessagesController().maxPinnedDialogsCount;
                    }
                    if (i10 + i8 > i4 || i9 + i7 > i4) {
                        AlertsCreator.showSimpleAlert(getCurrentFragment(), LocaleController.formatString("PinToTopLimitReached", R.string.PinToTopLimitReached, LocaleController.formatPluralString("Chats", i4)));
                        AndroidUtilities.shakeView(this.pinItem, 2.0f, 0);
                        Vibrator vibrator = (Vibrator) getParentActivity().getSystemService("vibrator");
                        if (vibrator != null) {
                            vibrator.vibrate(200L);
                            return;
                        }
                        return;
                    }
                }
                if (!dialog2.pinned) {
                    if (getMessagesController().pinDialog(dialog2.id, true, null, -1L)) {
                        swipeLayout2.setItemState(2, true);
                        z3 = true;
                    }
                } else if (getMessagesController().pinDialog(dialog2.id, false, null, -1L)) {
                    swipeLayout2.setItemState(2, true);
                    z3 = true;
                }
                getMessagesController().reorderPinnedDialogs(this.folderId, null, 0L);
                if (z3) {
                    this.layoutManager.scrollToPositionWithOffset(hasHiddenArchive() ? 1 : 0, AndroidUtilities.dp(55.0f));
                    return;
                }
                return;
            }
            return;
        }
        int i13 = 3;
        if (i == 0) {
            TLRPC.Dialog dialog4 = (TLRPC.Dialog) this.dialogsAdapter.getItem(i2);
            View viewFindViewByPosition2 = this.layoutManager.findViewByPosition(i2);
            if (!getMessagesController().isDialogMuted(dialog4.id)) {
                NotificationsController.getInstance(UserConfig.selectedAccount).setDialogNotificationsSettings(dialog4.id, 3);
                ((SwipeLayout) viewFindViewByPosition2).setItemState(2, true);
                return;
            }
            getNotificationsController().setDialogNotificationsSettings(dialog4.id, 4);
            if (viewFindViewByPosition2 instanceof SwipeLayout) {
                SwipeLayout swipeLayout3 = (SwipeLayout) viewFindViewByPosition2;
                swipeLayout3.setTextAtIndex(z, i, LocaleController.getString("ChatsMute", R.string.ChatsMute));
                swipeLayout3.setIconAtIndex(z, i, R.drawable.msg_mute);
                swipeLayout3.setItemState(2, true);
                return;
            }
            return;
        }
        if (i == 1) {
            final TLRPC.Dialog dialog5 = (TLRPC.Dialog) this.dialogsAdapter.getItem(i2);
            final int i14 = (int) dialog5.id;
            int i15 = (int) (dialog5.id >> 32);
            if (i14 != 0) {
                if (i14 <= 0) {
                    tL_userEmpty = null;
                    chat = getMessagesController().getChat(Integer.valueOf(-i14));
                } else {
                    tL_userEmpty = getMessagesController().getUser(Integer.valueOf(i14));
                    chat = null;
                }
            } else {
                TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(i15));
                if (encryptedChat != null) {
                    tL_userEmpty = getMessagesController().getUser(Integer.valueOf(encryptedChat.user_id));
                    chat = null;
                } else {
                    tL_userEmpty = new TLRPC.TL_userEmpty();
                    chat = null;
                }
            }
            if (chat == null && tL_userEmpty == null) {
                return;
            }
            boolean z4 = (tL_userEmpty == null || !tL_userEmpty.bot || MessagesController.isSupportUser(tL_userEmpty)) ? false : true;
            final SwipeLayout swipeLayout4 = (SwipeLayout) this.layoutManager.findViewByPosition(i2);
            final BottomDialog bottomDialog = new BottomDialog(getParentActivity());
            bottomDialog.setTitleDivider(false);
            bottomDialog.setDialogTextColor(getParentActivity().getResources().getColor(R.color.color_item_menu_red_f74c31));
            bottomDialog.setCancelButtonColor(getParentActivity().getResources().getColor(R.color.color_text_black_222222));
            bottomDialog.addDialogItem(new BottomDialog.NormalTextItem(0, LocaleController.getString("ClearHistory", R.string.ClearHistory), true));
            bottomDialog.addDialogItem(new BottomDialog.NormalTextItem(1, LocaleController.getString("Delete", R.string.Delete), false));
            final TLRPC.User user = tL_userEmpty;
            final TLRPC.Chat chat2 = chat;
            bottomDialog.setOnItemClickListener(new BottomDialog.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$4xf4mk-KrBk2NVEOPkNTDbr-k3U
                @Override // im.uwrkaxlmjj.ui.dialogs.BottomDialog.OnItemClickListener
                public final void onItemClick(int i16, View view) {
                    this.f$0.lambda$performMenuClick$17$DialogsFragment(chat2, user, i14, dialog5, bottomDialog, i16, view);
                }
            });
            bottomDialog.show();
            bottomDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$UlDAORnXp8AY5LRxJgM7Xw3VSik
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    swipeLayout4.setItemState(2, true);
                }
            });
            return;
        }
        if (i == 2) {
            final ArrayList<Long> arrayList2 = new ArrayList<>();
            arrayList2.add(Long.valueOf(j));
            getMessagesController().addDialogToFolder(arrayList2, this.folderId == 0 ? 1 : 0, -1, null, 0L);
            if (this.folderId == 0) {
                SharedPreferences globalMainSettings = MessagesController.getGlobalMainSettings();
                boolean z5 = globalMainSettings.getBoolean("archivehint_l", false) || SharedConfig.archiveHidden;
                if (!z5) {
                    i3 = 1;
                    globalMainSettings.edit().putBoolean("archivehint_l", true).commit();
                } else {
                    i3 = 1;
                }
                if (z5) {
                    i13 = arrayList2.size() > i3 ? 4 : 2;
                } else if (arrayList2.size() > i3) {
                    i13 = 5;
                }
                getUndoView().showWithAction(0L, i13, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$guwdbheumChb3T32uW7lSDrl3Pg
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        this.f$0.lambda$performMenuClick$19$DialogsFragment(arrayList2);
                    }
                });
            } else if (getMessagesController().getDialogs(this.folderId).isEmpty()) {
                this.listView.setEmptyView(null);
                this.progressView.setVisibility(4);
            }
            ((SwipeLayout) this.layoutManager.findViewByPosition(i2)).setItemState(2, true);
        }
    }

    public /* synthetic */ void lambda$performMenuClick$17$DialogsFragment(final TLRPC.Chat chat, TLRPC.User finalUser, int lower_id, final TLRPC.Dialog dialog, BottomDialog bottomDialog, int id, View v) {
        if (id == 0) {
            AlertsCreator.createClearOrDeleteDialogAlert(getCurrentFragment(), true, chat, finalUser, lower_id == 0, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$STlEIl-kppHFoP_cbTaZLlGbk_4
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                public final void run(boolean z) throws Exception {
                    this.f$0.lambda$null$14$DialogsFragment(chat, dialog, z);
                }
            });
            bottomDialog.dismiss();
        } else if (id == 1) {
            AlertsCreator.createClearOrDeleteDialogAlert(getCurrentFragment(), false, chat, finalUser, lower_id == 0, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$l18nE88OJ8AVTNd-7lBo_48TMFc
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                public final void run(boolean z) {
                    this.f$0.lambda$null$16$DialogsFragment(dialog, chat, z);
                }
            });
            bottomDialog.dismiss();
        }
    }

    public /* synthetic */ void lambda$null$14$DialogsFragment(TLRPC.Chat chat, final TLRPC.Dialog dialog, final boolean param) throws Exception {
        if (ChatObject.isChannel(chat) && (!chat.megagroup || !TextUtils.isEmpty(chat.username))) {
            getMessagesController().deleteDialog(dialog.id, 2, param);
        } else {
            getUndoView().showWithAction(dialog.id, 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$HmAWY1TkOdkfMuu1fZb2sJkMI4c
                @Override // java.lang.Runnable
                public final void run() throws Exception {
                    this.f$0.lambda$null$13$DialogsFragment(dialog, param);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$13$DialogsFragment(TLRPC.Dialog dialog, boolean param) throws Exception {
        getMessagesController().deleteDialog(dialog.id, 1, param);
    }

    public /* synthetic */ void lambda$null$16$DialogsFragment(final TLRPC.Dialog dialog, final TLRPC.Chat chat, final boolean param) {
        if (this.folderId != 0 && getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false).size() == 1) {
            this.progressView.setVisibility(4);
        }
        getUndoView().showWithAction(dialog.id, 1, new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$BV3KpBntJIgWWf4Ehx4zU9mbVmY
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$15$DialogsFragment(chat, dialog, param);
            }
        });
    }

    public /* synthetic */ void lambda$null$15$DialogsFragment(TLRPC.Chat chat, TLRPC.Dialog dialog, boolean param) throws Exception {
        if (chat == null || ChatObject.isNotInChat(chat)) {
            getMessagesController().deleteDialog(dialog.id, 0, param);
        } else {
            TLRPC.User currentUser = getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId()));
            getMessagesController().deleteUserFromChat((int) (-dialog.id), currentUser, null);
        }
        if (AndroidUtilities.isTablet()) {
            getNotificationCenter().postNotificationName(NotificationCenter.closeChats, Long.valueOf(dialog.id));
        }
        MessagesController.getInstance(this.currentAccount).checkIfFolderEmpty(this.folderId);
    }

    public /* synthetic */ void lambda$performMenuClick$19$DialogsFragment(ArrayList copy) throws Exception {
        getMessagesController().addDialogToFolder(copy, this.folderId == 0 ? 0 : 1, -1, null, 0L);
    }

    public void showDeleteOrClearSheet() {
        final BottomDialog bottomDialog = new BottomDialog(getParentActivity());
        bottomDialog.setDialogTextColor(getParentActivity().getResources().getColor(R.color.color_item_menu_red_f74c31));
        bottomDialog.setCancelButtonColor(getParentActivity().getResources().getColor(R.color.color_text_black_222222));
        ArrayList<Long> selectedDialogs = this.dialogsAdapter.getSelectedDialogs();
        int count = selectedDialogs.size();
        bottomDialog.addDialogItem(new BottomDialog.NormalTextItem(0, String.format(LocaleController.getString("DeleteManyDialogs", R.string.DeleteManyDialogs), Integer.valueOf(count)), true));
        bottomDialog.setOnItemClickListener(new BottomDialog.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$_61KQWKbZU51jmNUgPOVp8hs4Hw
            @Override // im.uwrkaxlmjj.ui.dialogs.BottomDialog.OnItemClickListener
            public final void onItemClick(int i, View view) throws Exception {
                this.f$0.lambda$showDeleteOrClearSheet$20$DialogsFragment(bottomDialog, i, view);
            }
        });
        bottomDialog.show();
    }

    public /* synthetic */ void lambda$showDeleteOrClearSheet$20$DialogsFragment(BottomDialog bottomDialog, int id, View v) throws Exception {
        if (id == 0) {
            perfromSelectedDialogsAction(2);
            bottomDialog.dismiss();
        }
    }

    public void perfromSelectedDialogsAction(final int action) throws Exception {
        ArrayList<Long> selectedDialogs;
        int count;
        TLRPC.Chat chat;
        TLRPC.User user;
        int i;
        int undoAction;
        ArrayList<Long> selectedDialogs2;
        int count2;
        if (getParentActivity() == null) {
            return;
        }
        ArrayList<Long> selectedDialogs3 = this.dialogsAdapter.getSelectedDialogs();
        int count3 = selectedDialogs3.size();
        if (count3 > 0) {
            selectedDialogs = selectedDialogs3;
            count = count3;
        } else {
            if (action != 4 || (count2 = (selectedDialogs2 = this.dialogsAdapter.getAllDialogIdsList()).size()) <= 0) {
                return;
            }
            updateCounters(true, false);
            selectedDialogs = selectedDialogs2;
            count = count2;
        }
        if (action == 1) {
            final ArrayList<Long> copy = new ArrayList<>(selectedDialogs);
            getMessagesController().addDialogToFolder(copy, this.folderId == 0 ? 1 : 0, -1, null, 0L);
            toggleEditModel();
            if (this.folderId != 0) {
                ArrayList<TLRPC.Dialog> dialogs = getMessagesController().getDialogs(this.folderId);
                if (dialogs.isEmpty()) {
                    this.listView.setEmptyView(null);
                    this.progressView.setVisibility(4);
                    return;
                }
                return;
            }
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean hintShowed = preferences.getBoolean("archivehint_l", false) || SharedConfig.archiveHidden;
            if (!hintShowed) {
                preferences.edit().putBoolean("archivehint_l", true).commit();
            }
            if (hintShowed) {
                undoAction = copy.size() <= 1 ? 2 : 4;
            } else {
                int undoAction2 = copy.size();
                undoAction = undoAction2 > 1 ? 5 : 3;
            }
            getUndoView().showWithAction(0L, undoAction, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$c4j2AAF8hUHujA8wBjxyDFK-1cI
                @Override // java.lang.Runnable
                public final void run() throws Exception {
                    this.f$0.lambda$perfromSelectedDialogsAction$21$DialogsFragment(copy);
                }
            });
            return;
        }
        for (int a = 0; a < count; a++) {
            final long selectedDialog = selectedDialogs.get(a).longValue();
            TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(selectedDialog);
            if (dialog != null) {
                int lower_id = (int) selectedDialog;
                int high_id = (int) (selectedDialog >> 32);
                if (lower_id != 0) {
                    if (lower_id > 0) {
                        TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(lower_id));
                        chat = null;
                        user = user2;
                    } else {
                        chat = getMessagesController().getChat(Integer.valueOf(-lower_id));
                        user = null;
                    }
                } else {
                    TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
                    if (encryptedChat != null) {
                        TLRPC.User user3 = getMessagesController().getUser(Integer.valueOf(encryptedChat.user_id));
                        chat = null;
                        user = user3;
                    } else {
                        TLRPC.User user4 = new TLRPC.TL_userEmpty();
                        chat = null;
                        user = user4;
                    }
                }
                if (chat != null || user != null) {
                    final boolean isBot = (user == null || !user.bot || MessagesController.isSupportUser(user)) ? false : true;
                    if (action == 4) {
                        if (this.canReadCount != 0) {
                            getMessagesController().markMentionsAsRead(selectedDialog);
                            getMessagesController().markDialogAsRead(selectedDialog, dialog.top_message, dialog.top_message, dialog.last_message_date, false, 0, true, 0);
                        } else {
                            getMessagesController().markDialogAsUnread(selectedDialog, null, 0L);
                        }
                    } else {
                        if (action != 2) {
                            i = 3;
                            if (action == 3) {
                            }
                        } else {
                            i = 3;
                        }
                        if (count != 1) {
                            if (action == 3 && this.canClearCacheCount != 0) {
                                getMessagesController().deleteDialog(selectedDialog, 2, false);
                            } else if (action == 3) {
                                getMessagesController().deleteDialog(selectedDialog, 1, false);
                            } else {
                                if (chat == null) {
                                    getMessagesController().deleteDialog(selectedDialog, 0, false);
                                    if (isBot) {
                                        getMessagesController().blockUser((int) selectedDialog);
                                    }
                                } else if (ChatObject.isNotInChat(chat)) {
                                    getMessagesController().deleteDialog(selectedDialog, 0, false);
                                } else {
                                    TLRPC.User currentUser = getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId()));
                                    getMessagesController().deleteUserFromChat((int) (-selectedDialog), currentUser, null);
                                }
                                if (AndroidUtilities.isTablet()) {
                                    getNotificationCenter().postNotificationName(NotificationCenter.closeChats, Long.valueOf(selectedDialog));
                                }
                            }
                        } else {
                            final TLRPC.Chat chat2 = chat;
                            AlertsCreator.createClearOrDeleteDialogAlert(getCurrentFragment(), action == i, chat, user, lower_id == 0, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$kWG0ryvoiEHAl2IUY2cysDIqwCo
                                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                                public final void run(boolean z) throws Exception {
                                    this.f$0.lambda$perfromSelectedDialogsAction$23$DialogsFragment(action, chat2, selectedDialog, isBot, z);
                                }
                            });
                            return;
                        }
                    }
                }
            }
        }
        toggleEditModel();
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$21$DialogsFragment(ArrayList copy) throws Exception {
        getMessagesController().addDialogToFolder(copy, this.folderId == 0 ? 0 : 1, -1, null, 0L);
    }

    public /* synthetic */ void lambda$perfromSelectedDialogsAction$23$DialogsFragment(final int action, final TLRPC.Chat chat, final long selectedDialog, final boolean isBot, final boolean param) throws Exception {
        toggleEditModel();
        if (action == 3 && ChatObject.isChannel(chat)) {
            if (!chat.megagroup || !TextUtils.isEmpty(chat.username)) {
                getMessagesController().deleteDialog(selectedDialog, 2, param);
                return;
            }
        }
        if (action == 2 && this.folderId != 0 && getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false).size() == 1) {
            this.progressView.setVisibility(4);
        }
        getUndoView().showWithAction(selectedDialog, action == 3 ? 0 : 1, new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DialogsFragment$02r6qtBlJqTFf8uzj-0qwbedrI4
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$22$DialogsFragment(action, selectedDialog, param, chat, isBot);
            }
        });
    }

    public /* synthetic */ void lambda$null$22$DialogsFragment(int action, long selectedDialog, boolean param, TLRPC.Chat chat, boolean isBot) throws Exception {
        if (action == 3) {
            getMessagesController().deleteDialog(selectedDialog, 1, param);
            return;
        }
        if (chat == null) {
            getMessagesController().deleteDialog(selectedDialog, 0, param);
            if (isBot) {
                getMessagesController().blockUser((int) selectedDialog);
            }
        } else if (ChatObject.isNotInChat(chat)) {
            getMessagesController().deleteDialog(selectedDialog, 0, param);
        } else {
            TLRPC.User currentUser = getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId()));
            getMessagesController().deleteUserFromChat((int) (-selectedDialog), currentUser, null);
        }
        if (AndroidUtilities.isTablet()) {
            getNotificationCenter().postNotificationName(NotificationCenter.closeChats, Long.valueOf(selectedDialog));
        }
        MessagesController.getInstance(this.currentAccount).checkIfFolderEmpty(this.folderId);
    }

    private void updateCounters(boolean markAllAsRead, boolean hide) {
        ArrayList<Long> selectedDialogs;
        int canUnarchiveCount;
        ArrayList<Long> selectedDialogs2;
        int count;
        TLRPC.User user;
        int canClearHistoryCount = 0;
        int canDeleteCount = 0;
        int canUnpinCount = 0;
        int canArchiveCount = 0;
        int canUnarchiveCount2 = 0;
        this.canUnmuteCount = 0;
        this.canMuteCount = 0;
        this.canPinCount = 0;
        this.canReadCount = 0;
        this.canClearCacheCount = 0;
        if (hide) {
            return;
        }
        if (!markAllAsRead) {
            selectedDialogs = this.dialogsAdapter.getSelectedDialogs();
        } else {
            selectedDialogs = this.dialogsAdapter.getAllDialogIdsList();
        }
        int count2 = selectedDialogs.size();
        int a = 0;
        while (a < count2) {
            TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(selectedDialogs.get(a).longValue());
            if (dialog == null) {
                selectedDialogs2 = selectedDialogs;
                count = count2;
            } else {
                long selectedDialog = dialog.id;
                boolean pinned = dialog.pinned;
                boolean hasUnread = dialog.unread_count != 0 || dialog.unread_mark;
                if (getMessagesController().isDialogMuted(selectedDialog)) {
                    this.canUnmuteCount++;
                } else {
                    this.canMuteCount++;
                }
                if (hasUnread) {
                    this.canReadCount++;
                }
                if (this.folderId == 1) {
                    canUnarchiveCount = canUnarchiveCount2 + 1;
                } else {
                    int canUnarchiveCount3 = canUnarchiveCount2;
                    if (selectedDialog != getUserConfig().getClientUserId() && selectedDialog != 777000) {
                        if (!getMessagesController().isProxyDialog(selectedDialog, false)) {
                            canArchiveCount++;
                            canUnarchiveCount = canUnarchiveCount3;
                        }
                    }
                    canUnarchiveCount = canUnarchiveCount3;
                }
                int lower_id = (int) selectedDialog;
                int canArchiveCount2 = canArchiveCount;
                int canUnarchiveCount4 = canUnarchiveCount;
                int high_id = (int) (selectedDialog >> 32);
                if (DialogObject.isChannel(dialog)) {
                    TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(-lower_id));
                    selectedDialogs2 = selectedDialogs;
                    count = count2;
                    if (getMessagesController().isProxyDialog(dialog.id, true)) {
                        this.canClearCacheCount++;
                    } else {
                        if (!pinned) {
                            this.canPinCount++;
                        } else {
                            canUnpinCount++;
                        }
                        if (chat == null || !chat.megagroup) {
                            this.canClearCacheCount++;
                            canDeleteCount++;
                        } else {
                            if (!TextUtils.isEmpty(chat.username)) {
                                this.canClearCacheCount++;
                            } else {
                                canClearHistoryCount++;
                            }
                            canDeleteCount++;
                        }
                    }
                    canArchiveCount = canArchiveCount2;
                    canUnarchiveCount2 = canUnarchiveCount4;
                } else {
                    selectedDialogs2 = selectedDialogs;
                    count = count2;
                    boolean isChat = lower_id < 0 && high_id != 1;
                    TLRPC.User user2 = null;
                    if (isChat) {
                        getMessagesController().getChat(Integer.valueOf(-lower_id));
                    }
                    if (lower_id == 0) {
                        TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
                        if (encryptedChat != null) {
                            user = getMessagesController().getUser(Integer.valueOf(encryptedChat.user_id));
                        } else {
                            user = new TLRPC.TL_userEmpty();
                        }
                    } else {
                        if (!isChat && lower_id > 0 && high_id != 1) {
                            user2 = getMessagesController().getUser(Integer.valueOf(lower_id));
                        }
                        user = user2;
                    }
                    if (user == null || !user.bot || !MessagesController.isSupportUser(user)) {
                    }
                    if (!pinned) {
                        this.canPinCount++;
                    } else {
                        canUnpinCount++;
                    }
                    canClearHistoryCount++;
                    canDeleteCount++;
                    canArchiveCount = canArchiveCount2;
                    canUnarchiveCount2 = canUnarchiveCount4;
                }
            }
            a++;
            selectedDialogs = selectedDialogs2;
            count2 = count;
        }
    }

    private int getCanReadCountInAllDialogs() {
        int canReadCount = 0;
        if (this.isEditModel) {
            ArrayList<Long> dialogs = this.dialogsAdapter.getAllDialogIdsList();
            for (int a = 0; a < dialogs.size(); a++) {
                TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(dialogs.get(a).longValue());
                if (dialog != null) {
                    boolean hasUnread = dialog.unread_count != 0 || dialog.unread_mark;
                    if (hasUnread) {
                        canReadCount++;
                    }
                }
            }
        }
        return canReadCount;
    }

    private void hideActionMode(boolean animateCheck) throws Exception {
        this.actionBar.hideActionMode();
        if (this.menuDrawable != null) {
            this.actionBar.setBackButtonContentDescription(LocaleController.getString("AccDescrOpenMenu", R.string.AccDescrOpenMenu));
        }
        this.dialogsAdapter.getSelectedDialogs().clear();
        MenuDrawable menuDrawable = this.menuDrawable;
        if (menuDrawable != null) {
            menuDrawable.setRotation(0.0f, true);
        } else {
            BackDrawable backDrawable = this.backDrawable;
            if (backDrawable != null) {
                backDrawable.setRotation(0.0f, true);
            }
        }
        this.allowMoving = false;
        if (this.movingWas) {
            getMessagesController().reorderPinnedDialogs(this.folderId, null, 0L);
            this.movingWas = false;
        }
        updateCounters(false, true);
        this.dialogsAdapter.onReorderStateChanged(false);
        updateVisibleRows((animateCheck ? 8192 : 0) | 196608);
    }

    private void hideActionPanel() {
        this.dialogsAdapter.getSelectedDialogs().clear();
        updateCounters(false, true);
        this.dialogsAdapter.onReorderStateChanged(false);
    }

    private int getPinnedCount() {
        int pinnedCount = 0;
        ArrayList<TLRPC.Dialog> dialogs = getMessagesController().getDialogs(this.folderId);
        int N = dialogs.size();
        for (int a = 0; a < N; a++) {
            TLRPC.Dialog dialog = dialogs.get(a);
            if (!(dialog instanceof TLRPC.TL_dialogFolder)) {
                if (!dialog.pinned) {
                    break;
                }
                pinnedCount++;
            }
        }
        return pinnedCount;
    }

    private void showOrUpdateActionMode(TLRPC.Dialog dialog, View cell) {
        this.dialogsAdapter.addOrRemoveSelectedDialog(dialog.id, cell);
        updateCounters(false, false);
        FmtConsumDelegate fmtConsumDelegate = this.delegate;
        if (fmtConsumDelegate != null) {
            fmtConsumDelegate.onUpdateState(getCanReadCountInAllDialogs() > 0, this.dialogsAdapter.getSelectedDialogs().size(), this.canReadCount);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void closeSearch() {
        if (AndroidUtilities.isTablet()) {
            MrySearchView mrySearchView = this.searchView;
            if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
                this.searchView.closeSearchField();
            }
            TLObject tLObject = this.searchObject;
            if (tLObject != null) {
                this.dialogsSearchAdapter.putRecentSearch(this.searchDialogId, tLObject);
                this.searchObject = null;
                return;
            }
            return;
        }
        closeSearchView(true);
    }

    public void closeSearchView(boolean anim) {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField(anim);
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public boolean onBackPressed() {
        MrySearchView mrySearchView = this.searchView;
        if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
            return true;
        }
        if (this.isEditModel) {
            toggleEditModel();
            return true;
        }
        return super.onBackPressed();
    }

    public static class ComputerLoginView extends AppCompatImageView {
        private int color;
        private boolean mIsLogin;
        private Paint mPointPaint;
        private RectF mRectF;
        private float mWidth;

        public ComputerLoginView(Context context) {
            super(context);
            Paint paint = new Paint(1);
            this.mPointPaint = paint;
            paint.setStyle(Paint.Style.FILL);
            this.mPointPaint.setStrokeWidth(AndroidUtilities.dp(3.0f));
            this.mWidth = AndroidUtilities.dp(8.0f);
        }

        @Override // android.view.View
        protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            super.onSizeChanged(w, h, oldw, oldh);
            float centerX = w / 2.0f;
            float left = AndroidUtilities.dp(5.0f) + centerX;
            float top = centerX - AndroidUtilities.dp(10.0f);
            float f = this.mWidth;
            this.mRectF = new RectF(left, top, left + f, f + top);
        }

        private void updatePaint() {
            if (Theme.isThemeDefault()) {
                this.color = -11010115;
            } else {
                this.color = Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton);
            }
            this.mPointPaint.setColor(this.color);
        }

        public void updateLoginStatus(boolean isLogin) {
            if (this.mIsLogin == isLogin) {
                return;
            }
            this.mIsLogin = isLogin;
            invalidate();
        }

        @Override // android.widget.ImageView, android.view.View
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            if (this.mIsLogin) {
                updatePaint();
                RectF rectF = this.mRectF;
                float f = this.mWidth;
                canvas.drawRoundRect(rectF, f / 2.0f, f / 2.0f, this.mPointPaint);
            }
        }
    }
}
