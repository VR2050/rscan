package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.PowerManager;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.status.SystemBarTintManager;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ChatActivityEnterView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.PlayingGameDrawable;
import im.uwrkaxlmjj.ui.components.PopupAudioView;
import im.uwrkaxlmjj.ui.components.RecordStatusDrawable;
import im.uwrkaxlmjj.ui.components.RoundStatusDrawable;
import im.uwrkaxlmjj.ui.components.SendingFileDrawable;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.StatusDrawable;
import im.uwrkaxlmjj.ui.components.TypingDotsDrawable;
import im.uwrkaxlmjj.ui.constants.ChatEnterMenuType;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PopupNotificationActivity extends Activity implements NotificationCenter.NotificationCenterDelegate {
    private static final int id_chat_compose_panel = 1000;
    private ActionBar actionBar;
    private FrameLayout avatarContainer;
    private BackupImageView avatarImageView;
    private ViewGroup centerButtonsView;
    private ViewGroup centerView;
    private ChatActivityEnterView chatActivityEnterView;
    private int classGuid;
    private TextView countText;
    private TLRPC.Chat currentChat;
    private TLRPC.User currentUser;
    private boolean isReply;
    private CharSequence lastPrintString;
    private ViewGroup leftButtonsView;
    private ViewGroup leftView;
    private ViewGroup messageContainer;
    private TextView nameTextView;
    private TextView onlineTextView;
    private RelativeLayout popupContainer;
    private ViewGroup rightButtonsView;
    private ViewGroup rightView;
    private ArrayList<ViewGroup> textViews = new ArrayList<>();
    private ArrayList<ViewGroup> imageViews = new ArrayList<>();
    private ArrayList<ViewGroup> audioViews = new ArrayList<>();
    private VelocityTracker velocityTracker = null;
    private StatusDrawable[] statusDrawables = new StatusDrawable[5];
    private int lastResumedAccount = -1;
    private boolean finished = false;
    private MessageObject currentMessageObject = null;
    private int currentMessageNum = 0;
    private PowerManager.WakeLock wakeLock = null;
    private boolean animationInProgress = false;
    private long animationStartTime = 0;
    private float moveStartX = -1.0f;
    private boolean startedMoving = false;
    private Runnable onAnimationEndRunnable = null;
    private ArrayList<MessageObject> popupMessages = new ArrayList<>();

    private class FrameLayoutTouch extends FrameLayout {
        public FrameLayoutTouch(Context context) {
            super(context);
        }

        public FrameLayoutTouch(Context context, AttributeSet attrs) {
            super(context, attrs);
        }

        public FrameLayoutTouch(Context context, AttributeSet attrs, int defStyle) {
            super(context, attrs, defStyle);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            return PopupNotificationActivity.this.checkTransitionAnimation() || ((PopupNotificationActivity) getContext()).onTouchEventMy(ev);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent ev) {
            return PopupNotificationActivity.this.checkTransitionAnimation() || ((PopupNotificationActivity) getContext()).onTouchEventMy(ev);
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            ((PopupNotificationActivity) getContext()).onTouchEventMy(null);
            super.requestDisallowInterceptTouchEvent(disallowIntercept);
        }
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Theme.createChatResources(this, false);
        int resourceId = getResources().getIdentifier("status_bar_height", "dimen", "android");
        if (resourceId > 0) {
            AndroidUtilities.statusBarHeight = getResources().getDimensionPixelSize(resourceId);
        }
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.appDidLogout);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.updateInterfaces);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.messagePlayingDidReset);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.contactsDidLoad);
        }
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.pushMessagesUpdated);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        this.classGuid = ConnectionsManager.generateClassGuid();
        this.statusDrawables[0] = new TypingDotsDrawable();
        this.statusDrawables[1] = new RecordStatusDrawable();
        this.statusDrawables[2] = new SendingFileDrawable();
        this.statusDrawables[3] = new PlayingGameDrawable();
        this.statusDrawables[4] = new RoundStatusDrawable();
        SizeNotifierFrameLayout contentView = new SizeNotifierFrameLayout(this) { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.1
            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int heightSize;
                View.MeasureSpec.getMode(widthMeasureSpec);
                View.MeasureSpec.getMode(heightMeasureSpec);
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize2 = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize2);
                int keyboardSize = getKeyboardHeight();
                if (keyboardSize <= AndroidUtilities.dp(20.0f)) {
                    heightSize = heightSize2 - PopupNotificationActivity.this.chatActivityEnterView.getEmojiPadding();
                } else {
                    heightSize = heightSize2;
                }
                int childCount = getChildCount();
                for (int i = 0; i < childCount; i++) {
                    View child = getChildAt(i);
                    if (child.getVisibility() != 8) {
                        if (!PopupNotificationActivity.this.chatActivityEnterView.isPopupView(child)) {
                            if (PopupNotificationActivity.this.chatActivityEnterView.isRecordCircle(child)) {
                                measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.max(AndroidUtilities.dp(10.0f), AndroidUtilities.dp(2.0f) + heightSize), 1073741824));
                            }
                        } else {
                            child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                        }
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                int childLeft;
                int childTop;
                int count = getChildCount();
                int paddingBottom = getKeyboardHeight() <= AndroidUtilities.dp(20.0f) ? PopupNotificationActivity.this.chatActivityEnterView.getEmojiPadding() : 0;
                for (int i = 0; i < count; i++) {
                    View child = getChildAt(i);
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
                        int i2 = absoluteGravity & 7;
                        if (i2 == 1) {
                            int childLeft2 = r - l;
                            childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                        } else if (i2 == 5) {
                            int childLeft3 = r - width;
                            childLeft = childLeft3 - lp.rightMargin;
                        } else {
                            childLeft = lp.leftMargin;
                        }
                        if (verticalGravity == 16) {
                            int childTop2 = b - paddingBottom;
                            childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                        } else if (verticalGravity != 48 && verticalGravity == 80) {
                            int childTop3 = b - paddingBottom;
                            childTop = ((childTop3 - t) - height) - lp.bottomMargin;
                        } else {
                            childTop = lp.topMargin;
                        }
                        if (!PopupNotificationActivity.this.chatActivityEnterView.isPopupView(child)) {
                            if (PopupNotificationActivity.this.chatActivityEnterView.isRecordCircle(child)) {
                                childTop = ((PopupNotificationActivity.this.popupContainer.getTop() + PopupNotificationActivity.this.popupContainer.getMeasuredHeight()) - child.getMeasuredHeight()) - lp.bottomMargin;
                                childLeft = ((PopupNotificationActivity.this.popupContainer.getLeft() + PopupNotificationActivity.this.popupContainer.getMeasuredWidth()) - child.getMeasuredWidth()) - lp.rightMargin;
                            }
                        } else {
                            int measuredHeight = getMeasuredHeight();
                            if (paddingBottom != 0) {
                                measuredHeight -= paddingBottom;
                            }
                            childTop = measuredHeight;
                        }
                        child.layout(childLeft, childTop, childLeft + width, childTop + height);
                    }
                }
                notifyHeightChanged();
            }
        };
        setContentView(contentView);
        contentView.setBackgroundColor(SystemBarTintManager.DEFAULT_TINT_COLOR);
        RelativeLayout relativeLayout = new RelativeLayout(this);
        contentView.addView(relativeLayout, LayoutHelper.createFrame(-1, -1.0f));
        RelativeLayout relativeLayout2 = new RelativeLayout(this) { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.2
            @Override // android.widget.RelativeLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                int w = PopupNotificationActivity.this.chatActivityEnterView.getMeasuredWidth();
                int h = PopupNotificationActivity.this.chatActivityEnterView.getMeasuredHeight();
                for (int a2 = 0; a2 < getChildCount(); a2++) {
                    View v = getChildAt(a2);
                    if (v.getTag() instanceof String) {
                        v.measure(View.MeasureSpec.makeMeasureSpec(w, 1073741824), View.MeasureSpec.makeMeasureSpec(h - AndroidUtilities.dp(3.0f), 1073741824));
                    }
                }
            }

            @Override // android.widget.RelativeLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                super.onLayout(changed, l, t, r, b);
                for (int a2 = 0; a2 < getChildCount(); a2++) {
                    View v = getChildAt(a2);
                    if (v.getTag() instanceof String) {
                        v.layout(v.getLeft(), PopupNotificationActivity.this.chatActivityEnterView.getTop() + AndroidUtilities.dp(3.0f), v.getRight(), PopupNotificationActivity.this.chatActivityEnterView.getBottom());
                    }
                }
            }
        };
        this.popupContainer = relativeLayout2;
        relativeLayout2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        relativeLayout.addView(this.popupContainer, LayoutHelper.createRelative(-1, PsExtractor.VIDEO_STREAM_MASK, 12, 0, 12, 0, 13));
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onDestroy();
        }
        ChatActivityEnterView chatActivityEnterView2 = new ChatActivityEnterView(this, contentView, null, false);
        this.chatActivityEnterView = chatActivityEnterView2;
        chatActivityEnterView2.setId(1000);
        this.popupContainer.addView(this.chatActivityEnterView, LayoutHelper.createRelative(-1, -2, 12));
        this.chatActivityEnterView.setDelegate(new ChatActivityEnterView.ChatActivityEnterViewDelegate() { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.3
            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public /* synthetic */ boolean hasScheduledMessages() {
                return ChatActivityEnterView.ChatActivityEnterViewDelegate.CC.$default$hasScheduledMessages(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public /* synthetic */ void openScheduledMessages() {
                ChatActivityEnterView.ChatActivityEnterViewDelegate.CC.$default$openScheduledMessages(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public /* synthetic */ void scrollToSendingMessage() {
                ChatActivityEnterView.ChatActivityEnterViewDelegate.CC.$default$scrollToSendingMessage(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onMessageSend(CharSequence message, boolean notify, int scheduleDate) {
                if (PopupNotificationActivity.this.currentMessageObject != null) {
                    if (PopupNotificationActivity.this.currentMessageNum >= 0 && PopupNotificationActivity.this.currentMessageNum < PopupNotificationActivity.this.popupMessages.size()) {
                        PopupNotificationActivity.this.popupMessages.remove(PopupNotificationActivity.this.currentMessageNum);
                    }
                    MessagesController.getInstance(PopupNotificationActivity.this.currentMessageObject.currentAccount).markDialogAsRead(PopupNotificationActivity.this.currentMessageObject.getDialogId(), PopupNotificationActivity.this.currentMessageObject.getId(), Math.max(0, PopupNotificationActivity.this.currentMessageObject.getId()), PopupNotificationActivity.this.currentMessageObject.messageOwner.date, true, 0, true, 0);
                    PopupNotificationActivity.this.currentMessageObject = null;
                    PopupNotificationActivity.this.getNewMessage();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onTextChanged(CharSequence text, boolean big) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onTextSelectionChanged(int start, int end) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onTextSpansChanged(CharSequence text) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onStickersExpandedChange() {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onSwitchRecordMode(boolean video) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onPreAudioVideoRecord() {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onMessageEditEnd(boolean loading) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needSendTyping() {
                if (PopupNotificationActivity.this.currentMessageObject != null) {
                    MessagesController.getInstance(PopupNotificationActivity.this.currentMessageObject.currentAccount).sendTyping(PopupNotificationActivity.this.currentMessageObject.getDialogId(), 0, PopupNotificationActivity.this.classGuid);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onAttachButtonHidden() {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onAttachButtonShow() {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onWindowSizeChanged(int size) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onStickersTab(boolean opened) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void didPressedAttachButton(int position, ChatEnterMenuType menuType) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needStartRecordVideo(int state, boolean notify, int scheduleDate) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needStartRecordAudio(int state) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needChangeVideoPreviewState(int state, float seekProgress) {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needShowMediaBanHint() {
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onUpdateSlowModeButton(View button, boolean show, CharSequence time) {
            }
        });
        FrameLayoutTouch frameLayoutTouch = new FrameLayoutTouch(this);
        this.messageContainer = frameLayoutTouch;
        this.popupContainer.addView(frameLayoutTouch, 0);
        ActionBar actionBar = new ActionBar(this);
        this.actionBar = actionBar;
        actionBar.setOccupyStatusBar(false);
        this.actionBar.setBackButtonImage(R.drawable.ic_close_white);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2), false);
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_actionBarDefault));
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultSelector), false);
        this.popupContainer.addView(this.actionBar);
        ViewGroup.LayoutParams layoutParams = this.actionBar.getLayoutParams();
        layoutParams.width = -1;
        this.actionBar.setLayoutParams(layoutParams);
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem view = menu.addItemWithWidth(2, 0, AndroidUtilities.dp(56.0f));
        TextView textView = new TextView(this);
        this.countText = textView;
        textView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubtitle));
        this.countText.setTextSize(1, 14.0f);
        this.countText.setGravity(17);
        view.addView(this.countText, LayoutHelper.createFrame(56, -1.0f));
        FrameLayout frameLayout = new FrameLayout(this);
        this.avatarContainer = frameLayout;
        frameLayout.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
        this.actionBar.addView(this.avatarContainer);
        FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.avatarContainer.getLayoutParams();
        layoutParams2.height = -2;
        layoutParams2.width = -2;
        layoutParams2.rightMargin = AndroidUtilities.dp(48.0f);
        layoutParams2.leftMargin = AndroidUtilities.dp(50.0f);
        layoutParams2.gravity = 51;
        this.avatarContainer.setLayoutParams(layoutParams2);
        BackupImageView backupImageView = new BackupImageView(this);
        this.avatarImageView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(21.0f));
        this.avatarContainer.addView(this.avatarImageView);
        FrameLayout.LayoutParams layoutParams22 = (FrameLayout.LayoutParams) this.avatarImageView.getLayoutParams();
        layoutParams22.width = AndroidUtilities.dp(37.0f);
        layoutParams22.height = AndroidUtilities.dp(37.0f);
        layoutParams22.topMargin = AndroidUtilities.dp(3.0f);
        layoutParams22.bottomMargin = AndroidUtilities.dp(3.0f);
        this.avatarImageView.setLayoutParams(layoutParams22);
        TextView textView2 = new TextView(this);
        this.nameTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        this.nameTextView.setTextSize(1, 16.0f);
        this.nameTextView.setLines(1);
        this.nameTextView.setMaxLines(1);
        this.nameTextView.setSingleLine(true);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.nameTextView.setGravity(3);
        this.nameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.avatarContainer.addView(this.nameTextView);
        FrameLayout.LayoutParams layoutParams23 = (FrameLayout.LayoutParams) this.nameTextView.getLayoutParams();
        layoutParams23.width = -2;
        layoutParams23.height = -2;
        layoutParams23.leftMargin = AndroidUtilities.dp(47.0f);
        layoutParams23.topMargin = AndroidUtilities.dp(5.0f);
        layoutParams23.bottomMargin = AndroidUtilities.dp(22.0f);
        layoutParams23.gravity = 80;
        this.nameTextView.setLayoutParams(layoutParams23);
        TextView textView3 = new TextView(this);
        this.onlineTextView = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubtitle));
        this.onlineTextView.setTextSize(1, 14.0f);
        this.onlineTextView.setLines(1);
        this.onlineTextView.setMaxLines(1);
        this.onlineTextView.setSingleLine(true);
        this.onlineTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.onlineTextView.setGravity(3);
        this.avatarContainer.addView(this.onlineTextView);
        FrameLayout.LayoutParams layoutParams24 = (FrameLayout.LayoutParams) this.onlineTextView.getLayoutParams();
        layoutParams24.width = -2;
        layoutParams24.height = -2;
        layoutParams24.leftMargin = AndroidUtilities.dp(47.0f);
        layoutParams24.bottomMargin = AndroidUtilities.dp(3.0f);
        layoutParams24.gravity = 80;
        this.onlineTextView.setLayoutParams(layoutParams24);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.4
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PopupNotificationActivity.this.onFinish();
                    PopupNotificationActivity.this.finish();
                } else if (id == 1) {
                    PopupNotificationActivity.this.openCurrentMessage();
                } else if (id == 2) {
                    PopupNotificationActivity.this.switchToNextMessage();
                }
            }
        });
        PowerManager pm = (PowerManager) ApplicationLoader.applicationContext.getSystemService("power");
        PowerManager.WakeLock wakeLockNewWakeLock = pm.newWakeLock(268435462, "screen");
        this.wakeLock = wakeLockNewWakeLock;
        wakeLockNewWakeLock.setReferenceCounted(false);
        handleIntent(getIntent());
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        AndroidUtilities.checkDisplaySize(this, newConfig);
        fixLayout();
    }

    @Override // android.app.Activity
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != 3 || grantResults[0] == 0) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("PermissionNoAudio", R.string.PermissionNoAudio));
        builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PopupNotificationActivity$e_TmW6YtZlVT1ekXi5afLAnZX_A
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$onRequestPermissionsResult$0$PopupNotificationActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.show();
    }

    public /* synthetic */ void lambda$onRequestPermissionsResult$0$PopupNotificationActivity(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void switchToNextMessage() {
        if (this.popupMessages.size() > 1) {
            if (this.currentMessageNum < this.popupMessages.size() - 1) {
                this.currentMessageNum++;
            } else {
                this.currentMessageNum = 0;
            }
            this.currentMessageObject = this.popupMessages.get(this.currentMessageNum);
            updateInterfaceForCurrentMessage(2);
            this.countText.setText(String.format("%d/%d", Integer.valueOf(this.currentMessageNum + 1), Integer.valueOf(this.popupMessages.size())));
        }
    }

    private void switchToPreviousMessage() {
        if (this.popupMessages.size() > 1) {
            int i = this.currentMessageNum;
            if (i > 0) {
                this.currentMessageNum = i - 1;
            } else {
                this.currentMessageNum = this.popupMessages.size() - 1;
            }
            this.currentMessageObject = this.popupMessages.get(this.currentMessageNum);
            updateInterfaceForCurrentMessage(1);
            this.countText.setText(String.format("%d/%d", Integer.valueOf(this.currentMessageNum + 1), Integer.valueOf(this.popupMessages.size())));
        }
    }

    public boolean checkTransitionAnimation() {
        if (this.animationInProgress && this.animationStartTime < System.currentTimeMillis() - 400) {
            this.animationInProgress = false;
            Runnable runnable = this.onAnimationEndRunnable;
            if (runnable != null) {
                runnable.run();
                this.onAnimationEndRunnable = null;
            }
        }
        return this.animationInProgress;
    }

    public boolean onTouchEventMy(MotionEvent motionEvent) {
        if (checkTransitionAnimation()) {
            return false;
        }
        if (motionEvent != null && motionEvent.getAction() == 0) {
            this.moveStartX = motionEvent.getX();
        } else if (motionEvent != null && motionEvent.getAction() == 2) {
            float x = motionEvent.getX();
            float f = this.moveStartX;
            int diff = (int) (x - f);
            if (f != -1.0f && !this.startedMoving && Math.abs(diff) > AndroidUtilities.dp(10.0f)) {
                this.startedMoving = true;
                this.moveStartX = x;
                AndroidUtilities.lockOrientation(this);
                diff = 0;
                VelocityTracker velocityTracker = this.velocityTracker;
                if (velocityTracker == null) {
                    this.velocityTracker = VelocityTracker.obtain();
                } else {
                    velocityTracker.clear();
                }
            }
            if (this.startedMoving) {
                if (this.leftView == null && diff > 0) {
                    diff = 0;
                }
                if (this.rightView == null && diff < 0) {
                    diff = 0;
                }
                VelocityTracker velocityTracker2 = this.velocityTracker;
                if (velocityTracker2 != null) {
                    velocityTracker2.addMovement(motionEvent);
                }
                applyViewsLayoutParams(diff);
            }
        } else if (motionEvent == null || motionEvent.getAction() == 1 || motionEvent.getAction() == 3) {
            if (motionEvent != null && this.startedMoving) {
                int diff2 = (int) (motionEvent.getX() - this.moveStartX);
                int width = AndroidUtilities.displaySize.x - AndroidUtilities.dp(24.0f);
                float moveDiff = 0.0f;
                int forceMove = 0;
                View otherView = null;
                View otherButtonsView = null;
                VelocityTracker velocityTracker3 = this.velocityTracker;
                if (velocityTracker3 != null) {
                    velocityTracker3.computeCurrentVelocity(1000);
                    if (this.velocityTracker.getXVelocity() >= 3500.0f) {
                        forceMove = 1;
                    } else if (this.velocityTracker.getXVelocity() <= -3500.0f) {
                        forceMove = 2;
                    }
                }
                if ((forceMove == 1 || diff2 > width / 3) && this.leftView != null) {
                    moveDiff = width - this.centerView.getTranslationX();
                    otherView = this.leftView;
                    otherButtonsView = this.leftButtonsView;
                    this.onAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PopupNotificationActivity$ZOP_ku3AVxrarv1F4AjruN9cgt4
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onTouchEventMy$1$PopupNotificationActivity();
                        }
                    };
                } else if ((forceMove == 2 || diff2 < (-width) / 3) && this.rightView != null) {
                    moveDiff = (-width) - this.centerView.getTranslationX();
                    otherView = this.rightView;
                    otherButtonsView = this.rightButtonsView;
                    this.onAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PopupNotificationActivity$4K0auzJKeorDswFnVNCKusI4wD0
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onTouchEventMy$2$PopupNotificationActivity();
                        }
                    };
                } else if (this.centerView.getTranslationX() != 0.0f) {
                    moveDiff = -this.centerView.getTranslationX();
                    otherView = diff2 > 0 ? this.leftView : this.rightView;
                    otherButtonsView = diff2 > 0 ? this.leftButtonsView : this.rightButtonsView;
                    this.onAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PopupNotificationActivity$_NCkyvHYkn-cH1hRYb8VN249yKg
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onTouchEventMy$3$PopupNotificationActivity();
                        }
                    };
                }
                if (moveDiff != 0.0f) {
                    int time = (int) (Math.abs(moveDiff / width) * 200.0f);
                    ArrayList<Animator> animators = new ArrayList<>();
                    ViewGroup viewGroup = this.centerView;
                    animators.add(ObjectAnimator.ofFloat(viewGroup, "translationX", viewGroup.getTranslationX() + moveDiff));
                    ViewGroup viewGroup2 = this.centerButtonsView;
                    if (viewGroup2 != null) {
                        animators.add(ObjectAnimator.ofFloat(viewGroup2, "translationX", viewGroup2.getTranslationX() + moveDiff));
                    }
                    if (otherView != null) {
                        animators.add(ObjectAnimator.ofFloat(otherView, "translationX", otherView.getTranslationX() + moveDiff));
                    }
                    if (otherButtonsView != null) {
                        animators.add(ObjectAnimator.ofFloat(otherButtonsView, "translationX", otherButtonsView.getTranslationX() + moveDiff));
                    }
                    AnimatorSet animatorSet = new AnimatorSet();
                    animatorSet.playTogether(animators);
                    animatorSet.setDuration(time);
                    animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.5
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (PopupNotificationActivity.this.onAnimationEndRunnable != null) {
                                PopupNotificationActivity.this.onAnimationEndRunnable.run();
                                PopupNotificationActivity.this.onAnimationEndRunnable = null;
                            }
                        }
                    });
                    animatorSet.start();
                    this.animationInProgress = true;
                    this.animationStartTime = System.currentTimeMillis();
                }
            } else {
                applyViewsLayoutParams(0);
            }
            VelocityTracker velocityTracker4 = this.velocityTracker;
            if (velocityTracker4 != null) {
                velocityTracker4.recycle();
                this.velocityTracker = null;
            }
            this.startedMoving = false;
            this.moveStartX = -1.0f;
        }
        return this.startedMoving;
    }

    public /* synthetic */ void lambda$onTouchEventMy$1$PopupNotificationActivity() {
        this.animationInProgress = false;
        switchToPreviousMessage();
        AndroidUtilities.unlockOrientation(this);
    }

    public /* synthetic */ void lambda$onTouchEventMy$2$PopupNotificationActivity() {
        this.animationInProgress = false;
        switchToNextMessage();
        AndroidUtilities.unlockOrientation(this);
    }

    public /* synthetic */ void lambda$onTouchEventMy$3$PopupNotificationActivity() {
        this.animationInProgress = false;
        applyViewsLayoutParams(0);
        AndroidUtilities.unlockOrientation(this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void applyViewsLayoutParams(int xOffset) {
        int widht = AndroidUtilities.displaySize.x - AndroidUtilities.dp(24.0f);
        ViewGroup viewGroup = this.leftView;
        if (viewGroup != null) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) viewGroup.getLayoutParams();
            if (layoutParams.width != widht) {
                layoutParams.width = widht;
                this.leftView.setLayoutParams(layoutParams);
            }
            this.leftView.setTranslationX((-widht) + xOffset);
        }
        ViewGroup viewGroup2 = this.leftButtonsView;
        if (viewGroup2 != null) {
            viewGroup2.setTranslationX((-widht) + xOffset);
        }
        ViewGroup viewGroup3 = this.centerView;
        if (viewGroup3 != null) {
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) viewGroup3.getLayoutParams();
            if (layoutParams2.width != widht) {
                layoutParams2.width = widht;
                this.centerView.setLayoutParams(layoutParams2);
            }
            this.centerView.setTranslationX(xOffset);
        }
        ViewGroup viewGroup4 = this.centerButtonsView;
        if (viewGroup4 != null) {
            viewGroup4.setTranslationX(xOffset);
        }
        ViewGroup viewGroup5 = this.rightView;
        if (viewGroup5 != null) {
            FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) viewGroup5.getLayoutParams();
            if (layoutParams3.width != widht) {
                layoutParams3.width = widht;
                this.rightView.setLayoutParams(layoutParams3);
            }
            this.rightView.setTranslationX(widht + xOffset);
        }
        ViewGroup viewGroup6 = this.rightButtonsView;
        if (viewGroup6 != null) {
            viewGroup6.setTranslationX(widht + xOffset);
        }
        this.messageContainer.invalidate();
    }

    private LinearLayout getButtonsViewForMessage(int num, boolean applyOffset) {
        TLRPC.ReplyMarkup markup;
        int num2 = num;
        if (this.popupMessages.size() == 1 && (num2 < 0 || num2 >= this.popupMessages.size())) {
            return null;
        }
        if (num2 == -1) {
            num2 = this.popupMessages.size() - 1;
        } else if (num2 == this.popupMessages.size()) {
            num2 = 0;
        }
        LinearLayout view = null;
        final MessageObject messageObject = this.popupMessages.get(num2);
        int buttonsCount = 0;
        TLRPC.ReplyMarkup markup2 = messageObject.messageOwner.reply_markup;
        if (messageObject.getDialogId() == 777000 && markup2 != null) {
            ArrayList<TLRPC.TL_keyboardButtonRow> rows = markup2.rows;
            int size = rows.size();
            for (int a = 0; a < size; a++) {
                TLRPC.TL_keyboardButtonRow row = rows.get(a);
                int size2 = row.buttons.size();
                for (int b = 0; b < size2; b++) {
                    if (row.buttons.get(b) instanceof TLRPC.TL_keyboardButtonCallback) {
                        buttonsCount++;
                    }
                }
            }
        }
        final int account = messageObject.currentAccount;
        if (buttonsCount > 0) {
            ArrayList<TLRPC.TL_keyboardButtonRow> rows2 = markup2.rows;
            int size3 = rows2.size();
            for (int a2 = 0; a2 < size3; a2++) {
                TLRPC.TL_keyboardButtonRow row2 = rows2.get(a2);
                int b2 = 0;
                int size22 = row2.buttons.size();
                while (b2 < size22) {
                    TLRPC.KeyboardButton button = row2.buttons.get(b2);
                    if (button instanceof TLRPC.TL_keyboardButtonCallback) {
                        if (view == null) {
                            view = new LinearLayout(this);
                            view.setOrientation(0);
                            view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                            view.setWeightSum(100.0f);
                            view.setTag("b");
                            view.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PopupNotificationActivity$YyhefEk2GI5pTsx5JyOWZbE4kJo
                                @Override // android.view.View.OnTouchListener
                                public final boolean onTouch(View view2, MotionEvent motionEvent) {
                                    return PopupNotificationActivity.lambda$getButtonsViewForMessage$4(view2, motionEvent);
                                }
                            });
                        }
                        TextView textView = new TextView(this);
                        markup = markup2;
                        textView.setTextSize(1, 16.0f);
                        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
                        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                        textView.setText(button.text.toUpperCase());
                        textView.setTag(button);
                        textView.setGravity(17);
                        textView.setBackgroundDrawable(Theme.getSelectorDrawable(true));
                        view.addView(textView, LayoutHelper.createLinear(-1, -1, 100.0f / buttonsCount));
                        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PopupNotificationActivity$X_4TOHFfNdBup24Nfx2DUx8IA_0
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view2) {
                                PopupNotificationActivity.lambda$getButtonsViewForMessage$5(account, messageObject, view2);
                            }
                        });
                    } else {
                        markup = markup2;
                    }
                    b2++;
                    markup2 = markup;
                }
            }
        }
        if (view != null) {
            int widht = AndroidUtilities.displaySize.x - AndroidUtilities.dp(24.0f);
            RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-1, -2);
            layoutParams.addRule(12);
            if (applyOffset) {
                int i = this.currentMessageNum;
                if (num2 == i) {
                    view.setTranslationX(0.0f);
                } else if (num2 == i - 1) {
                    view.setTranslationX(-widht);
                } else if (num2 == i + 1) {
                    view.setTranslationX(widht);
                }
            }
            this.popupContainer.addView(view, layoutParams);
        }
        return view;
    }

    static /* synthetic */ boolean lambda$getButtonsViewForMessage$4(View v, MotionEvent event) {
        return true;
    }

    static /* synthetic */ void lambda$getButtonsViewForMessage$5(int account, MessageObject messageObject, View v) {
        TLRPC.KeyboardButton button1 = (TLRPC.KeyboardButton) v.getTag();
        if (button1 != null) {
            SendMessagesHelper.getInstance(account).sendNotificationCallback(messageObject.getDialogId(), messageObject.getId(), button1.data);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x012c  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0363  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x036e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private android.view.ViewGroup getViewForMessage(int r21, boolean r22) {
        /*
            Method dump skipped, instruction units count: 938
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PopupNotificationActivity.getViewForMessage(int, boolean):android.view.ViewGroup");
    }

    public /* synthetic */ void lambda$getViewForMessage$6$PopupNotificationActivity(View v) {
        openCurrentMessage();
    }

    public /* synthetic */ void lambda$getViewForMessage$7$PopupNotificationActivity(View v) {
        openCurrentMessage();
    }

    public /* synthetic */ void lambda$getViewForMessage$8$PopupNotificationActivity(View v) {
        openCurrentMessage();
    }

    private void reuseButtonsView(ViewGroup view) {
        if (view == null) {
            return;
        }
        this.popupContainer.removeView(view);
    }

    private void reuseView(ViewGroup view) {
        if (view == null) {
            return;
        }
        int tag = ((Integer) view.getTag()).intValue();
        view.setVisibility(8);
        if (tag == 1) {
            this.textViews.add(view);
        } else if (tag == 2) {
            this.imageViews.add(view);
        } else if (tag == 3) {
            this.audioViews.add(view);
        }
    }

    private void prepareLayouts(int move) {
        int widht = AndroidUtilities.displaySize.x - AndroidUtilities.dp(24.0f);
        if (move == 0) {
            reuseView(this.centerView);
            reuseView(this.leftView);
            reuseView(this.rightView);
            reuseButtonsView(this.centerButtonsView);
            reuseButtonsView(this.leftButtonsView);
            reuseButtonsView(this.rightButtonsView);
            int a = this.currentMessageNum - 1;
            while (true) {
                int i = this.currentMessageNum;
                if (a < i + 2) {
                    if (a == i - 1) {
                        this.leftView = getViewForMessage(a, true);
                        this.leftButtonsView = getButtonsViewForMessage(a, true);
                    } else if (a == i) {
                        this.centerView = getViewForMessage(a, true);
                        this.centerButtonsView = getButtonsViewForMessage(a, true);
                    } else if (a == i + 1) {
                        this.rightView = getViewForMessage(a, true);
                        this.rightButtonsView = getButtonsViewForMessage(a, true);
                    }
                    a++;
                } else {
                    return;
                }
            }
        } else {
            if (move == 1) {
                reuseView(this.rightView);
                reuseButtonsView(this.rightButtonsView);
                this.rightView = this.centerView;
                this.centerView = this.leftView;
                this.leftView = getViewForMessage(this.currentMessageNum - 1, true);
                this.rightButtonsView = this.centerButtonsView;
                this.centerButtonsView = this.leftButtonsView;
                this.leftButtonsView = getButtonsViewForMessage(this.currentMessageNum - 1, true);
                return;
            }
            if (move == 2) {
                reuseView(this.leftView);
                reuseButtonsView(this.leftButtonsView);
                this.leftView = this.centerView;
                this.centerView = this.rightView;
                this.rightView = getViewForMessage(this.currentMessageNum + 1, true);
                this.leftButtonsView = this.centerButtonsView;
                this.centerButtonsView = this.rightButtonsView;
                this.rightButtonsView = getButtonsViewForMessage(this.currentMessageNum + 1, true);
                return;
            }
            if (move == 3) {
                ViewGroup viewGroup = this.rightView;
                if (viewGroup != null) {
                    float offset = viewGroup.getTranslationX();
                    reuseView(this.rightView);
                    ViewGroup viewForMessage = getViewForMessage(this.currentMessageNum + 1, false);
                    this.rightView = viewForMessage;
                    if (viewForMessage != null) {
                        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) viewForMessage.getLayoutParams();
                        layoutParams.width = widht;
                        this.rightView.setLayoutParams(layoutParams);
                        this.rightView.setTranslationX(offset);
                        this.rightView.invalidate();
                    }
                }
                ViewGroup viewGroup2 = this.rightButtonsView;
                if (viewGroup2 != null) {
                    float offset2 = viewGroup2.getTranslationX();
                    reuseButtonsView(this.rightButtonsView);
                    LinearLayout buttonsViewForMessage = getButtonsViewForMessage(this.currentMessageNum + 1, false);
                    this.rightButtonsView = buttonsViewForMessage;
                    if (buttonsViewForMessage != null) {
                        buttonsViewForMessage.setTranslationX(offset2);
                        return;
                    }
                    return;
                }
                return;
            }
            if (move == 4) {
                ViewGroup viewGroup3 = this.leftView;
                if (viewGroup3 != null) {
                    float offset3 = viewGroup3.getTranslationX();
                    reuseView(this.leftView);
                    ViewGroup viewForMessage2 = getViewForMessage(0, false);
                    this.leftView = viewForMessage2;
                    if (viewForMessage2 != null) {
                        FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) viewForMessage2.getLayoutParams();
                        layoutParams2.width = widht;
                        this.leftView.setLayoutParams(layoutParams2);
                        this.leftView.setTranslationX(offset3);
                        this.leftView.invalidate();
                    }
                }
                ViewGroup viewGroup4 = this.leftButtonsView;
                if (viewGroup4 != null) {
                    float offset4 = viewGroup4.getTranslationX();
                    reuseButtonsView(this.leftButtonsView);
                    LinearLayout buttonsViewForMessage2 = getButtonsViewForMessage(0, false);
                    this.leftButtonsView = buttonsViewForMessage2;
                    if (buttonsViewForMessage2 != null) {
                        buttonsViewForMessage2.setTranslationX(offset4);
                    }
                }
            }
        }
    }

    private void fixLayout() {
        FrameLayout frameLayout = this.avatarContainer;
        if (frameLayout != null) {
            frameLayout.getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.6
                @Override // android.view.ViewTreeObserver.OnPreDrawListener
                public boolean onPreDraw() {
                    if (PopupNotificationActivity.this.avatarContainer != null) {
                        PopupNotificationActivity.this.avatarContainer.getViewTreeObserver().removeOnPreDrawListener(this);
                    }
                    int padding = (ActionBar.getCurrentActionBarHeight() - AndroidUtilities.dp(48.0f)) / 2;
                    PopupNotificationActivity.this.avatarContainer.setPadding(PopupNotificationActivity.this.avatarContainer.getPaddingLeft(), padding, PopupNotificationActivity.this.avatarContainer.getPaddingRight(), padding);
                    return true;
                }
            });
        }
        ViewGroup viewGroup = this.messageContainer;
        if (viewGroup != null) {
            viewGroup.getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.PopupNotificationActivity.7
                @Override // android.view.ViewTreeObserver.OnPreDrawListener
                public boolean onPreDraw() {
                    PopupNotificationActivity.this.messageContainer.getViewTreeObserver().removeOnPreDrawListener(this);
                    if (!PopupNotificationActivity.this.checkTransitionAnimation() && !PopupNotificationActivity.this.startedMoving) {
                        ViewGroup.MarginLayoutParams layoutParams = (ViewGroup.MarginLayoutParams) PopupNotificationActivity.this.messageContainer.getLayoutParams();
                        layoutParams.topMargin = ActionBar.getCurrentActionBarHeight();
                        layoutParams.bottomMargin = AndroidUtilities.dp(48.0f);
                        layoutParams.width = -1;
                        layoutParams.height = -1;
                        PopupNotificationActivity.this.messageContainer.setLayoutParams(layoutParams);
                        PopupNotificationActivity.this.applyViewsLayoutParams(0);
                        return true;
                    }
                    return true;
                }
            });
        }
    }

    private void handleIntent(Intent intent) {
        this.isReply = intent != null && intent.getBooleanExtra("force", false);
        this.popupMessages.clear();
        if (this.isReply) {
            int account = UserConfig.selectedAccount;
            if (intent != null) {
                account = intent.getIntExtra("currentAccount", account);
            }
            this.popupMessages.addAll(NotificationsController.getInstance(account).popupReplyMessages);
        } else {
            for (int a = 0; a < 3; a++) {
                if (UserConfig.getInstance(a).isClientActivated()) {
                    this.popupMessages.addAll(NotificationsController.getInstance(a).popupMessages);
                }
            }
        }
        KeyguardManager km = (KeyguardManager) getSystemService("keyguard");
        if (km.inKeyguardRestrictedInputMode() || !ApplicationLoader.isScreenOn) {
            getWindow().addFlags(2623490);
        } else {
            getWindow().addFlags(2623488);
            getWindow().clearFlags(2);
        }
        if (this.currentMessageObject == null) {
            this.currentMessageNum = 0;
        }
        getNewMessage();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getNewMessage() {
        if (this.popupMessages.isEmpty()) {
            onFinish();
            finish();
            return;
        }
        boolean found = false;
        if ((this.currentMessageNum != 0 || this.chatActivityEnterView.hasText() || this.startedMoving) && this.currentMessageObject != null) {
            int a = 0;
            int size = this.popupMessages.size();
            while (true) {
                if (a >= size) {
                    break;
                }
                MessageObject messageObject = this.popupMessages.get(a);
                if (messageObject.currentAccount != this.currentMessageObject.currentAccount || messageObject.getDialogId() != this.currentMessageObject.getDialogId() || messageObject.getId() != this.currentMessageObject.getId()) {
                    a++;
                } else {
                    this.currentMessageNum = a;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            this.currentMessageNum = 0;
            this.currentMessageObject = this.popupMessages.get(0);
            updateInterfaceForCurrentMessage(0);
        } else if (this.startedMoving) {
            if (this.currentMessageNum == this.popupMessages.size() - 1) {
                prepareLayouts(3);
            } else if (this.currentMessageNum == 1) {
                prepareLayouts(4);
            }
        }
        this.countText.setText(String.format("%d/%d", Integer.valueOf(this.currentMessageNum + 1), Integer.valueOf(this.popupMessages.size())));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openCurrentMessage() {
        if (this.currentMessageObject == null) {
            return;
        }
        Intent intent = new Intent(ApplicationLoader.applicationContext, (Class<?>) LaunchActivity.class);
        long dialog_id = this.currentMessageObject.getDialogId();
        if (((int) dialog_id) != 0) {
            int lower_id = (int) dialog_id;
            if (lower_id < 0) {
                intent.putExtra("chatId", -lower_id);
            } else {
                intent.putExtra("userId", lower_id);
            }
        } else {
            intent.putExtra("encId", (int) (dialog_id >> 32));
        }
        intent.putExtra("currentAccount", this.currentMessageObject.currentAccount);
        intent.setAction("com.tmessages.openchat" + Math.random() + Integer.MAX_VALUE);
        intent.setFlags(32768);
        startActivity(intent);
        onFinish();
        finish();
    }

    private void updateInterfaceForCurrentMessage(int move) {
        if (this.actionBar == null) {
            return;
        }
        if (this.lastResumedAccount != this.currentMessageObject.currentAccount) {
            int i = this.lastResumedAccount;
            if (i >= 0) {
                ConnectionsManager.getInstance(i).setAppPaused(true, false);
            }
            int i2 = this.currentMessageObject.currentAccount;
            this.lastResumedAccount = i2;
            ConnectionsManager.getInstance(i2).setAppPaused(false, false);
        }
        this.currentChat = null;
        this.currentUser = null;
        long dialog_id = this.currentMessageObject.getDialogId();
        this.chatActivityEnterView.setDialogId(dialog_id, this.currentMessageObject.currentAccount);
        if (((int) dialog_id) != 0) {
            int lower_id = (int) dialog_id;
            if (lower_id > 0) {
                this.currentUser = MessagesController.getInstance(this.currentMessageObject.currentAccount).getUser(Integer.valueOf(lower_id));
            } else {
                this.currentChat = MessagesController.getInstance(this.currentMessageObject.currentAccount).getChat(Integer.valueOf(-lower_id));
                this.currentUser = MessagesController.getInstance(this.currentMessageObject.currentAccount).getUser(Integer.valueOf(this.currentMessageObject.messageOwner.from_id));
            }
        } else {
            TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentMessageObject.currentAccount).getEncryptedChat(Integer.valueOf((int) (dialog_id >> 32)));
            this.currentUser = MessagesController.getInstance(this.currentMessageObject.currentAccount).getUser(Integer.valueOf(encryptedChat.user_id));
        }
        TLRPC.Chat chat = this.currentChat;
        if (chat != null && this.currentUser != null) {
            this.nameTextView.setText(chat.title);
            this.onlineTextView.setText(UserObject.getName(this.currentUser));
            this.nameTextView.setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
            this.nameTextView.setCompoundDrawablePadding(0);
        } else {
            TLRPC.User user = this.currentUser;
            if (user != null) {
                this.nameTextView.setText(UserObject.getName(user));
                if (((int) dialog_id) == 0) {
                    this.nameTextView.setCompoundDrawablesWithIntrinsicBounds(R.drawable.ic_lock_white, 0, 0, 0);
                    this.nameTextView.setCompoundDrawablePadding(AndroidUtilities.dp(4.0f));
                } else {
                    this.nameTextView.setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
                    this.nameTextView.setCompoundDrawablePadding(0);
                }
            }
        }
        prepareLayouts(move);
        updateSubtitle();
        checkAndUpdateAvatar();
        applyViewsLayoutParams(0);
    }

    private void updateSubtitle() {
        TLRPC.User user;
        if (this.actionBar == null || this.currentMessageObject == null || this.currentChat != null || (user = this.currentUser) == null) {
            return;
        }
        if (user.id / 1000 != 777 && this.currentUser.id / 1000 != 333 && ContactsController.getInstance(this.currentMessageObject.currentAccount).contactsDict.get(Integer.valueOf(this.currentUser.id)) == null && ((ContactsController.getInstance(this.currentMessageObject.currentAccount).contactsDict.size() != 0 || !ContactsController.getInstance(this.currentMessageObject.currentAccount).isLoadingContacts()) && this.currentUser.phone != null && this.currentUser.phone.length() != 0)) {
            this.nameTextView.setText(PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + this.currentUser.phone));
        } else {
            this.nameTextView.setText(UserObject.getName(this.currentUser));
        }
        TLRPC.User user2 = this.currentUser;
        if (user2 != null && user2.id == 777000) {
            this.onlineTextView.setText(LocaleController.getString("ServiceNotifications", R.string.ServiceNotifications));
            return;
        }
        CharSequence printString = MessagesController.getInstance(this.currentMessageObject.currentAccount).printingStrings.get(this.currentMessageObject.getDialogId());
        if (printString == null || printString.length() == 0) {
            this.lastPrintString = null;
            setTypingAnimation(false);
            TLRPC.User user3 = MessagesController.getInstance(this.currentMessageObject.currentAccount).getUser(Integer.valueOf(this.currentUser.id));
            if (user3 != null) {
                this.currentUser = user3;
            }
            this.onlineTextView.setText(LocaleController.formatUserStatus(this.currentMessageObject.currentAccount, this.currentUser));
            return;
        }
        this.lastPrintString = printString;
        this.onlineTextView.setText(printString);
        setTypingAnimation(true);
    }

    private void checkAndUpdateAvatar() {
        TLRPC.User user;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null) {
            return;
        }
        if (this.currentChat != null) {
            TLRPC.Chat chat = MessagesController.getInstance(messageObject.currentAccount).getChat(Integer.valueOf(this.currentChat.id));
            if (chat == null) {
                return;
            }
            this.currentChat = chat;
            if (this.avatarImageView != null) {
                AvatarDrawable avatarDrawable = new AvatarDrawable(this.currentChat);
                this.avatarImageView.setImage(ImageLocation.getForChat(chat, false), "50_50", avatarDrawable, chat);
                return;
            }
            return;
        }
        if (this.currentUser == null || (user = MessagesController.getInstance(messageObject.currentAccount).getUser(Integer.valueOf(this.currentUser.id))) == null) {
            return;
        }
        this.currentUser = user;
        if (this.avatarImageView != null) {
            AvatarDrawable avatarDrawable2 = new AvatarDrawable(this.currentUser);
            this.avatarImageView.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable2, user);
        }
    }

    private void setTypingAnimation(boolean start) {
        if (this.actionBar == null) {
            return;
        }
        if (!start) {
            this.onlineTextView.setCompoundDrawablesWithIntrinsicBounds((Drawable) null, (Drawable) null, (Drawable) null, (Drawable) null);
            this.onlineTextView.setCompoundDrawablePadding(0);
            int a = 0;
            while (true) {
                StatusDrawable[] statusDrawableArr = this.statusDrawables;
                if (a < statusDrawableArr.length) {
                    statusDrawableArr[a].stop();
                    a++;
                } else {
                    return;
                }
            }
        } else {
            try {
                Integer type = MessagesController.getInstance(this.currentMessageObject.currentAccount).printingStringsTypes.get(this.currentMessageObject.getDialogId());
                this.onlineTextView.setCompoundDrawablesWithIntrinsicBounds(this.statusDrawables[type.intValue()], (Drawable) null, (Drawable) null, (Drawable) null);
                this.onlineTextView.setCompoundDrawablePadding(AndroidUtilities.dp(4.0f));
                for (int a2 = 0; a2 < this.statusDrawables.length; a2++) {
                    if (a2 == type.intValue()) {
                        this.statusDrawables[a2].start();
                    } else {
                        this.statusDrawables[a2].stop();
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        if (this.chatActivityEnterView.isPopupShowing()) {
            this.chatActivityEnterView.hidePopup(true);
        } else {
            super.onBackPressed();
        }
    }

    @Override // android.app.Activity
    protected void onResume() {
        super.onResume();
        MediaController.getInstance().setFeedbackView(this.chatActivityEnterView, true);
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.setFieldFocused(true);
        }
        fixLayout();
        checkAndUpdateAvatar();
        this.wakeLock.acquire(7000L);
    }

    @Override // android.app.Activity
    protected void onPause() {
        super.onPause();
        overridePendingTransition(0, 0);
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.hidePopup(false);
            this.chatActivityEnterView.setFieldFocused(false);
        }
        int i = this.lastResumedAccount;
        if (i >= 0) {
            ConnectionsManager.getInstance(i).setAppPaused(true, false);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TextView textView;
        PopupAudioView cell;
        MessageObject messageObject;
        PopupAudioView cell2;
        MessageObject messageObject2;
        CharSequence charSequence;
        if (id == NotificationCenter.appDidLogout) {
            if (account == this.lastResumedAccount) {
                onFinish();
                finish();
                return;
            }
            return;
        }
        if (id == NotificationCenter.pushMessagesUpdated) {
            if (!this.isReply) {
                this.popupMessages.clear();
                for (int a = 0; a < 3; a++) {
                    if (UserConfig.getInstance(a).isClientActivated()) {
                        this.popupMessages.addAll(NotificationsController.getInstance(a).popupMessages);
                    }
                }
                getNewMessage();
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            if (this.currentMessageObject == null || account != this.lastResumedAccount) {
                return;
            }
            int updateMask = ((Integer) args[0]).intValue();
            if ((updateMask & 1) != 0 || (updateMask & 4) != 0 || (updateMask & 16) != 0 || (updateMask & 32) != 0) {
                updateSubtitle();
            }
            if ((updateMask & 2) != 0 || (updateMask & 8) != 0) {
                checkAndUpdateAvatar();
            }
            if ((updateMask & 64) != 0) {
                CharSequence printString = MessagesController.getInstance(this.currentMessageObject.currentAccount).printingStrings.get(this.currentMessageObject.getDialogId());
                if ((this.lastPrintString != null && printString == null) || ((this.lastPrintString == null && printString != null) || ((charSequence = this.lastPrintString) != null && printString != null && !charSequence.equals(printString)))) {
                    updateSubtitle();
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagePlayingDidReset) {
            Integer mid = (Integer) args[0];
            ViewGroup viewGroup = this.messageContainer;
            if (viewGroup != null) {
                int count = viewGroup.getChildCount();
                for (int a2 = 0; a2 < count; a2++) {
                    View view = this.messageContainer.getChildAt(a2);
                    if (((Integer) view.getTag()).intValue() == 3 && (messageObject2 = (cell2 = (PopupAudioView) view.findViewWithTag(300)).getMessageObject()) != null && messageObject2.currentAccount == account && messageObject2.getId() == mid.intValue()) {
                        cell2.updateButtonState();
                        return;
                    }
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagePlayingProgressDidChanged) {
            Integer mid2 = (Integer) args[0];
            ViewGroup viewGroup2 = this.messageContainer;
            if (viewGroup2 != null) {
                int count2 = viewGroup2.getChildCount();
                for (int a3 = 0; a3 < count2; a3++) {
                    View view2 = this.messageContainer.getChildAt(a3);
                    if (((Integer) view2.getTag()).intValue() == 3 && (messageObject = (cell = (PopupAudioView) view2.findViewWithTag(300)).getMessageObject()) != null && messageObject.currentAccount == account && messageObject.getId() == mid2.intValue()) {
                        cell.updateProgress();
                        return;
                    }
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.emojiDidLoad) {
            ViewGroup viewGroup3 = this.messageContainer;
            if (viewGroup3 != null) {
                int count3 = viewGroup3.getChildCount();
                for (int a4 = 0; a4 < count3; a4++) {
                    View view3 = this.messageContainer.getChildAt(a4);
                    if (((Integer) view3.getTag()).intValue() == 1 && (textView = (TextView) view3.findViewWithTag(301)) != null) {
                        textView.invalidate();
                    }
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.contactsDidLoad && account == this.lastResumedAccount) {
            updateSubtitle();
        }
    }

    @Override // android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        onFinish();
        MediaController.getInstance().setFeedbackView(this.chatActivityEnterView, false);
        if (this.wakeLock.isHeld()) {
            this.wakeLock.release();
        }
        BackupImageView backupImageView = this.avatarImageView;
        if (backupImageView != null) {
            backupImageView.setImageDrawable(null);
        }
    }

    protected void onFinish() {
        if (this.finished) {
            return;
        }
        this.finished = true;
        if (this.isReply) {
            this.popupMessages.clear();
        }
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.appDidLogout);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.updateInterfaces);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.messagePlayingDidReset);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.contactsDidLoad);
        }
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.pushMessagesUpdated);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onDestroy();
        }
        if (this.wakeLock.isHeld()) {
            this.wakeLock.release();
        }
    }
}
