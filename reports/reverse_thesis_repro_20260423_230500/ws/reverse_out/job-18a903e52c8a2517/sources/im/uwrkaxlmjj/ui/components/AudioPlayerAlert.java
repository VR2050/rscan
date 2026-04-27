package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.audioinfo.AudioInfo;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.AudioPlayerCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SeekBarView;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AudioPlayerAlert extends BottomSheet implements NotificationCenter.NotificationCenterDelegate, DownloadController.FileDownloadProgressListener {
    private int TAG;
    private ActionBar actionBar;
    private AnimatorSet actionBarAnimation;
    private AnimatorSet animatorSet;
    private TextView authorTextView;
    private ChatAvatarContainer avatarContainer;
    private View[] buttons;
    private TextView durationTextView;
    private float endTranslation;
    private float fullAnimationProgress;
    private int hasNoCover;
    private boolean hasOptions;
    private boolean inFullSize;
    private boolean isInFullMode;
    private int lastTime;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private ActionBarMenuItem menuItem;
    private Drawable noCoverDrawable;
    private ActionBarMenuItem optionsButton;
    private Paint paint;
    private float panelEndTranslation;
    private float panelStartTranslation;
    private LaunchActivity parentActivity;
    private BackupImageView placeholderImageView;
    private ImageView playButton;
    private Drawable[] playOrderButtons;
    private FrameLayout playerLayout;
    private ArrayList<MessageObject> playlist;
    private LineProgressView progressView;
    private ImageView repeatButton;
    private int scrollOffsetY;
    private boolean scrollToSong;
    private ActionBarMenuItem searchItem;
    private int searchOpenOffset;
    private int searchOpenPosition;
    private boolean searchWas;
    private boolean searching;
    private SeekBarView seekBarView;
    private View shadow;
    private View shadow2;
    private Drawable shadowDrawable;
    private ActionBarMenuItem shuffleButton;
    private float startTranslation;
    private float thumbMaxScale;
    private int thumbMaxX;
    private int thumbMaxY;
    private SimpleTextView timeTextView;
    private TextView titleTextView;
    private int topBeforeSwitch;

    public AudioPlayerAlert(Context context) {
        TLRPC.User user;
        super(context, true, 0);
        this.buttons = new View[5];
        this.playOrderButtons = new Drawable[2];
        this.hasOptions = true;
        this.scrollToSong = true;
        this.searchOpenPosition = -1;
        this.paint = new Paint(1);
        this.scrollOffsetY = Integer.MAX_VALUE;
        MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
        if (messageObject != null) {
            this.currentAccount = messageObject.currentAccount;
        } else {
            this.currentAccount = UserConfig.selectedAccount;
        }
        this.parentActivity = (LaunchActivity) context;
        Drawable drawableMutate = context.getResources().getDrawable(R.drawable.nocover).mutate();
        this.noCoverDrawable = drawableMutate;
        drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_placeholder), PorterDuff.Mode.MULTIPLY));
        this.TAG = DownloadController.getInstance(this.currentAccount).generateObserverTag();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidStart);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.musicDidLoad);
        Drawable drawableMutate2 = context.getResources().getDrawable(R.drawable.sheet_shadow).mutate();
        this.shadowDrawable = drawableMutate2;
        drawableMutate2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_background), PorterDuff.Mode.MULTIPLY));
        this.paint.setColor(Theme.getColor(Theme.key_player_placeholderBackground));
        this.containerView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.1
            private boolean ignoreLayout = false;

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (ev.getAction() == 0 && AudioPlayerAlert.this.scrollOffsetY != 0 && ev.getY() < AudioPlayerAlert.this.scrollOffsetY && AudioPlayerAlert.this.placeholderImageView.getTranslationX() == 0.0f) {
                    AudioPlayerAlert.this.dismiss();
                    return true;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                return !AudioPlayerAlert.this.isDismissed() && super.onTouchEvent(e);
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int padding;
                int padding2;
                int height = View.MeasureSpec.getSize(heightMeasureSpec);
                int contentSize = AndroidUtilities.dp(178.0f) + (AudioPlayerAlert.this.playlist.size() * AndroidUtilities.dp(56.0f)) + AudioPlayerAlert.this.backgroundPaddingTop + ActionBar.getCurrentActionBarHeight() + AndroidUtilities.statusBarHeight;
                int heightMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(height, 1073741824);
                if (AudioPlayerAlert.this.searching) {
                    padding2 = AndroidUtilities.dp(178.0f) + ActionBar.getCurrentActionBarHeight() + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                } else {
                    if (contentSize < height) {
                        padding = height - contentSize;
                    } else {
                        padding = contentSize < height ? 0 : height - ((height / 5) * 3);
                    }
                    padding2 = padding + ActionBar.getCurrentActionBarHeight() + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                }
                if (AudioPlayerAlert.this.listView.getPaddingTop() != padding2) {
                    this.ignoreLayout = true;
                    AudioPlayerAlert.this.listView.setPadding(0, padding2, 0, AndroidUtilities.dp(8.0f));
                    this.ignoreLayout = false;
                }
                super.onMeasure(widthMeasureSpec, heightMeasureSpec2);
                AudioPlayerAlert.this.inFullSize = getMeasuredHeight() >= height;
                int availableHeight = ((height - ActionBar.getCurrentActionBarHeight()) - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - AndroidUtilities.dp(120.0f);
                int maxSize = Math.max(availableHeight, getMeasuredWidth());
                AudioPlayerAlert.this.thumbMaxX = ((getMeasuredWidth() - maxSize) / 2) - AndroidUtilities.dp(17.0f);
                AudioPlayerAlert.this.thumbMaxY = AndroidUtilities.dp(19.0f);
                AudioPlayerAlert.this.panelEndTranslation = getMeasuredHeight() - AudioPlayerAlert.this.playerLayout.getMeasuredHeight();
                AudioPlayerAlert.this.thumbMaxScale = (maxSize / r5.placeholderImageView.getMeasuredWidth()) - 1.0f;
                AudioPlayerAlert.this.endTranslation = ActionBar.getCurrentActionBarHeight() + (AndroidUtilities.statusBarHeight - AndroidUtilities.dp(19.0f));
                int scaledHeight = (int) Math.ceil(AudioPlayerAlert.this.placeholderImageView.getMeasuredHeight() * (AudioPlayerAlert.this.thumbMaxScale + 1.0f));
                if (scaledHeight > availableHeight) {
                    AudioPlayerAlert.this.endTranslation -= scaledHeight - availableHeight;
                }
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                int y = AudioPlayerAlert.this.actionBar.getMeasuredHeight();
                AudioPlayerAlert.this.shadow.layout(AudioPlayerAlert.this.shadow.getLeft(), y, AudioPlayerAlert.this.shadow.getRight(), AudioPlayerAlert.this.shadow.getMeasuredHeight() + y);
                AudioPlayerAlert.this.updateLayout();
                AudioPlayerAlert audioPlayerAlert = AudioPlayerAlert.this;
                audioPlayerAlert.setFullAnimationProgress(audioPlayerAlert.fullAnimationProgress);
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                AudioPlayerAlert.this.shadowDrawable.setBounds(0, Math.max(AudioPlayerAlert.this.actionBar.getMeasuredHeight(), AudioPlayerAlert.this.scrollOffsetY) - AudioPlayerAlert.this.backgroundPaddingTop, getMeasuredWidth(), getMeasuredHeight());
                AudioPlayerAlert.this.shadowDrawable.draw(canvas);
            }
        };
        this.containerView.setWillNotDraw(false);
        this.containerView.setPadding(this.backgroundPaddingLeft, 0, this.backgroundPaddingLeft, 0);
        ActionBar actionBar = new ActionBar(context);
        this.actionBar = actionBar;
        actionBar.setBackgroundColor(Theme.getColor(Theme.key_player_actionBar));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_player_actionBarItems), false);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_player_actionBarSelector), false);
        this.actionBar.setTitleColor(Theme.getColor(Theme.key_player_actionBarTitle));
        this.actionBar.setSubtitleColor(Theme.getColor(Theme.key_player_actionBarSubtitle));
        this.actionBar.setAlpha(0.0f);
        this.actionBar.setTitle("1");
        this.actionBar.setSubtitle("1");
        this.actionBar.getTitleTextView().setAlpha(0.0f);
        this.actionBar.getSubtitleTextView().setAlpha(0.0f);
        ChatAvatarContainer chatAvatarContainer = new ChatAvatarContainer(context, null, false);
        this.avatarContainer = chatAvatarContainer;
        chatAvatarContainer.setEnabled(false);
        this.avatarContainer.setTitleColors(Theme.getColor(Theme.key_player_actionBarTitle), Theme.getColor(Theme.key_player_actionBarSubtitle));
        if (messageObject != null) {
            long did = messageObject.getDialogId();
            int lower_id = (int) did;
            int high_id = (int) (did >> 32);
            if (lower_id != 0) {
                if (lower_id > 0) {
                    TLRPC.User user2 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(lower_id));
                    if (user2 != null) {
                        this.avatarContainer.setTitle(ContactsController.formatName(user2.first_name, user2.last_name));
                        this.avatarContainer.setUserAvatar(user2);
                    }
                } else {
                    TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
                    if (chat != null) {
                        this.avatarContainer.setTitle(chat.title);
                        this.avatarContainer.setChatAvatar(chat);
                    }
                }
            } else {
                TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf(high_id));
                if (encryptedChat != null && (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(encryptedChat.user_id))) != null) {
                    this.avatarContainer.setTitle(ContactsController.formatName(user.first_name, user.last_name));
                    this.avatarContainer.setUserAvatar(user);
                }
            }
        }
        this.avatarContainer.setSubtitle(LocaleController.getString("AudioTitle", R.string.AudioTitle));
        this.actionBar.addView(this.avatarContainer, 0, LayoutHelper.createFrame(-2.0f, -1.0f, 51, 56.0f, 0.0f, 40.0f, 0.0f));
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(0, R.drawable.ic_ab_other);
        this.menuItem = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.addSubItem(1, R.drawable.msg_forward, LocaleController.getString("Forward", R.string.Forward));
        this.menuItem.addSubItem(2, R.drawable.msg_shareout, LocaleController.getString("ShareFile", R.string.ShareFile));
        this.menuItem.addSubItem(4, R.drawable.msg_message, LocaleController.getString("ShowInChat", R.string.ShowInChat));
        this.menuItem.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        this.menuItem.setTranslationX(AndroidUtilities.dp(48.0f));
        this.menuItem.setAlpha(0.0f);
        ActionBarMenuItem actionBarMenuItemSearchListener = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchCollapse() {
                AudioPlayerAlert.this.avatarContainer.setVisibility(0);
                if (AudioPlayerAlert.this.hasOptions) {
                    AudioPlayerAlert.this.menuItem.setVisibility(4);
                }
                if (AudioPlayerAlert.this.searching) {
                    AudioPlayerAlert.this.searchWas = false;
                    AudioPlayerAlert.this.searching = false;
                    AudioPlayerAlert.this.setAllowNestedScroll(true);
                    AudioPlayerAlert.this.listAdapter.search(null);
                }
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchExpand() {
                AudioPlayerAlert audioPlayerAlert = AudioPlayerAlert.this;
                audioPlayerAlert.searchOpenPosition = audioPlayerAlert.layoutManager.findLastVisibleItemPosition();
                View firstVisView = AudioPlayerAlert.this.layoutManager.findViewByPosition(AudioPlayerAlert.this.searchOpenPosition);
                AudioPlayerAlert.this.searchOpenOffset = (firstVisView == null ? 0 : firstVisView.getTop()) - AudioPlayerAlert.this.listView.getPaddingTop();
                AudioPlayerAlert.this.avatarContainer.setVisibility(8);
                if (AudioPlayerAlert.this.hasOptions) {
                    AudioPlayerAlert.this.menuItem.setVisibility(8);
                }
                AudioPlayerAlert.this.searching = true;
                AudioPlayerAlert.this.setAllowNestedScroll(false);
                AudioPlayerAlert.this.listAdapter.notifyDataSetChanged();
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onTextChanged(EditText editText) {
                if (editText.length() > 0) {
                    AudioPlayerAlert.this.listAdapter.search(editText.getText().toString());
                } else {
                    AudioPlayerAlert.this.searchWas = false;
                    AudioPlayerAlert.this.listAdapter.search(null);
                }
            }
        });
        this.searchItem = actionBarMenuItemSearchListener;
        actionBarMenuItemSearchListener.setContentDescription(LocaleController.getString("Search", R.string.Search));
        EditTextBoldCursor editText = this.searchItem.getSearchField();
        editText.setHint(LocaleController.getString("Search", R.string.Search));
        editText.setTextColor(Theme.getColor(Theme.key_player_actionBarTitle));
        editText.setHintTextColor(Theme.getColor(Theme.key_player_time));
        editText.setCursorColor(Theme.getColor(Theme.key_player_actionBarTitle));
        if (!AndroidUtilities.isTablet()) {
            this.actionBar.showActionModeTop();
            this.actionBar.setActionModeTopColor(Theme.getColor(Theme.key_player_actionBarTop));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.3
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id != -1) {
                    AudioPlayerAlert.this.onSubItemClick(id);
                } else {
                    AudioPlayerAlert.this.dismiss();
                }
            }
        });
        View view = new View(context);
        this.shadow = view;
        view.setAlpha(0.0f);
        this.shadow.setBackgroundResource(R.drawable.header_shadow);
        View view2 = new View(context);
        this.shadow2 = view2;
        view2.setAlpha(0.0f);
        this.shadow2.setBackgroundResource(R.drawable.header_shadow);
        FrameLayout frameLayout = new FrameLayout(context);
        this.playerLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_player_background));
        BackupImageView backupImageView = new BackupImageView(context) { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.4
            private RectF rect = new RectF();

            @Override // im.uwrkaxlmjj.ui.components.BackupImageView, android.view.View
            protected void onDraw(Canvas canvas) {
                if (AudioPlayerAlert.this.hasNoCover == 1 || (AudioPlayerAlert.this.hasNoCover == 2 && (!getImageReceiver().hasBitmapImage() || getImageReceiver().getCurrentAlpha() != 1.0f))) {
                    this.rect.set(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight());
                    canvas.drawRoundRect(this.rect, getRoundRadius(), getRoundRadius(), AudioPlayerAlert.this.paint);
                    float plusScale = (AudioPlayerAlert.this.thumbMaxScale / getScaleX()) / 3.0f;
                    int s = (int) (AndroidUtilities.dp(63.0f) * Math.max(plusScale / AudioPlayerAlert.this.thumbMaxScale, 1.0f / AudioPlayerAlert.this.thumbMaxScale));
                    int x = (int) (this.rect.centerX() - (s / 2));
                    int y = (int) (this.rect.centerY() - (s / 2));
                    AudioPlayerAlert.this.noCoverDrawable.setBounds(x, y, x + s, y + s);
                    AudioPlayerAlert.this.noCoverDrawable.draw(canvas);
                }
                if (AudioPlayerAlert.this.hasNoCover != 1) {
                    super.onDraw(canvas);
                }
            }
        };
        this.placeholderImageView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(20.0f));
        this.placeholderImageView.setPivotX(0.0f);
        this.placeholderImageView.setPivotY(0.0f);
        this.placeholderImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$EazCaRNHpB4rK04VH15UJILXdQ8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$0$AudioPlayerAlert(view3);
            }
        });
        TextView textView = new TextView(context);
        this.titleTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_player_actionBarTitle));
        this.titleTextView.setTextSize(1, 15.0f);
        this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.titleTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.titleTextView.setSingleLine(true);
        this.playerLayout.addView(this.titleTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 72.0f, 18.0f, 60.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.authorTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_player_time));
        this.authorTextView.setTextSize(1, 14.0f);
        this.authorTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.authorTextView.setSingleLine(true);
        this.playerLayout.addView(this.authorTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 72.0f, 40.0f, 60.0f, 0.0f));
        ActionBarMenuItem actionBarMenuItem = new ActionBarMenuItem(context, null, 0, Theme.getColor(Theme.key_player_actionBarItems));
        this.optionsButton = actionBarMenuItem;
        actionBarMenuItem.setLongClickEnabled(false);
        this.optionsButton.setIcon(R.drawable.ic_ab_other);
        this.optionsButton.setAdditionalYOffset(-AndroidUtilities.dp(120.0f));
        this.playerLayout.addView(this.optionsButton, LayoutHelper.createFrame(40.0f, 40.0f, 53, 0.0f, 19.0f, 10.0f, 0.0f));
        this.optionsButton.addSubItem(1, R.drawable.msg_forward, LocaleController.getString("Forward", R.string.Forward));
        this.optionsButton.addSubItem(2, R.drawable.msg_shareout, LocaleController.getString("ShareFile", R.string.ShareFile));
        this.optionsButton.addSubItem(4, R.drawable.msg_message, LocaleController.getString("ShowInChat", R.string.ShowInChat));
        this.optionsButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$BKaTlh9ERb-DOaDXjpYCOzCBLbk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$1$AudioPlayerAlert(view3);
            }
        });
        this.optionsButton.setDelegate(new ActionBarMenuItem.ActionBarMenuItemDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$lafapgjvJ1hUOcqvEn64xXeC9tY
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemDelegate
            public final void onItemClick(int i) {
                this.f$0.onSubItemClick(i);
            }
        });
        this.optionsButton.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        SeekBarView seekBarView = new SeekBarView(context);
        this.seekBarView = seekBarView;
        seekBarView.setDelegate(new SeekBarView.SeekBarViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$blSPNsyu5lx5NZmqCtIO9SqKllA
            @Override // im.uwrkaxlmjj.ui.components.SeekBarView.SeekBarViewDelegate
            public final void onSeekBarDrag(float f) {
                MediaController.getInstance().seekToProgress(MediaController.getInstance().getPlayingMessageObject(), f);
            }
        });
        this.playerLayout.addView(this.seekBarView, LayoutHelper.createFrame(-1.0f, 30.0f, 51, 8.0f, 62.0f, 8.0f, 0.0f));
        LineProgressView lineProgressView = new LineProgressView(context);
        this.progressView = lineProgressView;
        lineProgressView.setVisibility(4);
        this.progressView.setBackgroundColor(Theme.getColor(Theme.key_player_progressBackground));
        this.progressView.setProgressColor(Theme.getColor(Theme.key_player_progress));
        this.playerLayout.addView(this.progressView, LayoutHelper.createFrame(-1.0f, 2.0f, 51, 20.0f, 78.0f, 20.0f, 0.0f));
        SimpleTextView simpleTextView = new SimpleTextView(context);
        this.timeTextView = simpleTextView;
        simpleTextView.setTextSize(12);
        this.timeTextView.setText("0:00");
        this.timeTextView.setTextColor(Theme.getColor(Theme.key_player_time));
        this.playerLayout.addView(this.timeTextView, LayoutHelper.createFrame(100.0f, -2.0f, 51, 20.0f, 92.0f, 0.0f, 0.0f));
        TextView textView3 = new TextView(context);
        this.durationTextView = textView3;
        textView3.setTextSize(1, 12.0f);
        this.durationTextView.setTextColor(Theme.getColor(Theme.key_player_time));
        this.durationTextView.setGravity(17);
        this.playerLayout.addView(this.durationTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 53, 0.0f, 90.0f, 20.0f, 0.0f));
        FrameLayout bottomView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.6
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                int dist = ((right - left) - AndroidUtilities.dp(248.0f)) / 4;
                for (int a = 0; a < 5; a++) {
                    int l = AndroidUtilities.dp((a * 48) + 4) + (dist * a);
                    int t = AndroidUtilities.dp(9.0f);
                    AudioPlayerAlert.this.buttons[a].layout(l, t, AudioPlayerAlert.this.buttons[a].getMeasuredWidth() + l, AudioPlayerAlert.this.buttons[a].getMeasuredHeight() + t);
                }
            }
        };
        this.playerLayout.addView(bottomView, LayoutHelper.createFrame(-1.0f, 66.0f, 51, 0.0f, 106.0f, 0.0f, 0.0f));
        View[] viewArr = this.buttons;
        ActionBarMenuItem actionBarMenuItem2 = new ActionBarMenuItem(context, null, 0, 0);
        this.shuffleButton = actionBarMenuItem2;
        viewArr[0] = actionBarMenuItem2;
        actionBarMenuItem2.setLongClickEnabled(false);
        this.shuffleButton.setAdditionalYOffset(-AndroidUtilities.dp(10.0f));
        bottomView.addView(this.shuffleButton, LayoutHelper.createFrame(48, 48, 51));
        this.shuffleButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$ihi9viWDvCoIcIBVM8KPBeRchx4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$3$AudioPlayerAlert(view3);
            }
        });
        TextView textView4 = this.shuffleButton.addSubItem(1, LocaleController.getString("ReverseOrder", R.string.ReverseOrder));
        textView4.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(16.0f), 0);
        this.playOrderButtons[0] = context.getResources().getDrawable(R.drawable.music_reverse).mutate();
        textView4.setCompoundDrawablePadding(AndroidUtilities.dp(8.0f));
        textView4.setCompoundDrawablesWithIntrinsicBounds(this.playOrderButtons[0], (Drawable) null, (Drawable) null, (Drawable) null);
        TextView textView5 = this.shuffleButton.addSubItem(2, LocaleController.getString("Shuffle", R.string.Shuffle));
        textView5.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(16.0f), 0);
        this.playOrderButtons[1] = context.getResources().getDrawable(R.drawable.pl_shuffle).mutate();
        textView5.setCompoundDrawablePadding(AndroidUtilities.dp(8.0f));
        textView5.setCompoundDrawablesWithIntrinsicBounds(this.playOrderButtons[1], (Drawable) null, (Drawable) null, (Drawable) null);
        this.shuffleButton.setDelegate(new ActionBarMenuItem.ActionBarMenuItemDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$P-SlttS6UDMKqM9GgIfXiCGRyw0
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemDelegate
            public final void onItemClick(int i) {
                this.f$0.lambda$new$4$AudioPlayerAlert(i);
            }
        });
        View[] viewArr2 = this.buttons;
        ImageView prevButton = new ImageView(context);
        viewArr2[1] = prevButton;
        prevButton.setScaleType(ImageView.ScaleType.CENTER);
        prevButton.setImageDrawable(Theme.createSimpleSelectorDrawable(context, R.drawable.pl_previous, Theme.getColor(Theme.key_player_button), Theme.getColor(Theme.key_player_buttonActive)));
        bottomView.addView(prevButton, LayoutHelper.createFrame(48, 48, 51));
        prevButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$IhyP8vUF5B-XqK-QapdlONCdNgM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                MediaController.getInstance().playPreviousMessage();
            }
        });
        prevButton.setContentDescription(LocaleController.getString("AccDescrPrevious", R.string.AccDescrPrevious));
        View[] viewArr3 = this.buttons;
        ImageView imageView = new ImageView(context);
        this.playButton = imageView;
        viewArr3[2] = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.playButton.setImageDrawable(Theme.createSimpleSelectorDrawable(context, R.drawable.pl_play, Theme.getColor(Theme.key_player_button), Theme.getColor(Theme.key_player_buttonActive)));
        bottomView.addView(this.playButton, LayoutHelper.createFrame(48, 48, 51));
        this.playButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$u6vlMgiYup2pVbdtoY7wJj90wUE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                AudioPlayerAlert.lambda$new$6(view3);
            }
        });
        View[] viewArr4 = this.buttons;
        ImageView nextButton = new ImageView(context);
        viewArr4[3] = nextButton;
        nextButton.setScaleType(ImageView.ScaleType.CENTER);
        nextButton.setImageDrawable(Theme.createSimpleSelectorDrawable(context, R.drawable.pl_next, Theme.getColor(Theme.key_player_button), Theme.getColor(Theme.key_player_buttonActive)));
        bottomView.addView(nextButton, LayoutHelper.createFrame(48, 48, 51));
        nextButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$yrVmnr-QIKO3sQsLnD9g_67s0Qk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                MediaController.getInstance().playNextMessage();
            }
        });
        nextButton.setContentDescription(LocaleController.getString("Next", R.string.Next));
        View[] viewArr5 = this.buttons;
        ImageView imageView2 = new ImageView(context);
        this.repeatButton = imageView2;
        viewArr5[4] = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        this.repeatButton.setPadding(0, 0, AndroidUtilities.dp(8.0f), 0);
        bottomView.addView(this.repeatButton, LayoutHelper.createFrame(50, 48, 51));
        this.repeatButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$vZ7MJX_WXBTrCu4fMyP76LYfQwI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$8$AudioPlayerAlert(view3);
            }
        });
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.7
            boolean ignoreLayout;

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                boolean found;
                int idx;
                super.onLayout(changed, l, t, r, b);
                if (AudioPlayerAlert.this.searchOpenPosition == -1 || AudioPlayerAlert.this.actionBar.isSearchFieldVisible()) {
                    if (AudioPlayerAlert.this.scrollToSong) {
                        AudioPlayerAlert.this.scrollToSong = false;
                        MessageObject playingMessageObject = MediaController.getInstance().getPlayingMessageObject();
                        if (playingMessageObject != null) {
                            int count = AudioPlayerAlert.this.listView.getChildCount();
                            int a = 0;
                            while (true) {
                                if (a >= count) {
                                    break;
                                }
                                View child = AudioPlayerAlert.this.listView.getChildAt(a);
                                if (!(child instanceof AudioPlayerCell) || ((AudioPlayerCell) child).getMessageObject() != playingMessageObject) {
                                    a++;
                                } else if (child.getBottom() <= getMeasuredHeight()) {
                                    found = true;
                                }
                            }
                            found = false;
                            if (!found && (idx = AudioPlayerAlert.this.playlist.indexOf(playingMessageObject)) >= 0) {
                                this.ignoreLayout = true;
                                if (SharedConfig.playOrderReversed) {
                                    AudioPlayerAlert.this.layoutManager.scrollToPosition(idx);
                                } else {
                                    AudioPlayerAlert.this.layoutManager.scrollToPosition(AudioPlayerAlert.this.playlist.size() - idx);
                                }
                                super.onLayout(false, l, t, r, b);
                                this.ignoreLayout = false;
                                return;
                            }
                            return;
                        }
                        return;
                    }
                    return;
                }
                this.ignoreLayout = true;
                AudioPlayerAlert.this.layoutManager.scrollToPositionWithOffset(AudioPlayerAlert.this.searchOpenPosition, AudioPlayerAlert.this.searchOpenOffset);
                super.onLayout(false, l, t, r, b);
                this.ignoreLayout = false;
                AudioPlayerAlert.this.searchOpenPosition = -1;
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView
            protected boolean allowSelectChildAtPosition(float x, float y) {
                return AudioPlayerAlert.this.playerLayout == null || y > AudioPlayerAlert.this.playerLayout.getY() + ((float) AudioPlayerAlert.this.playerLayout.getMeasuredHeight());
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean drawChild(Canvas canvas, View child, long drawingTime) {
                canvas.save();
                canvas.clipRect(0, (AudioPlayerAlert.this.actionBar != null ? AudioPlayerAlert.this.actionBar.getMeasuredHeight() : 0) + AndroidUtilities.dp(50.0f), getMeasuredWidth(), getMeasuredHeight());
                boolean result = super.drawChild(canvas, child, drawingTime);
                canvas.restore();
                return result;
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setPadding(0, 0, 0, AndroidUtilities.dp(8.0f));
        this.listView.setClipToPadding(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(getContext(), 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        this.listView.setHorizontalScrollBarEnabled(false);
        this.listView.setVerticalScrollBarEnabled(false);
        this.containerView.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listAdapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        this.listView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$uodriH9ZnK_M8reNMVoxKdEIpzE
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view3, int i) {
                AudioPlayerAlert.lambda$new$9(view3, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.8
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && AudioPlayerAlert.this.searching && AudioPlayerAlert.this.searchWas) {
                    AndroidUtilities.hideKeyboard(AudioPlayerAlert.this.getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                AudioPlayerAlert.this.updateLayout();
            }
        });
        this.playlist = MediaController.getInstance().getPlaylist();
        this.listAdapter.notifyDataSetChanged();
        this.containerView.addView(this.playerLayout, LayoutHelper.createFrame(-1, 178.0f));
        this.containerView.addView(this.shadow2, LayoutHelper.createFrame(-1, 3.0f));
        this.containerView.addView(this.placeholderImageView, LayoutHelper.createFrame(40.0f, 40.0f, 51, 17.0f, 19.0f, 0.0f, 0.0f));
        this.containerView.addView(this.shadow, LayoutHelper.createFrame(-1, 3.0f));
        this.containerView.addView(this.actionBar);
        updateTitle(false);
        updateRepeatButton();
        updateShuffleButton();
    }

    public /* synthetic */ void lambda$new$0$AudioPlayerAlert(View view) {
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.animatorSet = null;
        }
        this.animatorSet = new AnimatorSet();
        if (this.scrollOffsetY <= this.actionBar.getMeasuredHeight()) {
            AnimatorSet animatorSet2 = this.animatorSet;
            Animator[] animatorArr = new Animator[1];
            float[] fArr = new float[1];
            fArr[0] = this.isInFullMode ? 0.0f : 1.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(this, "fullAnimationProgress", fArr);
            animatorSet2.playTogether(animatorArr);
        } else {
            AnimatorSet animatorSet3 = this.animatorSet;
            Animator[] animatorArr2 = new Animator[4];
            float[] fArr2 = new float[1];
            fArr2[0] = this.isInFullMode ? 0.0f : 1.0f;
            animatorArr2[0] = ObjectAnimator.ofFloat(this, "fullAnimationProgress", fArr2);
            ActionBar actionBar = this.actionBar;
            float[] fArr3 = new float[1];
            fArr3[0] = this.isInFullMode ? 0.0f : 1.0f;
            animatorArr2[1] = ObjectAnimator.ofFloat(actionBar, "alpha", fArr3);
            View view2 = this.shadow;
            float[] fArr4 = new float[1];
            fArr4[0] = this.isInFullMode ? 0.0f : 1.0f;
            animatorArr2[2] = ObjectAnimator.ofFloat(view2, "alpha", fArr4);
            View view3 = this.shadow2;
            float[] fArr5 = new float[1];
            fArr5[0] = this.isInFullMode ? 0.0f : 1.0f;
            animatorArr2[3] = ObjectAnimator.ofFloat(view3, "alpha", fArr5);
            animatorSet3.playTogether(animatorArr2);
        }
        this.animatorSet.setInterpolator(new DecelerateInterpolator());
        this.animatorSet.setDuration(250L);
        this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(AudioPlayerAlert.this.animatorSet)) {
                    if (!AudioPlayerAlert.this.isInFullMode) {
                        AudioPlayerAlert.this.listView.setScrollEnabled(true);
                        if (AudioPlayerAlert.this.hasOptions) {
                            AudioPlayerAlert.this.menuItem.setVisibility(4);
                        }
                        AudioPlayerAlert.this.searchItem.setVisibility(0);
                    } else {
                        if (AudioPlayerAlert.this.hasOptions) {
                            AudioPlayerAlert.this.menuItem.setVisibility(0);
                        }
                        AudioPlayerAlert.this.searchItem.setVisibility(4);
                    }
                    AudioPlayerAlert.this.animatorSet = null;
                }
            }
        });
        this.animatorSet.start();
        if (this.hasOptions) {
            this.menuItem.setVisibility(0);
        }
        this.searchItem.setVisibility(0);
        this.isInFullMode = !this.isInFullMode;
        this.listView.setScrollEnabled(false);
        if (this.isInFullMode) {
            this.shuffleButton.setAdditionalYOffset(-AndroidUtilities.dp(68.0f));
        } else {
            this.shuffleButton.setAdditionalYOffset(-AndroidUtilities.dp(10.0f));
        }
    }

    public /* synthetic */ void lambda$new$1$AudioPlayerAlert(View v) {
        this.optionsButton.toggleSubMenu();
    }

    public /* synthetic */ void lambda$new$3$AudioPlayerAlert(View v) {
        this.shuffleButton.toggleSubMenu();
    }

    public /* synthetic */ void lambda$new$4$AudioPlayerAlert(int id) {
        MediaController.getInstance().toggleShuffleMusic(id);
        updateShuffleButton();
        this.listAdapter.notifyDataSetChanged();
    }

    static /* synthetic */ void lambda$new$6(View v) {
        if (MediaController.getInstance().isDownloadingCurrentMessage()) {
            return;
        }
        if (MediaController.getInstance().isMessagePaused()) {
            MediaController.getInstance().playMessage(MediaController.getInstance().getPlayingMessageObject());
        } else {
            MediaController.getInstance().lambda$startAudioAgain$5$MediaController(MediaController.getInstance().getPlayingMessageObject());
        }
    }

    public /* synthetic */ void lambda$new$8$AudioPlayerAlert(View v) {
        SharedConfig.toggleRepeatMode();
        updateRepeatButton();
    }

    static /* synthetic */ void lambda$new$9(View view, int position) {
        if (view instanceof AudioPlayerCell) {
            ((AudioPlayerCell) view).didPressedButton();
        }
    }

    public void setFullAnimationProgress(float value) {
        this.fullAnimationProgress = value;
        this.placeholderImageView.setRoundRadius(AndroidUtilities.dp((1.0f - value) * 20.0f));
        float scale = (this.thumbMaxScale * this.fullAnimationProgress) + 1.0f;
        this.placeholderImageView.setScaleX(scale);
        this.placeholderImageView.setScaleY(scale);
        this.placeholderImageView.getTranslationY();
        this.placeholderImageView.setTranslationX(this.thumbMaxX * this.fullAnimationProgress);
        BackupImageView backupImageView = this.placeholderImageView;
        float f = this.startTranslation;
        backupImageView.setTranslationY(f + ((this.endTranslation - f) * this.fullAnimationProgress));
        FrameLayout frameLayout = this.playerLayout;
        float f2 = this.panelStartTranslation;
        frameLayout.setTranslationY(f2 + ((this.panelEndTranslation - f2) * this.fullAnimationProgress));
        View view = this.shadow2;
        float f3 = this.panelStartTranslation;
        view.setTranslationY(f3 + ((this.panelEndTranslation - f3) * this.fullAnimationProgress) + this.playerLayout.getMeasuredHeight());
        this.menuItem.setAlpha(this.fullAnimationProgress);
        this.searchItem.setAlpha(1.0f - this.fullAnimationProgress);
        this.avatarContainer.setAlpha(1.0f - this.fullAnimationProgress);
        this.actionBar.getTitleTextView().setAlpha(this.fullAnimationProgress);
        this.actionBar.getSubtitleTextView().setAlpha(this.fullAnimationProgress);
    }

    public float getFullAnimationProgress() {
        return this.fullAnimationProgress;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSubItemClick(int id) {
        MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
        if (messageObject == null || this.parentActivity == null) {
            return;
        }
        if (id == 1) {
            if (UserConfig.selectedAccount != this.currentAccount) {
                this.parentActivity.switchToAccount(this.currentAccount, true);
            }
            Bundle args = new Bundle();
            args.putBoolean("onlySelect", true);
            args.putInt("dialogsType", 3);
            DialogsActivity fragment = new DialogsActivity(args);
            final ArrayList<MessageObject> fmessages = new ArrayList<>();
            fmessages.add(messageObject);
            fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$bXyq9qs81Drrrsiaq5ly08Gma10
                @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                    this.f$0.lambda$onSubItemClick$10$AudioPlayerAlert(fmessages, dialogsActivity, arrayList, charSequence, z);
                }
            });
            this.parentActivity.lambda$runLinkRequest$26$LaunchActivity(fragment);
            dismiss();
            return;
        }
        if (id == 2) {
            File f = null;
            try {
                if (!TextUtils.isEmpty(messageObject.messageOwner.attachPath)) {
                    f = new File(messageObject.messageOwner.attachPath);
                    if (!f.exists()) {
                        f = null;
                    }
                }
                if (f == null) {
                    f = FileLoader.getPathToMessage(messageObject.messageOwner);
                }
                if (f.exists()) {
                    Intent intent = new Intent("android.intent.action.SEND");
                    if (messageObject != null) {
                        intent.setType(messageObject.getMimeType());
                    } else {
                        intent.setType("audio/mp3");
                    }
                    if (Build.VERSION.SDK_INT >= 24) {
                        try {
                            intent.putExtra("android.intent.extra.STREAM", FileProvider.getUriForFile(ApplicationLoader.applicationContext, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f));
                            intent.setFlags(1);
                        } catch (Exception e) {
                            intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
                        }
                    } else {
                        intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
                    }
                    this.parentActivity.startActivityForResult(Intent.createChooser(intent, LocaleController.getString("ShareFile", R.string.ShareFile)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(this.parentActivity);
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                builder.setMessage(LocaleController.getString("PleaseDownload", R.string.PleaseDownload));
                builder.show();
                return;
            } catch (Exception e2) {
                FileLog.e(e2);
                return;
            }
        }
        if (id == 4) {
            if (UserConfig.selectedAccount != this.currentAccount) {
                this.parentActivity.switchToAccount(this.currentAccount, true);
            }
            Bundle args2 = new Bundle();
            long did = messageObject.getDialogId();
            int lower_part = (int) did;
            int high_id = (int) (did >> 32);
            if (lower_part != 0) {
                if (lower_part > 0) {
                    args2.putInt("user_id", lower_part);
                } else if (lower_part < 0) {
                    TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_part));
                    if (chat != null && chat.migrated_to != null) {
                        args2.putInt("migrated_to", lower_part);
                        lower_part = -chat.migrated_to.channel_id;
                    }
                    args2.putInt("chat_id", -lower_part);
                }
            } else {
                args2.putInt("enc_id", high_id);
            }
            args2.putInt("message_id", messageObject.getId());
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            this.parentActivity.presentFragment(new ChatActivity(args2), false, false);
            dismiss();
        }
    }

    public /* synthetic */ void lambda$onSubItemClick$10$AudioPlayerAlert(ArrayList fmessages, DialogsActivity fragment1, ArrayList dids, CharSequence message, boolean param) {
        if (dids.size() > 1 || ((Long) dids.get(0)).longValue() == UserConfig.getInstance(this.currentAccount).getClientUserId() || message != null) {
            for (int a = 0; a < dids.size(); a++) {
                long did = ((Long) dids.get(a)).longValue();
                if (message != null) {
                    SendMessagesHelper.getInstance(this.currentAccount).sendMessage(message.toString(), did, null, null, true, null, null, null, true, 0);
                }
                SendMessagesHelper.getInstance(this.currentAccount).sendMessage(fmessages, did, true, 0);
            }
            fragment1.finishFragment();
            return;
        }
        long did2 = ((Long) dids.get(0)).longValue();
        int lower_part = (int) did2;
        int high_part = (int) (did2 >> 32);
        Bundle args1 = new Bundle();
        args1.putBoolean("scrollToTopOnResume", true);
        if (lower_part != 0) {
            if (lower_part > 0) {
                args1.putInt("user_id", lower_part);
            } else if (lower_part < 0) {
                args1.putInt("chat_id", -lower_part);
            }
        } else {
            args1.putInt("enc_id", high_part);
        }
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        ChatActivity chatActivity = new ChatActivity(args1);
        if (this.parentActivity.presentFragment(chatActivity, true, false)) {
            chatActivity.showFieldPanelForForward(true, fmessages);
        } else {
            fragment1.finishFragment();
        }
    }

    private int getCurrentTop() {
        if (this.listView.getChildCount() != 0) {
            int top = 0;
            View child = this.listView.getChildAt(0);
            RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findContainingViewHolder(child);
            if (holder != null) {
                int paddingTop = this.listView.getPaddingTop();
                if (holder.getAdapterPosition() == 0 && child.getTop() >= 0) {
                    top = child.getTop();
                }
                return paddingTop - top;
            }
            return -1000;
        }
        return -1000;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        AudioPlayerCell cell;
        MessageObject messageObject;
        AudioPlayerCell cell2;
        MessageObject messageObject1;
        if (id == NotificationCenter.messagePlayingDidStart || id == NotificationCenter.messagePlayingPlayStateChanged || id == NotificationCenter.messagePlayingDidReset) {
            updateTitle(id == NotificationCenter.messagePlayingDidReset && ((Boolean) args[1]).booleanValue());
            if (id == NotificationCenter.messagePlayingDidReset || id == NotificationCenter.messagePlayingPlayStateChanged) {
                int count = this.listView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View view = this.listView.getChildAt(a);
                    if ((view instanceof AudioPlayerCell) && (messageObject = (cell = (AudioPlayerCell) view).getMessageObject()) != null && (messageObject.isVoice() || messageObject.isMusic())) {
                        cell.updateButtonState(false, true);
                    }
                }
                return;
            }
            if (id != NotificationCenter.messagePlayingDidStart || ((MessageObject) args[0]).eventId != 0) {
                return;
            }
            int count2 = this.listView.getChildCount();
            for (int a2 = 0; a2 < count2; a2++) {
                View view2 = this.listView.getChildAt(a2);
                if ((view2 instanceof AudioPlayerCell) && (messageObject1 = (cell2 = (AudioPlayerCell) view2).getMessageObject()) != null && (messageObject1.isVoice() || messageObject1.isMusic())) {
                    cell2.updateButtonState(false, true);
                }
            }
            return;
        }
        if (id == NotificationCenter.messagePlayingProgressDidChanged) {
            MessageObject messageObject2 = MediaController.getInstance().getPlayingMessageObject();
            if (messageObject2 != null && messageObject2.isMusic()) {
                updateProgress(messageObject2);
                return;
            }
            return;
        }
        if (id == NotificationCenter.musicDidLoad) {
            this.playlist = MediaController.getInstance().getPlaylist();
            this.listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLayout() {
        if (this.listView.getChildCount() <= 0) {
            return;
        }
        View child = this.listView.getChildAt(0);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findContainingViewHolder(child);
        int top = child.getTop();
        int newOffset = (top <= 0 || holder == null || holder.getAdapterPosition() != 0) ? 0 : top;
        if (this.searchWas || this.searching) {
            newOffset = 0;
        }
        if (this.scrollOffsetY != newOffset) {
            RecyclerListView recyclerListView = this.listView;
            this.scrollOffsetY = newOffset;
            recyclerListView.setTopGlowOffset(newOffset);
            this.playerLayout.setTranslationY(Math.max(this.actionBar.getMeasuredHeight(), this.scrollOffsetY));
            this.placeholderImageView.setTranslationY(Math.max(this.actionBar.getMeasuredHeight(), this.scrollOffsetY));
            this.shadow2.setTranslationY(Math.max(this.actionBar.getMeasuredHeight(), this.scrollOffsetY) + this.playerLayout.getMeasuredHeight());
            this.containerView.invalidate();
            if ((this.inFullSize && this.scrollOffsetY <= this.actionBar.getMeasuredHeight()) || this.searchWas) {
                if (this.actionBar.getTag() == null) {
                    AnimatorSet animatorSet = this.actionBarAnimation;
                    if (animatorSet != null) {
                        animatorSet.cancel();
                    }
                    this.actionBar.setTag(1);
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.actionBarAnimation = animatorSet2;
                    animatorSet2.playTogether(ObjectAnimator.ofFloat(this.actionBar, "alpha", 1.0f), ObjectAnimator.ofFloat(this.shadow, "alpha", 1.0f), ObjectAnimator.ofFloat(this.shadow2, "alpha", 1.0f));
                    this.actionBarAnimation.setDuration(180L);
                    this.actionBarAnimation.start();
                }
            } else if (this.actionBar.getTag() != null) {
                AnimatorSet animatorSet3 = this.actionBarAnimation;
                if (animatorSet3 != null) {
                    animatorSet3.cancel();
                }
                this.actionBar.setTag(null);
                AnimatorSet animatorSet4 = new AnimatorSet();
                this.actionBarAnimation = animatorSet4;
                animatorSet4.playTogether(ObjectAnimator.ofFloat(this.actionBar, "alpha", 0.0f), ObjectAnimator.ofFloat(this.shadow, "alpha", 0.0f), ObjectAnimator.ofFloat(this.shadow2, "alpha", 0.0f));
                this.actionBarAnimation.setDuration(180L);
                this.actionBarAnimation.start();
            }
        }
        this.startTranslation = Math.max(this.actionBar.getMeasuredHeight(), this.scrollOffsetY);
        this.panelStartTranslation = Math.max(this.actionBar.getMeasuredHeight(), this.scrollOffsetY);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        super.dismiss();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidStart);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.musicDidLoad);
        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
    }

    @Override // android.app.Dialog
    public void onBackPressed() {
        ActionBar actionBar = this.actionBar;
        if (actionBar != null && actionBar.isSearchFieldVisible()) {
            this.actionBar.closeSearchField();
        } else {
            super.onBackPressed();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onFailedDownload(String fileName, boolean canceled) {
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onSuccessDownload(String fileName) {
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressDownload(String fileName, float progress) {
        this.progressView.setProgress(progress, true);
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public int getObserverTag() {
        return this.TAG;
    }

    private void updateShuffleButton() {
        boolean z = SharedConfig.shuffleMusic;
        String str = Theme.key_player_button;
        if (z) {
            Drawable drawable = getContext().getResources().getDrawable(R.drawable.pl_shuffle).mutate();
            drawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_buttonActive), PorterDuff.Mode.MULTIPLY));
            this.shuffleButton.setIcon(drawable);
            this.shuffleButton.setContentDescription(LocaleController.getString("Shuffle", R.string.Shuffle));
        } else {
            Drawable drawable2 = getContext().getResources().getDrawable(R.drawable.music_reverse).mutate();
            if (SharedConfig.playOrderReversed) {
                drawable2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_buttonActive), PorterDuff.Mode.MULTIPLY));
            } else {
                drawable2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_button), PorterDuff.Mode.MULTIPLY));
            }
            this.shuffleButton.setIcon(drawable2);
            this.shuffleButton.setContentDescription(LocaleController.getString("ReverseOrder", R.string.ReverseOrder));
        }
        this.playOrderButtons[0].setColorFilter(new PorterDuffColorFilter(Theme.getColor(SharedConfig.playOrderReversed ? Theme.key_player_buttonActive : Theme.key_player_button), PorterDuff.Mode.MULTIPLY));
        Drawable drawable3 = this.playOrderButtons[1];
        if (SharedConfig.shuffleMusic) {
            str = Theme.key_player_buttonActive;
        }
        drawable3.setColorFilter(new PorterDuffColorFilter(Theme.getColor(str), PorterDuff.Mode.MULTIPLY));
    }

    private void updateRepeatButton() {
        int mode = SharedConfig.repeatMode;
        if (mode == 0) {
            this.repeatButton.setImageResource(R.drawable.pl_repeat);
            this.repeatButton.setTag(Theme.key_player_button);
            this.repeatButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_button), PorterDuff.Mode.MULTIPLY));
            this.repeatButton.setContentDescription(LocaleController.getString("AccDescrRepeatOff", R.string.AccDescrRepeatOff));
            return;
        }
        if (mode == 1) {
            this.repeatButton.setImageResource(R.drawable.pl_repeat);
            this.repeatButton.setTag(Theme.key_player_buttonActive);
            this.repeatButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_buttonActive), PorterDuff.Mode.MULTIPLY));
            this.repeatButton.setContentDescription(LocaleController.getString("AccDescrRepeatList", R.string.AccDescrRepeatList));
            return;
        }
        if (mode == 2) {
            this.repeatButton.setImageResource(R.drawable.pl_repeat1);
            this.repeatButton.setTag(Theme.key_player_buttonActive);
            this.repeatButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_player_buttonActive), PorterDuff.Mode.MULTIPLY));
            this.repeatButton.setContentDescription(LocaleController.getString("AccDescrRepeatOne", R.string.AccDescrRepeatOne));
        }
    }

    private void updateProgress(MessageObject messageObject) {
        SeekBarView seekBarView = this.seekBarView;
        if (seekBarView != null) {
            if (!seekBarView.isDragging()) {
                this.seekBarView.setProgress(messageObject.audioProgress);
                this.seekBarView.setBufferedProgress(messageObject.bufferedProgress);
            }
            if (this.lastTime != messageObject.audioProgressSec) {
                this.lastTime = messageObject.audioProgressSec;
                this.timeTextView.setText(String.format("%d:%02d", Integer.valueOf(messageObject.audioProgressSec / 60), Integer.valueOf(messageObject.audioProgressSec % 60)));
            }
        }
    }

    private void checkIfMusicDownloaded(MessageObject messageObject) {
        File cacheFile = null;
        if (messageObject.messageOwner.attachPath != null && messageObject.messageOwner.attachPath.length() > 0) {
            cacheFile = new File(messageObject.messageOwner.attachPath);
            if (!cacheFile.exists()) {
                cacheFile = null;
            }
        }
        if (cacheFile == null) {
            cacheFile = FileLoader.getPathToMessage(messageObject.messageOwner);
        }
        boolean canStream = SharedConfig.streamMedia && ((int) messageObject.getDialogId()) != 0 && messageObject.isMusic();
        if (!cacheFile.exists() && !canStream) {
            String fileName = messageObject.getFileName();
            DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this);
            Float progress = ImageLoader.getInstance().getFileProgress(fileName);
            this.progressView.setProgress(progress != null ? progress.floatValue() : 0.0f, false);
            this.progressView.setVisibility(0);
            this.seekBarView.setVisibility(4);
            this.playButton.setEnabled(false);
            return;
        }
        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
        this.progressView.setVisibility(4);
        this.seekBarView.setVisibility(0);
        this.playButton.setEnabled(true);
    }

    private void updateTitle(boolean shutdown) {
        MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
        if ((messageObject == null && shutdown) || (messageObject != null && !messageObject.isMusic())) {
            dismiss();
            return;
        }
        if (messageObject == null) {
            return;
        }
        if (messageObject.eventId != 0 || messageObject.getId() <= -2000000000) {
            this.hasOptions = false;
            this.menuItem.setVisibility(4);
            this.optionsButton.setVisibility(4);
        } else {
            this.hasOptions = true;
            if (!this.actionBar.isSearchFieldVisible()) {
                this.menuItem.setVisibility(0);
            }
            this.optionsButton.setVisibility(0);
        }
        checkIfMusicDownloaded(messageObject);
        updateProgress(messageObject);
        if (MediaController.getInstance().isMessagePaused()) {
            ImageView imageView = this.playButton;
            imageView.setImageDrawable(Theme.createSimpleSelectorDrawable(imageView.getContext(), R.drawable.pl_play, Theme.getColor(Theme.key_player_button), Theme.getColor(Theme.key_player_buttonActive)));
            this.playButton.setContentDescription(LocaleController.getString("AccActionPlay", R.string.AccActionPlay));
        } else {
            ImageView imageView2 = this.playButton;
            imageView2.setImageDrawable(Theme.createSimpleSelectorDrawable(imageView2.getContext(), R.drawable.pl_pause, Theme.getColor(Theme.key_player_button), Theme.getColor(Theme.key_player_buttonActive)));
            this.playButton.setContentDescription(LocaleController.getString("AccActionPause", R.string.AccActionPause));
        }
        String title = messageObject.getMusicTitle();
        String author = messageObject.getMusicAuthor();
        this.titleTextView.setText(title);
        this.authorTextView.setText(author);
        this.actionBar.setTitle(title);
        this.actionBar.setSubtitle(author);
        String str = author + " " + title;
        AudioInfo audioInfo = MediaController.getInstance().getAudioInfo();
        if (audioInfo != null && audioInfo.getCover() != null) {
            this.hasNoCover = 0;
            this.placeholderImageView.setImageBitmap(audioInfo.getCover());
        } else {
            String artworkUrl = messageObject.getArtworkUrl(false);
            if (!TextUtils.isEmpty(artworkUrl)) {
                this.placeholderImageView.setImage(artworkUrl, null, null);
                this.hasNoCover = 2;
            } else {
                this.placeholderImageView.setImageDrawable(null);
                this.hasNoCover = 1;
            }
            this.placeholderImageView.invalidate();
        }
        if (this.durationTextView != null) {
            int duration = messageObject.getDuration();
            this.durationTextView.setText(duration != 0 ? String.format("%d:%02d", Integer.valueOf(duration / 60), Integer.valueOf(duration % 60)) : "-:--");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private ArrayList<MessageObject> searchResult = new ArrayList<>();
        private Timer searchTimer;

        public ListAdapter(Context context) {
            this.context = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (AudioPlayerAlert.this.searchWas) {
                return this.searchResult.size();
            }
            return AudioPlayerAlert.this.searching ? AudioPlayerAlert.this.playlist.size() : AudioPlayerAlert.this.playlist.size() + 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return AudioPlayerAlert.this.searchWas || holder.getAdapterPosition() > 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new View(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(178.0f)));
            } else {
                view = new AudioPlayerCell(this.context);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 1) {
                AudioPlayerCell cell = (AudioPlayerCell) holder.itemView;
                if (!AudioPlayerAlert.this.searchWas) {
                    if (AudioPlayerAlert.this.searching) {
                        if (SharedConfig.playOrderReversed) {
                            cell.setMessageObject((MessageObject) AudioPlayerAlert.this.playlist.get(position));
                            return;
                        } else {
                            cell.setMessageObject((MessageObject) AudioPlayerAlert.this.playlist.get((AudioPlayerAlert.this.playlist.size() - position) - 1));
                            return;
                        }
                    }
                    if (position > 0) {
                        if (SharedConfig.playOrderReversed) {
                            cell.setMessageObject((MessageObject) AudioPlayerAlert.this.playlist.get(position - 1));
                            return;
                        } else {
                            cell.setMessageObject((MessageObject) AudioPlayerAlert.this.playlist.get(AudioPlayerAlert.this.playlist.size() - position));
                            return;
                        }
                    }
                    return;
                }
                cell.setMessageObject(this.searchResult.get(position));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            return (AudioPlayerAlert.this.searchWas || AudioPlayerAlert.this.searching || i != 0) ? 1 : 0;
        }

        public void search(final String query) {
            try {
                if (this.searchTimer != null) {
                    this.searchTimer.cancel();
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (query == null) {
                this.searchResult.clear();
                notifyDataSetChanged();
            } else {
                Timer timer = new Timer();
                this.searchTimer = timer;
                timer.schedule(new TimerTask() { // from class: im.uwrkaxlmjj.ui.components.AudioPlayerAlert.ListAdapter.1
                    @Override // java.util.TimerTask, java.lang.Runnable
                    public void run() {
                        try {
                            ListAdapter.this.searchTimer.cancel();
                            ListAdapter.this.searchTimer = null;
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                        ListAdapter.this.processSearch(query);
                    }
                }, 200L, 300L);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void processSearch(final String query) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$ListAdapter$_nOkoNDZ1ecNskU65Kmt2MkYxeI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processSearch$1$AudioPlayerAlert$ListAdapter(query);
                }
            });
        }

        public /* synthetic */ void lambda$processSearch$1$AudioPlayerAlert$ListAdapter(final String query) {
            final ArrayList<MessageObject> copy = new ArrayList<>(AudioPlayerAlert.this.playlist);
            Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$ListAdapter$9T7JrjTYq9GyVV5v_2dlWrlwUWw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$AudioPlayerAlert$ListAdapter(query, copy);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$AudioPlayerAlert$ListAdapter(String query, ArrayList copy) {
            TLRPC.Document document;
            String search1 = query.trim().toLowerCase();
            if (search1.length() == 0) {
                updateSearchResults(new ArrayList<>());
                return;
            }
            String search2 = LocaleController.getInstance().getTranslitString(search1);
            if (search1.equals(search2) || search2.length() == 0) {
                search2 = null;
            }
            String[] search = new String[(search2 != null ? 1 : 0) + 1];
            search[0] = search1;
            if (search2 != null) {
                search[1] = search2;
            }
            ArrayList<MessageObject> resultArray = new ArrayList<>();
            for (int a = 0; a < copy.size(); a++) {
                MessageObject messageObject = (MessageObject) copy.get(a);
                int b = 0;
                while (true) {
                    if (b < search.length) {
                        String q = search[b];
                        String name = messageObject.getDocumentName();
                        if (name != null && name.length() != 0) {
                            if (name.toLowerCase().contains(q)) {
                                resultArray.add(messageObject);
                                break;
                            }
                            if (messageObject.type == 0) {
                                document = messageObject.messageOwner.media.webpage.document;
                            } else {
                                document = messageObject.messageOwner.media.document;
                            }
                            boolean ok = false;
                            int c = 0;
                            while (true) {
                                if (c >= document.attributes.size()) {
                                    break;
                                }
                                TLRPC.DocumentAttribute attribute = document.attributes.get(c);
                                if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                                    c++;
                                } else {
                                    if (attribute.performer != null) {
                                        ok = attribute.performer.toLowerCase().contains(q);
                                    }
                                    if (!ok && attribute.title != null) {
                                        ok = attribute.title.toLowerCase().contains(q);
                                    }
                                }
                            }
                            if (ok) {
                                resultArray.add(messageObject);
                                break;
                            }
                        }
                        b++;
                    }
                }
            }
            updateSearchResults(resultArray);
        }

        private void updateSearchResults(final ArrayList<MessageObject> documents) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AudioPlayerAlert$ListAdapter$zzk6bM5L2aC5lvKhvzB0MipXF68
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$2$AudioPlayerAlert$ListAdapter(documents);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$2$AudioPlayerAlert$ListAdapter(ArrayList documents) {
            AudioPlayerAlert.this.searchWas = true;
            this.searchResult = documents;
            notifyDataSetChanged();
            AudioPlayerAlert.this.layoutManager.scrollToPosition(0);
        }
    }
}
