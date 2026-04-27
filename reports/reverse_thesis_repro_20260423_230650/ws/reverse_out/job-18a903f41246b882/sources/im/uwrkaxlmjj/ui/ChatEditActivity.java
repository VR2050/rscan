package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Vibrator;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Property;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.RadioButtonCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextDetailCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.EditTextEmoji;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatEditActivity extends BaseFragment implements ImageUpdater.ImageUpdaterDelegate, NotificationCenter.NotificationCenterDelegate {
    private static final int done_button = 1;
    private TextCell adminCell;
    private TLRPC.FileLocation avatar;
    private AnimatorSet avatarAnimation;
    private TLRPC.FileLocation avatarBig;
    private LinearLayout avatarContainer;
    private AvatarDrawable avatarDrawable;
    private ImageView avatarEditor;
    private BackupImageView avatarImage;
    private View avatarOverlay;
    private RadialProgressView avatarProgressView;
    private TextCell blockCell;
    private int chatId;
    private boolean createAfterUpload;
    private TLRPC.Chat currentChat;
    private TextSettingsCell deleteCell;
    private FrameLayout deleteContainer;
    private EditTextBoldCursor descriptionTextView;
    private View doneButton;
    private boolean donePressed;
    private TextDetailCell historyCell;
    private boolean historyHidden;
    private ImageUpdater imageUpdater;
    private TLRPC.ChatFull info;
    private LinearLayout infoContainer;
    private boolean isChannel;
    private TextDetailCell linkedCell;
    private TextDetailCell locationCell;
    private TextCell logCell;
    private TextCell membersCell;
    private EditTextEmoji nameTextView;
    private AlertDialog progressDialog;
    private LinearLayout settingsContainer;
    private TextCheckCell signCell;
    private boolean signMessages;
    private TextSettingsCell stickersCell;
    private FrameLayout stickersContainer;
    private TextInfoPrivacyCell stickersInfoCell3;
    private TextDetailCell typeCell;
    private LinearLayout typeEditContainer;
    private TLRPC.InputFile uploadedAvatar;

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList, boolean z, int i) {
        ImageUpdater.ImageUpdaterDelegate.CC.$default$didSelectPhotos(this, arrayList, z, i);
    }

    public ChatEditActivity(Bundle args) {
        super(args);
        this.avatarDrawable = new AvatarDrawable();
        this.imageUpdater = new ImageUpdater();
        this.chatId = args.getInt("chat_id", 0);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chatId));
        this.currentChat = chat;
        if (chat == null) {
            TLRPC.Chat chatSync = MessagesStorage.getInstance(this.currentAccount).getChatSync(this.chatId);
            this.currentChat = chatSync;
            if (chatSync == null) {
                return false;
            }
            MessagesController.getInstance(this.currentAccount).putChat(this.currentChat, true);
            if (this.info == null) {
                TLRPC.ChatFull chatFullLoadChatInfo = MessagesStorage.getInstance(this.currentAccount).loadChatInfo(this.chatId, new CountDownLatch(1), false, false);
                this.info = chatFullLoadChatInfo;
                if (chatFullLoadChatInfo == null) {
                    return false;
                }
            }
        }
        this.isChannel = ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup;
        this.imageUpdater.parentFragment = this;
        this.imageUpdater.delegate = this;
        this.signMessages = this.currentChat.signatures;
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.chatInfoDidLoad);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null) {
            imageUpdater.clear();
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.chatInfoDidLoad);
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
        EditTextEmoji editTextEmoji = this.nameTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onDestroy();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        EditTextEmoji editTextEmoji = this.nameTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onResume();
            this.nameTextView.getEditText().requestFocus();
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
        updateFields(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        EditTextEmoji editTextEmoji = this.nameTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onPause();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        EditTextEmoji editTextEmoji = this.nameTextView;
        if (editTextEmoji != null && editTextEmoji.isPopupShowing()) {
            this.nameTextView.hidePopup(true);
            return false;
        }
        return checkDiscard();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(final Context context) {
        int i;
        int i2;
        TLRPC.ChatFull chatFull;
        boolean z;
        TLRPC.ChatFull chatFull2;
        TLRPC.ChatFull chatFull3;
        EditTextEmoji editTextEmoji = this.nameTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onDestroy();
        }
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (ChatEditActivity.this.checkDiscard()) {
                        ChatEditActivity.this.finishFragment();
                    }
                } else if (id == 1) {
                    ChatEditActivity.this.processDone();
                }
            }
        });
        SizeNotifierFrameLayout sizeNotifierFrameLayout = new SizeNotifierFrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.2
            private boolean ignoreLayout;

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize);
                int heightSize2 = heightSize - getPaddingTop();
                measureChildWithMargins(ChatEditActivity.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
                int keyboardSize = getKeyboardHeight();
                if (keyboardSize > AndroidUtilities.dp(20.0f)) {
                    this.ignoreLayout = true;
                    ChatEditActivity.this.nameTextView.hideEmojiView();
                    this.ignoreLayout = false;
                }
                int childCount = getChildCount();
                for (int i3 = 0; i3 < childCount; i3++) {
                    View child = getChildAt(i3);
                    if (child != null && child.getVisibility() != 8 && child != ChatEditActivity.this.actionBar) {
                        if (ChatEditActivity.this.nameTextView != null && ChatEditActivity.this.nameTextView.isPopupView(child)) {
                            if (AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) {
                                if (AndroidUtilities.isTablet()) {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(AndroidUtilities.isTablet() ? 200.0f : 320.0f), (heightSize2 - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                                } else {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec((heightSize2 - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
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
                int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) ? 0 : ChatEditActivity.this.nameTextView.getEmojiPadding();
                setBottomClip(paddingBottom);
                for (int i3 = 0; i3 < count; i3++) {
                    View child = getChildAt(i3);
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
                        int i4 = absoluteGravity & 7;
                        if (i4 == 1) {
                            int childLeft2 = r - l;
                            childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                        } else if (i4 == 5) {
                            int childLeft3 = r - width;
                            childLeft = childLeft3 - lp.rightMargin;
                        } else {
                            childLeft = lp.leftMargin;
                        }
                        if (verticalGravity == 16) {
                            int childTop2 = b - paddingBottom;
                            childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                        } else if (verticalGravity == 48) {
                            int childTop3 = lp.topMargin;
                            childTop = childTop3 + getPaddingTop();
                        } else if (verticalGravity == 80) {
                            int childTop4 = b - paddingBottom;
                            childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                        } else {
                            childTop = lp.topMargin;
                        }
                        if (ChatEditActivity.this.nameTextView != null && ChatEditActivity.this.nameTextView.isPopupView(child)) {
                            if (AndroidUtilities.isTablet()) {
                                childTop = getMeasuredHeight() - child.getMeasuredHeight();
                            } else {
                                childTop = (getMeasuredHeight() + getKeyboardHeight()) - child.getMeasuredHeight();
                            }
                        }
                        child.layout(childLeft, childTop, childLeft + width, childTop + height);
                    }
                }
                notifyHeightChanged();
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        sizeNotifierFrameLayout.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$1G149vVg768G_2-lt-qEPXVt-gE
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ChatEditActivity.lambda$createView$0(view, motionEvent);
            }
        });
        this.fragmentView = sizeNotifierFrameLayout;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        ScrollView scrollView = new ScrollView(context);
        sizeNotifierFrameLayout.addView(scrollView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        LinearLayout linearLayout1 = new LinearLayout(context);
        GradientDrawable divider = (GradientDrawable) context.getResources().getDrawable(R.drawable.shape_transaction_list_divider);
        divider.setColor(Theme.getColor(Theme.key_windowBackgroundGray));
        linearLayout1.setDividerDrawable(divider);
        linearLayout1.setShowDividers(2);
        linearLayout1.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        scrollView.addView(linearLayout1, new FrameLayout.LayoutParams(-1, -2));
        linearLayout1.setOrientation(1);
        this.actionBar.setTitle(LocaleController.getString("ChannelEdit", R.string.ChannelEdit));
        LinearLayout linearLayout = new LinearLayout(context);
        this.avatarContainer = linearLayout;
        linearLayout.setOrientation(1);
        linearLayout1.addView(this.avatarContainer, LayoutHelper.createLinear(-1, -2));
        FrameLayout frameLayout = new FrameLayout(context);
        this.avatarContainer.addView(frameLayout, LayoutHelper.createLinear(-1, 65));
        BackupImageView backupImageView = new BackupImageView(context) { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.3
            @Override // android.view.View
            public void invalidate() {
                if (ChatEditActivity.this.avatarOverlay != null) {
                    ChatEditActivity.this.avatarOverlay.invalidate();
                }
                super.invalidate();
            }

            @Override // android.view.View
            public void invalidate(int l, int t, int r, int b) {
                if (ChatEditActivity.this.avatarOverlay != null) {
                    ChatEditActivity.this.avatarOverlay.invalidate();
                }
                super.invalidate(l, t, r, b);
            }
        };
        this.avatarImage = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        frameLayout.addView(this.avatarImage, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
        if (!ChatObject.canChangeChatInfo(this.currentChat)) {
            this.avatarDrawable.setInfo(5, this.currentChat.title, null);
        } else {
            this.avatarDrawable.setInfo(5, null, null);
            final Paint paint = new Paint(1);
            paint.setColor(1426063360);
            View view = new View(context) { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.4
                @Override // android.view.View
                protected void onDraw(Canvas canvas) {
                    if (ChatEditActivity.this.avatarImage != null && ChatEditActivity.this.avatarImage.getImageReceiver().hasNotThumb()) {
                        paint.setAlpha((int) (ChatEditActivity.this.avatarImage.getImageReceiver().getCurrentAlpha() * 85.0f));
                        canvas.drawCircle(getMeasuredWidth() / 2, getMeasuredHeight() / 2, AndroidUtilities.dp(7.5f), paint);
                    }
                }
            };
            this.avatarOverlay = view;
            frameLayout.addView(view, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
            this.avatarOverlay.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$DKiBs30-xO6tMnUbo3chk8oT0WE
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$2$ChatEditActivity(view2);
                }
            });
            this.avatarOverlay.setContentDescription(LocaleController.getString("ChoosePhoto", R.string.ChoosePhoto));
            ImageView imageView = new ImageView(context) { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.5
                @Override // android.view.View
                public void invalidate(int l, int t, int r, int b) {
                    super.invalidate(l, t, r, b);
                    ChatEditActivity.this.avatarOverlay.invalidate();
                }

                @Override // android.view.View
                public void invalidate() {
                    super.invalidate();
                    ChatEditActivity.this.avatarOverlay.invalidate();
                }
            };
            this.avatarEditor = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.avatarEditor.setImageResource(R.drawable.menu_camera_av);
            this.avatarEditor.setEnabled(false);
            this.avatarEditor.setClickable(false);
            frameLayout.addView(this.avatarEditor, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
            RadialProgressView radialProgressView = new RadialProgressView(context);
            this.avatarProgressView = radialProgressView;
            radialProgressView.setSize(AndroidUtilities.dp(30.0f));
            this.avatarProgressView.setProgressColor(-1);
            frameLayout.addView(this.avatarProgressView, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
            showAvatarProgress(false, false);
        }
        EditTextEmoji editTextEmoji2 = new EditTextEmoji(context, sizeNotifierFrameLayout, this, 0);
        this.nameTextView = editTextEmoji2;
        if (this.isChannel) {
            editTextEmoji2.setHint(LocaleController.getString("EnterChannelName", R.string.EnterChannelName));
        } else {
            editTextEmoji2.setHint(LocaleController.getString("GroupName", R.string.GroupName));
        }
        this.nameTextView.setEnabled(ChatObject.canChangeChatInfo(this.currentChat));
        this.nameTextView.hideEditBackgroup();
        EditTextEmoji editTextEmoji3 = this.nameTextView;
        editTextEmoji3.setFocusable(editTextEmoji3.isEnabled());
        InputFilter[] inputFilters = {new InputFilter.LengthFilter(100)};
        this.nameTextView.setFilters(inputFilters);
        frameLayout.addView(this.nameTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 16, LocaleController.isRTL ? 5.0f : 96.0f, 0.0f, LocaleController.isRTL ? 96.0f : 5.0f, 0.0f));
        LinearLayout linearLayout2 = new LinearLayout(context);
        this.settingsContainer = linearLayout2;
        linearLayout2.setOrientation(1);
        linearLayout1.addView(this.settingsContainer, LayoutHelper.createLinear(-1, -2));
        EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
        this.descriptionTextView = editTextBoldCursor;
        editTextBoldCursor.setTextSize(1, 16.0f);
        this.descriptionTextView.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.descriptionTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.descriptionTextView.setPadding(AndroidUtilities.dp(23.0f), AndroidUtilities.dp(12.0f), AndroidUtilities.dp(23.0f), AndroidUtilities.dp(12.0f));
        this.descriptionTextView.setBackgroundDrawable(null);
        this.descriptionTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        this.descriptionTextView.setInputType(180225);
        this.descriptionTextView.setImeOptions(6);
        this.descriptionTextView.setEnabled(ChatObject.canChangeChatInfo(this.currentChat));
        EditTextBoldCursor editTextBoldCursor2 = this.descriptionTextView;
        editTextBoldCursor2.setFocusable(editTextBoldCursor2.isEnabled());
        InputFilter[] inputFilters2 = {new InputFilter.LengthFilter(255)};
        this.descriptionTextView.setFilters(inputFilters2);
        this.descriptionTextView.setHint(LocaleController.getString("DescriptionOptionalPlaceholder", R.string.DescriptionOptionalPlaceholder));
        this.descriptionTextView.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.descriptionTextView.setCursorSize(AndroidUtilities.dp(20.0f));
        this.descriptionTextView.setCursorWidth(1.5f);
        this.settingsContainer.addView(this.descriptionTextView, LayoutHelper.createLinear(-1, -2));
        this.descriptionTextView.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$Hl_g4cC8gvv1ZXxGnU05FGT9wGU
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i3, KeyEvent keyEvent) {
                return this.f$0.lambda$createView$3$ChatEditActivity(textView, i3, keyEvent);
            }
        });
        this.descriptionTextView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.6
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i3, int i22, int i32) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int i3, int i22, int i32) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
            }
        });
        LinearLayout linearLayout3 = new LinearLayout(context);
        this.typeEditContainer = linearLayout3;
        linearLayout3.setOrientation(1);
        linearLayout1.addView(this.typeEditContainer, LayoutHelper.createLinear(-1, -2));
        if (this.currentChat.megagroup && ((chatFull3 = this.info) == null || chatFull3.can_set_location)) {
            TextDetailCell textDetailCell = new TextDetailCell(context);
            this.locationCell = textDetailCell;
            textDetailCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            this.typeEditContainer.addView(this.locationCell, LayoutHelper.createLinear(-1, -2));
            this.locationCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$vacVvnt8Wa_ZeJDQ1wfzGR3z-tk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$4$ChatEditActivity(view2);
                }
            });
        }
        if (this.currentChat.creator && ((chatFull2 = this.info) == null || chatFull2.can_set_username)) {
            TextDetailCell textDetailCell2 = new TextDetailCell(context);
            this.typeCell = textDetailCell2;
            textDetailCell2.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            this.typeEditContainer.addView(this.typeCell, LayoutHelper.createLinear(-1, -2));
            this.typeCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$d57bFr69H6ZIx3Tt6plxk_e-2k8
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$5$ChatEditActivity(view2);
                }
            });
        }
        if (ChatObject.isChannel(this.currentChat)) {
            if (this.isChannel && ChatObject.canUserDoAdminAction(this.currentChat, 1)) {
                z = false;
            } else {
                TLRPC.ChatFull chatFull4 = this.info;
                if (chatFull4 != null && !this.isChannel && chatFull4.linked_chat_id != 0) {
                    z = false;
                    if (ChatObject.canUserDoAdminAction(this.currentChat, 0)) {
                    }
                }
            }
            TextDetailCell textDetailCell3 = new TextDetailCell(context);
            this.linkedCell = textDetailCell3;
            textDetailCell3.setBackgroundDrawable(Theme.getSelectorDrawable(z));
            this.typeEditContainer.addView(this.linkedCell, LayoutHelper.createLinear(-1, -2));
            this.linkedCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$pJQBFHMQjxSgjBuR95Q_4VqIUEw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$6$ChatEditActivity(view2);
                }
            });
        }
        if (!this.isChannel && ChatObject.canBlockUsers(this.currentChat) && (ChatObject.isChannel(this.currentChat) || this.currentChat.creator)) {
            TextDetailCell textDetailCell4 = new TextDetailCell(context);
            this.historyCell = textDetailCell4;
            textDetailCell4.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            this.historyCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$4P-baZnRPF1BW5DDH0xeIQt30rw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$8$ChatEditActivity(context, view2);
                }
            });
        }
        if (this.isChannel) {
            TextCheckCell textCheckCell = new TextCheckCell(context);
            this.signCell = textCheckCell;
            textCheckCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            this.signCell.setTextAndValueAndCheck(LocaleController.getString("ChannelSignMessages", R.string.ChannelSignMessages), LocaleController.getString("ChannelSignMessagesInfo", R.string.ChannelSignMessagesInfo), this.signMessages, true, false);
            this.typeEditContainer.addView(this.signCell, LayoutHelper.createFrame(-1, -2.0f));
            this.signCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$AFV96LOFBhg4vafioUCuYxc-4Bs
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$9$ChatEditActivity(view2);
                }
            });
        }
        if (this.typeEditContainer.getChildCount() == 0) {
            this.typeEditContainer.setVisibility(8);
        }
        ActionBarMenu menu = this.actionBar.createMenu();
        if (ChatObject.canChangeChatInfo(this.currentChat) || this.signCell != null || this.historyCell != null) {
            ActionBarMenuItem actionBarMenuItemAddItemWithWidth = menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f));
            this.doneButton = actionBarMenuItemAddItemWithWidth;
            actionBarMenuItemAddItemWithWidth.setContentDescription(LocaleController.getString("Done", R.string.Done));
        }
        LinearLayout linearLayout4 = new LinearLayout(context);
        this.infoContainer = linearLayout4;
        linearLayout4.setOrientation(1);
        linearLayout1.addView(this.infoContainer, LayoutHelper.createLinear(-1, -2));
        TextCell textCell = new TextCell(context);
        this.blockCell = textCell;
        textCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        this.blockCell.setVisibility((ChatObject.isChannel(this.currentChat) || this.currentChat.creator) ? 0 : 8);
        this.blockCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$32E5incQaItvnwG_wi2THlLvM2A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$createView$10$ChatEditActivity(view2);
            }
        });
        TextCell textCell2 = new TextCell(context);
        this.adminCell = textCell2;
        textCell2.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        this.adminCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$6-fO0wlswfe5zyl5ybkkywK8O1A
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$createView$11$ChatEditActivity(view2);
            }
        });
        TextCell textCell3 = new TextCell(context);
        this.membersCell = textCell3;
        textCell3.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        this.membersCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$lV1EjHzOW2G_fbKRoE5quCG2bqk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$createView$12$ChatEditActivity(view2);
            }
        });
        if (ChatObject.isChannel(this.currentChat)) {
            TextCell textCell4 = new TextCell(context);
            this.logCell = textCell4;
            textCell4.setTextAndIcon(LocaleController.getString("EventLog", R.string.EventLog), R.drawable.group_log, false);
            this.logCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            this.logCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$ZnhqT9FdrO-FacNPH2ydm2Q53sc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$13$ChatEditActivity(view2);
                }
            });
        }
        if (!this.isChannel) {
            i = -2;
            i2 = -1;
            this.infoContainer.addView(this.blockCell, LayoutHelper.createLinear(-1, -2));
        } else {
            i = -2;
            i2 = -1;
        }
        this.infoContainer.addView(this.adminCell, LayoutHelper.createLinear(i2, i));
        this.infoContainer.addView(this.membersCell, LayoutHelper.createLinear(i2, i));
        if (this.isChannel) {
            this.infoContainer.addView(this.blockCell, LayoutHelper.createLinear(i2, i));
        }
        TextCell textCell5 = this.logCell;
        if (textCell5 != null) {
            this.infoContainer.addView(textCell5, LayoutHelper.createLinear(i2, i));
        }
        if (!ChatObject.hasAdminRights(this.currentChat)) {
            this.infoContainer.setVisibility(8);
        }
        if (!this.isChannel && (chatFull = this.info) != null && chatFull.can_set_stickers) {
            FrameLayout frameLayout2 = new FrameLayout(context);
            this.stickersContainer = frameLayout2;
            linearLayout1.addView(frameLayout2, LayoutHelper.createLinear(-1, -2));
            TextSettingsCell textSettingsCell = new TextSettingsCell(context);
            this.stickersCell = textSettingsCell;
            textSettingsCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.stickersCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            this.stickersContainer.addView(this.stickersCell, LayoutHelper.createFrame(-1, -2.0f));
            this.stickersCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$A0ReAGnV75kUx5dLpQO4LJazJn4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$14$ChatEditActivity(view2);
                }
            });
            TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(context);
            this.stickersInfoCell3 = textInfoPrivacyCell;
            textInfoPrivacyCell.setText(LocaleController.getString("GroupStickersInfo", R.string.GroupStickersInfo));
            linearLayout1.addView(this.stickersInfoCell3, LayoutHelper.createLinear(-1, -2));
        }
        if (this.currentChat.creator) {
            FrameLayout frameLayout3 = new FrameLayout(context);
            this.deleteContainer = frameLayout3;
            linearLayout1.addView(frameLayout3, LayoutHelper.createLinear(-1, -2));
            TextSettingsCell textSettingsCell2 = new TextSettingsCell(context);
            this.deleteCell = textSettingsCell2;
            textSettingsCell2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText5));
            this.deleteCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            if (this.isChannel) {
                this.deleteCell.setText(LocaleController.getString("ChannelDelete", R.string.ChannelDelete), false);
            } else if (this.currentChat.megagroup) {
                this.deleteCell.setText(LocaleController.getString("DeleteMega", R.string.DeleteMega), false);
            } else {
                this.deleteCell.setText(LocaleController.getString("DeleteAndExitButton", R.string.DeleteAndExitButton), false);
            }
            this.deleteContainer.addView(this.deleteCell, LayoutHelper.createFrame(-1, -2.0f));
            this.deleteCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$nk5ymqfHgnOOYqy_7QOHyOFslVs
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$16$ChatEditActivity(view2);
                }
            });
        }
        this.nameTextView.setText(this.currentChat.title);
        EditTextEmoji editTextEmoji4 = this.nameTextView;
        editTextEmoji4.setSelection(editTextEmoji4.length());
        TLRPC.ChatFull chatFull5 = this.info;
        if (chatFull5 != null) {
            this.descriptionTextView.setText(chatFull5.about);
        }
        if (this.currentChat.photo != null) {
            this.avatar = this.currentChat.photo.photo_small;
            this.avatarBig = this.currentChat.photo.photo_big;
            this.avatarImage.setImage(ImageLocation.getForChat(this.currentChat, false), "50_50", this.avatarDrawable, this.currentChat);
        } else {
            this.avatarImage.setImageDrawable(this.avatarDrawable);
        }
        updateFields(true);
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$0(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$2$ChatEditActivity(View view) {
        this.imageUpdater.openMenu(this.avatar != null, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$8BZbtzCZL5iRw0bj9vwXDn0vlqw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$ChatEditActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$1$ChatEditActivity() {
        this.avatar = null;
        this.avatarBig = null;
        this.uploadedAvatar = null;
        showAvatarProgress(false, true);
        this.avatarImage.setImage((ImageLocation) null, (String) null, this.avatarDrawable, this.currentChat);
    }

    public /* synthetic */ boolean lambda$createView$3$ChatEditActivity(TextView textView, int i, KeyEvent keyEvent) {
        View view;
        if (i == 6 && (view = this.doneButton) != null) {
            view.performClick();
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createView$4$ChatEditActivity(View v) {
        if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"}, 2);
        }
    }

    public /* synthetic */ void lambda$createView$5$ChatEditActivity(View v) {
        int i = this.chatId;
        TextDetailCell textDetailCell = this.locationCell;
        ChatEditTypeActivity fragment = new ChatEditTypeActivity(i, textDetailCell != null && textDetailCell.getVisibility() == 0);
        fragment.setInfo(this.info);
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$createView$6$ChatEditActivity(View v) {
        ChatLinkActivity fragment = new ChatLinkActivity(this.chatId);
        fragment.setInfo(this.info);
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$createView$8$ChatEditActivity(Context context, View v) {
        final BottomSheet.Builder builder = new BottomSheet.Builder(context);
        builder.setApplyTopPadding(false);
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        HeaderCell headerCell = new HeaderCell(context, true, 23, 15, false);
        headerCell.setHeight(47);
        headerCell.setText(LocaleController.getString("ChatHistory", R.string.ChatHistory));
        linearLayout.addView(headerCell);
        LinearLayout linearLayoutInviteContainer = new LinearLayout(context);
        linearLayoutInviteContainer.setOrientation(1);
        linearLayout.addView(linearLayoutInviteContainer, LayoutHelper.createLinear(-1, -2));
        final RadioButtonCell[] buttons = new RadioButtonCell[2];
        int a = 0;
        for (int i = 2; a < i; i = 2) {
            buttons[a] = new RadioButtonCell(context, true);
            buttons[a].setTag(Integer.valueOf(a));
            buttons[a].setBackgroundDrawable(Theme.getSelectorDrawable(false));
            if (a == 0) {
                buttons[a].setTextAndValue(LocaleController.getString("ChatHistoryVisible", R.string.ChatHistoryVisible), LocaleController.getString("ChatHistoryVisibleInfo", R.string.ChatHistoryVisibleInfo), true, !this.historyHidden);
            } else if (ChatObject.isChannel(this.currentChat)) {
                buttons[a].setTextAndValue(LocaleController.getString("ChatHistoryHidden", R.string.ChatHistoryHidden), LocaleController.getString("ChatHistoryHiddenInfo", R.string.ChatHistoryHiddenInfo), false, this.historyHidden);
            } else {
                buttons[a].setTextAndValue(LocaleController.getString("ChatHistoryHidden", R.string.ChatHistoryHidden), LocaleController.getString("ChatHistoryHiddenInfo2", R.string.ChatHistoryHiddenInfo2), false, this.historyHidden);
            }
            linearLayoutInviteContainer.addView(buttons[a], LayoutHelper.createLinear(-1, -2));
            buttons[a].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$UdaBA4yFUjyX6qKxjY6GTHRPYlw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$null$7$ChatEditActivity(buttons, builder, view);
                }
            });
            a++;
        }
        builder.setCustomView(linearLayout);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$null$7$ChatEditActivity(RadioButtonCell[] buttons, BottomSheet.Builder builder, View v2) {
        Integer tag = (Integer) v2.getTag();
        buttons[0].setChecked(tag.intValue() == 0, true);
        buttons[1].setChecked(tag.intValue() == 1, true);
        this.historyHidden = tag.intValue() == 1;
        builder.getDismissRunnable().run();
        updateFields(true);
    }

    public /* synthetic */ void lambda$createView$9$ChatEditActivity(View v) {
        boolean z = !this.signMessages;
        this.signMessages = z;
        ((TextCheckCell) v).setChecked(z);
    }

    public /* synthetic */ void lambda$createView$10$ChatEditActivity(View v) {
        Bundle args = new Bundle();
        args.putInt("chat_id", this.chatId);
        args.putInt("type", !this.isChannel ? 3 : 0);
        ChatUsersActivity fragment = new ChatUsersActivity(args);
        fragment.setInfo(this.info);
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$createView$11$ChatEditActivity(View v) {
        Bundle args = new Bundle();
        args.putInt("chat_id", this.chatId);
        args.putInt("type", 1);
        ChatUsersActivity fragment = new ChatUsersActivity(args);
        fragment.setInfo(this.info);
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$createView$12$ChatEditActivity(View v) {
        Bundle args = new Bundle();
        args.putInt("chat_id", this.chatId);
        args.putInt("type", 2);
        ChatUsersActivity fragment = new ChatUsersActivity(args);
        fragment.setInfo(this.info);
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$createView$13$ChatEditActivity(View v) {
        presentFragment(new ChannelAdminLogActivity(this.currentChat));
    }

    public /* synthetic */ void lambda$createView$14$ChatEditActivity(View v) {
        GroupStickersActivity groupStickersActivity = new GroupStickersActivity(this.currentChat.id);
        groupStickersActivity.setInfo(this.info);
        presentFragment(groupStickersActivity);
    }

    public /* synthetic */ void lambda$createView$16$ChatEditActivity(View v) {
        AlertsCreator.createClearOrDeleteDialogAlert(this, false, true, false, this.currentChat, null, false, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$187KFVs6_JAc6Y7PPvEh0btJuIA
            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
            public final void run(boolean z) {
                this.f$0.lambda$null$15$ChatEditActivity(z);
            }
        });
    }

    public /* synthetic */ void lambda$null$15$ChatEditActivity(boolean param) {
        if (AndroidUtilities.isTablet()) {
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, Long.valueOf(-this.chatId));
        } else {
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        }
        MessagesController.getInstance(this.currentAccount).deleteUserFromChat(this.chatId, MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId())), this.info, true, false);
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        EditTextBoldCursor editTextBoldCursor;
        if (id == NotificationCenter.chatInfoDidLoad) {
            TLRPC.ChatFull chatFull = (TLRPC.ChatFull) args[0];
            if (chatFull.id == this.chatId) {
                if (this.info == null && (editTextBoldCursor = this.descriptionTextView) != null) {
                    editTextBoldCursor.setText(chatFull.about);
                }
                this.info = chatFull;
                this.historyHidden = !ChatObject.isChannel(this.currentChat) || this.info.hidden_prehistory;
                updateFields(true);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didUploadPhoto(final TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$L1Ul5Z9QFqmZxidj4qnWbGWe6XM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didUploadPhoto$17$ChatEditActivity(file, smallSize, bigSize);
            }
        });
    }

    public /* synthetic */ void lambda$didUploadPhoto$17$ChatEditActivity(TLRPC.InputFile file, TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
        if (file != null) {
            this.uploadedAvatar = file;
            if (this.createAfterUpload) {
                try {
                    if (this.progressDialog != null && this.progressDialog.isShowing()) {
                        this.progressDialog.dismiss();
                        this.progressDialog = null;
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
                this.donePressed = false;
                this.doneButton.performClick();
            }
            showAvatarProgress(false, true);
            return;
        }
        this.avatar = smallSize.location;
        this.avatarBig = bigSize.location;
        this.avatarImage.setImage(ImageLocation.getForLocal(this.avatar), "50_50", this.avatarDrawable, this.currentChat);
        showAvatarProgress(true, false);
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public String getInitialSearchString() {
        return this.nameTextView.getText().toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkDiscard() {
        EditTextBoldCursor editTextBoldCursor;
        TLRPC.ChatFull chatFull = this.info;
        String about = (chatFull == null || chatFull.about == null) ? "" : this.info.about;
        if ((this.info != null && ChatObject.isChannel(this.currentChat) && this.info.hidden_prehistory != this.historyHidden) || this.imageUpdater.uploadingImage != null || ((this.nameTextView != null && !this.currentChat.title.equals(this.nameTextView.getText().toString())) || (((editTextBoldCursor = this.descriptionTextView) != null && !about.equals(editTextBoldCursor.getText().toString())) || this.signMessages != this.currentChat.signatures || this.uploadedAvatar != null || (this.avatar == null && (this.currentChat.photo instanceof TLRPC.TL_chatPhoto))))) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("UserRestrictionsApplyChanges", R.string.UserRestrictionsApplyChanges));
            if (this.isChannel) {
                builder.setMessage(LocaleController.getString("ChannelSettingsChangedAlert", R.string.ChannelSettingsChangedAlert));
            } else {
                builder.setMessage(LocaleController.getString("GroupSettingsChangedAlert", R.string.GroupSettingsChangedAlert));
            }
            builder.setPositiveButton(LocaleController.getString("ApplyTheme", R.string.ApplyTheme), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$Xmggr-T2T2h-yqmtt7VZOj8VlRg
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$18$ChatEditActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("PassportDiscard", R.string.PassportDiscard), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$G9xEVPa5EVIBi5-j7JA42tV_4dI
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$19$ChatEditActivity(dialogInterface, i);
                }
            });
            showDialog(builder.create());
            return false;
        }
        return true;
    }

    public /* synthetic */ void lambda$checkDiscard$18$ChatEditActivity(DialogInterface dialogInterface, int i) {
        processDone();
    }

    public /* synthetic */ void lambda$checkDiscard$19$ChatEditActivity(DialogInterface dialog, int which) {
        finishFragment();
    }

    private int getAdminCount() {
        TLRPC.ChatFull chatFull = this.info;
        if (chatFull == null) {
            return 1;
        }
        int count = 0;
        int N = chatFull.participants.participants.size();
        for (int a = 0; a < N; a++) {
            TLRPC.ChatParticipant chatParticipant = this.info.participants.participants.get(a);
            if ((chatParticipant instanceof TLRPC.TL_chatParticipantAdmin) || (chatParticipant instanceof TLRPC.TL_chatParticipantCreator)) {
                count++;
            }
        }
        return count;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processDone() {
        EditTextEmoji editTextEmoji;
        if (this.donePressed || (editTextEmoji = this.nameTextView) == null) {
            return;
        }
        if (editTextEmoji.length() == 0) {
            Vibrator v = (Vibrator) getParentActivity().getSystemService("vibrator");
            if (v != null) {
                v.vibrate(200L);
            }
            AndroidUtilities.shakeView(this.nameTextView, 2.0f, 0);
            return;
        }
        this.donePressed = true;
        if (!ChatObject.isChannel(this.currentChat) && !this.historyHidden) {
            MessagesController.getInstance(this.currentAccount).convertToMegaGroup(getParentActivity(), this.chatId, this, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$Ry8Y8V32tkqR7hZtQsmWoilMNUQ
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                public final void run(int i) {
                    this.f$0.lambda$processDone$20$ChatEditActivity(i);
                }
            });
            return;
        }
        if (this.info != null && ChatObject.isChannel(this.currentChat)) {
            boolean z = this.info.hidden_prehistory;
            boolean z2 = this.historyHidden;
            if (z != z2) {
                this.info.hidden_prehistory = z2;
                MessagesController.getInstance(this.currentAccount).toogleChannelInvitesHistory(this.chatId, this.historyHidden);
            }
        }
        if (this.imageUpdater.uploadingImage != null) {
            this.createAfterUpload = true;
            AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
            this.progressDialog = alertDialog;
            alertDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$1_KEr0VIg9YKDUX5qQCZPEf4V2k
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    this.f$0.lambda$processDone$21$ChatEditActivity(dialogInterface);
                }
            });
            this.progressDialog.show();
            return;
        }
        if (!this.currentChat.title.equals(this.nameTextView.getText().toString())) {
            MessagesController.getInstance(this.currentAccount).changeChatTitle(this.chatId, this.nameTextView.getText().toString());
        }
        TLRPC.ChatFull chatFull = this.info;
        String about = (chatFull == null || chatFull.about == null) ? "" : this.info.about;
        EditTextBoldCursor editTextBoldCursor = this.descriptionTextView;
        if (editTextBoldCursor != null && !about.equals(editTextBoldCursor.getText().toString())) {
            MessagesController.getInstance(this.currentAccount).updateChatAbout(this.chatId, this.descriptionTextView.getText().toString(), this.info);
        }
        if (this.signMessages != this.currentChat.signatures) {
            this.currentChat.signatures = true;
            MessagesController.getInstance(this.currentAccount).toogleChannelSignatures(this.chatId, this.signMessages);
        }
        if (this.uploadedAvatar != null) {
            MessagesController.getInstance(this.currentAccount).changeChatAvatar(this.chatId, this.uploadedAvatar, this.avatar, this.avatarBig);
        } else if (this.avatar == null && (this.currentChat.photo instanceof TLRPC.TL_chatPhoto)) {
            MessagesController.getInstance(this.currentAccount).changeChatAvatar(this.chatId, null, null, null);
        }
        finishFragment();
    }

    public /* synthetic */ void lambda$processDone$20$ChatEditActivity(int param) {
        this.chatId = param;
        this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(param));
        this.donePressed = false;
        TLRPC.ChatFull chatFull = this.info;
        if (chatFull != null) {
            chatFull.hidden_prehistory = true;
        }
        processDone();
    }

    public /* synthetic */ void lambda$processDone$21$ChatEditActivity(DialogInterface dialog) {
        this.createAfterUpload = false;
        this.progressDialog = null;
        this.donePressed = false;
    }

    private void showAvatarProgress(final boolean show, boolean animated) {
        if (this.avatarEditor == null) {
            return;
        }
        AnimatorSet animatorSet = this.avatarAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.avatarAnimation = null;
        }
        if (animated) {
            this.avatarAnimation = new AnimatorSet();
            if (show) {
                this.avatarProgressView.setVisibility(0);
                this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.avatarEditor, (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.avatarProgressView, (Property<RadialProgressView, Float>) View.ALPHA, 1.0f));
            } else {
                this.avatarEditor.setVisibility(0);
                this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.avatarEditor, (Property<ImageView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.avatarProgressView, (Property<RadialProgressView, Float>) View.ALPHA, 0.0f));
            }
            this.avatarAnimation.setDuration(180L);
            this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatEditActivity.7
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatEditActivity.this.avatarAnimation == null || ChatEditActivity.this.avatarEditor == null) {
                        return;
                    }
                    if (show) {
                        ChatEditActivity.this.avatarEditor.setVisibility(4);
                    } else {
                        ChatEditActivity.this.avatarProgressView.setVisibility(4);
                    }
                    ChatEditActivity.this.avatarAnimation = null;
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    ChatEditActivity.this.avatarAnimation = null;
                }
            });
            this.avatarAnimation.start();
            return;
        }
        if (show) {
            this.avatarEditor.setAlpha(1.0f);
            this.avatarEditor.setVisibility(4);
            this.avatarProgressView.setAlpha(1.0f);
            this.avatarProgressView.setVisibility(0);
            return;
        }
        this.avatarEditor.setAlpha(1.0f);
        this.avatarEditor.setVisibility(0);
        this.avatarProgressView.setAlpha(0.0f);
        this.avatarProgressView.setVisibility(4);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        this.imageUpdater.onActivityResult(requestCode, resultCode, data);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        String text;
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null && imageUpdater.currentPicturePath != null) {
            args.putString("path", this.imageUpdater.currentPicturePath);
        }
        EditTextEmoji editTextEmoji = this.nameTextView;
        if (editTextEmoji != null && (text = editTextEmoji.getText().toString()) != null && text.length() != 0) {
            args.putString("nameTextView", text);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null) {
            imageUpdater.currentPicturePath = args.getString("path");
        }
    }

    public void setInfo(TLRPC.ChatFull chatFull) {
        this.info = chatFull;
        if (chatFull != null) {
            if (this.currentChat == null) {
                this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chatId));
            }
            this.historyHidden = !ChatObject.isChannel(this.currentChat) || this.info.hidden_prehistory;
        }
    }

    private void updateFields(boolean updateChat) {
        TLRPC.ChatFull chatFull;
        int i;
        String str;
        int i2;
        String str2;
        String type;
        TextDetailCell textDetailCell;
        TextDetailCell textDetailCell2;
        int i3;
        String str3;
        String link;
        TextDetailCell textDetailCell3;
        TLRPC.ChatFull chatFull2;
        TLRPC.Chat chat;
        if (updateChat && (chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chatId))) != null) {
            this.currentChat = chat;
        }
        boolean isPrivate = TextUtils.isEmpty(this.currentChat.username);
        TextDetailCell textDetailCell4 = this.historyCell;
        if (textDetailCell4 != null) {
            textDetailCell4.setVisibility(8);
        }
        TextCell textCell = this.logCell;
        if (textCell != null) {
            textCell.setVisibility((!this.currentChat.megagroup || ((chatFull2 = this.info) != null && chatFull2.participants_count > 200)) ? 0 : 8);
        }
        if (this.linkedCell != null) {
            TLRPC.ChatFull chatFull3 = this.info;
            if (chatFull3 == null || (!this.isChannel && chatFull3.linked_chat_id == 0)) {
                this.linkedCell.setVisibility(8);
            } else {
                this.linkedCell.setVisibility(0);
                if (this.info.linked_chat_id != 0) {
                    TLRPC.Chat chat2 = getMessagesController().getChat(Integer.valueOf(this.info.linked_chat_id));
                    if (chat2 == null) {
                        this.linkedCell.setVisibility(8);
                    } else if (this.isChannel) {
                        if (TextUtils.isEmpty(chat2.username)) {
                            this.linkedCell.setTextAndValue(LocaleController.getString("Discussion", R.string.Discussion), chat2.title, true);
                        } else {
                            this.linkedCell.setTextAndValue(LocaleController.getString("Discussion", R.string.Discussion), "@" + chat2.username, true);
                        }
                    } else if (TextUtils.isEmpty(chat2.username)) {
                        this.linkedCell.setTextAndValue(LocaleController.getString("LinkedChannel", R.string.LinkedChannel), chat2.title, false);
                    } else {
                        this.linkedCell.setTextAndValue(LocaleController.getString("LinkedChannel", R.string.LinkedChannel), "@" + chat2.username, false);
                    }
                } else {
                    this.linkedCell.setTextAndValue(LocaleController.getString("Discussion", R.string.Discussion), LocaleController.getString("DiscussionInfo", R.string.DiscussionInfo), true);
                }
            }
        }
        if (this.locationCell != null) {
            TLRPC.ChatFull chatFull4 = this.info;
            if (chatFull4 != null && chatFull4.can_set_location) {
                this.locationCell.setVisibility(0);
                if (this.info.location instanceof TLRPC.TL_channelLocation) {
                    TLRPC.TL_channelLocation location = (TLRPC.TL_channelLocation) this.info.location;
                    this.locationCell.setTextAndValue(LocaleController.getString("AttachLocation", R.string.AttachLocation), location.address, true);
                } else {
                    this.locationCell.setTextAndValue(LocaleController.getString("AttachLocation", R.string.AttachLocation), "Unknown address", true);
                }
            } else {
                this.locationCell.setVisibility(8);
            }
        }
        if (this.typeCell != null) {
            TLRPC.ChatFull chatFull5 = this.info;
            if (chatFull5 != null && (chatFull5.location instanceof TLRPC.TL_channelLocation)) {
                if (isPrivate) {
                    link = LocaleController.getString("TypeLocationGroupEdit", R.string.TypeLocationGroupEdit);
                } else {
                    link = String.format(DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(this.currentAccount).linkPrefix + "/%s", this.currentChat.username);
                }
                TextDetailCell textDetailCell5 = this.typeCell;
                String string = LocaleController.getString("TypeLocationGroup", R.string.TypeLocationGroup);
                TextDetailCell textDetailCell6 = this.historyCell;
                textDetailCell5.setTextAndValue(string, link, (textDetailCell6 != null && textDetailCell6.getVisibility() == 0) || ((textDetailCell3 = this.linkedCell) != null && textDetailCell3.getVisibility() == 0));
            } else {
                if (this.isChannel) {
                    if (isPrivate) {
                        i3 = R.string.TypePrivate;
                        str3 = "TypePrivate";
                    } else {
                        i3 = R.string.TypePublic;
                        str3 = "TypePublic";
                    }
                    type = LocaleController.getString(str3, i3);
                } else {
                    if (isPrivate) {
                        i2 = R.string.TypePrivateGroup;
                        str2 = "TypePrivateGroup";
                    } else {
                        i2 = R.string.TypePublicGroup;
                        str2 = "TypePublicGroup";
                    }
                    type = LocaleController.getString(str2, i2);
                }
                if (this.isChannel) {
                    TextDetailCell textDetailCell7 = this.typeCell;
                    String string2 = LocaleController.getString("ChannelType", R.string.ChannelType);
                    TextDetailCell textDetailCell8 = this.historyCell;
                    textDetailCell7.setTextAndValue(string2, type, (textDetailCell8 != null && textDetailCell8.getVisibility() == 0) || ((textDetailCell2 = this.linkedCell) != null && textDetailCell2.getVisibility() == 0));
                } else {
                    TextDetailCell textDetailCell9 = this.typeCell;
                    String string3 = LocaleController.getString("GroupType", R.string.GroupType);
                    TextDetailCell textDetailCell10 = this.historyCell;
                    textDetailCell9.setTextAndValue(string3, type, (textDetailCell10 != null && textDetailCell10.getVisibility() == 0) || ((textDetailCell = this.linkedCell) != null && textDetailCell.getVisibility() == 0));
                }
            }
        }
        if (this.info != null && this.historyCell != null) {
            if (this.historyHidden) {
                i = R.string.ChatHistoryHidden;
                str = "ChatHistoryHidden";
            } else {
                i = R.string.ChatHistoryVisible;
                str = "ChatHistoryVisible";
            }
            String type2 = LocaleController.getString(str, i);
            this.historyCell.setTextAndValue(LocaleController.getString("ChatHistory", R.string.ChatHistory), type2, false);
        }
        if (this.stickersCell != null) {
            if (this.info.stickerset != null) {
                this.stickersCell.setTextAndValue(LocaleController.getString("GroupStickers", R.string.GroupStickers), this.info.stickerset.title, false);
            } else {
                this.stickersCell.setText(LocaleController.getString("GroupStickers", R.string.GroupStickers), false);
            }
        }
        TextCell textCell2 = this.membersCell;
        if (textCell2 != null) {
            if (this.info != null) {
                if (this.isChannel) {
                    textCell2.setTextAndValueAndIcon(LocaleController.getString("ChannelSubscribers", R.string.ChannelSubscribers), String.format("%d", Integer.valueOf(this.info.participants_count)), R.drawable.actions_viewmembers, true);
                    TextCell textCell3 = this.blockCell;
                    String string4 = LocaleController.getString("ChannelBlacklist", R.string.ChannelBlacklist);
                    String str4 = String.format("%d", Integer.valueOf(Math.max(this.info.banned_count, this.info.kicked_count)));
                    TextCell textCell4 = this.logCell;
                    textCell3.setTextAndValueAndIcon(string4, str4, R.drawable.actions_removed, textCell4 != null && textCell4.getVisibility() == 0);
                } else {
                    if (ChatObject.isChannel(this.currentChat)) {
                        TextCell textCell5 = this.membersCell;
                        String string5 = LocaleController.getString("ChannelMembers", R.string.ChannelMembers);
                        String str5 = String.format("%d", Integer.valueOf(this.info.participants_count));
                        TextCell textCell6 = this.logCell;
                        textCell5.setTextAndValueAndIcon(string5, str5, R.drawable.actions_viewmembers, textCell6 != null && textCell6.getVisibility() == 0);
                    } else {
                        TextCell textCell7 = this.membersCell;
                        String string6 = LocaleController.getString("ChannelMembers", R.string.ChannelMembers);
                        String str6 = String.format("%d", Integer.valueOf(this.info.participants.participants.size()));
                        TextCell textCell8 = this.logCell;
                        textCell7.setTextAndValueAndIcon(string6, str6, R.drawable.actions_viewmembers, textCell8 != null && textCell8.getVisibility() == 0);
                    }
                    int count = 0;
                    if (this.currentChat.default_banned_rights != null) {
                        if (!this.currentChat.default_banned_rights.send_stickers) {
                            count = 0 + 1;
                        }
                        if (!this.currentChat.default_banned_rights.send_media) {
                            count++;
                        }
                        if (!this.currentChat.default_banned_rights.embed_links) {
                            count++;
                        }
                        if (!this.currentChat.default_banned_rights.send_messages) {
                            count++;
                        }
                        if (!this.currentChat.default_banned_rights.pin_messages) {
                            count++;
                        }
                        if (!this.currentChat.default_banned_rights.send_polls) {
                            count++;
                        }
                        if (!this.currentChat.default_banned_rights.invite_users) {
                            count++;
                        }
                        if (!this.currentChat.default_banned_rights.change_info) {
                            count++;
                        }
                    } else {
                        count = 8;
                    }
                    this.blockCell.setTextAndValueAndIcon(LocaleController.getString("ChannelPermissions", R.string.ChannelPermissions), String.format("%d/%d", Integer.valueOf(count), 8), R.drawable.actions_permissions, true);
                }
                TextCell textCell9 = this.adminCell;
                String string7 = LocaleController.getString("ChannelAdministrators", R.string.ChannelAdministrators);
                Object[] objArr = new Object[1];
                objArr[0] = Integer.valueOf(ChatObject.isChannel(this.currentChat) ? this.info.admins_count : getAdminCount());
                textCell9.setTextAndValueAndIcon(string7, String.format("%d", objArr), R.drawable.actions_addadmin, true);
            } else {
                if (this.isChannel) {
                    textCell2.setTextAndIcon(LocaleController.getString("ChannelSubscribers", R.string.ChannelSubscribers), R.drawable.actions_viewmembers, true);
                    TextCell textCell10 = this.blockCell;
                    String string8 = LocaleController.getString("ChannelBlacklist", R.string.ChannelBlacklist);
                    TextCell textCell11 = this.logCell;
                    textCell10.setTextAndIcon(string8, R.drawable.actions_removed, textCell11 != null && textCell11.getVisibility() == 0);
                } else {
                    String string9 = LocaleController.getString("ChannelMembers", R.string.ChannelMembers);
                    TextCell textCell12 = this.logCell;
                    textCell2.setTextAndIcon(string9, R.drawable.actions_viewmembers, textCell12 != null && textCell12.getVisibility() == 0);
                    this.blockCell.setTextAndIcon(LocaleController.getString("ChannelPermissions", R.string.ChannelPermissions), R.drawable.actions_permissions, true);
                }
                this.adminCell.setTextAndIcon(LocaleController.getString("ChannelAdministrators", R.string.ChannelAdministrators), R.drawable.actions_addadmin, true);
            }
        }
        if (this.stickersCell != null && (chatFull = this.info) != null) {
            if (chatFull.stickerset != null) {
                this.stickersCell.setTextAndValue(LocaleController.getString("GroupStickers", R.string.GroupStickers), this.info.stickerset.title, false);
            } else {
                this.stickersCell.setText(LocaleController.getString("GroupStickers", R.string.GroupStickers), false);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatEditActivity$I1WXZ6PNZuwRYoTClu8JZyR50mY
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$22$ChatEditActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.membersCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.membersCell, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.membersCell, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.adminCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.adminCell, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.adminCell, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.blockCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.blockCell, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.blockCell, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.logCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.logCell, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.logCell, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.typeCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.typeCell, 0, new Class[]{TextDetailCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.typeCell, 0, new Class[]{TextDetailCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.historyCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.historyCell, 0, new Class[]{TextDetailCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.historyCell, 0, new Class[]{TextDetailCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.locationCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.locationCell, 0, new Class[]{TextDetailCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.locationCell, 0, new Class[]{TextDetailCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.nameTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.nameTextView, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.nameTextView, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField), new ThemeDescription(this.nameTextView, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated), new ThemeDescription(this.descriptionTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.descriptionTextView, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.avatarContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.settingsContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.typeEditContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.deleteContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.stickersContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.infoContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.signCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.signCell, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.signCell, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.signCell, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.deleteCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.deleteCell, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText5), new ThemeDescription(this.stickersCell, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.stickersCell, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.stickersInfoCell3, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.stickersInfoCell3, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.avatar_savedDrawable}, cellDelegate, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$22$ChatEditActivity() {
        if (this.avatarImage != null) {
            this.avatarDrawable.setInfo(5, null, null);
            this.avatarImage.invalidate();
        }
    }
}
