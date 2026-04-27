package im.uwrkaxlmjj.ui.hui.chats;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Vibrator;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Property;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.SpanUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.GroupCreateUserCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hcells.AvatarDelCell;
import im.uwrkaxlmjj.ui.hcells.MryTextCheckCell;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CreateGroupFinalActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, ImageUpdater.ImageUpdaterDelegate {
    private final int CREATE_CHAT;
    private GroupCreateAdapter adapter;
    private TLRPC.FileLocation avatar;
    private AnimatorSet avatarAnimation;
    private TLRPC.FileLocation avatarBig;
    private AvatarDrawable avatarDrawable;
    private ImageView avatarEditor;
    private BackupImageView avatarImage;
    private ImageView avatarOverlay;
    private RadialProgressView avatarProgressView;
    private final int chatType;
    private boolean createAfterUpload;
    private final String currentGroupCreateAddress;
    private CreateGroupDelegate delegate;
    private boolean donePressed;
    private EditText editText;
    private FrameLayout editTextContainer;
    private MryTextCheckCell forbitContacts;
    private ImageUpdater imageUpdater;
    private GridLayoutManager layoutManager;
    private RecyclerListView listView;
    private Context mContext;
    private int maxCount;
    private MryTextView memberInfoCell;
    private String nameToSet;
    private MryTextView nextTextView;
    private int reqId;
    private ArrayList<Integer> selectedContacts;
    private Drawable shadowDrawable;
    private TLRPC.InputFile uploadedAvatar;

    public interface CreateGroupDelegate {
        void didFailChatCreation();

        void didFinishChatCreation(CreateGroupFinalActivity createGroupFinalActivity, int i);

        void didStartChatCreation();
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList, boolean z, int i) {
        ImageUpdater.ImageUpdaterDelegate.CC.$default$didSelectPhotos(this, arrayList, z, i);
    }

    public CreateGroupFinalActivity(Bundle args) {
        super(args);
        this.CREATE_CHAT = 1;
        this.maxCount = MessagesController.getInstance(this.currentAccount).maxMegagroupCount;
        this.chatType = args.getInt("chatType", 4);
        this.avatarDrawable = new AvatarDrawable();
        this.currentGroupCreateAddress = args.getString("address");
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.chatDidCreated);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.chatDidFailCreate);
        ImageUpdater imageUpdater = new ImageUpdater();
        this.imageUpdater = imageUpdater;
        imageUpdater.parentFragment = this;
        this.imageUpdater.delegate = this;
        if (getArguments() != null) {
            this.selectedContacts = getArguments().getIntegerArrayList("result");
            final ArrayList<Integer> usersToLoad = new ArrayList<>();
            for (int a = 0; a < this.selectedContacts.size(); a++) {
                Integer uid = this.selectedContacts.get(a);
                if (MessagesController.getInstance(this.currentAccount).getUser(uid) == null) {
                    usersToLoad.add(uid);
                }
            }
            if (!usersToLoad.isEmpty()) {
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                final ArrayList<TLRPC.User> users = new ArrayList<>();
                MessagesStorage.getInstance(this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$7W1wOfMSBHfx_YYYCx5t8BYld1c
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onFragmentCreate$0$CreateGroupFinalActivity(users, usersToLoad, countDownLatch);
                    }
                });
                try {
                    countDownLatch.await();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                if (usersToLoad.size() != users.size() || users.isEmpty()) {
                    return false;
                }
                for (TLRPC.User user : users) {
                    MessagesController.getInstance(this.currentAccount).putUser(user, true);
                }
            }
        }
        return super.onFragmentCreate();
    }

    public /* synthetic */ void lambda$onFragmentCreate$0$CreateGroupFinalActivity(ArrayList users, ArrayList usersToLoad, CountDownLatch countDownLatch) {
        users.addAll(MessagesStorage.getInstance(this.currentAccount).getUsers(usersToLoad));
        countDownLatch.countDown();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        GroupCreateAdapter groupCreateAdapter = this.adapter;
        if (groupCreateAdapter != null) {
            groupCreateAdapter.notifyDataSetChanged();
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.chatDidCreated);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.chatDidFailCreate);
        this.imageUpdater.clear();
        if (this.reqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.reqId, true);
        }
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        super.createView(context);
        this.mContext = context;
        initActionBar();
        SizeNotifierFrameLayout sizeNotifierFrameLayout = new SizeNotifierFrameLayout(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.1
            private boolean ignoreLayout;

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize);
                int paddingTop = heightSize - getPaddingTop();
                measureChildWithMargins(CreateGroupFinalActivity.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
                int keyboardSize = getKeyboardHeight();
                if (keyboardSize > AndroidUtilities.dp(20.0f)) {
                    this.ignoreLayout = true;
                    this.ignoreLayout = false;
                }
                int childCount = getChildCount();
                for (int i = 0; i < childCount; i++) {
                    View child = getChildAt(i);
                    if (child != null && child.getVisibility() != 8 && child != CreateGroupFinalActivity.this.actionBar) {
                        measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                int childLeft;
                int childTop;
                int count = getChildCount();
                setBottomClip(0);
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
                            int childTop2 = b - 0;
                            childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                        } else if (verticalGravity == 48) {
                            int childTop3 = lp.topMargin;
                            childTop = childTop3 + getPaddingTop();
                        } else if (verticalGravity == 80) {
                            int childTop4 = b - 0;
                            childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                        } else {
                            childTop = lp.topMargin;
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
        this.fragmentView = sizeNotifierFrameLayout;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.fragmentView.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
        this.fragmentView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$sUg5ag2AmuC6Q2oZUT1-lljLCqo
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return CreateGroupFinalActivity.lambda$createView$1(view, motionEvent);
            }
        });
        this.shadowDrawable = new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundGray));
        LinearLayout linearLayout = new LinearLayout(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.2
            @Override // android.view.ViewGroup
            protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                boolean result = super.drawChild(canvas, child, drawingTime);
                if (child == CreateGroupFinalActivity.this.listView && CreateGroupFinalActivity.this.shadowDrawable != null) {
                    int y = CreateGroupFinalActivity.this.editTextContainer.getMeasuredHeight();
                    CreateGroupFinalActivity.this.shadowDrawable.setBounds(0, y, getMeasuredWidth(), CreateGroupFinalActivity.this.shadowDrawable.getIntrinsicHeight() + y);
                    CreateGroupFinalActivity.this.shadowDrawable.draw(canvas);
                }
                return result;
            }
        };
        linearLayout.setOrientation(1);
        linearLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        sizeNotifierFrameLayout.addView(linearLayout, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f)));
        FrameLayout frameLayout = new FrameLayout(context);
        this.editTextContainer = frameLayout;
        linearLayout.addView(frameLayout, LayoutHelper.createLinear(-1, 65));
        BackupImageView backupImageView = new BackupImageView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.3
            @Override // android.view.View
            public void invalidate() {
                if (CreateGroupFinalActivity.this.avatarOverlay != null) {
                    CreateGroupFinalActivity.this.avatarOverlay.invalidate();
                }
                super.invalidate();
            }

            @Override // android.view.View
            public void invalidate(int l, int t, int r, int b) {
                if (CreateGroupFinalActivity.this.avatarOverlay != null) {
                    CreateGroupFinalActivity.this.avatarOverlay.invalidate();
                }
                super.invalidate(l, t, r, b);
            }
        };
        this.avatarImage = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.avatarImage.setImageDrawable(this.avatarDrawable);
        this.avatarImage.setContentDescription(LocaleController.getString("ChoosePhoto", R.string.ChoosePhoto));
        this.editTextContainer.addView(this.avatarImage, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
        Paint paint = new Paint(1);
        paint.setColor(1426063360);
        ImageView imageView = new ImageView(context);
        this.avatarOverlay = imageView;
        imageView.setImageResource(R.id.ic_create_group_photo);
        this.editTextContainer.addView(this.avatarOverlay, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
        this.avatarOverlay.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$GzGSB73LSuHzdgXNRtm4_Ga0bsQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$3$CreateGroupFinalActivity(view);
            }
        });
        AppCompatImageView appCompatImageView = new AppCompatImageView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.4
            @Override // android.view.View
            public void invalidate(int l, int t, int r, int b) {
                super.invalidate(l, t, r, b);
                CreateGroupFinalActivity.this.avatarOverlay.invalidate();
            }

            @Override // android.view.View
            public void invalidate() {
                super.invalidate();
                CreateGroupFinalActivity.this.avatarOverlay.invalidate();
            }
        };
        this.avatarEditor = appCompatImageView;
        appCompatImageView.setScaleType(ImageView.ScaleType.CENTER);
        this.avatarEditor.setEnabled(false);
        this.avatarEditor.setClickable(false);
        this.avatarEditor.setPadding(AndroidUtilities.dp(2.0f), 0, 0, 0);
        this.editTextContainer.addView(this.avatarEditor, LayoutHelper.createFrame(16.0f, 16.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
        RadialProgressView radialProgressView = new RadialProgressView(context) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.5
            @Override // im.uwrkaxlmjj.ui.components.RadialProgressView, android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                CreateGroupFinalActivity.this.avatarOverlay.invalidate();
            }
        };
        this.avatarProgressView = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(30.0f));
        this.avatarProgressView.setProgressColor(-1);
        this.editTextContainer.addView(this.avatarProgressView, LayoutHelper.createFrame(49.0f, 49.0f, (LocaleController.isRTL ? 5 : 3) | 16, LocaleController.isRTL ? 0.0f : 16.0f, 0.0f, LocaleController.isRTL ? 16.0f : 0.0f, 0.0f));
        showAvatarProgress(false, false);
        EditText editText = new EditText(context);
        this.editText = editText;
        editText.setBackgroundColor(0);
        this.editText.setHint(LocaleController.getString("EnterGroupNamePlaceholder", R.string.EnterGroupNamePlaceholder));
        this.editText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.editText.setHintTextColor(Theme.getColor(Theme.key_groupcreate_hintText));
        String str = this.nameToSet;
        if (str != null) {
            this.editText.setText(str);
            this.nameToSet = null;
        }
        InputFilter[] inputFilters = {new InputFilter.LengthFilter(100)};
        this.editText.setFilters(inputFilters);
        this.editText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.6
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                CreateGroupFinalActivity.this.updateNextView();
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
            }
        });
        this.editTextContainer.addView(this.editText, LayoutHelper.createFrame(-1.0f, -2.0f, 16, LocaleController.isRTL ? 5.0f : 96.0f, 0.0f, LocaleController.isRTL ? 96.0f : 5.0f, 0.0f));
        ShadowSectionCell shadowSectionCell = new ShadowSectionCell(context);
        linearLayout.addView(shadowSectionCell);
        MryTextCheckCell mryTextCheckCell = new MryTextCheckCell(context);
        this.forbitContacts = mryTextCheckCell;
        mryTextCheckCell.setBackground(Theme.getSelectorDrawable(false));
        linearLayout.addView(this.forbitContacts, LayoutHelper.createLinear(-1, AndroidUtilities.dp(48.0f)));
        this.forbitContacts.setTextAndCheck(LocaleController.getString("ForbidPrivateChat", R.string.ForbidPrivateChat), false, false);
        this.forbitContacts.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$3c_cluiip_fGOMCpAzZZ8qIODYM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$4$CreateGroupFinalActivity(view);
            }
        });
        MryTextView forbitContactsTips = new MryTextView(context);
        forbitContactsTips.setText(LocaleController.getString(R.string.ForbidPrivateChatTips));
        forbitContactsTips.setTextSize(13.0f);
        forbitContactsTips.setLineSpacing(AndroidUtilities.dp(5.0f), 1.0f);
        forbitContactsTips.setTextColor(Theme.getColor(Theme.key_graySectionText));
        forbitContactsTips.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        forbitContactsTips.setPadding(0, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f));
        linearLayout.addView(forbitContactsTips, LayoutHelper.createLinear(-1, -2));
        MryTextView mryTextView = new MryTextView(this.mContext);
        this.memberInfoCell = mryTextView;
        mryTextView.setGravity(16);
        this.memberInfoCell.setPadding(AndroidUtilities.dp(10.0f), 0, 0, 0);
        this.memberInfoCell.setTextSize(1, 14.0f);
        this.memberInfoCell.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.memberInfoCell.setTextColor(Theme.getColor(Theme.key_graySectionText));
        this.memberInfoCell.setText(new SpanUtils().append(LocaleController.getString("GroupMembers", R.string.GroupMembers)).append("  ").append(String.valueOf(this.selectedContacts.size())).setForegroundColor(-12862209).append("/").append(String.valueOf(this.maxCount)).create());
        this.memberInfoCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        linearLayout.addView(this.memberInfoCell, LayoutHelper.createLinear(-1, 36));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setPadding(0, AndroidUtilities.dp(10.0f), 0, 0);
        RecyclerListView recyclerListView2 = this.listView;
        GroupCreateAdapter groupCreateAdapter = new GroupCreateAdapter(context);
        this.adapter = groupCreateAdapter;
        recyclerListView2.setAdapter(groupCreateAdapter);
        RecyclerListView recyclerListView3 = this.listView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(context, 5) { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.7
            @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = gridLayoutManager;
        recyclerListView3.setLayoutManager(gridLayoutManager);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        linearLayout.addView(this.listView, LayoutHelper.createLinear(-1, -1));
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.8
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1) {
                    AndroidUtilities.hideKeyboard(CreateGroupFinalActivity.this.editText);
                }
            }
        });
        updateNextView();
        return this.fragmentView;
    }

    static /* synthetic */ boolean lambda$createView$1(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$3$CreateGroupFinalActivity(View view) {
        this.imageUpdater.openMenu(this.avatar != null, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$8rAH6K2qtjclrfl060d7jj9GqMQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$CreateGroupFinalActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$2$CreateGroupFinalActivity() {
        this.avatar = null;
        this.avatarBig = null;
        this.uploadedAvatar = null;
        showAvatarProgress(false, true);
        this.avatarImage.setImage((ImageLocation) null, (String) null, this.avatarDrawable, (Object) null);
    }

    public /* synthetic */ void lambda$createView$4$CreateGroupFinalActivity(View v) {
        this.forbitContacts.setChecked(!r0.isChecked());
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
            this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.9
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (CreateGroupFinalActivity.this.avatarAnimation == null || CreateGroupFinalActivity.this.avatarEditor == null) {
                        return;
                    }
                    if (show) {
                        CreateGroupFinalActivity.this.avatarEditor.setVisibility(4);
                    } else {
                        CreateGroupFinalActivity.this.avatarProgressView.setVisibility(4);
                    }
                    CreateGroupFinalActivity.this.avatarAnimation = null;
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    CreateGroupFinalActivity.this.avatarAnimation = null;
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

    public void setDelegate(CreateGroupDelegate delegate) {
        this.delegate = delegate;
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setCastShadows(true);
        this.actionBar.setTitle(LocaleController.getString("NewGroup", R.string.NewGroup));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.chats.CreateGroupFinalActivity.10
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == 1) {
                    CreateGroupFinalActivity.this.createChat();
                }
            }
        });
        this.actionBar.setBackTitle(LocaleController.getString("Cancel", R.string.Cancel));
        this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$_epY61tKGALpnxUYmZHtm7578Z8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$5$CreateGroupFinalActivity(view);
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView mryTextView = new MryTextView(getParentActivity());
        this.nextTextView = mryTextView;
        mryTextView.setText(LocaleController.getString("Create", R.string.Create));
        this.nextTextView.setTextSize(1, 14.0f);
        this.nextTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.nextTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        this.nextTextView.setGravity(17);
        menu.addItemView(1, this.nextTextView);
    }

    public /* synthetic */ void lambda$initActionBar$5$CreateGroupFinalActivity(View v) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createChat() {
        if (this.donePressed) {
            return;
        }
        if (this.editText.length() == 0) {
            Vibrator v = (Vibrator) getParentActivity().getSystemService("vibrator");
            if (v != null) {
                v.vibrate(200L);
            }
            AndroidUtilities.shakeView(this.editText, 2.0f, 0);
            return;
        }
        if (this.selectedContacts.size() <= 0) {
            Vibrator v2 = (Vibrator) getParentActivity().getSystemService("vibrator");
            if (v2 != null) {
                v2.vibrate(200L);
            }
            ToastUtils.show(R.string.AtLeastOneContact);
            return;
        }
        this.donePressed = true;
        AndroidUtilities.hideKeyboard(this.editText);
        this.editText.setEnabled(false);
        if (this.imageUpdater.uploadingImage != null) {
            this.createAfterUpload = true;
        } else {
            this.reqId = MessagesController.getInstance(this.currentAccount).createMegaGroup(this.editText.getText().toString(), this.selectedContacts, null, this.chatType, this, this.forbitContacts.isChecked());
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didUploadPhoto(final TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$69lstqNHhqAkkGgBy7tqyCvh-tQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didUploadPhoto$6$CreateGroupFinalActivity(file, smallSize, bigSize);
            }
        });
    }

    public /* synthetic */ void lambda$didUploadPhoto$6$CreateGroupFinalActivity(TLRPC.InputFile file, TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
        if (file != null) {
            this.uploadedAvatar = file;
            if (this.createAfterUpload) {
                CreateGroupDelegate createGroupDelegate = this.delegate;
                if (createGroupDelegate != null) {
                    createGroupDelegate.didStartChatCreation();
                }
                MessagesController.getInstance(this.currentAccount).createChat(this.editText.getText().toString(), this.selectedContacts, null, this.chatType, this);
            }
            showAvatarProgress(false, true);
            this.avatarEditor.setImageDrawable(null);
            return;
        }
        this.avatar = smallSize.location;
        this.avatarBig = bigSize.location;
        this.avatarImage.setImage(ImageLocation.getForLocal(this.avatar), "50_50", this.avatarDrawable, (Object) null);
        showAvatarProgress(true, false);
        this.avatarOverlay.setImageResource(0);
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public String getInitialSearchString() {
        return this.editText.getText().toString();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        String text;
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null && imageUpdater.currentPicturePath != null) {
            args.putString("path", this.imageUpdater.currentPicturePath);
        }
        EditText editText = this.editText;
        if (editText != null && (text = editText.getText().toString()) != null && text.length() != 0) {
            args.putString("nameTextView", text);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.imageUpdater;
        if (imageUpdater != null) {
            imageUpdater.currentPicturePath = args.getString("path");
        }
        String text = args.getString("nameTextView");
        if (text != null) {
            EditText editText = this.editText;
            if (editText != null) {
                editText.setText(text);
            } else {
                this.nameToSet = text;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.updateInterfaces) {
            if (this.listView == null) {
                return;
            }
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) {
                int count = this.listView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child = this.listView.getChildAt(a);
                    if (child instanceof GroupCreateUserCell) {
                        ((GroupCreateUserCell) child).update(mask);
                    }
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.chatDidFailCreate) {
            this.reqId = 0;
            this.donePressed = false;
            EditText editText = this.editText;
            if (editText != null) {
                editText.setEnabled(true);
            }
            CreateGroupDelegate createGroupDelegate = this.delegate;
            if (createGroupDelegate != null) {
                createGroupDelegate.didFailChatCreation();
                return;
            }
            return;
        }
        if (id == NotificationCenter.chatDidCreated) {
            this.reqId = 0;
            this.donePressed = false;
            int chat_id = ((Integer) args[0]).intValue();
            CreateGroupDelegate createGroupDelegate2 = this.delegate;
            if (createGroupDelegate2 != null) {
                createGroupDelegate2.didFinishChatCreation(this, chat_id);
            } else {
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
                Bundle args2 = new Bundle();
                args2.putInt("chat_id", chat_id);
                presentFragment(new ChatActivity(args2), true);
            }
            if (this.uploadedAvatar != null) {
                MessagesController.getInstance(this.currentAccount).changeChatAvatar(chat_id, this.uploadedAvatar, this.avatar, this.avatarBig);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        this.imageUpdater.onActivityResult(requestCode, resultCode, data);
    }

    public class GroupCreateAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int usersStartRow;

        public GroupCreateAdapter(Context ctx) {
            this.context = ctx;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = CreateGroupFinalActivity.this.selectedContacts.size();
            return count;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == 3;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View avatarDelCell;
            if (i != 0) {
                if (i == 1) {
                    HeaderCell headerCell = new HeaderCell(this.context);
                    headerCell.setHeight(46);
                    avatarDelCell = headerCell;
                } else if (i == 2) {
                    avatarDelCell = new AvatarDelCell(this.context);
                } else {
                    avatarDelCell = new TextSettingsCell(this.context);
                }
            } else {
                View shadowSectionCell = new ShadowSectionCell(this.context);
                CombinedDrawable combinedDrawable = new CombinedDrawable(new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundGray)), Theme.getThemedDrawable(this.context, R.drawable.greydivider_top, Theme.key_windowBackgroundGrayShadow));
                combinedDrawable.setFullsize(true);
                shadowSectionCell.setBackgroundDrawable(combinedDrawable);
                avatarDelCell = shadowSectionCell;
            }
            return new RecyclerListView.Holder(avatarDelCell);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, final int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 1) {
                HeaderCell cell = (HeaderCell) holder.itemView;
                if (position != 1) {
                    cell.setText(LocaleController.formatPluralString("Members", CreateGroupFinalActivity.this.selectedContacts.size()));
                    return;
                } else {
                    cell.setText(LocaleController.getString("AttachLocation", R.string.AttachLocation));
                    return;
                }
            }
            if (itemViewType != 2) {
                if (itemViewType == 3) {
                    ((TextSettingsCell) holder.itemView).setText("xxxxx", false);
                }
            } else {
                AvatarDelCell cell2 = (AvatarDelCell) holder.itemView;
                TLRPC.User user = MessagesController.getInstance(CreateGroupFinalActivity.this.currentAccount).getUser((Integer) CreateGroupFinalActivity.this.selectedContacts.get(position - this.usersStartRow));
                cell2.setUser(user);
                cell2.setDelegate(new AvatarDelCell.AvatarDelDelegate() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$CreateGroupFinalActivity$GroupCreateAdapter$PGCTNQNjeSivI2AZQ0a0HJtb2Bg
                    @Override // im.uwrkaxlmjj.ui.hcells.AvatarDelCell.AvatarDelDelegate
                    public final void onClickDelete() {
                        this.f$0.lambda$onBindViewHolder$0$CreateGroupFinalActivity$GroupCreateAdapter(position);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$CreateGroupFinalActivity$GroupCreateAdapter(int position) {
            CreateGroupFinalActivity.this.selectedContacts.remove(position);
            notifyDataSetChanged();
            CreateGroupFinalActivity.this.memberInfoCell.setText(new SpanUtils().append(LocaleController.getString("GroupMembers", R.string.GroupMembers)).append("  ").append(String.valueOf(CreateGroupFinalActivity.this.selectedContacts.size())).setForegroundColor(-12862209).append("/").append(String.valueOf(CreateGroupFinalActivity.this.maxCount)).create());
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            CreateGroupFinalActivity.this.updateNextView();
            super.notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return 2;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateNextView() {
        this.nextTextView.setEnabled(!TextUtils.isEmpty(this.editText.getText().toString()) && this.adapter.getItemCount() > 0);
    }
}
