package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.StickerSetCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GroupStickersActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int done_button = 1;
    private int chatId;
    private ActionBarMenuItem doneItem;
    private AnimatorSet doneItemAnimation;
    private boolean donePressed;
    private EditText editText;
    private ImageView eraseImageView;
    private int headerRow;
    private boolean ignoreTextChanges;
    private TLRPC.ChatFull info;
    private int infoRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private LinearLayout nameContainer;
    private int nameRow;
    private ContextProgressView progressView;
    private Runnable queryRunnable;
    private int reqId;
    private int rowCount;
    private boolean searchWas;
    private boolean searching;
    private int selectedStickerRow;
    private TLRPC.TL_messages_stickerSet selectedStickerSet;
    private int stickersEndRow;
    private int stickersShadowRow;
    private int stickersStartRow;
    private EditTextBoldCursor usernameTextView;

    public GroupStickersActivity(int id) {
        this.chatId = id;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        MediaDataController.getInstance(this.currentAccount).checkStickers(0);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.stickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.chatInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.groupStickersDidLoad);
        updateRows();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.stickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.chatInfoDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.groupStickersDidLoad);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("GroupStickers", R.string.GroupStickers));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    GroupStickersActivity.this.finishFragment();
                    return;
                }
                if (id == 1 && !GroupStickersActivity.this.donePressed) {
                    GroupStickersActivity.this.donePressed = true;
                    if (GroupStickersActivity.this.searching) {
                        GroupStickersActivity.this.showEditDoneProgress(true);
                    } else {
                        GroupStickersActivity.this.saveStickerSet();
                    }
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        this.doneItem = menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f));
        ContextProgressView contextProgressView = new ContextProgressView(context, 1);
        this.progressView = contextProgressView;
        contextProgressView.setAlpha(0.0f);
        this.progressView.setScaleX(0.1f);
        this.progressView.setScaleY(0.1f);
        this.progressView.setVisibility(4);
        this.doneItem.addView(this.progressView, LayoutHelper.createFrame(-1, -1.0f));
        LinearLayout linearLayout = new LinearLayout(context) { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.2
            @Override // android.widget.LinearLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(42.0f), 1073741824));
            }

            @Override // android.widget.LinearLayout, android.view.View
            protected void onDraw(Canvas canvas) {
                if (GroupStickersActivity.this.selectedStickerSet != null) {
                    canvas.drawLine(0.0f, getHeight() - 1, getWidth(), getHeight() - 1, Theme.dividerPaint);
                }
            }
        };
        this.nameContainer = linearLayout;
        linearLayout.setWeightSum(1.0f);
        this.nameContainer.setWillNotDraw(false);
        this.nameContainer.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.nameContainer.setOrientation(0);
        this.nameContainer.setPadding(AndroidUtilities.dp(17.0f), 0, AndroidUtilities.dp(14.0f), 0);
        EditText editText = new EditText(context);
        this.editText = editText;
        editText.setText(MessagesController.getInstance(this.currentAccount).linkPrefix + "/addstickers/");
        this.editText.setTextSize(1, 17.0f);
        this.editText.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.editText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.editText.setMaxLines(1);
        this.editText.setLines(1);
        this.editText.setEnabled(false);
        this.editText.setFocusable(false);
        this.editText.setBackgroundDrawable(null);
        this.editText.setPadding(0, 0, 0, 0);
        this.editText.setGravity(16);
        this.editText.setSingleLine(true);
        this.editText.setInputType(163840);
        this.editText.setImeOptions(6);
        this.nameContainer.addView(this.editText, LayoutHelper.createLinear(-2, 42));
        EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
        this.usernameTextView = editTextBoldCursor;
        editTextBoldCursor.setTextSize(1, 17.0f);
        this.usernameTextView.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.usernameTextView.setCursorSize(AndroidUtilities.dp(20.0f));
        this.usernameTextView.setCursorWidth(1.5f);
        this.usernameTextView.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        this.usernameTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.usernameTextView.setMaxLines(1);
        this.usernameTextView.setLines(1);
        this.usernameTextView.setBackgroundDrawable(null);
        this.usernameTextView.setPadding(0, 0, 0, 0);
        this.usernameTextView.setSingleLine(true);
        this.usernameTextView.setGravity(16);
        this.usernameTextView.setInputType(163872);
        this.usernameTextView.setImeOptions(6);
        this.usernameTextView.setHint(LocaleController.getString("ChooseStickerSetPlaceholder", R.string.ChooseStickerSetPlaceholder));
        this.usernameTextView.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.3
            boolean ignoreTextChange;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                if (GroupStickersActivity.this.eraseImageView != null) {
                    GroupStickersActivity.this.eraseImageView.setVisibility(s.length() > 0 ? 0 : 4);
                }
                if (this.ignoreTextChange || GroupStickersActivity.this.ignoreTextChanges) {
                    return;
                }
                if (s.length() > 5) {
                    this.ignoreTextChange = true;
                    try {
                        Uri uri = Uri.parse(s.toString());
                        if (uri != null) {
                            List<String> segments = uri.getPathSegments();
                            if (segments.size() == 2 && segments.get(0).toLowerCase().equals("addstickers")) {
                                GroupStickersActivity.this.usernameTextView.setText(segments.get(1));
                                GroupStickersActivity.this.usernameTextView.setSelection(GroupStickersActivity.this.usernameTextView.length());
                            }
                        }
                    } catch (Exception e) {
                    }
                    this.ignoreTextChange = false;
                }
                GroupStickersActivity.this.resolveStickerSet();
            }
        });
        this.nameContainer.addView(this.usernameTextView, LayoutHelper.createLinear(0, 42, 1.0f));
        ImageView imageView = new ImageView(context);
        this.eraseImageView = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.eraseImageView.setImageResource(R.drawable.ic_close_white);
        this.eraseImageView.setPadding(AndroidUtilities.dp(16.0f), 0, 0, 0);
        this.eraseImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3), PorterDuff.Mode.MULTIPLY));
        this.eraseImageView.setVisibility(4);
        this.eraseImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$eBUnm2hMMRB_hK8niCo2XRyUf2g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$0$GroupStickersActivity(view);
            }
        });
        this.nameContainer.addView(this.eraseImageView, LayoutHelper.createLinear(42, 42, 0.0f));
        TLRPC.ChatFull chatFull = this.info;
        if (chatFull != null && chatFull.stickerset != null) {
            this.ignoreTextChanges = true;
            this.usernameTextView.setText(this.info.stickerset.short_name);
            EditTextBoldCursor editTextBoldCursor2 = this.usernameTextView;
            editTextBoldCursor2.setSelection(editTextBoldCursor2.length());
            this.ignoreTextChanges = false;
        }
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setFocusable(true);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context) { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.4
            @Override // androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean requestChildRectangleOnScreen(RecyclerView parent, View child, Rect rect, boolean immediate, boolean focusedChildVisible) {
                return false;
            }

            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.layoutManager = linearLayoutManager;
        linearLayoutManager.setOrientation(1);
        this.listView.setLayoutManager(this.layoutManager);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$TCp6V8AAM5WLO2_NGKAAeyizjj0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$1$GroupStickersActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.5
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1) {
                    AndroidUtilities.hideKeyboard(GroupStickersActivity.this.getParentActivity().getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$GroupStickersActivity(View v) {
        this.searchWas = false;
        this.selectedStickerSet = null;
        this.usernameTextView.setText("");
        updateRows();
    }

    public /* synthetic */ void lambda$createView$1$GroupStickersActivity(View view, int position) {
        if (getParentActivity() == null) {
            return;
        }
        int i = this.selectedStickerRow;
        if (position == i) {
            if (this.selectedStickerSet == null) {
                return;
            }
            showDialog(new StickersAlert(getParentActivity(), this, null, this.selectedStickerSet, null));
            return;
        }
        if (position >= this.stickersStartRow && position < this.stickersEndRow) {
            boolean needScroll = i == -1;
            int row = this.layoutManager.findFirstVisibleItemPosition();
            int top = Integer.MAX_VALUE;
            RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findViewHolderForAdapterPosition(row);
            if (holder != null) {
                top = holder.itemView.getTop();
            }
            TLRPC.TL_messages_stickerSet tL_messages_stickerSet = MediaDataController.getInstance(this.currentAccount).getStickerSets(0).get(position - this.stickersStartRow);
            this.selectedStickerSet = tL_messages_stickerSet;
            this.ignoreTextChanges = true;
            this.usernameTextView.setText(tL_messages_stickerSet.set.short_name);
            EditTextBoldCursor editTextBoldCursor = this.usernameTextView;
            editTextBoldCursor.setSelection(editTextBoldCursor.length());
            this.ignoreTextChanges = false;
            AndroidUtilities.hideKeyboard(this.usernameTextView);
            updateRows();
            if (needScroll && top != Integer.MAX_VALUE) {
                this.layoutManager.scrollToPositionWithOffset(row + 1, top);
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.stickersDidLoad) {
            if (((Integer) args[0]).intValue() == 0) {
                updateRows();
                return;
            }
            return;
        }
        if (id == NotificationCenter.chatInfoDidLoad) {
            TLRPC.ChatFull chatFull = (TLRPC.ChatFull) args[0];
            if (chatFull.id == this.chatId) {
                if (this.info == null && chatFull.stickerset != null) {
                    this.selectedStickerSet = MediaDataController.getInstance(this.currentAccount).getGroupStickerSetById(chatFull.stickerset);
                }
                this.info = chatFull;
                updateRows();
                return;
            }
            return;
        }
        if (id == NotificationCenter.groupStickersDidLoad) {
            ((Long) args[0]).longValue();
            TLRPC.ChatFull chatFull2 = this.info;
            if (chatFull2 != null && chatFull2.stickerset != null && this.info.stickerset.id == id) {
                updateRows();
            }
        }
    }

    public void setInfo(TLRPC.ChatFull chatFull) {
        this.info = chatFull;
        if (chatFull != null && chatFull.stickerset != null) {
            this.selectedStickerSet = MediaDataController.getInstance(this.currentAccount).getGroupStickerSetById(this.info.stickerset);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resolveStickerSet() {
        if (this.listAdapter == null) {
            return;
        }
        if (this.reqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.reqId, true);
            this.reqId = 0;
        }
        Runnable runnable = this.queryRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.queryRunnable = null;
        }
        this.selectedStickerSet = null;
        if (this.usernameTextView.length() <= 0) {
            this.searching = false;
            this.searchWas = false;
            if (this.selectedStickerRow != -1) {
                updateRows();
                return;
            }
            return;
        }
        this.searching = true;
        this.searchWas = true;
        final String query = this.usernameTextView.getText().toString();
        TLRPC.TL_messages_stickerSet existingSet = MediaDataController.getInstance(this.currentAccount).getStickerSetByName(query);
        if (existingSet != null) {
            this.selectedStickerSet = existingSet;
        }
        int i = this.selectedStickerRow;
        if (i == -1) {
            updateRows();
        } else {
            this.listAdapter.notifyItemChanged(i);
        }
        if (existingSet != null) {
            this.searching = false;
            return;
        }
        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$NzjTZuUrV0-miISBdqCJmdXETi8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$resolveStickerSet$4$GroupStickersActivity(query);
            }
        };
        this.queryRunnable = runnable2;
        AndroidUtilities.runOnUIThread(runnable2, 500L);
    }

    public /* synthetic */ void lambda$resolveStickerSet$4$GroupStickersActivity(String query) {
        if (this.queryRunnable == null) {
            return;
        }
        TLRPC.TL_messages_getStickerSet req = new TLRPC.TL_messages_getStickerSet();
        req.stickerset = new TLRPC.TL_inputStickerSetShortName();
        req.stickerset.short_name = query;
        this.reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$iEynUORkWv0AqkmFTwnoyEwXaVk
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$3$GroupStickersActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$GroupStickersActivity(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$e2xXNOnwJGrPsRPyKyvXLbHko4U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$GroupStickersActivity(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$GroupStickersActivity(TLObject response) {
        this.searching = false;
        if (response instanceof TLRPC.TL_messages_stickerSet) {
            this.selectedStickerSet = (TLRPC.TL_messages_stickerSet) response;
            if (this.donePressed) {
                saveStickerSet();
            } else {
                int i = this.selectedStickerRow;
                if (i != -1) {
                    this.listAdapter.notifyItemChanged(i);
                } else {
                    updateRows();
                }
            }
        } else {
            int i2 = this.selectedStickerRow;
            if (i2 != -1) {
                this.listAdapter.notifyItemChanged(i2);
            }
            if (this.donePressed) {
                this.donePressed = false;
                showEditDoneProgress(false);
                if (getParentActivity() != null) {
                    ToastUtils.show(R.string.AddStickersNotFound);
                }
            }
        }
        this.reqId = 0;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$ATJnBshOh-huX4_6I3juL5hUgek
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onTransitionAnimationEnd$5$GroupStickersActivity();
                }
            }, 100L);
        }
    }

    public /* synthetic */ void lambda$onTransitionAnimationEnd$5$GroupStickersActivity() {
        EditTextBoldCursor editTextBoldCursor = this.usernameTextView;
        if (editTextBoldCursor != null) {
            editTextBoldCursor.requestFocus();
            AndroidUtilities.showKeyboard(this.usernameTextView);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveStickerSet() {
        TLRPC.TL_messages_stickerSet tL_messages_stickerSet;
        TLRPC.ChatFull chatFull = this.info;
        if (chatFull == null || ((chatFull.stickerset != null && (tL_messages_stickerSet = this.selectedStickerSet) != null && tL_messages_stickerSet.set.id == this.info.stickerset.id) || (this.info.stickerset == null && this.selectedStickerSet == null))) {
            finishFragment();
            return;
        }
        showEditDoneProgress(true);
        TLRPC.TL_channels_setStickers req = new TLRPC.TL_channels_setStickers();
        req.channel = MessagesController.getInstance(this.currentAccount).getInputChannel(this.chatId);
        if (this.selectedStickerSet == null) {
            req.stickerset = new TLRPC.TL_inputStickerSetEmpty();
        } else {
            MessagesController.getEmojiSettings(this.currentAccount).edit().remove("group_hide_stickers_" + this.info.id).commit();
            req.stickerset = new TLRPC.TL_inputStickerSetID();
            req.stickerset.id = this.selectedStickerSet.set.id;
            req.stickerset.access_hash = this.selectedStickerSet.set.access_hash;
        }
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$DR0oUDL3Mg9gpnw6kpj6tutxmQU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveStickerSet$7$GroupStickersActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$saveStickerSet$7$GroupStickersActivity(TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$GroupStickersActivity$3GaVuUmpL0rjoscUGCD-kwKDyQw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$6$GroupStickersActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$GroupStickersActivity(TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.TL_messages_stickerSet tL_messages_stickerSet = this.selectedStickerSet;
            if (tL_messages_stickerSet == null) {
                this.info.stickerset = null;
            } else {
                this.info.stickerset = tL_messages_stickerSet.set;
                MediaDataController.getInstance(this.currentAccount).putGroupStickerSet(this.selectedStickerSet);
            }
            if (this.info.stickerset == null) {
                this.info.flags |= 256;
            } else {
                this.info.flags &= -257;
            }
            MessagesStorage.getInstance(this.currentAccount).updateChatInfo(this.info, false);
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.chatInfoDidLoad, this.info, 0, true, null);
            finishFragment();
            return;
        }
        ToastUtils.show(R.string.ErrorOccurred);
        this.donePressed = false;
        showEditDoneProgress(false);
    }

    private void updateRows() {
        this.rowCount = 0;
        this.rowCount = 0 + 1;
        this.nameRow = 0;
        if (this.selectedStickerSet != null || this.searchWas) {
            int i = this.rowCount;
            this.rowCount = i + 1;
            this.selectedStickerRow = i;
        } else {
            this.selectedStickerRow = -1;
        }
        int i2 = this.rowCount;
        this.rowCount = i2 + 1;
        this.infoRow = i2;
        ArrayList<TLRPC.TL_messages_stickerSet> stickerSets = MediaDataController.getInstance(this.currentAccount).getStickerSets(0);
        if (!stickerSets.isEmpty()) {
            int i3 = this.rowCount;
            int i4 = i3 + 1;
            this.rowCount = i4;
            this.headerRow = i3;
            this.stickersStartRow = i4;
            this.stickersEndRow = i4 + stickerSets.size();
            int size = this.rowCount + stickerSets.size();
            this.rowCount = size;
            this.rowCount = size + 1;
            this.stickersShadowRow = size;
        } else {
            this.headerRow = -1;
            this.stickersStartRow = -1;
            this.stickersEndRow = -1;
            this.stickersShadowRow = -1;
        }
        LinearLayout linearLayout = this.nameContainer;
        if (linearLayout != null) {
            linearLayout.invalidate();
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        boolean animations = preferences.getBoolean("view_animations", true);
        if (!animations) {
            this.usernameTextView.requestFocus();
            AndroidUtilities.showKeyboard(this.usernameTextView);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showEditDoneProgress(final boolean show) {
        if (this.doneItem == null) {
            return;
        }
        AnimatorSet animatorSet = this.doneItemAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.doneItemAnimation = new AnimatorSet();
        if (show) {
            this.progressView.setVisibility(0);
            this.doneItem.setEnabled(false);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleX", 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleY", 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "alpha", 0.0f), ObjectAnimator.ofFloat(this.progressView, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.progressView, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.progressView, "alpha", 1.0f));
        } else {
            this.doneItem.getContentView().setVisibility(0);
            this.doneItem.setEnabled(true);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.progressView, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.progressView, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.progressView, "alpha", 0.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleX", 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "scaleY", 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), "alpha", 1.0f));
        }
        this.doneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.6
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (GroupStickersActivity.this.doneItemAnimation != null && GroupStickersActivity.this.doneItemAnimation.equals(animation)) {
                    if (!show) {
                        GroupStickersActivity.this.progressView.setVisibility(4);
                    } else {
                        GroupStickersActivity.this.doneItem.getContentView().setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (GroupStickersActivity.this.doneItemAnimation != null && GroupStickersActivity.this.doneItemAnimation.equals(animation)) {
                    GroupStickersActivity.this.doneItemAnimation = null;
                }
            }
        });
        this.doneItemAnimation.setDuration(150L);
        this.doneItemAnimation.start();
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return GroupStickersActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            long id;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                ArrayList<TLRPC.TL_messages_stickerSet> arrayList = MediaDataController.getInstance(GroupStickersActivity.this.currentAccount).getStickerSets(0);
                int row = position - GroupStickersActivity.this.stickersStartRow;
                StickerSetCell cell = (StickerSetCell) holder.itemView;
                TLRPC.TL_messages_stickerSet set = arrayList.get(row);
                cell.setStickersSet(arrayList.get(row), row != arrayList.size() - 1);
                if (GroupStickersActivity.this.selectedStickerSet != null) {
                    id = GroupStickersActivity.this.selectedStickerSet.set.id;
                } else {
                    id = (GroupStickersActivity.this.info == null || GroupStickersActivity.this.info.stickerset == null) ? 0L : GroupStickersActivity.this.info.stickerset.id;
                }
                cell.setChecked(set.set.id == id);
                return;
            }
            if (itemViewType != 1) {
                if (itemViewType == 4) {
                    ((HeaderCell) holder.itemView).setText(LocaleController.getString("ChooseFromYourStickers", R.string.ChooseFromYourStickers));
                    return;
                }
                if (itemViewType == 5) {
                    StickerSetCell cell2 = (StickerSetCell) holder.itemView;
                    if (GroupStickersActivity.this.selectedStickerSet != null) {
                        cell2.setStickersSet(GroupStickersActivity.this.selectedStickerSet, false);
                        return;
                    } else if (GroupStickersActivity.this.searching) {
                        cell2.setText(LocaleController.getString("Loading", R.string.Loading), null, 0, false);
                        return;
                    } else {
                        cell2.setText(LocaleController.getString("ChooseStickerSetNotFound", R.string.ChooseStickerSetNotFound), LocaleController.getString("ChooseStickerSetNotFoundInfo", R.string.ChooseStickerSetNotFoundInfo), R.drawable.ic_smiles2_sad, false);
                        return;
                    }
                }
                return;
            }
            if (position == GroupStickersActivity.this.infoRow) {
                String text = LocaleController.getString("ChooseStickerSetMy", R.string.ChooseStickerSetMy);
                int index = text.indexOf("@stickers");
                if (index != -1) {
                    try {
                        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(text);
                        URLSpanNoUnderline spanNoUnderline = new URLSpanNoUnderline("@stickers") { // from class: im.uwrkaxlmjj.ui.GroupStickersActivity.ListAdapter.1
                            @Override // im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.URLSpan, android.text.style.ClickableSpan
                            public void onClick(View widget) {
                                MessagesController.getInstance(GroupStickersActivity.this.currentAccount).openByUserName("stickers", GroupStickersActivity.this, 1);
                            }
                        };
                        stringBuilder.setSpan(spanNoUnderline, index, "@stickers".length() + index, 18);
                        ((TextInfoPrivacyCell) holder.itemView).setText(stringBuilder);
                        return;
                    } catch (Exception e) {
                        FileLog.e(e);
                        ((TextInfoPrivacyCell) holder.itemView).setText(text);
                        return;
                    }
                }
                ((TextInfoPrivacyCell) holder.itemView).setText(text);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 2 || type == 5;
        }

        /* JADX WARN: Removed duplicated region for block: B:17:0x0055  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public androidx.recyclerview.widget.RecyclerView.ViewHolder onCreateViewHolder(android.view.ViewGroup r8, int r9) {
            /*
                r7 = this;
                r0 = 0
                java.lang.String r1 = "windowBackgroundWhite"
                r2 = 3
                r3 = 2
                if (r9 == 0) goto L55
                r4 = 1
                java.lang.String r5 = "windowBackgroundGrayShadow"
                r6 = 2131231059(0x7f080153, float:1.8078188E38)
                if (r9 == r4) goto L43
                if (r9 == r3) goto L3c
                if (r9 == r2) goto L2a
                r4 = 4
                if (r9 == r4) goto L1a
                r4 = 5
                if (r9 == r4) goto L55
                goto L69
            L1a:
                im.uwrkaxlmjj.ui.cells.HeaderCell r2 = new im.uwrkaxlmjj.ui.cells.HeaderCell
                android.content.Context r3 = r7.mContext
                r2.<init>(r3)
                r0 = r2
                int r1 = im.uwrkaxlmjj.ui.actionbar.Theme.getColor(r1)
                r0.setBackgroundColor(r1)
                goto L69
            L2a:
                im.uwrkaxlmjj.ui.cells.ShadowSectionCell r1 = new im.uwrkaxlmjj.ui.cells.ShadowSectionCell
                android.content.Context r2 = r7.mContext
                r1.<init>(r2)
                r0 = r1
                android.content.Context r1 = r7.mContext
                android.graphics.drawable.Drawable r1 = im.uwrkaxlmjj.ui.actionbar.Theme.getThemedDrawable(r1, r6, r5)
                r0.setBackgroundDrawable(r1)
                goto L69
            L3c:
                im.uwrkaxlmjj.ui.GroupStickersActivity r1 = im.uwrkaxlmjj.ui.GroupStickersActivity.this
                android.widget.LinearLayout r0 = im.uwrkaxlmjj.ui.GroupStickersActivity.access$1800(r1)
                goto L69
            L43:
                im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell r1 = new im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell
                android.content.Context r2 = r7.mContext
                r1.<init>(r2)
                r0 = r1
                android.content.Context r1 = r7.mContext
                android.graphics.drawable.Drawable r1 = im.uwrkaxlmjj.ui.actionbar.Theme.getThemedDrawable(r1, r6, r5)
                r0.setBackgroundDrawable(r1)
                goto L69
            L55:
                im.uwrkaxlmjj.ui.cells.StickerSetCell r4 = new im.uwrkaxlmjj.ui.cells.StickerSetCell
                android.content.Context r5 = r7.mContext
                if (r9 != 0) goto L5c
                goto L5d
            L5c:
                r2 = 2
            L5d:
                r4.<init>(r5, r2)
                r0 = r4
                int r1 = im.uwrkaxlmjj.ui.actionbar.Theme.getColor(r1)
                r0.setBackgroundColor(r1)
            L69:
                androidx.recyclerview.widget.RecyclerView$LayoutParams r1 = new androidx.recyclerview.widget.RecyclerView$LayoutParams
                r2 = -1
                r3 = -2
                r1.<init>(r2, r3)
                r0.setLayoutParams(r1)
                im.uwrkaxlmjj.ui.components.RecyclerListView$Holder r1 = new im.uwrkaxlmjj.ui.components.RecyclerListView$Holder
                r1.<init>(r0)
                return r1
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.GroupStickersActivity.ListAdapter.onCreateViewHolder(android.view.ViewGroup, int):androidx.recyclerview.widget.RecyclerView$ViewHolder");
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i >= GroupStickersActivity.this.stickersStartRow && i < GroupStickersActivity.this.stickersEndRow) {
                return 0;
            }
            if (i != GroupStickersActivity.this.infoRow) {
                if (i != GroupStickersActivity.this.nameRow) {
                    if (i != GroupStickersActivity.this.stickersShadowRow) {
                        if (i == GroupStickersActivity.this.headerRow) {
                            return 4;
                        }
                        return i == GroupStickersActivity.this.selectedStickerRow ? 5 : 0;
                    }
                    return 3;
                }
                return 2;
            }
            return 1;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{StickerSetCell.class, TextSettingsCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.editText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.editText, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.usernameTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.usernameTextView, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_LINKCOLOR, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteLinkText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.nameContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.listView, 0, new Class[]{StickerSetCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{StickerSetCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, ThemeDescription.FLAG_USEBACKGROUNDDRAWABLE | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, new Class[]{StickerSetCell.class}, new String[]{"optionsButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_stickers_menuSelector), new ThemeDescription(this.listView, 0, new Class[]{StickerSetCell.class}, new String[]{"optionsButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_stickers_menu)};
    }
}
