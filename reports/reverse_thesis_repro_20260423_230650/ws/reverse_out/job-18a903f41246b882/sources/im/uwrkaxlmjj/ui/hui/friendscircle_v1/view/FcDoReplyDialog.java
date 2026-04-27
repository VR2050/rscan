package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputFilter;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import cn.dreamtobe.kpswitch.widget.KPSwitchPanelRelativeLayout;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.litesuits.orm.db.assit.SQLBuilder;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.EmojiView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.KeyboardUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.AtUserMethod;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.method.MethodContext;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.User;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryAlphaImageView;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcDoReplyDialog extends Dialog implements NotificationCenter.NotificationCenterDelegate, ChooseAtContactsActivity.ContactsActivityDelegate {
    private ViewTreeObserver.OnGlobalLayoutListener attach;
    private long currentForumId;
    private final Window dialogWindow;
    private EditTextBoldCursor etReply;
    private FrameLayout flEtContainer;
    private boolean isAutoDismiss;
    private boolean isEnableAtUser;
    private boolean isNewReply;
    private ImageView ivEmoji;
    private MryAlphaImageView ivSend;
    private HashMap<Long, Editable> lastUnPostContent;
    private OnFcDoReplyListener listener;
    private KPSwitchPanelRelativeLayout llEmoji;
    private Activity mActivity;
    private EmojiView mEmojiView;
    private int maxContentLen;
    private MethodContext methodContext;
    private final RelativeLayout rlContentView;

    public interface OnFcDoReplyListener {
        void onInputReplyContent(String str, ArrayList<FCEntitysRequest> arrayList);

        void startFragment(BaseFragment baseFragment);
    }

    public FcDoReplyDialog(Context context) {
        super(context, R.plurals.FcDoReplyDialogStyle);
        this.maxContentLen = 400;
        this.isEnableAtUser = false;
        this.isAutoDismiss = false;
        this.lastUnPostContent = null;
        this.isNewReply = true;
        this.currentForumId = -1L;
        this.mActivity = (Activity) context;
        RelativeLayout rlRootView = new RelativeLayout(this.mActivity);
        RelativeLayout.LayoutParams layoutParams = LayoutHelper.createRelative(-1, -1);
        rlRootView.setLayoutParams(layoutParams);
        rlRootView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                FcDoReplyDialog.this.saveUnPostContent();
                FcDoReplyDialog.this.dismiss();
            }
        });
        this.rlContentView = new RelativeLayout(this.mActivity);
        RelativeLayout.LayoutParams pLayoutParams = LayoutHelper.createRelative(-1, -2);
        pLayoutParams.addRule(12);
        this.rlContentView.setLayoutParams(pLayoutParams);
        this.rlContentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        FrameLayout frameLayout = new FrameLayout(this.mActivity);
        this.flEtContainer = frameLayout;
        frameLayout.setId(frameLayout.hashCode());
        MryAlphaImageView mryAlphaImageView = new MryAlphaImageView(context);
        this.ivSend = mryAlphaImageView;
        mryAlphaImageView.setId(mryAlphaImageView.hashCode());
        this.ivSend.setImageResource(R.drawable.ic_send);
        this.ivSend.getDrawable().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelSend), PorterDuff.Mode.MULTIPLY));
        this.ivSend.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.-$$Lambda$FcDoReplyDialog$OePnEYKcB3p-Vz3QulohCntr-9I
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$0$FcDoReplyDialog(view);
            }
        });
        RelativeLayout.LayoutParams ivSendLp = LayoutHelper.createRelative(40, 40);
        ivSendLp.addRule(21);
        ivSendLp.addRule(15);
        ivSendLp.addRule(6, this.flEtContainer.getId());
        ivSendLp.addRule(8, this.flEtContainer.getId());
        this.ivSend.setLayoutParams(ivSendLp);
        this.ivSend.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        this.rlContentView.addView(this.ivSend);
        ImageView imageView = new ImageView(this.mActivity);
        this.ivEmoji = imageView;
        imageView.setId(imageView.hashCode());
        RelativeLayout.LayoutParams ivEmojiLp = LayoutHelper.createRelative(40, 40);
        ivEmojiLp.addRule(0, this.ivSend.getId());
        ivEmojiLp.addRule(15);
        ivEmojiLp.addRule(6, this.flEtContainer.getId());
        ivEmojiLp.addRule(8, this.flEtContainer.getId());
        this.ivEmoji.setLayoutParams(ivEmojiLp);
        this.ivEmoji.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        this.ivEmoji.setImageResource(R.drawable.emoji_menu);
        this.rlContentView.addView(this.ivEmoji);
        RelativeLayout.LayoutParams etLp = LayoutHelper.createRelative(-1, -2, 10);
        etLp.setMarginStart(AndroidUtilities.dp(15.0f));
        etLp.topMargin = AndroidUtilities.dp(18.0f);
        etLp.bottomMargin = AndroidUtilities.dp(18.0f);
        etLp.addRule(0, this.ivEmoji.getId());
        this.flEtContainer.setLayoutParams(etLp);
        this.flEtContainer.setBackground(ShapeUtils.createStrokeAndFill(this.mActivity.getResources().getColor(R.color.color_FFD8D8D8), AndroidUtilities.dp(1.0f), AndroidUtilities.dp(20.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.flEtContainer.setMinimumHeight(AndroidUtilities.dp(40.0f));
        this.flEtContainer.setPadding(AndroidUtilities.dp(16.0f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(16.0f), AndroidUtilities.dp(2.0f));
        this.rlContentView.addView(this.flEtContainer);
        rlRootView.addView(this.rlContentView);
        initReply();
        initEmoji();
        setContentView(rlRootView);
        Window window = getWindow();
        this.dialogWindow = window;
        window.setBackgroundDrawable(null);
        WindowManager.LayoutParams lp = this.dialogWindow.getAttributes();
        lp.width = -1;
        lp.height = -1;
        this.dialogWindow.setAttributes(lp);
        this.dialogWindow.getDecorView().setPadding(0, 0, 0, 0);
        this.mActivity.getWindow().setSoftInputMode(16);
        this.dialogWindow.clearFlags(131072);
        this.dialogWindow.setSoftInputMode(20);
        setCanceledOnTouchOutside(true);
        setOnKeyListener(new DialogInterface.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.2
            @Override // android.content.DialogInterface.OnKeyListener
            public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
                if (keyCode == 4) {
                    FcDoReplyDialog.this.saveUnPostContent();
                    FcDoReplyDialog.this.dismiss();
                    return true;
                }
                return false;
            }
        });
    }

    public /* synthetic */ void lambda$new$0$FcDoReplyDialog(View v) {
        tryPublishComment();
        dismiss();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        EmojiView emojiView;
        KLog.d("---------通知" + id);
        if (id == NotificationCenter.emojiDidLoad && (emojiView = this.mEmojiView) != null) {
            emojiView.invalidateViews();
        }
    }

    private void initReply() {
        EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(this.mActivity);
        this.etReply = editTextBoldCursor;
        editTextBoldCursor.setBackground(null);
        this.etReply.setTextSize(2, 15.0f);
        this.etReply.setGravity(8388627);
        this.etReply.setFilters(new InputFilter[]{new InputFilter.LengthFilter(this.maxContentLen)});
        this.etReply.setHint("");
        this.etReply.setImeOptions(6);
        this.etReply.setInputType(131072);
        this.etReply.setSingleLine(false);
        if (Theme.getCurrentTheme().isDark()) {
            this.etReply.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
        }
        this.etReply.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.etReply.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.-$$Lambda$FcDoReplyDialog$NGtkSTZtSmQ1E-1IJfb6S59HAYY
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                return this.f$0.lambda$initReply$1$FcDoReplyDialog(textView, i, keyEvent);
            }
        });
        this.etReply.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.3
            private int beforeCount;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                this.beforeCount = s.toString().length();
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String setMsg = s.toString();
                if (setMsg.length() >= FcDoReplyDialog.this.maxContentLen) {
                    FcToastUtils.show((CharSequence) "不能输入更多啦～");
                }
                if (FcDoReplyDialog.this.isEnableAtUser && setMsg.length() >= this.beforeCount && FcDoReplyDialog.this.etReply.getSelectionEnd() > 0 && setMsg.charAt(FcDoReplyDialog.this.etReply.getSelectionEnd() - 1) == '@' && FcDoReplyDialog.this.listener != null) {
                    FcDoReplyDialog.this.dismiss();
                    Bundle args = new Bundle();
                    ChooseAtContactsActivity chooseAtContactsActivity = new ChooseAtContactsActivity(args);
                    chooseAtContactsActivity.setDelegate(FcDoReplyDialog.this);
                    FcDoReplyDialog.this.listener.startFragment(chooseAtContactsActivity);
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                FcDoReplyDialog.this.changeSendBtn();
            }
        });
        MethodContext methodContext = new MethodContext();
        this.methodContext = methodContext;
        methodContext.setMethod(AtUserMethod.INSTANCE);
        this.methodContext.init(this.etReply);
        this.flEtContainer.addView(this.etReply, LayoutHelper.createFrame(-1, -1, 8388627));
    }

    public /* synthetic */ boolean lambda$initReply$1$FcDoReplyDialog(TextView v, int actionId, KeyEvent event) {
        if (actionId == 6) {
            tryPublishComment();
            dismiss();
            return true;
        }
        return false;
    }

    private void initEmoji() {
        this.llEmoji = new KPSwitchPanelRelativeLayout(this.mActivity);
        int validPanelHeight = KeyboardUtils.getValidPanelHeight(this.mActivity);
        this.llEmoji.setLayoutParams(LayoutHelper.createRelative(-1, validPanelHeight, 3, this.flEtContainer.getId()));
        EmojiView emojiView = new EmojiView(false, false, this.mActivity, false, null);
        this.mEmojiView = emojiView;
        this.llEmoji.addView(emojiView, LayoutHelper.createRelative(-1, -2));
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        this.mEmojiView.setDelegate(new AnonymousClass4());
        this.ivEmoji.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.5
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                FcDoReplyDialog.this.isAutoDismiss = true;
                if (FcDoReplyDialog.this.llEmoji.getVisibility() == 0) {
                    FcDoReplyDialog.this.llEmoji.setVisibility(4);
                    AndroidUtilities.showKeyboard(FcDoReplyDialog.this.etReply);
                } else {
                    AndroidUtilities.hideKeyboard(FcDoReplyDialog.this.etReply);
                }
            }
        });
        this.attach = KeyboardUtils.attach(this.mActivity, this.llEmoji, new KeyboardUtils.OnKeyboardShowingListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.6
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.KeyboardUtils.OnKeyboardShowingListener
            public void onKeyboardShowing(boolean isShowing) {
                if (isShowing) {
                    FcDoReplyDialog.this.llEmoji.setVisibility(8);
                    if (FcDoReplyDialog.this.isNewReply) {
                        if (FcDoReplyDialog.this.currentForumId == -1 || FcDoReplyDialog.this.lastUnPostContent == null || FcDoReplyDialog.this.lastUnPostContent.size() <= 0 || !FcDoReplyDialog.this.lastUnPostContent.containsKey(Long.valueOf(FcDoReplyDialog.this.currentForumId)) || FcDoReplyDialog.this.lastUnPostContent.get(Long.valueOf(FcDoReplyDialog.this.currentForumId)) == null) {
                            FcDoReplyDialog.this.etReply.setText("");
                        } else {
                            FcDoReplyDialog.this.etReply.setText((CharSequence) FcDoReplyDialog.this.lastUnPostContent.get(Long.valueOf(FcDoReplyDialog.this.currentForumId)));
                        }
                        FcDoReplyDialog.this.isNewReply = false;
                    }
                } else if (FcDoReplyDialog.this.isAutoDismiss) {
                    FcDoReplyDialog.this.llEmoji.setVisibility(0);
                } else {
                    FcDoReplyDialog.this.saveUnPostContent();
                    FcDoReplyDialog.this.dismiss();
                }
                FcDoReplyDialog.this.isAutoDismiss = false;
            }
        });
        this.rlContentView.addView(this.llEmoji);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog$4, reason: invalid class name */
    class AnonymousClass4 implements EmojiView.EmojiViewDelegate {
        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ boolean canSchedule() {
            return EmojiView.EmojiViewDelegate.CC.$default$canSchedule(this);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ boolean isExpanded() {
            return EmojiView.EmojiViewDelegate.CC.$default$isExpanded(this);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ boolean isInScheduleMode() {
            return EmojiView.EmojiViewDelegate.CC.$default$isInScheduleMode(this);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ boolean isSearchOpened() {
            return EmojiView.EmojiViewDelegate.CC.$default$isSearchOpened(this);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        /* JADX INFO: renamed from: onGifSelected */
        public /* synthetic */ void lambda$onGifSelected$0$ChatActivityEnterView$35(View view, Object obj, Object obj2, boolean z, int i) {
            EmojiView.EmojiViewDelegate.CC.$default$onGifSelected(this, view, obj, obj2, z, i);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onSearchOpenClose(int i) {
            EmojiView.EmojiViewDelegate.CC.$default$onSearchOpenClose(this, i);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onShowStickerSet(TLRPC.StickerSet stickerSet, TLRPC.InputStickerSet inputStickerSet) {
            EmojiView.EmojiViewDelegate.CC.$default$onShowStickerSet(this, stickerSet, inputStickerSet);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onStickerSelected(View view, TLRPC.Document document, Object obj, boolean z, int i) {
            EmojiView.EmojiViewDelegate.CC.$default$onStickerSelected(this, view, document, obj, z, i);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onStickerSetAdd(TLRPC.StickerSetCovered stickerSetCovered) {
            EmojiView.EmojiViewDelegate.CC.$default$onStickerSetAdd(this, stickerSetCovered);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onStickerSetRemove(TLRPC.StickerSetCovered stickerSetCovered) {
            EmojiView.EmojiViewDelegate.CC.$default$onStickerSetRemove(this, stickerSetCovered);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onStickersGroupClick(int i) {
            EmojiView.EmojiViewDelegate.CC.$default$onStickersGroupClick(this, i);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onStickersSettingsClick() {
            EmojiView.EmojiViewDelegate.CC.$default$onStickersSettingsClick(this);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public /* synthetic */ void onTabOpened(int i) {
            EmojiView.EmojiViewDelegate.CC.$default$onTabOpened(this, i);
        }

        AnonymousClass4() {
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public boolean onBackspace() {
            if (FcDoReplyDialog.this.etReply.length() == 0) {
                return false;
            }
            FcDoReplyDialog.this.etReply.dispatchKeyEvent(new KeyEvent(0, 67));
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onEmojiSelected(String symbol) {
            int i = FcDoReplyDialog.this.etReply.getSelectionEnd();
            if (i < 0) {
                i = 0;
            }
            try {
                CharSequence localCharSequence = Emoji.replaceEmoji(symbol, FcDoReplyDialog.this.etReply.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
                FcDoReplyDialog.this.etReply.setText(FcDoReplyDialog.this.etReply.getText().insert(i, localCharSequence));
                int j = localCharSequence.length() + i;
                FcDoReplyDialog.this.etReply.setSelection(j, j);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onClearEmojiRecent() {
            AlertDialog.Builder builder = new AlertDialog.Builder(FcDoReplyDialog.this.mActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("ClearRecentEmoji", R.string.ClearRecentEmoji));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.-$$Lambda$FcDoReplyDialog$4$8YcxCkfy1sZLb2_YUJbu1Fax4so
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onClearEmojiRecent$0$FcDoReplyDialog$4(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        }

        public /* synthetic */ void lambda$onClearEmojiRecent$0$FcDoReplyDialog$4(DialogInterface dialogInterface, int i) {
            FcDoReplyDialog.this.mEmojiView.clearRecentEmoji();
        }
    }

    private void tryPublishComment() {
        HashMap<Long, Editable> map;
        final Editable text = this.etReply.getText();
        if (!TextUtils.isEmpty(text.toString().trim())) {
            String mStrContent = text.toString().trim();
            if (this.listener != null) {
                String replaceStr = mStrContent;
                ArrayList<FCEntitysRequest> atUserBeanList = null;
                if (this.isEnableAtUser) {
                    atUserBeanList = new ArrayList<>();
                    User[] spans = (User[]) text.getSpans(0, text.length(), User.class);
                    if (spans.length > 1) {
                        Arrays.sort(spans, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.-$$Lambda$FcDoReplyDialog$QGfAebXF49a8Q0aJxtcBkDy8F4I
                            @Override // java.util.Comparator
                            public final int compare(Object obj, Object obj2) {
                                return FcDoReplyDialog.lambda$tryPublishComment$2(text, (User) obj, (User) obj2);
                            }
                        });
                    }
                    for (User atUserSpan : spans) {
                        FCEntitysRequest fcEntitysRequest = new FCEntitysRequest("@" + atUserSpan.getNickName(), atUserSpan.getUserID(), atUserSpan.getAccessHash());
                        atUserBeanList.add(fcEntitysRequest);
                        if (!TextUtils.isEmpty(atUserSpan.getUserName())) {
                            String s = "@" + atUserSpan.getNickName() + SQLBuilder.PARENTHESES_LEFT + atUserSpan.getUserName() + SQLBuilder.PARENTHESES_RIGHT;
                            if (replaceStr.contains(s)) {
                                replaceStr = replaceStr.replace(s, "@" + atUserSpan.getNickName());
                            }
                        }
                    }
                }
                this.listener.onInputReplyContent(replaceStr, atUserBeanList);
                if (this.currentForumId != -1 && (map = this.lastUnPostContent) != null && map.size() > 0 && this.lastUnPostContent.containsKey(Long.valueOf(this.currentForumId))) {
                    this.lastUnPostContent.remove(Long.valueOf(this.currentForumId));
                }
                this.currentForumId = -1L;
                this.etReply.setText("");
            }
        }
    }

    static /* synthetic */ int lambda$tryPublishComment$2(Editable text, User o1, User o2) {
        return text.getSpanStart(o1) - text.getSpanStart(o2);
    }

    public void saveUnPostContent() {
        Editable text = this.etReply.getText();
        if (this.currentForumId != -1 && text != null && text.length() > 0) {
            if (this.lastUnPostContent == null) {
                this.lastUnPostContent = new HashMap<>();
            }
            this.lastUnPostContent.put(Long.valueOf(this.currentForumId), text);
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        this.etReply.clearFocus();
        AndroidUtilities.hideKeyboard(this.etReply);
        super.dismiss();
    }

    public void show(String receiver, long forumId, boolean isEnableAtUser, boolean isComment) {
        if (this.etReply != null) {
            String hint = "";
            if (!TextUtils.isEmpty(receiver)) {
                if (isComment) {
                    hint = String.format("%s%s", this.mActivity.getString(R.string.friends_circle_hint_edittext_comment), receiver);
                } else {
                    hint = String.format("%s%s", this.mActivity.getString(R.string.friends_circle_hint_edittext_reply), receiver);
                }
                if (!hint.endsWith("...")) {
                    hint = hint + "...";
                }
            }
            this.etReply.setHint(hint);
            if (!isComment) {
                this.isEnableAtUser = false;
            } else {
                this.isEnableAtUser = isEnableAtUser;
            }
            this.currentForumId = forumId;
            this.isNewReply = true;
            show();
            this.etReply.setFocusable(true);
            this.etReply.setFocusableInTouchMode(true);
            this.etReply.requestFocus();
            AndroidUtilities.showKeyboard(this.etReply);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeSendBtn() {
        if (this.ivSend == null) {
            return;
        }
        EditTextBoldCursor editTextBoldCursor = this.etReply;
        if (editTextBoldCursor == null || editTextBoldCursor.getText() == null) {
            this.ivSend.setEnabled(false);
        }
        String comment = this.etReply.getText().toString().trim();
        this.ivSend.setEnabled(!TextUtils.isEmpty(comment));
    }

    public void onDestroy() {
        NotificationCenter.getInstance(UserConfig.selectedAccount).removeObserver(this, NotificationCenter.emojiDidLoad);
        Window window = this.dialogWindow;
        if (window != null) {
            window.setSoftInputMode(16);
        }
        ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener = this.attach;
        if (onGlobalLayoutListener != null) {
            KeyboardUtils.detach(this.mActivity, onGlobalLayoutListener);
        }
        Activity activity = this.mActivity;
        if (activity != null) {
            activity.getWindow().setSoftInputMode(16);
        }
        EmojiView emojiView = this.mEmojiView;
        if (emojiView != null) {
            emojiView.onDestroy();
        }
        HashMap<Long, Editable> map = this.lastUnPostContent;
        if (map != null) {
            map.clear();
            this.lastUnPostContent = null;
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.ContactsActivityDelegate
    public void didSelectContact(TLRPC.User user) {
        show();
        if (user != null && !TextUtils.isEmpty(user.first_name)) {
            String nickName = user.first_name.trim();
            final Editable text = this.etReply.getText();
            if (text instanceof SpannableStringBuilder) {
                int index = text.toString().indexOf("@", this.etReply.getSelectionEnd() - 1);
                if (index != -1) {
                    text.delete(index, index + 1);
                }
                User insertAtUserSpan = new User(user.id, nickName, user.username, "@" + nickName, user.access_hash);
                User[] spans = (User[]) text.getSpans(0, text.length(), User.class);
                Arrays.sort(spans, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.-$$Lambda$FcDoReplyDialog$HuOGXaEK_g0c6zXBJthgh2FQKMo
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return FcDoReplyDialog.lambda$didSelectContact$3(text, (User) obj, (User) obj2);
                    }
                });
                for (User result : spans) {
                    if (TextUtils.equals(result.getShowName(), insertAtUserSpan.getShowName())) {
                        if (result.getUserID() == insertAtUserSpan.getUserID()) {
                            insertAtUserSpan.setShowName(result.getShowName());
                        } else {
                            StringBuilder sb = new StringBuilder();
                            sb.append(insertAtUserSpan.getShowName());
                            sb.append(TextUtils.isEmpty(insertAtUserSpan.getUserName()) ? "" : SQLBuilder.PARENTHESES_LEFT + insertAtUserSpan.getUserName() + SQLBuilder.PARENTHESES_RIGHT);
                            insertAtUserSpan.setShowName(sb.toString());
                        }
                    } else if (result.getUserID() == insertAtUserSpan.getUserID()) {
                        insertAtUserSpan.setShowName(result.getShowName());
                    }
                }
                this.etReply.getText().insert(this.etReply.getSelectionStart(), this.methodContext.newSpannable(insertAtUserSpan)).insert(this.etReply.getSelectionStart(), " ");
            }
        }
    }

    static /* synthetic */ int lambda$didSelectContact$3(Editable text, User o1, User o2) {
        return text.getSpanStart(o1) - text.getSpanStart(o2);
    }

    public void setListener(OnFcDoReplyListener listener) {
        this.listener = listener;
    }
}
