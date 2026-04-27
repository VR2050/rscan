package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;
import android.text.SpannableStringBuilder;
import android.text.StaticLayout;
import android.text.TextUtils;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.Interpolator;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DialogObject;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.CheckBoxBase;
import im.uwrkaxlmjj.ui.components.RLottieDrawable;
import im.uwrkaxlmjj.ui.components.TypefaceSpan;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DialogCell extends BaseCell {
    private boolean animatingArchiveAvatar;
    private float animatingArchiveAvatarProgress;
    private float archiveBackgroundProgress;
    private boolean archiveHidden;
    private boolean attachedToWindow;
    private AvatarDrawable avatarDrawable;
    private ImageReceiver avatarImage;
    private int avatarLeft;
    private int bottomClip;
    private TLRPC.Chat chat;
    private CheckBoxBase checkBox;
    private boolean checkBoxAnimationInProgress;
    private float checkBoxAnimationProgress;
    private int checkBoxTranslation;
    private boolean checkBoxVisible;
    private boolean clearingDialog;
    private float clipProgress;
    private int clockDrawLeft;
    private int clockDrawTop;
    private float cornerProgress;
    private boolean countIsBiggerThanTen;
    private StaticLayout countLayout;
    private int countLeft;
    private int countTop;
    private int countWidth;
    private int currentAccount;
    private int currentDialogFolderDialogsCount;
    private int currentDialogFolderId;
    private long currentDialogId;
    private int currentEditDate;
    private float currentRevealBounceProgress;
    private float currentRevealProgress;
    private CustomDialog customDialog;
    private boolean dialogMuted;
    private int dialogsType;
    private TLRPC.DraftMessage draftMessage;
    private boolean drawBotIcon;
    private boolean drawBroadcastIcon;
    private boolean drawCheck1;
    private boolean drawCheck2;
    private boolean drawClockIcon;
    private boolean drawCount;
    private boolean drawErrorIcon;
    private boolean drawGroupIcon;
    private boolean drawMentionIcon;
    private boolean drawPinBackground;
    private boolean drawPinIcon;
    private boolean drawReorder;
    private boolean drawRevealBackground;
    private boolean drawScam;
    private boolean drawSecretLockIcon;
    private boolean drawVerifiedIcon;
    private TLRPC.EncryptedChat encryptedChat;
    private int errorLeft;
    private int errorTop;
    private int folderId;
    public boolean fullSeparator;
    public boolean fullSeparator2;
    private int index;
    private BounceInterpolator interpolator;
    private boolean isDialogCell;
    private boolean isSelected;
    private boolean isSliding;
    private long lastCheckBoxAnimationTime;
    private int lastMessageDate;
    private CharSequence lastMessageString;
    private CharSequence lastPrintString;
    private int lastSendState;
    private boolean lastUnreadState;
    private long lastUpdateTime;
    private boolean markUnread;
    private int mentionCount;
    private StaticLayout mentionLayout;
    private int mentionLeft;
    private int mentionWidth;
    private MessageObject message;
    private int messageId;
    private StaticLayout messageLayout;
    private int messageLeft;
    private StaticLayout messageNameLayout;
    private int messageNameLeft;
    private int messageNameTop;
    private int messageTop;
    private StaticLayout nameLayout;
    private int nameLeft;
    private int nameMuteLeft;
    private float onlineProgress;
    private int pinLeft;
    private int pinTop;
    private int position;
    private int recorderLeft;
    private int recorderTop;
    private RectF rect;
    private float reorderIconProgress;
    private StaticLayout timeLayout;
    private int timeLeft;
    private int timeTop;
    private int topClip;
    private float topOffset;
    private boolean translationAnimationStarted;
    private RLottieDrawable translationDrawable;
    private float translationX;
    private int unreadCount;
    public boolean useForceThreeLines;
    public boolean useSeparator;
    private TLRPC.User user;

    public static class CustomDialog {
        public int date;
        public int id;
        public boolean isMedia;
        public String message;
        public boolean muted;
        public String name;
        public boolean pinned;
        public boolean sent;
        public int type;
        public int unread_count;
        public boolean verified;
    }

    public class BounceInterpolator implements Interpolator {
        public BounceInterpolator() {
        }

        @Override // android.animation.TimeInterpolator
        public float getInterpolation(float t) {
            if (t < 0.33f) {
                return (t / 0.33f) * 0.1f;
            }
            float t2 = t - 0.33f;
            if (t2 < 0.33f) {
                return 0.1f - ((t2 / 0.34f) * 0.15f);
            }
            return (((t2 - 0.34f) / 0.33f) * 0.05f) - 0.05f;
        }
    }

    public DialogCell(Context context, boolean forceThreeLines) {
        this(context, false, forceThreeLines);
    }

    public DialogCell(Context context, boolean needCheck, boolean forceThreeLines) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.avatarImage = new ImageReceiver(this);
        this.avatarDrawable = new AvatarDrawable();
        this.interpolator = new BounceInterpolator();
        this.rect = new RectF();
        this.checkBoxVisible = needCheck;
        Theme.createDialogsResources(context);
        this.avatarImage.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.useForceThreeLines = forceThreeLines;
        setClipChildren(false);
    }

    public void setDialog(CustomDialog dialog) {
        this.customDialog = dialog;
        this.messageId = 0;
        update(0);
        checkOnline();
    }

    public void setDialog(TLRPC.Dialog dialog, int type, int folder) {
        this.currentDialogId = dialog.id;
        this.isDialogCell = true;
        if (dialog instanceof TLRPC.TL_dialogFolder) {
            TLRPC.TL_dialogFolder dialogFolder = (TLRPC.TL_dialogFolder) dialog;
            this.currentDialogFolderId = dialogFolder.folder.id;
        } else {
            this.currentDialogFolderId = 0;
        }
        this.dialogsType = type;
        this.folderId = folder;
        this.messageId = 0;
        update(0);
        checkOnline();
    }

    public void setDialog(long dialog_id, MessageObject messageObject, int date) {
        this.currentDialogId = dialog_id;
        this.message = messageObject;
        this.isDialogCell = false;
        this.lastMessageDate = date;
        this.currentEditDate = messageObject != null ? messageObject.messageOwner.edit_date : 0;
        this.unreadCount = 0;
        this.markUnread = false;
        this.messageId = messageObject != null ? messageObject.getId() : 0;
        this.mentionCount = 0;
        this.lastUnreadState = messageObject != null && messageObject.isUnread();
        MessageObject messageObject2 = this.message;
        if (messageObject2 != null) {
            this.lastSendState = messageObject2.messageOwner.send_state;
        }
        update(0);
    }

    public void setCheckBoxVisible(boolean visible, boolean animated, int position) {
        this.position = position;
        if (visible && this.checkBox == null) {
            CheckBoxBase checkBoxBase = new CheckBoxBase(this, 21);
            this.checkBox = checkBoxBase;
            if (this.attachedToWindow) {
                checkBoxBase.onAttachedToWindow();
            }
        }
        this.checkBoxVisible = visible;
        this.checkBoxAnimationInProgress = animated;
        if (animated) {
            this.lastCheckBoxAnimationTime = SystemClock.uptimeMillis();
        } else {
            this.checkBoxAnimationProgress = visible ? 1.0f : 0.0f;
        }
        invalidate();
    }

    public void setChecked(boolean checked, boolean animated) {
        CheckBoxBase checkBoxBase = this.checkBox;
        if (checkBoxBase == null) {
            return;
        }
        checkBoxBase.setChecked(checked, animated);
    }

    @Override // android.view.View
    public void setScrollX(int value) {
        super.setScrollX(value);
    }

    private void checkOnline() {
        TLRPC.User user = this.user;
        boolean isOnline = (user == null || user.self || ((this.user.status == null || this.user.status.expires <= ConnectionsManager.getInstance(this.currentAccount).getCurrentTime()) && !MessagesController.getInstance(this.currentAccount).onlinePrivacy.containsKey(Integer.valueOf(this.user.id)))) ? false : true;
        this.onlineProgress = isOnline ? 1.0f : 0.0f;
    }

    public void setDialogIndex(int i) {
        this.index = i;
    }

    public int getDialogIndex() {
        return this.index;
    }

    public long getDialogId() {
        return this.currentDialogId;
    }

    public int getMessageId() {
        return this.messageId;
    }

    public boolean isUnread() {
        return (this.unreadCount != 0 || this.markUnread) && !this.dialogMuted;
    }

    public boolean isPinned() {
        return this.drawPinIcon;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.isSliding = false;
        this.drawRevealBackground = false;
        this.currentRevealProgress = 0.0f;
        this.attachedToWindow = false;
        this.reorderIconProgress = (this.drawPinIcon && this.drawReorder) ? 1.0f : 0.0f;
        this.avatarImage.onDetachedFromWindow();
        RLottieDrawable rLottieDrawable = this.translationDrawable;
        if (rLottieDrawable != null) {
            rLottieDrawable.stop();
            this.translationDrawable.setProgress(0.0f);
            this.translationDrawable.setCallback(null);
            this.translationDrawable = null;
            this.translationAnimationStarted = false;
        }
        CheckBoxBase checkBoxBase = this.checkBox;
        if (checkBoxBase != null) {
            checkBoxBase.onDetachedFromWindow();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.avatarImage.onAttachedToWindow();
        CheckBoxBase checkBoxBase = this.checkBox;
        if (checkBoxBase != null) {
            checkBoxBase.onAttachedToWindow();
        }
        boolean z = SharedConfig.archiveHidden;
        this.archiveHidden = z;
        float f = z ? 0.0f : 1.0f;
        this.archiveBackgroundProgress = f;
        this.avatarDrawable.setArchivedAvatarHiddenProgress(f);
        this.clipProgress = 0.0f;
        this.isSliding = false;
        this.reorderIconProgress = (this.drawPinIcon && this.drawReorder) ? 1.0f : 0.0f;
        this.attachedToWindow = true;
        this.cornerProgress = 0.0f;
        setTranslationX(0.0f);
        setTranslationY(0.0f);
    }

    @Override // android.view.View
    protected void onMeasure(int i, int i2) {
        setMeasuredDimension(View.MeasureSpec.getSize(i), AndroidUtilities.dp((this.useForceThreeLines || SharedConfig.useThreeLinesLayout) ? 77.0f : 71.0f) + (this.useSeparator ? 1 : 0));
        this.topClip = 0;
        this.bottomClip = getMeasuredHeight();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if ((this.currentDialogId != 0 || this.customDialog != null) && changed) {
            try {
                buildLayout();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    private CharSequence formatArchivedDialogNames() {
        String title;
        ArrayList<TLRPC.Dialog> dialogs = MessagesController.getInstance(this.currentAccount).getDialogs(this.currentDialogFolderId);
        this.currentDialogFolderDialogsCount = dialogs.size();
        SpannableStringBuilder builder = new SpannableStringBuilder();
        int N = dialogs.size();
        for (int a = 0; a < N; a++) {
            TLRPC.Dialog dialog = dialogs.get(a);
            TLRPC.User currentUser = null;
            TLRPC.Chat currentChat = null;
            if (DialogObject.isSecretDialogId(dialog.id)) {
                TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf((int) (dialog.id >> 32)));
                if (encryptedChat != null) {
                    currentUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(encryptedChat.user_id));
                }
            } else {
                int lowerId = (int) dialog.id;
                if (lowerId > 0) {
                    currentUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(lowerId));
                } else {
                    currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lowerId));
                }
            }
            if (currentChat != null) {
                title = currentChat.title.replace('\n', ' ');
            } else if (currentUser == null) {
                continue;
            } else {
                title = UserObject.isDeleted(currentUser) ? LocaleController.getString("HiddenName", R.string.HiddenName) : ContactsController.formatName(currentUser.first_name, currentUser.last_name).replace('\n', ' ');
            }
            if (builder.length() > 0) {
                builder.append(", ");
            }
            int boldStart = builder.length();
            int boldEnd = title.length() + boldStart;
            builder.append((CharSequence) title);
            if (dialog.unread_count > 0) {
                builder.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf"), 0, Theme.getColor(Theme.key_chats_nameArchived)), boldStart, boldEnd, 33);
            }
            if (builder.length() > 150) {
                break;
            }
        }
        return Emoji.replaceEmoji(builder, Theme.dialogs_messagePaint.getFontMetricsInt(), AndroidUtilities.dp(17.0f), false);
    }

    /* JADX WARN: Removed duplicated region for block: B:168:0x0348  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x0372  */
    /* JADX WARN: Removed duplicated region for block: B:241:0x042a  */
    /* JADX WARN: Removed duplicated region for block: B:624:0x0df0  */
    /* JADX WARN: Removed duplicated region for block: B:630:0x0e48  */
    /* JADX WARN: Removed duplicated region for block: B:635:0x0e6c  */
    /* JADX WARN: Removed duplicated region for block: B:645:0x0e99  */
    /* JADX WARN: Removed duplicated region for block: B:663:0x0f3b  */
    /* JADX WARN: Removed duplicated region for block: B:665:0x0f40  */
    /* JADX WARN: Removed duplicated region for block: B:687:0x0fd1  */
    /* JADX WARN: Removed duplicated region for block: B:726:0x1085 A[Catch: Exception -> 0x10f8, TryCatch #1 {Exception -> 0x10f8, blocks: (B:720:0x107a, B:722:0x107e, B:732:0x1095, B:734:0x1099, B:737:0x109f, B:739:0x10b0, B:741:0x10b4, B:744:0x10b9, B:745:0x10d1, B:749:0x10e7, B:726:0x1085, B:728:0x1089, B:730:0x108e), top: B:835:0x107a }] */
    /* JADX WARN: Removed duplicated region for block: B:741:0x10b4 A[Catch: Exception -> 0x10f8, TryCatch #1 {Exception -> 0x10f8, blocks: (B:720:0x107a, B:722:0x107e, B:732:0x1095, B:734:0x1099, B:737:0x109f, B:739:0x10b0, B:741:0x10b4, B:744:0x10b9, B:745:0x10d1, B:749:0x10e7, B:726:0x1085, B:728:0x1089, B:730:0x108e), top: B:835:0x107a }] */
    /* JADX WARN: Removed duplicated region for block: B:745:0x10d1 A[Catch: Exception -> 0x10f8, TryCatch #1 {Exception -> 0x10f8, blocks: (B:720:0x107a, B:722:0x107e, B:732:0x1095, B:734:0x1099, B:737:0x109f, B:739:0x10b0, B:741:0x10b4, B:744:0x10b9, B:745:0x10d1, B:749:0x10e7, B:726:0x1085, B:728:0x1089, B:730:0x108e), top: B:835:0x107a }] */
    /* JADX WARN: Removed duplicated region for block: B:747:0x10e2  */
    /* JADX WARN: Removed duplicated region for block: B:748:0x10e5  */
    /* JADX WARN: Removed duplicated region for block: B:755:0x1100  */
    /* JADX WARN: Removed duplicated region for block: B:803:0x121b  */
    /* JADX WARN: Removed duplicated region for block: B:840:0x0e9b A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void buildLayout() {
        /*
            Method dump skipped, instruction units count: 4776
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.DialogCell.buildLayout():void");
    }

    public boolean isPointInsideAvatar(float x, float y) {
        return !LocaleController.isRTL ? x >= 0.0f && x < ((float) AndroidUtilities.dp(60.0f)) : x >= ((float) (getMeasuredWidth() - AndroidUtilities.dp(60.0f))) && x < ((float) getMeasuredWidth());
    }

    public void setDialogSelected(boolean value) {
        if (this.isSelected != value) {
            invalidate();
        }
        this.isSelected = value;
    }

    public void checkCurrentDialogIndex(boolean frozen) {
        MessageObject newMessageObject;
        MessageObject messageObject;
        MessageObject messageObject2;
        ArrayList<TLRPC.Dialog> dialogsArray = DialogsActivity.getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, frozen);
        if (this.index < dialogsArray.size()) {
            TLRPC.Dialog dialog = dialogsArray.get(this.index);
            TLRPC.Dialog nextDialog = this.index + 1 < dialogsArray.size() ? dialogsArray.get(this.index + 1) : null;
            TLRPC.DraftMessage newDraftMessage = MediaDataController.getInstance(this.currentAccount).getDraft(this.currentDialogId);
            if (this.currentDialogFolderId != 0) {
                newMessageObject = findFolderTopMessage();
            } else {
                newMessageObject = MessagesController.getInstance(this.currentAccount).dialogMessage.get(dialog.id);
            }
            if (this.currentDialogId != dialog.id || (((messageObject = this.message) != null && messageObject.getId() != dialog.top_message) || ((newMessageObject != null && newMessageObject.messageOwner.edit_date != this.currentEditDate) || this.unreadCount != dialog.unread_count || this.mentionCount != dialog.unread_mentions_count || this.markUnread != dialog.unread_mark || (messageObject2 = this.message) != newMessageObject || ((messageObject2 == null && newMessageObject != null) || newDraftMessage != this.draftMessage || this.drawPinIcon != dialog.pinned)))) {
                boolean dialogChanged = this.currentDialogId != dialog.id;
                this.currentDialogId = dialog.id;
                if (dialog instanceof TLRPC.TL_dialogFolder) {
                    TLRPC.TL_dialogFolder dialogFolder = (TLRPC.TL_dialogFolder) dialog;
                    this.currentDialogFolderId = dialogFolder.folder.id;
                } else {
                    this.currentDialogFolderId = 0;
                }
                this.fullSeparator = (dialog instanceof TLRPC.TL_dialog) && dialog.pinned && nextDialog != null && !nextDialog.pinned;
                this.fullSeparator2 = (!(dialog instanceof TLRPC.TL_dialogFolder) || nextDialog == null || nextDialog.pinned) ? false : true;
                update(0);
                if (dialogChanged) {
                    this.reorderIconProgress = (this.drawPinIcon && this.drawReorder) ? 1.0f : 0.0f;
                }
                checkOnline();
            }
        }
    }

    public void animateArchiveAvatar() {
        if (this.avatarDrawable.getAvatarType() != 3) {
            return;
        }
        this.animatingArchiveAvatar = true;
        this.animatingArchiveAvatarProgress = 0.0f;
        Theme.dialogs_archiveAvatarDrawable.setProgress(0.0f);
        Theme.dialogs_archiveAvatarDrawable.start();
        invalidate();
    }

    private MessageObject findFolderTopMessage() {
        ArrayList<TLRPC.Dialog> dialogs = DialogsActivity.getDialogsArray(this.currentAccount, this.dialogsType, this.currentDialogFolderId, false);
        MessageObject maxMessage = null;
        if (!dialogs.isEmpty()) {
            int N = dialogs.size();
            for (int a = 0; a < N; a++) {
                TLRPC.Dialog dialog = dialogs.get(a);
                MessageObject object = MessagesController.getInstance(this.currentAccount).dialogMessage.get(dialog.id);
                if (object != null && (maxMessage == null || object.messageOwner.date > maxMessage.messageOwner.date)) {
                    maxMessage = object;
                }
                if (dialog.pinnedNum == 0) {
                    break;
                }
            }
        }
        return maxMessage;
    }

    public void update(int mask) {
        long dialogId;
        TLRPC.Chat chat2;
        MessageObject messageObject;
        TLRPC.Dialog dialog;
        MessageObject messageObject2;
        CharSequence charSequence;
        CustomDialog customDialog = this.customDialog;
        if (customDialog != null) {
            this.lastMessageDate = customDialog.date;
            this.lastUnreadState = this.customDialog.unread_count != 0;
            this.unreadCount = this.customDialog.unread_count;
            this.drawPinIcon = this.customDialog.pinned;
            this.dialogMuted = this.customDialog.muted;
            this.avatarDrawable.setInfo(this.customDialog.id, this.customDialog.name, null);
            this.avatarImage.setImage(null, "50_50", this.avatarDrawable, null, 0);
        } else {
            if (this.isDialogCell) {
                TLRPC.Dialog dialog2 = MessagesController.getInstance(this.currentAccount).dialogs_dict.get(this.currentDialogId);
                if (dialog2 != null) {
                    if (mask == 0) {
                        this.clearingDialog = MessagesController.getInstance(this.currentAccount).isClearingDialog(dialog2.id);
                        MessageObject messageObject3 = MessagesController.getInstance(this.currentAccount).dialogMessage.get(dialog2.id);
                        this.message = messageObject3;
                        this.lastUnreadState = messageObject3 != null && messageObject3.isUnread();
                        this.unreadCount = dialog2.unread_count;
                        this.markUnread = dialog2.unread_mark;
                        this.mentionCount = dialog2.unread_mentions_count;
                        MessageObject messageObject4 = this.message;
                        this.currentEditDate = messageObject4 != null ? messageObject4.messageOwner.edit_date : 0;
                        this.lastMessageDate = dialog2.last_message_date;
                        this.drawPinIcon = this.currentDialogFolderId == 0 && dialog2.pinned;
                        MessageObject messageObject5 = this.message;
                        if (messageObject5 != null) {
                            this.lastSendState = messageObject5.messageOwner.send_state;
                        }
                    }
                } else {
                    this.unreadCount = 0;
                    this.mentionCount = 0;
                    this.currentEditDate = 0;
                    this.lastMessageDate = 0;
                    this.clearingDialog = false;
                }
            } else {
                this.drawPinIcon = false;
            }
            if (mask != 0) {
                boolean continueUpdate = false;
                if (this.user != null && (mask & 4) != 0) {
                    this.user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.user.id));
                    invalidate();
                }
                if (this.isDialogCell && (mask & 64) != 0) {
                    CharSequence printString = MessagesController.getInstance(this.currentAccount).printingStrings.get(this.currentDialogId);
                    if ((this.lastPrintString != null && printString == null) || ((this.lastPrintString == null && printString != null) || ((charSequence = this.lastPrintString) != null && printString != null && !charSequence.equals(printString)))) {
                        continueUpdate = true;
                    }
                }
                if (!continueUpdate && (32768 & mask) != 0 && (messageObject2 = this.message) != null && messageObject2.messageText != this.lastMessageString) {
                    continueUpdate = true;
                }
                if (!continueUpdate && (mask & 2) != 0 && this.chat == null) {
                    continueUpdate = true;
                }
                if (!continueUpdate && (mask & 1) != 0 && this.chat == null) {
                    continueUpdate = true;
                }
                if (!continueUpdate && (mask & 8) != 0 && this.user == null) {
                    continueUpdate = true;
                }
                if (!continueUpdate && (mask & 16) != 0 && this.user == null) {
                    continueUpdate = true;
                }
                if (!continueUpdate && (mask & 256) != 0) {
                    MessageObject messageObject6 = this.message;
                    if (messageObject6 != null && this.lastUnreadState != messageObject6.isUnread()) {
                        this.lastUnreadState = this.message.isUnread();
                        continueUpdate = true;
                    } else if (this.isDialogCell && (dialog = MessagesController.getInstance(this.currentAccount).dialogs_dict.get(this.currentDialogId)) != null && (this.unreadCount != dialog.unread_count || this.markUnread != dialog.unread_mark || this.mentionCount != dialog.unread_mentions_count)) {
                        this.unreadCount = dialog.unread_count;
                        this.mentionCount = dialog.unread_mentions_count;
                        this.markUnread = dialog.unread_mark;
                        continueUpdate = true;
                    }
                }
                if (!continueUpdate && (mask & 4096) != 0 && (messageObject = this.message) != null && this.lastSendState != messageObject.messageOwner.send_state) {
                    this.lastSendState = this.message.messageOwner.send_state;
                    continueUpdate = true;
                }
                if (!continueUpdate) {
                    invalidate();
                    return;
                }
            }
            this.user = null;
            this.chat = null;
            this.encryptedChat = null;
            if (this.currentDialogFolderId == 0) {
                this.dialogMuted = this.isDialogCell && MessagesController.getInstance(this.currentAccount).isDialogMuted(this.currentDialogId);
                dialogId = this.currentDialogId;
            } else {
                this.dialogMuted = false;
                MessageObject messageObjectFindFolderTopMessage = findFolderTopMessage();
                this.message = messageObjectFindFolderTopMessage;
                if (messageObjectFindFolderTopMessage != null) {
                    dialogId = messageObjectFindFolderTopMessage.getDialogId();
                } else {
                    dialogId = 0;
                }
            }
            if (dialogId != 0) {
                int lower_id = (int) dialogId;
                int high_id = (int) (dialogId >> 32);
                if (lower_id != 0) {
                    if (lower_id >= 0) {
                        this.user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(lower_id));
                    } else {
                        TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
                        this.chat = chat;
                        if (!this.isDialogCell && chat != null && chat.migrated_to != null && (chat2 = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.chat.migrated_to.channel_id))) != null) {
                            this.chat = chat2;
                        }
                    }
                } else {
                    TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf(high_id));
                    this.encryptedChat = encryptedChat;
                    if (encryptedChat != null) {
                        this.user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.encryptedChat.user_id));
                    }
                }
            }
            if (this.currentDialogFolderId != 0) {
                Theme.dialogs_archiveAvatarDrawable.setCallback(this);
                this.avatarDrawable.setAvatarType(3);
                this.avatarImage.setImage(null, null, this.avatarDrawable, null, this.user, 0);
            } else {
                TLRPC.User user = this.user;
                if (user != null) {
                    this.avatarDrawable.setInfo(user);
                    if (!UserObject.isUserSelf(this.user)) {
                        this.avatarImage.setImage(ImageLocation.getForUser(this.user, false), "50_50", this.avatarDrawable, null, this.user, 0);
                    } else {
                        this.avatarDrawable.setAvatarType(1);
                        this.avatarImage.setImage(null, null, this.avatarDrawable, null, this.user, 0);
                    }
                } else {
                    TLRPC.Chat chat3 = this.chat;
                    if (chat3 != null) {
                        this.avatarDrawable.setInfo(chat3);
                        this.avatarImage.setImage(ImageLocation.getForChat(this.chat, false), "50_50", this.avatarDrawable, null, this.chat, 0);
                    }
                }
            }
        }
        if (getMeasuredWidth() != 0 || getMeasuredHeight() != 0) {
            buildLayout();
        } else {
            requestLayout();
        }
        invalidate();
    }

    public void drawCheckBox(Canvas canvas) {
        if (this.checkBox != null) {
            if (this.checkBoxVisible || this.checkBoxAnimationInProgress) {
                canvas.save();
                canvas.translate(0.0f, getTop());
                this.checkBox.draw(canvas);
                canvas.restore();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0294  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0308  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x035c  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x03b4  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x044b  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x044f  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0470  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0491  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x04ad  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x04d5  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x053a  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x06c8  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x06ef  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x06f6  */
    /* JADX WARN: Removed duplicated region for block: B:238:0x071d  */
    /* JADX WARN: Removed duplicated region for block: B:309:0x08b2  */
    /* JADX WARN: Removed duplicated region for block: B:312:0x08ba  */
    /* JADX WARN: Removed duplicated region for block: B:315:0x08c1  */
    /* JADX WARN: Removed duplicated region for block: B:321:0x090e  */
    /* JADX WARN: Removed duplicated region for block: B:329:0x0960  */
    /* JADX WARN: Removed duplicated region for block: B:331:0x0964  */
    /* JADX WARN: Removed duplicated region for block: B:337:0x097b  */
    /* JADX WARN: Removed duplicated region for block: B:345:0x0994  */
    /* JADX WARN: Removed duplicated region for block: B:354:0x09bc  */
    /* JADX WARN: Removed duplicated region for block: B:365:0x09e8  */
    /* JADX WARN: Removed duplicated region for block: B:371:0x09fe  */
    /* JADX WARN: Removed duplicated region for block: B:382:0x0a29  */
    /* JADX WARN: Removed duplicated region for block: B:393:0x0a4d  */
    /* JADX WARN: Removed duplicated region for block: B:399:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x01b4  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0230  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0238  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0266  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x027a  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x028f  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void onDraw(android.graphics.Canvas r24) {
        /*
            Method dump skipped, instruction units count: 2641
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.DialogCell.onDraw(android.graphics.Canvas):void");
    }

    public void onReorderStateChanged(boolean reordering, boolean animated) {
        if ((!this.drawPinIcon && reordering) || this.drawReorder == reordering) {
            if (!this.drawPinIcon) {
                this.drawReorder = false;
            }
        } else {
            this.drawReorder = reordering;
            if (animated) {
                this.reorderIconProgress = reordering ? 0.0f : 1.0f;
            } else {
                this.reorderIconProgress = reordering ? 1.0f : 0.0f;
            }
            invalidate();
        }
    }

    public void setSliding(boolean value) {
        this.isSliding = value;
    }

    @Override // android.view.View, android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable who) {
        if (who == this.translationDrawable || who == Theme.dialogs_archiveAvatarDrawable) {
            invalidate(who.getBounds());
        } else {
            super.invalidateDrawable(who);
        }
    }

    @Override // im.uwrkaxlmjj.ui.cells.BaseCell, android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        info.addAction(16);
        info.addAction(32);
    }

    @Override // android.view.View
    public void onPopulateAccessibilityEvent(AccessibilityEvent event) {
        TLRPC.User fromUser;
        super.onPopulateAccessibilityEvent(event);
        StringBuilder sb = new StringBuilder();
        if (this.currentDialogFolderId == 1) {
            sb.append(LocaleController.getString("ArchivedChats", R.string.ArchivedChats));
            sb.append(". ");
        } else {
            if (this.encryptedChat != null) {
                sb.append(LocaleController.getString("AccDescrSecretChat", R.string.AccDescrSecretChat));
                sb.append(". ");
            }
            TLRPC.User user = this.user;
            if (user != null) {
                if (user.bot) {
                    sb.append(LocaleController.getString("Bot", R.string.Bot));
                    sb.append(". ");
                }
                if (this.user.self) {
                    sb.append(LocaleController.getString("SavedMessages", R.string.SavedMessages));
                } else {
                    sb.append(ContactsController.formatName(this.user.first_name, this.user.last_name));
                }
                sb.append(". ");
            } else {
                TLRPC.Chat chat = this.chat;
                if (chat != null) {
                    if (chat.broadcast) {
                        sb.append(LocaleController.getString("AccDescrChannel", R.string.AccDescrChannel));
                    } else {
                        sb.append(LocaleController.getString("AccDescrGroup", R.string.AccDescrGroup));
                    }
                    sb.append(". ");
                    sb.append(this.chat.title);
                    sb.append(". ");
                }
            }
        }
        int i = this.unreadCount;
        if (i > 0) {
            sb.append(LocaleController.formatPluralString("NewMessages", i));
            sb.append(". ");
        }
        MessageObject messageObject = this.message;
        if (messageObject == null || this.currentDialogFolderId != 0) {
            event.setContentDescription(sb.toString());
            return;
        }
        int lastDate = this.lastMessageDate;
        if (this.lastMessageDate == 0 && messageObject != null) {
            lastDate = messageObject.messageOwner.date;
        }
        String date = LocaleController.formatDateAudio(lastDate);
        if (this.message.isOut()) {
            sb.append(LocaleController.formatString("AccDescrSentDate", R.string.AccDescrSentDate, date));
        } else {
            sb.append(LocaleController.formatString("AccDescrReceivedDate", R.string.AccDescrReceivedDate, date));
        }
        sb.append(". ");
        if (this.chat != null && !this.message.isOut() && this.message.isFromUser() && this.message.messageOwner.action == null && (fromUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.message.messageOwner.from_id))) != null) {
            sb.append(ContactsController.formatName(fromUser.first_name, fromUser.last_name));
            sb.append(". ");
        }
        if (this.encryptedChat == null) {
            sb.append(this.message.messageText);
            if (!this.message.isMediaEmpty() && !TextUtils.isEmpty(this.message.caption)) {
                sb.append(". ");
                sb.append(this.message.caption);
            }
        }
        event.setContentDescription(sb.toString());
    }

    public void setClipProgress(float value) {
        this.clipProgress = value;
        invalidate();
    }

    public float getClipProgress() {
        return this.clipProgress;
    }

    public void setTopClip(int value) {
        this.topClip = value;
    }

    public void setBottomClip(int value) {
        this.bottomClip = value;
    }
}
