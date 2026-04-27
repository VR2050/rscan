package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.RectF;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextUtils;
import android.text.style.ClickableSpan;
import android.text.style.URLSpan;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatActionCell extends BaseCell {
    private AvatarDrawable avatarDrawable;
    private int currentAccount;
    private MessageObject currentMessageObject;
    private int customDate;
    private CharSequence customText;
    private ChatActionCellDelegate delegate;
    private boolean hasReplyMessage;
    private boolean imagePressed;
    private ImageReceiver imageReceiver;
    private float lastTouchX;
    private float lastTouchY;
    private URLSpan pressedLink;
    private ClickableSpan pressedRedLink;
    private int previousWidth;
    private int textHeight;
    private StaticLayout textLayout;
    private int textWidth;
    private int textX;
    private int textXLeft;
    private int textY;
    private boolean wasLayout;

    public interface ChatActionCellDelegate {
        void didClickImage(ChatActionCell chatActionCell);

        void didLongPress(ChatActionCell chatActionCell, float f, float f2);

        void didPressBotButton(MessageObject messageObject, TLRPC.KeyboardButton keyboardButton);

        void didPressReplyMessage(ChatActionCell chatActionCell, int i);

        void didRedUrl(MessageObject messageObject);

        void needOpenUserProfile(int i);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.cells.ChatActionCell$ChatActionCellDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$didClickImage(ChatActionCellDelegate _this, ChatActionCell cell) {
            }

            public static void $default$didLongPress(ChatActionCellDelegate _this, ChatActionCell cell, float x, float y) {
            }

            public static void $default$needOpenUserProfile(ChatActionCellDelegate _this, int uid) {
            }

            public static void $default$didPressBotButton(ChatActionCellDelegate _this, MessageObject messageObject, TLRPC.KeyboardButton button) {
            }

            public static void $default$didPressReplyMessage(ChatActionCellDelegate _this, ChatActionCell cell, int id) {
            }

            public static void $default$didRedUrl(ChatActionCellDelegate _this, MessageObject messageObject) {
            }
        }
    }

    public ChatActionCell(Context context) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        ImageReceiver imageReceiver = new ImageReceiver(this);
        this.imageReceiver = imageReceiver;
        imageReceiver.setRoundRadius(AndroidUtilities.dp(32.0f));
        this.avatarDrawable = new AvatarDrawable();
    }

    public void setDelegate(ChatActionCellDelegate delegate) {
        this.delegate = delegate;
    }

    public void setCustomDate(int date, boolean scheduled) {
        CharSequence newText;
        if (this.customDate == date) {
            return;
        }
        if (scheduled) {
            newText = LocaleController.formatString("MessageScheduledOn", R.string.MessageScheduledOn, LocaleController.formatDateChat(date));
        } else {
            newText = LocaleController.formatDateChat(date);
        }
        CharSequence charSequence = this.customText;
        if (charSequence != null && TextUtils.equals(newText, charSequence)) {
            return;
        }
        this.customDate = date;
        this.customText = newText;
        if (getMeasuredWidth() != 0) {
            createLayout(this.customText, getMeasuredWidth());
            invalidate();
        }
        if (!this.wasLayout) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ghq6MqeQ7W1I9obKQ2sgiV5GEC4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.requestLayout();
                }
            });
        } else {
            buildLayout();
        }
    }

    public void setMessageObject(MessageObject messageObject) {
        if (this.currentMessageObject == messageObject && (this.hasReplyMessage || messageObject.replyMessageObject == null)) {
            return;
        }
        this.currentMessageObject = messageObject;
        messageObject.setDelegate(new MessageObject.Delegate() { // from class: im.uwrkaxlmjj.ui.cells.ChatActionCell.1
            @Override // im.uwrkaxlmjj.messenger.MessageObject.Delegate
            public void onClickRed() {
                if (ChatActionCell.this.delegate != null) {
                    ChatActionCell.this.delegate.didRedUrl(ChatActionCell.this.currentMessageObject);
                }
            }
        });
        this.hasReplyMessage = messageObject.replyMessageObject != null;
        this.previousWidth = 0;
        if (this.currentMessageObject.type == 11) {
            int id = 0;
            if (messageObject.messageOwner.to_id != null) {
                if (messageObject.messageOwner.to_id.chat_id != 0) {
                    id = messageObject.messageOwner.to_id.chat_id;
                } else if (messageObject.messageOwner.to_id.channel_id != 0) {
                    id = messageObject.messageOwner.to_id.channel_id;
                } else {
                    id = messageObject.messageOwner.to_id.user_id;
                    if (id == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                        id = messageObject.messageOwner.from_id;
                    }
                }
            }
            this.avatarDrawable.setInfo(id, null, null);
            if (this.currentMessageObject.messageOwner.action instanceof TLRPC.TL_messageActionUserUpdatedPhoto) {
                this.imageReceiver.setImage(null, null, this.avatarDrawable, null, this.currentMessageObject, 0);
            } else {
                TLRPC.PhotoSize photo = FileLoader.getClosestPhotoSizeWithSize(this.currentMessageObject.photoThumbs, AndroidUtilities.dp(64.0f));
                if (photo != null) {
                    this.imageReceiver.setImage(ImageLocation.getForObject(photo, this.currentMessageObject.photoThumbsObject), "50_50", this.avatarDrawable, null, this.currentMessageObject, 0);
                } else {
                    this.imageReceiver.setImageBitmap(this.avatarDrawable);
                }
            }
            this.imageReceiver.setVisible(true ^ PhotoViewer.isShowingImage(this.currentMessageObject), false);
        } else {
            this.imageReceiver.setImageBitmap((Bitmap) null);
        }
        requestLayout();
    }

    public MessageObject getMessageObject() {
        return this.currentMessageObject;
    }

    public ImageReceiver getPhotoImage() {
        return this.imageReceiver;
    }

    @Override // im.uwrkaxlmjj.ui.cells.BaseCell
    protected void onLongPress() {
        ChatActionCellDelegate chatActionCellDelegate = this.delegate;
        if (chatActionCellDelegate != null) {
            chatActionCellDelegate.didLongPress(this, this.lastTouchX, this.lastTouchY);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.wasLayout = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:96:0x0182  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r12) {
        /*
            Method dump skipped, instruction units count: 397
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatActionCell.onTouchEvent(android.view.MotionEvent):boolean");
    }

    private void createLayout(CharSequence text, int width) {
        if (TextUtils.isEmpty(text)) {
            return;
        }
        int maxWidth = width - AndroidUtilities.dp(30.0f);
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && messageObject.messageOwner != null && this.currentMessageObject.messageOwner.action != null && (this.currentMessageObject.messageOwner.action instanceof TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer)) {
            Theme.chat_actionTextPaint.setColor(Theme.getColor(Theme.key_chat_redpacketServiceText));
            Theme.chat_actionTextPaint.linkColor = Theme.getColor(Theme.key_chat_redpacketLinkServiceText);
        } else {
            Theme.chat_actionTextPaint.setColor(Theme.getColor(Theme.key_chat_serviceText));
            Theme.chat_actionTextPaint.linkColor = Theme.getColor(Theme.key_chat_serviceLink);
        }
        StaticLayout staticLayout = new StaticLayout(text, Theme.chat_actionTextPaint, maxWidth, Layout.Alignment.ALIGN_CENTER, 1.0f, 0.0f, false);
        this.textLayout = staticLayout;
        this.textHeight = 0;
        this.textWidth = 0;
        try {
            int linesCount = staticLayout.getLineCount();
            for (int a = 0; a < linesCount; a++) {
                try {
                    float lineWidth = this.textLayout.getLineWidth(a);
                    if (lineWidth > maxWidth) {
                        lineWidth = maxWidth;
                    }
                    this.textHeight = (int) Math.max(this.textHeight, Math.ceil(this.textLayout.getLineBottom(a)));
                    this.textWidth = (int) Math.max(this.textWidth, Math.ceil(lineWidth));
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        this.textX = (width - this.textWidth) / 2;
        this.textY = AndroidUtilities.dp(11.0f);
        this.textXLeft = (width - this.textLayout.getWidth()) / 2;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (this.currentMessageObject == null && this.customText == null) {
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), this.textHeight + AndroidUtilities.dp(20.0f));
            return;
        }
        int width = Math.max(AndroidUtilities.dp(30.0f), View.MeasureSpec.getSize(widthMeasureSpec));
        if (this.previousWidth != width) {
            this.wasLayout = true;
            this.previousWidth = width;
            buildLayout();
        }
        MessageObject messageObject = this.currentMessageObject;
        int i = 0;
        if (messageObject != null && (messageObject.messageOwner.media instanceof TLRPCRedpacket.CL_messagesPayBillOverMedia) && TextUtils.isEmpty(this.currentMessageObject.messageText)) {
            setMeasuredDimension(width, 0);
            return;
        }
        int i2 = this.textHeight;
        MessageObject messageObject2 = this.currentMessageObject;
        if (messageObject2 != null && messageObject2.type == 11) {
            i = 70;
        }
        setMeasuredDimension(width, i2 + AndroidUtilities.dp(20 + i));
    }

    private void buildLayout() {
        CharSequence text;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null) {
            if (messageObject.messageOwner != null && this.currentMessageObject.messageOwner.media != null && this.currentMessageObject.messageOwner.media.ttl_seconds != 0) {
                if (this.currentMessageObject.messageOwner.media.photo instanceof TLRPC.TL_photoEmpty) {
                    text = LocaleController.getString("AttachPhotoExpired", R.string.AttachPhotoExpired);
                } else if (this.currentMessageObject.messageOwner.media.document instanceof TLRPC.TL_documentEmpty) {
                    text = LocaleController.getString("AttachVideoExpired", R.string.AttachVideoExpired);
                } else {
                    text = this.currentMessageObject.messageText;
                }
            } else {
                text = this.currentMessageObject.messageText;
            }
        } else {
            text = this.customText;
        }
        createLayout(text, this.previousWidth);
        MessageObject messageObject2 = this.currentMessageObject;
        if (messageObject2 != null && messageObject2.type == 11) {
            this.imageReceiver.setImageCoords((this.previousWidth - AndroidUtilities.dp(64.0f)) / 2, this.textHeight + AndroidUtilities.dp(15.0f), AndroidUtilities.dp(64.0f), AndroidUtilities.dp(64.0f));
        }
    }

    public int getCustomDate() {
        return this.customDate;
    }

    private int findMaxWidthAroundLine(int line) {
        int width = (int) Math.ceil(this.textLayout.getLineWidth(line));
        int count = this.textLayout.getLineCount();
        for (int a = line + 1; a < count; a++) {
            int w = (int) Math.ceil(this.textLayout.getLineWidth(a));
            if (Math.abs(w - width) >= AndroidUtilities.dp(10.0f)) {
                break;
            }
            width = Math.max(w, width);
        }
        for (int a2 = line - 1; a2 >= 0; a2--) {
            int w2 = (int) Math.ceil(this.textLayout.getLineWidth(a2));
            if (Math.abs(w2 - width) >= AndroidUtilities.dp(10.0f)) {
                break;
            }
            width = Math.max(w2, width);
        }
        return width;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && messageObject.type == 11) {
            this.imageReceiver.draw(canvas);
        }
        StaticLayout staticLayout = this.textLayout;
        if (staticLayout != null) {
            int count = staticLayout.getLineCount();
            int previousLineBottom = 0;
            int finalWidth = AndroidUtilities.dp(50.0f);
            int finalHeight = AndroidUtilities.dp(6.0f);
            int finalY = AndroidUtilities.dp(8.0f);
            for (int a = 0; a < count; a++) {
                int width = findMaxWidthAroundLine(a);
                if (width > finalWidth) {
                    finalWidth = width;
                }
                int lineBottom = this.textLayout.getLineBottom(a);
                int height = lineBottom - previousLineBottom;
                finalHeight += height;
                previousLineBottom = lineBottom;
            }
            int finalX = (getMeasuredWidth() - (finalWidth + AndroidUtilities.dp(11.0f))) / 2;
            RectF rectF = new RectF(finalX, finalY, finalX + r2, finalHeight + finalY);
            canvas.drawRoundRect(rectF, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.chat_actionBackgroundPaint2);
            canvas.save();
            canvas.translate(this.textXLeft, this.textY);
            MessageObject messageObject2 = this.currentMessageObject;
            if (messageObject2 != null && messageObject2.messageOwner != null && this.currentMessageObject.messageOwner.action != null && (this.currentMessageObject.messageOwner.action instanceof TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer)) {
                Theme.chat_actionTextPaint.setColor(Theme.getColor(Theme.key_chat_redpacketServiceText));
                Theme.chat_actionTextPaint.linkColor = Theme.getColor(Theme.key_chat_redpacketServiceText);
            } else {
                Theme.chat_actionTextPaint.setColor(Theme.getColor(Theme.key_chat_serviceText));
                Theme.chat_actionTextPaint.linkColor = Theme.getColor(Theme.key_chat_serviceLink);
            }
            this.textLayout.draw(canvas);
            canvas.restore();
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        if (TextUtils.isEmpty(this.customText) && this.currentMessageObject == null) {
            return;
        }
        info.setText(!TextUtils.isEmpty(this.customText) ? this.customText : this.currentMessageObject.messageText);
        info.setEnabled(true);
    }
}
