package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.text.style.CharacterStyle;
import android.view.MotionEvent;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBarLayout;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ThemePreviewMessagesCell extends LinearLayout {
    private Drawable backgroundDrawable;
    private ChatMessageCell[] cells;
    private Drawable oldBackgroundDrawable;
    private ActionBarLayout parentLayout;
    private Drawable shadowDrawable;

    public ThemePreviewMessagesCell(Context context, ActionBarLayout layout, int type) {
        super(context);
        this.cells = new ChatMessageCell[2];
        this.parentLayout = layout;
        setWillNotDraw(false);
        setOrientation(1);
        setPadding(0, AndroidUtilities.dp(11.0f), 0, AndroidUtilities.dp(11.0f));
        this.shadowDrawable = Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow);
        int date = ((int) (System.currentTimeMillis() / 1000)) - 3600;
        TLRPC.Message message = new TLRPC.TL_message();
        if (type == 0) {
            message.message = LocaleController.getString("FontSizePreviewReply", R.string.FontSizePreviewReply);
        } else {
            message.message = LocaleController.getString("NewThemePreviewReply", R.string.NewThemePreviewReply);
        }
        message.date = date + 60;
        message.dialog_id = 1L;
        message.flags = 259;
        message.from_id = UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId();
        message.id = 1;
        message.media = new TLRPC.TL_messageMediaEmpty();
        message.out = true;
        message.to_id = new TLRPC.TL_peerUser();
        message.to_id.user_id = 0;
        MessageObject replyMessageObject = new MessageObject(UserConfig.selectedAccount, message, true);
        TLRPC.Message message2 = new TLRPC.TL_message();
        if (type == 0) {
            message2.message = LocaleController.getString("FontSizePreviewLine2", R.string.FontSizePreviewLine2);
        } else {
            message2.message = LocaleController.getString("NewThemePreviewLine2", R.string.NewThemePreviewLine2);
        }
        message2.date = date + 960;
        message2.dialog_id = 1L;
        message2.flags = 259;
        message2.from_id = UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId();
        message2.id = 1;
        message2.media = new TLRPC.TL_messageMediaEmpty();
        message2.out = true;
        message2.to_id = new TLRPC.TL_peerUser();
        message2.to_id.user_id = 0;
        MessageObject message1 = new MessageObject(UserConfig.selectedAccount, message2, true);
        message1.resetLayout();
        message1.eventId = 1L;
        TLRPC.Message message3 = new TLRPC.TL_message();
        if (type == 0) {
            message3.message = LocaleController.getString("FontSizePreviewLine1", R.string.FontSizePreviewLine1);
        } else {
            message3.message = LocaleController.getString("NewThemePreviewLine1", R.string.NewThemePreviewLine1);
        }
        message3.date = date + 60;
        message3.dialog_id = 1L;
        message3.flags = 265;
        message3.from_id = 0;
        message3.id = 1;
        message3.reply_to_msg_id = 5;
        message3.media = new TLRPC.TL_messageMediaEmpty();
        message3.out = false;
        message3.to_id = new TLRPC.TL_peerUser();
        message3.to_id.user_id = UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId();
        MessageObject message22 = new MessageObject(UserConfig.selectedAccount, message3, true);
        if (type == 0) {
            message22.customReplyName = LocaleController.getString("FontSizePreviewName", R.string.FontSizePreviewName);
        } else {
            message22.customReplyName = LocaleController.getString("NewThemePreviewName", R.string.NewThemePreviewName);
        }
        message22.eventId = 1L;
        message22.resetLayout();
        message22.replyMessageObject = replyMessageObject;
        int a = 0;
        while (true) {
            ChatMessageCell[] chatMessageCellArr = this.cells;
            if (a < chatMessageCellArr.length) {
                chatMessageCellArr[a] = new ChatMessageCell(context);
                this.cells[a].setDelegate(new ChatMessageCell.ChatMessageCellDelegate() { // from class: im.uwrkaxlmjj.ui.cells.ThemePreviewMessagesCell.1
                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean canPerformActions() {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$canPerformActions(this);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didLongPress(ChatMessageCell chatMessageCell, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPress(this, chatMessageCell, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didLongPressUserAvatar(ChatMessageCell chatMessageCell, TLRPC.User user, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPressUserAvatar(this, chatMessageCell, user, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressBotButton(ChatMessageCell chatMessageCell, TLRPC.KeyboardButton keyboardButton) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressBotButton(this, chatMessageCell, keyboardButton);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressCancelSendButton(ChatMessageCell chatMessageCell) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressCancelSendButton(this, chatMessageCell);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressChannelAvatar(ChatMessageCell chatMessageCell, TLRPC.Chat chat, int i, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressChannelAvatar(this, chatMessageCell, chat, i, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressHiddenForward(ChatMessageCell chatMessageCell) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressHiddenForward(this, chatMessageCell);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressImage(ChatMessageCell chatMessageCell, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressImage(this, chatMessageCell, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressInstantButton(ChatMessageCell chatMessageCell, int i) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressInstantButton(this, chatMessageCell, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressOther(ChatMessageCell chatMessageCell, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressOther(this, chatMessageCell, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressReaction(ChatMessageCell chatMessageCell, TLRPC.TL_reactionCount tL_reactionCount) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReaction(this, chatMessageCell, tL_reactionCount);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressRedpkgTransfer(ChatMessageCell chatMessageCell, MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressRedpkgTransfer(this, chatMessageCell, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressReplyMessage(ChatMessageCell chatMessageCell, int i) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReplyMessage(this, chatMessageCell, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressShare(ChatMessageCell chatMessageCell) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressShare(this, chatMessageCell);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressSysNotifyVideoFullPlayer(ChatMessageCell chatMessageCell) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressSysNotifyVideoFullPlayer(this, chatMessageCell);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressUrl(ChatMessageCell chatMessageCell, CharacterStyle characterStyle, boolean z) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUrl(this, chatMessageCell, characterStyle, z);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressUserAvatar(ChatMessageCell chatMessageCell, TLRPC.User user, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUserAvatar(this, chatMessageCell, user, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressViaBot(ChatMessageCell chatMessageCell, String str) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressViaBot(this, chatMessageCell, str);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressVoteButton(ChatMessageCell chatMessageCell, TLRPC.TL_pollAnswer tL_pollAnswer) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressVoteButton(this, chatMessageCell, tL_pollAnswer);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didStartVideoStream(MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didStartVideoStream(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ String getAdminRank(int i) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$getAdminRank(this, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void needOpenWebView(String str, String str2, String str3, String str4, int i, int i2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$needOpenWebView(this, str, str2, str3, str4, i, i2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean needPlayMessage(MessageObject messageObject) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$needPlayMessage(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void setShouldNotRepeatSticker(MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$setShouldNotRepeatSticker(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean shouldRepeatSticker(MessageObject messageObject) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$shouldRepeatSticker(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void videoTimerReached() {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$videoTimerReached(this);
                    }
                });
                this.cells[a].isChat = false;
                this.cells[a].setFullyDraw(true);
                this.cells[a].setMessageObject(a == 0 ? message22 : message1, null, false, false);
                addView(this.cells[a], LayoutHelper.createLinear(-1, -2));
                a++;
            } else {
                return;
            }
        }
    }

    public ChatMessageCell[] getCells() {
        return this.cells;
    }

    @Override // android.view.View
    public void invalidate() {
        super.invalidate();
        int a = 0;
        while (true) {
            ChatMessageCell[] chatMessageCellArr = this.cells;
            if (a < chatMessageCellArr.length) {
                chatMessageCellArr[a].invalidate();
                a++;
            } else {
                return;
            }
        }
    }

    @Override // android.widget.LinearLayout, android.view.View
    protected void onDraw(Canvas canvas) {
        Drawable newDrawable;
        Drawable newDrawable2 = Theme.getCachedWallpaperNonBlocking();
        if (newDrawable2 != this.backgroundDrawable && newDrawable2 != null) {
            if (Theme.isAnimatingColor()) {
                this.oldBackgroundDrawable = this.backgroundDrawable;
            }
            this.backgroundDrawable = newDrawable2;
        }
        float themeAnimationValue = this.parentLayout.getThemeAnimationValue();
        int a = 0;
        while (a < 2) {
            Drawable drawable = a == 0 ? this.oldBackgroundDrawable : this.backgroundDrawable;
            if (drawable == null) {
                newDrawable = newDrawable2;
            } else {
                if (a == 1 && this.oldBackgroundDrawable != null && this.parentLayout != null) {
                    drawable.setAlpha((int) (255.0f * themeAnimationValue));
                } else {
                    drawable.setAlpha(255);
                }
                if ((drawable instanceof ColorDrawable) || (drawable instanceof GradientDrawable)) {
                    newDrawable = newDrawable2;
                    drawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
                    drawable.draw(canvas);
                    if (a != 0 && this.oldBackgroundDrawable != null && themeAnimationValue >= 1.0f) {
                        this.oldBackgroundDrawable = null;
                    }
                } else {
                    if (!(drawable instanceof BitmapDrawable)) {
                        newDrawable = newDrawable2;
                    } else {
                        BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
                        if (bitmapDrawable.getTileModeX() == Shader.TileMode.REPEAT) {
                            canvas.save();
                            float scale = 2.0f / AndroidUtilities.density;
                            canvas.scale(scale, scale);
                            drawable.setBounds(0, 0, (int) Math.ceil(getMeasuredWidth() / scale), (int) Math.ceil(getMeasuredHeight() / scale));
                            drawable.draw(canvas);
                            canvas.restore();
                            newDrawable = newDrawable2;
                        } else {
                            int viewHeight = getMeasuredHeight();
                            float scaleX = getMeasuredWidth() / drawable.getIntrinsicWidth();
                            float scaleY = viewHeight / drawable.getIntrinsicHeight();
                            float scale2 = scaleX < scaleY ? scaleY : scaleX;
                            int width = (int) Math.ceil(drawable.getIntrinsicWidth() * scale2);
                            int height = (int) Math.ceil(drawable.getIntrinsicHeight() * scale2);
                            int x = (getMeasuredWidth() - width) / 2;
                            int y = (viewHeight - height) / 2;
                            canvas.save();
                            newDrawable = newDrawable2;
                            canvas.clipRect(0, 0, width, getMeasuredHeight());
                            drawable.setBounds(x, y, x + width, y + height);
                            drawable.draw(canvas);
                            canvas.restore();
                        }
                    }
                    if (a != 0) {
                    }
                }
            }
            a++;
            newDrawable2 = newDrawable;
        }
        this.shadowDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
        this.shadowDrawable.draw(canvas);
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        return false;
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent ev) {
        return false;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchSetPressed(boolean pressed) {
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        return false;
    }
}
