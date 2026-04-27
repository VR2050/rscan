package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.RectF;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CheckBox2;
import im.uwrkaxlmjj.ui.components.CheckBoxBase;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ShareDialogCell extends FrameLayout {
    private AvatarDrawable avatarDrawable;
    private RectF checkBgRectF;
    private CheckBox2 checkBox;
    private int currentAccount;
    private BackupImageView imageView;
    private long lastUpdateTime;
    private TextView nameTextView;
    private float onlineProgress;
    private TLRPC.User user;

    public ShareDialogCell(Context context) {
        super(context);
        this.avatarDrawable = new AvatarDrawable();
        this.currentAccount = UserConfig.selectedAccount;
        setWillNotDraw(false);
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        addView(this.imageView, LayoutHelper.createFrame(56.0f, 56.0f, 49, 0.0f, 7.0f, 0.0f, 0.0f));
        TextView textView = new TextView(context);
        this.nameTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.nameTextView.setTextSize(1, 12.0f);
        this.nameTextView.setMaxLines(2);
        this.nameTextView.setGravity(49);
        this.nameTextView.setLines(2);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        addView(this.nameTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 6.0f, 66.0f, 6.0f, 0.0f));
        CheckBox2 checkBox2 = new CheckBox2(context, 21);
        this.checkBox = checkBox2;
        checkBox2.setColor(Theme.key_dialogRoundCheckBox, Theme.key_dialogBackground, Theme.key_dialogRoundCheckBoxCheck);
        this.checkBox.setDrawUnchecked(false);
        this.checkBox.setDrawBackgroundAsArc(4);
        this.checkBox.setProgressDelegate(new CheckBoxBase.ProgressDelegate() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ShareDialogCell$ZVjuitG7MJ5tI-SeH9DsNprErtg
            @Override // im.uwrkaxlmjj.ui.components.CheckBoxBase.ProgressDelegate
            public final void setProgress(float f) {
                this.f$0.lambda$new$0$ShareDialogCell(f);
            }
        });
        addView(this.checkBox, LayoutHelper.createFrame(24.0f, 24.0f, 49, 19.0f, 42.0f, 0.0f, 0.0f));
        this.checkBgRectF = new RectF();
    }

    public /* synthetic */ void lambda$new$0$ShareDialogCell(float progress) {
        float scale = 1.0f - (this.checkBox.getProgress() * 0.143f);
        this.imageView.setScaleX(scale);
        this.imageView.setScaleY(scale);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(103.0f), 1073741824));
    }

    public void setDialog(int uid, boolean checked, CharSequence name) {
        if (uid > 0) {
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(uid));
            this.user = user;
            this.avatarDrawable.setInfo(user);
            if (UserObject.isUserSelf(this.user)) {
                this.nameTextView.setText(LocaleController.getString("SavedMessages", R.string.SavedMessages));
                this.avatarDrawable.setAvatarType(1);
                this.imageView.setImage((ImageLocation) null, (String) null, this.avatarDrawable, this.user);
            } else {
                if (name != null) {
                    this.nameTextView.setText(name);
                } else {
                    TLRPC.User user2 = this.user;
                    if (user2 != null) {
                        this.nameTextView.setText(ContactsController.formatName(user2.first_name, this.user.last_name));
                    } else {
                        this.nameTextView.setText("");
                    }
                }
                this.imageView.setImage(ImageLocation.getForUser(this.user, false), "50_50", this.avatarDrawable, this.user);
            }
        } else {
            this.user = null;
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-uid));
            if (name != null) {
                this.nameTextView.setText(name);
            } else if (chat != null) {
                this.nameTextView.setText(chat.title);
            } else {
                this.nameTextView.setText("");
            }
            this.avatarDrawable.setInfo(chat);
            this.imageView.setImage(ImageLocation.getForChat(chat, false), "50_50", this.avatarDrawable, chat);
        }
        this.checkBox.setChecked(checked, false);
    }

    public void setChecked(boolean checked, boolean animated) {
        this.checkBox.setChecked(checked, animated);
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        TLRPC.User user;
        boolean result = super.drawChild(canvas, child, drawingTime);
        if (child == this.imageView && (user = this.user) != null && !MessagesController.isSupportUser(user)) {
            long newTime = SystemClock.uptimeMillis();
            long dt = newTime - this.lastUpdateTime;
            if (dt > 17) {
                dt = 17;
            }
            this.lastUpdateTime = newTime;
            boolean isOnline = (this.user.self || this.user.bot || ((this.user.status == null || this.user.status.expires <= ConnectionsManager.getInstance(this.currentAccount).getCurrentTime()) && !MessagesController.getInstance(this.currentAccount).onlinePrivacy.containsKey(Integer.valueOf(this.user.id)))) ? false : true;
            if (isOnline || this.onlineProgress != 0.0f) {
                int top = this.imageView.getBottom() - AndroidUtilities.dp(6.0f);
                int left = this.imageView.getRight() - AndroidUtilities.dp(7.0f);
                Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                canvas.drawCircle(left, top, AndroidUtilities.dp(7.0f) * this.onlineProgress, Theme.dialogs_onlineCirclePaint);
                Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_chats_onlineCircle));
                canvas.drawCircle(left, top, AndroidUtilities.dp(5.0f) * this.onlineProgress, Theme.dialogs_onlineCirclePaint);
                if (isOnline) {
                    float f = this.onlineProgress;
                    if (f < 1.0f) {
                        float f2 = f + (dt / 150.0f);
                        this.onlineProgress = f2;
                        if (f2 > 1.0f) {
                            this.onlineProgress = 1.0f;
                        }
                        this.imageView.invalidate();
                        invalidate();
                    }
                } else {
                    float f3 = this.onlineProgress;
                    if (f3 > 0.0f) {
                        float f4 = f3 - (dt / 150.0f);
                        this.onlineProgress = f4;
                        if (f4 < 0.0f) {
                            this.onlineProgress = 0.0f;
                        }
                        this.imageView.invalidate();
                        invalidate();
                    }
                }
            }
        }
        return result;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        Theme.checkboxSquare_checkPaint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBox));
        Theme.checkboxSquare_checkPaint.setAlpha((int) (this.checkBox.getProgress() * 255.0f));
        this.checkBgRectF.set(this.imageView.getLeft(), this.imageView.getTop(), this.imageView.getRight(), this.imageView.getBottom());
        float radius = AndroidUtilities.dp(7.5f);
        canvas.drawRoundRect(this.checkBgRectF, radius, radius, Theme.checkboxSquare_checkPaint);
    }
}
