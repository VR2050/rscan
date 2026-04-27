package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.RectF;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.GroupCreateCheckBox;
import im.uwrkaxlmjj.ui.components.LayoutHelper;

/* JADX INFO: loaded from: classes5.dex */
public class PopUserCell extends FrameLayout implements NotificationCenter.NotificationCenterDelegate {
    private int accountNumber;
    private AvatarDrawable avatarDrawable;
    private GroupCreateCheckBox checkBox;
    private BackupImageView imageView;
    private RectF rect;
    private TextView textView;

    public PopUserCell(Context context) {
        super(context);
        this.rect = new RectF();
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        this.avatarDrawable = avatarDrawable;
        avatarDrawable.setTextSize(AndroidUtilities.dp(12.0f));
        BackupImageView backupImageView = new BackupImageView(context);
        this.imageView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        addView(this.imageView, LayoutHelper.createFrame(36.0f, 36.0f, 51, 16.0f, 6.0f, 16.0f, 0.0f));
        TextView textView = new TextView(context);
        this.textView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_chats_menuItemText));
        this.textView.setTextSize(1, 14.0f);
        this.textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.textView.setLines(1);
        this.textView.setMaxLines(1);
        this.textView.setSingleLine(true);
        this.textView.setGravity(19);
        this.textView.setEllipsize(TextUtils.TruncateAt.END);
        addView(this.textView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 67.0f, 0.0f, 8.0f, 0.0f));
        GroupCreateCheckBox groupCreateCheckBox = new GroupCreateCheckBox(context);
        this.checkBox = groupCreateCheckBox;
        groupCreateCheckBox.setChecked(true, false);
        this.checkBox.setCheckScale(0.9f);
        this.checkBox.setInnerRadDiff(AndroidUtilities.dp(1.5f));
        this.checkBox.setColorKeysOverrides(Theme.key_chats_unreadCounterText, Theme.key_chats_unreadCounter, Theme.key_chats_menuBackground);
        addView(this.checkBox, LayoutHelper.createFrame(18.0f, 18.0f, 51, 37.0f, 27.0f, 0.0f, 0.0f));
        setWillNotDraw(false);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.textView.setTextColor(Theme.getColor(Theme.key_chats_menuItemText));
        NotificationCenter.getInstance(this.accountNumber).addObserver(this, NotificationCenter.dialogsUnreadCounterChanged);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        NotificationCenter.getInstance(this.accountNumber).removeObserver(this, NotificationCenter.dialogsUnreadCounterChanged);
    }

    public void setAccount(int account) {
        this.accountNumber = account;
        TLRPC.User user = UserConfig.getInstance(account).getCurrentUser();
        if (user == null) {
            return;
        }
        this.avatarDrawable.setInfo(user);
        this.textView.setText(ContactsController.formatName(user.first_name, user.last_name));
        this.imageView.getImageReceiver().setCurrentAccount(account);
        this.imageView.setImage(ImageLocation.getForUser(user, false), "50_50", this.avatarDrawable, user);
        this.checkBox.setVisibility(account != UserConfig.selectedAccount ? 4 : 0);
    }

    public int getAccountNumber() {
        return this.accountNumber;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        NotificationsController.getInstance(this.accountNumber).getTotalUnreadCount();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (UserConfig.getActivatedAccountsCount() <= 1 || !NotificationsController.getInstance(this.accountNumber).showBadgeNumber) {
            return;
        }
        int count = NotificationsController.getInstance(this.accountNumber).getTotalUnreadCount();
        int nameWidth = getMeasuredWidth() - AndroidUtilities.dp(100.0f);
        if (count <= 0) {
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) this.textView.getLayoutParams();
            if (lp != null && lp.width != nameWidth) {
                lp.width = nameWidth;
                this.textView.setLayoutParams(lp);
                return;
            }
            return;
        }
        String text = String.format("%d", Integer.valueOf(count));
        int countTop = AndroidUtilities.dp(12.5f);
        int textWidth = (int) Math.ceil(Theme.dialogs_countTextPaint.measureText(text));
        int countWidth = Math.max(AndroidUtilities.dp(10.0f), textWidth);
        int countLeft = (getMeasuredWidth() - countWidth) - AndroidUtilities.dp(25.0f);
        int nameWidth2 = nameWidth - countWidth;
        FrameLayout.LayoutParams lp2 = (FrameLayout.LayoutParams) this.textView.getLayoutParams();
        if (lp2 != null && lp2.width != nameWidth2) {
            lp2.width = nameWidth2;
            this.textView.setLayoutParams(lp2);
        }
        int x = countLeft - AndroidUtilities.dp(5.5f);
        this.rect.set(x, countTop, x + countWidth + AndroidUtilities.dp(14.0f), AndroidUtilities.dp(23.0f) + countTop);
        canvas.drawRoundRect(this.rect, AndroidUtilities.density * 11.5f, AndroidUtilities.density * 11.5f, Theme.dialogs_countPaint);
        canvas.drawText(text, this.rect.left + ((this.rect.width() - textWidth) / 2.0f), AndroidUtilities.dp(16.0f) + countTop, Theme.dialogs_countTextPaint);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.dialogsUnreadCounterChanged) {
            int count = ((Integer) args[0]).intValue();
            if (count > 0) {
                invalidate();
            }
        }
    }
}
