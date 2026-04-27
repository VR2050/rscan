package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Typeface;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.NotificationsSettingsActivity;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CheckBox2;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class UserBoxCell extends FrameLayout {
    private AvatarDrawable avatarDrawable;
    private BackupImageView avatarImageView;
    private CheckBox2 checkBox;
    private int currentAccount;
    private int currentDrawable;
    private int currentId;
    private CharSequence currentName;
    private TLObject currentObject;
    private CharSequence currentStatus;
    private TLRPC.EncryptedChat encryptedChat;
    private TLRPC.FileLocation lastAvatar;
    private String lastName;
    private int lastStatus;
    private SimpleTextView nameTextView;
    private boolean needDivider;
    private FrameLayout shadow;
    private boolean shadowIsVisible;
    private int statusColor;
    private int statusOnlineColor;
    private SimpleTextView statusTextView;

    public UserBoxCell(Context context, int padding, int checkbox, boolean admin) {
        this(context, padding, checkbox, admin, false);
    }

    public UserBoxCell(Context context, int padding, int checkbox, boolean admin, boolean needAddButton) {
        int i;
        int i2;
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.statusColor = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText);
        this.statusOnlineColor = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText);
        this.avatarDrawable = new AvatarDrawable();
        BackupImageView backupImageView = new BackupImageView(context);
        this.avatarImageView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        addView(this.avatarImageView, LayoutHelper.createFrame(45.0f, 45.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : padding + 7, 10.0f, LocaleController.isRTL ? padding + 7 : 0.0f, 10.0f));
        SimpleTextView simpleTextView = new SimpleTextView(context);
        this.nameTextView = simpleTextView;
        simpleTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.nameTextView.setTextSize(14);
        this.nameTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        View view = this.nameTextView;
        int i3 = (LocaleController.isRTL ? 5 : 3) | 48;
        if (LocaleController.isRTL) {
            i = (checkbox == 2 ? 18 : 0) + 28 + 0;
        } else {
            i = padding + 64;
        }
        float f = i;
        if (LocaleController.isRTL) {
            i2 = padding + 64;
        } else {
            i2 = (checkbox != 2 ? 0 : 18) + 28 + 0;
        }
        addView(view, LayoutHelper.createFrame(-1.0f, 20.0f, i3, f, 13.5f, i2, 0.0f));
        SimpleTextView simpleTextView2 = new SimpleTextView(context);
        this.statusTextView = simpleTextView2;
        simpleTextView2.setTextSize(13);
        this.statusTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        addView(this.statusTextView, LayoutHelper.createFrame(-1.0f, 20.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0 + 28 : padding + 64, 35.5f, LocaleController.isRTL ? padding + 64 : 0 + 28, 0.0f));
        if (checkbox == 1) {
            CheckBox2 checkBox2 = new CheckBox2(context);
            this.checkBox = checkBox2;
            addView(checkBox2, LayoutHelper.createFrame(24.0f, 24.0f, 51, 16.0f, 18.0f, 0.0f, 0.0f));
        }
        FrameLayout frameLayout = new FrameLayout(context);
        this.shadow = frameLayout;
        frameLayout.setBackgroundColor(-2130706433);
        this.shadow.setVisibility(8);
        this.shadow.setClickable(true);
        addView(this.shadow, LayoutHelper.createFrame(-1, -1.0f));
        setFocusable(true);
    }

    public void setAvatarPadding(int padding) {
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.avatarImageView.getLayoutParams();
        layoutParams.leftMargin = AndroidUtilities.dp(padding + 7);
        layoutParams.rightMargin = AndroidUtilities.dp(0.0f);
        this.avatarImageView.setLayoutParams(layoutParams);
        FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.nameTextView.getLayoutParams();
        layoutParams2.leftMargin = AndroidUtilities.dp(padding + 64);
        layoutParams2.rightMargin = AndroidUtilities.dp(28.0f);
        FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) this.statusTextView.getLayoutParams();
        layoutParams3.leftMargin = AndroidUtilities.dp(padding + 64);
        layoutParams3.rightMargin = AndroidUtilities.dp(28.0f);
    }

    public void setData(TLObject object, CharSequence name, CharSequence status, int resId) {
        setData(object, null, name, status, resId, false);
    }

    public void setData(TLObject object, CharSequence name, CharSequence status, int resId, boolean divider) {
        setData(object, null, name, status, resId, divider);
    }

    public void setData(TLObject object, TLRPC.EncryptedChat ec, CharSequence name, CharSequence status, int resId, boolean divider) {
        if (object == null && name == null && status == null) {
            this.currentStatus = null;
            this.currentName = null;
            this.currentObject = null;
            this.nameTextView.setText("");
            this.statusTextView.setText("");
            this.avatarImageView.setImageDrawable(null);
            return;
        }
        this.encryptedChat = ec;
        this.currentStatus = status;
        this.currentName = name;
        this.currentObject = object;
        this.currentDrawable = resId;
        this.needDivider = divider;
        setWillNotDraw(!divider);
        update(0);
    }

    public void setException(NotificationsSettingsActivity.NotificationException exception, CharSequence name, boolean divider) {
        boolean enabled;
        String text;
        String text2;
        TLRPC.User user;
        boolean custom = exception.hasCustom;
        int value = exception.notify;
        int delta = exception.muteUntil;
        if (value == 3 && delta != Integer.MAX_VALUE) {
            int delta2 = delta - ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
            if (delta2 <= 0) {
                if (custom) {
                    text = LocaleController.getString("NotificationsCustom", R.string.NotificationsCustom);
                } else {
                    text = LocaleController.getString("NotificationsUnmuted", R.string.NotificationsUnmuted);
                }
            } else if (delta2 < 3600) {
                text = LocaleController.formatString("WillUnmuteIn", R.string.WillUnmuteIn, LocaleController.formatPluralString("Minutes", delta2 / 60));
            } else if (delta2 < 86400) {
                text = LocaleController.formatString("WillUnmuteIn", R.string.WillUnmuteIn, LocaleController.formatPluralString("Hours", (int) Math.ceil((delta2 / 60.0f) / 60.0f)));
            } else if (delta2 < 31536000) {
                text = LocaleController.formatString("WillUnmuteIn", R.string.WillUnmuteIn, LocaleController.formatPluralString("Days", (int) Math.ceil(((delta2 / 60.0f) / 60.0f) / 24.0f)));
            } else {
                text = null;
            }
        } else {
            if (value == 0 || value == 1) {
                enabled = true;
            } else if (value == 2) {
                enabled = false;
            } else {
                enabled = false;
            }
            if (enabled && custom) {
                text = LocaleController.getString("NotificationsCustom", R.string.NotificationsCustom);
            } else {
                text = enabled ? LocaleController.getString("NotificationsUnmuted", R.string.NotificationsUnmuted) : LocaleController.getString("NotificationsMuted", R.string.NotificationsMuted);
            }
        }
        if (text != null) {
            text2 = text;
        } else {
            String text3 = LocaleController.getString("NotificationsOff", R.string.NotificationsOff);
            text2 = text3;
        }
        int lower_id = (int) exception.did;
        int high_id = (int) (exception.did >> 32);
        if (lower_id != 0) {
            if (lower_id > 0) {
                TLRPC.User user2 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(lower_id));
                if (user2 != null) {
                    setData(user2, null, name, text2, 0, divider);
                    return;
                }
                return;
            }
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
            if (chat != null) {
                setData(chat, null, name, text2, 0, divider);
                return;
            }
            return;
        }
        TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf(high_id));
        if (encryptedChat != null && (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(encryptedChat.user_id))) != null) {
            setData(user, encryptedChat, name, text2, 0, false);
        }
    }

    public void setNameTypeface(Typeface typeface) {
        this.nameTextView.setTypeface(typeface);
    }

    public void setCurrentId(int id) {
        this.currentId = id;
    }

    public void setChecked(boolean checked, boolean animated) {
        CheckBox2 checkBox2 = this.checkBox;
        if (checkBox2 != null) {
            if (checkBox2.getVisibility() != 0) {
                this.checkBox.setVisibility(0);
            }
            this.checkBox.setChecked(checked, animated);
        }
    }

    public void setShadow(boolean isVisible) {
        this.shadowIsVisible = isVisible;
        this.shadow.setVisibility(isVisible ? 0 : 8);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(i), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(65.0f) + (this.needDivider ? 1 : 0), 1073741824));
    }

    public void setStatusColors(int color, int onlineColor) {
        this.statusColor = color;
        this.statusOnlineColor = onlineColor;
    }

    @Override // android.view.View
    public void invalidate() {
        super.invalidate();
    }

    public void update(int mask) {
        TLRPC.FileLocation fileLocation;
        TLRPC.FileLocation photo = null;
        String newName = null;
        TLRPC.User currentUser = null;
        TLRPC.Chat currentChat = null;
        TLObject tLObject = this.currentObject;
        if (tLObject instanceof TLRPC.User) {
            currentUser = (TLRPC.User) tLObject;
            if (currentUser.photo != null) {
                photo = currentUser.photo.photo_small;
            }
        } else if (tLObject instanceof TLRPC.Chat) {
            currentChat = (TLRPC.Chat) tLObject;
            if (currentChat.photo != null) {
                photo = currentChat.photo.photo_small;
            }
        }
        if (mask != 0) {
            boolean continueUpdate = false;
            if ((mask & 2) != 0 && ((this.lastAvatar != null && photo == null) || ((this.lastAvatar == null && photo != null) || ((fileLocation = this.lastAvatar) != null && photo != null && (fileLocation.volume_id != photo.volume_id || this.lastAvatar.local_id != photo.local_id))))) {
                continueUpdate = true;
            }
            if (currentUser != null && !continueUpdate && (mask & 4) != 0) {
                int newStatus = 0;
                if (currentUser.status != null) {
                    newStatus = currentUser.status.expires;
                }
                if (newStatus != this.lastStatus) {
                    continueUpdate = true;
                }
            }
            if (!continueUpdate && this.currentName == null && this.lastName != null && (mask & 1) != 0) {
                if (currentUser != null) {
                    newName = UserObject.getName(currentUser);
                } else {
                    newName = currentChat.title;
                }
                if (!newName.equals(this.lastName)) {
                    continueUpdate = true;
                }
            }
            if (!continueUpdate) {
                return;
            }
        }
        if (currentUser != null) {
            this.avatarDrawable.setInfo(currentUser);
            if (currentUser.status != null) {
                this.lastStatus = currentUser.status.expires;
            } else {
                this.lastStatus = 0;
            }
        } else if (currentChat != null) {
            this.avatarDrawable.setInfo(currentChat);
        } else {
            CharSequence charSequence = this.currentName;
            if (charSequence != null) {
                this.avatarDrawable.setInfo(this.currentId, charSequence.toString(), null);
            } else {
                this.avatarDrawable.setInfo(this.currentId, "#", null);
            }
        }
        CharSequence charSequence2 = this.currentName;
        if (charSequence2 != null) {
            this.lastName = null;
            this.nameTextView.setText(charSequence2);
        } else {
            if (currentUser != null) {
                this.lastName = newName == null ? UserObject.getName(currentUser) : newName;
            } else if (currentChat != null) {
                this.lastName = newName == null ? currentChat.title : newName;
            } else {
                this.lastName = "";
            }
            this.nameTextView.setText(this.lastName);
        }
        if (this.currentStatus != null) {
            this.statusTextView.setTextColor(this.statusColor);
            this.statusTextView.setText(this.currentStatus);
        } else if (currentUser != null) {
            if (currentUser.bot) {
                this.statusTextView.setTextColor(this.statusColor);
                this.statusTextView.setText(LocaleController.getString("BotStatusCantRead", R.string.BotStatusCantRead));
            } else if (currentUser.id == UserConfig.getInstance(this.currentAccount).getClientUserId() || ((currentUser.status != null && currentUser.status.expires > ConnectionsManager.getInstance(this.currentAccount).getCurrentTime()) || MessagesController.getInstance(this.currentAccount).onlinePrivacy.containsKey(Integer.valueOf(currentUser.id)))) {
                this.statusTextView.setTextColor(this.statusOnlineColor);
                this.statusTextView.setText(LocaleController.getString("Online", R.string.Online));
            } else {
                this.statusTextView.setTextColor(this.statusColor);
                this.statusTextView.setText(LocaleController.formatUserStatus(this.currentAccount, currentUser));
            }
        }
        this.lastAvatar = photo;
        if (currentUser != null) {
            this.avatarImageView.setImage(ImageLocation.getForUser(currentUser, false), "50_50", this.avatarDrawable, currentUser);
        } else if (currentChat != null) {
            this.avatarImageView.setImage(ImageLocation.getForChat(currentChat, false), "50_50", this.avatarDrawable, currentChat);
        } else {
            this.avatarImageView.setImageDrawable(this.avatarDrawable);
        }
    }

    @Override // android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.needDivider) {
            canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(68.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(68.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        CheckBox2 checkBox2 = this.checkBox;
        if (checkBox2 != null && checkBox2.getVisibility() == 0) {
            info.setCheckable(true);
            info.setChecked(this.checkBox.isChecked());
            info.setClassName("android.widget.CheckBox");
        }
    }
}
