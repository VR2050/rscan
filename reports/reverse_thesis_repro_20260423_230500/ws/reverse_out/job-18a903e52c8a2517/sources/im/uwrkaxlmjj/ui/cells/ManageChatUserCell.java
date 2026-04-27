package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ManageChatUserCell extends FrameLayout {
    private AvatarDrawable avatarDrawable;
    private BackupImageView avatarImageView;
    private int currentAccount;
    private CharSequence currentName;
    private TLObject currentObject;
    private CharSequence currrntStatus;
    private ManageChatUserCellDelegate delegate;
    private boolean isAdmin;
    private TLRPC.FileLocation lastAvatar;
    private String lastName;
    private int lastStatus;
    private int namePadding;
    private SimpleTextView nameTextView;
    private boolean needDivider;
    private ImageView optionsButton;
    private int statusColor;
    private int statusOnlineColor;
    private SimpleTextView statusTextView;

    public interface ManageChatUserCellDelegate {
        boolean onOptionsButtonCheck(ManageChatUserCell manageChatUserCell, boolean z);
    }

    public ManageChatUserCell(Context context, int avatarPadding, int nPadding, boolean needOption) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.statusColor = Theme.getColor(Theme.key_windowBackgroundWhiteGrayText);
        this.statusOnlineColor = Theme.getColor(Theme.key_windowBackgroundWhiteBlueText);
        this.namePadding = nPadding;
        this.avatarDrawable = new AvatarDrawable();
        BackupImageView backupImageView = new BackupImageView(context);
        this.avatarImageView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(23.0f));
        addView(this.avatarImageView, LayoutHelper.createFrame(46.0f, 46.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : avatarPadding + 7, 8.0f, LocaleController.isRTL ? avatarPadding + 7 : 0.0f, 0.0f));
        SimpleTextView simpleTextView = new SimpleTextView(context);
        this.nameTextView = simpleTextView;
        simpleTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.nameTextView.setTextSize(14);
        this.nameTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        addView(this.nameTextView, LayoutHelper.createFrame(-1.0f, 20.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 46.0f : this.namePadding + 68, 11.5f, LocaleController.isRTL ? this.namePadding + 68 : 46.0f, 0.0f));
        SimpleTextView simpleTextView2 = new SimpleTextView(context);
        this.statusTextView = simpleTextView2;
        simpleTextView2.setTextSize(13);
        this.statusTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        addView(this.statusTextView, LayoutHelper.createFrame(-1.0f, 20.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 28.0f : this.namePadding + 68, 34.5f, LocaleController.isRTL ? this.namePadding + 68 : 28.0f, 0.0f));
        if (needOption) {
            ImageView imageView = new ImageView(context);
            this.optionsButton = imageView;
            imageView.setFocusable(false);
            this.optionsButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_stickers_menuSelector)));
            this.optionsButton.setImageResource(R.drawable.ic_ab_other);
            this.optionsButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_stickers_menu), PorterDuff.Mode.MULTIPLY));
            this.optionsButton.setScaleType(ImageView.ScaleType.CENTER);
            addView(this.optionsButton, LayoutHelper.createFrame(52, 64, (LocaleController.isRTL ? 3 : 5) | 48));
            this.optionsButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ManageChatUserCell$PUonwZfUgEjdKkGZNbCVD6liURg
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$ManageChatUserCell(view);
                }
            });
            this.optionsButton.setContentDescription(LocaleController.getString("AccDescrUserOptions", R.string.AccDescrUserOptions));
        }
    }

    public /* synthetic */ void lambda$new$0$ManageChatUserCell(View v) {
        this.delegate.onOptionsButtonCheck(this, true);
    }

    public void setData(TLObject object, CharSequence name, CharSequence status, boolean divider) {
        int i;
        int i2;
        int i3;
        int i4;
        if (object == null) {
            this.currrntStatus = null;
            this.currentName = null;
            this.currentObject = null;
            this.nameTextView.setText("");
            this.statusTextView.setText("");
            this.avatarImageView.setImageDrawable(null);
            return;
        }
        this.currrntStatus = status;
        this.currentName = name;
        this.currentObject = object;
        if (this.optionsButton != null) {
            boolean visible = this.delegate.onOptionsButtonCheck(this, false);
            this.optionsButton.setVisibility(visible ? 0 : 4);
            SimpleTextView simpleTextView = this.nameTextView;
            int i5 = (LocaleController.isRTL ? 5 : 3) | 48;
            if (LocaleController.isRTL) {
                i = visible ? 46 : 28;
            } else {
                i = this.namePadding + 68;
            }
            float f = i;
            float f2 = (status == null || status.length() > 0) ? 11.5f : 20.5f;
            if (LocaleController.isRTL) {
                i2 = this.namePadding + 68;
            } else {
                i2 = visible ? 46 : 28;
            }
            simpleTextView.setLayoutParams(LayoutHelper.createFrame(-1.0f, 20.0f, i5, f, f2, i2, 0.0f));
            SimpleTextView simpleTextView2 = this.statusTextView;
            int i6 = (LocaleController.isRTL ? 5 : 3) | 48;
            if (LocaleController.isRTL) {
                i3 = visible ? 46 : 28;
            } else {
                i3 = this.namePadding + 68;
            }
            float f3 = i3;
            if (LocaleController.isRTL) {
                i4 = this.namePadding + 68;
            } else {
                i4 = visible ? 46 : 28;
            }
            simpleTextView2.setLayoutParams(LayoutHelper.createFrame(-1.0f, 20.0f, i6, f3, 34.5f, i4, 0.0f));
        }
        this.needDivider = divider;
        setWillNotDraw(!divider);
        update(0);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(i), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f) + (this.needDivider ? 1 : 0), 1073741824));
    }

    public void setStatusColors(int color, int onlineColor) {
        this.statusColor = color;
        this.statusOnlineColor = onlineColor;
    }

    public void setIsAdmin(boolean value) {
        this.isAdmin = value;
    }

    public void update(int mask) {
        TLRPC.FileLocation fileLocation;
        TLRPC.FileLocation fileLocation2;
        TLObject tLObject = this.currentObject;
        if (tLObject == null) {
            return;
        }
        if (tLObject instanceof TLRPC.User) {
            TLRPC.User currentUser = (TLRPC.User) tLObject;
            TLRPC.FileLocation photo = null;
            String newName = null;
            if (currentUser.photo != null) {
                photo = currentUser.photo.photo_small;
            }
            if (mask != 0) {
                boolean continueUpdate = false;
                if ((mask & 2) != 0 && ((this.lastAvatar != null && photo == null) || ((this.lastAvatar == null && photo != null) || ((fileLocation2 = this.lastAvatar) != null && photo != null && (fileLocation2.volume_id != photo.volume_id || this.lastAvatar.local_id != photo.local_id))))) {
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
                    newName = UserObject.getName(currentUser);
                    if (!newName.equals(this.lastName)) {
                        continueUpdate = true;
                    }
                }
                if (!continueUpdate) {
                    return;
                }
            }
            this.avatarDrawable.setInfo(currentUser);
            if (currentUser.status != null) {
                this.lastStatus = currentUser.status.expires;
            } else {
                this.lastStatus = 0;
            }
            CharSequence charSequence = this.currentName;
            if (charSequence != null) {
                this.lastName = null;
                this.nameTextView.setText(charSequence);
            } else {
                String name = newName == null ? UserObject.getName(currentUser) : newName;
                this.lastName = name;
                this.nameTextView.setText(name);
            }
            if (this.currrntStatus != null) {
                this.statusTextView.setTextColor(this.statusColor);
                this.statusTextView.setText(this.currrntStatus);
            } else if (currentUser.bot) {
                this.statusTextView.setTextColor(this.statusColor);
                if (currentUser.bot_chat_history || this.isAdmin) {
                    this.statusTextView.setText(LocaleController.getString("BotStatusRead", R.string.BotStatusRead));
                } else {
                    this.statusTextView.setText(LocaleController.getString("BotStatusCantRead", R.string.BotStatusCantRead));
                }
            } else if (currentUser.id == UserConfig.getInstance(this.currentAccount).getClientUserId() || ((currentUser.status != null && currentUser.status.expires > ConnectionsManager.getInstance(this.currentAccount).getCurrentTime()) || MessagesController.getInstance(this.currentAccount).onlinePrivacy.containsKey(Integer.valueOf(currentUser.id)))) {
                this.statusTextView.setTextColor(this.statusOnlineColor);
                this.statusTextView.setText(LocaleController.getString("Online", R.string.Online));
            } else {
                this.statusTextView.setTextColor(this.statusColor);
                this.statusTextView.setText(LocaleController.formatUserStatus(this.currentAccount, currentUser));
            }
            this.lastAvatar = photo;
            this.avatarImageView.setImage(ImageLocation.getForUser(currentUser, false), "50_50", this.avatarDrawable, currentUser);
            return;
        }
        if (tLObject instanceof TLRPC.Chat) {
            TLRPC.Chat currentChat = (TLRPC.Chat) tLObject;
            TLRPC.FileLocation photo2 = null;
            String newName2 = null;
            if (currentChat.photo != null) {
                photo2 = currentChat.photo.photo_small;
            }
            if (mask != 0) {
                boolean continueUpdate2 = false;
                if ((mask & 2) != 0 && ((this.lastAvatar != null && photo2 == null) || ((this.lastAvatar == null && photo2 != null) || ((fileLocation = this.lastAvatar) != null && photo2 != null && (fileLocation.volume_id != photo2.volume_id || this.lastAvatar.local_id != photo2.local_id))))) {
                    continueUpdate2 = true;
                }
                if (!continueUpdate2 && this.currentName == null && this.lastName != null && (mask & 1) != 0) {
                    newName2 = currentChat.title;
                    if (!newName2.equals(this.lastName)) {
                        continueUpdate2 = true;
                    }
                }
                if (!continueUpdate2) {
                    return;
                }
            }
            this.avatarDrawable.setInfo(currentChat);
            CharSequence charSequence2 = this.currentName;
            if (charSequence2 != null) {
                this.lastName = null;
                this.nameTextView.setText(charSequence2);
            } else {
                String str = newName2 == null ? currentChat.title : newName2;
                this.lastName = str;
                this.nameTextView.setText(str);
            }
            if (this.currrntStatus != null) {
                this.statusTextView.setTextColor(this.statusColor);
                this.statusTextView.setText(this.currrntStatus);
            } else {
                this.statusTextView.setTextColor(this.statusColor);
                if (currentChat.participants_count != 0) {
                    this.statusTextView.setText(LocaleController.formatPluralString("Members", currentChat.participants_count));
                } else if (currentChat.has_geo) {
                    this.statusTextView.setText(LocaleController.getString("MegaLocation", R.string.MegaLocation));
                } else if (TextUtils.isEmpty(currentChat.username)) {
                    this.statusTextView.setText(LocaleController.getString("MegaPrivate", R.string.MegaPrivate));
                } else {
                    this.statusTextView.setText(LocaleController.getString("MegaPublic", R.string.MegaPublic));
                }
            }
            this.lastAvatar = photo2;
            this.avatarImageView.setImage(ImageLocation.getForChat(currentChat, false), "50_50", this.avatarDrawable, currentChat);
        }
    }

    public void recycle() {
        this.avatarImageView.getImageReceiver().cancelLoadImage();
    }

    public void setDelegate(ManageChatUserCellDelegate manageChatUserCellDelegate) {
        this.delegate = manageChatUserCellDelegate;
    }

    public TLObject getCurrentObject() {
        return this.currentObject;
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
}
