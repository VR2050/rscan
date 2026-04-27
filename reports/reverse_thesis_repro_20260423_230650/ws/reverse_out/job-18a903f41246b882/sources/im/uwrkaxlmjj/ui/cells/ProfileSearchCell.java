package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityNodeInfo;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.NotificationsSettingsActivity;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class ProfileSearchCell extends BaseCell {
    private AvatarDrawable avatarDrawable;
    private ImageReceiver avatarImage;
    private int avatarLeft;
    private TLRPC.Chat chat;
    private boolean countIsBiggerThanTen;
    private StaticLayout countLayout;
    private int countLeft;
    private int countTop;
    private int countWidth;
    private int currentAccount;
    private CharSequence currentName;
    private long dialog_id;
    private boolean drawBotIcon;
    private boolean drawBroadcastIcon;
    private boolean drawCheck;
    private boolean drawCount;
    private boolean drawGroupIcon;
    private boolean drawSecretLockIcon;
    private TLRPC.EncryptedChat encryptedChat;
    private TLRPC.FileLocation lastAvatar;
    private String lastName;
    private int lastStatus;
    private int lastUnreadCount;
    private int miViewType;
    private StaticLayout nameLayout;
    private int nameLeft;
    private int nameWidth;
    private RectF rect;
    private boolean savedMessages;
    private StaticLayout statusLayout;
    private int statusLeft;
    private CharSequence subLabel;
    private int sublabelOffsetX;
    private int sublabelOffsetY;
    private float topOffset;
    public boolean useSeparator;
    private TLRPC.User user;

    public ProfileSearchCell(Context context) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.countTop = AndroidUtilities.dp(19.0f);
        this.rect = new RectF();
        this.miViewType = 0;
        ImageReceiver imageReceiver = new ImageReceiver(this);
        this.avatarImage = imageReceiver;
        imageReceiver.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.avatarDrawable = new AvatarDrawable();
    }

    public void setData(TLObject object, TLRPC.EncryptedChat ec, CharSequence n, CharSequence s, boolean needCount, boolean saved) {
        this.currentName = n;
        if (object instanceof TLRPC.User) {
            this.user = (TLRPC.User) object;
            this.chat = null;
        } else if (object instanceof TLRPC.Chat) {
            this.chat = (TLRPC.Chat) object;
            this.user = null;
        }
        this.encryptedChat = ec;
        this.subLabel = s;
        this.drawCount = needCount;
        this.savedMessages = saved;
        update(0);
    }

    public void setMiViewType(int miViewType) {
        this.miViewType = miViewType;
    }

    public void setException(NotificationsSettingsActivity.NotificationException exception, CharSequence name) {
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
                    setData(user2, null, name, text2, false, false);
                    return;
                }
                return;
            }
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
            if (chat != null) {
                setData(chat, null, name, text2, false, false);
                return;
            }
            return;
        }
        TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf(high_id));
        if (encryptedChat != null && (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(encryptedChat.user_id))) != null) {
            setData(user, encryptedChat, name, text2, false, false);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.avatarImage.onDetachedFromWindow();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.avatarImage.onAttachedToWindow();
    }

    @Override // android.view.View
    protected void onMeasure(int i, int i2) {
        setMeasuredDimension(getDefaultSize(getSuggestedMinimumWidth(), i), AndroidUtilities.dp(70.0f) + (this.useSeparator ? 1 : 0));
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if ((this.user != null || this.chat != null || this.encryptedChat != null) && changed) {
            buildLayout();
        }
    }

    public void setSublabelOffset(int x, int y) {
        this.sublabelOffsetX = x;
        this.sublabelOffsetY = y;
    }

    public void buildLayout() {
        CharSequence nameString;
        TextPaint currentNamePaint;
        int statusWidth;
        TLRPC.Dialog dialog;
        if (this.topOffset == 0.0f) {
            this.topOffset = (getMeasuredHeight() - AndroidUtilities.dp(48.0f)) / 2.0f;
        }
        this.drawBroadcastIcon = false;
        this.drawSecretLockIcon = false;
        this.drawGroupIcon = false;
        this.drawCheck = false;
        this.drawBotIcon = false;
        if (!LocaleController.isRTL) {
            this.nameLeft = AndroidUtilities.dp(AndroidUtilities.leftBaseline);
        } else {
            this.nameLeft = AndroidUtilities.dp(11.0f);
        }
        TLRPC.EncryptedChat encryptedChat = this.encryptedChat;
        if (encryptedChat != null) {
            this.drawSecretLockIcon = true;
            this.dialog_id = ((long) encryptedChat.id) << 32;
        } else {
            if (this.chat != null) {
                this.dialog_id = -r4.id;
                if (SharedConfig.drawDialogIcons) {
                    if (ChatObject.isChannel(this.chat) && !this.chat.megagroup) {
                        this.drawBroadcastIcon = true;
                    } else {
                        this.drawGroupIcon = true;
                    }
                }
                this.drawCheck = this.chat.verified;
            } else {
                if (this.user != null) {
                    this.dialog_id = r4.id;
                    if (SharedConfig.drawDialogIcons && this.user.bot && !MessagesController.isSupportUser(this.user)) {
                        this.drawBotIcon = true;
                    }
                    this.drawCheck = this.user.verified;
                }
            }
        }
        if (this.currentName != null) {
            nameString = this.currentName;
        } else {
            String nameString2 = "";
            TLRPC.Chat chat = this.chat;
            if (chat != null) {
                nameString2 = chat.title;
            } else {
                TLRPC.User user = this.user;
                if (user != null) {
                    nameString2 = UserObject.getName(user);
                }
            }
            nameString = nameString2.replace('\n', ' ');
        }
        if (nameString.length() == 0) {
            TLRPC.User user2 = this.user;
            if (user2 != null && user2.phone != null && this.user.phone.length() != 0) {
                nameString = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + this.user.phone);
            } else {
                nameString = LocaleController.getString("HiddenName", R.string.HiddenName);
            }
        }
        if (this.encryptedChat != null) {
            currentNamePaint = Theme.dialogs_searchNameEncryptedPaint;
        } else {
            currentNamePaint = Theme.dialogs_searchNamePaint;
        }
        if (!LocaleController.isRTL) {
            statusWidth = (getMeasuredWidth() - this.nameLeft) - AndroidUtilities.dp(14.0f);
            this.nameWidth = statusWidth;
            this.avatarLeft = AndroidUtilities.dp(16.0f);
        } else {
            statusWidth = (getMeasuredWidth() - this.nameLeft) - AndroidUtilities.dp(AndroidUtilities.leftBaseline);
            this.nameWidth = statusWidth;
            this.avatarLeft = AndroidUtilities.dp(11.0f) + getPaddingLeft();
        }
        this.nameWidth -= getPaddingLeft() + getPaddingRight();
        int statusWidth2 = statusWidth - (getPaddingLeft() + getPaddingRight());
        if (this.drawCount && (dialog = MessagesController.getInstance(this.currentAccount).dialogs_dict.get(this.dialog_id)) != null && dialog.unread_count != 0) {
            this.lastUnreadCount = dialog.unread_count;
            String countString = String.format("%d", Integer.valueOf(dialog.unread_count));
            this.countWidth = Math.max(AndroidUtilities.dp(12.0f), (int) Math.ceil(Theme.dialogs_countTextPaint.measureText(countString)));
            this.countLayout = new StaticLayout(countString, Theme.dialogs_countTextPaint, this.countWidth, Layout.Alignment.ALIGN_CENTER, 1.0f, 0.0f, false);
            int w = this.countWidth + AndroidUtilities.dp(18.0f);
            this.nameWidth -= w;
            boolean z = this.lastUnreadCount > 10;
            this.countIsBiggerThanTen = z;
            this.countTop += z ? AndroidUtilities.dp(3.0f) : 0;
            if (!LocaleController.isRTL) {
                this.countLeft = (getMeasuredWidth() - this.countWidth) - AndroidUtilities.dp(20.0f);
            } else {
                this.countLeft = AndroidUtilities.dp(20.0f);
                this.nameLeft += w;
            }
        } else {
            this.lastUnreadCount = 0;
            this.countLayout = null;
        }
        CharSequence nameStringFinal = TextUtils.ellipsize(nameString, currentNamePaint, this.nameWidth - AndroidUtilities.dp(12.0f), TextUtils.TruncateAt.END);
        this.nameLayout = new StaticLayout(nameStringFinal, currentNamePaint, this.nameWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
        CharSequence statusString = null;
        TextPaint currentStatusPaint = Theme.dialogs_offlinePaint;
        if (!LocaleController.isRTL) {
            this.statusLeft = AndroidUtilities.dp(AndroidUtilities.leftBaseline);
        } else {
            this.statusLeft = AndroidUtilities.dp(11.0f);
        }
        TLRPC.Chat chat2 = this.chat;
        if (chat2 == null || this.subLabel != null) {
            if (this.subLabel != null) {
                statusString = this.subLabel;
            } else {
                TLRPC.User user3 = this.user;
                if (user3 != null) {
                    if (MessagesController.isSupportUser(user3)) {
                        statusString = LocaleController.getString("SupportStatus", R.string.SupportStatus);
                    } else if (this.user.bot) {
                        statusString = LocaleController.getString("Bot", R.string.Bot);
                    } else if (this.user.id == 333000 || this.user.id == 777000) {
                        statusString = LocaleController.getString("ServiceNotifications", R.string.ServiceNotifications);
                    } else if (this.miViewType == 0) {
                        statusString = LocaleController.formatUserStatus(this.currentAccount, this.user);
                        TLRPC.User user4 = this.user;
                        if (user4 != null && (user4.id == UserConfig.getInstance(this.currentAccount).getClientUserId() || (this.user.status != null && this.user.status.expires > ConnectionsManager.getInstance(this.currentAccount).getCurrentTime()))) {
                            TextPaint currentStatusPaint2 = Theme.dialogs_onlinePaint;
                            statusString = LocaleController.getString("Online", R.string.Online);
                            currentStatusPaint = currentStatusPaint2;
                        }
                    } else {
                        boolean[] booleans = {false};
                        statusString = LocaleController.formatUserStatusNew(this.currentAccount, this.user, booleans);
                        if (booleans[0]) {
                            TextPaint textPaint = new TextPaint();
                            textPaint.setTextSize(currentStatusPaint.getTextSize());
                            textPaint.setColor(Color.parseColor("#42B71E"));
                            currentStatusPaint = textPaint;
                        }
                    }
                }
            }
            if (this.savedMessages) {
                statusString = null;
            }
        } else if (chat2 != null) {
            if (ChatObject.isChannel(chat2) && !this.chat.megagroup) {
                if (TextUtils.isEmpty(this.chat.username)) {
                    statusString = LocaleController.getString("ChannelPrivate", R.string.ChannelPrivate).toLowerCase();
                } else {
                    statusString = LocaleController.getString("ChannelPublic", R.string.ChannelPublic).toLowerCase();
                }
            } else if (this.chat.has_geo) {
                statusString = LocaleController.getString("MegaLocation", R.string.MegaLocation);
            } else if (TextUtils.isEmpty(this.chat.username)) {
                statusString = LocaleController.getString("MegaPrivate", R.string.MegaPrivate).toLowerCase();
            } else {
                statusString = LocaleController.getString("MegaPublic", R.string.MegaPublic).toLowerCase();
            }
        }
        if (TextUtils.isEmpty(statusString)) {
            this.statusLayout = null;
        } else {
            CharSequence statusStringFinal = TextUtils.ellipsize(statusString, currentStatusPaint, statusWidth2 - AndroidUtilities.dp(12.0f), TextUtils.TruncateAt.END);
            this.statusLayout = new StaticLayout(statusStringFinal, currentStatusPaint, statusWidth2, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
        }
        this.avatarImage.setImageCoords(this.avatarLeft, (int) this.topOffset, AndroidUtilities.dp(48.0f), AndroidUtilities.dp(48.0f));
        if (LocaleController.isRTL) {
            if (this.nameLayout.getLineCount() > 0) {
                float left = this.nameLayout.getLineLeft(0);
                if (left == 0.0f) {
                    double widthpx = Math.ceil(this.nameLayout.getLineWidth(0));
                    int i = this.nameWidth;
                    if (widthpx < i) {
                        this.nameLeft = (int) (((double) this.nameLeft) + (((double) i) - widthpx));
                    }
                }
            }
            StaticLayout staticLayout = this.statusLayout;
            if (staticLayout != null && staticLayout.getLineCount() > 0) {
                float left2 = this.statusLayout.getLineLeft(0);
                if (left2 == 0.0f) {
                    double widthpx2 = Math.ceil(this.statusLayout.getLineWidth(0));
                    if (widthpx2 < statusWidth2) {
                        this.statusLeft = (int) (((double) this.statusLeft) + (((double) statusWidth2) - widthpx2));
                    }
                }
            }
        } else {
            if (this.nameLayout.getLineCount() > 0) {
                float left3 = this.nameLayout.getLineRight(0);
                if (left3 == this.nameWidth) {
                    double widthpx3 = Math.ceil(this.nameLayout.getLineWidth(0));
                    int i2 = this.nameWidth;
                    if (widthpx3 < i2) {
                        this.nameLeft = (int) (((double) this.nameLeft) - (((double) i2) - widthpx3));
                    }
                }
            }
            StaticLayout staticLayout2 = this.statusLayout;
            if (staticLayout2 != null && staticLayout2.getLineCount() > 0) {
                float left4 = this.statusLayout.getLineRight(0);
                if (left4 == statusWidth2) {
                    double widthpx4 = Math.ceil(this.statusLayout.getLineWidth(0));
                    if (widthpx4 < statusWidth2) {
                        this.statusLeft = (int) (((double) this.statusLeft) - (((double) statusWidth2) - widthpx4));
                    }
                }
            }
        }
        this.nameLeft += getPaddingLeft();
        this.statusLeft += getPaddingLeft();
    }

    public void update(int mask) {
        TLRPC.Dialog dialog;
        String newName;
        TLRPC.User user;
        TLRPC.FileLocation fileLocation;
        TLRPC.FileLocation photo = null;
        TLRPC.User user2 = this.user;
        if (user2 != null) {
            this.avatarDrawable.setInfo(user2);
            if (this.savedMessages) {
                this.avatarDrawable.setAvatarType(1);
                this.avatarImage.setImage(null, null, this.avatarDrawable, null, null, 0);
            } else {
                if (this.user.photo != null) {
                    photo = this.user.photo.photo_small;
                }
                this.avatarImage.setImage(ImageLocation.getForUser(this.user, false), "50_50", this.avatarDrawable, null, this.user, 0);
            }
        } else {
            TLRPC.Chat chat = this.chat;
            if (chat != null) {
                if (chat.photo != null) {
                    photo = this.chat.photo.photo_small;
                }
                this.avatarDrawable.setInfo(this.chat);
                this.avatarImage.setImage(ImageLocation.getForChat(this.chat, false), "50_50", this.avatarDrawable, null, this.chat, 0);
            } else {
                this.avatarDrawable.setInfo(0, null, null);
                this.avatarImage.setImage(null, null, this.avatarDrawable, null, null, 0);
            }
        }
        if (mask != 0) {
            boolean continueUpdate = false;
            if ((((mask & 2) != 0 && this.user != null) || ((mask & 8) != 0 && this.chat != null)) && ((this.lastAvatar != null && photo == null) || ((this.lastAvatar == null && photo != null) || ((fileLocation = this.lastAvatar) != null && photo != null && (fileLocation.volume_id != photo.volume_id || this.lastAvatar.local_id != photo.local_id))))) {
                continueUpdate = true;
            }
            if (!continueUpdate && (mask & 4) != 0 && (user = this.user) != null) {
                int newStatus = 0;
                if (user.status != null) {
                    newStatus = this.user.status.expires;
                }
                if (newStatus != this.lastStatus) {
                    continueUpdate = true;
                }
            }
            if ((!continueUpdate && (mask & 1) != 0 && this.user != null) || ((mask & 16) != 0 && this.chat != null)) {
                if (this.user != null) {
                    newName = this.user.first_name + this.user.last_name;
                } else {
                    newName = this.chat.title;
                }
                if (!newName.equals(this.lastName)) {
                    continueUpdate = true;
                }
            }
            if (!continueUpdate && this.drawCount && (mask & 256) != 0 && (dialog = MessagesController.getInstance(this.currentAccount).dialogs_dict.get(this.dialog_id)) != null && dialog.unread_count != this.lastUnreadCount) {
                continueUpdate = true;
            }
            if (!continueUpdate) {
                return;
            }
        }
        TLRPC.User user3 = this.user;
        if (user3 != null) {
            if (user3.status != null) {
                this.lastStatus = this.user.status.expires;
            } else {
                this.lastStatus = 0;
            }
            this.lastName = this.user.first_name + this.user.last_name;
        } else {
            TLRPC.Chat chat2 = this.chat;
            if (chat2 != null) {
                this.lastName = chat2.title;
            }
        }
        this.lastAvatar = photo;
        if (getMeasuredWidth() != 0 || getMeasuredHeight() != 0) {
            buildLayout();
        } else {
            requestLayout();
        }
        postInvalidate();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        int x;
        if (this.user == null && this.chat == null && this.encryptedChat == null) {
            return;
        }
        if (this.useSeparator) {
            if (LocaleController.isRTL) {
                canvas.drawLine(0.0f, getMeasuredHeight() - 1, getMeasuredWidth() - AndroidUtilities.dp(AndroidUtilities.leftBaseline), getMeasuredHeight() - 1, Theme.dividerPaint);
            } else {
                canvas.drawLine(AndroidUtilities.dp(AndroidUtilities.leftBaseline), getMeasuredHeight() - 1, getMeasuredWidth(), getMeasuredHeight() - 1, Theme.dividerPaint);
            }
        }
        if (this.nameLayout != null) {
            canvas.save();
            canvas.translate(this.nameLeft, this.topOffset);
            this.nameLayout.draw(canvas);
            canvas.restore();
            if (this.drawCheck) {
                if (!LocaleController.isRTL) {
                    x = (int) (this.nameLeft + this.nameLayout.getLineRight(0) + AndroidUtilities.dp(6.0f));
                } else if (this.nameLayout.getLineLeft(0) == 0.0f) {
                    x = (this.nameLeft - AndroidUtilities.dp(6.0f)) - Theme.dialogs_verifiedDrawable.getIntrinsicWidth();
                } else {
                    x = (int) (((((double) (this.nameLeft + this.nameWidth)) - Math.ceil(this.nameLayout.getLineWidth(0))) - ((double) AndroidUtilities.dp(6.0f))) - ((double) Theme.dialogs_verifiedDrawable.getIntrinsicWidth()));
                }
                setDrawableBounds(Theme.dialogs_verifiedDrawable, x, this.topOffset + AndroidUtilities.dp(3.0f));
                setDrawableBounds(Theme.dialogs_verifiedCheckDrawable, x, this.topOffset + AndroidUtilities.dp(3.0f));
                Theme.dialogs_verifiedDrawable.draw(canvas);
                Theme.dialogs_verifiedCheckDrawable.draw(canvas);
            }
        }
        if (this.statusLayout != null) {
            canvas.save();
            canvas.translate(this.statusLeft + this.sublabelOffsetX, AndroidUtilities.dp(34.0f) + this.sublabelOffsetY + this.topOffset);
            this.statusLayout.draw(canvas);
            canvas.restore();
        }
        if (this.countLayout != null) {
            Paint paint = MessagesController.getInstance(this.currentAccount).isDialogMuted(this.dialog_id) ? Theme.dialogs_countGrayPaint : Theme.dialogs_countPaint;
            if (this.countIsBiggerThanTen) {
                int x2 = this.countLeft - AndroidUtilities.dp(6.0f);
                float radius = AndroidUtilities.dp(8.0f);
                this.rect.set(x2, this.countTop, this.countWidth + x2 + AndroidUtilities.dp(10.0f), this.countTop + AndroidUtilities.dp(16.0f));
                canvas.drawRoundRect(this.rect, radius, radius, paint);
            } else {
                int x3 = this.countLeft - AndroidUtilities.dp(4.0f);
                float w = this.countWidth + AndroidUtilities.dp(8.0f);
                int i = this.countTop;
                this.rect.set(x3, i, x3 + w, i + w);
                canvas.drawRoundRect(this.rect, w / 2.0f, w / 2.0f, paint);
            }
            if (this.countLayout != null) {
                canvas.save();
                canvas.translate(this.countLeft - AndroidUtilities.dp(this.countIsBiggerThanTen ? 1.0f : 0.5f), this.countTop + AndroidUtilities.dp(this.countIsBiggerThanTen ? 2.0f : 3.0f));
                this.countLayout.draw(canvas);
                canvas.restore();
            }
        }
        this.avatarImage.draw(canvas);
        if (this.drawSecretLockIcon) {
            int height = Theme.dialogs_lockDrawable.getIntrinsicHeight();
            setDrawableBounds(Theme.dialogs_lockDrawable, this.avatarLeft, (int) ((this.topOffset + this.avatarImage.getImageHeight()) - height), Theme.dialogs_lockDrawable.getIntrinsicWidth(), height);
            Theme.dialogs_lockDrawable.draw(canvas);
        } else if (this.drawGroupIcon) {
            setDrawableBounds(Theme.dialogs_groupDrawable, this.avatarLeft, (int) ((this.topOffset + this.avatarImage.getImageHeight()) - AndroidUtilities.dp(7.5f)), AndroidUtilities.dp(19.0f), AndroidUtilities.dp(7.5f));
            Theme.dialogs_groupDrawable.draw(canvas);
        } else if (this.drawBroadcastIcon) {
            int height2 = Theme.dialogs_broadcastDrawable.getIntrinsicHeight();
            setDrawableBounds(Theme.dialogs_broadcastDrawable, this.avatarLeft, (int) ((this.topOffset + this.avatarImage.getImageHeight()) - height2), Theme.dialogs_broadcastDrawable.getIntrinsicWidth(), height2);
            Theme.dialogs_broadcastDrawable.draw(canvas);
        } else if (this.drawBotIcon) {
            int height3 = Theme.dialogs_botDrawable.getIntrinsicHeight();
            setDrawableBounds(Theme.dialogs_botDrawable, this.avatarLeft, (int) ((this.topOffset + this.avatarImage.getImageHeight()) - height3), Theme.dialogs_botDrawable.getIntrinsicWidth(), height3);
            Theme.dialogs_botDrawable.draw(canvas);
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        StringBuilder builder = new StringBuilder();
        StaticLayout staticLayout = this.nameLayout;
        if (staticLayout != null) {
            builder.append(staticLayout.getText());
        }
        if (this.statusLayout != null) {
            if (builder.length() > 0) {
                builder.append(", ");
            }
            builder.append(this.statusLayout.getText());
        }
        info.setText(builder.toString());
    }
}
