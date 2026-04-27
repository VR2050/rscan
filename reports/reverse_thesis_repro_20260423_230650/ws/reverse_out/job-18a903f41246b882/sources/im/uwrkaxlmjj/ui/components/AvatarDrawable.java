package im.uwrkaxlmjj.ui.components;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class AvatarDrawable extends Drawable {
    public static final int AVATAR_TYPE_ARCHIVED = 3;
    public static final int AVATAR_TYPE_NORMAL = 0;
    public static final int AVATAR_TYPE_SAVED = 1;
    public static final int AVATAR_TYPE_SAVED_SMALL = 2;
    private float archivedAvatarProgress;
    private int avatarType;
    private int color;
    private boolean drawDeleted;
    private boolean isProfile;
    private RectF mRectF;
    private TextPaint namePaint;
    private boolean needApplyColorAccent;
    private StringBuilder stringBuilder;
    private float textHeight;
    private StaticLayout textLayout;
    private float textLeft;
    private float textWidth;

    public AvatarDrawable() {
        this.stringBuilder = new StringBuilder(5);
        TextPaint textPaint = new TextPaint(1);
        this.namePaint = textPaint;
        textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.namePaint.setTextSize(AndroidUtilities.dp(16.0f));
    }

    public AvatarDrawable(TLRPC.User user) {
        this(user, false);
    }

    public AvatarDrawable(TLRPC.Chat chat) {
        this(chat, false);
    }

    public AvatarDrawable(TLRPC.User user, boolean profile) {
        this();
        this.isProfile = profile;
        if (user != null) {
            setInfo(user.id, user.first_name, "", null);
            this.drawDeleted = UserObject.isDeleted(user);
        }
    }

    public AvatarDrawable(TLRPC.Chat chat, boolean profile) {
        this();
        this.isProfile = profile;
        if (chat != null) {
            setInfo(chat.id, chat.title, null, null);
        }
    }

    public void setNameTextSize(int size) {
        this.namePaint.setTextSize(size);
    }

    public void setProfile(boolean value) {
        this.isProfile = value;
    }

    private static int getColorIndex(int id) {
        if (id >= 0 && id < 7) {
            return id;
        }
        return Math.abs(id % Theme.keys_avatar_background.length);
    }

    public static int getColorForId(int id) {
        return Theme.getColor(Theme.keys_avatar_background[getColorIndex(id)]);
    }

    public static int getButtonColorForId(int id) {
        return Theme.getColor(Theme.key_avatar_actionBarSelectorBlue);
    }

    public static int getIconColorForId(int id) {
        return Theme.getColor(Theme.key_avatar_actionBarIconBlue);
    }

    public static int getProfileColorForId(int id) {
        return Theme.getColor(Theme.keys_avatar_background[getColorIndex(id)]);
    }

    public static int getProfileTextColorForId(int id) {
        return Theme.getColor(Theme.key_avatar_subtitleInProfileBlue);
    }

    public static int getProfileBackColorForId(int id) {
        return Theme.getColor(Theme.key_avatar_backgroundActionBarBlue);
    }

    public static int getNameColorForId(int id) {
        return Theme.getColor(Theme.keys_avatar_nameInMessage[getColorIndex(id)]);
    }

    public void setInfo(TLRPC.User user) {
        if (user != null) {
            setInfo(user.id, user.first_name, "", null);
            this.drawDeleted = UserObject.isDeleted(user);
        }
    }

    public void setAvatarType(int value) {
        this.avatarType = value;
        if (value == 3) {
            this.color = Theme.getColor(Theme.key_avatar_backgroundArchivedHidden);
        } else {
            this.color = Theme.getColor(Theme.key_avatar_backgroundSaved);
        }
        this.needApplyColorAccent = false;
    }

    public void setArchivedAvatarHiddenProgress(float progress) {
        this.archivedAvatarProgress = progress;
    }

    public int getAvatarType() {
        return this.avatarType;
    }

    public void setInfo(TLRPC.Chat chat) {
        if (chat != null) {
            setInfo(chat.id, chat.title, null, null);
        }
    }

    public void setColor(int value) {
        this.color = value;
        this.needApplyColorAccent = false;
    }

    public void setTextSize(int size) {
        this.namePaint.setTextSize(size);
    }

    public void setInfo(int id, String firstName, String lastName) {
        setInfo(id, firstName, lastName, null);
    }

    public int getColor() {
        return this.needApplyColorAccent ? Theme.changeColorAccent(this.color) : this.color;
    }

    public void setInfo(int id, String firstName, String lastName, String custom) {
        if (this.isProfile) {
            this.color = getProfileColorForId(id);
        } else {
            this.color = getColorForId(id);
        }
        this.needApplyColorAccent = id == 5;
        this.avatarType = 0;
        this.drawDeleted = false;
        if (firstName == null || firstName.length() == 0) {
            firstName = lastName;
            lastName = null;
        }
        this.stringBuilder.setLength(0);
        if (custom != null) {
            this.stringBuilder.append(custom);
        } else {
            if (firstName != null && firstName.length() > 0) {
                this.stringBuilder.appendCodePoint(firstName.codePointAt(0));
            }
            if (lastName != null && lastName.length() > 0) {
                Integer lastch = null;
                for (int a = lastName.length() - 1; a >= 0 && (lastch == null || lastName.charAt(a) != ' '); a--) {
                    lastch = Integer.valueOf(lastName.codePointAt(a));
                }
                if (Build.VERSION.SDK_INT > 17) {
                    this.stringBuilder.append("\u200c");
                }
                this.stringBuilder.appendCodePoint(lastch.intValue());
            } else if (firstName != null && firstName.length() > 0) {
                int a2 = firstName.length() - 1;
                while (true) {
                    if (a2 < 0) {
                        break;
                    }
                    if (firstName.charAt(a2) != ' ' || a2 == firstName.length() - 1 || firstName.charAt(a2 + 1) == ' ') {
                        a2--;
                    } else {
                        if (Build.VERSION.SDK_INT > 17) {
                            this.stringBuilder.append("\u200c");
                        }
                        this.stringBuilder.appendCodePoint(firstName.codePointAt(a2 + 1));
                    }
                }
            }
        }
        if (this.stringBuilder.length() > 0) {
            String text = this.stringBuilder.toString().toUpperCase();
            try {
                StaticLayout staticLayout = new StaticLayout(text, this.namePaint, AndroidUtilities.dp(100.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                this.textLayout = staticLayout;
                if (staticLayout.getLineCount() > 0) {
                    this.textLeft = this.textLayout.getLineLeft(0);
                    this.textWidth = this.textLayout.getLineWidth(0);
                    this.textHeight = this.textLayout.getLineBottom(0);
                    return;
                }
                return;
            } catch (Exception e) {
                FileLog.e(e);
                return;
            }
        }
        this.textLayout = null;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        android.graphics.Rect bounds = getBounds();
        if (bounds == null) {
            return;
        }
        int size = bounds.width();
        this.namePaint.setColor(Theme.getColor(Theme.key_avatar_text));
        Theme.avatar_backgroundPaint.setColor(getColor());
        canvas.save();
        canvas.translate(bounds.left, bounds.top);
        if (this.mRectF == null) {
            this.mRectF = new RectF(0.0f, 0.0f, size, size);
        }
        float radius = AndroidUtilities.dp(90.0f);
        canvas.drawRoundRect(this.mRectF, radius, radius, Theme.avatar_backgroundPaint);
        int i = this.avatarType;
        if (i == 3) {
            if (this.archivedAvatarProgress != 0.0f) {
                Theme.avatar_backgroundPaint.setColor(Theme.getColor(Theme.key_avatar_backgroundArchived));
                canvas.drawRoundRect(this.mRectF, radius, radius, Theme.avatar_backgroundPaint);
                if (Theme.dialogs_archiveAvatarDrawableRecolored) {
                    Theme.dialogs_archiveAvatarDrawable.beginApplyLayerColors();
                    Theme.dialogs_archiveAvatarDrawable.setLayerColor("Arrow1.**", Theme.getColor(Theme.key_avatar_backgroundArchived));
                    Theme.dialogs_archiveAvatarDrawable.setLayerColor("Arrow2.**", Theme.getColor(Theme.key_avatar_backgroundArchived));
                    Theme.dialogs_archiveAvatarDrawable.commitApplyLayerColors();
                    Theme.dialogs_archiveAvatarDrawableRecolored = false;
                }
            } else if (!Theme.dialogs_archiveAvatarDrawableRecolored) {
                Theme.dialogs_archiveAvatarDrawable.beginApplyLayerColors();
                Theme.dialogs_archiveAvatarDrawable.setLayerColor("Arrow1.**", Theme.getColor(Theme.key_avatar_backgroundArchivedHidden));
                Theme.dialogs_archiveAvatarDrawable.setLayerColor("Arrow2.**", Theme.getColor(Theme.key_avatar_backgroundArchivedHidden));
                Theme.dialogs_archiveAvatarDrawable.commitApplyLayerColors();
                Theme.dialogs_archiveAvatarDrawableRecolored = true;
            }
            int w = Theme.dialogs_archiveAvatarDrawable.getIntrinsicWidth();
            int h = Theme.dialogs_archiveAvatarDrawable.getIntrinsicHeight();
            int x = (size - w) / 2;
            int y = (size - h) / 2;
            canvas.save();
            Theme.dialogs_archiveAvatarDrawable.setBounds(x, y, x + w, y + h);
            Theme.dialogs_archiveAvatarDrawable.draw(canvas);
            canvas.restore();
        } else if (i != 0 && Theme.avatar_savedDrawable != null) {
            int w2 = Theme.avatar_savedDrawable.getIntrinsicWidth();
            int h2 = Theme.avatar_savedDrawable.getIntrinsicHeight();
            if (this.avatarType == 2) {
                w2 = (int) (w2 * 0.8f);
                h2 = (int) (h2 * 0.8f);
            }
            int x2 = (size - w2) / 2;
            int y2 = (size - h2) / 2;
            Theme.avatar_savedDrawable.setBounds(x2, y2, x2 + w2, y2 + h2);
            Theme.avatar_savedDrawable.draw(canvas);
        } else if (this.drawDeleted && Theme.avatar_ghostDrawable != null) {
            int x3 = (size - Theme.avatar_ghostDrawable.getIntrinsicWidth()) / 2;
            int y3 = (size - Theme.avatar_ghostDrawable.getIntrinsicHeight()) / 2;
            Theme.avatar_ghostDrawable.setBounds(x3, y3, Theme.avatar_ghostDrawable.getIntrinsicWidth() + x3, Theme.avatar_ghostDrawable.getIntrinsicHeight() + y3);
            Theme.avatar_ghostDrawable.draw(canvas);
        } else if (this.textLayout != null) {
            canvas.translate(((size - this.textWidth) / 2.0f) - this.textLeft, (size - this.textHeight) / 2.0f);
            this.textLayout.draw(canvas);
        }
        canvas.restore();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter cf) {
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -2;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return 0;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return 0;
    }
}
