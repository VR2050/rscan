package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SessionCell extends FrameLayout {
    private AvatarDrawable avatarDrawable;
    private int currentAccount;
    private TextView detailExTextView;
    private TextView detailTextView;
    private BackupImageView imageView;
    private TextView nameTextView;
    private boolean needDivider;
    private TextView onlineTextView;
    private int type;

    public SessionCell(Context context, int type) {
        this(context, (AttributeSet) null);
        this.type = type;
    }

    public SessionCell(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SessionCell(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.currentAccount = UserConfig.selectedAccount;
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(0);
        linearLayout.setWeightSum(1.0f);
        if (this.type == 1) {
            addView(linearLayout, LayoutHelper.createFrame(-1.0f, 30.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 15 : 49, 11.0f, LocaleController.isRTL ? 49 : 15, 0.0f));
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            this.avatarDrawable = avatarDrawable;
            avatarDrawable.setTextSize(AndroidUtilities.dp(10.0f));
            BackupImageView backupImageView = new BackupImageView(context);
            this.imageView = backupImageView;
            backupImageView.setRoundRadius(AndroidUtilities.dp(10.0f));
            addView(this.imageView, LayoutHelper.createFrame(20.0f, 20.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0 : 21, 13.0f, LocaleController.isRTL ? 21 : 0, 0.0f));
        } else {
            addView(linearLayout, LayoutHelper.createFrame(-1.0f, 30.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 15 : 21, 11.0f, LocaleController.isRTL ? 21 : 15, 0.0f));
        }
        TextView textView = new TextView(context);
        this.nameTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.nameTextView.setTextSize(1, 14.0f);
        this.nameTextView.setLines(1);
        this.nameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.nameTextView.setMaxLines(1);
        this.nameTextView.setSingleLine(true);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.nameTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        TextView textView2 = new TextView(context);
        this.onlineTextView = textView2;
        textView2.setTextSize(1, 13.0f);
        this.onlineTextView.setGravity((LocaleController.isRTL ? 3 : 5) | 48);
        if (LocaleController.isRTL) {
            linearLayout.addView(this.onlineTextView, LayoutHelper.createLinear(-2, -1, 51, 0, 2, 0, 0));
            linearLayout.addView(this.nameTextView, LayoutHelper.createLinear(0, -1, 1.0f, 53, 10, 0, 0, 0));
        } else {
            linearLayout.addView(this.nameTextView, LayoutHelper.createLinear(0, -1, 1.0f, 51, 0, 0, 10, 0));
            linearLayout.addView(this.onlineTextView, LayoutHelper.createLinear(-2, -1, 53, 0, 2, 0, 0));
        }
        TextView textView3 = new TextView(context);
        this.detailTextView = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.detailTextView.setTextSize(1, 14.0f);
        this.detailTextView.setLines(1);
        this.detailTextView.setMaxLines(1);
        this.detailTextView.setSingleLine(true);
        this.detailTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.detailTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        addView(this.detailTextView, LayoutHelper.createFrame(-1.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 36.0f, 21.0f, 0.0f));
        TextView textView4 = new TextView(context);
        this.detailExTextView = textView4;
        textView4.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        this.detailExTextView.setTextSize(1, 14.0f);
        this.detailExTextView.setLines(1);
        this.detailExTextView.setMaxLines(1);
        this.detailExTextView.setSingleLine(true);
        this.detailExTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.detailExTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        addView(this.detailExTextView, LayoutHelper.createFrame(-1.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 59.0f, 21.0f, 0.0f));
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(i), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(90.0f) + (this.needDivider ? 1 : 0), 1073741824));
    }

    public void setSession(TLObject object, boolean divider) {
        String name;
        this.needDivider = divider;
        if (object instanceof TLRPC.TL_authorization) {
            TLRPC.TL_authorization session = (TLRPC.TL_authorization) object;
            this.nameTextView.setText(String.format(Locale.US, "%s %s", session.app_name, session.app_version));
            if ((session.flags & 1) != 0) {
                setTag(Theme.key_windowBackgroundWhiteValueText);
                this.onlineTextView.setText(LocaleController.getString("Online", R.string.Online));
                this.onlineTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteValueText));
            } else {
                setTag(Theme.key_windowBackgroundWhiteGrayText3);
                this.onlineTextView.setText(LocaleController.stringForMessageListDate(session.date_active));
                this.onlineTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            }
            StringBuilder stringBuilder = new StringBuilder();
            if (session.ip.length() != 0) {
                stringBuilder.append(session.ip);
            }
            if (session.country.length() != 0) {
                if (stringBuilder.length() != 0) {
                    stringBuilder.append(" ");
                }
                stringBuilder.append("— ");
                stringBuilder.append(session.country);
            }
            this.detailExTextView.setText(stringBuilder);
            StringBuilder stringBuilder2 = new StringBuilder();
            if (session.device_model.length() != 0) {
                if (stringBuilder2.length() != 0) {
                    stringBuilder2.append(", ");
                }
                stringBuilder2.append(session.device_model);
            }
            if (session.system_version.length() != 0 || session.platform.length() != 0) {
                if (stringBuilder2.length() != 0) {
                    stringBuilder2.append(", ");
                }
                if (session.platform.length() != 0) {
                    stringBuilder2.append(session.platform);
                }
                if (session.system_version.length() != 0) {
                    if (session.platform.length() != 0) {
                        stringBuilder2.append(" ");
                    }
                    stringBuilder2.append(session.system_version);
                }
            }
            this.detailTextView.setText(stringBuilder2);
            return;
        }
        if (object instanceof TLRPC.TL_webAuthorization) {
            TLRPC.TL_webAuthorization session2 = (TLRPC.TL_webAuthorization) object;
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(session2.bot_id));
            this.nameTextView.setText(session2.domain);
            if (user != null) {
                this.avatarDrawable.setInfo(user);
                name = UserObject.getFirstName(user);
                this.imageView.setImage(ImageLocation.getForUser(user, false), "50_50", this.avatarDrawable, user);
            } else {
                name = "";
            }
            setTag(Theme.key_windowBackgroundWhiteGrayText3);
            this.onlineTextView.setText(LocaleController.stringForMessageListDate(session2.date_active));
            this.onlineTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            StringBuilder stringBuilder3 = new StringBuilder();
            if (session2.ip.length() != 0) {
                stringBuilder3.append(session2.ip);
            }
            if (session2.region.length() != 0) {
                if (stringBuilder3.length() != 0) {
                    stringBuilder3.append(" ");
                }
                stringBuilder3.append("— ");
                stringBuilder3.append(session2.region);
            }
            this.detailExTextView.setText(stringBuilder3);
            StringBuilder stringBuilder4 = new StringBuilder();
            if (!TextUtils.isEmpty(name)) {
                stringBuilder4.append(name);
            }
            if (session2.browser.length() != 0) {
                if (stringBuilder4.length() != 0) {
                    stringBuilder4.append(", ");
                }
                stringBuilder4.append(session2.browser);
            }
            if (session2.platform.length() != 0) {
                if (stringBuilder4.length() != 0) {
                    stringBuilder4.append(", ");
                }
                stringBuilder4.append(session2.platform);
            }
            this.detailTextView.setText(stringBuilder4);
        }
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.needDivider) {
            canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(20.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(20.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
        }
    }
}
