package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class IndexTextCell2 extends FrameLayout {
    AvatarDrawable avatarDrawable;
    private SimpleTextView countText;
    View fc_point_root;
    private ImageView imageView;
    BackupImageView iv_head;
    private int leftPadding;
    private boolean needDivider;
    private View pointView;
    private SimpleTextView textView;
    private ImageView valueImageView;
    private SimpleTextView valueTextView;

    public IndexTextCell2(Context context) {
        this(context, 23);
    }

    public IndexTextCell2(Context context, int left) {
        super(context);
        this.leftPadding = left;
        SimpleTextView simpleTextView = new SimpleTextView(context);
        this.textView = simpleTextView;
        simpleTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.textView.setTextSize(14);
        this.textView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.textView);
        SimpleTextView simpleTextView2 = new SimpleTextView(context);
        this.valueTextView = simpleTextView2;
        simpleTextView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.valueTextView.setTextSize(12);
        this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.valueTextView);
        SimpleTextView simpleTextView3 = new SimpleTextView(context);
        this.countText = simpleTextView3;
        simpleTextView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        this.countText.setTextSize(12);
        this.countText.setGravity(17);
        addView(this.countText);
        ImageView imageView = new ImageView(context);
        this.imageView = imageView;
        imageView.setScaleType(ImageView.ScaleType.FIT_XY);
        addView(this.imageView);
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.view_friends_head_point, (ViewGroup) null);
        this.pointView = viewInflate;
        addView(viewInflate);
        this.iv_head = (BackupImageView) this.pointView.findViewById(R.attr.iv_head);
        this.fc_point_root = this.pointView.findViewById(R.attr.fc_point_root);
        ImageView imageView2 = new ImageView(context);
        this.valueImageView = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        addView(this.valueImageView);
        setFocusable(true);
    }

    public void setShowPointView(TLRPC.User itemUser, boolean isShow) {
        this.iv_head.setRoundRadius(AndroidUtilities.dp(15.0f));
        if (itemUser != null) {
            this.avatarDrawable = new AvatarDrawable(itemUser, true);
            this.iv_head.setImage(ImageLocation.getForUser(itemUser, false), "50_50", this.avatarDrawable, itemUser);
        }
        this.fc_point_root.setVisibility(isShow ? 0 : 8);
    }

    public SimpleTextView getTextView() {
        return this.textView;
    }

    public SimpleTextView getValueTextView() {
        return this.valueTextView;
    }

    public ImageView getValueImageView() {
        return this.valueImageView;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        int size = View.MeasureSpec.getSize(i);
        int iDp = AndroidUtilities.dp(50.0f);
        this.valueTextView.measure(View.MeasureSpec.makeMeasureSpec(size - AndroidUtilities.dp(this.leftPadding), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(20.0f), 1073741824));
        if (this.imageView.getVisibility() == 0) {
            this.imageView.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(iDp, Integer.MIN_VALUE));
            this.textView.measure(View.MeasureSpec.makeMeasureSpec((size - AndroidUtilities.dp(this.leftPadding + 71)) - this.valueTextView.getTextWidth(), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(20.0f), 1073741824));
        } else {
            this.textView.measure(View.MeasureSpec.makeMeasureSpec((size - AndroidUtilities.dp(this.leftPadding)) - this.valueTextView.getTextWidth(), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(20.0f), 1073741824));
        }
        if (this.valueImageView.getVisibility() == 0) {
            this.valueImageView.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(iDp, Integer.MIN_VALUE));
        }
        if (this.pointView.getVisibility() == 0) {
            this.pointView.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(iDp, Integer.MIN_VALUE));
        }
        if (this.countText.getVisibility() == 0) {
            this.countText.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(iDp, Integer.MIN_VALUE));
        }
        setMeasuredDimension(size, AndroidUtilities.dp(50.0f) + (this.needDivider ? 1 : 0));
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int height = bottom - top;
        int width = right - left;
        int viewTop = (height - this.textView.getTextHeight()) / 2;
        if (this.valueTextView.getVisibility() == 0) {
            viewTop = ((height / 2) - this.textView.getTextHeight()) / 2;
        }
        int viewLeft = AndroidUtilities.dp(this.imageView.getVisibility() == 0 ? 50.0f : this.leftPadding);
        SimpleTextView simpleTextView = this.textView;
        simpleTextView.layout(viewLeft, viewTop, simpleTextView.getMeasuredWidth() + viewLeft, this.textView.getMeasuredHeight() + viewTop);
        int valueTop = (((height * 3) / 2) - this.valueTextView.getTextHeight()) / 2;
        SimpleTextView simpleTextView2 = this.valueTextView;
        simpleTextView2.layout(viewLeft, valueTop, simpleTextView2.getMeasuredWidth() + viewLeft, this.valueTextView.getMeasuredHeight() + valueTop);
        if (this.imageView.getVisibility() == 0) {
            int viewTop2 = (height - AndroidUtilities.dp(27.0f)) / 2;
            int viewLeft2 = AndroidUtilities.dp(12.0f);
            this.imageView.layout(viewLeft2, viewTop2, AndroidUtilities.dp(27.0f) + viewLeft2, AndroidUtilities.dp(27.0f) + viewTop2);
        }
        if (this.pointView.getVisibility() == 0) {
            int viewTop3 = (height - this.pointView.getMeasuredHeight()) / 2;
            int viewLeft3 = LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : ((width - this.pointView.getMeasuredWidth()) - AndroidUtilities.dp(32.0f)) - this.valueImageView.getMeasuredWidth();
            View view = this.pointView;
            view.layout(viewLeft3, viewTop3, view.getMeasuredWidth() + viewLeft3, this.pointView.getMeasuredHeight() + viewTop3);
        }
        if (this.valueImageView.getVisibility() == 0) {
            int viewTop4 = (height - this.valueImageView.getMeasuredHeight()) / 2;
            int viewLeft4 = LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : (width - this.valueImageView.getMeasuredWidth()) - AndroidUtilities.dp(16.0f);
            ImageView imageView = this.valueImageView;
            imageView.layout(viewLeft4, viewTop4, imageView.getMeasuredWidth() + viewLeft4, this.valueImageView.getMeasuredHeight() + viewTop4);
        }
    }

    public void setTextColor(int color) {
        this.textView.setTextColor(color);
    }

    public void setColors(String icon, String text) {
        this.textView.setTextColor(Theme.getColor(text));
        this.textView.setTag(text);
        if (icon != null) {
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(icon), PorterDuff.Mode.MULTIPLY));
            this.imageView.setTag(icon);
        }
    }

    public void setText(String text, boolean divider) {
        this.textView.setText(text);
        this.valueTextView.setText(null);
        this.imageView.setVisibility(8);
        this.valueTextView.setVisibility(8);
        this.valueImageView.setVisibility(8);
        this.needDivider = divider;
        setWillNotDraw(!divider);
        check(0, null, 0);
    }

    public void setTextAndIcon(String text, int resId, boolean divider) {
        setTextAndIcon(text, resId, false, divider);
    }

    public void setTextAndIcon(String text, int resId, boolean arrow, boolean divider) {
        this.textView.setText(text);
        this.valueTextView.setText(null);
        this.imageView.setVisibility(0);
        this.imageView.setImageResource(resId);
        this.imageView.setBackgroundResource(R.id.fmt_contacts_icon_bg);
        this.valueTextView.setVisibility(8);
        this.valueImageView.setVisibility(arrow ? 0 : 8);
        if (arrow) {
            this.valueImageView.setImageResource(R.id.icon_arrow_right);
        }
        this.needDivider = divider;
        setWillNotDraw(!divider);
        check(resId, null, arrow ? R.id.icon_arrow_right : 0);
    }

    public void setTextAndIcon(String text, int resId, int rightId, boolean divider) {
        this.textView.setText(text);
        this.valueTextView.setText(null);
        this.imageView.setImageResource(resId);
        this.imageView.setVisibility(0);
        this.valueTextView.setVisibility(8);
        this.valueImageView.setVisibility(0);
        this.valueImageView.setImageResource(rightId);
        this.needDivider = divider;
        setWillNotDraw(!divider);
        check(resId, null, rightId);
    }

    public void setTextAndValue(String text, String value, boolean divider) {
        this.textView.setText(text);
        this.valueTextView.setText(value);
        this.valueTextView.setVisibility(0);
        this.imageView.setVisibility(8);
        this.valueImageView.setVisibility(8);
        this.needDivider = divider;
        setWillNotDraw(!divider);
        check(0, value, 0);
    }

    public void setTextAndValueAndIcon(String text, String value, int resId, int valueId, boolean divider) {
        this.textView.setText(text);
        this.valueTextView.setText(value);
        this.valueTextView.setVisibility(0);
        this.valueImageView.setVisibility(0);
        this.valueImageView.setImageResource(valueId);
        this.imageView.setVisibility(0);
        this.imageView.setImageResource(resId);
        this.needDivider = divider;
        setWillNotDraw(!divider);
        check(resId, value, valueId);
    }

    private void check(int resId, String value, int valueId) {
        if (resId <= 0) {
            this.imageView.setVisibility(8);
        } else {
            this.imageView.setVisibility(0);
        }
        if (valueId <= 0) {
            this.valueImageView.setVisibility(8);
        } else {
            this.valueImageView.setVisibility(0);
        }
        if (TextUtils.isEmpty(value)) {
            this.valueTextView.setVisibility(8);
        } else {
            this.valueTextView.setVisibility(0);
        }
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        float fDp;
        int iDp;
        if (this.needDivider) {
            if (LocaleController.isRTL) {
                fDp = 0.0f;
            } else {
                fDp = AndroidUtilities.dp(this.imageView.getVisibility() == 0 ? 50.0f : 20.0f);
            }
            float measuredHeight = getMeasuredHeight() - AndroidUtilities.dp(0.25f);
            int measuredWidth = getMeasuredWidth();
            if (LocaleController.isRTL) {
                iDp = AndroidUtilities.dp(this.imageView.getVisibility() == 0 ? 68.0f : 20.0f);
            } else {
                iDp = 0;
            }
            canvas.drawLine(fDp, measuredHeight, measuredWidth - iDp, getMeasuredHeight() - AndroidUtilities.dp(0.25f), Theme.dividerPaint);
        }
    }
}
