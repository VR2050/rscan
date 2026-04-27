package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class IndexTextCountCell extends FrameLayout {
    private TextView countText;
    private ImageView imageView;
    private boolean needDivider;
    private SimpleTextView textView;

    public IndexTextCountCell(Context context) {
        super(context);
        ImageView imageView = new ImageView(context);
        this.imageView = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        this.imageView.setBackgroundResource(R.id.fmt_contacts_icon_bg);
        addView(this.imageView);
        SimpleTextView simpleTextView = new SimpleTextView(context);
        this.textView = simpleTextView;
        simpleTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.textView.setTextSize(14);
        this.textView.setGravity(LocaleController.isRTL ? 5 : 3);
        addView(this.textView);
        TextView textView = new TextView(context);
        this.countText = textView;
        textView.setTextColor(-1);
        this.countText.setTextSize(12.0f);
        this.countText.setGravity(17);
        this.countText.setText("99");
        this.countText.setBackgroundResource(R.drawable.shape_contacts_unread);
        addView(this.countText);
        setFocusable(true);
    }

    public SimpleTextView getTextView() {
        return this.textView;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        int size = View.MeasureSpec.getSize(i);
        this.imageView.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), Integer.MIN_VALUE));
        this.textView.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(20.0f), 1073741824));
        if (this.countText.getVisibility() == 0) {
            this.countText.measure(View.MeasureSpec.makeMeasureSpec(size, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(18.0f), 1073741824));
        }
        setMeasuredDimension(size, AndroidUtilities.dp(50.0f) + (this.needDivider ? 1 : 0));
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int height = bottom - top;
        int width = right - left;
        int viewTop = (height - AndroidUtilities.dp(36.5f)) / 2;
        int viewLeft = AndroidUtilities.dp(15.0f);
        this.imageView.layout(viewLeft, viewTop, AndroidUtilities.dp(36.5f) + viewLeft, AndroidUtilities.dp(36.5f) + viewTop);
        int viewLeft2 = AndroidUtilities.dp(60.0f);
        int viewTop2 = (height - this.textView.getTextHeight()) / 2;
        SimpleTextView simpleTextView = this.textView;
        simpleTextView.layout(viewLeft2, viewTop2, simpleTextView.getMeasuredWidth() + viewLeft2, this.textView.getMeasuredHeight() + viewTop2);
        if (this.countText.getVisibility() == 0) {
            int viewTop3 = (height - this.countText.getMeasuredHeight()) / 2;
            int viewLeft3 = (width - this.countText.getMeasuredWidth()) - AndroidUtilities.dp(36.0f);
            TextView textView = this.countText;
            textView.layout(viewLeft3, viewTop3, textView.getMeasuredWidth() + viewLeft3, this.countText.getMeasuredHeight() + viewTop3);
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

    public void setTextAndIcon(String text, int resId, boolean divider) {
        this.imageView.setImageResource(resId);
        this.textView.setText(text);
        this.needDivider = divider;
    }

    public void setCount(int count) {
        this.countText.setVisibility(count <= 0 ? 8 : 0);
        this.countText.setText(String.valueOf(count));
        invalidate();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        float fDp;
        int iDp;
        if (this.needDivider) {
            if (LocaleController.isRTL) {
                fDp = 0.0f;
            } else {
                fDp = AndroidUtilities.dp(this.imageView.getVisibility() == 0 ? 68.0f : 20.0f);
            }
            float measuredHeight = getMeasuredHeight() - 1;
            int measuredWidth = getMeasuredWidth();
            if (LocaleController.isRTL) {
                iDp = AndroidUtilities.dp(this.imageView.getVisibility() != 0 ? 20.0f : 68.0f);
            } else {
                iDp = 0;
            }
            canvas.drawLine(fDp, measuredHeight, measuredWidth - iDp, getMeasuredHeight() - 1, Theme.dividerPaint);
        }
    }
}
