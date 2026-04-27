package im.uwrkaxlmjj.ui.cells;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.SeekBarView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MaxFileSizeCell extends FrameLayout {
    private long currentSize;
    private boolean drawDivider;
    private SeekBarView seekBarView;
    private TextView sizeTextView;
    private TextView textView;

    public MaxFileSizeCell(Context context) {
        super(context);
        init(context);
        this.drawDivider = true;
    }

    public MaxFileSizeCell(Context context, boolean drawDivider) {
        super(context);
        init(context);
        this.drawDivider = drawDivider;
    }

    private void init(Context context) {
        setWillNotDraw(false);
        TextView textView = new TextView(context);
        this.textView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        this.textView.setTextSize(1, 14.0f);
        this.textView.setLines(1);
        this.textView.setMaxLines(1);
        this.textView.setSingleLine(true);
        this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        this.textView.setEllipsize(TextUtils.TruncateAt.END);
        addView(this.textView, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 13.0f, 21.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.sizeTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        this.sizeTextView.setTextSize(1, 14.0f);
        this.sizeTextView.setLines(1);
        this.sizeTextView.setMaxLines(1);
        this.sizeTextView.setSingleLine(true);
        this.sizeTextView.setGravity((LocaleController.isRTL ? 3 : 5) | 48);
        addView(this.sizeTextView, LayoutHelper.createFrame(-2.0f, -1.0f, (LocaleController.isRTL ? 3 : 5) | 48, 21.0f, 13.0f, 21.0f, 0.0f));
        SeekBarView seekBarView = new SeekBarView(context) { // from class: im.uwrkaxlmjj.ui.cells.MaxFileSizeCell.1
            @Override // im.uwrkaxlmjj.ui.components.SeekBarView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (event.getAction() == 0) {
                    getParent().requestDisallowInterceptTouchEvent(true);
                }
                return super.onTouchEvent(event);
            }
        };
        this.seekBarView = seekBarView;
        seekBarView.setReportChanges(true);
        this.seekBarView.setDelegate(new SeekBarView.SeekBarViewDelegate() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$MaxFileSizeCell$dRpoJ2zSlj5yKmEplNHCVsw7mZ4
            @Override // im.uwrkaxlmjj.ui.components.SeekBarView.SeekBarViewDelegate
            public final void onSeekBarDrag(float f) {
                this.f$0.lambda$init$0$MaxFileSizeCell(f);
            }
        });
        addView(this.seekBarView, LayoutHelper.createFrame(-1.0f, 30.0f, 51, 10.0f, 40.0f, 10.0f, 0.0f));
    }

    public /* synthetic */ void lambda$init$0$MaxFileSizeCell(float progress) {
        int size;
        if (progress <= 0.25f) {
            size = (int) (512000 + ((progress / 0.25f) * 536576.0f));
        } else {
            float progress2 = progress - 0.25f;
            int size2 = 512000 + 536576;
            if (progress2 < 0.25f) {
                size = (int) (size2 + ((progress2 / 0.25f) * 9437184.0f));
            } else {
                float progress3 = progress2 - 0.25f;
                size = progress3 <= 0.25f ? (int) (size2 + 9437184 + ((progress3 / 0.25f) * 9.437184E7f)) : (int) (r0 + 94371840 + (((progress3 - 0.25f) / 0.25f) * 1.5057551E9f));
            }
        }
        this.sizeTextView.setText(LocaleController.formatString("AutodownloadSizeLimitUpTo", R.string.AutodownloadSizeLimitUpTo, AndroidUtilities.formatFileSize(size)));
        this.currentSize = size;
        didChangedSizeValue(size);
    }

    protected void didChangedSizeValue(int value) {
    }

    public void setText(String text) {
        this.textView.setText(text);
    }

    public long getSize() {
        return this.currentSize;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(80.0f), 1073741824));
        setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), AndroidUtilities.dp(80.0f));
        int availableWidth = getMeasuredWidth() - AndroidUtilities.dp(42.0f);
        this.sizeTextView.measure(View.MeasureSpec.makeMeasureSpec(availableWidth, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(30.0f), 1073741824));
        int width = Math.max(AndroidUtilities.dp(10.0f), (availableWidth - this.sizeTextView.getMeasuredWidth()) - AndroidUtilities.dp(8.0f));
        this.textView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(30.0f), 1073741824));
        this.seekBarView.measure(View.MeasureSpec.makeMeasureSpec(getMeasuredWidth() - AndroidUtilities.dp(20.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(30.0f), 1073741824));
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        if (!isEnabled()) {
            return true;
        }
        return super.onInterceptTouchEvent(ev);
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchTouchEvent(MotionEvent ev) {
        if (!isEnabled()) {
            return true;
        }
        return super.dispatchTouchEvent(ev);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (!isEnabled()) {
            return true;
        }
        return super.onTouchEvent(event);
    }

    public void setSize(long size) {
        float progress;
        this.currentSize = size;
        this.sizeTextView.setText(LocaleController.formatString("AutodownloadSizeLimitUpTo", R.string.AutodownloadSizeLimitUpTo, AndroidUtilities.formatFileSize(size)));
        long size2 = size - 512000;
        if (size2 < 536576) {
            progress = Math.max(0.0f, size2 / 536576.0f) * 0.25f;
        } else {
            float progress2 = 0.0f + 0.25f;
            long size3 = size2 - 536576;
            if (size3 < 9437184) {
                progress = (Math.max(0.0f, size3 / 9437184.0f) * 0.25f) + progress2;
            } else {
                float progress3 = progress2 + 0.25f;
                long size4 = size3 - 9437184;
                if (size4 < 94371840) {
                    progress = (Math.max(0.0f, size4 / 9.437184E7f) * 0.25f) + progress3;
                } else {
                    progress = (Math.max(0.0f, (size4 - 94371840) / 1.5057551E9f) * 0.25f) + progress3 + 0.25f;
                }
            }
        }
        this.seekBarView.setProgress(progress);
    }

    public void setEnabled(boolean value, ArrayList<Animator> animators) {
        super.setEnabled(value);
        if (animators != null) {
            TextView textView = this.textView;
            float[] fArr = new float[1];
            fArr[0] = value ? 1.0f : 0.5f;
            animators.add(ObjectAnimator.ofFloat(textView, "alpha", fArr));
            SeekBarView seekBarView = this.seekBarView;
            float[] fArr2 = new float[1];
            fArr2[0] = value ? 1.0f : 0.5f;
            animators.add(ObjectAnimator.ofFloat(seekBarView, "alpha", fArr2));
            TextView textView2 = this.sizeTextView;
            float[] fArr3 = new float[1];
            fArr3[0] = value ? 1.0f : 0.5f;
            animators.add(ObjectAnimator.ofFloat(textView2, "alpha", fArr3));
            return;
        }
        this.textView.setAlpha(value ? 1.0f : 0.5f);
        this.seekBarView.setAlpha(value ? 1.0f : 0.5f);
        this.sizeTextView.setAlpha(value ? 1.0f : 0.5f);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.drawDivider) {
            canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(20.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(20.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
        }
    }
}
