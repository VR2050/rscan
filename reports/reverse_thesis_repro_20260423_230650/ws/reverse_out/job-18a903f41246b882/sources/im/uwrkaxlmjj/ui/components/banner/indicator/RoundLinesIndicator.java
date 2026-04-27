package im.uwrkaxlmjj.ui.components.banner.indicator;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;

/* JADX INFO: loaded from: classes5.dex */
public class RoundLinesIndicator extends BaseIndicator {
    public RoundLinesIndicator(Context context) {
        this(context, null);
    }

    public RoundLinesIndicator(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public RoundLinesIndicator(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mPaint.setStyle(Paint.Style.FILL);
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int count = this.config.getIndicatorSize();
        if (count <= 1) {
            return;
        }
        setMeasuredDimension((int) (this.config.getSelectedWidth() * count), (int) this.config.getHeight());
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int count = this.config.getIndicatorSize();
        if (count <= 1) {
            return;
        }
        this.mPaint.setColor(this.config.getNormalColor());
        RectF oval = new RectF(0.0f, 0.0f, canvas.getWidth(), this.config.getHeight());
        canvas.drawRoundRect(oval, this.config.getRadius(), this.config.getRadius(), this.mPaint);
        this.mPaint.setColor(this.config.getSelectedColor());
        float left = this.config.getCurrentPosition() * this.config.getSelectedWidth();
        RectF rectF = new RectF(left, 0.0f, this.config.getSelectedWidth() + left, this.config.getHeight());
        canvas.drawRoundRect(rectF, this.config.getRadius(), this.config.getRadius(), this.mPaint);
    }
}
