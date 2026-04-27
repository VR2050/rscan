package im.uwrkaxlmjj.ui.components.banner.indicator;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.RectF;
import android.util.AttributeSet;

/* JADX INFO: loaded from: classes5.dex */
public class RectangleIndicator extends BaseIndicator {
    RectF rectF;

    public RectangleIndicator(Context context) {
        this(context, null);
    }

    public RectangleIndicator(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public RectangleIndicator(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.rectF = new RectF();
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int count = this.config.getIndicatorSize();
        if (count <= 1) {
            return;
        }
        int space = (int) (this.config.getIndicatorSpace() * (count - 1));
        int normal = (int) (this.config.getNormalWidth() * (count - 1));
        setMeasuredDimension(space + normal + ((int) this.config.getSelectedWidth()) + getPaddingLeft() + getPaddingRight(), ((int) this.config.getHeight()) + getPaddingTop() + getPaddingBottom());
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int count = this.config.getIndicatorSize();
        if (count <= 1) {
            return;
        }
        float left = getPaddingLeft();
        int i = 0;
        while (i < count) {
            this.mPaint.setColor(this.config.getCurrentPosition() == i ? this.config.getSelectedColor() : this.config.getNormalColor());
            float indicatorWidth = this.config.getCurrentPosition() == i ? this.config.getSelectedWidth() : this.config.getNormalWidth();
            this.rectF.set(left, getPaddingTop(), left + indicatorWidth, getPaddingTop() + this.config.getHeight());
            left += this.config.getIndicatorSpace() + indicatorWidth;
            canvas.drawRoundRect(this.rectF, this.config.getRadius(), this.config.getRadius(), this.mPaint);
            i++;
        }
    }
}
