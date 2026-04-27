package im.uwrkaxlmjj.ui.hui.views;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class ArcView extends View {
    private int lgColor;
    private LinearGradient linearGradient;
    private int mArcHeight;
    private int mBgColor;
    private int mHeight;
    private Paint mPaint;
    private int mWidth;
    private Path path;
    private Rect rect;

    public ArcView(Context context) {
        this(context, null);
    }

    public ArcView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public ArcView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.rect = new Rect(0, 0, 0, 0);
        this.path = new Path();
        this.mArcHeight = AndroidUtilities.dp(50.0f);
        this.mBgColor = -104343;
        this.lgColor = -96917;
        Paint paint = new Paint();
        this.mPaint = paint;
        paint.setAntiAlias(true);
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        LinearGradient linearGradient = new LinearGradient(0.0f, 0.0f, getMeasuredWidth(), 0.0f, this.mBgColor, this.lgColor, Shader.TileMode.CLAMP);
        this.linearGradient = linearGradient;
        this.mPaint.setShader(linearGradient);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        this.mPaint.setStyle(Paint.Style.FILL);
        this.mPaint.setColor(this.mBgColor);
        this.rect.set(0, 0, this.mWidth, (this.mHeight - this.mArcHeight) + 1);
        canvas.drawRect(this.rect, this.mPaint);
        this.path.moveTo(0.0f, this.mHeight - this.mArcHeight);
        Path path = this.path;
        int i = this.mWidth;
        path.quadTo(i >> 1, this.mHeight, i, r3 - this.mArcHeight);
        canvas.drawPath(this.path, this.mPaint);
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
        int widthMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
        int heightMode = View.MeasureSpec.getMode(heightMeasureSpec);
        if (widthMode == 1073741824) {
            this.mWidth = widthSize;
        }
        if (heightMode == 1073741824) {
            this.mHeight = heightSize;
        }
        setMeasuredDimension(this.mWidth, this.mHeight);
    }
}
