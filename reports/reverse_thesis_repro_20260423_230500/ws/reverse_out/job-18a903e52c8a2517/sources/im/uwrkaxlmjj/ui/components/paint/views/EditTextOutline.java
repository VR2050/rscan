package im.uwrkaxlmjj.ui.components.paint.views;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.widget.EditText;

/* JADX INFO: loaded from: classes5.dex */
public class EditTextOutline extends EditText {
    private Bitmap mCache;
    private final Canvas mCanvas;
    private final TextPaint mPaint;
    private int mStrokeColor;
    private float mStrokeWidth;
    private boolean mUpdateCachedBitmap;

    public EditTextOutline(Context context) {
        super(context);
        this.mCanvas = new Canvas();
        TextPaint textPaint = new TextPaint();
        this.mPaint = textPaint;
        this.mStrokeColor = 0;
        this.mUpdateCachedBitmap = true;
        textPaint.setAntiAlias(true);
        this.mPaint.setStyle(Paint.Style.FILL_AND_STROKE);
    }

    @Override // android.widget.TextView
    protected void onTextChanged(CharSequence text, int start, int before, int after) {
        super.onTextChanged(text, start, before, after);
        this.mUpdateCachedBitmap = true;
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        if (w > 0 && h > 0) {
            this.mUpdateCachedBitmap = true;
            this.mCache = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        } else {
            this.mCache = null;
        }
    }

    public void setStrokeColor(int strokeColor) {
        this.mStrokeColor = strokeColor;
        this.mUpdateCachedBitmap = true;
        invalidate();
    }

    public void setStrokeWidth(float strokeWidth) {
        this.mStrokeWidth = strokeWidth;
        this.mUpdateCachedBitmap = true;
        invalidate();
    }

    @Override // android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.mCache != null && this.mStrokeColor != 0) {
            if (this.mUpdateCachedBitmap) {
                int w = (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
                int h = getMeasuredHeight();
                String text = getText().toString();
                this.mCanvas.setBitmap(this.mCache);
                this.mCanvas.drawColor(0, PorterDuff.Mode.CLEAR);
                float fCeil = this.mStrokeWidth;
                if (fCeil <= 0.0f) {
                    fCeil = (float) Math.ceil(getTextSize() / 11.5f);
                }
                float strokeWidth = fCeil;
                this.mPaint.setStrokeWidth(strokeWidth);
                this.mPaint.setColor(this.mStrokeColor);
                this.mPaint.setTextSize(getTextSize());
                this.mPaint.setTypeface(getTypeface());
                this.mPaint.setStyle(Paint.Style.FILL_AND_STROKE);
                StaticLayout sl = new StaticLayout(text, this.mPaint, w, Layout.Alignment.ALIGN_CENTER, 1.0f, 0.0f, true);
                this.mCanvas.save();
                float a = (((h - getPaddingTop()) - getPaddingBottom()) - sl.getHeight()) / 2.0f;
                this.mCanvas.translate(getPaddingLeft(), getPaddingTop() + a);
                sl.draw(this.mCanvas);
                this.mCanvas.restore();
                this.mUpdateCachedBitmap = false;
            }
            canvas.drawBitmap(this.mCache, 0.0f, 0.0f, this.mPaint);
        }
        super.onDraw(canvas);
    }
}
