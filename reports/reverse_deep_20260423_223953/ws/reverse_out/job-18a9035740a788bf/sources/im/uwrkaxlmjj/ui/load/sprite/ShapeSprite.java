package im.uwrkaxlmjj.ui.load.sprite;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;

/* JADX INFO: loaded from: classes5.dex */
public abstract class ShapeSprite extends Sprite {
    private int mBaseColor;
    private Paint mPaint;
    private int mUseColor;

    public abstract void drawShape(Canvas canvas, Paint paint);

    public ShapeSprite() {
        setColor(-1);
        Paint paint = new Paint();
        this.mPaint = paint;
        paint.setAntiAlias(true);
        this.mPaint.setColor(this.mUseColor);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    public void setColor(int color) {
        this.mBaseColor = color;
        updateUseColor();
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    public int getColor() {
        return this.mBaseColor;
    }

    public int getUseColor() {
        return this.mUseColor;
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        super.setAlpha(alpha);
        updateUseColor();
    }

    private void updateUseColor() {
        int alpha = getAlpha();
        int i = this.mBaseColor;
        int baseAlpha = i >>> 24;
        int useAlpha = (baseAlpha * (alpha + (alpha >> 7))) >> 8;
        this.mUseColor = ((i << 8) >>> 8) | (useAlpha << 24);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.mPaint.setColorFilter(colorFilter);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    protected final void drawSelf(Canvas canvas) {
        this.mPaint.setColor(this.mUseColor);
        drawShape(canvas, this.mPaint);
    }
}
