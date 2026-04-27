package im.uwrkaxlmjj.ui.load.sprite;

import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.Paint;

/* JADX INFO: loaded from: classes5.dex */
public class RingSprite extends ShapeSprite {
    @Override // im.uwrkaxlmjj.ui.load.sprite.ShapeSprite
    public void drawShape(Canvas canvas, Paint paint) {
        if (getDrawBounds() != null) {
            paint.setStyle(Paint.Style.STROKE);
            int radius = Math.min(getDrawBounds().width(), getDrawBounds().height()) / 2;
            paint.setStrokeWidth(radius / 12);
            canvas.drawCircle(getDrawBounds().centerX(), getDrawBounds().centerY(), radius, paint);
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    public ValueAnimator onCreateAnimation() {
        return null;
    }
}
