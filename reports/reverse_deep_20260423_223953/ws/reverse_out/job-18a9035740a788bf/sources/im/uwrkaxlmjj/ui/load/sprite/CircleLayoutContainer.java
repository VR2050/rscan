package im.uwrkaxlmjj.ui.load.sprite;

import android.graphics.Canvas;
import android.graphics.Rect;

/* JADX INFO: loaded from: classes5.dex */
public abstract class CircleLayoutContainer extends SpriteContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public void drawChild(Canvas canvas) {
        for (int i = 0; i < getChildCount(); i++) {
            Sprite sprite = getChildAt(i);
            int count = canvas.save();
            canvas.rotate((i * 360) / getChildCount(), getBounds().centerX(), getBounds().centerY());
            sprite.draw(canvas);
            canvas.restoreToCount(count);
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer, im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        Rect bounds2 = clipSquare(bounds);
        int radius = (int) (((((double) bounds2.width()) * 3.141592653589793d) / 3.5999999046325684d) / ((double) getChildCount()));
        int left = bounds2.centerX() - radius;
        int right = bounds2.centerX() + radius;
        for (int i = 0; i < getChildCount(); i++) {
            Sprite sprite = getChildAt(i);
            sprite.setDrawBounds(left, bounds2.top, right, bounds2.top + (radius * 2));
        }
    }
}
