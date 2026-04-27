package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.graphics.Rect;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.RectSprite;

/* JADX INFO: loaded from: classes5.dex */
public class RotatingPlane extends RectSprite {
    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        setDrawBounds(clipSquare(bounds));
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.RectSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
    public ValueAnimator onCreateAnimation() {
        float[] fractions = {0.0f, 0.5f, 1.0f};
        return new SpriteAnimatorBuilder(this).rotateX(fractions, 0, -180, -180).rotateY(fractions, 0, 0, -180).duration(1200L).easeInOut(fractions).build();
    }
}
