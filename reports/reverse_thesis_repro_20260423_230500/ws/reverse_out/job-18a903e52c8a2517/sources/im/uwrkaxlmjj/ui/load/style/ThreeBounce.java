package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.graphics.Rect;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.CircleSprite;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.sprite.SpriteContainer;

/* JADX INFO: loaded from: classes5.dex */
public class ThreeBounce extends SpriteContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        return new Sprite[]{new Bounce(), new Bounce(), new Bounce()};
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public void onChildCreated(Sprite... sprites) {
        super.onChildCreated(sprites);
        sprites[1].setAnimationDelay(160);
        sprites[2].setAnimationDelay(320);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer, im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        Rect bounds2 = clipSquare(bounds);
        int radius = bounds2.width() / 8;
        int top = bounds2.centerY() - radius;
        int bottom = bounds2.centerY() + radius;
        for (int i = 0; i < getChildCount(); i++) {
            int left = ((bounds2.width() * i) / 3) + bounds2.left;
            getChildAt(i).setDrawBounds(left, top, (radius * 2) + left, bottom);
        }
    }

    private class Bounce extends CircleSprite {
        Bounce() {
            setScale(0.0f);
        }

        @Override // im.uwrkaxlmjj.ui.load.sprite.CircleSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
        public ValueAnimator onCreateAnimation() {
            float[] fractions = {0.0f, 0.4f, 0.8f, 1.0f};
            SpriteAnimatorBuilder spriteAnimatorBuilder = new SpriteAnimatorBuilder(this);
            Float fValueOf = Float.valueOf(0.0f);
            return spriteAnimatorBuilder.scale(fractions, fValueOf, Float.valueOf(1.0f), fValueOf, fValueOf).duration(1400L).easeInOut(fractions).build();
        }
    }
}
