package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.graphics.Rect;
import android.os.Build;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.RectSprite;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.sprite.SpriteContainer;

/* JADX INFO: loaded from: classes5.dex */
public class WanderingCubes extends SpriteContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        return new Sprite[]{new Cube(0), new Cube(3)};
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public void onChildCreated(Sprite... sprites) {
        super.onChildCreated(sprites);
        if (Build.VERSION.SDK_INT < 24) {
            sprites[1].setAnimationDelay(-900);
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer, im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        Rect bounds2 = clipSquare(bounds);
        super.onBoundsChange(bounds2);
        for (int i = 0; i < getChildCount(); i++) {
            Sprite sprite = getChildAt(i);
            sprite.setDrawBounds(bounds2.left, bounds2.top, bounds2.left + (bounds2.width() / 4), bounds2.top + (bounds2.height() / 4));
        }
    }

    private class Cube extends RectSprite {
        int startFrame;

        public Cube(int startFrame) {
            this.startFrame = startFrame;
        }

        @Override // im.uwrkaxlmjj.ui.load.sprite.RectSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
        public ValueAnimator onCreateAnimation() {
            float[] fractions = {0.0f, 0.25f, 0.5f, 0.51f, 0.75f, 1.0f};
            SpriteAnimatorBuilder spriteAnimatorBuilderRotate = new SpriteAnimatorBuilder(this).rotate(fractions, 0, -90, -179, -180, -270, -360);
            Float fValueOf = Float.valueOf(0.0f);
            Float fValueOf2 = Float.valueOf(0.75f);
            SpriteAnimatorBuilder spriteAnimatorBuilderTranslateYPercentage = spriteAnimatorBuilderRotate.translateXPercentage(fractions, fValueOf, fValueOf2, fValueOf2, fValueOf2, fValueOf, fValueOf).translateYPercentage(fractions, fValueOf, fValueOf, fValueOf2, fValueOf2, fValueOf2, fValueOf);
            Float fValueOf3 = Float.valueOf(1.0f);
            Float fValueOf4 = Float.valueOf(0.5f);
            SpriteAnimatorBuilder builder = spriteAnimatorBuilderTranslateYPercentage.scale(fractions, fValueOf3, fValueOf4, fValueOf3, fValueOf3, fValueOf4, fValueOf3).duration(1800L).easeInOut(fractions);
            if (Build.VERSION.SDK_INT >= 24) {
                builder.startFrame(this.startFrame);
            }
            return builder.build();
        }
    }
}
