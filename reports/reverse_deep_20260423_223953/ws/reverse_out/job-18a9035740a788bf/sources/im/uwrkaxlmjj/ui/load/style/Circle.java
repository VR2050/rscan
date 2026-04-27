package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.os.Build;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.CircleLayoutContainer;
import im.uwrkaxlmjj.ui.load.sprite.CircleSprite;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;

/* JADX INFO: loaded from: classes5.dex */
public class Circle extends CircleLayoutContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        Dot[] dots = new Dot[12];
        for (int i = 0; i < dots.length; i++) {
            dots[i] = new Dot();
            if (Build.VERSION.SDK_INT >= 24) {
                dots[i].setAnimationDelay(i * 100);
            } else {
                dots[i].setAnimationDelay((i * 100) - 1200);
            }
        }
        return dots;
    }

    private class Dot extends CircleSprite {
        Dot() {
            setScale(0.0f);
        }

        @Override // im.uwrkaxlmjj.ui.load.sprite.CircleSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
        public ValueAnimator onCreateAnimation() {
            float[] fractions = {0.0f, 0.5f, 1.0f};
            SpriteAnimatorBuilder spriteAnimatorBuilder = new SpriteAnimatorBuilder(this);
            Float fValueOf = Float.valueOf(0.0f);
            return spriteAnimatorBuilder.scale(fractions, fValueOf, Float.valueOf(1.0f), fValueOf).duration(1200L).easeInOut(fractions).build();
        }
    }
}
