package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.animation.interpolator.KeyFrameInterpolator;
import im.uwrkaxlmjj.ui.load.sprite.RingSprite;

/* JADX INFO: loaded from: classes5.dex */
public class PulseRing extends RingSprite {
    public PulseRing() {
        setScale(0.0f);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.RingSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
    public ValueAnimator onCreateAnimation() {
        float[] fractions = {0.0f, 0.7f, 1.0f};
        SpriteAnimatorBuilder spriteAnimatorBuilder = new SpriteAnimatorBuilder(this);
        Float fValueOf = Float.valueOf(1.0f);
        return spriteAnimatorBuilder.scale(fractions, Float.valueOf(0.0f), fValueOf, fValueOf).alpha(fractions, 255, 178, 0).duration(1000L).interpolator(KeyFrameInterpolator.pathInterpolator(0.21f, 0.53f, 0.56f, 0.8f, fractions)).build();
    }
}
