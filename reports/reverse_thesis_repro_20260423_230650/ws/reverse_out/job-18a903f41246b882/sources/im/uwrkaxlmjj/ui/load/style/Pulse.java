package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.CircleSprite;

/* JADX INFO: loaded from: classes5.dex */
public class Pulse extends CircleSprite {
    public Pulse() {
        setScale(0.0f);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.CircleSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
    public ValueAnimator onCreateAnimation() {
        float[] fractions = {0.0f, 1.0f};
        return new SpriteAnimatorBuilder(this).scale(fractions, Float.valueOf(0.0f), Float.valueOf(1.0f)).alpha(fractions, 255, 0).duration(1000L).easeInOut(fractions).build();
    }
}
