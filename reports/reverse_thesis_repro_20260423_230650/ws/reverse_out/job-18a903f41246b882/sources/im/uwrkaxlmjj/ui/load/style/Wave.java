package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.graphics.Rect;
import android.os.Build;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.RectSprite;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.sprite.SpriteContainer;

/* JADX INFO: loaded from: classes5.dex */
public class Wave extends SpriteContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        WaveItem[] waveItems = new WaveItem[5];
        for (int i = 0; i < waveItems.length; i++) {
            waveItems[i] = new WaveItem();
            if (Build.VERSION.SDK_INT >= 24) {
                waveItems[i].setAnimationDelay((i * 100) + 600);
            } else {
                waveItems[i].setAnimationDelay((i * 100) - 1200);
            }
        }
        return waveItems;
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer, im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        Rect bounds2 = clipSquare(bounds);
        int rw = bounds2.width() / getChildCount();
        int width = ((bounds2.width() / 5) * 3) / 5;
        for (int i = 0; i < getChildCount(); i++) {
            Sprite sprite = getChildAt(i);
            int l = bounds2.left + (i * rw) + (rw / 5);
            int r = l + width;
            sprite.setDrawBounds(l, bounds2.top, r, bounds2.bottom);
        }
    }

    private class WaveItem extends RectSprite {
        WaveItem() {
            setScaleY(0.4f);
        }

        @Override // im.uwrkaxlmjj.ui.load.sprite.RectSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
        public ValueAnimator onCreateAnimation() {
            float[] fractions = {0.0f, 0.2f, 0.4f, 1.0f};
            SpriteAnimatorBuilder spriteAnimatorBuilder = new SpriteAnimatorBuilder(this);
            Float fValueOf = Float.valueOf(0.4f);
            return spriteAnimatorBuilder.scaleY(fractions, fValueOf, Float.valueOf(1.0f), fValueOf, fValueOf).duration(1200L).easeInOut(fractions).build();
        }
    }
}
