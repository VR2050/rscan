package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.os.Build;
import android.view.animation.LinearInterpolator;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.RectSprite;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.sprite.SpriteContainer;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class FoldingCube extends SpriteContainer {
    private boolean wrapContent = false;

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        Cube[] cubes = new Cube[4];
        for (int i = 0; i < cubes.length; i++) {
            cubes[i] = new Cube();
            if (Build.VERSION.SDK_INT >= 24) {
                cubes[i].setAnimationDelay(i * 300);
            } else {
                cubes[i].setAnimationDelay((i * 300) - 1200);
            }
        }
        return cubes;
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer, im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        Rect bounds2 = clipSquare(bounds);
        int size = Math.min(bounds2.width(), bounds2.height());
        if (this.wrapContent) {
            size = (int) Math.sqrt((size * size) / 2);
            int oW = (bounds2.width() - size) / 2;
            int oH = (bounds2.height() - size) / 2;
            bounds2 = new Rect(bounds2.left + oW, bounds2.top + oH, bounds2.right - oW, bounds2.bottom - oH);
        }
        int px = bounds2.left + (size / 2) + 1;
        int py = bounds2.top + (size / 2) + 1;
        for (int i = 0; i < getChildCount(); i++) {
            Sprite sprite = getChildAt(i);
            sprite.setDrawBounds(bounds2.left, bounds2.top, px, py);
            sprite.setPivotX(sprite.getDrawBounds().right);
            sprite.setPivotY(sprite.getDrawBounds().bottom);
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public void drawChild(Canvas canvas) {
        Rect bounds = clipSquare(getBounds());
        for (int i = 0; i < getChildCount(); i++) {
            int count = canvas.save();
            canvas.rotate((i * 90) + 45, bounds.centerX(), bounds.centerY());
            Sprite sprite = getChildAt(i);
            sprite.draw(canvas);
            canvas.restoreToCount(count);
        }
    }

    private class Cube extends RectSprite {
        Cube() {
            setAlpha(0);
            setRotateX(-180);
        }

        @Override // im.uwrkaxlmjj.ui.load.sprite.RectSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
        public ValueAnimator onCreateAnimation() {
            float[] fractions = {0.0f, 0.1f, 0.25f, 0.75f, 0.9f, 1.0f};
            SpriteAnimatorBuilder spriteAnimatorBuilderRotateX = new SpriteAnimatorBuilder(this).alpha(fractions, 0, 0, 255, 255, 0, 0).rotateX(fractions, -180, -180, 0, 0, 0, 0);
            Integer numValueOf = Integer.valueOf(JavaScreenCapturer.DEGREE_180);
            return spriteAnimatorBuilderRotateX.rotateY(fractions, 0, 0, 0, 0, numValueOf, numValueOf).duration(2400L).interpolator(new LinearInterpolator()).build();
        }
    }
}
