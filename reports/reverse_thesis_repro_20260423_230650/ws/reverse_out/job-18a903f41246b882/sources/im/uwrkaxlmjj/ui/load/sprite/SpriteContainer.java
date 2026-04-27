package im.uwrkaxlmjj.ui.load.sprite;

import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.Rect;
import im.uwrkaxlmjj.ui.load.animation.AnimationUtils;

/* JADX INFO: loaded from: classes5.dex */
public abstract class SpriteContainer extends Sprite {
    private int color;
    private Sprite[] sprites = onCreateChild();

    public abstract Sprite[] onCreateChild();

    public SpriteContainer() {
        initCallBack();
        onChildCreated(this.sprites);
    }

    private void initCallBack() {
        Sprite[] spriteArr = this.sprites;
        if (spriteArr != null) {
            for (Sprite sprite : spriteArr) {
                sprite.setCallback(this);
            }
        }
    }

    public void onChildCreated(Sprite... sprites) {
    }

    public int getChildCount() {
        Sprite[] spriteArr = this.sprites;
        if (spriteArr == null) {
            return 0;
        }
        return spriteArr.length;
    }

    public Sprite getChildAt(int index) {
        Sprite[] spriteArr = this.sprites;
        if (spriteArr == null) {
            return null;
        }
        return spriteArr[index];
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    public void setColor(int color) {
        this.color = color;
        for (int i = 0; i < getChildCount(); i++) {
            getChildAt(i).setColor(color);
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    public int getColor() {
        return this.color;
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        super.draw(canvas);
        drawChild(canvas);
    }

    public void drawChild(Canvas canvas) {
        Sprite[] spriteArr = this.sprites;
        if (spriteArr != null) {
            for (Sprite sprite : spriteArr) {
                int count = canvas.save();
                sprite.draw(canvas);
                canvas.restoreToCount(count);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    protected void drawSelf(Canvas canvas) {
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        for (Sprite sprite : this.sprites) {
            sprite.setBounds(bounds);
        }
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Animatable
    public void start() {
        super.start();
        AnimationUtils.start(this.sprites);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Animatable
    public void stop() {
        super.stop();
        AnimationUtils.stop(this.sprites);
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Animatable
    public boolean isRunning() {
        return AnimationUtils.isRunning(this.sprites) || super.isRunning();
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.Sprite
    public ValueAnimator onCreateAnimation() {
        return null;
    }
}
