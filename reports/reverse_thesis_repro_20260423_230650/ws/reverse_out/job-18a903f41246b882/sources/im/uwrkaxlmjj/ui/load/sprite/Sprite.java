package im.uwrkaxlmjj.ui.load.sprite;

import android.animation.ValueAnimator;
import android.graphics.Camera;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.util.Property;
import im.uwrkaxlmjj.ui.load.animation.AnimationUtils;
import im.uwrkaxlmjj.ui.load.animation.FloatProperty;
import im.uwrkaxlmjj.ui.load.animation.IntProperty;

/* JADX INFO: loaded from: classes5.dex */
public abstract class Sprite extends Drawable implements ValueAnimator.AnimatorUpdateListener, Animatable, Drawable.Callback {
    private int animationDelay;
    private ValueAnimator animator;
    private float pivotX;
    private float pivotY;
    private int rotate;
    private int rotateX;
    private int rotateY;
    private int translateX;
    private float translateXPercentage;
    private int translateY;
    private float translateYPercentage;
    private static final Rect ZERO_BOUNDS_RECT = new Rect();
    public static final Property<Sprite, Integer> ROTATE_X = new IntProperty<Sprite>("rotateX") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.1
        @Override // im.uwrkaxlmjj.ui.load.animation.IntProperty
        public void setValue(Sprite object, int value) {
            object.setRotateX(value);
        }

        @Override // android.util.Property
        public Integer get(Sprite object) {
            return Integer.valueOf(object.getRotateX());
        }
    };
    public static final Property<Sprite, Integer> ROTATE = new IntProperty<Sprite>("rotate") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.2
        @Override // im.uwrkaxlmjj.ui.load.animation.IntProperty
        public void setValue(Sprite object, int value) {
            object.setRotate(value);
        }

        @Override // android.util.Property
        public Integer get(Sprite object) {
            return Integer.valueOf(object.getRotate());
        }
    };
    public static final Property<Sprite, Integer> ROTATE_Y = new IntProperty<Sprite>("rotateY") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.3
        @Override // im.uwrkaxlmjj.ui.load.animation.IntProperty
        public void setValue(Sprite object, int value) {
            object.setRotateY(value);
        }

        @Override // android.util.Property
        public Integer get(Sprite object) {
            return Integer.valueOf(object.getRotateY());
        }
    };
    public static final Property<Sprite, Integer> TRANSLATE_X = new IntProperty<Sprite>("translateX") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.4
        @Override // im.uwrkaxlmjj.ui.load.animation.IntProperty
        public void setValue(Sprite object, int value) {
            object.setTranslateX(value);
        }

        @Override // android.util.Property
        public Integer get(Sprite object) {
            return Integer.valueOf(object.getTranslateX());
        }
    };
    public static final Property<Sprite, Integer> TRANSLATE_Y = new IntProperty<Sprite>("translateY") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.5
        @Override // im.uwrkaxlmjj.ui.load.animation.IntProperty
        public void setValue(Sprite object, int value) {
            object.setTranslateY(value);
        }

        @Override // android.util.Property
        public Integer get(Sprite object) {
            return Integer.valueOf(object.getTranslateY());
        }
    };
    public static final Property<Sprite, Float> TRANSLATE_X_PERCENTAGE = new FloatProperty<Sprite>("translateXPercentage") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.6
        @Override // im.uwrkaxlmjj.ui.load.animation.FloatProperty
        public void setValue(Sprite object, float value) {
            object.setTranslateXPercentage(value);
        }

        @Override // android.util.Property
        public Float get(Sprite object) {
            return Float.valueOf(object.getTranslateXPercentage());
        }
    };
    public static final Property<Sprite, Float> TRANSLATE_Y_PERCENTAGE = new FloatProperty<Sprite>("translateYPercentage") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.7
        @Override // im.uwrkaxlmjj.ui.load.animation.FloatProperty
        public void setValue(Sprite object, float value) {
            object.setTranslateYPercentage(value);
        }

        @Override // android.util.Property
        public Float get(Sprite object) {
            return Float.valueOf(object.getTranslateYPercentage());
        }
    };
    public static final Property<Sprite, Float> SCALE_X = new FloatProperty<Sprite>("scaleX") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.8
        @Override // im.uwrkaxlmjj.ui.load.animation.FloatProperty
        public void setValue(Sprite object, float value) {
            object.setScaleX(value);
        }

        @Override // android.util.Property
        public Float get(Sprite object) {
            return Float.valueOf(object.getScaleX());
        }
    };
    public static final Property<Sprite, Float> SCALE_Y = new FloatProperty<Sprite>("scaleY") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.9
        @Override // im.uwrkaxlmjj.ui.load.animation.FloatProperty
        public void setValue(Sprite object, float value) {
            object.setScaleY(value);
        }

        @Override // android.util.Property
        public Float get(Sprite object) {
            return Float.valueOf(object.getScaleY());
        }
    };
    public static final Property<Sprite, Float> SCALE = new FloatProperty<Sprite>("scale") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.10
        @Override // im.uwrkaxlmjj.ui.load.animation.FloatProperty
        public void setValue(Sprite object, float value) {
            object.setScale(value);
        }

        @Override // android.util.Property
        public Float get(Sprite object) {
            return Float.valueOf(object.getScale());
        }
    };
    public static final Property<Sprite, Integer> ALPHA = new IntProperty<Sprite>("alpha") { // from class: im.uwrkaxlmjj.ui.load.sprite.Sprite.11
        @Override // im.uwrkaxlmjj.ui.load.animation.IntProperty
        public void setValue(Sprite object, int value) {
            object.setAlpha(value);
        }

        @Override // android.util.Property
        public Integer get(Sprite object) {
            return Integer.valueOf(object.getAlpha());
        }
    };
    private float scale = 1.0f;
    private float scaleX = 1.0f;
    private float scaleY = 1.0f;
    private int alpha = 255;
    protected Rect drawBounds = ZERO_BOUNDS_RECT;
    private Camera mCamera = new Camera();
    private Matrix mMatrix = new Matrix();

    protected abstract void drawSelf(Canvas canvas);

    public abstract int getColor();

    public abstract ValueAnimator onCreateAnimation();

    public abstract void setColor(int i);

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int alpha) {
        this.alpha = alpha;
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.alpha;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    public float getTranslateXPercentage() {
        return this.translateXPercentage;
    }

    public void setTranslateXPercentage(float translateXPercentage) {
        this.translateXPercentage = translateXPercentage;
    }

    public float getTranslateYPercentage() {
        return this.translateYPercentage;
    }

    public void setTranslateYPercentage(float translateYPercentage) {
        this.translateYPercentage = translateYPercentage;
    }

    public int getTranslateX() {
        return this.translateX;
    }

    public void setTranslateX(int translateX) {
        this.translateX = translateX;
    }

    public int getTranslateY() {
        return this.translateY;
    }

    public void setTranslateY(int translateY) {
        this.translateY = translateY;
    }

    public int getRotate() {
        return this.rotate;
    }

    public void setRotate(int rotate) {
        this.rotate = rotate;
    }

    public float getScale() {
        return this.scale;
    }

    public void setScale(float scale) {
        this.scale = scale;
        setScaleX(scale);
        setScaleY(scale);
    }

    public float getScaleX() {
        return this.scaleX;
    }

    public void setScaleX(float scaleX) {
        this.scaleX = scaleX;
    }

    public float getScaleY() {
        return this.scaleY;
    }

    public void setScaleY(float scaleY) {
        this.scaleY = scaleY;
    }

    public int getRotateX() {
        return this.rotateX;
    }

    public void setRotateX(int rotateX) {
        this.rotateX = rotateX;
    }

    public int getRotateY() {
        return this.rotateY;
    }

    public void setRotateY(int rotateY) {
        this.rotateY = rotateY;
    }

    public float getPivotX() {
        return this.pivotX;
    }

    public void setPivotX(float pivotX) {
        this.pivotX = pivotX;
    }

    public float getPivotY() {
        return this.pivotY;
    }

    public void setPivotY(float pivotY) {
        this.pivotY = pivotY;
    }

    public int getAnimationDelay() {
        return this.animationDelay;
    }

    public Sprite setAnimationDelay(int animationDelay) {
        this.animationDelay = animationDelay;
        return this;
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        if (AnimationUtils.isStarted(this.animator)) {
            return;
        }
        ValueAnimator valueAnimatorObtainAnimation = obtainAnimation();
        this.animator = valueAnimatorObtainAnimation;
        if (valueAnimatorObtainAnimation == null) {
            return;
        }
        AnimationUtils.start(valueAnimatorObtainAnimation);
        invalidateSelf();
    }

    public ValueAnimator obtainAnimation() {
        if (this.animator == null) {
            this.animator = onCreateAnimation();
        }
        ValueAnimator valueAnimator = this.animator;
        if (valueAnimator != null) {
            valueAnimator.addUpdateListener(this);
            this.animator.setStartDelay(this.animationDelay);
        }
        return this.animator;
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        if (AnimationUtils.isStarted(this.animator)) {
            this.animator.removeAllUpdateListeners();
            this.animator.end();
            reset();
        }
    }

    public void reset() {
        this.scale = 1.0f;
        this.rotateX = 0;
        this.rotateY = 0;
        this.translateX = 0;
        this.translateY = 0;
        this.rotate = 0;
        this.translateXPercentage = 0.0f;
        this.translateYPercentage = 0.0f;
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return AnimationUtils.isRunning(this.animator);
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        setDrawBounds(bounds);
    }

    public void setDrawBounds(Rect drawBounds) {
        setDrawBounds(drawBounds.left, drawBounds.top, drawBounds.right, drawBounds.bottom);
    }

    public void setDrawBounds(int left, int top, int right, int bottom) {
        this.drawBounds = new Rect(left, top, right, bottom);
        setPivotX(getDrawBounds().centerX());
        setPivotY(getDrawBounds().centerY());
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable who) {
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void scheduleDrawable(Drawable who, Runnable what, long when) {
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void unscheduleDrawable(Drawable who, Runnable what) {
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator animation) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.invalidateDrawable(this);
        }
    }

    public Rect getDrawBounds() {
        return this.drawBounds;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        int tx = getTranslateX();
        int tx2 = tx == 0 ? (int) (getBounds().width() * getTranslateXPercentage()) : tx;
        int ty = getTranslateY();
        canvas.translate(tx2, ty == 0 ? (int) (getBounds().height() * getTranslateYPercentage()) : ty);
        canvas.scale(getScaleX(), getScaleY(), getPivotX(), getPivotY());
        canvas.rotate(getRotate(), getPivotX(), getPivotY());
        if (getRotateX() != 0 || getRotateY() != 0) {
            this.mCamera.save();
            this.mCamera.rotateX(getRotateX());
            this.mCamera.rotateY(getRotateY());
            this.mCamera.getMatrix(this.mMatrix);
            this.mMatrix.preTranslate(-getPivotX(), -getPivotY());
            this.mMatrix.postTranslate(getPivotX(), getPivotY());
            this.mCamera.restore();
            canvas.concat(this.mMatrix);
        }
        drawSelf(canvas);
    }

    public Rect clipSquare(Rect rect) {
        int w = rect.width();
        int h = rect.height();
        int min = Math.min(w, h);
        int cx = rect.centerX();
        int cy = rect.centerY();
        int r = min / 2;
        return new Rect(cx - r, cy - r, cx + r, cy + r);
    }
}
