package im.uwrkaxlmjj.ui.components.crop;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PointF;
import android.graphics.RectF;
import android.os.Build;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.components.crop.CropAreaView;
import im.uwrkaxlmjj.ui.components.crop.CropGestureDetector;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CropView extends FrameLayout implements CropAreaView.AreaViewListener, CropGestureDetector.CropGestureListener {
    private static final float EPSILON = 1.0E-5f;
    private static final float MAX_SCALE = 30.0f;
    private static final int RESULT_SIDE = 1280;
    private boolean animating;
    private CropAreaView areaView;
    private View backView;
    private Bitmap bitmap;
    private float bottomPadding;
    private CropGestureDetector detector;
    private boolean freeform;
    private boolean hasAspectRatioDialog;
    private ImageView imageView;
    private RectF initialAreaRect;
    private CropViewListener listener;
    private Matrix presentationMatrix;
    private RectF previousAreaRect;
    private float rotationStartScale;
    private CropState state;
    private Matrix tempMatrix;
    private CropRectangle tempRect;

    public interface CropViewListener {
        void onAspectLock(boolean z);

        void onChange(boolean z);
    }

    private class CropState {
        private float baseRotation;
        private float height;
        private Matrix matrix;
        private float minimumScale;
        private float orientation;
        private float rotation;
        private float scale;
        private float width;
        private float x;
        private float y;

        private CropState(Bitmap bitmap, int bRotation) {
            this.width = bitmap.getWidth();
            this.height = bitmap.getHeight();
            this.x = 0.0f;
            this.y = 0.0f;
            this.scale = 1.0f;
            this.baseRotation = bRotation;
            this.rotation = 0.0f;
            this.matrix = new Matrix();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void updateBitmap(Bitmap bitmap, int rotation) {
            float ps = this.width / bitmap.getWidth();
            this.scale *= ps;
            this.width = bitmap.getWidth();
            this.height = bitmap.getHeight();
            updateMinimumScale();
            float[] values = new float[9];
            this.matrix.getValues(values);
            this.matrix.reset();
            Matrix matrix = this.matrix;
            float f = this.scale;
            matrix.postScale(f, f);
            this.matrix.postTranslate(values[2], values[5]);
            CropView.this.updateMatrix();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean hasChanges() {
            return Math.abs(this.x) > CropView.EPSILON || Math.abs(this.y) > CropView.EPSILON || Math.abs(this.scale - this.minimumScale) > CropView.EPSILON || Math.abs(this.rotation) > CropView.EPSILON || Math.abs(this.orientation) > CropView.EPSILON;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getWidth() {
            return this.width;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getHeight() {
            return this.height;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getOrientedWidth() {
            return (this.orientation + this.baseRotation) % 180.0f != 0.0f ? this.height : this.width;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getOrientedHeight() {
            return (this.orientation + this.baseRotation) % 180.0f != 0.0f ? this.width : this.height;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void translate(float x, float y) {
            this.x += x;
            this.y += y;
            this.matrix.postTranslate(x, y);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getX() {
            return this.x;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getY() {
            return this.y;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void scale(float s, float pivotX, float pivotY) {
            this.scale *= s;
            this.matrix.postScale(s, s, pivotX, pivotY);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getScale() {
            return this.scale;
        }

        private float getMinimumScale() {
            return this.minimumScale;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void rotate(float angle, float pivotX, float pivotY) {
            this.rotation += angle;
            this.matrix.postRotate(angle, pivotX, pivotY);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getRotation() {
            return this.rotation;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getOrientation() {
            return this.orientation + this.baseRotation;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public float getBaseRotation() {
            return this.baseRotation;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void reset(CropAreaView areaView, float orient, boolean freeform) {
            this.matrix.reset();
            this.x = 0.0f;
            this.y = 0.0f;
            this.rotation = 0.0f;
            this.orientation = orient;
            updateMinimumScale();
            float f = this.minimumScale;
            this.scale = f;
            this.matrix.postScale(f, f);
        }

        private void updateMinimumScale() {
            float w = (this.orientation + this.baseRotation) % 180.0f != 0.0f ? this.height : this.width;
            float h = (this.orientation + this.baseRotation) % 180.0f != 0.0f ? this.width : this.height;
            if (CropView.this.freeform) {
                this.minimumScale = CropView.this.areaView.getCropWidth() / w;
                return;
            }
            float wScale = CropView.this.areaView.getCropWidth() / w;
            float hScale = CropView.this.areaView.getCropHeight() / h;
            this.minimumScale = Math.max(wScale, hScale);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void getConcatMatrix(Matrix toMatrix) {
            toMatrix.postConcat(this.matrix);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public Matrix getMatrix() {
            Matrix m = new Matrix();
            m.set(this.matrix);
            return m;
        }
    }

    public CropView(Context context) {
        super(context);
        this.previousAreaRect = new RectF();
        this.initialAreaRect = new RectF();
        this.presentationMatrix = new Matrix();
        this.tempRect = new CropRectangle();
        this.tempMatrix = new Matrix();
        this.animating = false;
        View view = new View(context);
        this.backView = view;
        view.setBackgroundColor(-16777216);
        this.backView.setVisibility(4);
        addView(this.backView);
        ImageView imageView = new ImageView(context);
        this.imageView = imageView;
        imageView.setDrawingCacheEnabled(true);
        this.imageView.setScaleType(ImageView.ScaleType.MATRIX);
        addView(this.imageView);
        CropGestureDetector cropGestureDetector = new CropGestureDetector(context);
        this.detector = cropGestureDetector;
        cropGestureDetector.setOnGestureListener(this);
        CropAreaView cropAreaView = new CropAreaView(context);
        this.areaView = cropAreaView;
        cropAreaView.setListener(this);
        addView(this.areaView);
    }

    public CropView(Context context, boolean isFcCrop) {
        super(context);
        this.previousAreaRect = new RectF();
        this.initialAreaRect = new RectF();
        this.presentationMatrix = new Matrix();
        this.tempRect = new CropRectangle();
        this.tempMatrix = new Matrix();
        this.animating = false;
        View view = new View(context);
        this.backView = view;
        view.setBackgroundColor(-16777216);
        this.backView.setVisibility(4);
        addView(this.backView);
        ImageView imageView = new ImageView(context);
        this.imageView = imageView;
        imageView.setDrawingCacheEnabled(true);
        this.imageView.setScaleType(ImageView.ScaleType.MATRIX);
        addView(this.imageView);
        CropGestureDetector cropGestureDetector = new CropGestureDetector(context);
        this.detector = cropGestureDetector;
        cropGestureDetector.setOnGestureListener(this);
        if (isFcCrop) {
            this.areaView = new CropAreaView(context, true);
        } else {
            this.areaView = new CropAreaView(context);
        }
        this.areaView.setListener(this);
        addView(this.areaView);
    }

    public boolean isReady() {
        return (this.detector.isScaling() || this.detector.isDragging() || this.areaView.isDragging()) ? false : true;
    }

    public void setListener(CropViewListener l) {
        this.listener = l;
    }

    public void setBottomPadding(float value) {
        this.bottomPadding = value;
        this.areaView.setBottomPadding(value);
    }

    public void setAspectRatio(float ratio) {
        this.areaView.setActualRect(ratio);
    }

    public void setBitmap(Bitmap b, int rotation, boolean fform, boolean same) {
        this.freeform = fform;
        if (b == null) {
            this.bitmap = null;
            this.state = null;
            this.imageView.setImageDrawable(null);
            return;
        }
        this.bitmap = b;
        CropState cropState = this.state;
        if (cropState != null && same) {
            cropState.updateBitmap(b, rotation);
        } else {
            this.state = new CropState(this.bitmap, rotation);
            this.imageView.getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.components.crop.CropView.1
                @Override // android.view.ViewTreeObserver.OnPreDrawListener
                public boolean onPreDraw() {
                    CropView.this.reset();
                    CropView.this.imageView.getViewTreeObserver().removeOnPreDrawListener(this);
                    return false;
                }
            });
        }
        this.imageView.setImageBitmap(this.bitmap);
    }

    public void willShow() {
        this.areaView.setFrameVisibility(true);
        this.areaView.setDimVisibility(true);
        this.areaView.invalidate();
    }

    public void hideBackView() {
        this.backView.setVisibility(4);
    }

    public void showBackView() {
        this.backView.setVisibility(0);
    }

    public void setFreeform(boolean fform) {
        this.areaView.setFreeform(fform);
        this.freeform = fform;
    }

    public void show() {
        this.backView.setVisibility(0);
        this.imageView.setVisibility(0);
        this.areaView.setDimVisibility(true);
        this.areaView.setFrameVisibility(true);
        this.areaView.invalidate();
    }

    public void hide() {
        this.backView.setVisibility(4);
        this.imageView.setVisibility(4);
        this.areaView.setDimVisibility(false);
        this.areaView.setFrameVisibility(false);
        this.areaView.invalidate();
    }

    public void reset() {
        this.areaView.resetAnimator();
        this.areaView.setBitmap(this.bitmap, this.state.getBaseRotation() % 180.0f != 0.0f, this.freeform);
        this.areaView.setLockedAspectRatio(this.freeform ? 0.0f : 1.0f);
        this.state.reset(this.areaView, 0.0f, this.freeform);
        this.areaView.getCropRect(this.initialAreaRect);
        updateMatrix();
        resetRotationStartScale();
        CropViewListener cropViewListener = this.listener;
        if (cropViewListener != null) {
            cropViewListener.onChange(true);
            this.listener.onAspectLock(false);
        }
    }

    public void updateMatrix() {
        this.presentationMatrix.reset();
        this.presentationMatrix.postTranslate((-this.state.getWidth()) / 2.0f, (-this.state.getHeight()) / 2.0f);
        this.presentationMatrix.postRotate(this.state.getOrientation());
        this.state.getConcatMatrix(this.presentationMatrix);
        this.presentationMatrix.postTranslate(this.areaView.getCropCenterX(), this.areaView.getCropCenterY());
        this.imageView.setImageMatrix(this.presentationMatrix);
    }

    private void fillAreaView(RectF targetRect, boolean allowZoomOut) {
        float scale;
        boolean ensureFit;
        final float[] currentScale = {1.0f};
        float scale2 = Math.max(targetRect.width() / this.areaView.getCropWidth(), targetRect.height() / this.areaView.getCropHeight());
        float newScale = this.state.getScale() * scale2;
        if (newScale > 30.0f) {
            scale = 30.0f / this.state.getScale();
            ensureFit = true;
        } else {
            scale = scale2;
            ensureFit = false;
        }
        float statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
        final float x = ((targetRect.centerX() - (this.imageView.getWidth() / 2)) / this.areaView.getCropWidth()) * this.state.getOrientedWidth();
        final float y = ((targetRect.centerY() - (((this.imageView.getHeight() - this.bottomPadding) + statusBarHeight) / 2.0f)) / this.areaView.getCropHeight()) * this.state.getOrientedHeight();
        final float targetScale = scale;
        final boolean animEnsureFit = ensureFit;
        ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.components.crop.-$$Lambda$CropView$pHZKmWeYKDqsy-p5e5NRC6QQOOw
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                this.f$0.lambda$fillAreaView$0$CropView(targetScale, currentScale, x, y, valueAnimator);
            }
        });
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.crop.CropView.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animEnsureFit) {
                    CropView.this.fitContentInBounds(false, false, true);
                }
            }
        });
        this.areaView.fill(targetRect, animator, true);
        this.initialAreaRect.set(targetRect);
    }

    public /* synthetic */ void lambda$fillAreaView$0$CropView(float targetScale, float[] currentScale, float x, float y, ValueAnimator animation) {
        float value = ((Float) animation.getAnimatedValue()).floatValue();
        float deltaScale = (((targetScale - 1.0f) * value) + 1.0f) / currentScale[0];
        currentScale[0] = currentScale[0] * deltaScale;
        this.state.scale(deltaScale, x, y);
        updateMatrix();
    }

    private float fitScale(RectF contentRect, float scale, float ratio) {
        float scaledW = contentRect.width() * ratio;
        float scaledH = contentRect.height() * ratio;
        float scaledX = (contentRect.width() - scaledW) / 2.0f;
        float scaledY = (contentRect.height() - scaledH) / 2.0f;
        contentRect.set(contentRect.left + scaledX, contentRect.top + scaledY, contentRect.left + scaledX + scaledW, contentRect.top + scaledY + scaledH);
        return scale * ratio;
    }

    private void fitTranslation(RectF contentRect, RectF boundsRect, PointF translation, float radians) {
        float frameLeft = boundsRect.left;
        float frameTop = boundsRect.top;
        float frameRight = boundsRect.right;
        float frameBottom = boundsRect.bottom;
        if (contentRect.left > frameLeft) {
            frameRight += contentRect.left - frameLeft;
            frameLeft = contentRect.left;
        }
        if (contentRect.top > frameTop) {
            frameBottom += contentRect.top - frameTop;
            frameTop = contentRect.top;
        }
        if (contentRect.right < frameRight) {
            frameLeft += contentRect.right - frameRight;
        }
        if (contentRect.bottom < frameBottom) {
            frameTop += contentRect.bottom - frameBottom;
        }
        float deltaX = boundsRect.centerX() - ((boundsRect.width() / 2.0f) + frameLeft);
        float deltaY = boundsRect.centerY() - ((boundsRect.height() / 2.0f) + frameTop);
        float xCompX = (float) (Math.sin(1.5707963267948966d - ((double) radians)) * ((double) deltaX));
        float xCompY = (float) (Math.cos(1.5707963267948966d - ((double) radians)) * ((double) deltaX));
        float yCompX = (float) (Math.cos(((double) radians) + 1.5707963267948966d) * ((double) deltaY));
        float yCompY = (float) (Math.sin(((double) radians) + 1.5707963267948966d) * ((double) deltaY));
        translation.set(translation.x + xCompX + yCompX, translation.y + xCompY + yCompY);
    }

    public RectF calculateBoundingBox(float w, float h, float rotation) {
        RectF result = new RectF(0.0f, 0.0f, w, h);
        Matrix m = new Matrix();
        m.postRotate(rotation, w / 2.0f, h / 2.0f);
        m.mapRect(result);
        return result;
    }

    public float scaleWidthToMaxSize(RectF sizeRect, RectF maxSizeRect) {
        float w = maxSizeRect.width();
        float h = (float) Math.floor((sizeRect.height() * w) / sizeRect.width());
        if (h > maxSizeRect.height()) {
            float h2 = maxSizeRect.height();
            return (float) Math.floor((sizeRect.width() * h2) / sizeRect.height());
        }
        return w;
    }

    private class CropRectangle {
        float[] coords = new float[8];

        CropRectangle() {
        }

        void setRect(RectF rect) {
            this.coords[0] = rect.left;
            this.coords[1] = rect.top;
            this.coords[2] = rect.right;
            this.coords[3] = rect.top;
            this.coords[4] = rect.right;
            this.coords[5] = rect.bottom;
            this.coords[6] = rect.left;
            this.coords[7] = rect.bottom;
        }

        void applyMatrix(Matrix m) {
            m.mapPoints(this.coords);
        }

        void getRect(RectF rect) {
            float[] fArr = this.coords;
            rect.set(fArr[0], fArr[1], fArr[2], fArr[7]);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fitContentInBounds(boolean allowScale, boolean maximize, boolean animated) {
        fitContentInBounds(allowScale, maximize, animated, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fitContentInBounds(final boolean allowScale, final boolean maximize, final boolean animated, final boolean fast) {
        float targetScale;
        if (this.state == null) {
            return;
        }
        float boundsW = this.areaView.getCropWidth();
        float boundsH = this.areaView.getCropHeight();
        float contentW = this.state.getOrientedWidth();
        float contentH = this.state.getOrientedHeight();
        float rotation = this.state.getRotation();
        float radians = (float) Math.toRadians(rotation);
        RectF boundsRect = calculateBoundingBox(boundsW, boundsH, rotation);
        RectF contentRect = new RectF(0.0f, 0.0f, contentW, contentH);
        float initialX = (boundsW - contentW) / 2.0f;
        float initialY = (boundsH - contentH) / 2.0f;
        float scale = this.state.getScale();
        this.tempRect.setRect(contentRect);
        Matrix matrix = this.state.getMatrix();
        matrix.preTranslate(initialX / scale, initialY / scale);
        this.tempMatrix.reset();
        this.tempMatrix.setTranslate(contentRect.centerX(), contentRect.centerY());
        Matrix matrix2 = this.tempMatrix;
        matrix2.setConcat(matrix2, matrix);
        this.tempMatrix.preTranslate(-contentRect.centerX(), -contentRect.centerY());
        this.tempRect.applyMatrix(this.tempMatrix);
        this.tempMatrix.reset();
        this.tempMatrix.preRotate(-rotation, contentW / 2.0f, contentH / 2.0f);
        this.tempRect.applyMatrix(this.tempMatrix);
        this.tempRect.getRect(contentRect);
        PointF targetTranslation = new PointF(this.state.getX(), this.state.getY());
        float targetScale2 = scale;
        if (!contentRect.contains(boundsRect)) {
            if (allowScale && (boundsRect.width() > contentRect.width() || boundsRect.height() > contentRect.height())) {
                targetScale2 = fitScale(contentRect, scale, boundsRect.width() / scaleWidthToMaxSize(boundsRect, contentRect));
            }
            fitTranslation(contentRect, boundsRect, targetTranslation, radians);
            targetScale = targetScale2;
        } else if (maximize && this.rotationStartScale > 0.0f) {
            float ratio = boundsRect.width() / scaleWidthToMaxSize(boundsRect, contentRect);
            float newScale = this.state.getScale() * ratio;
            if (newScale < this.rotationStartScale) {
                ratio = 1.0f;
            }
            float targetScale3 = fitScale(contentRect, scale, ratio);
            fitTranslation(contentRect, boundsRect, targetTranslation, radians);
            targetScale = targetScale3;
        } else {
            targetScale = targetScale2;
        }
        final float dx = targetTranslation.x - this.state.getX();
        final float dy = targetTranslation.y - this.state.getY();
        if (!animated) {
            this.state.translate(dx, dy);
            this.state.scale(targetScale / scale, 0.0f, 0.0f);
            updateMatrix();
            return;
        }
        final float animScale = targetScale / scale;
        if (Math.abs(animScale - 1.0f) >= EPSILON || Math.abs(dx) >= EPSILON || Math.abs(dy) >= EPSILON) {
            this.animating = true;
            final float[] currentValues = {1.0f, 0.0f, 0.0f};
            ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
            animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.components.crop.-$$Lambda$CropView$1dVjIcW4QE2sp0D0QIRUHFrKpls
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                    this.f$0.lambda$fitContentInBounds$1$CropView(dx, currentValues, dy, animScale, valueAnimator);
                }
            });
            animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.crop.CropView.3
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    CropView.this.animating = false;
                    if (!fast) {
                        CropView.this.fitContentInBounds(allowScale, maximize, animated, true);
                    }
                }
            });
            animator.setInterpolator(this.areaView.getInterpolator());
            animator.setDuration(fast ? 100L : 200L);
            animator.start();
        }
    }

    public /* synthetic */ void lambda$fitContentInBounds$1$CropView(float animDX, float[] currentValues, float animDY, float animScale, ValueAnimator animation) {
        float value = ((Float) animation.getAnimatedValue()).floatValue();
        float deltaX = (animDX * value) - currentValues[1];
        currentValues[1] = currentValues[1] + deltaX;
        float deltaY = (animDY * value) - currentValues[2];
        currentValues[2] = currentValues[2] + deltaY;
        this.state.translate(currentValues[0] * deltaX, currentValues[0] * deltaY);
        float deltaScale = (((animScale - 1.0f) * value) + 1.0f) / currentValues[0];
        currentValues[0] = currentValues[0] * deltaScale;
        this.state.scale(deltaScale, 0.0f, 0.0f);
        updateMatrix();
    }

    public void rotate90Degrees() {
        if (this.state == null) {
            return;
        }
        this.areaView.resetAnimator();
        resetRotationStartScale();
        float orientation = ((this.state.getOrientation() - this.state.getBaseRotation()) - 90.0f) % 360.0f;
        boolean fform = this.freeform;
        if (this.freeform && this.areaView.getLockAspectRatio() > 0.0f) {
            CropAreaView cropAreaView = this.areaView;
            cropAreaView.setLockedAspectRatio(1.0f / cropAreaView.getLockAspectRatio());
            CropAreaView cropAreaView2 = this.areaView;
            cropAreaView2.setActualRect(cropAreaView2.getLockAspectRatio());
            fform = false;
        } else {
            this.areaView.setBitmap(this.bitmap, (this.state.getBaseRotation() + orientation) % 180.0f != 0.0f, this.freeform);
        }
        this.state.reset(this.areaView, orientation, fform);
        updateMatrix();
        CropViewListener cropViewListener = this.listener;
        if (cropViewListener != null) {
            cropViewListener.onChange(orientation == 0.0f && this.areaView.getLockAspectRatio() == 0.0f);
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.animating || this.areaView.onTouchEvent(event)) {
            return true;
        }
        int action = event.getAction();
        if (action == 0) {
            onScrollChangeBegan();
        } else if (action == 1 || action == 3) {
            onScrollChangeEnded();
        }
        try {
            boolean result = this.detector.onTouchEvent(event);
            return result;
        } catch (Exception e) {
            return false;
        }
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.components.crop.CropAreaView.AreaViewListener
    public void onAreaChangeBegan() {
        this.areaView.getCropRect(this.previousAreaRect);
        resetRotationStartScale();
        CropViewListener cropViewListener = this.listener;
        if (cropViewListener != null) {
            cropViewListener.onChange(false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.crop.CropAreaView.AreaViewListener
    public void onAreaChange() {
        this.areaView.setGridType(CropAreaView.GridType.MAJOR, false);
        float x = this.previousAreaRect.centerX() - this.areaView.getCropCenterX();
        float y = this.previousAreaRect.centerY() - this.areaView.getCropCenterY();
        this.state.translate(x, y);
        updateMatrix();
        this.areaView.getCropRect(this.previousAreaRect);
        fitContentInBounds(true, false, false);
    }

    @Override // im.uwrkaxlmjj.ui.components.crop.CropAreaView.AreaViewListener
    public void onAreaChangeEnded() {
        this.areaView.setGridType(CropAreaView.GridType.NONE, true);
        fillAreaView(this.areaView.getTargetRectToFill(), false);
    }

    @Override // im.uwrkaxlmjj.ui.components.crop.CropGestureDetector.CropGestureListener
    public void onDrag(float dx, float dy) {
        if (!this.animating) {
            this.state.translate(dx, dy);
            updateMatrix();
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.crop.CropGestureDetector.CropGestureListener
    public void onFling(float startX, float startY, float velocityX, float velocityY) {
    }

    public void onScrollChangeBegan() {
        if (this.animating) {
            return;
        }
        this.areaView.setGridType(CropAreaView.GridType.MAJOR, true);
        resetRotationStartScale();
        CropViewListener cropViewListener = this.listener;
        if (cropViewListener != null) {
            cropViewListener.onChange(false);
        }
    }

    public void onScrollChangeEnded() {
        this.areaView.setGridType(CropAreaView.GridType.NONE, true);
        fitContentInBounds(true, false, true);
    }

    @Override // im.uwrkaxlmjj.ui.components.crop.CropGestureDetector.CropGestureListener
    public void onScale(float scale, float x, float y) {
        if (!this.animating) {
            float newScale = this.state.getScale() * scale;
            if (newScale > 30.0f) {
                scale = 30.0f / this.state.getScale();
            }
            float statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
            float pivotX = ((x - (this.imageView.getWidth() / 2)) / this.areaView.getCropWidth()) * this.state.getOrientedWidth();
            float pivotY = ((y - (((this.imageView.getHeight() - this.bottomPadding) - statusBarHeight) / 2.0f)) / this.areaView.getCropHeight()) * this.state.getOrientedHeight();
            this.state.scale(scale, pivotX, pivotY);
            updateMatrix();
        }
    }

    public void onRotationBegan() {
        this.areaView.setGridType(CropAreaView.GridType.MINOR, false);
        if (this.rotationStartScale < EPSILON) {
            this.rotationStartScale = this.state.getScale();
        }
    }

    public void onRotationEnded() {
        this.areaView.setGridType(CropAreaView.GridType.NONE, true);
    }

    private void resetRotationStartScale() {
        this.rotationStartScale = 0.0f;
    }

    @Override // android.view.View
    public void setRotation(float angle) {
        float deltaAngle = angle - this.state.getRotation();
        this.state.rotate(deltaAngle, 0.0f, 0.0f);
        fitContentInBounds(true, true, false);
    }

    public Bitmap getResult() {
        CropState cropState = this.state;
        if (cropState == null || (!cropState.hasChanges() && this.state.getBaseRotation() < EPSILON && this.freeform)) {
            return this.bitmap;
        }
        RectF cropRect = new RectF();
        this.areaView.getCropRect(cropRect);
        RectF sizeRect = new RectF(0.0f, 0.0f, 1280.0f, 1280.0f);
        float w = scaleWidthToMaxSize(cropRect, sizeRect);
        int width = (int) Math.ceil(w);
        int height = (int) Math.ceil(width / this.areaView.getAspectRatio());
        Bitmap resultBitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Matrix matrix = new Matrix();
        matrix.postTranslate((-this.state.getWidth()) / 2.0f, (-this.state.getHeight()) / 2.0f);
        matrix.postRotate(this.state.getOrientation());
        this.state.getConcatMatrix(matrix);
        float scale = width / this.areaView.getCropWidth();
        matrix.postScale(scale, scale);
        matrix.postTranslate(width / 2, height / 2);
        new Canvas(resultBitmap).drawBitmap(this.bitmap, matrix, new Paint(2));
        return resultBitmap;
    }

    private void setLockedAspectRatio(float aspectRatio) {
        this.areaView.setLockedAspectRatio(aspectRatio);
        RectF targetRect = new RectF();
        this.areaView.calculateRect(targetRect, aspectRatio);
        fillAreaView(targetRect, true);
        CropViewListener cropViewListener = this.listener;
        if (cropViewListener != null) {
            cropViewListener.onChange(false);
            this.listener.onAspectLock(true);
        }
    }

    public void showAspectRatioDialog() {
        if (this.areaView.getLockAspectRatio() > 0.0f) {
            this.areaView.setLockedAspectRatio(0.0f);
            CropViewListener cropViewListener = this.listener;
            if (cropViewListener != null) {
                cropViewListener.onAspectLock(false);
                return;
            }
            return;
        }
        if (this.hasAspectRatioDialog) {
            return;
        }
        this.hasAspectRatioDialog = true;
        String[] actions = new String[8];
        final Integer[][] ratios = {new Integer[]{3, 2}, new Integer[]{5, 3}, new Integer[]{4, 3}, new Integer[]{5, 4}, new Integer[]{7, 5}, new Integer[]{16, 9}};
        actions[0] = LocaleController.getString("CropOriginal", R.string.CropOriginal);
        actions[1] = LocaleController.getString("CropSquare", R.string.CropSquare);
        int i = 2;
        for (Integer[] ratioPair : ratios) {
            if (this.areaView.getAspectRatio() > 1.0f) {
                actions[i] = String.format("%d:%d", ratioPair[0], ratioPair[1]);
            } else {
                actions[i] = String.format("%d:%d", ratioPair[1], ratioPair[0]);
            }
            i++;
        }
        AlertDialog dialog = new AlertDialog.Builder(getContext()).setItems(actions, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.crop.-$$Lambda$CropView$ldVG7hpjpaSvCE1CCx3mryKSgd8
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i2) {
                this.f$0.lambda$showAspectRatioDialog$2$CropView(ratios, dialogInterface, i2);
            }
        }).create();
        dialog.setCanceledOnTouchOutside(true);
        dialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.components.crop.-$$Lambda$CropView$nZjszCsmW4lxiSsMj1iJkQd464M
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$showAspectRatioDialog$3$CropView(dialogInterface);
            }
        });
        dialog.show();
    }

    public /* synthetic */ void lambda$showAspectRatioDialog$2$CropView(Integer[][] ratios, DialogInterface dialog12, int which) {
        this.hasAspectRatioDialog = false;
        if (which == 0) {
            float w = this.state.getBaseRotation() % 180.0f != 0.0f ? this.state.getHeight() : this.state.getWidth();
            float h = this.state.getBaseRotation() % 180.0f != 0.0f ? this.state.getWidth() : this.state.getHeight();
            setLockedAspectRatio(w / h);
        } else {
            if (which == 1) {
                setLockedAspectRatio(1.0f);
                return;
            }
            Integer[] ratioPair = ratios[which - 2];
            if (this.areaView.getAspectRatio() <= 1.0f) {
                setLockedAspectRatio(ratioPair[1].intValue() / ratioPair[0].intValue());
            } else {
                setLockedAspectRatio(ratioPair[0].intValue() / ratioPair[1].intValue());
            }
        }
    }

    public /* synthetic */ void lambda$showAspectRatioDialog$3$CropView(DialogInterface dialog1) {
        this.hasAspectRatioDialog = false;
    }

    public void updateLayout() {
        float w = this.areaView.getCropWidth();
        CropState cropState = this.state;
        if (cropState != null) {
            this.areaView.calculateRect(this.initialAreaRect, cropState.getWidth() / this.state.getHeight());
            CropAreaView cropAreaView = this.areaView;
            cropAreaView.setActualRect(cropAreaView.getAspectRatio());
            this.areaView.getCropRect(this.previousAreaRect);
            float ratio = this.areaView.getCropWidth() / w;
            this.state.scale(ratio, 0.0f, 0.0f);
            updateMatrix();
        }
    }

    public float getCropLeft() {
        return this.areaView.getCropLeft();
    }

    public float getCropTop() {
        return this.areaView.getCropTop();
    }

    public float getCropWidth() {
        return this.areaView.getCropWidth();
    }

    public float getCropHeight() {
        return this.areaView.getCropHeight();
    }
}
