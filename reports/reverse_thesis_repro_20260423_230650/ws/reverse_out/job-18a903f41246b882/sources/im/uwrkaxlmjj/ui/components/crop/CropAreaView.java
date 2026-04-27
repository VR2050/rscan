package im.uwrkaxlmjj.ui.components.crop;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.os.Build;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.Interpolator;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class CropAreaView extends View {
    private Control activeControl;
    private RectF actualRect;
    private Animator animator;
    private RectF bottomEdge;
    private RectF bottomLeftCorner;
    private float bottomPadding;
    private RectF bottomRightCorner;
    private Bitmap circleBitmap;
    Paint dimPaint;
    private boolean dimVisibile;
    private Paint eraserPaint;
    Paint framePaint;
    private boolean frameVisible;
    private boolean freeform;
    private Animator gridAnimator;
    private float gridProgress;
    private GridType gridType;
    Paint handlePaint;
    AccelerateDecelerateInterpolator interpolator;
    private boolean isDragging;
    boolean isFcCrop;
    private RectF leftEdge;
    Paint linePaint;
    private AreaViewListener listener;
    private float lockAspectRatio;
    private float minWidth;
    private GridType previousGridType;
    private int previousX;
    private int previousY;
    private RectF rightEdge;
    Paint shadowPaint;
    private float sidePadding;
    private RectF tempRect;
    private RectF topEdge;
    private RectF topLeftCorner;
    private RectF topRightCorner;

    interface AreaViewListener {
        void onAreaChange();

        void onAreaChangeBegan();

        void onAreaChangeEnded();
    }

    private enum Control {
        NONE,
        TOP_LEFT,
        TOP_RIGHT,
        BOTTOM_LEFT,
        BOTTOM_RIGHT,
        TOP,
        LEFT,
        BOTTOM,
        RIGHT
    }

    enum GridType {
        NONE,
        MINOR,
        MAJOR
    }

    public CropAreaView(Context context) {
        super(context);
        this.topLeftCorner = new RectF();
        this.topRightCorner = new RectF();
        this.bottomLeftCorner = new RectF();
        this.bottomRightCorner = new RectF();
        this.topEdge = new RectF();
        this.leftEdge = new RectF();
        this.bottomEdge = new RectF();
        this.rightEdge = new RectF();
        this.actualRect = new RectF();
        this.tempRect = new RectF();
        this.interpolator = new AccelerateDecelerateInterpolator();
        this.freeform = true;
        this.frameVisible = true;
        this.dimVisibile = true;
        this.sidePadding = AndroidUtilities.dp(16.0f);
        this.minWidth = AndroidUtilities.dp(32.0f);
        this.gridType = GridType.NONE;
        Paint paint = new Paint();
        this.dimPaint = paint;
        paint.setColor(-872415232);
        Paint paint2 = new Paint();
        this.shadowPaint = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.shadowPaint.setColor(436207616);
        this.shadowPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        Paint paint3 = new Paint();
        this.linePaint = paint3;
        paint3.setStyle(Paint.Style.FILL);
        this.linePaint.setColor(-1);
        this.linePaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        Paint paint4 = new Paint();
        this.handlePaint = paint4;
        paint4.setStyle(Paint.Style.FILL);
        this.handlePaint.setColor(-1);
        Paint paint5 = new Paint();
        this.framePaint = paint5;
        paint5.setStyle(Paint.Style.FILL);
        this.framePaint.setColor(-1291845633);
        Paint paint6 = new Paint(1);
        this.eraserPaint = paint6;
        paint6.setColor(0);
        this.eraserPaint.setStyle(Paint.Style.FILL);
        this.eraserPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
    }

    public CropAreaView(Context context, boolean isFcCrop) {
        super(context);
        this.topLeftCorner = new RectF();
        this.topRightCorner = new RectF();
        this.bottomLeftCorner = new RectF();
        this.bottomRightCorner = new RectF();
        this.topEdge = new RectF();
        this.leftEdge = new RectF();
        this.bottomEdge = new RectF();
        this.rightEdge = new RectF();
        this.actualRect = new RectF();
        this.tempRect = new RectF();
        this.interpolator = new AccelerateDecelerateInterpolator();
        this.freeform = true;
        this.isFcCrop = isFcCrop;
        this.frameVisible = true;
        this.dimVisibile = true;
        this.sidePadding = AndroidUtilities.dp(16.0f);
        this.minWidth = AndroidUtilities.dp(32.0f);
        this.gridType = GridType.NONE;
        Paint paint = new Paint();
        this.dimPaint = paint;
        paint.setColor(-872415232);
        Paint paint2 = new Paint();
        this.shadowPaint = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.shadowPaint.setColor(436207616);
        this.shadowPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        Paint paint3 = new Paint();
        this.linePaint = paint3;
        paint3.setStyle(Paint.Style.FILL);
        this.linePaint.setColor(-1);
        this.linePaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        Paint paint4 = new Paint();
        this.handlePaint = paint4;
        paint4.setStyle(Paint.Style.FILL);
        this.handlePaint.setColor(-1);
        Paint paint5 = new Paint();
        this.framePaint = paint5;
        paint5.setStyle(Paint.Style.FILL);
        this.framePaint.setColor(-1291845633);
        Paint paint6 = new Paint(1);
        this.eraserPaint = paint6;
        paint6.setColor(0);
        this.eraserPaint.setStyle(Paint.Style.FILL);
        this.eraserPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
    }

    public boolean isDragging() {
        return this.isDragging;
    }

    public void setDimVisibility(boolean visible) {
        this.dimVisibile = visible;
    }

    public void setFrameVisibility(boolean visible) {
        this.frameVisible = visible;
    }

    public void setBottomPadding(float value) {
        this.bottomPadding = value;
    }

    public Interpolator getInterpolator() {
        return this.interpolator;
    }

    public void setListener(AreaViewListener l) {
        this.listener = l;
    }

    public void setBitmap(Bitmap bitmap, boolean sideward, boolean fform) {
        float aspectRatio;
        if (bitmap == null || bitmap.isRecycled()) {
            return;
        }
        this.freeform = fform;
        if (sideward) {
            aspectRatio = bitmap.getHeight() / bitmap.getWidth();
        } else {
            aspectRatio = bitmap.getWidth() / bitmap.getHeight();
        }
        if (!this.freeform) {
            aspectRatio = 1.0f;
            this.lockAspectRatio = 1.0f;
        }
        setActualRect(aspectRatio);
    }

    public void setFreeform(boolean fform) {
        this.freeform = fform;
    }

    public void setActualRect(float aspectRatio) {
        calculateRect(this.actualRect, aspectRatio);
        updateTouchAreas();
        invalidate();
    }

    public void setActualRect(RectF rect) {
        this.actualRect.set(rect);
        updateTouchAreas();
        invalidate();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        int lineThickness;
        int handleSize;
        int height;
        int handleSize2;
        int height2;
        int lineThickness2;
        if (this.freeform) {
            int lineThickness3 = AndroidUtilities.dp(2.0f);
            int handleSize3 = AndroidUtilities.dp(16.0f);
            int handleThickness = AndroidUtilities.dp(3.0f);
            int originX = ((int) this.actualRect.left) - lineThickness3;
            int originY = ((int) this.actualRect.top) - lineThickness3;
            int width = ((int) (this.actualRect.right - this.actualRect.left)) + (lineThickness3 * 2);
            int height3 = ((int) (this.actualRect.bottom - this.actualRect.top)) + (lineThickness3 * 2);
            if (this.dimVisibile) {
                canvas.drawRect(0.0f, 0.0f, getWidth(), originY + lineThickness3, this.dimPaint);
                canvas.drawRect(0.0f, originY + lineThickness3, originX + lineThickness3, (originY + height3) - lineThickness3, this.dimPaint);
                canvas.drawRect((originX + width) - lineThickness3, originY + lineThickness3, getWidth(), (originY + height3) - lineThickness3, this.dimPaint);
                canvas.drawRect(0.0f, (originY + height3) - lineThickness3, getWidth(), getHeight(), this.dimPaint);
            }
            if (!this.frameVisible) {
                return;
            }
            int inset = handleThickness - lineThickness3;
            int gridWidth = width - (handleThickness * 2);
            int gridHeight = height3 - (handleThickness * 2);
            GridType type = this.gridType;
            if (type == GridType.NONE && this.gridProgress > 0.0f) {
                type = this.previousGridType;
            }
            this.shadowPaint.setAlpha((int) (this.gridProgress * 26.0f));
            this.linePaint.setAlpha((int) (this.gridProgress * 178.0f));
            int i = 0;
            while (true) {
                int i2 = 3;
                if (i >= 3) {
                    int lineThickness4 = lineThickness3;
                    int handleSize4 = handleSize3;
                    int height4 = height3;
                    canvas.drawRect(originX + inset, originY + inset, (originX + width) - inset, originY + inset + lineThickness4, this.framePaint);
                    canvas.drawRect(originX + inset, originY + inset, originX + inset + lineThickness4, (originY + height4) - inset, this.framePaint);
                    canvas.drawRect(originX + inset, ((originY + height4) - inset) - lineThickness4, (originX + width) - inset, (originY + height4) - inset, this.framePaint);
                    canvas.drawRect(((originX + width) - inset) - lineThickness4, originY + inset, (originX + width) - inset, (originY + height4) - inset, this.framePaint);
                    canvas.drawRect(originX, originY, originX + handleSize4, originY + handleThickness, this.handlePaint);
                    canvas.drawRect(originX, originY, originX + handleThickness, originY + handleSize4, this.handlePaint);
                    canvas.drawRect((originX + width) - handleSize4, originY, originX + width, originY + handleThickness, this.handlePaint);
                    canvas.drawRect((originX + width) - handleThickness, originY, originX + width, originY + handleSize4, this.handlePaint);
                    canvas.drawRect(originX, (originY + height4) - handleThickness, originX + handleSize4, originY + height4, this.handlePaint);
                    canvas.drawRect(originX, (originY + height4) - handleSize4, originX + handleThickness, originY + height4, this.handlePaint);
                    canvas.drawRect((originX + width) - handleSize4, (originY + height4) - handleThickness, originX + width, originY + height4, this.handlePaint);
                    canvas.drawRect((originX + width) - handleThickness, (originY + height4) - handleSize4, originX + width, originY + height4, this.handlePaint);
                    return;
                }
                if (type == GridType.MINOR) {
                    int j = 1;
                    while (j < 4) {
                        if (i != 2 || j != i2) {
                            handleSize2 = handleSize3;
                            int handleSize5 = originX + handleThickness + (((gridWidth / 3) / 3) * j) + ((gridWidth / 3) * i);
                            height2 = height3;
                            lineThickness2 = lineThickness3;
                            canvas.drawLine(originX + handleThickness + (((gridWidth / 3) / 3) * j) + ((gridWidth / 3) * i), originY + handleThickness, handleSize5, originY + handleThickness + gridHeight, this.shadowPaint);
                            canvas.drawLine(originX + handleThickness + (((gridWidth / 3) / 3) * j) + ((gridWidth / 3) * i), originY + handleThickness, originX + handleThickness + (((gridWidth / 3) / 3) * j) + ((gridWidth / 3) * i), originY + handleThickness + gridHeight, this.linePaint);
                            canvas.drawLine(originX + handleThickness, originY + handleThickness + (((gridHeight / 3) / 3) * j) + ((gridHeight / 3) * i), originX + handleThickness + gridWidth, originY + handleThickness + (((gridHeight / 3) / 3) * j) + ((gridHeight / 3) * i), this.shadowPaint);
                            canvas.drawLine(originX + handleThickness, originY + handleThickness + (((gridHeight / 3) / 3) * j) + ((gridHeight / 3) * i), originX + handleThickness + gridWidth, originY + handleThickness + (((gridHeight / 3) / 3) * j) + ((gridHeight / 3) * i), this.linePaint);
                        } else {
                            lineThickness2 = lineThickness3;
                            handleSize2 = handleSize3;
                            height2 = height3;
                        }
                        j++;
                        handleSize3 = handleSize2;
                        height3 = height2;
                        lineThickness3 = lineThickness2;
                        i2 = 3;
                    }
                    lineThickness = lineThickness3;
                    handleSize = handleSize3;
                    height = height3;
                } else {
                    lineThickness = lineThickness3;
                    handleSize = handleSize3;
                    height = height3;
                    if (type == GridType.MAJOR && i > 0) {
                        canvas.drawLine(originX + handleThickness + ((gridWidth / 3) * i), originY + handleThickness, originX + handleThickness + ((gridWidth / 3) * i), originY + handleThickness + gridHeight, this.shadowPaint);
                        canvas.drawLine(originX + handleThickness + ((gridWidth / 3) * i), originY + handleThickness, originX + handleThickness + ((gridWidth / 3) * i), originY + handleThickness + gridHeight, this.linePaint);
                        canvas.drawLine(originX + handleThickness, originY + handleThickness + ((gridHeight / 3) * i), originX + handleThickness + gridWidth, originY + handleThickness + ((gridHeight / 3) * i), this.shadowPaint);
                        canvas.drawLine(originX + handleThickness, originY + handleThickness + ((gridHeight / 3) * i), originX + handleThickness + gridWidth, originY + handleThickness + ((gridHeight / 3) * i), this.linePaint);
                    }
                }
                i++;
                handleSize3 = handleSize;
                height3 = height;
                lineThickness3 = lineThickness;
            }
        } else {
            if (this.circleBitmap == null || r0.getWidth() != this.actualRect.width()) {
                Bitmap bitmap = this.circleBitmap;
                if (bitmap != null) {
                    bitmap.recycle();
                    this.circleBitmap = null;
                }
                try {
                    this.circleBitmap = Bitmap.createBitmap((int) this.actualRect.width(), (int) this.actualRect.height(), Bitmap.Config.ARGB_8888);
                    Canvas circleCanvas = new Canvas(this.circleBitmap);
                    if (this.isFcCrop) {
                        circleCanvas.drawRect(0.0f, 0.0f, this.actualRect.width(), this.actualRect.height(), this.dimPaint);
                        circleCanvas.drawRect(0.0f, 0.0f, this.actualRect.height(), this.actualRect.width(), this.eraserPaint);
                    } else {
                        circleCanvas.drawRect(0.0f, 0.0f, this.actualRect.width(), this.actualRect.height(), this.dimPaint);
                        circleCanvas.drawCircle(this.actualRect.width() / 2.0f, this.actualRect.height() / 2.0f, this.actualRect.width() / 2.0f, this.eraserPaint);
                    }
                    circleCanvas.setBitmap(null);
                } catch (Throwable th) {
                }
            }
            canvas.drawRect(0.0f, 0.0f, getWidth(), (int) this.actualRect.top, this.dimPaint);
            canvas.drawRect(0.0f, (int) this.actualRect.top, (int) this.actualRect.left, (int) this.actualRect.bottom, this.dimPaint);
            canvas.drawRect((int) this.actualRect.right, (int) this.actualRect.top, getWidth(), (int) this.actualRect.bottom, this.dimPaint);
            canvas.drawRect(0.0f, (int) this.actualRect.bottom, getWidth(), getHeight(), this.dimPaint);
            canvas.drawBitmap(this.circleBitmap, (int) this.actualRect.left, (int) this.actualRect.top, (Paint) null);
            if (this.isFcCrop) {
                int side = AndroidUtilities.dp(1.0f);
                int rectX = ((int) this.actualRect.left) - 15;
                int rectY = ((int) this.actualRect.top) - 15;
                int rectSizeX = (int) this.actualRect.width();
                int rectSizeY = (int) this.actualRect.height();
                Paint circlePaint = new Paint();
                circlePaint.setColor(-1);
                canvas.drawRect(rectX + side, rectY + side, rectX + side + AndroidUtilities.dp(20.0f), (side * 3) + rectY, circlePaint);
                canvas.drawRect(rectX + side, rectY + side, (side * 3) + rectX, rectY + side + AndroidUtilities.dp(20.0f), circlePaint);
                canvas.drawRect((((rectX + rectSizeX) - side) - AndroidUtilities.dp(20.0f)) + 30, rectY + side, ((rectX + rectSizeX) - side) + 30, (side * 3) + rectY, circlePaint);
                canvas.drawRect(((rectX + rectSizeX) - (side * 3)) + 30, rectY + side, ((rectX + rectSizeX) - side) + 30, rectY + side + AndroidUtilities.dp(20.0f), circlePaint);
                canvas.drawRect(rectX + side, (((rectY + rectSizeY) - side) - AndroidUtilities.dp(20.0f)) + 30, (side * 3) + rectX, ((rectY + rectSizeY) - side) + 30, circlePaint);
                canvas.drawRect(rectX + side, ((rectY + rectSizeY) - (side * 3)) + 30, rectX + side + AndroidUtilities.dp(20.0f), ((rectY + rectSizeY) - side) + 30, circlePaint);
                canvas.drawRect((((rectX + rectSizeX) - side) - AndroidUtilities.dp(20.0f)) + 30, ((rectY + rectSizeY) - (side * 3)) + 30, ((rectX + rectSizeX) - side) + 30, ((rectY + rectSizeY) - side) + 30, circlePaint);
                canvas.drawRect(((rectX + rectSizeX) - (side * 3)) + 30, (((rectY + rectSizeY) - side) - AndroidUtilities.dp(20.0f)) + 30, ((rectX + rectSizeX) - side) + 30, ((rectY + rectSizeY) - side) + 30, circlePaint);
            }
        }
    }

    private void updateTouchAreas() {
        int touchPadding = AndroidUtilities.dp(16.0f);
        this.topLeftCorner.set(this.actualRect.left - touchPadding, this.actualRect.top - touchPadding, this.actualRect.left + touchPadding, this.actualRect.top + touchPadding);
        this.topRightCorner.set(this.actualRect.right - touchPadding, this.actualRect.top - touchPadding, this.actualRect.right + touchPadding, this.actualRect.top + touchPadding);
        this.bottomLeftCorner.set(this.actualRect.left - touchPadding, this.actualRect.bottom - touchPadding, this.actualRect.left + touchPadding, this.actualRect.bottom + touchPadding);
        this.bottomRightCorner.set(this.actualRect.right - touchPadding, this.actualRect.bottom - touchPadding, this.actualRect.right + touchPadding, this.actualRect.bottom + touchPadding);
        this.topEdge.set(this.actualRect.left + touchPadding, this.actualRect.top - touchPadding, this.actualRect.right - touchPadding, this.actualRect.top + touchPadding);
        this.leftEdge.set(this.actualRect.left - touchPadding, this.actualRect.top + touchPadding, this.actualRect.left + touchPadding, this.actualRect.bottom - touchPadding);
        this.rightEdge.set(this.actualRect.right - touchPadding, this.actualRect.top + touchPadding, this.actualRect.right + touchPadding, this.actualRect.bottom - touchPadding);
        this.bottomEdge.set(this.actualRect.left + touchPadding, this.actualRect.bottom - touchPadding, this.actualRect.right - touchPadding, this.actualRect.bottom + touchPadding);
    }

    public float getLockAspectRatio() {
        return this.lockAspectRatio;
    }

    public void setLockedAspectRatio(float aspectRatio) {
        this.lockAspectRatio = aspectRatio;
    }

    public void setGridType(GridType type, boolean animated) {
        if (this.gridAnimator != null && (!animated || this.gridType != type)) {
            this.gridAnimator.cancel();
            this.gridAnimator = null;
        }
        GridType gridType = this.gridType;
        if (gridType == type) {
            return;
        }
        this.previousGridType = gridType;
        this.gridType = type;
        float targetProgress = type == GridType.NONE ? 0.0f : 1.0f;
        if (!animated) {
            this.gridProgress = targetProgress;
            invalidate();
            return;
        }
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "gridProgress", this.gridProgress, targetProgress);
        this.gridAnimator = objectAnimatorOfFloat;
        objectAnimatorOfFloat.setDuration(200L);
        this.gridAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.crop.CropAreaView.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                CropAreaView.this.gridAnimator = null;
            }
        });
        if (type == GridType.NONE) {
            this.gridAnimator.setStartDelay(200L);
        }
        this.gridAnimator.start();
    }

    private void setGridProgress(float value) {
        this.gridProgress = value;
        invalidate();
    }

    private float getGridProgress() {
        return this.gridProgress;
    }

    public float getAspectRatio() {
        return (this.actualRect.right - this.actualRect.left) / (this.actualRect.bottom - this.actualRect.top);
    }

    public void fill(final RectF targetRect, Animator scaleAnimator, boolean animated) {
        if (animated) {
            Animator animator = this.animator;
            if (animator != null) {
                animator.cancel();
                this.animator = null;
            }
            AnimatorSet set = new AnimatorSet();
            this.animator = set;
            set.setDuration(300L);
            float[] fArr = {targetRect.left};
            animators[0].setInterpolator(this.interpolator);
            float[] fArr2 = {targetRect.top};
            animators[1].setInterpolator(this.interpolator);
            float[] fArr3 = {targetRect.right};
            animators[2].setInterpolator(this.interpolator);
            float[] fArr4 = {targetRect.bottom};
            animators[3].setInterpolator(this.interpolator);
            Animator[] animators = {ObjectAnimator.ofFloat(this, "cropLeft", fArr), ObjectAnimator.ofFloat(this, "cropTop", fArr2), ObjectAnimator.ofFloat(this, "cropRight", fArr3), ObjectAnimator.ofFloat(this, "cropBottom", fArr4), scaleAnimator};
            animators[4].setInterpolator(this.interpolator);
            set.playTogether(animators);
            set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.crop.CropAreaView.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    CropAreaView.this.setActualRect(targetRect);
                    CropAreaView.this.animator = null;
                }
            });
            set.start();
            return;
        }
        setActualRect(targetRect);
    }

    public void resetAnimator() {
        Animator animator = this.animator;
        if (animator != null) {
            animator.cancel();
            this.animator = null;
        }
    }

    private void setCropLeft(float value) {
        this.actualRect.left = value;
        invalidate();
    }

    public float getCropLeft() {
        return this.actualRect.left;
    }

    private void setCropTop(float value) {
        this.actualRect.top = value;
        invalidate();
    }

    public float getCropTop() {
        return this.actualRect.top;
    }

    private void setCropRight(float value) {
        this.actualRect.right = value;
        invalidate();
    }

    public float getCropRight() {
        return this.actualRect.right;
    }

    private void setCropBottom(float value) {
        this.actualRect.bottom = value;
        invalidate();
    }

    public float getCropBottom() {
        return this.actualRect.bottom;
    }

    public float getCropCenterX() {
        return this.actualRect.left + ((this.actualRect.right - this.actualRect.left) / 2.0f);
    }

    public float getCropCenterY() {
        return this.actualRect.top + ((this.actualRect.bottom - this.actualRect.top) / 2.0f);
    }

    public float getCropWidth() {
        return this.actualRect.right - this.actualRect.left;
    }

    public float getCropHeight() {
        return this.actualRect.bottom - this.actualRect.top;
    }

    public RectF getTargetRectToFill() {
        RectF rect = new RectF();
        calculateRect(rect, getAspectRatio());
        return rect;
    }

    public void calculateRect(RectF rect, float cropAspectRatio) {
        float left;
        float top;
        float right;
        float bottom;
        float statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
        float measuredHeight = (getMeasuredHeight() - this.bottomPadding) - statusBarHeight;
        float aspectRatio = getMeasuredWidth() / measuredHeight;
        float minSide = Math.min(getMeasuredWidth(), measuredHeight) - (this.sidePadding * 2.0f);
        float measuredWidth = getMeasuredWidth();
        float f = this.sidePadding;
        float width = measuredWidth - (f * 2.0f);
        float height = measuredHeight - (f * 2.0f);
        float centerX = getMeasuredWidth() / 2.0f;
        float centerY = (measuredHeight / 2.0f) + statusBarHeight;
        if (Math.abs(1.0f - cropAspectRatio) < 1.0E-4d) {
            left = centerX - (minSide / 2.0f);
            top = centerY - (minSide / 2.0f);
            right = (minSide / 2.0f) + centerX;
            bottom = (minSide / 2.0f) + centerY;
        } else if (cropAspectRatio > aspectRatio) {
            left = centerX - (width / 2.0f);
            top = centerY - ((width / cropAspectRatio) / 2.0f);
            right = (width / 2.0f) + centerX;
            bottom = centerY + ((width / cropAspectRatio) / 2.0f);
        } else {
            float left2 = height * cropAspectRatio;
            left = centerX - (left2 / 2.0f);
            top = centerY - (height / 2.0f);
            right = ((height * cropAspectRatio) / 2.0f) + centerX;
            bottom = (height / 2.0f) + centerY;
        }
        rect.set(left, top, right, bottom);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        int x = (int) (event.getX() - ((ViewGroup) getParent()).getX());
        int y = (int) (event.getY() - ((ViewGroup) getParent()).getY());
        float statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
        int action = event.getActionMasked();
        if (action == 0) {
            if (this.freeform) {
                if (this.topLeftCorner.contains(x, y)) {
                    this.activeControl = Control.TOP_LEFT;
                } else if (this.topRightCorner.contains(x, y)) {
                    this.activeControl = Control.TOP_RIGHT;
                } else if (this.bottomLeftCorner.contains(x, y)) {
                    this.activeControl = Control.BOTTOM_LEFT;
                } else if (this.bottomRightCorner.contains(x, y)) {
                    this.activeControl = Control.BOTTOM_RIGHT;
                } else if (this.leftEdge.contains(x, y)) {
                    this.activeControl = Control.LEFT;
                } else if (this.topEdge.contains(x, y)) {
                    this.activeControl = Control.TOP;
                } else if (this.rightEdge.contains(x, y)) {
                    this.activeControl = Control.RIGHT;
                } else if (this.bottomEdge.contains(x, y)) {
                    this.activeControl = Control.BOTTOM;
                } else {
                    this.activeControl = Control.NONE;
                    return false;
                }
                this.previousX = x;
                this.previousY = y;
                setGridType(GridType.MAJOR, false);
                this.isDragging = true;
                AreaViewListener areaViewListener = this.listener;
                if (areaViewListener != null) {
                    areaViewListener.onAreaChangeBegan();
                }
                return true;
            }
            this.activeControl = Control.NONE;
            return false;
        }
        if (action == 1 || action == 3) {
            this.isDragging = false;
            if (this.activeControl == Control.NONE) {
                return false;
            }
            this.activeControl = Control.NONE;
            AreaViewListener areaViewListener2 = this.listener;
            if (areaViewListener2 != null) {
                areaViewListener2.onAreaChangeEnded();
            }
            return true;
        }
        if (action != 2 || this.activeControl == Control.NONE) {
            return false;
        }
        this.tempRect.set(this.actualRect);
        float translationX = x - this.previousX;
        float translationY = y - this.previousY;
        this.previousX = x;
        this.previousY = y;
        switch (AnonymousClass3.$SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[this.activeControl.ordinal()]) {
            case 1:
                this.tempRect.left += translationX;
                this.tempRect.top += translationY;
                if (this.lockAspectRatio > 0.0f) {
                    float w = this.tempRect.width();
                    float h = this.tempRect.height();
                    if (Math.abs(translationX) > Math.abs(translationY)) {
                        constrainRectByWidth(this.tempRect, this.lockAspectRatio);
                    } else {
                        constrainRectByHeight(this.tempRect, this.lockAspectRatio);
                    }
                    this.tempRect.left -= this.tempRect.width() - w;
                    this.tempRect.top -= this.tempRect.width() - h;
                }
                break;
            case 2:
                this.tempRect.right += translationX;
                this.tempRect.top += translationY;
                if (this.lockAspectRatio > 0.0f) {
                    float h2 = this.tempRect.height();
                    if (Math.abs(translationX) > Math.abs(translationY)) {
                        constrainRectByWidth(this.tempRect, this.lockAspectRatio);
                    } else {
                        constrainRectByHeight(this.tempRect, this.lockAspectRatio);
                    }
                    this.tempRect.top -= this.tempRect.width() - h2;
                }
                break;
            case 3:
                this.tempRect.left += translationX;
                this.tempRect.bottom += translationY;
                if (this.lockAspectRatio > 0.0f) {
                    float w2 = this.tempRect.width();
                    if (Math.abs(translationX) > Math.abs(translationY)) {
                        constrainRectByWidth(this.tempRect, this.lockAspectRatio);
                    } else {
                        constrainRectByHeight(this.tempRect, this.lockAspectRatio);
                    }
                    this.tempRect.left -= this.tempRect.width() - w2;
                }
                break;
            case 4:
                this.tempRect.right += translationX;
                this.tempRect.bottom += translationY;
                if (this.lockAspectRatio > 0.0f) {
                    if (Math.abs(translationX) > Math.abs(translationY)) {
                        constrainRectByWidth(this.tempRect, this.lockAspectRatio);
                    } else {
                        constrainRectByHeight(this.tempRect, this.lockAspectRatio);
                    }
                }
                break;
            case 5:
                this.tempRect.top += translationY;
                float f = this.lockAspectRatio;
                if (f > 0.0f) {
                    constrainRectByHeight(this.tempRect, f);
                }
                break;
            case 6:
                this.tempRect.left += translationX;
                float f2 = this.lockAspectRatio;
                if (f2 > 0.0f) {
                    constrainRectByWidth(this.tempRect, f2);
                }
                break;
            case 7:
                this.tempRect.right += translationX;
                float f3 = this.lockAspectRatio;
                if (f3 > 0.0f) {
                    constrainRectByWidth(this.tempRect, f3);
                }
                break;
            case 8:
                this.tempRect.bottom += translationY;
                float f4 = this.lockAspectRatio;
                if (f4 > 0.0f) {
                    constrainRectByHeight(this.tempRect, f4);
                }
                break;
        }
        if (this.tempRect.left < this.sidePadding) {
            if (this.lockAspectRatio > 0.0f) {
                RectF rectF = this.tempRect;
                rectF.bottom = rectF.top + ((this.tempRect.right - this.sidePadding) / this.lockAspectRatio);
            }
            this.tempRect.left = this.sidePadding;
        } else if (this.tempRect.right > getWidth() - this.sidePadding) {
            this.tempRect.right = getWidth() - this.sidePadding;
            if (this.lockAspectRatio > 0.0f) {
                RectF rectF2 = this.tempRect;
                rectF2.bottom = rectF2.top + (this.tempRect.width() / this.lockAspectRatio);
            }
        }
        float f5 = this.sidePadding;
        float topPadding = statusBarHeight + f5;
        float finalBottomPadidng = this.bottomPadding + f5;
        if (this.tempRect.top < topPadding) {
            if (this.lockAspectRatio > 0.0f) {
                RectF rectF3 = this.tempRect;
                rectF3.right = rectF3.left + ((this.tempRect.bottom - topPadding) * this.lockAspectRatio);
            }
            this.tempRect.top = topPadding;
        } else if (this.tempRect.bottom > getHeight() - finalBottomPadidng) {
            this.tempRect.bottom = getHeight() - finalBottomPadidng;
            if (this.lockAspectRatio > 0.0f) {
                RectF rectF4 = this.tempRect;
                rectF4.right = rectF4.left + (this.tempRect.height() * this.lockAspectRatio);
            }
        }
        if (this.tempRect.width() < this.minWidth) {
            RectF rectF5 = this.tempRect;
            rectF5.right = rectF5.left + this.minWidth;
        }
        if (this.tempRect.height() < this.minWidth) {
            RectF rectF6 = this.tempRect;
            rectF6.bottom = rectF6.top + this.minWidth;
        }
        float f6 = this.lockAspectRatio;
        if (f6 > 0.0f) {
            if (f6 < 1.0f) {
                if (this.tempRect.width() <= this.minWidth) {
                    RectF rectF7 = this.tempRect;
                    rectF7.right = rectF7.left + this.minWidth;
                    RectF rectF8 = this.tempRect;
                    rectF8.bottom = rectF8.top + (this.tempRect.width() / this.lockAspectRatio);
                }
            } else if (this.tempRect.height() <= this.minWidth) {
                RectF rectF9 = this.tempRect;
                rectF9.bottom = rectF9.top + this.minWidth;
                RectF rectF10 = this.tempRect;
                rectF10.right = rectF10.left + (this.tempRect.height() * this.lockAspectRatio);
            }
        }
        setActualRect(this.tempRect);
        AreaViewListener areaViewListener3 = this.listener;
        if (areaViewListener3 != null) {
            areaViewListener3.onAreaChange();
        }
        return true;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.crop.CropAreaView$3, reason: invalid class name */
    static /* synthetic */ class AnonymousClass3 {
        static final /* synthetic */ int[] $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control;

        static {
            int[] iArr = new int[Control.values().length];
            $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control = iArr;
            try {
                iArr[Control.TOP_LEFT.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.TOP_RIGHT.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.BOTTOM_LEFT.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.BOTTOM_RIGHT.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.TOP.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.LEFT.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.RIGHT.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$crop$CropAreaView$Control[Control.BOTTOM.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
        }
    }

    private void constrainRectByWidth(RectF rect, float aspectRatio) {
        float w = rect.width();
        float h = w / aspectRatio;
        rect.right = rect.left + w;
        rect.bottom = rect.top + h;
    }

    private void constrainRectByHeight(RectF rect, float aspectRatio) {
        float h = rect.height();
        float w = h * aspectRatio;
        rect.right = rect.left + w;
        rect.bottom = rect.top + h;
    }

    public void getCropRect(RectF rect) {
        rect.set(this.actualRect);
    }
}
