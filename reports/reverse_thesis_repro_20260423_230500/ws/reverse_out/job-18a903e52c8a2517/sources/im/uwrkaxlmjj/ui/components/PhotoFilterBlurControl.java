package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.os.Build;
import android.view.MotionEvent;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoFilterBlurControl extends FrameLayout {
    private static final float BlurMinimumDifference = 0.02f;
    private static final float BlurMinimumFalloff = 0.1f;
    private final int GestureStateBegan;
    private final int GestureStateCancelled;
    private final int GestureStateChanged;
    private final int GestureStateEnded;
    private final int GestureStateFailed;
    private BlurViewActiveControl activeControl;
    private Size actualAreaSize;
    private float angle;
    private Paint arcPaint;
    private RectF arcRect;
    private Point centerPoint;
    private boolean checkForMoving;
    private boolean checkForZooming;
    private PhotoFilterLinearBlurControlDelegate delegate;
    private float falloff;
    private boolean isMoving;
    private boolean isZooming;
    private Paint paint;
    private float pointerScale;
    private float pointerStartX;
    private float pointerStartY;
    private float size;
    private Point startCenterPoint;
    private float startDistance;
    private float startPointerDistance;
    private float startRadius;
    private int type;
    private static final float BlurInsetProximity = AndroidUtilities.dp(20.0f);
    private static final float BlurViewCenterInset = AndroidUtilities.dp(30.0f);
    private static final float BlurViewRadiusInset = AndroidUtilities.dp(30.0f);

    private enum BlurViewActiveControl {
        BlurViewActiveControlNone,
        BlurViewActiveControlCenter,
        BlurViewActiveControlInnerRadius,
        BlurViewActiveControlOuterRadius,
        BlurViewActiveControlWholeArea,
        BlurViewActiveControlRotation
    }

    public interface PhotoFilterLinearBlurControlDelegate {
        void valueChanged(Point point, float f, float f2, float f3);
    }

    public PhotoFilterBlurControl(Context context) {
        super(context);
        this.GestureStateBegan = 1;
        this.GestureStateChanged = 2;
        this.GestureStateEnded = 3;
        this.GestureStateCancelled = 4;
        this.GestureStateFailed = 5;
        this.startCenterPoint = new Point();
        this.actualAreaSize = new Size();
        this.centerPoint = new Point(0.5f, 0.5f);
        this.falloff = 0.15f;
        this.size = 0.35f;
        this.arcRect = new RectF();
        this.pointerScale = 1.0f;
        this.checkForMoving = true;
        this.paint = new Paint(1);
        this.arcPaint = new Paint(1);
        setWillNotDraw(false);
        this.paint.setColor(-1);
        this.arcPaint.setColor(-1);
        this.arcPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.arcPaint.setStyle(Paint.Style.STROKE);
    }

    public void setType(int blurType) {
        this.type = blurType;
        invalidate();
    }

    public void setDelegate(PhotoFilterLinearBlurControlDelegate delegate) {
        this.delegate = delegate;
    }

    private float getDistance(MotionEvent event) {
        if (event.getPointerCount() != 2) {
            return 0.0f;
        }
        float x1 = event.getX(0);
        float y1 = event.getY(0);
        float x2 = event.getX(1);
        float y2 = event.getY(1);
        return (float) Math.sqrt(((x1 - x2) * (x1 - x2)) + ((y1 - y2) * (y1 - y2)));
    }

    private float degreesToRadians(float degrees) {
        return (3.1415927f * degrees) / 180.0f;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        int action = event.getActionMasked();
        if (action != 0) {
            if (action != 1) {
                if (action == 2) {
                    if (this.isMoving) {
                        handlePan(2, event);
                        return true;
                    }
                    if (!this.isZooming) {
                        return true;
                    }
                    handlePinch(2, event);
                    return true;
                }
                if (action != 3) {
                    if (action != 5) {
                        if (action != 6) {
                            return true;
                        }
                    }
                }
            }
            if (this.isMoving) {
                handlePan(3, event);
                this.isMoving = false;
            } else if (this.isZooming) {
                handlePinch(3, event);
                this.isZooming = false;
            }
            this.checkForMoving = true;
            this.checkForZooming = true;
            return true;
        }
        if (event.getPointerCount() != 1) {
            if (this.isMoving) {
                handlePan(3, event);
                this.checkForMoving = true;
                this.isMoving = false;
            }
            if (event.getPointerCount() != 2) {
                handlePinch(3, event);
                this.checkForZooming = true;
                this.isZooming = false;
                return true;
            }
            if (this.checkForZooming && !this.isZooming) {
                handlePinch(1, event);
                this.isZooming = true;
                return true;
            }
            return true;
        }
        if (!this.checkForMoving || this.isMoving) {
            return true;
        }
        float locationX = event.getX();
        float locationY = event.getY();
        Point centerPoint = getActualCenterPoint();
        Point delta = new Point(locationX - centerPoint.x, locationY - centerPoint.y);
        float radialDistance = (float) Math.sqrt((delta.x * delta.x) + (delta.y * delta.y));
        float innerRadius = getActualInnerRadius();
        float outerRadius = getActualOuterRadius();
        boolean close = Math.abs(outerRadius - innerRadius) < BlurInsetProximity;
        float innerRadiusOuterInset = close ? 0.0f : BlurViewRadiusInset;
        float outerRadiusInnerInset = close ? 0.0f : BlurViewRadiusInset;
        int i = this.type;
        if (i == 0) {
            float distance = (float) Math.abs((((double) delta.x) * Math.cos(((double) degreesToRadians(this.angle)) + 1.5707963267948966d)) + (((double) delta.y) * Math.sin(((double) degreesToRadians(this.angle)) + 1.5707963267948966d)));
            if (radialDistance < BlurViewCenterInset) {
                this.isMoving = true;
            } else if (distance > innerRadius - BlurViewRadiusInset && distance < innerRadius + innerRadiusOuterInset) {
                this.isMoving = true;
            } else if (distance > outerRadius - outerRadiusInnerInset && distance < BlurViewRadiusInset + outerRadius) {
                this.isMoving = true;
            } else {
                float f = BlurViewRadiusInset;
                if (distance <= innerRadius - f || distance >= f + outerRadius) {
                    this.isMoving = true;
                }
            }
        } else if (i == 1) {
            if (radialDistance < BlurViewCenterInset) {
                this.isMoving = true;
            } else if (radialDistance > innerRadius - BlurViewRadiusInset && radialDistance < innerRadius + innerRadiusOuterInset) {
                this.isMoving = true;
            } else if (radialDistance > outerRadius - outerRadiusInnerInset && radialDistance < BlurViewRadiusInset + outerRadius) {
                this.isMoving = true;
            }
        }
        this.checkForMoving = false;
        if (this.isMoving) {
            handlePan(1, event);
        }
        return true;
    }

    private void handlePan(int state, MotionEvent event) {
        float locationX = event.getX();
        float locationY = event.getY();
        Point actualCenterPoint = getActualCenterPoint();
        Point delta = new Point(locationX - actualCenterPoint.x, locationY - actualCenterPoint.y);
        float radialDistance = (float) Math.sqrt((delta.x * delta.x) + (delta.y * delta.y));
        float shorterSide = this.actualAreaSize.width > this.actualAreaSize.height ? this.actualAreaSize.height : this.actualAreaSize.width;
        float innerRadius = this.falloff * shorterSide;
        float outerRadius = this.size * shorterSide;
        float distance = (float) Math.abs((((double) delta.x) * Math.cos(((double) degreesToRadians(this.angle)) + 1.5707963267948966d)) + (((double) delta.y) * Math.sin(((double) degreesToRadians(this.angle)) + 1.5707963267948966d)));
        if (state == 1) {
            this.pointerStartX = event.getX();
            this.pointerStartY = event.getY();
            boolean close = Math.abs(outerRadius - innerRadius) < BlurInsetProximity;
            float innerRadiusOuterInset = close ? 0.0f : BlurViewRadiusInset;
            float outerRadiusInnerInset = close ? 0.0f : BlurViewRadiusInset;
            int i = this.type;
            if (i == 0) {
                if (radialDistance < BlurViewCenterInset) {
                    this.activeControl = BlurViewActiveControl.BlurViewActiveControlCenter;
                    this.startCenterPoint = actualCenterPoint;
                } else if (distance > innerRadius - BlurViewRadiusInset && distance < innerRadius + innerRadiusOuterInset) {
                    this.activeControl = BlurViewActiveControl.BlurViewActiveControlInnerRadius;
                    this.startDistance = distance;
                    this.startRadius = innerRadius;
                } else if (distance > outerRadius - outerRadiusInnerInset && distance < BlurViewRadiusInset + outerRadius) {
                    this.activeControl = BlurViewActiveControl.BlurViewActiveControlOuterRadius;
                    this.startDistance = distance;
                    this.startRadius = outerRadius;
                } else {
                    float f = BlurViewRadiusInset;
                    if (distance <= innerRadius - f || distance >= f + outerRadius) {
                        this.activeControl = BlurViewActiveControl.BlurViewActiveControlRotation;
                    }
                }
            } else if (i == 1) {
                if (radialDistance < BlurViewCenterInset) {
                    this.activeControl = BlurViewActiveControl.BlurViewActiveControlCenter;
                    this.startCenterPoint = actualCenterPoint;
                } else if (radialDistance > innerRadius - BlurViewRadiusInset && radialDistance < innerRadius + innerRadiusOuterInset) {
                    this.activeControl = BlurViewActiveControl.BlurViewActiveControlInnerRadius;
                    this.startDistance = radialDistance;
                    this.startRadius = innerRadius;
                } else if (radialDistance > outerRadius - outerRadiusInnerInset && radialDistance < BlurViewRadiusInset + outerRadius) {
                    this.activeControl = BlurViewActiveControl.BlurViewActiveControlOuterRadius;
                    this.startDistance = radialDistance;
                    this.startRadius = outerRadius;
                }
            }
            setSelected(true, true);
            return;
        }
        if (state != 2) {
            if (state == 3 || state == 4 || state == 5) {
                this.activeControl = BlurViewActiveControl.BlurViewActiveControlNone;
                setSelected(false, true);
                return;
            }
            return;
        }
        int i2 = this.type;
        if (i2 == 0) {
            int i3 = AnonymousClass1.$SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl[this.activeControl.ordinal()];
            if (i3 == 1) {
                float translationX = locationX - this.pointerStartX;
                float translationY = locationY - this.pointerStartY;
                Rect actualArea = new Rect((getWidth() - this.actualAreaSize.width) / 2.0f, (getHeight() - this.actualAreaSize.height) / 2.0f, this.actualAreaSize.width, this.actualAreaSize.height);
                float fMax = Math.max(actualArea.x, Math.min(actualArea.x + actualArea.width, this.startCenterPoint.x + translationX));
                float f2 = actualArea.y;
                float f3 = actualArea.y;
                float translationX2 = actualArea.height;
                Point newPoint = new Point(fMax, Math.max(f2, Math.min(f3 + translationX2, this.startCenterPoint.y + translationY)));
                this.centerPoint = new Point((newPoint.x - actualArea.x) / this.actualAreaSize.width, ((newPoint.y - actualArea.y) + ((this.actualAreaSize.width - this.actualAreaSize.height) / 2.0f)) / this.actualAreaSize.width);
            } else if (i3 == 2) {
                float d = distance - this.startDistance;
                this.falloff = Math.min(Math.max(0.1f, (this.startRadius + d) / shorterSide), this.size - BlurMinimumDifference);
            } else if (i3 == 3) {
                float d2 = distance - this.startDistance;
                this.size = Math.max(this.falloff + BlurMinimumDifference, (this.startRadius + d2) / shorterSide);
            } else if (i3 == 4) {
                float translationX3 = locationX - this.pointerStartX;
                float translationY2 = locationY - this.pointerStartY;
                int i4 = 0;
                boolean right = locationX > actualCenterPoint.x;
                boolean bottom = locationY > actualCenterPoint.y;
                if (right || bottom) {
                    if (!right || bottom) {
                        if (right && bottom) {
                            if (Math.abs(translationY2) > Math.abs(translationX3)) {
                                if (translationY2 > 0.0f) {
                                    i4 = 1;
                                }
                            } else if (translationX3 < 0.0f) {
                                i4 = 1;
                            }
                        } else if (Math.abs(translationY2) > Math.abs(translationX3)) {
                            if (translationY2 < 0.0f) {
                                i4 = 1;
                            }
                        } else if (translationX3 < 0.0f) {
                            i4 = 1;
                        }
                    } else if (Math.abs(translationY2) > Math.abs(translationX3)) {
                        if (translationY2 > 0.0f) {
                            i4 = 1;
                        }
                    } else if (translationX3 > 0.0f) {
                        i4 = 1;
                    }
                } else if (Math.abs(translationY2) > Math.abs(translationX3)) {
                    if (translationY2 < 0.0f) {
                        i4 = 1;
                    }
                } else if (translationX3 > 0.0f) {
                    i4 = 1;
                }
                float d3 = (float) Math.sqrt((translationX3 * translationX3) + (translationY2 * translationY2));
                this.angle += ((((i4 * 2) - 1) * d3) / 3.1415927f) / 1.15f;
                this.pointerStartX = locationX;
                this.pointerStartY = locationY;
            }
        } else if (i2 == 1) {
            int i5 = AnonymousClass1.$SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl[this.activeControl.ordinal()];
            if (i5 == 1) {
                float translationX4 = locationX - this.pointerStartX;
                float translationY3 = locationY - this.pointerStartY;
                Rect actualArea2 = new Rect((getWidth() - this.actualAreaSize.width) / 2.0f, (getHeight() - this.actualAreaSize.height) / 2.0f, this.actualAreaSize.width, this.actualAreaSize.height);
                float fMax2 = Math.max(actualArea2.x, Math.min(actualArea2.x + actualArea2.width, this.startCenterPoint.x + translationX4));
                float f4 = actualArea2.y;
                float f5 = actualArea2.y;
                float translationX5 = actualArea2.height;
                Point newPoint2 = new Point(fMax2, Math.max(f4, Math.min(f5 + translationX5, this.startCenterPoint.y + translationY3)));
                this.centerPoint = new Point((newPoint2.x - actualArea2.x) / this.actualAreaSize.width, ((newPoint2.y - actualArea2.y) + ((this.actualAreaSize.width - this.actualAreaSize.height) / 2.0f)) / this.actualAreaSize.width);
            } else if (i5 == 2) {
                float d4 = radialDistance - this.startDistance;
                this.falloff = Math.min(Math.max(0.1f, (this.startRadius + d4) / shorterSide), this.size - BlurMinimumDifference);
            } else if (i5 == 3) {
                float d5 = radialDistance - this.startDistance;
                this.size = Math.max(this.falloff + BlurMinimumDifference, (this.startRadius + d5) / shorterSide);
            }
        }
        invalidate();
        PhotoFilterLinearBlurControlDelegate photoFilterLinearBlurControlDelegate = this.delegate;
        if (photoFilterLinearBlurControlDelegate != null) {
            photoFilterLinearBlurControlDelegate.valueChanged(this.centerPoint, this.falloff, this.size, degreesToRadians(this.angle) + 1.5707964f);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.PhotoFilterBlurControl$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl;

        static {
            int[] iArr = new int[BlurViewActiveControl.values().length];
            $SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl = iArr;
            try {
                iArr[BlurViewActiveControl.BlurViewActiveControlCenter.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl[BlurViewActiveControl.BlurViewActiveControlInnerRadius.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl[BlurViewActiveControl.BlurViewActiveControlOuterRadius.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$components$PhotoFilterBlurControl$BlurViewActiveControl[BlurViewActiveControl.BlurViewActiveControlRotation.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
        }
    }

    private void handlePinch(int state, MotionEvent event) {
        if (state == 1) {
            this.startPointerDistance = getDistance(event);
            this.pointerScale = 1.0f;
            this.activeControl = BlurViewActiveControl.BlurViewActiveControlWholeArea;
            setSelected(true, true);
        } else if (state != 2) {
            if (state == 3 || state == 4 || state == 5) {
                this.activeControl = BlurViewActiveControl.BlurViewActiveControlNone;
                setSelected(false, true);
                return;
            }
            return;
        }
        float newDistance = getDistance(event);
        float f = this.pointerScale + (((newDistance - this.startPointerDistance) / AndroidUtilities.density) * 0.01f);
        this.pointerScale = f;
        float fMax = Math.max(0.1f, this.falloff * f);
        this.falloff = fMax;
        this.size = Math.max(fMax + BlurMinimumDifference, this.size * this.pointerScale);
        this.pointerScale = 1.0f;
        this.startPointerDistance = newDistance;
        invalidate();
        PhotoFilterLinearBlurControlDelegate photoFilterLinearBlurControlDelegate = this.delegate;
        if (photoFilterLinearBlurControlDelegate != null) {
            photoFilterLinearBlurControlDelegate.valueChanged(this.centerPoint, this.falloff, this.size, degreesToRadians(this.angle) + 1.5707964f);
        }
    }

    private void setSelected(boolean selected, boolean animated) {
    }

    public void setActualAreaSize(float width, float height) {
        this.actualAreaSize.width = width;
        this.actualAreaSize.height = height;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        Point centerPoint = getActualCenterPoint();
        float innerRadius = getActualInnerRadius();
        float outerRadius = getActualOuterRadius();
        canvas.translate(centerPoint.x, centerPoint.y);
        int i = this.type;
        if (i == 0) {
            canvas.rotate(this.angle);
            float space = AndroidUtilities.dp(6.0f);
            float length = AndroidUtilities.dp(12.0f);
            float thickness = AndroidUtilities.dp(1.5f);
            int i2 = 0;
            while (i2 < 30) {
                int i3 = i2;
                canvas.drawRect((length + space) * i2, -innerRadius, (i2 * (length + space)) + length, thickness - innerRadius, this.paint);
                canvas.drawRect((((-i3) * (length + space)) - space) - length, -innerRadius, ((-i3) * (length + space)) - space, thickness - innerRadius, this.paint);
                canvas.drawRect((length + space) * i3, innerRadius, length + (i3 * (length + space)), thickness + innerRadius, this.paint);
                canvas.drawRect((((-i3) * (length + space)) - space) - length, innerRadius, ((-i3) * (length + space)) - space, thickness + innerRadius, this.paint);
                i2 = i3 + 1;
            }
            float length2 = AndroidUtilities.dp(6.0f);
            for (int i4 = 0; i4 < 64; i4++) {
                canvas.drawRect((length2 + space) * i4, -outerRadius, length2 + (i4 * (length2 + space)), thickness - outerRadius, this.paint);
                canvas.drawRect((((-i4) * (length2 + space)) - space) - length2, -outerRadius, ((-i4) * (length2 + space)) - space, thickness - outerRadius, this.paint);
                canvas.drawRect((length2 + space) * i4, outerRadius, length2 + (i4 * (length2 + space)), thickness + outerRadius, this.paint);
                canvas.drawRect((((-i4) * (length2 + space)) - space) - length2, outerRadius, ((-i4) * (length2 + space)) - space, thickness + outerRadius, this.paint);
            }
        } else if (i == 1) {
            this.arcRect.set(-innerRadius, -innerRadius, innerRadius, innerRadius);
            for (int i5 = 0; i5 < 22; i5++) {
                canvas.drawArc(this.arcRect, (6.15f + 10.2f) * i5, 10.2f, false, this.arcPaint);
            }
            this.arcRect.set(-outerRadius, -outerRadius, outerRadius, outerRadius);
            for (int i6 = 0; i6 < 64; i6++) {
                canvas.drawArc(this.arcRect, (2.02f + 3.6f) * i6, 3.6f, false, this.arcPaint);
            }
        }
        canvas.drawCircle(0.0f, 0.0f, AndroidUtilities.dp(8.0f), this.paint);
    }

    private Point getActualCenterPoint() {
        return new Point(((getWidth() - this.actualAreaSize.width) / 2.0f) + (this.centerPoint.x * this.actualAreaSize.width), (((Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0) + ((getHeight() - this.actualAreaSize.height) / 2.0f)) - ((this.actualAreaSize.width - this.actualAreaSize.height) / 2.0f)) + (this.centerPoint.y * this.actualAreaSize.width));
    }

    private float getActualInnerRadius() {
        return (this.actualAreaSize.width > this.actualAreaSize.height ? this.actualAreaSize.height : this.actualAreaSize.width) * this.falloff;
    }

    private float getActualOuterRadius() {
        return (this.actualAreaSize.width > this.actualAreaSize.height ? this.actualAreaSize.height : this.actualAreaSize.width) * this.size;
    }
}
