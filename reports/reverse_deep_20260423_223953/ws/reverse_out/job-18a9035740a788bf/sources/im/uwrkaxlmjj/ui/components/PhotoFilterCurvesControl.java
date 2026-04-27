package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.text.TextPaint;
import android.view.MotionEvent;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.PhotoFilterView;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoFilterCurvesControl extends View {
    private static final int CurvesSegmentBlacks = 1;
    private static final int CurvesSegmentHighlights = 4;
    private static final int CurvesSegmentMidtones = 3;
    private static final int CurvesSegmentNone = 0;
    private static final int CurvesSegmentShadows = 2;
    private static final int CurvesSegmentWhites = 5;
    private static final int GestureStateBegan = 1;
    private static final int GestureStateCancelled = 4;
    private static final int GestureStateChanged = 2;
    private static final int GestureStateEnded = 3;
    private static final int GestureStateFailed = 5;
    private int activeSegment;
    private Rect actualArea;
    private boolean checkForMoving;
    private PhotoFilterView.CurvesToolValue curveValue;
    private PhotoFilterCurvesControlDelegate delegate;
    private boolean isMoving;
    private float lastX;
    private float lastY;
    private Paint paint;
    private Paint paintCurve;
    private Paint paintDash;
    private Path path;
    private TextPaint textPaint;

    public interface PhotoFilterCurvesControlDelegate {
        void valueChanged();
    }

    public PhotoFilterCurvesControl(Context context, PhotoFilterView.CurvesToolValue value) {
        super(context);
        this.activeSegment = 0;
        this.checkForMoving = true;
        this.actualArea = new Rect();
        this.paint = new Paint(1);
        this.paintDash = new Paint(1);
        this.paintCurve = new Paint(1);
        this.textPaint = new TextPaint(1);
        this.path = new Path();
        setWillNotDraw(false);
        this.curveValue = value;
        this.paint.setColor(-1711276033);
        this.paint.setStrokeWidth(AndroidUtilities.dp(1.0f));
        this.paint.setStyle(Paint.Style.STROKE);
        this.paintDash.setColor(-1711276033);
        this.paintDash.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.paintDash.setStyle(Paint.Style.STROKE);
        this.paintCurve.setColor(-1);
        this.paintCurve.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.paintCurve.setStyle(Paint.Style.STROKE);
        this.textPaint.setColor(-4210753);
        this.textPaint.setTextSize(AndroidUtilities.dp(13.0f));
    }

    public void setDelegate(PhotoFilterCurvesControlDelegate photoFilterCurvesControlDelegate) {
        this.delegate = photoFilterCurvesControlDelegate;
    }

    public void setActualArea(float x, float y, float width, float height) {
        this.actualArea.x = x;
        this.actualArea.y = y;
        this.actualArea.width = width;
        this.actualArea.height = height;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x0020  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x002c  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r8) {
        /*
            r7 = this;
            int r0 = r8.getActionMasked()
            r1 = 0
            r2 = 3
            r3 = 1
            if (r0 == 0) goto L2c
            if (r0 == r3) goto L20
            r4 = 2
            if (r0 == r4) goto L18
            if (r0 == r2) goto L20
            r4 = 5
            if (r0 == r4) goto L2c
            r4 = 6
            if (r0 == r4) goto L20
            goto L87
        L18:
            boolean r1 = r7.isMoving
            if (r1 == 0) goto L87
            r7.handlePan(r4, r8)
            goto L87
        L20:
            boolean r4 = r7.isMoving
            if (r4 == 0) goto L29
            r7.handlePan(r2, r8)
            r7.isMoving = r1
        L29:
            r7.checkForMoving = r3
            goto L87
        L2c:
            int r4 = r8.getPointerCount()
            if (r4 != r3) goto L7c
            boolean r2 = r7.checkForMoving
            if (r2 == 0) goto L87
            boolean r2 = r7.isMoving
            if (r2 != 0) goto L87
            float r2 = r8.getX()
            float r4 = r8.getY()
            r7.lastX = r2
            r7.lastY = r4
            im.uwrkaxlmjj.ui.components.Rect r5 = r7.actualArea
            float r5 = r5.x
            int r5 = (r2 > r5 ? 1 : (r2 == r5 ? 0 : -1))
            if (r5 < 0) goto L72
            im.uwrkaxlmjj.ui.components.Rect r5 = r7.actualArea
            float r5 = r5.x
            im.uwrkaxlmjj.ui.components.Rect r6 = r7.actualArea
            float r6 = r6.width
            float r5 = r5 + r6
            int r5 = (r2 > r5 ? 1 : (r2 == r5 ? 0 : -1))
            if (r5 > 0) goto L72
            im.uwrkaxlmjj.ui.components.Rect r5 = r7.actualArea
            float r5 = r5.y
            int r5 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r5 < 0) goto L72
            im.uwrkaxlmjj.ui.components.Rect r5 = r7.actualArea
            float r5 = r5.y
            im.uwrkaxlmjj.ui.components.Rect r6 = r7.actualArea
            float r6 = r6.height
            float r5 = r5 + r6
            int r5 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r5 > 0) goto L72
            r7.isMoving = r3
        L72:
            r7.checkForMoving = r1
            boolean r1 = r7.isMoving
            if (r1 == 0) goto L7b
            r7.handlePan(r3, r8)
        L7b:
            goto L87
        L7c:
            boolean r4 = r7.isMoving
            if (r4 == 0) goto L87
            r7.handlePan(r2, r8)
            r7.checkForMoving = r3
            r7.isMoving = r1
        L87:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.PhotoFilterCurvesControl.onTouchEvent(android.view.MotionEvent):boolean");
    }

    private void handlePan(int state, MotionEvent event) {
        float locationX = event.getX();
        float locationY = event.getY();
        if (state == 1) {
            selectSegmentWithPoint(locationX);
            return;
        }
        if (state != 2) {
            if (state == 3 || state == 4 || state == 5) {
                unselectSegments();
                return;
            }
            return;
        }
        float delta = Math.min(2.0f, (this.lastY - locationY) / 8.0f);
        PhotoFilterView.CurvesValue curveValue = null;
        int i = this.curveValue.activeType;
        if (i != 0) {
            if (i == 1) {
                curveValue = this.curveValue.redCurve;
            } else if (i == 2) {
                curveValue = this.curveValue.greenCurve;
            } else if (i == 3) {
                curveValue = this.curveValue.blueCurve;
            }
        } else {
            curveValue = this.curveValue.luminanceCurve;
        }
        int i2 = this.activeSegment;
        if (i2 == 1) {
            curveValue.blacksLevel = Math.max(0.0f, Math.min(100.0f, curveValue.blacksLevel + delta));
        } else if (i2 == 2) {
            curveValue.shadowsLevel = Math.max(0.0f, Math.min(100.0f, curveValue.shadowsLevel + delta));
        } else if (i2 == 3) {
            curveValue.midtonesLevel = Math.max(0.0f, Math.min(100.0f, curveValue.midtonesLevel + delta));
        } else if (i2 == 4) {
            curveValue.highlightsLevel = Math.max(0.0f, Math.min(100.0f, curveValue.highlightsLevel + delta));
        } else if (i2 == 5) {
            curveValue.whitesLevel = Math.max(0.0f, Math.min(100.0f, curveValue.whitesLevel + delta));
        }
        invalidate();
        PhotoFilterCurvesControlDelegate photoFilterCurvesControlDelegate = this.delegate;
        if (photoFilterCurvesControlDelegate != null) {
            photoFilterCurvesControlDelegate.valueChanged();
        }
        this.lastX = locationX;
        this.lastY = locationY;
    }

    private void selectSegmentWithPoint(float pointx) {
        if (this.activeSegment != 0) {
            return;
        }
        float segmentWidth = this.actualArea.width / 5.0f;
        this.activeSegment = (int) Math.floor(((pointx - this.actualArea.x) / segmentWidth) + 1.0f);
    }

    private void unselectSegments() {
        if (this.activeSegment == 0) {
            return;
        }
        this.activeSegment = 0;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        String str;
        float segmentWidth = this.actualArea.width / 5.0f;
        for (int i = 0; i < 4; i++) {
            canvas.drawLine(this.actualArea.x + segmentWidth + (i * segmentWidth), this.actualArea.y, this.actualArea.x + segmentWidth + (i * segmentWidth), this.actualArea.y + this.actualArea.height, this.paint);
        }
        canvas.drawLine(this.actualArea.x, this.actualArea.y + this.actualArea.height, this.actualArea.x + this.actualArea.width, this.actualArea.y, this.paintDash);
        PhotoFilterView.CurvesValue curvesValue = null;
        int i2 = this.curveValue.activeType;
        if (i2 == 0) {
            this.paintCurve.setColor(-1);
            curvesValue = this.curveValue.luminanceCurve;
        } else if (i2 == 1) {
            this.paintCurve.setColor(-1229492);
            curvesValue = this.curveValue.redCurve;
        } else if (i2 == 2) {
            this.paintCurve.setColor(-15667555);
            curvesValue = this.curveValue.greenCurve;
        } else if (i2 == 3) {
            this.paintCurve.setColor(-13404165);
            curvesValue = this.curveValue.blueCurve;
        }
        for (int a = 0; a < 5; a++) {
            if (a == 0) {
                str = String.format(Locale.US, "%.2f", Float.valueOf(curvesValue.blacksLevel / 100.0f));
            } else if (a == 1) {
                str = String.format(Locale.US, "%.2f", Float.valueOf(curvesValue.shadowsLevel / 100.0f));
            } else if (a == 2) {
                str = String.format(Locale.US, "%.2f", Float.valueOf(curvesValue.midtonesLevel / 100.0f));
            } else if (a == 3) {
                str = String.format(Locale.US, "%.2f", Float.valueOf(curvesValue.highlightsLevel / 100.0f));
            } else if (a == 4) {
                str = String.format(Locale.US, "%.2f", Float.valueOf(curvesValue.whitesLevel / 100.0f));
            } else {
                str = "";
            }
            float width = this.textPaint.measureText(str);
            canvas.drawText(str, this.actualArea.x + ((segmentWidth - width) / 2.0f) + (a * segmentWidth), (this.actualArea.y + this.actualArea.height) - AndroidUtilities.dp(4.0f), this.textPaint);
        }
        float[] points = curvesValue.interpolateCurve();
        invalidate();
        this.path.reset();
        for (int a2 = 0; a2 < points.length / 2; a2++) {
            if (a2 == 0) {
                this.path.moveTo(this.actualArea.x + (points[a2 * 2] * this.actualArea.width), this.actualArea.y + ((1.0f - points[(a2 * 2) + 1]) * this.actualArea.height));
            } else {
                this.path.lineTo(this.actualArea.x + (points[a2 * 2] * this.actualArea.width), this.actualArea.y + ((1.0f - points[(a2 * 2) + 1]) * this.actualArea.height));
            }
        }
        canvas.drawPath(this.path, this.paintCurve);
    }
}
