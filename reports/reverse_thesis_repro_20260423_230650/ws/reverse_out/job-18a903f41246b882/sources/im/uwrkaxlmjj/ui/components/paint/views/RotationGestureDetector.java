package im.uwrkaxlmjj.ui.components.paint.views;

/* JADX INFO: loaded from: classes5.dex */
public class RotationGestureDetector {
    private float angle;
    private float fX;
    private float fY;
    private OnRotationGestureListener mListener;
    private float sX;
    private float sY;
    private float startAngle;

    public interface OnRotationGestureListener {
        void onRotation(RotationGestureDetector rotationGestureDetector);

        void onRotationBegin(RotationGestureDetector rotationGestureDetector);

        void onRotationEnd(RotationGestureDetector rotationGestureDetector);
    }

    public float getAngle() {
        return this.angle;
    }

    public float getStartAngle() {
        return this.startAngle;
    }

    public RotationGestureDetector(OnRotationGestureListener listener) {
        this.mListener = listener;
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x006c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r15) {
        /*
            r14 = this;
            int r0 = r15.getPointerCount()
            r1 = 2
            r2 = 0
            if (r0 == r1) goto L9
            return r2
        L9:
            int r0 = r15.getActionMasked()
            r3 = 1
            if (r0 == 0) goto L6c
            r4 = 2143289344(0x7fc00000, float:NaN)
            if (r0 == r3) goto L69
            if (r0 == r1) goto L2a
            r1 = 3
            if (r0 == r1) goto L69
            r1 = 5
            if (r0 == r1) goto L6c
            r1 = 6
            if (r0 == r1) goto L20
            goto L85
        L20:
            r14.startAngle = r4
            im.uwrkaxlmjj.ui.components.paint.views.RotationGestureDetector$OnRotationGestureListener r0 = r14.mListener
            if (r0 == 0) goto L85
            r0.onRotationEnd(r14)
            goto L85
        L2a:
            float r0 = r15.getX(r2)
            float r1 = r15.getY(r2)
            float r2 = r15.getX(r3)
            float r13 = r15.getY(r3)
            float r5 = r14.fX
            float r6 = r14.fY
            float r7 = r14.sX
            float r8 = r14.sY
            r4 = r14
            r9 = r2
            r10 = r13
            r11 = r0
            r12 = r1
            float r4 = r4.angleBetweenLines(r5, r6, r7, r8, r9, r10, r11, r12)
            r14.angle = r4
            im.uwrkaxlmjj.ui.components.paint.views.RotationGestureDetector$OnRotationGestureListener r4 = r14.mListener
            if (r4 == 0) goto L68
            float r4 = r14.startAngle
            boolean r4 = java.lang.Float.isNaN(r4)
            if (r4 == 0) goto L63
            float r4 = r14.angle
            r14.startAngle = r4
            im.uwrkaxlmjj.ui.components.paint.views.RotationGestureDetector$OnRotationGestureListener r4 = r14.mListener
            r4.onRotationBegin(r14)
            goto L68
        L63:
            im.uwrkaxlmjj.ui.components.paint.views.RotationGestureDetector$OnRotationGestureListener r4 = r14.mListener
            r4.onRotation(r14)
        L68:
            goto L85
        L69:
            r14.startAngle = r4
            goto L85
        L6c:
            float r0 = r15.getX(r2)
            r14.sX = r0
            float r0 = r15.getY(r2)
            r14.sY = r0
            float r0 = r15.getX(r3)
            r14.fX = r0
            float r0 = r15.getY(r3)
            r14.fY = r0
        L85:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.paint.views.RotationGestureDetector.onTouchEvent(android.view.MotionEvent):boolean");
    }

    private float angleBetweenLines(float fX, float fY, float sX, float sY, float nfX, float nfY, float nsX, float nsY) {
        float angle1 = (float) Math.atan2(fY - sY, fX - sX);
        float angle2 = (float) Math.atan2(nfY - nsY, nfX - nsX);
        float angle = ((float) Math.toDegrees(angle1 - angle2)) % 360.0f;
        if (angle < -180.0f) {
            angle += 360.0f;
        }
        if (angle > 180.0f) {
            return angle - 360.0f;
        }
        return angle;
    }
}
