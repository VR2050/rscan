package im.uwrkaxlmjj.ui.components.paint;

import android.graphics.Matrix;
import android.view.MotionEvent;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.util.Vector;

/* JADX INFO: loaded from: classes5.dex */
public class Input {
    private boolean beganDrawing;
    private boolean clearBuffer;
    private boolean hasMoved;
    private Matrix invertMatrix;
    private boolean isFirst;
    private Point lastLocation;
    private double lastRemainder;
    private int pointsCount;
    private RenderView renderView;
    private Point[] points = new Point[3];
    private float[] tempPoint = new float[2];

    public Input(RenderView render) {
        this.renderView = render;
    }

    public void setMatrix(Matrix m) {
        Matrix matrix = new Matrix();
        this.invertMatrix = matrix;
        m.invert(matrix);
    }

    public void process(MotionEvent event) {
        int action = event.getActionMasked();
        float x = event.getX();
        float y = this.renderView.getHeight() - event.getY();
        float[] fArr = this.tempPoint;
        fArr[0] = x;
        fArr[1] = y;
        this.invertMatrix.mapPoints(fArr);
        float[] fArr2 = this.tempPoint;
        Point location = new Point(fArr2[0], fArr2[1], 1.0d);
        if (action != 0) {
            if (action == 1) {
                if (!this.hasMoved) {
                    if (this.renderView.shouldDraw()) {
                        location.edge = true;
                        paintPath(new Path(location));
                    }
                    reset();
                } else if (this.pointsCount > 0) {
                    smoothenAndPaintPoints(true);
                }
                this.pointsCount = 0;
                this.renderView.getPainting().commitStroke(this.renderView.getCurrentColor());
                this.beganDrawing = false;
                this.renderView.onFinishedDrawing(this.hasMoved);
                return;
            }
            if (action != 2) {
                return;
            }
        }
        if (!this.beganDrawing) {
            this.beganDrawing = true;
            this.hasMoved = false;
            this.isFirst = true;
            this.lastLocation = location;
            this.points[0] = location;
            this.pointsCount = 1;
            this.clearBuffer = true;
            return;
        }
        float distance = location.getDistanceTo(this.lastLocation);
        if (distance < AndroidUtilities.dp(5.0f)) {
            return;
        }
        if (!this.hasMoved) {
            this.renderView.onBeganDrawing();
            this.hasMoved = true;
        }
        Point[] pointArr = this.points;
        int i = this.pointsCount;
        pointArr[i] = location;
        int i2 = i + 1;
        this.pointsCount = i2;
        if (i2 == 3) {
            smoothenAndPaintPoints(false);
        }
        this.lastLocation = location;
    }

    private void reset() {
        this.pointsCount = 0;
    }

    private void smoothenAndPaintPoints(boolean ended) {
        int i = this.pointsCount;
        if (i > 2) {
            Vector<Point> points = new Vector<>();
            Point[] pointArr = this.points;
            Point prev2 = pointArr[0];
            Point prev1 = pointArr[1];
            Point cur = pointArr[2];
            if (cur == null || prev1 == null) {
                return;
            }
            if (prev2 == null) {
                return;
            }
            Point midPoint1 = prev1.multiplySum(prev2, 0.5d);
            Point midPoint2 = cur.multiplySum(prev1, 0.5d);
            float distance = midPoint1.getDistanceTo(midPoint2);
            int numberOfSegments = (int) Math.min(48.0d, Math.max(Math.floor(distance / 1), 24.0d));
            float t = 0.0f;
            float step = 1.0f / numberOfSegments;
            for (int j = 0; j < numberOfSegments; j++) {
                Point point = smoothPoint(midPoint1, midPoint2, prev1, t);
                if (this.isFirst) {
                    point.edge = true;
                    this.isFirst = false;
                }
                points.add(point);
                t += step;
            }
            if (ended) {
                midPoint2.edge = true;
            }
            points.add(midPoint2);
            Point[] result = new Point[points.size()];
            points.toArray(result);
            Path path = new Path(result);
            paintPath(path);
            Point[] pointArr2 = this.points;
            System.arraycopy(pointArr2, 1, pointArr2, 0, 2);
            if (ended) {
                this.pointsCount = 0;
                return;
            } else {
                this.pointsCount = 2;
                return;
            }
        }
        Point[] result2 = new Point[i];
        System.arraycopy(this.points, 0, result2, 0, i);
        Path path2 = new Path(result2);
        paintPath(path2);
    }

    private Point smoothPoint(Point midPoint1, Point midPoint2, Point prev1, float t) {
        double a1 = Math.pow(1.0f - t, 2.0d);
        double a2 = (1.0f - t) * 2.0f * t;
        double a3 = t * t;
        return new Point((midPoint1.x * a1) + (prev1.x * a2) + (midPoint2.x * a3), (midPoint1.y * a1) + (prev1.y * a2) + (midPoint2.y * a3), 1.0d);
    }

    private void paintPath(final Path path) {
        path.setup(this.renderView.getCurrentColor(), this.renderView.getCurrentWeight(), this.renderView.getCurrentBrush());
        if (this.clearBuffer) {
            this.lastRemainder = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        }
        path.remainder = this.lastRemainder;
        this.renderView.getPainting().paintStroke(path, this.clearBuffer, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.Input.1
            @Override // java.lang.Runnable
            public void run() {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.paint.Input.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        Input.this.lastRemainder = path.remainder;
                        Input.this.clearBuffer = false;
                    }
                });
            }
        });
    }
}
