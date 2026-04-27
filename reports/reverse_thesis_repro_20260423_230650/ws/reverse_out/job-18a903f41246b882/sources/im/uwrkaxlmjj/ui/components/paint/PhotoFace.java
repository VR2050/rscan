package im.uwrkaxlmjj.ui.components.paint;

import android.graphics.Bitmap;
import android.graphics.PointF;
import com.google.android.gms.vision.face.Face;
import com.google.android.gms.vision.face.Landmark;
import im.uwrkaxlmjj.ui.components.Size;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoFace {
    private float angle;
    private im.uwrkaxlmjj.ui.components.Point chinPoint;
    private im.uwrkaxlmjj.ui.components.Point eyesCenterPoint;
    private float eyesDistance;
    private im.uwrkaxlmjj.ui.components.Point foreheadPoint;
    private im.uwrkaxlmjj.ui.components.Point mouthPoint;
    private float width;

    public PhotoFace(Face face, Bitmap sourceBitmap, Size targetSize, boolean sideward) {
        List<Landmark> landmarks = face.getLandmarks();
        im.uwrkaxlmjj.ui.components.Point leftEyePoint = null;
        im.uwrkaxlmjj.ui.components.Point rightEyePoint = null;
        im.uwrkaxlmjj.ui.components.Point leftMouthPoint = null;
        im.uwrkaxlmjj.ui.components.Point rightMouthPoint = null;
        for (Landmark landmark : landmarks) {
            PointF point = landmark.getPosition();
            int type = landmark.getType();
            if (type == 4) {
                leftEyePoint = transposePoint(point, sourceBitmap, targetSize, sideward);
            } else if (type == 5) {
                leftMouthPoint = transposePoint(point, sourceBitmap, targetSize, sideward);
            } else if (type == 10) {
                rightEyePoint = transposePoint(point, sourceBitmap, targetSize, sideward);
            } else if (type == 11) {
                rightMouthPoint = transposePoint(point, sourceBitmap, targetSize, sideward);
            }
        }
        if (leftEyePoint != null && rightEyePoint != null) {
            if (leftEyePoint.x < rightEyePoint.x) {
                im.uwrkaxlmjj.ui.components.Point temp = leftEyePoint;
                leftEyePoint = rightEyePoint;
                rightEyePoint = temp;
            }
            this.eyesCenterPoint = new im.uwrkaxlmjj.ui.components.Point((leftEyePoint.x * 0.5f) + (rightEyePoint.x * 0.5f), (leftEyePoint.y * 0.5f) + (rightEyePoint.y * 0.5f));
            this.eyesDistance = (float) Math.hypot(rightEyePoint.x - leftEyePoint.x, rightEyePoint.y - leftEyePoint.y);
            this.angle = (float) Math.toDegrees(Math.atan2(rightEyePoint.y - leftEyePoint.y, rightEyePoint.x - leftEyePoint.x) + 3.141592653589793d);
            float f = this.eyesDistance;
            this.width = 2.35f * f;
            float foreheadHeight = f * 0.8f;
            float upAngle = (float) Math.toRadians(r9 - 90.0f);
            this.foreheadPoint = new im.uwrkaxlmjj.ui.components.Point(this.eyesCenterPoint.x + (((float) Math.cos(upAngle)) * foreheadHeight), this.eyesCenterPoint.y + (((float) Math.sin(upAngle)) * foreheadHeight));
        }
        if (leftMouthPoint != null && rightMouthPoint != null) {
            if (leftMouthPoint.x < rightMouthPoint.x) {
                im.uwrkaxlmjj.ui.components.Point temp2 = leftMouthPoint;
                leftMouthPoint = rightMouthPoint;
                rightMouthPoint = temp2;
            }
            this.mouthPoint = new im.uwrkaxlmjj.ui.components.Point((leftMouthPoint.x * 0.5f) + (rightMouthPoint.x * 0.5f), (leftMouthPoint.y * 0.5f) + (rightMouthPoint.y * 0.5f));
            float chinDepth = this.eyesDistance * 0.7f;
            float downAngle = (float) Math.toRadians(this.angle + 90.0f);
            this.chinPoint = new im.uwrkaxlmjj.ui.components.Point(this.mouthPoint.x + (((float) Math.cos(downAngle)) * chinDepth), this.mouthPoint.y + (((float) Math.sin(downAngle)) * chinDepth));
        }
    }

    public boolean isSufficient() {
        return this.eyesCenterPoint != null;
    }

    private im.uwrkaxlmjj.ui.components.Point transposePoint(PointF point, Bitmap sourceBitmap, Size targetSize, boolean sideward) {
        float bitmapW = sideward ? sourceBitmap.getHeight() : sourceBitmap.getWidth();
        float bitmapH = sideward ? sourceBitmap.getWidth() : sourceBitmap.getHeight();
        return new im.uwrkaxlmjj.ui.components.Point((targetSize.width * point.x) / bitmapW, (targetSize.height * point.y) / bitmapH);
    }

    public im.uwrkaxlmjj.ui.components.Point getPointForAnchor(int anchor) {
        if (anchor == 0) {
            return this.foreheadPoint;
        }
        if (anchor == 1) {
            return this.eyesCenterPoint;
        }
        if (anchor == 2) {
            return this.mouthPoint;
        }
        if (anchor == 3) {
            return this.chinPoint;
        }
        return null;
    }

    public float getWidthForAnchor(int anchor) {
        if (anchor == 1) {
            return this.eyesDistance;
        }
        return this.width;
    }

    public float getAngle() {
        return this.angle;
    }
}
