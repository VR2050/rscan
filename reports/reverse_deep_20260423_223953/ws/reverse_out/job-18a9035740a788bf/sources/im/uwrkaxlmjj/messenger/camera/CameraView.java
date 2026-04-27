package im.uwrkaxlmjj.messenger.camera;

import android.app.Activity;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.view.TextureView;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes2.dex */
public class CameraView extends FrameLayout implements TextureView.SurfaceTextureListener {
    private CameraSession cameraSession;
    private int clipBottom;
    private int clipTop;
    private int cx;
    private int cy;
    private CameraViewDelegate delegate;
    private int focusAreaSize;
    private float focusProgress;
    private boolean initialFrontface;
    private boolean initied;
    private float innerAlpha;
    private Paint innerPaint;
    private DecelerateInterpolator interpolator;
    private boolean isFrontface;
    private long lastDrawTime;
    private Matrix matrix;
    private boolean mirror;
    private float outerAlpha;
    private Paint outerPaint;
    private Size previewSize;
    private TextureView textureView;
    private Matrix txform;

    public interface CameraViewDelegate {
        void onCameraCreated(Camera camera);

        void onCameraInit();
    }

    public CameraView(Context context, boolean frontface) {
        super(context, null);
        this.txform = new Matrix();
        this.matrix = new Matrix();
        this.focusProgress = 1.0f;
        this.outerPaint = new Paint(1);
        this.innerPaint = new Paint(1);
        this.interpolator = new DecelerateInterpolator();
        this.isFrontface = frontface;
        this.initialFrontface = frontface;
        TextureView textureView = new TextureView(context);
        this.textureView = textureView;
        textureView.setSurfaceTextureListener(this);
        addView(this.textureView);
        this.focusAreaSize = AndroidUtilities.dp(96.0f);
        this.outerPaint.setColor(-1);
        this.outerPaint.setStyle(Paint.Style.STROKE);
        this.outerPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        this.innerPaint.setColor(Integer.MAX_VALUE);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        checkPreviewMatrix();
    }

    public void setMirror(boolean value) {
        this.mirror = value;
    }

    public boolean isFrontface() {
        return this.isFrontface;
    }

    public TextureView getTextureView() {
        return this.textureView;
    }

    public boolean hasFrontFaceCamera() {
        ArrayList<CameraInfo> cameraInfos = CameraController.getInstance().getCameras();
        for (int a = 0; a < cameraInfos.size(); a++) {
            if (cameraInfos.get(a).frontCamera != 0) {
                return true;
            }
        }
        return false;
    }

    public void switchCamera() {
        if (this.cameraSession != null) {
            CameraController.getInstance().close(this.cameraSession, null, null);
            this.cameraSession = null;
        }
        this.initied = false;
        this.isFrontface = !this.isFrontface;
        initCamera();
    }

    private void initCamera() {
        Size aspectRatio;
        int wantedWidth;
        int wantedHeight;
        Size aspectRatio2;
        CameraInfo info = null;
        ArrayList<CameraInfo> cameraInfos = CameraController.getInstance().getCameras();
        if (cameraInfos == null) {
            return;
        }
        for (int a = 0; a < cameraInfos.size(); a++) {
            CameraInfo cameraInfo = cameraInfos.get(a);
            if ((this.isFrontface && cameraInfo.frontCamera != 0) || (!this.isFrontface && cameraInfo.frontCamera == 0)) {
                info = cameraInfo;
                break;
            }
        }
        if (info == null) {
            return;
        }
        float screenSize = Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) / Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y);
        if (this.initialFrontface) {
            aspectRatio = new Size(16, 9);
            wantedWidth = 480;
            wantedHeight = JavaScreenCapturer.DEGREE_270;
        } else if (Math.abs(screenSize - 1.3333334f) < 0.1f) {
            aspectRatio = new Size(4, 3);
            wantedWidth = 1280;
            wantedHeight = 960;
        } else {
            aspectRatio = new Size(16, 9);
            wantedWidth = 1280;
            wantedHeight = 720;
        }
        if (this.textureView.getWidth() > 0 && this.textureView.getHeight() > 0) {
            int width = Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y);
            int height = (aspectRatio.getHeight() * width) / aspectRatio.getWidth();
            this.previewSize = CameraController.chooseOptimalSize(info.getPreviewSizes(), width, height, aspectRatio);
        }
        Size pictureSize = CameraController.chooseOptimalSize(info.getPictureSizes(), wantedWidth, wantedHeight, aspectRatio);
        if (pictureSize.getWidth() >= 1280 && pictureSize.getHeight() >= 1280) {
            if (Math.abs(screenSize - 1.3333334f) < 0.1f) {
                aspectRatio2 = new Size(3, 4);
            } else {
                aspectRatio2 = new Size(9, 16);
            }
            Size pictureSize2 = CameraController.chooseOptimalSize(info.getPictureSizes(), wantedHeight, wantedWidth, aspectRatio2);
            if (pictureSize2.getWidth() < 1280 || pictureSize2.getHeight() < 1280) {
                pictureSize = pictureSize2;
            }
        }
        SurfaceTexture surfaceTexture = this.textureView.getSurfaceTexture();
        Size size = this.previewSize;
        if (size != null && surfaceTexture != null) {
            surfaceTexture.setDefaultBufferSize(size.getWidth(), this.previewSize.getHeight());
            this.cameraSession = new CameraSession(info, this.previewSize, pictureSize, 256);
            CameraController.getInstance().open(this.cameraSession, surfaceTexture, new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraView$3KNdJjE7MJe882BdbQKF3Fv8rK0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$initCamera$0$CameraView();
                }
            }, new Runnable() { // from class: im.uwrkaxlmjj.messenger.camera.-$$Lambda$CameraView$UTfkt8Mbvzu4H0uGXmuJ0FPvyk8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$initCamera$1$CameraView();
                }
            });
        }
    }

    public /* synthetic */ void lambda$initCamera$0$CameraView() {
        CameraSession cameraSession = this.cameraSession;
        if (cameraSession != null) {
            cameraSession.setInitied();
        }
        checkPreviewMatrix();
    }

    public /* synthetic */ void lambda$initCamera$1$CameraView() {
        CameraViewDelegate cameraViewDelegate = this.delegate;
        if (cameraViewDelegate != null) {
            cameraViewDelegate.onCameraCreated(this.cameraSession.cameraInfo.camera);
        }
    }

    public Size getPreviewSize() {
        return this.previewSize;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        initCamera();
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureSizeChanged(SurfaceTexture surfaceTexture, int width, int height) {
        checkPreviewMatrix();
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public boolean onSurfaceTextureDestroyed(SurfaceTexture surfaceTexture) {
        if (this.cameraSession != null) {
            CameraController.getInstance().close(this.cameraSession, null, null);
            return false;
        }
        return false;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public void onSurfaceTextureUpdated(SurfaceTexture surface) {
        CameraSession cameraSession;
        if (!this.initied && (cameraSession = this.cameraSession) != null && cameraSession.isInitied()) {
            CameraViewDelegate cameraViewDelegate = this.delegate;
            if (cameraViewDelegate != null) {
                cameraViewDelegate.onCameraInit();
            }
            this.initied = true;
        }
    }

    public void setClipTop(int value) {
        this.clipTop = value;
    }

    public void setClipBottom(int value) {
        this.clipBottom = value;
    }

    private void checkPreviewMatrix() {
        Size size = this.previewSize;
        if (size == null) {
            return;
        }
        adjustAspectRatio(size.getWidth(), this.previewSize.getHeight(), ((Activity) getContext()).getWindowManager().getDefaultDisplay().getRotation());
    }

    private void adjustAspectRatio(int previewWidth, int previewHeight, int rotation) {
        this.txform.reset();
        int viewWidth = getWidth();
        int viewHeight = getHeight();
        float viewCenterX = viewWidth / 2;
        float viewCenterY = viewHeight / 2;
        float scale = (rotation == 0 || rotation == 2) ? Math.max(((this.clipTop + viewHeight) + this.clipBottom) / previewWidth, viewWidth / previewHeight) : Math.max(((this.clipTop + viewHeight) + this.clipBottom) / previewHeight, viewWidth / previewWidth);
        float previewWidthScaled = previewWidth * scale;
        float previewHeightScaled = previewHeight * scale;
        float scaleX = previewHeightScaled / viewWidth;
        float scaleY = previewWidthScaled / viewHeight;
        this.txform.postScale(scaleX, scaleY, viewCenterX, viewCenterY);
        if (1 == rotation || 3 == rotation) {
            this.txform.postRotate((rotation - 2) * 90, viewCenterX, viewCenterY);
        } else if (2 == rotation) {
            this.txform.postRotate(180.0f, viewCenterX, viewCenterY);
        }
        if (this.mirror) {
            this.txform.postScale(-1.0f, 1.0f, viewCenterX, viewCenterY);
        }
        if (this.clipTop == 0) {
            if (this.clipBottom != 0) {
                this.txform.postTranslate(0.0f, r8 / 2);
            }
        } else {
            this.txform.postTranslate(0.0f, (-r8) / 2);
        }
        this.textureView.setTransform(this.txform);
        Matrix matrix = new Matrix();
        matrix.postRotate(this.cameraSession.getDisplayOrientation());
        matrix.postScale(viewWidth / 2000.0f, viewHeight / 2000.0f);
        matrix.postTranslate(viewWidth / 2.0f, viewHeight / 2.0f);
        matrix.invert(this.matrix);
    }

    private Rect calculateTapArea(float x, float y, float coefficient) {
        int areaSize = Float.valueOf(this.focusAreaSize * coefficient).intValue();
        int left = clamp(((int) x) - (areaSize / 2), 0, getWidth() - areaSize);
        int top = clamp(((int) y) - (areaSize / 2), 0, getHeight() - areaSize);
        RectF rectF = new RectF(left, top, left + areaSize, top + areaSize);
        this.matrix.mapRect(rectF);
        return new Rect(Math.round(rectF.left), Math.round(rectF.top), Math.round(rectF.right), Math.round(rectF.bottom));
    }

    private int clamp(int x, int min, int max) {
        if (x > max) {
            return max;
        }
        if (x < min) {
            return min;
        }
        return x;
    }

    public void focusToPoint(int x, int y) {
        Rect focusRect = calculateTapArea(x, y, 1.0f);
        Rect meteringRect = calculateTapArea(x, y, 1.5f);
        CameraSession cameraSession = this.cameraSession;
        if (cameraSession != null) {
            cameraSession.focusToRect(focusRect, meteringRect);
        }
        this.focusProgress = 0.0f;
        this.innerAlpha = 1.0f;
        this.outerAlpha = 1.0f;
        this.cx = x;
        this.cy = y;
        this.lastDrawTime = System.currentTimeMillis();
        invalidate();
    }

    public void setZoom(float value) {
        CameraSession cameraSession = this.cameraSession;
        if (cameraSession != null) {
            cameraSession.setZoom(value);
        }
    }

    public void setDelegate(CameraViewDelegate cameraViewDelegate) {
        this.delegate = cameraViewDelegate;
    }

    public boolean isInitied() {
        return this.initied;
    }

    public CameraSession getCameraSession() {
        return this.cameraSession;
    }

    public void destroy(boolean async, Runnable beforeDestroyRunnable) {
        CameraSession cameraSession = this.cameraSession;
        if (cameraSession != null) {
            cameraSession.destroy();
            CameraController.getInstance().close(this.cameraSession, !async ? new CountDownLatch(1) : null, beforeDestroyRunnable);
        }
    }

    @Override // android.view.View
    public Matrix getMatrix() {
        return this.txform;
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        boolean result = super.drawChild(canvas, child, drawingTime);
        if (this.focusProgress != 1.0f || this.innerAlpha != 0.0f || this.outerAlpha != 0.0f) {
            int baseRad = AndroidUtilities.dp(30.0f);
            long newTime = System.currentTimeMillis();
            long dt = newTime - this.lastDrawTime;
            if (dt < 0 || dt > 17) {
                dt = 17;
            }
            this.lastDrawTime = newTime;
            this.outerPaint.setAlpha((int) (this.interpolator.getInterpolation(this.outerAlpha) * 255.0f));
            this.innerPaint.setAlpha((int) (this.interpolator.getInterpolation(this.innerAlpha) * 127.0f));
            float interpolated = this.interpolator.getInterpolation(this.focusProgress);
            canvas.drawCircle(this.cx, this.cy, baseRad + (baseRad * (1.0f - interpolated)), this.outerPaint);
            canvas.drawCircle(this.cx, this.cy, baseRad * interpolated, this.innerPaint);
            float f = this.focusProgress;
            if (f < 1.0f) {
                float f2 = f + (dt / 200.0f);
                this.focusProgress = f2;
                if (f2 > 1.0f) {
                    this.focusProgress = 1.0f;
                }
                invalidate();
            } else {
                float f3 = this.innerAlpha;
                if (f3 != 0.0f) {
                    float f4 = f3 - (dt / 150.0f);
                    this.innerAlpha = f4;
                    if (f4 < 0.0f) {
                        this.innerAlpha = 0.0f;
                    }
                    invalidate();
                } else {
                    float f5 = this.outerAlpha;
                    if (f5 != 0.0f) {
                        float f6 = f5 - (dt / 150.0f);
                        this.outerAlpha = f6;
                        if (f6 < 0.0f) {
                            this.outerAlpha = 0.0f;
                        }
                        invalidate();
                    }
                }
            }
        }
        return result;
    }
}
