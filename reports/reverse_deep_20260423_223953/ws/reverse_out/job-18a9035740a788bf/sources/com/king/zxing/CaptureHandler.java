package com.king.zxing;

import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Point;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.view.Display;
import android.view.WindowManager;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.DecodeHintType;
import com.google.zxing.Result;
import com.google.zxing.ResultPoint;
import com.google.zxing.ResultPointCallback;
import com.king.zxing.camera.CameraManager;
import java.util.Collection;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class CaptureHandler extends Handler implements ResultPointCallback {
    private static final String TAG = CaptureHandler.class.getSimpleName();
    private final CameraManager cameraManager;
    private final DecodeThread decodeThread;
    private boolean isReturnBitmap;
    private boolean isSupportAutoZoom;
    private boolean isSupportLuminanceInvert;
    private boolean isSupportVerticalCode;
    private final OnCaptureListener onCaptureListener;
    private State state;
    private final ViewfinderView viewfinderView;

    private enum State {
        PREVIEW,
        SUCCESS,
        DONE
    }

    CaptureHandler(Activity activity, ViewfinderView viewfinderView, OnCaptureListener onCaptureListener, Collection<BarcodeFormat> decodeFormats, Map<DecodeHintType, Object> baseHints, String characterSet, CameraManager cameraManager) {
        this.viewfinderView = viewfinderView;
        this.onCaptureListener = onCaptureListener;
        DecodeThread decodeThread = new DecodeThread(activity, cameraManager, this, decodeFormats, baseHints, characterSet, this);
        this.decodeThread = decodeThread;
        decodeThread.start();
        this.state = State.SUCCESS;
        this.cameraManager = cameraManager;
        cameraManager.startPreview();
        restartPreviewAndDecode();
    }

    @Override // android.os.Handler
    public void handleMessage(Message message) {
        if (message.what == R.id.restart_preview) {
            restartPreviewAndDecode();
            return;
        }
        if (message.what == R.id.decode_succeeded) {
            this.state = State.SUCCESS;
            Bundle bundle = message.getData();
            Bitmap barcode = null;
            float scaleFactor = 1.0f;
            if (bundle != null) {
                byte[] compressedBitmap = bundle.getByteArray(DecodeThread.BARCODE_BITMAP);
                if (compressedBitmap != null) {
                    barcode = BitmapFactory.decodeByteArray(compressedBitmap, 0, compressedBitmap.length, null).copy(Bitmap.Config.ARGB_8888, true);
                }
                scaleFactor = bundle.getFloat(DecodeThread.BARCODE_SCALED_FACTOR);
            }
            this.onCaptureListener.onHandleDecode((Result) message.obj, barcode, scaleFactor);
            return;
        }
        if (message.what == R.id.decode_failed) {
            this.state = State.PREVIEW;
            this.cameraManager.requestPreviewFrame(this.decodeThread.getHandler(), R.id.decode);
        }
    }

    public void quitSynchronously() {
        this.state = State.DONE;
        this.cameraManager.stopPreview();
        Message quit = Message.obtain(this.decodeThread.getHandler(), R.id.quit);
        quit.sendToTarget();
        try {
            this.decodeThread.join(100L);
        } catch (InterruptedException e) {
        }
        removeMessages(R.id.decode_succeeded);
        removeMessages(R.id.decode_failed);
    }

    public void restartPreviewAndDecode() {
        if (this.state == State.SUCCESS) {
            this.state = State.PREVIEW;
            this.cameraManager.requestPreviewFrame(this.decodeThread.getHandler(), R.id.decode);
            ViewfinderView viewfinderView = this.viewfinderView;
            if (viewfinderView != null) {
                viewfinderView.drawViewfinder();
            }
        }
    }

    @Override // com.google.zxing.ResultPointCallback
    public void foundPossibleResultPoint(ResultPoint point) {
        if (this.viewfinderView != null) {
            ResultPoint resultPoint = transform(point);
            this.viewfinderView.addPossibleResultPoint(resultPoint);
        }
    }

    private boolean isScreenPortrait(Context context) {
        WindowManager manager = (WindowManager) context.getSystemService("window");
        Display display = manager.getDefaultDisplay();
        Point screenResolution = new Point();
        display.getSize(screenResolution);
        return screenResolution.x < screenResolution.y;
    }

    private ResultPoint transform(ResultPoint originPoint) {
        float x;
        float y;
        Point screenPoint = this.cameraManager.getScreenResolution();
        Point cameraPoint = this.cameraManager.getCameraResolution();
        if (screenPoint.x < screenPoint.y) {
            float scaleX = (screenPoint.x * 1.0f) / cameraPoint.y;
            float scaleY = (screenPoint.y * 1.0f) / cameraPoint.x;
            x = (originPoint.getX() * scaleX) - (Math.max(screenPoint.x, cameraPoint.y) / 2);
            y = (originPoint.getY() * scaleY) - (Math.min(screenPoint.y, cameraPoint.x) / 2);
        } else {
            float scaleX2 = (screenPoint.x * 1.0f) / cameraPoint.x;
            float scaleY2 = (screenPoint.y * 1.0f) / cameraPoint.y;
            x = (originPoint.getX() * scaleX2) - (Math.min(screenPoint.y, cameraPoint.y) / 2);
            y = (originPoint.getY() * scaleY2) - (Math.max(screenPoint.x, cameraPoint.x) / 2);
        }
        return new ResultPoint(x, y);
    }

    public boolean isSupportVerticalCode() {
        return this.isSupportVerticalCode;
    }

    public void setSupportVerticalCode(boolean supportVerticalCode) {
        this.isSupportVerticalCode = supportVerticalCode;
    }

    public boolean isReturnBitmap() {
        return this.isReturnBitmap;
    }

    public void setReturnBitmap(boolean returnBitmap) {
        this.isReturnBitmap = returnBitmap;
    }

    public boolean isSupportAutoZoom() {
        return this.isSupportAutoZoom;
    }

    public void setSupportAutoZoom(boolean supportAutoZoom) {
        this.isSupportAutoZoom = supportAutoZoom;
    }

    public boolean isSupportLuminanceInvert() {
        return this.isSupportLuminanceInvert;
    }

    public void setSupportLuminanceInvert(boolean supportLuminanceInvert) {
        this.isSupportLuminanceInvert = supportLuminanceInvert;
    }
}
