package com.king.zxing;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.hardware.Camera;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.view.Display;
import android.view.WindowManager;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.ResultPoint;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.king.zxing.camera.CameraManager;
import com.king.zxing.util.LogUtils;
import java.io.ByteArrayOutputStream;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
final class DecodeHandler extends Handler {
    private final CameraManager cameraManager;
    private final Context context;
    private final CaptureHandler handler;
    private long lastZoomTime;
    private final MultiFormatReader multiFormatReader;
    private boolean running = true;

    DecodeHandler(Context context, CameraManager cameraManager, CaptureHandler handler, Map<DecodeHintType, Object> hints) {
        MultiFormatReader multiFormatReader = new MultiFormatReader();
        this.multiFormatReader = multiFormatReader;
        multiFormatReader.setHints(hints);
        this.context = context;
        this.cameraManager = cameraManager;
        this.handler = handler;
    }

    @Override // android.os.Handler
    public void handleMessage(Message message) throws NotFoundException {
        if (message == null || !this.running) {
            return;
        }
        if (message.what == R.id.decode) {
            decode((byte[]) message.obj, message.arg1, message.arg2, isScreenPortrait(), this.handler.isSupportVerticalCode());
        } else if (message.what == R.id.quit) {
            this.running = false;
            Looper.myLooper().quit();
        }
    }

    private boolean isScreenPortrait() {
        WindowManager manager = (WindowManager) this.context.getSystemService("window");
        Display display = manager.getDefaultDisplay();
        Point screenResolution = new Point();
        display.getSize(screenResolution);
        return screenResolution.x < screenResolution.y;
    }

    private void decode(byte[] data, int width, int height, boolean isScreenPortrait, boolean isSupportVerticalCode) throws NotFoundException {
        boolean isReDecode;
        long start = System.currentTimeMillis();
        Result rawResult = null;
        PlanarYUVLuminanceSource source = buildPlanarYUVLuminanceSource(data, width, height, isScreenPortrait);
        if (source != null) {
            try {
                BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
                rawResult = this.multiFormatReader.decodeWithState(bitmap);
                isReDecode = false;
            } catch (Exception e) {
                isReDecode = true;
            }
            if (isReDecode && this.handler.isSupportLuminanceInvert()) {
                try {
                    BinaryBitmap bitmap2 = new BinaryBitmap(new HybridBinarizer(source.invert()));
                    rawResult = this.multiFormatReader.decodeWithState(bitmap2);
                    isReDecode = false;
                } catch (Exception e2) {
                    isReDecode = true;
                }
            }
            if (isReDecode) {
                try {
                    BinaryBitmap bitmap3 = new BinaryBitmap(new GlobalHistogramBinarizer(source));
                    rawResult = this.multiFormatReader.decodeWithState(bitmap3);
                    isReDecode = false;
                } catch (Exception e3) {
                    isReDecode = true;
                }
            }
            if (isReDecode && isSupportVerticalCode) {
                source = buildPlanarYUVLuminanceSource(data, width, height, !isScreenPortrait);
                if (source != null) {
                    try {
                        BinaryBitmap bitmap4 = new BinaryBitmap(new HybridBinarizer(source));
                        rawResult = this.multiFormatReader.decodeWithState(bitmap4);
                    } catch (Exception e4) {
                    }
                }
            }
            this.multiFormatReader.reset();
        }
        if (rawResult == null) {
            CaptureHandler captureHandler = this.handler;
            if (captureHandler != null) {
                Message.obtain(captureHandler, R.id.decode_failed).sendToTarget();
                return;
            }
            return;
        }
        long end = System.currentTimeMillis();
        LogUtils.d("Found barcode in " + (end - start) + " ms");
        BarcodeFormat barcodeFormat = rawResult.getBarcodeFormat();
        CaptureHandler captureHandler2 = this.handler;
        if (captureHandler2 != null && captureHandler2.isSupportAutoZoom() && barcodeFormat == BarcodeFormat.QR_CODE) {
            ResultPoint[] resultPoints = rawResult.getResultPoints();
            if (resultPoints.length >= 3) {
                float distance1 = ResultPoint.distance(resultPoints[0], resultPoints[1]);
                float distance2 = ResultPoint.distance(resultPoints[1], resultPoints[2]);
                float distance3 = ResultPoint.distance(resultPoints[0], resultPoints[2]);
                int maxDistance = (int) Math.max(Math.max(distance1, distance2), distance3);
                if (handleAutoZoom(maxDistance, width)) {
                    Message message = Message.obtain();
                    message.what = R.id.decode_succeeded;
                    message.obj = rawResult;
                    if (this.handler.isReturnBitmap()) {
                        Bundle bundle = new Bundle();
                        bundleThumbnail(source, bundle);
                        message.setData(bundle);
                    }
                    this.handler.sendMessageDelayed(message, 300L);
                    return;
                }
            }
        }
        CaptureHandler captureHandler3 = this.handler;
        if (captureHandler3 != null) {
            Message message2 = Message.obtain(captureHandler3, R.id.decode_succeeded, rawResult);
            if (this.handler.isReturnBitmap()) {
                Bundle bundle2 = new Bundle();
                bundleThumbnail(source, bundle2);
                message2.setData(bundle2);
            }
            message2.sendToTarget();
        }
    }

    private PlanarYUVLuminanceSource buildPlanarYUVLuminanceSource(byte[] data, int width, int height, boolean isRotate) {
        if (isRotate) {
            byte[] rotatedData = new byte[data.length];
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    rotatedData[(((x * height) + height) - y) - 1] = data[(y * width) + x];
                }
            }
            PlanarYUVLuminanceSource source = this.cameraManager.buildLuminanceSource(rotatedData, height, width);
            return source;
        }
        PlanarYUVLuminanceSource source2 = this.cameraManager.buildLuminanceSource(data, width, height);
        return source2;
    }

    private static void bundleThumbnail(PlanarYUVLuminanceSource source, Bundle bundle) {
        int[] pixels = source.renderThumbnail();
        int width = source.getThumbnailWidth();
        int height = source.getThumbnailHeight();
        Bitmap bitmap = Bitmap.createBitmap(pixels, 0, width, width, height, Bitmap.Config.ARGB_8888);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bitmap.compress(Bitmap.CompressFormat.JPEG, 50, out);
        bundle.putByteArray(DecodeThread.BARCODE_BITMAP, out.toByteArray());
        bundle.putFloat(DecodeThread.BARCODE_SCALED_FACTOR, width / source.getWidth());
    }

    private boolean handleAutoZoom(int length, int width) {
        Camera camera;
        if (this.lastZoomTime > System.currentTimeMillis() - 1000) {
            return true;
        }
        if (length < width / 5 && (camera = this.cameraManager.getOpenCamera().getCamera()) != null) {
            Camera.Parameters params = camera.getParameters();
            if (params.isZoomSupported()) {
                int maxZoom = params.getMaxZoom();
                int zoom = params.getZoom();
                params.setZoom(Math.min((maxZoom / 5) + zoom, maxZoom));
                camera.setParameters(params);
                this.lastZoomTime = System.currentTimeMillis();
                return true;
            }
            LogUtils.d("Zoom not supported");
            return false;
        }
        return false;
    }
}
