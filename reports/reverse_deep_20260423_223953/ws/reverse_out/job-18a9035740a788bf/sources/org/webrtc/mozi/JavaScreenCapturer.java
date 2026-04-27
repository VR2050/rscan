package org.webrtc.mozi;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.WindowManager;
import com.google.android.exoplayer2.C;
import com.king.zxing.util.LogUtils;
import org.webrtc.mozi.ScreenAudioCapturer;
import org.webrtc.mozi.VideoFrame;

/* JADX INFO: loaded from: classes3.dex */
public class JavaScreenCapturer {
    private static final int DEFAULT_AUDIO_CAPTURE_CHANNELS = 1;
    private static final int DEFAULT_AUDIO_CAPTURE_SAMPLERATE = 44100;
    public static final int DEGREE_0 = 0;
    public static final int DEGREE_180 = 180;
    public static final int DEGREE_270 = 270;
    public static final int DEGREE_90 = 90;
    public static final int ERROR_SCREEN_CAPTURE_PERMISSION_DENIED = -1000;
    public static final int ERROR_SCREEN_CAPTURE_SYSTEM_AUDIO_NOT_SUPPORTED = -1002;
    public static final int ERROR_SCREEN_CAPTURE_SYSTEM_NOT_SUPPORTED = -1001;
    public static final int ERROR_UNKNOWN = -1;
    public static final int MEDIA_PROJECTION_REQUEST_CODE = 1001;
    public static final int SCREEN_CAPTURE_EVENT_AUDIO_STARTED = 3;
    public static final int SCREEN_CAPTURE_EVENT_AUDIO_STOPPED = 4;
    public static final int SCREEN_CAPTURE_EVENT_VIDEO_STARTED = 1;
    public static final int SCREEN_CAPTURE_EVENT_VIDEO_STOPPED = 2;
    private static final String TAG = "JavaScreenCapturer";
    private static Display sDisplay;
    private boolean mCapturing;
    private Context mContext;
    private int mFps;
    private int mHeight;
    public MediaProjectionManager mMediaProjectManager;
    private MediaProjection mMediaProjection;
    private Intent mMediaProjectionPermissionResultData;
    private long mNativeHandler;
    private ScreenAudioCapturer mScreenAudioCapturer;
    private ScreenAudioCapturer.ScreenAudioCapturerObserver mScreenAudioCapturerObserver;
    private ScreenCapturerAndroid mScreenVideoCapturer;
    private CapturerObserver mScreenVideoCapturerObserver;
    private SurfaceTextureHelper mSurfaceTextureHelper;
    private int mWidth;
    public static int mScreenWidth = 0;
    public static int mScreenHeight = 0;
    private int mLastOrientation = 0;
    private boolean mAudioEnabled = false;
    private boolean mVideoEnabled = false;
    private boolean mInitialized = false;
    private final ForceDeliver mForceDeliver = new ForceDeliver();
    private long mForceDeliverIntervalMs = 500;
    private BroadcastReceiver mScreenOrientationRecevier = new BroadcastReceiver() { // from class: org.webrtc.mozi.JavaScreenCapturer.5
        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            int orientation;
            if ("android.intent.action.CONFIGURATION_CHANGED".equalsIgnoreCase(intent.getAction()) && JavaScreenCapturer.this.mScreenVideoCapturer != null && JavaScreenCapturer.this.mWidth != 0 && JavaScreenCapturer.this.mHeight != 0 && JavaScreenCapturer.this.mLastOrientation != (orientation = JavaScreenCapturer.getScreenRotation(context))) {
                Logging.d(JavaScreenCapturer.TAG, "orientation change to " + orientation);
                JavaScreenCapturer.this.mLastOrientation = orientation;
                JavaScreenCapturer.this.mScreenVideoCapturer.setRotation(orientation);
                if (JavaScreenCapturer.this.mCapturing) {
                    JavaScreenCapturer.this.mScreenVideoCapturer.changeCaptureFormat(JavaScreenCapturer.this.mWidth, JavaScreenCapturer.this.mHeight, JavaScreenCapturer.this.mFps);
                }
            }
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    public static native int nativeOnAudioCaptured(long j, byte[] bArr, int i, int i2, int i3);

    private static native int nativeOnData(long j, byte[] bArr, long j2, int i, int i2, int i3);

    private static native int nativeOnError(long j, int i);

    private static native int nativeOnEvent(long j, int i);

    /* JADX INFO: Access modifiers changed from: private */
    public static native int nativeOnTexture(long j, int i, int i2, int i3, int i4, long j2, VideoFrame.Buffer buffer);

    public static boolean isScreenCaptureSupported() {
        return Build.VERSION.SDK_INT >= 21;
    }

    public static boolean isScreenCaptureAudioSupported() {
        return Build.VERSION.SDK_INT >= 29;
    }

    public JavaScreenCapturer(long nativeHandler) {
        this.mNativeHandler = 0L;
        Logging.d(TAG, "JavaScreenCapturer " + nativeHandler);
        this.mNativeHandler = nativeHandler;
    }

    public void init(Intent mediaProjectionPermissionResultData, SurfaceTextureHelper surfaceTextureHelper, boolean enableVideo, boolean enableAudio) {
        Logging.d(TAG, "init, enableVideo=" + enableVideo + ", enableAudio=" + enableAudio);
        this.mMediaProjectionPermissionResultData = mediaProjectionPermissionResultData;
        this.mSurfaceTextureHelper = surfaceTextureHelper;
        this.mContext = ContextUtils.getApplicationContext();
        if (!isScreenCaptureSupported()) {
            onError(-1001);
            return;
        }
        if (enableVideo) {
            initScreenVideoCapture();
            this.mVideoEnabled = true;
        }
        if (enableAudio) {
            if (!isScreenCaptureAudioSupported()) {
                onError(-1002);
            } else {
                initScreenAudioCapture();
                this.mAudioEnabled = true;
            }
        }
        if (this.mMediaProjectManager == null) {
            this.mMediaProjectManager = (MediaProjectionManager) this.mContext.getSystemService("media_projection");
        }
        this.mContext.registerReceiver(this.mScreenOrientationRecevier, new IntentFilter("android.intent.action.CONFIGURATION_CHANGED"));
        this.mInitialized = true;
    }

    public synchronized int startCapture(int width, int height, int fps) {
        Logging.d(TAG, "startCapture " + width + "x" + height + ", fps:" + fps);
        if (!this.mVideoEnabled && !this.mAudioEnabled) {
            Logging.e(TAG, "audio video not enabled!");
            return -1;
        }
        if (this.mCapturing) {
            Logging.d(TAG, "startCapture: capturing");
            return -1;
        }
        this.mWidth = width;
        this.mHeight = height;
        this.mFps = fps;
        this.mCapturing = true;
        if (this.mMediaProjectionPermissionResultData != null) {
            maybeStartScreenCastService();
        } else {
            Intent intent = new Intent(this.mContext, (Class<?>) ScreenCaptureAssistantActivity.class);
            intent.addFlags(C.ENCODING_PCM_MU_LAW);
            ScreenCaptureAssistantActivity.mScreenShareControl = this;
            this.mContext.startActivity(intent);
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startScreenCaptureInternal() {
        if (this.mMediaProjection == null) {
            try {
                this.mMediaProjection = this.mMediaProjectManager.getMediaProjection(-1, this.mMediaProjectionPermissionResultData);
            } catch (SecurityException e) {
                Logging.d(TAG, "GetMediaProjection Permission Denied, exception: " + e.getMessage());
            }
            if (this.mMediaProjection == null) {
                try {
                    StringBuilder intentDetails = new StringBuilder();
                    intentDetails.append("GetMediaProjection return null, intent maybe invalid. ");
                    intentDetails.append("Intent: {action: ");
                    intentDetails.append(this.mMediaProjectionPermissionResultData.getAction());
                    intentDetails.append(", ");
                    intentDetails.append("data: ");
                    intentDetails.append(this.mMediaProjectionPermissionResultData.getData());
                    intentDetails.append(", ");
                    Bundle extras = this.mMediaProjectionPermissionResultData.getExtras();
                    if (extras != null) {
                        intentDetails.append("extras: {");
                        for (String key : extras.keySet()) {
                            Object value = extras.get(key);
                            intentDetails.append(key);
                            intentDetails.append(LogUtils.COLON);
                            intentDetails.append(value);
                            intentDetails.append(", ");
                        }
                        intentDetails.append("}");
                    } else {
                        intentDetails.append("extras: null");
                    }
                    intentDetails.append("}");
                    Logging.e(TAG, intentDetails.toString());
                    return;
                } catch (Exception e2) {
                    Logging.e(TAG, "GetMediaProjection return null, intent can't resolved, error: " + e2.getMessage());
                    return;
                }
            }
        }
        if (this.mMediaProjection == null) {
            Logging.e(TAG, "MediaProjection is null!");
            return;
        }
        if (this.mVideoEnabled) {
            startScreenVideoCapture();
        }
        if (this.mAudioEnabled) {
            startScreenAudioCapture();
        }
    }

    private void stopScreenCapture() {
        if (this.mVideoEnabled) {
            stopScreenVideoCapture();
        }
        if (this.mAudioEnabled) {
            stopScreenAudioCapture();
        }
        MediaProjection mediaProjection = this.mMediaProjection;
        if (mediaProjection != null) {
            mediaProjection.stop();
            this.mMediaProjection = null;
        }
    }

    private void initScreenVideoCapture() {
        if (this.mScreenVideoCapturer == null) {
            this.mScreenVideoCapturer = new ScreenCapturerAndroid(this.mMediaProjectionPermissionResultData, new MediaProjection.Callback() { // from class: org.webrtc.mozi.JavaScreenCapturer.1
                @Override // android.media.projection.MediaProjection.Callback
                public void onStop() {
                    super.onStop();
                }
            });
            if (this.mScreenVideoCapturerObserver == null) {
                this.mScreenVideoCapturerObserver = new CapturerObserver() { // from class: org.webrtc.mozi.JavaScreenCapturer.2
                    @Override // org.webrtc.mozi.CapturerObserver
                    public void onCapturerStarted(boolean success) {
                        if (success) {
                            JavaScreenCapturer.this.onEvent(1);
                        }
                    }

                    @Override // org.webrtc.mozi.CapturerObserver
                    public void onCapturerStopped() {
                        JavaScreenCapturer.this.onEvent(2);
                    }

                    @Override // org.webrtc.mozi.CapturerObserver
                    public void onFrameCaptured(VideoFrame frame) {
                        VideoFrame deliverFrame = JavaScreenCapturer.this.mForceDeliver.deliverFrame(frame);
                        VideoFrame.Buffer buffer = deliverFrame.getBuffer();
                        if (buffer instanceof VideoFrame.TextureBuffer) {
                            JavaScreenCapturer.nativeOnTexture(JavaScreenCapturer.this.mNativeHandler, deliverFrame.getBuffer().getWidth(), deliverFrame.getBuffer().getHeight(), deliverFrame.getRotation(), deliverFrame.getExtraRotation(), deliverFrame.getTimestampNs(), deliverFrame.getBuffer());
                        } else {
                            deliverFrame.getTimestampNs();
                            deliverFrame.getRotation();
                            deliverFrame.getRotatedWidth();
                            deliverFrame.getRotatedHeight();
                        }
                        if (deliverFrame != frame) {
                            deliverFrame.release();
                        }
                    }

                    @Override // org.webrtc.mozi.CapturerObserver
                    public void onCaptureThreadChanged() {
                    }

                    @Override // org.webrtc.mozi.CapturerObserver
                    public void setOutputFormatRequest(int width, int height, int fps) {
                    }
                };
            }
            this.mScreenVideoCapturer.initialize(this.mSurfaceTextureHelper, this.mContext, this.mScreenVideoCapturerObserver);
        }
    }

    private void startScreenVideoCapture() {
        if (this.mScreenVideoCapturer != null) {
            int screenRotation = getScreenRotation(this.mContext);
            this.mLastOrientation = screenRotation;
            this.mScreenVideoCapturer.setRotation(screenRotation);
            this.mScreenVideoCapturer.setExternalMediaProjection(this.mMediaProjection);
            this.mScreenVideoCapturer.startCapture(this.mWidth, this.mHeight, this.mFps);
        }
    }

    private void stopScreenVideoCapture() {
        ScreenCapturerAndroid screenCapturerAndroid = this.mScreenVideoCapturer;
        if (screenCapturerAndroid != null) {
            screenCapturerAndroid.stopCapture();
            this.mForceDeliver.stopDeliver();
        }
    }

    private void initScreenAudioCapture() {
        if (this.mScreenAudioCapturer == null) {
            this.mScreenAudioCapturer = new ScreenAudioCapturer(this.mContext);
        }
        if (this.mScreenAudioCapturerObserver == null) {
            this.mScreenAudioCapturerObserver = new ScreenAudioCapturer.ScreenAudioCapturerObserver() { // from class: org.webrtc.mozi.JavaScreenCapturer.3
                @Override // org.webrtc.mozi.ScreenAudioCapturer.ScreenAudioCapturerObserver
                public void onStarted() {
                    JavaScreenCapturer.this.onEvent(3);
                }

                @Override // org.webrtc.mozi.ScreenAudioCapturer.ScreenAudioCapturerObserver
                public void onStopped() {
                    JavaScreenCapturer.this.onEvent(4);
                }

                @Override // org.webrtc.mozi.ScreenAudioCapturer.ScreenAudioCapturerObserver
                public void onError(int errorCode) {
                    onError(errorCode);
                }

                @Override // org.webrtc.mozi.ScreenAudioCapturer.ScreenAudioCapturerObserver
                public void OnAudioCaptured(byte[] audioData, int audioDataSize, int sampleRate, int channels) {
                    JavaScreenCapturer.nativeOnAudioCaptured(JavaScreenCapturer.this.mNativeHandler, audioData, audioDataSize, sampleRate, channels);
                }
            };
        }
        this.mScreenAudioCapturer.setScreenAudioCapturerObserver(this.mScreenAudioCapturerObserver);
    }

    public int startScreenAudioCapture() {
        ScreenAudioCapturer screenAudioCapturer = this.mScreenAudioCapturer;
        if (screenAudioCapturer != null) {
            return screenAudioCapturer.startCapture(this.mMediaProjection, DEFAULT_AUDIO_CAPTURE_SAMPLERATE, 1);
        }
        return -1;
    }

    public int stopScreenAudioCapture() {
        Logging.d(TAG, "stopScreenAudioCapture begin");
        ScreenAudioCapturer screenAudioCapturer = this.mScreenAudioCapturer;
        if (screenAudioCapturer != null) {
            screenAudioCapturer.stopCapture();
        }
        this.mScreenAudioCapturer.setScreenAudioCapturerObserver(null);
        Logging.d(TAG, "stopScreenAudioCapture end");
        return 0;
    }

    public synchronized int startCapture(int requestCode, int resultCode, Intent intent) {
        Logging.d(TAG, "startCapture requestCode " + requestCode + ", resultCode " + resultCode);
        if (requestCode != 1001) {
            Logging.e(TAG, "Unknown request code: " + requestCode);
            onError(-1);
            return -1;
        }
        if (resultCode != -1) {
            Logging.e(TAG, "Screen Cast Permission Denied, resultCode: " + resultCode);
            stopCapture();
            onError(-1000);
            return -1;
        }
        if (intent == null) {
            Logging.e(TAG, "intent null");
            stopCapture();
            onError(-1);
            return -1;
        }
        if (!this.mCapturing) {
            Logging.e(TAG, "screen cast stoped");
            return -1;
        }
        this.mMediaProjectionPermissionResultData = intent;
        maybeStartScreenCastService();
        return 0;
    }

    private boolean isForegroundServiceNecessary() {
        ApplicationInfo applicationInfo;
        Context context = this.mContext;
        return context != null && (applicationInfo = context.getApplicationInfo()) != null && applicationInfo.targetSdkVersion >= 29 && Build.VERSION.SDK_INT >= 29;
    }

    private void maybeStartScreenCastService() {
        if (this.mMediaProjectionPermissionResultData == null) {
            Logging.d(TAG, "maybeStartScreenCastService request intent is null");
        }
        if (!isForegroundServiceNecessary()) {
            startScreenCaptureInternal();
        } else {
            startForegroundService();
        }
    }

    private void startForegroundService() {
        if (this.mContext == null) {
            Logging.d(TAG, "startForegroundService context null");
            return;
        }
        Logging.d(TAG, "startForegroundService");
        Intent intent = new Intent(this.mContext, (Class<?>) AndroidScreenCapService.class);
        if (Build.VERSION.SDK_INT >= 26) {
            try {
                this.mContext.startForegroundService(intent);
            } catch (Exception e) {
                e.printStackTrace();
                Logging.d(TAG, "startForegroundService failed");
            }
        } else {
            this.mContext.startService(intent);
        }
        this.mContext.bindService(intent, new ServiceConnection() { // from class: org.webrtc.mozi.JavaScreenCapturer.4
            @Override // android.content.ServiceConnection
            public void onServiceConnected(ComponentName name, IBinder service) {
                Logging.d(JavaScreenCapturer.TAG, "ForegroundService onServiceConnected");
                if (!JavaScreenCapturer.this.mCapturing) {
                    JavaScreenCapturer.this.stopForegroundService();
                } else {
                    JavaScreenCapturer.this.startScreenCaptureInternal();
                }
            }

            @Override // android.content.ServiceConnection
            public void onServiceDisconnected(ComponentName name) {
                Logging.d(JavaScreenCapturer.TAG, "ForegroundService onServiceDisconnected");
            }
        }, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stopForegroundService() {
        if (isForegroundServiceNecessary()) {
            Logging.d(TAG, "stopForegroundService");
            Context context = this.mContext;
            if (context == null) {
                return;
            }
            context.stopService(new Intent(this.mContext, (Class<?>) AndroidScreenCapService.class));
        }
    }

    public synchronized int stopCapture() {
        Logging.d(TAG, "stopCapture");
        stopScreenCapture();
        this.mCapturing = false;
        stopForegroundService();
        return 0;
    }

    public boolean isCapturing() {
        return this.mCapturing;
    }

    public void setEnableAudio(boolean enabled) {
        if (this.mAudioEnabled == enabled) {
            return;
        }
        Logging.d(TAG, "setEnableAudio " + enabled);
        if (enabled) {
            if (!isScreenCaptureAudioSupported()) {
                onError(-1002);
                return;
            }
            initScreenAudioCapture();
            if (this.mCapturing) {
                int ret = startScreenAudioCapture();
                Logging.d(TAG, "startScreenAudioCapture return " + ret);
            }
            this.mAudioEnabled = true;
            return;
        }
        if (this.mCapturing) {
            stopScreenAudioCapture();
        }
        this.mAudioEnabled = false;
    }

    public void dispose() {
        Logging.d(TAG, "dispose");
        if (this.mInitialized) {
            this.mContext.unregisterReceiver(this.mScreenOrientationRecevier);
        }
        ScreenCapturerAndroid screenCapturerAndroid = this.mScreenVideoCapturer;
        if (screenCapturerAndroid != null) {
            screenCapturerAndroid.dispose();
            this.mScreenVideoCapturer = null;
            this.mForceDeliver.stopDeliver();
        }
        SurfaceTextureHelper surfaceTextureHelper = this.mSurfaceTextureHelper;
        if (surfaceTextureHelper != null) {
            surfaceTextureHelper.dispose();
            this.mSurfaceTextureHelper = null;
        }
        this.mInitialized = false;
    }

    public void setForceDeliverEnabled(boolean enabled) {
        Logging.i(TAG, "setForceDeliverEnabled " + enabled);
        this.mForceDeliver.setEnabled(enabled);
    }

    public static int getScreenRotation(Context context) {
        WindowManager windowManager;
        Display display = sDisplay;
        if (display != null) {
            return display.getRotation() * 90;
        }
        if (context == null || (windowManager = (WindowManager) context.getApplicationContext().getSystemService("window")) == null) {
            return 0;
        }
        Display defaultDisplay = windowManager.getDefaultDisplay();
        sDisplay = defaultDisplay;
        return defaultDisplay.getRotation() * 90;
    }

    public static void getScreenResolution() {
        if (mScreenWidth == 0 || mScreenHeight == 0) {
            Context context = ContextUtils.getApplicationContext();
            WindowManager windowManager = (WindowManager) context.getSystemService("window");
            if (windowManager == null) {
                Logging.e(TAG, "getScreenWidth windowManager = null");
            }
            DisplayMetrics displayMetrics = new DisplayMetrics();
            windowManager.getDefaultDisplay().getMetrics(displayMetrics);
            mScreenWidth = displayMetrics.widthPixels;
            mScreenHeight = displayMetrics.heightPixels;
        }
    }

    public static int getScreenWidth() {
        getScreenResolution();
        return mScreenWidth;
    }

    public static int getScreenHeight() {
        getScreenResolution();
        return mScreenHeight;
    }

    public static class ScreenCaptureAssistantActivity extends Activity {
        public static JavaScreenCapturer mScreenShareControl;

        @Override // android.app.Activity
        public void onCreate(Bundle bundle) {
            super.onCreate(bundle);
            requestWindowFeature(1);
            JavaScreenCapturer javaScreenCapturer = mScreenShareControl;
            if (javaScreenCapturer == null) {
                Logging.e(JavaScreenCapturer.TAG, "ScreenCaptureAssistantActivity onCreate mScreenShareControl = null");
                return;
            }
            if (javaScreenCapturer.mMediaProjectManager == null) {
                mScreenShareControl.mMediaProjectManager = (MediaProjectionManager) getSystemService("media_projection");
            }
            if (mScreenShareControl.mMediaProjectManager == null) {
                Logging.e(JavaScreenCapturer.TAG, "ScreenCaptureAssistantActivity onCreate mMediaProjectManager = null");
                return;
            }
            try {
                startActivityForResult(mScreenShareControl.mMediaProjectManager.createScreenCaptureIntent(), 1001);
            } catch (ActivityNotFoundException e) {
                Logging.e(JavaScreenCapturer.TAG, "ScreenCaptureAssistantActivity onCreate MediaProjectionPermissionActivity not exist");
                processError(-1, "MediaProjectionPermissionActivity not exist");
            } catch (Exception e2) {
                Logging.e(JavaScreenCapturer.TAG, "ScreenCaptureAssistantActivity onCreate startActivityForResult error");
                processError(-1, "startActivityForResult");
            }
        }

        private void processError(int errorCode, String errorMsg) {
            Logging.e(JavaScreenCapturer.TAG, "ScreenCaptureAssistantActivity processError errorCode:" + errorCode + ", " + errorMsg);
            JavaScreenCapturer javaScreenCapturer = mScreenShareControl;
            if (javaScreenCapturer != null) {
                javaScreenCapturer.stopCapture();
            }
            mScreenShareControl = null;
            finish();
        }

        @Override // android.app.Activity
        public void onActivityResult(int requestCode, int resultCode, Intent intent) {
            JavaScreenCapturer javaScreenCapturer = mScreenShareControl;
            if (javaScreenCapturer != null) {
                javaScreenCapturer.startCapture(requestCode, resultCode, intent);
            }
            mScreenShareControl = null;
            finish();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onEvent(int eventId) {
        nativeOnEvent(this.mNativeHandler, eventId);
    }

    private void onError(int errorCode) {
        nativeOnError(this.mNativeHandler, errorCode);
    }

    private class ForceDeliver implements Runnable {
        private static final long STATISTIC_INTERVAL = 5000;
        private long mDeliverTimeStamp;
        private boolean mDelivering;
        private boolean mEnabled;
        private long mForceDeliverFrameCount;
        private long mLastStatisticTime;

        private ForceDeliver() {
        }

        public void setEnabled(boolean enabled) {
            this.mEnabled = enabled;
        }

        public boolean isEnabled() {
            return this.mEnabled;
        }

        public void stopDeliver() {
            if (JavaScreenCapturer.this.mSurfaceTextureHelper != null && JavaScreenCapturer.this.mSurfaceTextureHelper.getHandler() != null) {
                JavaScreenCapturer.this.mSurfaceTextureHelper.getHandler().removeCallbacks(this);
                this.mEnabled = false;
            }
        }

        public VideoFrame deliverFrame(VideoFrame frame) {
            if (!isEnabled()) {
                return frame;
            }
            VideoFrame deliverFrame = frame;
            if (this.mDelivering) {
                deliverFrame = new VideoFrame(frame.getBuffer(), frame.getRotation(), this.mDeliverTimeStamp);
            }
            if (deliverFrame != null && JavaScreenCapturer.this.mSurfaceTextureHelper != null && JavaScreenCapturer.this.mSurfaceTextureHelper.getHandler() != null) {
                JavaScreenCapturer.this.mSurfaceTextureHelper.getHandler().removeCallbacks(this);
                this.mDeliverTimeStamp = deliverFrame.getTimestampNs() + (JavaScreenCapturer.this.mForceDeliverIntervalMs * 1000 * 1000);
                JavaScreenCapturer.this.mSurfaceTextureHelper.getHandler().postDelayed(this, JavaScreenCapturer.this.mForceDeliverIntervalMs);
            }
            return deliverFrame;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (!isEnabled()) {
                return;
            }
            this.mDelivering = true;
            if (JavaScreenCapturer.this.mSurfaceTextureHelper != null) {
                JavaScreenCapturer.this.mSurfaceTextureHelper.deliverTextureFrame();
            }
            this.mForceDeliverFrameCount++;
            long time = System.currentTimeMillis();
            if (time - this.mLastStatisticTime > 5000) {
                Logging.w(JavaScreenCapturer.TAG, "force deliver frame counts " + this.mForceDeliverFrameCount);
                this.mForceDeliverFrameCount = 0L;
                this.mLastStatisticTime = time;
            }
            this.mDelivering = false;
        }
    }
}
