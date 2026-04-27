package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.ColorDrawable;
import android.media.AudioRecord;
import android.media.MediaCodec;
import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.net.Uri;
import android.opengl.EGL14;
import android.opengl.EGLExt;
import android.opengl.GLES20;
import android.opengl.GLUtils;
import android.opengl.Matrix;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import android.view.ViewOutlineProvider;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import com.google.android.exoplayer2.upstream.cache.CacheDataSink;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.messenger.camera.CameraController;
import im.uwrkaxlmjj.messenger.camera.CameraInfo;
import im.uwrkaxlmjj.messenger.camera.CameraSession;
import im.uwrkaxlmjj.messenger.video.MP4Builder;
import im.uwrkaxlmjj.messenger.video.Mp4Movie;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.VideoPlayer;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.ref.WeakReference;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import javax.microedition.khronos.egl.EGL10;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.egl.EGLContext;
import javax.microedition.khronos.egl.EGLDisplay;
import javax.microedition.khronos.egl.EGLSurface;
import javax.microedition.khronos.opengles.GL;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.EglBase;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class InstantCameraView extends FrameLayout implements NotificationCenter.NotificationCenterDelegate {
    private static final String FRAGMENT_SCREEN_SHADER = "#extension GL_OES_EGL_image_external : require\nprecision lowp float;\nvarying vec2 vTextureCoord;\nuniform samplerExternalOES sTexture;\nvoid main() {\n   gl_FragColor = texture2D(sTexture, vTextureCoord);\n}\n";
    private static final String FRAGMENT_SHADER = "#extension GL_OES_EGL_image_external : require\nprecision highp float;\nvarying vec2 vTextureCoord;\nuniform float scaleX;\nuniform float scaleY;\nuniform float alpha;\nuniform samplerExternalOES sTexture;\nvoid main() {\n   vec2 coord = vec2((vTextureCoord.x - 0.5) * scaleX, (vTextureCoord.y - 0.5) * scaleY);\n   float coef = ceil(clamp(0.2601 - dot(coord, coord), 0.0, 1.0));\n   vec3 color = texture2D(sTexture, vTextureCoord).rgb * coef + (1.0 - step(0.001, coef));\n   gl_FragColor = vec4(color * alpha, alpha);\n}\n";
    private static final int MSG_AUDIOFRAME_AVAILABLE = 3;
    private static final int MSG_START_RECORDING = 0;
    private static final int MSG_STOP_RECORDING = 1;
    private static final int MSG_VIDEOFRAME_AVAILABLE = 2;
    private static final String VERTEX_SHADER = "uniform mat4 uMVPMatrix;\nuniform mat4 uSTMatrix;\nattribute vec4 aPosition;\nattribute vec4 aTextureCoord;\nvarying vec2 vTextureCoord;\nvoid main() {\n   gl_Position = uMVPMatrix * aPosition;\n   vTextureCoord = (uSTMatrix * aTextureCoord).xy;\n}\n";
    private AnimatorSet animatorSet;
    private im.uwrkaxlmjj.messenger.camera.Size aspectRatio;
    private ChatActivity baseFragment;
    private FrameLayout cameraContainer;
    private File cameraFile;
    private volatile boolean cameraReady;
    private CameraSession cameraSession;
    private int[] cameraTexture;
    private float cameraTextureAlpha;
    private CameraGLThread cameraThread;
    private boolean cancelled;
    private int currentAccount;
    private boolean deviceHasGoodCamera;
    private long duration;
    private TLRPC.InputEncryptedFile encryptedFile;
    private TLRPC.InputFile file;
    private boolean isFrontface;
    private boolean isSecretChat;
    private byte[] iv;
    private byte[] key;
    private Bitmap lastBitmap;
    private float[] mMVPMatrix;
    private float[] mSTMatrix;
    private float[] moldSTMatrix;
    private AnimatorSet muteAnimation;
    private ImageView muteImageView;
    private int[] oldCameraTexture;
    private Paint paint;
    private im.uwrkaxlmjj.messenger.camera.Size pictureSize;
    private int[] position;
    private im.uwrkaxlmjj.messenger.camera.Size previewSize;
    private float progress;
    private Timer progressTimer;
    private long recordStartTime;
    private long recordedTime;
    private boolean recording;
    private int recordingGuid;
    private RectF rect;
    private boolean requestingPermissions;
    private float scaleX;
    private float scaleY;
    private CameraInfo selectedCamera;
    private long size;
    private ImageView switchCameraButton;
    private FloatBuffer textureBuffer;
    private BackupImageView textureOverlayView;
    private TextureView textureView;
    private Runnable timerRunnable;
    private FloatBuffer vertexBuffer;
    private VideoEditedInfo videoEditedInfo;
    private VideoPlayer videoPlayer;

    public InstantCameraView(Context context, ChatActivity parentFragment) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        int i = 1;
        this.isFrontface = true;
        this.position = new int[2];
        this.cameraTexture = new int[1];
        this.oldCameraTexture = new int[1];
        this.cameraTextureAlpha = 1.0f;
        this.timerRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.1
            @Override // java.lang.Runnable
            public void run() {
                if (InstantCameraView.this.recording) {
                    NotificationCenter.getInstance(InstantCameraView.this.currentAccount).postNotificationName(NotificationCenter.recordProgressChanged, Integer.valueOf(InstantCameraView.this.recordingGuid), Long.valueOf(InstantCameraView.this.duration = System.currentTimeMillis() - InstantCameraView.this.recordStartTime), Double.valueOf(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE));
                    AndroidUtilities.runOnUIThread(InstantCameraView.this.timerRunnable, 50L);
                }
            }
        };
        this.aspectRatio = SharedConfig.roundCamera16to9 ? new im.uwrkaxlmjj.messenger.camera.Size(16, 9) : new im.uwrkaxlmjj.messenger.camera.Size(4, 3);
        this.mMVPMatrix = new float[16];
        this.mSTMatrix = new float[16];
        this.moldSTMatrix = new float[16];
        setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$bBzlt4xTVphzDzi24RKWTAFFiDA
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return this.f$0.lambda$new$0$InstantCameraView(view, motionEvent);
            }
        });
        setWillNotDraw(false);
        setBackgroundColor(-1073741824);
        this.baseFragment = parentFragment;
        this.recordingGuid = parentFragment.getClassGuid();
        this.isSecretChat = this.baseFragment.getCurrentEncryptedChat() != null;
        Paint paint = new Paint(i) { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.3
            @Override // android.graphics.Paint
            public void setAlpha(int a) {
                super.setAlpha(a);
                InstantCameraView.this.invalidate();
            }
        };
        this.paint = paint;
        paint.setStyle(Paint.Style.STROKE);
        this.paint.setStrokeCap(Paint.Cap.ROUND);
        this.paint.setStrokeWidth(AndroidUtilities.dp(3.0f));
        this.paint.setColor(-1);
        this.rect = new RectF();
        if (Build.VERSION.SDK_INT >= 21) {
            FrameLayout frameLayout = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.4
                @Override // android.view.View
                public void setScaleX(float scaleX) {
                    super.setScaleX(scaleX);
                    InstantCameraView.this.invalidate();
                }

                @Override // android.view.View
                public void setAlpha(float alpha) {
                    super.setAlpha(alpha);
                    InstantCameraView.this.invalidate();
                }
            };
            this.cameraContainer = frameLayout;
            frameLayout.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.5
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.roundMessageSize, AndroidUtilities.roundMessageSize);
                }
            });
            this.cameraContainer.setClipToOutline(true);
            this.cameraContainer.setWillNotDraw(false);
        } else {
            final Path path = new Path();
            final Paint paint2 = new Paint(1);
            paint2.setColor(-16777216);
            paint2.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
            FrameLayout frameLayout2 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.6
                @Override // android.view.View
                public void setScaleX(float scaleX) {
                    super.setScaleX(scaleX);
                    InstantCameraView.this.invalidate();
                }

                @Override // android.view.View
                protected void onSizeChanged(int w, int h, int oldw, int oldh) {
                    super.onSizeChanged(w, h, oldw, oldh);
                    path.reset();
                    path.addCircle(w / 2, h / 2, w / 2, Path.Direction.CW);
                    path.toggleInverseFillType();
                }

                @Override // android.view.ViewGroup, android.view.View
                protected void dispatchDraw(Canvas canvas) {
                    try {
                        super.dispatchDraw(canvas);
                        canvas.drawPath(path, paint2);
                    } catch (Exception e) {
                    }
                }
            };
            this.cameraContainer = frameLayout2;
            frameLayout2.setWillNotDraw(false);
            this.cameraContainer.setLayerType(2, null);
        }
        addView(this.cameraContainer, new FrameLayout.LayoutParams(AndroidUtilities.roundMessageSize, AndroidUtilities.roundMessageSize, 17));
        ImageView imageView = new ImageView(context);
        this.switchCameraButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.switchCameraButton.setContentDescription(LocaleController.getString("AccDescrSwitchCamera", R.string.AccDescrSwitchCamera));
        addView(this.switchCameraButton, LayoutHelper.createFrame(48.0f, 48.0f, 83, 20.0f, 0.0f, 0.0f, 14.0f));
        this.switchCameraButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$YEgdlGglE3CknK0lsymsDlbQ29s
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$1$InstantCameraView(view);
            }
        });
        ImageView imageView2 = new ImageView(context);
        this.muteImageView = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        this.muteImageView.setImageResource(R.drawable.video_mute);
        this.muteImageView.setAlpha(0.0f);
        addView(this.muteImageView, LayoutHelper.createFrame(48, 48, 17));
        ((FrameLayout.LayoutParams) this.muteImageView.getLayoutParams()).topMargin = (AndroidUtilities.roundMessageSize / 2) - AndroidUtilities.dp(24.0f);
        BackupImageView backupImageView = new BackupImageView(getContext());
        this.textureOverlayView = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.roundMessageSize / 2);
        addView(this.textureOverlayView, new FrameLayout.LayoutParams(AndroidUtilities.roundMessageSize, AndroidUtilities.roundMessageSize, 17));
        setVisibility(4);
    }

    public /* synthetic */ boolean lambda$new$0$InstantCameraView(View v, MotionEvent event) {
        ChatActivity chatActivity;
        if (event.getAction() == 0 && (chatActivity = this.baseFragment) != null) {
            VideoPlayer videoPlayer = this.videoPlayer;
            if (videoPlayer != null) {
                boolean mute = !videoPlayer.isMuted();
                this.videoPlayer.setMute(mute);
                AnimatorSet animatorSet = this.muteAnimation;
                if (animatorSet != null) {
                    animatorSet.cancel();
                }
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.muteAnimation = animatorSet2;
                Animator[] animatorArr = new Animator[3];
                ImageView imageView = this.muteImageView;
                float[] fArr = new float[1];
                fArr[0] = mute ? 1.0f : 0.0f;
                animatorArr[0] = ObjectAnimator.ofFloat(imageView, "alpha", fArr);
                ImageView imageView2 = this.muteImageView;
                float[] fArr2 = new float[1];
                fArr2[0] = mute ? 1.0f : 0.5f;
                animatorArr[1] = ObjectAnimator.ofFloat(imageView2, "scaleX", fArr2);
                ImageView imageView3 = this.muteImageView;
                float[] fArr3 = new float[1];
                fArr3[0] = mute ? 1.0f : 0.5f;
                animatorArr[2] = ObjectAnimator.ofFloat(imageView3, "scaleY", fArr3);
                animatorSet2.playTogether(animatorArr);
                this.muteAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.2
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(InstantCameraView.this.muteAnimation)) {
                            InstantCameraView.this.muteAnimation = null;
                        }
                    }
                });
                this.muteAnimation.setDuration(180L);
                this.muteAnimation.setInterpolator(new DecelerateInterpolator());
                this.muteAnimation.start();
            } else {
                chatActivity.checkRecordLocked();
            }
        }
        return true;
    }

    public /* synthetic */ void lambda$new$1$InstantCameraView(View v) {
        CameraSession cameraSession;
        if (!this.cameraReady || (cameraSession = this.cameraSession) == null || !cameraSession.isInitied() || this.cameraThread == null) {
            return;
        }
        switchCamera();
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.switchCameraButton, "scaleX", 0.0f).setDuration(100L);
        animator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.7
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator2) {
                InstantCameraView.this.switchCameraButton.setImageResource(InstantCameraView.this.isFrontface ? R.drawable.camera_revert1 : R.drawable.camera_revert2);
                ObjectAnimator.ofFloat(InstantCameraView.this.switchCameraButton, "scaleX", 1.0f).setDuration(100L).start();
            }
        });
        animator.start();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        getParent().requestDisallowInterceptTouchEvent(true);
        return super.onInterceptTouchEvent(ev);
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        if (getVisibility() != 0) {
            this.cameraContainer.setTranslationY(getMeasuredHeight() / 2);
            this.textureOverlayView.setTranslationY(getMeasuredHeight() / 2);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordProgressChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidUpload);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordProgressChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidUpload);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.recordProgressChanged) {
            int guid = ((Integer) args[0]).intValue();
            if (guid != this.recordingGuid) {
                return;
            }
            long t = ((Long) args[1]).longValue();
            this.progress = t / 60000.0f;
            this.recordedTime = t;
            invalidate();
            return;
        }
        if (id == NotificationCenter.FileDidUpload) {
            String location = (String) args[0];
            File file = this.cameraFile;
            if (file != null && file.getAbsolutePath().equals(location)) {
                this.file = (TLRPC.InputFile) args[1];
                this.encryptedFile = (TLRPC.InputEncryptedFile) args[2];
                this.size = ((Long) args[5]).longValue();
                if (this.encryptedFile != null) {
                    this.key = (byte[]) args[3];
                    this.iv = (byte[]) args[4];
                }
            }
        }
    }

    public void destroy(boolean async, Runnable beforeDestroyRunnable) {
        CameraSession cameraSession = this.cameraSession;
        if (cameraSession != null) {
            cameraSession.destroy();
            CameraController.getInstance().close(this.cameraSession, !async ? new CountDownLatch(1) : null, beforeDestroyRunnable);
        }
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        float x = this.cameraContainer.getX();
        float y = this.cameraContainer.getY();
        this.rect.set(x - AndroidUtilities.dp(8.0f), y - AndroidUtilities.dp(8.0f), this.cameraContainer.getMeasuredWidth() + x + AndroidUtilities.dp(8.0f), this.cameraContainer.getMeasuredHeight() + y + AndroidUtilities.dp(8.0f));
        float f = this.progress;
        if (f != 0.0f) {
            canvas.drawArc(this.rect, -90.0f, f * 360.0f, false, this.paint);
        }
        if (Theme.chat_roundVideoShadow != null) {
            int x1 = ((int) x) - AndroidUtilities.dp(3.0f);
            int y1 = ((int) y) - AndroidUtilities.dp(2.0f);
            canvas.save();
            canvas.scale(this.cameraContainer.getScaleX(), this.cameraContainer.getScaleY(), (AndroidUtilities.roundMessageSize / 2) + x1 + AndroidUtilities.dp(3.0f), (AndroidUtilities.roundMessageSize / 2) + y1 + AndroidUtilities.dp(3.0f));
            Theme.chat_roundVideoShadow.setAlpha((int) (this.cameraContainer.getAlpha() * 255.0f));
            Theme.chat_roundVideoShadow.setBounds(x1, y1, AndroidUtilities.roundMessageSize + x1 + AndroidUtilities.dp(6.0f), AndroidUtilities.roundMessageSize + y1 + AndroidUtilities.dp(6.0f));
            Theme.chat_roundVideoShadow.draw(canvas);
            canvas.restore();
        }
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        setAlpha(0.0f);
        this.switchCameraButton.setAlpha(0.0f);
        this.cameraContainer.setAlpha(0.0f);
        this.textureOverlayView.setAlpha(0.0f);
        this.muteImageView.setAlpha(0.0f);
        this.muteImageView.setScaleX(1.0f);
        this.muteImageView.setScaleY(1.0f);
        this.cameraContainer.setScaleX(0.1f);
        this.cameraContainer.setScaleY(0.1f);
        this.textureOverlayView.setScaleX(0.1f);
        this.textureOverlayView.setScaleY(0.1f);
        if (this.cameraContainer.getMeasuredWidth() != 0) {
            this.cameraContainer.setPivotX(r0.getMeasuredWidth() / 2);
            this.cameraContainer.setPivotY(r0.getMeasuredHeight() / 2);
            this.textureOverlayView.setPivotX(r0.getMeasuredWidth() / 2);
            this.textureOverlayView.setPivotY(r0.getMeasuredHeight() / 2);
        }
        try {
            if (visibility == 0) {
                ((Activity) getContext()).getWindow().addFlags(128);
            } else {
                ((Activity) getContext()).getWindow().clearFlags(128);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void showCamera() {
        if (this.textureView != null) {
            return;
        }
        this.switchCameraButton.setImageResource(R.drawable.camera_revert1);
        this.textureOverlayView.setAlpha(1.0f);
        if (this.lastBitmap == null) {
            try {
                File file = new File(ApplicationLoader.getFilesDirFixed(), "icthumb.jpg");
                this.lastBitmap = BitmapFactory.decodeFile(file.getAbsolutePath());
            } catch (Throwable th) {
            }
        }
        Bitmap bitmap = this.lastBitmap;
        if (bitmap != null) {
            this.textureOverlayView.setImageBitmap(bitmap);
        } else {
            this.textureOverlayView.setImageResource(R.drawable.icplaceholder);
        }
        this.cameraReady = false;
        this.isFrontface = true;
        this.selectedCamera = null;
        this.recordedTime = 0L;
        this.progress = 0.0f;
        this.cancelled = false;
        this.file = null;
        this.encryptedFile = null;
        this.key = null;
        this.iv = null;
        if (!initCamera()) {
            return;
        }
        MediaController.getInstance().lambda$startAudioAgain$5$MediaController(MediaController.getInstance().getPlayingMessageObject());
        this.cameraFile = new File(FileLoader.getDirectory(4), SharedConfig.getLastLocalId() + ".mp4");
        SharedConfig.saveConfig();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("show round camera");
        }
        TextureView textureView = new TextureView(getContext());
        this.textureView = textureView;
        textureView.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.8
            @Override // android.view.TextureView.SurfaceTextureListener
            public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("camera surface available");
                }
                if (InstantCameraView.this.cameraThread != null || surface == null || InstantCameraView.this.cancelled) {
                    return;
                }
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("start create thread");
                }
                InstantCameraView.this.cameraThread = InstantCameraView.this.new CameraGLThread(surface, width, height);
            }

            @Override // android.view.TextureView.SurfaceTextureListener
            public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
            }

            @Override // android.view.TextureView.SurfaceTextureListener
            public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
                if (InstantCameraView.this.cameraThread != null) {
                    InstantCameraView.this.cameraThread.shutdown(0);
                    InstantCameraView.this.cameraThread = null;
                }
                if (InstantCameraView.this.cameraSession != null) {
                    CameraController.getInstance().close(InstantCameraView.this.cameraSession, null, null);
                    return true;
                }
                return true;
            }

            @Override // android.view.TextureView.SurfaceTextureListener
            public void onSurfaceTextureUpdated(SurfaceTexture surface) {
            }
        });
        this.cameraContainer.addView(this.textureView, LayoutHelper.createFrame(-1, -1.0f));
        setVisibility(0);
        startAnimation(true);
    }

    public FrameLayout getCameraContainer() {
        return this.cameraContainer;
    }

    public void startAnimation(boolean open) {
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        PipRoundVideoView pipRoundVideoView = PipRoundVideoView.getInstance();
        if (pipRoundVideoView != null) {
            pipRoundVideoView.showTemporary(!open);
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.animatorSet = animatorSet2;
        Animator[] animatorArr = new Animator[12];
        float[] fArr = new float[1];
        fArr[0] = open ? 1.0f : 0.0f;
        animatorArr[0] = ObjectAnimator.ofFloat(this, "alpha", fArr);
        ImageView imageView = this.switchCameraButton;
        float[] fArr2 = new float[1];
        fArr2[0] = open ? 1.0f : 0.0f;
        animatorArr[1] = ObjectAnimator.ofFloat(imageView, "alpha", fArr2);
        animatorArr[2] = ObjectAnimator.ofFloat(this.muteImageView, "alpha", 0.0f);
        Paint paint = this.paint;
        int[] iArr = new int[1];
        iArr[0] = open ? 255 : 0;
        animatorArr[3] = ObjectAnimator.ofInt(paint, "alpha", iArr);
        FrameLayout frameLayout = this.cameraContainer;
        float[] fArr3 = new float[1];
        fArr3[0] = open ? 1.0f : 0.0f;
        animatorArr[4] = ObjectAnimator.ofFloat(frameLayout, "alpha", fArr3);
        FrameLayout frameLayout2 = this.cameraContainer;
        float[] fArr4 = new float[1];
        fArr4[0] = open ? 1.0f : 0.1f;
        animatorArr[5] = ObjectAnimator.ofFloat(frameLayout2, "scaleX", fArr4);
        FrameLayout frameLayout3 = this.cameraContainer;
        float[] fArr5 = new float[1];
        fArr5[0] = open ? 1.0f : 0.1f;
        animatorArr[6] = ObjectAnimator.ofFloat(frameLayout3, "scaleY", fArr5);
        FrameLayout frameLayout4 = this.cameraContainer;
        float[] fArr6 = new float[2];
        fArr6[0] = open ? getMeasuredHeight() / 2 : 0.0f;
        fArr6[1] = open ? 0.0f : getMeasuredHeight() / 2;
        animatorArr[7] = ObjectAnimator.ofFloat(frameLayout4, "translationY", fArr6);
        BackupImageView backupImageView = this.textureOverlayView;
        float[] fArr7 = new float[1];
        fArr7[0] = open ? 1.0f : 0.0f;
        animatorArr[8] = ObjectAnimator.ofFloat(backupImageView, "alpha", fArr7);
        BackupImageView backupImageView2 = this.textureOverlayView;
        float[] fArr8 = new float[1];
        fArr8[0] = open ? 1.0f : 0.1f;
        animatorArr[9] = ObjectAnimator.ofFloat(backupImageView2, "scaleX", fArr8);
        BackupImageView backupImageView3 = this.textureOverlayView;
        float[] fArr9 = new float[1];
        fArr9[0] = open ? 1.0f : 0.1f;
        animatorArr[10] = ObjectAnimator.ofFloat(backupImageView3, "scaleY", fArr9);
        BackupImageView backupImageView4 = this.textureOverlayView;
        float[] fArr10 = new float[2];
        fArr10[0] = open ? getMeasuredHeight() / 2 : 0.0f;
        fArr10[1] = open ? 0.0f : getMeasuredHeight() / 2;
        animatorArr[11] = ObjectAnimator.ofFloat(backupImageView4, "translationY", fArr10);
        animatorSet2.playTogether(animatorArr);
        if (!open) {
            this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.9
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(InstantCameraView.this.animatorSet)) {
                        InstantCameraView.this.hideCamera(true);
                        InstantCameraView.this.setVisibility(4);
                    }
                }
            });
        }
        this.animatorSet.setDuration(180L);
        this.animatorSet.setInterpolator(new DecelerateInterpolator());
        this.animatorSet.start();
    }

    public Rect getCameraRect() {
        this.cameraContainer.getLocationOnScreen(this.position);
        int[] iArr = this.position;
        return new Rect(iArr[0], iArr[1], this.cameraContainer.getWidth(), this.cameraContainer.getHeight());
    }

    public void changeVideoPreviewState(int state, float progress) {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer == null) {
            return;
        }
        if (state == 0) {
            startProgressTimer();
            this.videoPlayer.play();
        } else if (state == 1) {
            stopProgressTimer();
            this.videoPlayer.pause();
        } else if (state == 2) {
            videoPlayer.seekTo((long) (videoPlayer.getDuration() * progress));
        }
    }

    public void send(int state, boolean notify, int scheduleDate) {
        int send;
        if (this.textureView == null) {
            return;
        }
        stopProgressTimer();
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.releasePlayer(true);
            this.videoPlayer = null;
        }
        if (state != 4) {
            this.cancelled = this.recordedTime < 800;
            this.recording = false;
            AndroidUtilities.cancelRunOnUIThread(this.timerRunnable);
            if (this.cameraThread != null) {
                NotificationCenter notificationCenter = NotificationCenter.getInstance(this.currentAccount);
                int i = NotificationCenter.recordStopped;
                Object[] objArr = new Object[2];
                objArr[0] = Integer.valueOf(this.recordingGuid);
                objArr[1] = Integer.valueOf((this.cancelled || state != 3) ? 0 : 2);
                notificationCenter.postNotificationName(i, objArr);
                if (this.cancelled) {
                    send = 0;
                } else if (state == 3) {
                    send = 2;
                } else {
                    send = 1;
                }
                saveLastCameraBitmap();
                this.cameraThread.shutdown(send);
                this.cameraThread = null;
            }
            if (this.cancelled) {
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.audioRecordTooShort, Integer.valueOf(this.recordingGuid), true);
                startAnimation(false);
                return;
            }
            return;
        }
        if (!this.videoEditedInfo.needConvert()) {
            this.videoEditedInfo.estimatedSize = Math.max(1L, this.size);
        } else {
            this.file = null;
            this.encryptedFile = null;
            this.key = null;
            this.iv = null;
            double totalDuration = this.videoEditedInfo.estimatedDuration;
            long startTime = this.videoEditedInfo.startTime >= 0 ? this.videoEditedInfo.startTime : 0L;
            long endTime = this.videoEditedInfo.endTime >= 0 ? this.videoEditedInfo.endTime : this.videoEditedInfo.estimatedDuration;
            this.videoEditedInfo.estimatedDuration = endTime - startTime;
            this.videoEditedInfo.estimatedSize = Math.max(1L, (long) (this.size * (r5.estimatedDuration / totalDuration)));
            this.videoEditedInfo.bitrate = 400000;
            if (this.videoEditedInfo.startTime > 0) {
                this.videoEditedInfo.startTime *= 1000;
            }
            if (this.videoEditedInfo.endTime > 0) {
                this.videoEditedInfo.endTime *= 1000;
            }
            FileLoader.getInstance(this.currentAccount).cancelUploadFile(this.cameraFile.getAbsolutePath(), false);
        }
        this.videoEditedInfo.file = this.file;
        this.videoEditedInfo.encryptedFile = this.encryptedFile;
        this.videoEditedInfo.key = this.key;
        this.videoEditedInfo.iv = this.iv;
        this.baseFragment.sendMedia(new MediaController.PhotoEntry(0, 0, 0L, this.cameraFile.getAbsolutePath(), 0, true), this.videoEditedInfo, notify, scheduleDate);
        if (scheduleDate != 0) {
            startAnimation(false);
        }
    }

    private void saveLastCameraBitmap() {
        Bitmap bitmap = this.textureView.getBitmap();
        if (bitmap != null) {
            Bitmap bitmapCreateScaledBitmap = Bitmap.createScaledBitmap(this.textureView.getBitmap(), 80, 80, true);
            this.lastBitmap = bitmapCreateScaledBitmap;
            if (bitmapCreateScaledBitmap != null) {
                Utilities.blurBitmap(bitmapCreateScaledBitmap, 7, 1, bitmapCreateScaledBitmap.getWidth(), this.lastBitmap.getHeight(), this.lastBitmap.getRowBytes());
                try {
                    File file = new File(ApplicationLoader.getFilesDirFixed(), "icthumb.jpg");
                    FileOutputStream stream = new FileOutputStream(file);
                    this.lastBitmap.compress(Bitmap.CompressFormat.JPEG, 87, stream);
                } catch (Throwable th) {
                }
            }
        }
    }

    public void cancel() {
        stopProgressTimer();
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.releasePlayer(true);
            this.videoPlayer = null;
        }
        if (this.textureView == null) {
            return;
        }
        this.cancelled = true;
        this.recording = false;
        AndroidUtilities.cancelRunOnUIThread(this.timerRunnable);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.recordStopped, Integer.valueOf(this.recordingGuid), 0);
        if (this.cameraThread != null) {
            saveLastCameraBitmap();
            this.cameraThread.shutdown(0);
            this.cameraThread = null;
        }
        File file = this.cameraFile;
        if (file != null) {
            file.delete();
            this.cameraFile = null;
        }
        startAnimation(false);
    }

    @Override // android.view.View
    public void setAlpha(float alpha) {
        ColorDrawable colorDrawable = (ColorDrawable) getBackground();
        colorDrawable.setAlpha((int) (192.0f * alpha));
        invalidate();
    }

    public View getSwitchButtonView() {
        return this.switchCameraButton;
    }

    public View getMuteImageView() {
        return this.muteImageView;
    }

    public Paint getPaint() {
        return this.paint;
    }

    public void hideCamera(boolean async) {
        destroy(async, null);
        this.cameraContainer.removeView(this.textureView);
        this.cameraContainer.setTranslationX(0.0f);
        this.cameraContainer.setTranslationY(0.0f);
        this.textureOverlayView.setTranslationX(0.0f);
        this.textureOverlayView.setTranslationY(0.0f);
        this.textureView = null;
    }

    private void switchCamera() {
        saveLastCameraBitmap();
        Bitmap bitmap = this.lastBitmap;
        if (bitmap != null) {
            this.textureOverlayView.setImageBitmap(bitmap);
            this.textureOverlayView.animate().setDuration(120L).alpha(1.0f).setInterpolator(new DecelerateInterpolator()).start();
        }
        CameraSession cameraSession = this.cameraSession;
        if (cameraSession != null) {
            cameraSession.destroy();
            CameraController.getInstance().close(this.cameraSession, null, null);
            this.cameraSession = null;
        }
        this.isFrontface = !this.isFrontface;
        initCamera();
        this.cameraReady = false;
        this.cameraThread.reinitForNewCamera();
    }

    private boolean initCamera() {
        ArrayList<CameraInfo> cameraInfos = CameraController.getInstance().getCameras();
        if (cameraInfos == null) {
            return false;
        }
        CameraInfo notFrontface = null;
        for (int a = 0; a < cameraInfos.size(); a++) {
            CameraInfo cameraInfo = cameraInfos.get(a);
            if (!cameraInfo.isFrontface()) {
                notFrontface = cameraInfo;
            }
            if ((this.isFrontface && cameraInfo.isFrontface()) || (!this.isFrontface && !cameraInfo.isFrontface())) {
                this.selectedCamera = cameraInfo;
                break;
            }
            notFrontface = cameraInfo;
        }
        if (this.selectedCamera == null) {
            this.selectedCamera = notFrontface;
        }
        CameraInfo cameraInfo2 = this.selectedCamera;
        if (cameraInfo2 == null) {
            return false;
        }
        ArrayList<im.uwrkaxlmjj.messenger.camera.Size> previewSizes = cameraInfo2.getPreviewSizes();
        ArrayList<im.uwrkaxlmjj.messenger.camera.Size> pictureSizes = this.selectedCamera.getPictureSizes();
        this.previewSize = CameraController.chooseOptimalSize(previewSizes, 480, JavaScreenCapturer.DEGREE_270, this.aspectRatio);
        this.pictureSize = CameraController.chooseOptimalSize(pictureSizes, 480, JavaScreenCapturer.DEGREE_270, this.aspectRatio);
        if (this.previewSize.mWidth != this.pictureSize.mWidth) {
            boolean found = false;
            for (int a2 = previewSizes.size() - 1; a2 >= 0; a2--) {
                im.uwrkaxlmjj.messenger.camera.Size preview = previewSizes.get(a2);
                int b = pictureSizes.size() - 1;
                while (true) {
                    if (b < 0) {
                        break;
                    }
                    im.uwrkaxlmjj.messenger.camera.Size picture = pictureSizes.get(b);
                    if (preview.mWidth >= this.pictureSize.mWidth && preview.mHeight >= this.pictureSize.mHeight && preview.mWidth == picture.mWidth && preview.mHeight == picture.mHeight) {
                        this.previewSize = preview;
                        this.pictureSize = picture;
                        found = true;
                        break;
                    }
                    b--;
                }
                if (found) {
                    break;
                }
            }
            if (!found) {
                for (int a3 = previewSizes.size() - 1; a3 >= 0; a3--) {
                    im.uwrkaxlmjj.messenger.camera.Size preview2 = previewSizes.get(a3);
                    int b2 = pictureSizes.size() - 1;
                    while (true) {
                        if (b2 < 0) {
                            break;
                        }
                        im.uwrkaxlmjj.messenger.camera.Size picture2 = pictureSizes.get(b2);
                        if (preview2.mWidth >= 240 && preview2.mHeight >= 240 && preview2.mWidth == picture2.mWidth && preview2.mHeight == picture2.mHeight) {
                            this.previewSize = preview2;
                            this.pictureSize = picture2;
                            found = true;
                            break;
                        }
                        b2--;
                    }
                    if (found) {
                        break;
                    }
                }
            }
        }
        boolean found2 = BuildVars.LOGS_ENABLED;
        if (found2) {
            FileLog.d("preview w = " + this.previewSize.mWidth + " h = " + this.previewSize.mHeight);
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createCamera(final SurfaceTexture surfaceTexture) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$uLojUJhoY2B5G0MoF7oaFuPOOzg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createCamera$4$InstantCameraView(surfaceTexture);
            }
        });
    }

    public /* synthetic */ void lambda$createCamera$4$InstantCameraView(SurfaceTexture surfaceTexture) {
        if (this.cameraThread == null) {
            return;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("create camera session");
        }
        surfaceTexture.setDefaultBufferSize(this.previewSize.getWidth(), this.previewSize.getHeight());
        CameraSession cameraSession = new CameraSession(this.selectedCamera, this.previewSize, this.pictureSize, 256);
        this.cameraSession = cameraSession;
        this.cameraThread.setCurrentSession(cameraSession);
        CameraController.getInstance().openRound(this.cameraSession, surfaceTexture, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$mdll6ZTxifuFmpBET3dcF1YVok8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$InstantCameraView();
            }
        }, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$Xonigr2bof9D4_f51c8ftVhqWSc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$InstantCameraView();
            }
        });
    }

    public /* synthetic */ void lambda$null$2$InstantCameraView() {
        if (this.cameraSession != null) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("camera initied");
            }
            this.cameraSession.setInitied();
        }
    }

    public /* synthetic */ void lambda$null$3$InstantCameraView() {
        this.cameraThread.setCurrentSession(this.cameraSession);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int loadShader(int type, String shaderCode) {
        int shader = GLES20.glCreateShader(type);
        GLES20.glShaderSource(shader, shaderCode);
        GLES20.glCompileShader(shader);
        int[] compileStatus = new int[1];
        GLES20.glGetShaderiv(shader, 35713, compileStatus, 0);
        if (compileStatus[0] == 0) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e(GLES20.glGetShaderInfoLog(shader));
            }
            GLES20.glDeleteShader(shader);
            return 0;
        }
        return shader;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startProgressTimer() {
        Timer timer = this.progressTimer;
        if (timer != null) {
            try {
                timer.cancel();
                this.progressTimer = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        Timer timer2 = new Timer();
        this.progressTimer = timer2;
        timer2.schedule(new AnonymousClass10(), 0L, 17L);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.InstantCameraView$10, reason: invalid class name */
    class AnonymousClass10 extends TimerTask {
        AnonymousClass10() {
        }

        @Override // java.util.TimerTask, java.lang.Runnable
        public void run() {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$10$boFL3g-Hi3-YDjp8PVlThbTghZo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$run$0$InstantCameraView$10();
                }
            });
        }

        public /* synthetic */ void lambda$run$0$InstantCameraView$10() {
            try {
                if (InstantCameraView.this.videoPlayer == null || InstantCameraView.this.videoEditedInfo == null) {
                    return;
                }
                if (InstantCameraView.this.videoEditedInfo.endTime > 0 && InstantCameraView.this.videoPlayer.getCurrentPosition() >= InstantCameraView.this.videoEditedInfo.endTime) {
                    InstantCameraView.this.videoPlayer.seekTo(InstantCameraView.this.videoEditedInfo.startTime > 0 ? InstantCameraView.this.videoEditedInfo.startTime : 0L);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    private void stopProgressTimer() {
        Timer timer = this.progressTimer;
        if (timer != null) {
            try {
                timer.cancel();
                this.progressTimer = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public class CameraGLThread extends DispatchQueue {
        private final int DO_REINIT_MESSAGE;
        private final int DO_RENDER_MESSAGE;
        private final int DO_SETSESSION_MESSAGE;
        private final int DO_SHUTDOWN_MESSAGE;
        private final int EGL_CONTEXT_CLIENT_VERSION;
        private final int EGL_OPENGL_ES2_BIT;
        private Integer cameraId;
        private SurfaceTexture cameraSurface;
        private CameraSession currentSession;
        private int drawProgram;
        private EGL10 egl10;
        private EGLConfig eglConfig;
        private EGLContext eglContext;
        private EGLDisplay eglDisplay;
        private EGLSurface eglSurface;
        private GL gl;
        private boolean initied;
        private int positionHandle;
        private boolean recording;
        private int rotationAngle;
        private SurfaceTexture surfaceTexture;
        private int textureHandle;
        private int textureMatrixHandle;
        private int vertexMatrixHandle;
        private VideoRecorder videoEncoder;

        public CameraGLThread(SurfaceTexture surface, int surfaceWidth, int surfaceHeight) {
            super("CameraGLThread");
            this.EGL_CONTEXT_CLIENT_VERSION = 12440;
            this.EGL_OPENGL_ES2_BIT = 4;
            this.DO_RENDER_MESSAGE = 0;
            this.DO_SHUTDOWN_MESSAGE = 1;
            this.DO_REINIT_MESSAGE = 2;
            this.DO_SETSESSION_MESSAGE = 3;
            this.cameraId = 0;
            this.surfaceTexture = surface;
            int width = InstantCameraView.this.previewSize.getWidth();
            int height = InstantCameraView.this.previewSize.getHeight();
            float scale = surfaceWidth / Math.min(width, height);
            int width2 = (int) (width * scale);
            int height2 = (int) (height * scale);
            if (width2 > height2) {
                InstantCameraView.this.scaleX = 1.0f;
                InstantCameraView.this.scaleY = width2 / surfaceHeight;
            } else {
                InstantCameraView.this.scaleX = height2 / surfaceWidth;
                InstantCameraView.this.scaleY = 1.0f;
            }
        }

        private boolean initGL() {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("start init gl");
            }
            EGL10 egl10 = (EGL10) EGLContext.getEGL();
            this.egl10 = egl10;
            EGLDisplay eGLDisplayEglGetDisplay = egl10.eglGetDisplay(EGL10.EGL_DEFAULT_DISPLAY);
            this.eglDisplay = eGLDisplayEglGetDisplay;
            if (eGLDisplayEglGetDisplay == EGL10.EGL_NO_DISPLAY) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglGetDisplay failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            int[] version = new int[2];
            if (!this.egl10.eglInitialize(this.eglDisplay, version)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglInitialize failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            int[] configsCount = new int[1];
            EGLConfig[] configs = new EGLConfig[1];
            int[] configSpec = {12352, 4, 12324, 8, 12323, 8, 12322, 8, 12321, 0, 12325, 0, 12326, 0, 12344};
            if (!this.egl10.eglChooseConfig(this.eglDisplay, configSpec, configs, 1, configsCount)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("eglChooseConfig failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                }
                finish();
                return false;
            }
            if (configsCount[0] > 0) {
                EGLConfig eGLConfig = configs[0];
                this.eglConfig = eGLConfig;
                int[] attrib_list = {12440, 2, 12344};
                EGLContext eGLContextEglCreateContext = this.egl10.eglCreateContext(this.eglDisplay, eGLConfig, EGL10.EGL_NO_CONTEXT, attrib_list);
                this.eglContext = eGLContextEglCreateContext;
                if (eGLContextEglCreateContext == null) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("eglCreateContext failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                    }
                    finish();
                    return false;
                }
                SurfaceTexture surfaceTexture = this.surfaceTexture;
                if (surfaceTexture instanceof SurfaceTexture) {
                    EGLSurface eGLSurfaceEglCreateWindowSurface = this.egl10.eglCreateWindowSurface(this.eglDisplay, this.eglConfig, surfaceTexture, null);
                    this.eglSurface = eGLSurfaceEglCreateWindowSurface;
                    if (eGLSurfaceEglCreateWindowSurface == null || eGLSurfaceEglCreateWindowSurface == EGL10.EGL_NO_SURFACE) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("createWindowSurface failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                        }
                        finish();
                        return false;
                    }
                    EGL10 egl102 = this.egl10;
                    EGLDisplay eGLDisplay = this.eglDisplay;
                    EGLSurface eGLSurface = this.eglSurface;
                    if (egl102.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, this.eglContext)) {
                        this.gl = this.eglContext.getGL();
                        float tX = (1.0f / InstantCameraView.this.scaleX) / 2.0f;
                        float tY = (1.0f / InstantCameraView.this.scaleY) / 2.0f;
                        float[] verticesData = {-1.0f, -1.0f, 0.0f, 1.0f, -1.0f, 0.0f, -1.0f, 1.0f, 0.0f, 1.0f, 1.0f, 0.0f};
                        float[] texData = {0.5f - tX, 0.5f - tY, tX + 0.5f, 0.5f - tY, 0.5f - tX, tY + 0.5f, tX + 0.5f, 0.5f + tY};
                        this.videoEncoder = new VideoRecorder();
                        InstantCameraView.this.vertexBuffer = ByteBuffer.allocateDirect(verticesData.length * 4).order(ByteOrder.nativeOrder()).asFloatBuffer();
                        InstantCameraView.this.vertexBuffer.put(verticesData).position(0);
                        InstantCameraView.this.textureBuffer = ByteBuffer.allocateDirect(texData.length * 4).order(ByteOrder.nativeOrder()).asFloatBuffer();
                        InstantCameraView.this.textureBuffer.put(texData).position(0);
                        Matrix.setIdentityM(InstantCameraView.this.mSTMatrix, 0);
                        int vertexShader = InstantCameraView.this.loadShader(35633, InstantCameraView.VERTEX_SHADER);
                        int fragmentShader = InstantCameraView.this.loadShader(35632, InstantCameraView.FRAGMENT_SCREEN_SHADER);
                        if (vertexShader != 0 && fragmentShader != 0) {
                            int iGlCreateProgram = GLES20.glCreateProgram();
                            this.drawProgram = iGlCreateProgram;
                            GLES20.glAttachShader(iGlCreateProgram, vertexShader);
                            GLES20.glAttachShader(this.drawProgram, fragmentShader);
                            GLES20.glLinkProgram(this.drawProgram);
                            int[] linkStatus = new int[1];
                            GLES20.glGetProgramiv(this.drawProgram, 35714, linkStatus, 0);
                            if (linkStatus[0] != 0) {
                                this.positionHandle = GLES20.glGetAttribLocation(this.drawProgram, "aPosition");
                                this.textureHandle = GLES20.glGetAttribLocation(this.drawProgram, "aTextureCoord");
                                this.vertexMatrixHandle = GLES20.glGetUniformLocation(this.drawProgram, "uMVPMatrix");
                                this.textureMatrixHandle = GLES20.glGetUniformLocation(this.drawProgram, "uSTMatrix");
                            } else {
                                if (BuildVars.LOGS_ENABLED) {
                                    FileLog.e("failed link shader");
                                }
                                GLES20.glDeleteProgram(this.drawProgram);
                                this.drawProgram = 0;
                            }
                            GLES20.glGenTextures(1, InstantCameraView.this.cameraTexture, 0);
                            GLES20.glBindTexture(36197, InstantCameraView.this.cameraTexture[0]);
                            GLES20.glTexParameteri(36197, 10241, 9729);
                            GLES20.glTexParameteri(36197, 10240, 9729);
                            GLES20.glTexParameteri(36197, 10242, 33071);
                            GLES20.glTexParameteri(36197, 10243, 33071);
                            Matrix.setIdentityM(InstantCameraView.this.mMVPMatrix, 0);
                            SurfaceTexture surfaceTexture2 = new SurfaceTexture(InstantCameraView.this.cameraTexture[0]);
                            this.cameraSurface = surfaceTexture2;
                            surfaceTexture2.setOnFrameAvailableListener(new SurfaceTexture.OnFrameAvailableListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$CameraGLThread$T5lj4IoYiN46DN0XHeFZHkoJrew
                                @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
                                public final void onFrameAvailable(SurfaceTexture surfaceTexture3) {
                                    this.f$0.lambda$initGL$0$InstantCameraView$CameraGLThread(surfaceTexture3);
                                }
                            });
                            InstantCameraView.this.createCamera(this.cameraSurface);
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.e("gl initied");
                                return true;
                            }
                            return true;
                        }
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("failed creating shader");
                        }
                        finish();
                        return false;
                    }
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("eglMakeCurrent failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                    }
                    finish();
                    return false;
                }
                finish();
                return false;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("eglConfig not initialized");
            }
            finish();
            return false;
        }

        public /* synthetic */ void lambda$initGL$0$InstantCameraView$CameraGLThread(SurfaceTexture surfaceTexture) {
            requestRender();
        }

        public void reinitForNewCamera() {
            Handler handler = InstantCameraView.this.getHandler();
            if (handler != null) {
                sendMessage(handler.obtainMessage(2), 0);
            }
        }

        public void finish() {
            if (this.eglSurface != null) {
                this.egl10.eglMakeCurrent(this.eglDisplay, EGL10.EGL_NO_SURFACE, EGL10.EGL_NO_SURFACE, EGL10.EGL_NO_CONTEXT);
                this.egl10.eglDestroySurface(this.eglDisplay, this.eglSurface);
                this.eglSurface = null;
            }
            EGLContext eGLContext = this.eglContext;
            if (eGLContext != null) {
                this.egl10.eglDestroyContext(this.eglDisplay, eGLContext);
                this.eglContext = null;
            }
            EGLDisplay eGLDisplay = this.eglDisplay;
            if (eGLDisplay != null) {
                this.egl10.eglTerminate(eGLDisplay);
                this.eglDisplay = null;
            }
        }

        public void setCurrentSession(CameraSession session) {
            Handler handler = InstantCameraView.this.getHandler();
            if (handler != null) {
                sendMessage(handler.obtainMessage(3, session), 0);
            }
        }

        private void onDraw(Integer cameraId) {
            if (!this.initied) {
                return;
            }
            if (!this.eglContext.equals(this.egl10.eglGetCurrentContext()) || !this.eglSurface.equals(this.egl10.eglGetCurrentSurface(12377))) {
                EGL10 egl10 = this.egl10;
                EGLDisplay eGLDisplay = this.eglDisplay;
                EGLSurface eGLSurface = this.eglSurface;
                if (!egl10.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, this.eglContext)) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("eglMakeCurrent failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                        return;
                    }
                    return;
                }
            }
            this.cameraSurface.updateTexImage();
            if (!this.recording) {
                this.videoEncoder.startRecording(InstantCameraView.this.cameraFile, EGL14.eglGetCurrentContext());
                this.recording = true;
                int orientation = this.currentSession.getCurrentOrientation();
                if (orientation == 90 || orientation == 270) {
                    float temp = InstantCameraView.this.scaleX;
                    InstantCameraView instantCameraView = InstantCameraView.this;
                    instantCameraView.scaleX = instantCameraView.scaleY;
                    InstantCameraView.this.scaleY = temp;
                }
            }
            this.videoEncoder.frameAvailable(this.cameraSurface, cameraId, System.nanoTime());
            this.cameraSurface.getTransformMatrix(InstantCameraView.this.mSTMatrix);
            GLES20.glUseProgram(this.drawProgram);
            GLES20.glActiveTexture(33984);
            GLES20.glBindTexture(36197, InstantCameraView.this.cameraTexture[0]);
            GLES20.glVertexAttribPointer(this.positionHandle, 3, 5126, false, 12, (Buffer) InstantCameraView.this.vertexBuffer);
            GLES20.glEnableVertexAttribArray(this.positionHandle);
            GLES20.glVertexAttribPointer(this.textureHandle, 2, 5126, false, 8, (Buffer) InstantCameraView.this.textureBuffer);
            GLES20.glEnableVertexAttribArray(this.textureHandle);
            GLES20.glUniformMatrix4fv(this.textureMatrixHandle, 1, false, InstantCameraView.this.mSTMatrix, 0);
            GLES20.glUniformMatrix4fv(this.vertexMatrixHandle, 1, false, InstantCameraView.this.mMVPMatrix, 0);
            GLES20.glDrawArrays(5, 0, 4);
            GLES20.glDisableVertexAttribArray(this.positionHandle);
            GLES20.glDisableVertexAttribArray(this.textureHandle);
            GLES20.glBindTexture(36197, 0);
            GLES20.glUseProgram(0);
            this.egl10.eglSwapBuffers(this.eglDisplay, this.eglSurface);
        }

        @Override // im.uwrkaxlmjj.messenger.DispatchQueue, java.lang.Thread, java.lang.Runnable
        public void run() {
            this.initied = initGL();
            super.run();
        }

        @Override // im.uwrkaxlmjj.messenger.DispatchQueue
        public void handleMessage(Message inputMessage) {
            int what = inputMessage.what;
            if (what == 0) {
                onDraw((Integer) inputMessage.obj);
                return;
            }
            if (what == 1) {
                finish();
                if (this.recording) {
                    this.videoEncoder.stopRecording(inputMessage.arg1);
                }
                Looper looper = Looper.myLooper();
                if (looper != null) {
                    looper.quit();
                    return;
                }
                return;
            }
            if (what != 2) {
                if (what == 3) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("set gl rednderer session");
                    }
                    CameraSession newSession = (CameraSession) inputMessage.obj;
                    CameraSession cameraSession = this.currentSession;
                    if (cameraSession == newSession) {
                        this.rotationAngle = cameraSession.getWorldAngle();
                        Matrix.setIdentityM(InstantCameraView.this.mMVPMatrix, 0);
                        if (this.rotationAngle != 0) {
                            Matrix.rotateM(InstantCameraView.this.mMVPMatrix, 0, this.rotationAngle, 0.0f, 0.0f, 1.0f);
                            return;
                        }
                        return;
                    }
                    this.currentSession = newSession;
                    return;
                }
                return;
            }
            EGL10 egl10 = this.egl10;
            EGLDisplay eGLDisplay = this.eglDisplay;
            EGLSurface eGLSurface = this.eglSurface;
            if (!egl10.eglMakeCurrent(eGLDisplay, eGLSurface, eGLSurface, this.eglContext)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("eglMakeCurrent failed " + GLUtils.getEGLErrorString(this.egl10.eglGetError()));
                    return;
                }
                return;
            }
            SurfaceTexture surfaceTexture = this.cameraSurface;
            if (surfaceTexture != null) {
                surfaceTexture.getTransformMatrix(InstantCameraView.this.moldSTMatrix);
                this.cameraSurface.setOnFrameAvailableListener(null);
                this.cameraSurface.release();
                InstantCameraView.this.oldCameraTexture[0] = InstantCameraView.this.cameraTexture[0];
                InstantCameraView.this.cameraTextureAlpha = 0.0f;
                InstantCameraView.this.cameraTexture[0] = 0;
            }
            this.cameraId = Integer.valueOf(this.cameraId.intValue() + 1);
            InstantCameraView.this.cameraReady = false;
            GLES20.glGenTextures(1, InstantCameraView.this.cameraTexture, 0);
            GLES20.glBindTexture(36197, InstantCameraView.this.cameraTexture[0]);
            GLES20.glTexParameteri(36197, 10241, 9729);
            GLES20.glTexParameteri(36197, 10240, 9729);
            GLES20.glTexParameteri(36197, 10242, 33071);
            GLES20.glTexParameteri(36197, 10243, 33071);
            SurfaceTexture surfaceTexture2 = new SurfaceTexture(InstantCameraView.this.cameraTexture[0]);
            this.cameraSurface = surfaceTexture2;
            surfaceTexture2.setOnFrameAvailableListener(new SurfaceTexture.OnFrameAvailableListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$CameraGLThread$no4hqLev_sujnm0BwxchYn2nuv0
                @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
                public final void onFrameAvailable(SurfaceTexture surfaceTexture3) {
                    this.f$0.lambda$handleMessage$1$InstantCameraView$CameraGLThread(surfaceTexture3);
                }
            });
            InstantCameraView.this.createCamera(this.cameraSurface);
        }

        public /* synthetic */ void lambda$handleMessage$1$InstantCameraView$CameraGLThread(SurfaceTexture surfaceTexture) {
            requestRender();
        }

        public void shutdown(int send) {
            Handler handler = InstantCameraView.this.getHandler();
            if (handler != null) {
                sendMessage(handler.obtainMessage(1, send, 0), 0);
            }
        }

        public void requestRender() {
            Handler handler = InstantCameraView.this.getHandler();
            if (handler != null) {
                sendMessage(handler.obtainMessage(0, this.cameraId), 0);
            }
        }
    }

    private static class EncoderHandler extends Handler {
        private WeakReference<VideoRecorder> mWeakEncoder;

        public EncoderHandler(VideoRecorder encoder) {
            this.mWeakEncoder = new WeakReference<>(encoder);
        }

        @Override // android.os.Handler
        public void handleMessage(Message inputMessage) {
            int what = inputMessage.what;
            Object obj = inputMessage.obj;
            VideoRecorder encoder = this.mWeakEncoder.get();
            if (encoder == null) {
                return;
            }
            if (what == 0) {
                try {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.e("start encoder");
                    }
                    encoder.prepareEncoder();
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    encoder.handleStopRecording(0);
                    Looper.myLooper().quit();
                    return;
                }
            }
            if (what == 1) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("stop encoder");
                }
                encoder.handleStopRecording(inputMessage.arg1);
            } else if (what != 2) {
                if (what != 3) {
                    return;
                }
                encoder.handleAudioFrameAvailable((AudioBufferInfo) inputMessage.obj);
            } else {
                long timestamp = (((long) inputMessage.arg1) << 32) | (((long) inputMessage.arg2) & 4294967295L);
                Integer cameraId = (Integer) inputMessage.obj;
                encoder.handleVideoFrameAvailable(timestamp, cameraId);
            }
        }

        public void exit() {
            Looper.myLooper().quit();
        }
    }

    private class AudioBufferInfo {
        byte[] buffer;
        boolean last;
        int lastWroteBuffer;
        long[] offset;
        int[] read;
        int results;

        private AudioBufferInfo() {
            this.buffer = new byte[CacheDataSink.DEFAULT_BUFFER_SIZE];
            this.offset = new long[10];
            this.read = new int[10];
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class VideoRecorder implements Runnable {
        private static final String AUDIO_MIME_TYPE = "audio/mp4a-latm";
        private static final int FRAME_RATE = 30;
        private static final int IFRAME_INTERVAL = 1;
        private static final String VIDEO_MIME_TYPE = "video/avc";
        private int alphaHandle;
        private MediaCodec.BufferInfo audioBufferInfo;
        private MediaCodec audioEncoder;
        private long audioFirst;
        private AudioRecord audioRecorder;
        private long audioStartTime;
        private boolean audioStopedByTime;
        private int audioTrackIndex;
        private boolean blendEnabled;
        private ArrayBlockingQueue<AudioBufferInfo> buffers;
        private ArrayList<AudioBufferInfo> buffersToWrite;
        private long currentTimestamp;
        private long desyncTime;
        private int drawProgram;
        private android.opengl.EGLConfig eglConfig;
        private android.opengl.EGLContext eglContext;
        private android.opengl.EGLDisplay eglDisplay;
        private android.opengl.EGLSurface eglSurface;
        private volatile EncoderHandler handler;
        private Integer lastCameraId;
        private long lastCommitedFrameTime;
        private long lastTimestamp;
        private MP4Builder mediaMuxer;
        private int positionHandle;
        private boolean ready;
        private Runnable recorderRunnable;
        private volatile boolean running;
        private int scaleXHandle;
        private int scaleYHandle;
        private volatile int sendWhenDone;
        private android.opengl.EGLContext sharedEglContext;
        private boolean skippedFirst;
        private long skippedTime;
        private Surface surface;
        private final Object sync;
        private int textureHandle;
        private int textureMatrixHandle;
        private int vertexMatrixHandle;
        private int videoBitrate;
        private MediaCodec.BufferInfo videoBufferInfo;
        private boolean videoConvertFirstWrite;
        private MediaCodec videoEncoder;
        private File videoFile;
        private long videoFirst;
        private int videoHeight;
        private long videoLast;
        private int videoTrackIndex;
        private int videoWidth;
        private int zeroTimeStamps;

        private VideoRecorder() {
            this.videoConvertFirstWrite = true;
            this.eglDisplay = EGL14.EGL_NO_DISPLAY;
            this.eglContext = EGL14.EGL_NO_CONTEXT;
            this.eglSurface = EGL14.EGL_NO_SURFACE;
            this.buffersToWrite = new ArrayList<>();
            this.videoTrackIndex = -5;
            this.audioTrackIndex = -5;
            this.audioStartTime = -1L;
            this.currentTimestamp = 0L;
            this.lastTimestamp = -1L;
            this.sync = new Object();
            this.videoFirst = -1L;
            this.audioFirst = -1L;
            this.lastCameraId = 0;
            this.buffers = new ArrayBlockingQueue<>(10);
            this.recorderRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.VideoRecorder.1
                /* JADX WARN: Code restructure failed: missing block: B:14:0x002d, code lost:
                
                    if (r11.this$1.sendWhenDone == 0) goto L58;
                 */
                @Override // java.lang.Runnable
                /*
                    Code decompiled incorrectly, please refer to instructions dump.
                    To view partially-correct add '--show-bad-code' argument
                */
                public void run() {
                    /*
                        Method dump skipped, instruction units count: 268
                        To view this dump add '--comments-level debug' option
                    */
                    throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.InstantCameraView.VideoRecorder.AnonymousClass1.run():void");
                }
            };
        }

        public void startRecording(File outputFile, android.opengl.EGLContext sharedContext) {
            int resolution;
            int bitrate;
            String model = Build.DEVICE;
            if (model == null) {
                model = "";
            }
            if (model.startsWith("zeroflte") || model.startsWith("zenlte")) {
                resolution = 320;
                bitrate = 600000;
            } else {
                resolution = PsExtractor.VIDEO_STREAM_MASK;
                bitrate = 400000;
            }
            this.videoFile = outputFile;
            this.videoWidth = resolution;
            this.videoHeight = resolution;
            this.videoBitrate = bitrate;
            this.sharedEglContext = sharedContext;
            synchronized (this.sync) {
                if (this.running) {
                    return;
                }
                this.running = true;
                Thread thread = new Thread(this, "TextureMovieEncoder");
                thread.setPriority(10);
                thread.start();
                while (!this.ready) {
                    try {
                        this.sync.wait();
                    } catch (InterruptedException e) {
                    }
                }
                this.handler.sendMessage(this.handler.obtainMessage(0));
            }
        }

        public void stopRecording(int send) {
            this.handler.sendMessage(this.handler.obtainMessage(1, send, 0));
        }

        public void frameAvailable(SurfaceTexture st, Integer cameraId, long timestampInternal) {
            synchronized (this.sync) {
                if (this.ready) {
                    long timestamp = st.getTimestamp();
                    if (timestamp == 0) {
                        int i = this.zeroTimeStamps + 1;
                        this.zeroTimeStamps = i;
                        if (i > 1) {
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("fix timestamp enabled");
                            }
                            timestamp = timestampInternal;
                        } else {
                            return;
                        }
                    } else {
                        this.zeroTimeStamps = 0;
                    }
                    this.handler.sendMessage(this.handler.obtainMessage(2, (int) (timestamp >> 32), (int) timestamp, cameraId));
                }
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            Looper.prepare();
            synchronized (this.sync) {
                this.handler = new EncoderHandler(this);
                this.ready = true;
                this.sync.notify();
            }
            Looper.loop();
            synchronized (this.sync) {
                this.ready = false;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX WARN: Removed duplicated region for block: B:117:0x01e6 A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:76:0x01c1 A[Catch: all -> 0x020c, TryCatch #0 {all -> 0x020c, blocks: (B:51:0x012c, B:53:0x0136, B:55:0x013c, B:57:0x0150, B:58:0x015a, B:60:0x015e, B:62:0x0162, B:64:0x0166, B:66:0x0173, B:68:0x0177, B:69:0x0199, B:70:0x01a3, B:72:0x01ad, B:73:0x01b1, B:74:0x01bc, B:76:0x01c1, B:78:0x01ca, B:79:0x01cf, B:81:0x01d7, B:82:0x01e1, B:83:0x01e6, B:84:0x01ec, B:91:0x0206, B:87:0x01fb, B:56:0x0144), top: B:97:0x012c }] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void handleAudioFrameAvailable(im.uwrkaxlmjj.ui.components.InstantCameraView.AudioBufferInfo r19) {
            /*
                Method dump skipped, instruction units count: 531
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.InstantCameraView.VideoRecorder.handleAudioFrameAvailable(im.uwrkaxlmjj.ui.components.InstantCameraView$AudioBufferInfo):void");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void handleVideoFrameAvailable(long timestampNanos, Integer cameraId) {
            long alphaDt;
            long dt;
            try {
                drainEncoder(false);
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (!this.lastCameraId.equals(cameraId)) {
                this.lastTimestamp = -1L;
                this.lastCameraId = cameraId;
            }
            long dt2 = this.lastTimestamp;
            if (dt2 == -1) {
                this.lastTimestamp = timestampNanos;
                dt = 0;
                if (this.currentTimestamp != 0) {
                    alphaDt = (System.currentTimeMillis() - this.lastCommitedFrameTime) * 1000000;
                    dt = 0;
                } else {
                    alphaDt = 0;
                }
            } else {
                alphaDt = timestampNanos - dt2;
                this.lastTimestamp = timestampNanos;
                dt = alphaDt;
            }
            this.lastCommitedFrameTime = System.currentTimeMillis();
            if (!this.skippedFirst) {
                long j = this.skippedTime + alphaDt;
                this.skippedTime = j;
                if (j < 200000000) {
                    return;
                } else {
                    this.skippedFirst = true;
                }
            }
            this.currentTimestamp += alphaDt;
            if (this.videoFirst == -1) {
                this.videoFirst = timestampNanos / 1000;
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("first video frame was at " + this.videoFirst);
                }
            }
            this.videoLast = timestampNanos;
            GLES20.glUseProgram(this.drawProgram);
            GLES20.glVertexAttribPointer(this.positionHandle, 3, 5126, false, 12, (Buffer) InstantCameraView.this.vertexBuffer);
            GLES20.glEnableVertexAttribArray(this.positionHandle);
            GLES20.glVertexAttribPointer(this.textureHandle, 2, 5126, false, 8, (Buffer) InstantCameraView.this.textureBuffer);
            GLES20.glEnableVertexAttribArray(this.textureHandle);
            GLES20.glUniform1f(this.scaleXHandle, InstantCameraView.this.scaleX);
            GLES20.glUniform1f(this.scaleYHandle, InstantCameraView.this.scaleY);
            GLES20.glUniformMatrix4fv(this.vertexMatrixHandle, 1, false, InstantCameraView.this.mMVPMatrix, 0);
            GLES20.glActiveTexture(33984);
            if (InstantCameraView.this.oldCameraTexture[0] != 0) {
                if (!this.blendEnabled) {
                    GLES20.glEnable(3042);
                    this.blendEnabled = true;
                }
                GLES20.glUniformMatrix4fv(this.textureMatrixHandle, 1, false, InstantCameraView.this.moldSTMatrix, 0);
                GLES20.glUniform1f(this.alphaHandle, 1.0f);
                GLES20.glBindTexture(36197, InstantCameraView.this.oldCameraTexture[0]);
                GLES20.glDrawArrays(5, 0, 4);
            }
            GLES20.glUniformMatrix4fv(this.textureMatrixHandle, 1, false, InstantCameraView.this.mSTMatrix, 0);
            GLES20.glUniform1f(this.alphaHandle, InstantCameraView.this.cameraTextureAlpha);
            GLES20.glBindTexture(36197, InstantCameraView.this.cameraTexture[0]);
            GLES20.glDrawArrays(5, 0, 4);
            GLES20.glDisableVertexAttribArray(this.positionHandle);
            GLES20.glDisableVertexAttribArray(this.textureHandle);
            GLES20.glBindTexture(36197, 0);
            GLES20.glUseProgram(0);
            EGLExt.eglPresentationTimeANDROID(this.eglDisplay, this.eglSurface, this.currentTimestamp);
            EGL14.eglSwapBuffers(this.eglDisplay, this.eglSurface);
            if (InstantCameraView.this.oldCameraTexture[0] == 0 || InstantCameraView.this.cameraTextureAlpha >= 1.0f) {
                if (!InstantCameraView.this.cameraReady) {
                    InstantCameraView.this.cameraReady = true;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$VideoRecorder$rDJYc5cFJUOMtQXFPx15pJbupEQ
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$handleVideoFrameAvailable$1$InstantCameraView$VideoRecorder();
                        }
                    });
                    return;
                }
                return;
            }
            InstantCameraView.this.cameraTextureAlpha += dt / 2.0E8f;
            if (InstantCameraView.this.cameraTextureAlpha > 1.0f) {
                GLES20.glDisable(3042);
                this.blendEnabled = false;
                InstantCameraView.this.cameraTextureAlpha = 1.0f;
                GLES20.glDeleteTextures(1, InstantCameraView.this.oldCameraTexture, 0);
                InstantCameraView.this.oldCameraTexture[0] = 0;
                if (!InstantCameraView.this.cameraReady) {
                    InstantCameraView.this.cameraReady = true;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$VideoRecorder$rrVbm3prF4HotdZAf2qCFThXVcc
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$handleVideoFrameAvailable$0$InstantCameraView$VideoRecorder();
                        }
                    });
                }
            }
        }

        public /* synthetic */ void lambda$handleVideoFrameAvailable$0$InstantCameraView$VideoRecorder() {
            InstantCameraView.this.textureOverlayView.animate().setDuration(120L).alpha(0.0f).setInterpolator(new DecelerateInterpolator()).start();
        }

        public /* synthetic */ void lambda$handleVideoFrameAvailable$1$InstantCameraView$VideoRecorder() {
            InstantCameraView.this.textureOverlayView.animate().setDuration(120L).alpha(0.0f).setInterpolator(new DecelerateInterpolator()).start();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void handleStopRecording(final int send) {
            if (this.running) {
                this.sendWhenDone = send;
                this.running = false;
                return;
            }
            try {
                drainEncoder(true);
            } catch (Exception e) {
                FileLog.e(e);
            }
            MediaCodec mediaCodec = this.videoEncoder;
            if (mediaCodec != null) {
                try {
                    mediaCodec.stop();
                    this.videoEncoder.release();
                    this.videoEncoder = null;
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
            MediaCodec mediaCodec2 = this.audioEncoder;
            if (mediaCodec2 != null) {
                try {
                    mediaCodec2.stop();
                    this.audioEncoder.release();
                    this.audioEncoder = null;
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
            }
            MP4Builder mP4Builder = this.mediaMuxer;
            if (mP4Builder != null) {
                try {
                    mP4Builder.finishMovie();
                } catch (Exception e4) {
                    FileLog.e(e4);
                }
            }
            if (send == 0) {
                FileLoader.getInstance(InstantCameraView.this.currentAccount).cancelUploadFile(this.videoFile.getAbsolutePath(), false);
                this.videoFile.delete();
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$VideoRecorder$7qg4b1NQJtY2-RNCnkM46R2zrt4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$handleStopRecording$3$InstantCameraView$VideoRecorder(send);
                    }
                });
            }
            EGL14.eglDestroySurface(this.eglDisplay, this.eglSurface);
            this.eglSurface = EGL14.EGL_NO_SURFACE;
            Surface surface = this.surface;
            if (surface != null) {
                surface.release();
                this.surface = null;
            }
            if (this.eglDisplay != EGL14.EGL_NO_DISPLAY) {
                EGL14.eglMakeCurrent(this.eglDisplay, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                EGL14.eglDestroyContext(this.eglDisplay, this.eglContext);
                EGL14.eglReleaseThread();
                EGL14.eglTerminate(this.eglDisplay);
            }
            this.eglDisplay = EGL14.EGL_NO_DISPLAY;
            this.eglContext = EGL14.EGL_NO_CONTEXT;
            this.eglConfig = null;
            this.handler.exit();
        }

        public /* synthetic */ void lambda$handleStopRecording$3$InstantCameraView$VideoRecorder(int send) {
            InstantCameraView.this.videoEditedInfo = new VideoEditedInfo();
            InstantCameraView.this.videoEditedInfo.roundVideo = true;
            InstantCameraView.this.videoEditedInfo.startTime = -1L;
            InstantCameraView.this.videoEditedInfo.endTime = -1L;
            InstantCameraView.this.videoEditedInfo.file = InstantCameraView.this.file;
            InstantCameraView.this.videoEditedInfo.encryptedFile = InstantCameraView.this.encryptedFile;
            InstantCameraView.this.videoEditedInfo.key = InstantCameraView.this.key;
            InstantCameraView.this.videoEditedInfo.iv = InstantCameraView.this.iv;
            InstantCameraView.this.videoEditedInfo.estimatedSize = Math.max(1L, InstantCameraView.this.size);
            InstantCameraView.this.videoEditedInfo.framerate = 25;
            VideoEditedInfo videoEditedInfo = InstantCameraView.this.videoEditedInfo;
            InstantCameraView.this.videoEditedInfo.originalWidth = PsExtractor.VIDEO_STREAM_MASK;
            videoEditedInfo.resultWidth = PsExtractor.VIDEO_STREAM_MASK;
            VideoEditedInfo videoEditedInfo2 = InstantCameraView.this.videoEditedInfo;
            InstantCameraView.this.videoEditedInfo.originalHeight = PsExtractor.VIDEO_STREAM_MASK;
            videoEditedInfo2.resultHeight = PsExtractor.VIDEO_STREAM_MASK;
            InstantCameraView.this.videoEditedInfo.originalPath = this.videoFile.getAbsolutePath();
            if (send == 1) {
                if (InstantCameraView.this.baseFragment.isInScheduleMode()) {
                    AlertsCreator.createScheduleDatePickerDialog(InstantCameraView.this.baseFragment.getParentActivity(), UserObject.isUserSelf(InstantCameraView.this.baseFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$VideoRecorder$KiBjsc6rlSVlwLfRYpryaaOeSv4
                        @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                        public final void didSelectDate(boolean z, int i) {
                            this.f$0.lambda$null$2$InstantCameraView$VideoRecorder(z, i);
                        }
                    });
                } else {
                    InstantCameraView.this.baseFragment.sendMedia(new MediaController.PhotoEntry(0, 0, 0L, this.videoFile.getAbsolutePath(), 0, true), InstantCameraView.this.videoEditedInfo, true, 0);
                }
            } else {
                InstantCameraView.this.videoPlayer = new VideoPlayer();
                InstantCameraView.this.videoPlayer.setDelegate(new VideoPlayer.VideoPlayerDelegate() { // from class: im.uwrkaxlmjj.ui.components.InstantCameraView.VideoRecorder.2
                    @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                    public void onStateChanged(boolean playWhenReady, int playbackState) {
                        if (InstantCameraView.this.videoPlayer != null && InstantCameraView.this.videoPlayer.isPlaying() && playbackState == 4) {
                            InstantCameraView.this.videoPlayer.seekTo(InstantCameraView.this.videoEditedInfo.startTime > 0 ? InstantCameraView.this.videoEditedInfo.startTime : 0L);
                        }
                    }

                    @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                    public void onError(Exception e) {
                        FileLog.e(e);
                    }

                    @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                    public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
                    }

                    @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                    public void onRenderedFirstFrame() {
                    }

                    @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                    public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
                        return false;
                    }

                    @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                    public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
                    }
                });
                InstantCameraView.this.videoPlayer.setTextureView(InstantCameraView.this.textureView);
                InstantCameraView.this.videoPlayer.preparePlayer(Uri.fromFile(this.videoFile), "other");
                InstantCameraView.this.videoPlayer.play();
                InstantCameraView.this.videoPlayer.setMute(true);
                InstantCameraView.this.startProgressTimer();
                AnimatorSet animatorSet = new AnimatorSet();
                animatorSet.playTogether(ObjectAnimator.ofFloat(InstantCameraView.this.switchCameraButton, "alpha", 0.0f), ObjectAnimator.ofInt(InstantCameraView.this.paint, "alpha", 0), ObjectAnimator.ofFloat(InstantCameraView.this.muteImageView, "alpha", 1.0f));
                animatorSet.setDuration(180L);
                animatorSet.setInterpolator(new DecelerateInterpolator());
                animatorSet.start();
                InstantCameraView.this.videoEditedInfo.estimatedDuration = InstantCameraView.this.duration;
                NotificationCenter.getInstance(InstantCameraView.this.currentAccount).postNotificationName(NotificationCenter.audioDidSent, Integer.valueOf(InstantCameraView.this.recordingGuid), InstantCameraView.this.videoEditedInfo, this.videoFile.getAbsolutePath());
            }
            didWriteData(this.videoFile, 0L, true);
        }

        public /* synthetic */ void lambda$null$2$InstantCameraView$VideoRecorder(boolean notify, int scheduleDate) {
            InstantCameraView.this.baseFragment.sendMedia(new MediaController.PhotoEntry(0, 0, 0L, this.videoFile.getAbsolutePath(), 0, true), InstantCameraView.this.videoEditedInfo, notify, scheduleDate);
            InstantCameraView.this.startAnimation(false);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void prepareEncoder() {
            try {
                int recordBufferSize = AudioRecord.getMinBufferSize(44100, 16, 2);
                if (recordBufferSize <= 0) {
                    recordBufferSize = 3584;
                }
                int bufferSize = 49152;
                if (49152 < recordBufferSize) {
                    bufferSize = ((recordBufferSize / 2048) + 1) * 2048 * 2;
                }
                int a = 0;
                while (true) {
                    if (a >= 3) {
                        break;
                    }
                    this.buffers.add(new AudioBufferInfo());
                    a++;
                }
                AudioRecord audioRecord = new AudioRecord(0, 44100, 16, 2, bufferSize);
                this.audioRecorder = audioRecord;
                audioRecord.startRecording();
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("initied audio record with channels " + this.audioRecorder.getChannelCount() + " sample rate = " + this.audioRecorder.getSampleRate() + " bufferSize = " + bufferSize);
                }
                Thread thread = new Thread(this.recorderRunnable);
                thread.setPriority(10);
                thread.start();
                this.audioBufferInfo = new MediaCodec.BufferInfo();
                this.videoBufferInfo = new MediaCodec.BufferInfo();
                MediaFormat audioFormat = new MediaFormat();
                audioFormat.setString("mime", "audio/mp4a-latm");
                audioFormat.setInteger("aac-profile", 2);
                audioFormat.setInteger("sample-rate", 44100);
                audioFormat.setInteger("channel-count", 1);
                audioFormat.setInteger("bitrate", 32000);
                audioFormat.setInteger("max-input-size", CacheDataSink.DEFAULT_BUFFER_SIZE);
                MediaCodec mediaCodecCreateEncoderByType = MediaCodec.createEncoderByType("audio/mp4a-latm");
                this.audioEncoder = mediaCodecCreateEncoderByType;
                mediaCodecCreateEncoderByType.configure(audioFormat, (Surface) null, (MediaCrypto) null, 1);
                this.audioEncoder.start();
                this.videoEncoder = MediaCodec.createEncoderByType("video/avc");
                MediaFormat format = MediaFormat.createVideoFormat("video/avc", this.videoWidth, this.videoHeight);
                format.setInteger("color-format", 2130708361);
                format.setInteger("bitrate", this.videoBitrate);
                format.setInteger("frame-rate", 30);
                format.setInteger("i-frame-interval", 1);
                this.videoEncoder.configure(format, (Surface) null, (MediaCrypto) null, 1);
                this.surface = this.videoEncoder.createInputSurface();
                this.videoEncoder.start();
                Mp4Movie movie = new Mp4Movie();
                movie.setCacheFile(this.videoFile);
                movie.setRotation(0);
                movie.setSize(this.videoWidth, this.videoHeight);
                this.mediaMuxer = new MP4Builder().createMovie(movie, InstantCameraView.this.isSecretChat);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$InstantCameraView$VideoRecorder$6w-TRIHBwII9Ex4KeLnNdEnbP34
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$prepareEncoder$4$InstantCameraView$VideoRecorder();
                    }
                });
                if (this.eglDisplay != EGL14.EGL_NO_DISPLAY) {
                    throw new RuntimeException("EGL already set up");
                }
                android.opengl.EGLDisplay eGLDisplayEglGetDisplay = EGL14.eglGetDisplay(0);
                this.eglDisplay = eGLDisplayEglGetDisplay;
                if (eGLDisplayEglGetDisplay == EGL14.EGL_NO_DISPLAY) {
                    throw new RuntimeException("unable to get EGL14 display");
                }
                int[] version = new int[2];
                if (!EGL14.eglInitialize(this.eglDisplay, version, 0, version, 1)) {
                    this.eglDisplay = null;
                    throw new RuntimeException("unable to initialize EGL14");
                }
                if (this.eglContext == EGL14.EGL_NO_CONTEXT) {
                    int[] attribList = {12324, 8, 12323, 8, 12322, 8, 12321, 8, 12352, 4, EglBase.EGL_RECORDABLE_ANDROID, 1, 12344};
                    android.opengl.EGLConfig[] configs = new android.opengl.EGLConfig[1];
                    int[] numConfigs = new int[1];
                    if (!EGL14.eglChooseConfig(this.eglDisplay, attribList, 0, configs, 0, configs.length, numConfigs, 0)) {
                        throw new RuntimeException("Unable to find a suitable EGLConfig");
                    }
                    int[] attrib2_list = {12440, 2, 12344};
                    this.eglContext = EGL14.eglCreateContext(this.eglDisplay, configs[0], this.sharedEglContext, attrib2_list, 0);
                    this.eglConfig = configs[0];
                }
                int[] values = new int[1];
                EGL14.eglQueryContext(this.eglDisplay, this.eglContext, 12440, values, 0);
                if (this.eglSurface != EGL14.EGL_NO_SURFACE) {
                    throw new IllegalStateException("surface already created");
                }
                int[] surfaceAttribs = {12344};
                android.opengl.EGLSurface eGLSurfaceEglCreateWindowSurface = EGL14.eglCreateWindowSurface(this.eglDisplay, this.eglConfig, this.surface, surfaceAttribs, 0);
                this.eglSurface = eGLSurfaceEglCreateWindowSurface;
                if (eGLSurfaceEglCreateWindowSurface != null) {
                    if (!EGL14.eglMakeCurrent(this.eglDisplay, eGLSurfaceEglCreateWindowSurface, eGLSurfaceEglCreateWindowSurface, this.eglContext)) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.e("eglMakeCurrent failed " + GLUtils.getEGLErrorString(EGL14.eglGetError()));
                        }
                        throw new RuntimeException("eglMakeCurrent failed");
                    }
                    GLES20.glBlendFunc(770, 771);
                    int vertexShader = InstantCameraView.this.loadShader(35633, InstantCameraView.VERTEX_SHADER);
                    int fragmentShader = InstantCameraView.this.loadShader(35632, InstantCameraView.FRAGMENT_SHADER);
                    if (vertexShader != 0 && fragmentShader != 0) {
                        int iGlCreateProgram = GLES20.glCreateProgram();
                        this.drawProgram = iGlCreateProgram;
                        GLES20.glAttachShader(iGlCreateProgram, vertexShader);
                        GLES20.glAttachShader(this.drawProgram, fragmentShader);
                        GLES20.glLinkProgram(this.drawProgram);
                        int[] linkStatus = new int[1];
                        GLES20.glGetProgramiv(this.drawProgram, 35714, linkStatus, 0);
                        if (linkStatus[0] != 0) {
                            this.positionHandle = GLES20.glGetAttribLocation(this.drawProgram, "aPosition");
                            this.textureHandle = GLES20.glGetAttribLocation(this.drawProgram, "aTextureCoord");
                            this.scaleXHandle = GLES20.glGetUniformLocation(this.drawProgram, "scaleX");
                            this.scaleYHandle = GLES20.glGetUniformLocation(this.drawProgram, "scaleY");
                            this.alphaHandle = GLES20.glGetUniformLocation(this.drawProgram, "alpha");
                            this.vertexMatrixHandle = GLES20.glGetUniformLocation(this.drawProgram, "uMVPMatrix");
                            this.textureMatrixHandle = GLES20.glGetUniformLocation(this.drawProgram, "uSTMatrix");
                            return;
                        }
                        GLES20.glDeleteProgram(this.drawProgram);
                        this.drawProgram = 0;
                        return;
                    }
                    return;
                }
                throw new RuntimeException("surface was null");
            } catch (Exception ioe) {
                throw new RuntimeException(ioe);
            }
        }

        public /* synthetic */ void lambda$prepareEncoder$4$InstantCameraView$VideoRecorder() {
            if (InstantCameraView.this.cancelled) {
                return;
            }
            try {
                InstantCameraView.this.performHapticFeedback(3, 2);
            } catch (Exception e) {
            }
            AndroidUtilities.lockOrientation(InstantCameraView.this.baseFragment.getParentActivity());
            InstantCameraView.this.recording = true;
            InstantCameraView.this.recordStartTime = System.currentTimeMillis();
            AndroidUtilities.runOnUIThread(InstantCameraView.this.timerRunnable);
            NotificationCenter.getInstance(InstantCameraView.this.currentAccount).postNotificationName(NotificationCenter.recordStarted, Integer.valueOf(InstantCameraView.this.recordingGuid));
        }

        public Surface getInputSurface() {
            return this.surface;
        }

        private void didWriteData(File file, long availableSize, boolean last) {
            if (this.videoConvertFirstWrite) {
                FileLoader.getInstance(InstantCameraView.this.currentAccount).uploadFile(file.toString(), InstantCameraView.this.isSecretChat, false, 1, ConnectionsManager.FileTypeVideo, true);
                this.videoConvertFirstWrite = false;
                if (last) {
                    FileLoader.getInstance(InstantCameraView.this.currentAccount).checkUploadNewDataAvailable(file.toString(), InstantCameraView.this.isSecretChat, availableSize, last ? file.length() : 0L);
                    return;
                }
                return;
            }
            FileLoader.getInstance(InstantCameraView.this.currentAccount).checkUploadNewDataAvailable(file.toString(), InstantCameraView.this.isSecretChat, availableSize, last ? file.length() : 0L);
        }

        public void drainEncoder(boolean endOfStream) throws Exception {
            ByteBuffer encodedData;
            ByteBuffer encodedData2;
            if (endOfStream) {
                this.videoEncoder.signalEndOfInputStream();
            }
            ByteBuffer[] encoderOutputBuffers = null;
            int i = 21;
            if (Build.VERSION.SDK_INT < 21) {
                encoderOutputBuffers = this.videoEncoder.getOutputBuffers();
            }
            while (true) {
                int encoderStatus = this.videoEncoder.dequeueOutputBuffer(this.videoBufferInfo, OkHttpUtils.DEFAULT_MILLISECONDS);
                byte b = 1;
                if (encoderStatus == -1) {
                    if (!endOfStream) {
                        break;
                    } else {
                        i = 21;
                    }
                } else {
                    if (encoderStatus == -3) {
                        if (Build.VERSION.SDK_INT < i) {
                            encoderOutputBuffers = this.videoEncoder.getOutputBuffers();
                        }
                    } else if (encoderStatus == -2) {
                        MediaFormat newFormat = this.videoEncoder.getOutputFormat();
                        if (this.videoTrackIndex == -5) {
                            this.videoTrackIndex = this.mediaMuxer.addTrack(newFormat, false);
                        }
                    } else if (encoderStatus < 0) {
                        continue;
                    } else {
                        if (Build.VERSION.SDK_INT < i) {
                            encodedData = encoderOutputBuffers[encoderStatus];
                        } else {
                            encodedData = this.videoEncoder.getOutputBuffer(encoderStatus);
                        }
                        if (encodedData == null) {
                            throw new RuntimeException("encoderOutputBuffer " + encoderStatus + " was null");
                        }
                        if (this.videoBufferInfo.size > 1) {
                            if ((this.videoBufferInfo.flags & 2) == 0) {
                                long availableSize = this.mediaMuxer.writeSampleData(this.videoTrackIndex, encodedData, this.videoBufferInfo, true);
                                if (availableSize != 0) {
                                    didWriteData(this.videoFile, availableSize, false);
                                }
                            } else if (this.videoTrackIndex == -5) {
                                byte[] csd = new byte[this.videoBufferInfo.size];
                                encodedData.limit(this.videoBufferInfo.offset + this.videoBufferInfo.size);
                                encodedData.position(this.videoBufferInfo.offset);
                                encodedData.get(csd);
                                ByteBuffer sps = null;
                                ByteBuffer pps = null;
                                int a = this.videoBufferInfo.size - 1;
                                while (true) {
                                    if (a >= 0 && a > 3) {
                                        if (csd[a] != b || csd[a - 1] != 0 || csd[a - 2] != 0 || csd[a - 3] != 0) {
                                            a--;
                                            b = 1;
                                        } else {
                                            sps = ByteBuffer.allocate(a - 3);
                                            pps = ByteBuffer.allocate(this.videoBufferInfo.size - (a - 3));
                                            sps.put(csd, 0, a - 3).position(0);
                                            pps.put(csd, a - 3, this.videoBufferInfo.size - (a - 3)).position(0);
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                                int a2 = this.videoWidth;
                                MediaFormat newFormat2 = MediaFormat.createVideoFormat("video/avc", a2, this.videoHeight);
                                if (sps != null && pps != null) {
                                    newFormat2.setByteBuffer("csd-0", sps);
                                    newFormat2.setByteBuffer("csd-1", pps);
                                }
                                this.videoTrackIndex = this.mediaMuxer.addTrack(newFormat2, false);
                            }
                        }
                        this.videoEncoder.releaseOutputBuffer(encoderStatus, false);
                        if ((this.videoBufferInfo.flags & 4) != 0) {
                            break;
                        }
                    }
                    i = 21;
                }
            }
            if (Build.VERSION.SDK_INT < i) {
                encoderOutputBuffers = this.audioEncoder.getOutputBuffers();
            }
            while (true) {
                int encoderStatus2 = this.audioEncoder.dequeueOutputBuffer(this.audioBufferInfo, 0L);
                if (encoderStatus2 == -1) {
                    if (endOfStream) {
                        if (!this.running && this.sendWhenDone == 0) {
                            return;
                        }
                    } else {
                        return;
                    }
                } else if (encoderStatus2 == -3) {
                    if (Build.VERSION.SDK_INT < i) {
                        encoderOutputBuffers = this.audioEncoder.getOutputBuffers();
                    }
                } else if (encoderStatus2 == -2) {
                    MediaFormat newFormat3 = this.audioEncoder.getOutputFormat();
                    if (this.audioTrackIndex == -5) {
                        this.audioTrackIndex = this.mediaMuxer.addTrack(newFormat3, true);
                    }
                } else if (encoderStatus2 < 0) {
                    continue;
                } else {
                    if (Build.VERSION.SDK_INT < i) {
                        encodedData2 = encoderOutputBuffers[encoderStatus2];
                    } else {
                        encodedData2 = this.audioEncoder.getOutputBuffer(encoderStatus2);
                    }
                    if (encodedData2 == null) {
                        throw new RuntimeException("encoderOutputBuffer " + encoderStatus2 + " was null");
                    }
                    if ((this.audioBufferInfo.flags & 2) != 0) {
                        this.audioBufferInfo.size = 0;
                    }
                    if (this.audioBufferInfo.size != 0) {
                        long availableSize2 = this.mediaMuxer.writeSampleData(this.audioTrackIndex, encodedData2, this.audioBufferInfo, false);
                        if (availableSize2 != 0) {
                            didWriteData(this.videoFile, availableSize2, false);
                        }
                    }
                    this.audioEncoder.releaseOutputBuffer(encoderStatus2, false);
                    if ((this.audioBufferInfo.flags & 4) != 0) {
                        return;
                    }
                }
                i = 21;
            }
        }

        protected void finalize() throws Throwable {
            try {
                if (this.eglDisplay != EGL14.EGL_NO_DISPLAY) {
                    EGL14.eglMakeCurrent(this.eglDisplay, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                    EGL14.eglDestroyContext(this.eglDisplay, this.eglContext);
                    EGL14.eglReleaseThread();
                    EGL14.eglTerminate(this.eglDisplay);
                    this.eglDisplay = EGL14.EGL_NO_DISPLAY;
                    this.eglContext = EGL14.EGL_NO_CONTEXT;
                    this.eglConfig = null;
                }
            } finally {
                super.finalize();
            }
        }
    }
}
