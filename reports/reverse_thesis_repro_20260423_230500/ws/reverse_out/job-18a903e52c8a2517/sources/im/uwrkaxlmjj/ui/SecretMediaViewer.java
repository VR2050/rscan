package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.util.SparseArray;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.VelocityTracker;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.ui.AspectRatioFrameLayout;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.Scroller;
import im.uwrkaxlmjj.ui.components.VideoPlayer;
import java.io.File;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class SecretMediaViewer implements NotificationCenter.NotificationCenterDelegate, GestureDetector.OnGestureListener, GestureDetector.OnDoubleTapListener {
    private static volatile SecretMediaViewer Instance = null;
    private ActionBar actionBar;
    private float animateToClipBottom;
    private float animateToClipHorizontal;
    private float animateToClipTop;
    private float animateToScale;
    private float animateToX;
    private float animateToY;
    private long animationStartTime;
    private float animationValue;
    private AspectRatioFrameLayout aspectRatioFrameLayout;
    private float clipBottom;
    private float clipHorizontal;
    private float clipTop;
    private long closeTime;
    private boolean closeVideoAfterWatch;
    private FrameLayoutDrawer containerView;
    private int currentAccount;
    private AnimatorSet currentActionBarAnimation;
    private int currentChannelId;
    private MessageObject currentMessageObject;
    private PhotoViewer.PhotoViewerProvider currentProvider;
    private int currentRotation;
    private ImageReceiver.BitmapHolder currentThumb;
    private boolean disableShowCheck;
    private boolean discardTap;
    private boolean doubleTap;
    private float dragY;
    private boolean draggingDown;
    private GestureDetector gestureDetector;
    private AnimatorSet imageMoveAnimation;
    private boolean invalidCoords;
    private boolean isPhotoVisible;
    private boolean isPlaying;
    private boolean isVideo;
    private boolean isVisible;
    private Object lastInsets;
    private float maxX;
    private float maxY;
    private float minX;
    private float minY;
    private float moveStartX;
    private float moveStartY;
    private boolean moving;
    private long openTime;
    private Activity parentActivity;
    private Runnable photoAnimationEndRunnable;
    private int photoAnimationInProgress;
    private long photoTransitionAnimationStartTime;
    private float pinchCenterX;
    private float pinchCenterY;
    private float pinchStartDistance;
    private float pinchStartX;
    private float pinchStartY;
    private int playerRetryPlayCount;
    private Scroller scroller;
    private SecretDeleteTimer secretDeleteTimer;
    private boolean textureUploaded;
    private float translationX;
    private float translationY;
    private boolean useOvershootForScale;
    private VelocityTracker velocityTracker;
    private float videoCrossfadeAlpha;
    private long videoCrossfadeAlphaLastTime;
    private boolean videoCrossfadeStarted;
    private VideoPlayer videoPlayer;
    private TextureView videoTextureView;
    private boolean videoWatchedOneTime;
    private WindowManager.LayoutParams windowLayoutParams;
    private FrameLayout windowView;
    private boolean zoomAnimation;
    private boolean zooming;
    private ImageReceiver centerImage = new ImageReceiver();
    private int[] coords = new int[2];
    private boolean isActionBarVisible = true;
    private PhotoBackgroundDrawable photoBackgroundDrawable = new PhotoBackgroundDrawable(-16777216);
    private Paint blackPaint = new Paint();
    private float scale = 1.0f;
    private DecelerateInterpolator interpolator = new DecelerateInterpolator(1.5f);
    private float pinchStartScale = 1.0f;
    private boolean canDragDown = true;

    static /* synthetic */ int access$1210(SecretMediaViewer x0) {
        int i = x0.playerRetryPlayCount;
        x0.playerRetryPlayCount = i - 1;
        return i;
    }

    private class FrameLayoutDrawer extends FrameLayout {
        public FrameLayoutDrawer(Context context) {
            super(context);
            setWillNotDraw(false);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            SecretMediaViewer.this.processTouchEvent(event);
            return true;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            SecretMediaViewer.this.onDraw(canvas);
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            return child != SecretMediaViewer.this.aspectRatioFrameLayout && super.drawChild(canvas, child, drawingTime);
        }
    }

    private class SecretDeleteTimer extends FrameLayout {
        private Paint afterDeleteProgressPaint;
        private Paint circlePaint;
        private Paint deleteProgressPaint;
        private RectF deleteProgressRect;
        private long destroyTime;
        private long destroyTtl;
        private Drawable drawable;
        private ArrayList<Particle> freeParticles;
        private long lastAnimationTime;
        private Paint particlePaint;
        private ArrayList<Particle> particles;
        private boolean useVideoProgress;

        private class Particle {
            float alpha;
            float currentTime;
            float lifeTime;
            float velocity;
            float vx;
            float vy;
            float x;
            float y;

            private Particle() {
            }

            /* synthetic */ Particle(SecretDeleteTimer x0, AnonymousClass1 x1) {
                this();
            }
        }

        public SecretDeleteTimer(Context context) {
            super(context);
            this.deleteProgressRect = new RectF();
            this.particles = new ArrayList<>();
            this.freeParticles = new ArrayList<>();
            setWillNotDraw(false);
            Paint paint = new Paint(1);
            this.particlePaint = paint;
            paint.setStrokeWidth(AndroidUtilities.dp(1.5f));
            this.particlePaint.setColor(-1644826);
            this.particlePaint.setStrokeCap(Paint.Cap.ROUND);
            this.particlePaint.setStyle(Paint.Style.STROKE);
            Paint paint2 = new Paint(1);
            this.deleteProgressPaint = paint2;
            paint2.setColor(-1644826);
            Paint paint3 = new Paint(1);
            this.afterDeleteProgressPaint = paint3;
            paint3.setStyle(Paint.Style.STROKE);
            this.afterDeleteProgressPaint.setStrokeCap(Paint.Cap.ROUND);
            this.afterDeleteProgressPaint.setColor(-1644826);
            this.afterDeleteProgressPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            Paint paint4 = new Paint(1);
            this.circlePaint = paint4;
            paint4.setColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
            this.drawable = context.getResources().getDrawable(R.drawable.flame_small);
            for (int a = 0; a < 40; a++) {
                this.freeParticles.add(new Particle(this, null));
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setDestroyTime(long time, long ttl, boolean videoProgress) {
            this.destroyTime = time;
            this.destroyTtl = ttl;
            this.useVideoProgress = videoProgress;
            this.lastAnimationTime = System.currentTimeMillis();
            invalidate();
        }

        private void updateParticles(long dt) {
            int count = this.particles.size();
            int a = 0;
            while (a < count) {
                Particle particle = this.particles.get(a);
                if (particle.currentTime >= particle.lifeTime) {
                    if (this.freeParticles.size() < 40) {
                        this.freeParticles.add(particle);
                    }
                    this.particles.remove(a);
                    a--;
                    count--;
                } else {
                    particle.alpha = 1.0f - AndroidUtilities.decelerateInterpolator.getInterpolation(particle.currentTime / particle.lifeTime);
                    particle.x += ((particle.vx * particle.velocity) * dt) / 500.0f;
                    particle.y += ((particle.vy * particle.velocity) * dt) / 500.0f;
                    particle.currentTime += dt;
                }
                a++;
            }
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            int y = (getMeasuredHeight() / 2) - (AndroidUtilities.dp(28.0f) / 2);
            this.deleteProgressRect.set(getMeasuredWidth() - AndroidUtilities.dp(49.0f), y, getMeasuredWidth() - AndroidUtilities.dp(21.0f), AndroidUtilities.dp(28.0f) + y);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            float progress;
            Particle newParticle;
            float progress2;
            if (SecretMediaViewer.this.currentMessageObject != null && SecretMediaViewer.this.currentMessageObject.messageOwner.destroyTime != 0) {
                canvas.drawCircle(getMeasuredWidth() - AndroidUtilities.dp(35.0f), getMeasuredHeight() / 2, AndroidUtilities.dp(16.0f), this.circlePaint);
                if (this.useVideoProgress) {
                    if (SecretMediaViewer.this.videoPlayer != null) {
                        long duration = SecretMediaViewer.this.videoPlayer.getDuration();
                        long position = SecretMediaViewer.this.videoPlayer.getCurrentPosition();
                        if (duration != C.TIME_UNSET && position != C.TIME_UNSET) {
                            progress2 = 1.0f - (position / duration);
                        } else {
                            progress2 = 1.0f;
                        }
                        progress = progress2;
                    } else {
                        progress = 1.0f;
                    }
                } else {
                    long msTime = System.currentTimeMillis() + ((long) (ConnectionsManager.getInstance(SecretMediaViewer.this.currentAccount).getTimeDifference() * 1000));
                    progress = Math.max(0L, this.destroyTime - msTime) / (this.destroyTtl * 1000.0f);
                }
                int x = getMeasuredWidth() - AndroidUtilities.dp(40.0f);
                int y = ((getMeasuredHeight() - AndroidUtilities.dp(14.0f)) / 2) - AndroidUtilities.dp(0.5f);
                this.drawable.setBounds(x, y, AndroidUtilities.dp(10.0f) + x, AndroidUtilities.dp(14.0f) + y);
                this.drawable.draw(canvas);
                float radProgress = progress * (-360.0f);
                canvas.drawArc(this.deleteProgressRect, -90.0f, radProgress, false, this.afterDeleteProgressPaint);
                int count = this.particles.size();
                for (int a = 0; a < count; a++) {
                    Particle particle = this.particles.get(a);
                    this.particlePaint.setAlpha((int) (particle.alpha * 255.0f));
                    canvas.drawPoint(particle.x, particle.y, this.particlePaint);
                }
                double vx = Math.sin(((double) (radProgress - 90.0f)) * 0.017453292519943295d);
                double vy = -Math.cos(((double) (radProgress - 90.0f)) * 0.017453292519943295d);
                int rad = AndroidUtilities.dp(14.0f);
                float cx = (float) (((-vy) * ((double) rad)) + ((double) this.deleteProgressRect.centerX()));
                float cy = (float) ((((double) rad) * vx) + ((double) this.deleteProgressRect.centerY()));
                int a2 = 0;
                while (a2 < 1) {
                    if (this.freeParticles.isEmpty()) {
                        newParticle = new Particle(this, null);
                    } else {
                        newParticle = this.freeParticles.get(0);
                        this.freeParticles.remove(0);
                    }
                    newParticle.x = cx;
                    newParticle.y = cy;
                    double angle = ((double) (Utilities.random.nextInt(140) - 70)) * 0.017453292519943295d;
                    if (angle < FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE) {
                        angle += 6.283185307179586d;
                    }
                    newParticle.vx = (float) ((Math.cos(angle) * vx) - (Math.sin(angle) * vy));
                    newParticle.vy = (float) ((Math.sin(angle) * vx) + (Math.cos(angle) * vy));
                    newParticle.alpha = 1.0f;
                    newParticle.currentTime = 0.0f;
                    newParticle.lifeTime = Utilities.random.nextInt(100) + 400;
                    newParticle.velocity = (Utilities.random.nextFloat() * 4.0f) + 20.0f;
                    this.particles.add(newParticle);
                    a2++;
                    count = count;
                    rad = rad;
                }
                long newTime = System.currentTimeMillis();
                long dt = newTime - this.lastAnimationTime;
                updateParticles(dt);
                this.lastAnimationTime = newTime;
                invalidate();
            }
        }
    }

    private class PhotoBackgroundDrawable extends ColorDrawable {
        private Runnable drawRunnable;
        private int frame;

        public PhotoBackgroundDrawable(int color) {
            super(color);
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
            if (SecretMediaViewer.this.parentActivity instanceof LaunchActivity) {
                ((LaunchActivity) SecretMediaViewer.this.parentActivity).drawerLayoutContainer.setAllowDrawContent((SecretMediaViewer.this.isPhotoVisible && alpha == 255) ? false : true);
            }
            super.setAlpha(alpha);
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            Runnable runnable;
            super.draw(canvas);
            if (getAlpha() != 0) {
                if (this.frame == 2 && (runnable = this.drawRunnable) != null) {
                    runnable.run();
                    this.drawRunnable = null;
                } else {
                    invalidateSelf();
                }
                this.frame++;
            }
        }
    }

    public static SecretMediaViewer getInstance() {
        SecretMediaViewer localInstance = Instance;
        if (localInstance == null) {
            synchronized (PhotoViewer.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    SecretMediaViewer secretMediaViewer = new SecretMediaViewer();
                    localInstance = secretMediaViewer;
                    Instance = secretMediaViewer;
                }
            }
        }
        return localInstance;
    }

    public static boolean hasInstance() {
        return Instance != null;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.messagesDeleted) {
            boolean scheduled = ((Boolean) args[2]).booleanValue();
            if (scheduled || this.currentMessageObject == null || ((Integer) args[1]).intValue() != 0) {
                return;
            }
            ArrayList<Integer> markAsDeletedMessages = (ArrayList) args[0];
            if (markAsDeletedMessages.contains(Integer.valueOf(this.currentMessageObject.getId()))) {
                if (this.isVideo && !this.videoWatchedOneTime) {
                    this.closeVideoAfterWatch = true;
                    return;
                } else {
                    closePhoto(true, true);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.didCreatedNewDeleteTask) {
            if (this.currentMessageObject == null || this.secretDeleteTimer == null) {
                return;
            }
            SparseArray<ArrayList<Long>> mids = (SparseArray) args[0];
            for (int i = 0; i < mids.size(); i++) {
                int key = mids.keyAt(i);
                ArrayList<Long> arr = mids.get(key);
                for (int a = 0; a < arr.size(); a++) {
                    long mid = arr.get(a).longValue();
                    if (a == 0) {
                        int channelId = (int) (mid >> 32);
                        if (channelId < 0) {
                            channelId = 0;
                        }
                        if (channelId != this.currentChannelId) {
                            return;
                        }
                    }
                    if (this.currentMessageObject.getId() == mid) {
                        this.currentMessageObject.messageOwner.destroyTime = key;
                        this.secretDeleteTimer.invalidate();
                        return;
                    }
                }
            }
            return;
        }
        if (id == NotificationCenter.updateMessageMedia) {
            TLRPC.Message message = (TLRPC.Message) args[0];
            if (this.currentMessageObject.getId() == message.id) {
                if (this.isVideo && !this.videoWatchedOneTime) {
                    this.closeVideoAfterWatch = true;
                } else {
                    closePhoto(true, true);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void preparePlayer(File file) {
        if (this.parentActivity == null) {
            return;
        }
        releasePlayer();
        if (this.videoTextureView == null) {
            AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(this.parentActivity);
            this.aspectRatioFrameLayout = aspectRatioFrameLayout;
            aspectRatioFrameLayout.setVisibility(4);
            this.containerView.addView(this.aspectRatioFrameLayout, 0, LayoutHelper.createFrame(-1, -1, 17));
            TextureView textureView = new TextureView(this.parentActivity);
            this.videoTextureView = textureView;
            textureView.setOpaque(false);
            this.aspectRatioFrameLayout.addView(this.videoTextureView, LayoutHelper.createFrame(-1, -1, 17));
        }
        this.textureUploaded = false;
        this.videoCrossfadeStarted = false;
        TextureView textureView2 = this.videoTextureView;
        this.videoCrossfadeAlpha = 0.0f;
        textureView2.setAlpha(0.0f);
        if (this.videoPlayer == null) {
            VideoPlayer videoPlayer = new VideoPlayer();
            this.videoPlayer = videoPlayer;
            videoPlayer.setTextureView(this.videoTextureView);
            this.videoPlayer.setDelegate(new AnonymousClass1(file));
        }
        this.videoPlayer.preparePlayer(Uri.fromFile(file), "other");
        this.videoPlayer.setPlayWhenReady(true);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.SecretMediaViewer$1, reason: invalid class name */
    class AnonymousClass1 implements VideoPlayer.VideoPlayerDelegate {
        final /* synthetic */ File val$file;

        AnonymousClass1(File file) {
            this.val$file = file;
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onStateChanged(boolean playWhenReady, int playbackState) {
            if (SecretMediaViewer.this.videoPlayer == null || SecretMediaViewer.this.currentMessageObject == null) {
                return;
            }
            if (playbackState == 4 || playbackState == 1) {
                try {
                    SecretMediaViewer.this.parentActivity.getWindow().clearFlags(128);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            } else {
                try {
                    SecretMediaViewer.this.parentActivity.getWindow().addFlags(128);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
            if (playbackState == 3 && SecretMediaViewer.this.aspectRatioFrameLayout.getVisibility() != 0) {
                SecretMediaViewer.this.aspectRatioFrameLayout.setVisibility(0);
            }
            if (!SecretMediaViewer.this.videoPlayer.isPlaying() || playbackState == 4) {
                if (SecretMediaViewer.this.isPlaying) {
                    SecretMediaViewer.this.isPlaying = false;
                    if (playbackState == 4) {
                        SecretMediaViewer.this.videoWatchedOneTime = true;
                        if (!SecretMediaViewer.this.closeVideoAfterWatch) {
                            SecretMediaViewer.this.videoPlayer.seekTo(0L);
                            SecretMediaViewer.this.videoPlayer.play();
                            return;
                        } else {
                            SecretMediaViewer.this.closePhoto(true, true);
                            return;
                        }
                    }
                    return;
                }
                return;
            }
            if (!SecretMediaViewer.this.isPlaying) {
                SecretMediaViewer.this.isPlaying = true;
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onError(Exception e) {
            if (SecretMediaViewer.this.playerRetryPlayCount > 0) {
                SecretMediaViewer.access$1210(SecretMediaViewer.this);
                final File file = this.val$file;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$1$XC0WlzBFEXixD8D0X40LzPjSNtg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onError$0$SecretMediaViewer$1(file);
                    }
                }, 100L);
                return;
            }
            FileLog.e(e);
        }

        public /* synthetic */ void lambda$onError$0$SecretMediaViewer$1(File file) {
            SecretMediaViewer.this.preparePlayer(file);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
            if (SecretMediaViewer.this.aspectRatioFrameLayout != null) {
                if (unappliedRotationDegrees == 90 || unappliedRotationDegrees == 270) {
                    width = height;
                    height = width;
                }
                SecretMediaViewer.this.aspectRatioFrameLayout.setAspectRatio(height == 0 ? 1.0f : (width * pixelWidthHeightRatio) / height, unappliedRotationDegrees);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onRenderedFirstFrame() {
            if (!SecretMediaViewer.this.textureUploaded) {
                SecretMediaViewer.this.textureUploaded = true;
                SecretMediaViewer.this.containerView.invalidate();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        }
    }

    private void releasePlayer() {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            this.playerRetryPlayCount = 0;
            videoPlayer.releasePlayer(true);
            this.videoPlayer = null;
        }
        try {
            if (this.parentActivity != null) {
                this.parentActivity.getWindow().clearFlags(128);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
        if (aspectRatioFrameLayout != null) {
            this.containerView.removeView(aspectRatioFrameLayout);
            this.aspectRatioFrameLayout = null;
        }
        if (this.videoTextureView != null) {
            this.videoTextureView = null;
        }
        this.isPlaying = false;
    }

    public void setParentActivity(Activity activity) {
        int i = UserConfig.selectedAccount;
        this.currentAccount = i;
        this.centerImage.setCurrentAccount(i);
        if (this.parentActivity == activity) {
            return;
        }
        this.parentActivity = activity;
        this.scroller = new Scroller(activity);
        FrameLayout frameLayout = new FrameLayout(activity) { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.2
            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                if (Build.VERSION.SDK_INT >= 21 && SecretMediaViewer.this.lastInsets != null) {
                    WindowInsets insets = (WindowInsets) SecretMediaViewer.this.lastInsets;
                    if (AndroidUtilities.incorrectDisplaySizeFix) {
                        if (heightSize > AndroidUtilities.displaySize.y) {
                            heightSize = AndroidUtilities.displaySize.y;
                        }
                        heightSize += AndroidUtilities.statusBarHeight;
                    }
                    heightSize -= insets.getSystemWindowInsetBottom();
                    widthSize -= insets.getSystemWindowInsetRight();
                } else if (heightSize > AndroidUtilities.displaySize.y) {
                    heightSize = AndroidUtilities.displaySize.y;
                }
                setMeasuredDimension(widthSize, heightSize);
                if (Build.VERSION.SDK_INT >= 21 && SecretMediaViewer.this.lastInsets != null) {
                    widthSize -= ((WindowInsets) SecretMediaViewer.this.lastInsets).getSystemWindowInsetLeft();
                }
                SecretMediaViewer.this.containerView.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                int x = 0;
                if (Build.VERSION.SDK_INT >= 21 && SecretMediaViewer.this.lastInsets != null) {
                    x = 0 + ((WindowInsets) SecretMediaViewer.this.lastInsets).getSystemWindowInsetLeft();
                }
                SecretMediaViewer.this.containerView.layout(x, 0, SecretMediaViewer.this.containerView.getMeasuredWidth() + x, SecretMediaViewer.this.containerView.getMeasuredHeight());
                if (changed) {
                    if (SecretMediaViewer.this.imageMoveAnimation == null) {
                        SecretMediaViewer.this.scale = 1.0f;
                        SecretMediaViewer.this.translationX = 0.0f;
                        SecretMediaViewer.this.translationY = 0.0f;
                    }
                    SecretMediaViewer secretMediaViewer = SecretMediaViewer.this;
                    secretMediaViewer.updateMinMax(secretMediaViewer.scale);
                }
            }
        };
        this.windowView = frameLayout;
        frameLayout.setBackgroundDrawable(this.photoBackgroundDrawable);
        this.windowView.setFocusable(true);
        this.windowView.setFocusableInTouchMode(true);
        FrameLayoutDrawer frameLayoutDrawer = new FrameLayoutDrawer(activity) { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.3
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (SecretMediaViewer.this.secretDeleteTimer != null) {
                    int y = ((ActionBar.getCurrentActionBarHeight() - SecretMediaViewer.this.secretDeleteTimer.getMeasuredHeight()) / 2) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                    SecretMediaViewer.this.secretDeleteTimer.layout(SecretMediaViewer.this.secretDeleteTimer.getLeft(), y, SecretMediaViewer.this.secretDeleteTimer.getRight(), SecretMediaViewer.this.secretDeleteTimer.getMeasuredHeight() + y);
                }
            }
        };
        this.containerView = frameLayoutDrawer;
        frameLayoutDrawer.setFocusable(false);
        this.windowView.addView(this.containerView);
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.containerView.getLayoutParams();
        layoutParams.width = -1;
        layoutParams.height = -1;
        layoutParams.gravity = 51;
        this.containerView.setLayoutParams(layoutParams);
        if (Build.VERSION.SDK_INT >= 21) {
            this.containerView.setFitsSystemWindows(true);
            this.containerView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$V36UmrgrbjVdqbDRhgar7YN8PDY
                @Override // android.view.View.OnApplyWindowInsetsListener
                public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                    return this.f$0.lambda$setParentActivity$0$SecretMediaViewer(view, windowInsets);
                }
            });
            this.containerView.setSystemUiVisibility(1280);
        }
        GestureDetector gestureDetector = new GestureDetector(this.containerView.getContext(), this);
        this.gestureDetector = gestureDetector;
        gestureDetector.setOnDoubleTapListener(this);
        ActionBar actionBar = new ActionBar(activity);
        this.actionBar = actionBar;
        actionBar.setTitleColor(-1);
        this.actionBar.setSubtitleColor(-1);
        this.actionBar.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.actionBar.setOccupyStatusBar(Build.VERSION.SDK_INT >= 21);
        this.actionBar.setItemsBackgroundColor(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR, false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitleRightMargin(AndroidUtilities.dp(70.0f));
        this.containerView.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.4
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    SecretMediaViewer.this.closePhoto(true, false);
                }
            }
        });
        SecretDeleteTimer secretDeleteTimer = new SecretDeleteTimer(activity);
        this.secretDeleteTimer = secretDeleteTimer;
        this.containerView.addView(secretDeleteTimer, LayoutHelper.createFrame(119.0f, 48.0f, 53, 0.0f, 0.0f, 0.0f, 0.0f));
        WindowManager.LayoutParams layoutParams2 = new WindowManager.LayoutParams();
        this.windowLayoutParams = layoutParams2;
        layoutParams2.height = -1;
        this.windowLayoutParams.format = -3;
        this.windowLayoutParams.width = -1;
        this.windowLayoutParams.gravity = 48;
        this.windowLayoutParams.type = 99;
        if (Build.VERSION.SDK_INT >= 21) {
            this.windowLayoutParams.flags = -2147417848;
        } else {
            this.windowLayoutParams.flags = 8;
        }
        this.windowLayoutParams.flags |= 8192;
        this.centerImage.setParentView(this.containerView);
        this.centerImage.setForceCrossfade(true);
    }

    public /* synthetic */ WindowInsets lambda$setParentActivity$0$SecretMediaViewer(View v, WindowInsets insets) {
        WindowInsets oldInsets = (WindowInsets) this.lastInsets;
        this.lastInsets = insets;
        if (oldInsets == null || !oldInsets.toString().equals(insets.toString())) {
            this.windowView.requestLayout();
        }
        return insets.consumeSystemWindowInsets();
    }

    public void openMedia(MessageObject messageObject, PhotoViewer.PhotoViewerProvider provider) {
        PhotoViewer.PlaceProviderObject object;
        final PhotoViewer.PlaceProviderObject object2;
        char c;
        if (this.parentActivity == null || messageObject == null || !messageObject.needDrawBluredPreview() || provider == null || (object = provider.getPlaceForPhoto(messageObject, null, 0, true)) == null) {
            return;
        }
        this.currentProvider = provider;
        this.openTime = System.currentTimeMillis();
        this.closeTime = 0L;
        this.isActionBarVisible = true;
        this.isPhotoVisible = true;
        this.draggingDown = false;
        AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
        if (aspectRatioFrameLayout != null) {
            aspectRatioFrameLayout.setVisibility(4);
        }
        releasePlayer();
        this.pinchStartDistance = 0.0f;
        this.pinchStartScale = 1.0f;
        this.pinchCenterX = 0.0f;
        this.pinchCenterY = 0.0f;
        this.pinchStartX = 0.0f;
        this.pinchStartY = 0.0f;
        this.moveStartX = 0.0f;
        this.moveStartY = 0.0f;
        this.zooming = false;
        this.moving = false;
        this.doubleTap = false;
        this.invalidCoords = false;
        this.canDragDown = true;
        updateMinMax(this.scale);
        this.photoBackgroundDrawable.setAlpha(0);
        this.containerView.setAlpha(1.0f);
        this.containerView.setVisibility(0);
        this.secretDeleteTimer.setAlpha(1.0f);
        this.isVideo = false;
        this.videoWatchedOneTime = false;
        this.closeVideoAfterWatch = false;
        this.disableShowCheck = true;
        this.centerImage.setManualAlphaAnimator(false);
        RectF drawRegion = object.imageReceiver.getDrawRegion();
        float width = drawRegion.width();
        float height = drawRegion.height();
        int viewWidth = AndroidUtilities.displaySize.x;
        int viewHeight = (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0) + AndroidUtilities.displaySize.y;
        this.scale = Math.max(width / viewWidth, height / viewHeight);
        this.translationX = ((object.viewX + drawRegion.left) + (width / 2.0f)) - (viewWidth / 2);
        this.translationY = ((object.viewY + drawRegion.top) + (height / 2.0f)) - (viewHeight / 2);
        this.clipHorizontal = Math.abs(drawRegion.left - object.imageReceiver.getImageX());
        int clipVertical = (int) Math.abs(drawRegion.top - object.imageReceiver.getImageY());
        int[] coords2 = new int[2];
        object.parentView.getLocationInWindow(coords2);
        float f = ((coords2[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight)) - (object.viewY + drawRegion.top)) + object.clipTopAddition;
        this.clipTop = f;
        if (f < 0.0f) {
            this.clipTop = 0.0f;
        }
        float height2 = (((object.viewY + drawRegion.top) + ((int) height)) - ((coords2[1] + object.parentView.getHeight()) - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight))) + object.clipBottomAddition;
        this.clipBottom = height2;
        if (height2 < 0.0f) {
            this.clipBottom = 0.0f;
        }
        this.clipTop = Math.max(this.clipTop, clipVertical);
        this.clipBottom = Math.max(this.clipBottom, clipVertical);
        this.animationStartTime = System.currentTimeMillis();
        this.animateToX = 0.0f;
        this.animateToY = 0.0f;
        this.animateToClipBottom = 0.0f;
        this.animateToClipHorizontal = 0.0f;
        this.animateToClipTop = 0.0f;
        this.animateToScale = 1.0f;
        this.zoomAnimation = true;
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagesDeleted);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateMessageMedia);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didCreatedNewDeleteTask);
        this.currentChannelId = messageObject.messageOwner.to_id != null ? messageObject.messageOwner.to_id.channel_id : 0;
        toggleActionBar(true, false);
        this.currentMessageObject = messageObject;
        TLRPC.Document document = messageObject.getDocument();
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        this.currentThumb = object.imageReceiver.getThumbBitmapSafe();
        if (document == null) {
            object2 = object;
            c = 4;
            this.actionBar.setTitle(LocaleController.getString("DisappearingPhoto", R.string.DisappearingPhoto));
            TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(messageObject.photoThumbs, AndroidUtilities.getPhotoSize());
            this.centerImage.setImage(ImageLocation.getForObject(sizeFull, messageObject.photoThumbsObject), (String) null, this.currentThumb != null ? new BitmapDrawable(this.currentThumb.bitmap) : null, -1, (String) null, messageObject, 2);
            this.secretDeleteTimer.setDestroyTime(((long) messageObject.messageOwner.destroyTime) * 1000, messageObject.messageOwner.ttl, false);
        } else if (!MessageObject.isGifDocument(document)) {
            object2 = object;
            c = 4;
            this.playerRetryPlayCount = 1;
            this.actionBar.setTitle(LocaleController.getString("DisappearingVideo", R.string.DisappearingVideo));
            File f2 = new File(messageObject.messageOwner.attachPath);
            if (f2.exists()) {
                preparePlayer(f2);
            } else {
                File file = FileLoader.getPathToMessage(messageObject.messageOwner);
                File encryptedFile = new File(file.getAbsolutePath() + ".enc");
                if (encryptedFile.exists()) {
                    file = encryptedFile;
                }
                preparePlayer(file);
            }
            this.isVideo = true;
            this.centerImage.setImage((ImageLocation) null, (String) null, this.currentThumb != null ? new BitmapDrawable(this.currentThumb.bitmap) : null, -1, (String) null, messageObject, 2);
            long destroyTime = ((long) messageObject.messageOwner.destroyTime) * 1000;
            long currentTime = System.currentTimeMillis() + ((long) (ConnectionsManager.getInstance(this.currentAccount).getTimeDifference() * 1000));
            long timeToDestroy = destroyTime - currentTime;
            long duration = messageObject.getDuration() * 1000;
            if (duration > timeToDestroy) {
                this.secretDeleteTimer.setDestroyTime(-1L, -1L, true);
            } else {
                this.secretDeleteTimer.setDestroyTime(((long) messageObject.messageOwner.destroyTime) * 1000, messageObject.messageOwner.ttl, false);
            }
        } else {
            this.actionBar.setTitle(LocaleController.getString("DisappearingGif", R.string.DisappearingGif));
            c = 4;
            object2 = object;
            this.centerImage.setImage(ImageLocation.getForDocument(document), (String) null, this.currentThumb != null ? new BitmapDrawable(this.currentThumb.bitmap) : null, -1, (String) null, messageObject, 1);
            this.secretDeleteTimer.setDestroyTime(((long) messageObject.messageOwner.destroyTime) * 1000, messageObject.messageOwner.ttl, false);
        }
        try {
            if (this.windowView.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeView(this.windowView);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        WindowManager wm2 = (WindowManager) this.parentActivity.getSystemService("window");
        wm2.addView(this.windowView, this.windowLayoutParams);
        this.secretDeleteTimer.invalidate();
        this.isVisible = true;
        AnimatorSet animatorSet = new AnimatorSet();
        this.imageMoveAnimation = animatorSet;
        Animator[] animatorArr = new Animator[5];
        animatorArr[0] = ObjectAnimator.ofFloat(this.actionBar, "alpha", 0.0f, 1.0f);
        animatorArr[1] = ObjectAnimator.ofFloat(this.secretDeleteTimer, "alpha", 0.0f, 1.0f);
        animatorArr[2] = ObjectAnimator.ofInt(this.photoBackgroundDrawable, "alpha", 0, 255);
        animatorArr[3] = ObjectAnimator.ofFloat(this.secretDeleteTimer, "alpha", 0.0f, 1.0f);
        animatorArr[c] = ObjectAnimator.ofFloat(this, "animationValue", 0.0f, 1.0f);
        animatorSet.playTogether(animatorArr);
        this.photoAnimationInProgress = 3;
        this.photoAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$35RftjbR4GNUgBQuZvECtpVDxGs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$openMedia$1$SecretMediaViewer();
            }
        };
        this.imageMoveAnimation.setDuration(250L);
        this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (SecretMediaViewer.this.photoAnimationEndRunnable != null) {
                    SecretMediaViewer.this.photoAnimationEndRunnable.run();
                    SecretMediaViewer.this.photoAnimationEndRunnable = null;
                }
            }
        });
        this.photoTransitionAnimationStartTime = System.currentTimeMillis();
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(2, null);
        }
        this.imageMoveAnimation.setInterpolator(new DecelerateInterpolator());
        this.photoBackgroundDrawable.frame = 0;
        this.photoBackgroundDrawable.drawRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$SQztj-DytbFfBxIGacH55nxrDwU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$openMedia$2$SecretMediaViewer(object2);
            }
        };
        this.imageMoveAnimation.start();
    }

    public /* synthetic */ void lambda$openMedia$1$SecretMediaViewer() {
        this.photoAnimationInProgress = 0;
        this.imageMoveAnimation = null;
        if (this.containerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.containerView.invalidate();
    }

    public /* synthetic */ void lambda$openMedia$2$SecretMediaViewer(PhotoViewer.PlaceProviderObject object) {
        this.disableShowCheck = false;
        object.imageReceiver.setVisible(false, true);
    }

    public boolean isShowingImage(MessageObject object) {
        MessageObject messageObject;
        return (!this.isVisible || this.disableShowCheck || object == null || (messageObject = this.currentMessageObject) == null || messageObject.getId() != object.getId()) ? false : true;
    }

    private void toggleActionBar(boolean show, boolean animated) {
        if (show) {
            this.actionBar.setVisibility(0);
        }
        this.actionBar.setEnabled(show);
        this.isActionBarVisible = show;
        if (animated) {
            ArrayList<Animator> arrayList = new ArrayList<>();
            ActionBar actionBar = this.actionBar;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(actionBar, "alpha", fArr));
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentActionBarAnimation = animatorSet;
            animatorSet.playTogether(arrayList);
            if (!show) {
                this.currentActionBarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.6
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (SecretMediaViewer.this.currentActionBarAnimation != null && SecretMediaViewer.this.currentActionBarAnimation.equals(animation)) {
                            SecretMediaViewer.this.actionBar.setVisibility(8);
                            SecretMediaViewer.this.currentActionBarAnimation = null;
                        }
                    }
                });
            }
            this.currentActionBarAnimation.setDuration(200L);
            this.currentActionBarAnimation.start();
            return;
        }
        this.actionBar.setAlpha(show ? 1.0f : 0.0f);
        if (!show) {
            this.actionBar.setVisibility(8);
        }
    }

    public boolean isVisible() {
        return this.isVisible;
    }

    public void destroyPhotoViewer() {
        FrameLayout frameLayout;
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagesDeleted);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateMessageMedia);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didCreatedNewDeleteTask);
        this.isVisible = false;
        this.currentProvider = null;
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        releasePlayer();
        if (this.parentActivity != null && (frameLayout = this.windowView) != null) {
            try {
                if (frameLayout.getParent() != null) {
                    WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                    wm.removeViewImmediate(this.windowView);
                }
                this.windowView = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        Instance = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:102:0x031f  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x02a6  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x02bd  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onDraw(android.graphics.Canvas r28) {
        /*
            Method dump skipped, instruction units count: 805
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.SecretMediaViewer.onDraw(android.graphics.Canvas):void");
    }

    public float getVideoCrossfadeAlpha() {
        return this.videoCrossfadeAlpha;
    }

    public void setVideoCrossfadeAlpha(float value) {
        this.videoCrossfadeAlpha = value;
        this.containerView.invalidate();
    }

    private boolean checkPhotoAnimation() {
        if (this.photoAnimationInProgress != 0 && Math.abs(this.photoTransitionAnimationStartTime - System.currentTimeMillis()) >= 500) {
            Runnable runnable = this.photoAnimationEndRunnable;
            if (runnable != null) {
                runnable.run();
                this.photoAnimationEndRunnable = null;
            }
            this.photoAnimationInProgress = 0;
        }
        return this.photoAnimationInProgress != 0;
    }

    public long getOpenTime() {
        return this.openTime;
    }

    public long getCloseTime() {
        return this.closeTime;
    }

    public MessageObject getCurrentMessageObject() {
        return this.currentMessageObject;
    }

    public void closePhoto(boolean animated, boolean byDelete) {
        final PhotoViewer.PlaceProviderObject object;
        if (this.parentActivity != null && this.isPhotoVisible && !checkPhotoAnimation()) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagesDeleted);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateMessageMedia);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didCreatedNewDeleteTask);
            this.isActionBarVisible = false;
            VelocityTracker velocityTracker = this.velocityTracker;
            if (velocityTracker != null) {
                velocityTracker.recycle();
                this.velocityTracker = null;
            }
            this.closeTime = System.currentTimeMillis();
            if (this.currentProvider != null && !(this.currentMessageObject.messageOwner.media.photo instanceof TLRPC.TL_photoEmpty) && !(this.currentMessageObject.messageOwner.media.document instanceof TLRPC.TL_documentEmpty)) {
                object = this.currentProvider.getPlaceForPhoto(this.currentMessageObject, null, 0, true);
            } else {
                object = null;
            }
            VideoPlayer videoPlayer = this.videoPlayer;
            if (videoPlayer != null) {
                videoPlayer.pause();
            }
            if (animated) {
                this.photoAnimationInProgress = 3;
                this.containerView.invalidate();
                this.imageMoveAnimation = new AnimatorSet();
                if (object != null && object.imageReceiver.getThumbBitmap() != null && !byDelete) {
                    object.imageReceiver.setVisible(false, true);
                    RectF drawRegion = object.imageReceiver.getDrawRegion();
                    float width = drawRegion.right - drawRegion.left;
                    float height = drawRegion.bottom - drawRegion.top;
                    int viewWidth = AndroidUtilities.displaySize.x;
                    int viewHeight = AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                    this.animateToScale = Math.max(width / viewWidth, height / viewHeight);
                    this.animateToX = ((object.viewX + drawRegion.left) + (width / 2.0f)) - (viewWidth / 2);
                    this.animateToY = ((object.viewY + drawRegion.top) + (height / 2.0f)) - (viewHeight / 2);
                    this.animateToClipHorizontal = Math.abs(drawRegion.left - object.imageReceiver.getImageX());
                    int clipVertical = (int) Math.abs(drawRegion.top - object.imageReceiver.getImageY());
                    int[] coords2 = new int[2];
                    object.parentView.getLocationInWindow(coords2);
                    float f = ((coords2[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight)) - (object.viewY + drawRegion.top)) + object.clipTopAddition;
                    this.animateToClipTop = f;
                    if (f < 0.0f) {
                        this.animateToClipTop = 0.0f;
                    }
                    float height2 = (((object.viewY + drawRegion.top) + ((int) height)) - ((coords2[1] + object.parentView.getHeight()) - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight))) + object.clipBottomAddition;
                    this.animateToClipBottom = height2;
                    if (height2 < 0.0f) {
                        this.animateToClipBottom = 0.0f;
                    }
                    this.animationStartTime = System.currentTimeMillis();
                    this.animateToClipBottom = Math.max(this.animateToClipBottom, clipVertical);
                    this.animateToClipTop = Math.max(this.animateToClipTop, clipVertical);
                    this.zoomAnimation = true;
                } else {
                    int h = AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                    this.animateToY = this.translationY >= 0.0f ? h : -h;
                }
                if (this.isVideo) {
                    this.videoCrossfadeStarted = false;
                    this.textureUploaded = false;
                    this.imageMoveAnimation.playTogether(ObjectAnimator.ofInt(this.photoBackgroundDrawable, "alpha", 0), ObjectAnimator.ofFloat(this, "animationValue", 0.0f, 1.0f), ObjectAnimator.ofFloat(this.actionBar, "alpha", 0.0f), ObjectAnimator.ofFloat(this.secretDeleteTimer, "alpha", 0.0f), ObjectAnimator.ofFloat(this, "videoCrossfadeAlpha", 0.0f));
                } else {
                    this.centerImage.setManualAlphaAnimator(true);
                    this.imageMoveAnimation.playTogether(ObjectAnimator.ofInt(this.photoBackgroundDrawable, "alpha", 0), ObjectAnimator.ofFloat(this, "animationValue", 0.0f, 1.0f), ObjectAnimator.ofFloat(this.actionBar, "alpha", 0.0f), ObjectAnimator.ofFloat(this.secretDeleteTimer, "alpha", 0.0f), ObjectAnimator.ofFloat(this.centerImage, "currentAlpha", 0.0f));
                }
                this.photoAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$2Nj01u70eaSrBtqzvdQBMbcRIvg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$closePhoto$3$SecretMediaViewer(object);
                    }
                };
                this.imageMoveAnimation.setInterpolator(new DecelerateInterpolator());
                this.imageMoveAnimation.setDuration(250L);
                this.imageMoveAnimation.addListener(new AnonymousClass7(object));
                this.photoTransitionAnimationStartTime = System.currentTimeMillis();
                if (Build.VERSION.SDK_INT >= 18) {
                    this.containerView.setLayerType(2, null);
                }
                this.imageMoveAnimation.start();
                return;
            }
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(ObjectAnimator.ofFloat(this.containerView, "scaleX", 0.9f), ObjectAnimator.ofFloat(this.containerView, "scaleY", 0.9f), ObjectAnimator.ofInt(this.photoBackgroundDrawable, "alpha", 0), ObjectAnimator.ofFloat(this.actionBar, "alpha", 0.0f));
            this.photoAnimationInProgress = 2;
            this.photoAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$9OFIaAPneD1v7NjlsO5tcfPFIuw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$closePhoto$4$SecretMediaViewer(object);
                }
            };
            animatorSet.setDuration(200L);
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.8
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (SecretMediaViewer.this.photoAnimationEndRunnable != null) {
                        SecretMediaViewer.this.photoAnimationEndRunnable.run();
                        SecretMediaViewer.this.photoAnimationEndRunnable = null;
                    }
                }
            });
            this.photoTransitionAnimationStartTime = System.currentTimeMillis();
            if (Build.VERSION.SDK_INT >= 18) {
                this.containerView.setLayerType(2, null);
            }
            animatorSet.start();
        }
    }

    public /* synthetic */ void lambda$closePhoto$3$SecretMediaViewer(PhotoViewer.PlaceProviderObject object) {
        this.imageMoveAnimation = null;
        this.photoAnimationInProgress = 0;
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.containerView.setVisibility(4);
        onPhotoClosed(object);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.SecretMediaViewer$7, reason: invalid class name */
    class AnonymousClass7 extends AnimatorListenerAdapter {
        final /* synthetic */ PhotoViewer.PlaceProviderObject val$object;

        AnonymousClass7(PhotoViewer.PlaceProviderObject placeProviderObject) {
            this.val$object = placeProviderObject;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            PhotoViewer.PlaceProviderObject placeProviderObject = this.val$object;
            if (placeProviderObject != null) {
                placeProviderObject.imageReceiver.setVisible(true, true);
            }
            SecretMediaViewer.this.isVisible = false;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$7$yHdYAyeLK5eQ_7DDq74gSnrMOZ0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$SecretMediaViewer$7();
                }
            });
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$SecretMediaViewer$7() {
            if (SecretMediaViewer.this.photoAnimationEndRunnable != null) {
                SecretMediaViewer.this.photoAnimationEndRunnable.run();
                SecretMediaViewer.this.photoAnimationEndRunnable = null;
            }
        }
    }

    public /* synthetic */ void lambda$closePhoto$4$SecretMediaViewer(PhotoViewer.PlaceProviderObject object) {
        if (this.containerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.containerView.setVisibility(4);
        this.photoAnimationInProgress = 0;
        onPhotoClosed(object);
        this.containerView.setScaleX(1.0f);
        this.containerView.setScaleY(1.0f);
    }

    private void onPhotoClosed(PhotoViewer.PlaceProviderObject object) {
        this.isVisible = false;
        this.currentProvider = null;
        this.disableShowCheck = false;
        releasePlayer();
        new ArrayList();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$SecretMediaViewer$-UrXoxXbt8KTTTly4SE9gZSUqd8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onPhotoClosed$5$SecretMediaViewer();
            }
        }, 50L);
    }

    public /* synthetic */ void lambda$onPhotoClosed$5$SecretMediaViewer() {
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        this.centerImage.setImageBitmap((Bitmap) null);
        try {
            if (this.windowView.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeView(this.windowView);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.isPhotoVisible = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateMinMax(float scale) {
        int maxW = ((int) ((this.centerImage.getImageWidth() * scale) - getContainerViewWidth())) / 2;
        int maxH = ((int) ((this.centerImage.getImageHeight() * scale) - getContainerViewHeight())) / 2;
        if (maxW > 0) {
            this.minX = -maxW;
            this.maxX = maxW;
        } else {
            this.maxX = 0.0f;
            this.minX = 0.0f;
        }
        if (maxH > 0) {
            this.minY = -maxH;
            this.maxY = maxH;
        } else {
            this.maxY = 0.0f;
            this.minY = 0.0f;
        }
    }

    private int getContainerViewWidth() {
        return this.containerView.getWidth();
    }

    private int getContainerViewHeight() {
        return this.containerView.getHeight();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:86:0x01c7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean processTouchEvent(android.view.MotionEvent r13) {
        /*
            Method dump skipped, instruction units count: 903
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.SecretMediaViewer.processTouchEvent(android.view.MotionEvent):boolean");
    }

    private void checkMinMax(boolean zoom) {
        float moveToX = this.translationX;
        float moveToY = this.translationY;
        updateMinMax(this.scale);
        float f = this.translationX;
        if (f < this.minX) {
            moveToX = this.minX;
        } else if (f > this.maxX) {
            moveToX = this.maxX;
        }
        float f2 = this.translationY;
        if (f2 < this.minY) {
            moveToY = this.minY;
        } else if (f2 > this.maxY) {
            moveToY = this.maxY;
        }
        animateTo(this.scale, moveToX, moveToY, zoom);
    }

    private void animateTo(float newScale, float newTx, float newTy, boolean isZoom) {
        animateTo(newScale, newTx, newTy, isZoom, 250);
    }

    private void animateTo(float newScale, float newTx, float newTy, boolean isZoom, int duration) {
        if (this.scale == newScale && this.translationX == newTx && this.translationY == newTy) {
            return;
        }
        this.zoomAnimation = isZoom;
        this.animateToScale = newScale;
        this.animateToX = newTx;
        this.animateToY = newTy;
        this.animationStartTime = System.currentTimeMillis();
        AnimatorSet animatorSet = new AnimatorSet();
        this.imageMoveAnimation = animatorSet;
        animatorSet.playTogether(ObjectAnimator.ofFloat(this, "animationValue", 0.0f, 1.0f));
        this.imageMoveAnimation.setInterpolator(this.interpolator);
        this.imageMoveAnimation.setDuration(duration);
        this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.SecretMediaViewer.9
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SecretMediaViewer.this.imageMoveAnimation = null;
                SecretMediaViewer.this.containerView.invalidate();
            }
        });
        this.imageMoveAnimation.start();
    }

    public void setAnimationValue(float value) {
        this.animationValue = value;
        this.containerView.invalidate();
    }

    public float getAnimationValue() {
        return this.animationValue;
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onDown(MotionEvent e) {
        return false;
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public void onShowPress(MotionEvent e) {
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onSingleTapUp(MotionEvent e) {
        return false;
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX, float distanceY) {
        return false;
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public void onLongPress(MotionEvent e) {
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
        if (this.scale != 1.0f) {
            this.scroller.abortAnimation();
            this.scroller.fling(Math.round(this.translationX), Math.round(this.translationY), Math.round(velocityX), Math.round(velocityY), (int) this.minX, (int) this.maxX, (int) this.minY, (int) this.maxY);
            this.containerView.postInvalidate();
            return false;
        }
        return false;
    }

    @Override // android.view.GestureDetector.OnDoubleTapListener
    public boolean onSingleTapConfirmed(MotionEvent e) {
        if (this.discardTap) {
            return false;
        }
        toggleActionBar(!this.isActionBarVisible, true);
        return true;
    }

    @Override // android.view.GestureDetector.OnDoubleTapListener
    public boolean onDoubleTap(MotionEvent e) {
        if ((this.scale == 1.0f && (this.translationY != 0.0f || this.translationX != 0.0f)) || this.animationStartTime != 0 || this.photoAnimationInProgress != 0) {
            return false;
        }
        if (this.scale == 1.0f) {
            float atx = (e.getX() - (getContainerViewWidth() / 2)) - (((e.getX() - (getContainerViewWidth() / 2)) - this.translationX) * (3.0f / this.scale));
            float aty = (e.getY() - (getContainerViewHeight() / 2)) - (((e.getY() - (getContainerViewHeight() / 2)) - this.translationY) * (3.0f / this.scale));
            updateMinMax(3.0f);
            if (atx < this.minX) {
                atx = this.minX;
            } else if (atx > this.maxX) {
                atx = this.maxX;
            }
            if (aty < this.minY) {
                aty = this.minY;
            } else if (aty > this.maxY) {
                aty = this.maxY;
            }
            animateTo(3.0f, atx, aty, true);
        } else {
            animateTo(1.0f, 0.0f, 0.0f, true);
        }
        this.doubleTap = true;
        return true;
    }

    @Override // android.view.GestureDetector.OnDoubleTapListener
    public boolean onDoubleTapEvent(MotionEvent e) {
        return false;
    }

    private boolean scaleToFill() {
        return false;
    }
}
