package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.webkit.WebView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import com.google.android.exoplayer2.ui.AspectRatioFrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.components.PipVideoView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PipVideoView {
    private View controlsView;
    private DecelerateInterpolator decelerateInterpolator;
    private Activity parentActivity;
    private EmbedBottomSheet parentSheet;
    private PhotoViewer photoViewer;
    private SharedPreferences preferences;
    private int videoHeight;
    private int videoWidth;
    private WindowManager.LayoutParams windowLayoutParams;
    private WindowManager windowManager;
    private FrameLayout windowView;

    /* JADX INFO: Access modifiers changed from: private */
    class MiniControlsView extends FrameLayout {
        private float bufferedPosition;
        private AnimatorSet currentAnimation;
        private Runnable hideRunnable;
        private ImageView inlineButton;
        private boolean isCompleted;
        private boolean isVisible;
        private ImageView playButton;
        private float progress;
        private Paint progressInnerPaint;
        private Paint progressPaint;
        private Runnable progressRunnable;

        public /* synthetic */ void lambda$new$0$PipVideoView$MiniControlsView() {
            show(false, true);
        }

        public MiniControlsView(Context context, boolean fullControls) {
            super(context);
            this.isVisible = true;
            this.hideRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PipVideoView$MiniControlsView$XO7H32dLZNEIQMnpTMGEgCoT84Y
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$0$PipVideoView$MiniControlsView();
                }
            };
            this.progressRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.PipVideoView.MiniControlsView.1
                @Override // java.lang.Runnable
                public void run() {
                    VideoPlayer videoPlayer;
                    if (PipVideoView.this.photoViewer == null || (videoPlayer = PipVideoView.this.photoViewer.getVideoPlayer()) == null) {
                        return;
                    }
                    MiniControlsView.this.setProgress(videoPlayer.getCurrentPosition() / videoPlayer.getDuration());
                    if (PipVideoView.this.photoViewer == null) {
                        MiniControlsView.this.setBufferedProgress(videoPlayer.getBufferedPosition() / videoPlayer.getDuration());
                    }
                    AndroidUtilities.runOnUIThread(MiniControlsView.this.progressRunnable, 1000L);
                }
            };
            ImageView imageView = new ImageView(context);
            this.inlineButton = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.inlineButton.setImageResource(R.drawable.ic_outinline);
            addView(this.inlineButton, LayoutHelper.createFrame(56, 48, 53));
            this.inlineButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PipVideoView$MiniControlsView$7tGF9KoBkmEQI2Lw90dlbpW0T8A
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$1$PipVideoView$MiniControlsView(view);
                }
            });
            if (fullControls) {
                Paint paint = new Paint();
                this.progressPaint = paint;
                paint.setColor(-15095832);
                Paint paint2 = new Paint();
                this.progressInnerPaint = paint2;
                paint2.setColor(-6975081);
                setWillNotDraw(false);
                ImageView imageView2 = new ImageView(context);
                this.playButton = imageView2;
                imageView2.setScaleType(ImageView.ScaleType.CENTER);
                addView(this.playButton, LayoutHelper.createFrame(48, 48, 17));
                this.playButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PipVideoView$MiniControlsView$47PcCx6zS10FbmXpzD-5X6B-OSs
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$new$2$PipVideoView$MiniControlsView(view);
                    }
                });
            }
            setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PipVideoView$MiniControlsView$e_blUM9oxt-TSJyBqtJwQRXpdJ4
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    return PipVideoView.MiniControlsView.lambda$new$3(view, motionEvent);
                }
            });
            updatePlayButton();
            show(false, false);
        }

        public /* synthetic */ void lambda$new$1$PipVideoView$MiniControlsView(View v) {
            if (PipVideoView.this.parentSheet != null) {
                PipVideoView.this.parentSheet.exitFromPip();
            } else if (PipVideoView.this.photoViewer != null) {
                PipVideoView.this.photoViewer.exitFromPip();
            }
        }

        public /* synthetic */ void lambda$new$2$PipVideoView$MiniControlsView(View v) {
            VideoPlayer videoPlayer;
            if (PipVideoView.this.photoViewer == null || (videoPlayer = PipVideoView.this.photoViewer.getVideoPlayer()) == null) {
                return;
            }
            if (videoPlayer.isPlaying()) {
                videoPlayer.pause();
            } else {
                videoPlayer.play();
            }
            updatePlayButton();
        }

        static /* synthetic */ boolean lambda$new$3(View v, MotionEvent event) {
            return true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void updatePlayButton() {
            VideoPlayer videoPlayer;
            if (PipVideoView.this.photoViewer == null || (videoPlayer = PipVideoView.this.photoViewer.getVideoPlayer()) == null) {
                return;
            }
            AndroidUtilities.cancelRunOnUIThread(this.progressRunnable);
            if (!videoPlayer.isPlaying()) {
                if (this.isCompleted) {
                    this.playButton.setImageResource(R.drawable.ic_againinline);
                    return;
                } else {
                    this.playButton.setImageResource(R.drawable.ic_playinline);
                    return;
                }
            }
            this.playButton.setImageResource(R.drawable.ic_pauseinline);
            AndroidUtilities.runOnUIThread(this.progressRunnable, 500L);
        }

        public void setBufferedProgress(float position) {
            this.bufferedPosition = position;
            invalidate();
        }

        public void setProgress(float value) {
            this.progress = value;
            invalidate();
        }

        public void show(boolean value, boolean animated) {
            if (this.isVisible == value) {
                return;
            }
            this.isVisible = value;
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            if (this.isVisible) {
                if (animated) {
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.currentAnimation = animatorSet2;
                    animatorSet2.playTogether(ObjectAnimator.ofFloat(this, "alpha", 1.0f));
                    this.currentAnimation.setDuration(150L);
                    this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PipVideoView.MiniControlsView.2
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animator) {
                            MiniControlsView.this.currentAnimation = null;
                        }
                    });
                    this.currentAnimation.start();
                } else {
                    setAlpha(1.0f);
                }
            } else if (animated) {
                AnimatorSet animatorSet3 = new AnimatorSet();
                this.currentAnimation = animatorSet3;
                animatorSet3.playTogether(ObjectAnimator.ofFloat(this, "alpha", 0.0f));
                this.currentAnimation.setDuration(150L);
                this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PipVideoView.MiniControlsView.3
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animator) {
                        MiniControlsView.this.currentAnimation = null;
                    }
                });
                this.currentAnimation.start();
            } else {
                setAlpha(0.0f);
            }
            checkNeedHide();
        }

        private void checkNeedHide() {
            AndroidUtilities.cancelRunOnUIThread(this.hideRunnable);
            if (this.isVisible) {
                AndroidUtilities.runOnUIThread(this.hideRunnable, 3000L);
            }
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            if (ev.getAction() == 0) {
                if (!this.isVisible) {
                    show(true, true);
                    return true;
                }
                checkNeedHide();
            }
            return super.onInterceptTouchEvent(ev);
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            super.requestDisallowInterceptTouchEvent(disallowIntercept);
            checkNeedHide();
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            checkNeedHide();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int width = getMeasuredWidth();
            int height = getMeasuredHeight();
            int progressLineY = height - AndroidUtilities.dp(3.0f);
            int iDp = height - AndroidUtilities.dp(7.0f);
            int progressX = ((int) ((width - 0) * this.progress)) + 0;
            float f = this.bufferedPosition;
            if (f != 0.0f) {
                canvas.drawRect(0, progressLineY, 0 + ((width - 0) * f), AndroidUtilities.dp(3.0f) + progressLineY, this.progressInnerPaint);
            }
            canvas.drawRect(0, progressLineY, progressX, AndroidUtilities.dp(3.0f) + progressLineY, this.progressPaint);
        }
    }

    public TextureView show(Activity activity, EmbedBottomSheet sheet, View controls, float aspectRatio, int rotation, WebView webview) {
        return show(activity, null, sheet, controls, aspectRatio, rotation, webview);
    }

    public TextureView show(Activity activity, PhotoViewer viewer, float aspectRatio, int rotation) {
        return show(activity, viewer, null, null, aspectRatio, rotation, null);
    }

    public TextureView show(Activity activity, PhotoViewer viewer, EmbedBottomSheet sheet, View controls, float aspectRatio, int rotation, WebView webview) {
        TextureView textureView;
        this.parentSheet = sheet;
        this.parentActivity = activity;
        this.photoViewer = viewer;
        this.windowView = new FrameLayout(activity) { // from class: im.uwrkaxlmjj.ui.components.PipVideoView.1
            private boolean dragging;
            private float startX;
            private float startY;

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent event) {
                float x = event.getRawX();
                float y = event.getRawY();
                if (event.getAction() == 0) {
                    this.startX = x;
                    this.startY = y;
                } else if (event.getAction() == 2 && !this.dragging && (Math.abs(this.startX - x) >= AndroidUtilities.getPixelsInCM(0.3f, true) || Math.abs(this.startY - y) >= AndroidUtilities.getPixelsInCM(0.3f, false))) {
                    this.dragging = true;
                    this.startX = x;
                    this.startY = y;
                    if (PipVideoView.this.controlsView != null) {
                        ((ViewParent) PipVideoView.this.controlsView).requestDisallowInterceptTouchEvent(true);
                    }
                    return true;
                }
                return super.onInterceptTouchEvent(event);
            }

            @Override // android.view.ViewGroup, android.view.ViewParent
            public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
                super.requestDisallowInterceptTouchEvent(disallowIntercept);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (!this.dragging) {
                    return false;
                }
                float x = event.getRawX();
                float y = event.getRawY();
                if (event.getAction() == 2) {
                    float dx = x - this.startX;
                    float dy = y - this.startY;
                    PipVideoView.this.windowLayoutParams.x = (int) (r6.x + dx);
                    PipVideoView.this.windowLayoutParams.y = (int) (r6.y + dy);
                    int maxDiff = PipVideoView.this.videoWidth / 2;
                    if (PipVideoView.this.windowLayoutParams.x < (-maxDiff)) {
                        PipVideoView.this.windowLayoutParams.x = -maxDiff;
                    } else if (PipVideoView.this.windowLayoutParams.x > (AndroidUtilities.displaySize.x - PipVideoView.this.windowLayoutParams.width) + maxDiff) {
                        PipVideoView.this.windowLayoutParams.x = (AndroidUtilities.displaySize.x - PipVideoView.this.windowLayoutParams.width) + maxDiff;
                    }
                    float alpha = 1.0f;
                    if (PipVideoView.this.windowLayoutParams.x < 0) {
                        alpha = ((PipVideoView.this.windowLayoutParams.x / maxDiff) * 0.5f) + 1.0f;
                    } else if (PipVideoView.this.windowLayoutParams.x > AndroidUtilities.displaySize.x - PipVideoView.this.windowLayoutParams.width) {
                        alpha = 1.0f - ((((PipVideoView.this.windowLayoutParams.x - AndroidUtilities.displaySize.x) + PipVideoView.this.windowLayoutParams.width) / maxDiff) * 0.5f);
                    }
                    if (PipVideoView.this.windowView.getAlpha() != alpha) {
                        PipVideoView.this.windowView.setAlpha(alpha);
                    }
                    if (PipVideoView.this.windowLayoutParams.y < (-0)) {
                        PipVideoView.this.windowLayoutParams.y = -0;
                    } else if (PipVideoView.this.windowLayoutParams.y > (AndroidUtilities.displaySize.y - PipVideoView.this.windowLayoutParams.height) + 0) {
                        PipVideoView.this.windowLayoutParams.y = (AndroidUtilities.displaySize.y - PipVideoView.this.windowLayoutParams.height) + 0;
                    }
                    PipVideoView.this.windowManager.updateViewLayout(PipVideoView.this.windowView, PipVideoView.this.windowLayoutParams);
                    this.startX = x;
                    this.startY = y;
                } else if (event.getAction() == 1) {
                    this.dragging = false;
                    PipVideoView.this.animateToBoundsMaybe();
                }
                return true;
            }
        };
        if (aspectRatio > 1.0f) {
            int iDp = AndroidUtilities.dp(192.0f);
            this.videoWidth = iDp;
            this.videoHeight = (int) (iDp / aspectRatio);
        } else {
            int iDp2 = AndroidUtilities.dp(192.0f);
            this.videoHeight = iDp2;
            this.videoWidth = (int) (iDp2 * aspectRatio);
        }
        AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(activity);
        aspectRatioFrameLayout.setAspectRatio(aspectRatio, rotation);
        this.windowView.addView(aspectRatioFrameLayout, LayoutHelper.createFrame(-1, -1, 17));
        if (webview != null) {
            ViewGroup parent = (ViewGroup) webview.getParent();
            if (parent != null) {
                parent.removeView(webview);
            }
            aspectRatioFrameLayout.addView(webview, LayoutHelper.createFrame(-1, -1.0f));
            textureView = null;
        } else {
            textureView = new TextureView(activity);
            aspectRatioFrameLayout.addView(textureView, LayoutHelper.createFrame(-1, -1.0f));
        }
        if (controls == null) {
            this.controlsView = new MiniControlsView(activity, viewer != null);
        } else {
            this.controlsView = controls;
        }
        this.windowView.addView(this.controlsView, LayoutHelper.createFrame(-1, -1.0f));
        this.windowManager = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("pipconfig", 0);
        this.preferences = sharedPreferences;
        int sidex = sharedPreferences.getInt("sidex", 1);
        int sidey = this.preferences.getInt("sidey", 0);
        float px = this.preferences.getFloat("px", 0.0f);
        float py = this.preferences.getFloat("py", 0.0f);
        try {
            WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
            this.windowLayoutParams = layoutParams;
            layoutParams.width = this.videoWidth;
            this.windowLayoutParams.height = this.videoHeight;
            this.windowLayoutParams.x = getSideCoord(true, sidex, px, this.videoWidth);
            this.windowLayoutParams.y = getSideCoord(false, sidey, py, this.videoHeight);
            this.windowLayoutParams.format = -3;
            this.windowLayoutParams.gravity = 51;
            if (Build.VERSION.SDK_INT >= 26) {
                this.windowLayoutParams.type = 2038;
            } else {
                this.windowLayoutParams.type = 2003;
            }
            this.windowLayoutParams.flags = 16777736;
            this.windowManager.addView(this.windowView, this.windowLayoutParams);
            return textureView;
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    public void onVideoCompleted() {
        View view = this.controlsView;
        if (view instanceof MiniControlsView) {
            MiniControlsView miniControlsView = (MiniControlsView) view;
            miniControlsView.isCompleted = true;
            miniControlsView.progress = 0.0f;
            miniControlsView.bufferedPosition = 0.0f;
            miniControlsView.updatePlayButton();
            miniControlsView.invalidate();
            miniControlsView.show(true, true);
        }
    }

    public void setBufferedProgress(float progress) {
        View view = this.controlsView;
        if (view instanceof MiniControlsView) {
            ((MiniControlsView) view).setBufferedProgress(progress);
        }
    }

    public void updatePlayButton() {
        View view = this.controlsView;
        if (view instanceof MiniControlsView) {
            MiniControlsView miniControlsView = (MiniControlsView) view;
            miniControlsView.updatePlayButton();
            miniControlsView.invalidate();
        }
    }

    private static int getSideCoord(boolean isX, int side, float p, int sideSize) {
        int total;
        int result;
        if (isX) {
            total = AndroidUtilities.displaySize.x - sideSize;
        } else {
            total = (AndroidUtilities.displaySize.y - sideSize) - ActionBar.getCurrentActionBarHeight();
        }
        if (side == 0) {
            result = AndroidUtilities.dp(10.0f);
        } else if (side == 1) {
            result = total - AndroidUtilities.dp(10.0f);
        } else {
            result = AndroidUtilities.dp(10.0f) + Math.round((total - AndroidUtilities.dp(20.0f)) * p);
        }
        if (!isX) {
            return result + ActionBar.getCurrentActionBarHeight();
        }
        return result;
    }

    public void close() {
        try {
            this.windowManager.removeView(this.windowView);
        } catch (Exception e) {
        }
        this.parentSheet = null;
        this.photoViewer = null;
        this.parentActivity = null;
    }

    public void onConfigurationChanged() {
        int sidex = this.preferences.getInt("sidex", 1);
        int sidey = this.preferences.getInt("sidey", 0);
        float px = this.preferences.getFloat("px", 0.0f);
        float py = this.preferences.getFloat("py", 0.0f);
        this.windowLayoutParams.x = getSideCoord(true, sidex, px, this.videoWidth);
        this.windowLayoutParams.y = getSideCoord(false, sidey, py, this.videoHeight);
        this.windowManager.updateViewLayout(this.windowView, this.windowLayoutParams);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void animateToBoundsMaybe() {
        char c;
        int startX = getSideCoord(true, 0, 0.0f, this.videoWidth);
        int endX = getSideCoord(true, 1, 0.0f, this.videoWidth);
        int startY = getSideCoord(false, 0, 0.0f, this.videoHeight);
        int endY = getSideCoord(false, 1, 0.0f, this.videoHeight);
        ArrayList<Animator> animators = null;
        SharedPreferences.Editor editor = this.preferences.edit();
        int maxDiff = AndroidUtilities.dp(20.0f);
        boolean slideOut = false;
        if (Math.abs(startX - this.windowLayoutParams.x) <= maxDiff || (this.windowLayoutParams.x < 0 && this.windowLayoutParams.x > (-this.videoWidth) / 4)) {
            if (0 == 0) {
                animators = new ArrayList<>();
            }
            editor.putInt("sidex", 0);
            if (this.windowView.getAlpha() != 1.0f) {
                animators.add(ObjectAnimator.ofFloat(this.windowView, "alpha", 1.0f));
            }
            animators.add(ObjectAnimator.ofInt(this, "x", startX));
        } else if (Math.abs(endX - this.windowLayoutParams.x) <= maxDiff || (this.windowLayoutParams.x > AndroidUtilities.displaySize.x - this.videoWidth && this.windowLayoutParams.x < AndroidUtilities.displaySize.x - ((this.videoWidth / 4) * 3))) {
            if (0 == 0) {
                animators = new ArrayList<>();
            }
            editor.putInt("sidex", 1);
            if (this.windowView.getAlpha() != 1.0f) {
                c = 0;
                animators.add(ObjectAnimator.ofFloat(this.windowView, "alpha", 1.0f));
            } else {
                c = 0;
            }
            int[] iArr = new int[1];
            iArr[c] = endX;
            animators.add(ObjectAnimator.ofInt(this, "x", iArr));
        } else if (this.windowView.getAlpha() != 1.0f) {
            if (0 == 0) {
                animators = new ArrayList<>();
            }
            if (this.windowLayoutParams.x < 0) {
                animators.add(ObjectAnimator.ofInt(this, "x", -this.videoWidth));
            } else {
                animators.add(ObjectAnimator.ofInt(this, "x", AndroidUtilities.displaySize.x));
            }
            slideOut = true;
        } else {
            editor.putFloat("px", (this.windowLayoutParams.x - startX) / (endX - startX));
            editor.putInt("sidex", 2);
        }
        if (!slideOut) {
            if (Math.abs(startY - this.windowLayoutParams.y) <= maxDiff || this.windowLayoutParams.y <= ActionBar.getCurrentActionBarHeight()) {
                if (animators == null) {
                    animators = new ArrayList<>();
                }
                editor.putInt("sidey", 0);
                animators.add(ObjectAnimator.ofInt(this, "y", startY));
            } else if (Math.abs(endY - this.windowLayoutParams.y) <= maxDiff) {
                if (animators == null) {
                    animators = new ArrayList<>();
                }
                editor.putInt("sidey", 1);
                animators.add(ObjectAnimator.ofInt(this, "y", endY));
            } else {
                editor.putFloat("py", (this.windowLayoutParams.y - startY) / (endY - startY));
                editor.putInt("sidey", 2);
            }
            editor.commit();
        }
        if (animators != null) {
            if (this.decelerateInterpolator == null) {
                this.decelerateInterpolator = new DecelerateInterpolator();
            }
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.setInterpolator(this.decelerateInterpolator);
            animatorSet.setDuration(150L);
            if (slideOut) {
                animators.add(ObjectAnimator.ofFloat(this.windowView, "alpha", 0.0f));
                animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PipVideoView.2
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (PipVideoView.this.parentSheet != null) {
                            PipVideoView.this.parentSheet.destroy();
                        } else if (PipVideoView.this.photoViewer != null) {
                            PipVideoView.this.photoViewer.destroyPhotoViewer();
                        }
                    }
                });
            }
            animatorSet.playTogether(animators);
            animatorSet.start();
        }
    }

    public static Rect getPipRect(float aspectRatio) {
        int videoHeight;
        int videoWidth;
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("pipconfig", 0);
        int sidex = preferences.getInt("sidex", 1);
        int sidey = preferences.getInt("sidey", 0);
        float px = preferences.getFloat("px", 0.0f);
        float py = preferences.getFloat("py", 0.0f);
        if (aspectRatio > 1.0f) {
            videoWidth = AndroidUtilities.dp(192.0f);
            videoHeight = (int) (videoWidth / aspectRatio);
        } else {
            videoHeight = AndroidUtilities.dp(192.0f);
            videoWidth = (int) (videoHeight * aspectRatio);
        }
        return new Rect(getSideCoord(true, sidex, px, videoWidth), getSideCoord(false, sidey, py, videoHeight), videoWidth, videoHeight);
    }

    public int getX() {
        return this.windowLayoutParams.x;
    }

    public int getY() {
        return this.windowLayoutParams.y;
    }

    public void setX(int value) {
        this.windowLayoutParams.x = value;
        this.windowManager.updateViewLayout(this.windowView, this.windowLayoutParams);
    }

    public void setY(int value) {
        this.windowLayoutParams.y = value;
        this.windowManager.updateViewLayout(this.windowView, this.windowLayoutParams);
    }
}
