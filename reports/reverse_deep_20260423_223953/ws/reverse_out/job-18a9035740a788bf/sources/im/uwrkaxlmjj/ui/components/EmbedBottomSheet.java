package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Property;
import android.view.MotionEvent;
import android.view.OrientationEventListener;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BringAppForegroundService;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.WebPlayerView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.HashMap;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class EmbedBottomSheet extends BottomSheet {
    private static EmbedBottomSheet instance;
    private boolean animationInProgress;
    private FrameLayout containerLayout;
    private TextView copyTextButton;
    private View customView;
    private WebChromeClient.CustomViewCallback customViewCallback;
    private String embedUrl;
    private FrameLayout fullscreenVideoContainer;
    private boolean fullscreenedByButton;
    private boolean hasDescription;
    private int height;
    private LinearLayout imageButtonsContainer;
    private boolean isYouTube;
    private int lastOrientation;
    private DialogInterface.OnShowListener onShowListener;
    private String openUrl;
    private OrientationEventListener orientationEventListener;
    private Activity parentActivity;
    private ImageView pipButton;
    private PipVideoView pipVideoView;
    private int[] position;
    private int prevOrientation;
    private RadialProgressView progressBar;
    private View progressBarBlackBackground;
    private int seekTimeOverride;
    private WebPlayerView videoView;
    private int waitingForDraw;
    private boolean wasInLandscape;
    private WebView webView;
    private int width;
    private final String youtubeFrame;

    /* JADX INFO: Access modifiers changed from: private */
    class YoutubeProxy {
        private YoutubeProxy() {
        }

        @JavascriptInterface
        public void postEvent(String eventName, String eventData) {
            if ("loaded".equals(eventName)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$YoutubeProxy$tONoNSHDc73PitWf0YabJ6HNoCY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$postEvent$0$EmbedBottomSheet$YoutubeProxy();
                    }
                });
            }
        }

        public /* synthetic */ void lambda$postEvent$0$EmbedBottomSheet$YoutubeProxy() {
            EmbedBottomSheet.this.progressBar.setVisibility(4);
            EmbedBottomSheet.this.progressBarBlackBackground.setVisibility(4);
            EmbedBottomSheet.this.pipButton.setEnabled(true);
            EmbedBottomSheet.this.pipButton.setAlpha(1.0f);
        }
    }

    public static void show(Context context, String title, String description, String originalUrl, String url, int w, int h) {
        show(context, title, description, originalUrl, url, w, h, -1);
    }

    public static void show(Context context, String title, String description, String originalUrl, String url, int w, int h, int seekTime) {
        EmbedBottomSheet embedBottomSheet = instance;
        if (embedBottomSheet != null) {
            embedBottomSheet.destroy();
        }
        new EmbedBottomSheet(context, title, description, originalUrl, url, w, h, seekTime).show();
    }

    private EmbedBottomSheet(Context context, String title, String description, String originalUrl, String url, int w, int h, int seekTime) {
        super(context, false, 0);
        this.position = new int[2];
        this.lastOrientation = -1;
        this.prevOrientation = -2;
        this.youtubeFrame = "<!DOCTYPE html><html><head><style>body { margin: 0; width:100%%; height:100%%;  background-color:#000; }html { width:100%%; height:100%%; background-color:#000; }.embed-container iframe,.embed-container object,   .embed-container embed {       position: absolute;       top: 0;       left: 0;       width: 100%% !important;       height: 100%% !important;   }   </style></head><body>   <div class=\"embed-container\">       <div id=\"player\"></div>   </div>   <script src=\"https://www.youtube.com/iframe_api\"></script>   <script>   var player;   var observer;   var videoEl;   var playing;   var posted = false;   YT.ready(function() {       player = new YT.Player(\"player\", {                              \"width\" : \"100%%\",                              \"events\" : {                              \"onReady\" : \"onReady\",                              \"onError\" : \"onError\",                              },                              \"videoId\" : \"%1$s\",                              \"height\" : \"100%%\",                              \"playerVars\" : {                              \"start\" : %2$d,                              \"rel\" : 0,                              \"showinfo\" : 0,                              \"modestbranding\" : 1,                              \"iv_load_policy\" : 3,                              \"autohide\" : 1,                              \"autoplay\" : 1,                              \"cc_load_policy\" : 1,                              \"playsinline\" : 1,                              \"controls\" : 1                              }                            });        player.setSize(window.innerWidth, window.innerHeight);    });    function hideControls() {        playing = !videoEl.paused;       videoEl.controls = 0;       observer.observe(videoEl, {attributes: true});    }    function showControls() {        playing = !videoEl.paused;       observer.disconnect();       videoEl.controls = 1;    }    function onError(event) {       if (!posted) {            if (window.YoutubeProxy !== undefined) {                   YoutubeProxy.postEvent(\"loaded\", null);             }            posted = true;       }    }    function onReady(event) {       player.playVideo();       videoEl = player.getIframe().contentDocument.getElementsByTagName('video')[0];\n       videoEl.addEventListener(\"canplay\", function() {            if (playing) {               videoEl.play();            }       }, true);       videoEl.addEventListener(\"timeupdate\", function() {            if (!posted && videoEl.currentTime > 0) {               if (window.YoutubeProxy !== undefined) {                   YoutubeProxy.postEvent(\"loaded\", null);                }               posted = true;           }       }, true);       observer = new MutationObserver(function() {\n          if (videoEl.controls) {\n               videoEl.controls = 0;\n          }       });\n    }    window.onresize = function() {        player.setSize(window.innerWidth, window.innerHeight);    }    </script></body></html>";
        this.onShowListener = new DialogInterface.OnShowListener() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.1
            @Override // android.content.DialogInterface.OnShowListener
            public void onShow(DialogInterface dialog) {
                if (EmbedBottomSheet.this.pipVideoView != null && EmbedBottomSheet.this.videoView.isInline()) {
                    EmbedBottomSheet.this.videoView.getViewTreeObserver().addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.1.1
                        @Override // android.view.ViewTreeObserver.OnPreDrawListener
                        public boolean onPreDraw() {
                            EmbedBottomSheet.this.videoView.getViewTreeObserver().removeOnPreDrawListener(this);
                            return true;
                        }
                    });
                }
            }
        };
        this.fullWidth = true;
        setApplyTopPadding(false);
        setApplyBottomPadding(false);
        this.seekTimeOverride = seekTime;
        if (context instanceof Activity) {
            this.parentActivity = (Activity) context;
        }
        this.embedUrl = url;
        this.hasDescription = description != null && description.length() > 0;
        this.openUrl = originalUrl;
        this.width = w;
        this.height = h;
        if (w == 0 || h == 0) {
            this.width = AndroidUtilities.displaySize.x;
            this.height = AndroidUtilities.displaySize.y / 2;
        }
        FrameLayout frameLayout = new FrameLayout(context);
        this.fullscreenVideoContainer = frameLayout;
        frameLayout.setKeepScreenOn(true);
        this.fullscreenVideoContainer.setBackgroundColor(-16777216);
        if (Build.VERSION.SDK_INT >= 21) {
            this.fullscreenVideoContainer.setFitsSystemWindows(true);
        }
        this.fullscreenVideoContainer.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$4DrflPTELpSgp9gPP9282kumFik
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return EmbedBottomSheet.lambda$new$0(view, motionEvent);
            }
        });
        this.container.addView(this.fullscreenVideoContainer, LayoutHelper.createFrame(-1, -1.0f));
        this.fullscreenVideoContainer.setVisibility(4);
        this.fullscreenVideoContainer.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$i_sSsvdKNUXe-qds2fG4E-cHVco
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return EmbedBottomSheet.lambda$new$1(view, motionEvent);
            }
        });
        FrameLayout frameLayout2 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.2
            @Override // android.view.ViewGroup, android.view.View
            protected void onDetachedFromWindow() {
                super.onDetachedFromWindow();
                try {
                    if ((EmbedBottomSheet.this.pipVideoView == null || EmbedBottomSheet.this.webView.getVisibility() != 0) && EmbedBottomSheet.this.webView.getParent() != null) {
                        removeView(EmbedBottomSheet.this.webView);
                        EmbedBottomSheet.this.webView.stopLoading();
                        EmbedBottomSheet.this.webView.loadUrl("about:blank");
                        EmbedBottomSheet.this.webView.destroy();
                    }
                    if (!EmbedBottomSheet.this.videoView.isInline() && EmbedBottomSheet.this.pipVideoView == null) {
                        if (EmbedBottomSheet.instance == EmbedBottomSheet.this) {
                            EmbedBottomSheet unused = EmbedBottomSheet.instance = null;
                        }
                        EmbedBottomSheet.this.videoView.destroy();
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int parentWidth = View.MeasureSpec.getSize(widthMeasureSpec);
                float scale = EmbedBottomSheet.this.width / parentWidth;
                int h2 = (int) Math.min(EmbedBottomSheet.this.height / scale, AndroidUtilities.displaySize.y / 2);
                super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp((EmbedBottomSheet.this.hasDescription ? 22 : 0) + 84) + h2 + 1, 1073741824));
            }
        };
        this.containerLayout = frameLayout2;
        frameLayout2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$DEycN9mOzRVZTBrUPuYzyaQN5Xs
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return EmbedBottomSheet.lambda$new$2(view, motionEvent);
            }
        });
        setCustomView(this.containerLayout);
        WebView webView = new WebView(context);
        this.webView = webView;
        webView.getSettings().setJavaScriptEnabled(true);
        this.webView.getSettings().setDomStorageEnabled(true);
        if (Build.VERSION.SDK_INT >= 17) {
            this.webView.getSettings().setMediaPlaybackRequiresUserGesture(false);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.webView.getSettings().setMixedContentMode(0);
            CookieManager cookieManager = CookieManager.getInstance();
            cookieManager.setAcceptThirdPartyCookies(this.webView, true);
        }
        this.webView.setWebChromeClient(new WebChromeClient() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.3
            @Override // android.webkit.WebChromeClient
            public void onShowCustomView(View view, int requestedOrientation, WebChromeClient.CustomViewCallback callback) {
                onShowCustomView(view, callback);
            }

            @Override // android.webkit.WebChromeClient
            public void onShowCustomView(View view, WebChromeClient.CustomViewCallback callback) {
                if (EmbedBottomSheet.this.customView != null || EmbedBottomSheet.this.pipVideoView != null) {
                    callback.onCustomViewHidden();
                    return;
                }
                EmbedBottomSheet.this.exitFromPip();
                EmbedBottomSheet.this.customView = view;
                EmbedBottomSheet.this.getSheetContainer().setVisibility(4);
                EmbedBottomSheet.this.fullscreenVideoContainer.setVisibility(0);
                EmbedBottomSheet.this.fullscreenVideoContainer.addView(view, LayoutHelper.createFrame(-1, -1.0f));
                EmbedBottomSheet.this.customViewCallback = callback;
            }

            @Override // android.webkit.WebChromeClient
            public void onHideCustomView() {
                super.onHideCustomView();
                if (EmbedBottomSheet.this.customView == null) {
                    return;
                }
                EmbedBottomSheet.this.getSheetContainer().setVisibility(0);
                EmbedBottomSheet.this.fullscreenVideoContainer.setVisibility(4);
                EmbedBottomSheet.this.fullscreenVideoContainer.removeView(EmbedBottomSheet.this.customView);
                if (EmbedBottomSheet.this.customViewCallback != null && !EmbedBottomSheet.this.customViewCallback.getClass().getName().contains(".chromium.")) {
                    EmbedBottomSheet.this.customViewCallback.onCustomViewHidden();
                }
                EmbedBottomSheet.this.customView = null;
            }
        });
        this.webView.setWebViewClient(new WebViewClient() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.4
            @Override // android.webkit.WebViewClient
            public void onLoadResource(WebView view, String url2) {
                super.onLoadResource(view, url2);
            }

            @Override // android.webkit.WebViewClient
            public void onPageFinished(WebView view, String url2) {
                super.onPageFinished(view, url2);
                if (!EmbedBottomSheet.this.isYouTube || Build.VERSION.SDK_INT < 17) {
                    EmbedBottomSheet.this.progressBar.setVisibility(4);
                    EmbedBottomSheet.this.progressBarBlackBackground.setVisibility(4);
                    EmbedBottomSheet.this.pipButton.setEnabled(true);
                    EmbedBottomSheet.this.pipButton.setAlpha(1.0f);
                }
            }
        });
        this.containerLayout.addView(this.webView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, (this.hasDescription ? 22 : 0) + 84));
        WebPlayerView webPlayerView = new WebPlayerView(context, true, false, new WebPlayerView.WebPlayerViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.5
            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public void onInitFailed() {
                EmbedBottomSheet.this.webView.setVisibility(0);
                EmbedBottomSheet.this.imageButtonsContainer.setVisibility(0);
                EmbedBottomSheet.this.copyTextButton.setVisibility(4);
                EmbedBottomSheet.this.webView.setKeepScreenOn(true);
                EmbedBottomSheet.this.videoView.setVisibility(4);
                EmbedBottomSheet.this.videoView.getControlsView().setVisibility(4);
                EmbedBottomSheet.this.videoView.getTextureView().setVisibility(4);
                if (EmbedBottomSheet.this.videoView.getTextureImageView() != null) {
                    EmbedBottomSheet.this.videoView.getTextureImageView().setVisibility(4);
                }
                EmbedBottomSheet.this.videoView.loadVideo(null, null, null, null, false);
                HashMap<String, String> args = new HashMap<>();
                args.put("Referer", "http://youtube.com");
                try {
                    EmbedBottomSheet.this.webView.loadUrl(EmbedBottomSheet.this.embedUrl, args);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public TextureView onSwitchToFullscreen(View controlsView, boolean fullscreen, float aspectRatio, int rotation, boolean byButton) {
                if (!fullscreen) {
                    EmbedBottomSheet.this.fullscreenVideoContainer.setVisibility(4);
                    EmbedBottomSheet.this.fullscreenedByButton = false;
                    if (EmbedBottomSheet.this.parentActivity != null) {
                        try {
                            EmbedBottomSheet.this.containerView.setSystemUiVisibility(0);
                            EmbedBottomSheet.this.parentActivity.setRequestedOrientation(EmbedBottomSheet.this.prevOrientation);
                            return null;
                        } catch (Exception e) {
                            FileLog.e(e);
                            return null;
                        }
                    }
                    return null;
                }
                EmbedBottomSheet.this.fullscreenVideoContainer.setVisibility(0);
                EmbedBottomSheet.this.fullscreenVideoContainer.setAlpha(1.0f);
                EmbedBottomSheet.this.fullscreenVideoContainer.addView(EmbedBottomSheet.this.videoView.getAspectRatioView());
                EmbedBottomSheet.this.wasInLandscape = false;
                EmbedBottomSheet.this.fullscreenedByButton = byButton;
                if (EmbedBottomSheet.this.parentActivity != null) {
                    try {
                        EmbedBottomSheet.this.prevOrientation = EmbedBottomSheet.this.parentActivity.getRequestedOrientation();
                        if (byButton) {
                            WindowManager manager = (WindowManager) EmbedBottomSheet.this.parentActivity.getSystemService("window");
                            int displayRotation = manager.getDefaultDisplay().getRotation();
                            if (displayRotation == 3) {
                                EmbedBottomSheet.this.parentActivity.setRequestedOrientation(8);
                            } else {
                                EmbedBottomSheet.this.parentActivity.setRequestedOrientation(0);
                            }
                        }
                        EmbedBottomSheet.this.containerView.setSystemUiVisibility(1028);
                        return null;
                    } catch (Exception e2) {
                        FileLog.e(e2);
                        return null;
                    }
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public void onVideoSizeChanged(float aspectRatio, int rotation) {
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public void onInlineSurfaceTextureReady() {
                if (EmbedBottomSheet.this.videoView.isInline()) {
                    EmbedBottomSheet.this.dismissInternal();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public void prepareToSwitchInlineMode(boolean inline, final Runnable switchInlineModeRunnable, float aspectRatio, boolean animated) {
                if (inline) {
                    if (EmbedBottomSheet.this.parentActivity != null) {
                        try {
                            EmbedBottomSheet.this.containerView.setSystemUiVisibility(0);
                            if (EmbedBottomSheet.this.prevOrientation != -2) {
                                EmbedBottomSheet.this.parentActivity.setRequestedOrientation(EmbedBottomSheet.this.prevOrientation);
                            }
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                    if (EmbedBottomSheet.this.fullscreenVideoContainer.getVisibility() == 0) {
                        EmbedBottomSheet.this.containerView.setTranslationY(EmbedBottomSheet.this.containerView.getMeasuredHeight() + AndroidUtilities.dp(10.0f));
                        EmbedBottomSheet.this.backDrawable.setAlpha(0);
                    }
                    EmbedBottomSheet.this.setOnShowListener(null);
                    if (animated) {
                        TextureView textureView = EmbedBottomSheet.this.videoView.getTextureView();
                        View controlsView = EmbedBottomSheet.this.videoView.getControlsView();
                        ImageView textureImageView = EmbedBottomSheet.this.videoView.getTextureImageView();
                        Rect rect = PipVideoView.getPipRect(aspectRatio);
                        float scale = rect.width / textureView.getWidth();
                        if (Build.VERSION.SDK_INT >= 21) {
                            rect.y += AndroidUtilities.statusBarHeight;
                        }
                        AnimatorSet animatorSet = new AnimatorSet();
                        animatorSet.playTogether(ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.SCALE_X, scale), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.SCALE_Y, scale), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.TRANSLATION_X, rect.x), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.TRANSLATION_Y, rect.y), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.SCALE_X, scale), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.SCALE_Y, scale), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.TRANSLATION_X, rect.x), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.TRANSLATION_Y, rect.y), ObjectAnimator.ofFloat(EmbedBottomSheet.this.containerView, (Property<ViewGroup, Float>) View.TRANSLATION_Y, EmbedBottomSheet.this.containerView.getMeasuredHeight() + AndroidUtilities.dp(10.0f)), ObjectAnimator.ofInt(EmbedBottomSheet.this.backDrawable, AnimationProperties.COLOR_DRAWABLE_ALPHA, 0), ObjectAnimator.ofFloat(EmbedBottomSheet.this.fullscreenVideoContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(controlsView, (Property<View, Float>) View.ALPHA, 0.0f));
                        animatorSet.setInterpolator(new DecelerateInterpolator());
                        animatorSet.setDuration(250L);
                        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.5.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (EmbedBottomSheet.this.fullscreenVideoContainer.getVisibility() == 0) {
                                    EmbedBottomSheet.this.fullscreenVideoContainer.setAlpha(1.0f);
                                    EmbedBottomSheet.this.fullscreenVideoContainer.setVisibility(4);
                                }
                                switchInlineModeRunnable.run();
                            }
                        });
                        animatorSet.start();
                        return;
                    }
                    if (EmbedBottomSheet.this.fullscreenVideoContainer.getVisibility() == 0) {
                        EmbedBottomSheet.this.fullscreenVideoContainer.setAlpha(1.0f);
                        EmbedBottomSheet.this.fullscreenVideoContainer.setVisibility(4);
                    }
                    switchInlineModeRunnable.run();
                    EmbedBottomSheet.this.dismissInternal();
                    return;
                }
                if (ApplicationLoader.mainInterfacePaused) {
                    try {
                        EmbedBottomSheet.this.parentActivity.startService(new Intent(ApplicationLoader.applicationContext, (Class<?>) BringAppForegroundService.class));
                    } catch (Throwable e2) {
                        FileLog.e(e2);
                    }
                }
                if (!animated) {
                    EmbedBottomSheet.this.pipVideoView.close();
                    EmbedBottomSheet.this.pipVideoView = null;
                } else {
                    EmbedBottomSheet embedBottomSheet = EmbedBottomSheet.this;
                    embedBottomSheet.setOnShowListener(embedBottomSheet.onShowListener);
                    Rect rect2 = PipVideoView.getPipRect(aspectRatio);
                    TextureView textureView2 = EmbedBottomSheet.this.videoView.getTextureView();
                    ImageView textureImageView2 = EmbedBottomSheet.this.videoView.getTextureImageView();
                    float scale2 = rect2.width / textureView2.getLayoutParams().width;
                    if (Build.VERSION.SDK_INT >= 21) {
                        rect2.y += AndroidUtilities.statusBarHeight;
                    }
                    textureImageView2.setScaleX(scale2);
                    textureImageView2.setScaleY(scale2);
                    textureImageView2.setTranslationX(rect2.x);
                    textureImageView2.setTranslationY(rect2.y);
                    textureView2.setScaleX(scale2);
                    textureView2.setScaleY(scale2);
                    textureView2.setTranslationX(rect2.x);
                    textureView2.setTranslationY(rect2.y);
                }
                EmbedBottomSheet.this.setShowWithoutAnimation(true);
                EmbedBottomSheet.this.show();
                if (animated) {
                    EmbedBottomSheet.this.waitingForDraw = 4;
                    EmbedBottomSheet.this.backDrawable.setAlpha(1);
                    EmbedBottomSheet.this.containerView.setTranslationY(EmbedBottomSheet.this.containerView.getMeasuredHeight() + AndroidUtilities.dp(10.0f));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public TextureView onSwitchInlineMode(View controlsView, boolean inline, float aspectRatio, int rotation, boolean animated) {
                if (inline) {
                    controlsView.setTranslationY(0.0f);
                    EmbedBottomSheet.this.pipVideoView = new PipVideoView();
                    return EmbedBottomSheet.this.pipVideoView.show(EmbedBottomSheet.this.parentActivity, EmbedBottomSheet.this, controlsView, aspectRatio, rotation, null);
                }
                if (animated) {
                    EmbedBottomSheet.this.animationInProgress = true;
                    View view = EmbedBottomSheet.this.videoView.getAspectRatioView();
                    view.getLocationInWindow(EmbedBottomSheet.this.position);
                    int[] iArr = EmbedBottomSheet.this.position;
                    iArr[0] = iArr[0] - EmbedBottomSheet.this.getLeftInset();
                    EmbedBottomSheet.this.position[1] = (int) (r4[1] - EmbedBottomSheet.this.containerView.getTranslationY());
                    TextureView textureView = EmbedBottomSheet.this.videoView.getTextureView();
                    ImageView textureImageView = EmbedBottomSheet.this.videoView.getTextureImageView();
                    AnimatorSet animatorSet = new AnimatorSet();
                    animatorSet.playTogether(ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.TRANSLATION_X, EmbedBottomSheet.this.position[0]), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.TRANSLATION_Y, EmbedBottomSheet.this.position[1]), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.TRANSLATION_X, EmbedBottomSheet.this.position[0]), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.TRANSLATION_Y, EmbedBottomSheet.this.position[1]), ObjectAnimator.ofFloat(EmbedBottomSheet.this.containerView, (Property<ViewGroup, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofInt(EmbedBottomSheet.this.backDrawable, AnimationProperties.COLOR_DRAWABLE_ALPHA, 51));
                    animatorSet.setInterpolator(new DecelerateInterpolator());
                    animatorSet.setDuration(250L);
                    animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.5.2
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            EmbedBottomSheet.this.animationInProgress = false;
                        }
                    });
                    animatorSet.start();
                    return null;
                }
                EmbedBottomSheet.this.containerView.setTranslationY(0.0f);
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public void onSharePressed() {
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public void onPlayStateChanged(WebPlayerView playerView, boolean playing) {
                if (playing) {
                    try {
                        EmbedBottomSheet.this.parentActivity.getWindow().addFlags(128);
                        return;
                    } catch (Exception e) {
                        FileLog.e(e);
                        return;
                    }
                }
                try {
                    EmbedBottomSheet.this.parentActivity.getWindow().clearFlags(128);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public boolean checkInlinePermissions() {
                return EmbedBottomSheet.this.checkInlinePermissions();
            }

            @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
            public ViewGroup getTextureViewContainer() {
                return EmbedBottomSheet.this.container;
            }
        });
        this.videoView = webPlayerView;
        webPlayerView.setVisibility(4);
        this.containerLayout.addView(this.videoView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, ((this.hasDescription ? 22 : 0) + 84) - 10));
        View view = new View(context);
        this.progressBarBlackBackground = view;
        view.setBackgroundColor(-16777216);
        this.progressBarBlackBackground.setVisibility(4);
        this.containerLayout.addView(this.progressBarBlackBackground, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, (this.hasDescription ? 22 : 0) + 84));
        RadialProgressView radialProgressView = new RadialProgressView(context);
        this.progressBar = radialProgressView;
        radialProgressView.setVisibility(4);
        this.containerLayout.addView(this.progressBar, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 0.0f, 0.0f, ((this.hasDescription ? 22 : 0) + 84) / 2));
        if (this.hasDescription) {
            TextView textView = new TextView(context);
            textView.setTextSize(1, 16.0f);
            textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            textView.setText(description);
            textView.setSingleLine(true);
            textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            textView.setEllipsize(TextUtils.TruncateAt.END);
            textView.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
            this.containerLayout.addView(textView, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 0.0f, 0.0f, 0.0f, 77.0f));
        }
        TextView textView2 = new TextView(context);
        textView2.setTextSize(1, 14.0f);
        textView2.setTextColor(Theme.getColor(Theme.key_dialogTextGray));
        textView2.setText(title);
        textView2.setSingleLine(true);
        textView2.setEllipsize(TextUtils.TruncateAt.END);
        textView2.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        this.containerLayout.addView(textView2, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 0.0f, 0.0f, 0.0f, 57.0f));
        View lineView = new View(context);
        lineView.setBackgroundColor(Theme.getColor(Theme.key_dialogGrayLine));
        this.containerLayout.addView(lineView, new FrameLayout.LayoutParams(-1, 1, 83));
        ((FrameLayout.LayoutParams) lineView.getLayoutParams()).bottomMargin = AndroidUtilities.dp(48.0f);
        FrameLayout frameLayout3 = new FrameLayout(context);
        frameLayout3.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.containerLayout.addView(frameLayout3, LayoutHelper.createFrame(-1, 48, 83));
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(0);
        linearLayout.setWeightSum(1.0f);
        frameLayout3.addView(linearLayout, LayoutHelper.createFrame(-2, -1, 53));
        TextView textView3 = new TextView(context);
        textView3.setTextSize(1, 14.0f);
        textView3.setTextColor(Theme.getColor(Theme.key_dialogTextBlue4));
        textView3.setGravity(17);
        textView3.setSingleLine(true);
        textView3.setEllipsize(TextUtils.TruncateAt.END);
        textView3.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 0));
        textView3.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        textView3.setText(LocaleController.getString("Close", R.string.Close).toUpperCase());
        textView3.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        frameLayout3.addView(textView3, LayoutHelper.createLinear(-2, -1, 51));
        textView3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$DGhEf3nVEkBsapRtRPK0jLCLODo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$3$EmbedBottomSheet(view2);
            }
        });
        LinearLayout linearLayout2 = new LinearLayout(context);
        this.imageButtonsContainer = linearLayout2;
        linearLayout2.setVisibility(4);
        frameLayout3.addView(this.imageButtonsContainer, LayoutHelper.createFrame(-2, -1, 17));
        ImageView imageView = new ImageView(context);
        this.pipButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.pipButton.setImageResource(R.drawable.video_pip);
        this.pipButton.setEnabled(false);
        this.pipButton.setAlpha(0.5f);
        this.pipButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogTextBlue4), PorterDuff.Mode.MULTIPLY));
        this.pipButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 0));
        this.imageButtonsContainer.addView(this.pipButton, LayoutHelper.createFrame(48.0f, 48.0f, 51, 0.0f, 0.0f, 4.0f, 0.0f));
        this.pipButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$w1xpK4oaxbICblFjoGNdaieVz_w
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$4$EmbedBottomSheet(view2);
            }
        });
        View.OnClickListener copyClickListener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$SSOGnOP_dv66woc-D12AP-1vXWo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$5$EmbedBottomSheet(view2);
            }
        };
        ImageView copyButton = new ImageView(context);
        copyButton.setScaleType(ImageView.ScaleType.CENTER);
        copyButton.setImageResource(R.drawable.video_copy);
        copyButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogTextBlue4), PorterDuff.Mode.MULTIPLY));
        copyButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 0));
        this.imageButtonsContainer.addView(copyButton, LayoutHelper.createFrame(48, 48, 51));
        copyButton.setOnClickListener(copyClickListener);
        TextView textView4 = new TextView(context);
        this.copyTextButton = textView4;
        textView4.setTextSize(1, 14.0f);
        this.copyTextButton.setTextColor(Theme.getColor(Theme.key_dialogTextBlue4));
        this.copyTextButton.setGravity(17);
        this.copyTextButton.setSingleLine(true);
        this.copyTextButton.setEllipsize(TextUtils.TruncateAt.END);
        this.copyTextButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 0));
        this.copyTextButton.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        this.copyTextButton.setText(LocaleController.getString("Copy", R.string.Copy).toUpperCase());
        this.copyTextButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        linearLayout.addView(this.copyTextButton, LayoutHelper.createFrame(-2, -1, 51));
        this.copyTextButton.setOnClickListener(copyClickListener);
        TextView openInButton = new TextView(context);
        openInButton.setTextSize(1, 14.0f);
        openInButton.setTextColor(Theme.getColor(Theme.key_dialogTextBlue4));
        openInButton.setGravity(17);
        openInButton.setSingleLine(true);
        openInButton.setEllipsize(TextUtils.TruncateAt.END);
        openInButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 0));
        openInButton.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        openInButton.setText(LocaleController.getString("OpenInBrowser", R.string.OpenInBrowser).toUpperCase());
        openInButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        linearLayout.addView(openInButton, LayoutHelper.createFrame(-2, -1, 51));
        openInButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$ttmzS3rHt9MBtOo21p1EeMhSS8w
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$6$EmbedBottomSheet(view2);
            }
        });
        setDelegate(new BottomSheet.BottomSheetDelegate() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.7
            /* JADX WARN: Multi-variable type inference failed */
            @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegate, im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
            public void onOpenAnimationEnd() {
                if (!EmbedBottomSheet.this.videoView.loadVideo(EmbedBottomSheet.this.embedUrl, null, null, EmbedBottomSheet.this.openUrl, true)) {
                    EmbedBottomSheet.this.progressBar.setVisibility(0);
                    EmbedBottomSheet.this.webView.setVisibility(0);
                    EmbedBottomSheet.this.imageButtonsContainer.setVisibility(0);
                    EmbedBottomSheet.this.copyTextButton.setVisibility(4);
                    EmbedBottomSheet.this.webView.setKeepScreenOn(true);
                    EmbedBottomSheet.this.videoView.setVisibility(4);
                    EmbedBottomSheet.this.videoView.getControlsView().setVisibility(4);
                    EmbedBottomSheet.this.videoView.getTextureView().setVisibility(4);
                    if (EmbedBottomSheet.this.videoView.getTextureImageView() != null) {
                        EmbedBottomSheet.this.videoView.getTextureImageView().setVisibility(4);
                    }
                    EmbedBottomSheet.this.videoView.loadVideo(null, null, null, null, false);
                    HashMap map = new HashMap();
                    map.put("Referer", "http://youtube.com");
                    try {
                        String youtubeId = EmbedBottomSheet.this.videoView.getYoutubeId();
                        if (youtubeId != null) {
                            EmbedBottomSheet.this.progressBarBlackBackground.setVisibility(0);
                            EmbedBottomSheet.this.isYouTube = true;
                            String queryParameter = null;
                            Object[] objArr = 0;
                            if (Build.VERSION.SDK_INT >= 17) {
                                EmbedBottomSheet.this.webView.addJavascriptInterface(new YoutubeProxy(), "YoutubeProxy");
                            }
                            int iIntValue = 0;
                            if (EmbedBottomSheet.this.openUrl != null) {
                                try {
                                    Uri uri = Uri.parse(EmbedBottomSheet.this.openUrl);
                                    if (EmbedBottomSheet.this.seekTimeOverride > 0) {
                                        queryParameter = "" + EmbedBottomSheet.this.seekTimeOverride;
                                    }
                                    if (queryParameter == null && (queryParameter = uri.getQueryParameter("t")) == null) {
                                        queryParameter = uri.getQueryParameter("time_continue");
                                    }
                                    if (queryParameter != null) {
                                        if (queryParameter.contains("m")) {
                                            String[] strArrSplit = queryParameter.split("m");
                                            iIntValue = (Utilities.parseInt(strArrSplit[0]).intValue() * 60) + Utilities.parseInt(strArrSplit[1]).intValue();
                                        } else {
                                            iIntValue = Utilities.parseInt(queryParameter).intValue();
                                        }
                                    }
                                } catch (Exception e) {
                                    FileLog.e(e);
                                }
                            }
                            EmbedBottomSheet.this.webView.loadDataWithBaseURL("https://www.youtube.com", String.format(Locale.US, "<!DOCTYPE html><html><head><style>body { margin: 0; width:100%%; height:100%%;  background-color:#000; }html { width:100%%; height:100%%; background-color:#000; }.embed-container iframe,.embed-container object,   .embed-container embed {       position: absolute;       top: 0;       left: 0;       width: 100%% !important;       height: 100%% !important;   }   </style></head><body>   <div class=\"embed-container\">       <div id=\"player\"></div>   </div>   <script src=\"https://www.youtube.com/iframe_api\"></script>   <script>   var player;   var observer;   var videoEl;   var playing;   var posted = false;   YT.ready(function() {       player = new YT.Player(\"player\", {                              \"width\" : \"100%%\",                              \"events\" : {                              \"onReady\" : \"onReady\",                              \"onError\" : \"onError\",                              },                              \"videoId\" : \"%1$s\",                              \"height\" : \"100%%\",                              \"playerVars\" : {                              \"start\" : %2$d,                              \"rel\" : 0,                              \"showinfo\" : 0,                              \"modestbranding\" : 1,                              \"iv_load_policy\" : 3,                              \"autohide\" : 1,                              \"autoplay\" : 1,                              \"cc_load_policy\" : 1,                              \"playsinline\" : 1,                              \"controls\" : 1                              }                            });        player.setSize(window.innerWidth, window.innerHeight);    });    function hideControls() {        playing = !videoEl.paused;       videoEl.controls = 0;       observer.observe(videoEl, {attributes: true});    }    function showControls() {        playing = !videoEl.paused;       observer.disconnect();       videoEl.controls = 1;    }    function onError(event) {       if (!posted) {            if (window.YoutubeProxy !== undefined) {                   YoutubeProxy.postEvent(\"loaded\", null);             }            posted = true;       }    }    function onReady(event) {       player.playVideo();       videoEl = player.getIframe().contentDocument.getElementsByTagName('video')[0];\n       videoEl.addEventListener(\"canplay\", function() {            if (playing) {               videoEl.play();            }       }, true);       videoEl.addEventListener(\"timeupdate\", function() {            if (!posted && videoEl.currentTime > 0) {               if (window.YoutubeProxy !== undefined) {                   YoutubeProxy.postEvent(\"loaded\", null);                }               posted = true;           }       }, true);       observer = new MutationObserver(function() {\n          if (videoEl.controls) {\n               videoEl.controls = 0;\n          }       });\n    }    window.onresize = function() {        player.setSize(window.innerWidth, window.innerHeight);    }    </script></body></html>", youtubeId, Integer.valueOf(iIntValue)), "text/html", "UTF-8", "http://youtube.com");
                            return;
                        }
                        EmbedBottomSheet.this.webView.loadUrl(EmbedBottomSheet.this.embedUrl, map);
                        return;
                    } catch (Exception e2) {
                        FileLog.e(e2);
                        return;
                    }
                }
                EmbedBottomSheet.this.progressBar.setVisibility(4);
                EmbedBottomSheet.this.webView.setVisibility(4);
                EmbedBottomSheet.this.videoView.setVisibility(0);
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegate, im.uwrkaxlmjj.ui.actionbar.BottomSheet.BottomSheetDelegateInterface
            public boolean canDismiss() {
                if (EmbedBottomSheet.this.videoView.isInFullscreen()) {
                    EmbedBottomSheet.this.videoView.exitFullscreen();
                    return false;
                }
                try {
                    EmbedBottomSheet.this.parentActivity.getWindow().clearFlags(128);
                    return true;
                } catch (Exception e) {
                    FileLog.e(e);
                    return true;
                }
            }
        });
        this.orientationEventListener = new OrientationEventListener(ApplicationLoader.applicationContext) { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.8
            @Override // android.view.OrientationEventListener
            public void onOrientationChanged(int orientation) {
                if (EmbedBottomSheet.this.orientationEventListener != null && EmbedBottomSheet.this.videoView.getVisibility() == 0 && EmbedBottomSheet.this.parentActivity != null && EmbedBottomSheet.this.videoView.isInFullscreen() && EmbedBottomSheet.this.fullscreenedByButton) {
                    if (orientation < 240 || orientation > 300) {
                        if (EmbedBottomSheet.this.wasInLandscape) {
                            if (orientation >= 330 || orientation <= 30) {
                                EmbedBottomSheet.this.parentActivity.setRequestedOrientation(EmbedBottomSheet.this.prevOrientation);
                                EmbedBottomSheet.this.fullscreenedByButton = false;
                                EmbedBottomSheet.this.wasInLandscape = false;
                                return;
                            }
                            return;
                        }
                        return;
                    }
                    EmbedBottomSheet.this.wasInLandscape = true;
                }
            }
        };
        String currentYoutubeId = this.videoView.getYouTubeVideoId(this.embedUrl);
        if (currentYoutubeId != null) {
            this.progressBar.setVisibility(0);
            this.webView.setVisibility(0);
            this.imageButtonsContainer.setVisibility(0);
            this.progressBarBlackBackground.setVisibility(0);
            this.copyTextButton.setVisibility(4);
            this.webView.setKeepScreenOn(true);
            this.videoView.setVisibility(4);
            this.videoView.getControlsView().setVisibility(4);
            this.videoView.getTextureView().setVisibility(4);
            if (this.videoView.getTextureImageView() != null) {
                this.videoView.getTextureImageView().setVisibility(4);
            }
        }
        if (this.orientationEventListener.canDetectOrientation()) {
            this.orientationEventListener.enable();
        } else {
            this.orientationEventListener.disable();
            this.orientationEventListener = null;
        }
        instance = this;
    }

    static /* synthetic */ boolean lambda$new$0(View v, MotionEvent event) {
        return true;
    }

    static /* synthetic */ boolean lambda$new$1(View v, MotionEvent event) {
        return true;
    }

    static /* synthetic */ boolean lambda$new$2(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$new$3$EmbedBottomSheet(View v) {
        dismiss();
    }

    public /* synthetic */ void lambda$new$4$EmbedBottomSheet(View v) {
        int i;
        if (!checkInlinePermissions() || this.progressBar.getVisibility() == 0) {
            return;
        }
        PipVideoView pipVideoView = new PipVideoView();
        this.pipVideoView = pipVideoView;
        Activity activity = this.parentActivity;
        int i2 = this.width;
        pipVideoView.show(activity, this, null, (i2 == 0 || (i = this.height) == 0) ? 1.0f : i2 / i, 0, this.webView);
        if (this.isYouTube) {
            runJsCode("hideControls();");
        }
        if (0 == 0) {
            this.containerView.setTranslationY(0.0f);
        } else {
            this.animationInProgress = true;
            View view = this.videoView.getAspectRatioView();
            view.getLocationInWindow(this.position);
            int[] iArr = this.position;
            iArr[0] = iArr[0] - getLeftInset();
            this.position[1] = (int) (r4[1] - this.containerView.getTranslationY());
            TextureView textureView = this.videoView.getTextureView();
            ImageView textureImageView = this.videoView.getTextureImageView();
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.TRANSLATION_X, this.position[0]), ObjectAnimator.ofFloat(textureImageView, (Property<ImageView, Float>) View.TRANSLATION_Y, this.position[1]), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.TRANSLATION_X, this.position[0]), ObjectAnimator.ofFloat(textureView, (Property<TextureView, Float>) View.TRANSLATION_Y, this.position[1]), ObjectAnimator.ofFloat(this.containerView, (Property<ViewGroup, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofInt(this.backDrawable, AnimationProperties.COLOR_DRAWABLE_ALPHA, 51));
            animatorSet.setInterpolator(new DecelerateInterpolator());
            animatorSet.setDuration(250L);
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmbedBottomSheet.6
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    EmbedBottomSheet.this.animationInProgress = false;
                }
            });
            animatorSet.start();
        }
        dismissInternal();
    }

    public /* synthetic */ void lambda$new$5$EmbedBottomSheet(View v) {
        try {
            ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
            ClipData clip = ClipData.newPlainText("label", this.openUrl);
            clipboard.setPrimaryClip(clip);
        } catch (Exception e) {
            FileLog.e(e);
        }
        ToastUtils.show(R.string.LinkCopied);
        dismiss();
    }

    public /* synthetic */ void lambda$new$6$EmbedBottomSheet(View v) {
        Browser.openUrl(this.parentActivity, this.openUrl);
        dismiss();
    }

    private void runJsCode(String code) {
        if (Build.VERSION.SDK_INT >= 21) {
            this.webView.evaluateJavascript(code, null);
            return;
        }
        try {
            this.webView.loadUrl("javascript:" + code);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public boolean checkInlinePermissions() {
        if (this.parentActivity == null) {
            return false;
        }
        if (Build.VERSION.SDK_INT < 23 || Settings.canDrawOverlays(this.parentActivity)) {
            return true;
        }
        new AlertDialog.Builder(this.parentActivity).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("PermissionDrawAboveOtherApps", R.string.PermissionDrawAboveOtherApps)).setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmbedBottomSheet$hCyPZndFqDmXy8A_FMoveekrmQ4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$checkInlinePermissions$7$EmbedBottomSheet(dialogInterface, i);
            }
        }).show();
        return false;
    }

    public /* synthetic */ void lambda$checkInlinePermissions$7$EmbedBottomSheet(DialogInterface dialog, int which) {
        Activity activity = this.parentActivity;
        if (activity != null) {
            activity.startActivity(new Intent("android.settings.action.MANAGE_OVERLAY_PERMISSION", Uri.parse("package:" + this.parentActivity.getPackageName())));
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return (this.videoView.getVisibility() == 0 && this.videoView.isInFullscreen()) ? false : true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    public void onConfigurationChanged(Configuration newConfig) {
        if (this.videoView.getVisibility() == 0 && this.videoView.isInitied() && !this.videoView.isInline()) {
            if (newConfig.orientation == 2) {
                if (!this.videoView.isInFullscreen()) {
                    this.videoView.enterFullscreen();
                }
            } else if (this.videoView.isInFullscreen()) {
                this.videoView.exitFullscreen();
            }
        }
        PipVideoView pipVideoView = this.pipVideoView;
        if (pipVideoView != null) {
            pipVideoView.onConfigurationChanged();
        }
    }

    public void destroy() {
        WebView webView = this.webView;
        if (webView != null && webView.getVisibility() == 0) {
            this.containerLayout.removeView(this.webView);
            this.webView.stopLoading();
            this.webView.loadUrl("about:blank");
            this.webView.destroy();
        }
        PipVideoView pipVideoView = this.pipVideoView;
        if (pipVideoView != null) {
            pipVideoView.close();
            this.pipVideoView = null;
        }
        WebPlayerView webPlayerView = this.videoView;
        if (webPlayerView != null) {
            webPlayerView.destroy();
        }
        instance = null;
        dismissInternal();
    }

    public void exitFromPip() {
        if (this.webView == null || this.pipVideoView == null) {
            return;
        }
        if (ApplicationLoader.mainInterfacePaused) {
            try {
                this.parentActivity.startService(new Intent(ApplicationLoader.applicationContext, (Class<?>) BringAppForegroundService.class));
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        if (this.isYouTube) {
            runJsCode("showControls();");
        }
        ViewGroup parent = (ViewGroup) this.webView.getParent();
        if (parent != null) {
            parent.removeView(this.webView);
        }
        this.containerLayout.addView(this.webView, 0, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, (this.hasDescription ? 22 : 0) + 84));
        setShowWithoutAnimation(true);
        show();
        this.pipVideoView.close();
        this.pipVideoView = null;
    }

    public static EmbedBottomSheet getInstance() {
        return instance;
    }

    public void updateTextureViewPosition() {
        View view = this.videoView.getAspectRatioView();
        view.getLocationInWindow(this.position);
        int[] iArr = this.position;
        iArr[0] = iArr[0] - getLeftInset();
        if (!this.videoView.isInline() && !this.animationInProgress) {
            TextureView textureView = this.videoView.getTextureView();
            textureView.setTranslationX(this.position[0]);
            textureView.setTranslationY(this.position[1]);
            View textureImageView = this.videoView.getTextureImageView();
            if (textureImageView != null) {
                textureImageView.setTranslationX(this.position[0]);
                textureImageView.setTranslationY(this.position[1]);
            }
        }
        View controlsView = this.videoView.getControlsView();
        if (controlsView.getParent() == this.container) {
            controlsView.setTranslationY(this.position[1]);
        } else {
            controlsView.setTranslationY(0.0f);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithTouchOutside() {
        return this.fullscreenVideoContainer.getVisibility() != 0;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected void onContainerTranslationYChanged(float translationY) {
        updateTextureViewPosition();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onCustomMeasure(View view, int width, int height) {
        if (view == this.videoView.getControlsView()) {
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            layoutParams.width = this.videoView.getMeasuredWidth();
            layoutParams.height = this.videoView.getAspectRatioView().getMeasuredHeight() + (this.videoView.isInFullscreen() ? 0 : AndroidUtilities.dp(10.0f));
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean onCustomLayout(View view, int left, int top, int right, int bottom) {
        if (view == this.videoView.getControlsView()) {
            updateTextureViewPosition();
            return false;
        }
        return false;
    }

    public void pause() {
        WebPlayerView webPlayerView = this.videoView;
        if (webPlayerView != null && webPlayerView.isInitied()) {
            this.videoView.pause();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    public void onContainerDraw(Canvas canvas) {
        int i = this.waitingForDraw;
        if (i != 0) {
            int i2 = i - 1;
            this.waitingForDraw = i2;
            if (i2 == 0) {
                this.videoView.updateTextureImageView();
                this.pipVideoView.close();
                this.pipVideoView = null;
                return;
            }
            this.container.invalidate();
        }
    }
}
