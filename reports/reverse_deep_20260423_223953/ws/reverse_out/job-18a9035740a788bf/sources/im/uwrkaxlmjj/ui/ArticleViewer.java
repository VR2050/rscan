package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.IntEvaluator;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.DataSetObserver;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.style.MetricAffectingSpan;
import android.text.style.URLSpan;
import android.util.LongSparseArray;
import android.util.Property;
import android.util.SparseArray;
import android.view.DisplayCutout;
import android.view.GestureDetector;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.DecelerateInterpolator;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.core.internal.view.SupportMenu;
import androidx.core.net.MailTo;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.GridLayoutManagerFixed;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.ui.AspectRatioFrameLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.WebFile;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BackDrawable;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AnchorSpan;
import im.uwrkaxlmjj.ui.components.AnimatedArrowDrawable;
import im.uwrkaxlmjj.ui.components.AnimatedFileDrawable;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.ClippingImageView;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.GroupedPhotosListView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.LineProgressView;
import im.uwrkaxlmjj.ui.components.LinkPath;
import im.uwrkaxlmjj.ui.components.RadialProgress2;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.Scroller;
import im.uwrkaxlmjj.ui.components.SeekBar;
import im.uwrkaxlmjj.ui.components.ShareAlert;
import im.uwrkaxlmjj.ui.components.StaticLayoutEx;
import im.uwrkaxlmjj.ui.components.TableLayout;
import im.uwrkaxlmjj.ui.components.TextPaintImageReceiverSpan;
import im.uwrkaxlmjj.ui.components.TextPaintMarkSpan;
import im.uwrkaxlmjj.ui.components.TextPaintSpan;
import im.uwrkaxlmjj.ui.components.TextPaintUrlSpan;
import im.uwrkaxlmjj.ui.components.TextPaintWebpageUrlSpan;
import im.uwrkaxlmjj.ui.components.TypefaceSpan;
import im.uwrkaxlmjj.ui.components.VideoPlayer;
import im.uwrkaxlmjj.ui.components.WebPlayerView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.lang.reflect.Array;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes5.dex */
public class ArticleViewer implements NotificationCenter.NotificationCenterDelegate, GestureDetector.OnGestureListener, GestureDetector.OnDoubleTapListener {
    private static final int TEXT_FLAG_ITALIC = 2;
    private static final int TEXT_FLAG_MARKED = 64;
    private static final int TEXT_FLAG_MEDIUM = 1;
    private static final int TEXT_FLAG_MONO = 4;
    private static final int TEXT_FLAG_REGULAR = 0;
    private static final int TEXT_FLAG_STRIKE = 32;
    private static final int TEXT_FLAG_SUB = 128;
    private static final int TEXT_FLAG_SUP = 256;
    private static final int TEXT_FLAG_UNDERLINE = 16;
    private static final int TEXT_FLAG_URL = 8;
    private static final int TEXT_FLAG_WEBPAGE_URL = 512;
    private static TextPaint channelNamePaint = null;
    private static Paint colorPaint = null;
    private static DecelerateInterpolator decelerateInterpolator = null;
    private static Paint dividerPaint = null;
    private static Paint dotsPaint = null;
    private static TextPaint embedPostAuthorPaint = null;
    private static TextPaint embedPostDatePaint = null;
    private static TextPaint errorTextPaint = null;
    private static final int gallery_menu_openin = 3;
    private static final int gallery_menu_save = 1;
    private static final int gallery_menu_share = 2;
    private static TextPaint listTextNumPaint;
    private static TextPaint listTextPointerPaint;
    private static Paint photoBackgroundPaint;
    private static Paint preformattedBackgroundPaint;
    private static Drawable[] progressDrawables;
    private static Paint progressPaint;
    private static Paint quoteLinePaint;
    private static TextPaint relatedArticleHeaderPaint;
    private static TextPaint relatedArticleTextPaint;
    private static Paint selectorPaint;
    private static Paint tableHalfLinePaint;
    private static Paint tableHeaderPaint;
    private static Paint tableLinePaint;
    private static Paint tableStripPaint;
    private static Paint urlPaint;
    private static Paint webpageMarkPaint;
    private static Paint webpageUrlPaint;
    private ActionBar actionBar;
    private WebpageAdapter[] adapter;
    private int anchorsOffsetMeasuredWidth;
    private float animateToScale;
    private float animateToX;
    private float animateToY;
    private ClippingImageView animatingImageView;
    private Runnable animationEndRunnable;
    private int animationInProgress;
    private long animationStartTime;
    private float animationValue;
    private AspectRatioFrameLayout aspectRatioFrameLayout;
    private boolean attachedToWindow;
    private ImageView backButton;
    private BackDrawable backDrawable;
    private Paint backgroundPaint;
    private FrameLayout bottomLayout;
    private TextView captionTextView;
    private TextView captionTextViewNext;
    private boolean changingPage;
    private TLRPC.TL_pageBlockChannel channelBlock;
    private boolean collapsed;
    private FrameLayout containerView;
    private Drawable copyBackgroundDrawable;
    private int currentAccount;
    private AnimatorSet currentActionBarAnimation;
    private AnimatedFileDrawable currentAnimation;
    private int currentHeaderHeight;
    private int currentIndex;
    private TLRPC.PageBlock currentMedia;
    private TLRPC.WebPage currentPage;
    private PlaceProviderObject currentPlaceObject;
    private WebPlayerView currentPlayingVideo;
    private int currentRotation;
    private ImageReceiver.BitmapHolder currentThumb;
    private View customView;
    private WebChromeClient.CustomViewCallback customViewCallback;
    private TextView deleteView;
    private boolean disableShowCheck;
    private boolean discardTap;
    private boolean dontResetZoomOnFirstLayout;
    private boolean doubleTap;
    private float dragY;
    private boolean draggingDown;
    private boolean drawBlockSelection;
    private AspectRatioFrameLayout fullscreenAspectRatioView;
    private TextureView fullscreenTextureView;
    private FrameLayout fullscreenVideoContainer;
    private WebPlayerView fullscreenedVideo;
    private GestureDetector gestureDetector;
    private GroupedPhotosListView groupedPhotosListView;
    boolean hasCutout;
    private FrameLayout headerView;
    private PlaceProviderObject hideAfterAnimation;
    private AnimatorSet imageMoveAnimation;
    private boolean invalidCoords;
    private boolean isPhotoVisible;
    private boolean isPlaying;
    private boolean isRtl;
    private boolean isVisible;
    private Object lastInsets;
    private int lastReqId;
    private Drawable layerShadowDrawable;
    private LinearLayoutManager[] layoutManager;
    private Runnable lineProgressTickRunnable;
    private LineProgressView lineProgressView;
    private BottomSheet linkSheet;
    private RecyclerListView[] listView;
    private TLRPC.Chat loadedChannel;
    private boolean loadingChannel;
    private float maxX;
    private float maxY;
    private ActionBarMenuItem menuItem;
    private float minX;
    private float minY;
    private float moveStartX;
    private float moveStartY;
    private boolean moving;
    private boolean nightModeEnabled;
    private FrameLayout nightModeHintView;
    private ImageView nightModeImageView;
    private int openUrlReqId;
    private AnimatorSet pageSwitchAnimation;
    private Activity parentActivity;
    private BaseFragment parentFragment;
    private Runnable photoAnimationEndRunnable;
    private int photoAnimationInProgress;
    private View photoContainerBackground;
    private FrameLayoutDrawer photoContainerView;
    private long photoTransitionAnimationStartTime;
    private float pinchCenterX;
    private float pinchCenterY;
    private float pinchStartDistance;
    private float pinchStartX;
    private float pinchStartY;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout popupLayout;
    private Rect popupRect;
    private ActionBarPopupWindow popupWindow;
    private int pressedLayoutY;
    private TextPaintUrlSpan pressedLink;
    private DrawingText pressedLinkOwnerLayout;
    private View pressedLinkOwnerView;
    private int previewsReqId;
    private ContextProgressView progressView;
    private AnimatorSet progressViewAnimation;
    private Paint scrimPaint;
    private Scroller scroller;
    private ActionBarMenuItem settingsButton;
    private ImageView shareButton;
    private FrameLayout shareContainer;
    private PlaceProviderObject showAfterAnimation;
    private Drawable slideDotBigDrawable;
    private Drawable slideDotDrawable;
    private int switchImageAfterAnimation;
    private boolean textureUploaded;
    private SimpleTextView titleTextView;
    private long transitionAnimationStartTime;
    private float translationX;
    private float translationY;
    private VelocityTracker velocityTracker;
    private float videoCrossfadeAlpha;
    private long videoCrossfadeAlphaLastTime;
    private boolean videoCrossfadeStarted;
    private ImageView videoPlayButton;
    private VideoPlayer videoPlayer;
    private FrameLayout videoPlayerControlFrameLayout;
    private SeekBar videoPlayerSeekbar;
    private TextView videoPlayerTime;
    private TextureView videoTextureView;
    private Dialog visibleDialog;
    private boolean wasLayout;
    private WindowManager.LayoutParams windowLayoutParams;
    private WindowView windowView;
    private boolean zoomAnimation;
    private boolean zooming;
    private static volatile ArticleViewer Instance = null;
    public static final Property<WindowView, Float> ARTICLE_VIEWER_INNER_TRANSLATION_X = new AnimationProperties.FloatProperty<WindowView>("innerTranslationX") { // from class: im.uwrkaxlmjj.ui.ArticleViewer.1
        @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
        public void setValue(WindowView object, float value) {
            object.setInnerTranslationX(value);
        }

        @Override // android.util.Property
        public Float get(WindowView object) {
            return Float.valueOf(object.getInnerTranslationX());
        }
    };
    private static TextPaint audioTimePaint = new TextPaint(1);
    private static SparseArray<TextPaint> photoCaptionTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> photoCreditTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> titleTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> kickerTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> headerTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> subtitleTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> subheaderTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> authorTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> footerTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> paragraphTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> listTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> preformattedTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> quoteTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> embedPostTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> embedPostCaptionTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> mediaCaptionTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> mediaCreditTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> relatedArticleTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> detailsTextPaints = new SparseArray<>();
    private static SparseArray<TextPaint> tableTextPaints = new SparseArray<>();
    private ArrayList<BlockEmbedCell> createdWebViews = new ArrayList<>();
    private int lastBlockNum = 1;
    private ArrayList<TLRPC.WebPage> pagesStack = new ArrayList<>();
    private Paint headerPaint = new Paint();
    private Paint statusBarPaint = new Paint();
    private Paint headerProgressPaint = new Paint();
    private boolean checkingForLongPress = false;
    private CheckForLongPress pendingCheckForLongPress = null;
    private int pressCount = 0;
    private CheckForTap pendingCheckForTap = null;
    private LinkPath urlPath = new LinkPath();
    private final int fontSizeCount = 5;
    private int selectedFontSize = 2;
    private int selectedColor = 0;
    private int selectedFont = 0;
    private ColorCell[] colorCells = new ColorCell[3];
    private FontCell[] fontCells = new FontCell[2];
    private int[] coords = new int[2];
    private boolean isActionBarVisible = true;
    private PhotoBackgroundDrawable photoBackgroundDrawable = new PhotoBackgroundDrawable(-16777216);
    private Paint blackPaint = new Paint();
    private RadialProgressView[] radialProgressViews = new RadialProgressView[3];
    private Runnable updateProgressRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.18
        @Override // java.lang.Runnable
        public void run() {
            if (ArticleViewer.this.videoPlayer != null && ArticleViewer.this.videoPlayerSeekbar != null && !ArticleViewer.this.videoPlayerSeekbar.isDragging()) {
                float progress = ArticleViewer.this.videoPlayer.getCurrentPosition() / ArticleViewer.this.videoPlayer.getDuration();
                ArticleViewer.this.videoPlayerSeekbar.setProgress(progress);
                ArticleViewer.this.videoPlayerControlFrameLayout.invalidate();
                ArticleViewer.this.updateVideoPlayerTime();
            }
            if (ArticleViewer.this.isPlaying) {
                AndroidUtilities.runOnUIThread(ArticleViewer.this.updateProgressRunnable, 100L);
            }
        }
    };
    private float[][] animationValues = (float[][]) Array.newInstance((Class<?>) float.class, 2, 10);
    private ImageReceiver leftImage = new ImageReceiver();
    private ImageReceiver centerImage = new ImageReceiver();
    private ImageReceiver rightImage = new ImageReceiver();
    private String[] currentFileNames = new String[3];
    private float scale = 1.0f;
    private DecelerateInterpolator interpolator = new DecelerateInterpolator(1.5f);
    private float pinchStartScale = 1.0f;
    private boolean canZoom = true;
    private boolean canDragDown = true;
    private ArrayList<TLRPC.PageBlock> imagesArr = new ArrayList<>();

    public static class PlaceProviderObject {
        public int clipBottomAddition;
        public int clipTopAddition;
        public ImageReceiver imageReceiver;
        public int index;
        public View parentView;
        public int radius;
        public float scale = 1.0f;
        public int size;
        public ImageReceiver.BitmapHolder thumb;
        public int viewX;
        public int viewY;
    }

    static /* synthetic */ int access$1104(ArticleViewer x0) {
        int i = x0.pressCount + 1;
        x0.pressCount = i;
        return i;
    }

    static /* synthetic */ int access$13108(ArticleViewer x0) {
        int i = x0.lastBlockNum;
        x0.lastBlockNum = i + 1;
        return i;
    }

    public static ArticleViewer getInstance() {
        ArticleViewer localInstance = Instance;
        if (localInstance == null) {
            synchronized (ArticleViewer.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    ArticleViewer articleViewer = new ArticleViewer();
                    localInstance = articleViewer;
                    Instance = articleViewer;
                }
            }
        }
        return localInstance;
    }

    public static boolean hasInstance() {
        return Instance != null;
    }

    private class TL_pageBlockRelatedArticlesChild extends TLRPC.PageBlock {
        private int num;
        private TLRPC.TL_pageBlockRelatedArticles parent;

        private TL_pageBlockRelatedArticlesChild() {
        }
    }

    private class TL_pageBlockRelatedArticlesShadow extends TLRPC.PageBlock {
        private TLRPC.TL_pageBlockRelatedArticles parent;

        private TL_pageBlockRelatedArticlesShadow() {
        }
    }

    private class TL_pageBlockDetailsChild extends TLRPC.PageBlock {
        private TLRPC.PageBlock block;
        private TLRPC.PageBlock parent;

        private TL_pageBlockDetailsChild() {
        }
    }

    private class TL_pageBlockDetailsBottom extends TLRPC.PageBlock {
        private TLRPC.TL_pageBlockDetails parent;

        private TL_pageBlockDetailsBottom() {
        }
    }

    private class TL_pageBlockListParent extends TLRPC.PageBlock {
        private ArrayList<TL_pageBlockListItem> items;
        private int lastFontSize;
        private int lastMaxNumCalcWidth;
        private int level;
        private int maxNumWidth;
        private TLRPC.TL_pageBlockList pageBlockList;

        private TL_pageBlockListParent() {
            this.items = new ArrayList<>();
        }
    }

    private class TL_pageBlockListItem extends TLRPC.PageBlock {
        private TLRPC.PageBlock blockItem;
        private int index;
        private String num;
        private DrawingText numLayout;
        private TL_pageBlockListParent parent;
        private TLRPC.RichText textItem;

        private TL_pageBlockListItem() {
            this.index = Integer.MAX_VALUE;
        }
    }

    private class TL_pageBlockOrderedListParent extends TLRPC.PageBlock {
        private ArrayList<TL_pageBlockOrderedListItem> items;
        private int lastFontSize;
        private int lastMaxNumCalcWidth;
        private int level;
        private int maxNumWidth;
        private TLRPC.TL_pageBlockOrderedList pageBlockOrderedList;

        private TL_pageBlockOrderedListParent() {
            this.items = new ArrayList<>();
        }
    }

    private class TL_pageBlockOrderedListItem extends TLRPC.PageBlock {
        private TLRPC.PageBlock blockItem;
        private int index;
        private String num;
        private DrawingText numLayout;
        private TL_pageBlockOrderedListParent parent;
        private TLRPC.RichText textItem;

        private TL_pageBlockOrderedListItem() {
            this.index = Integer.MAX_VALUE;
        }
    }

    private class TL_pageBlockEmbedPostCaption extends TLRPC.TL_pageBlockEmbedPost {
        private TLRPC.TL_pageBlockEmbedPost parent;

        private TL_pageBlockEmbedPostCaption() {
        }
    }

    public class DrawingText {
        public LinkPath markPath;
        public StaticLayout textLayout;
        public LinkPath textPath;

        public DrawingText() {
        }

        public void draw(Canvas canvas) {
            LinkPath linkPath = this.textPath;
            if (linkPath != null) {
                canvas.drawPath(linkPath, ArticleViewer.webpageUrlPaint);
            }
            LinkPath linkPath2 = this.markPath;
            if (linkPath2 != null) {
                canvas.drawPath(linkPath2, ArticleViewer.webpageMarkPaint);
            }
            ArticleViewer.this.drawLayoutLink(canvas, this);
            this.textLayout.draw(canvas);
        }

        public CharSequence getText() {
            return this.textLayout.getText();
        }

        public int getLineCount() {
            return this.textLayout.getLineCount();
        }

        public int getLineAscent(int line) {
            return this.textLayout.getLineAscent(line);
        }

        public float getLineLeft(int line) {
            return this.textLayout.getLineLeft(line);
        }

        public float getLineWidth(int line) {
            return this.textLayout.getLineWidth(line);
        }

        public int getHeight() {
            return this.textLayout.getHeight();
        }

        public int getWidth() {
            return this.textLayout.getWidth();
        }
    }

    private class SizeChooseView extends View {
        private int circleSize;
        private int gapSize;
        private int lineSize;
        private boolean moving;
        private Paint paint;
        private int sideSide;
        private boolean startMoving;
        private int startMovingQuality;
        private float startX;

        public SizeChooseView(Context context) {
            super(context);
            this.paint = new Paint(1);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            float x = event.getX();
            if (event.getAction() == 0) {
                getParent().requestDisallowInterceptTouchEvent(true);
                int a = 0;
                while (true) {
                    if (a >= 5) {
                        break;
                    }
                    int i = this.sideSide;
                    int i2 = this.lineSize + (this.gapSize * 2);
                    int i3 = this.circleSize;
                    int cx = i + ((i2 + i3) * a) + (i3 / 2);
                    if (x > cx - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx) {
                        this.startMoving = a == ArticleViewer.this.selectedFontSize;
                        this.startX = x;
                        this.startMovingQuality = ArticleViewer.this.selectedFontSize;
                    } else {
                        a++;
                    }
                }
            } else if (event.getAction() == 2) {
                if (this.startMoving) {
                    if (Math.abs(this.startX - x) >= AndroidUtilities.getPixelsInCM(0.5f, true)) {
                        this.moving = true;
                        this.startMoving = false;
                    }
                } else if (this.moving) {
                    int a2 = 0;
                    while (true) {
                        if (a2 >= 5) {
                            break;
                        }
                        int i4 = this.sideSide;
                        int i5 = this.lineSize;
                        int i6 = this.gapSize;
                        int i7 = this.circleSize;
                        int cx2 = i4 + (((i6 * 2) + i5 + i7) * a2) + (i7 / 2);
                        int diff = (i5 / 2) + (i7 / 2) + i6;
                        if (x > cx2 - diff && x < cx2 + diff) {
                            if (ArticleViewer.this.selectedFontSize != a2) {
                                ArticleViewer.this.selectedFontSize = a2;
                                ArticleViewer.this.updatePaintSize();
                                invalidate();
                            }
                        } else {
                            a2++;
                        }
                    }
                }
            } else if (event.getAction() == 1 || event.getAction() == 3) {
                if (this.moving) {
                    if (ArticleViewer.this.selectedFontSize != this.startMovingQuality) {
                        ArticleViewer.this.updatePaintSize();
                    }
                } else {
                    int a3 = 0;
                    while (true) {
                        if (a3 >= 5) {
                            break;
                        }
                        int i8 = this.sideSide;
                        int i9 = this.lineSize + (this.gapSize * 2);
                        int i10 = this.circleSize;
                        int cx3 = i8 + ((i9 + i10) * a3) + (i10 / 2);
                        if (x > cx3 - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx3) {
                            if (ArticleViewer.this.selectedFontSize != a3) {
                                ArticleViewer.this.selectedFontSize = a3;
                                ArticleViewer.this.updatePaintSize();
                                invalidate();
                            }
                        } else {
                            a3++;
                        }
                    }
                }
                this.startMoving = false;
                this.moving = false;
            }
            return true;
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            View.MeasureSpec.getSize(widthMeasureSpec);
            this.circleSize = AndroidUtilities.dp(5.0f);
            this.gapSize = AndroidUtilities.dp(2.0f);
            this.sideSide = AndroidUtilities.dp(17.0f);
            this.lineSize = (((getMeasuredWidth() - (this.circleSize * 5)) - ((this.gapSize * 2) * 4)) - (this.sideSide * 2)) / 4;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int cy = getMeasuredHeight() / 2;
            int a = 0;
            while (a < 5) {
                int i = this.sideSide;
                int i2 = this.lineSize + (this.gapSize * 2);
                int i3 = this.circleSize;
                int cx = i + ((i2 + i3) * a) + (i3 / 2);
                if (a <= ArticleViewer.this.selectedFontSize) {
                    this.paint.setColor(-15428119);
                } else {
                    this.paint.setColor(-3355444);
                }
                canvas.drawCircle(cx, cy, a == ArticleViewer.this.selectedFontSize ? AndroidUtilities.dp(4.0f) : this.circleSize / 2, this.paint);
                if (a != 0) {
                    int x = ((cx - (this.circleSize / 2)) - this.gapSize) - this.lineSize;
                    canvas.drawRect(x, cy - AndroidUtilities.dp(1.0f), this.lineSize + x, AndroidUtilities.dp(1.0f) + cy, this.paint);
                }
                a++;
            }
        }
    }

    public class ColorCell extends FrameLayout {
        private int currentColor;
        private boolean selected;
        private TextView textView;

        public ColorCell(Context context) {
            super(context);
            if (ArticleViewer.colorPaint == null) {
                Paint unused = ArticleViewer.colorPaint = new Paint(1);
                Paint unused2 = ArticleViewer.selectorPaint = new Paint(1);
                ArticleViewer.selectorPaint.setColor(-15428119);
                ArticleViewer.selectorPaint.setStyle(Paint.Style.STROKE);
                ArticleViewer.selectorPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            }
            setBackgroundDrawable(Theme.createSelectorDrawable(251658240, 2));
            setWillNotDraw(false);
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextColor(-14606047);
            this.textView.setTextSize(1, 16.0f);
            this.textView.setLines(1);
            this.textView.setMaxLines(1);
            this.textView.setSingleLine(true);
            this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
            this.textView.setPadding(0, 0, 0, AndroidUtilities.dp(1.0f));
            addView(this.textView, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 17 : 53, 0.0f, LocaleController.isRTL ? 53 : 17, 0.0f));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
        }

        public void setTextAndColor(String text, int color) {
            this.textView.setText(text);
            this.currentColor = color;
            invalidate();
        }

        public void select(boolean value) {
            if (this.selected == value) {
                return;
            }
            this.selected = value;
            invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            ArticleViewer.colorPaint.setColor(this.currentColor);
            canvas.drawCircle(!LocaleController.isRTL ? AndroidUtilities.dp(28.0f) : getMeasuredWidth() - AndroidUtilities.dp(28.0f), getMeasuredHeight() / 2, AndroidUtilities.dp(10.0f), ArticleViewer.colorPaint);
            if (this.selected) {
                ArticleViewer.selectorPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
                ArticleViewer.selectorPaint.setColor(-15428119);
                canvas.drawCircle(!LocaleController.isRTL ? AndroidUtilities.dp(28.0f) : getMeasuredWidth() - AndroidUtilities.dp(28.0f), getMeasuredHeight() / 2, AndroidUtilities.dp(10.0f), ArticleViewer.selectorPaint);
            } else if (this.currentColor == -1) {
                ArticleViewer.selectorPaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
                ArticleViewer.selectorPaint.setColor(-4539718);
                canvas.drawCircle(!LocaleController.isRTL ? AndroidUtilities.dp(28.0f) : getMeasuredWidth() - AndroidUtilities.dp(28.0f), getMeasuredHeight() / 2, AndroidUtilities.dp(9.0f), ArticleViewer.selectorPaint);
            }
        }
    }

    public class FontCell extends FrameLayout {
        private TextView textView;
        private TextView textView2;

        public FontCell(Context context) {
            super(context);
            setBackgroundDrawable(Theme.createSelectorDrawable(251658240, 2));
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextColor(-14606047);
            this.textView.setTextSize(1, 16.0f);
            this.textView.setLines(1);
            this.textView.setMaxLines(1);
            this.textView.setSingleLine(true);
            this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
            addView(this.textView, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 17 : 53, 0.0f, LocaleController.isRTL ? 53 : 17, 0.0f));
            TextView textView2 = new TextView(context);
            this.textView2 = textView2;
            textView2.setTextColor(-14606047);
            this.textView2.setTextSize(1, 16.0f);
            this.textView2.setLines(1);
            this.textView2.setMaxLines(1);
            this.textView2.setSingleLine(true);
            this.textView2.setText("Aa");
            this.textView2.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
            addView(this.textView2, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 5 : 3) | 48, 17.0f, 0.0f, 17.0f, 0.0f));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
        }

        public void select(boolean value) {
            this.textView2.setTextColor(value ? -15428119 : -14606047);
        }

        public void setTextAndTypeface(String text, Typeface typeface) {
            this.textView.setText(text);
            this.textView.setTypeface(typeface);
            this.textView2.setTypeface(typeface);
            invalidate();
        }
    }

    private class FrameLayoutDrawer extends FrameLayout {
        public FrameLayoutDrawer(Context context) {
            super(context);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            ArticleViewer.this.processTouchEvent(event);
            return true;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            ArticleViewer.this.drawContent(canvas);
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            return child != ArticleViewer.this.aspectRatioFrameLayout && super.drawChild(canvas, child, drawingTime);
        }
    }

    private final class CheckForTap implements Runnable {
        private CheckForTap() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (ArticleViewer.this.pendingCheckForLongPress == null) {
                ArticleViewer articleViewer = ArticleViewer.this;
                articleViewer.pendingCheckForLongPress = articleViewer.new CheckForLongPress();
            }
            ArticleViewer.this.pendingCheckForLongPress.currentPressCount = ArticleViewer.access$1104(ArticleViewer.this);
            if (ArticleViewer.this.windowView != null) {
                ArticleViewer.this.windowView.postDelayed(ArticleViewer.this.pendingCheckForLongPress, ViewConfiguration.getLongPressTimeout() - ViewConfiguration.getTapTimeout());
            }
        }
    }

    private class WindowView extends FrameLayout {
        private float alpha;
        private Runnable attachRunnable;
        private int bHeight;
        private int bWidth;
        private int bX;
        private int bY;
        private boolean closeAnimationInProgress;
        private float innerTranslationX;
        private boolean maybeStartTracking;
        private boolean movingPage;
        private boolean selfLayout;
        private int startMovingHeaderHeight;
        private boolean startedTracking;
        private int startedTrackingPointerId;
        private int startedTrackingX;
        private int startedTrackingY;
        private VelocityTracker tracker;

        public WindowView(Context context) {
            super(context);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            if (Build.VERSION.SDK_INT >= 21 && ArticleViewer.this.lastInsets != null) {
                setMeasuredDimension(widthSize, heightSize);
                WindowInsets insets = (WindowInsets) ArticleViewer.this.lastInsets;
                if (AndroidUtilities.incorrectDisplaySizeFix) {
                    if (heightSize > AndroidUtilities.displaySize.y) {
                        heightSize = AndroidUtilities.displaySize.y;
                    }
                    heightSize += AndroidUtilities.statusBarHeight;
                }
                int heightSize2 = heightSize - insets.getSystemWindowInsetBottom();
                widthSize -= insets.getSystemWindowInsetRight() + insets.getSystemWindowInsetLeft();
                if (insets.getSystemWindowInsetRight() != 0) {
                    this.bWidth = insets.getSystemWindowInsetRight();
                    this.bHeight = heightSize2;
                } else if (insets.getSystemWindowInsetLeft() != 0) {
                    this.bWidth = insets.getSystemWindowInsetLeft();
                    this.bHeight = heightSize2;
                } else {
                    this.bWidth = widthSize;
                    this.bHeight = insets.getSystemWindowInsetBottom();
                }
                heightSize = heightSize2 - insets.getSystemWindowInsetTop();
            } else {
                setMeasuredDimension(widthSize, heightSize);
            }
            ArticleViewer.this.containerView.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
            ArticleViewer.this.photoContainerView.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
            ArticleViewer.this.photoContainerBackground.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
            ArticleViewer.this.fullscreenVideoContainer.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
            ViewGroup.LayoutParams layoutParams = ArticleViewer.this.animatingImageView.getLayoutParams();
            ArticleViewer.this.animatingImageView.measure(View.MeasureSpec.makeMeasureSpec(layoutParams.width, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(layoutParams.height, Integer.MIN_VALUE));
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            int x;
            if (this.selfLayout) {
                return;
            }
            int width = right - left;
            if (ArticleViewer.this.anchorsOffsetMeasuredWidth != width) {
                for (int i = 0; i < ArticleViewer.this.listView.length; i++) {
                    for (Map.Entry<String, Integer> entry : ArticleViewer.this.adapter[i].anchorsOffset.entrySet()) {
                        entry.setValue(-1);
                    }
                }
                ArticleViewer.this.anchorsOffsetMeasuredWidth = width;
            }
            int y = 0;
            if (Build.VERSION.SDK_INT >= 21 && ArticleViewer.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) ArticleViewer.this.lastInsets;
                x = insets.getSystemWindowInsetLeft();
                if (insets.getSystemWindowInsetRight() != 0) {
                    this.bX = width - this.bWidth;
                    this.bY = 0;
                } else if (insets.getSystemWindowInsetLeft() != 0) {
                    this.bX = 0;
                    this.bY = 0;
                } else {
                    this.bX = 0;
                    this.bY = (bottom - top) - this.bHeight;
                }
                if (Build.VERSION.SDK_INT >= 28) {
                    y = 0 + insets.getSystemWindowInsetTop();
                }
            } else {
                x = 0;
            }
            ArticleViewer.this.containerView.layout(x, y, ArticleViewer.this.containerView.getMeasuredWidth() + x, ArticleViewer.this.containerView.getMeasuredHeight() + y);
            ArticleViewer.this.photoContainerView.layout(x, y, ArticleViewer.this.photoContainerView.getMeasuredWidth() + x, ArticleViewer.this.photoContainerView.getMeasuredHeight() + y);
            ArticleViewer.this.photoContainerBackground.layout(x, y, ArticleViewer.this.photoContainerBackground.getMeasuredWidth() + x, ArticleViewer.this.photoContainerBackground.getMeasuredHeight() + y);
            ArticleViewer.this.fullscreenVideoContainer.layout(x, y, ArticleViewer.this.fullscreenVideoContainer.getMeasuredWidth() + x, ArticleViewer.this.fullscreenVideoContainer.getMeasuredHeight() + y);
            ArticleViewer.this.animatingImageView.layout(0, 0, ArticleViewer.this.animatingImageView.getMeasuredWidth(), ArticleViewer.this.animatingImageView.getMeasuredHeight());
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            ArticleViewer.this.attachedToWindow = true;
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            ArticleViewer.this.attachedToWindow = false;
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            handleTouchEvent(null);
            super.requestDisallowInterceptTouchEvent(disallowIntercept);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            return !ArticleViewer.this.collapsed && (handleTouchEvent(ev) || super.onInterceptTouchEvent(ev));
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return !ArticleViewer.this.collapsed && (handleTouchEvent(event) || super.onTouchEvent(event));
        }

        public void setInnerTranslationX(float value) {
            this.innerTranslationX = value;
            if (ArticleViewer.this.parentActivity instanceof LaunchActivity) {
                ((LaunchActivity) ArticleViewer.this.parentActivity).drawerLayoutContainer.setAllowDrawContent((ArticleViewer.this.isVisible && this.alpha == 1.0f && this.innerTranslationX == 0.0f) ? false : true);
            }
            invalidate();
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            float opacity;
            int width = getMeasuredWidth();
            int translationX = (int) this.innerTranslationX;
            int restoreCount = canvas.save();
            canvas.clipRect(translationX, 0, width, getHeight());
            boolean result = super.drawChild(canvas, child, drawingTime);
            canvas.restoreToCount(restoreCount);
            if (translationX != 0 && child == ArticleViewer.this.containerView) {
                float opacity2 = Math.min(0.8f, (width - translationX) / width);
                if (opacity2 >= 0.0f) {
                    opacity = opacity2;
                } else {
                    opacity = 0.0f;
                }
                ArticleViewer.this.scrimPaint.setColor(((int) (153.0f * opacity)) << 24);
                canvas.drawRect(0.0f, 0.0f, translationX, getHeight(), ArticleViewer.this.scrimPaint);
                float alpha = Math.max(0.0f, Math.min((width - translationX) / AndroidUtilities.dp(20.0f), 1.0f));
                ArticleViewer.this.layerShadowDrawable.setBounds(translationX - ArticleViewer.this.layerShadowDrawable.getIntrinsicWidth(), child.getTop(), translationX, child.getBottom());
                ArticleViewer.this.layerShadowDrawable.setAlpha((int) (255.0f * alpha));
                ArticleViewer.this.layerShadowDrawable.draw(canvas);
            }
            return result;
        }

        public float getInnerTranslationX() {
            return this.innerTranslationX;
        }

        private void prepareForMoving(MotionEvent ev) {
            this.maybeStartTracking = false;
            this.startedTracking = true;
            this.startedTrackingX = (int) ev.getX();
            if (ArticleViewer.this.pagesStack.size() > 1) {
                this.movingPage = true;
                this.startMovingHeaderHeight = ArticleViewer.this.currentHeaderHeight;
                ArticleViewer.this.listView[1].setVisibility(0);
                ArticleViewer.this.listView[1].setAlpha(1.0f);
                ArticleViewer.this.listView[1].setTranslationX(0.0f);
                ArticleViewer.this.listView[0].setBackgroundColor(ArticleViewer.this.backgroundPaint.getColor());
            } else {
                this.movingPage = false;
            }
            ArticleViewer.this.cancelCheckLongPress();
        }

        public boolean handleTouchEvent(MotionEvent event) {
            float distToMove;
            if (ArticleViewer.this.isPhotoVisible || this.closeAnimationInProgress || ArticleViewer.this.fullscreenVideoContainer.getVisibility() == 0) {
                return false;
            }
            if (event == null || event.getAction() != 0 || this.startedTracking || this.maybeStartTracking) {
                if (event == null || event.getAction() != 2 || event.getPointerId(0) != this.startedTrackingPointerId) {
                    if (event != null && event.getPointerId(0) == this.startedTrackingPointerId && (event.getAction() == 3 || event.getAction() == 1 || event.getAction() == 6)) {
                        if (this.tracker == null) {
                            this.tracker = VelocityTracker.obtain();
                        }
                        this.tracker.computeCurrentVelocity(1000);
                        float velX = this.tracker.getXVelocity();
                        float velY = this.tracker.getYVelocity();
                        if (!this.startedTracking && velX >= 3500.0f && velX > Math.abs(velY)) {
                            prepareForMoving(event);
                        }
                        if (this.startedTracking) {
                            View movingView = this.movingPage ? ArticleViewer.this.listView[0] : ArticleViewer.this.containerView;
                            float x = movingView.getX();
                            final boolean backAnimation = x < ((float) movingView.getMeasuredWidth()) / 3.0f && (velX < 3500.0f || velX < velY);
                            AnimatorSet animatorSet = new AnimatorSet();
                            if (!backAnimation) {
                                distToMove = movingView.getMeasuredWidth() - x;
                                if (this.movingPage) {
                                    animatorSet.playTogether(ObjectAnimator.ofFloat(ArticleViewer.this.listView[0], (Property<RecyclerListView, Float>) View.TRANSLATION_X, movingView.getMeasuredWidth()));
                                } else {
                                    animatorSet.playTogether(ObjectAnimator.ofFloat(ArticleViewer.this.containerView, (Property<FrameLayout, Float>) View.TRANSLATION_X, movingView.getMeasuredWidth()), ObjectAnimator.ofFloat(this, ArticleViewer.ARTICLE_VIEWER_INNER_TRANSLATION_X, movingView.getMeasuredWidth()));
                                }
                            } else {
                                distToMove = x;
                                if (this.movingPage) {
                                    animatorSet.playTogether(ObjectAnimator.ofFloat(ArticleViewer.this.listView[0], (Property<RecyclerListView, Float>) View.TRANSLATION_X, 0.0f));
                                } else {
                                    animatorSet.playTogether(ObjectAnimator.ofFloat(ArticleViewer.this.containerView, (Property<FrameLayout, Float>) View.TRANSLATION_X, 0.0f), ObjectAnimator.ofFloat(this, ArticleViewer.ARTICLE_VIEWER_INNER_TRANSLATION_X, 0.0f));
                                }
                            }
                            animatorSet.setDuration(Math.max((int) ((200.0f / movingView.getMeasuredWidth()) * distToMove), 50));
                            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.WindowView.1
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animator) {
                                    if (WindowView.this.movingPage) {
                                        ArticleViewer.this.listView[0].setBackgroundDrawable(null);
                                        if (!backAnimation) {
                                            WebpageAdapter adapterToUpdate = ArticleViewer.this.adapter[1];
                                            ArticleViewer.this.adapter[1] = ArticleViewer.this.adapter[0];
                                            ArticleViewer.this.adapter[0] = adapterToUpdate;
                                            RecyclerListView listToUpdate = ArticleViewer.this.listView[1];
                                            ArticleViewer.this.listView[1] = ArticleViewer.this.listView[0];
                                            ArticleViewer.this.listView[0] = listToUpdate;
                                            LinearLayoutManager layoutManagerToUpdate = ArticleViewer.this.layoutManager[1];
                                            ArticleViewer.this.layoutManager[1] = ArticleViewer.this.layoutManager[0];
                                            ArticleViewer.this.layoutManager[0] = layoutManagerToUpdate;
                                            ArticleViewer.this.pagesStack.remove(ArticleViewer.this.pagesStack.size() - 1);
                                            ArticleViewer.this.currentPage = (TLRPC.WebPage) ArticleViewer.this.pagesStack.get(ArticleViewer.this.pagesStack.size() - 1);
                                        }
                                        ArticleViewer.this.listView[1].setVisibility(8);
                                        ArticleViewer.this.headerView.invalidate();
                                    } else if (!backAnimation) {
                                        ArticleViewer.this.saveCurrentPagePosition();
                                        ArticleViewer.this.onClosed();
                                    }
                                    WindowView.this.movingPage = false;
                                    WindowView.this.startedTracking = false;
                                    WindowView.this.closeAnimationInProgress = false;
                                }
                            });
                            animatorSet.start();
                            this.closeAnimationInProgress = true;
                        } else {
                            this.maybeStartTracking = false;
                            this.startedTracking = false;
                            this.movingPage = false;
                        }
                        VelocityTracker velocityTracker = this.tracker;
                        if (velocityTracker != null) {
                            velocityTracker.recycle();
                            this.tracker = null;
                        }
                    } else if (event == null) {
                        this.maybeStartTracking = false;
                        this.startedTracking = false;
                        this.movingPage = false;
                        VelocityTracker velocityTracker2 = this.tracker;
                        if (velocityTracker2 != null) {
                            velocityTracker2.recycle();
                            this.tracker = null;
                        }
                    }
                } else {
                    if (this.tracker == null) {
                        this.tracker = VelocityTracker.obtain();
                    }
                    int dx = Math.max(0, (int) (event.getX() - this.startedTrackingX));
                    int dy = Math.abs(((int) event.getY()) - this.startedTrackingY);
                    this.tracker.addMovement(event);
                    if (this.maybeStartTracking && !this.startedTracking && dx >= AndroidUtilities.getPixelsInCM(0.4f, true) && Math.abs(dx) / 3 > dy) {
                        prepareForMoving(event);
                    } else if (this.startedTracking) {
                        ArticleViewer.this.pressedLinkOwnerLayout = null;
                        ArticleViewer.this.pressedLinkOwnerView = null;
                        if (this.movingPage) {
                            ArticleViewer.this.listView[0].setTranslationX(dx);
                        } else {
                            ArticleViewer.this.containerView.setTranslationX(dx);
                            setInnerTranslationX(dx);
                        }
                    }
                }
            } else {
                this.startedTrackingPointerId = event.getPointerId(0);
                this.maybeStartTracking = true;
                this.startedTrackingX = (int) event.getX();
                this.startedTrackingY = (int) event.getY();
                VelocityTracker velocityTracker3 = this.tracker;
                if (velocityTracker3 != null) {
                    velocityTracker3.clear();
                }
            }
            return this.startedTracking;
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void dispatchDraw(Canvas canvas) {
            int i;
            int i2;
            super.dispatchDraw(canvas);
            if (this.bWidth != 0 && (i = this.bHeight) != 0) {
                int i3 = this.bX;
                if (i3 != 0 || (i2 = this.bY) != 0) {
                    canvas.drawRect(this.bX - getTranslationX(), this.bY, (this.bX + this.bWidth) - getTranslationX(), this.bY + this.bHeight, ArticleViewer.this.blackPaint);
                } else {
                    canvas.drawRect(i3, i2, i3 + r0, i2 + i, ArticleViewer.this.blackPaint);
                }
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            canvas.drawRect(this.innerTranslationX, 0.0f, getMeasuredWidth(), getMeasuredHeight(), ArticleViewer.this.backgroundPaint);
            if (Build.VERSION.SDK_INT >= 21 && ArticleViewer.this.hasCutout && ArticleViewer.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) ArticleViewer.this.lastInsets;
                canvas.drawRect(this.innerTranslationX, 0.0f, getMeasuredWidth(), insets.getSystemWindowInsetBottom(), ArticleViewer.this.statusBarPaint);
            }
        }

        @Override // android.view.View
        public void setAlpha(float value) {
            ArticleViewer.this.backgroundPaint.setAlpha((int) (value * 255.0f));
            ArticleViewer.this.statusBarPaint.setAlpha((int) (255.0f * value));
            this.alpha = value;
            if (ArticleViewer.this.parentActivity instanceof LaunchActivity) {
                ((LaunchActivity) ArticleViewer.this.parentActivity).drawerLayoutContainer.setAllowDrawContent((ArticleViewer.this.isVisible && this.alpha == 1.0f && this.innerTranslationX == 0.0f) ? false : true);
            }
            invalidate();
        }

        @Override // android.view.View
        public float getAlpha() {
            return this.alpha;
        }
    }

    class CheckForLongPress implements Runnable {
        public int currentPressCount;

        CheckForLongPress() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (ArticleViewer.this.checkingForLongPress && ArticleViewer.this.windowView != null) {
                ArticleViewer.this.checkingForLongPress = false;
                if (ArticleViewer.this.pressedLink != null) {
                    ArticleViewer.this.windowView.performHapticFeedback(0);
                    ArticleViewer articleViewer = ArticleViewer.this;
                    articleViewer.showCopyPopup(articleViewer.pressedLink.getUrl());
                    ArticleViewer.this.pressedLink = null;
                    ArticleViewer.this.pressedLinkOwnerLayout = null;
                    if (ArticleViewer.this.pressedLinkOwnerView != null) {
                        ArticleViewer.this.pressedLinkOwnerView.invalidate();
                        return;
                    }
                    return;
                }
                if (ArticleViewer.this.pressedLinkOwnerLayout != null && ArticleViewer.this.pressedLinkOwnerView != null) {
                    ArticleViewer.this.windowView.performHapticFeedback(0);
                    int[] location = new int[2];
                    ArticleViewer.this.pressedLinkOwnerView.getLocationInWindow(location);
                    int y = (location[1] + ArticleViewer.this.pressedLayoutY) - AndroidUtilities.dp(54.0f);
                    if (y < 0) {
                        y = 0;
                    }
                    ArticleViewer.this.pressedLinkOwnerView.invalidate();
                    ArticleViewer.this.drawBlockSelection = true;
                    ArticleViewer articleViewer2 = ArticleViewer.this;
                    articleViewer2.showPopup(articleViewer2.pressedLinkOwnerView, 48, 0, y);
                    ArticleViewer.this.listView[0].setLayoutFrozen(true);
                    ArticleViewer.this.listView[0].setLayoutFrozen(false);
                }
            }
        }
    }

    private void createPaint(boolean update) {
        if (quoteLinePaint == null) {
            quoteLinePaint = new Paint();
            preformattedBackgroundPaint = new Paint();
            Paint paint = new Paint(1);
            tableLinePaint = paint;
            paint.setStyle(Paint.Style.STROKE);
            tableLinePaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
            Paint paint2 = new Paint();
            tableHalfLinePaint = paint2;
            paint2.setStyle(Paint.Style.STROKE);
            tableHalfLinePaint.setStrokeWidth(AndroidUtilities.dp(1.0f) / 2.0f);
            tableHeaderPaint = new Paint();
            tableStripPaint = new Paint();
            urlPaint = new Paint();
            webpageUrlPaint = new Paint(1);
            photoBackgroundPaint = new Paint();
            dividerPaint = new Paint();
            webpageMarkPaint = new Paint(1);
        } else if (!update) {
            return;
        }
        int color = getSelectedColor();
        if (color == 0) {
            preformattedBackgroundPaint.setColor(-657156);
            webpageUrlPaint.setColor(-1313798);
            urlPaint.setColor(-2299145);
            tableHalfLinePaint.setColor(-2039584);
            tableLinePaint.setColor(-2039584);
            tableHeaderPaint.setColor(-723724);
            tableStripPaint.setColor(Theme.value_pageBackgroundColor);
            photoBackgroundPaint.setColor(-723724);
            dividerPaint.setColor(-3288619);
            webpageMarkPaint.setColor(-68676);
        } else if (color == 1) {
            preformattedBackgroundPaint.setColor(-1712440);
            webpageUrlPaint.setColor(-2365721);
            urlPaint.setColor(-3481882);
            tableHalfLinePaint.setColor(-3620432);
            tableLinePaint.setColor(-3620432);
            tableHeaderPaint.setColor(-1120560);
            tableStripPaint.setColor(-1120560);
            photoBackgroundPaint.setColor(-1120560);
            dividerPaint.setColor(-4080987);
            webpageMarkPaint.setColor(-1712691);
        } else if (color == 2) {
            preformattedBackgroundPaint.setColor(-15000805);
            webpageUrlPaint.setColor(-14536904);
            urlPaint.setColor(-14469050);
            tableHalfLinePaint.setColor(-13750738);
            tableLinePaint.setColor(-13750738);
            tableHeaderPaint.setColor(-15066598);
            tableStripPaint.setColor(-15066598);
            photoBackgroundPaint.setColor(-14935012);
            dividerPaint.setColor(-12303292);
            webpageMarkPaint.setColor(-14408668);
        }
        quoteLinePaint.setColor(getTextColor());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showCopyPopup(final String urlFinal) {
        if (this.parentActivity == null) {
            return;
        }
        BottomSheet bottomSheet = this.linkSheet;
        if (bottomSheet != null) {
            bottomSheet.dismiss();
            this.linkSheet = null;
        }
        BottomSheet.Builder builder = new BottomSheet.Builder(this.parentActivity);
        builder.setUseFullscreen(true);
        builder.setTitle(urlFinal);
        builder.setItems(new CharSequence[]{LocaleController.getString("Open", R.string.Open), LocaleController.getString("Copy", R.string.Copy)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$JR9WHnYe3-abHtOTHo7GZ_4SlYk
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showCopyPopup$0$ArticleViewer(urlFinal, dialogInterface, i);
            }
        });
        BottomSheet sheet = builder.create();
        showDialog(sheet);
        for (int a = 0; a < 2; a++) {
            sheet.setItemColor(a, getTextColor(), getTextColor());
        }
        int a2 = getGrayTextColor();
        sheet.setTitleColor(a2);
        int i = this.selectedColor;
        if (i == 0) {
            sheet.setBackgroundColor(-1);
        } else if (i == 1) {
            sheet.setBackgroundColor(-659492);
        } else if (i == 2) {
            sheet.setBackgroundColor(-15461356);
        }
    }

    public /* synthetic */ void lambda$showCopyPopup$0$ArticleViewer(String urlFinal, DialogInterface dialog, int which) {
        String webPageUrl;
        String anchor;
        if (this.parentActivity == null) {
            return;
        }
        if (which == 0) {
            int index = urlFinal.lastIndexOf(35);
            if (index != -1) {
                if (!TextUtils.isEmpty(this.currentPage.cached_page.url)) {
                    webPageUrl = this.currentPage.cached_page.url.toLowerCase();
                } else {
                    webPageUrl = this.currentPage.url.toLowerCase();
                }
                try {
                    anchor = URLDecoder.decode(urlFinal.substring(index + 1), "UTF-8");
                } catch (Exception e) {
                    anchor = "";
                }
                if (urlFinal.toLowerCase().contains(webPageUrl)) {
                    if (TextUtils.isEmpty(anchor)) {
                        this.layoutManager[0].scrollToPositionWithOffset(0, 0);
                        checkScrollAnimated();
                        return;
                    } else {
                        scrollToAnchor(anchor);
                        return;
                    }
                }
            }
            Browser.openUrl(this.parentActivity, urlFinal);
            return;
        }
        if (which == 1) {
            String url = urlFinal;
            if (url.startsWith(MailTo.MAILTO_SCHEME)) {
                url = url.substring(7);
            } else if (url.startsWith("tel:")) {
                url = url.substring(4);
            }
            AndroidUtilities.addToClipboard(url);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showPopup(View parent, int gravity, int x, int y) {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
            return;
        }
        if (this.popupLayout == null) {
            this.popupRect = new Rect();
            ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = new ActionBarPopupWindow.ActionBarPopupWindowLayout(this.parentActivity);
            this.popupLayout = actionBarPopupWindowLayout;
            actionBarPopupWindowLayout.setPadding(AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f));
            ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout2 = this.popupLayout;
            Drawable drawable = this.parentActivity.getResources().getDrawable(R.drawable.menu_copy);
            this.copyBackgroundDrawable = drawable;
            actionBarPopupWindowLayout2.setBackgroundDrawable(drawable);
            this.popupLayout.setAnimationEnabled(false);
            this.popupLayout.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$wME58MTJew2QQbpZ_EcHs5WcyhY
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    return this.f$0.lambda$showPopup$1$ArticleViewer(view, motionEvent);
                }
            });
            this.popupLayout.setDispatchKeyEventListener(new ActionBarPopupWindow.OnDispatchKeyEventListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$O5p7_9n2t9b1uYg3jYSbGdryiN0
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.OnDispatchKeyEventListener
                public final void onDispatchKeyEvent(KeyEvent keyEvent) {
                    this.f$0.lambda$showPopup$2$ArticleViewer(keyEvent);
                }
            });
            this.popupLayout.setShowedFromBotton(false);
            TextView textView = new TextView(this.parentActivity);
            this.deleteView = textView;
            textView.setBackgroundDrawable(Theme.createSelectorDrawable(251658240, 2));
            this.deleteView.setGravity(16);
            this.deleteView.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
            this.deleteView.setTextSize(1, 15.0f);
            this.deleteView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.deleteView.setText(LocaleController.getString("Copy", R.string.Copy).toUpperCase());
            this.deleteView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$MkTI-xCXC11IgToUiX-N86uvkJA
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$showPopup$3$ArticleViewer(view);
                }
            });
            this.popupLayout.addView(this.deleteView, LayoutHelper.createFrame(-2, 48.0f));
            ActionBarPopupWindow actionBarPopupWindow2 = new ActionBarPopupWindow(this.popupLayout, -2, -2);
            this.popupWindow = actionBarPopupWindow2;
            actionBarPopupWindow2.setAnimationEnabled(false);
            this.popupWindow.setAnimationStyle(R.plurals.PopupContextAnimation);
            this.popupWindow.setOutsideTouchable(true);
            this.popupWindow.setClippingEnabled(true);
            this.popupWindow.setInputMethodMode(2);
            this.popupWindow.setSoftInputMode(0);
            this.popupWindow.getContentView().setFocusableInTouchMode(true);
            this.popupWindow.setOnDismissListener(new PopupWindow.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$Kuym_ns85nhV572PQ_sCv0sq-7M
                @Override // android.widget.PopupWindow.OnDismissListener
                public final void onDismiss() {
                    this.f$0.lambda$showPopup$4$ArticleViewer();
                }
            });
        }
        if (this.selectedColor == 2) {
            this.deleteView.setTextColor(-5723992);
            Drawable drawable2 = this.copyBackgroundDrawable;
            if (drawable2 != null) {
                drawable2.setColorFilter(new PorterDuffColorFilter(-14408668, PorterDuff.Mode.MULTIPLY));
            }
        } else {
            this.deleteView.setTextColor(-14606047);
            Drawable drawable3 = this.copyBackgroundDrawable;
            if (drawable3 != null) {
                drawable3.setColorFilter(new PorterDuffColorFilter(-1, PorterDuff.Mode.MULTIPLY));
            }
        }
        this.popupLayout.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE));
        this.popupWindow.setFocusable(true);
        this.popupWindow.showAtLocation(parent, gravity, x, y);
        this.popupWindow.startAnimation();
    }

    public /* synthetic */ boolean lambda$showPopup$1$ArticleViewer(View v, MotionEvent event) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (event.getActionMasked() == 0 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            v.getHitRect(this.popupRect);
            if (!this.popupRect.contains((int) event.getX(), (int) event.getY())) {
                this.popupWindow.dismiss();
                return false;
            }
            return false;
        }
        return false;
    }

    public /* synthetic */ void lambda$showPopup$2$ArticleViewer(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
        }
    }

    public /* synthetic */ void lambda$showPopup$3$ArticleViewer(View v) {
        DrawingText drawingText = this.pressedLinkOwnerLayout;
        if (drawingText != null) {
            AndroidUtilities.addToClipboard(drawingText.getText());
            ToastUtils.show(R.string.TextCopied);
        }
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss(true);
        }
    }

    public /* synthetic */ void lambda$showPopup$4$ArticleViewer() {
        View view = this.pressedLinkOwnerView;
        if (view != null) {
            this.pressedLinkOwnerLayout = null;
            view.invalidate();
            this.pressedLinkOwnerView = null;
        }
    }

    private TLRPC.RichText getBlockCaption(TLRPC.PageBlock block, int type) {
        if (type == 2) {
            TLRPC.RichText text1 = getBlockCaption(block, 0);
            if (text1 instanceof TLRPC.TL_textEmpty) {
                text1 = null;
            }
            TLRPC.RichText text2 = getBlockCaption(block, 1);
            if (text2 instanceof TLRPC.TL_textEmpty) {
                text2 = null;
            }
            if (text1 != null && text2 == null) {
                return text1;
            }
            if (text1 == null && text2 != null) {
                return text2;
            }
            if (text1 == null || text2 == null) {
                return null;
            }
            TLRPC.TL_textPlain text3 = new TLRPC.TL_textPlain();
            text3.text = " ";
            TLRPC.TL_textConcat textConcat = new TLRPC.TL_textConcat();
            textConcat.texts.add(text1);
            textConcat.texts.add(text3);
            textConcat.texts.add(text2);
            return textConcat;
        }
        if (block instanceof TLRPC.TL_pageBlockEmbedPost) {
            TLRPC.TL_pageBlockEmbedPost blockEmbedPost = (TLRPC.TL_pageBlockEmbedPost) block;
            if (type == 0) {
                return blockEmbedPost.caption.text;
            }
            if (type == 1) {
                return blockEmbedPost.caption.credit;
            }
        } else if (block instanceof TLRPC.TL_pageBlockSlideshow) {
            TLRPC.TL_pageBlockSlideshow pageBlockSlideshow = (TLRPC.TL_pageBlockSlideshow) block;
            if (type == 0) {
                return pageBlockSlideshow.caption.text;
            }
            if (type == 1) {
                return pageBlockSlideshow.caption.credit;
            }
        } else if (block instanceof TLRPC.TL_pageBlockPhoto) {
            TLRPC.TL_pageBlockPhoto pageBlockPhoto = (TLRPC.TL_pageBlockPhoto) block;
            if (type == 0) {
                return pageBlockPhoto.caption.text;
            }
            if (type == 1) {
                return pageBlockPhoto.caption.credit;
            }
        } else if (block instanceof TLRPC.TL_pageBlockCollage) {
            TLRPC.TL_pageBlockCollage pageBlockCollage = (TLRPC.TL_pageBlockCollage) block;
            if (type == 0) {
                return pageBlockCollage.caption.text;
            }
            if (type == 1) {
                return pageBlockCollage.caption.credit;
            }
        } else if (block instanceof TLRPC.TL_pageBlockEmbed) {
            TLRPC.TL_pageBlockEmbed pageBlockEmbed = (TLRPC.TL_pageBlockEmbed) block;
            if (type == 0) {
                return pageBlockEmbed.caption.text;
            }
            if (type == 1) {
                return pageBlockEmbed.caption.credit;
            }
        } else {
            if (block instanceof TLRPC.TL_pageBlockBlockquote) {
                TLRPC.TL_pageBlockBlockquote pageBlockBlockquote = (TLRPC.TL_pageBlockBlockquote) block;
                return pageBlockBlockquote.caption;
            }
            if (block instanceof TLRPC.TL_pageBlockVideo) {
                TLRPC.TL_pageBlockVideo pageBlockVideo = (TLRPC.TL_pageBlockVideo) block;
                if (type == 0) {
                    return pageBlockVideo.caption.text;
                }
                if (type == 1) {
                    return pageBlockVideo.caption.credit;
                }
            } else {
                if (block instanceof TLRPC.TL_pageBlockPullquote) {
                    TLRPC.TL_pageBlockPullquote pageBlockPullquote = (TLRPC.TL_pageBlockPullquote) block;
                    return pageBlockPullquote.caption;
                }
                if (block instanceof TLRPC.TL_pageBlockAudio) {
                    TLRPC.TL_pageBlockAudio pageBlockAudio = (TLRPC.TL_pageBlockAudio) block;
                    if (type == 0) {
                        return pageBlockAudio.caption.text;
                    }
                    if (type == 1) {
                        return pageBlockAudio.caption.credit;
                    }
                } else {
                    if (block instanceof TLRPC.TL_pageBlockCover) {
                        TLRPC.TL_pageBlockCover pageBlockCover = (TLRPC.TL_pageBlockCover) block;
                        return getBlockCaption(pageBlockCover.cover, type);
                    }
                    if (block instanceof TLRPC.TL_pageBlockMap) {
                        TLRPC.TL_pageBlockMap pageBlockMap = (TLRPC.TL_pageBlockMap) block;
                        if (type == 0) {
                            return pageBlockMap.caption.text;
                        }
                        if (type == 1) {
                            return pageBlockMap.caption.credit;
                        }
                    }
                }
            }
        }
        return null;
    }

    private View getLastNonListCell(View view) {
        if (view instanceof BlockListItemCell) {
            BlockListItemCell cell = (BlockListItemCell) view;
            if (cell.blockLayout != null) {
                return getLastNonListCell(cell.blockLayout.itemView);
            }
        } else if (view instanceof BlockOrderedListItemCell) {
            BlockOrderedListItemCell cell2 = (BlockOrderedListItemCell) view;
            if (cell2.blockLayout != null) {
                return getLastNonListCell(cell2.blockLayout.itemView);
            }
        }
        return view;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isListItemBlock(TLRPC.PageBlock block) {
        return (block instanceof TL_pageBlockListItem) || (block instanceof TL_pageBlockOrderedListItem);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.PageBlock getLastNonListPageBlock(TLRPC.PageBlock block) {
        if (block instanceof TL_pageBlockListItem) {
            TL_pageBlockListItem blockListItem = (TL_pageBlockListItem) block;
            return blockListItem.blockItem != null ? getLastNonListPageBlock(blockListItem.blockItem) : blockListItem.blockItem;
        }
        if (block instanceof TL_pageBlockOrderedListItem) {
            TL_pageBlockOrderedListItem blockListItem2 = (TL_pageBlockOrderedListItem) block;
            return blockListItem2.blockItem != null ? getLastNonListPageBlock(blockListItem2.blockItem) : blockListItem2.blockItem;
        }
        return block;
    }

    private boolean openAllParentBlocks(TL_pageBlockDetailsChild child) {
        TLRPC.PageBlock parentBlock = getLastNonListPageBlock(child.parent);
        if (parentBlock instanceof TLRPC.TL_pageBlockDetails) {
            TLRPC.TL_pageBlockDetails blockDetails = (TLRPC.TL_pageBlockDetails) parentBlock;
            if (blockDetails.open) {
                return false;
            }
            blockDetails.open = true;
            return true;
        }
        if (!(parentBlock instanceof TL_pageBlockDetailsChild)) {
            return false;
        }
        TL_pageBlockDetailsChild parent = (TL_pageBlockDetailsChild) parentBlock;
        TLRPC.PageBlock parentBlock2 = getLastNonListPageBlock(parent.block);
        boolean opened = false;
        if (parentBlock2 instanceof TLRPC.TL_pageBlockDetails) {
            TLRPC.TL_pageBlockDetails blockDetails2 = (TLRPC.TL_pageBlockDetails) parentBlock2;
            if (!blockDetails2.open) {
                blockDetails2.open = true;
                opened = true;
            }
        }
        return openAllParentBlocks(parent) || opened;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.PageBlock fixListBlock(TLRPC.PageBlock parentBlock, TLRPC.PageBlock childBlock) {
        if (parentBlock instanceof TL_pageBlockListItem) {
            TL_pageBlockListItem blockListItem = (TL_pageBlockListItem) parentBlock;
            blockListItem.blockItem = childBlock;
            return parentBlock;
        }
        if (parentBlock instanceof TL_pageBlockOrderedListItem) {
            TL_pageBlockOrderedListItem blockListItem2 = (TL_pageBlockOrderedListItem) parentBlock;
            blockListItem2.blockItem = childBlock;
            return parentBlock;
        }
        return childBlock;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.PageBlock wrapInTableBlock(TLRPC.PageBlock parentBlock, TLRPC.PageBlock childBlock) {
        if (parentBlock instanceof TL_pageBlockListItem) {
            TL_pageBlockListItem parent = (TL_pageBlockListItem) parentBlock;
            TL_pageBlockListItem item = new TL_pageBlockListItem();
            item.parent = parent.parent;
            item.blockItem = wrapInTableBlock(parent.blockItem, childBlock);
            return item;
        }
        if (parentBlock instanceof TL_pageBlockOrderedListItem) {
            TL_pageBlockOrderedListItem parent2 = (TL_pageBlockOrderedListItem) parentBlock;
            TL_pageBlockOrderedListItem item2 = new TL_pageBlockOrderedListItem();
            item2.parent = parent2.parent;
            item2.blockItem = wrapInTableBlock(parent2.blockItem, childBlock);
            return item2;
        }
        return childBlock;
    }

    private void updateInterfaceForCurrentPage(int order) {
        int offset;
        TLRPC.WebPage webPage = this.currentPage;
        if (webPage != null && webPage.cached_page != null) {
            this.isRtl = this.currentPage.cached_page.rtl;
            this.channelBlock = null;
            this.titleTextView.setText(this.currentPage.site_name == null ? "" : this.currentPage.site_name);
            if (order != 0) {
                WebpageAdapter[] webpageAdapterArr = this.adapter;
                WebpageAdapter adapterToUpdate = webpageAdapterArr[1];
                webpageAdapterArr[1] = webpageAdapterArr[0];
                webpageAdapterArr[0] = adapterToUpdate;
                RecyclerListView[] recyclerListViewArr = this.listView;
                RecyclerListView listToUpdate = recyclerListViewArr[1];
                recyclerListViewArr[1] = recyclerListViewArr[0];
                recyclerListViewArr[0] = listToUpdate;
                LinearLayoutManager[] linearLayoutManagerArr = this.layoutManager;
                LinearLayoutManager layoutManagerToUpdate = linearLayoutManagerArr[1];
                linearLayoutManagerArr[1] = linearLayoutManagerArr[0];
                linearLayoutManagerArr[0] = layoutManagerToUpdate;
                int index1 = this.containerView.indexOfChild(recyclerListViewArr[0]);
                int index2 = this.containerView.indexOfChild(this.listView[1]);
                if (order == 1) {
                    if (index1 < index2) {
                        this.containerView.removeView(this.listView[0]);
                        this.containerView.addView(this.listView[0], index2);
                    }
                } else if (index2 < index1) {
                    this.containerView.removeView(this.listView[0]);
                    this.containerView.addView(this.listView[0], index1);
                }
                this.pageSwitchAnimation = new AnimatorSet();
                this.listView[0].setVisibility(0);
                final int index = order == 1 ? 0 : 1;
                this.listView[index].setBackgroundColor(this.backgroundPaint.getColor());
                if (Build.VERSION.SDK_INT >= 18) {
                    this.listView[index].setLayerType(2, null);
                }
                if (order == 1) {
                    this.pageSwitchAnimation.playTogether(ObjectAnimator.ofFloat(this.listView[0], (Property<RecyclerListView, Float>) View.TRANSLATION_X, AndroidUtilities.dp(56.0f), 0.0f), ObjectAnimator.ofFloat(this.listView[0], (Property<RecyclerListView, Float>) View.ALPHA, 0.0f, 1.0f));
                } else if (order == -1) {
                    this.listView[0].setAlpha(1.0f);
                    this.listView[0].setTranslationX(0.0f);
                    this.pageSwitchAnimation.playTogether(ObjectAnimator.ofFloat(this.listView[1], (Property<RecyclerListView, Float>) View.TRANSLATION_X, 0.0f, AndroidUtilities.dp(56.0f)), ObjectAnimator.ofFloat(this.listView[1], (Property<RecyclerListView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.pageSwitchAnimation.setDuration(150L);
                this.pageSwitchAnimation.setInterpolator(this.interpolator);
                this.pageSwitchAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.2
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ArticleViewer.this.listView[1].setVisibility(8);
                        ArticleViewer.this.listView[index].setBackgroundDrawable(null);
                        if (Build.VERSION.SDK_INT >= 18) {
                            ArticleViewer.this.listView[index].setLayerType(0, null);
                        }
                        ArticleViewer.this.pageSwitchAnimation = null;
                    }
                });
                this.pageSwitchAnimation.start();
            }
            this.headerView.invalidate();
            this.adapter[0].cleanup();
            int count = this.currentPage.cached_page.blocks.size();
            int a = 0;
            while (a < count) {
                TLRPC.PageBlock block = this.currentPage.cached_page.blocks.get(a);
                if (a == 0) {
                    block.first = true;
                    if (block instanceof TLRPC.TL_pageBlockCover) {
                        TLRPC.TL_pageBlockCover pageBlockCover = (TLRPC.TL_pageBlockCover) block;
                        TLRPC.RichText caption = getBlockCaption(pageBlockCover, 0);
                        TLRPC.RichText credit = getBlockCaption(pageBlockCover, 1);
                        if (((caption != null && !(caption instanceof TLRPC.TL_textEmpty)) || (credit != null && !(credit instanceof TLRPC.TL_textEmpty))) && count > 1) {
                            TLRPC.PageBlock next = this.currentPage.cached_page.blocks.get(1);
                            if (next instanceof TLRPC.TL_pageBlockChannel) {
                                this.channelBlock = (TLRPC.TL_pageBlockChannel) next;
                            }
                        }
                    }
                } else {
                    if (a != 1 || this.channelBlock == null) {
                    }
                    a++;
                }
                this.adapter[0].addBlock(block, 0, 0, a == count + (-1) ? a : 0);
                a++;
            }
            this.adapter[0].notifyDataSetChanged();
            if (this.pagesStack.size() == 1 || order == -1) {
                SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("articles", 0);
                String key = "article" + this.currentPage.id;
                int position = preferences.getInt(key, -1);
                if (preferences.getBoolean(key + "r", true) == (AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y)) {
                    offset = preferences.getInt(key + "o", 0) - this.listView[0].getPaddingTop();
                } else {
                    offset = AndroidUtilities.dp(10.0f);
                }
                if (position != -1) {
                    this.layoutManager[0].scrollToPositionWithOffset(position, offset);
                }
            } else {
                this.layoutManager[0].scrollToPositionWithOffset(0, 0);
            }
            checkScrollAnimated();
        }
    }

    private boolean addPageToStack(TLRPC.WebPage webPage, String anchor, int order) {
        saveCurrentPagePosition();
        this.currentPage = webPage;
        this.pagesStack.add(webPage);
        updateInterfaceForCurrentPage(order);
        return scrollToAnchor(anchor);
    }

    private boolean scrollToAnchor(String anchor) {
        if (TextUtils.isEmpty(anchor)) {
            return false;
        }
        String anchor2 = anchor.toLowerCase();
        Integer row = (Integer) this.adapter[0].anchors.get(anchor2);
        if (row == null) {
            return false;
        }
        TLRPC.TL_textAnchor textAnchor = (TLRPC.TL_textAnchor) this.adapter[0].anchorsParent.get(anchor2);
        if (textAnchor != null) {
            TLRPC.TL_pageBlockParagraph paragraph = new TLRPC.TL_pageBlockParagraph();
            paragraph.text = textAnchor.text;
            int type = this.adapter[0].getTypeForBlock(paragraph);
            RecyclerView.ViewHolder holder = this.adapter[0].onCreateViewHolder(null, type);
            this.adapter[0].bindBlockToHolder(type, holder, paragraph, 0, 0);
            BottomSheet.Builder builder = new BottomSheet.Builder(this.parentActivity);
            builder.setUseFullscreen(true);
            builder.setApplyTopPadding(false);
            LinearLayout linearLayout = new LinearLayout(this.parentActivity);
            linearLayout.setOrientation(1);
            TextView textView = new TextView(this.parentActivity) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.3
                @Override // android.widget.TextView, android.view.View
                protected void onDraw(Canvas canvas) {
                    canvas.drawLine(0.0f, getMeasuredHeight() - 1, getMeasuredWidth(), getMeasuredHeight() - 1, ArticleViewer.dividerPaint);
                    super.onDraw(canvas);
                }
            };
            textView.setTextSize(1, 16.0f);
            textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            textView.setText(LocaleController.getString("InstantViewReference", R.string.InstantViewReference));
            textView.setGravity((this.isRtl ? 5 : 3) | 16);
            textView.setTextColor(getTextColor());
            textView.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
            linearLayout.addView(textView, new LinearLayout.LayoutParams(-1, AndroidUtilities.dp(48.0f) + 1));
            linearLayout.addView(holder.itemView, LayoutHelper.createLinear(-1, -2, 0.0f, 7.0f, 0.0f, 0.0f));
            builder.setCustomView(linearLayout);
            BottomSheet bottomSheetCreate = builder.create();
            this.linkSheet = bottomSheetCreate;
            int i = this.selectedColor;
            if (i == 0) {
                bottomSheetCreate.setBackgroundColor(-1);
            } else if (i == 1) {
                bottomSheetCreate.setBackgroundColor(-659492);
            } else if (i == 2) {
                bottomSheetCreate.setBackgroundColor(-15461356);
            }
            showDialog(this.linkSheet);
            return true;
        }
        if (row.intValue() < 0 || row.intValue() >= this.adapter[0].blocks.size()) {
            return false;
        }
        TLRPC.PageBlock originalBlock = (TLRPC.PageBlock) this.adapter[0].blocks.get(row.intValue());
        TLRPC.PageBlock block = getLastNonListPageBlock(originalBlock);
        if ((block instanceof TL_pageBlockDetailsChild) && openAllParentBlocks((TL_pageBlockDetailsChild) block)) {
            this.adapter[0].updateRows();
            this.adapter[0].notifyDataSetChanged();
        }
        int position = this.adapter[0].localBlocks.indexOf(originalBlock);
        if (position != -1) {
            row = Integer.valueOf(position);
        }
        Integer offset = (Integer) this.adapter[0].anchorsOffset.get(anchor2);
        if (offset == null) {
            offset = 0;
        } else if (offset.intValue() == -1) {
            int type2 = this.adapter[0].getTypeForBlock(originalBlock);
            RecyclerView.ViewHolder holder2 = this.adapter[0].onCreateViewHolder(null, type2);
            this.adapter[0].bindBlockToHolder(type2, holder2, originalBlock, 0, 0);
            holder2.itemView.measure(View.MeasureSpec.makeMeasureSpec(this.listView[0].getMeasuredWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(0, 0));
            Integer offset2 = (Integer) this.adapter[0].anchorsOffset.get(anchor2);
            if (offset2.intValue() != -1) {
                offset = offset2;
            } else {
                offset = 0;
            }
        }
        this.layoutManager[0].scrollToPositionWithOffset(row.intValue(), (this.currentHeaderHeight - AndroidUtilities.dp(56.0f)) - offset.intValue());
        return true;
    }

    private boolean removeLastPageFromStack() {
        if (this.pagesStack.size() < 2) {
            return false;
        }
        ArrayList<TLRPC.WebPage> arrayList = this.pagesStack;
        arrayList.remove(arrayList.size() - 1);
        ArrayList<TLRPC.WebPage> arrayList2 = this.pagesStack;
        this.currentPage = arrayList2.get(arrayList2.size() - 1);
        updateInterfaceForCurrentPage(-1);
        return true;
    }

    protected void startCheckLongPress() {
        if (this.checkingForLongPress) {
            return;
        }
        this.checkingForLongPress = true;
        if (this.pendingCheckForTap == null) {
            this.pendingCheckForTap = new CheckForTap();
        }
        this.windowView.postDelayed(this.pendingCheckForTap, ViewConfiguration.getTapTimeout());
    }

    protected void cancelCheckLongPress() {
        this.checkingForLongPress = false;
        CheckForLongPress checkForLongPress = this.pendingCheckForLongPress;
        if (checkForLongPress != null) {
            this.windowView.removeCallbacks(checkForLongPress);
            this.pendingCheckForLongPress = null;
        }
        CheckForTap checkForTap = this.pendingCheckForTap;
        if (checkForTap != null) {
            this.windowView.removeCallbacks(checkForTap);
            this.pendingCheckForTap = null;
        }
    }

    private int getTextFlags(TLRPC.RichText richText) {
        if (richText instanceof TLRPC.TL_textFixed) {
            return getTextFlags(richText.parentRichText) | 4;
        }
        if (richText instanceof TLRPC.TL_textItalic) {
            return getTextFlags(richText.parentRichText) | 2;
        }
        if (richText instanceof TLRPC.TL_textBold) {
            return getTextFlags(richText.parentRichText) | 1;
        }
        if (richText instanceof TLRPC.TL_textUnderline) {
            return getTextFlags(richText.parentRichText) | 16;
        }
        if (richText instanceof TLRPC.TL_textStrike) {
            return getTextFlags(richText.parentRichText) | 32;
        }
        if (richText instanceof TLRPC.TL_textEmail) {
            return getTextFlags(richText.parentRichText) | 8;
        }
        if (richText instanceof TLRPC.TL_textPhone) {
            return getTextFlags(richText.parentRichText) | 8;
        }
        if (richText instanceof TLRPC.TL_textUrl) {
            TLRPC.TL_textUrl textUrl = (TLRPC.TL_textUrl) richText;
            if (textUrl.webpage_id != 0) {
                return getTextFlags(richText.parentRichText) | 512;
            }
            return getTextFlags(richText.parentRichText) | 8;
        }
        if (richText instanceof TLRPC.TL_textSubscript) {
            return getTextFlags(richText.parentRichText) | 128;
        }
        if (richText instanceof TLRPC.TL_textSuperscript) {
            return getTextFlags(richText.parentRichText) | 256;
        }
        if (richText instanceof TLRPC.TL_textMarked) {
            return getTextFlags(richText.parentRichText) | 64;
        }
        if (richText != null) {
            return getTextFlags(richText.parentRichText);
        }
        return 0;
    }

    private TLRPC.RichText getLastRichText(TLRPC.RichText richText) {
        if (richText == null) {
            return null;
        }
        if (richText instanceof TLRPC.TL_textFixed) {
            return getLastRichText(((TLRPC.TL_textFixed) richText).text);
        }
        if (richText instanceof TLRPC.TL_textItalic) {
            return getLastRichText(((TLRPC.TL_textItalic) richText).text);
        }
        if (richText instanceof TLRPC.TL_textBold) {
            return getLastRichText(((TLRPC.TL_textBold) richText).text);
        }
        if (richText instanceof TLRPC.TL_textUnderline) {
            return getLastRichText(((TLRPC.TL_textUnderline) richText).text);
        }
        if (richText instanceof TLRPC.TL_textStrike) {
            return getLastRichText(((TLRPC.TL_textStrike) richText).text);
        }
        if (richText instanceof TLRPC.TL_textEmail) {
            return getLastRichText(((TLRPC.TL_textEmail) richText).text);
        }
        if (richText instanceof TLRPC.TL_textUrl) {
            return getLastRichText(((TLRPC.TL_textUrl) richText).text);
        }
        if (richText instanceof TLRPC.TL_textAnchor) {
            getLastRichText(((TLRPC.TL_textAnchor) richText).text);
        } else {
            if (richText instanceof TLRPC.TL_textSubscript) {
                return getLastRichText(((TLRPC.TL_textSubscript) richText).text);
            }
            if (richText instanceof TLRPC.TL_textSuperscript) {
                return getLastRichText(((TLRPC.TL_textSuperscript) richText).text);
            }
            if (richText instanceof TLRPC.TL_textMarked) {
                return getLastRichText(((TLRPC.TL_textMarked) richText).text);
            }
            if (richText instanceof TLRPC.TL_textPhone) {
                return getLastRichText(((TLRPC.TL_textPhone) richText).text);
            }
        }
        return richText;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public CharSequence getText(View parentView, TLRPC.RichText parentRichText, TLRPC.RichText richText, TLRPC.PageBlock parentBlock, int maxWidth) {
        MetricAffectingSpan span;
        MetricAffectingSpan span2;
        if (richText == null) {
            return null;
        }
        if (richText instanceof TLRPC.TL_textFixed) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textFixed) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textItalic) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textItalic) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textBold) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textBold) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textUnderline) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textUnderline) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textStrike) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textStrike) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textEmail) {
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(getText(parentView, parentRichText, ((TLRPC.TL_textEmail) richText).text, parentBlock, maxWidth));
            MetricAffectingSpan[] innerSpans = (MetricAffectingSpan[]) spannableStringBuilder.getSpans(0, spannableStringBuilder.length(), MetricAffectingSpan.class);
            if (spannableStringBuilder.length() != 0) {
                spannableStringBuilder.setSpan(new TextPaintUrlSpan((innerSpans == null || innerSpans.length == 0) ? getTextPaint(parentRichText, richText, parentBlock) : null, MailTo.MAILTO_SCHEME + getUrl(richText)), 0, spannableStringBuilder.length(), 33);
            }
            return spannableStringBuilder;
        }
        long j = 0;
        if (richText instanceof TLRPC.TL_textUrl) {
            TLRPC.TL_textUrl textUrl = (TLRPC.TL_textUrl) richText;
            SpannableStringBuilder spannableStringBuilder2 = new SpannableStringBuilder(getText(parentView, parentRichText, ((TLRPC.TL_textUrl) richText).text, parentBlock, maxWidth));
            MetricAffectingSpan[] innerSpans2 = (MetricAffectingSpan[]) spannableStringBuilder2.getSpans(0, spannableStringBuilder2.length(), MetricAffectingSpan.class);
            TextPaint paint = (innerSpans2 == null || innerSpans2.length == 0) ? getTextPaint(parentRichText, richText, parentBlock) : null;
            if (textUrl.webpage_id != 0) {
                span2 = new TextPaintWebpageUrlSpan(paint, getUrl(richText));
            } else {
                span2 = new TextPaintUrlSpan(paint, getUrl(richText));
            }
            if (spannableStringBuilder2.length() != 0) {
                spannableStringBuilder2.setSpan(span2, 0, spannableStringBuilder2.length(), 33);
            }
            return spannableStringBuilder2;
        }
        if (richText instanceof TLRPC.TL_textPlain) {
            return ((TLRPC.TL_textPlain) richText).text;
        }
        if (richText instanceof TLRPC.TL_textAnchor) {
            TLRPC.TL_textAnchor textAnchor = (TLRPC.TL_textAnchor) richText;
            SpannableStringBuilder spannableStringBuilder3 = new SpannableStringBuilder(getText(parentView, parentRichText, textAnchor.text, parentBlock, maxWidth));
            spannableStringBuilder3.setSpan(new AnchorSpan(textAnchor.name), 0, spannableStringBuilder3.length(), 17);
            return spannableStringBuilder3;
        }
        if (richText instanceof TLRPC.TL_textEmpty) {
            return "";
        }
        int i = 1;
        if (richText instanceof TLRPC.TL_textConcat) {
            SpannableStringBuilder spannableStringBuilder4 = new SpannableStringBuilder();
            int count = richText.texts.size();
            int a = 0;
            while (a < count) {
                TLRPC.RichText innerRichText = richText.texts.get(a);
                TLRPC.RichText lastRichText = getLastRichText(innerRichText);
                boolean extraSpace = maxWidth >= 0 && (innerRichText instanceof TLRPC.TL_textUrl) && ((TLRPC.TL_textUrl) innerRichText).webpage_id != j;
                if (extraSpace && spannableStringBuilder4.length() != 0 && spannableStringBuilder4.charAt(spannableStringBuilder4.length() - i) != '\n') {
                    spannableStringBuilder4.append((CharSequence) " ");
                }
                int a2 = a;
                int count2 = count;
                CharSequence innerText = getText(parentView, parentRichText, innerRichText, parentBlock, maxWidth);
                int flags = getTextFlags(lastRichText);
                int startLength = spannableStringBuilder4.length();
                spannableStringBuilder4.append(innerText);
                if (flags != 0 && !(innerText instanceof SpannableStringBuilder)) {
                    if ((flags & 8) != 0 || (flags & 512) != 0) {
                        String url = getUrl(innerRichText);
                        if (url == null) {
                            url = getUrl(parentRichText);
                        }
                        if ((flags & 512) != 0) {
                            span = new TextPaintWebpageUrlSpan(getTextPaint(parentRichText, lastRichText, parentBlock), url);
                        } else {
                            span = new TextPaintUrlSpan(getTextPaint(parentRichText, lastRichText, parentBlock), url);
                        }
                        if (startLength != spannableStringBuilder4.length()) {
                            spannableStringBuilder4.setSpan(span, startLength, spannableStringBuilder4.length(), 33);
                        }
                    } else if (startLength != spannableStringBuilder4.length()) {
                        spannableStringBuilder4.setSpan(new TextPaintSpan(getTextPaint(parentRichText, lastRichText, parentBlock)), startLength, spannableStringBuilder4.length(), 33);
                    }
                }
                if (extraSpace && a2 != count2 - 1) {
                    spannableStringBuilder4.append((CharSequence) " ");
                }
                a = a2 + 1;
                count = count2;
                i = 1;
                j = 0;
            }
            return spannableStringBuilder4;
        }
        if (richText instanceof TLRPC.TL_textSubscript) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textSubscript) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textSuperscript) {
            return getText(parentView, parentRichText, ((TLRPC.TL_textSuperscript) richText).text, parentBlock, maxWidth);
        }
        if (richText instanceof TLRPC.TL_textMarked) {
            SpannableStringBuilder spannableStringBuilder5 = new SpannableStringBuilder(getText(parentView, parentRichText, ((TLRPC.TL_textMarked) richText).text, parentBlock, maxWidth));
            MetricAffectingSpan[] innerSpans3 = (MetricAffectingSpan[]) spannableStringBuilder5.getSpans(0, spannableStringBuilder5.length(), MetricAffectingSpan.class);
            if (spannableStringBuilder5.length() != 0) {
                spannableStringBuilder5.setSpan(new TextPaintMarkSpan((innerSpans3 == null || innerSpans3.length == 0) ? getTextPaint(parentRichText, richText, parentBlock) : null), 0, spannableStringBuilder5.length(), 33);
            }
            return spannableStringBuilder5;
        }
        if (richText instanceof TLRPC.TL_textPhone) {
            SpannableStringBuilder spannableStringBuilder6 = new SpannableStringBuilder(getText(parentView, parentRichText, ((TLRPC.TL_textPhone) richText).text, parentBlock, maxWidth));
            MetricAffectingSpan[] innerSpans4 = (MetricAffectingSpan[]) spannableStringBuilder6.getSpans(0, spannableStringBuilder6.length(), MetricAffectingSpan.class);
            if (spannableStringBuilder6.length() != 0) {
                spannableStringBuilder6.setSpan(new TextPaintUrlSpan((innerSpans4 == null || innerSpans4.length == 0) ? getTextPaint(parentRichText, richText, parentBlock) : null, "tel:" + getUrl(richText)), 0, spannableStringBuilder6.length(), 33);
            }
            return spannableStringBuilder6;
        }
        if (richText instanceof TLRPC.TL_textImage) {
            TLRPC.TL_textImage textImage = (TLRPC.TL_textImage) richText;
            TLRPC.Document document = getDocumentWithId(textImage.document_id);
            if (document == null) {
                return "";
            }
            SpannableStringBuilder spannableStringBuilder7 = new SpannableStringBuilder("*");
            int w = AndroidUtilities.dp(textImage.w);
            int h = AndroidUtilities.dp(textImage.h);
            int maxWidth2 = Math.abs(maxWidth);
            if (w > maxWidth2) {
                float scale = maxWidth2 / w;
                w = maxWidth2;
                h = (int) (h * scale);
            }
            spannableStringBuilder7.setSpan(new TextPaintImageReceiverSpan(parentView, document, this.currentPage, w, h, false, this.selectedColor == 2), 0, spannableStringBuilder7.length(), 33);
            return spannableStringBuilder7;
        }
        return "not supported " + richText;
    }

    public static CharSequence getPlainText(TLRPC.RichText richText) {
        if (richText == null) {
            return "";
        }
        if (richText instanceof TLRPC.TL_textFixed) {
            return getPlainText(((TLRPC.TL_textFixed) richText).text);
        }
        if (richText instanceof TLRPC.TL_textItalic) {
            return getPlainText(((TLRPC.TL_textItalic) richText).text);
        }
        if (richText instanceof TLRPC.TL_textBold) {
            return getPlainText(((TLRPC.TL_textBold) richText).text);
        }
        if (richText instanceof TLRPC.TL_textUnderline) {
            return getPlainText(((TLRPC.TL_textUnderline) richText).text);
        }
        if (richText instanceof TLRPC.TL_textStrike) {
            return getPlainText(((TLRPC.TL_textStrike) richText).text);
        }
        if (richText instanceof TLRPC.TL_textEmail) {
            return getPlainText(((TLRPC.TL_textEmail) richText).text);
        }
        if (richText instanceof TLRPC.TL_textUrl) {
            return getPlainText(((TLRPC.TL_textUrl) richText).text);
        }
        if (richText instanceof TLRPC.TL_textPlain) {
            return ((TLRPC.TL_textPlain) richText).text;
        }
        if (richText instanceof TLRPC.TL_textAnchor) {
            return getPlainText(((TLRPC.TL_textAnchor) richText).text);
        }
        if (richText instanceof TLRPC.TL_textEmpty) {
            return "";
        }
        if (richText instanceof TLRPC.TL_textConcat) {
            StringBuilder stringBuilder = new StringBuilder();
            int count = richText.texts.size();
            for (int a = 0; a < count; a++) {
                stringBuilder.append(getPlainText(richText.texts.get(a)));
            }
            return stringBuilder;
        }
        if (richText instanceof TLRPC.TL_textSubscript) {
            return getPlainText(((TLRPC.TL_textSubscript) richText).text);
        }
        if (richText instanceof TLRPC.TL_textSuperscript) {
            return getPlainText(((TLRPC.TL_textSuperscript) richText).text);
        }
        if (richText instanceof TLRPC.TL_textMarked) {
            return getPlainText(((TLRPC.TL_textMarked) richText).text);
        }
        if (richText instanceof TLRPC.TL_textPhone) {
            return getPlainText(((TLRPC.TL_textPhone) richText).text);
        }
        return richText instanceof TLRPC.TL_textImage ? "" : "";
    }

    public static String getUrl(TLRPC.RichText richText) {
        if (richText instanceof TLRPC.TL_textFixed) {
            return getUrl(((TLRPC.TL_textFixed) richText).text);
        }
        if (richText instanceof TLRPC.TL_textItalic) {
            return getUrl(((TLRPC.TL_textItalic) richText).text);
        }
        if (richText instanceof TLRPC.TL_textBold) {
            return getUrl(((TLRPC.TL_textBold) richText).text);
        }
        if (richText instanceof TLRPC.TL_textUnderline) {
            return getUrl(((TLRPC.TL_textUnderline) richText).text);
        }
        if (richText instanceof TLRPC.TL_textStrike) {
            return getUrl(((TLRPC.TL_textStrike) richText).text);
        }
        if (richText instanceof TLRPC.TL_textEmail) {
            return ((TLRPC.TL_textEmail) richText).email;
        }
        if (richText instanceof TLRPC.TL_textUrl) {
            return ((TLRPC.TL_textUrl) richText).url;
        }
        if (richText instanceof TLRPC.TL_textPhone) {
            return ((TLRPC.TL_textPhone) richText).phone;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getTextColor() {
        int selectedColor = getSelectedColor();
        if (selectedColor == 0 || selectedColor == 1) {
            return -14606047;
        }
        return -6710887;
    }

    private int getInstantLinkBackgroundColor() {
        int selectedColor = getSelectedColor();
        if (selectedColor == 0) {
            return -1707782;
        }
        if (selectedColor == 1) {
            return -2498337;
        }
        return -14536904;
    }

    private int getLinkTextColor() {
        int selectedColor = getSelectedColor();
        if (selectedColor == 0) {
            return -15435321;
        }
        if (selectedColor == 1) {
            return -13471296;
        }
        return -10838585;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getGrayTextColor() {
        int selectedColor = getSelectedColor();
        if (selectedColor == 0) {
            return -8156010;
        }
        if (selectedColor == 1) {
            return -11711675;
        }
        return -10066330;
    }

    private TextPaint getTextPaint(TLRPC.RichText parentRichText, TLRPC.RichText richText, TLRPC.PageBlock parentBlock) {
        int additionalSize;
        int flags = getTextFlags(richText);
        SparseArray<TextPaint> currentMap = null;
        int textSize = AndroidUtilities.dp(14.0f);
        int textColor = SupportMenu.CATEGORY_MASK;
        int additionalSize2 = this.selectedFontSize;
        if (additionalSize2 == 0) {
            additionalSize = -AndroidUtilities.dp(4.0f);
        } else if (additionalSize2 == 1) {
            additionalSize = -AndroidUtilities.dp(2.0f);
        } else if (additionalSize2 == 3) {
            additionalSize = AndroidUtilities.dp(2.0f);
        } else if (additionalSize2 == 4) {
            additionalSize = AndroidUtilities.dp(4.0f);
        } else {
            additionalSize = 0;
        }
        if (parentBlock instanceof TLRPC.TL_pageBlockPhoto) {
            TLRPC.TL_pageBlockPhoto pageBlockPhoto = (TLRPC.TL_pageBlockPhoto) parentBlock;
            if (pageBlockPhoto.caption.text == richText || pageBlockPhoto.caption.text == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
            } else {
                currentMap = photoCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
            }
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockMap) {
            TLRPC.TL_pageBlockMap pageBlockMap = (TLRPC.TL_pageBlockMap) parentBlock;
            if (pageBlockMap.caption.text == richText || pageBlockMap.caption.text == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
            } else {
                currentMap = photoCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
            }
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockTitle) {
            currentMap = titleTextPaints;
            textSize = AndroidUtilities.dp(24.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockKicker) {
            currentMap = kickerTextPaints;
            textSize = AndroidUtilities.dp(14.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockAuthorDate) {
            currentMap = authorTextPaints;
            textSize = AndroidUtilities.dp(14.0f);
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockFooter) {
            currentMap = footerTextPaints;
            textSize = AndroidUtilities.dp(14.0f);
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockSubtitle) {
            currentMap = subtitleTextPaints;
            textSize = AndroidUtilities.dp(21.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockHeader) {
            currentMap = headerTextPaints;
            textSize = AndroidUtilities.dp(21.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockSubheader) {
            currentMap = subheaderTextPaints;
            textSize = AndroidUtilities.dp(18.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockBlockquote) {
            TLRPC.TL_pageBlockBlockquote pageBlockBlockquote = (TLRPC.TL_pageBlockBlockquote) parentBlock;
            if (pageBlockBlockquote.text == parentRichText) {
                currentMap = quoteTextPaints;
                textSize = AndroidUtilities.dp(15.0f);
                textColor = getTextColor();
            } else if (pageBlockBlockquote.caption == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
                textColor = getGrayTextColor();
            }
        } else if (parentBlock instanceof TLRPC.TL_pageBlockPullquote) {
            TLRPC.TL_pageBlockPullquote pageBlockBlockquote2 = (TLRPC.TL_pageBlockPullquote) parentBlock;
            if (pageBlockBlockquote2.text == parentRichText) {
                currentMap = quoteTextPaints;
                textSize = AndroidUtilities.dp(15.0f);
                textColor = getTextColor();
            } else if (pageBlockBlockquote2.caption == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
                textColor = getGrayTextColor();
            }
        } else if (parentBlock instanceof TLRPC.TL_pageBlockPreformatted) {
            currentMap = preformattedTextPaints;
            textSize = AndroidUtilities.dp(14.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockParagraph) {
            currentMap = paragraphTextPaints;
            textSize = AndroidUtilities.dp(16.0f);
            textColor = getTextColor();
        } else if (isListItemBlock(parentBlock)) {
            currentMap = listTextPaints;
            textSize = AndroidUtilities.dp(16.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockEmbed) {
            TLRPC.TL_pageBlockEmbed pageBlockEmbed = (TLRPC.TL_pageBlockEmbed) parentBlock;
            if (pageBlockEmbed.caption.text == richText || pageBlockEmbed.caption.text == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
            } else {
                currentMap = photoCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
            }
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockSlideshow) {
            TLRPC.TL_pageBlockSlideshow pageBlockSlideshow = (TLRPC.TL_pageBlockSlideshow) parentBlock;
            if (pageBlockSlideshow.caption.text == richText || pageBlockSlideshow.caption.text == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
            } else {
                currentMap = photoCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
            }
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockCollage) {
            TLRPC.TL_pageBlockCollage pageBlockCollage = (TLRPC.TL_pageBlockCollage) parentBlock;
            if (pageBlockCollage.caption.text == richText || pageBlockCollage.caption.text == parentRichText) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
            } else {
                currentMap = photoCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
            }
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockEmbedPost) {
            TLRPC.TL_pageBlockEmbedPost pageBlockEmbedPost = (TLRPC.TL_pageBlockEmbedPost) parentBlock;
            if (richText == pageBlockEmbedPost.caption.text) {
                currentMap = photoCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
                textColor = getGrayTextColor();
            } else if (richText == pageBlockEmbedPost.caption.credit) {
                currentMap = photoCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
                textColor = getGrayTextColor();
            } else if (richText != null) {
                currentMap = embedPostTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
                textColor = getTextColor();
            }
        } else if (parentBlock instanceof TLRPC.TL_pageBlockVideo) {
            TLRPC.TL_pageBlockVideo pageBlockVideo = (TLRPC.TL_pageBlockVideo) parentBlock;
            if (richText == pageBlockVideo.caption.text) {
                currentMap = mediaCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
                textColor = getTextColor();
            } else {
                currentMap = mediaCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
                textColor = getTextColor();
            }
        } else if (parentBlock instanceof TLRPC.TL_pageBlockAudio) {
            TLRPC.TL_pageBlockAudio pageBlockAudio = (TLRPC.TL_pageBlockAudio) parentBlock;
            if (richText == pageBlockAudio.caption.text) {
                currentMap = mediaCaptionTextPaints;
                textSize = AndroidUtilities.dp(14.0f);
                textColor = getTextColor();
            } else {
                currentMap = mediaCreditTextPaints;
                textSize = AndroidUtilities.dp(12.0f);
                textColor = getTextColor();
            }
        } else if (parentBlock instanceof TLRPC.TL_pageBlockRelatedArticles) {
            currentMap = relatedArticleTextPaints;
            textSize = AndroidUtilities.dp(15.0f);
            textColor = getGrayTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockDetails) {
            currentMap = detailsTextPaints;
            textSize = AndroidUtilities.dp(15.0f);
            textColor = getTextColor();
        } else if (parentBlock instanceof TLRPC.TL_pageBlockTable) {
            currentMap = tableTextPaints;
            textSize = AndroidUtilities.dp(15.0f);
            textColor = getTextColor();
        }
        if ((flags & 256) != 0 || (flags & 128) != 0) {
            textSize -= AndroidUtilities.dp(4.0f);
        }
        if (currentMap == null) {
            if (errorTextPaint == null) {
                TextPaint textPaint = new TextPaint(1);
                errorTextPaint = textPaint;
                textPaint.setColor(SupportMenu.CATEGORY_MASK);
            }
            errorTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
            return errorTextPaint;
        }
        TextPaint paint = currentMap.get(flags);
        if (paint == null) {
            paint = new TextPaint(1);
            if ((flags & 4) != 0) {
                paint.setTypeface(AndroidUtilities.getTypeface("fonts/rmono.ttf"));
            } else if (parentBlock instanceof TLRPC.TL_pageBlockRelatedArticles) {
                paint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            } else if (this.selectedFont == 1 || (parentBlock instanceof TLRPC.TL_pageBlockTitle) || (parentBlock instanceof TLRPC.TL_pageBlockKicker) || (parentBlock instanceof TLRPC.TL_pageBlockHeader) || (parentBlock instanceof TLRPC.TL_pageBlockSubtitle) || (parentBlock instanceof TLRPC.TL_pageBlockSubheader)) {
                if ((flags & 1) != 0 && (flags & 2) != 0) {
                    paint.setTypeface(Typeface.create(C.SERIF_NAME, 3));
                } else if ((flags & 1) != 0) {
                    paint.setTypeface(Typeface.create(C.SERIF_NAME, 1));
                } else if ((flags & 2) != 0) {
                    paint.setTypeface(Typeface.create(C.SERIF_NAME, 2));
                } else {
                    paint.setTypeface(Typeface.create(C.SERIF_NAME, 0));
                }
            } else if ((flags & 1) != 0 && (flags & 2) != 0) {
                paint.setTypeface(AndroidUtilities.getTypeface("fonts/rmediumitalic.ttf"));
            } else if ((flags & 1) != 0) {
                paint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            } else if ((flags & 2) != 0) {
                paint.setTypeface(AndroidUtilities.getTypeface("fonts/ritalic.ttf"));
            }
            if ((flags & 32) != 0) {
                paint.setFlags(paint.getFlags() | 16);
            }
            if ((flags & 16) != 0) {
                paint.setFlags(paint.getFlags() | 8);
            }
            if ((flags & 8) != 0 || (flags & 512) != 0) {
                paint.setFlags(paint.getFlags());
                textColor = getLinkTextColor();
            }
            if ((flags & 256) != 0) {
                paint.baselineShift -= AndroidUtilities.dp(6.0f);
            } else if ((flags & 128) != 0) {
                paint.baselineShift += AndroidUtilities.dp(2.0f);
            }
            paint.setColor(textColor);
            currentMap.put(flags, paint);
        }
        paint.setTextSize(textSize + additionalSize);
        return paint;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public DrawingText createLayoutForText(View parentView, CharSequence plainText, TLRPC.RichText richText, int width, TLRPC.PageBlock parentBlock, WebpageAdapter parentAdapter) {
        return createLayoutForText(parentView, plainText, richText, width, 0, parentBlock, Layout.Alignment.ALIGN_NORMAL, 0, parentAdapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public DrawingText createLayoutForText(View parentView, CharSequence plainText, TLRPC.RichText richText, int width, TLRPC.PageBlock parentBlock, Layout.Alignment align, WebpageAdapter parentAdapter) {
        return createLayoutForText(parentView, plainText, richText, width, 0, parentBlock, align, 0, parentAdapter);
    }

    private DrawingText createLayoutForText(View parentView, CharSequence plainText, TLRPC.RichText richText, int width, int textY, TLRPC.PageBlock parentBlock, WebpageAdapter parentAdapter) {
        return createLayoutForText(parentView, plainText, richText, width, textY, parentBlock, Layout.Alignment.ALIGN_NORMAL, 0, parentAdapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public DrawingText createLayoutForText(View view, CharSequence charSequence, TLRPC.RichText richText, int i, int i2, TLRPC.PageBlock pageBlock, Layout.Alignment alignment, int i3, WebpageAdapter webpageAdapter) {
        int iDp;
        CharSequence text;
        int iDp2;
        TextPaint textPaint;
        StaticLayout staticLayout;
        int iDp3;
        CharSequence charSequence2;
        int i4;
        if (charSequence == null && (richText == null || (richText instanceof TLRPC.TL_textEmpty))) {
            return null;
        }
        if (i >= 0) {
            iDp = i;
        } else {
            iDp = AndroidUtilities.dp(10.0f);
        }
        int selectedColor = getSelectedColor();
        if (charSequence != null) {
            text = charSequence;
        } else {
            text = getText(view, richText, richText, pageBlock, iDp);
        }
        if (TextUtils.isEmpty(text)) {
            return null;
        }
        int i5 = this.selectedFontSize;
        if (i5 == 0) {
            iDp2 = -AndroidUtilities.dp(4.0f);
        } else if (i5 == 1) {
            iDp2 = -AndroidUtilities.dp(2.0f);
        } else if (i5 == 3) {
            iDp2 = AndroidUtilities.dp(2.0f);
        } else if (i5 == 4) {
            iDp2 = AndroidUtilities.dp(4.0f);
        } else {
            iDp2 = 0;
        }
        if ((pageBlock instanceof TLRPC.TL_pageBlockEmbedPost) && richText == null) {
            if (((TLRPC.TL_pageBlockEmbedPost) pageBlock).author == charSequence) {
                if (embedPostAuthorPaint == null) {
                    TextPaint textPaint2 = new TextPaint(1);
                    embedPostAuthorPaint = textPaint2;
                    textPaint2.setColor(getTextColor());
                }
                embedPostAuthorPaint.setTextSize(AndroidUtilities.dp(15.0f) + iDp2);
                textPaint = embedPostAuthorPaint;
            } else {
                if (embedPostDatePaint == null) {
                    TextPaint textPaint3 = new TextPaint(1);
                    embedPostDatePaint = textPaint3;
                    if (selectedColor == 0) {
                        textPaint3.setColor(-7366752);
                    } else {
                        textPaint3.setColor(getGrayTextColor());
                    }
                }
                embedPostDatePaint.setTextSize(AndroidUtilities.dp(14.0f) + iDp2);
                textPaint = embedPostDatePaint;
            }
        } else if (pageBlock instanceof TLRPC.TL_pageBlockChannel) {
            if (channelNamePaint == null) {
                TextPaint textPaint4 = new TextPaint(1);
                channelNamePaint = textPaint4;
                textPaint4.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            }
            if (this.channelBlock == null) {
                channelNamePaint.setColor(getTextColor());
            } else {
                channelNamePaint.setColor(-1);
            }
            channelNamePaint.setTextSize(AndroidUtilities.dp(15.0f));
            textPaint = channelNamePaint;
        } else if (!(pageBlock instanceof TL_pageBlockRelatedArticlesChild)) {
            if (isListItemBlock(pageBlock) && charSequence != null) {
                if (listTextPointerPaint == null) {
                    TextPaint textPaint5 = new TextPaint(1);
                    listTextPointerPaint = textPaint5;
                    textPaint5.setColor(getTextColor());
                }
                if (listTextNumPaint == null) {
                    TextPaint textPaint6 = new TextPaint(1);
                    listTextNumPaint = textPaint6;
                    textPaint6.setColor(getTextColor());
                }
                listTextPointerPaint.setTextSize(AndroidUtilities.dp(19.0f) + iDp2);
                listTextNumPaint.setTextSize(AndroidUtilities.dp(16.0f) + iDp2);
                if ((pageBlock instanceof TL_pageBlockListItem) && !((TL_pageBlockListItem) pageBlock).parent.pageBlockList.ordered) {
                    textPaint = listTextPointerPaint;
                } else {
                    textPaint = listTextNumPaint;
                }
            } else {
                textPaint = getTextPaint(richText, richText, pageBlock);
            }
        } else {
            TL_pageBlockRelatedArticlesChild tL_pageBlockRelatedArticlesChild = (TL_pageBlockRelatedArticlesChild) pageBlock;
            if (charSequence == tL_pageBlockRelatedArticlesChild.parent.articles.get(tL_pageBlockRelatedArticlesChild.num).title) {
                if (relatedArticleHeaderPaint == null) {
                    TextPaint textPaint7 = new TextPaint(1);
                    relatedArticleHeaderPaint = textPaint7;
                    textPaint7.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                }
                relatedArticleHeaderPaint.setColor(getTextColor());
                relatedArticleHeaderPaint.setTextSize(AndroidUtilities.dp(15.0f) + iDp2);
                textPaint = relatedArticleHeaderPaint;
            } else {
                if (relatedArticleTextPaint == null) {
                    relatedArticleTextPaint = new TextPaint(1);
                }
                relatedArticleTextPaint.setColor(getGrayTextColor());
                relatedArticleTextPaint.setTextSize(AndroidUtilities.dp(14.0f) + iDp2);
                textPaint = relatedArticleTextPaint;
            }
        }
        if (i3 != 0) {
            if (pageBlock instanceof TLRPC.TL_pageBlockPullquote) {
                staticLayout = StaticLayoutEx.createStaticLayout(text, textPaint, iDp, Layout.Alignment.ALIGN_CENTER, 1.0f, 0.0f, false, TextUtils.TruncateAt.END, iDp, i3);
            } else {
                staticLayout = StaticLayoutEx.createStaticLayout(text, textPaint, iDp, alignment, 1.0f, AndroidUtilities.dp(4.0f), false, TextUtils.TruncateAt.END, iDp, i3);
            }
        } else {
            if (text.charAt(text.length() - 1) == '\n') {
                text = text.subSequence(0, text.length() - 1);
            }
            if (pageBlock instanceof TLRPC.TL_pageBlockPullquote) {
                staticLayout = new StaticLayout(text, textPaint, iDp, Layout.Alignment.ALIGN_CENTER, 1.0f, 0.0f, false);
            } else {
                staticLayout = new StaticLayout(text, textPaint, iDp, alignment, 1.0f, AndroidUtilities.dp(4.0f), false);
            }
        }
        if (staticLayout == null) {
            return null;
        }
        CharSequence text2 = staticLayout.getText();
        LinkPath linkPath = null;
        linkPath = null;
        linkPath = null;
        linkPath = null;
        LinkPath linkPath2 = null;
        linkPath2 = null;
        linkPath2 = null;
        linkPath2 = null;
        if (staticLayout != null && (text2 instanceof Spanned)) {
            Spanned spanned = (Spanned) text2;
            try {
                AnchorSpan[] anchorSpanArr = (AnchorSpan[]) spanned.getSpans(0, spanned.length(), AnchorSpan.class);
                int lineCount = staticLayout.getLineCount();
                if (anchorSpanArr != null && anchorSpanArr.length > 0) {
                    int i6 = 0;
                    while (i6 < anchorSpanArr.length) {
                        if (lineCount > 1) {
                            charSequence2 = text;
                            i4 = iDp2;
                            webpageAdapter.anchorsOffset.put(anchorSpanArr[i6].getName(), Integer.valueOf(i2 + staticLayout.getLineTop(staticLayout.getLineForOffset(spanned.getSpanStart(anchorSpanArr[i6])))));
                        } else {
                            charSequence2 = text;
                            try {
                                i4 = iDp2;
                                try {
                                    webpageAdapter.anchorsOffset.put(anchorSpanArr[i6].getName(), Integer.valueOf(i2));
                                } catch (Exception e) {
                                }
                            } catch (Exception e2) {
                            }
                        }
                        i6++;
                        iDp2 = i4;
                        text = charSequence2;
                    }
                }
            } catch (Exception e3) {
            }
            float f = 0.0f;
            try {
                TextPaintWebpageUrlSpan[] textPaintWebpageUrlSpanArr = (TextPaintWebpageUrlSpan[]) spanned.getSpans(0, spanned.length(), TextPaintWebpageUrlSpan.class);
                if (textPaintWebpageUrlSpanArr != null && textPaintWebpageUrlSpanArr.length > 0) {
                    linkPath = new LinkPath(true);
                    linkPath.setAllowReset(false);
                    int i7 = 0;
                    while (i7 < textPaintWebpageUrlSpanArr.length) {
                        int spanStart = spanned.getSpanStart(textPaintWebpageUrlSpanArr[i7]);
                        int spanEnd = spanned.getSpanEnd(textPaintWebpageUrlSpanArr[i7]);
                        linkPath.setCurrentLayout(staticLayout, spanStart, f);
                        int i8 = textPaintWebpageUrlSpanArr[i7].getTextPaint() != null ? textPaintWebpageUrlSpanArr[i7].getTextPaint().baselineShift : 0;
                        if (i8 != 0) {
                            iDp3 = i8 + AndroidUtilities.dp(i8 > 0 ? 5.0f : -2.0f);
                        } else {
                            iDp3 = 0;
                        }
                        linkPath.setBaselineShift(iDp3);
                        staticLayout.getSelectionPath(spanStart, spanEnd, linkPath);
                        i7++;
                        f = 0.0f;
                    }
                    linkPath.setAllowReset(true);
                }
            } catch (Exception e4) {
            }
            try {
                TextPaintMarkSpan[] textPaintMarkSpanArr = (TextPaintMarkSpan[]) spanned.getSpans(0, spanned.length(), TextPaintMarkSpan.class);
                if (textPaintMarkSpanArr != null && textPaintMarkSpanArr.length > 0) {
                    LinkPath linkPath3 = new LinkPath(true);
                    int iDp4 = 0;
                    try {
                        linkPath3.setAllowReset(false);
                        int i9 = 0;
                        while (i9 < textPaintMarkSpanArr.length) {
                            int spanStart2 = spanned.getSpanStart(textPaintMarkSpanArr[i9]);
                            int spanEnd2 = spanned.getSpanEnd(textPaintMarkSpanArr[i9]);
                            linkPath3.setCurrentLayout(staticLayout, spanStart2, 0.0f);
                            int i10 = textPaintMarkSpanArr[i9].getTextPaint() != null ? textPaintMarkSpanArr[i9].getTextPaint().baselineShift : 0;
                            if (i10 != 0) {
                                iDp4 = i10 + AndroidUtilities.dp(i10 > 0 ? 5.0f : -2.0f);
                            }
                            linkPath3.setBaselineShift(iDp4);
                            staticLayout.getSelectionPath(spanStart2, spanEnd2, linkPath3);
                            i9++;
                            iDp4 = 0;
                        }
                        linkPath3.setAllowReset(true);
                        linkPath2 = linkPath3;
                    } catch (Exception e5) {
                        linkPath2 = linkPath3;
                    }
                }
            } catch (Exception e6) {
            }
        }
        DrawingText drawingText = new DrawingText();
        drawingText.textLayout = staticLayout;
        drawingText.textPath = linkPath;
        drawingText.markPath = linkPath2;
        return drawingText;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void drawLayoutLink(Canvas canvas, DrawingText layout) {
        float width;
        float x;
        if (canvas == null || layout == null || this.pressedLinkOwnerLayout != layout) {
            return;
        }
        if (this.pressedLink != null) {
            canvas.drawPath(this.urlPath, urlPaint);
            return;
        }
        if (this.drawBlockSelection && layout != null) {
            if (layout.getLineCount() == 1) {
                width = layout.getLineWidth(0);
                x = layout.getLineLeft(0);
            } else {
                width = layout.getWidth();
                x = 0.0f;
            }
            canvas.drawRect((-AndroidUtilities.dp(2.0f)) + x, 0.0f, x + width + AndroidUtilities.dp(2.0f), layout.getHeight(), urlPaint);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkLayoutForLinks(MotionEvent event, View parentView, DrawingText drawingText, int layoutX, int layoutY) {
        ActionBarPopupWindow actionBarPopupWindow;
        String anchor;
        String webPageUrl;
        TextPaintUrlSpan[] link;
        int end;
        if (this.pageSwitchAnimation != null || parentView == null || drawingText == null) {
            return false;
        }
        StaticLayout layout = drawingText.textLayout;
        int x = (int) event.getX();
        int y = (int) event.getY();
        boolean removeLink = false;
        if (event.getAction() == 0) {
            int N = layout.getLineCount();
            float width = 0.0f;
            float left = 2.1474836E9f;
            for (int a = 0; a < N; a++) {
                width = Math.max(layout.getLineWidth(a), width);
                left = Math.min(layout.getLineLeft(a), left);
            }
            if (x >= layoutX + left && x <= layoutX + left + width && y >= layoutY && y <= layout.getHeight() + layoutY) {
                this.pressedLinkOwnerLayout = drawingText;
                this.pressedLinkOwnerView = parentView;
                this.pressedLayoutY = layoutY;
                CharSequence text = layout.getText();
                if (text instanceof Spannable) {
                    int checkX = x - layoutX;
                    int checkY = y - layoutY;
                    try {
                        int line = layout.getLineForVertical(checkY);
                        int off = layout.getOffsetForHorizontal(line, checkX);
                        float left2 = layout.getLineLeft(line);
                        if (left2 <= checkX && layout.getLineWidth(line) + left2 >= checkX) {
                            Spannable buffer = (Spannable) layout.getText();
                            TextPaintUrlSpan[] link2 = (TextPaintUrlSpan[]) buffer.getSpans(off, off, TextPaintUrlSpan.class);
                            if (link2 != null && link2.length > 0) {
                                TextPaintUrlSpan textPaintUrlSpan = link2[0];
                                this.pressedLink = textPaintUrlSpan;
                                int pressedStart = buffer.getSpanStart(textPaintUrlSpan);
                                int pressedEnd = buffer.getSpanEnd(this.pressedLink);
                                int pressedStart2 = pressedStart;
                                int pressedEnd2 = pressedEnd;
                                int pressedEnd3 = 1;
                                while (true) {
                                    int x2 = x;
                                    try {
                                        if (pressedEnd3 >= link2.length) {
                                            break;
                                        }
                                        TextPaintUrlSpan span = link2[pressedEnd3];
                                        int start = buffer.getSpanStart(span);
                                        int end2 = buffer.getSpanEnd(span);
                                        Spannable buffer2 = buffer;
                                        if (pressedStart2 <= start) {
                                            link = link2;
                                            end = end2;
                                            if (end <= pressedEnd2) {
                                                pressedEnd3++;
                                                x = x2;
                                                buffer = buffer2;
                                                link2 = link;
                                            }
                                        } else {
                                            link = link2;
                                            end = end2;
                                        }
                                        this.pressedLink = span;
                                        pressedStart2 = start;
                                        pressedEnd2 = end;
                                        pressedEnd3++;
                                        x = x2;
                                        buffer = buffer2;
                                        link2 = link;
                                    } catch (Exception e) {
                                        e = e;
                                        FileLog.e(e);
                                    }
                                }
                                try {
                                    this.urlPath.setUseRoundRect(true);
                                    this.urlPath.setCurrentLayout(layout, pressedStart2, 0.0f);
                                    int shift = this.pressedLink.getTextPaint() != null ? this.pressedLink.getTextPaint().baselineShift : 0;
                                    this.urlPath.setBaselineShift(shift != 0 ? AndroidUtilities.dp(shift > 0 ? 5.0f : -2.0f) + shift : 0);
                                    layout.getSelectionPath(pressedStart2, pressedEnd2, this.urlPath);
                                    parentView.invalidate();
                                } catch (Exception e2) {
                                    FileLog.e(e2);
                                }
                            }
                        }
                    } catch (Exception e3) {
                        e = e3;
                    }
                }
            }
        } else if (event.getAction() == 1) {
            TextPaintUrlSpan textPaintUrlSpan2 = this.pressedLink;
            if (textPaintUrlSpan2 != null) {
                removeLink = true;
                String url = textPaintUrlSpan2.getUrl();
                if (url != null) {
                    BottomSheet bottomSheet = this.linkSheet;
                    if (bottomSheet != null) {
                        bottomSheet.dismiss();
                        this.linkSheet = null;
                    }
                    boolean isAnchor = false;
                    int index = url.lastIndexOf(35);
                    if (index != -1) {
                        if (!TextUtils.isEmpty(this.currentPage.cached_page.url)) {
                            webPageUrl = this.currentPage.cached_page.url.toLowerCase();
                        } else {
                            webPageUrl = this.currentPage.url.toLowerCase();
                        }
                        try {
                            anchor = URLDecoder.decode(url.substring(index + 1), "UTF-8");
                        } catch (Exception e4) {
                            anchor = "";
                        }
                        if (url.toLowerCase().contains(webPageUrl)) {
                            if (TextUtils.isEmpty(anchor)) {
                                this.layoutManager[0].scrollToPositionWithOffset(0, 0);
                                checkScrollAnimated();
                            } else {
                                scrollToAnchor(anchor);
                            }
                            isAnchor = true;
                        }
                    } else {
                        anchor = null;
                    }
                    if (!isAnchor) {
                        openWebpageUrl(this.pressedLink.getUrl(), anchor);
                    }
                }
            }
        } else if (event.getAction() == 3 && ((actionBarPopupWindow = this.popupWindow) == null || !actionBarPopupWindow.isShowing())) {
            removeLink = true;
        }
        if (removeLink) {
            removePressedLink();
        }
        if (event.getAction() == 0) {
            startCheckLongPress();
        }
        if (event.getAction() != 0 && event.getAction() != 2) {
            cancelCheckLongPress();
        }
        return parentView instanceof BlockDetailsCell ? this.pressedLink != null : this.pressedLinkOwnerLayout != null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removePressedLink() {
        if (this.pressedLink == null && this.pressedLinkOwnerView == null) {
            return;
        }
        View parentView = this.pressedLinkOwnerView;
        this.pressedLink = null;
        this.pressedLinkOwnerLayout = null;
        this.pressedLinkOwnerView = null;
        if (parentView != null) {
            parentView.invalidate();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openWebpageUrl(String url, final String anchor) {
        if (this.openUrlReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.openUrlReqId, false);
            this.openUrlReqId = 0;
        }
        final int reqId = this.lastReqId + 1;
        this.lastReqId = reqId;
        closePhoto(false);
        showProgressView(true, true);
        final TLRPC.TL_messages_getWebPage req = new TLRPC.TL_messages_getWebPage();
        req.url = url;
        req.hash = 0;
        this.openUrlReqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$pXMMQDRUIw31CHwmLTjvSh7OLGU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$openWebpageUrl$6$ArticleViewer(reqId, anchor, req, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$openWebpageUrl$6$ArticleViewer(final int reqId, final String anchor, final TLRPC.TL_messages_getWebPage req, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$X0hgap7MhFJronOYE9Hu3uChBY4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$ArticleViewer(reqId, response, anchor, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$ArticleViewer(int reqId, TLObject response, String anchor, TLRPC.TL_messages_getWebPage req) {
        if (this.openUrlReqId == 0 || reqId != this.lastReqId) {
            return;
        }
        this.openUrlReqId = 0;
        showProgressView(true, false);
        if (this.isVisible) {
            if ((response instanceof TLRPC.TL_webPage) && (((TLRPC.TL_webPage) response).cached_page instanceof TLRPC.TL_page)) {
                addPageToStack((TLRPC.TL_webPage) response, anchor, 1);
            } else {
                Browser.openUrl(this.parentActivity, req.url);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.Photo getPhotoWithId(long id) {
        TLRPC.WebPage webPage = this.currentPage;
        if (webPage == null || webPage.cached_page == null) {
            return null;
        }
        if (this.currentPage.photo != null && this.currentPage.photo.id == id) {
            return this.currentPage.photo;
        }
        for (int a = 0; a < this.currentPage.cached_page.photos.size(); a++) {
            TLRPC.Photo photo = this.currentPage.cached_page.photos.get(a);
            if (photo.id == id) {
                return photo;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.Document getDocumentWithId(long id) {
        TLRPC.WebPage webPage = this.currentPage;
        if (webPage == null || webPage.cached_page == null) {
            return null;
        }
        if (this.currentPage.document != null && this.currentPage.document.id == id) {
            return this.currentPage.document;
        }
        for (int a = 0; a < this.currentPage.cached_page.documents.size(); a++) {
            TLRPC.Document document = this.currentPage.cached_page.documents.get(a);
            if (document.id == id) {
                return document;
            }
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        BlockAudioCell cell;
        MessageObject playing;
        if (id == NotificationCenter.fileDidFailToLoad) {
            String location = (String) args[0];
            for (int a = 0; a < 3; a++) {
                String[] strArr = this.currentFileNames;
                if (strArr[a] != null && strArr[a].equals(location)) {
                    this.radialProgressViews[a].setProgress(1.0f, true);
                    checkProgress(a, true);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.fileDidLoad) {
            String location2 = (String) args[0];
            for (int a2 = 0; a2 < 3; a2++) {
                String[] strArr2 = this.currentFileNames;
                if (strArr2[a2] != null && strArr2[a2].equals(location2)) {
                    this.radialProgressViews[a2].setProgress(1.0f, true);
                    checkProgress(a2, true);
                    if (a2 == 0 && isMediaVideo(this.currentIndex)) {
                        onActionClick(false);
                        return;
                    }
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.FileLoadProgressChanged) {
            String location3 = (String) args[0];
            for (int a3 = 0; a3 < 3; a3++) {
                String[] strArr3 = this.currentFileNames;
                if (strArr3[a3] != null && strArr3[a3].equals(location3)) {
                    Float progress = (Float) args[1];
                    this.radialProgressViews[a3].setProgress(progress.floatValue(), true);
                }
            }
            return;
        }
        if (id == NotificationCenter.emojiDidLoad) {
            TextView textView = this.captionTextView;
            if (textView != null) {
                textView.invalidate();
                return;
            }
            return;
        }
        if (id == NotificationCenter.needSetDayNightTheme) {
            if (this.nightModeEnabled && this.selectedColor != 2 && this.adapter != null) {
                updatePaintColors();
                for (int i = 0; i < this.listView.length; i++) {
                    this.adapter[i].notifyDataSetChanged();
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagePlayingDidStart) {
            if (this.listView != null) {
                int i2 = 0;
                while (true) {
                    RecyclerListView[] recyclerListViewArr = this.listView;
                    if (i2 < recyclerListViewArr.length) {
                        int count = recyclerListViewArr[i2].getChildCount();
                        for (int a4 = 0; a4 < count; a4++) {
                            View view = this.listView[i2].getChildAt(a4);
                            if (view instanceof BlockAudioCell) {
                                ((BlockAudioCell) view).updateButtonState(true);
                            }
                        }
                        i2++;
                    } else {
                        return;
                    }
                }
            }
        } else if (id == NotificationCenter.messagePlayingDidReset || id == NotificationCenter.messagePlayingPlayStateChanged) {
            if (this.listView != null) {
                int i3 = 0;
                while (true) {
                    RecyclerListView[] recyclerListViewArr2 = this.listView;
                    if (i3 < recyclerListViewArr2.length) {
                        int count2 = recyclerListViewArr2[i3].getChildCount();
                        for (int a5 = 0; a5 < count2; a5++) {
                            View view2 = this.listView[i3].getChildAt(a5);
                            if (view2 instanceof BlockAudioCell) {
                                BlockAudioCell cell2 = (BlockAudioCell) view2;
                                MessageObject messageObject = cell2.getMessageObject();
                                if (messageObject != null) {
                                    cell2.updateButtonState(true);
                                }
                            }
                        }
                        i3++;
                    } else {
                        return;
                    }
                }
            }
        } else if (id == NotificationCenter.messagePlayingProgressDidChanged) {
            Integer mid = (Integer) args[0];
            if (this.listView != null) {
                int i4 = 0;
                while (true) {
                    RecyclerListView[] recyclerListViewArr3 = this.listView;
                    if (i4 < recyclerListViewArr3.length) {
                        int count3 = recyclerListViewArr3[i4].getChildCount();
                        int a6 = 0;
                        while (true) {
                            if (a6 < count3) {
                                View view3 = this.listView[i4].getChildAt(a6);
                                if (!(view3 instanceof BlockAudioCell) || (playing = (cell = (BlockAudioCell) view3).getMessageObject()) == null || playing.getId() != mid.intValue()) {
                                    a6++;
                                } else {
                                    MessageObject player = MediaController.getInstance().getPlayingMessageObject();
                                    if (player != null) {
                                        playing.audioProgress = player.audioProgress;
                                        playing.audioProgressSec = player.audioProgressSec;
                                        playing.audioPlayerDuration = player.audioPlayerDuration;
                                        cell.updatePlayingMessageProgress();
                                    }
                                }
                            }
                        }
                        i4++;
                    } else {
                        return;
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePaintSize() {
        ApplicationLoader.applicationContext.getSharedPreferences("articles", 0).edit().putInt("font_size", this.selectedFontSize).commit();
        for (int i = 0; i < 2; i++) {
            this.adapter[i].notifyDataSetChanged();
        }
    }

    private void updatePaintFonts() {
        ApplicationLoader.applicationContext.getSharedPreferences("articles", 0).edit().putInt("font_type", this.selectedFont).commit();
        Typeface typefaceNormal = this.selectedFont == 0 ? Typeface.DEFAULT : Typeface.SERIF;
        Typeface typefaceItalic = this.selectedFont == 0 ? AndroidUtilities.getTypeface("fonts/ritalic.ttf") : Typeface.create(C.SERIF_NAME, 2);
        Typeface typefaceBold = this.selectedFont == 0 ? AndroidUtilities.getTypeface("fonts/rmedium.ttf") : Typeface.create(C.SERIF_NAME, 1);
        Typeface typefaceBoldItalic = this.selectedFont == 0 ? AndroidUtilities.getTypeface("fonts/rmediumitalic.ttf") : Typeface.create(C.SERIF_NAME, 3);
        for (int a = 0; a < quoteTextPaints.size(); a++) {
            updateFontEntry(quoteTextPaints.keyAt(a), quoteTextPaints.valueAt(a), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a2 = 0; a2 < preformattedTextPaints.size(); a2++) {
            updateFontEntry(preformattedTextPaints.keyAt(a2), preformattedTextPaints.valueAt(a2), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a3 = 0; a3 < paragraphTextPaints.size(); a3++) {
            updateFontEntry(paragraphTextPaints.keyAt(a3), paragraphTextPaints.valueAt(a3), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a4 = 0; a4 < listTextPaints.size(); a4++) {
            updateFontEntry(listTextPaints.keyAt(a4), listTextPaints.valueAt(a4), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a5 = 0; a5 < embedPostTextPaints.size(); a5++) {
            updateFontEntry(embedPostTextPaints.keyAt(a5), embedPostTextPaints.valueAt(a5), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a6 = 0; a6 < mediaCaptionTextPaints.size(); a6++) {
            updateFontEntry(mediaCaptionTextPaints.keyAt(a6), mediaCaptionTextPaints.valueAt(a6), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a7 = 0; a7 < mediaCreditTextPaints.size(); a7++) {
            updateFontEntry(mediaCreditTextPaints.keyAt(a7), mediaCreditTextPaints.valueAt(a7), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a8 = 0; a8 < photoCaptionTextPaints.size(); a8++) {
            updateFontEntry(photoCaptionTextPaints.keyAt(a8), photoCaptionTextPaints.valueAt(a8), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a9 = 0; a9 < photoCreditTextPaints.size(); a9++) {
            updateFontEntry(photoCreditTextPaints.keyAt(a9), photoCreditTextPaints.valueAt(a9), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a10 = 0; a10 < authorTextPaints.size(); a10++) {
            updateFontEntry(authorTextPaints.keyAt(a10), authorTextPaints.valueAt(a10), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a11 = 0; a11 < footerTextPaints.size(); a11++) {
            updateFontEntry(footerTextPaints.keyAt(a11), footerTextPaints.valueAt(a11), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a12 = 0; a12 < embedPostCaptionTextPaints.size(); a12++) {
            updateFontEntry(embedPostCaptionTextPaints.keyAt(a12), embedPostCaptionTextPaints.valueAt(a12), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a13 = 0; a13 < relatedArticleTextPaints.size(); a13++) {
            updateFontEntry(relatedArticleTextPaints.keyAt(a13), relatedArticleTextPaints.valueAt(a13), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a14 = 0; a14 < detailsTextPaints.size(); a14++) {
            updateFontEntry(detailsTextPaints.keyAt(a14), detailsTextPaints.valueAt(a14), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
        for (int a15 = 0; a15 < tableTextPaints.size(); a15++) {
            updateFontEntry(tableTextPaints.keyAt(a15), tableTextPaints.valueAt(a15), typefaceNormal, typefaceBoldItalic, typefaceBold, typefaceItalic);
        }
    }

    private void updateFontEntry(int flags, TextPaint paint, Typeface typefaceNormal, Typeface typefaceBoldItalic, Typeface typefaceBold, Typeface typefaceItalic) {
        if ((flags & 1) != 0 && (flags & 2) != 0) {
            paint.setTypeface(typefaceBoldItalic);
            return;
        }
        if ((flags & 1) != 0) {
            paint.setTypeface(typefaceBold);
        } else if ((flags & 2) != 0) {
            paint.setTypeface(typefaceItalic);
        } else if ((flags & 4) == 0) {
            paint.setTypeface(typefaceNormal);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getSelectedColor() {
        int currentColor = this.selectedColor;
        if (this.nightModeEnabled && currentColor != 2) {
            if (Theme.selectedAutoNightType != 0) {
                if (Theme.isCurrentThemeNight()) {
                    return 2;
                }
                return currentColor;
            }
            int hour = Calendar.getInstance().get(11);
            if ((hour >= 22 && hour <= 24) || (hour >= 0 && hour <= 6)) {
                return 2;
            }
            return currentColor;
        }
        return currentColor;
    }

    private void updatePaintColors() {
        ApplicationLoader.applicationContext.getSharedPreferences("articles", 0).edit().putInt("font_color", this.selectedColor).commit();
        int currentColor = getSelectedColor();
        if (currentColor == 0) {
            this.backgroundPaint.setColor(-1);
            int i = 0;
            while (true) {
                RecyclerListView[] recyclerListViewArr = this.listView;
                if (i >= recyclerListViewArr.length) {
                    break;
                }
                recyclerListViewArr[i].setGlowColor(-657673);
                i++;
            }
        } else if (currentColor == 1) {
            this.backgroundPaint.setColor(-659492);
            int i2 = 0;
            while (true) {
                RecyclerListView[] recyclerListViewArr2 = this.listView;
                if (i2 >= recyclerListViewArr2.length) {
                    break;
                }
                recyclerListViewArr2[i2].setGlowColor(-659492);
                i2++;
            }
        } else if (currentColor == 2) {
            this.backgroundPaint.setColor(-15461356);
            int i3 = 0;
            while (true) {
                RecyclerListView[] recyclerListViewArr3 = this.listView;
                if (i3 >= recyclerListViewArr3.length) {
                    break;
                }
                recyclerListViewArr3[i3].setGlowColor(-15461356);
                i3++;
            }
        }
        TextPaint textPaint = listTextPointerPaint;
        if (textPaint != null) {
            textPaint.setColor(getTextColor());
        }
        TextPaint textPaint2 = listTextNumPaint;
        if (textPaint2 != null) {
            textPaint2.setColor(getTextColor());
        }
        TextPaint textPaint3 = embedPostAuthorPaint;
        if (textPaint3 != null) {
            textPaint3.setColor(getTextColor());
        }
        TextPaint textPaint4 = channelNamePaint;
        if (textPaint4 != null) {
            if (this.channelBlock == null) {
                textPaint4.setColor(getTextColor());
            } else {
                textPaint4.setColor(-1);
            }
        }
        TextPaint textPaint5 = relatedArticleHeaderPaint;
        if (textPaint5 != null) {
            textPaint5.setColor(getTextColor());
        }
        TextPaint textPaint6 = relatedArticleTextPaint;
        if (textPaint6 != null) {
            textPaint6.setColor(getGrayTextColor());
        }
        TextPaint textPaint7 = embedPostDatePaint;
        if (textPaint7 != null) {
            if (currentColor == 0) {
                textPaint7.setColor(-7366752);
            } else {
                textPaint7.setColor(getGrayTextColor());
            }
        }
        createPaint(true);
        setMapColors(titleTextPaints);
        setMapColors(kickerTextPaints);
        setMapColors(subtitleTextPaints);
        setMapColors(headerTextPaints);
        setMapColors(subheaderTextPaints);
        setMapColors(quoteTextPaints);
        setMapColors(preformattedTextPaints);
        setMapColors(paragraphTextPaints);
        setMapColors(listTextPaints);
        setMapColors(embedPostTextPaints);
        setMapColors(mediaCaptionTextPaints);
        setMapColors(mediaCreditTextPaints);
        setMapColors(photoCaptionTextPaints);
        setMapColors(photoCreditTextPaints);
        setMapColors(authorTextPaints);
        setMapColors(footerTextPaints);
        setMapColors(embedPostCaptionTextPaints);
        setMapColors(relatedArticleTextPaints);
        setMapColors(detailsTextPaints);
        setMapColors(tableTextPaints);
    }

    private void setMapColors(SparseArray<TextPaint> map) {
        for (int a = 0; a < map.size(); a++) {
            int flags = map.keyAt(a);
            TextPaint paint = map.valueAt(a);
            if ((flags & 8) != 0 || (flags & 512) != 0) {
                paint.setColor(getLinkTextColor());
            } else {
                paint.setColor(getTextColor());
            }
        }
    }

    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$PrimitiveArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public void setParentActivity(Activity activity, BaseFragment fragment) {
        this.parentFragment = fragment;
        int i = UserConfig.selectedAccount;
        this.currentAccount = i;
        this.leftImage.setCurrentAccount(i);
        this.rightImage.setCurrentAccount(this.currentAccount);
        this.centerImage.setCurrentAccount(this.currentAccount);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidStart);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.needSetDayNightTheme);
        if (this.parentActivity == activity) {
            updatePaintColors();
            return;
        }
        this.parentActivity = activity;
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("articles", 0);
        this.selectedFontSize = sharedPreferences.getInt("font_size", 2);
        this.selectedFont = sharedPreferences.getInt("font_type", 0);
        this.selectedColor = sharedPreferences.getInt("font_color", 0);
        this.nightModeEnabled = sharedPreferences.getBoolean("nightModeEnabled", false);
        createPaint(false);
        this.backgroundPaint = new Paint();
        this.layerShadowDrawable = activity.getResources().getDrawable(R.drawable.layer_shadow);
        this.slideDotDrawable = activity.getResources().getDrawable(R.drawable.slide_dot_small);
        this.slideDotBigDrawable = activity.getResources().getDrawable(R.drawable.slide_dot_big);
        this.scrimPaint = new Paint();
        WindowView windowView = new WindowView(activity);
        this.windowView = windowView;
        windowView.setWillNotDraw(false);
        this.windowView.setClipChildren(true);
        this.windowView.setFocusable(false);
        FrameLayout frameLayout = new FrameLayout(activity) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.4
            @Override // android.view.ViewGroup
            protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                int clipLeft;
                int clipRight;
                float opacity;
                if (ArticleViewer.this.windowView.movingPage) {
                    int width = getMeasuredWidth();
                    int translationX = (int) ArticleViewer.this.listView[0].getTranslationX();
                    if (child != ArticleViewer.this.listView[1]) {
                        if (child != ArticleViewer.this.listView[0]) {
                            clipLeft = 0;
                            clipRight = width;
                        } else {
                            clipLeft = translationX;
                            clipRight = width;
                        }
                    } else {
                        clipLeft = 0;
                        clipRight = translationX;
                    }
                    int restoreCount = canvas.save();
                    canvas.clipRect(clipLeft, 0, clipRight, getHeight());
                    boolean result = super.drawChild(canvas, child, drawingTime);
                    canvas.restoreToCount(restoreCount);
                    if (translationX != 0) {
                        if (child != ArticleViewer.this.listView[0]) {
                            if (child == ArticleViewer.this.listView[1]) {
                                float opacity2 = Math.min(0.8f, (width - translationX) / width);
                                if (opacity2 >= 0.0f) {
                                    opacity = opacity2;
                                } else {
                                    opacity = 0.0f;
                                }
                                ArticleViewer.this.scrimPaint.setColor(((int) (153.0f * opacity)) << 24);
                                canvas.drawRect(clipLeft, 0.0f, clipRight, getHeight(), ArticleViewer.this.scrimPaint);
                            }
                        } else {
                            float alpha = Math.max(0.0f, Math.min((width - translationX) / AndroidUtilities.dp(20.0f), 1.0f));
                            ArticleViewer.this.layerShadowDrawable.setBounds(translationX - ArticleViewer.this.layerShadowDrawable.getIntrinsicWidth(), child.getTop(), translationX, child.getBottom());
                            ArticleViewer.this.layerShadowDrawable.setAlpha((int) (255.0f * alpha));
                            ArticleViewer.this.layerShadowDrawable.draw(canvas);
                        }
                    }
                    return result;
                }
                return super.drawChild(canvas, child, drawingTime);
            }
        };
        this.containerView = frameLayout;
        this.windowView.addView(frameLayout, LayoutHelper.createFrame(-1, -1, 51));
        this.containerView.setFitsSystemWindows(true);
        if (Build.VERSION.SDK_INT >= 21) {
            this.containerView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$AcIfVfqrcdTWFo0g0O77kKrsKAk
                @Override // android.view.View.OnApplyWindowInsetsListener
                public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                    return this.f$0.lambda$setParentActivity$7$ArticleViewer(view, windowInsets);
                }
            });
        }
        this.containerView.setSystemUiVisibility(1028);
        View view = new View(activity);
        this.photoContainerBackground = view;
        view.setVisibility(4);
        this.photoContainerBackground.setBackgroundDrawable(this.photoBackgroundDrawable);
        this.windowView.addView(this.photoContainerBackground, LayoutHelper.createFrame(-1, -1, 51));
        ClippingImageView clippingImageView = new ClippingImageView(activity);
        this.animatingImageView = clippingImageView;
        clippingImageView.setAnimationValues(this.animationValues);
        this.animatingImageView.setVisibility(8);
        this.windowView.addView(this.animatingImageView, LayoutHelper.createFrame(40, 40.0f));
        FrameLayoutDrawer frameLayoutDrawer = new FrameLayoutDrawer(activity) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.5
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                int y = (bottom - top) - ArticleViewer.this.captionTextView.getMeasuredHeight();
                int y2 = (bottom - top) - ArticleViewer.this.groupedPhotosListView.getMeasuredHeight();
                if (ArticleViewer.this.bottomLayout.getVisibility() == 0) {
                    y -= ArticleViewer.this.bottomLayout.getMeasuredHeight();
                    y2 -= ArticleViewer.this.bottomLayout.getMeasuredHeight();
                }
                if (!ArticleViewer.this.groupedPhotosListView.currentPhotos.isEmpty()) {
                    y -= ArticleViewer.this.groupedPhotosListView.getMeasuredHeight();
                }
                ArticleViewer.this.captionTextView.layout(0, y, ArticleViewer.this.captionTextView.getMeasuredWidth(), ArticleViewer.this.captionTextView.getMeasuredHeight() + y);
                ArticleViewer.this.captionTextViewNext.layout(0, y, ArticleViewer.this.captionTextViewNext.getMeasuredWidth(), ArticleViewer.this.captionTextViewNext.getMeasuredHeight() + y);
                ArticleViewer.this.groupedPhotosListView.layout(0, y2, ArticleViewer.this.groupedPhotosListView.getMeasuredWidth(), ArticleViewer.this.groupedPhotosListView.getMeasuredHeight() + y2);
            }
        };
        this.photoContainerView = frameLayoutDrawer;
        frameLayoutDrawer.setVisibility(4);
        this.photoContainerView.setWillNotDraw(false);
        this.windowView.addView(this.photoContainerView, LayoutHelper.createFrame(-1, -1, 51));
        FrameLayout frameLayout2 = new FrameLayout(activity);
        this.fullscreenVideoContainer = frameLayout2;
        frameLayout2.setBackgroundColor(-16777216);
        this.fullscreenVideoContainer.setVisibility(4);
        this.windowView.addView(this.fullscreenVideoContainer, LayoutHelper.createFrame(-1, -1.0f));
        AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(activity);
        this.fullscreenAspectRatioView = aspectRatioFrameLayout;
        aspectRatioFrameLayout.setVisibility(8);
        this.fullscreenVideoContainer.addView(this.fullscreenAspectRatioView, LayoutHelper.createFrame(-1, -1, 17));
        this.fullscreenTextureView = new TextureView(activity);
        this.listView = new RecyclerListView[2];
        this.adapter = new WebpageAdapter[2];
        this.layoutManager = new LinearLayoutManager[2];
        int i2 = 0;
        while (true) {
            RecyclerListView[] recyclerListViewArr = this.listView;
            if (i2 >= recyclerListViewArr.length) {
                break;
            }
            recyclerListViewArr[i2] = new RecyclerListView(activity) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.6
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
                protected void onLayout(boolean changed, int l, int t, int r, int b) {
                    super.onLayout(changed, l, t, r, b);
                    int count = getChildCount();
                    for (int a = 0; a < count; a++) {
                        View child = getChildAt(a);
                        if (child.getTag() instanceof Integer) {
                            Integer tag = (Integer) child.getTag();
                            if (tag.intValue() == 90) {
                                int bottom = child.getBottom();
                                if (bottom < getMeasuredHeight()) {
                                    int height = getMeasuredHeight();
                                    child.layout(0, height - child.getMeasuredHeight(), child.getMeasuredWidth(), height);
                                    return;
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
                public boolean onInterceptTouchEvent(MotionEvent e) {
                    if (ArticleViewer.this.pressedLinkOwnerLayout == null || ArticleViewer.this.pressedLink != null || ((ArticleViewer.this.popupWindow != null && ArticleViewer.this.popupWindow.isShowing()) || (e.getAction() != 1 && e.getAction() != 3))) {
                        if (ArticleViewer.this.pressedLinkOwnerLayout != null && ArticleViewer.this.pressedLink != null && e.getAction() == 1) {
                            ArticleViewer articleViewer = ArticleViewer.this;
                            articleViewer.checkLayoutForLinks(e, articleViewer.pressedLinkOwnerView, ArticleViewer.this.pressedLinkOwnerLayout, 0, 0);
                        }
                    } else {
                        ArticleViewer.this.pressedLink = null;
                        ArticleViewer.this.pressedLinkOwnerLayout = null;
                        ArticleViewer.this.pressedLinkOwnerView = null;
                    }
                    return super.onInterceptTouchEvent(e);
                }

                @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
                public boolean onTouchEvent(MotionEvent e) {
                    if (ArticleViewer.this.pressedLinkOwnerLayout != null && ArticleViewer.this.pressedLink == null && ((ArticleViewer.this.popupWindow == null || !ArticleViewer.this.popupWindow.isShowing()) && (e.getAction() == 1 || e.getAction() == 3))) {
                        ArticleViewer.this.pressedLink = null;
                        ArticleViewer.this.pressedLinkOwnerLayout = null;
                        ArticleViewer.this.pressedLinkOwnerView = null;
                    }
                    return super.onTouchEvent(e);
                }

                @Override // android.view.View
                public void setTranslationX(float translationX) {
                    super.setTranslationX(translationX);
                    if (ArticleViewer.this.windowView.movingPage) {
                        ArticleViewer.this.containerView.invalidate();
                        float progress = translationX / getMeasuredWidth();
                        ArticleViewer.this.setCurrentHeaderHeight((int) (r1.windowView.startMovingHeaderHeight + ((AndroidUtilities.dp(56.0f) - ArticleViewer.this.windowView.startMovingHeaderHeight) * progress)));
                    }
                }
            };
            ((DefaultItemAnimator) this.listView[i2].getItemAnimator()).setDelayAnimations(false);
            RecyclerListView recyclerListView = this.listView[i2];
            LinearLayoutManager[] linearLayoutManagerArr = this.layoutManager;
            LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.parentActivity, 1, false);
            linearLayoutManagerArr[i2] = linearLayoutManager;
            recyclerListView.setLayoutManager(linearLayoutManager);
            WebpageAdapter[] webpageAdapterArr = this.adapter;
            final WebpageAdapter webpageAdapter = new WebpageAdapter(this.parentActivity);
            webpageAdapterArr[i2] = webpageAdapter;
            this.listView[i2].setAdapter(webpageAdapter);
            this.listView[i2].setClipToPadding(false);
            this.listView[i2].setVisibility(i2 == 0 ? 0 : 8);
            this.listView[i2].setPadding(0, AndroidUtilities.dp(56.0f), 0, 0);
            this.listView[i2].setTopGlowOffset(AndroidUtilities.dp(56.0f));
            this.containerView.addView(this.listView[i2], LayoutHelper.createFrame(-1, -1.0f));
            this.listView[i2].setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$PWiIwIv2X0bWl3oTlQehOR8aIN0
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
                public final boolean onItemClick(View view2, int i3) {
                    return this.f$0.lambda$setParentActivity$8$ArticleViewer(view2, i3);
                }
            });
            this.listView[i2].setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$N2lKWI1zW7WWVw3o1zIAlJTzMqA
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view2, int i3) {
                    this.f$0.lambda$setParentActivity$11$ArticleViewer(webpageAdapter, view2, i3);
                }
            });
            this.listView[i2].setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.7
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                    if (recyclerView.getChildCount() != 0) {
                        ArticleViewer.this.headerView.invalidate();
                        ArticleViewer.this.checkScroll(dy);
                    }
                }
            });
            i2++;
        }
        this.headerPaint.setColor(-16777216);
        this.statusBarPaint.setColor(-16777216);
        this.headerProgressPaint.setColor(-14408666);
        FrameLayout frameLayout3 = new FrameLayout(activity) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.8
            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                float viewProgress;
                int width = getMeasuredWidth();
                int height = getMeasuredHeight();
                canvas.drawRect(0.0f, 0.0f, width, height, ArticleViewer.this.headerPaint);
                if (ArticleViewer.this.layoutManager != null) {
                    int first = ArticleViewer.this.layoutManager[0].findFirstVisibleItemPosition();
                    int last = ArticleViewer.this.layoutManager[0].findLastVisibleItemPosition();
                    int count = ArticleViewer.this.layoutManager[0].getItemCount();
                    View view2 = last >= count + (-2) ? ArticleViewer.this.layoutManager[0].findViewByPosition(count - 2) : ArticleViewer.this.layoutManager[0].findViewByPosition(first);
                    if (view2 == null) {
                        return;
                    }
                    float itemProgress = width / (count - 1);
                    ArticleViewer.this.layoutManager[0].getChildCount();
                    float viewHeight = view2.getMeasuredHeight();
                    if (last >= count - 2) {
                        viewProgress = ((((count - 2) - first) * itemProgress) * (ArticleViewer.this.listView[0].getMeasuredHeight() - view2.getTop())) / viewHeight;
                    } else {
                        viewProgress = (1.0f - ((Math.min(0, view2.getTop() - ArticleViewer.this.listView[0].getPaddingTop()) + viewHeight) / viewHeight)) * itemProgress;
                    }
                    float progress = (first * itemProgress) + viewProgress;
                    canvas.drawRect(0.0f, 0.0f, progress, height, ArticleViewer.this.headerProgressPaint);
                }
            }
        };
        this.headerView = frameLayout3;
        frameLayout3.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$gLV0QQLuNKyJ4ITEnYUfU9CZqWY
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                return ArticleViewer.lambda$setParentActivity$12(view2, motionEvent);
            }
        });
        this.headerView.setWillNotDraw(false);
        this.containerView.addView(this.headerView, LayoutHelper.createFrame(-1, 56.0f));
        ImageView imageView = new ImageView(activity);
        this.backButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        BackDrawable backDrawable = new BackDrawable(false);
        this.backDrawable = backDrawable;
        backDrawable.setAnimationTime(200.0f);
        this.backDrawable.setColor(-5000269);
        this.backDrawable.setRotated(false);
        this.backButton.setImageDrawable(this.backDrawable);
        this.backButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.headerView.addView(this.backButton, LayoutHelper.createFrame(54, 56.0f));
        this.backButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$Ps7aLLhIPZIsfdeSDO5utNQQ3eI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$setParentActivity$13$ArticleViewer(view2);
            }
        });
        this.backButton.setContentDescription(LocaleController.getString("AccDescrGoBack", R.string.AccDescrGoBack));
        SimpleTextView simpleTextView = new SimpleTextView(activity);
        this.titleTextView = simpleTextView;
        simpleTextView.setGravity(19);
        this.titleTextView.setTextSize(20);
        this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.titleTextView.setTextColor(-5000269);
        this.titleTextView.setPivotX(0.0f);
        this.titleTextView.setPivotY(AndroidUtilities.dp(28.0f));
        this.headerView.addView(this.titleTextView, LayoutHelper.createFrame(-1.0f, 56.0f, 51, 72.0f, 0.0f, 96.0f, 0.0f));
        LineProgressView lineProgressView = new LineProgressView(activity);
        this.lineProgressView = lineProgressView;
        lineProgressView.setProgressColor(-1);
        this.lineProgressView.setPivotX(0.0f);
        this.lineProgressView.setPivotY(AndroidUtilities.dp(2.0f));
        this.headerView.addView(this.lineProgressView, LayoutHelper.createFrame(-1.0f, 2.0f, 83, 0.0f, 0.0f, 0.0f, 1.0f));
        this.lineProgressTickRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$XhlRoTIRdwVNDlkzt93PPU1YgDU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setParentActivity$14$ArticleViewer();
            }
        };
        LinearLayout settingsContainer = new LinearLayout(this.parentActivity);
        settingsContainer.setPadding(0, AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f));
        settingsContainer.setOrientation(1);
        int a = 0;
        while (a < 3) {
            this.colorCells[a] = new ColorCell(this.parentActivity);
            if (a == 0) {
                ImageView imageView2 = new ImageView(this.parentActivity);
                this.nightModeImageView = imageView2;
                imageView2.setScaleType(ImageView.ScaleType.CENTER);
                this.nightModeImageView.setImageResource(R.drawable.moon);
                this.nightModeImageView.setColorFilter(new PorterDuffColorFilter((!this.nightModeEnabled || this.selectedColor == 2) ? -3355444 : -15428119, PorterDuff.Mode.MULTIPLY));
                this.nightModeImageView.setBackgroundDrawable(Theme.createSelectorDrawable(251658240));
                this.colorCells[a].addView(this.nightModeImageView, LayoutHelper.createFrame(48, 48, (LocaleController.isRTL ? 3 : 5) | 48));
                this.nightModeImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$_HgpNYOPZZaOS09aDxdh3zA7pjg
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$setParentActivity$15$ArticleViewer(view2);
                    }
                });
                this.colorCells[a].setTextAndColor(LocaleController.getString("ColorWhite", R.string.ColorWhite), -1);
            } else if (a != 1) {
                if (a == 2) {
                    this.colorCells[a].setTextAndColor(LocaleController.getString("ColorDark", R.string.ColorDark), -14474461);
                }
            } else {
                this.colorCells[a].setTextAndColor(LocaleController.getString("ColorSepia", R.string.ColorSepia), -1382967);
            }
            this.colorCells[a].select(a == this.selectedColor);
            this.colorCells[a].setTag(Integer.valueOf(a));
            this.colorCells[a].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$UXqEJr6LRP5xQQ6iOOlJvr1aLMk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$setParentActivity$16$ArticleViewer(view2);
                }
            });
            settingsContainer.addView(this.colorCells[a], LayoutHelper.createLinear(-1, 50));
            a++;
        }
        updateNightModeButton();
        View divider = new View(this.parentActivity);
        divider.setBackgroundColor(-2039584);
        settingsContainer.addView(divider, LayoutHelper.createLinear(-1, 1, 15.0f, 4.0f, 15.0f, 4.0f));
        divider.getLayoutParams().height = 1;
        int a2 = 0;
        while (a2 < 2) {
            this.fontCells[a2] = new FontCell(this.parentActivity);
            if (a2 == 0) {
                this.fontCells[a2].setTextAndTypeface("Roboto", Typeface.DEFAULT);
            } else if (a2 == 1) {
                this.fontCells[a2].setTextAndTypeface("Serif", Typeface.SERIF);
            }
            this.fontCells[a2].select(a2 == this.selectedFont);
            this.fontCells[a2].setTag(Integer.valueOf(a2));
            this.fontCells[a2].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$C7jjBsCkKVAI_38WSyI7nIr6ZgM
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$setParentActivity$17$ArticleViewer(view2);
                }
            });
            settingsContainer.addView(this.fontCells[a2], LayoutHelper.createLinear(-1, 50));
            a2++;
        }
        View divider2 = new View(this.parentActivity);
        divider2.setBackgroundColor(-2039584);
        settingsContainer.addView(divider2, LayoutHelper.createLinear(-1, 1, 15.0f, 4.0f, 15.0f, 4.0f));
        divider2.getLayoutParams().height = 1;
        TextView textView = new TextView(this.parentActivity);
        textView.setTextColor(-14606047);
        textView.setTextSize(1, 16.0f);
        textView.setLines(1);
        textView.setMaxLines(1);
        textView.setSingleLine(true);
        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        textView.setText(LocaleController.getString("FontSize", R.string.FontSize));
        settingsContainer.addView(textView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 17, 12, 17, 0));
        SizeChooseView sizeChooseView = new SizeChooseView(this.parentActivity);
        settingsContainer.addView(sizeChooseView, LayoutHelper.createLinear(-1, 38, 0.0f, 0.0f, 0.0f, 1.0f));
        ActionBarMenuItem actionBarMenuItem = new ActionBarMenuItem(this.parentActivity, null, Theme.ACTION_BAR_WHITE_SELECTOR_COLOR, -1);
        this.settingsButton = actionBarMenuItem;
        actionBarMenuItem.setPopupAnimationEnabled(false);
        this.settingsButton.setLayoutInScreen(true);
        TextView textView2 = new TextView(this.parentActivity);
        textView2.setTextSize(1, 18.0f);
        textView2.setText("Aa");
        textView2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView2.setTextColor(-5000269);
        textView2.setGravity(17);
        textView2.setImportantForAccessibility(2);
        this.settingsButton.addView(textView2, LayoutHelper.createFrame(-1, -1.0f));
        this.settingsButton.addSubItem(settingsContainer, AndroidUtilities.dp(220.0f), -2);
        this.settingsButton.redrawPopup(-1);
        this.settingsButton.setContentDescription(LocaleController.getString("Settings", R.string.Settings));
        this.headerView.addView(this.settingsButton, LayoutHelper.createFrame(48.0f, 56.0f, 53, 0.0f, 0.0f, 56.0f, 0.0f));
        FrameLayout frameLayout4 = new FrameLayout(activity);
        this.shareContainer = frameLayout4;
        this.headerView.addView(frameLayout4, LayoutHelper.createFrame(48, 56, 53));
        this.shareContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$hk5GlwOeGxj1QHp9sI1DDzjwoK4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$setParentActivity$18$ArticleViewer(view2);
            }
        });
        ImageView imageView3 = new ImageView(activity);
        this.shareButton = imageView3;
        imageView3.setScaleType(ImageView.ScaleType.CENTER);
        this.shareButton.setImageResource(R.drawable.ic_share_article);
        this.shareButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.shareButton.setContentDescription(LocaleController.getString("ShareFile", R.string.ShareFile));
        this.shareContainer.addView(this.shareButton, LayoutHelper.createFrame(48, 56.0f));
        ContextProgressView contextProgressView = new ContextProgressView(activity, 2);
        this.progressView = contextProgressView;
        contextProgressView.setVisibility(8);
        this.shareContainer.addView(this.progressView, LayoutHelper.createFrame(48, 56.0f));
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
        this.windowLayoutParams = layoutParams;
        layoutParams.height = -1;
        this.windowLayoutParams.format = -3;
        this.windowLayoutParams.width = -1;
        this.windowLayoutParams.gravity = 51;
        this.windowLayoutParams.type = 99;
        if (Build.VERSION.SDK_INT >= 21) {
            this.windowLayoutParams.flags = -2147417848;
            if (Build.VERSION.SDK_INT >= 28) {
                this.windowLayoutParams.layoutInDisplayCutoutMode = 1;
            }
        } else {
            this.windowLayoutParams.flags = 8;
        }
        if (progressDrawables == null) {
            Drawable[] drawableArr = new Drawable[4];
            progressDrawables = drawableArr;
            drawableArr[0] = this.parentActivity.getResources().getDrawable(R.drawable.circle_big);
            progressDrawables[1] = this.parentActivity.getResources().getDrawable(R.drawable.cancel_big);
            progressDrawables[2] = this.parentActivity.getResources().getDrawable(R.drawable.load_big);
            progressDrawables[3] = this.parentActivity.getResources().getDrawable(R.drawable.play_big);
        }
        this.scroller = new Scroller(activity);
        this.blackPaint.setColor(-16777216);
        ActionBar actionBar = new ActionBar(activity);
        this.actionBar = actionBar;
        actionBar.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.actionBar.setOccupyStatusBar(false);
        this.actionBar.setTitleColor(-1);
        this.actionBar.setItemsBackgroundColor(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR, false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, 1, 1));
        this.photoContainerView.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.9
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int i3) {
                if (i3 == -1) {
                    ArticleViewer.this.closePhoto(true);
                    return;
                }
                if (i3 != 1) {
                    if (i3 == 2) {
                        ArticleViewer.this.onSharePressed();
                        return;
                    }
                    if (i3 == 3) {
                        try {
                            AndroidUtilities.openForView(ArticleViewer.this.getMedia(ArticleViewer.this.currentIndex), ArticleViewer.this.parentActivity);
                            ArticleViewer.this.closePhoto(false);
                            return;
                        } catch (Exception e) {
                            FileLog.e(e);
                            return;
                        }
                    }
                    return;
                }
                if (Build.VERSION.SDK_INT >= 23 && ArticleViewer.this.parentActivity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
                    ArticleViewer.this.parentActivity.requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 4);
                    return;
                }
                ArticleViewer articleViewer = ArticleViewer.this;
                File mediaFile = articleViewer.getMediaFile(articleViewer.currentIndex);
                if (mediaFile != null && mediaFile.exists()) {
                    String string = mediaFile.toString();
                    Activity activity2 = ArticleViewer.this.parentActivity;
                    ArticleViewer articleViewer2 = ArticleViewer.this;
                    MediaController.saveFile(string, activity2, articleViewer2.isMediaVideo(articleViewer2.currentIndex) ? 1 : 0, null, null);
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(ArticleViewer.this.parentActivity);
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                builder.setMessage(LocaleController.getString("PleaseDownload", R.string.PleaseDownload));
                ArticleViewer.this.showDialog(builder.create());
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public boolean canOpenMenu() {
                ArticleViewer articleViewer = ArticleViewer.this;
                File f = articleViewer.getMediaFile(articleViewer.currentIndex);
                return f != null && f.exists();
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(2, R.drawable.share);
        ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(0, R.drawable.ic_ab_other);
        this.menuItem = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.setLayoutInScreen(true);
        this.menuItem.addSubItem(3, R.drawable.msg_openin, LocaleController.getString("OpenInExternalApp", R.string.OpenInExternalApp)).setColors(-328966, -328966);
        this.menuItem.addSubItem(1, R.drawable.msg_gallery, LocaleController.getString("SaveToGallery", R.string.SaveToGallery)).setColors(-328966, -328966);
        this.menuItem.redrawPopup(-115203550);
        FrameLayout frameLayout5 = new FrameLayout(this.parentActivity);
        this.bottomLayout = frameLayout5;
        frameLayout5.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.photoContainerView.addView(this.bottomLayout, LayoutHelper.createFrame(-1, 48, 83));
        GroupedPhotosListView groupedPhotosListView = new GroupedPhotosListView(this.parentActivity);
        this.groupedPhotosListView = groupedPhotosListView;
        this.photoContainerView.addView(groupedPhotosListView, LayoutHelper.createFrame(-1.0f, 62.0f, 83, 0.0f, 0.0f, 0.0f, 0.0f));
        this.groupedPhotosListView.setDelegate(new GroupedPhotosListView.GroupedPhotosListViewDelegate() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.10
            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getCurrentIndex() {
                return ArticleViewer.this.currentIndex;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getCurrentAccount() {
                return ArticleViewer.this.currentAccount;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getAvatarsDialogId() {
                return 0;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getSlideshowMessageId() {
                return 0;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<ImageLocation> getImagesArrLocations() {
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<MessageObject> getImagesArr() {
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<TLRPC.PageBlock> getPageBlockArr() {
                return ArticleViewer.this.imagesArr;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public Object getParentObject() {
                return ArticleViewer.this.currentPage;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public void setCurrentIndex(int index) {
                ArticleViewer.this.currentIndex = -1;
                if (ArticleViewer.this.currentThumb != null) {
                    ArticleViewer.this.currentThumb.release();
                    ArticleViewer.this.currentThumb = null;
                }
                ArticleViewer.this.setImageIndex(index, true);
            }
        });
        TextView textView3 = new TextView(activity);
        this.captionTextViewNext = textView3;
        textView3.setMaxLines(10);
        this.captionTextViewNext.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.captionTextViewNext.setMovementMethod(new LinkMovementMethodMy());
        this.captionTextViewNext.setPadding(AndroidUtilities.dp(20.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(20.0f), AndroidUtilities.dp(8.0f));
        this.captionTextViewNext.setLinkTextColor(-1);
        this.captionTextViewNext.setTextColor(-1);
        this.captionTextViewNext.setHighlightColor(872415231);
        this.captionTextViewNext.setGravity(19);
        this.captionTextViewNext.setTextSize(1, 16.0f);
        this.captionTextViewNext.setVisibility(8);
        this.photoContainerView.addView(this.captionTextViewNext, LayoutHelper.createFrame(-1, -2, 83));
        TextView textView4 = new TextView(activity);
        this.captionTextView = textView4;
        textView4.setMaxLines(10);
        this.captionTextView.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.captionTextView.setMovementMethod(new LinkMovementMethodMy());
        this.captionTextView.setPadding(AndroidUtilities.dp(20.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(20.0f), AndroidUtilities.dp(8.0f));
        this.captionTextView.setLinkTextColor(-1);
        this.captionTextView.setTextColor(-1);
        this.captionTextView.setHighlightColor(872415231);
        this.captionTextView.setGravity(19);
        this.captionTextView.setTextSize(1, 16.0f);
        this.captionTextView.setVisibility(8);
        this.photoContainerView.addView(this.captionTextView, LayoutHelper.createFrame(-1, -2, 83));
        this.radialProgressViews[0] = new RadialProgressView(activity, this.photoContainerView);
        this.radialProgressViews[0].setBackgroundState(0, false);
        this.radialProgressViews[1] = new RadialProgressView(activity, this.photoContainerView);
        this.radialProgressViews[1].setBackgroundState(0, false);
        this.radialProgressViews[2] = new RadialProgressView(activity, this.photoContainerView);
        this.radialProgressViews[2].setBackgroundState(0, false);
        SeekBar seekBar = new SeekBar(activity);
        this.videoPlayerSeekbar = seekBar;
        seekBar.setColors(1728053247, 1728053247, -2764585, -1, -1);
        this.videoPlayerSeekbar.setDelegate(new SeekBar.SeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$Epfju06VRPeo8vqsMwubzdZqQok
            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public /* synthetic */ void onSeekBarContinuousDrag(float f) {
                SeekBar.SeekBarDelegate.CC.$default$onSeekBarContinuousDrag(this, f);
            }

            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public final void onSeekBarDrag(float f) {
                this.f$0.lambda$setParentActivity$19$ArticleViewer(f);
            }
        });
        FrameLayout frameLayout6 = new FrameLayout(activity) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.11
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (ArticleViewer.this.videoPlayerSeekbar.onTouch(event.getAction(), event.getX() - AndroidUtilities.dp(48.0f), event.getY())) {
                    getParent().requestDisallowInterceptTouchEvent(true);
                    invalidate();
                    return true;
                }
                return super.onTouchEvent(event);
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                long duration;
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                if (ArticleViewer.this.videoPlayer != null) {
                    duration = ArticleViewer.this.videoPlayer.getDuration();
                    if (duration == C.TIME_UNSET) {
                        duration = 0;
                    }
                } else {
                    duration = 0;
                }
                long duration2 = duration / 1000;
                int size = (int) Math.ceil(ArticleViewer.this.videoPlayerTime.getPaint().measureText(String.format("%02d:%02d / %02d:%02d", Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60), Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60))));
                ArticleViewer.this.videoPlayerSeekbar.setSize((getMeasuredWidth() - AndroidUtilities.dp(64.0f)) - size, getMeasuredHeight());
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                float progress = 0.0f;
                if (ArticleViewer.this.videoPlayer != null) {
                    progress = ArticleViewer.this.videoPlayer.getCurrentPosition() / ArticleViewer.this.videoPlayer.getDuration();
                }
                ArticleViewer.this.videoPlayerSeekbar.setProgress(progress);
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                canvas.save();
                canvas.translate(AndroidUtilities.dp(48.0f), 0.0f);
                ArticleViewer.this.videoPlayerSeekbar.draw(canvas);
                canvas.restore();
            }
        };
        this.videoPlayerControlFrameLayout = frameLayout6;
        frameLayout6.setWillNotDraw(false);
        this.bottomLayout.addView(this.videoPlayerControlFrameLayout, LayoutHelper.createFrame(-1, -1, 51));
        ImageView imageView4 = new ImageView(activity);
        this.videoPlayButton = imageView4;
        imageView4.setScaleType(ImageView.ScaleType.CENTER);
        this.videoPlayerControlFrameLayout.addView(this.videoPlayButton, LayoutHelper.createFrame(48, 48, 51));
        this.videoPlayButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$_7Ut6cUAXEEuj95Pb4W1V_gU92c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$setParentActivity$20$ArticleViewer(view2);
            }
        });
        TextView textView5 = new TextView(activity);
        this.videoPlayerTime = textView5;
        textView5.setTextColor(-1);
        this.videoPlayerTime.setGravity(16);
        this.videoPlayerTime.setTextSize(1, 13.0f);
        this.videoPlayerControlFrameLayout.addView(this.videoPlayerTime, LayoutHelper.createFrame(-2.0f, -1.0f, 53, 0.0f, 0.0f, 8.0f, 0.0f));
        GestureDetector gestureDetector = new GestureDetector(activity, this);
        this.gestureDetector = gestureDetector;
        gestureDetector.setOnDoubleTapListener(this);
        this.centerImage.setParentView(this.photoContainerView);
        this.centerImage.setCrossfadeAlpha((byte) 2);
        this.centerImage.setInvalidateAll(true);
        this.leftImage.setParentView(this.photoContainerView);
        this.leftImage.setCrossfadeAlpha((byte) 2);
        this.leftImage.setInvalidateAll(true);
        this.rightImage.setParentView(this.photoContainerView);
        this.rightImage.setCrossfadeAlpha((byte) 2);
        this.rightImage.setInvalidateAll(true);
        updatePaintColors();
    }

    public /* synthetic */ WindowInsets lambda$setParentActivity$7$ArticleViewer(View v, WindowInsets insets) {
        DisplayCutout cutout;
        List<Rect> rects;
        WindowInsets oldInsets = (WindowInsets) this.lastInsets;
        this.lastInsets = insets;
        if (oldInsets == null || !oldInsets.toString().equals(insets.toString())) {
            this.windowView.requestLayout();
        }
        if (Build.VERSION.SDK_INT >= 28 && (cutout = this.parentActivity.getWindow().getDecorView().getRootWindowInsets().getDisplayCutout()) != null && (rects = cutout.getBoundingRects()) != null && !rects.isEmpty()) {
            this.hasCutout = rects.get(0).height() != 0;
        }
        return insets.consumeSystemWindowInsets();
    }

    public /* synthetic */ boolean lambda$setParentActivity$8$ArticleViewer(View view, int position) {
        if (view instanceof BlockRelatedArticlesCell) {
            BlockRelatedArticlesCell cell = (BlockRelatedArticlesCell) view;
            showCopyPopup(cell.currentBlock.parent.articles.get(cell.currentBlock.num).url);
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$setParentActivity$11$ArticleViewer(WebpageAdapter webpageAdapter, View view, int position) {
        if (position == webpageAdapter.localBlocks.size() && this.currentPage != null) {
            if (this.previewsReqId != 0) {
                return;
            }
            TLObject object = MessagesController.getInstance(this.currentAccount).getUserOrChat("previews");
            if (object instanceof TLRPC.TL_user) {
                openPreviewsChat((TLRPC.User) object, this.currentPage.id);
                return;
            }
            final int currentAccount = UserConfig.selectedAccount;
            final long pageId = this.currentPage.id;
            showProgressView(true, true);
            TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
            req.username = "previews";
            this.previewsReqId = ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$r7fMIG-ZZJV3kK4TLJlVlBJ17dg
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$10$ArticleViewer(currentAccount, pageId, tLObject, tL_error);
                }
            });
            return;
        }
        if (position < 0 || position >= webpageAdapter.localBlocks.size()) {
            return;
        }
        TLRPC.PageBlock pageBlock = (TLRPC.PageBlock) webpageAdapter.localBlocks.get(position);
        TLRPC.PageBlock pageBlock2 = getLastNonListPageBlock(pageBlock);
        if (pageBlock2 instanceof TL_pageBlockDetailsChild) {
            TL_pageBlockDetailsChild detailsChild = (TL_pageBlockDetailsChild) pageBlock2;
            pageBlock2 = detailsChild.block;
        }
        if (pageBlock2 instanceof TLRPC.TL_pageBlockChannel) {
            TLRPC.TL_pageBlockChannel pageBlockChannel = (TLRPC.TL_pageBlockChannel) pageBlock2;
            MessagesController.getInstance(this.currentAccount).openByUserName(pageBlockChannel.channel.username, this.parentFragment, 2);
            close(false, true);
            return;
        }
        if (pageBlock2 instanceof TL_pageBlockRelatedArticlesChild) {
            TL_pageBlockRelatedArticlesChild pageBlockRelatedArticlesChild = (TL_pageBlockRelatedArticlesChild) pageBlock2;
            openWebpageUrl(pageBlockRelatedArticlesChild.parent.articles.get(pageBlockRelatedArticlesChild.num).url, null);
            return;
        }
        if (pageBlock2 instanceof TLRPC.TL_pageBlockDetails) {
            View view2 = getLastNonListCell(view);
            if (!(view2 instanceof BlockDetailsCell)) {
                return;
            }
            this.pressedLinkOwnerLayout = null;
            this.pressedLinkOwnerView = null;
            int index = webpageAdapter.blocks.indexOf(pageBlock);
            if (index < 0) {
                return;
            }
            TLRPC.TL_pageBlockDetails pageBlockDetails = (TLRPC.TL_pageBlockDetails) pageBlock2;
            pageBlockDetails.open = true ^ pageBlockDetails.open;
            int oldCount = webpageAdapter.getItemCount();
            webpageAdapter.updateRows();
            int newCount = webpageAdapter.getItemCount();
            int changeCount = Math.abs(newCount - oldCount);
            BlockDetailsCell cell = (BlockDetailsCell) view2;
            cell.arrow.setAnimationProgressAnimated(pageBlockDetails.open ? 0.0f : 1.0f);
            cell.invalidate();
            if (changeCount != 0) {
                if (pageBlockDetails.open) {
                    webpageAdapter.notifyItemRangeInserted(position + 1, changeCount);
                } else {
                    webpageAdapter.notifyItemRangeRemoved(position + 1, changeCount);
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$10$ArticleViewer(final int currentAccount, final long pageId, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$CuLEL8SYSgqIEXFs6B6CguN_G2Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$9$ArticleViewer(response, currentAccount, pageId);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$ArticleViewer(TLObject response, int currentAccount, long pageId) {
        if (this.previewsReqId == 0) {
            return;
        }
        this.previewsReqId = 0;
        showProgressView(true, false);
        if (response != null) {
            TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
            MessagesController.getInstance(currentAccount).putUsers(res.users, false);
            MessagesStorage.getInstance(currentAccount).putUsersAndChats(res.users, res.chats, false, true);
            if (!res.users.isEmpty()) {
                openPreviewsChat(res.users.get(0), pageId);
            }
        }
    }

    static /* synthetic */ boolean lambda$setParentActivity$12(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$setParentActivity$13$ArticleViewer(View v) {
        close(true, true);
    }

    public /* synthetic */ void lambda$setParentActivity$14$ArticleViewer() {
        float tick;
        float progressLeft = 0.7f - this.lineProgressView.getCurrentProgress();
        if (progressLeft > 0.0f) {
            if (progressLeft < 0.25f) {
                tick = 0.01f;
            } else {
                tick = 0.02f;
            }
            LineProgressView lineProgressView = this.lineProgressView;
            lineProgressView.setProgress(lineProgressView.getCurrentProgress() + tick, true);
            AndroidUtilities.runOnUIThread(this.lineProgressTickRunnable, 100L);
        }
    }

    public /* synthetic */ void lambda$setParentActivity$15$ArticleViewer(View v) {
        this.nightModeEnabled = !this.nightModeEnabled;
        ApplicationLoader.applicationContext.getSharedPreferences("articles", 0).edit().putBoolean("nightModeEnabled", this.nightModeEnabled).commit();
        updateNightModeButton();
        updatePaintColors();
        for (int i = 0; i < this.listView.length; i++) {
            this.adapter[i].notifyDataSetChanged();
        }
        if (this.nightModeEnabled) {
            showNightModeHint();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$16$ArticleViewer(View v) {
        int num = ((Integer) v.getTag()).intValue();
        this.selectedColor = num;
        int a12 = 0;
        while (a12 < 3) {
            this.colorCells[a12].select(a12 == num);
            a12++;
        }
        updateNightModeButton();
        updatePaintColors();
        for (int i = 0; i < this.listView.length; i++) {
            this.adapter[i].notifyDataSetChanged();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$17$ArticleViewer(View v) {
        int num = ((Integer) v.getTag()).intValue();
        this.selectedFont = num;
        int a1 = 0;
        while (a1 < 2) {
            this.fontCells[a1].select(a1 == num);
            a1++;
        }
        updatePaintFonts();
        for (int i = 0; i < this.listView.length; i++) {
            this.adapter[i].notifyDataSetChanged();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$18$ArticleViewer(View v) {
        if (this.currentPage == null || this.parentActivity == null) {
            return;
        }
        showDialog(new ShareAlert(this.parentActivity, null, this.currentPage.url, false, this.currentPage.url, true));
    }

    public /* synthetic */ void lambda$setParentActivity$19$ArticleViewer(float progress) {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.seekTo((int) (videoPlayer.getDuration() * progress));
        }
    }

    public /* synthetic */ void lambda$setParentActivity$20$ArticleViewer(View v) {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            if (this.isPlaying) {
                videoPlayer.pause();
            } else {
                videoPlayer.play();
            }
        }
    }

    private void showNightModeHint() {
        if (this.parentActivity == null || this.nightModeHintView != null || !this.nightModeEnabled) {
            return;
        }
        FrameLayout frameLayout = new FrameLayout(this.parentActivity);
        this.nightModeHintView = frameLayout;
        frameLayout.setBackgroundColor(Theme.ACTION_BAR_MEDIA_PICKER_COLOR);
        this.containerView.addView(this.nightModeHintView, LayoutHelper.createFrame(-1, -2, 83));
        ImageView nightModeImageView = new ImageView(this.parentActivity);
        nightModeImageView.setScaleType(ImageView.ScaleType.CENTER);
        nightModeImageView.setImageResource(R.drawable.moon);
        this.nightModeHintView.addView(nightModeImageView, LayoutHelper.createFrame(56, 56, (LocaleController.isRTL ? 5 : 3) | 16));
        TextView textView = new TextView(this.parentActivity);
        textView.setText(LocaleController.getString("InstantViewNightMode", R.string.InstantViewNightMode));
        textView.setTextColor(-1);
        textView.setTextSize(1, 15.0f);
        this.nightModeHintView.addView(textView, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 10 : 56, 11.0f, LocaleController.isRTL ? 56 : 10, 12.0f));
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.nightModeHintView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(100.0f), 0.0f));
        animatorSet.setInterpolator(new DecelerateInterpolator(1.5f));
        animatorSet.addListener(new AnonymousClass12());
        animatorSet.setDuration(250L);
        animatorSet.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ArticleViewer$12, reason: invalid class name */
    class AnonymousClass12 extends AnimatorListenerAdapter {
        AnonymousClass12() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$12$qYN-tZ2cs7a34HAELjZgBvIwLyg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ArticleViewer$12();
                }
            }, 3000L);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ArticleViewer$12() {
            AnimatorSet animatorSet1 = new AnimatorSet();
            animatorSet1.playTogether(ObjectAnimator.ofFloat(ArticleViewer.this.nightModeHintView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(100.0f)));
            animatorSet1.setInterpolator(new DecelerateInterpolator(1.5f));
            animatorSet1.setDuration(250L);
            animatorSet1.start();
        }
    }

    private void updateNightModeButton() {
        this.nightModeImageView.setEnabled(this.selectedColor != 2);
        this.nightModeImageView.setAlpha(this.selectedColor == 2 ? 0.5f : 1.0f);
        this.nightModeImageView.setColorFilter(new PorterDuffColorFilter((!this.nightModeEnabled || this.selectedColor == 2) ? -3355444 : -15428119, PorterDuff.Mode.MULTIPLY));
    }

    public class ScrollEvaluator extends IntEvaluator {
        public ScrollEvaluator() {
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.animation.TypeEvaluator
        public Integer evaluate(float fraction, Integer startValue, Integer endValue) {
            return super.evaluate(fraction, startValue, endValue);
        }
    }

    private void checkScrollAnimated() {
        int maxHeight = AndroidUtilities.dp(56.0f);
        if (this.currentHeaderHeight == maxHeight) {
            return;
        }
        ValueAnimator va = ValueAnimator.ofObject(new IntEvaluator(), Integer.valueOf(this.currentHeaderHeight), Integer.valueOf(AndroidUtilities.dp(56.0f))).setDuration(180L);
        va.setInterpolator(new DecelerateInterpolator());
        va.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$IVhj8gs-_n4ychPU3Rk6rR2pzsM
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                this.f$0.lambda$checkScrollAnimated$21$ArticleViewer(valueAnimator);
            }
        });
        va.start();
    }

    public /* synthetic */ void lambda$checkScrollAnimated$21$ArticleViewer(ValueAnimator animation) {
        setCurrentHeaderHeight(((Integer) animation.getAnimatedValue()).intValue());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCurrentHeaderHeight(int newHeight) {
        int maxHeight = AndroidUtilities.dp(56.0f);
        int minHeight = Math.max(AndroidUtilities.statusBarHeight, AndroidUtilities.dp(24.0f));
        if (newHeight < minHeight) {
            newHeight = minHeight;
        } else if (newHeight > maxHeight) {
            newHeight = maxHeight;
        }
        float heightDiff = maxHeight - minHeight;
        this.currentHeaderHeight = newHeight;
        float scale = (((newHeight - minHeight) / heightDiff) * 0.2f) + 0.8f;
        float scale2 = (((newHeight - minHeight) / heightDiff) * 0.5f) + 0.5f;
        this.backButton.setScaleX(scale);
        this.backButton.setScaleY(scale);
        this.backButton.setTranslationY((maxHeight - this.currentHeaderHeight) / 2);
        this.shareContainer.setScaleX(scale);
        this.shareContainer.setScaleY(scale);
        this.settingsButton.setScaleX(scale);
        this.settingsButton.setScaleY(scale);
        this.titleTextView.setScaleX(scale);
        this.titleTextView.setScaleY(scale);
        this.lineProgressView.setScaleY(scale2);
        this.shareContainer.setTranslationY((maxHeight - this.currentHeaderHeight) / 2);
        this.settingsButton.setTranslationY((maxHeight - this.currentHeaderHeight) / 2);
        this.titleTextView.setTranslationY((maxHeight - this.currentHeaderHeight) / 2);
        this.headerView.setTranslationY(this.currentHeaderHeight - maxHeight);
        int i = 0;
        while (true) {
            RecyclerListView[] recyclerListViewArr = this.listView;
            if (i < recyclerListViewArr.length) {
                recyclerListViewArr[i].setTopGlowOffset(this.currentHeaderHeight);
                i++;
            } else {
                return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkScroll(int dy) {
        setCurrentHeaderHeight(this.currentHeaderHeight - dy);
    }

    private void openPreviewsChat(TLRPC.User user, long wid) {
        if (user == null || this.parentActivity == null) {
            return;
        }
        Bundle args = new Bundle();
        args.putInt("user_id", user.id);
        args.putString("botUser", "webpage" + wid);
        ((LaunchActivity) this.parentActivity).presentFragment(new ChatActivity(args), false, true);
        close(false, true);
    }

    public boolean open(MessageObject messageObject) {
        return open(messageObject, null, null, true);
    }

    public boolean open(TLRPC.TL_webPage webpage, String url) {
        return open(null, webpage, url, true);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v61, types: [java.lang.CharSequence, java.lang.String] */
    /* JADX WARN: Type inference failed for: r0v65 */
    /* JADX WARN: Type inference failed for: r0v66 */
    /* JADX WARN: Type inference failed for: r10v2 */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v12 */
    /* JADX WARN: Type inference failed for: r5v13 */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v15, types: [java.lang.CharSequence, java.lang.String] */
    /* JADX WARN: Type inference failed for: r5v16 */
    private boolean open(final MessageObject messageObject, TLRPC.WebPage webPage, String str, boolean z) {
        TLRPC.WebPage webPage2;
        TLRPC.WebPage webPage3;
        String strSubstring;
        int iLastIndexOf;
        Paint paint;
        ?? lowerCase;
        if (this.parentActivity != null) {
            if (this.isVisible && !this.collapsed) {
                return false;
            }
            if (messageObject == null && webPage == null) {
                return false;
            }
            if (messageObject == null) {
                webPage2 = webPage;
            } else {
                webPage2 = messageObject.messageOwner.media.webpage;
            }
            String strSubstring2 = null;
            int i = -1;
            if (messageObject != null) {
                TLRPC.WebPage webPage4 = messageObject.messageOwner.media.webpage;
                int i2 = 0;
                ?? lowerCase2 = str;
                while (true) {
                    if (i2 >= messageObject.messageOwner.entities.size()) {
                        break;
                    }
                    TLRPC.MessageEntity messageEntity = messageObject.messageOwner.entities.get(i2);
                    if (messageEntity instanceof TLRPC.TL_messageEntityUrl) {
                        try {
                            lowerCase2 = messageObject.messageOwner.message.substring(messageEntity.offset, messageEntity.offset + messageEntity.length).toLowerCase();
                            if (!TextUtils.isEmpty(webPage4.cached_page.url)) {
                                lowerCase = webPage4.cached_page.url.toLowerCase();
                            } else {
                                lowerCase = webPage4.url.toLowerCase();
                            }
                            if (!lowerCase2.contains(lowerCase) && !lowerCase.contains(lowerCase2)) {
                            }
                            int iLastIndexOf2 = lowerCase2.lastIndexOf(35);
                            if (iLastIndexOf2 == i) {
                                break;
                            }
                            strSubstring2 = lowerCase2.substring(iLastIndexOf2 + 1);
                            break;
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                    i2++;
                    lowerCase2 = lowerCase2;
                }
                webPage3 = webPage4;
                strSubstring = strSubstring2;
            } else if (str == null || (iLastIndexOf = str.lastIndexOf(35)) == -1) {
                webPage3 = webPage2;
                strSubstring = null;
            } else {
                webPage3 = webPage2;
                strSubstring = str.substring(iLastIndexOf + 1);
            }
            this.pagesStack.clear();
            this.collapsed = false;
            this.backDrawable.setRotation(0.0f, false);
            this.containerView.setTranslationX(0.0f);
            this.containerView.setTranslationY(0.0f);
            this.listView[0].setTranslationY(0.0f);
            this.listView[0].setTranslationX(0.0f);
            this.listView[1].setTranslationX(0.0f);
            this.listView[0].setAlpha(1.0f);
            this.windowView.setInnerTranslationX(0.0f);
            this.actionBar.setVisibility(8);
            this.bottomLayout.setVisibility(8);
            this.captionTextView.setVisibility(8);
            this.captionTextViewNext.setVisibility(8);
            this.layoutManager[0].scrollToPositionWithOffset(0, 0);
            if (z) {
                setCurrentHeaderHeight(AndroidUtilities.dp(56.0f));
            } else {
                checkScrollAnimated();
            }
            boolean zAddPageToStack = addPageToStack(webPage3, strSubstring, 0);
            if (!z) {
                paint = null;
            } else {
                final String str2 = (zAddPageToStack || strSubstring == null) ? null : strSubstring;
                TLRPC.TL_messages_getWebPage tL_messages_getWebPage = new TLRPC.TL_messages_getWebPage();
                tL_messages_getWebPage.url = webPage3.url;
                if ((webPage3.cached_page instanceof TLRPC.TL_pagePart_layer82) || webPage3.cached_page.part) {
                    tL_messages_getWebPage.hash = 0;
                } else {
                    tL_messages_getWebPage.hash = webPage3.hash;
                }
                final TLRPC.WebPage webPage5 = webPage3;
                final int i3 = UserConfig.selectedAccount;
                paint = null;
                ConnectionsManager.getInstance(i3).sendRequest(tL_messages_getWebPage, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$dEPEgWxC4nXIyUqeXZTi8wXEmHE
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$open$23$ArticleViewer(webPage5, messageObject, str2, i3, tLObject, tL_error);
                    }
                });
            }
            this.lastInsets = paint;
            if (!this.isVisible) {
                WindowManager windowManager = (WindowManager) this.parentActivity.getSystemService("window");
                if (this.attachedToWindow) {
                    try {
                        windowManager.removeView(this.windowView);
                    } catch (Exception e2) {
                    }
                }
                try {
                    if (Build.VERSION.SDK_INT >= 21) {
                        this.windowLayoutParams.flags = -2147417856;
                        if (Build.VERSION.SDK_INT >= 28) {
                            this.windowLayoutParams.layoutInDisplayCutoutMode = 1;
                        }
                    }
                    this.windowLayoutParams.flags |= 1032;
                    this.windowView.setFocusable(false);
                    this.containerView.setFocusable(false);
                    windowManager.addView(this.windowView, this.windowLayoutParams);
                } catch (Exception e3) {
                    FileLog.e(e3);
                    return false;
                }
            } else {
                this.windowLayoutParams.flags &= -17;
                ((WindowManager) this.parentActivity.getSystemService("window")).updateViewLayout(this.windowView, this.windowLayoutParams);
            }
            this.isVisible = true;
            this.animationInProgress = 1;
            this.windowView.setAlpha(0.0f);
            this.containerView.setAlpha(0.0f);
            final AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(ObjectAnimator.ofFloat(this.windowView, (Property<WindowView, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.windowView, (Property<WindowView, Float>) View.TRANSLATION_X, AndroidUtilities.dp(56.0f), 0.0f));
            this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$vTTEySCik54tlSqkmDS4Gy9-VpI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$open$24$ArticleViewer();
                }
            };
            animatorSet.setDuration(150L);
            animatorSet.setInterpolator(this.interpolator);
            animatorSet.addListener(new AnonymousClass13());
            this.transitionAnimationStartTime = System.currentTimeMillis();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$T0e33x9fmB4M6Q3Hm_fo4SPJ0_8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$open$25$ArticleViewer(animatorSet);
                }
            });
            if (Build.VERSION.SDK_INT >= 18) {
                this.containerView.setLayerType(2, paint);
            }
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$open$23$ArticleViewer(final TLRPC.WebPage webPageFinal, final MessageObject messageObject, final String anchorFinal, int currentAccount, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_webPage) {
            final TLRPC.TL_webPage webPage = (TLRPC.TL_webPage) response;
            if (webPage.cached_page == null) {
                return;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$2SfDNsKoaeC8IP73M1t2KnYZ9E4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$22$ArticleViewer(webPageFinal, webPage, messageObject, anchorFinal);
                }
            });
            LongSparseArray<TLRPC.WebPage> webpages = new LongSparseArray<>(1);
            webpages.put(webPage.id, webPage);
            MessagesStorage.getInstance(currentAccount).putWebPages(webpages);
        }
    }

    public /* synthetic */ void lambda$null$22$ArticleViewer(TLRPC.WebPage webPageFinal, TLRPC.TL_webPage webPage, MessageObject messageObject, String anchorFinal) {
        if (!this.pagesStack.isEmpty() && this.pagesStack.get(0) == webPageFinal && webPage.cached_page != null) {
            if (messageObject != null) {
                messageObject.messageOwner.media.webpage = webPage;
            }
            this.pagesStack.set(0, webPage);
            if (this.pagesStack.size() == 1) {
                this.currentPage = webPage;
                ApplicationLoader.applicationContext.getSharedPreferences("articles", 0).edit().remove("article" + this.currentPage.id).commit();
                updateInterfaceForCurrentPage(0);
                if (anchorFinal != null) {
                    scrollToAnchor(anchorFinal);
                }
            }
        }
    }

    public /* synthetic */ void lambda$open$24$ArticleViewer() {
        if (this.containerView == null || this.windowView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
        AndroidUtilities.hideKeyboard(this.parentActivity.getCurrentFocus());
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ArticleViewer$13, reason: invalid class name */
    class AnonymousClass13 extends AnimatorListenerAdapter {
        AnonymousClass13() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$13$ZgitzgzcGo3VmcLsoEiE9pE2Hsg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ArticleViewer$13();
                }
            });
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ArticleViewer$13() {
            NotificationCenter.getInstance(ArticleViewer.this.currentAccount).setAnimationInProgress(false);
            if (ArticleViewer.this.animationEndRunnable != null) {
                ArticleViewer.this.animationEndRunnable.run();
                ArticleViewer.this.animationEndRunnable = null;
            }
        }
    }

    public /* synthetic */ void lambda$open$25$ArticleViewer(AnimatorSet animatorSet) {
        NotificationCenter.getInstance(this.currentAccount).setAllowedNotificationsDutingAnimation(new int[]{NotificationCenter.dialogsNeedReload, NotificationCenter.closeChats});
        NotificationCenter.getInstance(this.currentAccount).setAnimationInProgress(true);
        animatorSet.start();
    }

    private void showProgressView(boolean useLine, final boolean show) {
        if (useLine) {
            AndroidUtilities.cancelRunOnUIThread(this.lineProgressTickRunnable);
            if (show) {
                this.lineProgressView.setProgress(0.0f, false);
                this.lineProgressView.setProgress(0.3f, true);
                AndroidUtilities.runOnUIThread(this.lineProgressTickRunnable, 100L);
                return;
            }
            this.lineProgressView.setProgress(1.0f, true);
            return;
        }
        AnimatorSet animatorSet = this.progressViewAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.progressViewAnimation = new AnimatorSet();
        if (show) {
            this.progressView.setVisibility(0);
            this.shareContainer.setEnabled(false);
            this.progressViewAnimation.playTogether(ObjectAnimator.ofFloat(this.shareButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.shareButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.shareButton, (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.ALPHA, 1.0f));
        } else {
            this.shareButton.setVisibility(0);
            this.shareContainer.setEnabled(true);
            this.progressViewAnimation.playTogether(ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.shareButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.shareButton, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.shareButton, (Property<ImageView, Float>) View.ALPHA, 1.0f));
        }
        this.progressViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.14
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (ArticleViewer.this.progressViewAnimation != null && ArticleViewer.this.progressViewAnimation.equals(animation)) {
                    if (!show) {
                        ArticleViewer.this.progressView.setVisibility(4);
                    } else {
                        ArticleViewer.this.shareButton.setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (ArticleViewer.this.progressViewAnimation != null && ArticleViewer.this.progressViewAnimation.equals(animation)) {
                    ArticleViewer.this.progressViewAnimation = null;
                }
            }
        });
        this.progressViewAnimation.setDuration(150L);
        this.progressViewAnimation.start();
    }

    public void collapse() {
        if (this.parentActivity == null || !this.isVisible || checkAnimation()) {
            return;
        }
        if (this.fullscreenVideoContainer.getVisibility() == 0) {
            if (this.customView != null) {
                this.fullscreenVideoContainer.setVisibility(4);
                this.customViewCallback.onCustomViewHidden();
                this.fullscreenVideoContainer.removeView(this.customView);
                this.customView = null;
            } else {
                WebPlayerView webPlayerView = this.fullscreenedVideo;
                if (webPlayerView != null) {
                    webPlayerView.exitFullscreen();
                }
            }
        }
        if (this.isPhotoVisible) {
            closePhoto(false);
        }
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        AnimatorSet animatorSet = new AnimatorSet();
        Animator[] animatorArr = new Animator[12];
        animatorArr[0] = ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayout, Float>) View.TRANSLATION_X, this.containerView.getMeasuredWidth() - AndroidUtilities.dp(56.0f));
        FrameLayout frameLayout = this.containerView;
        Property property = View.TRANSLATION_Y;
        float[] fArr = new float[1];
        fArr[0] = ActionBar.getCurrentActionBarHeight() + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
        animatorArr[1] = ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr);
        animatorArr[2] = ObjectAnimator.ofFloat(this.windowView, (Property<WindowView, Float>) View.ALPHA, 0.0f);
        animatorArr[3] = ObjectAnimator.ofFloat(this.listView[0], (Property<RecyclerListView, Float>) View.ALPHA, 0.0f);
        animatorArr[4] = ObjectAnimator.ofFloat(this.listView[0], (Property<RecyclerListView, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(56.0f));
        animatorArr[5] = ObjectAnimator.ofFloat(this.headerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f);
        animatorArr[6] = ObjectAnimator.ofFloat(this.backButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f);
        animatorArr[7] = ObjectAnimator.ofFloat(this.backButton, (Property<ImageView, Float>) View.SCALE_Y, 1.0f);
        animatorArr[8] = ObjectAnimator.ofFloat(this.backButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f);
        animatorArr[9] = ObjectAnimator.ofFloat(this.shareContainer, (Property<FrameLayout, Float>) View.SCALE_X, 1.0f);
        animatorArr[10] = ObjectAnimator.ofFloat(this.shareContainer, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f);
        animatorArr[11] = ObjectAnimator.ofFloat(this.shareContainer, (Property<FrameLayout, Float>) View.SCALE_Y, 1.0f);
        animatorSet.playTogether(animatorArr);
        this.collapsed = true;
        this.animationInProgress = 2;
        this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$3ZpuTfd-mwVm3arDHxGQVLbLsxI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$collapse$26$ArticleViewer();
            }
        };
        animatorSet.setInterpolator(new DecelerateInterpolator());
        animatorSet.setDuration(250L);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.15
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (ArticleViewer.this.animationEndRunnable != null) {
                    ArticleViewer.this.animationEndRunnable.run();
                    ArticleViewer.this.animationEndRunnable = null;
                }
            }
        });
        this.transitionAnimationStartTime = System.currentTimeMillis();
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(2, null);
        }
        this.backDrawable.setRotation(1.0f, true);
        animatorSet.start();
    }

    public /* synthetic */ void lambda$collapse$26$ArticleViewer() {
        if (this.containerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
        WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
        wm.updateViewLayout(this.windowView, this.windowLayoutParams);
    }

    public void uncollapse() {
        if (this.parentActivity == null || !this.isVisible || checkAnimation()) {
            return;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayout, Float>) View.TRANSLATION_X, 0.0f), ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.windowView, (Property<WindowView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.listView[0], (Property<RecyclerListView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.listView[0], (Property<RecyclerListView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.headerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.backButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.backButton, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.backButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.shareContainer, (Property<FrameLayout, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.shareContainer, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.shareContainer, (Property<FrameLayout, Float>) View.SCALE_Y, 1.0f));
        this.collapsed = false;
        this.animationInProgress = 2;
        this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$17cXJDwesT2LuvMmxGogMxwoF_I
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$uncollapse$27$ArticleViewer();
            }
        };
        animatorSet.setDuration(250L);
        animatorSet.setInterpolator(new DecelerateInterpolator());
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.16
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (ArticleViewer.this.animationEndRunnable != null) {
                    ArticleViewer.this.animationEndRunnable.run();
                    ArticleViewer.this.animationEndRunnable = null;
                }
            }
        });
        this.transitionAnimationStartTime = System.currentTimeMillis();
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(2, null);
        }
        this.backDrawable.setRotation(0.0f, true);
        animatorSet.start();
    }

    public /* synthetic */ void lambda$uncollapse$27$ArticleViewer() {
        if (this.containerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveCurrentPagePosition() {
        int offset;
        if (this.currentPage == null) {
            return;
        }
        int position = this.layoutManager[0].findFirstVisibleItemPosition();
        if (position != -1) {
            View view = this.layoutManager[0].findViewByPosition(position);
            if (view != null) {
                offset = view.getTop();
            } else {
                offset = 0;
            }
            SharedPreferences.Editor editor = ApplicationLoader.applicationContext.getSharedPreferences("articles", 0).edit();
            String key = "article" + this.currentPage.id;
            editor.putInt(key, position).putInt(key + "o", offset).putBoolean(key + "r", AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y).commit();
        }
    }

    public void close(boolean byBackPress, boolean force) {
        if (this.parentActivity == null || !this.isVisible || checkAnimation()) {
            return;
        }
        if (this.fullscreenVideoContainer.getVisibility() == 0) {
            if (this.customView != null) {
                this.fullscreenVideoContainer.setVisibility(4);
                this.customViewCallback.onCustomViewHidden();
                this.fullscreenVideoContainer.removeView(this.customView);
                this.customView = null;
            } else {
                WebPlayerView webPlayerView = this.fullscreenedVideo;
                if (webPlayerView != null) {
                    webPlayerView.exitFullscreen();
                }
            }
            if (!force) {
                return;
            }
        }
        if (this.isPhotoVisible) {
            closePhoto(!force);
            if (!force) {
                return;
            }
        }
        if (this.openUrlReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.openUrlReqId, true);
            this.openUrlReqId = 0;
            showProgressView(true, false);
        }
        if (this.previewsReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.previewsReqId, true);
            this.previewsReqId = 0;
            showProgressView(true, false);
        }
        saveCurrentPagePosition();
        if (byBackPress && !force && removeLastPageFromStack()) {
            return;
        }
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidStart);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.needSetDayNightTheme);
        this.parentFragment = null;
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.windowView, (Property<WindowView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayout, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.windowView, (Property<WindowView, Float>) View.TRANSLATION_X, 0.0f, AndroidUtilities.dp(56.0f)));
        this.animationInProgress = 2;
        this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$sUc0-cUrXklP-MCIJi6D9glsML4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$close$28$ArticleViewer();
            }
        };
        animatorSet.setDuration(150L);
        animatorSet.setInterpolator(this.interpolator);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.17
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (ArticleViewer.this.animationEndRunnable != null) {
                    ArticleViewer.this.animationEndRunnable.run();
                    ArticleViewer.this.animationEndRunnable = null;
                }
            }
        });
        this.transitionAnimationStartTime = System.currentTimeMillis();
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(2, null);
        }
        animatorSet.start();
    }

    public /* synthetic */ void lambda$close$28$ArticleViewer() {
        if (this.containerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
        onClosed();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onClosed() {
        this.isVisible = false;
        this.currentPage = null;
        for (int i = 0; i < this.listView.length; i++) {
            this.adapter[i].cleanup();
        }
        try {
            this.parentActivity.getWindow().clearFlags(128);
        } catch (Exception e) {
            FileLog.e(e);
        }
        for (int a = 0; a < this.createdWebViews.size(); a++) {
            BlockEmbedCell cell = this.createdWebViews.get(a);
            cell.destroyWebView(false);
        }
        this.containerView.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$dVytOuzxObCdKb2xh-6H0jZAVNY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onClosed$29$ArticleViewer();
            }
        });
    }

    public /* synthetic */ void lambda$onClosed$29$ArticleViewer() {
        try {
            if (this.windowView.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeView(this.windowView);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadChannel(final BlockChannelCell cell, final WebpageAdapter adapter, TLRPC.Chat channel) {
        if (this.loadingChannel || TextUtils.isEmpty(channel.username)) {
            return;
        }
        this.loadingChannel = true;
        TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
        req.username = channel.username;
        final int currentAccount = UserConfig.selectedAccount;
        ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$QC_k1o6KezSq4TAvn_i6FuZIyyY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadChannel$31$ArticleViewer(adapter, currentAccount, cell, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadChannel$31$ArticleViewer(final WebpageAdapter adapter, final int currentAccount, final BlockChannelCell cell, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$Bfq3Kscm7YMva6c1y23f5Y2zu8s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$30$ArticleViewer(adapter, error, response, currentAccount, cell);
            }
        });
    }

    public /* synthetic */ void lambda$null$30$ArticleViewer(WebpageAdapter adapter, TLRPC.TL_error error, TLObject response, int currentAccount, BlockChannelCell cell) {
        this.loadingChannel = false;
        if (this.parentFragment == null || adapter.blocks.isEmpty()) {
            return;
        }
        if (error == null) {
            TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
            if (!res.chats.isEmpty()) {
                MessagesController.getInstance(currentAccount).putUsers(res.users, false);
                MessagesController.getInstance(currentAccount).putChats(res.chats, false);
                MessagesStorage.getInstance(currentAccount).putUsersAndChats(res.users, res.chats, false, true);
                TLRPC.Chat chat = res.chats.get(0);
                this.loadedChannel = chat;
                if (chat.left && !this.loadedChannel.kicked) {
                    cell.setState(0, false);
                    return;
                } else {
                    cell.setState(4, false);
                    return;
                }
            }
            cell.setState(4, false);
            return;
        }
        cell.setState(4, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void joinChannel(final BlockChannelCell cell, final TLRPC.Chat channel) {
        final TLRPC.TL_channels_joinChannel req = new TLRPC.TL_channels_joinChannel();
        req.channel = MessagesController.getInputChannel(channel);
        final int currentAccount = UserConfig.selectedAccount;
        ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$UmZ81DIkXxajK2GVjACoi0KMR0k
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$joinChannel$35$ArticleViewer(cell, currentAccount, req, channel, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$joinChannel$35$ArticleViewer(final BlockChannelCell cell, final int currentAccount, final TLRPC.TL_channels_joinChannel req, final TLRPC.Chat channel, TLObject response, final TLRPC.TL_error error) {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$myVcN9G-gv09Q64vDdJa11QhwmI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$32$ArticleViewer(cell, currentAccount, error, req);
                }
            });
            return;
        }
        boolean hasJoinMessage = false;
        TLRPC.Updates updates = (TLRPC.Updates) response;
        int a = 0;
        while (true) {
            if (a >= updates.updates.size()) {
                break;
            }
            TLRPC.Update update = updates.updates.get(a);
            if (!(update instanceof TLRPC.TL_updateNewChannelMessage) || !(((TLRPC.TL_updateNewChannelMessage) update).message.action instanceof TLRPC.TL_messageActionChatAddUser)) {
                a++;
            } else {
                hasJoinMessage = true;
                break;
            }
        }
        MessagesController.getInstance(currentAccount).processUpdates(updates, false);
        if (!hasJoinMessage) {
            MessagesController.getInstance(currentAccount).generateJoinMessage(channel.id, true);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$jewXiJwndJoHijm_Hr86vxzvyJQ
            @Override // java.lang.Runnable
            public final void run() {
                cell.setState(2, false);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$Npl_7ZbfP1n1hhfEtRIMowIueag
            @Override // java.lang.Runnable
            public final void run() {
                MessagesController.getInstance(currentAccount).loadFullChat(channel.id, 0, true);
            }
        }, 1000L);
        MessagesStorage.getInstance(currentAccount).updateDialogsWithDeletedMessages(new ArrayList<>(), null, true, channel.id);
    }

    public /* synthetic */ void lambda$null$32$ArticleViewer(BlockChannelCell cell, int currentAccount, TLRPC.TL_error error, TLRPC.TL_channels_joinChannel req) {
        cell.setState(0, false);
        AlertsCreator.processError(currentAccount, error, this.parentFragment, req, true);
    }

    private boolean checkAnimation() {
        if (this.animationInProgress != 0 && Math.abs(this.transitionAnimationStartTime - System.currentTimeMillis()) >= 500) {
            Runnable runnable = this.animationEndRunnable;
            if (runnable != null) {
                runnable.run();
                this.animationEndRunnable = null;
            }
            this.animationInProgress = 0;
        }
        return this.animationInProgress != 0;
    }

    public void destroyArticleViewer() {
        if (this.parentActivity == null || this.windowView == null) {
            return;
        }
        releasePlayer();
        try {
            if (this.windowView.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeViewImmediate(this.windowView);
            }
            this.windowView = null;
        } catch (Exception e) {
            FileLog.e(e);
        }
        for (int a = 0; a < this.createdWebViews.size(); a++) {
            BlockEmbedCell cell = this.createdWebViews.get(a);
            cell.destroyWebView(true);
        }
        this.createdWebViews.clear();
        try {
            this.parentActivity.getWindow().clearFlags(128);
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        this.animatingImageView.setImageBitmap(null);
        this.parentActivity = null;
        this.parentFragment = null;
        Instance = null;
    }

    public boolean isVisible() {
        return this.isVisible;
    }

    public void showDialog(Dialog dialog) {
        if (this.parentActivity == null) {
            return;
        }
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            this.visibleDialog = dialog;
            dialog.setCanceledOnTouchOutside(true);
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$zm72Vj67BZolDlj7euHG9E44LtM
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showDialog$36$ArticleViewer(dialogInterface);
                }
            });
            dialog.show();
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public /* synthetic */ void lambda$showDialog$36$ArticleViewer(DialogInterface dialog1) {
        this.visibleDialog = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    class WebpageAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private ArrayList<TLRPC.PageBlock> localBlocks = new ArrayList<>();
        private ArrayList<TLRPC.PageBlock> blocks = new ArrayList<>();
        private ArrayList<TLRPC.PageBlock> photoBlocks = new ArrayList<>();
        private HashMap<String, Integer> anchors = new HashMap<>();
        private HashMap<String, Integer> anchorsOffset = new HashMap<>();
        private HashMap<String, TLRPC.TL_textAnchor> anchorsParent = new HashMap<>();
        private HashMap<TLRPC.TL_pageBlockAudio, MessageObject> audioBlocks = new HashMap<>();
        private ArrayList<MessageObject> audioMessages = new ArrayList<>();

        public WebpageAdapter(Context ctx) {
            this.context = ctx;
        }

        private void setRichTextParents(TLRPC.RichText parentRichText, TLRPC.RichText richText) {
            if (richText == null) {
                return;
            }
            richText.parentRichText = parentRichText;
            if (richText instanceof TLRPC.TL_textFixed) {
                setRichTextParents(richText, ((TLRPC.TL_textFixed) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textItalic) {
                setRichTextParents(richText, ((TLRPC.TL_textItalic) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textBold) {
                setRichTextParents(richText, ((TLRPC.TL_textBold) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textUnderline) {
                setRichTextParents(richText, ((TLRPC.TL_textUnderline) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textStrike) {
                setRichTextParents(richText, ((TLRPC.TL_textStrike) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textEmail) {
                setRichTextParents(richText, ((TLRPC.TL_textEmail) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textPhone) {
                setRichTextParents(richText, ((TLRPC.TL_textPhone) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textUrl) {
                setRichTextParents(richText, ((TLRPC.TL_textUrl) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textConcat) {
                int count = richText.texts.size();
                for (int a = 0; a < count; a++) {
                    setRichTextParents(richText, richText.texts.get(a));
                }
                return;
            }
            if (richText instanceof TLRPC.TL_textSubscript) {
                setRichTextParents(richText, ((TLRPC.TL_textSubscript) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textSuperscript) {
                setRichTextParents(richText, ((TLRPC.TL_textSuperscript) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textMarked) {
                setRichTextParents(richText, ((TLRPC.TL_textMarked) richText).text);
                return;
            }
            if (richText instanceof TLRPC.TL_textAnchor) {
                TLRPC.TL_textAnchor textAnchor = (TLRPC.TL_textAnchor) richText;
                setRichTextParents(richText, textAnchor.text);
                String name = textAnchor.name.toLowerCase();
                this.anchors.put(name, Integer.valueOf(this.blocks.size()));
                if (textAnchor.text instanceof TLRPC.TL_textPlain) {
                    TLRPC.TL_textPlain textPlain = (TLRPC.TL_textPlain) textAnchor.text;
                    if (!TextUtils.isEmpty(textPlain.text)) {
                        this.anchorsParent.put(name, textAnchor);
                    }
                } else if (!(textAnchor.text instanceof TLRPC.TL_textEmpty)) {
                    this.anchorsParent.put(name, textAnchor);
                }
                this.anchorsOffset.put(name, -1);
            }
        }

        private void setRichTextParents(TLRPC.PageBlock block) {
            if (block instanceof TLRPC.TL_pageBlockEmbedPost) {
                TLRPC.TL_pageBlockEmbedPost blockEmbedPost = (TLRPC.TL_pageBlockEmbedPost) block;
                setRichTextParents(null, blockEmbedPost.caption.text);
                setRichTextParents(null, blockEmbedPost.caption.credit);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockParagraph) {
                TLRPC.TL_pageBlockParagraph pageBlockParagraph = (TLRPC.TL_pageBlockParagraph) block;
                setRichTextParents(null, pageBlockParagraph.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockKicker) {
                TLRPC.TL_pageBlockKicker pageBlockKicker = (TLRPC.TL_pageBlockKicker) block;
                setRichTextParents(null, pageBlockKicker.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockFooter) {
                TLRPC.TL_pageBlockFooter pageBlockFooter = (TLRPC.TL_pageBlockFooter) block;
                setRichTextParents(null, pageBlockFooter.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockHeader) {
                TLRPC.TL_pageBlockHeader pageBlockHeader = (TLRPC.TL_pageBlockHeader) block;
                setRichTextParents(null, pageBlockHeader.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockPreformatted) {
                TLRPC.TL_pageBlockPreformatted pageBlockPreformatted = (TLRPC.TL_pageBlockPreformatted) block;
                setRichTextParents(null, pageBlockPreformatted.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockSubheader) {
                TLRPC.TL_pageBlockSubheader pageBlockTitle = (TLRPC.TL_pageBlockSubheader) block;
                setRichTextParents(null, pageBlockTitle.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockSlideshow) {
                TLRPC.TL_pageBlockSlideshow pageBlockSlideshow = (TLRPC.TL_pageBlockSlideshow) block;
                setRichTextParents(null, pageBlockSlideshow.caption.text);
                setRichTextParents(null, pageBlockSlideshow.caption.credit);
                int size = pageBlockSlideshow.items.size();
                for (int a = 0; a < size; a++) {
                    setRichTextParents(pageBlockSlideshow.items.get(a));
                }
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockPhoto) {
                TLRPC.TL_pageBlockPhoto pageBlockPhoto = (TLRPC.TL_pageBlockPhoto) block;
                setRichTextParents(null, pageBlockPhoto.caption.text);
                setRichTextParents(null, pageBlockPhoto.caption.credit);
                return;
            }
            if (block instanceof TL_pageBlockListItem) {
                TL_pageBlockListItem pageBlockListItem = (TL_pageBlockListItem) block;
                if (pageBlockListItem.textItem != null) {
                    setRichTextParents(null, pageBlockListItem.textItem);
                    return;
                } else {
                    if (pageBlockListItem.blockItem != null) {
                        setRichTextParents(pageBlockListItem.blockItem);
                        return;
                    }
                    return;
                }
            }
            if (block instanceof TL_pageBlockOrderedListItem) {
                TL_pageBlockOrderedListItem pageBlockOrderedListItem = (TL_pageBlockOrderedListItem) block;
                if (pageBlockOrderedListItem.textItem != null) {
                    setRichTextParents(null, pageBlockOrderedListItem.textItem);
                    return;
                } else {
                    if (pageBlockOrderedListItem.blockItem != null) {
                        setRichTextParents(pageBlockOrderedListItem.blockItem);
                        return;
                    }
                    return;
                }
            }
            if (block instanceof TLRPC.TL_pageBlockCollage) {
                TLRPC.TL_pageBlockCollage pageBlockCollage = (TLRPC.TL_pageBlockCollage) block;
                setRichTextParents(null, pageBlockCollage.caption.text);
                setRichTextParents(null, pageBlockCollage.caption.credit);
                int size2 = pageBlockCollage.items.size();
                for (int a2 = 0; a2 < size2; a2++) {
                    setRichTextParents(pageBlockCollage.items.get(a2));
                }
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockEmbed) {
                TLRPC.TL_pageBlockEmbed pageBlockEmbed = (TLRPC.TL_pageBlockEmbed) block;
                setRichTextParents(null, pageBlockEmbed.caption.text);
                setRichTextParents(null, pageBlockEmbed.caption.credit);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockSubtitle) {
                TLRPC.TL_pageBlockSubtitle pageBlockSubtitle = (TLRPC.TL_pageBlockSubtitle) block;
                setRichTextParents(null, pageBlockSubtitle.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockBlockquote) {
                TLRPC.TL_pageBlockBlockquote pageBlockBlockquote = (TLRPC.TL_pageBlockBlockquote) block;
                setRichTextParents(null, pageBlockBlockquote.text);
                setRichTextParents(null, pageBlockBlockquote.caption);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockDetails) {
                TLRPC.TL_pageBlockDetails pageBlockDetails = (TLRPC.TL_pageBlockDetails) block;
                setRichTextParents(null, pageBlockDetails.title);
                int size3 = pageBlockDetails.blocks.size();
                for (int a3 = 0; a3 < size3; a3++) {
                    setRichTextParents(pageBlockDetails.blocks.get(a3));
                }
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockVideo) {
                TLRPC.TL_pageBlockVideo pageBlockVideo = (TLRPC.TL_pageBlockVideo) block;
                setRichTextParents(null, pageBlockVideo.caption.text);
                setRichTextParents(null, pageBlockVideo.caption.credit);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockPullquote) {
                TLRPC.TL_pageBlockPullquote pageBlockPullquote = (TLRPC.TL_pageBlockPullquote) block;
                setRichTextParents(null, pageBlockPullquote.text);
                setRichTextParents(null, pageBlockPullquote.caption);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockAudio) {
                TLRPC.TL_pageBlockAudio pageBlockAudio = (TLRPC.TL_pageBlockAudio) block;
                setRichTextParents(null, pageBlockAudio.caption.text);
                setRichTextParents(null, pageBlockAudio.caption.credit);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockTable) {
                TLRPC.TL_pageBlockTable pageBlockTable = (TLRPC.TL_pageBlockTable) block;
                setRichTextParents(null, pageBlockTable.title);
                int size4 = pageBlockTable.rows.size();
                for (int a4 = 0; a4 < size4; a4++) {
                    TLRPC.TL_pageTableRow row = pageBlockTable.rows.get(a4);
                    int size22 = row.cells.size();
                    for (int b = 0; b < size22; b++) {
                        TLRPC.TL_pageTableCell cell = row.cells.get(b);
                        setRichTextParents(null, cell.text);
                    }
                }
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockTitle) {
                TLRPC.TL_pageBlockTitle pageBlockTitle2 = (TLRPC.TL_pageBlockTitle) block;
                setRichTextParents(null, pageBlockTitle2.text);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockCover) {
                TLRPC.TL_pageBlockCover pageBlockCover = (TLRPC.TL_pageBlockCover) block;
                setRichTextParents(pageBlockCover.cover);
                return;
            }
            if (block instanceof TLRPC.TL_pageBlockAuthorDate) {
                TLRPC.TL_pageBlockAuthorDate pageBlockAuthorDate = (TLRPC.TL_pageBlockAuthorDate) block;
                setRichTextParents(null, pageBlockAuthorDate.author);
            } else if (block instanceof TLRPC.TL_pageBlockMap) {
                TLRPC.TL_pageBlockMap pageBlockMap = (TLRPC.TL_pageBlockMap) block;
                setRichTextParents(null, pageBlockMap.caption.text);
                setRichTextParents(null, pageBlockMap.caption.credit);
            } else if (block instanceof TLRPC.TL_pageBlockRelatedArticles) {
                TLRPC.TL_pageBlockRelatedArticles pageBlockRelatedArticles = (TLRPC.TL_pageBlockRelatedArticles) block;
                setRichTextParents(null, pageBlockRelatedArticles.title);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void addBlock(TLRPC.PageBlock block, int level, int listLevel, int position) {
            TLRPC.PageBlock block2;
            TLRPC.TL_pageBlockOrderedList pageBlockOrderedList;
            int size;
            String str;
            TLRPC.PageBlock finalBlock;
            TLRPC.TL_pageListOrderedItemBlocks pageListOrderedItemBlocks;
            TLRPC.TL_pageBlockList pageBlockList;
            String str2;
            TLRPC.PageBlock finalBlock2;
            TLRPC.TL_pageListItemBlocks pageListItemBlocks;
            int size2;
            TLRPC.PageBlock block3 = block;
            if (block3 instanceof TL_pageBlockDetailsChild) {
                TL_pageBlockDetailsChild blockDetailsChild = (TL_pageBlockDetailsChild) block3;
                block3 = blockDetailsChild.block;
            }
            if (!(block3 instanceof TLRPC.TL_pageBlockList) && !(block3 instanceof TLRPC.TL_pageBlockOrderedList)) {
                setRichTextParents(block3);
                addAllMediaFromBlock(block3);
            }
            TLRPC.PageBlock block4 = ArticleViewer.this.getLastNonListPageBlock(block3);
            if (block4 instanceof TLRPC.TL_pageBlockUnsupported) {
                return;
            }
            if (block4 instanceof TLRPC.TL_pageBlockAnchor) {
                this.anchors.put(((TLRPC.TL_pageBlockAnchor) block4).name.toLowerCase(), Integer.valueOf(this.blocks.size()));
                return;
            }
            if (!(block4 instanceof TLRPC.TL_pageBlockList) && !(block4 instanceof TLRPC.TL_pageBlockOrderedList)) {
                this.blocks.add(block);
            }
            if (block4 instanceof TLRPC.TL_pageBlockAudio) {
                TLRPC.TL_pageBlockAudio blockAudio = (TLRPC.TL_pageBlockAudio) block4;
                TLRPC.TL_message message = new TLRPC.TL_message();
                message.out = true;
                int i = -Long.valueOf(blockAudio.audio_id).hashCode();
                block4.mid = i;
                message.id = i;
                message.to_id = new TLRPC.TL_peerUser();
                TLRPC.Peer peer = message.to_id;
                int clientUserId = UserConfig.getInstance(ArticleViewer.this.currentAccount).getClientUserId();
                message.from_id = clientUserId;
                peer.user_id = clientUserId;
                message.date = (int) (System.currentTimeMillis() / 1000);
                message.message = "";
                message.media = new TLRPC.TL_messageMediaDocument();
                message.media.webpage = ArticleViewer.this.currentPage;
                message.media.flags |= 3;
                message.media.document = ArticleViewer.this.getDocumentWithId(blockAudio.audio_id);
                message.flags |= 768;
                MessageObject messageObject = new MessageObject(UserConfig.selectedAccount, message, false);
                this.audioMessages.add(messageObject);
                this.audioBlocks.put(blockAudio, messageObject);
                return;
            }
            AnonymousClass1 anonymousClass1 = null;
            if (block4 instanceof TLRPC.TL_pageBlockEmbedPost) {
                TLRPC.TL_pageBlockEmbedPost pageBlockEmbedPost = (TLRPC.TL_pageBlockEmbedPost) block4;
                if (!pageBlockEmbedPost.blocks.isEmpty()) {
                    block4.level = -1;
                    for (int b = 0; b < pageBlockEmbedPost.blocks.size(); b++) {
                        TLRPC.PageBlock innerBlock = pageBlockEmbedPost.blocks.get(b);
                        if (!(innerBlock instanceof TLRPC.TL_pageBlockUnsupported)) {
                            if (innerBlock instanceof TLRPC.TL_pageBlockAnchor) {
                                TLRPC.TL_pageBlockAnchor pageBlockAnchor = (TLRPC.TL_pageBlockAnchor) innerBlock;
                                this.anchors.put(pageBlockAnchor.name.toLowerCase(), Integer.valueOf(this.blocks.size()));
                            } else {
                                innerBlock.level = 1;
                                if (b == pageBlockEmbedPost.blocks.size() - 1) {
                                    innerBlock.bottom = true;
                                }
                                this.blocks.add(innerBlock);
                                addAllMediaFromBlock(innerBlock);
                            }
                        }
                    }
                    if (!TextUtils.isEmpty(ArticleViewer.getPlainText(pageBlockEmbedPost.caption.text)) || !TextUtils.isEmpty(ArticleViewer.getPlainText(pageBlockEmbedPost.caption.credit))) {
                        TL_pageBlockEmbedPostCaption pageBlockEmbedPostCaption = new TL_pageBlockEmbedPostCaption();
                        pageBlockEmbedPostCaption.parent = pageBlockEmbedPost;
                        pageBlockEmbedPostCaption.caption = pageBlockEmbedPost.caption;
                        this.blocks.add(pageBlockEmbedPostCaption);
                    }
                }
                return;
            }
            if (block4 instanceof TLRPC.TL_pageBlockRelatedArticles) {
                TLRPC.TL_pageBlockRelatedArticles pageBlockRelatedArticles = (TLRPC.TL_pageBlockRelatedArticles) block4;
                TL_pageBlockRelatedArticlesShadow shadow = new TL_pageBlockRelatedArticlesShadow();
                shadow.parent = pageBlockRelatedArticles;
                ArrayList<TLRPC.PageBlock> arrayList = this.blocks;
                arrayList.add(arrayList.size() - 1, shadow);
                int size3 = pageBlockRelatedArticles.articles.size();
                for (int b2 = 0; b2 < size3; b2++) {
                    TL_pageBlockRelatedArticlesChild child = new TL_pageBlockRelatedArticlesChild();
                    child.parent = pageBlockRelatedArticles;
                    child.num = b2;
                    this.blocks.add(child);
                }
                if (position == 0) {
                    TL_pageBlockRelatedArticlesShadow shadow2 = new TL_pageBlockRelatedArticlesShadow();
                    shadow2.parent = pageBlockRelatedArticles;
                    this.blocks.add(shadow2);
                }
                return;
            }
            if (block4 instanceof TLRPC.TL_pageBlockDetails) {
                TLRPC.TL_pageBlockDetails pageBlockDetails = (TLRPC.TL_pageBlockDetails) block4;
                int size4 = pageBlockDetails.blocks.size();
                for (int b3 = 0; b3 < size4; b3++) {
                    TL_pageBlockDetailsChild child2 = new TL_pageBlockDetailsChild();
                    child2.parent = block;
                    child2.block = pageBlockDetails.blocks.get(b3);
                    addBlock(ArticleViewer.this.wrapInTableBlock(block, child2), level + 1, listLevel, position);
                }
                return;
            }
            String str3 = " ";
            if (block4 instanceof TLRPC.TL_pageBlockList) {
                TLRPC.TL_pageBlockList pageBlockList2 = (TLRPC.TL_pageBlockList) block4;
                TL_pageBlockListParent pageBlockListParent = new TL_pageBlockListParent();
                pageBlockListParent.pageBlockList = pageBlockList2;
                pageBlockListParent.level = listLevel;
                int b4 = 0;
                int size5 = pageBlockList2.items.size();
                while (b4 < size5) {
                    TLRPC.PageListItem item = pageBlockList2.items.get(b4);
                    int size6 = size5;
                    TL_pageBlockListItem pageBlockListItem = new TL_pageBlockListItem();
                    pageBlockListItem.index = b4;
                    pageBlockListItem.parent = pageBlockListParent;
                    if (pageBlockList2.ordered) {
                        if (ArticleViewer.this.isRtl) {
                            pageBlockListItem.num = String.format(".%d", Integer.valueOf(b4 + 1));
                        } else {
                            pageBlockListItem.num = String.format("%d.", Integer.valueOf(b4 + 1));
                        }
                    } else {
                        pageBlockListItem.num = "•";
                    }
                    pageBlockListParent.items.add(pageBlockListItem);
                    if (item instanceof TLRPC.TL_pageListItemText) {
                        pageBlockListItem.textItem = ((TLRPC.TL_pageListItemText) item).text;
                        pageBlockList = pageBlockList2;
                    } else if (!(item instanceof TLRPC.TL_pageListItemBlocks)) {
                        pageBlockList = pageBlockList2;
                    } else {
                        TLRPC.TL_pageListItemBlocks pageListItemBlocks2 = (TLRPC.TL_pageListItemBlocks) item;
                        if (!pageListItemBlocks2.blocks.isEmpty()) {
                            pageBlockList = pageBlockList2;
                            pageBlockListItem.blockItem = pageListItemBlocks2.blocks.get(0);
                        } else {
                            pageBlockList = pageBlockList2;
                            TLRPC.TL_pageListItemText text = new TLRPC.TL_pageListItemText();
                            TLRPC.TL_textPlain textPlain = new TLRPC.TL_textPlain();
                            textPlain.text = str3;
                            text.text = textPlain;
                            item = text;
                        }
                    }
                    if (block instanceof TL_pageBlockDetailsChild) {
                        TL_pageBlockDetailsChild pageBlockDetailsChild = (TL_pageBlockDetailsChild) block;
                        str2 = str3;
                        TL_pageBlockDetailsChild child3 = new TL_pageBlockDetailsChild();
                        child3.parent = pageBlockDetailsChild.parent;
                        child3.block = pageBlockListItem;
                        addBlock(child3, level, listLevel + 1, position);
                    } else {
                        str2 = str3;
                        if (b4 == 0) {
                            finalBlock2 = ArticleViewer.this.fixListBlock(block, pageBlockListItem);
                        } else {
                            finalBlock2 = pageBlockListItem;
                        }
                        addBlock(finalBlock2, level, listLevel + 1, position);
                    }
                    if (item instanceof TLRPC.TL_pageListItemBlocks) {
                        TLRPC.TL_pageListItemBlocks pageListItemBlocks3 = (TLRPC.TL_pageListItemBlocks) item;
                        int c = 1;
                        int size22 = pageListItemBlocks3.blocks.size();
                        while (c < size22) {
                            TLRPC.PageListItem item2 = item;
                            pageBlockListItem = new TL_pageBlockListItem();
                            pageBlockListItem.blockItem = pageListItemBlocks3.blocks.get(c);
                            pageBlockListItem.parent = pageBlockListParent;
                            if (block instanceof TL_pageBlockDetailsChild) {
                                TL_pageBlockDetailsChild pageBlockDetailsChild2 = (TL_pageBlockDetailsChild) block;
                                pageListItemBlocks = pageListItemBlocks3;
                                size2 = size22;
                                TL_pageBlockDetailsChild child4 = new TL_pageBlockDetailsChild();
                                child4.parent = pageBlockDetailsChild2.parent;
                                child4.block = pageBlockListItem;
                                addBlock(child4, level, listLevel + 1, position);
                            } else {
                                pageListItemBlocks = pageListItemBlocks3;
                                size2 = size22;
                                addBlock(pageBlockListItem, level, listLevel + 1, position);
                            }
                            pageBlockListParent.items.add(pageBlockListItem);
                            c++;
                            item = item2;
                            pageListItemBlocks3 = pageListItemBlocks;
                            size22 = size2;
                        }
                    }
                    b4++;
                    size5 = size6;
                    pageBlockList2 = pageBlockList;
                    str3 = str2;
                    anonymousClass1 = null;
                }
                return;
            }
            String str4 = " ";
            if (block4 instanceof TLRPC.TL_pageBlockOrderedList) {
                TLRPC.TL_pageBlockOrderedList pageBlockOrderedList2 = (TLRPC.TL_pageBlockOrderedList) block4;
                TL_pageBlockOrderedListParent pageBlockOrderedListParent = new TL_pageBlockOrderedListParent();
                pageBlockOrderedListParent.pageBlockOrderedList = pageBlockOrderedList2;
                pageBlockOrderedListParent.level = listLevel;
                int b5 = 0;
                int size7 = pageBlockOrderedList2.items.size();
                while (b5 < size7) {
                    TLRPC.PageListOrderedItem item3 = pageBlockOrderedList2.items.get(b5);
                    TL_pageBlockOrderedListItem pageBlockOrderedListItem = new TL_pageBlockOrderedListItem();
                    pageBlockOrderedListItem.index = b5;
                    pageBlockOrderedListItem.parent = pageBlockOrderedListParent;
                    pageBlockOrderedListParent.items.add(pageBlockOrderedListItem);
                    if (item3 instanceof TLRPC.TL_pageListOrderedItemText) {
                        TLRPC.TL_pageListOrderedItemText pageListOrderedItemText = (TLRPC.TL_pageListOrderedItemText) item3;
                        block2 = block4;
                        pageBlockOrderedListItem.textItem = pageListOrderedItemText.text;
                        if (TextUtils.isEmpty(pageListOrderedItemText.num)) {
                            if (ArticleViewer.this.isRtl) {
                                pageBlockOrderedListItem.num = String.format(".%d", Integer.valueOf(b5 + 1));
                                pageBlockOrderedList = pageBlockOrderedList2;
                            } else {
                                pageBlockOrderedListItem.num = String.format("%d.", Integer.valueOf(b5 + 1));
                                pageBlockOrderedList = pageBlockOrderedList2;
                            }
                        } else if (ArticleViewer.this.isRtl) {
                            pageBlockOrderedListItem.num = "." + pageListOrderedItemText.num;
                            pageBlockOrderedList = pageBlockOrderedList2;
                        } else {
                            StringBuilder sb = new StringBuilder();
                            pageBlockOrderedList = pageBlockOrderedList2;
                            sb.append(pageListOrderedItemText.num);
                            sb.append(".");
                            pageBlockOrderedListItem.num = sb.toString();
                        }
                        size = size7;
                        str = str4;
                    } else {
                        block2 = block4;
                        pageBlockOrderedList = pageBlockOrderedList2;
                        if (!(item3 instanceof TLRPC.TL_pageListOrderedItemBlocks)) {
                            size = size7;
                            str = str4;
                        } else {
                            TLRPC.TL_pageListOrderedItemBlocks pageListOrderedItemBlocks2 = (TLRPC.TL_pageListOrderedItemBlocks) item3;
                            if (!pageListOrderedItemBlocks2.blocks.isEmpty()) {
                                pageBlockOrderedListItem.blockItem = pageListOrderedItemBlocks2.blocks.get(0);
                                size = size7;
                                str = str4;
                            } else {
                                TLRPC.TL_pageListOrderedItemText text2 = new TLRPC.TL_pageListOrderedItemText();
                                TLRPC.TL_textPlain textPlain2 = new TLRPC.TL_textPlain();
                                size = size7;
                                str = str4;
                                textPlain2.text = str;
                                text2.text = textPlain2;
                                item3 = text2;
                            }
                            if (TextUtils.isEmpty(pageListOrderedItemBlocks2.num)) {
                                if (ArticleViewer.this.isRtl) {
                                    pageBlockOrderedListItem.num = String.format(".%d", Integer.valueOf(b5 + 1));
                                } else {
                                    pageBlockOrderedListItem.num = String.format("%d.", Integer.valueOf(b5 + 1));
                                }
                            } else if (ArticleViewer.this.isRtl) {
                                pageBlockOrderedListItem.num = "." + pageListOrderedItemBlocks2.num;
                            } else {
                                pageBlockOrderedListItem.num = pageListOrderedItemBlocks2.num + ".";
                            }
                        }
                    }
                    if (block instanceof TL_pageBlockDetailsChild) {
                        TL_pageBlockDetailsChild pageBlockDetailsChild3 = (TL_pageBlockDetailsChild) block;
                        TL_pageBlockDetailsChild child5 = new TL_pageBlockDetailsChild();
                        child5.parent = pageBlockDetailsChild3.parent;
                        child5.block = pageBlockOrderedListItem;
                        addBlock(child5, level, listLevel + 1, position);
                    } else {
                        if (b5 == 0) {
                            finalBlock = ArticleViewer.this.fixListBlock(block, pageBlockOrderedListItem);
                        } else {
                            finalBlock = pageBlockOrderedListItem;
                        }
                        addBlock(finalBlock, level, listLevel + 1, position);
                    }
                    if (item3 instanceof TLRPC.TL_pageListOrderedItemBlocks) {
                        TLRPC.TL_pageListOrderedItemBlocks pageListOrderedItemBlocks3 = (TLRPC.TL_pageListOrderedItemBlocks) item3;
                        int c2 = 1;
                        int size23 = pageListOrderedItemBlocks3.blocks.size();
                        while (c2 < size23) {
                            String str5 = str;
                            TLRPC.PageListOrderedItem item4 = item3;
                            TL_pageBlockOrderedListItem pageBlockOrderedListItem2 = new TL_pageBlockOrderedListItem();
                            pageBlockOrderedListItem2.blockItem = pageListOrderedItemBlocks3.blocks.get(c2);
                            pageBlockOrderedListItem2.parent = pageBlockOrderedListParent;
                            if (block instanceof TL_pageBlockDetailsChild) {
                                TL_pageBlockDetailsChild pageBlockDetailsChild4 = (TL_pageBlockDetailsChild) block;
                                pageListOrderedItemBlocks = pageListOrderedItemBlocks3;
                                TL_pageBlockDetailsChild child6 = new TL_pageBlockDetailsChild();
                                child6.parent = pageBlockDetailsChild4.parent;
                                child6.block = pageBlockOrderedListItem2;
                                addBlock(child6, level, listLevel + 1, position);
                            } else {
                                pageListOrderedItemBlocks = pageListOrderedItemBlocks3;
                                addBlock(pageBlockOrderedListItem2, level, listLevel + 1, position);
                            }
                            pageBlockOrderedListParent.items.add(pageBlockOrderedListItem2);
                            c2++;
                            pageListOrderedItemBlocks3 = pageListOrderedItemBlocks;
                            str = str5;
                            item3 = item4;
                        }
                    }
                    String str6 = str;
                    b5++;
                    block4 = block2;
                    pageBlockOrderedList2 = pageBlockOrderedList;
                    size7 = size;
                    str4 = str6;
                }
            }
        }

        private void addAllMediaFromBlock(TLRPC.PageBlock block) {
            if (!(block instanceof TLRPC.TL_pageBlockPhoto)) {
                if ((block instanceof TLRPC.TL_pageBlockVideo) && ArticleViewer.this.isVideoBlock(block)) {
                    TLRPC.TL_pageBlockVideo pageBlockVideo = (TLRPC.TL_pageBlockVideo) block;
                    TLRPC.Document document = ArticleViewer.this.getDocumentWithId(pageBlockVideo.video_id);
                    if (document != null) {
                        pageBlockVideo.thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 56, true);
                        pageBlockVideo.thumbObject = document;
                        this.photoBlocks.add(block);
                        return;
                    }
                    return;
                }
                if (block instanceof TLRPC.TL_pageBlockSlideshow) {
                    TLRPC.TL_pageBlockSlideshow slideshow = (TLRPC.TL_pageBlockSlideshow) block;
                    int count = slideshow.items.size();
                    for (int a = 0; a < count; a++) {
                        TLRPC.PageBlock innerBlock = slideshow.items.get(a);
                        innerBlock.groupId = ArticleViewer.this.lastBlockNum;
                        addAllMediaFromBlock(innerBlock);
                    }
                    ArticleViewer.access$13108(ArticleViewer.this);
                    return;
                }
                if (block instanceof TLRPC.TL_pageBlockCollage) {
                    TLRPC.TL_pageBlockCollage collage = (TLRPC.TL_pageBlockCollage) block;
                    int count2 = collage.items.size();
                    for (int a2 = 0; a2 < count2; a2++) {
                        TLRPC.PageBlock innerBlock2 = collage.items.get(a2);
                        innerBlock2.groupId = ArticleViewer.this.lastBlockNum;
                        addAllMediaFromBlock(innerBlock2);
                    }
                    ArticleViewer.access$13108(ArticleViewer.this);
                    return;
                }
                if (block instanceof TLRPC.TL_pageBlockCover) {
                    TLRPC.TL_pageBlockCover pageBlockCover = (TLRPC.TL_pageBlockCover) block;
                    addAllMediaFromBlock(pageBlockCover.cover);
                    return;
                }
                return;
            }
            TLRPC.TL_pageBlockPhoto pageBlockPhoto = (TLRPC.TL_pageBlockPhoto) block;
            TLRPC.Photo photo = ArticleViewer.this.getPhotoWithId(pageBlockPhoto.photo_id);
            if (photo != null) {
                pageBlockPhoto.thumb = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 56, true);
                pageBlockPhoto.thumbObject = photo;
                this.photoBlocks.add(block);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View blockParagraphCell;
            if (i != 90) {
                switch (i) {
                    case 0:
                        blockParagraphCell = ArticleViewer.this.new BlockParagraphCell(this.context, this);
                        break;
                    case 1:
                        blockParagraphCell = ArticleViewer.this.new BlockHeaderCell(this.context, this);
                        break;
                    case 2:
                        blockParagraphCell = ArticleViewer.this.new BlockDividerCell(this.context);
                        break;
                    case 3:
                        blockParagraphCell = ArticleViewer.this.new BlockEmbedCell(this.context, this);
                        break;
                    case 4:
                        blockParagraphCell = ArticleViewer.this.new BlockSubtitleCell(this.context, this);
                        break;
                    case 5:
                        blockParagraphCell = ArticleViewer.this.new BlockVideoCell(this.context, this, 0);
                        break;
                    case 6:
                        blockParagraphCell = ArticleViewer.this.new BlockPullquoteCell(this.context, this);
                        break;
                    case 7:
                        blockParagraphCell = ArticleViewer.this.new BlockBlockquoteCell(this.context, this);
                        break;
                    case 8:
                        blockParagraphCell = ArticleViewer.this.new BlockSlideshowCell(this.context, this);
                        break;
                    case 9:
                        blockParagraphCell = ArticleViewer.this.new BlockPhotoCell(this.context, this, 0);
                        break;
                    case 10:
                        blockParagraphCell = ArticleViewer.this.new BlockAuthorDateCell(this.context, this);
                        break;
                    case 11:
                        blockParagraphCell = ArticleViewer.this.new BlockTitleCell(this.context, this);
                        break;
                    case 12:
                        blockParagraphCell = ArticleViewer.this.new BlockListItemCell(this.context, this);
                        break;
                    case 13:
                        blockParagraphCell = ArticleViewer.this.new BlockFooterCell(this.context, this);
                        break;
                    case 14:
                        blockParagraphCell = ArticleViewer.this.new BlockPreformattedCell(this.context, this);
                        break;
                    case 15:
                        blockParagraphCell = ArticleViewer.this.new BlockSubheaderCell(this.context, this);
                        break;
                    case 16:
                        blockParagraphCell = ArticleViewer.this.new BlockEmbedPostCell(this.context, this);
                        break;
                    case 17:
                        blockParagraphCell = ArticleViewer.this.new BlockCollageCell(this.context, this);
                        break;
                    case 18:
                        blockParagraphCell = ArticleViewer.this.new BlockChannelCell(this.context, this, 0);
                        break;
                    case 19:
                        blockParagraphCell = ArticleViewer.this.new BlockAudioCell(this.context, this);
                        break;
                    case 20:
                        blockParagraphCell = ArticleViewer.this.new BlockKickerCell(this.context, this);
                        break;
                    case 21:
                        blockParagraphCell = ArticleViewer.this.new BlockOrderedListItemCell(this.context, this);
                        break;
                    case 22:
                        blockParagraphCell = ArticleViewer.this.new BlockMapCell(this.context, this, 0);
                        break;
                    case 23:
                        blockParagraphCell = ArticleViewer.this.new BlockRelatedArticlesCell(this.context, this);
                        break;
                    case 24:
                        blockParagraphCell = ArticleViewer.this.new BlockDetailsCell(this.context, this);
                        break;
                    case 25:
                        blockParagraphCell = ArticleViewer.this.new BlockTableCell(this.context, this);
                        break;
                    case 26:
                        blockParagraphCell = ArticleViewer.this.new BlockRelatedArticlesHeaderCell(this.context, this);
                        break;
                    case 27:
                        blockParagraphCell = ArticleViewer.this.new BlockDetailsBottomCell(this.context);
                        break;
                    case 28:
                        blockParagraphCell = ArticleViewer.this.new BlockRelatedArticlesShadowCell(this.context);
                        break;
                    default:
                        TextView textView = new TextView(this.context);
                        textView.setBackgroundColor(SupportMenu.CATEGORY_MASK);
                        textView.setTextColor(-16777216);
                        textView.setTextSize(1, 20.0f);
                        blockParagraphCell = textView;
                        break;
                }
            } else {
                FrameLayout frameLayout = new FrameLayout(this.context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.WebpageAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(44.0f), 1073741824));
                    }
                };
                frameLayout.setTag(90);
                TextView textView2 = new TextView(this.context);
                frameLayout.addView(textView2, LayoutHelper.createFrame(-1.0f, 34.0f, 51, 0.0f, 10.0f, 0.0f, 0.0f));
                textView2.setText(LocaleController.getString("PreviewFeedback", R.string.PreviewFeedback));
                textView2.setTextSize(1, 12.0f);
                textView2.setGravity(17);
                blockParagraphCell = frameLayout;
            }
            blockParagraphCell.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            blockParagraphCell.setFocusable(true);
            return new RecyclerListView.Holder(blockParagraphCell);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            if (type == 23 || type == 24) {
                return true;
            }
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (position < this.localBlocks.size()) {
                TLRPC.PageBlock block = this.localBlocks.get(position);
                bindBlockToHolder(holder.getItemViewType(), holder, block, position, this.localBlocks.size());
                return;
            }
            if (holder.getItemViewType() == 90) {
                TextView textView = (TextView) ((ViewGroup) holder.itemView).getChildAt(0);
                int color = ArticleViewer.this.getSelectedColor();
                if (color == 0) {
                    textView.setTextColor(-8879475);
                    textView.setBackgroundColor(-1183760);
                } else if (color == 1) {
                    textView.setTextColor(ArticleViewer.this.getGrayTextColor());
                    textView.setBackgroundColor(-1712440);
                } else if (color == 2) {
                    textView.setTextColor(ArticleViewer.this.getGrayTextColor());
                    textView.setBackgroundColor(-15000805);
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void bindBlockToHolder(int type, RecyclerView.ViewHolder holder, TLRPC.PageBlock block, int position, int total) {
            if (block instanceof TLRPC.TL_pageBlockCover) {
                block = ((TLRPC.TL_pageBlockCover) block).cover;
            } else if (block instanceof TL_pageBlockDetailsChild) {
                TL_pageBlockDetailsChild pageBlockDetailsChild = (TL_pageBlockDetailsChild) block;
                block = pageBlockDetailsChild.block;
            }
            if (type != 100) {
                switch (type) {
                    case 0:
                        BlockParagraphCell cell = (BlockParagraphCell) holder.itemView;
                        cell.setBlock((TLRPC.TL_pageBlockParagraph) block);
                        break;
                    case 1:
                        BlockHeaderCell cell2 = (BlockHeaderCell) holder.itemView;
                        cell2.setBlock((TLRPC.TL_pageBlockHeader) block);
                        break;
                    case 2:
                        break;
                    case 3:
                        BlockEmbedCell cell3 = (BlockEmbedCell) holder.itemView;
                        cell3.setBlock((TLRPC.TL_pageBlockEmbed) block);
                        break;
                    case 4:
                        BlockSubtitleCell cell4 = (BlockSubtitleCell) holder.itemView;
                        cell4.setBlock((TLRPC.TL_pageBlockSubtitle) block);
                        break;
                    case 5:
                        BlockVideoCell cell5 = (BlockVideoCell) holder.itemView;
                        cell5.setBlock((TLRPC.TL_pageBlockVideo) block, position == 0, position == total + (-1));
                        cell5.setParentBlock(block);
                        break;
                    case 6:
                        BlockPullquoteCell cell6 = (BlockPullquoteCell) holder.itemView;
                        cell6.setBlock((TLRPC.TL_pageBlockPullquote) block);
                        break;
                    case 7:
                        BlockBlockquoteCell cell7 = (BlockBlockquoteCell) holder.itemView;
                        cell7.setBlock((TLRPC.TL_pageBlockBlockquote) block);
                        break;
                    case 8:
                        BlockSlideshowCell cell8 = (BlockSlideshowCell) holder.itemView;
                        cell8.setBlock((TLRPC.TL_pageBlockSlideshow) block);
                        break;
                    case 9:
                        BlockPhotoCell cell9 = (BlockPhotoCell) holder.itemView;
                        cell9.setBlock((TLRPC.TL_pageBlockPhoto) block, position == 0, position == total + (-1));
                        cell9.setParentBlock(block);
                        break;
                    case 10:
                        BlockAuthorDateCell cell10 = (BlockAuthorDateCell) holder.itemView;
                        cell10.setBlock((TLRPC.TL_pageBlockAuthorDate) block);
                        break;
                    case 11:
                        BlockTitleCell cell11 = (BlockTitleCell) holder.itemView;
                        cell11.setBlock((TLRPC.TL_pageBlockTitle) block);
                        break;
                    case 12:
                        BlockListItemCell cell12 = (BlockListItemCell) holder.itemView;
                        cell12.setBlock((TL_pageBlockListItem) block);
                        break;
                    case 13:
                        BlockFooterCell cell13 = (BlockFooterCell) holder.itemView;
                        cell13.setBlock((TLRPC.TL_pageBlockFooter) block);
                        break;
                    case 14:
                        BlockPreformattedCell cell14 = (BlockPreformattedCell) holder.itemView;
                        cell14.setBlock((TLRPC.TL_pageBlockPreformatted) block);
                        break;
                    case 15:
                        BlockSubheaderCell cell15 = (BlockSubheaderCell) holder.itemView;
                        cell15.setBlock((TLRPC.TL_pageBlockSubheader) block);
                        break;
                    case 16:
                        BlockEmbedPostCell cell16 = (BlockEmbedPostCell) holder.itemView;
                        cell16.setBlock((TLRPC.TL_pageBlockEmbedPost) block);
                        break;
                    case 17:
                        BlockCollageCell cell17 = (BlockCollageCell) holder.itemView;
                        cell17.setBlock((TLRPC.TL_pageBlockCollage) block);
                        break;
                    case 18:
                        BlockChannelCell cell18 = (BlockChannelCell) holder.itemView;
                        cell18.setBlock((TLRPC.TL_pageBlockChannel) block);
                        break;
                    case 19:
                        BlockAudioCell cell19 = (BlockAudioCell) holder.itemView;
                        cell19.setBlock((TLRPC.TL_pageBlockAudio) block, position == 0, position == total + (-1));
                        break;
                    case 20:
                        BlockKickerCell cell20 = (BlockKickerCell) holder.itemView;
                        cell20.setBlock((TLRPC.TL_pageBlockKicker) block);
                        break;
                    case 21:
                        BlockOrderedListItemCell cell21 = (BlockOrderedListItemCell) holder.itemView;
                        cell21.setBlock((TL_pageBlockOrderedListItem) block);
                        break;
                    case 22:
                        BlockMapCell cell22 = (BlockMapCell) holder.itemView;
                        cell22.setBlock((TLRPC.TL_pageBlockMap) block, position == 0, position == total + (-1));
                        break;
                    case 23:
                        BlockRelatedArticlesCell cell23 = (BlockRelatedArticlesCell) holder.itemView;
                        cell23.setBlock((TL_pageBlockRelatedArticlesChild) block);
                        break;
                    case 24:
                        BlockDetailsCell cell24 = (BlockDetailsCell) holder.itemView;
                        cell24.setBlock((TLRPC.TL_pageBlockDetails) block);
                        break;
                    case 25:
                        BlockTableCell cell25 = (BlockTableCell) holder.itemView;
                        cell25.setBlock((TLRPC.TL_pageBlockTable) block);
                        break;
                    case 26:
                        BlockRelatedArticlesHeaderCell cell26 = (BlockRelatedArticlesHeaderCell) holder.itemView;
                        cell26.setBlock((TLRPC.TL_pageBlockRelatedArticles) block);
                        break;
                    case 27:
                        break;
                }
            }
            TextView textView = (TextView) holder.itemView;
            textView.setText("unsupported block " + block);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public int getTypeForBlock(TLRPC.PageBlock block) {
            if (block instanceof TLRPC.TL_pageBlockParagraph) {
                return 0;
            }
            if (block instanceof TLRPC.TL_pageBlockHeader) {
                return 1;
            }
            if (block instanceof TLRPC.TL_pageBlockDivider) {
                return 2;
            }
            if (block instanceof TLRPC.TL_pageBlockEmbed) {
                return 3;
            }
            if (block instanceof TLRPC.TL_pageBlockSubtitle) {
                return 4;
            }
            if (block instanceof TLRPC.TL_pageBlockVideo) {
                return 5;
            }
            if (block instanceof TLRPC.TL_pageBlockPullquote) {
                return 6;
            }
            if (block instanceof TLRPC.TL_pageBlockBlockquote) {
                return 7;
            }
            if (block instanceof TLRPC.TL_pageBlockSlideshow) {
                return 8;
            }
            if (block instanceof TLRPC.TL_pageBlockPhoto) {
                return 9;
            }
            if (block instanceof TLRPC.TL_pageBlockAuthorDate) {
                return 10;
            }
            if (block instanceof TLRPC.TL_pageBlockTitle) {
                return 11;
            }
            if (block instanceof TL_pageBlockListItem) {
                return 12;
            }
            if (block instanceof TLRPC.TL_pageBlockFooter) {
                return 13;
            }
            if (block instanceof TLRPC.TL_pageBlockPreformatted) {
                return 14;
            }
            if (block instanceof TLRPC.TL_pageBlockSubheader) {
                return 15;
            }
            if (block instanceof TLRPC.TL_pageBlockEmbedPost) {
                return 16;
            }
            if (block instanceof TLRPC.TL_pageBlockCollage) {
                return 17;
            }
            if (block instanceof TLRPC.TL_pageBlockChannel) {
                return 18;
            }
            if (block instanceof TLRPC.TL_pageBlockAudio) {
                return 19;
            }
            if (block instanceof TLRPC.TL_pageBlockKicker) {
                return 20;
            }
            if (block instanceof TL_pageBlockOrderedListItem) {
                return 21;
            }
            if (block instanceof TLRPC.TL_pageBlockMap) {
                return 22;
            }
            if (block instanceof TL_pageBlockRelatedArticlesChild) {
                return 23;
            }
            if (block instanceof TLRPC.TL_pageBlockDetails) {
                return 24;
            }
            if (block instanceof TLRPC.TL_pageBlockTable) {
                return 25;
            }
            if (block instanceof TLRPC.TL_pageBlockRelatedArticles) {
                return 26;
            }
            if (block instanceof TL_pageBlockDetailsBottom) {
                return 27;
            }
            if (block instanceof TL_pageBlockRelatedArticlesShadow) {
                return 28;
            }
            if (block instanceof TL_pageBlockDetailsChild) {
                TL_pageBlockDetailsChild pageBlockDetailsChild = (TL_pageBlockDetailsChild) block;
                return getTypeForBlock(pageBlockDetailsChild.block);
            }
            if (block instanceof TLRPC.TL_pageBlockCover) {
                TLRPC.TL_pageBlockCover pageBlockCover = (TLRPC.TL_pageBlockCover) block;
                return getTypeForBlock(pageBlockCover.cover);
            }
            return 100;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == this.localBlocks.size()) {
                return 90;
            }
            return getTypeForBlock(this.localBlocks.get(position));
        }

        public TLRPC.PageBlock getItem(int position) {
            return this.localBlocks.get(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (ArticleViewer.this.currentPage == null || ArticleViewer.this.currentPage.cached_page == null) {
                return 0;
            }
            return this.localBlocks.size() + 1;
        }

        private boolean isBlockOpened(TL_pageBlockDetailsChild child) {
            TLRPC.PageBlock parentBlock = ArticleViewer.this.getLastNonListPageBlock(child.parent);
            if (parentBlock instanceof TLRPC.TL_pageBlockDetails) {
                return ((TLRPC.TL_pageBlockDetails) parentBlock).open;
            }
            if (!(parentBlock instanceof TL_pageBlockDetailsChild)) {
                return false;
            }
            TL_pageBlockDetailsChild parent = (TL_pageBlockDetailsChild) parentBlock;
            TLRPC.PageBlock parentBlock2 = ArticleViewer.this.getLastNonListPageBlock(parent.block);
            if (!(parentBlock2 instanceof TLRPC.TL_pageBlockDetails) || ((TLRPC.TL_pageBlockDetails) parentBlock2).open) {
                return isBlockOpened(parent);
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX WARN: Removed duplicated region for block: B:9:0x002a  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void updateRows() {
            /*
                r6 = this;
                java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$PageBlock> r0 = r6.localBlocks
                r0.clear()
                r0 = 0
                java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$PageBlock> r1 = r6.blocks
                int r1 = r1.size()
            Lc:
                if (r0 >= r1) goto L32
                java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$PageBlock> r2 = r6.blocks
                java.lang.Object r2 = r2.get(r0)
                im.uwrkaxlmjj.tgnet.TLRPC$PageBlock r2 = (im.uwrkaxlmjj.tgnet.TLRPC.PageBlock) r2
                im.uwrkaxlmjj.ui.ArticleViewer r3 = im.uwrkaxlmjj.ui.ArticleViewer.this
                im.uwrkaxlmjj.tgnet.TLRPC$PageBlock r3 = im.uwrkaxlmjj.ui.ArticleViewer.access$10700(r3, r2)
                boolean r4 = r3 instanceof im.uwrkaxlmjj.ui.ArticleViewer.TL_pageBlockDetailsChild
                if (r4 == 0) goto L2a
                r4 = r3
                im.uwrkaxlmjj.ui.ArticleViewer$TL_pageBlockDetailsChild r4 = (im.uwrkaxlmjj.ui.ArticleViewer.TL_pageBlockDetailsChild) r4
                boolean r5 = r6.isBlockOpened(r4)
                if (r5 != 0) goto L2a
                goto L2f
            L2a:
                java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$PageBlock> r4 = r6.localBlocks
                r4.add(r2)
            L2f:
                int r0 = r0 + 1
                goto Lc
            L32:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.WebpageAdapter.updateRows():void");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void cleanup() {
            this.blocks.clear();
            this.photoBlocks.clear();
            this.audioBlocks.clear();
            this.audioMessages.clear();
            this.anchors.clear();
            this.anchorsParent.clear();
            this.anchorsOffset.clear();
            notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            updateRows();
            super.notifyDataSetChanged();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemChanged(int position) {
            updateRows();
            super.notifyItemChanged(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemChanged(int position, Object payload) {
            updateRows();
            super.notifyItemChanged(position, payload);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeChanged(int positionStart, int itemCount) {
            updateRows();
            super.notifyItemRangeChanged(positionStart, itemCount);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeChanged(int positionStart, int itemCount, Object payload) {
            updateRows();
            super.notifyItemRangeChanged(positionStart, itemCount, payload);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemInserted(int position) {
            updateRows();
            super.notifyItemInserted(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemMoved(int fromPosition, int toPosition) {
            updateRows();
            super.notifyItemMoved(fromPosition, toPosition);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeInserted(int positionStart, int itemCount) {
            updateRows();
            super.notifyItemRangeInserted(positionStart, itemCount);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRemoved(int position) {
            updateRows();
            super.notifyItemRemoved(position);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeRemoved(int positionStart, int itemCount) {
            updateRows();
            super.notifyItemRangeRemoved(positionStart, itemCount);
        }
    }

    private class BlockVideoCell extends FrameLayout implements DownloadController.FileDownloadProgressListener {
        private int TAG;
        private boolean autoDownload;
        private int buttonPressed;
        private int buttonState;
        private int buttonX;
        private int buttonY;
        private boolean cancelLoading;
        private DrawingText captionLayout;
        private BlockChannelCell channelCell;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockVideo currentBlock;
        private TLRPC.Document currentDocument;
        private int currentType;
        private MessageObject.GroupedMessagePosition groupPosition;
        private ImageReceiver imageView;
        private boolean isFirst;
        private boolean isGif;
        private boolean isLast;
        private WebpageAdapter parentAdapter;
        private TLRPC.PageBlock parentBlock;
        private boolean photoPressed;
        private RadialProgress2 radialProgress;
        private int textX;
        private int textY;

        public BlockVideoCell(Context context, WebpageAdapter adapter, int type) {
            super(context);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
            ImageReceiver imageReceiver = new ImageReceiver(this);
            this.imageView = imageReceiver;
            imageReceiver.setNeedsQualityThumb(true);
            this.imageView.setShouldGenerateQualityThumb(true);
            this.currentType = type;
            RadialProgress2 radialProgress2 = new RadialProgress2(this);
            this.radialProgress = radialProgress2;
            radialProgress2.setProgressColor(-1);
            this.radialProgress.setColors(1711276032, Theme.ACTION_BAR_PHOTO_VIEWER_COLOR, -1, -2500135);
            this.TAG = DownloadController.getInstance(ArticleViewer.this.currentAccount).generateObserverTag();
            BlockChannelCell blockChannelCell = ArticleViewer.this.new BlockChannelCell(context, this.parentAdapter, 1);
            this.channelCell = blockChannelCell;
            addView(blockChannelCell, LayoutHelper.createFrame(-1, -2.0f));
        }

        public void setBlock(TLRPC.TL_pageBlockVideo block, boolean first, boolean last) {
            this.currentBlock = block;
            this.parentBlock = null;
            this.cancelLoading = false;
            TLRPC.Document documentWithId = ArticleViewer.this.getDocumentWithId(block.video_id);
            this.currentDocument = documentWithId;
            this.isGif = MessageObject.isGifDocument(documentWithId);
            this.isFirst = first;
            this.isLast = last;
            this.channelCell.setVisibility(4);
            updateButtonState(false);
            requestLayout();
        }

        public void setParentBlock(TLRPC.PageBlock block) {
            this.parentBlock = block;
            if (ArticleViewer.this.channelBlock != null && (this.parentBlock instanceof TLRPC.TL_pageBlockCover)) {
                this.channelCell.setBlock(ArticleViewer.this.channelBlock);
                this.channelCell.setVisibility(0);
            }
        }

        public View getChannelCell() {
            return this.channelCell;
        }

        /* JADX WARN: Removed duplicated region for block: B:28:0x0097  */
        /* JADX WARN: Removed duplicated region for block: B:30:0x009b  */
        @Override // android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean onTouchEvent(android.view.MotionEvent r12) {
            /*
                Method dump skipped, instruction units count: 261
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.BlockVideoCell.onTouchEvent(android.view.MotionEvent):boolean");
        }

        /* JADX WARN: Removed duplicated region for block: B:107:0x0319  */
        @Override // android.widget.FrameLayout, android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        protected void onMeasure(int r30, int r31) {
            /*
                Method dump skipped, instruction units count: 843
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.BlockVideoCell.onMeasure(int, int):void");
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (!this.imageView.hasBitmapImage() || this.imageView.getCurrentAlpha() != 1.0f) {
                canvas.drawRect(this.imageView.getDrawRegion(), ArticleViewer.photoBackgroundPaint);
            }
            this.imageView.draw(canvas);
            if (this.imageView.getVisible()) {
                this.radialProgress.draw(canvas);
            }
            this.textY = this.imageView.getImageY() + this.imageView.getImageHeight() + AndroidUtilities.dp(8.0f);
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }

        private int getIconForCurrentState() {
            int i = this.buttonState;
            if (i == 0) {
                return 2;
            }
            if (i == 1) {
                return 3;
            }
            if (i == 2) {
                return 8;
            }
            if (i == 3) {
                return 0;
            }
            return 4;
        }

        public void updateButtonState(boolean animated) {
            String fileName = FileLoader.getAttachFileName(this.currentDocument);
            File path = FileLoader.getPathToAttach(this.currentDocument, true);
            boolean fileExists = path.exists();
            if (TextUtils.isEmpty(fileName)) {
                this.radialProgress.setIcon(4, false, false);
                return;
            }
            if (fileExists) {
                DownloadController.getInstance(ArticleViewer.this.currentAccount).removeLoadingFileObserver(this);
                if (!this.isGif) {
                    this.buttonState = 3;
                } else {
                    this.buttonState = -1;
                }
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                invalidate();
                return;
            }
            DownloadController.getInstance(ArticleViewer.this.currentAccount).addLoadingFileObserver(fileName, null, this);
            float setProgress = 0.0f;
            boolean progressVisible = false;
            if (!FileLoader.getInstance(ArticleViewer.this.currentAccount).isLoadingFile(fileName)) {
                if (!this.cancelLoading && this.autoDownload && this.isGif) {
                    progressVisible = true;
                    this.buttonState = 1;
                } else {
                    this.buttonState = 0;
                }
            } else {
                progressVisible = true;
                this.buttonState = 1;
                Float progress = ImageLoader.getInstance().getFileProgress(fileName);
                setProgress = progress != null ? progress.floatValue() : 0.0f;
            }
            this.radialProgress.setIcon(getIconForCurrentState(), progressVisible, animated);
            this.radialProgress.setProgress(setProgress, false);
            invalidate();
        }

        private void didPressedButton(boolean animated) {
            int i = this.buttonState;
            if (i == 0) {
                this.cancelLoading = false;
                this.radialProgress.setProgress(0.0f, false);
                if (!this.isGif) {
                    FileLoader.getInstance(ArticleViewer.this.currentAccount).loadFile(this.currentDocument, ArticleViewer.this.currentPage, 1, 1);
                } else {
                    TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(this.currentDocument.thumbs, 40);
                    this.imageView.setImage(ImageLocation.getForDocument(this.currentDocument), null, ImageLocation.getForDocument(thumb, this.currentDocument), "80_80_b", this.currentDocument.size, null, ArticleViewer.this.currentPage, 1);
                }
                this.buttonState = 1;
                this.radialProgress.setIcon(getIconForCurrentState(), true, animated);
                invalidate();
                return;
            }
            if (i == 1) {
                this.cancelLoading = true;
                if (!this.isGif) {
                    FileLoader.getInstance(ArticleViewer.this.currentAccount).cancelLoadFile(this.currentDocument);
                } else {
                    this.imageView.cancelLoadImage();
                }
                this.buttonState = 0;
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                invalidate();
                return;
            }
            if (i == 2) {
                this.imageView.setAllowStartAnimation(true);
                this.imageView.startAnimation();
                this.buttonState = -1;
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                return;
            }
            if (i == 3) {
                ArticleViewer.this.openPhoto(this.currentBlock);
            }
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            this.imageView.onDetachedFromWindow();
            DownloadController.getInstance(ArticleViewer.this.currentAccount).removeLoadingFileObserver(this);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            this.imageView.onAttachedToWindow();
            updateButtonState(false);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onFailedDownload(String fileName, boolean canceled) {
            updateButtonState(false);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onSuccessDownload(String fileName) {
            this.radialProgress.setProgress(1.0f, true);
            if (this.isGif) {
                this.buttonState = 2;
                didPressedButton(true);
            } else {
                updateButtonState(true);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressDownload(String fileName, float progress) {
            this.radialProgress.setProgress(progress, true);
            if (this.buttonState != 1) {
                updateButtonState(true);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public int getObserverTag() {
            return this.TAG;
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            StringBuilder sb = new StringBuilder(LocaleController.getString("AttachVideo", R.string.AttachVideo));
            if (this.captionLayout != null) {
                sb.append(", ");
                sb.append(this.captionLayout.getText());
            }
            info.setText(sb.toString());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class BlockAudioCell extends View implements DownloadController.FileDownloadProgressListener {
        private int TAG;
        private int buttonPressed;
        private int buttonState;
        private int buttonX;
        private int buttonY;
        private DrawingText captionLayout;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockAudio currentBlock;
        private TLRPC.Document currentDocument;
        private MessageObject currentMessageObject;
        private StaticLayout durationLayout;
        private boolean isFirst;
        private boolean isLast;
        private String lastTimeString;
        private WebpageAdapter parentAdapter;
        private RadialProgress2 radialProgress;
        private SeekBar seekBar;
        private int seekBarX;
        private int seekBarY;
        private int textX;
        private int textY;
        private StaticLayout titleLayout;

        public BlockAudioCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textY = AndroidUtilities.dp(54.0f);
            this.parentAdapter = adapter;
            RadialProgress2 radialProgress2 = new RadialProgress2(this);
            this.radialProgress = radialProgress2;
            radialProgress2.setBackgroundStroke(AndroidUtilities.dp(3.0f));
            this.radialProgress.setCircleRadius(AndroidUtilities.dp(24.0f));
            this.TAG = DownloadController.getInstance(ArticleViewer.this.currentAccount).generateObserverTag();
            SeekBar seekBar = new SeekBar(context);
            this.seekBar = seekBar;
            seekBar.setDelegate(new SeekBar.SeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$BlockAudioCell$MCkJ-R_fpBhQttlsQEizVOoKT4M
                @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
                public /* synthetic */ void onSeekBarContinuousDrag(float f) {
                    SeekBar.SeekBarDelegate.CC.$default$onSeekBarContinuousDrag(this, f);
                }

                @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
                public final void onSeekBarDrag(float f) {
                    this.f$0.lambda$new$0$ArticleViewer$BlockAudioCell(f);
                }
            });
        }

        public /* synthetic */ void lambda$new$0$ArticleViewer$BlockAudioCell(float progress) {
            MessageObject messageObject = this.currentMessageObject;
            if (messageObject == null) {
                return;
            }
            messageObject.audioProgress = progress;
            MediaController.getInstance().seekToProgress(this.currentMessageObject, progress);
        }

        public void setBlock(TLRPC.TL_pageBlockAudio block, boolean first, boolean last) {
            this.currentBlock = block;
            MessageObject messageObject = (MessageObject) this.parentAdapter.audioBlocks.get(this.currentBlock);
            this.currentMessageObject = messageObject;
            this.currentDocument = messageObject.getDocument();
            this.isFirst = first;
            this.isLast = last;
            this.radialProgress.setProgressColor(ArticleViewer.this.getTextColor());
            this.seekBar.setColors(ArticleViewer.this.getTextColor() & 1073741823, ArticleViewer.this.getTextColor() & 1073741823, ArticleViewer.this.getTextColor(), ArticleViewer.this.getTextColor(), ArticleViewer.this.getTextColor());
            updateButtonState(false);
            requestLayout();
        }

        public MessageObject getMessageObject() {
            return this.currentMessageObject;
        }

        /* JADX WARN: Removed duplicated region for block: B:21:0x0066  */
        /* JADX WARN: Removed duplicated region for block: B:23:0x006a  */
        @Override // android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean onTouchEvent(android.view.MotionEvent r13) {
            /*
                r12 = this;
                float r0 = r13.getX()
                float r1 = r13.getY()
                im.uwrkaxlmjj.ui.components.SeekBar r2 = r12.seekBar
                int r3 = r13.getAction()
                float r4 = r13.getX()
                int r5 = r12.seekBarX
                float r5 = (float) r5
                float r4 = r4 - r5
                float r5 = r13.getY()
                int r6 = r12.seekBarY
                float r6 = (float) r6
                float r5 = r5 - r6
                boolean r2 = r2.onTouch(r3, r4, r5)
                r3 = 1
                if (r2 == 0) goto L36
                int r4 = r13.getAction()
                if (r4 != 0) goto L32
                android.view.ViewParent r4 = r12.getParent()
                r4.requestDisallowInterceptTouchEvent(r3)
            L32:
                r12.invalidate()
                return r3
            L36:
                int r4 = r13.getAction()
                r5 = 0
                if (r4 != 0) goto L70
                int r4 = r12.buttonState
                r6 = -1
                if (r4 == r6) goto L66
                int r4 = r12.buttonX
                float r6 = (float) r4
                int r6 = (r0 > r6 ? 1 : (r0 == r6 ? 0 : -1))
                if (r6 < 0) goto L66
                r6 = 1111490560(0x42400000, float:48.0)
                int r7 = im.uwrkaxlmjj.messenger.AndroidUtilities.dp(r6)
                int r4 = r4 + r7
                float r4 = (float) r4
                int r4 = (r0 > r4 ? 1 : (r0 == r4 ? 0 : -1))
                if (r4 > 0) goto L66
                int r4 = r12.buttonY
                float r7 = (float) r4
                int r7 = (r1 > r7 ? 1 : (r1 == r7 ? 0 : -1))
                if (r7 < 0) goto L66
                int r6 = im.uwrkaxlmjj.messenger.AndroidUtilities.dp(r6)
                int r4 = r4 + r6
                float r4 = (float) r4
                int r4 = (r1 > r4 ? 1 : (r1 == r4 ? 0 : -1))
                if (r4 <= 0) goto L6a
            L66:
                int r4 = r12.buttonState
                if (r4 != 0) goto L8f
            L6a:
                r12.buttonPressed = r3
                r12.invalidate()
                goto L8f
            L70:
                int r4 = r13.getAction()
                if (r4 != r3) goto L86
                int r4 = r12.buttonPressed
                if (r4 != r3) goto L8f
                r12.buttonPressed = r5
                r12.playSoundEffect(r5)
                r12.didPressedButton(r3)
                r12.invalidate()
                goto L8f
            L86:
                int r4 = r13.getAction()
                r6 = 3
                if (r4 != r6) goto L8f
                r12.buttonPressed = r5
            L8f:
                int r4 = r12.buttonPressed
                if (r4 != 0) goto Lbf
                im.uwrkaxlmjj.ui.ArticleViewer r6 = im.uwrkaxlmjj.ui.ArticleViewer.this
                im.uwrkaxlmjj.ui.ArticleViewer$DrawingText r9 = r12.captionLayout
                int r10 = r12.textX
                int r11 = r12.textY
                r7 = r13
                r8 = r12
                boolean r4 = im.uwrkaxlmjj.ui.ArticleViewer.access$8100(r6, r7, r8, r9, r10, r11)
                if (r4 != 0) goto Lbf
                im.uwrkaxlmjj.ui.ArticleViewer r6 = im.uwrkaxlmjj.ui.ArticleViewer.this
                im.uwrkaxlmjj.ui.ArticleViewer$DrawingText r9 = r12.creditLayout
                int r10 = r12.textX
                int r4 = r12.textY
                int r7 = r12.creditOffset
                int r11 = r4 + r7
                r7 = r13
                r8 = r12
                boolean r4 = im.uwrkaxlmjj.ui.ArticleViewer.access$8100(r6, r7, r8, r9, r10, r11)
                if (r4 != 0) goto Lbf
                boolean r4 = super.onTouchEvent(r13)
                if (r4 == 0) goto Lbe
                goto Lbf
            Lbe:
                r3 = 0
            Lbf:
                return r3
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.BlockAudioCell.onTouchEvent(android.view.MotionEvent):boolean");
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            SpannableStringBuilder stringBuilder;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height2 = AndroidUtilities.dp(54.0f);
            TLRPC.TL_pageBlockAudio tL_pageBlockAudio = this.currentBlock;
            if (tL_pageBlockAudio != null) {
                if (tL_pageBlockAudio.level > 0) {
                    this.textX = AndroidUtilities.dp(this.currentBlock.level * 14) + AndroidUtilities.dp(18.0f);
                } else {
                    this.textX = AndroidUtilities.dp(18.0f);
                }
                int textWidth = (width - this.textX) - AndroidUtilities.dp(18.0f);
                int size = AndroidUtilities.dp(44.0f);
                this.buttonX = AndroidUtilities.dp(16.0f);
                int iDp = AndroidUtilities.dp(5.0f);
                this.buttonY = iDp;
                RadialProgress2 radialProgress2 = this.radialProgress;
                int i = this.buttonX;
                radialProgress2.setProgressRect(i, iDp, i + size, iDp + size);
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                this.captionLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    int iDp2 = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                    this.creditOffset = iDp2;
                    height = height2 + iDp2 + AndroidUtilities.dp(4.0f);
                } else {
                    height = height2;
                }
                DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.creditLayout = drawingTextCreateLayoutForText2;
                if (drawingTextCreateLayoutForText2 != null) {
                    height += AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                }
                if (!this.isFirst && this.currentBlock.level <= 0) {
                    height += AndroidUtilities.dp(8.0f);
                }
                String author = this.currentMessageObject.getMusicAuthor(false);
                String title = this.currentMessageObject.getMusicTitle(false);
                int iDp3 = this.buttonX + AndroidUtilities.dp(50.0f) + size;
                this.seekBarX = iDp3;
                int w = (width - iDp3) - AndroidUtilities.dp(18.0f);
                if (TextUtils.isEmpty(title) && TextUtils.isEmpty(author)) {
                    this.titleLayout = null;
                    this.seekBarY = this.buttonY + ((size - AndroidUtilities.dp(30.0f)) / 2);
                } else {
                    if (!TextUtils.isEmpty(title) && !TextUtils.isEmpty(author)) {
                        stringBuilder = new SpannableStringBuilder(String.format("%s - %s", author, title));
                    } else if (!TextUtils.isEmpty(title)) {
                        stringBuilder = new SpannableStringBuilder(title);
                    } else {
                        stringBuilder = new SpannableStringBuilder(author);
                    }
                    if (!TextUtils.isEmpty(author)) {
                        TypefaceSpan span = new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                        stringBuilder.setSpan(span, 0, author.length(), 18);
                    }
                    CharSequence stringFinal = TextUtils.ellipsize(stringBuilder, Theme.chat_audioTitlePaint, w, TextUtils.TruncateAt.END);
                    this.titleLayout = new StaticLayout(stringFinal, ArticleViewer.audioTimePaint, w, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    this.seekBarY = this.buttonY + ((size - AndroidUtilities.dp(30.0f)) / 2) + AndroidUtilities.dp(11.0f);
                }
                this.seekBar.setSize(w, AndroidUtilities.dp(30.0f));
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
            updatePlayingMessageProgress();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null) {
                this.radialProgress.setColors(ArticleViewer.this.getTextColor(), ArticleViewer.this.getTextColor(), ArticleViewer.this.getTextColor(), ArticleViewer.this.getTextColor());
                this.radialProgress.draw(canvas);
                canvas.save();
                canvas.translate(this.seekBarX, this.seekBarY);
                this.seekBar.draw(canvas);
                canvas.restore();
                if (this.durationLayout != null) {
                    canvas.save();
                    canvas.translate(this.buttonX + AndroidUtilities.dp(54.0f), this.seekBarY + AndroidUtilities.dp(6.0f));
                    this.durationLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.titleLayout != null) {
                    canvas.save();
                    canvas.translate(this.buttonX + AndroidUtilities.dp(54.0f), this.seekBarY - AndroidUtilities.dp(16.0f));
                    this.titleLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.captionLayout != null) {
                    canvas.save();
                    canvas.translate(this.textX, this.textY);
                    this.captionLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.creditLayout != null) {
                    canvas.save();
                    canvas.translate(this.textX, this.textY + this.creditOffset);
                    this.creditLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.currentBlock.level > 0) {
                    canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
                }
            }
        }

        private int getIconForCurrentState() {
            int i = this.buttonState;
            if (i == 1) {
                return 1;
            }
            if (i == 2) {
                return 2;
            }
            if (i == 3) {
                return 3;
            }
            return 0;
        }

        public void updatePlayingMessageProgress() {
            if (this.currentDocument == null || this.currentMessageObject == null) {
                return;
            }
            if (!this.seekBar.isDragging()) {
                this.seekBar.setProgress(this.currentMessageObject.audioProgress);
            }
            int duration = 0;
            if (MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                duration = this.currentMessageObject.audioProgressSec;
            } else {
                int a = 0;
                while (true) {
                    if (a >= this.currentDocument.attributes.size()) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute = this.currentDocument.attributes.get(a);
                    if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                        a++;
                    } else {
                        duration = attribute.duration;
                        break;
                    }
                }
            }
            String timeString = String.format("%d:%02d", Integer.valueOf(duration / 60), Integer.valueOf(duration % 60));
            String str = this.lastTimeString;
            if (str == null || (str != null && !str.equals(timeString))) {
                this.lastTimeString = timeString;
                ArticleViewer.audioTimePaint.setTextSize(AndroidUtilities.dp(16.0f));
                int timeWidth = (int) Math.ceil(ArticleViewer.audioTimePaint.measureText(timeString));
                this.durationLayout = new StaticLayout(timeString, ArticleViewer.audioTimePaint, timeWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            }
            ArticleViewer.audioTimePaint.setColor(ArticleViewer.this.getTextColor());
            invalidate();
        }

        public void updateButtonState(boolean animated) {
            String fileName = FileLoader.getAttachFileName(this.currentDocument);
            File path = FileLoader.getPathToAttach(this.currentDocument, true);
            boolean fileExists = path.exists();
            if (TextUtils.isEmpty(fileName)) {
                this.radialProgress.setIcon(4, false, false);
                return;
            }
            if (fileExists) {
                DownloadController.getInstance(ArticleViewer.this.currentAccount).removeLoadingFileObserver(this);
                boolean playing = MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
                if (!playing || (playing && MediaController.getInstance().isMessagePaused())) {
                    this.buttonState = 0;
                } else {
                    this.buttonState = 1;
                }
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
            } else {
                DownloadController.getInstance(ArticleViewer.this.currentAccount).addLoadingFileObserver(fileName, null, this);
                if (!FileLoader.getInstance(ArticleViewer.this.currentAccount).isLoadingFile(fileName)) {
                    this.buttonState = 2;
                    this.radialProgress.setProgress(0.0f, animated);
                    this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                } else {
                    this.buttonState = 3;
                    Float progress = ImageLoader.getInstance().getFileProgress(fileName);
                    if (progress != null) {
                        this.radialProgress.setProgress(progress.floatValue(), animated);
                    } else {
                        this.radialProgress.setProgress(0.0f, animated);
                    }
                    this.radialProgress.setIcon(getIconForCurrentState(), true, animated);
                }
            }
            updatePlayingMessageProgress();
        }

        private void didPressedButton(boolean animated) {
            int i = this.buttonState;
            if (i == 0) {
                if (MediaController.getInstance().setPlaylist(this.parentAdapter.audioMessages, this.currentMessageObject, false)) {
                    this.buttonState = 1;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                    invalidate();
                    return;
                }
                return;
            }
            if (i == 1) {
                boolean result = MediaController.getInstance().lambda$startAudioAgain$5$MediaController(this.currentMessageObject);
                if (result) {
                    this.buttonState = 0;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                    invalidate();
                    return;
                }
                return;
            }
            if (i == 2) {
                this.radialProgress.setProgress(0.0f, false);
                FileLoader.getInstance(ArticleViewer.this.currentAccount).loadFile(this.currentDocument, ArticleViewer.this.currentPage, 1, 1);
                this.buttonState = 3;
                this.radialProgress.setIcon(getIconForCurrentState(), true, animated);
                invalidate();
                return;
            }
            if (i == 3) {
                FileLoader.getInstance(ArticleViewer.this.currentAccount).cancelLoadFile(this.currentDocument);
                this.buttonState = 2;
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                invalidate();
            }
        }

        @Override // android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            DownloadController.getInstance(ArticleViewer.this.currentAccount).removeLoadingFileObserver(this);
        }

        @Override // android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            updateButtonState(false);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onFailedDownload(String fileName, boolean canceled) {
            updateButtonState(true);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onSuccessDownload(String fileName) {
            this.radialProgress.setProgress(1.0f, true);
            updateButtonState(true);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressDownload(String fileName, float progress) {
            this.radialProgress.setProgress(progress, true);
            if (this.buttonState != 3) {
                updateButtonState(true);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public int getObserverTag() {
            return this.TAG;
        }
    }

    private class BlockEmbedPostCell extends View {
        private AvatarDrawable avatarDrawable;
        private ImageReceiver avatarImageView;
        private boolean avatarVisible;
        private DrawingText captionLayout;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockEmbedPost currentBlock;
        private DrawingText dateLayout;
        private int dateX;
        private int lineHeight;
        private DrawingText nameLayout;
        private int nameX;
        private WebpageAdapter parentAdapter;
        private int textX;
        private int textY;

        public BlockEmbedPostCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
            ImageReceiver imageReceiver = new ImageReceiver(this);
            this.avatarImageView = imageReceiver;
            imageReceiver.setRoundRadius(AndroidUtilities.dp(20.0f));
            this.avatarImageView.setImageCoords(AndroidUtilities.dp(32.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(40.0f), AndroidUtilities.dp(40.0f));
            this.avatarDrawable = new AvatarDrawable();
        }

        public void setBlock(TLRPC.TL_pageBlockEmbedPost block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.captionLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.creditLayout, this.textX, this.textY + this.creditOffset) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockEmbedPost tL_pageBlockEmbedPost = this.currentBlock;
            if (tL_pageBlockEmbedPost != null) {
                if (!(tL_pageBlockEmbedPost instanceof TL_pageBlockEmbedPostCaption)) {
                    boolean z = tL_pageBlockEmbedPost.author_photo_id != 0;
                    this.avatarVisible = z;
                    if (z) {
                        TLRPC.Photo photo = ArticleViewer.this.getPhotoWithId(this.currentBlock.author_photo_id);
                        boolean z2 = photo instanceof TLRPC.TL_photo;
                        this.avatarVisible = z2;
                        if (z2) {
                            this.avatarDrawable.setInfo(0, this.currentBlock.author, null);
                            TLRPC.PhotoSize image = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.dp(40.0f), true);
                            this.avatarImageView.setImage(ImageLocation.getForPhoto(image, photo), "40_40", this.avatarDrawable, 0, (String) null, ArticleViewer.this.currentPage, 1);
                        }
                    }
                    this.nameLayout = ArticleViewer.this.createLayoutForText(this, this.currentBlock.author, null, width - AndroidUtilities.dp((this.avatarVisible ? 54 : 0) + 50), 0, this.currentBlock, Layout.Alignment.ALIGN_NORMAL, 1, this.parentAdapter);
                    if (this.currentBlock.date != 0) {
                        this.dateLayout = ArticleViewer.this.createLayoutForText(this, LocaleController.getInstance().chatFullDate.format(((long) this.currentBlock.date) * 1000), null, width - AndroidUtilities.dp((this.avatarVisible ? 54 : 0) + 50), this.currentBlock, this.parentAdapter);
                    } else {
                        this.dateLayout = null;
                    }
                    height = AndroidUtilities.dp(56.0f);
                    if (this.currentBlock.blocks.isEmpty()) {
                        int textWidth = width - AndroidUtilities.dp(50.0f);
                        DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                        this.captionLayout = drawingTextCreateLayoutForText;
                        if (drawingTextCreateLayoutForText != null) {
                            int iDp = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                            this.creditOffset = iDp;
                            height += iDp + AndroidUtilities.dp(4.0f);
                        }
                        DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                        this.creditLayout = drawingTextCreateLayoutForText2;
                        if (drawingTextCreateLayoutForText2 != null) {
                            height += AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                        }
                        this.textX = AndroidUtilities.dp(32.0f);
                        this.textY = AndroidUtilities.dp(56.0f);
                    } else {
                        this.captionLayout = null;
                        this.creditLayout = null;
                    }
                } else {
                    int textWidth2 = width - AndroidUtilities.dp(50.0f);
                    DrawingText drawingTextCreateLayoutForText3 = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth2, this.currentBlock, this.parentAdapter);
                    this.captionLayout = drawingTextCreateLayoutForText3;
                    if (drawingTextCreateLayoutForText3 != null) {
                        int iDp2 = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                        this.creditOffset = iDp2;
                        int height2 = 0 + iDp2 + AndroidUtilities.dp(4.0f);
                        height = height2;
                    } else {
                        height = 0;
                    }
                    DrawingText drawingTextCreateLayoutForText4 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth2, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                    this.creditLayout = drawingTextCreateLayoutForText4;
                    if (drawingTextCreateLayoutForText4 != null) {
                        height += AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                    }
                    this.textX = AndroidUtilities.dp(18.0f);
                    this.textY = AndroidUtilities.dp(4.0f);
                }
                this.lineHeight = height;
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            TLRPC.TL_pageBlockEmbedPost tL_pageBlockEmbedPost = this.currentBlock;
            if (tL_pageBlockEmbedPost == null) {
                return;
            }
            if (!(tL_pageBlockEmbedPost instanceof TL_pageBlockEmbedPostCaption)) {
                if (this.avatarVisible) {
                    this.avatarImageView.draw(canvas);
                }
                if (this.nameLayout != null) {
                    canvas.save();
                    canvas.translate(AndroidUtilities.dp((this.avatarVisible ? 54 : 0) + 32), AndroidUtilities.dp(this.dateLayout != null ? 10.0f : 19.0f));
                    this.nameLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.dateLayout != null) {
                    canvas.save();
                    canvas.translate(AndroidUtilities.dp((this.avatarVisible ? 54 : 0) + 32), AndroidUtilities.dp(29.0f));
                    this.dateLayout.draw(canvas);
                    canvas.restore();
                }
                canvas.drawRect(AndroidUtilities.dp(18.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(20.0f), this.lineHeight - (this.currentBlock.level == 0 ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
        }
    }

    private class BlockParagraphCell extends View {
        private TLRPC.TL_pageBlockParagraph currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockParagraphCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockParagraph block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TLRPC.TL_pageBlockParagraph tL_pageBlockParagraph = this.currentBlock;
            if (tL_pageBlockParagraph != null) {
                if (tL_pageBlockParagraph.level == 0) {
                    this.textY = AndroidUtilities.dp(8.0f);
                    this.textX = AndroidUtilities.dp(18.0f);
                } else {
                    this.textY = 0;
                    this.textX = AndroidUtilities.dp((this.currentBlock.level * 14) + 18);
                }
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.text, (width - AndroidUtilities.dp(18.0f)) - this.textX, this.textY, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, 0, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    int height2 = drawingTextCreateLayoutForText.getHeight();
                    if (this.currentBlock.level > 0) {
                        height = height2 + AndroidUtilities.dp(8.0f);
                    } else {
                        height = height2 + AndroidUtilities.dp(16.0f);
                    }
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            DrawingText drawingText = this.textLayout;
            if (drawingText == null) {
                return;
            }
            info.setText(drawingText.getText());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class BlockEmbedCell extends FrameLayout {
        private DrawingText captionLayout;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockEmbed currentBlock;
        private int exactWebViewHeight;
        private int listX;
        private WebpageAdapter parentAdapter;
        private int textX;
        private int textY;
        private WebPlayerView videoView;
        private boolean wasUserInteraction;
        private TouchyWebView webView;

        /* JADX INFO: Access modifiers changed from: private */
        class WebviewProxy {
            private WebviewProxy() {
            }

            @JavascriptInterface
            public void postEvent(final String eventName, final String eventData) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$BlockEmbedCell$WebviewProxy$4bN8vZb1wsGz6V4YEV9E8yCH9ks
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$postEvent$0$ArticleViewer$BlockEmbedCell$WebviewProxy(eventName, eventData);
                    }
                });
            }

            public /* synthetic */ void lambda$postEvent$0$ArticleViewer$BlockEmbedCell$WebviewProxy(String eventName, String eventData) {
                if ("resize_frame".equals(eventName)) {
                    try {
                        JSONObject object = new JSONObject(eventData);
                        BlockEmbedCell.this.exactWebViewHeight = Utilities.parseInt(object.getString("height")).intValue();
                        BlockEmbedCell.this.requestLayout();
                    } catch (Throwable th) {
                    }
                }
            }
        }

        public class TouchyWebView extends WebView {
            public TouchyWebView(Context context) {
                super(context);
                setFocusable(false);
            }

            @Override // android.webkit.WebView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                BlockEmbedCell.this.wasUserInteraction = true;
                if (BlockEmbedCell.this.currentBlock != null) {
                    if (!BlockEmbedCell.this.currentBlock.allow_scrolling) {
                        ArticleViewer.this.windowView.requestDisallowInterceptTouchEvent(true);
                    } else {
                        requestDisallowInterceptTouchEvent(true);
                    }
                }
                return super.onTouchEvent(event);
            }
        }

        public BlockEmbedCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
            WebPlayerView webPlayerView = new WebPlayerView(context, false, false, new WebPlayerView.WebPlayerViewDelegate() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockEmbedCell.1
                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public void onInitFailed() {
                    BlockEmbedCell.this.webView.setVisibility(0);
                    BlockEmbedCell.this.videoView.setVisibility(4);
                    BlockEmbedCell.this.videoView.loadVideo(null, null, null, null, false);
                    HashMap<String, String> args = new HashMap<>();
                    args.put("Referer", "http://youtube.com");
                    BlockEmbedCell.this.webView.loadUrl(BlockEmbedCell.this.currentBlock.url, args);
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public void onVideoSizeChanged(float aspectRatio, int rotation) {
                    ArticleViewer.this.fullscreenAspectRatioView.setAspectRatio(aspectRatio, rotation);
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public void onInlineSurfaceTextureReady() {
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public TextureView onSwitchToFullscreen(View controlsView, boolean fullscreen, float aspectRatio, int rotation, boolean byButton) {
                    if (fullscreen) {
                        ArticleViewer.this.fullscreenAspectRatioView.addView(ArticleViewer.this.fullscreenTextureView, LayoutHelper.createFrame(-1, -1.0f));
                        ArticleViewer.this.fullscreenAspectRatioView.setVisibility(0);
                        ArticleViewer.this.fullscreenAspectRatioView.setAspectRatio(aspectRatio, rotation);
                        ArticleViewer.this.fullscreenedVideo = BlockEmbedCell.this.videoView;
                        ArticleViewer.this.fullscreenVideoContainer.addView(controlsView, LayoutHelper.createFrame(-1, -1.0f));
                        ArticleViewer.this.fullscreenVideoContainer.setVisibility(0);
                    } else {
                        ArticleViewer.this.fullscreenAspectRatioView.removeView(ArticleViewer.this.fullscreenTextureView);
                        ArticleViewer.this.fullscreenedVideo = null;
                        ArticleViewer.this.fullscreenAspectRatioView.setVisibility(8);
                        ArticleViewer.this.fullscreenVideoContainer.setVisibility(4);
                    }
                    return ArticleViewer.this.fullscreenTextureView;
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public void prepareToSwitchInlineMode(boolean inline, Runnable switchInlineModeRunnable, float aspectRatio, boolean animated) {
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public TextureView onSwitchInlineMode(View controlsView, boolean inline, float aspectRatio, int rotation, boolean animated) {
                    return null;
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public void onSharePressed() {
                    if (ArticleViewer.this.parentActivity != null) {
                        ArticleViewer.this.showDialog(new ShareAlert(ArticleViewer.this.parentActivity, null, BlockEmbedCell.this.currentBlock.url, false, BlockEmbedCell.this.currentBlock.url, true));
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public void onPlayStateChanged(WebPlayerView playerView, boolean playing) {
                    if (playing) {
                        if (ArticleViewer.this.currentPlayingVideo != null && ArticleViewer.this.currentPlayingVideo != playerView) {
                            ArticleViewer.this.currentPlayingVideo.pause();
                        }
                        ArticleViewer.this.currentPlayingVideo = playerView;
                        try {
                            ArticleViewer.this.parentActivity.getWindow().addFlags(128);
                            return;
                        } catch (Exception e) {
                            FileLog.e(e);
                            return;
                        }
                    }
                    if (ArticleViewer.this.currentPlayingVideo == playerView) {
                        ArticleViewer.this.currentPlayingVideo = null;
                    }
                    try {
                        ArticleViewer.this.parentActivity.getWindow().clearFlags(128);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public boolean checkInlinePermissions() {
                    return false;
                }

                @Override // im.uwrkaxlmjj.ui.components.WebPlayerView.WebPlayerViewDelegate
                public ViewGroup getTextureViewContainer() {
                    return null;
                }
            });
            this.videoView = webPlayerView;
            addView(webPlayerView);
            ArticleViewer.this.createdWebViews.add(this);
            TouchyWebView touchyWebView = new TouchyWebView(context);
            this.webView = touchyWebView;
            touchyWebView.getSettings().setJavaScriptEnabled(true);
            this.webView.getSettings().setDomStorageEnabled(true);
            this.webView.getSettings().setAllowContentAccess(true);
            if (Build.VERSION.SDK_INT >= 17) {
                this.webView.getSettings().setMediaPlaybackRequiresUserGesture(false);
                this.webView.addJavascriptInterface(new WebviewProxy(), "WebviewProxy");
            }
            if (Build.VERSION.SDK_INT >= 21) {
                this.webView.getSettings().setMixedContentMode(0);
                CookieManager cookieManager = CookieManager.getInstance();
                cookieManager.setAcceptThirdPartyCookies(this.webView, true);
            }
            this.webView.setWebChromeClient(new AnonymousClass2(ArticleViewer.this));
            this.webView.setWebViewClient(new WebViewClient() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockEmbedCell.3
                @Override // android.webkit.WebViewClient
                public void onLoadResource(WebView view, String url) {
                    super.onLoadResource(view, url);
                }

                @Override // android.webkit.WebViewClient
                public void onPageFinished(WebView view, String url) {
                    super.onPageFinished(view, url);
                }

                @Override // android.webkit.WebViewClient
                public boolean shouldOverrideUrlLoading(WebView view, String url) {
                    if (BlockEmbedCell.this.wasUserInteraction) {
                        Browser.openUrl(ArticleViewer.this.parentActivity, url);
                        return true;
                    }
                    return false;
                }
            });
            addView(this.webView);
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ArticleViewer$BlockEmbedCell$2, reason: invalid class name */
        class AnonymousClass2 extends WebChromeClient {
            final /* synthetic */ ArticleViewer val$this$0;

            AnonymousClass2(ArticleViewer articleViewer) {
                this.val$this$0 = articleViewer;
            }

            @Override // android.webkit.WebChromeClient
            public void onShowCustomView(View view, int requestedOrientation, WebChromeClient.CustomViewCallback callback) {
                onShowCustomView(view, callback);
            }

            @Override // android.webkit.WebChromeClient
            public void onShowCustomView(View view, WebChromeClient.CustomViewCallback callback) {
                if (ArticleViewer.this.customView == null) {
                    ArticleViewer.this.customView = view;
                    ArticleViewer.this.customViewCallback = callback;
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$BlockEmbedCell$2$SGh5G_aP9-Nq5CbrwQWbZCcQMmY
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onShowCustomView$0$ArticleViewer$BlockEmbedCell$2();
                        }
                    }, 100L);
                    return;
                }
                callback.onCustomViewHidden();
            }

            public /* synthetic */ void lambda$onShowCustomView$0$ArticleViewer$BlockEmbedCell$2() {
                if (ArticleViewer.this.customView != null) {
                    ArticleViewer.this.fullscreenVideoContainer.addView(ArticleViewer.this.customView, LayoutHelper.createFrame(-1, -1.0f));
                    ArticleViewer.this.fullscreenVideoContainer.setVisibility(0);
                }
            }

            @Override // android.webkit.WebChromeClient
            public void onHideCustomView() {
                super.onHideCustomView();
                if (ArticleViewer.this.customView != null) {
                    ArticleViewer.this.fullscreenVideoContainer.setVisibility(4);
                    ArticleViewer.this.fullscreenVideoContainer.removeView(ArticleViewer.this.customView);
                    if (ArticleViewer.this.customViewCallback != null && !ArticleViewer.this.customViewCallback.getClass().getName().contains(".chromium.")) {
                        ArticleViewer.this.customViewCallback.onCustomViewHidden();
                    }
                    ArticleViewer.this.customView = null;
                }
            }
        }

        public void destroyWebView(boolean completely) {
            try {
                this.webView.stopLoading();
                this.webView.loadUrl("about:blank");
                if (completely) {
                    this.webView.destroy();
                }
                this.currentBlock = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
            this.videoView.destroy();
        }

        public void setBlock(TLRPC.TL_pageBlockEmbed block) {
            TLRPC.TL_pageBlockEmbed previousBlock = this.currentBlock;
            this.currentBlock = block;
            if (previousBlock != block) {
                this.wasUserInteraction = false;
                if (!block.allow_scrolling) {
                    this.webView.setVerticalScrollBarEnabled(false);
                    this.webView.setHorizontalScrollBarEnabled(false);
                } else {
                    this.webView.setVerticalScrollBarEnabled(true);
                    this.webView.setHorizontalScrollBarEnabled(true);
                }
                this.exactWebViewHeight = 0;
                try {
                    this.webView.loadUrl("about:blank");
                } catch (Exception e) {
                    FileLog.e(e);
                }
                try {
                    if (this.currentBlock.html == null) {
                        TLRPC.Photo thumb = this.currentBlock.poster_photo_id != 0 ? ArticleViewer.this.getPhotoWithId(this.currentBlock.poster_photo_id) : null;
                        boolean handled = this.videoView.loadVideo(block.url, thumb, ArticleViewer.this.currentPage, null, false);
                        if (!handled) {
                            this.webView.setVisibility(0);
                            this.videoView.setVisibility(4);
                            this.videoView.loadVideo(null, null, null, null, false);
                            HashMap<String, String> args = new HashMap<>();
                            args.put("Referer", "http://youtube.com");
                            this.webView.loadUrl(this.currentBlock.url, args);
                        } else {
                            this.webView.setVisibility(4);
                            this.videoView.setVisibility(0);
                            this.webView.stopLoading();
                            this.webView.loadUrl("about:blank");
                        }
                    } else {
                        this.webView.loadDataWithBaseURL("https://m12345.com/embed", this.currentBlock.html, "text/html", "UTF-8", null);
                        this.videoView.setVisibility(4);
                        this.videoView.loadVideo(null, null, null, null, false);
                        this.webView.setVisibility(0);
                    }
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
            requestLayout();
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            if (!ArticleViewer.this.isVisible) {
                this.currentBlock = null;
            }
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.captionLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.creditLayout, this.textX, this.textY + this.creditOffset) || super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int listWidth;
            int textWidth;
            float scale;
            int height2;
            int height3;
            int height4;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockEmbed tL_pageBlockEmbed = this.currentBlock;
            if (tL_pageBlockEmbed != null) {
                if (tL_pageBlockEmbed.level <= 0) {
                    this.listX = 0;
                    this.textX = AndroidUtilities.dp(18.0f);
                    int textWidth2 = width - AndroidUtilities.dp(36.0f);
                    if (!this.currentBlock.full_width) {
                        int listWidth2 = width - AndroidUtilities.dp(36.0f);
                        this.listX += AndroidUtilities.dp(18.0f);
                        listWidth = listWidth2;
                        textWidth = textWidth2;
                    } else {
                        listWidth = width;
                        textWidth = textWidth2;
                    }
                } else {
                    int iDp = AndroidUtilities.dp(this.currentBlock.level * 14) + AndroidUtilities.dp(18.0f);
                    this.listX = iDp;
                    this.textX = iDp;
                    int listWidth3 = width - (iDp + AndroidUtilities.dp(18.0f));
                    textWidth = listWidth3;
                    listWidth = listWidth3;
                }
                if (this.currentBlock.w == 0) {
                    scale = 1.0f;
                } else {
                    float scale2 = width;
                    scale = scale2 / this.currentBlock.w;
                }
                int i = this.exactWebViewHeight;
                if (i != 0) {
                    height2 = AndroidUtilities.dp(i);
                } else {
                    height2 = (int) ((this.currentBlock.w == 0 ? AndroidUtilities.dp(this.currentBlock.h) : this.currentBlock.h) * scale);
                }
                if (height2 != 0) {
                    height3 = height2;
                } else {
                    int height5 = AndroidUtilities.dp(10.0f);
                    height3 = height5;
                }
                this.webView.measure(View.MeasureSpec.makeMeasureSpec(listWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(height3, 1073741824));
                if (this.videoView.getParent() == this) {
                    this.videoView.measure(View.MeasureSpec.makeMeasureSpec(listWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(10.0f) + height3, 1073741824));
                }
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                this.captionLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    this.textY = AndroidUtilities.dp(8.0f) + height3;
                    int iDp2 = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                    this.creditOffset = iDp2;
                    height4 = height3 + iDp2 + AndroidUtilities.dp(4.0f);
                } else {
                    height4 = height3;
                }
                DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.creditLayout = drawingTextCreateLayoutForText2;
                if (drawingTextCreateLayoutForText2 != null) {
                    height4 += AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                }
                height = height4 + AndroidUtilities.dp(5.0f);
                if (this.currentBlock.level > 0 && !this.currentBlock.bottom) {
                    height += AndroidUtilities.dp(8.0f);
                } else if (this.currentBlock.level == 0 && this.captionLayout != null) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            TouchyWebView touchyWebView = this.webView;
            int i = this.listX;
            touchyWebView.layout(i, 0, touchyWebView.getMeasuredWidth() + i, this.webView.getMeasuredHeight());
            if (this.videoView.getParent() == this) {
                WebPlayerView webPlayerView = this.videoView;
                int i2 = this.listX;
                webPlayerView.layout(i2, 0, webPlayerView.getMeasuredWidth() + i2, this.videoView.getMeasuredHeight());
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }
    }

    private class BlockTableCell extends FrameLayout implements TableLayout.TableLayoutDelegate {
        private TLRPC.TL_pageBlockTable currentBlock;
        private boolean firstLayout;
        private boolean inLayout;
        private int listX;
        private int listY;
        private WebpageAdapter parentAdapter;
        private HorizontalScrollView scrollView;
        private TableLayout tableLayout;
        private int textX;
        private int textY;
        private DrawingText titleLayout;

        public BlockTableCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
            HorizontalScrollView horizontalScrollView = new HorizontalScrollView(context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockTableCell.1
                @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
                public boolean onInterceptTouchEvent(MotionEvent ev) {
                    if (BlockTableCell.this.tableLayout.getMeasuredWidth() > getMeasuredWidth() - AndroidUtilities.dp(36.0f)) {
                        ArticleViewer.this.windowView.requestDisallowInterceptTouchEvent(true);
                    }
                    return super.onInterceptTouchEvent(ev);
                }

                @Override // android.view.View
                protected void onScrollChanged(int l, int t, int oldl, int oldt) {
                    super.onScrollChanged(l, t, oldl, oldt);
                    if (ArticleViewer.this.pressedLinkOwnerLayout != null) {
                        ArticleViewer.this.pressedLinkOwnerLayout = null;
                        ArticleViewer.this.pressedLinkOwnerView = null;
                    }
                }

                @Override // android.view.View
                protected boolean overScrollBy(int deltaX, int deltaY, int scrollX, int scrollY, int scrollRangeX, int scrollRangeY, int maxOverScrollX, int maxOverScrollY, boolean isTouchEvent) {
                    ArticleViewer.this.removePressedLink();
                    return super.overScrollBy(deltaX, deltaY, scrollX, scrollY, scrollRangeX, scrollRangeY, maxOverScrollX, maxOverScrollY, isTouchEvent);
                }

                @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    BlockTableCell.this.tableLayout.measure(View.MeasureSpec.makeMeasureSpec((View.MeasureSpec.getSize(widthMeasureSpec) - getPaddingLeft()) - getPaddingRight(), 0), heightMeasureSpec);
                    setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), BlockTableCell.this.tableLayout.getMeasuredHeight());
                }
            };
            this.scrollView = horizontalScrollView;
            horizontalScrollView.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
            this.scrollView.setClipToPadding(false);
            addView(this.scrollView, LayoutHelper.createFrame(-1, -2.0f));
            TableLayout tableLayout = new TableLayout(context, this);
            this.tableLayout = tableLayout;
            tableLayout.setOrientation(0);
            this.tableLayout.setRowOrderPreserved(true);
            this.scrollView.addView(this.tableLayout, new FrameLayout.LayoutParams(-2, -2));
            setWillNotDraw(false);
        }

        @Override // im.uwrkaxlmjj.ui.components.TableLayout.TableLayoutDelegate
        public DrawingText createTextLayout(TLRPC.TL_pageTableCell cell, int maxWidth) {
            Layout.Alignment alignment;
            if (cell == null) {
                return null;
            }
            if (cell.align_right) {
                alignment = Layout.Alignment.ALIGN_OPPOSITE;
            } else if (cell.align_center) {
                alignment = Layout.Alignment.ALIGN_CENTER;
            } else {
                alignment = Layout.Alignment.ALIGN_NORMAL;
            }
            return ArticleViewer.this.createLayoutForText(this, null, cell.text, maxWidth, 0, this.currentBlock, alignment, 0, this.parentAdapter);
        }

        @Override // im.uwrkaxlmjj.ui.components.TableLayout.TableLayoutDelegate
        public Paint getLinePaint() {
            return ArticleViewer.tableLinePaint;
        }

        @Override // im.uwrkaxlmjj.ui.components.TableLayout.TableLayoutDelegate
        public Paint getHalfLinePaint() {
            return ArticleViewer.tableHalfLinePaint;
        }

        @Override // im.uwrkaxlmjj.ui.components.TableLayout.TableLayoutDelegate
        public Paint getHeaderPaint() {
            return ArticleViewer.tableHeaderPaint;
        }

        @Override // im.uwrkaxlmjj.ui.components.TableLayout.TableLayoutDelegate
        public Paint getStripPaint() {
            return ArticleViewer.tableStripPaint;
        }

        public void setBlock(TLRPC.TL_pageBlockTable block) {
            this.currentBlock = block;
            int color = ArticleViewer.this.getSelectedColor();
            if (color == 0) {
                AndroidUtilities.setScrollViewEdgeEffectColor(this.scrollView, -657673);
            } else if (color == 1) {
                AndroidUtilities.setScrollViewEdgeEffectColor(this.scrollView, -659492);
            } else if (color == 2) {
                AndroidUtilities.setScrollViewEdgeEffectColor(this.scrollView, -15461356);
            }
            this.tableLayout.removeAllChildrens();
            this.tableLayout.setDrawLines(this.currentBlock.bordered);
            this.tableLayout.setStriped(this.currentBlock.striped);
            this.tableLayout.setRtl(ArticleViewer.this.isRtl);
            int maxCols = 0;
            if (!this.currentBlock.rows.isEmpty()) {
                TLRPC.TL_pageTableRow row = this.currentBlock.rows.get(0);
                int size2 = row.cells.size();
                for (int c = 0; c < size2; c++) {
                    TLRPC.TL_pageTableCell cell = row.cells.get(c);
                    maxCols += cell.colspan != 0 ? cell.colspan : 1;
                }
            }
            int size = this.currentBlock.rows.size();
            for (int r = 0; r < size; r++) {
                TLRPC.TL_pageTableRow row2 = this.currentBlock.rows.get(r);
                int cols = 0;
                int size22 = row2.cells.size();
                for (int c2 = 0; c2 < size22; c2++) {
                    TLRPC.TL_pageTableCell cell2 = row2.cells.get(c2);
                    int colspan = cell2.colspan != 0 ? cell2.colspan : 1;
                    int rowspan = cell2.rowspan != 0 ? cell2.rowspan : 1;
                    if (cell2.text != null) {
                        this.tableLayout.addChild(cell2, cols, r, colspan);
                    } else {
                        this.tableLayout.addChild(cols, r, colspan, rowspan);
                    }
                    cols += colspan;
                }
            }
            this.tableLayout.setColumnCount(maxCols);
            this.firstLayout = true;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            int N = this.tableLayout.getChildCount();
            for (int i = 0; i < N; i++) {
                TableLayout.Child c = this.tableLayout.getChildAt(i);
                if (ArticleViewer.this.checkLayoutForLinks(event, this, c.textLayout, (this.scrollView.getPaddingLeft() - this.scrollView.getScrollX()) + this.listX + c.getTextX(), this.listY + c.getTextY())) {
                    return true;
                }
            }
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.titleLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        public void invalidate() {
            super.invalidate();
            this.tableLayout.invalidate();
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int textWidth;
            this.inLayout = true;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height2 = 0;
            TLRPC.TL_pageBlockTable tL_pageBlockTable = this.currentBlock;
            if (tL_pageBlockTable != null) {
                if (tL_pageBlockTable.level > 0) {
                    int iDp = AndroidUtilities.dp(this.currentBlock.level * 14);
                    this.listX = iDp;
                    int iDp2 = iDp + AndroidUtilities.dp(18.0f);
                    this.textX = iDp2;
                    textWidth = width - iDp2;
                } else {
                    this.listX = 0;
                    this.textX = AndroidUtilities.dp(18.0f);
                    textWidth = width - AndroidUtilities.dp(36.0f);
                }
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.title, textWidth, 0, this.currentBlock, Layout.Alignment.ALIGN_CENTER, 0, this.parentAdapter);
                this.titleLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText == null) {
                    this.listY = AndroidUtilities.dp(8.0f);
                } else {
                    this.textY = 0;
                    height2 = 0 + drawingTextCreateLayoutForText.getHeight() + AndroidUtilities.dp(8.0f);
                    this.listY = height2;
                }
                this.scrollView.measure(View.MeasureSpec.makeMeasureSpec(width - this.listX, 1073741824), View.MeasureSpec.makeMeasureSpec(0, 0));
                height = height2 + this.scrollView.getMeasuredHeight() + AndroidUtilities.dp(8.0f);
                if (this.currentBlock.level > 0 && !this.currentBlock.bottom) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
            this.inLayout = false;
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            HorizontalScrollView horizontalScrollView = this.scrollView;
            int i = this.listX;
            horizontalScrollView.layout(i, this.listY, horizontalScrollView.getMeasuredWidth() + i, this.listY + this.scrollView.getMeasuredHeight());
            if (this.firstLayout) {
                if (ArticleViewer.this.isRtl) {
                    this.scrollView.setScrollX((this.tableLayout.getMeasuredWidth() - this.scrollView.getMeasuredWidth()) + AndroidUtilities.dp(36.0f));
                } else {
                    this.scrollView.setScrollX(0);
                }
                this.firstLayout = false;
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.titleLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.titleLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }
    }

    private class BlockCollageCell extends FrameLayout {
        private DrawingText captionLayout;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockCollage currentBlock;
        private GridLayoutManager gridLayoutManager;
        private GroupedMessages group;
        private boolean inLayout;
        private RecyclerView.Adapter innerAdapter;
        private RecyclerListView innerListView;
        private int listX;
        private WebpageAdapter parentAdapter;
        private int textX;
        private int textY;

        public class GroupedMessages {
            public long groupId;
            public boolean hasSibling;
            public ArrayList<MessageObject.GroupedMessagePosition> posArray = new ArrayList<>();
            public HashMap<TLObject, MessageObject.GroupedMessagePosition> positions = new HashMap<>();
            private int maxSizeWidth = 1000;

            public GroupedMessages() {
            }

            private class MessageGroupedLayoutAttempt {
                public float[] heights;
                public int[] lineCounts;

                public MessageGroupedLayoutAttempt(int i1, int i2, float f1, float f2) {
                    this.lineCounts = new int[]{i1, i2};
                    this.heights = new float[]{f1, f2};
                }

                public MessageGroupedLayoutAttempt(int i1, int i2, int i3, float f1, float f2, float f3) {
                    this.lineCounts = new int[]{i1, i2, i3};
                    this.heights = new float[]{f1, f2, f3};
                }

                public MessageGroupedLayoutAttempt(int i1, int i2, int i3, int i4, float f1, float f2, float f3, float f4) {
                    this.lineCounts = new int[]{i1, i2, i3, i4};
                    this.heights = new float[]{f1, f2, f3, f4};
                }
            }

            private float multiHeight(float[] array, int start, int end) {
                float sum = 0.0f;
                for (int a = start; a < end; a++) {
                    sum += array[a];
                }
                int a2 = this.maxSizeWidth;
                return a2 / sum;
            }

            /* JADX WARN: Removed duplicated region for block: B:119:0x067b  */
            /* JADX WARN: Removed duplicated region for block: B:202:0x086d  */
            /* JADX WARN: Removed duplicated region for block: B:22:0x0089  */
            /* JADX WARN: Removed duplicated region for block: B:23:0x008b  */
            /* JADX WARN: Removed duplicated region for block: B:240:0x0882 A[SYNTHETIC] */
            /* JADX WARN: Removed duplicated region for block: B:26:0x0090  */
            /* JADX WARN: Removed duplicated region for block: B:27:0x0093  */
            /* JADX WARN: Removed duplicated region for block: B:30:0x00a2  */
            /* JADX WARN: Removed duplicated region for block: B:31:0x00a8  */
            /* JADX WARN: Removed duplicated region for block: B:37:0x00c5  */
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public void calculate() {
                /*
                    Method dump skipped, instruction units count: 2179
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.BlockCollageCell.GroupedMessages.calculate():void");
            }
        }

        public BlockCollageCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.group = new GroupedMessages();
            this.parentAdapter = adapter;
            RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockCollageCell.1
                @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
                public void requestLayout() {
                    if (BlockCollageCell.this.inLayout) {
                        return;
                    }
                    super.requestLayout();
                }
            };
            this.innerListView = recyclerListView;
            recyclerListView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockCollageCell.2
                @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
                public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
                    MessageObject.GroupedMessagePosition position;
                    outRect.bottom = 0;
                    if (!(view instanceof BlockPhotoCell)) {
                        if (view instanceof BlockVideoCell) {
                            position = BlockCollageCell.this.group.positions.get(((BlockVideoCell) view).currentBlock);
                        } else {
                            position = null;
                        }
                    } else {
                        position = BlockCollageCell.this.group.positions.get(((BlockPhotoCell) view).currentBlock);
                    }
                    if (position != null && position.siblingHeights != null) {
                        float maxHeight = Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.5f;
                        int h = 0;
                        for (int a = 0; a < position.siblingHeights.length; a++) {
                            h += (int) Math.ceil(position.siblingHeights[a] * maxHeight);
                        }
                        int a2 = position.maxY;
                        int h2 = h + ((a2 - position.minY) * AndroidUtilities.dp2(11.0f));
                        int count = BlockCollageCell.this.group.posArray.size();
                        int a3 = 0;
                        while (true) {
                            if (a3 >= count) {
                                break;
                            }
                            MessageObject.GroupedMessagePosition pos = BlockCollageCell.this.group.posArray.get(a3);
                            if (pos.minY != position.minY || ((pos.minX == position.minX && pos.maxX == position.maxX && pos.minY == position.minY && pos.maxY == position.maxY) || pos.minY != position.minY)) {
                                a3++;
                            } else {
                                h2 -= ((int) Math.ceil(pos.ph * maxHeight)) - AndroidUtilities.dp(4.0f);
                                break;
                            }
                        }
                        int a4 = -h2;
                        outRect.bottom = a4;
                    }
                }
            });
            GridLayoutManagerFixed gridLayoutManagerFixed = new GridLayoutManagerFixed(context, 1000, 1, true) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockCollageCell.3
                @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
                public boolean supportsPredictiveItemAnimations() {
                    return false;
                }

                @Override // androidx.recyclerview.widget.GridLayoutManagerFixed
                public boolean shouldLayoutChildFromOpositeSide(View child) {
                    return false;
                }

                @Override // androidx.recyclerview.widget.GridLayoutManagerFixed
                protected boolean hasSiblingChild(int position) {
                    TLObject message = BlockCollageCell.this.currentBlock.items.get((BlockCollageCell.this.currentBlock.items.size() - position) - 1);
                    MessageObject.GroupedMessagePosition pos = BlockCollageCell.this.group.positions.get(message);
                    if (pos.minX == pos.maxX || pos.minY != pos.maxY || pos.minY == 0) {
                        return false;
                    }
                    int count = BlockCollageCell.this.group.posArray.size();
                    for (int a = 0; a < count; a++) {
                        MessageObject.GroupedMessagePosition p = BlockCollageCell.this.group.posArray.get(a);
                        if (p != pos && p.minY <= pos.minY && p.maxY >= pos.minY) {
                            return true;
                        }
                    }
                    return false;
                }
            };
            this.gridLayoutManager = gridLayoutManagerFixed;
            gridLayoutManagerFixed.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockCollageCell.4
                @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
                public int getSpanSize(int position) {
                    TLObject message = BlockCollageCell.this.currentBlock.items.get((BlockCollageCell.this.currentBlock.items.size() - position) - 1);
                    return BlockCollageCell.this.group.positions.get(message).spanSize;
                }
            });
            this.innerListView.setLayoutManager(this.gridLayoutManager);
            RecyclerListView recyclerListView2 = this.innerListView;
            RecyclerView.Adapter adapter2 = new RecyclerView.Adapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockCollageCell.5
                @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
                    View view;
                    if (viewType == 0) {
                        view = ArticleViewer.this.new BlockPhotoCell(BlockCollageCell.this.getContext(), BlockCollageCell.this.parentAdapter, 2);
                    } else {
                        view = ArticleViewer.this.new BlockVideoCell(BlockCollageCell.this.getContext(), BlockCollageCell.this.parentAdapter, 2);
                    }
                    return new RecyclerListView.Holder(view);
                }

                @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
                    TLRPC.PageBlock pageBlock = BlockCollageCell.this.currentBlock.items.get((BlockCollageCell.this.currentBlock.items.size() - position) - 1);
                    if (holder.getItemViewType() == 0) {
                        BlockPhotoCell cell = (BlockPhotoCell) holder.itemView;
                        cell.groupPosition = BlockCollageCell.this.group.positions.get(pageBlock);
                        cell.setBlock((TLRPC.TL_pageBlockPhoto) pageBlock, true, true);
                    } else {
                        BlockVideoCell cell2 = (BlockVideoCell) holder.itemView;
                        cell2.groupPosition = BlockCollageCell.this.group.positions.get(pageBlock);
                        cell2.setBlock((TLRPC.TL_pageBlockVideo) pageBlock, true, true);
                    }
                }

                @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                public int getItemCount() {
                    if (BlockCollageCell.this.currentBlock != null) {
                        return BlockCollageCell.this.currentBlock.items.size();
                    }
                    return 0;
                }

                @Override // androidx.recyclerview.widget.RecyclerView.Adapter
                public int getItemViewType(int position) {
                    TLRPC.PageBlock block = BlockCollageCell.this.currentBlock.items.get((BlockCollageCell.this.currentBlock.items.size() - position) - 1);
                    return block instanceof TLRPC.TL_pageBlockPhoto ? 0 : 1;
                }
            };
            this.innerAdapter = adapter2;
            recyclerListView2.setAdapter(adapter2);
            addView(this.innerListView, LayoutHelper.createFrame(-1, -2.0f));
            setWillNotDraw(false);
        }

        public void setBlock(TLRPC.TL_pageBlockCollage block) {
            if (this.currentBlock != block) {
                this.currentBlock = block;
                this.group.calculate();
            }
            this.innerAdapter.notifyDataSetChanged();
            int color = ArticleViewer.this.getSelectedColor();
            if (color == 0) {
                this.innerListView.setGlowColor(-657673);
            } else if (color == 1) {
                this.innerListView.setGlowColor(-659492);
            } else if (color == 2) {
                this.innerListView.setGlowColor(-15461356);
            }
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.captionLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.creditLayout, this.textX, this.textY + this.creditOffset) || super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int textWidth;
            int listWidth;
            int height2;
            this.inLayout = true;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockCollage tL_pageBlockCollage = this.currentBlock;
            if (tL_pageBlockCollage != null) {
                if (tL_pageBlockCollage.level > 0) {
                    int iDp = AndroidUtilities.dp(this.currentBlock.level * 14) + AndroidUtilities.dp(18.0f);
                    this.listX = iDp;
                    this.textX = iDp;
                    int listWidth2 = width - (iDp + AndroidUtilities.dp(18.0f));
                    textWidth = listWidth2;
                    listWidth = listWidth2;
                } else {
                    this.listX = 0;
                    this.textX = AndroidUtilities.dp(18.0f);
                    textWidth = width - AndroidUtilities.dp(36.0f);
                    listWidth = width;
                }
                this.innerListView.measure(View.MeasureSpec.makeMeasureSpec(listWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(0, 0));
                int height3 = this.innerListView.getMeasuredHeight();
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                this.captionLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    this.textY = AndroidUtilities.dp(8.0f) + height3;
                    int iDp2 = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                    this.creditOffset = iDp2;
                    height2 = height3 + iDp2 + AndroidUtilities.dp(4.0f);
                } else {
                    height2 = height3;
                }
                DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.creditLayout = drawingTextCreateLayoutForText2;
                if (drawingTextCreateLayoutForText2 != null) {
                    height2 += AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                }
                height = height2 + AndroidUtilities.dp(16.0f);
                if (this.currentBlock.level > 0 && !this.currentBlock.bottom) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
            this.inLayout = false;
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            this.innerListView.layout(this.listX, AndroidUtilities.dp(8.0f), this.listX + this.innerListView.getMeasuredWidth(), this.innerListView.getMeasuredHeight() + AndroidUtilities.dp(8.0f));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }
    }

    private class BlockSlideshowCell extends FrameLayout {
        private DrawingText captionLayout;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockSlideshow currentBlock;
        private int currentPage;
        private View dotsContainer;
        private PagerAdapter innerAdapter;
        private ViewPager innerListView;
        private float pageOffset;
        private WebpageAdapter parentAdapter;
        private int textX;
        private int textY;

        public BlockSlideshowCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.parentAdapter = adapter;
            if (ArticleViewer.dotsPaint == null) {
                Paint unused = ArticleViewer.dotsPaint = new Paint(1);
                ArticleViewer.dotsPaint.setColor(-1);
            }
            ViewPager viewPager = new ViewPager(context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockSlideshowCell.1
                @Override // androidx.viewpager.widget.ViewPager, android.view.View
                public boolean onTouchEvent(MotionEvent ev) {
                    return super.onTouchEvent(ev);
                }

                @Override // androidx.viewpager.widget.ViewPager, android.view.ViewGroup
                public boolean onInterceptTouchEvent(MotionEvent ev) {
                    ArticleViewer.this.windowView.requestDisallowInterceptTouchEvent(true);
                    return super.onInterceptTouchEvent(ev);
                }
            };
            this.innerListView = viewPager;
            viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockSlideshowCell.2
                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                    float width = BlockSlideshowCell.this.innerListView.getMeasuredWidth();
                    if (width == 0.0f) {
                        return;
                    }
                    BlockSlideshowCell.this.pageOffset = (((position * width) + positionOffsetPixels) - (r1.currentPage * width)) / width;
                    BlockSlideshowCell.this.dotsContainer.invalidate();
                }

                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageSelected(int position) {
                    BlockSlideshowCell.this.currentPage = position;
                    BlockSlideshowCell.this.dotsContainer.invalidate();
                }

                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageScrollStateChanged(int state) {
                }
            });
            ViewPager viewPager2 = this.innerListView;
            PagerAdapter pagerAdapter = new PagerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockSlideshowCell.3

                /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ArticleViewer$BlockSlideshowCell$3$ObjectContainer */
                class ObjectContainer {
                    private TLRPC.PageBlock block;
                    private View view;

                    ObjectContainer() {
                    }
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public int getCount() {
                    if (BlockSlideshowCell.this.currentBlock != null) {
                        return BlockSlideshowCell.this.currentBlock.items.size();
                    }
                    return 0;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public boolean isViewFromObject(View view, Object object) {
                    return ((ObjectContainer) object).view == view;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public int getItemPosition(Object object) {
                    ObjectContainer objectContainer = (ObjectContainer) object;
                    if (BlockSlideshowCell.this.currentBlock.items.contains(objectContainer.block)) {
                        return -1;
                    }
                    return -2;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public Object instantiateItem(ViewGroup container, int position) {
                    View view;
                    TLRPC.PageBlock block = BlockSlideshowCell.this.currentBlock.items.get(position);
                    if (block instanceof TLRPC.TL_pageBlockPhoto) {
                        view = ArticleViewer.this.new BlockPhotoCell(BlockSlideshowCell.this.getContext(), BlockSlideshowCell.this.parentAdapter, 1);
                        ((BlockPhotoCell) view).setBlock((TLRPC.TL_pageBlockPhoto) block, true, true);
                    } else {
                        view = ArticleViewer.this.new BlockVideoCell(BlockSlideshowCell.this.getContext(), BlockSlideshowCell.this.parentAdapter, 1);
                        ((BlockVideoCell) view).setBlock((TLRPC.TL_pageBlockVideo) block, true, true);
                    }
                    container.addView(view);
                    ObjectContainer objectContainer = new ObjectContainer();
                    objectContainer.view = view;
                    objectContainer.block = block;
                    return objectContainer;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public void destroyItem(ViewGroup container, int position, Object object) {
                    container.removeView(((ObjectContainer) object).view);
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public void unregisterDataSetObserver(DataSetObserver observer) {
                    if (observer != null) {
                        super.unregisterDataSetObserver(observer);
                    }
                }
            };
            this.innerAdapter = pagerAdapter;
            viewPager2.setAdapter(pagerAdapter);
            int color = ArticleViewer.this.getSelectedColor();
            if (color == 0) {
                AndroidUtilities.setViewPagerEdgeEffectColor(this.innerListView, -657673);
            } else if (color == 1) {
                AndroidUtilities.setViewPagerEdgeEffectColor(this.innerListView, -659492);
            } else if (color == 2) {
                AndroidUtilities.setViewPagerEdgeEffectColor(this.innerListView, -15461356);
            }
            addView(this.innerListView);
            View view = new View(context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockSlideshowCell.4
                @Override // android.view.View
                protected void onDraw(Canvas canvas) {
                    int xOffset;
                    if (BlockSlideshowCell.this.currentBlock != null) {
                        int count = BlockSlideshowCell.this.innerAdapter.getCount();
                        int totalWidth = (AndroidUtilities.dp(7.0f) * count) + ((count - 1) * AndroidUtilities.dp(6.0f)) + AndroidUtilities.dp(4.0f);
                        if (totalWidth < getMeasuredWidth()) {
                            xOffset = (getMeasuredWidth() - totalWidth) / 2;
                        } else {
                            xOffset = AndroidUtilities.dp(4.0f);
                            int size = AndroidUtilities.dp(13.0f);
                            int halfCount = ((getMeasuredWidth() - AndroidUtilities.dp(8.0f)) / 2) / size;
                            if (BlockSlideshowCell.this.currentPage != (count - halfCount) - 1 || BlockSlideshowCell.this.pageOffset >= 0.0f) {
                                if (BlockSlideshowCell.this.currentPage < (count - halfCount) - 1) {
                                    if (BlockSlideshowCell.this.currentPage > halfCount) {
                                        xOffset -= ((int) (BlockSlideshowCell.this.pageOffset * size)) + ((BlockSlideshowCell.this.currentPage - halfCount) * size);
                                    } else if (BlockSlideshowCell.this.currentPage == halfCount && BlockSlideshowCell.this.pageOffset > 0.0f) {
                                        xOffset -= (int) (BlockSlideshowCell.this.pageOffset * size);
                                    }
                                } else {
                                    xOffset -= ((count - (halfCount * 2)) - 1) * size;
                                }
                            } else {
                                xOffset -= ((int) (BlockSlideshowCell.this.pageOffset * size)) + (((count - (halfCount * 2)) - 1) * size);
                            }
                        }
                        int a = 0;
                        while (a < BlockSlideshowCell.this.currentBlock.items.size()) {
                            int cx = AndroidUtilities.dp(4.0f) + xOffset + (AndroidUtilities.dp(13.0f) * a);
                            Drawable drawable = BlockSlideshowCell.this.currentPage == a ? ArticleViewer.this.slideDotBigDrawable : ArticleViewer.this.slideDotDrawable;
                            drawable.setBounds(cx - AndroidUtilities.dp(5.0f), 0, AndroidUtilities.dp(5.0f) + cx, AndroidUtilities.dp(10.0f));
                            drawable.draw(canvas);
                            a++;
                        }
                    }
                }
            };
            this.dotsContainer = view;
            addView(view);
            setWillNotDraw(false);
        }

        public void setBlock(TLRPC.TL_pageBlockSlideshow block) {
            this.currentBlock = block;
            this.innerAdapter.notifyDataSetChanged();
            this.innerListView.setCurrentItem(0, false);
            this.innerListView.forceLayout();
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.captionLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.creditLayout, this.textX, this.textY + this.creditOffset) || super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int height2;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            if (this.currentBlock != null) {
                int height3 = AndroidUtilities.dp(310.0f);
                this.innerListView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(height3, 1073741824));
                this.currentBlock.items.size();
                this.dotsContainer.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(10.0f), 1073741824));
                int textWidth = width - AndroidUtilities.dp(36.0f);
                this.textY = AndroidUtilities.dp(16.0f) + height3;
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                this.captionLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    int iDp = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                    this.creditOffset = iDp;
                    height2 = height3 + iDp + AndroidUtilities.dp(4.0f);
                } else {
                    height2 = height3;
                }
                DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.creditLayout = drawingTextCreateLayoutForText2;
                if (drawingTextCreateLayoutForText2 != null) {
                    height2 += AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                }
                height = height2 + AndroidUtilities.dp(16.0f);
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            this.innerListView.layout(0, AndroidUtilities.dp(8.0f), this.innerListView.getMeasuredWidth(), AndroidUtilities.dp(8.0f) + this.innerListView.getMeasuredHeight());
            int y = this.innerListView.getBottom() - AndroidUtilities.dp(23.0f);
            View view = this.dotsContainer;
            view.layout(0, y, view.getMeasuredWidth(), this.dotsContainer.getMeasuredHeight() + y);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
        }
    }

    private class BlockListItemCell extends ViewGroup {
        private RecyclerView.ViewHolder blockLayout;
        private int blockX;
        private int blockY;
        private TL_pageBlockListItem currentBlock;
        private int currentBlockType;
        private boolean drawDot;
        private int numOffsetY;
        private WebpageAdapter parentAdapter;
        private boolean parentIsList;
        private DrawingText textLayout;
        private int textX;
        private int textY;
        private boolean verticalAlign;

        public BlockListItemCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
        }

        public void setBlock(TL_pageBlockListItem block) {
            if (this.currentBlock != block) {
                this.currentBlock = block;
                RecyclerView.ViewHolder viewHolder = this.blockLayout;
                if (viewHolder != null) {
                    removeView(viewHolder.itemView);
                    this.blockLayout = null;
                }
                if (this.currentBlock.blockItem != null) {
                    int typeForBlock = this.parentAdapter.getTypeForBlock(this.currentBlock.blockItem);
                    this.currentBlockType = typeForBlock;
                    RecyclerView.ViewHolder viewHolderOnCreateViewHolder = this.parentAdapter.onCreateViewHolder(this, typeForBlock);
                    this.blockLayout = viewHolderOnCreateViewHolder;
                    addView(viewHolderOnCreateViewHolder.itemView);
                }
            }
            if (this.currentBlock.blockItem != null) {
                this.parentAdapter.bindBlockToHolder(this.currentBlockType, this.blockLayout, this.currentBlock.blockItem, 0, 0);
            }
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY)) {
                return true;
            }
            return super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int maxWidth;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TL_pageBlockListItem tL_pageBlockListItem = this.currentBlock;
            if (tL_pageBlockListItem != null) {
                this.textLayout = null;
                this.textY = (tL_pageBlockListItem.index == 0 && this.currentBlock.parent.level == 0) ? AndroidUtilities.dp(10.0f) : 0;
                this.numOffsetY = 0;
                if (this.currentBlock.parent.lastMaxNumCalcWidth != width || this.currentBlock.parent.lastFontSize != ArticleViewer.this.selectedFontSize) {
                    this.currentBlock.parent.lastMaxNumCalcWidth = width;
                    this.currentBlock.parent.lastFontSize = ArticleViewer.this.selectedFontSize;
                    this.currentBlock.parent.maxNumWidth = 0;
                    int size = this.currentBlock.parent.items.size();
                    for (int a = 0; a < size; a++) {
                        TL_pageBlockListItem item = (TL_pageBlockListItem) this.currentBlock.parent.items.get(a);
                        if (item.num != null) {
                            item.numLayout = ArticleViewer.this.createLayoutForText(this, item.num, null, width - AndroidUtilities.dp(54.0f), this.currentBlock, this.parentAdapter);
                            this.currentBlock.parent.maxNumWidth = Math.max(this.currentBlock.parent.maxNumWidth, (int) Math.ceil(item.numLayout.getLineWidth(0)));
                        }
                    }
                    this.currentBlock.parent.maxNumWidth = Math.max(this.currentBlock.parent.maxNumWidth, (int) Math.ceil(ArticleViewer.listTextNumPaint.measureText("00.")));
                }
                this.drawDot = !this.currentBlock.parent.pageBlockList.ordered;
                this.parentIsList = (getParent() instanceof BlockListItemCell) || (getParent() instanceof BlockOrderedListItemCell);
                if (ArticleViewer.this.isRtl) {
                    this.textX = AndroidUtilities.dp(18.0f);
                } else {
                    this.textX = AndroidUtilities.dp(24.0f) + this.currentBlock.parent.maxNumWidth + (this.currentBlock.parent.level * AndroidUtilities.dp(12.0f));
                }
                int maxWidth2 = (width - AndroidUtilities.dp(18.0f)) - this.textX;
                if (ArticleViewer.this.isRtl) {
                    maxWidth = maxWidth2 - ((AndroidUtilities.dp(6.0f) + this.currentBlock.parent.maxNumWidth) + (this.currentBlock.parent.level * AndroidUtilities.dp(12.0f)));
                } else {
                    maxWidth = maxWidth2;
                }
                if (this.currentBlock.textItem != null) {
                    DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.textItem, maxWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                    this.textLayout = drawingTextCreateLayoutForText;
                    if (drawingTextCreateLayoutForText != null && drawingTextCreateLayoutForText.getLineCount() > 0) {
                        if (this.currentBlock.numLayout != null && this.currentBlock.numLayout.getLineCount() > 0) {
                            int ascent = this.textLayout.getLineAscent(0);
                            this.numOffsetY = (this.currentBlock.numLayout.getLineAscent(0) + AndroidUtilities.dp(2.5f)) - ascent;
                        }
                        height = 0 + this.textLayout.getHeight() + AndroidUtilities.dp(8.0f);
                    }
                } else if (this.currentBlock.blockItem != null) {
                    this.blockX = this.textX;
                    this.blockY = this.textY;
                    RecyclerView.ViewHolder viewHolder = this.blockLayout;
                    if (viewHolder != null) {
                        if (viewHolder.itemView instanceof BlockParagraphCell) {
                            this.blockY -= AndroidUtilities.dp(8.0f);
                            if (!ArticleViewer.this.isRtl) {
                                this.blockX -= AndroidUtilities.dp(18.0f);
                            }
                            maxWidth += AndroidUtilities.dp(18.0f);
                            height = 0 - AndroidUtilities.dp(8.0f);
                        } else if ((this.blockLayout.itemView instanceof BlockHeaderCell) || (this.blockLayout.itemView instanceof BlockSubheaderCell) || (this.blockLayout.itemView instanceof BlockTitleCell) || (this.blockLayout.itemView instanceof BlockSubtitleCell)) {
                            if (!ArticleViewer.this.isRtl) {
                                this.blockX -= AndroidUtilities.dp(18.0f);
                            }
                            maxWidth += AndroidUtilities.dp(18.0f);
                        } else if (ArticleViewer.this.isListItemBlock(this.currentBlock.blockItem)) {
                            this.blockX = 0;
                            this.blockY = 0;
                            this.textY = 0;
                            if (this.currentBlock.index == 0 && this.currentBlock.parent.level == 0) {
                                height = 0 - AndroidUtilities.dp(10.0f);
                            }
                            maxWidth = width;
                            height -= AndroidUtilities.dp(8.0f);
                        } else if (this.blockLayout.itemView instanceof BlockTableCell) {
                            this.blockX -= AndroidUtilities.dp(18.0f);
                            maxWidth += AndroidUtilities.dp(36.0f);
                        }
                        this.blockLayout.itemView.measure(View.MeasureSpec.makeMeasureSpec(maxWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(0, 0));
                        if ((this.blockLayout.itemView instanceof BlockParagraphCell) && this.currentBlock.numLayout != null && this.currentBlock.numLayout.getLineCount() > 0) {
                            BlockParagraphCell paragraphCell = (BlockParagraphCell) this.blockLayout.itemView;
                            if (paragraphCell.textLayout != null && paragraphCell.textLayout.getLineCount() > 0) {
                                int ascent2 = paragraphCell.textLayout.getLineAscent(0);
                                this.numOffsetY = (this.currentBlock.numLayout.getLineAscent(0) + AndroidUtilities.dp(2.5f)) - ascent2;
                            }
                        }
                        if (this.currentBlock.blockItem instanceof TLRPC.TL_pageBlockDetails) {
                            this.verticalAlign = true;
                            this.blockY = 0;
                            if (this.currentBlock.index == 0 && this.currentBlock.parent.level == 0) {
                                height -= AndroidUtilities.dp(10.0f);
                            }
                            height -= AndroidUtilities.dp(8.0f);
                        } else if (this.blockLayout.itemView instanceof BlockOrderedListItemCell) {
                            this.verticalAlign = ((BlockOrderedListItemCell) this.blockLayout.itemView).verticalAlign;
                        } else if (this.blockLayout.itemView instanceof BlockListItemCell) {
                            this.verticalAlign = ((BlockListItemCell) this.blockLayout.itemView).verticalAlign;
                        }
                        if (this.verticalAlign && this.currentBlock.numLayout != null) {
                            this.textY = ((this.blockLayout.itemView.getMeasuredHeight() - this.currentBlock.numLayout.getHeight()) / 2) - AndroidUtilities.dp(4.0f);
                            this.drawDot = false;
                        }
                        height += this.blockLayout.itemView.getMeasuredHeight();
                    }
                    height += AndroidUtilities.dp(8.0f);
                }
                if (this.currentBlock.parent.items.get(this.currentBlock.parent.items.size() - 1) == this.currentBlock) {
                    height += AndroidUtilities.dp(8.0f);
                }
                if (this.currentBlock.index == 0 && this.currentBlock.parent.level == 0) {
                    height += AndroidUtilities.dp(10.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            RecyclerView.ViewHolder viewHolder = this.blockLayout;
            if (viewHolder != null) {
                View view = viewHolder.itemView;
                int i = this.blockX;
                view.layout(i, this.blockY, this.blockLayout.itemView.getMeasuredWidth() + i, this.blockY + this.blockLayout.itemView.getMeasuredHeight());
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            int width = getMeasuredWidth();
            if (this.currentBlock.numLayout != null) {
                canvas.save();
                if (ArticleViewer.this.isRtl) {
                    canvas.translate(((width - AndroidUtilities.dp(15.0f)) - this.currentBlock.parent.maxNumWidth) - (this.currentBlock.parent.level * AndroidUtilities.dp(12.0f)), (this.textY + this.numOffsetY) - (this.drawDot ? AndroidUtilities.dp(1.0f) : 0));
                } else {
                    canvas.translate(((AndroidUtilities.dp(15.0f) + this.currentBlock.parent.maxNumWidth) - ((int) Math.ceil(this.currentBlock.numLayout.getLineWidth(0)))) + (this.currentBlock.parent.level * AndroidUtilities.dp(12.0f)), (this.textY + this.numOffsetY) - (this.drawDot ? AndroidUtilities.dp(1.0f) : 0));
                }
                this.currentBlock.numLayout.draw(canvas);
                canvas.restore();
            }
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            DrawingText drawingText = this.textLayout;
            if (drawingText == null) {
                return;
            }
            info.setText(drawingText.getText());
        }
    }

    private class BlockOrderedListItemCell extends ViewGroup {
        private RecyclerView.ViewHolder blockLayout;
        private int blockX;
        private int blockY;
        private TL_pageBlockOrderedListItem currentBlock;
        private int currentBlockType;
        private int numOffsetY;
        private WebpageAdapter parentAdapter;
        private boolean parentIsList;
        private DrawingText textLayout;
        private int textX;
        private int textY;
        private boolean verticalAlign;

        public BlockOrderedListItemCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
        }

        public void setBlock(TL_pageBlockOrderedListItem block) {
            if (this.currentBlock != block) {
                this.currentBlock = block;
                RecyclerView.ViewHolder viewHolder = this.blockLayout;
                if (viewHolder != null) {
                    removeView(viewHolder.itemView);
                    this.blockLayout = null;
                }
                if (this.currentBlock.blockItem != null) {
                    int typeForBlock = this.parentAdapter.getTypeForBlock(this.currentBlock.blockItem);
                    this.currentBlockType = typeForBlock;
                    RecyclerView.ViewHolder viewHolderOnCreateViewHolder = this.parentAdapter.onCreateViewHolder(this, typeForBlock);
                    this.blockLayout = viewHolderOnCreateViewHolder;
                    addView(viewHolderOnCreateViewHolder.itemView);
                }
            }
            if (this.currentBlock.blockItem != null) {
                this.parentAdapter.bindBlockToHolder(this.currentBlockType, this.blockLayout, this.currentBlock.blockItem, 0, 0);
            }
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY)) {
                return true;
            }
            return super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int maxWidth;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TL_pageBlockOrderedListItem tL_pageBlockOrderedListItem = this.currentBlock;
            if (tL_pageBlockOrderedListItem != null) {
                this.textLayout = null;
                this.textY = (tL_pageBlockOrderedListItem.index == 0 && this.currentBlock.parent.level == 0) ? AndroidUtilities.dp(10.0f) : 0;
                this.numOffsetY = 0;
                if (this.currentBlock.parent.lastMaxNumCalcWidth != width || this.currentBlock.parent.lastFontSize != ArticleViewer.this.selectedFontSize) {
                    this.currentBlock.parent.lastMaxNumCalcWidth = width;
                    this.currentBlock.parent.lastFontSize = ArticleViewer.this.selectedFontSize;
                    this.currentBlock.parent.maxNumWidth = 0;
                    int size = this.currentBlock.parent.items.size();
                    for (int a = 0; a < size; a++) {
                        TL_pageBlockOrderedListItem item = (TL_pageBlockOrderedListItem) this.currentBlock.parent.items.get(a);
                        if (item.num != null) {
                            item.numLayout = ArticleViewer.this.createLayoutForText(this, item.num, null, width - AndroidUtilities.dp(54.0f), this.currentBlock, this.parentAdapter);
                            this.currentBlock.parent.maxNumWidth = Math.max(this.currentBlock.parent.maxNumWidth, (int) Math.ceil(item.numLayout.getLineWidth(0)));
                        }
                    }
                    this.currentBlock.parent.maxNumWidth = Math.max(this.currentBlock.parent.maxNumWidth, (int) Math.ceil(ArticleViewer.listTextNumPaint.measureText("00.")));
                }
                if (ArticleViewer.this.isRtl) {
                    this.textX = AndroidUtilities.dp(18.0f);
                } else {
                    this.textX = AndroidUtilities.dp(24.0f) + this.currentBlock.parent.maxNumWidth + (this.currentBlock.parent.level * AndroidUtilities.dp(20.0f));
                }
                this.verticalAlign = false;
                int maxWidth2 = (width - AndroidUtilities.dp(18.0f)) - this.textX;
                if (ArticleViewer.this.isRtl) {
                    maxWidth = maxWidth2 - ((AndroidUtilities.dp(6.0f) + this.currentBlock.parent.maxNumWidth) + (this.currentBlock.parent.level * AndroidUtilities.dp(20.0f)));
                } else {
                    maxWidth = maxWidth2;
                }
                if (this.currentBlock.textItem != null) {
                    DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.textItem, maxWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                    this.textLayout = drawingTextCreateLayoutForText;
                    if (drawingTextCreateLayoutForText != null && drawingTextCreateLayoutForText.getLineCount() > 0) {
                        if (this.currentBlock.numLayout != null && this.currentBlock.numLayout.getLineCount() > 0) {
                            int ascent = this.textLayout.getLineAscent(0);
                            this.numOffsetY = this.currentBlock.numLayout.getLineAscent(0) - ascent;
                        }
                        height = 0 + this.textLayout.getHeight() + AndroidUtilities.dp(8.0f);
                    }
                } else if (this.currentBlock.blockItem != null) {
                    this.blockX = this.textX;
                    this.blockY = this.textY;
                    RecyclerView.ViewHolder viewHolder = this.blockLayout;
                    if (viewHolder != null) {
                        if (viewHolder.itemView instanceof BlockParagraphCell) {
                            this.blockY -= AndroidUtilities.dp(8.0f);
                            if (!ArticleViewer.this.isRtl) {
                                this.blockX -= AndroidUtilities.dp(18.0f);
                            }
                            maxWidth += AndroidUtilities.dp(18.0f);
                            height = 0 - AndroidUtilities.dp(8.0f);
                        } else if ((this.blockLayout.itemView instanceof BlockHeaderCell) || (this.blockLayout.itemView instanceof BlockSubheaderCell) || (this.blockLayout.itemView instanceof BlockTitleCell) || (this.blockLayout.itemView instanceof BlockSubtitleCell)) {
                            if (!ArticleViewer.this.isRtl) {
                                this.blockX -= AndroidUtilities.dp(18.0f);
                            }
                            maxWidth += AndroidUtilities.dp(18.0f);
                        } else if (ArticleViewer.this.isListItemBlock(this.currentBlock.blockItem)) {
                            this.blockX = 0;
                            this.blockY = 0;
                            this.textY = 0;
                            maxWidth = width;
                            height = 0 - AndroidUtilities.dp(8.0f);
                        } else if (this.blockLayout.itemView instanceof BlockTableCell) {
                            this.blockX -= AndroidUtilities.dp(18.0f);
                            maxWidth += AndroidUtilities.dp(36.0f);
                        }
                        this.blockLayout.itemView.measure(View.MeasureSpec.makeMeasureSpec(maxWidth, 1073741824), View.MeasureSpec.makeMeasureSpec(0, 0));
                        if ((this.blockLayout.itemView instanceof BlockParagraphCell) && this.currentBlock.numLayout != null && this.currentBlock.numLayout.getLineCount() > 0) {
                            BlockParagraphCell paragraphCell = (BlockParagraphCell) this.blockLayout.itemView;
                            if (paragraphCell.textLayout != null && paragraphCell.textLayout.getLineCount() > 0) {
                                int ascent2 = paragraphCell.textLayout.getLineAscent(0);
                                this.numOffsetY = this.currentBlock.numLayout.getLineAscent(0) - ascent2;
                            }
                        }
                        if (this.currentBlock.blockItem instanceof TLRPC.TL_pageBlockDetails) {
                            this.verticalAlign = true;
                            this.blockY = 0;
                            height -= AndroidUtilities.dp(8.0f);
                        } else if (this.blockLayout.itemView instanceof BlockOrderedListItemCell) {
                            this.verticalAlign = ((BlockOrderedListItemCell) this.blockLayout.itemView).verticalAlign;
                        } else if (this.blockLayout.itemView instanceof BlockListItemCell) {
                            this.verticalAlign = ((BlockListItemCell) this.blockLayout.itemView).verticalAlign;
                        }
                        if (this.verticalAlign && this.currentBlock.numLayout != null) {
                            this.textY = (this.blockLayout.itemView.getMeasuredHeight() - this.currentBlock.numLayout.getHeight()) / 2;
                        }
                        height += this.blockLayout.itemView.getMeasuredHeight();
                    }
                    height += AndroidUtilities.dp(8.0f);
                }
                if (this.currentBlock.parent.items.get(this.currentBlock.parent.items.size() - 1) == this.currentBlock) {
                    height += AndroidUtilities.dp(8.0f);
                }
                if (this.currentBlock.index == 0 && this.currentBlock.parent.level == 0) {
                    height += AndroidUtilities.dp(10.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            RecyclerView.ViewHolder viewHolder = this.blockLayout;
            if (viewHolder != null) {
                View view = viewHolder.itemView;
                int i = this.blockX;
                view.layout(i, this.blockY, this.blockLayout.itemView.getMeasuredWidth() + i, this.blockY + this.blockLayout.itemView.getMeasuredHeight());
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            int width = getMeasuredWidth();
            if (this.currentBlock.numLayout != null) {
                canvas.save();
                if (ArticleViewer.this.isRtl) {
                    canvas.translate(((width - AndroidUtilities.dp(18.0f)) - this.currentBlock.parent.maxNumWidth) - (this.currentBlock.parent.level * AndroidUtilities.dp(20.0f)), this.textY + this.numOffsetY);
                } else {
                    canvas.translate(((AndroidUtilities.dp(18.0f) + this.currentBlock.parent.maxNumWidth) - ((int) Math.ceil(this.currentBlock.numLayout.getLineWidth(0)))) + (this.currentBlock.parent.level * AndroidUtilities.dp(20.0f)), this.textY + this.numOffsetY);
                }
                this.currentBlock.numLayout.draw(canvas);
                canvas.restore();
            }
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            DrawingText drawingText = this.textLayout;
            if (drawingText == null) {
                return;
            }
            info.setText(drawingText.getText());
        }
    }

    private class BlockDetailsCell extends View implements Drawable.Callback {
        private AnimatedArrowDrawable arrow;
        private TLRPC.TL_pageBlockDetails currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockDetailsCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(50.0f);
            this.textY = AndroidUtilities.dp(11.0f) + 1;
            this.parentAdapter = adapter;
            this.arrow = new AnimatedArrowDrawable(ArticleViewer.this.getGrayTextColor(), true);
        }

        @Override // android.view.View, android.graphics.drawable.Drawable.Callback
        public void invalidateDrawable(Drawable drawable) {
            invalidate();
        }

        @Override // android.view.View, android.graphics.drawable.Drawable.Callback
        public void scheduleDrawable(Drawable drawable, Runnable runnable, long l) {
        }

        @Override // android.view.View, android.graphics.drawable.Drawable.Callback
        public void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        }

        public void setBlock(TLRPC.TL_pageBlockDetails block) {
            this.currentBlock = block;
            this.arrow.setAnimationProgress(block.open ? 0.0f : 1.0f);
            this.arrow.setCallback(this);
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int h = AndroidUtilities.dp(39.0f);
            TLRPC.TL_pageBlockDetails tL_pageBlockDetails = this.currentBlock;
            if (tL_pageBlockDetails != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, tL_pageBlockDetails.title, width - AndroidUtilities.dp(52.0f), this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    h = Math.max(h, AndroidUtilities.dp(21.0f) + this.textLayout.getHeight());
                    this.textY = ((this.textLayout.getHeight() + AndroidUtilities.dp(21.0f)) - this.textLayout.getHeight()) / 2;
                }
            }
            setMeasuredDimension(width, h + 1);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            canvas.save();
            canvas.translate(AndroidUtilities.dp(18.0f), ((getMeasuredHeight() - AndroidUtilities.dp(13.0f)) - 1) / 2);
            this.arrow.draw(canvas);
            canvas.restore();
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
            int y = getMeasuredHeight() - 1;
            canvas.drawLine(0.0f, y, getMeasuredWidth(), y, ArticleViewer.dividerPaint);
        }
    }

    private class BlockDetailsBottomCell extends View {
        private RectF rect;

        public BlockDetailsBottomCell(Context context) {
            super(context);
            this.rect = new RectF();
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), AndroidUtilities.dp(4.0f) + 1);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            canvas.drawLine(0.0f, 0.0f, getMeasuredWidth(), 0.0f, ArticleViewer.dividerPaint);
        }
    }

    private class BlockRelatedArticlesShadowCell extends View {
        private CombinedDrawable shadowDrawable;

        public BlockRelatedArticlesShadowCell(Context context) {
            super(context);
            Drawable drawable = Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, -16777216);
            CombinedDrawable combinedDrawable = new CombinedDrawable(new ColorDrawable(-986896), drawable);
            this.shadowDrawable = combinedDrawable;
            combinedDrawable.setFullsize(true);
            setBackgroundDrawable(this.shadowDrawable);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), AndroidUtilities.dp(12.0f));
            int color = ArticleViewer.this.getSelectedColor();
            if (color == 0) {
                Theme.setCombinedDrawableColor(this.shadowDrawable, -986896, false);
            } else if (color == 1) {
                Theme.setCombinedDrawableColor(this.shadowDrawable, -1712440, false);
            } else if (color == 2) {
                Theme.setCombinedDrawableColor(this.shadowDrawable, -15000805, false);
            }
        }
    }

    private class BlockRelatedArticlesHeaderCell extends View {
        private TLRPC.TL_pageBlockRelatedArticles currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockRelatedArticlesHeaderCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockRelatedArticles block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockRelatedArticles tL_pageBlockRelatedArticles = this.currentBlock;
            if (tL_pageBlockRelatedArticles != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, tL_pageBlockRelatedArticles.title, width - AndroidUtilities.dp(52.0f), 0, this.currentBlock, Layout.Alignment.ALIGN_NORMAL, 1, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    this.textY = AndroidUtilities.dp(6.0f) + ((AndroidUtilities.dp(32.0f) - this.textLayout.getHeight()) / 2);
                }
            }
            if (this.textLayout != null) {
                setMeasuredDimension(width, AndroidUtilities.dp(38.0f));
            } else {
                setMeasuredDimension(width, 1);
            }
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }
    }

    private class BlockRelatedArticlesCell extends View {
        private int additionalHeight;
        private TL_pageBlockRelatedArticlesChild currentBlock;
        private boolean divider;
        private boolean drawImage;
        private ImageReceiver imageView;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private DrawingText textLayout2;
        private int textOffset;
        private int textX;
        private int textY;

        public BlockRelatedArticlesCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(10.0f);
            this.parentAdapter = adapter;
            ImageReceiver imageReceiver = new ImageReceiver(this);
            this.imageView = imageReceiver;
            imageReceiver.setRoundRadius(AndroidUtilities.dp(6.0f));
        }

        public void setBlock(TL_pageBlockRelatedArticlesChild block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        protected void onMeasure(int i, int i2) {
            int imageWidth;
            int i3;
            boolean z;
            int i4;
            int i5;
            String string;
            int iDp;
            int size = View.MeasureSpec.getSize(i);
            this.divider = this.currentBlock.num != this.currentBlock.parent.articles.size() - 1;
            TLRPC.TL_pageRelatedArticle tL_pageRelatedArticle = this.currentBlock.parent.articles.get(this.currentBlock.num);
            this.additionalHeight = 0;
            if (ArticleViewer.this.selectedFontSize != 0) {
                if (ArticleViewer.this.selectedFontSize != 1) {
                    if (ArticleViewer.this.selectedFontSize != 3) {
                        if (ArticleViewer.this.selectedFontSize == 4) {
                            this.additionalHeight = AndroidUtilities.dp(4.0f);
                        }
                    } else {
                        this.additionalHeight = AndroidUtilities.dp(2.0f);
                    }
                } else {
                    this.additionalHeight = -AndroidUtilities.dp(2.0f);
                }
            } else {
                this.additionalHeight = -AndroidUtilities.dp(4.0f);
            }
            TLRPC.Photo photoWithId = tL_pageRelatedArticle.photo_id != 0 ? ArticleViewer.this.getPhotoWithId(tL_pageRelatedArticle.photo_id) : null;
            if (photoWithId != null) {
                this.drawImage = true;
                TLRPC.PhotoSize closestPhotoSizeWithSize = FileLoader.getClosestPhotoSizeWithSize(photoWithId.sizes, AndroidUtilities.getPhotoSize());
                TLRPC.PhotoSize closestPhotoSizeWithSize2 = FileLoader.getClosestPhotoSizeWithSize(photoWithId.sizes, 80, true);
                if (closestPhotoSizeWithSize == closestPhotoSizeWithSize2) {
                    closestPhotoSizeWithSize2 = null;
                }
                this.imageView.setImage(ImageLocation.getForPhoto(closestPhotoSizeWithSize, photoWithId), "64_64", ImageLocation.getForPhoto(closestPhotoSizeWithSize2, photoWithId), "64_64_b", closestPhotoSizeWithSize.size, null, ArticleViewer.this.currentPage, 1);
            } else {
                this.drawImage = false;
            }
            int iDp2 = AndroidUtilities.dp(60.0f);
            int iDp3 = size - AndroidUtilities.dp(36.0f);
            if (!this.drawImage) {
                imageWidth = iDp3;
            } else {
                int iDp4 = AndroidUtilities.dp(44.0f);
                this.imageView.setImageCoords((size - iDp4) - AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), iDp4, iDp4);
                imageWidth = iDp3 - (this.imageView.getImageWidth() + AndroidUtilities.dp(6.0f));
            }
            int iDp5 = AndroidUtilities.dp(18.0f);
            boolean z2 = false;
            if (tL_pageRelatedArticle.title != null) {
                i3 = iDp2;
                this.textLayout = ArticleViewer.this.createLayoutForText(this, tL_pageRelatedArticle.title, null, imageWidth, this.textY, this.currentBlock, Layout.Alignment.ALIGN_NORMAL, 3, this.parentAdapter);
            } else {
                i3 = iDp2;
            }
            DrawingText drawingText = this.textLayout;
            if (drawingText != null) {
                int lineCount = drawingText.getLineCount();
                int i6 = 4 - lineCount;
                this.textOffset = this.textLayout.getHeight() + AndroidUtilities.dp(6.0f) + this.additionalHeight;
                int height = iDp5 + this.textLayout.getHeight();
                int i7 = 0;
                while (true) {
                    if (i7 >= lineCount) {
                        break;
                    }
                    if (this.textLayout.getLineLeft(i7) == 0.0f) {
                        i7++;
                    } else {
                        z2 = true;
                        break;
                    }
                }
                z = z2;
                i4 = height;
                i5 = i6;
            } else {
                this.textOffset = 0;
                z = false;
                i4 = iDp5;
                i5 = 4;
            }
            if (tL_pageRelatedArticle.published_date != 0 && !TextUtils.isEmpty(tL_pageRelatedArticle.author)) {
                string = LocaleController.formatString("ArticleDateByAuthor", R.string.ArticleDateByAuthor, LocaleController.getInstance().chatFullDate.format(((long) tL_pageRelatedArticle.published_date) * 1000), tL_pageRelatedArticle.author);
            } else if (!TextUtils.isEmpty(tL_pageRelatedArticle.author)) {
                string = LocaleController.formatString("ArticleByAuthor", R.string.ArticleByAuthor, tL_pageRelatedArticle.author);
            } else if (tL_pageRelatedArticle.published_date != 0) {
                string = LocaleController.getInstance().chatFullDate.format(((long) tL_pageRelatedArticle.published_date) * 1000);
            } else if (!TextUtils.isEmpty(tL_pageRelatedArticle.description)) {
                string = tL_pageRelatedArticle.description;
            } else {
                string = tL_pageRelatedArticle.url;
            }
            ArticleViewer articleViewer = ArticleViewer.this;
            DrawingText drawingTextCreateLayoutForText = articleViewer.createLayoutForText(this, string, null, imageWidth, this.textY + this.textOffset, this.currentBlock, (articleViewer.isRtl || z) ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, i5, this.parentAdapter);
            this.textLayout2 = drawingTextCreateLayoutForText;
            if (drawingTextCreateLayoutForText == null) {
                iDp = i4;
            } else {
                int height2 = i4 + drawingTextCreateLayoutForText.getHeight();
                if (this.textLayout != null) {
                    iDp = height2 + AndroidUtilities.dp(6.0f) + this.additionalHeight;
                } else {
                    iDp = height2;
                }
            }
            setMeasuredDimension(size, (this.divider ? 1 : 0) + Math.max(i3, iDp));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.drawImage) {
                this.imageView.draw(canvas);
            }
            canvas.save();
            canvas.translate(this.textX, AndroidUtilities.dp(10.0f));
            DrawingText drawingText = this.textLayout;
            if (drawingText != null) {
                drawingText.draw(canvas);
            }
            if (this.textLayout2 != null) {
                canvas.translate(0.0f, this.textOffset);
                this.textLayout2.draw(canvas);
            }
            canvas.restore();
            if (this.divider) {
                canvas.drawLine(ArticleViewer.this.isRtl ? 0.0f : AndroidUtilities.dp(17.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (ArticleViewer.this.isRtl ? AndroidUtilities.dp(17.0f) : 0), getMeasuredHeight() - 1, ArticleViewer.dividerPaint);
            }
        }
    }

    private class BlockHeaderCell extends View {
        private TLRPC.TL_pageBlockHeader currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockHeaderCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockHeader block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TLRPC.TL_pageBlockHeader tL_pageBlockHeader = this.currentBlock;
            if (tL_pageBlockHeader != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, tL_pageBlockHeader.text, width - AndroidUtilities.dp(36.0f), this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    height = 0 + AndroidUtilities.dp(16.0f) + this.textLayout.getHeight();
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            if (this.textLayout == null) {
                return;
            }
            info.setText(((Object) this.textLayout.getText()) + ", " + LocaleController.getString("AccDescrIVHeading", R.string.AccDescrIVHeading));
        }
    }

    private class BlockDividerCell extends View {
        private RectF rect;

        public BlockDividerCell(Context context) {
            super(context);
            this.rect = new RectF();
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), AndroidUtilities.dp(18.0f));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int width = getMeasuredWidth() / 3;
            this.rect.set(width, AndroidUtilities.dp(8.0f), width * 2, AndroidUtilities.dp(10.0f));
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), ArticleViewer.dividerPaint);
        }
    }

    private class BlockSubtitleCell extends View {
        private TLRPC.TL_pageBlockSubtitle currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockSubtitleCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockSubtitle block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TLRPC.TL_pageBlockSubtitle tL_pageBlockSubtitle = this.currentBlock;
            if (tL_pageBlockSubtitle != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, tL_pageBlockSubtitle.text, width - AndroidUtilities.dp(36.0f), this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    height = 0 + AndroidUtilities.dp(16.0f) + this.textLayout.getHeight();
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            if (this.textLayout == null) {
                return;
            }
            info.setText(((Object) this.textLayout.getText()) + ", " + LocaleController.getString("AccDescrIVHeading", R.string.AccDescrIVHeading));
        }
    }

    private class BlockPullquoteCell extends View {
        private TLRPC.TL_pageBlockPullquote currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private DrawingText textLayout2;
        private int textX;
        private int textY;
        private int textY2;

        public BlockPullquoteCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockPullquote block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout2, this.textX, this.textY2) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockPullquote tL_pageBlockPullquote = this.currentBlock;
            if (tL_pageBlockPullquote != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, tL_pageBlockPullquote.text, width - AndroidUtilities.dp(36.0f), this.currentBlock, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                height = drawingTextCreateLayoutForText != null ? 0 + AndroidUtilities.dp(8.0f) + this.textLayout.getHeight() : 0;
                DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption, width - AndroidUtilities.dp(36.0f), this.currentBlock, this.parentAdapter);
                this.textLayout2 = drawingTextCreateLayoutForText2;
                if (drawingTextCreateLayoutForText2 != null) {
                    this.textY2 = AndroidUtilities.dp(2.0f) + height;
                    height += AndroidUtilities.dp(8.0f) + this.textLayout2.getHeight();
                }
                if (height != 0) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
            if (this.textLayout2 != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY2);
                this.textLayout2.draw(canvas);
                canvas.restore();
            }
        }
    }

    private class BlockBlockquoteCell extends View {
        private TLRPC.TL_pageBlockBlockquote currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private DrawingText textLayout2;
        private int textX;
        private int textY;
        private int textY2;

        public BlockBlockquoteCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockBlockquote block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout2, this.textX, this.textY2) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            if (this.currentBlock != null) {
                int textWidth = width - AndroidUtilities.dp(50.0f);
                if (this.currentBlock.level > 0) {
                    textWidth -= AndroidUtilities.dp(this.currentBlock.level * 14);
                }
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.text, textWidth, this.currentBlock, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                height = drawingTextCreateLayoutForText != null ? 0 + AndroidUtilities.dp(8.0f) + this.textLayout.getHeight() : 0;
                if (this.currentBlock.level > 0) {
                    if (ArticleViewer.this.isRtl) {
                        this.textX = AndroidUtilities.dp((this.currentBlock.level * 14) + 14);
                    } else {
                        this.textX = AndroidUtilities.dp(this.currentBlock.level * 14) + AndroidUtilities.dp(32.0f);
                    }
                } else if (ArticleViewer.this.isRtl) {
                    this.textX = AndroidUtilities.dp(14.0f);
                } else {
                    this.textX = AndroidUtilities.dp(32.0f);
                }
                DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption, textWidth, this.currentBlock, this.parentAdapter);
                this.textLayout2 = drawingTextCreateLayoutForText2;
                if (drawingTextCreateLayoutForText2 != null) {
                    this.textY2 = AndroidUtilities.dp(8.0f) + height;
                    height += AndroidUtilities.dp(8.0f) + this.textLayout2.getHeight();
                }
                if (height != 0) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
            if (this.textLayout2 != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY2);
                this.textLayout2.draw(canvas);
                canvas.restore();
            }
            if (!ArticleViewer.this.isRtl) {
                canvas.drawRect(AndroidUtilities.dp((this.currentBlock.level * 14) + 18), AndroidUtilities.dp(6.0f), AndroidUtilities.dp((this.currentBlock.level * 14) + 20), getMeasuredHeight() - AndroidUtilities.dp(6.0f), ArticleViewer.quoteLinePaint);
            } else {
                int x = getMeasuredWidth() - AndroidUtilities.dp(20.0f);
                canvas.drawRect(x, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(2.0f) + x, getMeasuredHeight() - AndroidUtilities.dp(6.0f), ArticleViewer.quoteLinePaint);
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }
    }

    private class BlockPhotoCell extends FrameLayout implements DownloadController.FileDownloadProgressListener {
        private int TAG;
        boolean autoDownload;
        private int buttonPressed;
        private int buttonState;
        private int buttonX;
        private int buttonY;
        private boolean cancelLoading;
        private DrawingText captionLayout;
        private BlockChannelCell channelCell;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockPhoto currentBlock;
        private String currentFilter;
        private TLRPC.Photo currentPhoto;
        private TLRPC.PhotoSize currentPhotoObject;
        private TLRPC.PhotoSize currentPhotoObjectThumb;
        private String currentThumbFilter;
        private int currentType;
        private MessageObject.GroupedMessagePosition groupPosition;
        private ImageReceiver imageView;
        private boolean isFirst;
        private boolean isLast;
        private Drawable linkDrawable;
        private WebpageAdapter parentAdapter;
        private TLRPC.PageBlock parentBlock;
        private boolean photoPressed;
        private RadialProgress2 radialProgress;
        private int textX;
        private int textY;

        public BlockPhotoCell(Context context, WebpageAdapter adapter, int type) {
            super(context);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
            this.imageView = new ImageReceiver(this);
            this.channelCell = ArticleViewer.this.new BlockChannelCell(context, this.parentAdapter, 1);
            RadialProgress2 radialProgress2 = new RadialProgress2(this);
            this.radialProgress = radialProgress2;
            radialProgress2.setProgressColor(-1);
            this.radialProgress.setColors(1711276032, Theme.ACTION_BAR_PHOTO_VIEWER_COLOR, -1, -2500135);
            this.TAG = DownloadController.getInstance(ArticleViewer.this.currentAccount).generateObserverTag();
            addView(this.channelCell, LayoutHelper.createFrame(-1, -2.0f));
            this.currentType = type;
        }

        public void setBlock(TLRPC.TL_pageBlockPhoto block, boolean first, boolean last) {
            TLRPC.Photo photo;
            this.parentBlock = null;
            this.currentBlock = block;
            this.isFirst = first;
            this.isLast = last;
            this.channelCell.setVisibility(4);
            if (!TextUtils.isEmpty(this.currentBlock.url)) {
                this.linkDrawable = getResources().getDrawable(R.drawable.instant_link);
            }
            TLRPC.TL_pageBlockPhoto tL_pageBlockPhoto = this.currentBlock;
            if (tL_pageBlockPhoto != null && (photo = ArticleViewer.this.getPhotoWithId(tL_pageBlockPhoto.photo_id)) != null) {
                this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
            } else {
                this.currentPhotoObject = null;
            }
            updateButtonState(false);
            requestLayout();
        }

        public void setParentBlock(TLRPC.PageBlock block) {
            this.parentBlock = block;
            if (ArticleViewer.this.channelBlock != null && (this.parentBlock instanceof TLRPC.TL_pageBlockCover)) {
                this.channelCell.setBlock(ArticleViewer.this.channelBlock);
                this.channelCell.setVisibility(0);
            }
        }

        public View getChannelCell() {
            return this.channelCell;
        }

        /* JADX WARN: Removed duplicated region for block: B:28:0x0097  */
        /* JADX WARN: Removed duplicated region for block: B:30:0x009b  */
        @Override // android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public boolean onTouchEvent(android.view.MotionEvent r12) {
            /*
                Method dump skipped, instruction units count: 263
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.BlockPhotoCell.onTouchEvent(android.view.MotionEvent):boolean");
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width;
            int height;
            int photoX;
            int textWidth;
            int height2;
            int i;
            int width2 = View.MeasureSpec.getSize(widthMeasureSpec);
            int height3 = 0;
            int i2 = this.currentType;
            if (i2 == 1) {
                int width3 = ((View) getParent()).getMeasuredWidth();
                height3 = ((View) getParent()).getMeasuredHeight();
                width = width3;
            } else if (i2 != 2) {
                width = width2;
            } else {
                height3 = (int) Math.ceil(this.groupPosition.ph * Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.5f);
                width = width2;
            }
            TLRPC.TL_pageBlockPhoto tL_pageBlockPhoto = this.currentBlock;
            if (tL_pageBlockPhoto != null) {
                this.currentPhoto = ArticleViewer.this.getPhotoWithId(tL_pageBlockPhoto.photo_id);
                int size = AndroidUtilities.dp(48.0f);
                int photoWidth = width;
                int photoHeight = height3;
                if (this.currentType == 0 && this.currentBlock.level > 0) {
                    int iDp = AndroidUtilities.dp(this.currentBlock.level * 14) + AndroidUtilities.dp(18.0f);
                    photoX = iDp;
                    this.textX = iDp;
                    photoWidth -= AndroidUtilities.dp(18.0f) + photoX;
                    textWidth = photoWidth;
                } else {
                    photoX = 0;
                    this.textX = AndroidUtilities.dp(18.0f);
                    textWidth = width - AndroidUtilities.dp(36.0f);
                }
                TLRPC.Photo photo = this.currentPhoto;
                if (photo == null || this.currentPhotoObject == null) {
                    height = height3;
                } else {
                    TLRPC.PhotoSize closestPhotoSizeWithSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 40, true);
                    this.currentPhotoObjectThumb = closestPhotoSizeWithSize;
                    if (this.currentPhotoObject == closestPhotoSizeWithSize) {
                        this.currentPhotoObjectThumb = null;
                    }
                    int i3 = this.currentType;
                    if (i3 == 0) {
                        float scale = photoWidth / this.currentPhotoObject.w;
                        height3 = (int) (this.currentPhotoObject.h * scale);
                        if (!(this.parentBlock instanceof TLRPC.TL_pageBlockCover)) {
                            int maxHeight = (int) ((Math.max(ArticleViewer.this.listView[0].getMeasuredWidth(), ArticleViewer.this.listView[0].getMeasuredHeight()) - AndroidUtilities.dp(56.0f)) * 0.9f);
                            if (height3 > maxHeight) {
                                height3 = maxHeight;
                                float scale2 = height3 / this.currentPhotoObject.h;
                                photoWidth = (int) (this.currentPhotoObject.w * scale2);
                                photoX += ((width - photoX) - photoWidth) / 2;
                            }
                        } else {
                            height3 = Math.min(height3, photoWidth);
                        }
                        photoHeight = height3;
                    } else if (i3 == 2) {
                        if ((this.groupPosition.flags & 2) == 0) {
                            photoWidth -= AndroidUtilities.dp(2.0f);
                        }
                        if ((this.groupPosition.flags & 8) == 0) {
                            photoHeight -= AndroidUtilities.dp(2.0f);
                        }
                        if (this.groupPosition.leftSpanOffset != 0) {
                            int offset = (int) Math.ceil((this.groupPosition.leftSpanOffset * width) / 1000.0f);
                            photoWidth -= offset;
                            photoX += offset;
                        }
                    }
                    this.imageView.setImageCoords(photoX, (this.isFirst || (i = this.currentType) == 1 || i == 2 || this.currentBlock.level > 0) ? 0 : AndroidUtilities.dp(8.0f), photoWidth, photoHeight);
                    if (this.currentType == 0) {
                        this.currentFilter = null;
                    } else {
                        this.currentFilter = String.format(Locale.US, "%d_%d", Integer.valueOf(photoWidth), Integer.valueOf(photoHeight));
                    }
                    this.currentThumbFilter = "80_80_b";
                    this.autoDownload = (DownloadController.getInstance(ArticleViewer.this.currentAccount).getCurrentDownloadMask() & 1) != 0;
                    File path = FileLoader.getPathToAttach(this.currentPhotoObject, true);
                    if (!this.autoDownload && !path.exists()) {
                        this.imageView.setStrippedLocation(ImageLocation.getForPhoto(this.currentPhotoObject, this.currentPhoto));
                        this.imageView.setImage(null, this.currentFilter, ImageLocation.getForPhoto(this.currentPhotoObjectThumb, this.currentPhoto), this.currentThumbFilter, this.currentPhotoObject.size, null, ArticleViewer.this.currentPage, 1);
                    } else {
                        this.imageView.setStrippedLocation(null);
                        this.imageView.setImage(ImageLocation.getForPhoto(this.currentPhotoObject, this.currentPhoto), this.currentFilter, ImageLocation.getForPhoto(this.currentPhotoObjectThumb, this.currentPhoto), this.currentThumbFilter, this.currentPhotoObject.size, null, ArticleViewer.this.currentPage, 1);
                    }
                    this.buttonX = (int) (this.imageView.getImageX() + ((this.imageView.getImageWidth() - size) / 2.0f));
                    int imageY = (int) (this.imageView.getImageY() + ((this.imageView.getImageHeight() - size) / 2.0f));
                    this.buttonY = imageY;
                    RadialProgress2 radialProgress2 = this.radialProgress;
                    int i4 = this.buttonX;
                    radialProgress2.setProgressRect(i4, imageY, i4 + size, imageY + size);
                    height = height3;
                }
                if (this.currentType == 0) {
                    DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                    this.captionLayout = drawingTextCreateLayoutForText;
                    if (drawingTextCreateLayoutForText != null) {
                        int iDp2 = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                        this.creditOffset = iDp2;
                        height2 = height + iDp2 + AndroidUtilities.dp(4.0f);
                    } else {
                        height2 = height;
                    }
                    DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                    this.creditLayout = drawingTextCreateLayoutForText2;
                    if (drawingTextCreateLayoutForText2 != null) {
                        height = height2 + AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                    } else {
                        height = height2;
                    }
                }
                if (!this.isFirst && this.currentType == 0 && this.currentBlock.level <= 0) {
                    height += AndroidUtilities.dp(8.0f);
                }
                boolean nextIsChannel = (this.parentBlock instanceof TLRPC.TL_pageBlockCover) && this.parentAdapter.blocks != null && this.parentAdapter.blocks.size() > 1 && (this.parentAdapter.blocks.get(1) instanceof TLRPC.TL_pageBlockChannel);
                if (this.currentType != 2 && !nextIsChannel) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            this.channelCell.measure(widthMeasureSpec, heightMeasureSpec);
            this.channelCell.setTranslationY(this.imageView.getImageHeight() - AndroidUtilities.dp(39.0f));
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (!this.imageView.hasBitmapImage() || this.imageView.getCurrentAlpha() != 1.0f) {
                canvas.drawRect(this.imageView.getImageX(), this.imageView.getImageY(), this.imageView.getImageX2(), this.imageView.getImageY2(), ArticleViewer.photoBackgroundPaint);
            }
            this.imageView.draw(canvas);
            if (this.imageView.getVisible()) {
                this.radialProgress.draw(canvas);
            }
            if (!TextUtils.isEmpty(this.currentBlock.url)) {
                int x = getMeasuredWidth() - AndroidUtilities.dp(35.0f);
                int y = this.imageView.getImageY() + AndroidUtilities.dp(11.0f);
                this.linkDrawable.setBounds(x, y, AndroidUtilities.dp(24.0f) + x, AndroidUtilities.dp(24.0f) + y);
                this.linkDrawable.draw(canvas);
            }
            this.textY = this.imageView.getImageY() + this.imageView.getImageHeight() + AndroidUtilities.dp(8.0f);
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }

        private int getIconForCurrentState() {
            int i = this.buttonState;
            if (i == 0) {
                return 2;
            }
            if (i == 1) {
                return 3;
            }
            return 4;
        }

        private void didPressedButton(boolean animated) {
            int i = this.buttonState;
            if (i == 0) {
                this.cancelLoading = false;
                this.radialProgress.setProgress(0.0f, animated);
                this.imageView.setImage(ImageLocation.getForPhoto(this.currentPhotoObject, this.currentPhoto), this.currentFilter, ImageLocation.getForPhoto(this.currentPhotoObjectThumb, this.currentPhoto), this.currentThumbFilter, this.currentPhotoObject.size, null, ArticleViewer.this.currentPage, 1);
                this.buttonState = 1;
                this.radialProgress.setIcon(getIconForCurrentState(), true, animated);
                invalidate();
                return;
            }
            if (i == 1) {
                this.cancelLoading = true;
                this.imageView.cancelLoadImage();
                this.buttonState = 0;
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                invalidate();
            }
        }

        public void updateButtonState(boolean animated) {
            String fileName = FileLoader.getAttachFileName(this.currentPhotoObject);
            File path = FileLoader.getPathToAttach(this.currentPhotoObject, true);
            boolean fileExists = path.exists();
            if (TextUtils.isEmpty(fileName)) {
                this.radialProgress.setIcon(4, false, false);
                return;
            }
            if (fileExists) {
                DownloadController.getInstance(ArticleViewer.this.currentAccount).removeLoadingFileObserver(this);
                this.buttonState = -1;
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                invalidate();
                return;
            }
            DownloadController.getInstance(ArticleViewer.this.currentAccount).addLoadingFileObserver(fileName, null, this);
            float setProgress = 0.0f;
            if (this.autoDownload || FileLoader.getInstance(ArticleViewer.this.currentAccount).isLoadingFile(fileName)) {
                this.buttonState = 1;
                Float progress = ImageLoader.getInstance().getFileProgress(fileName);
                setProgress = progress != null ? progress.floatValue() : 0.0f;
            } else {
                this.buttonState = 0;
            }
            this.radialProgress.setIcon(getIconForCurrentState(), true, animated);
            this.radialProgress.setProgress(setProgress, false);
            invalidate();
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            this.imageView.onDetachedFromWindow();
            DownloadController.getInstance(ArticleViewer.this.currentAccount).removeLoadingFileObserver(this);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            this.imageView.onAttachedToWindow();
            updateButtonState(false);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onFailedDownload(String fileName, boolean canceled) {
            updateButtonState(false);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onSuccessDownload(String fileName) {
            this.radialProgress.setProgress(1.0f, true);
            updateButtonState(true);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressDownload(String fileName, float progress) {
            this.radialProgress.setProgress(progress, true);
            if (this.buttonState != 1) {
                updateButtonState(true);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public int getObserverTag() {
            return this.TAG;
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            StringBuilder sb = new StringBuilder(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
            if (this.captionLayout != null) {
                sb.append(", ");
                sb.append(this.captionLayout.getText());
            }
            info.setText(sb.toString());
        }
    }

    private class BlockMapCell extends FrameLayout {
        private DrawingText captionLayout;
        private DrawingText creditLayout;
        private int creditOffset;
        private TLRPC.TL_pageBlockMap currentBlock;
        private int currentMapProvider;
        private int currentType;
        private ImageReceiver imageView;
        private boolean isFirst;
        private boolean isLast;
        private WebpageAdapter parentAdapter;
        private boolean photoPressed;
        private int textX;
        private int textY;

        public BlockMapCell(Context context, WebpageAdapter adapter, int type) {
            super(context);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
            this.imageView = new ImageReceiver(this);
            this.currentType = type;
        }

        public void setBlock(TLRPC.TL_pageBlockMap block, boolean first, boolean last) {
            this.currentBlock = block;
            this.isFirst = first;
            this.isLast = last;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            float x = event.getX();
            float y = event.getY();
            if (event.getAction() == 0 && this.imageView.isInsideImage(x, y)) {
                this.photoPressed = true;
            } else if (event.getAction() == 1 && this.photoPressed) {
                this.photoPressed = false;
                try {
                    double lat = this.currentBlock.geo.lat;
                    double lon = this.currentBlock.geo._long;
                    ArticleViewer.this.parentActivity.startActivity(new Intent("android.intent.action.VIEW", Uri.parse("geo:" + lat + "," + lon + "?q=" + lat + "," + lon)));
                } catch (Exception e) {
                    FileLog.e(e);
                }
            } else if (event.getAction() == 3) {
                this.photoPressed = false;
            }
            return this.photoPressed || ArticleViewer.this.checkLayoutForLinks(event, this, this.captionLayout, this.textX, this.textY) || ArticleViewer.this.checkLayoutForLinks(event, this, this.creditLayout, this.textX, this.textY + this.creditOffset) || super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width;
            int height;
            int photoX;
            int textWidth;
            int photoWidth;
            int photoX2;
            int height2;
            int i;
            int width2 = View.MeasureSpec.getSize(widthMeasureSpec);
            int height3 = 0;
            int i2 = this.currentType;
            if (i2 == 1) {
                int width3 = ((View) getParent()).getMeasuredWidth();
                height3 = ((View) getParent()).getMeasuredHeight();
                width = width3;
            } else if (i2 != 2) {
                width = width2;
            } else {
                height3 = width2;
                width = width2;
            }
            TLRPC.TL_pageBlockMap tL_pageBlockMap = this.currentBlock;
            if (tL_pageBlockMap != null) {
                int photoWidth2 = width;
                if (this.currentType == 0 && tL_pageBlockMap.level > 0) {
                    int iDp = AndroidUtilities.dp(this.currentBlock.level * 14) + AndroidUtilities.dp(18.0f);
                    photoX = iDp;
                    this.textX = iDp;
                    photoWidth2 -= AndroidUtilities.dp(18.0f) + photoX;
                    textWidth = photoWidth2;
                } else {
                    photoX = 0;
                    this.textX = AndroidUtilities.dp(18.0f);
                    textWidth = width - AndroidUtilities.dp(36.0f);
                }
                if (this.currentType == 0) {
                    float scale = photoWidth2 / this.currentBlock.w;
                    int height4 = (int) (this.currentBlock.h * scale);
                    int maxHeight = (int) ((Math.max(ArticleViewer.this.listView[0].getMeasuredWidth(), ArticleViewer.this.listView[0].getMeasuredHeight()) - AndroidUtilities.dp(56.0f)) * 0.9f);
                    if (height4 > maxHeight) {
                        float scale2 = maxHeight / this.currentBlock.h;
                        int photoWidth3 = (int) (this.currentBlock.w * scale2);
                        height = maxHeight;
                        photoWidth = photoWidth3;
                        photoX2 = photoX + (((width - photoX) - photoWidth3) / 2);
                    } else {
                        height = height4;
                        photoWidth = photoWidth2;
                        photoX2 = photoX;
                    }
                } else {
                    height = height3;
                    photoWidth = photoWidth2;
                    photoX2 = photoX;
                }
                this.imageView.setImageCoords(photoX2, (this.isFirst || (i = this.currentType) == 1 || i == 2 || this.currentBlock.level > 0) ? 0 : AndroidUtilities.dp(8.0f), photoWidth, height);
                WebFile currentWebFile = WebFile.createWithGeoPoint(this.currentBlock.geo, (int) (photoWidth / AndroidUtilities.density), (int) (height / AndroidUtilities.density), 15, Math.min(2, (int) Math.ceil(AndroidUtilities.density)));
                int i3 = MessagesController.getInstance(ArticleViewer.this.currentAccount).mapProvider;
                this.currentMapProvider = i3;
                if (i3 == 2 && currentWebFile != null) {
                    this.imageView.setImage(ImageLocation.getForWebFile(currentWebFile), null, Theme.chat_locationDrawable[0], null, ArticleViewer.this.currentPage, 0);
                }
                if (this.currentType == 0) {
                    DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, null, this.currentBlock.caption.text, textWidth, this.currentBlock, this.parentAdapter);
                    this.captionLayout = drawingTextCreateLayoutForText;
                    if (drawingTextCreateLayoutForText != null) {
                        int iDp2 = AndroidUtilities.dp(4.0f) + this.captionLayout.getHeight();
                        this.creditOffset = iDp2;
                        height2 = height + iDp2 + AndroidUtilities.dp(4.0f);
                    } else {
                        height2 = height;
                    }
                    DrawingText drawingTextCreateLayoutForText2 = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.caption.credit, textWidth, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                    this.creditLayout = drawingTextCreateLayoutForText2;
                    if (drawingTextCreateLayoutForText2 != null) {
                        height = height2 + AndroidUtilities.dp(4.0f) + this.creditLayout.getHeight();
                    } else {
                        height = height2;
                    }
                }
                if (!this.isFirst && this.currentType == 0 && this.currentBlock.level <= 0) {
                    height += AndroidUtilities.dp(8.0f);
                }
                if (this.currentType != 2) {
                    height += AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            this.imageView.draw(canvas);
            if (this.currentMapProvider == 2 && this.imageView.hasNotThumb()) {
                int w = (int) (Theme.chat_redLocationIcon.getIntrinsicWidth() * 0.8f);
                int h = (int) (Theme.chat_redLocationIcon.getIntrinsicHeight() * 0.8f);
                int x = this.imageView.getImageX() + ((this.imageView.getImageWidth() - w) / 2);
                int y = this.imageView.getImageY() + ((this.imageView.getImageHeight() / 2) - h);
                Theme.chat_redLocationIcon.setAlpha((int) (this.imageView.getCurrentAlpha() * 255.0f));
                Theme.chat_redLocationIcon.setBounds(x, y, x + w, y + h);
                Theme.chat_redLocationIcon.draw(canvas);
            }
            this.textY = this.imageView.getImageY() + this.imageView.getImageHeight() + AndroidUtilities.dp(8.0f);
            if (this.captionLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.captionLayout.draw(canvas);
                canvas.restore();
            }
            if (this.creditLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY + this.creditOffset);
                this.creditLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            StringBuilder sb = new StringBuilder(LocaleController.getString("Map", R.string.Map));
            if (this.captionLayout != null) {
                sb.append(", ");
                sb.append(this.captionLayout.getText());
            }
            info.setText(sb.toString());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class BlockChannelCell extends FrameLayout {
        private Paint backgroundPaint;
        private int buttonWidth;
        private AnimatorSet currentAnimation;
        private TLRPC.TL_pageBlockChannel currentBlock;
        private int currentState;
        private int currentType;
        private ImageView imageView;
        private WebpageAdapter parentAdapter;
        private ContextProgressView progressView;
        private DrawingText textLayout;
        private TextView textView;
        private int textX;
        private int textX2;
        private int textY;

        public BlockChannelCell(Context context, WebpageAdapter adapter, int type) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(11.0f);
            this.parentAdapter = adapter;
            setWillNotDraw(false);
            this.backgroundPaint = new Paint();
            this.currentType = type;
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextSize(1, 14.0f);
            this.textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.textView.setText(LocaleController.getString("ChannelJoin", R.string.ChannelJoin));
            this.textView.setGravity(19);
            addView(this.textView, LayoutHelper.createFrame(-2, 39, 53));
            this.textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$BlockChannelCell$FS_ZyFLc1O3HsK_suZ3i2LHxAik
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$ArticleViewer$BlockChannelCell(view);
                }
            });
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setImageResource(R.drawable.list_check);
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            addView(this.imageView, LayoutHelper.createFrame(39, 39, 53));
            ContextProgressView contextProgressView = new ContextProgressView(context, 0);
            this.progressView = contextProgressView;
            addView(contextProgressView, LayoutHelper.createFrame(39, 39, 53));
        }

        public /* synthetic */ void lambda$new$0$ArticleViewer$BlockChannelCell(View v) {
            if (this.currentState != 0) {
                return;
            }
            setState(1, true);
            ArticleViewer articleViewer = ArticleViewer.this;
            articleViewer.joinChannel(this, articleViewer.loadedChannel);
        }

        public void setBlock(TLRPC.TL_pageBlockChannel block) {
            this.currentBlock = block;
            int color = ArticleViewer.this.getSelectedColor();
            if (this.currentType == 0) {
                this.textView.setTextColor(-14840360);
                if (color == 0) {
                    this.backgroundPaint.setColor(Theme.value_pageBackgroundColor);
                } else if (color == 1) {
                    this.backgroundPaint.setColor(-1712440);
                } else if (color == 2) {
                    this.backgroundPaint.setColor(-15000805);
                }
                this.imageView.setColorFilter(new PorterDuffColorFilter(-6710887, PorterDuff.Mode.MULTIPLY));
            } else {
                this.textView.setTextColor(-1);
                this.backgroundPaint.setColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
                this.imageView.setColorFilter(new PorterDuffColorFilter(-1, PorterDuff.Mode.MULTIPLY));
            }
            TLRPC.Chat channel = MessagesController.getInstance(ArticleViewer.this.currentAccount).getChat(Integer.valueOf(block.channel.id));
            if (channel == null || channel.min) {
                ArticleViewer.this.loadChannel(this, this.parentAdapter, block.channel);
                setState(1, false);
            } else {
                ArticleViewer.this.loadedChannel = channel;
                if (!channel.left || channel.kicked) {
                    setState(4, false);
                } else {
                    setState(0, false);
                }
            }
            requestLayout();
        }

        public void setState(int state, boolean animated) {
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            this.currentState = state;
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.currentAnimation = animatorSet2;
                Animator[] animatorArr = new Animator[9];
                TextView textView = this.textView;
                Property property = View.ALPHA;
                float[] fArr = new float[1];
                fArr[0] = state == 0 ? 1.0f : 0.0f;
                animatorArr[0] = ObjectAnimator.ofFloat(textView, (Property<TextView, Float>) property, fArr);
                TextView textView2 = this.textView;
                Property property2 = View.SCALE_X;
                float[] fArr2 = new float[1];
                fArr2[0] = state == 0 ? 1.0f : 0.1f;
                animatorArr[1] = ObjectAnimator.ofFloat(textView2, (Property<TextView, Float>) property2, fArr2);
                TextView textView3 = this.textView;
                Property property3 = View.SCALE_Y;
                float[] fArr3 = new float[1];
                fArr3[0] = state == 0 ? 1.0f : 0.1f;
                animatorArr[2] = ObjectAnimator.ofFloat(textView3, (Property<TextView, Float>) property3, fArr3);
                ContextProgressView contextProgressView = this.progressView;
                Property property4 = View.ALPHA;
                float[] fArr4 = new float[1];
                fArr4[0] = state == 1 ? 1.0f : 0.0f;
                animatorArr[3] = ObjectAnimator.ofFloat(contextProgressView, (Property<ContextProgressView, Float>) property4, fArr4);
                ContextProgressView contextProgressView2 = this.progressView;
                Property property5 = View.SCALE_X;
                float[] fArr5 = new float[1];
                fArr5[0] = state == 1 ? 1.0f : 0.1f;
                animatorArr[4] = ObjectAnimator.ofFloat(contextProgressView2, (Property<ContextProgressView, Float>) property5, fArr5);
                ContextProgressView contextProgressView3 = this.progressView;
                Property property6 = View.SCALE_Y;
                float[] fArr6 = new float[1];
                fArr6[0] = state == 1 ? 1.0f : 0.1f;
                animatorArr[5] = ObjectAnimator.ofFloat(contextProgressView3, (Property<ContextProgressView, Float>) property6, fArr6);
                ImageView imageView = this.imageView;
                Property property7 = View.ALPHA;
                float[] fArr7 = new float[1];
                fArr7[0] = state == 2 ? 1.0f : 0.0f;
                animatorArr[6] = ObjectAnimator.ofFloat(imageView, (Property<ImageView, Float>) property7, fArr7);
                ImageView imageView2 = this.imageView;
                Property property8 = View.SCALE_X;
                float[] fArr8 = new float[1];
                fArr8[0] = state == 2 ? 1.0f : 0.1f;
                animatorArr[7] = ObjectAnimator.ofFloat(imageView2, (Property<ImageView, Float>) property8, fArr8);
                ImageView imageView3 = this.imageView;
                Property property9 = View.SCALE_Y;
                float[] fArr9 = new float[1];
                fArr9[0] = state == 2 ? 1.0f : 0.1f;
                animatorArr[8] = ObjectAnimator.ofFloat(imageView3, (Property<ImageView, Float>) property9, fArr9);
                animatorSet2.playTogether(animatorArr);
                this.currentAnimation.setDuration(150L);
                this.currentAnimation.start();
                return;
            }
            this.textView.setAlpha(state == 0 ? 1.0f : 0.0f);
            this.textView.setScaleX(state == 0 ? 1.0f : 0.1f);
            this.textView.setScaleY(state == 0 ? 1.0f : 0.1f);
            this.progressView.setAlpha(state == 1 ? 1.0f : 0.0f);
            this.progressView.setScaleX(state == 1 ? 1.0f : 0.1f);
            this.progressView.setScaleY(state == 1 ? 1.0f : 0.1f);
            this.imageView.setAlpha(state == 2 ? 1.0f : 0.0f);
            this.imageView.setScaleX(state == 2 ? 1.0f : 0.1f);
            this.imageView.setScaleY(state == 2 ? 1.0f : 0.1f);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (this.currentType != 0) {
                return super.onTouchEvent(event);
            }
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            setMeasuredDimension(width, AndroidUtilities.dp(48.0f));
            this.textView.measure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(39.0f), 1073741824));
            this.buttonWidth = this.textView.getMeasuredWidth();
            this.progressView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(39.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(39.0f), 1073741824));
            this.imageView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(39.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(39.0f), 1073741824));
            TLRPC.TL_pageBlockChannel tL_pageBlockChannel = this.currentBlock;
            if (tL_pageBlockChannel != null) {
                this.textLayout = ArticleViewer.this.createLayoutForText(this, tL_pageBlockChannel.channel.title, (TLRPC.RichText) null, (width - AndroidUtilities.dp(52.0f)) - this.buttonWidth, this.currentBlock, StaticLayoutEx.ALIGN_LEFT(), this.parentAdapter);
                if (ArticleViewer.this.isRtl) {
                    this.textX2 = this.textX;
                } else {
                    this.textX2 = (getMeasuredWidth() - this.textX) - this.buttonWidth;
                }
            }
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            this.imageView.layout((this.textX2 + (this.buttonWidth / 2)) - AndroidUtilities.dp(19.0f), 0, this.textX2 + (this.buttonWidth / 2) + AndroidUtilities.dp(20.0f), AndroidUtilities.dp(39.0f));
            this.progressView.layout((this.textX2 + (this.buttonWidth / 2)) - AndroidUtilities.dp(19.0f), 0, this.textX2 + (this.buttonWidth / 2) + AndroidUtilities.dp(20.0f), AndroidUtilities.dp(39.0f));
            TextView textView = this.textView;
            int i = this.textX2;
            textView.layout(i, 0, textView.getMeasuredWidth() + i, this.textView.getMeasuredHeight());
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            canvas.drawRect(0.0f, 0.0f, getMeasuredWidth(), AndroidUtilities.dp(39.0f), this.backgroundPaint);
            DrawingText drawingText = this.textLayout;
            if (drawingText != null && drawingText.getLineCount() > 0) {
                canvas.save();
                if (ArticleViewer.this.isRtl) {
                    canvas.translate((getMeasuredWidth() - this.textLayout.getLineWidth(0)) - this.textX, this.textY);
                } else {
                    canvas.translate(this.textX, this.textY);
                }
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }
    }

    private class BlockAuthorDateCell extends View {
        private TLRPC.TL_pageBlockAuthorDate currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockAuthorDateCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockAuthorDate block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        /* JADX WARN: Removed duplicated region for block: B:32:0x00df  */
        @Override // android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        protected void onMeasure(int r16, int r17) {
            /*
                Method dump skipped, instruction units count: 282
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.BlockAuthorDateCell.onMeasure(int, int):void");
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            DrawingText drawingText = this.textLayout;
            if (drawingText == null) {
                return;
            }
            info.setText(drawingText.getText());
        }
    }

    private class BlockTitleCell extends View {
        private TLRPC.TL_pageBlockTitle currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockTitleCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockTitle block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockTitle tL_pageBlockTitle = this.currentBlock;
            if (tL_pageBlockTitle != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, tL_pageBlockTitle.text, width - AndroidUtilities.dp(36.0f), this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                height = drawingTextCreateLayoutForText != null ? 0 + AndroidUtilities.dp(16.0f) + this.textLayout.getHeight() : 0;
                if (this.currentBlock.first) {
                    height += AndroidUtilities.dp(8.0f);
                    this.textY = AndroidUtilities.dp(16.0f);
                } else {
                    this.textY = AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            if (this.textLayout == null) {
                return;
            }
            info.setText(((Object) this.textLayout.getText()) + ", " + LocaleController.getString("AccDescrIVTitle", R.string.AccDescrIVTitle));
        }
    }

    private class BlockKickerCell extends View {
        private TLRPC.TL_pageBlockKicker currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockKickerCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockKicker block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int height;
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            TLRPC.TL_pageBlockKicker tL_pageBlockKicker = this.currentBlock;
            if (tL_pageBlockKicker != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, tL_pageBlockKicker.text, width - AndroidUtilities.dp(36.0f), this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                height = drawingTextCreateLayoutForText != null ? 0 + AndroidUtilities.dp(16.0f) + this.textLayout.getHeight() : 0;
                if (this.currentBlock.first) {
                    height += AndroidUtilities.dp(8.0f);
                    this.textY = AndroidUtilities.dp(16.0f);
                } else {
                    this.textY = AndroidUtilities.dp(8.0f);
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }
    }

    private class BlockFooterCell extends View {
        private TLRPC.TL_pageBlockFooter currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockFooterCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockFooter block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TLRPC.TL_pageBlockFooter tL_pageBlockFooter = this.currentBlock;
            if (tL_pageBlockFooter != null) {
                if (tL_pageBlockFooter.level == 0) {
                    this.textY = AndroidUtilities.dp(8.0f);
                    this.textX = AndroidUtilities.dp(18.0f);
                } else {
                    this.textY = 0;
                    this.textX = AndroidUtilities.dp((this.currentBlock.level * 14) + 18);
                }
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, this.currentBlock.text, (width - AndroidUtilities.dp(18.0f)) - this.textX, this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    int height2 = drawingTextCreateLayoutForText.getHeight();
                    if (this.currentBlock.level > 0) {
                        height = height2 + AndroidUtilities.dp(8.0f);
                    } else {
                        height = height2 + AndroidUtilities.dp(16.0f);
                    }
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            if (this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
            if (this.currentBlock.level > 0) {
                canvas.drawRect(AndroidUtilities.dp(18.0f), 0.0f, AndroidUtilities.dp(20.0f), getMeasuredHeight() - (this.currentBlock.bottom ? AndroidUtilities.dp(6.0f) : 0), ArticleViewer.quoteLinePaint);
            }
        }
    }

    private class BlockPreformattedCell extends FrameLayout {
        private TLRPC.TL_pageBlockPreformatted currentBlock;
        private WebpageAdapter parentAdapter;
        private HorizontalScrollView scrollView;
        private View textContainer;
        private DrawingText textLayout;

        public BlockPreformattedCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.parentAdapter = adapter;
            HorizontalScrollView horizontalScrollView = new HorizontalScrollView(context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockPreformattedCell.1
                @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
                public boolean onInterceptTouchEvent(MotionEvent ev) {
                    if (BlockPreformattedCell.this.textContainer.getMeasuredWidth() > getMeasuredWidth()) {
                        ArticleViewer.this.windowView.requestDisallowInterceptTouchEvent(true);
                    }
                    return super.onInterceptTouchEvent(ev);
                }

                @Override // android.view.View
                protected void onScrollChanged(int l, int t, int oldl, int oldt) {
                    super.onScrollChanged(l, t, oldl, oldt);
                    if (ArticleViewer.this.pressedLinkOwnerLayout != null) {
                        ArticleViewer.this.pressedLinkOwnerLayout = null;
                        ArticleViewer.this.pressedLinkOwnerView = null;
                    }
                }
            };
            this.scrollView = horizontalScrollView;
            horizontalScrollView.setPadding(0, AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f));
            addView(this.scrollView, LayoutHelper.createFrame(-1, -2.0f));
            this.textContainer = new View(context) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.BlockPreformattedCell.2
                @Override // android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    int height = 0;
                    int width = 1;
                    if (BlockPreformattedCell.this.currentBlock != null) {
                        BlockPreformattedCell blockPreformattedCell = BlockPreformattedCell.this;
                        blockPreformattedCell.textLayout = ArticleViewer.this.createLayoutForText(this, null, BlockPreformattedCell.this.currentBlock.text, AndroidUtilities.dp(5000.0f), BlockPreformattedCell.this.currentBlock, BlockPreformattedCell.this.parentAdapter);
                        if (BlockPreformattedCell.this.textLayout != null) {
                            height = 0 + BlockPreformattedCell.this.textLayout.getHeight();
                            int count = BlockPreformattedCell.this.textLayout.getLineCount();
                            for (int a = 0; a < count; a++) {
                                width = Math.max((int) Math.ceil(BlockPreformattedCell.this.textLayout.getLineWidth(a)), width);
                            }
                        }
                    } else {
                        height = 1;
                    }
                    setMeasuredDimension(AndroidUtilities.dp(32.0f) + width, height);
                }

                @Override // android.view.View
                protected void onDraw(Canvas canvas) {
                    if (BlockPreformattedCell.this.textLayout != null) {
                        canvas.save();
                        BlockPreformattedCell.this.textLayout.draw(canvas);
                        canvas.restore();
                    }
                }
            };
            FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, -1);
            int iDp = AndroidUtilities.dp(16.0f);
            layoutParams.rightMargin = iDp;
            layoutParams.leftMargin = iDp;
            int iDp2 = AndroidUtilities.dp(12.0f);
            layoutParams.bottomMargin = iDp2;
            layoutParams.topMargin = iDp2;
            this.scrollView.addView(this.textContainer, layoutParams);
            setWillNotDraw(false);
        }

        public void setBlock(TLRPC.TL_pageBlockPreformatted block) {
            this.currentBlock = block;
            this.scrollView.setScrollX(0);
            this.textContainer.requestLayout();
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            this.scrollView.measure(View.MeasureSpec.makeMeasureSpec(width, 1073741824), View.MeasureSpec.makeMeasureSpec(0, 0));
            setMeasuredDimension(width, this.scrollView.getMeasuredHeight());
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock == null) {
                return;
            }
            canvas.drawRect(0.0f, AndroidUtilities.dp(8.0f), getMeasuredWidth(), getMeasuredHeight() - AndroidUtilities.dp(8.0f), ArticleViewer.preformattedBackgroundPaint);
        }
    }

    private class BlockSubheaderCell extends View {
        private TLRPC.TL_pageBlockSubheader currentBlock;
        private WebpageAdapter parentAdapter;
        private DrawingText textLayout;
        private int textX;
        private int textY;

        public BlockSubheaderCell(Context context, WebpageAdapter adapter) {
            super(context);
            this.textX = AndroidUtilities.dp(18.0f);
            this.textY = AndroidUtilities.dp(8.0f);
            this.parentAdapter = adapter;
        }

        public void setBlock(TLRPC.TL_pageBlockSubheader block) {
            this.currentBlock = block;
            requestLayout();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ArticleViewer.this.checkLayoutForLinks(event, this, this.textLayout, this.textX, this.textY) || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int width = View.MeasureSpec.getSize(widthMeasureSpec);
            int height = 0;
            TLRPC.TL_pageBlockSubheader tL_pageBlockSubheader = this.currentBlock;
            if (tL_pageBlockSubheader != null) {
                DrawingText drawingTextCreateLayoutForText = ArticleViewer.this.createLayoutForText(this, (CharSequence) null, tL_pageBlockSubheader.text, width - AndroidUtilities.dp(36.0f), this.currentBlock, ArticleViewer.this.isRtl ? StaticLayoutEx.ALIGN_RIGHT() : Layout.Alignment.ALIGN_NORMAL, this.parentAdapter);
                this.textLayout = drawingTextCreateLayoutForText;
                if (drawingTextCreateLayoutForText != null) {
                    height = 0 + AndroidUtilities.dp(16.0f) + this.textLayout.getHeight();
                }
            } else {
                height = 1;
            }
            setMeasuredDimension(width, height);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.currentBlock != null && this.textLayout != null) {
                canvas.save();
                canvas.translate(this.textX, this.textY);
                this.textLayout.draw(canvas);
                canvas.restore();
            }
        }

        @Override // android.view.View
        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setEnabled(true);
            if (this.textLayout == null) {
                return;
            }
            info.setText(((Object) this.textLayout.getText()) + ", " + LocaleController.getString("AccDescrIVHeading", R.string.AccDescrIVHeading));
        }
    }

    private class LinkMovementMethodMy extends LinkMovementMethod {
        private LinkMovementMethodMy() {
        }

        @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
        public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
            try {
                boolean result = super.onTouchEvent(widget, buffer, event);
                if (event.getAction() == 1 || event.getAction() == 3) {
                    Selection.removeSelection(buffer);
                }
                return result;
            } catch (Exception e) {
                FileLog.e(e);
                return false;
            }
        }
    }

    private class PhotoBackgroundDrawable extends ColorDrawable {
        private Runnable drawRunnable;

        public PhotoBackgroundDrawable(int color) {
            super(color);
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
            if (ArticleViewer.this.parentActivity instanceof LaunchActivity) {
                ((LaunchActivity) ArticleViewer.this.parentActivity).drawerLayoutContainer.setAllowDrawContent((ArticleViewer.this.isPhotoVisible && alpha == 255) ? false : true);
            }
            super.setAlpha(alpha);
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            Runnable runnable;
            super.draw(canvas);
            if (getAlpha() != 0 && (runnable = this.drawRunnable) != null) {
                runnable.run();
                this.drawRunnable = null;
            }
        }
    }

    private class RadialProgressView {
        private View parent;
        private long lastUpdateTime = 0;
        private float radOffset = 0.0f;
        private float currentProgress = 0.0f;
        private float animationProgressStart = 0.0f;
        private long currentProgressTime = 0;
        private float animatedProgressValue = 0.0f;
        private RectF progressRect = new RectF();
        private int backgroundState = -1;
        private int size = AndroidUtilities.dp(64.0f);
        private int previousBackgroundState = -2;
        private float animatedAlphaValue = 1.0f;
        private float alpha = 1.0f;
        private float scale = 1.0f;

        public RadialProgressView(Context context, View parentView) {
            if (ArticleViewer.decelerateInterpolator == null) {
                DecelerateInterpolator unused = ArticleViewer.decelerateInterpolator = new DecelerateInterpolator(1.5f);
                Paint unused2 = ArticleViewer.progressPaint = new Paint(1);
                ArticleViewer.progressPaint.setStyle(Paint.Style.STROKE);
                ArticleViewer.progressPaint.setStrokeCap(Paint.Cap.ROUND);
                ArticleViewer.progressPaint.setStrokeWidth(AndroidUtilities.dp(3.0f));
                ArticleViewer.progressPaint.setColor(-1);
            }
            this.parent = parentView;
        }

        private void updateAnimation() {
            long newTime = System.currentTimeMillis();
            long dt = newTime - this.lastUpdateTime;
            this.lastUpdateTime = newTime;
            if (this.animatedProgressValue != 1.0f) {
                this.radOffset += (360 * dt) / 3000.0f;
                float f = this.currentProgress;
                float f2 = this.animationProgressStart;
                float progressDiff = f - f2;
                if (progressDiff > 0.0f) {
                    long j = this.currentProgressTime + dt;
                    this.currentProgressTime = j;
                    if (j < 300) {
                        this.animatedProgressValue = f2 + (ArticleViewer.decelerateInterpolator.getInterpolation(this.currentProgressTime / 300.0f) * progressDiff);
                    } else {
                        this.animatedProgressValue = f;
                        this.animationProgressStart = f;
                        this.currentProgressTime = 0L;
                    }
                }
                this.parent.invalidate();
            }
            if (this.animatedProgressValue >= 1.0f && this.previousBackgroundState != -2) {
                float f3 = this.animatedAlphaValue - (dt / 200.0f);
                this.animatedAlphaValue = f3;
                if (f3 <= 0.0f) {
                    this.animatedAlphaValue = 0.0f;
                    this.previousBackgroundState = -2;
                }
                this.parent.invalidate();
            }
        }

        public void setProgress(float value, boolean animated) {
            if (!animated) {
                this.animatedProgressValue = value;
                this.animationProgressStart = value;
            } else {
                this.animationProgressStart = this.animatedProgressValue;
            }
            this.currentProgress = value;
            this.currentProgressTime = 0L;
        }

        public void setBackgroundState(int state, boolean animated) {
            int i;
            this.lastUpdateTime = System.currentTimeMillis();
            if (animated && (i = this.backgroundState) != state) {
                this.previousBackgroundState = i;
                this.animatedAlphaValue = 1.0f;
            } else {
                this.previousBackgroundState = -2;
            }
            this.backgroundState = state;
            this.parent.invalidate();
        }

        public void setAlpha(float value) {
            this.alpha = value;
        }

        public void setScale(float value) {
            this.scale = value;
        }

        public void onDraw(Canvas canvas) {
            int i;
            Drawable drawable;
            Drawable drawable2;
            int sizeScaled = (int) (this.size * this.scale);
            int x = (ArticleViewer.this.getContainerViewWidth() - sizeScaled) / 2;
            int y = (ArticleViewer.this.getContainerViewHeight() - sizeScaled) / 2;
            int i2 = this.previousBackgroundState;
            if (i2 >= 0 && i2 < 4 && (drawable2 = ArticleViewer.progressDrawables[this.previousBackgroundState]) != null) {
                drawable2.setAlpha((int) (this.animatedAlphaValue * 255.0f * this.alpha));
                drawable2.setBounds(x, y, x + sizeScaled, y + sizeScaled);
                drawable2.draw(canvas);
            }
            int i3 = this.backgroundState;
            if (i3 >= 0 && i3 < 4 && (drawable = ArticleViewer.progressDrawables[this.backgroundState]) != null) {
                if (this.previousBackgroundState != -2) {
                    drawable.setAlpha((int) ((1.0f - this.animatedAlphaValue) * 255.0f * this.alpha));
                } else {
                    drawable.setAlpha((int) (this.alpha * 255.0f));
                }
                drawable.setBounds(x, y, x + sizeScaled, y + sizeScaled);
                drawable.draw(canvas);
            }
            int i4 = this.backgroundState;
            if (i4 == 0 || i4 == 1 || (i = this.previousBackgroundState) == 0 || i == 1) {
                int diff = AndroidUtilities.dp(4.0f);
                if (this.previousBackgroundState != -2) {
                    ArticleViewer.progressPaint.setAlpha((int) (this.animatedAlphaValue * 255.0f * this.alpha));
                } else {
                    ArticleViewer.progressPaint.setAlpha((int) (this.alpha * 255.0f));
                }
                this.progressRect.set(x + diff, y + diff, (x + sizeScaled) - diff, (y + sizeScaled) - diff);
                canvas.drawArc(this.progressRect, (-90.0f) + this.radOffset, Math.max(4.0f, this.animatedProgressValue * 360.0f), false, ArticleViewer.progressPaint);
                updateAnimation();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSharePressed() {
        if (this.parentActivity == null || this.currentMedia == null) {
            return;
        }
        try {
            File f = getMediaFile(this.currentIndex);
            if (f != null && f.exists()) {
                Intent intent = new Intent("android.intent.action.SEND");
                intent.setType(getMediaMime(this.currentIndex));
                if (Build.VERSION.SDK_INT >= 24) {
                    try {
                        intent.putExtra("android.intent.extra.STREAM", FileProvider.getUriForFile(this.parentActivity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f));
                        intent.setFlags(1);
                    } catch (Exception e) {
                        intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
                    }
                } else {
                    intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
                }
                this.parentActivity.startActivityForResult(Intent.createChooser(intent, LocaleController.getString("ShareFile", R.string.ShareFile)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(this.parentActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            builder.setMessage(LocaleController.getString("PleaseDownload", R.string.PleaseDownload));
            showDialog(builder.create());
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    private void setScaleToFill() {
        float bitmapWidth = this.centerImage.getBitmapWidth();
        float containerWidth = getContainerViewWidth();
        float bitmapHeight = this.centerImage.getBitmapHeight();
        float containerHeight = getContainerViewHeight();
        float scaleFit = Math.min(containerHeight / bitmapHeight, containerWidth / bitmapWidth);
        float width = (int) (bitmapWidth * scaleFit);
        float height = (int) (bitmapHeight * scaleFit);
        float fMax = Math.max(containerWidth / width, containerHeight / height);
        this.scale = fMax;
        updateMinMax(fMax);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVideoPlayerTime() {
        String newText;
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer == null) {
            newText = String.format("%02d:%02d / %02d:%02d", 0, 0, 0, 0);
        } else {
            long current = videoPlayer.getCurrentPosition() / 1000;
            long total = this.videoPlayer.getDuration() / 1000;
            if (total != C.TIME_UNSET && current != C.TIME_UNSET) {
                newText = String.format("%02d:%02d / %02d:%02d", Long.valueOf(current / 60), Long.valueOf(current % 60), Long.valueOf(total / 60), Long.valueOf(total % 60));
            } else {
                newText = String.format("%02d:%02d / %02d:%02d", 0, 0, 0, 0);
            }
        }
        if (!TextUtils.equals(this.videoPlayerTime.getText(), newText)) {
            this.videoPlayerTime.setText(newText);
        }
    }

    private void preparePlayer(File file, boolean playWhenReady) {
        long duration;
        if (this.parentActivity == null) {
            return;
        }
        releasePlayer();
        if (this.videoTextureView == null) {
            AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(this.parentActivity);
            this.aspectRatioFrameLayout = aspectRatioFrameLayout;
            aspectRatioFrameLayout.setVisibility(4);
            this.photoContainerView.addView(this.aspectRatioFrameLayout, 0, LayoutHelper.createFrame(-1, -1, 17));
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
        this.videoPlayButton.setImageResource(R.drawable.inline_video_play);
        if (this.videoPlayer == null) {
            VideoPlayer videoPlayer = new VideoPlayer();
            this.videoPlayer = videoPlayer;
            videoPlayer.setTextureView(this.videoTextureView);
            this.videoPlayer.setDelegate(new VideoPlayer.VideoPlayerDelegate() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.19
                @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                public void onStateChanged(boolean playWhenReady2, int playbackState) {
                    if (ArticleViewer.this.videoPlayer == null) {
                        return;
                    }
                    if (playbackState == 4 || playbackState == 1) {
                        try {
                            ArticleViewer.this.parentActivity.getWindow().clearFlags(128);
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    } else {
                        try {
                            ArticleViewer.this.parentActivity.getWindow().addFlags(128);
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                    }
                    if (playbackState == 3 && ArticleViewer.this.aspectRatioFrameLayout.getVisibility() != 0) {
                        ArticleViewer.this.aspectRatioFrameLayout.setVisibility(0);
                    }
                    if (!ArticleViewer.this.videoPlayer.isPlaying() || playbackState == 4) {
                        if (ArticleViewer.this.isPlaying) {
                            ArticleViewer.this.isPlaying = false;
                            ArticleViewer.this.videoPlayButton.setImageResource(R.drawable.inline_video_play);
                            AndroidUtilities.cancelRunOnUIThread(ArticleViewer.this.updateProgressRunnable);
                            if (playbackState == 4 && !ArticleViewer.this.videoPlayerSeekbar.isDragging()) {
                                ArticleViewer.this.videoPlayerSeekbar.setProgress(0.0f);
                                ArticleViewer.this.videoPlayerControlFrameLayout.invalidate();
                                ArticleViewer.this.videoPlayer.seekTo(0L);
                                ArticleViewer.this.videoPlayer.pause();
                            }
                        }
                    } else if (!ArticleViewer.this.isPlaying) {
                        ArticleViewer.this.isPlaying = true;
                        ArticleViewer.this.videoPlayButton.setImageResource(R.drawable.inline_video_pause);
                        AndroidUtilities.runOnUIThread(ArticleViewer.this.updateProgressRunnable);
                    }
                    ArticleViewer.this.updateVideoPlayerTime();
                }

                @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                public void onError(Exception e) {
                    FileLog.e(e);
                }

                @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
                    if (ArticleViewer.this.aspectRatioFrameLayout != null) {
                        if (unappliedRotationDegrees == 90 || unappliedRotationDegrees == 270) {
                            width = height;
                            height = width;
                        }
                        ArticleViewer.this.aspectRatioFrameLayout.setAspectRatio(height == 0 ? 1.0f : (width * pixelWidthHeightRatio) / height, unappliedRotationDegrees);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                public void onRenderedFirstFrame() {
                    if (!ArticleViewer.this.textureUploaded) {
                        ArticleViewer.this.textureUploaded = true;
                        ArticleViewer.this.containerView.invalidate();
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
                    return false;
                }

                @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
                public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
                }
            });
            VideoPlayer videoPlayer2 = this.videoPlayer;
            if (videoPlayer2 != null) {
                duration = videoPlayer2.getDuration();
                if (duration == C.TIME_UNSET) {
                    duration = 0;
                }
            } else {
                duration = 0;
            }
            long duration2 = duration / 1000;
            Math.ceil(this.videoPlayerTime.getPaint().measureText(String.format("%02d:%02d / %02d:%02d", Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60), Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60))));
        }
        this.videoPlayer.preparePlayer(Uri.fromFile(file), "other");
        this.bottomLayout.setVisibility(0);
        this.videoPlayer.setPlayWhenReady(playWhenReady);
    }

    private void releasePlayer() {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.releasePlayer(true);
            this.videoPlayer = null;
        }
        try {
            this.parentActivity.getWindow().clearFlags(128);
        } catch (Exception e) {
            FileLog.e(e);
        }
        AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
        if (aspectRatioFrameLayout != null) {
            this.photoContainerView.removeView(aspectRatioFrameLayout);
            this.aspectRatioFrameLayout = null;
        }
        if (this.videoTextureView != null) {
            this.videoTextureView = null;
        }
        if (this.isPlaying) {
            this.isPlaying = false;
            this.videoPlayButton.setImageResource(R.drawable.inline_video_play);
            AndroidUtilities.cancelRunOnUIThread(this.updateProgressRunnable);
        }
        this.bottomLayout.setVisibility(8);
    }

    private void toggleActionBar(boolean show, boolean animated) {
        if (show) {
            this.actionBar.setVisibility(0);
            if (this.videoPlayer != null) {
                this.bottomLayout.setVisibility(0);
            }
            if (this.captionTextView.getTag() != null) {
                this.captionTextView.setVisibility(0);
            }
        }
        this.isActionBarVisible = show;
        this.actionBar.setEnabled(show);
        this.bottomLayout.setEnabled(show);
        if (animated) {
            ArrayList<Animator> arrayList = new ArrayList<>();
            ActionBar actionBar = this.actionBar;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(actionBar, (Property<ActionBar, Float>) property, fArr));
            GroupedPhotosListView groupedPhotosListView = this.groupedPhotosListView;
            Property property2 = View.ALPHA;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(groupedPhotosListView, (Property<GroupedPhotosListView, Float>) property2, fArr2));
            FrameLayout frameLayout = this.bottomLayout;
            Property property3 = View.ALPHA;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property3, fArr3));
            if (this.captionTextView.getTag() != null) {
                TextView textView = this.captionTextView;
                Property property4 = View.ALPHA;
                float[] fArr4 = new float[1];
                fArr4[0] = show ? 1.0f : 0.0f;
                arrayList.add(ObjectAnimator.ofFloat(textView, (Property<TextView, Float>) property4, fArr4));
            }
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentActionBarAnimation = animatorSet;
            animatorSet.playTogether(arrayList);
            if (!show) {
                this.currentActionBarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.20
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ArticleViewer.this.currentActionBarAnimation != null && ArticleViewer.this.currentActionBarAnimation.equals(animation)) {
                            ArticleViewer.this.actionBar.setVisibility(8);
                            if (ArticleViewer.this.videoPlayer != null) {
                                ArticleViewer.this.bottomLayout.setVisibility(8);
                            }
                            if (ArticleViewer.this.captionTextView.getTag() != null) {
                                ArticleViewer.this.captionTextView.setVisibility(8);
                            }
                            ArticleViewer.this.currentActionBarAnimation = null;
                        }
                    }
                });
            }
            this.currentActionBarAnimation.setDuration(200L);
            this.currentActionBarAnimation.start();
            return;
        }
        this.actionBar.setAlpha(show ? 1.0f : 0.0f);
        this.bottomLayout.setAlpha(show ? 1.0f : 0.0f);
        if (this.captionTextView.getTag() != null) {
            this.captionTextView.setAlpha(show ? 1.0f : 0.0f);
        }
        if (!show) {
            this.actionBar.setVisibility(8);
            if (this.videoPlayer != null) {
                this.bottomLayout.setVisibility(8);
            }
            if (this.captionTextView.getTag() != null) {
                this.captionTextView.setVisibility(8);
            }
        }
    }

    private String getFileName(int index) {
        TLObject media = getMedia(index);
        if (media instanceof TLRPC.Photo) {
            media = FileLoader.getClosestPhotoSizeWithSize(((TLRPC.Photo) media).sizes, AndroidUtilities.getPhotoSize());
        }
        return FileLoader.getAttachFileName(media);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLObject getMedia(int index) {
        if (this.imagesArr.isEmpty() || index >= this.imagesArr.size() || index < 0) {
            return null;
        }
        TLRPC.PageBlock block = this.imagesArr.get(index);
        if (block instanceof TLRPC.TL_pageBlockPhoto) {
            return getPhotoWithId(((TLRPC.TL_pageBlockPhoto) block).photo_id);
        }
        if (block instanceof TLRPC.TL_pageBlockVideo) {
            return getDocumentWithId(((TLRPC.TL_pageBlockVideo) block).video_id);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public File getMediaFile(int index) {
        TLRPC.Document document;
        TLRPC.PhotoSize sizeFull;
        if (this.imagesArr.isEmpty() || index >= this.imagesArr.size() || index < 0) {
            return null;
        }
        TLRPC.PageBlock block = this.imagesArr.get(index);
        if (block instanceof TLRPC.TL_pageBlockPhoto) {
            TLRPC.Photo photo = getPhotoWithId(((TLRPC.TL_pageBlockPhoto) block).photo_id);
            if (photo != null && (sizeFull = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize())) != null) {
                return FileLoader.getPathToAttach(sizeFull, true);
            }
        } else if ((block instanceof TLRPC.TL_pageBlockVideo) && (document = getDocumentWithId(((TLRPC.TL_pageBlockVideo) block).video_id)) != null) {
            return FileLoader.getPathToAttach(document, true);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isVideoBlock(TLRPC.PageBlock block) {
        TLRPC.Document document;
        if ((block instanceof TLRPC.TL_pageBlockVideo) && (document = getDocumentWithId(((TLRPC.TL_pageBlockVideo) block).video_id)) != null) {
            return MessageObject.isVideoDocument(document);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isMediaVideo(int index) {
        return !this.imagesArr.isEmpty() && index < this.imagesArr.size() && index >= 0 && isVideoBlock(this.imagesArr.get(index));
    }

    private String getMediaMime(int index) {
        if (index >= this.imagesArr.size() || index < 0) {
            return "image/jpeg";
        }
        TLRPC.PageBlock block = this.imagesArr.get(index);
        if (block instanceof TLRPC.TL_pageBlockVideo) {
            TLRPC.TL_pageBlockVideo pageBlockVideo = (TLRPC.TL_pageBlockVideo) block;
            TLRPC.Document document = getDocumentWithId(pageBlockVideo.video_id);
            if (document != null) {
                return document.mime_type;
            }
        }
        return "image/jpeg";
    }

    private TLRPC.PhotoSize getFileLocation(TLObject media, int[] size) {
        if (media instanceof TLRPC.Photo) {
            TLRPC.Photo photo = (TLRPC.Photo) media;
            TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
            if (sizeFull != null) {
                size[0] = sizeFull.size;
                if (size[0] == 0) {
                    size[0] = -1;
                }
                return sizeFull;
            }
            size[0] = -1;
            return null;
        }
        if (media instanceof TLRPC.Document) {
            TLRPC.Document document = (TLRPC.Document) media;
            TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
            if (thumb != null) {
                size[0] = thumb.size;
                if (size[0] == 0) {
                    size[0] = -1;
                }
                return thumb;
            }
            return null;
        }
        return null;
    }

    private void onPhotoShow(int index, PlaceProviderObject object) {
        this.currentIndex = -1;
        String[] strArr = this.currentFileNames;
        strArr[0] = null;
        strArr[1] = null;
        strArr[2] = null;
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
        }
        this.currentThumb = object != null ? object.thumb : null;
        this.menuItem.setVisibility(0);
        this.menuItem.hideSubItem(3);
        this.actionBar.setTranslationY(0.0f);
        this.captionTextView.setTag(null);
        this.captionTextView.setVisibility(8);
        for (int a = 0; a < 3; a++) {
            RadialProgressView[] radialProgressViewArr = this.radialProgressViews;
            if (radialProgressViewArr[a] != null) {
                radialProgressViewArr[a].setBackgroundState(-1, false);
            }
        }
        setImageIndex(index, true);
        if (this.currentMedia != null && isMediaVideo(this.currentIndex)) {
            onActionClick(false);
        }
    }

    private void setImages() {
        if (this.photoAnimationInProgress == 0) {
            setIndexToImage(this.centerImage, this.currentIndex);
            setIndexToImage(this.rightImage, this.currentIndex + 1);
            setIndexToImage(this.leftImage, this.currentIndex - 1);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:30:0x009e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setImageIndex(int r20, boolean r21) {
        /*
            Method dump skipped, instruction units count: 607
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.setImageIndex(int, boolean):void");
    }

    private void setCurrentCaption(CharSequence caption, boolean setAsIs) {
        CharSequence result;
        if (!TextUtils.isEmpty(caption)) {
            Theme.createChatResources(null, true);
            if (setAsIs) {
                result = caption;
            } else if (caption instanceof Spannable) {
                Spannable spannable = (Spannable) caption;
                TextPaintUrlSpan[] spans = (TextPaintUrlSpan[]) spannable.getSpans(0, caption.length(), TextPaintUrlSpan.class);
                SpannableStringBuilder builder = new SpannableStringBuilder(caption.toString());
                if (spans != null && spans.length > 0) {
                    for (int a = 0; a < spans.length; a++) {
                        builder.setSpan(new URLSpan(spans[a].getUrl()) { // from class: im.uwrkaxlmjj.ui.ArticleViewer.22
                            @Override // android.text.style.URLSpan, android.text.style.ClickableSpan
                            public void onClick(View widget) {
                                ArticleViewer.this.openWebpageUrl(getURL(), null);
                            }
                        }, spannable.getSpanStart(spans[a]), spannable.getSpanEnd(spans[a]), 33);
                    }
                }
                result = builder;
            } else {
                result = new SpannableStringBuilder(caption.toString());
            }
            CharSequence str = Emoji.replaceEmoji(result, this.captionTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            this.captionTextView.setTag(str);
            this.captionTextView.setText(str);
            this.captionTextView.setVisibility(0);
            return;
        }
        this.captionTextView.setTag(null);
        this.captionTextView.setVisibility(8);
    }

    private void checkProgress(int a, boolean animated) {
        if (this.currentFileNames[a] != null) {
            int index = this.currentIndex;
            if (a == 1) {
                index++;
            } else if (a == 2) {
                index--;
            }
            File f = getMediaFile(index);
            boolean isVideo = isMediaVideo(index);
            if (f != null && f.exists()) {
                if (isVideo) {
                    this.radialProgressViews[a].setBackgroundState(3, animated);
                } else {
                    this.radialProgressViews[a].setBackgroundState(-1, animated);
                }
            } else {
                if (!isVideo) {
                    this.radialProgressViews[a].setBackgroundState(0, animated);
                } else if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[a])) {
                    this.radialProgressViews[a].setBackgroundState(2, false);
                } else {
                    this.radialProgressViews[a].setBackgroundState(1, false);
                }
                Float progress = ImageLoader.getInstance().getFileProgress(this.currentFileNames[a]);
                if (progress == null) {
                    progress = Float.valueOf(0.0f);
                }
                this.radialProgressViews[a].setProgress(progress.floatValue(), false);
            }
            if (a == 0) {
                this.canZoom = (this.currentFileNames[0] == null || isVideo || this.radialProgressViews[0].backgroundState == 0) ? false : true;
                return;
            }
            return;
        }
        this.radialProgressViews[a].setBackgroundState(-1, animated);
    }

    private void setIndexToImage(ImageReceiver imageReceiver, int index) {
        ImageReceiver.BitmapHolder placeHolder;
        ImageReceiver.BitmapHolder placeHolder2;
        imageReceiver.setOrientation(0, false);
        int[] size = new int[1];
        TLObject media = getMedia(index);
        TLRPC.PhotoSize fileLocation = getFileLocation(media, size);
        if (fileLocation != null) {
            if (!(media instanceof TLRPC.Photo)) {
                if (isMediaVideo(index)) {
                    if (fileLocation.location instanceof TLRPC.TL_fileLocationUnavailable) {
                        imageReceiver.setImageBitmap(this.parentActivity.getResources().getDrawable(R.drawable.photoview_placeholder));
                        return;
                    }
                    if (this.currentThumb != null && imageReceiver == this.centerImage) {
                        ImageReceiver.BitmapHolder placeHolder3 = this.currentThumb;
                        placeHolder = placeHolder3;
                    } else {
                        placeHolder = null;
                    }
                    imageReceiver.setImage(null, null, ImageLocation.getForDocument(fileLocation, (TLRPC.Document) media), "b", placeHolder != null ? new BitmapDrawable(placeHolder.bitmap) : null, 0, null, this.currentPage, 1);
                    return;
                }
                AnimatedFileDrawable animatedFileDrawable = this.currentAnimation;
                if (animatedFileDrawable != null) {
                    imageReceiver.setImageBitmap(animatedFileDrawable);
                    this.currentAnimation.setSecondParentView(this.photoContainerView);
                    return;
                }
                return;
            }
            TLRPC.Photo photo = (TLRPC.Photo) media;
            if (this.currentThumb != null && imageReceiver == this.centerImage) {
                ImageReceiver.BitmapHolder placeHolder4 = this.currentThumb;
                placeHolder2 = placeHolder4;
            } else {
                placeHolder2 = null;
            }
            if (size[0] == 0) {
                size[0] = -1;
            }
            TLRPC.PhotoSize thumbLocation = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 80);
            imageReceiver.setImage(ImageLocation.getForPhoto(fileLocation, photo), null, ImageLocation.getForPhoto(thumbLocation, photo), "b", placeHolder2 != null ? new BitmapDrawable(placeHolder2.bitmap) : null, size[0], null, this.currentPage, 1);
            return;
        }
        if (size[0] != 0) {
            imageReceiver.setImageBitmap(this.parentActivity.getResources().getDrawable(R.drawable.photoview_placeholder));
        } else {
            imageReceiver.setImageBitmap((Bitmap) null);
        }
    }

    public boolean isShowingImage(TLRPC.PageBlock object) {
        return this.isPhotoVisible && !this.disableShowCheck && object != null && this.currentMedia == object;
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

    public boolean openPhoto(TLRPC.PageBlock block) {
        final PlaceProviderObject object;
        int clipHorizontal;
        Object obj;
        if (this.pageSwitchAnimation != null || this.parentActivity == null || this.isPhotoVisible || checkPhotoAnimation() || block == null || (object = getPlaceForPhoto(block)) == null) {
            return false;
        }
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileLoadProgressChanged);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.isPhotoVisible = true;
        toggleActionBar(true, false);
        this.actionBar.setAlpha(0.0f);
        this.bottomLayout.setAlpha(0.0f);
        this.captionTextView.setAlpha(0.0f);
        this.photoBackgroundDrawable.setAlpha(0);
        this.groupedPhotosListView.setAlpha(0.0f);
        this.photoContainerView.setAlpha(1.0f);
        this.disableShowCheck = true;
        this.photoAnimationInProgress = 1;
        if (block != null) {
            this.currentAnimation = object.imageReceiver.getAnimation();
        }
        int index = this.adapter[0].photoBlocks.indexOf(block);
        this.imagesArr.clear();
        if (!(block instanceof TLRPC.TL_pageBlockVideo) || isVideoBlock(block)) {
            this.imagesArr.addAll(this.adapter[0].photoBlocks);
        } else {
            this.imagesArr.add(block);
            index = 0;
        }
        onPhotoShow(index, object);
        RectF drawRegion = object.imageReceiver.getDrawRegion();
        int orientation = object.imageReceiver.getOrientation();
        int animatedOrientation = object.imageReceiver.getAnimatedOrientation();
        if (animatedOrientation != 0) {
            orientation = animatedOrientation;
        }
        this.animatingImageView.setVisibility(0);
        this.animatingImageView.setRadius(object.radius);
        this.animatingImageView.setOrientation(orientation);
        this.animatingImageView.setNeedRadius(object.radius != 0);
        this.animatingImageView.setImageBitmap(object.thumb);
        this.animatingImageView.setAlpha(1.0f);
        this.animatingImageView.setPivotX(0.0f);
        this.animatingImageView.setPivotY(0.0f);
        this.animatingImageView.setScaleX(object.scale);
        this.animatingImageView.setScaleY(object.scale);
        this.animatingImageView.setTranslationX(object.viewX + (drawRegion.left * object.scale));
        this.animatingImageView.setTranslationY(object.viewY + (drawRegion.top * object.scale));
        ViewGroup.LayoutParams layoutParams = this.animatingImageView.getLayoutParams();
        layoutParams.width = (int) drawRegion.width();
        layoutParams.height = (int) drawRegion.height();
        this.animatingImageView.setLayoutParams(layoutParams);
        float scaleX = AndroidUtilities.displaySize.x / layoutParams.width;
        float scaleY = (AndroidUtilities.displaySize.y + AndroidUtilities.statusBarHeight) / layoutParams.height;
        float scale = scaleX > scaleY ? scaleY : scaleX;
        float width = layoutParams.width * scale;
        float height = layoutParams.height * scale;
        float xPos = (AndroidUtilities.displaySize.x - width) / 2.0f;
        if (Build.VERSION.SDK_INT >= 21 && (obj = this.lastInsets) != null) {
            xPos += ((WindowInsets) obj).getSystemWindowInsetLeft();
        }
        float yPos = ((AndroidUtilities.displaySize.y + AndroidUtilities.statusBarHeight) - height) / 2.0f;
        if (object.imageReceiver.isAspectFit()) {
            clipHorizontal = 0;
        } else {
            clipHorizontal = (int) Math.abs(drawRegion.left - object.imageReceiver.getImageX());
        }
        int clipVertical = (int) Math.abs(drawRegion.top - object.imageReceiver.getImageY());
        int[] coords2 = new int[2];
        object.parentView.getLocationInWindow(coords2);
        int clipTop = (int) ((coords2[1] - (object.viewY + drawRegion.top)) + object.clipTopAddition);
        if (clipTop < 0) {
            clipTop = 0;
        }
        int clipBottom = (int) ((((object.viewY + drawRegion.top) + layoutParams.height) - (coords2[1] + object.parentView.getHeight())) + object.clipBottomAddition);
        if (clipBottom < 0) {
            clipBottom = 0;
        }
        int clipTop2 = Math.max(clipTop, clipVertical);
        int clipBottom2 = Math.max(clipBottom, clipVertical);
        this.animationValues[0][0] = this.animatingImageView.getScaleX();
        this.animationValues[0][1] = this.animatingImageView.getScaleY();
        this.animationValues[0][2] = this.animatingImageView.getTranslationX();
        this.animationValues[0][3] = this.animatingImageView.getTranslationY();
        this.animationValues[0][4] = clipHorizontal * object.scale;
        this.animationValues[0][5] = clipTop2 * object.scale;
        this.animationValues[0][6] = clipBottom2 * object.scale;
        this.animationValues[0][7] = this.animatingImageView.getRadius();
        this.animationValues[0][8] = clipVertical * object.scale;
        this.animationValues[0][9] = clipHorizontal * object.scale;
        float[][] fArr = this.animationValues;
        fArr[1][0] = scale;
        fArr[1][1] = scale;
        fArr[1][2] = xPos;
        fArr[1][3] = yPos;
        fArr[1][4] = 0.0f;
        fArr[1][5] = 0.0f;
        fArr[1][6] = 0.0f;
        fArr[1][7] = 0.0f;
        fArr[1][8] = 0.0f;
        fArr[1][9] = 0.0f;
        this.photoContainerView.setVisibility(0);
        this.photoContainerBackground.setVisibility(0);
        this.animatingImageView.setAnimationProgress(0.0f);
        final AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.animatingImageView, "animationProgress", 0.0f, 1.0f), ObjectAnimator.ofInt(this.photoBackgroundDrawable, (Property<PhotoBackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0, 255), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.groupedPhotosListView, (Property<GroupedPhotosListView, Float>) View.ALPHA, 0.0f, 1.0f));
        this.photoAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$W1EhtY3N3TYeLNC0xPk4v9zR8Cw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$openPhoto$37$ArticleViewer();
            }
        };
        animatorSet.setDuration(200L);
        animatorSet.addListener(new AnonymousClass23());
        this.photoTransitionAnimationStartTime = System.currentTimeMillis();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$J4hXGAk21xYnLb7Vs86obg9Vuus
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$openPhoto$38$ArticleViewer(animatorSet);
            }
        });
        if (Build.VERSION.SDK_INT >= 18) {
            this.photoContainerView.setLayerType(2, null);
        }
        this.photoBackgroundDrawable.drawRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$nf7r16wZr3ozg_s63hU0BnpEDIU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$openPhoto$39$ArticleViewer(object);
            }
        };
        return true;
    }

    public /* synthetic */ void lambda$openPhoto$37$ArticleViewer() {
        if (this.photoContainerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.photoContainerView.setLayerType(0, null);
        }
        this.photoAnimationInProgress = 0;
        this.photoTransitionAnimationStartTime = 0L;
        setImages();
        this.photoContainerView.invalidate();
        this.animatingImageView.setVisibility(8);
        PlaceProviderObject placeProviderObject = this.showAfterAnimation;
        if (placeProviderObject != null) {
            placeProviderObject.imageReceiver.setVisible(true, true);
        }
        PlaceProviderObject placeProviderObject2 = this.hideAfterAnimation;
        if (placeProviderObject2 != null) {
            placeProviderObject2.imageReceiver.setVisible(false, true);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ArticleViewer$23, reason: invalid class name */
    class AnonymousClass23 extends AnimatorListenerAdapter {
        AnonymousClass23() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$23$Q3sQ_b_9lY76vKLGc8x_jrgO4a4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ArticleViewer$23();
                }
            });
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ArticleViewer$23() {
            NotificationCenter.getInstance(ArticleViewer.this.currentAccount).setAnimationInProgress(false);
            if (ArticleViewer.this.photoAnimationEndRunnable != null) {
                ArticleViewer.this.photoAnimationEndRunnable.run();
                ArticleViewer.this.photoAnimationEndRunnable = null;
            }
        }
    }

    public /* synthetic */ void lambda$openPhoto$38$ArticleViewer(AnimatorSet animatorSet) {
        NotificationCenter.getInstance(this.currentAccount).setAllowedNotificationsDutingAnimation(new int[]{NotificationCenter.dialogsNeedReload, NotificationCenter.closeChats});
        NotificationCenter.getInstance(this.currentAccount).setAnimationInProgress(true);
        animatorSet.start();
    }

    public /* synthetic */ void lambda$openPhoto$39$ArticleViewer(PlaceProviderObject object) {
        this.disableShowCheck = false;
        object.imageReceiver.setVisible(false, true);
    }

    public void closePhoto(boolean animated) {
        int clipHorizontal;
        Object obj;
        if (this.parentActivity == null || !this.isPhotoVisible || checkPhotoAnimation()) {
            return;
        }
        releasePlayer();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileLoadProgressChanged);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.needSetDayNightTheme);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        this.isActionBarVisible = false;
        VelocityTracker velocityTracker = this.velocityTracker;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.velocityTracker = null;
        }
        final PlaceProviderObject object = getPlaceForPhoto(this.currentMedia);
        if (animated) {
            this.photoAnimationInProgress = 1;
            this.animatingImageView.setVisibility(0);
            this.photoContainerView.invalidate();
            AnimatorSet animatorSet = new AnimatorSet();
            ViewGroup.LayoutParams layoutParams = this.animatingImageView.getLayoutParams();
            RectF drawRegion = null;
            int orientation = this.centerImage.getOrientation();
            int animatedOrientation = 0;
            if (object != null && object.imageReceiver != null) {
                animatedOrientation = object.imageReceiver.getAnimatedOrientation();
            }
            if (animatedOrientation != 0) {
                orientation = animatedOrientation;
            }
            this.animatingImageView.setOrientation(orientation);
            if (object == null) {
                this.animatingImageView.setNeedRadius(false);
                layoutParams.width = this.centerImage.getImageWidth();
                layoutParams.height = this.centerImage.getImageHeight();
                this.animatingImageView.setImageBitmap(this.centerImage.getBitmapSafe());
            } else {
                this.animatingImageView.setNeedRadius(object.radius != 0);
                drawRegion = object.imageReceiver.getDrawRegion();
                layoutParams.width = (int) drawRegion.width();
                layoutParams.height = (int) drawRegion.height();
                this.animatingImageView.setImageBitmap(object.thumb);
            }
            this.animatingImageView.setLayoutParams(layoutParams);
            float scaleX = AndroidUtilities.displaySize.x / layoutParams.width;
            float scaleY = (AndroidUtilities.displaySize.y + AndroidUtilities.statusBarHeight) / layoutParams.height;
            float scale2 = scaleX > scaleY ? scaleY : scaleX;
            float width = layoutParams.width * this.scale * scale2;
            float height = layoutParams.height * this.scale * scale2;
            float xPos = (AndroidUtilities.displaySize.x - width) / 2.0f;
            if (Build.VERSION.SDK_INT >= 21 && (obj = this.lastInsets) != null) {
                xPos += ((WindowInsets) obj).getSystemWindowInsetLeft();
            }
            float yPos = ((AndroidUtilities.displaySize.y + AndroidUtilities.statusBarHeight) - height) / 2.0f;
            this.animatingImageView.setTranslationX(this.translationX + xPos);
            this.animatingImageView.setTranslationY(this.translationY + yPos);
            this.animatingImageView.setScaleX(this.scale * scale2);
            this.animatingImageView.setScaleY(this.scale * scale2);
            if (object != null) {
                object.imageReceiver.setVisible(false, true);
                if (object.imageReceiver.isAspectFit()) {
                    clipHorizontal = 0;
                } else {
                    clipHorizontal = (int) Math.abs(drawRegion.left - object.imageReceiver.getImageX());
                }
                int clipVertical = (int) Math.abs(drawRegion.top - object.imageReceiver.getImageY());
                int[] coords2 = new int[2];
                object.parentView.getLocationInWindow(coords2);
                int clipTop = (int) ((coords2[1] - (object.viewY + drawRegion.top)) + object.clipTopAddition);
                if (clipTop < 0) {
                    clipTop = 0;
                }
                int clipBottom = (int) ((((object.viewY + drawRegion.top) + (drawRegion.bottom - drawRegion.top)) - (coords2[1] + object.parentView.getHeight())) + object.clipBottomAddition);
                if (clipBottom < 0) {
                    clipBottom = 0;
                }
                int clipTop2 = Math.max(clipTop, clipVertical);
                int clipBottom2 = Math.max(clipBottom, clipVertical);
                this.animationValues[0][0] = this.animatingImageView.getScaleX();
                this.animationValues[0][1] = this.animatingImageView.getScaleY();
                this.animationValues[0][2] = this.animatingImageView.getTranslationX();
                this.animationValues[0][3] = this.animatingImageView.getTranslationY();
                float[][] fArr = this.animationValues;
                fArr[0][4] = 0.0f;
                fArr[0][5] = 0.0f;
                fArr[0][6] = 0.0f;
                fArr[0][7] = 0.0f;
                fArr[0][8] = 0.0f;
                fArr[0][9] = 0.0f;
                fArr[1][0] = object.scale;
                this.animationValues[1][1] = object.scale;
                this.animationValues[1][2] = object.viewX + (drawRegion.left * object.scale);
                this.animationValues[1][3] = object.viewY + (drawRegion.top * object.scale);
                this.animationValues[1][4] = clipHorizontal * object.scale;
                this.animationValues[1][5] = clipTop2 * object.scale;
                this.animationValues[1][6] = clipBottom2 * object.scale;
                this.animationValues[1][7] = object.radius;
                this.animationValues[1][8] = clipVertical * object.scale;
                this.animationValues[1][9] = clipHorizontal * object.scale;
                animatorSet.playTogether(ObjectAnimator.ofFloat(this.animatingImageView, "animationProgress", 0.0f, 1.0f), ObjectAnimator.ofInt(this.photoBackgroundDrawable, (Property<PhotoBackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.groupedPhotosListView, (Property<GroupedPhotosListView, Float>) View.ALPHA, 0.0f));
            } else {
                int h = AndroidUtilities.displaySize.y + AndroidUtilities.statusBarHeight;
                Animator[] animatorArr = new Animator[7];
                animatorArr[0] = ObjectAnimator.ofInt(this.photoBackgroundDrawable, (Property<PhotoBackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0);
                animatorArr[1] = ObjectAnimator.ofFloat(this.animatingImageView, (Property<ClippingImageView, Float>) View.ALPHA, 0.0f);
                ClippingImageView clippingImageView = this.animatingImageView;
                Property property = View.TRANSLATION_Y;
                float[] fArr2 = new float[1];
                fArr2[0] = this.translationY >= 0.0f ? h : -h;
                animatorArr[2] = ObjectAnimator.ofFloat(clippingImageView, (Property<ClippingImageView, Float>) property, fArr2);
                animatorArr[3] = ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 0.0f);
                animatorArr[4] = ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.ALPHA, 0.0f);
                animatorArr[5] = ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.ALPHA, 0.0f);
                animatorArr[6] = ObjectAnimator.ofFloat(this.groupedPhotosListView, (Property<GroupedPhotosListView, Float>) View.ALPHA, 0.0f);
                animatorSet.playTogether(animatorArr);
            }
            this.photoAnimationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$L57A_Is2WP_Pae0baH7_Bx2amqQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$closePhoto$40$ArticleViewer(object);
                }
            };
            animatorSet.setDuration(200L);
            animatorSet.addListener(new AnonymousClass24());
            this.photoTransitionAnimationStartTime = System.currentTimeMillis();
            if (Build.VERSION.SDK_INT >= 18) {
                this.photoContainerView.setLayerType(2, null);
            }
            animatorSet.start();
        } else {
            this.photoContainerView.setVisibility(4);
            this.photoContainerBackground.setVisibility(4);
            this.photoAnimationInProgress = 0;
            onPhotoClosed(object);
            this.photoContainerView.setScaleX(1.0f);
            this.photoContainerView.setScaleY(1.0f);
        }
        AnimatedFileDrawable animatedFileDrawable = this.currentAnimation;
        if (animatedFileDrawable != null) {
            animatedFileDrawable.setSecondParentView(null);
            this.currentAnimation = null;
            this.centerImage.setImageBitmap((Drawable) null);
        }
    }

    public /* synthetic */ void lambda$closePhoto$40$ArticleViewer(PlaceProviderObject object) {
        if (Build.VERSION.SDK_INT >= 18) {
            this.photoContainerView.setLayerType(0, null);
        }
        this.photoContainerView.setVisibility(4);
        this.photoContainerBackground.setVisibility(4);
        this.photoAnimationInProgress = 0;
        onPhotoClosed(object);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ArticleViewer$24, reason: invalid class name */
    class AnonymousClass24 extends AnimatorListenerAdapter {
        AnonymousClass24() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$24$Nh_9jDyeINqndcGI3xgHU1I3irc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ArticleViewer$24();
                }
            });
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ArticleViewer$24() {
            if (ArticleViewer.this.photoAnimationEndRunnable != null) {
                ArticleViewer.this.photoAnimationEndRunnable.run();
                ArticleViewer.this.photoAnimationEndRunnable = null;
            }
        }
    }

    private void onPhotoClosed(PlaceProviderObject object) {
        this.isPhotoVisible = false;
        this.disableShowCheck = true;
        this.currentMedia = null;
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        AnimatedFileDrawable animatedFileDrawable = this.currentAnimation;
        if (animatedFileDrawable != null) {
            animatedFileDrawable.setSecondParentView(null);
            this.currentAnimation = null;
        }
        for (int a = 0; a < 3; a++) {
            RadialProgressView[] radialProgressViewArr = this.radialProgressViews;
            if (radialProgressViewArr[a] != null) {
                radialProgressViewArr[a].setBackgroundState(-1, false);
            }
        }
        Bitmap bitmap = (Bitmap) null;
        this.centerImage.setImageBitmap(bitmap);
        this.leftImage.setImageBitmap(bitmap);
        this.rightImage.setImageBitmap(bitmap);
        this.photoContainerView.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ArticleViewer$Ex3Rrh3KTRHqAJ-QeC1drwomO9Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onPhotoClosed$41$ArticleViewer();
            }
        });
        this.disableShowCheck = false;
        if (object != null) {
            object.imageReceiver.setVisible(true, true);
        }
        this.groupedPhotosListView.clear();
    }

    public /* synthetic */ void lambda$onPhotoClosed$41$ArticleViewer() {
        this.animatingImageView.setImageBitmap(null);
    }

    public void onPause() {
        if (this.currentAnimation != null) {
            closePhoto(false);
        }
    }

    private void updateMinMax(float scale) {
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

    /* JADX INFO: Access modifiers changed from: private */
    public int getContainerViewWidth() {
        return this.photoContainerView.getWidth();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getContainerViewHeight() {
        return this.photoContainerView.getHeight();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01e1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean processTouchEvent(android.view.MotionEvent r13) {
        /*
            Method dump skipped, instruction units count: 1020
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.processTouchEvent(android.view.MotionEvent):boolean");
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

    private void goToNext() {
        float extra = 0.0f;
        if (this.scale != 1.0f) {
            extra = ((getContainerViewWidth() - this.centerImage.getImageWidth()) / 2) * this.scale;
        }
        this.switchImageAfterAnimation = 1;
        animateTo(this.scale, ((this.minX - getContainerViewWidth()) - extra) - (AndroidUtilities.dp(30.0f) / 2), this.translationY, false);
    }

    private void goToPrev() {
        float extra = 0.0f;
        if (this.scale != 1.0f) {
            extra = ((getContainerViewWidth() - this.centerImage.getImageWidth()) / 2) * this.scale;
        }
        this.switchImageAfterAnimation = 2;
        animateTo(this.scale, this.maxX + getContainerViewWidth() + extra + (AndroidUtilities.dp(30.0f) / 2), this.translationY, false);
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
        this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ArticleViewer.25
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ArticleViewer.this.imageMoveAnimation = null;
                ArticleViewer.this.photoContainerView.invalidate();
            }
        });
        this.imageMoveAnimation.start();
    }

    public void setAnimationValue(float value) {
        this.animationValue = value;
        this.photoContainerView.invalidate();
    }

    public float getAnimationValue() {
        return this.animationValue;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01a8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void drawContent(android.graphics.Canvas r30) {
        /*
            Method dump skipped, instruction units count: 1208
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ArticleViewer.drawContent(android.graphics.Canvas):void");
    }

    public /* synthetic */ void lambda$drawContent$42$ArticleViewer() {
        setImageIndex(this.currentIndex + 1, false);
    }

    public /* synthetic */ void lambda$drawContent$43$ArticleViewer() {
        setImageIndex(this.currentIndex - 1, false);
    }

    private void onActionClick(boolean download) {
        TLObject media = getMedia(this.currentIndex);
        if (!(media instanceof TLRPC.Document) || this.currentFileNames[0] == null) {
            return;
        }
        TLRPC.Document document = (TLRPC.Document) media;
        File file = null;
        if (this.currentMedia != null && (file = getMediaFile(this.currentIndex)) != null && !file.exists()) {
            file = null;
        }
        if (file == null) {
            if (download) {
                if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[0])) {
                    FileLoader.getInstance(this.currentAccount).loadFile(document, this.currentPage, 1, 1);
                    return;
                } else {
                    FileLoader.getInstance(this.currentAccount).cancelLoadFile(document);
                    return;
                }
            }
            return;
        }
        preparePlayer(file, true);
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
            this.photoContainerView.postInvalidate();
            return false;
        }
        return false;
    }

    @Override // android.view.GestureDetector.OnDoubleTapListener
    public boolean onSingleTapConfirmed(MotionEvent e) {
        int state;
        if (this.discardTap) {
            return false;
        }
        AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
        boolean drawTextureView = aspectRatioFrameLayout != null && aspectRatioFrameLayout.getVisibility() == 0;
        RadialProgressView[] radialProgressViewArr = this.radialProgressViews;
        if (radialProgressViewArr[0] != null && this.photoContainerView != null && !drawTextureView && (state = radialProgressViewArr[0].backgroundState) > 0 && state <= 3) {
            float x = e.getX();
            float y = e.getY();
            if (x >= (getContainerViewWidth() - AndroidUtilities.dp(100.0f)) / 2.0f && x <= (getContainerViewWidth() + AndroidUtilities.dp(100.0f)) / 2.0f && y >= (getContainerViewHeight() - AndroidUtilities.dp(100.0f)) / 2.0f && y <= (getContainerViewHeight() + AndroidUtilities.dp(100.0f)) / 2.0f) {
                onActionClick(true);
                checkProgress(0, true);
                return true;
            }
        }
        toggleActionBar(!this.isActionBarVisible, true);
        return true;
    }

    @Override // android.view.GestureDetector.OnDoubleTapListener
    public boolean onDoubleTap(MotionEvent e) {
        if (!this.canZoom || ((this.scale == 1.0f && (this.translationY != 0.0f || this.translationX != 0.0f)) || this.animationStartTime != 0 || this.photoAnimationInProgress != 0)) {
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

    private ImageReceiver getImageReceiverView(View view, TLRPC.PageBlock pageBlock, int[] coords) {
        ImageReceiver imageReceiver;
        ImageReceiver imageReceiver2;
        if (view instanceof BlockPhotoCell) {
            BlockPhotoCell cell = (BlockPhotoCell) view;
            if (cell.currentBlock == pageBlock) {
                view.getLocationInWindow(coords);
                return cell.imageView;
            }
            return null;
        }
        if (view instanceof BlockVideoCell) {
            BlockVideoCell cell2 = (BlockVideoCell) view;
            if (cell2.currentBlock == pageBlock) {
                view.getLocationInWindow(coords);
                return cell2.imageView;
            }
            return null;
        }
        if (view instanceof BlockCollageCell) {
            ImageReceiver imageReceiver3 = getImageReceiverFromListView(((BlockCollageCell) view).innerListView, pageBlock, coords);
            if (imageReceiver3 != null) {
                return imageReceiver3;
            }
            return null;
        }
        if (view instanceof BlockSlideshowCell) {
            ImageReceiver imageReceiver4 = getImageReceiverFromListView(((BlockSlideshowCell) view).innerListView, pageBlock, coords);
            if (imageReceiver4 != null) {
                return imageReceiver4;
            }
            return null;
        }
        if (view instanceof BlockListItemCell) {
            BlockListItemCell blockListItemCell = (BlockListItemCell) view;
            if (blockListItemCell.blockLayout != null && (imageReceiver2 = getImageReceiverView(blockListItemCell.blockLayout.itemView, pageBlock, coords)) != null) {
                return imageReceiver2;
            }
            return null;
        }
        if (view instanceof BlockOrderedListItemCell) {
            BlockOrderedListItemCell blockOrderedListItemCell = (BlockOrderedListItemCell) view;
            if (blockOrderedListItemCell.blockLayout != null && (imageReceiver = getImageReceiverView(blockOrderedListItemCell.blockLayout.itemView, pageBlock, coords)) != null) {
                return imageReceiver;
            }
            return null;
        }
        return null;
    }

    private ImageReceiver getImageReceiverFromListView(ViewGroup listView, TLRPC.PageBlock pageBlock, int[] coords) {
        int count = listView.getChildCount();
        for (int a = 0; a < count; a++) {
            ImageReceiver imageReceiver = getImageReceiverView(listView.getChildAt(a), pageBlock, coords);
            if (imageReceiver != null) {
                return imageReceiver;
            }
        }
        return null;
    }

    private PlaceProviderObject getPlaceForPhoto(TLRPC.PageBlock pageBlock) {
        ImageReceiver imageReceiver = getImageReceiverFromListView(this.listView[0], pageBlock, this.coords);
        if (imageReceiver == null) {
            return null;
        }
        PlaceProviderObject object = new PlaceProviderObject();
        object.viewX = this.coords[0];
        object.viewY = this.coords[1];
        object.parentView = this.listView[0];
        object.imageReceiver = imageReceiver;
        object.thumb = imageReceiver.getBitmapSafe();
        object.radius = imageReceiver.getRoundRadius();
        object.clipTopAddition = this.currentHeaderHeight;
        return object;
    }
}
