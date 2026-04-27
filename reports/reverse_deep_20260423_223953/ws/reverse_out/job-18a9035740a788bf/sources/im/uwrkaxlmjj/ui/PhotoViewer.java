package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.SurfaceTexture;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.media.MediaCodecInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.Layout;
import android.text.Selection;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.style.ForegroundColorSpan;
import android.util.Property;
import android.util.SparseArray;
import android.view.ActionMode;
import android.view.ContextThemeWrapper;
import android.view.GestureDetector;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Scroller;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import androidx.core.internal.view.SupportMenu;
import androidx.core.view.InputDeviceCompat;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSmoothScrollerEnd;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.ui.AspectRatioFrameLayout;
import com.google.android.exoplayer2.util.MimeTypes;
import com.king.zxing.util.LogUtils;
import com.socks.library.KLog;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.Bitmaps;
import im.uwrkaxlmjj.messenger.BringAppForegroundService;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SecureDocument;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.messenger.WebFile;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.MentionsAdapter;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.PhotoPickerPhotoCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AnimatedFileDrawable;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ChatAttachAlert;
import im.uwrkaxlmjj.ui.components.CheckBox;
import im.uwrkaxlmjj.ui.components.ClippingImageView;
import im.uwrkaxlmjj.ui.components.GroupedPhotosListView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberPicker;
import im.uwrkaxlmjj.ui.components.OtherDocumentPlaceholderDrawable;
import im.uwrkaxlmjj.ui.components.PhotoCropView;
import im.uwrkaxlmjj.ui.components.PhotoFilterView;
import im.uwrkaxlmjj.ui.components.PhotoPaintView;
import im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView;
import im.uwrkaxlmjj.ui.components.PickerBottomLayoutViewer;
import im.uwrkaxlmjj.ui.components.PipVideoView;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SeekBar;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayoutPhoto;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import im.uwrkaxlmjj.ui.components.URLSpanUserMention;
import im.uwrkaxlmjj.ui.components.VideoForwardDrawable;
import im.uwrkaxlmjj.ui.components.VideoPlayer;
import im.uwrkaxlmjj.ui.components.VideoSeekPreviewImage;
import im.uwrkaxlmjj.ui.components.VideoTimelinePlayView;
import im.uwrkaxlmjj.ui.components.paint.views.ColorPicker;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Array;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoViewer implements NotificationCenter.NotificationCenterDelegate, GestureDetector.OnGestureListener, GestureDetector.OnDoubleTapListener {
    private static volatile PhotoViewer Instance = null;
    private static volatile PhotoViewer PipInstance = null;
    public static final int SELECT_TYPE_AVATAR = 1;
    public static final int SELECT_TYPE_WALLPAPER = 3;
    private static DecelerateInterpolator decelerateInterpolator = null;
    private static final int gallery_menu_cancel_loading = 7;
    private static final int gallery_menu_delete = 6;
    private static final int gallery_menu_masks = 13;
    private static final int gallery_menu_openin = 11;
    private static final int gallery_menu_pip = 5;
    private static final int gallery_menu_save = 1;
    private static final int gallery_menu_send = 3;
    private static final int gallery_menu_share = 10;
    private static final int gallery_menu_showall = 2;
    private static final int gallery_menu_showinchat = 4;
    private static Drawable[] progressDrawables;
    private static Paint progressPaint;
    private ActionBar actionBar;
    private AnimatorSet actionBarAnimator;
    private Context actvityContext;
    private ActionBarMenuSubItem allMediaItem;
    private boolean allowMentions;
    private boolean allowShare;
    private float animateToScale;
    private float animateToX;
    private float animateToY;
    private ClippingImageView animatingImageView;
    private Runnable animationEndRunnable;
    private int animationInProgress;
    private long animationStartTime;
    private float animationValue;
    private boolean applying;
    private AspectRatioFrameLayout aspectRatioFrameLayout;
    private boolean attachedToWindow;
    private long audioFramesSize;
    private int avatarsDialogId;
    private int bitrate;
    private FrameLayout bottomLayout;
    private ImageView cameraItem;
    private PhotoViewerCaptionEnterView captionEditText;
    private TextView captionTextView;
    private AnimatorSet changeModeAnimation;
    private TextureView changedTextureView;
    private boolean changingPage;
    private boolean changingTextureView;
    private CheckBox checkImageView;
    private int classGuid;
    private ImageView compressItem;
    private AnimatorSet compressItemAnimation;
    private FrameLayoutDrawer containerView;
    private ImageView cropItem;
    private int currentAccount;
    private AnimatedFileDrawable currentAnimation;
    private Bitmap currentBitmap;
    private TLRPC.BotInlineResult currentBotInlineResult;
    private AnimatorSet currentCaptionAnimation;
    private long currentDialogId;
    private int currentEditMode;
    private ImageLocation currentFileLocation;
    private int currentIndex;
    private AnimatorSet currentListViewAnimation;
    private Runnable currentLoadingVideoRunnable;
    private MessageObject currentMessageObject;
    private String currentPathObject;
    private PlaceProviderObject currentPlaceObject;
    private Uri currentPlayingVideoFile;
    private SecureDocument currentSecureDocument;
    private String currentSubtitle;
    private ImageReceiver.BitmapHolder currentThumb;
    private boolean currentVideoFinishedLoading;
    private int dateOverride;
    private TextView dateTextView;
    private boolean disableShowCheck;
    private boolean discardTap;
    private boolean doneButtonPressed;
    private boolean dontResetZoomOnFirstLayout;
    private boolean doubleTap;
    private boolean doubleTapEnabled;
    private float dragY;
    private boolean draggingDown;
    private PickerBottomLayoutViewer editorDoneLayout;
    private long endTime;
    private long estimatedDuration;
    private int estimatedSize;
    private boolean firstAnimationDelay;
    boolean fromCamera;
    private GestureDetector gestureDetector;
    private GroupedPhotosListView groupedPhotosListView;
    private PlaceProviderObject hideAfterAnimation;
    private boolean ignoreDidSetImage;
    private AnimatorSet imageMoveAnimation;
    private boolean inPreview;
    private VideoPlayer injectingVideoPlayer;
    private SurfaceTexture injectingVideoPlayerSurface;
    private boolean invalidCoords;
    private boolean isCurrentVideo;
    private boolean isEvent;
    boolean isFcCrop;
    private boolean isFirstLoading;
    private boolean isInline;
    private boolean isPhotosListViewVisible;
    private boolean isPlaying;
    private boolean isSingleLine;
    private boolean isStreaming;
    private boolean isVisible;
    private boolean keepScreenOnFlagSet;
    private long lastBufferedPositionCheck;
    private Object lastInsets;
    private long lastSaveTime;
    private String lastTitle;
    private boolean loadInitialVideo;
    private boolean loadingMoreImages;
    private ActionBarMenuItem masksItem;
    private float maxX;
    private float maxY;
    private LinearLayoutManager mentionLayoutManager;
    private AnimatorSet mentionListAnimation;
    private RecyclerListView mentionListView;
    private MentionsAdapter mentionsAdapter;
    private ActionBarMenuItem menuItem;
    private long mergeDialogId;
    private float minX;
    private float minY;
    private AnimatorSet miniProgressAnimator;
    private RadialProgressView miniProgressView;
    private float moveStartX;
    private float moveStartY;
    private boolean moving;
    private ImageView muteItem;
    private boolean muteVideo;
    private String nameOverride;
    private TextView nameTextView;
    private boolean needCaptionLayout;
    private boolean needSearchImageInArr;
    private boolean needShowOnReady;
    private boolean openedFullScreenVideo;
    private boolean opennedFromMedia;
    private int originalBitrate;
    private int originalHeight;
    private long originalSize;
    private int originalWidth;
    private boolean padImageForHorizontalInsets;
    private ImageView paintItem;
    private Activity parentActivity;
    private ChatAttachAlert parentAlert;
    private ChatActivity parentChatActivity;
    private PhotoCropView photoCropView;
    private PhotoFilterView photoFilterView;
    private PhotoPaintView photoPaintView;
    private CounterView photosCounterView;
    private FrameLayout pickerView;
    private ImageView pickerViewSendButton;
    private float pinchCenterX;
    private float pinchCenterY;
    private float pinchStartDistance;
    private float pinchStartX;
    private float pinchStartY;
    private boolean pipAnimationInProgress;
    private boolean pipAvailable;
    private ActionBarMenuItem pipItem;
    private PipVideoView pipVideoView;
    private PhotoViewerProvider placeProvider;
    private View playButtonAccessibilityOverlay;
    private boolean playerInjected;
    private boolean playerWasReady;
    private int previewViewEnd;
    private int previousCompression;
    private RadialProgressView progressView;
    private QualityChooseView qualityChooseView;
    private AnimatorSet qualityChooseViewAnimation;
    private PickerBottomLayoutViewer qualityPicker;
    private boolean requestingPreview;
    private TextView resetButton;
    private int resultHeight;
    private int resultWidth;
    private ImageView rotateItem;
    private int rotationValue;
    private Scroller scroller;
    private float seekToProgressPending;
    private float seekToProgressPending2;
    private int selectedCompression;
    private ListAdapter selectedPhotosAdapter;
    private RecyclerListView selectedPhotosListView;
    private ActionBarMenuItem sendItem;
    private int sendPhotoType;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout sendPopupLayout;
    private ActionBarPopupWindow sendPopupWindow;
    private ImageView shareButton;
    private int sharedMediaType;
    private String shouldSavePositionForCurrentVideo;
    private PlaceProviderObject showAfterAnimation;
    private ImageReceiver sideImage;
    private boolean skipFirstBufferingProgress;
    private int slideshowMessageId;
    private long startTime;
    private long startedPlayTime;
    private boolean streamingAlertShown;
    private TextView switchCaptionTextView;
    private int switchImageAfterAnimation;
    private boolean switchingInlineMode;
    private int switchingToIndex;
    private ImageView textureImageView;
    private boolean textureUploaded;
    private ImageView timeItem;
    private int totalImagesCount;
    private int totalImagesCountMerge;
    private long transitionAnimationStartTime;
    private float translationX;
    private float translationY;
    private boolean tryStartRequestPreviewOnFinish;
    private ImageView tuneItem;
    private VelocityTracker velocityTracker;
    private ImageView videoBackwardButton;
    private float videoCrossfadeAlpha;
    private long videoCrossfadeAlphaLastTime;
    private boolean videoCrossfadeStarted;
    private float videoCutEnd;
    private float videoCutStart;
    private float videoDuration;
    private ImageView videoForwardButton;
    private VideoForwardDrawable videoForwardDrawable;
    private int videoFramerate;
    private long videoFramesSize;
    private boolean videoHasAudio;
    private ImageView videoPlayButton;
    private VideoPlayer videoPlayer;
    private FrameLayout videoPlayerControlFrameLayout;
    private SeekBar videoPlayerSeekbar;
    private SimpleTextView videoPlayerTime;
    private VideoSeekPreviewImage videoPreviewFrame;
    private AnimatorSet videoPreviewFrameAnimation;
    private MessageObject videoPreviewMessageObject;
    private TextureView videoTextureView;
    private VideoTimelinePlayView videoTimelineView;
    private AlertDialog visibleDialog;
    private int waitingForDraw;
    private int waitingForFirstTextureUpload;
    private boolean wasLayout;
    private WindowManager.LayoutParams windowLayoutParams;
    private FrameLayout windowView;
    private boolean zoomAnimation;
    private boolean zooming;
    private int maxSelectedPhotos = -1;
    private boolean allowOrder = true;
    private Runnable miniProgressShowRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$7wchKNsdRQoF-EslZLM19HbqFks
        @Override // java.lang.Runnable
        public final void run() {
            this.f$0.lambda$new$0$PhotoViewer();
        }
    };
    private boolean isActionBarVisible = true;
    private BackgroundDrawable backgroundDrawable = new BackgroundDrawable(-16777216);
    private Paint blackPaint = new Paint();
    private PhotoProgressView[] photoProgressViews = new PhotoProgressView[3];
    private Runnable setLoadingRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.1
        @Override // java.lang.Runnable
        public void run() {
            if (PhotoViewer.this.currentMessageObject != null) {
                FileLoader.getInstance(PhotoViewer.this.currentMessageObject.currentAccount).setLoadingVideo(PhotoViewer.this.currentMessageObject.getDocument(), true, false);
            }
        }
    };
    private int[] pipPosition = new int[2];
    private boolean mShowNeedAddMorePicButton = true;
    private Runnable updateProgressRunnable = new AnonymousClass2();
    private Runnable switchToInlineRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.3
        @Override // java.lang.Runnable
        public void run() {
            PhotoViewer.this.switchingInlineMode = false;
            if (PhotoViewer.this.currentBitmap != null) {
                PhotoViewer.this.currentBitmap.recycle();
                PhotoViewer.this.currentBitmap = null;
            }
            PhotoViewer.this.changingTextureView = true;
            if (PhotoViewer.this.textureImageView != null) {
                try {
                    PhotoViewer.this.currentBitmap = Bitmaps.createBitmap(PhotoViewer.this.videoTextureView.getWidth(), PhotoViewer.this.videoTextureView.getHeight(), Bitmap.Config.ARGB_8888);
                    PhotoViewer.this.videoTextureView.getBitmap(PhotoViewer.this.currentBitmap);
                } catch (Throwable e) {
                    if (PhotoViewer.this.currentBitmap != null) {
                        PhotoViewer.this.currentBitmap.recycle();
                        PhotoViewer.this.currentBitmap = null;
                    }
                    FileLog.e(e);
                }
                if (PhotoViewer.this.currentBitmap != null) {
                    PhotoViewer.this.textureImageView.setVisibility(0);
                    PhotoViewer.this.textureImageView.setImageBitmap(PhotoViewer.this.currentBitmap);
                } else {
                    PhotoViewer.this.textureImageView.setImageDrawable(null);
                }
            }
            PhotoViewer.this.isInline = true;
            PhotoViewer.this.pipVideoView = new PipVideoView();
            PhotoViewer photoViewer = PhotoViewer.this;
            PipVideoView pipVideoView = photoViewer.pipVideoView;
            Activity activity = PhotoViewer.this.parentActivity;
            PhotoViewer photoViewer2 = PhotoViewer.this;
            photoViewer.changedTextureView = pipVideoView.show(activity, photoViewer2, photoViewer2.aspectRatioFrameLayout.getAspectRatio(), PhotoViewer.this.aspectRatioFrameLayout.getVideoRotation());
            PhotoViewer.this.changedTextureView.setVisibility(4);
            PhotoViewer.this.aspectRatioFrameLayout.removeView(PhotoViewer.this.videoTextureView);
        }
    };
    private TextureView.SurfaceTextureListener surfaceTextureListener = new TextureView.SurfaceTextureListener() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.4
        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
            if (PhotoViewer.this.videoTextureView == null || !PhotoViewer.this.changingTextureView) {
                return true;
            }
            if (PhotoViewer.this.switchingInlineMode) {
                PhotoViewer.this.waitingForFirstTextureUpload = 2;
            }
            PhotoViewer.this.videoTextureView.setSurfaceTexture(surface);
            PhotoViewer.this.videoTextureView.setVisibility(0);
            PhotoViewer.this.changingTextureView = false;
            PhotoViewer.this.containerView.invalidate();
            return false;
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$4$1, reason: invalid class name */
        class AnonymousClass1 implements ViewTreeObserver.OnPreDrawListener {
            AnonymousClass1() {
            }

            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                PhotoViewer.this.changedTextureView.getViewTreeObserver().removeOnPreDrawListener(this);
                if (PhotoViewer.this.textureImageView != null) {
                    PhotoViewer.this.textureImageView.setVisibility(4);
                    PhotoViewer.this.textureImageView.setImageDrawable(null);
                    if (PhotoViewer.this.currentBitmap != null) {
                        PhotoViewer.this.currentBitmap.recycle();
                        PhotoViewer.this.currentBitmap = null;
                    }
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$4$1$2j9tXHvdYRZMqdywDmAhaG4N2HY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onPreDraw$0$PhotoViewer$4$1();
                    }
                });
                PhotoViewer.this.waitingForFirstTextureUpload = 0;
                return true;
            }

            public /* synthetic */ void lambda$onPreDraw$0$PhotoViewer$4$1() {
                if (PhotoViewer.this.isInline) {
                    PhotoViewer.this.dismissInternal();
                }
            }
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureUpdated(SurfaceTexture surface) {
            if (PhotoViewer.this.waitingForFirstTextureUpload == 1) {
                PhotoViewer.this.changedTextureView.getViewTreeObserver().addOnPreDrawListener(new AnonymousClass1());
                PhotoViewer.this.changedTextureView.invalidate();
            }
        }
    };
    private float[][] animationValues = (float[][]) Array.newInstance((Class<?>) float.class, 2, 10);
    private ImageReceiver leftImage = new ImageReceiver();
    private ImageReceiver centerImage = new ImageReceiver();
    private ImageReceiver rightImage = new ImageReceiver();
    private String[] currentFileNames = new String[3];
    private boolean[] endReached = {false, true};
    private float scale = 1.0f;
    private DecelerateInterpolator interpolator = new DecelerateInterpolator(1.5f);
    private float pinchStartScale = 1.0f;
    private boolean canZoom = true;
    private boolean canDragDown = true;
    private boolean bottomTouchEnabled = true;
    private ArrayList<MessageObject> imagesArrTemp = new ArrayList<>();
    private SparseArray<MessageObject>[] imagesByIdsTemp = {new SparseArray<>(), new SparseArray<>()};
    private ArrayList<MessageObject> imagesArr = new ArrayList<>();
    private SparseArray<MessageObject>[] imagesByIds = {new SparseArray<>(), new SparseArray<>()};
    private ArrayList<ImageLocation> imagesArrLocations = new ArrayList<>();
    private ArrayList<SecureDocument> secureDocuments = new ArrayList<>();
    private ArrayList<TLRPC.Photo> avatarsArr = new ArrayList<>();
    private ArrayList<Integer> imagesArrLocationsSizes = new ArrayList<>();
    private ArrayList<Object> imagesArrLocals = new ArrayList<>();
    private ImageLocation currentUserAvatarLocation = null;
    private int compressionsCount = -1;

    public interface PhotoViewerProvider {
        boolean allowCaption();

        boolean canCaptureMorePhotos();

        boolean canScrollAway();

        boolean cancelButtonPressed();

        void deleteImageAtIndex(int i);

        String getDeleteMessageString();

        int getPhotoIndex(int i);

        PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int i, boolean z);

        int getSelectedCount();

        HashMap<Object, Object> getSelectedPhotos();

        ArrayList<Object> getSelectedPhotosOrder();

        ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int i);

        boolean isPhotoChecked(int i);

        void needAddMorePhotos();

        boolean scaleToFill();

        void sendButtonPressed(int i, VideoEditedInfo videoEditedInfo, boolean z, int i2);

        int setPhotoChecked(int i, VideoEditedInfo videoEditedInfo);

        int setPhotoUnchecked(Object obj);

        void updatePhotoAtIndex(int i);

        void willHidePhotoViewer();

        void willSwitchFromPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int i);
    }

    public static class PlaceProviderObject {
        public ClippingImageView animatingImageView;
        public int clipBottomAddition;
        public int clipTopAddition;
        public int dialogId;
        public ImageReceiver imageReceiver;
        public int index;
        public boolean isEvent;
        public View parentView;
        public int radius;
        public float scale = 1.0f;
        public int size;
        public ImageReceiver.BitmapHolder thumb;
        public int viewX;
        public int viewY;
    }

    public /* synthetic */ void lambda$new$0$PhotoViewer() {
        toggleMiniProgressInternal(true);
    }

    private class LinkMovementMethodMy extends LinkMovementMethod {
        private LinkMovementMethodMy() {
        }

        @Override // android.text.method.LinkMovementMethod, android.text.method.ScrollingMovementMethod, android.text.method.BaseMovementMethod, android.text.method.MovementMethod
        public boolean onTouchEvent(TextView widget, Spannable buffer, MotionEvent event) {
            try {
                boolean result = super.onTouchEvent(widget, buffer, event);
                if (event.getAction() == 1 || event.getAction() == 3) {
                    URLSpanNoUnderline[] links = (URLSpanNoUnderline[]) buffer.getSpans(widget.getSelectionStart(), widget.getSelectionEnd(), URLSpanNoUnderline.class);
                    if (links != null && links.length > 0) {
                        String url = links[0].getURL();
                        if (url.startsWith("video") && PhotoViewer.this.videoPlayer != null && PhotoViewer.this.currentMessageObject != null) {
                            int seconds = Utilities.parseInt(url).intValue();
                            if (PhotoViewer.this.videoPlayer.getDuration() != C.TIME_UNSET) {
                                PhotoViewer.this.videoPlayer.seekTo(((long) seconds) * 1000);
                            } else {
                                PhotoViewer.this.seekToProgressPending = seconds / PhotoViewer.this.currentMessageObject.getDuration();
                            }
                        }
                    }
                    Selection.removeSelection(buffer);
                }
                return result;
            } catch (Exception e) {
                FileLog.e(e);
                return false;
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$2, reason: invalid class name */
    class AnonymousClass2 implements Runnable {
        AnonymousClass2() {
        }

        @Override // java.lang.Runnable
        public void run() {
            float bufferedProgress;
            float bufferedProgress2;
            if (PhotoViewer.this.videoPlayer != null) {
                if (PhotoViewer.this.isCurrentVideo) {
                    if (!PhotoViewer.this.videoTimelineView.isDragging()) {
                        float progress = PhotoViewer.this.videoPlayer.getCurrentPosition() / PhotoViewer.this.videoPlayer.getDuration();
                        if (PhotoViewer.this.inPreview || PhotoViewer.this.videoTimelineView.getVisibility() != 0) {
                            PhotoViewer.this.videoTimelineView.setProgress(progress);
                        } else if (progress >= PhotoViewer.this.videoTimelineView.getRightProgress()) {
                            PhotoViewer.this.videoTimelineView.setProgress(0.0f);
                            PhotoViewer.this.videoPlayer.seekTo((int) (PhotoViewer.this.videoTimelineView.getLeftProgress() * PhotoViewer.this.videoPlayer.getDuration()));
                            if (PhotoViewer.this.muteVideo) {
                                PhotoViewer.this.videoPlayer.play();
                            } else {
                                PhotoViewer.this.videoPlayer.pause();
                            }
                            PhotoViewer.this.containerView.invalidate();
                        } else {
                            float progress2 = progress - PhotoViewer.this.videoTimelineView.getLeftProgress();
                            if (progress2 < 0.0f) {
                                progress2 = 0.0f;
                            }
                            float progress3 = progress2 / (PhotoViewer.this.videoTimelineView.getRightProgress() - PhotoViewer.this.videoTimelineView.getLeftProgress());
                            if (progress3 > 1.0f) {
                                progress3 = 1.0f;
                            }
                            PhotoViewer.this.videoTimelineView.setProgress(progress3);
                        }
                        PhotoViewer.this.updateVideoPlayerTime();
                    }
                } else {
                    float progress4 = PhotoViewer.this.videoPlayer.getCurrentPosition() / PhotoViewer.this.videoPlayer.getDuration();
                    if (PhotoViewer.this.currentVideoFinishedLoading) {
                        bufferedProgress = 1.0f;
                    } else {
                        long newTime = SystemClock.elapsedRealtime();
                        if (Math.abs(newTime - PhotoViewer.this.lastBufferedPositionCheck) >= 500) {
                            if (PhotoViewer.this.isStreaming) {
                                bufferedProgress2 = FileLoader.getInstance(PhotoViewer.this.currentAccount).getBufferedProgressFromPosition(PhotoViewer.this.seekToProgressPending != 0.0f ? PhotoViewer.this.seekToProgressPending : progress4, PhotoViewer.this.currentFileNames[0]);
                            } else {
                                bufferedProgress2 = 1.0f;
                            }
                            PhotoViewer.this.lastBufferedPositionCheck = newTime;
                            bufferedProgress = bufferedProgress2;
                        } else {
                            bufferedProgress = -1.0f;
                        }
                    }
                    if (PhotoViewer.this.inPreview || PhotoViewer.this.videoTimelineView.getVisibility() != 0) {
                        if (PhotoViewer.this.seekToProgressPending == 0.0f) {
                            PhotoViewer.this.videoPlayerSeekbar.setProgress(progress4);
                        }
                        if (bufferedProgress != -1.0f) {
                            PhotoViewer.this.videoPlayerSeekbar.setBufferedProgress(bufferedProgress);
                            if (PhotoViewer.this.pipVideoView != null) {
                                PhotoViewer.this.pipVideoView.setBufferedProgress(bufferedProgress);
                            }
                        }
                    } else if (progress4 >= PhotoViewer.this.videoTimelineView.getRightProgress()) {
                        PhotoViewer.this.videoPlayer.pause();
                        PhotoViewer.this.videoPlayerSeekbar.setProgress(0.0f);
                        PhotoViewer.this.videoPlayer.seekTo((int) (PhotoViewer.this.videoTimelineView.getLeftProgress() * PhotoViewer.this.videoPlayer.getDuration()));
                        PhotoViewer.this.containerView.invalidate();
                    } else {
                        float progress5 = progress4 - PhotoViewer.this.videoTimelineView.getLeftProgress();
                        if (progress5 < 0.0f) {
                            progress5 = 0.0f;
                        }
                        progress4 = progress5 / (PhotoViewer.this.videoTimelineView.getRightProgress() - PhotoViewer.this.videoTimelineView.getLeftProgress());
                        if (progress4 > 1.0f) {
                            progress4 = 1.0f;
                        }
                        PhotoViewer.this.videoPlayerSeekbar.setProgress(progress4);
                    }
                    PhotoViewer.this.videoPlayerControlFrameLayout.invalidate();
                    if (PhotoViewer.this.shouldSavePositionForCurrentVideo != null) {
                        final float value = progress4;
                        if (value >= 0.0f && PhotoViewer.this.shouldSavePositionForCurrentVideo != null && SystemClock.uptimeMillis() - PhotoViewer.this.lastSaveTime >= 1000) {
                            String unused = PhotoViewer.this.shouldSavePositionForCurrentVideo;
                            PhotoViewer.this.lastSaveTime = SystemClock.uptimeMillis();
                            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$2$boejFlgY1NdDoyCUXHIg76qJKEI
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$run$0$PhotoViewer$2(value);
                                }
                            });
                        }
                    }
                    PhotoViewer.this.updateVideoPlayerTime();
                }
            }
            if (PhotoViewer.this.isPlaying) {
                AndroidUtilities.runOnUIThread(PhotoViewer.this.updateProgressRunnable, 17L);
            }
        }

        public /* synthetic */ void lambda$run$0$PhotoViewer$2(float value) {
            SharedPreferences.Editor editor = ApplicationLoader.applicationContext.getSharedPreferences("media_saved_pos", 0).edit();
            editor.putFloat(PhotoViewer.this.shouldSavePositionForCurrentVideo, value).commit();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class BackgroundDrawable extends ColorDrawable {
        private boolean allowDrawContent;
        private Runnable drawRunnable;
        private final Paint paint;
        private final RectF rect;
        private final RectF visibleRect;

        public BackgroundDrawable(int color) {
            super(color);
            this.rect = new RectF();
            this.visibleRect = new RectF();
            Paint paint = new Paint(1);
            this.paint = paint;
            paint.setColor(color);
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
            if (PhotoViewer.this.parentActivity instanceof LaunchActivity) {
                this.allowDrawContent = (PhotoViewer.this.isVisible && alpha == 255) ? false : true;
                ((LaunchActivity) PhotoViewer.this.parentActivity).drawerLayoutContainer.setAllowDrawContent(this.allowDrawContent);
                if (PhotoViewer.this.parentAlert != null) {
                    if (this.allowDrawContent) {
                        if (PhotoViewer.this.parentAlert != null) {
                            PhotoViewer.this.parentAlert.setAllowDrawContent(this.allowDrawContent);
                        }
                    } else {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$BackgroundDrawable$QxpsBsG4AxZlqh9l-s00NovhBKs
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$setAlpha$0$PhotoViewer$BackgroundDrawable();
                            }
                        }, 50L);
                    }
                }
            }
            super.setAlpha(alpha);
            this.paint.setAlpha(alpha);
        }

        public /* synthetic */ void lambda$setAlpha$0$PhotoViewer$BackgroundDrawable() {
            if (PhotoViewer.this.parentAlert != null) {
                PhotoViewer.this.parentAlert.setAllowDrawContent(this.allowDrawContent);
            }
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            Runnable runnable;
            if (PhotoViewer.this.animationInProgress != 0 && !AndroidUtilities.isTablet() && PhotoViewer.this.currentPlaceObject != null && PhotoViewer.this.currentPlaceObject.animatingImageView != null) {
                PhotoViewer.this.animatingImageView.getClippedVisibleRect(this.visibleRect);
                if (!this.visibleRect.isEmpty()) {
                    this.visibleRect.inset(AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f));
                    Rect boundsRect = getBounds();
                    float width = boundsRect.right;
                    float height = boundsRect.bottom;
                    for (int i = 0; i < 4; i++) {
                        if (i == 0) {
                            this.rect.set(0.0f, this.visibleRect.top, this.visibleRect.left, this.visibleRect.bottom);
                        } else if (i == 1) {
                            this.rect.set(0.0f, 0.0f, width, this.visibleRect.top);
                        } else if (i == 2) {
                            this.rect.set(this.visibleRect.right, this.visibleRect.top, width, this.visibleRect.bottom);
                        } else if (i == 3) {
                            this.rect.set(0.0f, this.visibleRect.bottom, width, height);
                        }
                        canvas.drawRect(this.rect, this.paint);
                    }
                }
            } else {
                super.draw(canvas);
            }
            if (getAlpha() != 0 && (runnable = this.drawRunnable) != null) {
                AndroidUtilities.runOnUIThread(runnable);
                this.drawRunnable = null;
            }
        }
    }

    private class CounterView extends View {
        private int currentCount;
        private int height;
        private Paint paint;
        private RectF rect;
        private float rotation;
        private StaticLayout staticLayout;
        private TextPaint textPaint;
        private int width;

        public CounterView(Context context) {
            super(context);
            this.currentCount = 0;
            TextPaint textPaint = new TextPaint(1);
            this.textPaint = textPaint;
            textPaint.setTextSize(AndroidUtilities.dp(18.0f));
            this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.textPaint.setColor(-1);
            Paint paint = new Paint(1);
            this.paint = paint;
            paint.setColor(-1);
            this.paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            this.paint.setStyle(Paint.Style.STROKE);
            this.paint.setStrokeJoin(Paint.Join.ROUND);
            this.rect = new RectF();
            setCount(0);
        }

        @Override // android.view.View
        public void setScaleX(float scaleX) {
            super.setScaleX(scaleX);
            invalidate();
        }

        @Override // android.view.View
        public void setRotationX(float rotationX) {
            this.rotation = rotationX;
            invalidate();
        }

        @Override // android.view.View
        public float getRotationX() {
            return this.rotation;
        }

        public void setCount(int value) {
            StaticLayout staticLayout = new StaticLayout("" + Math.max(1, value), this.textPaint, AndroidUtilities.dp(100.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.staticLayout = staticLayout;
            this.width = (int) Math.ceil((double) staticLayout.getLineWidth(0));
            this.height = this.staticLayout.getLineBottom(0);
            AnimatorSet animatorSet = new AnimatorSet();
            if (value == 0) {
                animatorSet.playTogether(ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_X, 0.0f), ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_Y, 0.0f), ObjectAnimator.ofInt(this.paint, AnimationProperties.PAINT_ALPHA, 0), ObjectAnimator.ofInt(this.textPaint, (Property<TextPaint, Integer>) AnimationProperties.PAINT_ALPHA, 0));
                animatorSet.setInterpolator(new DecelerateInterpolator());
            } else {
                int i = this.currentCount;
                if (i == 0) {
                    animatorSet.playTogether(ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_X, 0.0f, 1.0f), ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_Y, 0.0f, 1.0f), ObjectAnimator.ofInt(this.paint, AnimationProperties.PAINT_ALPHA, 0, 255), ObjectAnimator.ofInt(this.textPaint, (Property<TextPaint, Integer>) AnimationProperties.PAINT_ALPHA, 0, 255));
                    animatorSet.setInterpolator(new DecelerateInterpolator());
                } else if (value < i) {
                    animatorSet.playTogether(ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_X, 1.1f, 1.0f), ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_Y, 1.1f, 1.0f));
                    animatorSet.setInterpolator(new OvershootInterpolator());
                } else {
                    animatorSet.playTogether(ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_X, 0.9f, 1.0f), ObjectAnimator.ofFloat(this, (Property<CounterView, Float>) View.SCALE_Y, 0.9f, 1.0f));
                    animatorSet.setInterpolator(new OvershootInterpolator());
                }
            }
            animatorSet.setDuration(180L);
            animatorSet.start();
            requestLayout();
            this.currentCount = value;
        }

        @Override // android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(Math.max(this.width + AndroidUtilities.dp(20.0f), AndroidUtilities.dp(30.0f)), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(40.0f), 1073741824));
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int cy = getMeasuredHeight() / 2;
            this.paint.setAlpha(255);
            this.rect.set(AndroidUtilities.dp(1.0f), cy - AndroidUtilities.dp(14.0f), getMeasuredWidth() - AndroidUtilities.dp(1.0f), AndroidUtilities.dp(14.0f) + cy);
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(15.0f), AndroidUtilities.dp(15.0f), this.paint);
            if (this.staticLayout != null) {
                this.textPaint.setAlpha((int) ((1.0f - this.rotation) * 255.0f));
                canvas.save();
                canvas.translate((getMeasuredWidth() - this.width) / 2, ((getMeasuredHeight() - this.height) / 2) + AndroidUtilities.dpf2(0.2f) + (this.rotation * AndroidUtilities.dp(5.0f)));
                this.staticLayout.draw(canvas);
                canvas.restore();
                this.paint.setAlpha((int) (this.rotation * 255.0f));
                int cx = (int) this.rect.centerX();
                int cy2 = (int) (((int) this.rect.centerY()) - ((AndroidUtilities.dp(5.0f) * (1.0f - this.rotation)) + AndroidUtilities.dp(3.0f)));
                canvas.drawLine(AndroidUtilities.dp(0.5f) + cx, cy2 - AndroidUtilities.dp(0.5f), cx - AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f) + cy2, this.paint);
                canvas.drawLine(cx - AndroidUtilities.dp(0.5f), cy2 - AndroidUtilities.dp(0.5f), AndroidUtilities.dp(6.0f) + cx, AndroidUtilities.dp(6.0f) + cy2, this.paint);
            }
        }
    }

    private class PhotoProgressView {
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

        public PhotoProgressView(Context context, View parentView) {
            if (PhotoViewer.decelerateInterpolator == null) {
                DecelerateInterpolator unused = PhotoViewer.decelerateInterpolator = new DecelerateInterpolator(1.5f);
                Paint unused2 = PhotoViewer.progressPaint = new Paint(1);
                PhotoViewer.progressPaint.setStyle(Paint.Style.STROKE);
                PhotoViewer.progressPaint.setStrokeCap(Paint.Cap.ROUND);
                PhotoViewer.progressPaint.setStrokeWidth(AndroidUtilities.dp(3.0f));
                PhotoViewer.progressPaint.setColor(-1);
            }
            this.parent = parentView;
        }

        private void updateAnimation() {
            long newTime = System.currentTimeMillis();
            long dt = newTime - this.lastUpdateTime;
            if (dt > 18) {
                dt = 18;
            }
            this.lastUpdateTime = newTime;
            if (this.animatedProgressValue != 1.0f || this.currentProgress != 1.0f) {
                this.radOffset += (360 * dt) / 3000.0f;
                float progressDiff = this.currentProgress - this.animationProgressStart;
                if (Math.abs(progressDiff) > 0.0f) {
                    long j = this.currentProgressTime + dt;
                    this.currentProgressTime = j;
                    if (j < 300) {
                        this.animatedProgressValue = this.animationProgressStart + (PhotoViewer.decelerateInterpolator.getInterpolation(this.currentProgressTime / 300.0f) * progressDiff);
                    } else {
                        float f = this.currentProgress;
                        this.animatedProgressValue = f;
                        this.animationProgressStart = f;
                        this.currentProgressTime = 0L;
                    }
                }
                this.parent.invalidate();
            }
            if (this.animatedProgressValue >= 1.0f && this.previousBackgroundState != -2) {
                float f2 = this.animatedAlphaValue - (dt / 200.0f);
                this.animatedAlphaValue = f2;
                if (f2 <= 0.0f) {
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
            this.parent.invalidate();
        }

        public void setBackgroundState(int state, boolean animated) {
            int i;
            if (this.backgroundState == state) {
                return;
            }
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
            int x = (PhotoViewer.this.getContainerViewWidth() - sizeScaled) / 2;
            int y = (PhotoViewer.this.getContainerViewHeight() - sizeScaled) / 2;
            int i2 = this.previousBackgroundState;
            if (i2 >= 0 && i2 < 4 && (drawable2 = PhotoViewer.progressDrawables[this.previousBackgroundState]) != null) {
                drawable2.setAlpha((int) (this.animatedAlphaValue * 255.0f * this.alpha));
                drawable2.setBounds(x, y, x + sizeScaled, y + sizeScaled);
                drawable2.draw(canvas);
            }
            int i3 = this.backgroundState;
            if (i3 >= 0 && i3 < 4 && (drawable = PhotoViewer.progressDrawables[this.backgroundState]) != null) {
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
                    PhotoViewer.progressPaint.setAlpha((int) (this.animatedAlphaValue * 255.0f * this.alpha));
                } else {
                    PhotoViewer.progressPaint.setAlpha((int) (this.alpha * 255.0f));
                }
                this.progressRect.set(x + diff, y + diff, (x + sizeScaled) - diff, (y + sizeScaled) - diff);
                canvas.drawArc(this.progressRect, (-90.0f) + this.radOffset, Math.max(4.0f, this.animatedProgressValue * 360.0f), false, PhotoViewer.progressPaint);
                updateAnimation();
            }
        }
    }

    public static class EmptyPhotoViewerProvider implements PhotoViewerProvider {
        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willSwitchFromPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void willHidePhotoViewer() {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int setPhotoUnchecked(Object photoEntry) {
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean isPhotoChecked(int index) {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int setPhotoChecked(int index, VideoEditedInfo videoEditedInfo) {
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean cancelButtonPressed() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int getSelectedCount() {
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void updatePhotoAtIndex(int index) {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean allowCaption() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean scaleToFill() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public ArrayList<Object> getSelectedPhotosOrder() {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public HashMap<Object, Object> getSelectedPhotos() {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean canScrollAway() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void needAddMorePhotos() {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public int getPhotoIndex(int index) {
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public void deleteImageAtIndex(int index) {
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public String getDeleteMessageString() {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
        public boolean canCaptureMorePhotos() {
            return true;
        }
    }

    private class FrameLayoutDrawer extends SizeNotifierFrameLayoutPhoto {
        private boolean ignoreLayout;
        private Paint paint;

        public FrameLayoutDrawer(Context context) {
            super(context);
            this.paint = new Paint();
            setWillNotDraw(false);
            this.paint.setColor(Theme.value_blackAlpha80);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, heightSize);
            this.ignoreLayout = true;
            PhotoViewer.this.captionTextView.setMaxLines(AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? 5 : 10);
            this.ignoreLayout = false;
            measureChildWithMargins(PhotoViewer.this.captionEditText, widthMeasureSpec, 0, heightMeasureSpec, 0);
            int inputFieldHeight = PhotoViewer.this.captionEditText.getMeasuredHeight();
            int widthSize2 = widthSize - (getPaddingRight() + getPaddingLeft());
            int heightSize2 = heightSize - getPaddingBottom();
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8 && child != PhotoViewer.this.captionEditText) {
                    if (child != PhotoViewer.this.aspectRatioFrameLayout) {
                        if (PhotoViewer.this.captionEditText.isPopupView(child)) {
                            if (AndroidUtilities.isInMultiwindow) {
                                if (AndroidUtilities.isTablet()) {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(320.0f), (heightSize2 - inputFieldHeight) - AndroidUtilities.statusBarHeight), 1073741824));
                                } else {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec((heightSize2 - inputFieldHeight) - AndroidUtilities.statusBarHeight, 1073741824));
                                }
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                            }
                        } else {
                            measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                        }
                    } else {
                        int heightSpec = View.MeasureSpec.makeMeasureSpec(AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0), 1073741824);
                        child.measure(widthMeasureSpec, heightSpec);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayoutPhoto, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int _l, int t, int _r, int _b) {
            int l;
            int r;
            int b;
            int count;
            int childLeft;
            int childTop;
            int paddingBottom;
            int count2 = getChildCount();
            int paddingBottom2 = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : PhotoViewer.this.captionEditText.getEmojiPadding();
            int i = 0;
            while (i < count2) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8) {
                    if (child == PhotoViewer.this.aspectRatioFrameLayout) {
                        l = _l;
                        r = _r;
                        b = _b;
                    } else {
                        int l2 = getPaddingLeft();
                        l = _l + l2;
                        r = _r - getPaddingRight();
                        b = _b - getPaddingBottom();
                    }
                    FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                    int width = child.getMeasuredWidth();
                    int height = child.getMeasuredHeight();
                    int gravity = lp.gravity;
                    if (gravity == -1) {
                        gravity = 51;
                    }
                    int absoluteGravity = gravity & 7;
                    int verticalGravity = gravity & 112;
                    int i2 = absoluteGravity & 7;
                    count = count2;
                    if (i2 == 1) {
                        int childLeft2 = r - l;
                        childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                    } else if (i2 == 5) {
                        int childLeft3 = r - l;
                        childLeft = (childLeft3 - width) - lp.rightMargin;
                    } else {
                        childLeft = lp.leftMargin;
                    }
                    if (verticalGravity == 16) {
                        int childTop2 = b - paddingBottom2;
                        childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                    } else if (verticalGravity == 80) {
                        int childTop3 = b - paddingBottom2;
                        childTop = ((childTop3 - t) - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (child == PhotoViewer.this.mentionListView) {
                        childTop -= PhotoViewer.this.captionEditText.getMeasuredHeight();
                        paddingBottom = paddingBottom2;
                    } else if (!PhotoViewer.this.captionEditText.isPopupView(child)) {
                        if (child == PhotoViewer.this.selectedPhotosListView) {
                            childTop = PhotoViewer.this.actionBar.getMeasuredHeight();
                            paddingBottom = paddingBottom2;
                        } else if (child == PhotoViewer.this.captionTextView || child == PhotoViewer.this.switchCaptionTextView) {
                            paddingBottom = paddingBottom2;
                            if (!PhotoViewer.this.groupedPhotosListView.currentPhotos.isEmpty()) {
                                childTop -= PhotoViewer.this.groupedPhotosListView.getMeasuredHeight();
                            }
                        } else if (child == PhotoViewer.this.cameraItem) {
                            paddingBottom = paddingBottom2;
                            childTop = (PhotoViewer.this.pickerView.getTop() - AndroidUtilities.dp((PhotoViewer.this.sendPhotoType == 4 || PhotoViewer.this.sendPhotoType == 5) ? 40.0f : 15.0f)) - PhotoViewer.this.cameraItem.getMeasuredHeight();
                        } else {
                            paddingBottom = paddingBottom2;
                            if (child == PhotoViewer.this.videoPreviewFrame) {
                                if (!PhotoViewer.this.groupedPhotosListView.currentPhotos.isEmpty()) {
                                    childTop -= PhotoViewer.this.groupedPhotosListView.getMeasuredHeight();
                                }
                                if (PhotoViewer.this.captionTextView.getVisibility() == 0) {
                                    childTop -= PhotoViewer.this.captionTextView.getMeasuredHeight();
                                }
                            }
                        }
                    } else if (AndroidUtilities.isInMultiwindow) {
                        childTop = (PhotoViewer.this.captionEditText.getTop() - child.getMeasuredHeight()) + AndroidUtilities.dp(1.0f);
                        paddingBottom = paddingBottom2;
                    } else {
                        childTop = PhotoViewer.this.captionEditText.getBottom();
                        paddingBottom = paddingBottom2;
                    }
                    child.layout(childLeft + l, childTop, childLeft + width + l, childTop + height);
                } else {
                    count = count2;
                    paddingBottom = paddingBottom2;
                }
                i++;
                count2 = count;
                paddingBottom2 = paddingBottom;
            }
            notifyHeightChanged();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            PhotoViewer.this.onDraw(canvas);
            if (Build.VERSION.SDK_INT >= 21 && AndroidUtilities.statusBarHeight != 0 && PhotoViewer.this.actionBar != null) {
                this.paint.setAlpha((int) (PhotoViewer.this.actionBar.getAlpha() * 255.0f * 0.2f));
                canvas.drawRect(0.0f, 0.0f, getMeasuredWidth(), AndroidUtilities.statusBarHeight, this.paint);
                this.paint.setAlpha((int) (PhotoViewer.this.actionBar.getAlpha() * 255.0f * 0.498f));
                if (getPaddingRight() > 0) {
                    canvas.drawRect(getMeasuredWidth() - getPaddingRight(), 0.0f, getMeasuredWidth(), getMeasuredHeight(), this.paint);
                }
                if (getPaddingLeft() > 0) {
                    canvas.drawRect(0.0f, 0.0f, getPaddingLeft(), getMeasuredHeight(), this.paint);
                }
            }
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            if (child == PhotoViewer.this.mentionListView || child == PhotoViewer.this.captionEditText) {
                if (!PhotoViewer.this.captionEditText.isPopupShowing() && PhotoViewer.this.captionEditText.getEmojiPadding() == 0 && ((AndroidUtilities.usingHardwareInput && PhotoViewer.this.captionEditText.getTag() == null) || getKeyboardHeight() == 0)) {
                    return false;
                }
            } else if (child != PhotoViewer.this.cameraItem && child != PhotoViewer.this.pickerView && child != PhotoViewer.this.pickerViewSendButton && child != PhotoViewer.this.captionTextView && (PhotoViewer.this.muteItem.getVisibility() != 0 || child != PhotoViewer.this.bottomLayout)) {
                if (child == PhotoViewer.this.checkImageView || child == PhotoViewer.this.photosCounterView) {
                    if (PhotoViewer.this.captionEditText.getTag() != null) {
                        PhotoViewer.this.bottomTouchEnabled = false;
                        return false;
                    }
                    PhotoViewer.this.bottomTouchEnabled = true;
                } else if (child == PhotoViewer.this.miniProgressView) {
                    return false;
                }
            } else {
                int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : PhotoViewer.this.captionEditText.getEmojiPadding();
                if (!PhotoViewer.this.captionEditText.isPopupShowing() && ((!AndroidUtilities.usingHardwareInput || PhotoViewer.this.captionEditText.getTag() == null) && getKeyboardHeight() <= AndroidUtilities.dp(80.0f) && paddingBottom == 0)) {
                    PhotoViewer.this.bottomTouchEnabled = true;
                } else {
                    if (BuildVars.DEBUG_VERSION) {
                        FileLog.d("keyboard height = " + getKeyboardHeight() + " padding = " + paddingBottom);
                    }
                    PhotoViewer.this.bottomTouchEnabled = false;
                    return false;
                }
            }
            try {
                if (child != PhotoViewer.this.aspectRatioFrameLayout) {
                    if (super.drawChild(canvas, child, drawingTime)) {
                        return true;
                    }
                }
                return false;
            } catch (Throwable th) {
                return true;
            }
        }

        @Override // android.view.View, android.view.ViewParent
        public void requestLayout() {
            if (this.ignoreLayout) {
                return;
            }
            super.requestLayout();
        }
    }

    public static PhotoViewer getPipInstance() {
        return PipInstance;
    }

    public static PhotoViewer getInstance() {
        PhotoViewer localInstance = Instance;
        if (localInstance == null) {
            synchronized (PhotoViewer.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    PhotoViewer photoViewer = new PhotoViewer();
                    localInstance = photoViewer;
                    Instance = photoViewer;
                }
            }
        }
        return localInstance;
    }

    public boolean isOpenedFullScreenVideo() {
        return this.openedFullScreenVideo;
    }

    public static boolean hasInstance() {
        return Instance != null;
    }

    public PhotoViewer() {
        this.blackPaint.setColor(-16777216);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int loadFromMaxId;
        int id2;
        boolean z;
        ImageLocation location;
        TLRPC.PhotoSize sizeFull;
        int setToImage;
        int setToImage2;
        float bufferedProgress;
        float progress;
        MessageObject messageObject;
        TLRPC.BotInlineResult botInlineResult;
        int i = 3;
        int i2 = 2;
        int i3 = 1;
        boolean animated = false;
        if (id == NotificationCenter.fileDidFailToLoad) {
            String location2 = (String) args[0];
            for (int a = 0; a < 3; a++) {
                String[] strArr = this.currentFileNames;
                if (strArr[a] != null && strArr[a].equals(location2)) {
                    if (a == 0 || ((a == 1 && this.sideImage == this.rightImage) || (a == 2 && this.sideImage == this.leftImage))) {
                        animated = true;
                    }
                    this.photoProgressViews[a].setProgress(1.0f, animated);
                    checkProgress(a, true);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.fileDidLoad) {
            String location3 = (String) args[0];
            int a2 = 0;
            while (a2 < 3) {
                String[] strArr2 = this.currentFileNames;
                if (strArr2[a2] == null || !strArr2[a2].equals(location3)) {
                    a2++;
                } else {
                    boolean animated2 = a2 == 0 || (a2 == 1 && this.sideImage == this.rightImage) || (a2 == 2 && this.sideImage == this.leftImage);
                    this.photoProgressViews[a2].setProgress(1.0f, animated2);
                    checkProgress(a2, animated2);
                    if (this.videoPlayer == null && a2 == 0 && (((messageObject = this.currentMessageObject) != null && messageObject.isVideo()) || ((botInlineResult = this.currentBotInlineResult) != null && (botInlineResult.type.equals("video") || MessageObject.isVideoDocument(this.currentBotInlineResult.document))))) {
                        onActionClick(false);
                    }
                    if (a2 == 0 && this.videoPlayer != null) {
                        this.currentVideoFinishedLoading = true;
                        return;
                    }
                    return;
                }
            }
            return;
        }
        long j = 0;
        if (id == NotificationCenter.FileLoadProgressChanged) {
            String location4 = (String) args[0];
            int a3 = 0;
            while (a3 < i) {
                String[] strArr3 = this.currentFileNames;
                if (strArr3[a3] != null && strArr3[a3].equals(location4)) {
                    Float loadProgress = (Float) args[i3];
                    this.photoProgressViews[a3].setProgress(loadProgress.floatValue(), a3 == 0 || (a3 == i3 && this.sideImage == this.rightImage) || (a3 == i2 && this.sideImage == this.leftImage));
                    if (a3 == 0 && this.videoPlayer != null && this.videoPlayerSeekbar != null) {
                        if (this.currentVideoFinishedLoading) {
                            bufferedProgress = 1.0f;
                        } else {
                            long newTime = SystemClock.elapsedRealtime();
                            if (Math.abs(newTime - this.lastBufferedPositionCheck) >= 500) {
                                if (this.seekToProgressPending == 0.0f) {
                                    long duration = this.videoPlayer.getDuration();
                                    long position = this.videoPlayer.getCurrentPosition();
                                    if (duration >= j && duration != C.TIME_UNSET && position >= j) {
                                        progress = position / duration;
                                    } else {
                                        progress = 0.0f;
                                    }
                                } else {
                                    progress = this.seekToProgressPending;
                                }
                                float bufferedProgress2 = this.isStreaming ? FileLoader.getInstance(this.currentAccount).getBufferedProgressFromPosition(progress, this.currentFileNames[0]) : 1.0f;
                                this.lastBufferedPositionCheck = newTime;
                                bufferedProgress = bufferedProgress2;
                            } else {
                                bufferedProgress = -1.0f;
                            }
                        }
                        if (bufferedProgress != -1.0f) {
                            this.videoPlayerSeekbar.setBufferedProgress(bufferedProgress);
                            PipVideoView pipVideoView = this.pipVideoView;
                            if (pipVideoView != null) {
                                pipVideoView.setBufferedProgress(bufferedProgress);
                            }
                            this.videoPlayerControlFrameLayout.invalidate();
                        }
                        checkBufferedProgress(loadProgress.floatValue());
                    }
                }
                a3++;
                i = 3;
                i2 = 2;
                i3 = 1;
                j = 0;
            }
            return;
        }
        int i4 = -1;
        if (id == NotificationCenter.dialogPhotosLoaded) {
            int guid = ((Integer) args[3]).intValue();
            int did = ((Integer) args[0]).intValue();
            if (this.avatarsDialogId == did && this.classGuid == guid) {
                boolean fromCache = ((Boolean) args[2]).booleanValue();
                int setToImage3 = -1;
                ArrayList<TLRPC.Photo> photos = (ArrayList) args[4];
                if (photos.isEmpty()) {
                    return;
                }
                this.imagesArrLocations.clear();
                this.imagesArrLocationsSizes.clear();
                this.avatarsArr.clear();
                int a4 = 0;
                while (a4 < photos.size()) {
                    TLRPC.Photo photo = photos.get(a4);
                    if (photo == null || (photo instanceof TLRPC.TL_photoEmpty) || photo.sizes == null || (sizeFull = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 640)) == null) {
                        int setToImage4 = setToImage3;
                        setToImage3 = setToImage4;
                        a4++;
                        i4 = -1;
                    } else {
                        if (setToImage3 != i4 || this.currentFileLocation == null) {
                            setToImage = setToImage3;
                        } else {
                            int b = 0;
                            while (b < photo.sizes.size()) {
                                TLRPC.PhotoSize size = photo.sizes.get(b);
                                if (size.location.local_id == this.currentFileLocation.location.local_id) {
                                    setToImage2 = setToImage3;
                                    if (size.location.volume_id == this.currentFileLocation.location.volume_id) {
                                        setToImage3 = this.imagesArrLocations.size();
                                        break;
                                    }
                                } else {
                                    setToImage2 = setToImage3;
                                }
                                b++;
                                setToImage3 = setToImage2;
                            }
                            setToImage = setToImage3;
                        }
                        setToImage3 = setToImage;
                        if (photo.dc_id != 0) {
                            sizeFull.location.dc_id = photo.dc_id;
                            sizeFull.location.file_reference = photo.file_reference;
                        }
                        ImageLocation location5 = ImageLocation.getForPhoto(sizeFull, photo);
                        if (location5 != null) {
                            this.imagesArrLocations.add(location5);
                            this.imagesArrLocationsSizes.add(Integer.valueOf(sizeFull.size));
                            this.avatarsArr.add(photo);
                        }
                        a4++;
                        i4 = -1;
                    }
                }
                int setToImage5 = setToImage3;
                if (!this.avatarsArr.isEmpty()) {
                    this.menuItem.showSubItem(6);
                } else {
                    this.menuItem.hideSubItem(6);
                }
                this.needSearchImageInArr = false;
                this.currentIndex = -1;
                if (setToImage5 != -1) {
                    setImageIndex(setToImage5, true);
                } else {
                    TLRPC.User user = null;
                    TLRPC.Chat chat = null;
                    if (this.avatarsDialogId > 0) {
                        user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.avatarsDialogId));
                    } else {
                        chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-this.avatarsDialogId));
                    }
                    if (user != null || chat != null) {
                        if (user != null) {
                            location = ImageLocation.getForUser(user, true);
                        } else {
                            location = ImageLocation.getForChat(chat, true);
                        }
                        if (location != null) {
                            this.imagesArrLocations.add(0, location);
                            this.avatarsArr.add(0, new TLRPC.TL_photoEmpty());
                            this.imagesArrLocationsSizes.add(0, 0);
                            setImageIndex(0, true);
                        }
                    }
                }
                if (fromCache) {
                    MessagesController.getInstance(this.currentAccount).loadDialogPhotos(this.avatarsDialogId, 80, 0L, false, this.classGuid);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.mediaCountDidLoad) {
            long uid = ((Long) args[0]).longValue();
            if (uid == this.currentDialogId || uid == this.mergeDialogId) {
                if (uid == this.currentDialogId) {
                    this.totalImagesCount = ((Integer) args[1]).intValue();
                } else if (uid == this.mergeDialogId) {
                    this.totalImagesCountMerge = ((Integer) args[1]).intValue();
                }
                if (this.needSearchImageInArr && this.isFirstLoading) {
                    this.isFirstLoading = false;
                    this.loadingMoreImages = true;
                    MediaDataController.getInstance(this.currentAccount).loadMedia(this.currentDialogId, 80, 0, this.sharedMediaType, 1, this.classGuid);
                    return;
                } else {
                    if (!this.imagesArr.isEmpty()) {
                        if (this.opennedFromMedia) {
                            this.totalImagesCount = this.imagesArr.size();
                            this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(this.currentIndex + 1), Integer.valueOf(this.totalImagesCount + this.totalImagesCountMerge)));
                            return;
                        } else {
                            this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(((this.totalImagesCount + this.totalImagesCountMerge) - this.imagesArr.size()) + this.currentIndex + 1), Integer.valueOf(this.totalImagesCount + this.totalImagesCountMerge)));
                            return;
                        }
                    }
                    return;
                }
            }
            return;
        }
        if (id != NotificationCenter.mediaDidLoad) {
            if (id == NotificationCenter.emojiDidLoad) {
                TextView textView = this.captionTextView;
                if (textView != null) {
                    textView.invalidate();
                    return;
                }
                return;
            }
            if (id == NotificationCenter.filePreparingFailed) {
                MessageObject messageObject2 = (MessageObject) args[0];
                if (this.loadInitialVideo) {
                    this.loadInitialVideo = false;
                    this.progressView.setVisibility(4);
                    preparePlayer(this.currentPlayingVideoFile, false, false);
                    return;
                } else if (this.tryStartRequestPreviewOnFinish) {
                    releasePlayer(false);
                    this.tryStartRequestPreviewOnFinish = !MediaController.getInstance().scheduleVideoConvert(this.videoPreviewMessageObject, true);
                    return;
                } else {
                    if (messageObject2 == this.videoPreviewMessageObject) {
                        this.requestingPreview = false;
                        this.progressView.setVisibility(4);
                        return;
                    }
                    return;
                }
            }
            if (id == NotificationCenter.fileNewChunkAvailable) {
                MessageObject messageObject3 = (MessageObject) args[0];
                if (messageObject3 == this.videoPreviewMessageObject) {
                    String finalPath = (String) args[1];
                    long finalSize = ((Long) args[3]).longValue();
                    if (finalSize != 0) {
                        this.requestingPreview = false;
                        this.photoProgressViews[0].setProgress(1.0f, true);
                        this.photoProgressViews[0].setBackgroundState(3, true);
                        preparePlayer(Uri.fromFile(new File(finalPath)), false, true);
                        return;
                    }
                    return;
                }
                return;
            }
            if (id == NotificationCenter.saveGallerySetChanged) {
                boolean blnSave = ((Boolean) args[0]).booleanValue();
                if (blnSave) {
                    this.menuItem.showSubItem(1);
                    return;
                } else {
                    this.menuItem.hideSubItem(1);
                    this.menuItem.invalidate();
                    return;
                }
            }
            return;
        }
        long uid2 = ((Long) args[0]).longValue();
        int guid2 = ((Integer) args[3]).intValue();
        if ((uid2 == this.currentDialogId || uid2 == this.mergeDialogId) && guid2 == this.classGuid) {
            this.loadingMoreImages = false;
            int loadIndex = uid2 == this.currentDialogId ? 0 : 1;
            ArrayList<MessageObject> arr = (ArrayList) args[2];
            this.endReached[loadIndex] = ((Boolean) args[5]).booleanValue();
            if (this.needSearchImageInArr) {
                if (arr.isEmpty() && (loadIndex != 0 || this.mergeDialogId == 0)) {
                    this.needSearchImageInArr = false;
                    return;
                }
                int foundIndex = -1;
                MessageObject currentMessage = this.imagesArr.get(this.currentIndex);
                int added = 0;
                for (int a5 = 0; a5 < arr.size(); a5++) {
                    MessageObject message = arr.get(a5);
                    if (this.imagesByIdsTemp[loadIndex].indexOfKey(message.getId()) < 0) {
                        this.imagesByIdsTemp[loadIndex].put(message.getId(), message);
                        if (this.opennedFromMedia) {
                            this.imagesArrTemp.add(message);
                            if (message.getId() == currentMessage.getId()) {
                                foundIndex = added;
                            }
                            added++;
                        } else {
                            added++;
                            this.imagesArrTemp.add(0, message);
                            if (message.getId() == currentMessage.getId()) {
                                foundIndex = arr.size() - added;
                            }
                        }
                    }
                }
                if (added != 0 && (loadIndex != 0 || this.mergeDialogId == 0)) {
                    this.totalImagesCount = this.imagesArr.size();
                    this.totalImagesCountMerge = 0;
                }
                if (foundIndex != -1) {
                    this.imagesArr.clear();
                    this.imagesArr.addAll(this.imagesArrTemp);
                    for (int a6 = 0; a6 < 2; a6++) {
                        this.imagesByIds[a6] = this.imagesByIdsTemp[a6].clone();
                        this.imagesByIdsTemp[a6].clear();
                    }
                    this.imagesArrTemp.clear();
                    this.needSearchImageInArr = false;
                    this.currentIndex = -1;
                    if (foundIndex < this.imagesArr.size()) {
                        z = true;
                    } else {
                        z = true;
                        foundIndex = this.imagesArr.size() - 1;
                    }
                    setImageIndex(foundIndex, z);
                    return;
                }
                if (this.opennedFromMedia) {
                    if (this.imagesArrTemp.isEmpty()) {
                        id2 = 0;
                    } else {
                        ArrayList<MessageObject> arrayList = this.imagesArrTemp;
                        id2 = arrayList.get(arrayList.size() - 1).getId();
                    }
                    loadFromMaxId = id2;
                    if (loadIndex == 0 && this.endReached[loadIndex] && this.mergeDialogId != 0) {
                        loadIndex = 1;
                        if (!this.imagesArrTemp.isEmpty()) {
                            ArrayList<MessageObject> arrayList2 = this.imagesArrTemp;
                            if (arrayList2.get(arrayList2.size() - 1).getDialogId() != this.mergeDialogId) {
                                loadFromMaxId = 0;
                            }
                        }
                    }
                } else {
                    loadFromMaxId = this.imagesArrTemp.isEmpty() ? 0 : this.imagesArrTemp.get(0).getId();
                    if (loadIndex == 0 && this.endReached[loadIndex] && this.mergeDialogId != 0) {
                        loadIndex = 1;
                        if (!this.imagesArrTemp.isEmpty() && this.imagesArrTemp.get(0).getDialogId() != this.mergeDialogId) {
                            loadFromMaxId = 0;
                        }
                    }
                }
                if (!this.endReached[loadIndex]) {
                    this.loadingMoreImages = true;
                    if (this.opennedFromMedia) {
                        MediaDataController.getInstance(this.currentAccount).loadMedia(loadIndex == 0 ? this.currentDialogId : this.mergeDialogId, 80, loadFromMaxId, this.sharedMediaType, 1, this.classGuid);
                        return;
                    } else {
                        MediaDataController.getInstance(this.currentAccount).loadMedia(loadIndex == 0 ? this.currentDialogId : this.mergeDialogId, 80, loadFromMaxId, this.sharedMediaType, 1, this.classGuid);
                        return;
                    }
                }
                return;
            }
            int added2 = 0;
            for (MessageObject message2 : arr) {
                if (this.imagesByIds[loadIndex].indexOfKey(message2.getId()) < 0) {
                    added2++;
                    if (this.opennedFromMedia) {
                        this.imagesArr.add(message2);
                    } else {
                        this.imagesArr.add(0, message2);
                    }
                    this.imagesByIds[loadIndex].put(message2.getId(), message2);
                }
            }
            if (this.opennedFromMedia) {
                if (added2 == 0) {
                    this.totalImagesCount = this.imagesArr.size();
                    this.totalImagesCountMerge = 0;
                    return;
                }
                return;
            }
            if (added2 == 0) {
                this.totalImagesCount = this.imagesArr.size();
                this.totalImagesCountMerge = 0;
            } else {
                int index = this.currentIndex;
                this.currentIndex = -1;
                setImageIndex(index + added2, true);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDownloadAlert() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this.parentActivity);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        MessageObject messageObject = this.currentMessageObject;
        boolean z = false;
        if (messageObject != null && messageObject.isVideo() && FileLoader.getInstance(this.currentMessageObject.currentAccount).isLoadingFile(this.currentFileNames[0])) {
            z = true;
        }
        boolean alreadyDownloading = z;
        if (alreadyDownloading) {
            builder.setMessage(LocaleController.getString("PleaseStreamDownload", R.string.PleaseStreamDownload));
        } else {
            builder.setMessage(LocaleController.getString("PleaseDownload", R.string.PleaseDownload));
        }
        showAlertDialog(builder);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSharePressed() {
        if (this.parentActivity == null || !this.allowShare) {
            return;
        }
        File f = null;
        boolean isVideo = false;
        try {
            if (this.currentMessageObject != null) {
                isVideo = this.currentMessageObject.isVideo();
                if (!TextUtils.isEmpty(this.currentMessageObject.messageOwner.attachPath)) {
                    f = new File(this.currentMessageObject.messageOwner.attachPath);
                    if (!f.exists()) {
                        f = null;
                    }
                }
                if (f == null) {
                    f = FileLoader.getPathToMessage(this.currentMessageObject.messageOwner);
                }
            } else if (this.currentFileLocation != null) {
                f = FileLoader.getPathToAttach(this.currentFileLocation.location, this.avatarsDialogId != 0 || this.isEvent);
            }
            if (f.exists()) {
                Intent intent = new Intent("android.intent.action.SEND");
                if (isVideo) {
                    intent.setType(MimeTypes.VIDEO_MP4);
                } else if (this.currentMessageObject != null) {
                    intent.setType(this.currentMessageObject.getMimeType());
                } else {
                    intent.setType("image/jpeg");
                }
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
            showDownloadAlert();
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setScaleToFill() {
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

    public void setParentAlert(ChatAttachAlert alert) {
        this.parentAlert = alert;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public void setParentActivity(Activity activity) {
        int i = UserConfig.selectedAccount;
        this.currentAccount = i;
        this.centerImage.setCurrentAccount(i);
        this.leftImage.setCurrentAccount(this.currentAccount);
        this.rightImage.setCurrentAccount(this.currentAccount);
        if (this.parentActivity == activity || activity == null) {
            return;
        }
        this.parentActivity = activity;
        this.actvityContext = new ContextThemeWrapper(this.parentActivity, 2131755390);
        int i2 = 0;
        if (progressDrawables == null) {
            Drawable[] drawableArr = new Drawable[4];
            progressDrawables = drawableArr;
            drawableArr[0] = this.parentActivity.getResources().getDrawable(R.drawable.circle_big);
            progressDrawables[1] = this.parentActivity.getResources().getDrawable(R.drawable.cancel_big);
            progressDrawables[2] = this.parentActivity.getResources().getDrawable(R.drawable.load_big);
            progressDrawables[3] = this.parentActivity.getResources().getDrawable(R.drawable.play_big);
        }
        this.scroller = new Scroller(activity);
        AnonymousClass5 anonymousClass5 = new AnonymousClass5(activity);
        this.windowView = anonymousClass5;
        anonymousClass5.setBackgroundDrawable(this.backgroundDrawable);
        this.windowView.setClipChildren(true);
        this.windowView.setFocusable(false);
        ClippingImageView clippingImageView = new ClippingImageView(activity);
        this.animatingImageView = clippingImageView;
        clippingImageView.setAnimationValues(this.animationValues);
        this.windowView.addView(this.animatingImageView, LayoutHelper.createFrame(40, 40.0f));
        FrameLayoutDrawer frameLayoutDrawer = new FrameLayoutDrawer(activity);
        this.containerView = frameLayoutDrawer;
        frameLayoutDrawer.setFocusable(false);
        this.windowView.addView(this.containerView, LayoutHelper.createFrame(-1, -1, 51));
        if (Build.VERSION.SDK_INT >= 21) {
            this.containerView.setFitsSystemWindows(true);
            this.containerView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$slWhgX-Vb8Vpv7xHLjoPIiWrnsA
                @Override // android.view.View.OnApplyWindowInsetsListener
                public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                    return this.f$0.lambda$setParentActivity$1$PhotoViewer(view, windowInsets);
                }
            });
            this.containerView.setSystemUiVisibility(1792);
        }
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
        this.windowLayoutParams = layoutParams;
        layoutParams.height = -1;
        this.windowLayoutParams.format = -3;
        this.windowLayoutParams.width = -1;
        this.windowLayoutParams.gravity = 51;
        this.windowLayoutParams.type = 99;
        if (Build.VERSION.SDK_INT >= 28) {
            this.windowLayoutParams.layoutInDisplayCutoutMode = 1;
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.windowLayoutParams.flags = -2147286784;
        } else {
            this.windowLayoutParams.flags = 131072;
        }
        ActionBar actionBar = new ActionBar(activity) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.6
            @Override // android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                PhotoViewer.this.containerView.invalidate();
            }
        };
        this.actionBar = actionBar;
        actionBar.setTitleColor(-1);
        this.actionBar.setSubtitleColor(-1);
        this.actionBar.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.actionBar.setOccupyStatusBar(Build.VERSION.SDK_INT >= 21);
        this.actionBar.setItemsBackgroundColor(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR, false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, 1, 1));
        this.containerView.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass7());
        ActionBarMenu actionBarMenuCreateMenu = this.actionBar.createMenu();
        this.masksItem = actionBarMenuCreateMenu.addItem(13, R.drawable.msg_mask);
        this.pipItem = actionBarMenuCreateMenu.addItem(5, R.drawable.ic_goinline);
        this.sendItem = actionBarMenuCreateMenu.addItem(3, R.drawable.msg_forward);
        ActionBarMenuItem actionBarMenuItemAddItem = actionBarMenuCreateMenu.addItem(0, R.drawable.ic_ab_other);
        this.menuItem = actionBarMenuItemAddItem;
        actionBarMenuItemAddItem.addSubItem(11, R.drawable.msg_openin, LocaleController.getString("OpenInExternalApp", R.string.OpenInExternalApp)).setColors(-328966, -328966);
        this.menuItem.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
        ActionBarMenuSubItem actionBarMenuSubItemAddSubItem = this.menuItem.addSubItem(2, R.drawable.msg_media, LocaleController.getString("ShowAllMedia", R.string.ShowAllMedia));
        this.allMediaItem = actionBarMenuSubItemAddSubItem;
        actionBarMenuSubItemAddSubItem.setColors(-328966, -328966);
        this.menuItem.addSubItem(4, R.drawable.msg_message, LocaleController.getString("ShowInChat", R.string.ShowInChat)).setColors(-328966, -328966);
        this.menuItem.addSubItem(10, R.drawable.msg_shareout, LocaleController.getString("ShareFile", R.string.ShareFile)).setColors(-328966, -328966);
        this.menuItem.addSubItem(1, R.drawable.msg_gallery, LocaleController.getString("SaveToGallery", R.string.SaveToGallery)).setColors(-328966, -328966);
        this.menuItem.addSubItem(6, R.drawable.msg_delete, LocaleController.getString("Delete", R.string.Delete)).setColors(-328966, -328966);
        this.menuItem.addSubItem(7, R.drawable.msg_cancel, LocaleController.getString("StopDownload", R.string.StopDownload)).setColors(-328966, -328966);
        this.menuItem.redrawPopup(-115203550);
        this.sendItem.setContentDescription(LocaleController.getString("Forward", R.string.Forward));
        FrameLayout frameLayout = new FrameLayout(this.actvityContext);
        this.bottomLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.containerView.addView(this.bottomLayout, LayoutHelper.createFrame(-1, 48, 83));
        GroupedPhotosListView groupedPhotosListView = new GroupedPhotosListView(this.actvityContext);
        this.groupedPhotosListView = groupedPhotosListView;
        this.containerView.addView(groupedPhotosListView, LayoutHelper.createFrame(-1.0f, 62.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
        this.groupedPhotosListView.setDelegate(new GroupedPhotosListView.GroupedPhotosListViewDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.8
            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getCurrentIndex() {
                return PhotoViewer.this.currentIndex;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getCurrentAccount() {
                return PhotoViewer.this.currentAccount;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getAvatarsDialogId() {
                return PhotoViewer.this.avatarsDialogId;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getSlideshowMessageId() {
                return PhotoViewer.this.slideshowMessageId;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<ImageLocation> getImagesArrLocations() {
                return PhotoViewer.this.imagesArrLocations;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<MessageObject> getImagesArr() {
                return PhotoViewer.this.imagesArr;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<TLRPC.PageBlock> getPageBlockArr() {
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public Object getParentObject() {
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public void setCurrentIndex(int index) {
                PhotoViewer.this.currentIndex = -1;
                if (PhotoViewer.this.currentThumb != null) {
                    PhotoViewer.this.currentThumb.release();
                    PhotoViewer.this.currentThumb = null;
                }
                PhotoViewer.this.setImageIndex(index, true);
            }
        });
        this.captionTextView = createCaptionTextView();
        this.switchCaptionTextView = createCaptionTextView();
        for (int i3 = 0; i3 < 3; i3++) {
            this.photoProgressViews[i3] = new PhotoProgressView(this.containerView.getContext(), this.containerView);
            this.photoProgressViews[i3].setBackgroundState(0, false);
        }
        RadialProgressView radialProgressView = new RadialProgressView(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.9
            @Override // im.uwrkaxlmjj.ui.components.RadialProgressView, android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                if (PhotoViewer.this.containerView != null) {
                    PhotoViewer.this.containerView.invalidate();
                }
            }

            @Override // android.view.View
            public void invalidate() {
                super.invalidate();
                if (PhotoViewer.this.containerView != null) {
                    PhotoViewer.this.containerView.invalidate();
                }
            }
        };
        this.miniProgressView = radialProgressView;
        radialProgressView.setUseSelfAlpha(true);
        this.miniProgressView.setProgressColor(-1);
        this.miniProgressView.setSize(AndroidUtilities.dp(54.0f));
        this.miniProgressView.setBackgroundResource(R.drawable.circle_big);
        this.miniProgressView.setVisibility(4);
        this.miniProgressView.setAlpha(0.0f);
        this.containerView.addView(this.miniProgressView, LayoutHelper.createFrame(64, 64, 17));
        ImageView imageView = new ImageView(this.containerView.getContext());
        this.shareButton = imageView;
        imageView.setImageResource(R.drawable.share);
        this.shareButton.setScaleType(ImageView.ScaleType.CENTER);
        this.shareButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.bottomLayout.addView(this.shareButton, LayoutHelper.createFrame(50, -1, 53));
        this.shareButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$soF9Itk7OJyJmhrelYOIynoEId8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$2$PhotoViewer(view);
            }
        });
        this.shareButton.setContentDescription(LocaleController.getString("ShareFile", R.string.ShareFile));
        TextView textView = new TextView(this.containerView.getContext());
        this.nameTextView = textView;
        textView.setTextSize(1, 14.0f);
        this.nameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.nameTextView.setSingleLine(true);
        this.nameTextView.setMaxLines(1);
        this.nameTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.nameTextView.setTextColor(-1);
        this.nameTextView.setGravity(3);
        this.bottomLayout.addView(this.nameTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 16.0f, 5.0f, 60.0f, 0.0f));
        TextView textView2 = new TextView(this.containerView.getContext());
        this.dateTextView = textView2;
        textView2.setTextSize(1, 13.0f);
        this.dateTextView.setSingleLine(true);
        this.dateTextView.setMaxLines(1);
        this.dateTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.dateTextView.setTextColor(-1);
        this.dateTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.dateTextView.setGravity(3);
        this.bottomLayout.addView(this.dateTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 16.0f, 25.0f, 50.0f, 0.0f));
        createVideoControlsInterface();
        RadialProgressView radialProgressView2 = new RadialProgressView(this.parentActivity);
        this.progressView = radialProgressView2;
        radialProgressView2.setProgressColor(-1);
        this.progressView.setBackgroundResource(R.drawable.circle_big);
        this.progressView.setVisibility(4);
        this.containerView.addView(this.progressView, LayoutHelper.createFrame(54, 54, 17));
        PickerBottomLayoutViewer pickerBottomLayoutViewer = new PickerBottomLayoutViewer(this.parentActivity);
        this.qualityPicker = pickerBottomLayoutViewer;
        pickerBottomLayoutViewer.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.qualityPicker.updateSelectedCount(0, false);
        this.qualityPicker.setTranslationY(AndroidUtilities.dp(120.0f));
        this.qualityPicker.doneButton.setText(LocaleController.getString("Done", R.string.Done).toUpperCase());
        this.containerView.addView(this.qualityPicker, LayoutHelper.createFrame(-1, 48, 83));
        this.qualityPicker.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$fijcGZqK9XqZLKxKycju7L_EAgA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$3$PhotoViewer(view);
            }
        });
        this.qualityPicker.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$FfofpgoXbSvazWvgmYG_BYZWATs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$4$PhotoViewer(view);
            }
        });
        VideoForwardDrawable videoForwardDrawable = new VideoForwardDrawable();
        this.videoForwardDrawable = videoForwardDrawable;
        videoForwardDrawable.setDelegate(new VideoForwardDrawable.VideoForwardDrawableDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.10
            @Override // im.uwrkaxlmjj.ui.components.VideoForwardDrawable.VideoForwardDrawableDelegate
            public void onAnimationEnd() {
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoForwardDrawable.VideoForwardDrawableDelegate
            public void invalidate() {
                PhotoViewer.this.containerView.invalidate();
            }
        });
        QualityChooseView qualityChooseView = new QualityChooseView(this.parentActivity);
        this.qualityChooseView = qualityChooseView;
        qualityChooseView.setTranslationY(AndroidUtilities.dp(120.0f));
        this.qualityChooseView.setVisibility(4);
        this.qualityChooseView.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.containerView.addView(this.qualityChooseView, LayoutHelper.createFrame(-1.0f, 70.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
        FrameLayout frameLayout2 = new FrameLayout(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.11
            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                return PhotoViewer.this.bottomTouchEnabled && super.dispatchTouchEvent(ev);
            }

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                return PhotoViewer.this.bottomTouchEnabled && super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return PhotoViewer.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.pickerView = frameLayout2;
        frameLayout2.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.containerView.addView(this.pickerView, LayoutHelper.createFrame(-1, -2, 83));
        VideoTimelinePlayView videoTimelinePlayView = new VideoTimelinePlayView(this.parentActivity);
        this.videoTimelineView = videoTimelinePlayView;
        videoTimelinePlayView.setDelegate(new VideoTimelinePlayView.VideoTimelineViewDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.12
            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void onLeftProgressChanged(float progress) {
                if (PhotoViewer.this.videoPlayer != null) {
                    if (PhotoViewer.this.videoPlayer.isPlaying()) {
                        PhotoViewer.this.videoPlayer.pause();
                        PhotoViewer.this.containerView.invalidate();
                    }
                    PhotoViewer.this.videoPlayer.seekTo((int) (PhotoViewer.this.videoDuration * progress));
                    PhotoViewer.this.videoPlayerSeekbar.setProgress(0.0f);
                    PhotoViewer.this.videoTimelineView.setProgress(0.0f);
                    PhotoViewer.this.updateVideoInfo();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void onRightProgressChanged(float progress) {
                if (PhotoViewer.this.videoPlayer != null) {
                    if (PhotoViewer.this.videoPlayer.isPlaying()) {
                        PhotoViewer.this.videoPlayer.pause();
                        PhotoViewer.this.containerView.invalidate();
                    }
                    PhotoViewer.this.videoPlayer.seekTo((int) (PhotoViewer.this.videoDuration * progress));
                    PhotoViewer.this.videoPlayerSeekbar.setProgress(1.0f);
                    PhotoViewer.this.videoTimelineView.setProgress(1.0f);
                    PhotoViewer.this.updateVideoInfo();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void onPlayProgressChanged(float progress) {
                if (PhotoViewer.this.videoPlayer != null) {
                    PhotoViewer.this.videoPlayer.seekTo((int) (PhotoViewer.this.videoDuration * progress));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void didStartDragging() {
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void didStopDragging() {
            }
        });
        this.pickerView.addView(this.videoTimelineView, LayoutHelper.createFrame(-1.0f, 58.0f, 51, 0.0f, 8.0f, 0.0f, 88.0f));
        ImageView imageView2 = new ImageView(this.parentActivity) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.13
            @Override // android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                return PhotoViewer.this.bottomTouchEnabled && super.dispatchTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return PhotoViewer.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.pickerViewSendButton = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        this.pickerViewSendButton.setBackgroundDrawable(Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), -10043398, -10043398));
        this.pickerViewSendButton.setColorFilter(new PorterDuffColorFilter(-1, PorterDuff.Mode.MULTIPLY));
        this.pickerViewSendButton.setImageResource(R.drawable.attach_send);
        this.containerView.addView(this.pickerViewSendButton, LayoutHelper.createFrame(56.0f, 56.0f, 85, 0.0f, 0.0f, 14.0f, 14.0f));
        this.pickerViewSendButton.setContentDescription(LocaleController.getString("Send", R.string.Send));
        this.pickerViewSendButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$VHB29qz15wnRKl_oK12JtEtUy2E
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$5$PhotoViewer(view);
            }
        });
        this.pickerViewSendButton.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$sQ993VhrNxgq7K-LqiCiODzMJLo
            @Override // android.view.View.OnLongClickListener
            public final boolean onLongClick(View view) {
                return this.f$0.lambda$setParentActivity$8$PhotoViewer(view);
            }
        });
        LinearLayout linearLayout = new LinearLayout(this.parentActivity);
        linearLayout.setOrientation(0);
        this.pickerView.addView(linearLayout, LayoutHelper.createFrame(-2.0f, 48.0f, 81, 0.0f, 0.0f, 34.0f, 0.0f));
        ImageView imageView3 = new ImageView(this.parentActivity);
        this.cropItem = imageView3;
        imageView3.setScaleType(ImageView.ScaleType.CENTER);
        this.cropItem.setImageResource(R.drawable.photo_crop);
        this.cropItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.cropItem, LayoutHelper.createLinear(70, 48));
        this.cropItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$DpenQCgBlkctuzmGO5b40xI_8DQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.lambda$setParentActivity$9$PhotoViewer(view);
            }
        });
        this.cropItem.setContentDescription(LocaleController.getString("CropImage", R.string.CropImage));
        ImageView imageView4 = new ImageView(this.parentActivity);
        this.rotateItem = imageView4;
        imageView4.setScaleType(ImageView.ScaleType.CENTER);
        this.rotateItem.setImageResource(R.drawable.tool_rotate);
        this.rotateItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.rotateItem, LayoutHelper.createLinear(70, 48));
        this.rotateItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$cbVwZx-Jr6TPz88tfX-CHFyiWQE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$10$PhotoViewer(view);
            }
        });
        this.rotateItem.setContentDescription(LocaleController.getString("AccDescrRotate", R.string.AccDescrRotate));
        ImageView imageView5 = new ImageView(this.parentActivity);
        this.paintItem = imageView5;
        imageView5.setScaleType(ImageView.ScaleType.CENTER);
        this.paintItem.setImageResource(R.drawable.photo_paint);
        this.paintItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.paintItem, LayoutHelper.createLinear(70, 48));
        this.paintItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$RRe13Si1W1rCgtMa5MYITQ8p_P8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.lambda$setParentActivity$11$PhotoViewer(view);
            }
        });
        this.paintItem.setContentDescription(LocaleController.getString("AccDescrPhotoEditor", R.string.AccDescrPhotoEditor));
        ImageView imageView6 = new ImageView(this.parentActivity);
        this.compressItem = imageView6;
        imageView6.setTag(1);
        this.compressItem.setScaleType(ImageView.ScaleType.CENTER);
        this.compressItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        int i4 = MessagesController.getGlobalMainSettings().getInt("compress_video2", 1);
        this.selectedCompression = i4;
        if (i4 <= 0) {
            this.compressItem.setImageResource(R.drawable.video_240);
        } else if (i4 == 1) {
            this.compressItem.setImageResource(R.drawable.video_360);
        } else if (i4 == 2) {
            this.compressItem.setImageResource(R.drawable.video_480);
        } else if (i4 == 3) {
            this.compressItem.setImageResource(R.drawable.video_720);
        } else if (i4 == 4) {
            this.compressItem.setImageResource(R.drawable.video_1080);
        }
        linearLayout.addView(this.compressItem, LayoutHelper.createLinear(70, 48));
        this.compressItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$AC_DZzcVtwQGHngAtXSMMjTT-k0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$12$PhotoViewer(view);
            }
        });
        this.compressItem.setContentDescription(LocaleController.getString("AccDescrVideoQuality", R.string.AccDescrVideoQuality) + ", " + new String[]{"240", "360", "480", "720", "1080"}[Math.max(0, this.selectedCompression)]);
        ImageView imageView7 = new ImageView(this.parentActivity);
        this.muteItem = imageView7;
        imageView7.setScaleType(ImageView.ScaleType.CENTER);
        this.muteItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.muteItem, LayoutHelper.createLinear(70, 48));
        this.muteItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$5mOl_PSxDJIs8rymHOhZ3IPm-qQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$13$PhotoViewer(view);
            }
        });
        ImageView imageView8 = new ImageView(this.parentActivity);
        this.cameraItem = imageView8;
        imageView8.setScaleType(ImageView.ScaleType.CENTER);
        this.cameraItem.setImageResource(R.drawable.photo_add);
        this.cameraItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.cameraItem.setContentDescription(LocaleController.getString("AccDescrTakeMorePics", R.string.AccDescrTakeMorePics));
        this.containerView.addView(this.cameraItem, LayoutHelper.createFrame(48.0f, 48.0f, 85, 0.0f, 0.0f, 16.0f, 0.0f));
        this.cameraItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$WnWEjOhEouehzd5G6_X0efC5KOA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$14$PhotoViewer(view);
            }
        });
        ImageView imageView9 = new ImageView(this.parentActivity);
        this.tuneItem = imageView9;
        imageView9.setScaleType(ImageView.ScaleType.CENTER);
        this.tuneItem.setImageResource(R.drawable.photo_tools);
        this.tuneItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        linearLayout.addView(this.tuneItem, LayoutHelper.createLinear(70, 48));
        this.tuneItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$0JTpirLZEdbeTe0UFLKxJ6QySvQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.lambda$setParentActivity$15$PhotoViewer(view);
            }
        });
        this.tuneItem.setContentDescription(LocaleController.getString("AccDescrPhotoAdjust", R.string.AccDescrPhotoAdjust));
        ImageView imageView10 = new ImageView(this.parentActivity);
        this.timeItem = imageView10;
        imageView10.setScaleType(ImageView.ScaleType.CENTER);
        this.timeItem.setImageResource(R.drawable.photo_timer);
        this.timeItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.timeItem.setContentDescription(LocaleController.getString("SetTimer", R.string.SetTimer));
        linearLayout.addView(this.timeItem, LayoutHelper.createLinear(70, 48));
        this.timeItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$YbMCXh5RNeqAqrGdGEXqxuUQr_U
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$21$PhotoViewer(view);
            }
        });
        PickerBottomLayoutViewer pickerBottomLayoutViewer2 = new PickerBottomLayoutViewer(this.actvityContext);
        this.editorDoneLayout = pickerBottomLayoutViewer2;
        pickerBottomLayoutViewer2.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.editorDoneLayout.updateSelectedCount(0, false);
        this.editorDoneLayout.setVisibility(8);
        this.containerView.addView(this.editorDoneLayout, LayoutHelper.createFrame(-1, 48, 83));
        this.editorDoneLayout.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$hUjqA9OGfC1BlpktzEBq133o8Jo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.lambda$setParentActivity$22$PhotoViewer(view);
            }
        });
        this.editorDoneLayout.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$esMbPc3siZM0cfRNvo48pYzxVNk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.lambda$setParentActivity$23$PhotoViewer(view);
            }
        });
        TextView textView3 = new TextView(this.actvityContext);
        this.resetButton = textView3;
        textView3.setVisibility(8);
        this.resetButton.setTextSize(1, 14.0f);
        this.resetButton.setTextColor(-1);
        this.resetButton.setGravity(17);
        this.resetButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, 0));
        this.resetButton.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.resetButton.setText(LocaleController.getString("Reset", R.string.CropReset).toUpperCase());
        this.resetButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.editorDoneLayout.addView(this.resetButton, LayoutHelper.createFrame(-2, -1, 49));
        this.resetButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$UA7aAxC6x2FD0ezCfeoA6yuXu68
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$24$PhotoViewer(view);
            }
        });
        this.gestureDetector = new GestureDetector(this.containerView.getContext(), this);
        setDoubleTapEnabled(true);
        ImageReceiver.ImageReceiverDelegate imageReceiverDelegate = new ImageReceiver.ImageReceiverDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$3gGOjMi2gO-lWH4iPj5FTtTP2t8
            @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
            public final void didSetImage(ImageReceiver imageReceiver, boolean z, boolean z2) {
                this.f$0.lambda$setParentActivity$25$PhotoViewer(imageReceiver, z, z2);
            }

            @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
            public /* synthetic */ void onAnimationReady(ImageReceiver imageReceiver) {
                ImageReceiver.ImageReceiverDelegate.CC.$default$onAnimationReady(this, imageReceiver);
            }
        };
        this.centerImage.setParentView(this.containerView);
        this.centerImage.setCrossfadeAlpha((byte) 2);
        this.centerImage.setInvalidateAll(true);
        this.centerImage.setDelegate(imageReceiverDelegate);
        this.leftImage.setParentView(this.containerView);
        this.leftImage.setCrossfadeAlpha((byte) 2);
        this.leftImage.setInvalidateAll(true);
        this.leftImage.setDelegate(imageReceiverDelegate);
        this.rightImage.setParentView(this.containerView);
        this.rightImage.setCrossfadeAlpha((byte) 2);
        this.rightImage.setInvalidateAll(true);
        this.rightImage.setDelegate(imageReceiverDelegate);
        int rotation = ((WindowManager) ApplicationLoader.applicationContext.getSystemService("window")).getDefaultDisplay().getRotation();
        CheckBox checkBox = new CheckBox(this.containerView.getContext(), R.drawable.selectphoto_large) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.16
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return PhotoViewer.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.checkImageView = checkBox;
        checkBox.setDrawBackground(true);
        this.checkImageView.setHasBorder(true);
        this.checkImageView.setSize(40);
        this.checkImageView.setCheckOffset(AndroidUtilities.dp(1.0f));
        this.checkImageView.setColor(-10043398, -1);
        this.checkImageView.setVisibility(8);
        this.containerView.addView(this.checkImageView, LayoutHelper.createFrame(40.0f, 40.0f, 53, 0.0f, (rotation == 3 || rotation == 1) ? 58.0f : 68.0f, 10.0f, 0.0f));
        if (Build.VERSION.SDK_INT >= 21) {
            ((FrameLayout.LayoutParams) this.checkImageView.getLayoutParams()).topMargin += AndroidUtilities.statusBarHeight;
        }
        this.checkImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$lX0jFUrOrpFoDKEjSJhIR-hKsVY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$26$PhotoViewer(view);
            }
        });
        CounterView counterView = new CounterView(this.parentActivity);
        this.photosCounterView = counterView;
        this.containerView.addView(counterView, LayoutHelper.createFrame(40.0f, 40.0f, 53, 0.0f, (rotation == 3 || rotation == 1) ? 58.0f : 68.0f, 66.0f, 0.0f));
        if (Build.VERSION.SDK_INT >= 21) {
            ((FrameLayout.LayoutParams) this.photosCounterView.getLayoutParams()).topMargin += AndroidUtilities.statusBarHeight;
        }
        this.photosCounterView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$ecGoRT672ipsgaGRil68VCMOxeE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$27$PhotoViewer(view);
            }
        });
        RecyclerListView recyclerListView = new RecyclerListView(this.parentActivity);
        this.selectedPhotosListView = recyclerListView;
        recyclerListView.setVisibility(8);
        this.selectedPhotosListView.setAlpha(0.0f);
        this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
        this.selectedPhotosListView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.17
            @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
            public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
                int position = parent.getChildAdapterPosition(view);
                if ((view instanceof PhotoPickerPhotoCell) && position == 0) {
                    outRect.left = AndroidUtilities.dp(3.0f);
                } else {
                    outRect.left = 0;
                }
                outRect.right = AndroidUtilities.dp(3.0f);
            }
        });
        ((DefaultItemAnimator) this.selectedPhotosListView.getItemAnimator()).setDelayAnimations(false);
        this.selectedPhotosListView.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.selectedPhotosListView.setPadding(0, AndroidUtilities.dp(3.0f), 0, AndroidUtilities.dp(3.0f));
        this.selectedPhotosListView.setLayoutManager(new LinearLayoutManager(this.parentActivity, i2, null == true ? 1 : 0) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.18
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public void smoothScrollToPosition(RecyclerView recyclerView, RecyclerView.State state, int position) {
                LinearSmoothScrollerEnd linearSmoothScroller = new LinearSmoothScrollerEnd(recyclerView.getContext());
                linearSmoothScroller.setTargetPosition(position);
                startSmoothScroll(linearSmoothScroller);
            }
        });
        RecyclerListView recyclerListView2 = this.selectedPhotosListView;
        ListAdapter listAdapter = new ListAdapter(this.parentActivity);
        this.selectedPhotosAdapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.containerView.addView(this.selectedPhotosListView, LayoutHelper.createFrame(-1, 88, 51));
        this.selectedPhotosListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$nfU0Oni_BJRHaDnos6-shrcWSTc
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i5) {
                this.f$0.lambda$setParentActivity$28$PhotoViewer(view, i5);
            }
        });
        PhotoViewerCaptionEnterView photoViewerCaptionEnterView = new PhotoViewerCaptionEnterView(this.actvityContext, this.containerView, this.windowView) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.19
            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                try {
                    if (PhotoViewer.this.bottomTouchEnabled) {
                        return false;
                    }
                    return super.dispatchTouchEvent(ev);
                } catch (Exception e) {
                    FileLog.e(e);
                    return false;
                }
            }

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                try {
                    if (PhotoViewer.this.bottomTouchEnabled) {
                        return false;
                    }
                    return super.onInterceptTouchEvent(ev);
                } catch (Exception e) {
                    FileLog.e(e);
                    return false;
                }
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return !PhotoViewer.this.bottomTouchEnabled && super.onTouchEvent(event);
            }

            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView
            protected void extendActionMode(ActionMode actionMode, Menu menu) {
                if (PhotoViewer.this.parentChatActivity != null) {
                    PhotoViewer.this.parentChatActivity.extendActionMode(menu);
                }
            }
        };
        this.captionEditText = photoViewerCaptionEnterView;
        photoViewerCaptionEnterView.setDelegate(new PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.20
            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate
            public void onCaptionEnter() {
                PhotoViewer.this.closeCaptionEnter(true);
            }

            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate
            public void onTextChanged(CharSequence text) {
                if (PhotoViewer.this.mentionsAdapter != null && PhotoViewer.this.captionEditText != null && PhotoViewer.this.parentChatActivity != null && text != null) {
                    PhotoViewer.this.mentionsAdapter.searchUsernameOrHashtag(text.toString(), PhotoViewer.this.captionEditText.getCursorPosition(), PhotoViewer.this.parentChatActivity.messages, false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate
            public void onWindowSizeChanged(int size) {
                int height = AndroidUtilities.dp((Math.min(3, PhotoViewer.this.mentionsAdapter.getItemCount()) * 36) + (PhotoViewer.this.mentionsAdapter.getItemCount() > 3 ? 18 : 0));
                if (size - (ActionBar.getCurrentActionBarHeight() * 2) < height) {
                    PhotoViewer.this.allowMentions = false;
                    if (PhotoViewer.this.mentionListView != null && PhotoViewer.this.mentionListView.getVisibility() == 0) {
                        PhotoViewer.this.mentionListView.setVisibility(4);
                        return;
                    }
                    return;
                }
                PhotoViewer.this.allowMentions = true;
                if (PhotoViewer.this.mentionListView != null && PhotoViewer.this.mentionListView.getVisibility() == 4) {
                    PhotoViewer.this.mentionListView.setVisibility(0);
                }
            }
        });
        if (Build.VERSION.SDK_INT >= 19) {
            this.captionEditText.setImportantForAccessibility(4);
        }
        this.containerView.addView(this.captionEditText, LayoutHelper.createFrame(-1, -2, 83));
        RecyclerListView recyclerListView3 = new RecyclerListView(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.21
            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                return !PhotoViewer.this.bottomTouchEnabled && super.dispatchTouchEvent(ev);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                return !PhotoViewer.this.bottomTouchEnabled && super.onInterceptTouchEvent(ev);
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return !PhotoViewer.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.mentionListView = recyclerListView3;
        recyclerListView3.setTag(5);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.22
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.mentionLayoutManager = linearLayoutManager;
        linearLayoutManager.setOrientation(1);
        this.mentionListView.setLayoutManager(this.mentionLayoutManager);
        this.mentionListView.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.mentionListView.setVisibility(8);
        this.mentionListView.setClipToPadding(true);
        this.mentionListView.setOverScrollMode(2);
        this.containerView.addView(this.mentionListView, LayoutHelper.createFrame(-1, 110, 83));
        RecyclerListView recyclerListView4 = this.mentionListView;
        MentionsAdapter mentionsAdapter = new MentionsAdapter(this.actvityContext, true, 0L, new MentionsAdapter.MentionsAdapterDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.23
            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void needChangePanelVisibility(boolean show) {
                if (show) {
                    FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) PhotoViewer.this.mentionListView.getLayoutParams();
                    int height = (Math.min(3, PhotoViewer.this.mentionsAdapter.getItemCount()) * 36) + (PhotoViewer.this.mentionsAdapter.getItemCount() > 3 ? 18 : 0);
                    layoutParams3.height = AndroidUtilities.dp(height);
                    layoutParams3.topMargin = -AndroidUtilities.dp(height);
                    PhotoViewer.this.mentionListView.setLayoutParams(layoutParams3);
                    if (PhotoViewer.this.mentionListAnimation != null) {
                        PhotoViewer.this.mentionListAnimation.cancel();
                        PhotoViewer.this.mentionListAnimation = null;
                    }
                    if (PhotoViewer.this.mentionListView.getVisibility() == 0) {
                        PhotoViewer.this.mentionListView.setAlpha(1.0f);
                        return;
                    }
                    PhotoViewer.this.mentionLayoutManager.scrollToPositionWithOffset(0, 10000);
                    if (PhotoViewer.this.allowMentions) {
                        PhotoViewer.this.mentionListView.setVisibility(0);
                        PhotoViewer.this.mentionListAnimation = new AnimatorSet();
                        PhotoViewer.this.mentionListAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this.mentionListView, (Property<RecyclerListView, Float>) View.ALPHA, 0.0f, 1.0f));
                        PhotoViewer.this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.23.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (PhotoViewer.this.mentionListAnimation != null && PhotoViewer.this.mentionListAnimation.equals(animation)) {
                                    PhotoViewer.this.mentionListAnimation = null;
                                }
                            }
                        });
                        PhotoViewer.this.mentionListAnimation.setDuration(200L);
                        PhotoViewer.this.mentionListAnimation.start();
                        return;
                    }
                    PhotoViewer.this.mentionListView.setAlpha(1.0f);
                    PhotoViewer.this.mentionListView.setVisibility(4);
                    return;
                }
                if (PhotoViewer.this.mentionListAnimation != null) {
                    PhotoViewer.this.mentionListAnimation.cancel();
                    PhotoViewer.this.mentionListAnimation = null;
                }
                if (PhotoViewer.this.mentionListView.getVisibility() != 8) {
                    if (PhotoViewer.this.allowMentions) {
                        PhotoViewer.this.mentionListAnimation = new AnimatorSet();
                        PhotoViewer.this.mentionListAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this.mentionListView, (Property<RecyclerListView, Float>) View.ALPHA, 0.0f));
                        PhotoViewer.this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.23.2
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (PhotoViewer.this.mentionListAnimation != null && PhotoViewer.this.mentionListAnimation.equals(animation)) {
                                    PhotoViewer.this.mentionListView.setVisibility(8);
                                    PhotoViewer.this.mentionListAnimation = null;
                                }
                            }
                        });
                        PhotoViewer.this.mentionListAnimation.setDuration(200L);
                        PhotoViewer.this.mentionListAnimation.start();
                        return;
                    }
                    PhotoViewer.this.mentionListView.setVisibility(8);
                }
            }

            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void onContextSearch(boolean searching) {
            }

            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void onContextClick(TLRPC.BotInlineResult result) {
            }
        });
        this.mentionsAdapter = mentionsAdapter;
        recyclerListView4.setAdapter(mentionsAdapter);
        this.mentionListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$CgdfNNsWzw8bJVvBzaYGrUjw2kM
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i5) {
                this.f$0.lambda$setParentActivity$29$PhotoViewer(view, i5);
            }
        });
        this.mentionListView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$0PNxaKtOy7DPUl83CQ2qha0S8EU
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i5) {
                return this.f$0.lambda$setParentActivity$31$PhotoViewer(view, i5);
            }
        });
        if (((AccessibilityManager) this.actvityContext.getSystemService("accessibility")).isEnabled()) {
            View view = new View(this.actvityContext);
            this.playButtonAccessibilityOverlay = view;
            view.setContentDescription(LocaleController.getString("AccActionPlay", R.string.AccActionPlay));
            this.playButtonAccessibilityOverlay.setFocusable(true);
            this.containerView.addView(this.playButtonAccessibilityOverlay, LayoutHelper.createFrame(64, 64, 17));
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$5, reason: invalid class name */
    class AnonymousClass5 extends FrameLayout {
        private Runnable attachRunnable;

        AnonymousClass5(Context arg0) {
            super(arg0);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            return PhotoViewer.this.isVisible && super.onInterceptTouchEvent(ev);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return PhotoViewer.this.isVisible && PhotoViewer.this.onTouchEvent(event);
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            boolean result;
            try {
                result = super.drawChild(canvas, child, drawingTime);
            } catch (Throwable th) {
                result = false;
            }
            if (Build.VERSION.SDK_INT >= 21 && child == PhotoViewer.this.animatingImageView && PhotoViewer.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) PhotoViewer.this.lastInsets;
                canvas.drawRect(0.0f, getMeasuredHeight(), getMeasuredWidth(), getMeasuredHeight() + insets.getSystemWindowInsetBottom(), PhotoViewer.this.blackPaint);
            }
            return result;
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            if (Build.VERSION.SDK_INT >= 21 && PhotoViewer.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) PhotoViewer.this.lastInsets;
                if (AndroidUtilities.incorrectDisplaySizeFix) {
                    if (heightSize > AndroidUtilities.displaySize.y) {
                        heightSize = AndroidUtilities.displaySize.y;
                    }
                    heightSize += AndroidUtilities.statusBarHeight;
                }
                heightSize -= insets.getSystemWindowInsetBottom();
            } else if (heightSize > AndroidUtilities.displaySize.y) {
                heightSize = AndroidUtilities.displaySize.y;
            }
            setMeasuredDimension(widthSize, heightSize);
            ViewGroup.LayoutParams layoutParams = PhotoViewer.this.animatingImageView.getLayoutParams();
            PhotoViewer.this.animatingImageView.measure(View.MeasureSpec.makeMeasureSpec(layoutParams.width, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(layoutParams.height, Integer.MIN_VALUE));
            PhotoViewer.this.containerView.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            PhotoViewer.this.animatingImageView.layout(0, 0, PhotoViewer.this.animatingImageView.getMeasuredWidth() + 0, PhotoViewer.this.animatingImageView.getMeasuredHeight());
            PhotoViewer.this.containerView.layout(0, 0, PhotoViewer.this.containerView.getMeasuredWidth() + 0, PhotoViewer.this.containerView.getMeasuredHeight());
            PhotoViewer.this.wasLayout = true;
            if (changed) {
                if (!PhotoViewer.this.dontResetZoomOnFirstLayout) {
                    PhotoViewer.this.scale = 1.0f;
                    PhotoViewer.this.translationX = 0.0f;
                    PhotoViewer.this.translationY = 0.0f;
                    PhotoViewer photoViewer = PhotoViewer.this;
                    photoViewer.updateMinMax(photoViewer.scale);
                }
                if (PhotoViewer.this.checkImageView != null) {
                    PhotoViewer.this.checkImageView.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$5$fs40ALgoQQGGXJJNOZW1oikEwG8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onLayout$0$PhotoViewer$5();
                        }
                    });
                }
            }
            if (PhotoViewer.this.dontResetZoomOnFirstLayout) {
                PhotoViewer.this.setScaleToFill();
                PhotoViewer.this.dontResetZoomOnFirstLayout = false;
            }
        }

        public /* synthetic */ void lambda$onLayout$0$PhotoViewer$5() {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) PhotoViewer.this.checkImageView.getLayoutParams();
            WindowManager manager = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
            manager.getDefaultDisplay().getRotation();
            layoutParams.topMargin = ((ActionBar.getCurrentActionBarHeight() - AndroidUtilities.dp(40.0f)) / 2) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
            PhotoViewer.this.checkImageView.setLayoutParams(layoutParams);
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) PhotoViewer.this.photosCounterView.getLayoutParams();
            layoutParams2.topMargin = ((ActionBar.getCurrentActionBarHeight() - AndroidUtilities.dp(40.0f)) / 2) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
            PhotoViewer.this.photosCounterView.setLayoutParams(layoutParams2);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            PhotoViewer.this.attachedToWindow = true;
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            PhotoViewer.this.attachedToWindow = false;
            PhotoViewer.this.wasLayout = false;
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchKeyEventPreIme(KeyEvent event) {
            if (event != null && event.getKeyCode() == 4 && event.getAction() == 1) {
                if (PhotoViewer.this.captionEditText.isPopupShowing() || PhotoViewer.this.captionEditText.isKeyboardVisible()) {
                    PhotoViewer.this.closeCaptionEnter(false);
                    return false;
                }
                PhotoViewer.getInstance().closePhoto(true, false);
                return true;
            }
            return super.dispatchKeyEventPreIme(event);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (Build.VERSION.SDK_INT >= 21 && PhotoViewer.this.isVisible && PhotoViewer.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) PhotoViewer.this.lastInsets;
                if (PhotoViewer.this.animationInProgress == 1) {
                    PhotoViewer.this.blackPaint.setAlpha((int) (PhotoViewer.this.animatingImageView.getAnimationProgress() * 255.0f));
                } else if (PhotoViewer.this.animationInProgress == 3) {
                    PhotoViewer.this.blackPaint.setAlpha((int) ((1.0f - PhotoViewer.this.animatingImageView.getAnimationProgress()) * 255.0f));
                } else {
                    PhotoViewer.this.blackPaint.setAlpha(255);
                }
                canvas.drawRect(0.0f, getMeasuredHeight(), getMeasuredWidth(), getMeasuredHeight() + insets.getSystemWindowInsetBottom(), PhotoViewer.this.blackPaint);
            }
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public ActionMode startActionModeForChild(View originalView, ActionMode.Callback callback, int type) {
            if (Build.VERSION.SDK_INT >= 23) {
                View view = PhotoViewer.this.parentActivity.findViewById(android.R.id.content);
                if (view instanceof ViewGroup) {
                    try {
                        return ((ViewGroup) view).startActionModeForChild(originalView, callback, type);
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                }
            }
            return super.startActionModeForChild(originalView, callback, type);
        }
    }

    public /* synthetic */ WindowInsets lambda$setParentActivity$1$PhotoViewer(View v, WindowInsets insets) {
        WindowInsets oldInsets = (WindowInsets) this.lastInsets;
        this.lastInsets = insets;
        if (oldInsets == null || !oldInsets.toString().equals(insets.toString())) {
            int i = this.animationInProgress;
            if (i == 1 || i == 3) {
                ClippingImageView clippingImageView = this.animatingImageView;
                clippingImageView.setTranslationX(clippingImageView.getTranslationX() - getLeftInset());
                this.animationValues[0][2] = this.animatingImageView.getTranslationX();
            }
            this.windowView.requestLayout();
        }
        this.containerView.setPadding(insets.getSystemWindowInsetLeft(), 0, insets.getSystemWindowInsetRight(), 0);
        return insets.consumeSystemWindowInsets();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$7, reason: invalid class name */
    class AnonymousClass7 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass7() {
        }

        /* JADX WARN: Type inference fix 'apply assigned field type' failed
        java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
        	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
        	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
        	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
         */
        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            int lower_id;
            TLRPC.User currentUser;
            TLRPC.Chat currentChat;
            if (id == -1) {
                if (PhotoViewer.this.needCaptionLayout && (PhotoViewer.this.captionEditText.isPopupShowing() || PhotoViewer.this.captionEditText.isKeyboardVisible())) {
                    PhotoViewer.this.closeCaptionEnter(false);
                    return;
                } else {
                    PhotoViewer.this.closePhoto(true, false);
                    return;
                }
            }
            if (id == 1) {
                if (Build.VERSION.SDK_INT >= 23 && PhotoViewer.this.parentActivity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
                    PhotoViewer.this.parentActivity.requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 4);
                    return;
                }
                File f = null;
                if (PhotoViewer.this.currentMessageObject != null) {
                    if (!(PhotoViewer.this.currentMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) || PhotoViewer.this.currentMessageObject.messageOwner.media.webpage == null || PhotoViewer.this.currentMessageObject.messageOwner.media.webpage.document != null) {
                        f = FileLoader.getPathToMessage(PhotoViewer.this.currentMessageObject.messageOwner);
                    } else {
                        PhotoViewer photoViewer = PhotoViewer.this;
                        TLObject fileLocation = photoViewer.getFileLocation(photoViewer.currentIndex, null);
                        f = FileLoader.getPathToAttach(fileLocation, true);
                    }
                } else if (PhotoViewer.this.currentFileLocation != null) {
                    f = FileLoader.getPathToAttach(PhotoViewer.this.currentFileLocation.location, PhotoViewer.this.avatarsDialogId != 0 || PhotoViewer.this.isEvent);
                }
                if (f == null || !f.exists()) {
                    PhotoViewer.this.showDownloadAlert();
                    return;
                } else {
                    MediaController.saveFile(f.toString(), PhotoViewer.this.parentActivity, (PhotoViewer.this.currentMessageObject == null || !PhotoViewer.this.currentMessageObject.isVideo()) ? 0 : 1, null, null);
                    return;
                }
            }
            if (id == 2) {
                if (PhotoViewer.this.currentDialogId != 0) {
                    PhotoViewer.this.disableShowCheck = true;
                    Bundle args2 = new Bundle();
                    args2.putLong("dialog_id", PhotoViewer.this.currentDialogId);
                    MediaActivity mediaActivity = new MediaActivity(args2, new int[]{-1, -1, -1, -1, -1}, null, PhotoViewer.this.sharedMediaType);
                    if (PhotoViewer.this.parentChatActivity != null) {
                        mediaActivity.setChatInfo(PhotoViewer.this.parentChatActivity.getCurrentChatInfo());
                    }
                    PhotoViewer.this.closePhoto(false, false);
                    ((LaunchActivity) PhotoViewer.this.parentActivity).presentFragment(mediaActivity, false, true);
                    return;
                }
                return;
            }
            if (id == 4) {
                if (PhotoViewer.this.currentMessageObject == null) {
                    return;
                }
                Bundle args = new Bundle();
                int lower_part = (int) PhotoViewer.this.currentDialogId;
                int high_id = (int) (PhotoViewer.this.currentDialogId >> 32);
                if (lower_part != 0) {
                    if (lower_part > 0) {
                        args.putInt("user_id", lower_part);
                    } else if (lower_part < 0) {
                        TLRPC.Chat chat = MessagesController.getInstance(PhotoViewer.this.currentAccount).getChat(Integer.valueOf(-lower_part));
                        if (chat != null && chat.migrated_to != null) {
                            args.putInt("migrated_to", lower_part);
                            lower_part = -chat.migrated_to.channel_id;
                        }
                        args.putInt("chat_id", -lower_part);
                    }
                } else {
                    args.putInt("enc_id", high_id);
                }
                args.putInt("message_id", PhotoViewer.this.currentMessageObject.getId());
                NotificationCenter.getInstance(PhotoViewer.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
                LaunchActivity launchActivity = (LaunchActivity) PhotoViewer.this.parentActivity;
                boolean remove = launchActivity.getMainFragmentsCount() > 1 || AndroidUtilities.isTablet();
                launchActivity.presentFragment(new ChatActivity(args), remove, true);
                PhotoViewer.this.currentMessageObject = null;
                PhotoViewer.this.closePhoto(false, false);
                return;
            }
            if (id == 3) {
                if (PhotoViewer.this.currentMessageObject != null && PhotoViewer.this.parentActivity != null) {
                    ((LaunchActivity) PhotoViewer.this.parentActivity).switchToAccount(PhotoViewer.this.currentMessageObject.currentAccount, true);
                    Bundle args3 = new Bundle();
                    args3.putBoolean("onlySelect", true);
                    args3.putInt("dialogsType", 3);
                    DialogsActivity fragment = new DialogsActivity(args3);
                    final ArrayList<MessageObject> fmessages = new ArrayList<>();
                    fmessages.add(PhotoViewer.this.currentMessageObject);
                    fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$7$zSb8vAnIztZx_U1vHTrU0koUvUE
                        @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                        public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                            this.f$0.lambda$onItemClick$0$PhotoViewer$7(fmessages, dialogsActivity, arrayList, charSequence, z);
                        }
                    });
                    ((LaunchActivity) PhotoViewer.this.parentActivity).presentFragment(fragment, false, true);
                    PhotoViewer.this.closePhoto(false, false);
                    return;
                }
                return;
            }
            if (id == 6) {
                if (PhotoViewer.this.parentActivity == null || PhotoViewer.this.placeProvider == null) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(PhotoViewer.this.parentActivity);
                String text = PhotoViewer.this.placeProvider.getDeleteMessageString();
                if (text == null) {
                    if (PhotoViewer.this.currentMessageObject == null || !PhotoViewer.this.currentMessageObject.isVideo()) {
                        if (PhotoViewer.this.currentMessageObject != null && PhotoViewer.this.currentMessageObject.isGif()) {
                            builder.setMessage(LocaleController.formatString("AreYouSureDeleteGIF", R.string.AreYouSureDeleteGIF, new Object[0]));
                        } else {
                            builder.setMessage(LocaleController.formatString("AreYouSureDeletePhoto", R.string.AreYouSureDeletePhoto, new Object[0]));
                        }
                    } else {
                        builder.setMessage(LocaleController.formatString("AreYouSureDeleteVideo", R.string.AreYouSureDeleteVideo, new Object[0]));
                    }
                } else {
                    builder.setMessage(text);
                }
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                final boolean[] deleteForAll = new boolean[1];
                if (PhotoViewer.this.currentMessageObject != null && !PhotoViewer.this.currentMessageObject.scheduled && (lower_id = (int) PhotoViewer.this.currentMessageObject.getDialogId()) != 0) {
                    if (lower_id > 0) {
                        currentUser = MessagesController.getInstance(PhotoViewer.this.currentAccount).getUser(Integer.valueOf(lower_id));
                        currentChat = null;
                    } else {
                        currentUser = null;
                        currentChat = MessagesController.getInstance(PhotoViewer.this.currentAccount).getChat(Integer.valueOf(-lower_id));
                    }
                    if (currentUser != null || !ChatObject.isChannel(currentChat)) {
                        int currentDate = ConnectionsManager.getInstance(PhotoViewer.this.currentAccount).getCurrentTime();
                        int revokeTimeLimit = currentUser != null ? MessagesController.getInstance(PhotoViewer.this.currentAccount).revokeTimePmLimit : MessagesController.getInstance(PhotoViewer.this.currentAccount).revokeTimeLimit;
                        if (((currentUser != null && currentUser.id != UserConfig.getInstance(PhotoViewer.this.currentAccount).getClientUserId()) || currentChat != null) && ((PhotoViewer.this.currentMessageObject.messageOwner.action == null || (PhotoViewer.this.currentMessageObject.messageOwner.action instanceof TLRPC.TL_messageActionEmpty)) && PhotoViewer.this.currentMessageObject.isOut() && currentDate - PhotoViewer.this.currentMessageObject.messageOwner.date <= revokeTimeLimit)) {
                            FrameLayout frameLayout = new FrameLayout(PhotoViewer.this.parentActivity);
                            CheckBoxCell cell = new CheckBoxCell(PhotoViewer.this.parentActivity, 1);
                            cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                            if (currentChat != null) {
                                cell.setText(LocaleController.getString("DeleteForAll", R.string.DeleteForAll), "", false, false);
                            } else {
                                cell.setText(LocaleController.formatString("DeleteForUser", R.string.DeleteForUser, UserObject.getFirstName(currentUser)), "", false, false);
                            }
                            cell.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : AndroidUtilities.dp(8.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(8.0f) : AndroidUtilities.dp(16.0f), 0);
                            frameLayout.addView(cell, LayoutHelper.createFrame(-1.0f, 48.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$7$5VDrdcLQim4eiNbtZth6TplZl3k
                                @Override // android.view.View.OnClickListener
                                public final void onClick(View view) {
                                    PhotoViewer.AnonymousClass7.lambda$onItemClick$1(deleteForAll, view);
                                }
                            });
                            builder.setView(frameLayout);
                        }
                    }
                }
                builder.setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$7$FMzMHrCILSn5qqAnCstQkeOQDl0
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onItemClick$2$PhotoViewer$7(deleteForAll, dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                AlertDialog alertDialog = builder.create();
                PhotoViewer.this.showAlertDialog(builder);
                View button = alertDialog.getButton(-1);
                if (button instanceof TextView) {
                    ((TextView) button).setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
                    return;
                }
                return;
            }
            if (id == 10) {
                PhotoViewer.this.onSharePressed();
                return;
            }
            if (id == 11) {
                try {
                    AndroidUtilities.openForView(PhotoViewer.this.currentMessageObject, PhotoViewer.this.parentActivity);
                    PhotoViewer.this.closePhoto(false, false);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            if (id == 13) {
                if (PhotoViewer.this.parentActivity == null || PhotoViewer.this.currentMessageObject == null || PhotoViewer.this.currentMessageObject.messageOwner.media == null || PhotoViewer.this.currentMessageObject.messageOwner.media.photo == null) {
                    return;
                }
                StickersAlert stickersAlert = new StickersAlert(PhotoViewer.this.parentActivity, PhotoViewer.this.currentMessageObject, PhotoViewer.this.currentMessageObject.messageOwner.media.photo);
                stickersAlert.show();
                return;
            }
            if (id == 5) {
                if (PhotoViewer.this.pipItem.getAlpha() == 1.0f) {
                    PhotoViewer.this.switchToPip();
                }
            } else if (id == 7 && PhotoViewer.this.currentMessageObject != null) {
                FileLoader.getInstance(PhotoViewer.this.currentAccount).cancelLoadFile(PhotoViewer.this.currentMessageObject.getDocument());
                PhotoViewer.this.releasePlayer(false);
                PhotoViewer.this.bottomLayout.setTag(1);
                PhotoViewer.this.bottomLayout.setVisibility(0);
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$PhotoViewer$7(ArrayList fmessages, DialogsActivity fragment1, ArrayList dids, CharSequence message, boolean param) {
            if (dids.size() > 1 || ((Long) dids.get(0)).longValue() == UserConfig.getInstance(PhotoViewer.this.currentAccount).getClientUserId() || message != null) {
                for (int a = 0; a < dids.size(); a++) {
                    long did = ((Long) dids.get(a)).longValue();
                    if (message != null) {
                        SendMessagesHelper.getInstance(PhotoViewer.this.currentAccount).sendMessage(message.toString(), did, null, null, true, null, null, null, true, 0);
                    }
                    SendMessagesHelper.getInstance(PhotoViewer.this.currentAccount).sendMessage(fmessages, did, true, 0);
                }
                fragment1.finishFragment();
                return;
            }
            long did2 = ((Long) dids.get(0)).longValue();
            int lower_part = (int) did2;
            int high_part = (int) (did2 >> 32);
            Bundle args1 = new Bundle();
            args1.putBoolean("scrollToTopOnResume", true);
            if (lower_part != 0) {
                if (lower_part > 0) {
                    args1.putInt("user_id", lower_part);
                } else if (lower_part < 0) {
                    args1.putInt("chat_id", -lower_part);
                }
            } else {
                args1.putInt("enc_id", high_part);
            }
            NotificationCenter.getInstance(PhotoViewer.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            ChatActivity chatActivity = new ChatActivity(args1);
            if (((LaunchActivity) PhotoViewer.this.parentActivity).presentFragment(chatActivity, true, false)) {
                chatActivity.showFieldPanelForForward(true, fmessages);
            } else {
                fragment1.finishFragment();
            }
        }

        static /* synthetic */ void lambda$onItemClick$1(boolean[] deleteForAll, View v) {
            CheckBoxCell cell1 = (CheckBoxCell) v;
            deleteForAll[0] = !deleteForAll[0];
            cell1.setChecked(deleteForAll[0], true);
        }

        public /* synthetic */ void lambda$onItemClick$2$PhotoViewer$7(boolean[] deleteForAll, DialogInterface dialogInterface, int i) {
            ArrayList<Long> random_ids;
            TLRPC.EncryptedChat encryptedChat;
            if (!PhotoViewer.this.imagesArr.isEmpty()) {
                if (PhotoViewer.this.currentIndex >= 0 && PhotoViewer.this.currentIndex < PhotoViewer.this.imagesArr.size()) {
                    MessageObject obj = (MessageObject) PhotoViewer.this.imagesArr.get(PhotoViewer.this.currentIndex);
                    if (obj.isSent()) {
                        PhotoViewer.this.closePhoto(false, false);
                        ArrayList<Integer> arr = new ArrayList<>();
                        if (PhotoViewer.this.slideshowMessageId != 0) {
                            arr.add(Integer.valueOf(PhotoViewer.this.slideshowMessageId));
                        } else {
                            arr.add(Integer.valueOf(obj.getId()));
                        }
                        if (((int) obj.getDialogId()) == 0 && obj.messageOwner.random_id != 0) {
                            ArrayList<Long> random_ids2 = new ArrayList<>();
                            random_ids2.add(Long.valueOf(obj.messageOwner.random_id));
                            TLRPC.EncryptedChat encryptedChat2 = MessagesController.getInstance(PhotoViewer.this.currentAccount).getEncryptedChat(Integer.valueOf((int) (obj.getDialogId() >> 32)));
                            random_ids = random_ids2;
                            encryptedChat = encryptedChat2;
                        } else {
                            random_ids = null;
                            encryptedChat = null;
                        }
                        MessagesController.getInstance(PhotoViewer.this.currentAccount).deleteMessages(arr, random_ids, encryptedChat, obj.getDialogId(), obj.messageOwner.to_id.channel_id, deleteForAll[0], obj.scheduled);
                        return;
                    }
                    return;
                }
                return;
            }
            if (!PhotoViewer.this.avatarsArr.isEmpty()) {
                if (PhotoViewer.this.currentIndex >= 0 && PhotoViewer.this.currentIndex < PhotoViewer.this.avatarsArr.size()) {
                    TLRPC.Photo photo = (TLRPC.Photo) PhotoViewer.this.avatarsArr.get(PhotoViewer.this.currentIndex);
                    ImageLocation currentLocation = (ImageLocation) PhotoViewer.this.imagesArrLocations.get(PhotoViewer.this.currentIndex);
                    if (photo instanceof TLRPC.TL_photoEmpty) {
                        photo = null;
                    }
                    boolean current = false;
                    if (PhotoViewer.this.currentUserAvatarLocation != null) {
                        if (photo == null) {
                            if (currentLocation.location.local_id == PhotoViewer.this.currentUserAvatarLocation.location.local_id && currentLocation.location.volume_id == PhotoViewer.this.currentUserAvatarLocation.location.volume_id) {
                                current = true;
                            }
                        } else {
                            Iterator<TLRPC.PhotoSize> it = photo.sizes.iterator();
                            while (true) {
                                if (!it.hasNext()) {
                                    break;
                                }
                                TLRPC.PhotoSize size = it.next();
                                if (size.location.local_id == PhotoViewer.this.currentUserAvatarLocation.location.local_id && size.location.volume_id == PhotoViewer.this.currentUserAvatarLocation.location.volume_id) {
                                    current = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (current) {
                        MessagesController.getInstance(PhotoViewer.this.currentAccount).deleteUserPhoto(null);
                        PhotoViewer.this.closePhoto(false, false);
                        return;
                    }
                    if (photo != null) {
                        TLRPC.TL_inputPhoto inputPhoto = new TLRPC.TL_inputPhoto();
                        inputPhoto.id = photo.id;
                        inputPhoto.access_hash = photo.access_hash;
                        inputPhoto.file_reference = photo.file_reference;
                        if (inputPhoto.file_reference == null) {
                            inputPhoto.file_reference = new byte[0];
                        }
                        MessagesController.getInstance(PhotoViewer.this.currentAccount).deleteUserPhoto(inputPhoto);
                        MessagesStorage.getInstance(PhotoViewer.this.currentAccount).clearUserPhoto(PhotoViewer.this.avatarsDialogId, photo.id);
                        PhotoViewer.this.imagesArrLocations.remove(PhotoViewer.this.currentIndex);
                        PhotoViewer.this.imagesArrLocationsSizes.remove(PhotoViewer.this.currentIndex);
                        PhotoViewer.this.avatarsArr.remove(PhotoViewer.this.currentIndex);
                        if (!PhotoViewer.this.imagesArrLocations.isEmpty()) {
                            int index = PhotoViewer.this.currentIndex;
                            if (index >= PhotoViewer.this.avatarsArr.size()) {
                                index = PhotoViewer.this.avatarsArr.size() - 1;
                            }
                            PhotoViewer.this.currentIndex = -1;
                            PhotoViewer.this.setImageIndex(index, true);
                            return;
                        }
                        PhotoViewer.this.closePhoto(false, false);
                        return;
                    }
                    return;
                }
                return;
            }
            if (!PhotoViewer.this.secureDocuments.isEmpty() && PhotoViewer.this.placeProvider != null) {
                PhotoViewer.this.secureDocuments.remove(PhotoViewer.this.currentIndex);
                PhotoViewer.this.placeProvider.deleteImageAtIndex(PhotoViewer.this.currentIndex);
                if (!PhotoViewer.this.secureDocuments.isEmpty()) {
                    int index2 = PhotoViewer.this.currentIndex;
                    if (index2 >= PhotoViewer.this.secureDocuments.size()) {
                        index2 = PhotoViewer.this.secureDocuments.size() - 1;
                    }
                    PhotoViewer.this.currentIndex = -1;
                    PhotoViewer.this.setImageIndex(index2, true);
                    return;
                }
                PhotoViewer.this.closePhoto(false, false);
            }
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public boolean canOpenMenu() {
            if (PhotoViewer.this.currentMessageObject != null) {
                File f = FileLoader.getPathToMessage(PhotoViewer.this.currentMessageObject.messageOwner);
                return f.exists();
            }
            if (PhotoViewer.this.currentFileLocation == null) {
                return false;
            }
            PhotoViewer photoViewer = PhotoViewer.this;
            File f2 = FileLoader.getPathToAttach(photoViewer.getFileLocation(photoViewer.currentFileLocation), PhotoViewer.this.avatarsDialogId != 0 || PhotoViewer.this.isEvent);
            return f2.exists();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$2$PhotoViewer(View v) {
        onSharePressed();
    }

    public /* synthetic */ void lambda$setParentActivity$3$PhotoViewer(View view) {
        this.selectedCompression = this.previousCompression;
        didChangedCompressionLevel(false);
        showQualityView(false);
        requestVideoPreview(2);
    }

    public /* synthetic */ void lambda$setParentActivity$4$PhotoViewer(View view) {
        showQualityView(false);
        requestVideoPreview(2);
    }

    public /* synthetic */ void lambda$setParentActivity$5$PhotoViewer(View v) {
        ChatActivity chatActivity = this.parentChatActivity;
        if (chatActivity != null && chatActivity.isInScheduleMode() && !this.parentChatActivity.isEditingMessageMedia()) {
            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(this.parentChatActivity.getCurrentUser()), new $$Lambda$PhotoViewer$1AbJq_Bmo4eP2llPycO8mQRGlkU(this));
        } else {
            sendPressed(true, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00b1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ boolean lambda$setParentActivity$8$PhotoViewer(android.view.View r19) {
        /*
            Method dump skipped, instruction units count: 441
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PhotoViewer.lambda$setParentActivity$8$PhotoViewer(android.view.View):boolean");
    }

    public /* synthetic */ void lambda$null$6$PhotoViewer(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.sendPopupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.sendPopupWindow.dismiss();
        }
    }

    public /* synthetic */ void lambda$null$7$PhotoViewer(int num, TLRPC.User user, View v) {
        ActionBarPopupWindow actionBarPopupWindow = this.sendPopupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.sendPopupWindow.dismiss();
        }
        if (num == 0) {
            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(user), new $$Lambda$PhotoViewer$1AbJq_Bmo4eP2llPycO8mQRGlkU(this));
        } else if (num == 1) {
            sendPressed(false, 0);
        }
    }

    public /* synthetic */ void lambda$setParentActivity$9$PhotoViewer(View v) throws JSONException {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        switchToEditMode(1);
    }

    public /* synthetic */ void lambda$setParentActivity$10$PhotoViewer(View v) {
        PhotoCropView photoCropView = this.photoCropView;
        if (photoCropView == null) {
            return;
        }
        photoCropView.rotate();
    }

    public /* synthetic */ void lambda$setParentActivity$11$PhotoViewer(View v) throws JSONException {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        switchToEditMode(3);
    }

    public /* synthetic */ void lambda$setParentActivity$12$PhotoViewer(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        showQualityView(true);
        requestVideoPreview(1);
    }

    public /* synthetic */ void lambda$setParentActivity$13$PhotoViewer(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        this.muteVideo = !this.muteVideo;
        updateMuteButton();
        updateVideoInfo();
        if (this.muteVideo && !this.checkImageView.isChecked()) {
            this.checkImageView.callOnClick();
            return;
        }
        Object object = this.imagesArrLocals.get(this.currentIndex);
        if (object instanceof MediaController.PhotoEntry) {
            ((MediaController.PhotoEntry) object).editedInfo = getCurrentVideoEditedInfo();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$14$PhotoViewer(View v) {
        if (this.placeProvider == null || this.captionEditText.getTag() != null) {
            return;
        }
        this.placeProvider.needAddMorePhotos();
        closePhoto(true, false);
    }

    public /* synthetic */ void lambda$setParentActivity$15$PhotoViewer(View v) throws JSONException {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        switchToEditMode(2);
    }

    public /* synthetic */ void lambda$setParentActivity$21$PhotoViewer(View v) {
        int i;
        String str;
        int currentTTL;
        if (this.parentActivity == null || this.captionEditText.getTag() != null) {
            return;
        }
        BottomSheet.Builder builder = new BottomSheet.Builder(this.parentActivity);
        builder.setUseHardwareLayer(false);
        LinearLayout linearLayout = new LinearLayout(this.parentActivity);
        linearLayout.setOrientation(1);
        builder.setCustomView(linearLayout);
        TextView titleView = new TextView(this.parentActivity);
        titleView.setLines(1);
        titleView.setSingleLine(true);
        titleView.setText(LocaleController.getString("MessageLifetime", R.string.MessageLifetime));
        titleView.setTextColor(-1);
        titleView.setTextSize(1, 16.0f);
        titleView.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        titleView.setPadding(AndroidUtilities.dp(21.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(21.0f), AndroidUtilities.dp(4.0f));
        titleView.setGravity(16);
        linearLayout.addView(titleView, LayoutHelper.createFrame(-1, -2.0f));
        titleView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$ZABDv9T7Z2VSZEB5y4SVimLHQfw
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return PhotoViewer.lambda$null$16(view, motionEvent);
            }
        });
        TextView titleView2 = new TextView(this.parentActivity);
        if (this.isCurrentVideo) {
            i = R.string.MessageLifetimeVideo;
            str = "MessageLifetimeVideo";
        } else {
            i = R.string.MessageLifetimePhoto;
            str = "MessageLifetimePhoto";
        }
        titleView2.setText(LocaleController.getString(str, i));
        titleView2.setTextColor(-8355712);
        titleView2.setTextSize(1, 14.0f);
        titleView2.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        titleView2.setPadding(AndroidUtilities.dp(21.0f), 0, AndroidUtilities.dp(21.0f), AndroidUtilities.dp(8.0f));
        titleView2.setGravity(16);
        linearLayout.addView(titleView2, LayoutHelper.createFrame(-1, -2.0f));
        titleView2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$TV4L8UhEfbzYtae25EDTI2C3i5w
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return PhotoViewer.lambda$null$17(view, motionEvent);
            }
        });
        final BottomSheet bottomSheet = builder.create();
        final NumberPicker numberPicker = new NumberPicker(this.parentActivity);
        numberPicker.setMinValue(0);
        numberPicker.setMaxValue(28);
        Object object = this.imagesArrLocals.get(this.currentIndex);
        if (object instanceof MediaController.PhotoEntry) {
            currentTTL = ((MediaController.PhotoEntry) object).ttl;
        } else if (object instanceof MediaController.SearchImage) {
            currentTTL = ((MediaController.SearchImage) object).ttl;
        } else {
            currentTTL = 0;
        }
        if (currentTTL == 0) {
            SharedPreferences preferences1 = MessagesController.getGlobalMainSettings();
            numberPicker.setValue(preferences1.getInt("self_destruct", 7));
        } else if (currentTTL < 0 || currentTTL >= 21) {
            numberPicker.setValue(((currentTTL / 5) + 21) - 5);
        } else {
            numberPicker.setValue(currentTTL);
        }
        numberPicker.setTextColor(-1);
        numberPicker.setSelectorColor(-11711155);
        numberPicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$fowyUMDUR1B5huUbPSs8Y16j4Mk
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
            public final String format(int i2) {
                return PhotoViewer.lambda$null$18(i2);
            }
        });
        linearLayout.addView(numberPicker, LayoutHelper.createLinear(-1, -2));
        FrameLayout buttonsLayout = new FrameLayout(this.parentActivity) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.15
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                int count = getChildCount();
                View positiveButton = null;
                int width = right - left;
                for (int a = 0; a < count; a++) {
                    View child = getChildAt(a);
                    if (((Integer) child.getTag()).intValue() == -1) {
                        positiveButton = child;
                        child.layout((width - getPaddingRight()) - child.getMeasuredWidth(), getPaddingTop(), (width - getPaddingRight()) + child.getMeasuredWidth(), getPaddingTop() + child.getMeasuredHeight());
                    } else if (((Integer) child.getTag()).intValue() == -2) {
                        int x = (width - getPaddingRight()) - child.getMeasuredWidth();
                        if (positiveButton != null) {
                            x -= positiveButton.getMeasuredWidth() + AndroidUtilities.dp(8.0f);
                        }
                        child.layout(x, getPaddingTop(), child.getMeasuredWidth() + x, getPaddingTop() + child.getMeasuredHeight());
                    } else {
                        child.layout(getPaddingLeft(), getPaddingTop(), getPaddingLeft() + child.getMeasuredWidth(), getPaddingTop() + child.getMeasuredHeight());
                    }
                }
            }
        };
        buttonsLayout.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
        linearLayout.addView(buttonsLayout, LayoutHelper.createLinear(-1, 52));
        TextView textView = new TextView(this.parentActivity);
        textView.setMinWidth(AndroidUtilities.dp(64.0f));
        textView.setTag(-1);
        textView.setTextSize(1, 14.0f);
        textView.setTextColor(-11944718);
        textView.setGravity(17);
        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView.setText(LocaleController.getString("Done", R.string.Done).toUpperCase());
        textView.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(-11944718));
        textView.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
        buttonsLayout.addView(textView, LayoutHelper.createFrame(-2, 36, 53));
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$k_VbpPz9gPhYELaNwYPVKoOnMgY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$null$19$PhotoViewer(numberPicker, bottomSheet, view);
            }
        });
        TextView textView2 = new TextView(this.parentActivity);
        textView2.setMinWidth(AndroidUtilities.dp(64.0f));
        textView2.setTag(-2);
        textView2.setTextSize(1, 14.0f);
        textView2.setTextColor(-11944718);
        textView2.setGravity(17);
        textView2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView2.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        textView2.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(-11944718));
        textView2.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
        buttonsLayout.addView(textView2, LayoutHelper.createFrame(-2, 36, 53));
        textView2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$nYzjvoXuZhwuEntVFRQRmA9Zl5s
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                bottomSheet.dismiss();
            }
        });
        bottomSheet.show();
        bottomSheet.setBackgroundColor(-16777216);
    }

    static /* synthetic */ boolean lambda$null$16(View v13, MotionEvent event) {
        return true;
    }

    static /* synthetic */ boolean lambda$null$17(View v12, MotionEvent event) {
        return true;
    }

    static /* synthetic */ String lambda$null$18(int value) {
        if (value == 0) {
            return LocaleController.getString("ShortMessageLifetimeForever", R.string.ShortMessageLifetimeForever);
        }
        if (value >= 1 && value < 21) {
            return LocaleController.formatTTLString(value);
        }
        return LocaleController.formatTTLString((value - 16) * 5);
    }

    public /* synthetic */ void lambda$null$19$PhotoViewer(NumberPicker numberPicker, BottomSheet bottomSheet, View v1) {
        int seconds;
        int value = numberPicker.getValue();
        SharedPreferences preferences1 = MessagesController.getGlobalMainSettings();
        SharedPreferences.Editor editor = preferences1.edit();
        editor.putInt("self_destruct", value);
        editor.commit();
        bottomSheet.dismiss();
        if (value >= 0 && value < 21) {
            seconds = value;
        } else {
            int seconds2 = value - 16;
            seconds = seconds2 * 5;
        }
        Object object1 = this.imagesArrLocals.get(this.currentIndex);
        if (object1 instanceof MediaController.PhotoEntry) {
            ((MediaController.PhotoEntry) object1).ttl = seconds;
        } else if (object1 instanceof MediaController.SearchImage) {
            ((MediaController.SearchImage) object1).ttl = seconds;
        }
        this.timeItem.setColorFilter(seconds != 0 ? new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY) : null);
        if (!this.checkImageView.isChecked()) {
            this.checkImageView.callOnClick();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$22$PhotoViewer(View view) throws JSONException {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$setParentActivity$23$PhotoViewer(View view) throws JSONException {
        if (this.currentEditMode == 1 && !this.photoCropView.isReady()) {
            return;
        }
        applyCurrentEditMode();
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$setParentActivity$24$PhotoViewer(View v) {
        this.photoCropView.reset();
    }

    public /* synthetic */ void lambda$setParentActivity$25$PhotoViewer(ImageReceiver imageReceiver, boolean set, boolean thumb) {
        PhotoViewerProvider photoViewerProvider;
        Bitmap bitmap;
        if (imageReceiver == this.centerImage && set && !thumb && ((this.currentEditMode == 1 || this.sendPhotoType == 1) && this.photoCropView != null && (bitmap = imageReceiver.getBitmap()) != null)) {
            this.photoCropView.setBitmap(bitmap, imageReceiver.getOrientation(), this.sendPhotoType != 1, true);
        }
        if (imageReceiver == this.centerImage && set && (photoViewerProvider = this.placeProvider) != null && photoViewerProvider.scaleToFill() && !this.ignoreDidSetImage) {
            if (!this.wasLayout) {
                this.dontResetZoomOnFirstLayout = true;
            } else {
                setScaleToFill();
            }
        }
    }

    public /* synthetic */ void lambda$setParentActivity$26$PhotoViewer(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        setPhotoChecked();
    }

    public /* synthetic */ void lambda$setParentActivity$27$PhotoViewer(View v) {
        PhotoViewerProvider photoViewerProvider;
        if (this.captionEditText.getTag() != null || (photoViewerProvider = this.placeProvider) == null || photoViewerProvider.getSelectedPhotosOrder() == null || this.placeProvider.getSelectedPhotosOrder().isEmpty()) {
            return;
        }
        togglePhotosListView(!this.isPhotosListViewVisible, true);
    }

    public /* synthetic */ void lambda$setParentActivity$28$PhotoViewer(View view, int position) {
        this.ignoreDidSetImage = true;
        int idx = this.imagesArrLocals.indexOf(view.getTag());
        if (idx >= 0) {
            this.currentIndex = -1;
            setImageIndex(idx, true);
        }
        this.ignoreDidSetImage = false;
    }

    public /* synthetic */ void lambda$setParentActivity$29$PhotoViewer(View view, int position) {
        Object object = this.mentionsAdapter.getItem(position);
        int start = this.mentionsAdapter.getResultStartPosition();
        int len = this.mentionsAdapter.getResultLength();
        if (!(object instanceof TLRPC.User)) {
            if (object instanceof String) {
                this.captionEditText.replaceWithText(start, len, object + " ", false);
                return;
            }
            if (object instanceof MediaDataController.KeywordResult) {
                String code = ((MediaDataController.KeywordResult) object).emoji;
                this.captionEditText.addEmojiToRecent(code);
                this.captionEditText.replaceWithText(start, len, code, true);
                return;
            }
            return;
        }
        TLRPC.User user = (TLRPC.User) object;
        String name = UserObject.getName(user) + " ";
        if ("all".equals(name.trim()) && user.id == -1) {
            Spannable spannable = new SpannableString("@" + name);
            spannable.setSpan(new URLSpanUserMention("-1", 1), 0, spannable.length(), 33);
            spannable.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_chat_messagePanelMetionText)), 0, spannable.length(), 33);
            this.captionEditText.addMentionText1(start, len, spannable, false);
            return;
        }
        Spannable spannable2 = new SpannableString("@" + name);
        spannable2.setSpan(new URLSpanUserMention("" + user.id, 1), 0, spannable2.length(), 33);
        spannable2.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_chat_messagePanelMetionText)), 0, spannable2.length(), 33);
        this.captionEditText.addMentionText1(start, len, spannable2, false);
    }

    public /* synthetic */ boolean lambda$setParentActivity$31$PhotoViewer(View view, int position) {
        Object object = this.mentionsAdapter.getItem(position);
        if (object instanceof String) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this.parentActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("ClearSearch", R.string.ClearSearch));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$p7Avrm9wxVX7unKpElBxMXgylnk
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$30$PhotoViewer(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showAlertDialog(builder);
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$null$30$PhotoViewer(DialogInterface dialogInterface, int i) {
        this.mentionsAdapter.clearRecentHashtags();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendPressed(boolean notify, int scheduleDate) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        if (this.sendPhotoType == 1) {
            applyCurrentEditMode();
        }
        if (this.placeProvider != null && !this.doneButtonPressed) {
            ChatActivity chatActivity = this.parentChatActivity;
            if (chatActivity != null) {
                TLRPC.Chat chat = chatActivity.getCurrentChat();
                TLRPC.User user = this.parentChatActivity.getCurrentUser();
                if (user != null || ((ChatObject.isChannel(chat) && chat.megagroup) || !ChatObject.isChannel(chat))) {
                    MessagesController.getNotificationsSettings(this.currentAccount).edit().putBoolean("silent_" + this.parentChatActivity.getDialogId(), !notify).commit();
                }
            }
            VideoEditedInfo videoEditedInfo = getCurrentVideoEditedInfo();
            this.placeProvider.sendButtonPressed(this.currentIndex, videoEditedInfo, notify, scheduleDate);
            this.doneButtonPressed = true;
            closePhoto(false, false);
        }
    }

    private boolean checkInlinePermissions() {
        if (this.parentActivity == null) {
            return false;
        }
        if (Build.VERSION.SDK_INT < 23 || Settings.canDrawOverlays(this.parentActivity)) {
            return true;
        }
        new AlertDialog.Builder(this.parentActivity).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("PermissionDrawAboveOtherApps", R.string.PermissionDrawAboveOtherApps)).setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$wbpf8kG2kPmOlw4Cl8PCN-EKv5o
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$checkInlinePermissions$32$PhotoViewer(dialogInterface, i);
            }
        }).show();
        return false;
    }

    public /* synthetic */ void lambda$checkInlinePermissions$32$PhotoViewer(DialogInterface dialog, int which) {
        Activity activity = this.parentActivity;
        if (activity != null) {
            try {
                activity.startActivity(new Intent("android.settings.action.MANAGE_OVERLAY_PERMISSION", Uri.parse("package:" + this.parentActivity.getPackageName())));
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    private TextView createCaptionTextView() {
        TextView textView = new TextView(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.24
            @Override // android.widget.TextView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return PhotoViewer.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        textView.setMovementMethod(new LinkMovementMethodMy());
        textView.setPadding(AndroidUtilities.dp(20.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(20.0f), AndroidUtilities.dp(8.0f));
        textView.setLinkTextColor(-8994063);
        textView.setTextColor(-1);
        textView.setHighlightColor(872415231);
        textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
        textView.setTextSize(1, 16.0f);
        textView.setVisibility(4);
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$F-JLiBfsTkSlxVnup9OwUJSLFZw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createCaptionTextView$33$PhotoViewer(view);
            }
        });
        return textView;
    }

    public /* synthetic */ void lambda$createCaptionTextView$33$PhotoViewer(View v) {
        if (!this.needCaptionLayout) {
            return;
        }
        openCaptionEnter();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getLeftInset() {
        if (this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
            return ((WindowInsets) this.lastInsets).getSystemWindowInsetLeft();
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getRightInset() {
        if (this.lastInsets != null && Build.VERSION.SDK_INT >= 21) {
            return ((WindowInsets) this.lastInsets).getSystemWindowInsetRight();
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dismissInternal() {
        try {
            if (this.windowView.getParent() != null) {
                ((LaunchActivity) this.parentActivity).drawerLayoutContainer.setAllowDrawContent(true);
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeView(this.windowView);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void switchToPip() {
        if (this.videoPlayer == null || !this.textureUploaded || !checkInlinePermissions() || this.changingTextureView || this.switchingInlineMode || this.isInline) {
            return;
        }
        if (PipInstance != null) {
            PipInstance.destroyPhotoViewer();
        }
        this.openedFullScreenVideo = false;
        PipInstance = Instance;
        Instance = null;
        this.switchingInlineMode = true;
        this.isVisible = false;
        PlaceProviderObject placeProviderObject = this.currentPlaceObject;
        if (placeProviderObject != null) {
            placeProviderObject.imageReceiver.setVisible(true, true);
            AnimatedFileDrawable animation = this.currentPlaceObject.imageReceiver.getAnimation();
            if (animation != null) {
                Bitmap bitmap = animation.getAnimatedBitmap();
                if (bitmap != null) {
                    try {
                        Bitmap src = this.videoTextureView.getBitmap(bitmap.getWidth(), bitmap.getHeight());
                        Canvas canvas = new Canvas(bitmap);
                        canvas.drawBitmap(src, 0.0f, 0.0f, (Paint) null);
                        src.recycle();
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                }
                animation.seekTo(this.videoPlayer.getCurrentPosition(), true);
                this.currentPlaceObject.imageReceiver.setAllowStartAnimation(true);
                this.currentPlaceObject.imageReceiver.startAnimation();
            }
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.pipAnimationInProgress = true;
            im.uwrkaxlmjj.ui.components.Rect rect = PipVideoView.getPipRect(this.aspectRatioFrameLayout.getAspectRatio());
            float scale = rect.width / this.videoTextureView.getWidth();
            rect.y += AndroidUtilities.statusBarHeight;
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.playTogether(ObjectAnimator.ofFloat(this.textureImageView, (Property<ImageView, Float>) View.SCALE_X, scale), ObjectAnimator.ofFloat(this.textureImageView, (Property<ImageView, Float>) View.SCALE_Y, scale), ObjectAnimator.ofFloat(this.textureImageView, (Property<ImageView, Float>) View.TRANSLATION_X, rect.x), ObjectAnimator.ofFloat(this.textureImageView, (Property<ImageView, Float>) View.TRANSLATION_Y, rect.y), ObjectAnimator.ofFloat(this.videoTextureView, (Property<TextureView, Float>) View.SCALE_X, scale), ObjectAnimator.ofFloat(this.videoTextureView, (Property<TextureView, Float>) View.SCALE_Y, scale), ObjectAnimator.ofFloat(this.videoTextureView, (Property<TextureView, Float>) View.TRANSLATION_X, (rect.x - this.aspectRatioFrameLayout.getX()) + getLeftInset()), ObjectAnimator.ofFloat(this.videoTextureView, (Property<TextureView, Float>) View.TRANSLATION_Y, rect.y - this.aspectRatioFrameLayout.getY()), ObjectAnimator.ofInt(this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.groupedPhotosListView, (Property<GroupedPhotosListView, Float>) View.ALPHA, 0.0f));
            animatorSet.setInterpolator(new DecelerateInterpolator());
            animatorSet.setDuration(250L);
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.25
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation2) {
                    PhotoViewer.this.pipAnimationInProgress = false;
                    PhotoViewer.this.switchToInlineRunnable.run();
                }
            });
            animatorSet.start();
            return;
        }
        this.switchToInlineRunnable.run();
        dismissInternal();
    }

    public VideoPlayer getVideoPlayer() {
        return this.videoPlayer;
    }

    public void exitFromPip() {
        if (!this.isInline) {
            return;
        }
        if (Instance != null) {
            Instance.closePhoto(false, true);
        }
        Instance = PipInstance;
        PipInstance = null;
        this.switchingInlineMode = true;
        Bitmap bitmap = this.currentBitmap;
        if (bitmap != null) {
            bitmap.recycle();
            this.currentBitmap = null;
        }
        this.changingTextureView = true;
        this.isInline = false;
        this.videoTextureView.setVisibility(4);
        this.aspectRatioFrameLayout.addView(this.videoTextureView);
        if (ApplicationLoader.mainInterfacePaused) {
            try {
                this.parentActivity.startService(new Intent(ApplicationLoader.applicationContext, (Class<?>) BringAppForegroundService.class));
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.pipAnimationInProgress = true;
            im.uwrkaxlmjj.ui.components.Rect rect = PipVideoView.getPipRect(this.aspectRatioFrameLayout.getAspectRatio());
            float scale = rect.width / this.textureImageView.getLayoutParams().width;
            rect.y += AndroidUtilities.statusBarHeight;
            this.textureImageView.setScaleX(scale);
            this.textureImageView.setScaleY(scale);
            this.textureImageView.setTranslationX(rect.x);
            this.textureImageView.setTranslationY(rect.y);
            this.videoTextureView.setScaleX(scale);
            this.videoTextureView.setScaleY(scale);
            this.videoTextureView.setTranslationX(rect.x - this.aspectRatioFrameLayout.getX());
            this.videoTextureView.setTranslationY(rect.y - this.aspectRatioFrameLayout.getY());
        } else {
            this.pipVideoView.close();
            this.pipVideoView = null;
        }
        try {
            this.isVisible = true;
            WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
            wm.addView(this.windowView, this.windowLayoutParams);
            if (this.currentPlaceObject != null) {
                this.currentPlaceObject.imageReceiver.setVisible(false, false);
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.waitingForDraw = 4;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVideoSeekPreviewPosition() {
        int x = (this.videoPlayerSeekbar.getThumbX() + AndroidUtilities.dp(48.0f)) - (this.videoPreviewFrame.getMeasuredWidth() / 2);
        int min = AndroidUtilities.dp(10.0f);
        int max = (this.videoPlayerControlFrameLayout.getMeasuredWidth() - AndroidUtilities.dp(10.0f)) - (this.videoPreviewFrame.getMeasuredWidth() / 2);
        if (x < min) {
            x = min;
        } else if (x >= max) {
            x = max;
        }
        this.videoPreviewFrame.setTranslationX(x);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showVideoSeekPreviewPosition(boolean show) {
        if (!show || this.videoPreviewFrame.getTag() == null) {
            if (!show && this.videoPreviewFrame.getTag() == null) {
                return;
            }
            if (show && !this.videoPreviewFrame.isReady()) {
                this.needShowOnReady = show;
                return;
            }
            AnimatorSet animatorSet = this.videoPreviewFrameAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            this.videoPreviewFrame.setTag(show ? 1 : null);
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.videoPreviewFrameAnimation = animatorSet2;
            Animator[] animatorArr = new Animator[1];
            VideoSeekPreviewImage videoSeekPreviewImage = this.videoPreviewFrame;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(videoSeekPreviewImage, (Property<VideoSeekPreviewImage, Float>) property, fArr);
            animatorSet2.playTogether(animatorArr);
            this.videoPreviewFrameAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.26
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    PhotoViewer.this.videoPreviewFrameAnimation = null;
                }
            });
            this.videoPreviewFrameAnimation.setDuration(180L);
            this.videoPreviewFrameAnimation.start();
        }
    }

    private void createVideoControlsInterface() {
        SeekBar seekBar = new SeekBar(this.containerView.getContext());
        this.videoPlayerSeekbar = seekBar;
        seekBar.setLineHeight(AndroidUtilities.dp(4.0f));
        this.videoPlayerSeekbar.setColors(1728053247, 1728053247, -2764585, -1, -1);
        this.videoPlayerSeekbar.setDelegate(new SeekBar.SeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.27
            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public void onSeekBarDrag(float progress) {
                if (PhotoViewer.this.videoPlayer != null) {
                    if (!PhotoViewer.this.inPreview && PhotoViewer.this.videoTimelineView.getVisibility() == 0) {
                        progress = PhotoViewer.this.videoTimelineView.getLeftProgress() + ((PhotoViewer.this.videoTimelineView.getRightProgress() - PhotoViewer.this.videoTimelineView.getLeftProgress()) * progress);
                    }
                    long duration = PhotoViewer.this.videoPlayer.getDuration();
                    if (duration == C.TIME_UNSET) {
                        PhotoViewer.this.seekToProgressPending = progress;
                    } else {
                        PhotoViewer.this.videoPlayer.seekTo((int) (duration * progress));
                    }
                    PhotoViewer.this.showVideoSeekPreviewPosition(false);
                    PhotoViewer.this.needShowOnReady = false;
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public void onSeekBarContinuousDrag(float progress) {
                if (PhotoViewer.this.videoPlayer != null && PhotoViewer.this.videoPreviewFrame != null) {
                    PhotoViewer.this.videoPreviewFrame.setProgress(progress, PhotoViewer.this.videoPlayerSeekbar.getWidth());
                }
                PhotoViewer.this.showVideoSeekPreviewPosition(true);
                PhotoViewer.this.updateVideoSeekPreviewPosition();
            }
        });
        FrameLayout frameLayout = new FrameLayout(this.containerView.getContext()) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.28
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (!PhotoViewer.this.videoPlayerSeekbar.onTouch(event.getAction(), event.getX() - AndroidUtilities.dp(48.0f), event.getY())) {
                    return true;
                }
                getParent().requestDisallowInterceptTouchEvent(true);
                invalidate();
                return true;
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                long duration;
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                if (PhotoViewer.this.videoPlayer != null) {
                    duration = PhotoViewer.this.videoPlayer.getDuration();
                    if (duration == C.TIME_UNSET) {
                        duration = 0;
                    }
                } else {
                    duration = 0;
                }
                long duration2 = duration / 1000;
                int size = (int) Math.ceil(PhotoViewer.this.videoPlayerTime.getPaint().measureText(String.format("%02d:%02d / %02d:%02d", Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60), Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60))));
                PhotoViewer.this.videoPlayerSeekbar.setSize((getMeasuredWidth() - AndroidUtilities.dp(64.0f)) - size, getMeasuredHeight());
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                float progress = 0.0f;
                if (PhotoViewer.this.videoPlayer != null) {
                    progress = PhotoViewer.this.videoPlayer.getCurrentPosition() / PhotoViewer.this.videoPlayer.getDuration();
                    if (!PhotoViewer.this.inPreview && PhotoViewer.this.videoTimelineView.getVisibility() == 0) {
                        float progress2 = progress - PhotoViewer.this.videoTimelineView.getLeftProgress();
                        if (progress2 < 0.0f) {
                            progress2 = 0.0f;
                        }
                        progress = progress2 / (PhotoViewer.this.videoTimelineView.getRightProgress() - PhotoViewer.this.videoTimelineView.getLeftProgress());
                        if (progress > 1.0f) {
                            progress = 1.0f;
                        }
                    }
                }
                PhotoViewer.this.videoPlayerSeekbar.setProgress(progress);
                PhotoViewer.this.videoTimelineView.setProgress(progress);
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                canvas.save();
                canvas.translate(AndroidUtilities.dp(48.0f), 0.0f);
                PhotoViewer.this.videoPlayerSeekbar.draw(canvas);
                canvas.restore();
            }
        };
        this.videoPlayerControlFrameLayout = frameLayout;
        frameLayout.setWillNotDraw(false);
        this.bottomLayout.addView(this.videoPlayerControlFrameLayout, LayoutHelper.createFrame(-1, -1, 51));
        VideoSeekPreviewImage videoSeekPreviewImage = new VideoSeekPreviewImage(this.containerView.getContext(), new VideoSeekPreviewImage.VideoSeekPreviewImageDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$FQKOm81gchMzh3ZVYTUB2QhGCJo
            @Override // im.uwrkaxlmjj.ui.components.VideoSeekPreviewImage.VideoSeekPreviewImageDelegate
            public final void onReady() {
                this.f$0.lambda$createVideoControlsInterface$34$PhotoViewer();
            }
        }) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.29
            @Override // android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                PhotoViewer.this.updateVideoSeekPreviewPosition();
            }

            @Override // android.view.View
            public void setVisibility(int visibility) {
                super.setVisibility(visibility);
                if (visibility == 0) {
                    PhotoViewer.this.updateVideoSeekPreviewPosition();
                }
            }
        };
        this.videoPreviewFrame = videoSeekPreviewImage;
        videoSeekPreviewImage.setAlpha(0.0f);
        this.containerView.addView(this.videoPreviewFrame, LayoutHelper.createFrame(-2.0f, -2.0f, 83, 0.0f, 0.0f, 0.0f, 58.0f));
        ImageView imageView = new ImageView(this.containerView.getContext());
        this.videoPlayButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.videoPlayerControlFrameLayout.addView(this.videoPlayButton, LayoutHelper.createFrame(48.0f, 48.0f, 51, 4.0f, 0.0f, 0.0f, 0.0f));
        this.videoPlayButton.setFocusable(true);
        this.videoPlayButton.setContentDescription(LocaleController.getString("AccActionPlay", R.string.AccActionPlay));
        this.videoPlayButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$qoHH4AKe9hXegadCv611iRsbVfg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createVideoControlsInterface$35$PhotoViewer(view);
            }
        });
        SimpleTextView simpleTextView = new SimpleTextView(this.containerView.getContext());
        this.videoPlayerTime = simpleTextView;
        simpleTextView.setTextColor(-1);
        this.videoPlayerTime.setGravity(53);
        this.videoPlayerTime.setTextSize(13);
        this.videoPlayerControlFrameLayout.addView(this.videoPlayerTime, LayoutHelper.createFrame(-2.0f, -1.0f, 53, 0.0f, 17.0f, 7.0f, 0.0f));
    }

    public /* synthetic */ void lambda$createVideoControlsInterface$34$PhotoViewer() {
        if (this.needShowOnReady) {
            showVideoSeekPreviewPosition(true);
        }
    }

    public /* synthetic */ void lambda$createVideoControlsInterface$35$PhotoViewer(View v) {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer == null) {
            return;
        }
        if (this.isPlaying) {
            videoPlayer.pause();
        } else {
            if (this.isCurrentVideo) {
                if (Math.abs(this.videoTimelineView.getProgress() - 1.0f) < 0.01f || this.videoPlayer.getCurrentPosition() == this.videoPlayer.getDuration()) {
                    this.videoPlayer.seekTo((int) (this.videoTimelineView.getLeftProgress() * this.videoPlayer.getDuration()));
                }
            } else if (Math.abs(this.videoPlayerSeekbar.getProgress() - 1.0f) < 0.01f || this.videoPlayer.getCurrentPosition() == this.videoPlayer.getDuration()) {
                this.videoPlayer.seekTo(0L);
            }
            this.videoPlayer.play();
        }
        this.containerView.invalidate();
    }

    private void openCaptionEnter() {
        int i;
        int i2;
        String str;
        if (this.imageMoveAnimation != null || this.changeModeAnimation != null || this.currentEditMode != 0 || (i = this.sendPhotoType) == 1 || i == 3) {
            return;
        }
        this.selectedPhotosListView.setVisibility(8);
        this.selectedPhotosListView.setEnabled(false);
        this.selectedPhotosListView.setAlpha(0.0f);
        this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
        this.photosCounterView.setRotationX(0.0f);
        this.isPhotosListViewVisible = false;
        this.captionEditText.setTag(1);
        this.captionEditText.openKeyboard();
        this.captionEditText.setImportantForAccessibility(0);
        this.lastTitle = this.actionBar.getTitle();
        if (this.isCurrentVideo) {
            ActionBar actionBar = this.actionBar;
            if (this.muteVideo) {
                i2 = R.string.GifCaption;
                str = "GifCaption";
            } else {
                i2 = R.string.VideoCaption;
                str = "VideoCaption";
            }
            actionBar.setTitle(LocaleController.getString(str, i2));
            this.actionBar.setSubtitle(null);
            return;
        }
        this.actionBar.setTitle(LocaleController.getString("PhotoCaption", R.string.PhotoCaption));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public VideoEditedInfo getCurrentVideoEditedInfo() {
        if (!this.isCurrentVideo || this.currentPlayingVideoFile == null || this.compressionsCount == 0) {
            return null;
        }
        VideoEditedInfo videoEditedInfo = new VideoEditedInfo();
        videoEditedInfo.startTime = this.startTime;
        videoEditedInfo.endTime = this.endTime;
        videoEditedInfo.start = this.videoCutStart;
        videoEditedInfo.end = this.videoCutEnd;
        videoEditedInfo.rotationValue = this.rotationValue;
        videoEditedInfo.originalWidth = this.originalWidth;
        videoEditedInfo.originalHeight = this.originalHeight;
        videoEditedInfo.bitrate = this.bitrate;
        videoEditedInfo.originalPath = this.currentPlayingVideoFile.getPath();
        int i = this.estimatedSize;
        videoEditedInfo.estimatedSize = i != 0 ? i : 1L;
        videoEditedInfo.estimatedDuration = this.estimatedDuration;
        videoEditedInfo.framerate = this.videoFramerate;
        if (!this.muteVideo && (this.compressItem.getTag() == null || this.selectedCompression == this.compressionsCount - 1)) {
            videoEditedInfo.resultWidth = this.originalWidth;
            videoEditedInfo.resultHeight = this.originalHeight;
            videoEditedInfo.bitrate = this.muteVideo ? -1 : this.originalBitrate;
            videoEditedInfo.muted = this.muteVideo;
        } else {
            if (this.muteVideo) {
                this.selectedCompression = 1;
                updateWidthHeightBitrateForCompression();
            }
            videoEditedInfo.resultWidth = this.resultWidth;
            videoEditedInfo.resultHeight = this.resultHeight;
            videoEditedInfo.bitrate = this.muteVideo ? -1 : this.bitrate;
            videoEditedInfo.muted = this.muteVideo;
        }
        return videoEditedInfo;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void closeCaptionEnter(boolean apply) {
        int i = this.currentIndex;
        if (i < 0 || i >= this.imagesArrLocals.size()) {
            return;
        }
        Object object = this.imagesArrLocals.get(this.currentIndex);
        if (apply) {
            CharSequence caption = this.captionEditText.getFieldCharSequence();
            CharSequence[] result = {caption};
            ArrayList<TLRPC.MessageEntity> entities = MediaDataController.getInstance(this.currentAccount).getEntities(result);
            if (object instanceof MediaController.PhotoEntry) {
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                photoEntry.caption = result[0];
                photoEntry.entities = entities;
            } else if (object instanceof MediaController.SearchImage) {
                MediaController.SearchImage photoEntry2 = (MediaController.SearchImage) object;
                photoEntry2.caption = result[0];
                photoEntry2.entities = entities;
            }
            if (this.captionEditText.getFieldCharSequence().length() != 0 && !this.placeProvider.isPhotoChecked(this.currentIndex)) {
                setPhotoChecked();
            }
            setCurrentCaption(null, result[0], false);
        }
        this.captionEditText.setTag(null);
        String str = this.lastTitle;
        if (str != null) {
            this.actionBar.setTitle(str);
            this.lastTitle = null;
        }
        if (this.isCurrentVideo) {
            this.actionBar.setSubtitle(this.muteVideo ? null : this.currentSubtitle);
        }
        updateCaptionTextForCurrentPhoto(object);
        if (this.captionEditText.isPopupShowing()) {
            this.captionEditText.hidePopup();
        }
        this.captionEditText.closeKeyboard();
        if (Build.VERSION.SDK_INT >= 19) {
            this.captionEditText.setImportantForAccessibility(4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVideoPlayerTime() {
        String newText;
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer == null) {
            newText = String.format("%02d:%02d / %02d:%02d", 0, 0, 0, 0);
        } else {
            long current = videoPlayer.getCurrentPosition();
            if (current < 0) {
                current = 0;
            }
            long total = this.videoPlayer.getDuration();
            if (total < 0) {
                total = 0;
            }
            if (total != C.TIME_UNSET && current != C.TIME_UNSET) {
                if (!this.inPreview && this.videoTimelineView.getVisibility() == 0) {
                    total = (long) (total * (this.videoTimelineView.getRightProgress() - this.videoTimelineView.getLeftProgress()));
                    current = (long) (current - (this.videoTimelineView.getLeftProgress() * total));
                    if (current > total) {
                        current = total;
                    }
                }
                long current2 = current / 1000;
                long total2 = total / 1000;
                if (total2 == 0) {
                    total2 = 1;
                }
                newText = String.format("%02d:%02d / %02d:%02d", Long.valueOf(current2 / 60), Integer.valueOf((int) Math.ceil(current2 % 60.0d)), Long.valueOf(total2 / 60), Integer.valueOf((int) Math.ceil(total2 % 60.0d)));
            } else {
                newText = String.format("%02d:%02d / %02d:%02d", 0, 0, 0, 0);
            }
        }
        this.videoPlayerTime.setText(newText);
    }

    private void checkBufferedProgress(float progress) {
        MessageObject messageObject;
        TLRPC.Document document;
        if (!this.isStreaming || this.parentActivity == null || this.streamingAlertShown || this.videoPlayer == null || (messageObject = this.currentMessageObject) == null || (document = messageObject.getDocument()) == null) {
            return;
        }
        int innerDuration = this.currentMessageObject.getDuration();
        if (innerDuration >= 20 && progress < 0.9f) {
            if ((document.size * progress >= 5242880.0f || (progress >= 0.5f && document.size >= 2097152)) && Math.abs(SystemClock.elapsedRealtime() - this.startedPlayTime) >= AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                long duration = this.videoPlayer.getDuration();
                if (duration == C.TIME_UNSET) {
                    ToastUtils.show(R.string.VideoDoesNotSupportStreaming);
                }
                this.streamingAlertShown = true;
            }
        }
    }

    public void injectVideoPlayer(VideoPlayer player) {
        this.injectingVideoPlayer = player;
    }

    public void injectVideoPlayerSurface(SurfaceTexture surface) {
        this.injectingVideoPlayerSurface = surface;
    }

    public boolean isInjectingVideoPlayer() {
        return this.injectingVideoPlayer != null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePlayerState(boolean playWhenReady, int playbackState) {
        MessageObject messageObject;
        if (this.videoPlayer == null) {
            return;
        }
        if (this.isStreaming) {
            if (playbackState != 2 || !this.skipFirstBufferingProgress) {
                toggleMiniProgress(this.seekToProgressPending != 0.0f || playbackState == 2, true);
            } else if (playWhenReady) {
                this.skipFirstBufferingProgress = false;
            }
        }
        if (!playWhenReady || playbackState == 4 || playbackState == 1) {
            try {
                this.parentActivity.getWindow().clearFlags(128);
                this.keepScreenOnFlagSet = false;
            } catch (Exception e) {
                FileLog.e(e);
            }
        } else {
            try {
                this.parentActivity.getWindow().addFlags(128);
                this.keepScreenOnFlagSet = true;
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
        if (playbackState == 3 || playbackState == 1) {
            if (this.currentMessageObject != null) {
                this.videoPreviewFrame.open(this.videoPlayer.getCurrentUri());
            }
            if (this.seekToProgressPending != 0.0f) {
                int seekTo = (int) (this.videoPlayer.getDuration() * this.seekToProgressPending);
                this.videoPlayer.seekTo(seekTo);
                this.seekToProgressPending = 0.0f;
                MessageObject messageObject2 = this.currentMessageObject;
                if (messageObject2 != null && !FileLoader.getInstance(messageObject2.currentAccount).isLoadingVideoAny(this.currentMessageObject.getDocument())) {
                    this.skipFirstBufferingProgress = true;
                }
            }
        }
        if (playbackState == 3) {
            if (this.aspectRatioFrameLayout.getVisibility() != 0) {
                this.aspectRatioFrameLayout.setVisibility(0);
            }
            if (!this.pipItem.isEnabled()) {
                this.pipAvailable = true;
                this.pipItem.setEnabled(true);
                this.pipItem.setAlpha(1.0f);
            }
            this.playerWasReady = true;
            MessageObject messageObject3 = this.currentMessageObject;
            if (messageObject3 != null && messageObject3.isVideo()) {
                AndroidUtilities.cancelRunOnUIThread(this.setLoadingRunnable);
                FileLoader.getInstance(this.currentMessageObject.currentAccount).removeLoadingVideo(this.currentMessageObject.getDocument(), true, false);
            }
        } else if (playbackState == 2 && playWhenReady && (messageObject = this.currentMessageObject) != null && messageObject.isVideo()) {
            if (this.playerWasReady) {
                this.setLoadingRunnable.run();
            } else {
                AndroidUtilities.runOnUIThread(this.setLoadingRunnable, 1000L);
            }
        }
        if (this.videoPlayer.isPlaying() && playbackState != 4) {
            if (!this.isPlaying) {
                this.isPlaying = true;
                this.videoPlayButton.setImageResource(R.drawable.inline_video_pause);
                AndroidUtilities.runOnUIThread(this.updateProgressRunnable);
            }
        } else if (this.isPlaying) {
            this.isPlaying = false;
            this.videoPlayButton.setImageResource(R.drawable.inline_video_play);
            AndroidUtilities.cancelRunOnUIThread(this.updateProgressRunnable);
            if (playbackState == 4) {
                if (this.isCurrentVideo) {
                    if (!this.videoTimelineView.isDragging()) {
                        this.videoTimelineView.setProgress(0.0f);
                        if (!this.inPreview && this.videoTimelineView.getVisibility() == 0) {
                            this.videoPlayer.seekTo((int) (this.videoTimelineView.getLeftProgress() * this.videoPlayer.getDuration()));
                        } else {
                            this.videoPlayer.seekTo(0L);
                        }
                        this.videoPlayer.pause();
                        this.containerView.invalidate();
                    }
                } else {
                    if (!this.isActionBarVisible) {
                        toggleActionBar(true, true);
                    }
                    this.videoPlayerSeekbar.setProgress(0.0f);
                    this.videoPlayerControlFrameLayout.invalidate();
                    if (!this.inPreview && this.videoTimelineView.getVisibility() == 0) {
                        this.videoPlayer.seekTo((int) (this.videoTimelineView.getLeftProgress() * this.videoPlayer.getDuration()));
                    } else {
                        this.videoPlayer.seekTo(0L);
                    }
                    this.videoPlayer.pause();
                }
                PipVideoView pipVideoView = this.pipVideoView;
                if (pipVideoView != null) {
                    pipVideoView.onVideoCompleted();
                }
            }
        }
        PipVideoView pipVideoView2 = this.pipVideoView;
        if (pipVideoView2 != null) {
            pipVideoView2.updatePlayButton();
        }
        updateVideoPlayerTime();
    }

    private void preparePlayer(Uri uri, boolean playWhenReady, boolean preview) {
        if (!preview) {
            this.currentPlayingVideoFile = uri;
        }
        if (this.parentActivity == null) {
            return;
        }
        this.streamingAlertShown = false;
        this.startedPlayTime = SystemClock.elapsedRealtime();
        this.currentVideoFinishedLoading = false;
        this.lastBufferedPositionCheck = 0L;
        this.firstAnimationDelay = true;
        this.inPreview = preview;
        releasePlayer(false);
        if (this.videoTextureView == null) {
            AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(this.parentActivity) { // from class: im.uwrkaxlmjj.ui.PhotoViewer.30
                @Override // com.google.android.exoplayer2.ui.AspectRatioFrameLayout, android.widget.FrameLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                    if (PhotoViewer.this.textureImageView != null) {
                        ViewGroup.LayoutParams layoutParams = PhotoViewer.this.textureImageView.getLayoutParams();
                        layoutParams.width = getMeasuredWidth();
                        layoutParams.height = getMeasuredHeight();
                    }
                }
            };
            this.aspectRatioFrameLayout = aspectRatioFrameLayout;
            aspectRatioFrameLayout.setVisibility(4);
            this.containerView.addView(this.aspectRatioFrameLayout, 0, LayoutHelper.createFrame(-1, -1, 17));
            TextureView textureView = new TextureView(this.parentActivity);
            this.videoTextureView = textureView;
            SurfaceTexture surfaceTexture = this.injectingVideoPlayerSurface;
            if (surfaceTexture != null) {
                textureView.setSurfaceTexture(surfaceTexture);
                this.textureUploaded = true;
                this.injectingVideoPlayerSurface = null;
            }
            this.videoTextureView.setPivotX(0.0f);
            this.videoTextureView.setPivotY(0.0f);
            this.videoTextureView.setOpaque(false);
            this.aspectRatioFrameLayout.addView(this.videoTextureView, LayoutHelper.createFrame(-1, -1, 17));
        }
        if (Build.VERSION.SDK_INT >= 21 && this.textureImageView == null) {
            ImageView imageView = new ImageView(this.parentActivity);
            this.textureImageView = imageView;
            imageView.setBackgroundColor(SupportMenu.CATEGORY_MASK);
            this.textureImageView.setPivotX(0.0f);
            this.textureImageView.setPivotY(0.0f);
            this.textureImageView.setVisibility(4);
            this.containerView.addView(this.textureImageView);
        }
        this.textureUploaded = false;
        this.videoCrossfadeStarted = false;
        TextureView textureView2 = this.videoTextureView;
        this.videoCrossfadeAlpha = 0.0f;
        textureView2.setAlpha(0.0f);
        this.videoPlayButton.setImageResource(R.drawable.inline_video_play);
        boolean newPlayerCreated = false;
        this.playerWasReady = false;
        if (this.videoPlayer == null) {
            VideoPlayer videoPlayer = this.injectingVideoPlayer;
            if (videoPlayer != null) {
                this.videoPlayer = videoPlayer;
                this.injectingVideoPlayer = null;
                this.playerInjected = true;
                updatePlayerState(videoPlayer.getPlayWhenReady(), this.videoPlayer.getPlaybackState());
            } else {
                this.videoPlayer = new VideoPlayer();
                newPlayerCreated = true;
            }
            this.videoPlayer.setTextureView(this.videoTextureView);
            this.videoPlayer.setDelegate(new AnonymousClass31());
        }
        this.shouldSavePositionForCurrentVideo = null;
        this.lastSaveTime = 0L;
        if (newPlayerCreated) {
            this.seekToProgressPending = this.seekToProgressPending2;
            this.videoPlayer.preparePlayer(uri, "other");
            this.videoPlayerSeekbar.setProgress(0.0f);
            this.videoTimelineView.setProgress(0.0f);
            this.videoPlayerSeekbar.setBufferedProgress(0.0f);
            this.videoPlayer.setPlayWhenReady(playWhenReady);
            MessageObject messageObject = this.currentMessageObject;
            if (messageObject != null) {
                String name = messageObject.getFileName();
                if (!TextUtils.isEmpty(name) && this.currentMessageObject.getDuration() >= 1200) {
                    if (this.currentMessageObject.forceSeekTo < 0.0f) {
                        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("media_saved_pos", 0);
                        float pos = preferences.getFloat(name, -1.0f);
                        if (pos > 0.0f && pos < 0.999f) {
                            this.currentMessageObject.forceSeekTo = pos;
                            this.videoPlayerSeekbar.setProgress(pos);
                        }
                    }
                    this.shouldSavePositionForCurrentVideo = name;
                }
            }
        }
        MessageObject messageObject2 = this.currentMessageObject;
        if (messageObject2 != null && messageObject2.forceSeekTo >= 0.0f) {
            this.seekToProgressPending = this.currentMessageObject.forceSeekTo;
            this.currentMessageObject.forceSeekTo = -1.0f;
        }
        TLRPC.BotInlineResult botInlineResult = this.currentBotInlineResult;
        if (botInlineResult == null || (!botInlineResult.type.equals("video") && !MessageObject.isVideoDocument(this.currentBotInlineResult.document))) {
            this.bottomLayout.setPadding(0, 0, 0, 0);
        } else {
            this.bottomLayout.setVisibility(0);
            this.bottomLayout.setPadding(0, 0, AndroidUtilities.dp(84.0f), 0);
            this.pickerView.setVisibility(8);
        }
        this.videoPlayerControlFrameLayout.setVisibility(this.isCurrentVideo ? 8 : 0);
        this.dateTextView.setVisibility(8);
        this.nameTextView.setVisibility(8);
        if (this.allowShare) {
            this.shareButton.setVisibility(8);
            this.menuItem.showSubItem(10);
        }
        this.inPreview = preview;
        updateAccessibilityOverlayVisibility();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$31, reason: invalid class name */
    class AnonymousClass31 implements VideoPlayer.VideoPlayerDelegate {
        AnonymousClass31() {
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onStateChanged(boolean playWhenReady, int playbackState) {
            PhotoViewer.this.updatePlayerState(playWhenReady, playbackState);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onError(Exception e) {
            if (PhotoViewer.this.videoPlayer == null) {
                return;
            }
            FileLog.e(e);
            if (!PhotoViewer.this.menuItem.isSubItemVisible(11)) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(PhotoViewer.this.parentActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("CantPlayVideo", R.string.CantPlayVideo));
            builder.setPositiveButton(LocaleController.getString("Open", R.string.Open), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$31$koDomPb9wACNV7Q7J2XhcudBlgg
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onError$0$PhotoViewer$31(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            PhotoViewer.this.showAlertDialog(builder);
        }

        public /* synthetic */ void lambda$onError$0$PhotoViewer$31(DialogInterface dialog, int which) {
            try {
                AndroidUtilities.openForView(PhotoViewer.this.currentMessageObject, PhotoViewer.this.parentActivity);
                PhotoViewer.this.closePhoto(false, false);
            } catch (Exception e1) {
                FileLog.e(e1);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
            if (PhotoViewer.this.aspectRatioFrameLayout != null) {
                if (unappliedRotationDegrees == 90 || unappliedRotationDegrees == 270) {
                    width = height;
                    height = width;
                }
                PhotoViewer.this.aspectRatioFrameLayout.setAspectRatio(height == 0 ? 1.0f : (width * pixelWidthHeightRatio) / height, unappliedRotationDegrees);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onRenderedFirstFrame() {
            if (!PhotoViewer.this.textureUploaded) {
                PhotoViewer.this.textureUploaded = true;
                PhotoViewer.this.containerView.invalidate();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
            if (PhotoViewer.this.changingTextureView) {
                PhotoViewer.this.changingTextureView = false;
                if (PhotoViewer.this.isInline) {
                    if (PhotoViewer.this.isInline) {
                        PhotoViewer.this.waitingForFirstTextureUpload = 1;
                    }
                    PhotoViewer.this.changedTextureView.setSurfaceTexture(surfaceTexture);
                    PhotoViewer.this.changedTextureView.setSurfaceTextureListener(PhotoViewer.this.surfaceTextureListener);
                    PhotoViewer.this.changedTextureView.setVisibility(0);
                    return true;
                }
            }
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
            if (PhotoViewer.this.waitingForFirstTextureUpload == 2) {
                if (PhotoViewer.this.textureImageView != null) {
                    PhotoViewer.this.textureImageView.setVisibility(4);
                    PhotoViewer.this.textureImageView.setImageDrawable(null);
                    if (PhotoViewer.this.currentBitmap != null) {
                        PhotoViewer.this.currentBitmap.recycle();
                        PhotoViewer.this.currentBitmap = null;
                    }
                }
                PhotoViewer.this.switchingInlineMode = false;
                if (Build.VERSION.SDK_INT >= 21) {
                    PhotoViewer.this.aspectRatioFrameLayout.getLocationInWindow(PhotoViewer.this.pipPosition);
                    PhotoViewer.this.pipPosition[1] = (int) (r0[1] - PhotoViewer.this.containerView.getTranslationY());
                    PhotoViewer.this.textureImageView.setTranslationX(PhotoViewer.this.textureImageView.getTranslationX() + PhotoViewer.this.getLeftInset());
                    PhotoViewer.this.videoTextureView.setTranslationX((PhotoViewer.this.videoTextureView.getTranslationX() + PhotoViewer.this.getLeftInset()) - PhotoViewer.this.aspectRatioFrameLayout.getX());
                    AnimatorSet animatorSet = new AnimatorSet();
                    animatorSet.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this.textureImageView, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.textureImageView, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.textureImageView, (Property<ImageView, Float>) View.TRANSLATION_X, PhotoViewer.this.pipPosition[0]), ObjectAnimator.ofFloat(PhotoViewer.this.textureImageView, (Property<ImageView, Float>) View.TRANSLATION_Y, PhotoViewer.this.pipPosition[1]), ObjectAnimator.ofFloat(PhotoViewer.this.videoTextureView, (Property<TextureView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.videoTextureView, (Property<TextureView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.videoTextureView, (Property<TextureView, Float>) View.TRANSLATION_X, PhotoViewer.this.pipPosition[0] - PhotoViewer.this.aspectRatioFrameLayout.getX()), ObjectAnimator.ofFloat(PhotoViewer.this.videoTextureView, (Property<TextureView, Float>) View.TRANSLATION_Y, PhotoViewer.this.pipPosition[1] - PhotoViewer.this.aspectRatioFrameLayout.getY()), ObjectAnimator.ofInt(PhotoViewer.this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 255), ObjectAnimator.ofFloat(PhotoViewer.this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.bottomLayout, (Property<FrameLayout, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.captionTextView, (Property<TextView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.groupedPhotosListView, (Property<GroupedPhotosListView, Float>) View.ALPHA, 1.0f));
                    animatorSet.setInterpolator(new DecelerateInterpolator());
                    animatorSet.setDuration(250L);
                    animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.31.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            PhotoViewer.this.pipAnimationInProgress = false;
                        }
                    });
                    animatorSet.start();
                }
                PhotoViewer.this.waitingForFirstTextureUpload = 0;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void releasePlayer(boolean onClose) {
        if (this.videoPlayer != null) {
            AndroidUtilities.cancelRunOnUIThread(this.setLoadingRunnable);
            this.videoPlayer.releasePlayer(true);
            this.videoPlayer = null;
            updateAccessibilityOverlayVisibility();
        }
        this.videoPreviewFrame.close();
        toggleMiniProgress(false, false);
        this.pipAvailable = false;
        this.playerInjected = false;
        if (this.pipItem.isEnabled()) {
            this.pipItem.setEnabled(false);
            this.pipItem.setAlpha(0.5f);
        }
        if (this.keepScreenOnFlagSet) {
            try {
                this.parentActivity.getWindow().clearFlags(128);
                this.keepScreenOnFlagSet = false;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
        if (aspectRatioFrameLayout != null) {
            try {
                this.containerView.removeView(aspectRatioFrameLayout);
            } catch (Throwable th) {
            }
            this.aspectRatioFrameLayout = null;
        }
        if (this.videoTextureView != null) {
            this.videoTextureView = null;
        }
        if (this.isPlaying) {
            this.isPlaying = false;
            if (!onClose) {
                this.videoPlayButton.setImageResource(R.drawable.inline_video_play);
            }
            AndroidUtilities.cancelRunOnUIThread(this.updateProgressRunnable);
        }
        if (!onClose && !this.inPreview && !this.requestingPreview) {
            this.videoPlayerControlFrameLayout.setVisibility(8);
            this.dateTextView.setVisibility(0);
            this.nameTextView.setVisibility(0);
            if (this.allowShare) {
                this.shareButton.setVisibility(0);
                this.menuItem.hideSubItem(10);
            }
        }
    }

    private void updateCaptionTextForCurrentPhoto(Object object) {
        CharSequence caption = null;
        if (object instanceof MediaController.PhotoEntry) {
            caption = ((MediaController.PhotoEntry) object).caption;
        } else if (!(object instanceof TLRPC.BotInlineResult) && (object instanceof MediaController.SearchImage)) {
            caption = ((MediaController.SearchImage) object).caption;
        }
        if (TextUtils.isEmpty(caption)) {
            this.captionEditText.setFieldText("");
        } else {
            this.captionEditText.setFieldText(caption);
        }
        PhotoViewerCaptionEnterView photoViewerCaptionEnterView = this.captionEditText;
        ChatActivity chatActivity = this.parentChatActivity;
        photoViewerCaptionEnterView.setAllowTextEntitiesIntersection(chatActivity != null && (chatActivity.currentEncryptedChat == null || (this.parentChatActivity.currentEncryptedChat != null && AndroidUtilities.getPeerLayerVersion(this.parentChatActivity.currentEncryptedChat.layer) >= 101)));
    }

    public void showAlertDialog(AlertDialog.Builder builder) {
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
            AlertDialog alertDialogShow = builder.show();
            this.visibleDialog = alertDialogShow;
            alertDialogShow.setCanceledOnTouchOutside(true);
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$6bP_OfgVe7yNW0rFRqX3pYTDu6o
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showAlertDialog$36$PhotoViewer(dialogInterface);
                }
            });
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public /* synthetic */ void lambda$showAlertDialog$36$PhotoViewer(DialogInterface dialog) {
        this.visibleDialog = null;
    }

    private void applyCurrentEditMode() {
        View view;
        PhotoViewerProvider photoViewerProvider;
        View view2;
        Bitmap bitmap = null;
        ArrayList<TLRPC.InputDocument> stickers = null;
        MediaController.SavedFilterState savedFilterState = null;
        boolean removeSavedState = false;
        int i = this.currentEditMode;
        if (i == 1 || (i == 0 && this.sendPhotoType == 1)) {
            bitmap = this.photoCropView.getBitmap();
            removeSavedState = true;
        } else {
            int i2 = this.currentEditMode;
            if (i2 == 2) {
                bitmap = this.photoFilterView.getBitmap();
                savedFilterState = this.photoFilterView.getSavedFilterState();
            } else if (i2 == 3) {
                bitmap = this.photoPaintView.getBitmap();
                stickers = this.photoPaintView.getMasks();
                removeSavedState = true;
            }
        }
        if (bitmap != null) {
            TLRPC.PhotoSize size = ImageLoader.scaleAndSaveImage(bitmap, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), 80, false, 101, 101);
            if (size != null) {
                Object object = this.imagesArrLocals.get(this.currentIndex);
                if (object instanceof MediaController.PhotoEntry) {
                    MediaController.PhotoEntry entry = (MediaController.PhotoEntry) object;
                    entry.imagePath = FileLoader.getPathToAttach(size, true).toString();
                    TLRPC.PhotoSize size2 = ImageLoader.scaleAndSaveImage(bitmap, AndroidUtilities.dp(120.0f), AndroidUtilities.dp(120.0f), 70, false, 101, 101);
                    if (size2 != null) {
                        entry.thumbPath = FileLoader.getPathToAttach(size2, true).toString();
                    }
                    if (stickers != null) {
                        entry.stickers.addAll(stickers);
                    }
                    int i3 = this.currentEditMode;
                    if (i3 == 1) {
                        this.cropItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
                        entry.isCropped = true;
                    } else if (i3 == 2) {
                        this.tuneItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
                        entry.isFiltered = true;
                    } else if (i3 == 3) {
                        this.paintItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
                        entry.isPainted = true;
                    }
                    if (savedFilterState != null) {
                        entry.savedFilterState = savedFilterState;
                        view2 = null;
                    } else if (!removeSavedState) {
                        view2 = null;
                    } else {
                        view2 = null;
                        entry.savedFilterState = null;
                    }
                    view = view2;
                } else if (!(object instanceof MediaController.SearchImage)) {
                    view = null;
                } else {
                    MediaController.SearchImage entry2 = (MediaController.SearchImage) object;
                    entry2.imagePath = FileLoader.getPathToAttach(size, true).toString();
                    TLRPC.PhotoSize size3 = ImageLoader.scaleAndSaveImage(bitmap, AndroidUtilities.dp(120.0f), AndroidUtilities.dp(120.0f), 70, false, 101, 101);
                    if (size3 != null) {
                        entry2.thumbPath = FileLoader.getPathToAttach(size3, true).toString();
                    }
                    if (stickers != null) {
                        entry2.stickers.addAll(stickers);
                    }
                    int i4 = this.currentEditMode;
                    if (i4 == 1) {
                        this.cropItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
                        entry2.isCropped = true;
                    } else if (i4 == 2) {
                        this.tuneItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
                        entry2.isFiltered = true;
                    } else if (i4 == 3) {
                        this.paintItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
                        entry2.isPainted = true;
                    }
                    if (savedFilterState != null) {
                        entry2.savedFilterState = savedFilterState;
                        view = null;
                    } else if (!removeSavedState) {
                        view = null;
                    } else {
                        view = null;
                        entry2.savedFilterState = null;
                    }
                }
                int i5 = this.sendPhotoType;
                if ((i5 == 0 || i5 == 4) && (photoViewerProvider = this.placeProvider) != null) {
                    photoViewerProvider.updatePhotoAtIndex(this.currentIndex);
                    if (!this.placeProvider.isPhotoChecked(this.currentIndex)) {
                        setPhotoChecked();
                    }
                }
                if (this.currentEditMode == 1) {
                    float scaleX = this.photoCropView.getRectSizeX() / getContainerViewWidth();
                    float scaleY = this.photoCropView.getRectSizeY() / getContainerViewHeight();
                    this.scale = scaleX > scaleY ? scaleX : scaleY;
                    this.translationX = (this.photoCropView.getRectX() + (this.photoCropView.getRectSizeX() / 2.0f)) - (getContainerViewWidth() / 2);
                    this.translationY = (this.photoCropView.getRectY() + (this.photoCropView.getRectSizeY() / 2.0f)) - (getContainerViewHeight() / 2);
                    this.zoomAnimation = true;
                    this.applying = true;
                    this.photoCropView.onDisappear();
                }
                this.centerImage.setParentView(view);
                this.centerImage.setOrientation(0, true);
                this.ignoreDidSetImage = true;
                this.centerImage.setImageBitmap(bitmap);
                this.ignoreDidSetImage = false;
                this.centerImage.setParentView(this.containerView);
                if (this.sendPhotoType == 1) {
                    setCropBitmap();
                }
            }
        }
    }

    private void setPhotoChecked() {
        ChatActivity chatActivity;
        TLRPC.Chat chat;
        PhotoViewerProvider photoViewerProvider = this.placeProvider;
        if (photoViewerProvider != null) {
            if (photoViewerProvider.getSelectedPhotos() != null && this.maxSelectedPhotos > 0 && this.placeProvider.getSelectedPhotos().size() >= this.maxSelectedPhotos && !this.placeProvider.isPhotoChecked(this.currentIndex)) {
                if (this.allowOrder && (chatActivity = this.parentChatActivity) != null && (chat = chatActivity.getCurrentChat()) != null && !ChatObject.hasAdminRights(chat) && chat.slowmode_enabled) {
                    AlertsCreator.createSimpleAlert(this.parentActivity, LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSelectSendError", R.string.SlowmodeSelectSendError)).show();
                    return;
                }
                return;
            }
            int num = this.placeProvider.setPhotoChecked(this.currentIndex, getCurrentVideoEditedInfo());
            boolean checked = this.placeProvider.isPhotoChecked(this.currentIndex);
            this.checkImageView.setChecked(checked, true);
            if (num >= 0) {
                if (checked) {
                    this.selectedPhotosAdapter.notifyItemInserted(num);
                    this.selectedPhotosListView.smoothScrollToPosition(num);
                } else {
                    this.selectedPhotosAdapter.notifyItemRemoved(num);
                }
            }
            updateSelectedCount();
        }
    }

    private void createCropView() throws JSONException {
        PhotoCropView photoCropView = this.photoCropView;
        if (photoCropView != null && photoCropView.isFcCrop() == this.isFcCrop) {
            if (BuildVars.DEBUG_VERSION) {
                KLog.d(getClass().getSimpleName(), "不会重新构造裁剪样式");
            }
        } else {
            PhotoCropView photoCropView2 = new PhotoCropView(this.actvityContext, this.isFcCrop);
            this.photoCropView = photoCropView2;
            photoCropView2.setVisibility(8);
            int index = this.containerView.indexOfChild(this.pickerViewSendButton);
            this.containerView.addView(this.photoCropView, index - 1, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 48.0f));
            this.photoCropView.setDelegate(new PhotoCropView.PhotoCropViewDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$XPi9UhgZz-BfLcFidJcYZQMsm5A
                @Override // im.uwrkaxlmjj.ui.components.PhotoCropView.PhotoCropViewDelegate
                public final void onChange(boolean z) {
                    this.f$0.lambda$createCropView$37$PhotoViewer(z);
                }
            });
        }
    }

    public /* synthetic */ void lambda$createCropView$37$PhotoViewer(boolean reset) {
        this.resetButton.setVisibility(reset ? 8 : 0);
    }

    private void switchToEditMode(final int mode) throws JSONException {
        Bitmap bitmap;
        if (this.currentEditMode != mode && this.centerImage.getBitmap() != null && this.changeModeAnimation == null && this.imageMoveAnimation == null && this.photoProgressViews[0].backgroundState == -1 && this.captionEditText.getTag() == null) {
            if (mode == 0) {
                Bitmap bitmap2 = this.centerImage.getBitmap();
                if (bitmap2 != null) {
                    int bitmapWidth = this.centerImage.getBitmapWidth();
                    int bitmapHeight = this.centerImage.getBitmapHeight();
                    float scaleX = getContainerViewWidth() / bitmapWidth;
                    float scaleY = getContainerViewHeight() / bitmapHeight;
                    float newScaleX = getContainerViewWidth(0) / bitmapWidth;
                    float newScaleY = getContainerViewHeight(0) / bitmapHeight;
                    float scale = scaleX > scaleY ? scaleY : scaleX;
                    float newScale = newScaleX > newScaleY ? newScaleY : newScaleX;
                    if (this.sendPhotoType != 1) {
                        this.animateToScale = newScale / scale;
                        this.animateToX = 0.0f;
                        this.translationX = (getLeftInset() / 2) - (getRightInset() / 2);
                        int i = this.currentEditMode;
                        if (i == 1) {
                            this.animateToY = AndroidUtilities.dp(58.0f);
                        } else if (i == 2) {
                            this.animateToY = AndroidUtilities.dp(92.0f);
                        } else if (i == 3) {
                            this.animateToY = AndroidUtilities.dp(44.0f);
                        }
                        if (Build.VERSION.SDK_INT >= 21) {
                            this.animateToY -= AndroidUtilities.statusBarHeight / 2;
                        }
                        this.animationStartTime = System.currentTimeMillis();
                        this.zoomAnimation = true;
                    } else {
                        setCropTranslations(true);
                    }
                }
                this.padImageForHorizontalInsets = false;
                this.imageMoveAnimation = new AnimatorSet();
                ArrayList<Animator> animators = new ArrayList<>(4);
                int i2 = this.currentEditMode;
                if (i2 == 1) {
                    animators.add(ObjectAnimator.ofFloat(this.editorDoneLayout, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(48.0f)));
                    animators.add(ObjectAnimator.ofFloat(this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
                    animators.add(ObjectAnimator.ofFloat(this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f));
                } else if (i2 == 2) {
                    this.photoFilterView.shutdown();
                    animators.add(ObjectAnimator.ofFloat(this.photoFilterView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(186.0f)));
                    animators.add(ObjectAnimator.ofFloat(this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
                } else if (i2 == 3) {
                    this.photoPaintView.shutdown();
                    animators.add(ObjectAnimator.ofFloat(this.photoPaintView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f)));
                    animators.add(ObjectAnimator.ofFloat(this.photoPaintView.getColorPicker(), (Property<ColorPicker, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f)));
                    animators.add(ObjectAnimator.ofFloat(this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
                }
                this.imageMoveAnimation.playTogether(animators);
                this.imageMoveAnimation.setDuration(200L);
                this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.32
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (PhotoViewer.this.currentEditMode == 1) {
                            PhotoViewer.this.photoCropView.onDisappear();
                            PhotoViewer.this.editorDoneLayout.setVisibility(8);
                            PhotoViewer.this.photoCropView.setVisibility(8);
                        } else if (PhotoViewer.this.currentEditMode == 2) {
                            try {
                                PhotoViewer.this.containerView.removeView(PhotoViewer.this.photoFilterView);
                            } catch (Exception e) {
                                FileLog.e(e);
                            }
                            PhotoViewer.this.photoFilterView = null;
                        } else if (PhotoViewer.this.currentEditMode == 3) {
                            try {
                                PhotoViewer.this.containerView.removeView(PhotoViewer.this.photoPaintView);
                            } catch (Exception e2) {
                                FileLog.e(e2);
                            }
                            PhotoViewer.this.photoPaintView = null;
                        }
                        PhotoViewer.this.imageMoveAnimation = null;
                        PhotoViewer.this.currentEditMode = mode;
                        PhotoViewer.this.applying = false;
                        if (PhotoViewer.this.sendPhotoType != 1) {
                            PhotoViewer.this.animateToScale = 1.0f;
                            PhotoViewer.this.animateToX = 0.0f;
                            PhotoViewer.this.animateToY = 0.0f;
                            PhotoViewer.this.scale = 1.0f;
                        }
                        PhotoViewer photoViewer = PhotoViewer.this;
                        photoViewer.updateMinMax(photoViewer.scale);
                        PhotoViewer.this.containerView.invalidate();
                        AnimatorSet animatorSet = new AnimatorSet();
                        ArrayList<Animator> arrayList = new ArrayList<>();
                        arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
                        arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f));
                        if (PhotoViewer.this.sendPhotoType != 1) {
                            arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f));
                        }
                        if (PhotoViewer.this.needCaptionLayout) {
                            arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.captionTextView, (Property<TextView, Float>) View.TRANSLATION_Y, 0.0f));
                        }
                        if (PhotoViewer.this.sendPhotoType == 0 || PhotoViewer.this.sendPhotoType == 4) {
                            arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.checkImageView, (Property<CheckBox, Float>) View.ALPHA, 1.0f));
                            arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.photosCounterView, (Property<CounterView, Float>) View.ALPHA, 1.0f));
                        } else if (PhotoViewer.this.sendPhotoType == 1) {
                            arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 1.0f));
                        }
                        if (PhotoViewer.this.mShowNeedAddMorePicButton && PhotoViewer.this.cameraItem.getTag() != null) {
                            PhotoViewer.this.cameraItem.setVisibility(0);
                            arrayList.add(ObjectAnimator.ofFloat(PhotoViewer.this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                        }
                        animatorSet.playTogether(arrayList);
                        animatorSet.setDuration(200L);
                        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.32.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                                PhotoViewer.this.pickerView.setVisibility(0);
                                PhotoViewer.this.pickerViewSendButton.setVisibility(0);
                                PhotoViewer.this.actionBar.setVisibility(0);
                                if (PhotoViewer.this.needCaptionLayout) {
                                    PhotoViewer.this.captionTextView.setVisibility(PhotoViewer.this.captionTextView.getTag() != null ? 0 : 4);
                                }
                                if (PhotoViewer.this.sendPhotoType == 0 || PhotoViewer.this.sendPhotoType == 4 || ((PhotoViewer.this.sendPhotoType == 2 || PhotoViewer.this.sendPhotoType == 5) && PhotoViewer.this.imagesArrLocals.size() > 1)) {
                                    PhotoViewer.this.checkImageView.setVisibility(0);
                                    PhotoViewer.this.photosCounterView.setVisibility(0);
                                } else if (PhotoViewer.this.sendPhotoType == 1) {
                                    PhotoViewer.this.setCropTranslations(false);
                                }
                            }
                        });
                        animatorSet.start();
                    }
                });
                this.imageMoveAnimation.start();
                return;
            }
            if (mode == 1) {
                createCropView();
                this.photoCropView.onAppear();
                this.editorDoneLayout.doneButton.setText(LocaleController.getString("Crop", R.string.Crop));
                this.editorDoneLayout.doneButton.setTextColor(-11420173);
                this.changeModeAnimation = new AnimatorSet();
                ArrayList<Animator> arrayList = new ArrayList<>();
                arrayList.add(ObjectAnimator.ofFloat(this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                arrayList.add(ObjectAnimator.ofFloat(this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                arrayList.add(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f, -this.actionBar.getHeight()));
                if (this.needCaptionLayout) {
                    arrayList.add(ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                }
                int i3 = this.sendPhotoType;
                if (i3 == 0 || i3 == 4) {
                    arrayList.add(ObjectAnimator.ofFloat(this.checkImageView, (Property<CheckBox, Float>) View.ALPHA, 1.0f, 0.0f));
                    arrayList.add(ObjectAnimator.ofFloat(this.photosCounterView, (Property<CounterView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                if (this.selectedPhotosListView.getVisibility() == 0) {
                    arrayList.add(ObjectAnimator.ofFloat(this.selectedPhotosListView, (Property<RecyclerListView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                if (this.mShowNeedAddMorePicButton && this.cameraItem.getTag() != null) {
                    arrayList.add(ObjectAnimator.ofFloat(this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.changeModeAnimation.playTogether(arrayList);
                this.changeModeAnimation.setDuration(200L);
                this.changeModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.33
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        PhotoViewer.this.changeModeAnimation = null;
                        PhotoViewer.this.pickerView.setVisibility(8);
                        PhotoViewer.this.pickerViewSendButton.setVisibility(8);
                        PhotoViewer.this.cameraItem.setVisibility(8);
                        PhotoViewer.this.selectedPhotosListView.setVisibility(8);
                        PhotoViewer.this.selectedPhotosListView.setAlpha(0.0f);
                        PhotoViewer.this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
                        PhotoViewer.this.photosCounterView.setRotationX(0.0f);
                        PhotoViewer.this.selectedPhotosListView.setEnabled(false);
                        PhotoViewer.this.isPhotosListViewVisible = false;
                        if (PhotoViewer.this.needCaptionLayout) {
                            PhotoViewer.this.captionTextView.setVisibility(4);
                        }
                        if (PhotoViewer.this.sendPhotoType == 0 || PhotoViewer.this.sendPhotoType == 4 || ((PhotoViewer.this.sendPhotoType == 2 || PhotoViewer.this.sendPhotoType == 5) && PhotoViewer.this.imagesArrLocals.size() > 1)) {
                            PhotoViewer.this.checkImageView.setVisibility(8);
                            PhotoViewer.this.photosCounterView.setVisibility(8);
                        }
                        Bitmap bitmap3 = PhotoViewer.this.centerImage.getBitmap();
                        if (bitmap3 != null) {
                            PhotoViewer.this.photoCropView.setBitmap(bitmap3, PhotoViewer.this.centerImage.getOrientation(), PhotoViewer.this.sendPhotoType != 1, false);
                            PhotoViewer.this.photoCropView.onDisappear();
                            int bitmapWidth2 = PhotoViewer.this.centerImage.getBitmapWidth();
                            int bitmapHeight2 = PhotoViewer.this.centerImage.getBitmapHeight();
                            float scaleX2 = PhotoViewer.this.getContainerViewWidth() / bitmapWidth2;
                            float scaleY2 = PhotoViewer.this.getContainerViewHeight() / bitmapHeight2;
                            float newScaleX2 = PhotoViewer.this.getContainerViewWidth(1) / bitmapWidth2;
                            float newScaleY2 = PhotoViewer.this.getContainerViewHeight(1) / bitmapHeight2;
                            float scale2 = scaleX2 > scaleY2 ? scaleY2 : scaleX2;
                            float newScale2 = newScaleX2 > newScaleY2 ? newScaleY2 : newScaleX2;
                            if (PhotoViewer.this.sendPhotoType == 1) {
                                float minSide = Math.min(PhotoViewer.this.getContainerViewWidth(1), PhotoViewer.this.getContainerViewHeight(1));
                                float newScaleX3 = minSide / bitmapWidth2;
                                float newScaleY3 = minSide / bitmapHeight2;
                                newScale2 = newScaleX3 > newScaleY3 ? newScaleX3 : newScaleY3;
                            }
                            PhotoViewer.this.animateToScale = newScale2 / scale2;
                            PhotoViewer.this.animateToX = (r14.getLeftInset() / 2) - (PhotoViewer.this.getRightInset() / 2);
                            PhotoViewer.this.animateToY = (-AndroidUtilities.dp(56.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
                            PhotoViewer.this.animationStartTime = System.currentTimeMillis();
                            PhotoViewer.this.zoomAnimation = true;
                        }
                        PhotoViewer.this.imageMoveAnimation = new AnimatorSet();
                        PhotoViewer.this.imageMoveAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this.editorDoneLayout, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(48.0f), 0.0f), ObjectAnimator.ofFloat(PhotoViewer.this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f, 1.0f));
                        PhotoViewer.this.imageMoveAnimation.setDuration(200L);
                        PhotoViewer.this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.33.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                                PhotoViewer.this.editorDoneLayout.setVisibility(0);
                                PhotoViewer.this.photoCropView.setVisibility(0);
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                PhotoViewer.this.photoCropView.onAppeared();
                                PhotoViewer.this.imageMoveAnimation = null;
                                PhotoViewer.this.currentEditMode = mode;
                                PhotoViewer.this.animateToScale = 1.0f;
                                PhotoViewer.this.animateToX = 0.0f;
                                PhotoViewer.this.animateToY = 0.0f;
                                PhotoViewer.this.scale = 1.0f;
                                PhotoViewer.this.updateMinMax(PhotoViewer.this.scale);
                                PhotoViewer.this.padImageForHorizontalInsets = true;
                                PhotoViewer.this.containerView.invalidate();
                            }
                        });
                        PhotoViewer.this.imageMoveAnimation.start();
                    }
                });
                this.changeModeAnimation.start();
                return;
            }
            if (mode == 2) {
                if (this.photoFilterView == null) {
                    MediaController.SavedFilterState state = null;
                    String originalPath = null;
                    int orientation = 0;
                    if (!this.imagesArrLocals.isEmpty()) {
                        Object object = this.imagesArrLocals.get(this.currentIndex);
                        if (object instanceof MediaController.PhotoEntry) {
                            MediaController.PhotoEntry entry = (MediaController.PhotoEntry) object;
                            if (entry.imagePath == null) {
                                originalPath = entry.path;
                                state = entry.savedFilterState;
                            }
                            orientation = entry.orientation;
                        } else if (object instanceof MediaController.SearchImage) {
                            MediaController.SearchImage entry2 = (MediaController.SearchImage) object;
                            state = entry2.savedFilterState;
                            originalPath = entry2.imageUrl;
                        }
                    }
                    if (state == null) {
                        bitmap = this.centerImage.getBitmap();
                        orientation = this.centerImage.getOrientation();
                    } else {
                        bitmap = BitmapFactory.decodeFile(originalPath);
                    }
                    PhotoFilterView photoFilterView = new PhotoFilterView(this.parentActivity, bitmap, orientation, state);
                    this.photoFilterView = photoFilterView;
                    this.containerView.addView(photoFilterView, LayoutHelper.createFrame(-1, -1.0f));
                    this.photoFilterView.getDoneTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$QQtBf7T52nBBY3xftv-Y6RL1ays
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) throws JSONException {
                            this.f$0.lambda$switchToEditMode$38$PhotoViewer(view);
                        }
                    });
                    this.photoFilterView.getCancelTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$ZuSauCLQtqaFWTcsKCvC0bRoJ3Y
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) throws JSONException {
                            this.f$0.lambda$switchToEditMode$40$PhotoViewer(view);
                        }
                    });
                    this.photoFilterView.getToolsView().setTranslationY(AndroidUtilities.dp(186.0f));
                }
                this.changeModeAnimation = new AnimatorSet();
                ArrayList<Animator> arrayList2 = new ArrayList<>();
                arrayList2.add(ObjectAnimator.ofFloat(this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                arrayList2.add(ObjectAnimator.ofFloat(this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                arrayList2.add(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f, -this.actionBar.getHeight()));
                int i4 = this.sendPhotoType;
                if (i4 == 0 || i4 == 4) {
                    arrayList2.add(ObjectAnimator.ofFloat(this.checkImageView, (Property<CheckBox, Float>) View.ALPHA, 1.0f, 0.0f));
                    arrayList2.add(ObjectAnimator.ofFloat(this.photosCounterView, (Property<CounterView, Float>) View.ALPHA, 1.0f, 0.0f));
                } else if (i4 == 1) {
                    arrayList2.add(ObjectAnimator.ofFloat(this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                if (this.selectedPhotosListView.getVisibility() == 0) {
                    arrayList2.add(ObjectAnimator.ofFloat(this.selectedPhotosListView, (Property<RecyclerListView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                if (this.mShowNeedAddMorePicButton && this.cameraItem.getTag() != null) {
                    arrayList2.add(ObjectAnimator.ofFloat(this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.changeModeAnimation.playTogether(arrayList2);
                this.changeModeAnimation.setDuration(200L);
                this.changeModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.34
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        PhotoViewer.this.changeModeAnimation = null;
                        PhotoViewer.this.pickerView.setVisibility(8);
                        PhotoViewer.this.pickerViewSendButton.setVisibility(8);
                        PhotoViewer.this.actionBar.setVisibility(8);
                        PhotoViewer.this.cameraItem.setVisibility(8);
                        PhotoViewer.this.selectedPhotosListView.setVisibility(8);
                        PhotoViewer.this.selectedPhotosListView.setAlpha(0.0f);
                        PhotoViewer.this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
                        PhotoViewer.this.photosCounterView.setRotationX(0.0f);
                        PhotoViewer.this.selectedPhotosListView.setEnabled(false);
                        PhotoViewer.this.isPhotosListViewVisible = false;
                        if (PhotoViewer.this.needCaptionLayout) {
                            PhotoViewer.this.captionTextView.setVisibility(4);
                        }
                        if (PhotoViewer.this.sendPhotoType == 0 || PhotoViewer.this.sendPhotoType == 4 || ((PhotoViewer.this.sendPhotoType == 2 || PhotoViewer.this.sendPhotoType == 5) && PhotoViewer.this.imagesArrLocals.size() > 1)) {
                            PhotoViewer.this.checkImageView.setVisibility(8);
                            PhotoViewer.this.photosCounterView.setVisibility(8);
                        }
                        Bitmap bitmap3 = PhotoViewer.this.centerImage.getBitmap();
                        if (bitmap3 != null) {
                            int bitmapWidth2 = PhotoViewer.this.centerImage.getBitmapWidth();
                            int bitmapHeight2 = PhotoViewer.this.centerImage.getBitmapHeight();
                            float scaleX2 = PhotoViewer.this.getContainerViewWidth() / bitmapWidth2;
                            float scaleY2 = PhotoViewer.this.getContainerViewHeight() / bitmapHeight2;
                            float newScaleX2 = PhotoViewer.this.getContainerViewWidth(2) / bitmapWidth2;
                            float newScaleY2 = PhotoViewer.this.getContainerViewHeight(2) / bitmapHeight2;
                            float scale2 = scaleX2 > scaleY2 ? scaleY2 : scaleX2;
                            float newScale2 = newScaleX2 > newScaleY2 ? newScaleY2 : newScaleX2;
                            PhotoViewer.this.animateToScale = newScale2 / scale2;
                            PhotoViewer.this.animateToX = (r14.getLeftInset() / 2) - (PhotoViewer.this.getRightInset() / 2);
                            PhotoViewer.this.animateToY = (-AndroidUtilities.dp(92.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
                            PhotoViewer.this.animationStartTime = System.currentTimeMillis();
                            PhotoViewer.this.zoomAnimation = true;
                        }
                        PhotoViewer.this.imageMoveAnimation = new AnimatorSet();
                        PhotoViewer.this.imageMoveAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.photoFilterView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(186.0f), 0.0f));
                        PhotoViewer.this.imageMoveAnimation.setDuration(200L);
                        PhotoViewer.this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.34.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                PhotoViewer.this.photoFilterView.init();
                                PhotoViewer.this.imageMoveAnimation = null;
                                PhotoViewer.this.currentEditMode = mode;
                                PhotoViewer.this.animateToScale = 1.0f;
                                PhotoViewer.this.animateToX = 0.0f;
                                PhotoViewer.this.animateToY = 0.0f;
                                PhotoViewer.this.scale = 1.0f;
                                PhotoViewer.this.updateMinMax(PhotoViewer.this.scale);
                                PhotoViewer.this.padImageForHorizontalInsets = true;
                                PhotoViewer.this.containerView.invalidate();
                                if (PhotoViewer.this.sendPhotoType == 1) {
                                    PhotoViewer.this.photoCropView.reset();
                                }
                            }
                        });
                        PhotoViewer.this.imageMoveAnimation.start();
                    }
                });
                this.changeModeAnimation.start();
                return;
            }
            if (mode == 3) {
                if (this.photoPaintView == null) {
                    PhotoPaintView photoPaintView = new PhotoPaintView(this.parentActivity, this.centerImage.getBitmap(), this.centerImage.getOrientation());
                    this.photoPaintView = photoPaintView;
                    this.containerView.addView(photoPaintView, LayoutHelper.createFrame(-1, -1.0f));
                    this.photoPaintView.getDoneTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$rMP3KGOLEV9WqJD-wOb_FDqT-Ug
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) throws JSONException {
                            this.f$0.lambda$switchToEditMode$41$PhotoViewer(view);
                        }
                    });
                    this.photoPaintView.getCancelTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$km9IrgCJNdUntwpo__5snnkxhXM
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$switchToEditMode$43$PhotoViewer(view);
                        }
                    });
                    this.photoPaintView.getColorPicker().setTranslationY(AndroidUtilities.dp(126.0f));
                    this.photoPaintView.getToolsView().setTranslationY(AndroidUtilities.dp(126.0f));
                }
                this.changeModeAnimation = new AnimatorSet();
                ArrayList<Animator> arrayList3 = new ArrayList<>();
                arrayList3.add(ObjectAnimator.ofFloat(this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                arrayList3.add(ObjectAnimator.ofFloat(this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                arrayList3.add(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f, -this.actionBar.getHeight()));
                if (this.needCaptionLayout) {
                    arrayList3.add(ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(96.0f)));
                }
                int i5 = this.sendPhotoType;
                if (i5 == 0 || i5 == 4) {
                    arrayList3.add(ObjectAnimator.ofFloat(this.checkImageView, (Property<CheckBox, Float>) View.ALPHA, 1.0f, 0.0f));
                    arrayList3.add(ObjectAnimator.ofFloat(this.photosCounterView, (Property<CounterView, Float>) View.ALPHA, 1.0f, 0.0f));
                } else if (i5 == 1) {
                    arrayList3.add(ObjectAnimator.ofFloat(this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                if (this.selectedPhotosListView.getVisibility() == 0) {
                    arrayList3.add(ObjectAnimator.ofFloat(this.selectedPhotosListView, (Property<RecyclerListView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                if (this.mShowNeedAddMorePicButton && this.cameraItem.getTag() != null) {
                    arrayList3.add(ObjectAnimator.ofFloat(this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.changeModeAnimation.playTogether(arrayList3);
                this.changeModeAnimation.setDuration(200L);
                this.changeModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.35
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        PhotoViewer.this.changeModeAnimation = null;
                        PhotoViewer.this.pickerView.setVisibility(8);
                        PhotoViewer.this.pickerViewSendButton.setVisibility(8);
                        PhotoViewer.this.cameraItem.setVisibility(8);
                        PhotoViewer.this.selectedPhotosListView.setVisibility(8);
                        PhotoViewer.this.selectedPhotosListView.setAlpha(0.0f);
                        PhotoViewer.this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
                        PhotoViewer.this.photosCounterView.setRotationX(0.0f);
                        PhotoViewer.this.selectedPhotosListView.setEnabled(false);
                        PhotoViewer.this.isPhotosListViewVisible = false;
                        if (PhotoViewer.this.needCaptionLayout) {
                            PhotoViewer.this.captionTextView.setVisibility(4);
                        }
                        if (PhotoViewer.this.sendPhotoType == 0 || PhotoViewer.this.sendPhotoType == 4 || ((PhotoViewer.this.sendPhotoType == 2 || PhotoViewer.this.sendPhotoType == 5) && PhotoViewer.this.imagesArrLocals.size() > 1)) {
                            PhotoViewer.this.checkImageView.setVisibility(8);
                            PhotoViewer.this.photosCounterView.setVisibility(8);
                        }
                        Bitmap bitmap3 = PhotoViewer.this.centerImage.getBitmap();
                        if (bitmap3 != null) {
                            int bitmapWidth2 = PhotoViewer.this.centerImage.getBitmapWidth();
                            int bitmapHeight2 = PhotoViewer.this.centerImage.getBitmapHeight();
                            float scaleX2 = PhotoViewer.this.getContainerViewWidth() / bitmapWidth2;
                            float scaleY2 = PhotoViewer.this.getContainerViewHeight() / bitmapHeight2;
                            float newScaleX2 = PhotoViewer.this.getContainerViewWidth(3) / bitmapWidth2;
                            float newScaleY2 = PhotoViewer.this.getContainerViewHeight(3) / bitmapHeight2;
                            float scale2 = scaleX2 > scaleY2 ? scaleY2 : scaleX2;
                            float newScale2 = newScaleX2 > newScaleY2 ? newScaleY2 : newScaleX2;
                            PhotoViewer.this.animateToScale = newScale2 / scale2;
                            PhotoViewer.this.animateToX = (r3.getLeftInset() / 2) - (PhotoViewer.this.getRightInset() / 2);
                            PhotoViewer.this.animateToY = (-AndroidUtilities.dp(44.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
                            PhotoViewer.this.animationStartTime = System.currentTimeMillis();
                            PhotoViewer.this.zoomAnimation = true;
                        }
                        PhotoViewer.this.imageMoveAnimation = new AnimatorSet();
                        PhotoViewer.this.imageMoveAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f), ObjectAnimator.ofFloat(PhotoViewer.this.photoPaintView.getColorPicker(), (Property<ColorPicker, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f), 0.0f), ObjectAnimator.ofFloat(PhotoViewer.this.photoPaintView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f), 0.0f));
                        PhotoViewer.this.imageMoveAnimation.setDuration(200L);
                        PhotoViewer.this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.35.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                PhotoViewer.this.photoPaintView.init();
                                PhotoViewer.this.imageMoveAnimation = null;
                                PhotoViewer.this.currentEditMode = mode;
                                PhotoViewer.this.animateToScale = 1.0f;
                                PhotoViewer.this.animateToX = 0.0f;
                                PhotoViewer.this.animateToY = 0.0f;
                                PhotoViewer.this.scale = 1.0f;
                                PhotoViewer.this.updateMinMax(PhotoViewer.this.scale);
                                PhotoViewer.this.padImageForHorizontalInsets = true;
                                PhotoViewer.this.containerView.invalidate();
                                if (PhotoViewer.this.sendPhotoType == 1) {
                                    PhotoViewer.this.photoCropView.reset();
                                }
                            }
                        });
                        PhotoViewer.this.imageMoveAnimation.start();
                    }
                });
                this.changeModeAnimation.start();
            }
        }
    }

    public /* synthetic */ void lambda$switchToEditMode$38$PhotoViewer(View v) throws JSONException {
        applyCurrentEditMode();
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$switchToEditMode$40$PhotoViewer(View v) throws JSONException {
        if (this.photoFilterView.hasChanges()) {
            Activity activity = this.parentActivity;
            if (activity == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(activity);
            builder.setMessage(LocaleController.getString("DiscardChanges", R.string.DiscardChanges));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$Y9CzVgCJzhV34GkMrYPmgA-vQtA
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) throws JSONException {
                    this.f$0.lambda$null$39$PhotoViewer(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showAlertDialog(builder);
            return;
        }
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$null$39$PhotoViewer(DialogInterface dialogInterface, int i) throws JSONException {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$switchToEditMode$41$PhotoViewer(View v) throws JSONException {
        applyCurrentEditMode();
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$null$42$PhotoViewer() throws JSONException {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$switchToEditMode$43$PhotoViewer(View v) {
        this.photoPaintView.maybeShowDismissalAlert(this, this.parentActivity, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$YtSTRCN_gXz2gIN510I89PVc81M
            @Override // java.lang.Runnable
            public final void run() throws JSONException {
                this.f$0.lambda$null$42$PhotoViewer();
            }
        });
    }

    private void toggleCheckImageView(boolean show) {
        AnimatorSet animatorSet = new AnimatorSet();
        ArrayList<Animator> arrayList = new ArrayList<>();
        FrameLayout frameLayout = this.pickerView;
        Property property = View.ALPHA;
        float[] fArr = new float[1];
        fArr[0] = show ? 1.0f : 0.0f;
        arrayList.add(ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr));
        ImageView imageView = this.pickerViewSendButton;
        Property property2 = View.ALPHA;
        float[] fArr2 = new float[1];
        fArr2[0] = show ? 1.0f : 0.0f;
        arrayList.add(ObjectAnimator.ofFloat(imageView, (Property<ImageView, Float>) property2, fArr2));
        if (this.needCaptionLayout) {
            TextView textView = this.captionTextView;
            Property property3 = View.ALPHA;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(textView, (Property<TextView, Float>) property3, fArr3));
        }
        int i = this.sendPhotoType;
        if (i == 0 || i == 4) {
            CheckBox checkBox = this.checkImageView;
            Property property4 = View.ALPHA;
            float[] fArr4 = new float[1];
            fArr4[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(checkBox, (Property<CheckBox, Float>) property4, fArr4));
            CounterView counterView = this.photosCounterView;
            Property property5 = View.ALPHA;
            float[] fArr5 = new float[1];
            fArr5[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(counterView, (Property<CounterView, Float>) property5, fArr5));
        }
        animatorSet.playTogether(arrayList);
        animatorSet.setDuration(200L);
        animatorSet.start();
    }

    private void toggleMiniProgressInternal(final boolean show) {
        if (show) {
            this.miniProgressView.setVisibility(0);
        }
        AnimatorSet animatorSet = new AnimatorSet();
        this.miniProgressAnimator = animatorSet;
        Animator[] animatorArr = new Animator[1];
        RadialProgressView radialProgressView = this.miniProgressView;
        Property property = View.ALPHA;
        float[] fArr = new float[1];
        fArr[0] = show ? 1.0f : 0.0f;
        animatorArr[0] = ObjectAnimator.ofFloat(radialProgressView, (Property<RadialProgressView, Float>) property, fArr);
        animatorSet.playTogether(animatorArr);
        this.miniProgressAnimator.setDuration(200L);
        this.miniProgressAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.36
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(PhotoViewer.this.miniProgressAnimator)) {
                    if (!show) {
                        PhotoViewer.this.miniProgressView.setVisibility(4);
                    }
                    PhotoViewer.this.miniProgressAnimator = null;
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (animation.equals(PhotoViewer.this.miniProgressAnimator)) {
                    PhotoViewer.this.miniProgressAnimator = null;
                }
            }
        });
        this.miniProgressAnimator.start();
    }

    private void toggleMiniProgress(boolean show, boolean animated) {
        if (animated) {
            toggleMiniProgressInternal(show);
            if (show) {
                AnimatorSet animatorSet = this.miniProgressAnimator;
                if (animatorSet != null) {
                    animatorSet.cancel();
                    this.miniProgressAnimator = null;
                }
                AndroidUtilities.cancelRunOnUIThread(this.miniProgressShowRunnable);
                if (this.firstAnimationDelay) {
                    this.firstAnimationDelay = false;
                    toggleMiniProgressInternal(true);
                    return;
                } else {
                    AndroidUtilities.runOnUIThread(this.miniProgressShowRunnable, 500L);
                    return;
                }
            }
            AndroidUtilities.cancelRunOnUIThread(this.miniProgressShowRunnable);
            AnimatorSet animatorSet2 = this.miniProgressAnimator;
            if (animatorSet2 != null) {
                animatorSet2.cancel();
                toggleMiniProgressInternal(false);
                return;
            }
            return;
        }
        AnimatorSet animatorSet3 = this.miniProgressAnimator;
        if (animatorSet3 != null) {
            animatorSet3.cancel();
            this.miniProgressAnimator = null;
        }
        this.miniProgressView.setAlpha(show ? 1.0f : 0.0f);
        this.miniProgressView.setVisibility(show ? 0 : 4);
    }

    private void toggleActionBar(final boolean show, boolean animated) {
        AnimatorSet animatorSet = this.actionBarAnimator;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        if (show) {
            this.actionBar.setVisibility(0);
            if (this.bottomLayout.getTag() != null) {
                this.bottomLayout.setVisibility(0);
            }
            if (this.captionTextView.getTag() != null) {
                this.captionTextView.setVisibility(0);
                VideoSeekPreviewImage videoSeekPreviewImage = this.videoPreviewFrame;
                if (videoSeekPreviewImage != null) {
                    videoSeekPreviewImage.requestLayout();
                }
            }
        }
        this.isActionBarVisible = show;
        if (Build.VERSION.SDK_INT >= 21 && this.sendPhotoType != 1) {
            int flags = 4 | ((this.containerView.getPaddingLeft() > 0 || this.containerView.getPaddingRight() > 0) ? InputDeviceCompat.SOURCE_TOUCHSCREEN : 0);
            if (show) {
                FrameLayoutDrawer frameLayoutDrawer = this.containerView;
                frameLayoutDrawer.setSystemUiVisibility(frameLayoutDrawer.getSystemUiVisibility() & (~flags));
            } else {
                FrameLayoutDrawer frameLayoutDrawer2 = this.containerView;
                frameLayoutDrawer2.setSystemUiVisibility(frameLayoutDrawer2.getSystemUiVisibility() | flags);
            }
        }
        if (animated) {
            ArrayList<Animator> arrayList = new ArrayList<>();
            ActionBar actionBar = this.actionBar;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(actionBar, (Property<ActionBar, Float>) property, fArr));
            FrameLayout frameLayout = this.bottomLayout;
            if (frameLayout != null) {
                Property property2 = View.ALPHA;
                float[] fArr2 = new float[1];
                fArr2[0] = show ? 1.0f : 0.0f;
                arrayList.add(ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property2, fArr2));
            }
            GroupedPhotosListView groupedPhotosListView = this.groupedPhotosListView;
            Property property3 = View.ALPHA;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(groupedPhotosListView, (Property<GroupedPhotosListView, Float>) property3, fArr3));
            if (this.captionTextView.getTag() != null) {
                TextView textView = this.captionTextView;
                Property property4 = View.ALPHA;
                float[] fArr4 = new float[1];
                fArr4[0] = show ? 1065353216 : 0;
                arrayList.add(ObjectAnimator.ofFloat(textView, (Property<TextView, Float>) property4, fArr4));
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.actionBarAnimator = animatorSet2;
            animatorSet2.playTogether(arrayList);
            this.actionBarAnimator.setDuration(200L);
            this.actionBarAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.37
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(PhotoViewer.this.actionBarAnimator)) {
                        if (!show) {
                            PhotoViewer.this.actionBar.setVisibility(4);
                            if (PhotoViewer.this.bottomLayout.getTag() != null) {
                                PhotoViewer.this.bottomLayout.setVisibility(4);
                            }
                            if (PhotoViewer.this.captionTextView.getTag() != null) {
                                PhotoViewer.this.captionTextView.setVisibility(4);
                            }
                        }
                        PhotoViewer.this.actionBarAnimator = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (animation.equals(PhotoViewer.this.actionBarAnimator)) {
                        PhotoViewer.this.actionBarAnimator = null;
                    }
                }
            });
            this.actionBarAnimator.start();
            return;
        }
        this.actionBar.setAlpha(show ? 1.0f : 0.0f);
        this.bottomLayout.setAlpha(show ? 1.0f : 0.0f);
        this.groupedPhotosListView.setAlpha(show ? 1.0f : 0.0f);
        this.captionTextView.setAlpha(show ? 1065353216 : 0);
    }

    private void togglePhotosListView(boolean show, boolean animated) {
        if (show == this.isPhotosListViewVisible) {
            return;
        }
        if (show) {
            this.selectedPhotosListView.setVisibility(0);
        }
        this.isPhotosListViewVisible = show;
        this.selectedPhotosListView.setEnabled(show);
        if (animated) {
            ArrayList<Animator> arrayList = new ArrayList<>();
            RecyclerListView recyclerListView = this.selectedPhotosListView;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(recyclerListView, (Property<RecyclerListView, Float>) property, fArr));
            RecyclerListView recyclerListView2 = this.selectedPhotosListView;
            Property property2 = View.TRANSLATION_Y;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 0.0f : -AndroidUtilities.dp(10.0f);
            arrayList.add(ObjectAnimator.ofFloat(recyclerListView2, (Property<RecyclerListView, Float>) property2, fArr2));
            CounterView counterView = this.photosCounterView;
            Property property3 = View.ROTATION_X;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            arrayList.add(ObjectAnimator.ofFloat(counterView, (Property<CounterView, Float>) property3, fArr3));
            AnimatorSet animatorSet = new AnimatorSet();
            this.currentListViewAnimation = animatorSet;
            animatorSet.playTogether(arrayList);
            if (!show) {
                this.currentListViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.38
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (PhotoViewer.this.currentListViewAnimation != null && PhotoViewer.this.currentListViewAnimation.equals(animation)) {
                            PhotoViewer.this.selectedPhotosListView.setVisibility(8);
                            PhotoViewer.this.currentListViewAnimation = null;
                        }
                    }
                });
            }
            this.currentListViewAnimation.setDuration(200L);
            this.currentListViewAnimation.start();
            return;
        }
        this.selectedPhotosListView.setAlpha(show ? 1.0f : 0.0f);
        this.selectedPhotosListView.setTranslationY(show ? 0.0f : -AndroidUtilities.dp(10.0f));
        this.photosCounterView.setRotationX(show ? 1.0f : 0.0f);
        if (!show) {
            this.selectedPhotosListView.setVisibility(8);
        }
    }

    private String getFileName(int index) {
        ImageLocation location;
        if (index < 0) {
            return null;
        }
        if (!this.secureDocuments.isEmpty()) {
            if (index >= this.secureDocuments.size()) {
                return null;
            }
            SecureDocument location2 = this.secureDocuments.get(index);
            return location2.secureFile.dc_id + "_" + location2.secureFile.id + ".jpg";
        }
        if (!this.imagesArrLocations.isEmpty() || !this.imagesArr.isEmpty()) {
            if (!this.imagesArrLocations.isEmpty()) {
                if (index >= this.imagesArrLocations.size() || (location = this.imagesArrLocations.get(index)) == null) {
                    return null;
                }
                return location.location.volume_id + "_" + location.location.local_id + ".jpg";
            }
            if (this.imagesArr.isEmpty() || index >= this.imagesArr.size()) {
                return null;
            }
            return FileLoader.getMessageFileName(this.imagesArr.get(index).messageOwner);
        }
        if (this.imagesArrLocals.isEmpty() || index >= this.imagesArrLocals.size()) {
            return null;
        }
        Object object = this.imagesArrLocals.get(index);
        if (object instanceof MediaController.SearchImage) {
            MediaController.SearchImage searchImage = (MediaController.SearchImage) object;
            return searchImage.getAttachName();
        }
        if (object instanceof TLRPC.BotInlineResult) {
            TLRPC.BotInlineResult botInlineResult = (TLRPC.BotInlineResult) object;
            if (botInlineResult.document != null) {
                return FileLoader.getAttachFileName(botInlineResult.document);
            }
            if (botInlineResult.photo != null) {
                TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(botInlineResult.photo.sizes, AndroidUtilities.getPhotoSize());
                return FileLoader.getAttachFileName(sizeFull);
            }
            if (botInlineResult.content instanceof TLRPC.TL_webDocument) {
                return Utilities.MD5(botInlineResult.content.url) + "." + ImageLoader.getHttpUrlExtension(botInlineResult.content.url, FileLoader.getMimeTypePart(botInlineResult.content.mime_type));
            }
        }
        return null;
    }

    private ImageLocation getImageLocation(int index, int[] size) {
        if (index < 0) {
            return null;
        }
        if (!this.secureDocuments.isEmpty()) {
            if (index >= this.secureDocuments.size()) {
                return null;
            }
            if (size != null) {
                size[0] = this.secureDocuments.get(index).secureFile.size;
            }
            return ImageLocation.getForSecureDocument(this.secureDocuments.get(index));
        }
        if (!this.imagesArrLocations.isEmpty()) {
            if (index >= this.imagesArrLocations.size()) {
                return null;
            }
            if (size != null) {
                size[0] = this.imagesArrLocationsSizes.get(index).intValue();
            }
            return this.imagesArrLocations.get(index);
        }
        if (this.imagesArr.isEmpty() || index >= this.imagesArr.size()) {
            return null;
        }
        MessageObject message = this.imagesArr.get(index);
        if (message.messageOwner instanceof TLRPC.TL_messageService) {
            if (message.messageOwner.action instanceof TLRPC.TL_messageActionUserUpdatedPhoto) {
                return null;
            }
            TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(message.photoThumbs, AndroidUtilities.getPhotoSize());
            if (sizeFull != null) {
                if (size != null) {
                    size[0] = sizeFull.size;
                    if (size[0] == 0) {
                        size[0] = -1;
                    }
                }
                return ImageLocation.getForObject(sizeFull, message.photoThumbsObject);
            }
            if (size != null) {
                size[0] = -1;
            }
        } else if (((message.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) && message.messageOwner.media.photo != null) || ((message.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && message.messageOwner.media.webpage != null)) {
            if (message.isGif()) {
                return ImageLocation.getForDocument(message.getDocument());
            }
            TLRPC.PhotoSize sizeFull2 = FileLoader.getClosestPhotoSizeWithSize(message.photoThumbs, AndroidUtilities.getPhotoSize());
            if (sizeFull2 != null) {
                if (size != null) {
                    size[0] = sizeFull2.size;
                    if (size[0] == 0) {
                        size[0] = -1;
                    }
                }
                return ImageLocation.getForObject(sizeFull2, message.photoThumbsObject);
            }
            if (size != null) {
                size[0] = -1;
            }
        } else {
            if (message.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice) {
                return ImageLocation.getForWebFile(WebFile.createWithWebDocument(((TLRPC.TL_messageMediaInvoice) message.messageOwner.media).photo));
            }
            if (message.getDocument() != null && MessageObject.isDocumentHasThumb(message.getDocument())) {
                TLRPC.Document document = message.getDocument();
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
                if (size != null) {
                    size[0] = thumb.size;
                    if (size[0] == 0) {
                        size[0] = -1;
                    }
                }
                return ImageLocation.getForDocument(thumb, document);
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLObject getFileLocation(int index, int[] size) {
        if (index < 0) {
            return null;
        }
        if (!this.secureDocuments.isEmpty()) {
            if (index >= this.secureDocuments.size()) {
                return null;
            }
            if (size != null) {
                size[0] = this.secureDocuments.get(index).secureFile.size;
            }
            return this.secureDocuments.get(index);
        }
        if (!this.imagesArrLocations.isEmpty()) {
            if (index >= this.imagesArrLocations.size()) {
                return null;
            }
            if (size != null) {
                size[0] = this.imagesArrLocationsSizes.get(index).intValue();
            }
            return this.imagesArrLocations.get(index).location;
        }
        if (this.imagesArr.isEmpty() || index >= this.imagesArr.size()) {
            return null;
        }
        MessageObject message = this.imagesArr.get(index);
        if (message.messageOwner instanceof TLRPC.TL_messageService) {
            if (message.messageOwner.action instanceof TLRPC.TL_messageActionUserUpdatedPhoto) {
                return message.messageOwner.action.newUserPhoto.photo_big;
            }
            TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(message.photoThumbs, AndroidUtilities.getPhotoSize());
            if (sizeFull != null) {
                if (size != null) {
                    size[0] = sizeFull.size;
                    if (size[0] == 0) {
                        size[0] = -1;
                    }
                }
                return sizeFull;
            }
            if (size != null) {
                size[0] = -1;
            }
        } else if (((message.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) && message.messageOwner.media.photo != null) || ((message.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && message.messageOwner.media.webpage != null)) {
            TLRPC.PhotoSize sizeFull2 = FileLoader.getClosestPhotoSizeWithSize(message.photoThumbs, AndroidUtilities.getPhotoSize());
            if (sizeFull2 != null) {
                if (size != null) {
                    size[0] = sizeFull2.size;
                    if (size[0] == 0) {
                        size[0] = -1;
                    }
                }
                return sizeFull2;
            }
            if (size != null) {
                size[0] = -1;
            }
        } else {
            if (message.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice) {
                return ((TLRPC.TL_messageMediaInvoice) message.messageOwner.media).photo;
            }
            if (message.getDocument() != null && MessageObject.isDocumentHasThumb(message.getDocument())) {
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(message.getDocument().thumbs, 90);
                if (size != null) {
                    size[0] = thumb.size;
                    if (size[0] == 0) {
                        size[0] = -1;
                    }
                }
                return thumb;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSelectedCount() {
        PhotoViewerProvider photoViewerProvider = this.placeProvider;
        if (photoViewerProvider == null) {
            return;
        }
        int count = photoViewerProvider.getSelectedCount();
        this.photosCounterView.setCount(count);
        if (count == 0) {
            togglePhotosListView(false, true);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:229:0x05f0  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x05f4  */
    /* JADX WARN: Removed duplicated region for block: B:245:0x0639  */
    /* JADX WARN: Removed duplicated region for block: B:294:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void onPhotoShow(im.uwrkaxlmjj.messenger.MessageObject r25, im.uwrkaxlmjj.tgnet.TLRPC.FileLocation r26, im.uwrkaxlmjj.messenger.ImageLocation r27, java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r28, java.util.ArrayList<im.uwrkaxlmjj.messenger.SecureDocument> r29, java.util.ArrayList<java.lang.Object> r30, int r31, im.uwrkaxlmjj.ui.PhotoViewer.PlaceProviderObject r32) {
        /*
            Method dump skipped, instruction units count: 1711
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PhotoViewer.onPhotoShow(im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.tgnet.TLRPC$FileLocation, im.uwrkaxlmjj.messenger.ImageLocation, java.util.ArrayList, java.util.ArrayList, java.util.ArrayList, int, im.uwrkaxlmjj.ui.PhotoViewer$PlaceProviderObject):void");
    }

    private void setDoubleTapEnabled(boolean value) {
        this.doubleTapEnabled = value;
        this.gestureDetector.setOnDoubleTapListener(value ? this : null);
    }

    public boolean isMuteVideo() {
        return this.muteVideo;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setImages() {
        if (this.animationInProgress == 0) {
            setIndexToImage(this.centerImage, this.currentIndex);
            setIndexToImage(this.rightImage, this.currentIndex + 1);
            setIndexToImage(this.leftImage, this.currentIndex - 1);
        }
    }

    public void setNeedMore(boolean need) {
        this.mShowNeedAddMorePicButton = need;
        this.cameraItem.setVisibility(need ? 0 : 4);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r8v5 */
    /* JADX WARN: Type inference failed for: r8v6, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r8v7 */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    private void setIsAboutToSwitchToIndex(int index, boolean init) {
        boolean isVideo;
        boolean isVideo2;
        float end;
        boolean isMuted;
        CharSequence caption;
        boolean isVideo3;
        ?? r8;
        long date;
        boolean z;
        int loadFromMaxId;
        if (!init && this.switchingToIndex == index) {
            return;
        }
        this.switchingToIndex = index;
        boolean isVideo4 = false;
        String newFileName = getFileName(index);
        MessageObject newMessageObject = null;
        if (this.imagesArr.isEmpty()) {
            CharSequence caption2 = null;
            if (!this.secureDocuments.isEmpty()) {
                this.allowShare = false;
                this.menuItem.hideSubItem(1);
                this.nameTextView.setText("");
                this.dateTextView.setText("");
                this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(this.switchingToIndex + 1), Integer.valueOf(this.secureDocuments.size())));
                isVideo = false;
            } else if (!this.imagesArrLocations.isEmpty()) {
                if (index < 0 || index >= this.imagesArrLocations.size()) {
                    return;
                }
                this.nameTextView.setText("");
                this.dateTextView.setText("");
                if (this.avatarsDialogId != UserConfig.getInstance(this.currentAccount).getClientUserId() || this.avatarsArr.isEmpty()) {
                    this.menuItem.hideSubItem(6);
                } else {
                    this.menuItem.showSubItem(6);
                }
                if (this.isEvent) {
                    this.actionBar.setTitle(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
                    r8 = 1;
                } else {
                    r8 = 1;
                    this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(this.switchingToIndex + 1), Integer.valueOf(this.imagesArrLocations.size())));
                }
                this.menuItem.showSubItem(r8);
                this.allowShare = r8;
                this.shareButton.setVisibility(this.videoPlayerControlFrameLayout.getVisibility() != 0 ? 0 : 8);
                if (this.shareButton.getVisibility() == 0) {
                    this.menuItem.hideSubItem(10);
                } else {
                    this.menuItem.showSubItem(10);
                }
                this.groupedPhotosListView.fillList();
                isVideo = false;
            } else if (this.imagesArrLocals.isEmpty()) {
                isVideo = false;
            } else {
                if (index >= 0 && index < this.imagesArrLocals.size()) {
                    Object object = this.imagesArrLocals.get(index);
                    int ttl = 0;
                    boolean isFiltered = false;
                    boolean isPainted = false;
                    boolean isCropped = false;
                    if (object instanceof TLRPC.BotInlineResult) {
                        TLRPC.BotInlineResult botInlineResult = (TLRPC.BotInlineResult) object;
                        this.currentBotInlineResult = botInlineResult;
                        if (botInlineResult.document != null) {
                            isVideo4 = MessageObject.isVideoDocument(botInlineResult.document);
                        } else if (botInlineResult.content instanceof TLRPC.TL_webDocument) {
                            isVideo4 = botInlineResult.type.equals("video");
                        }
                        isVideo2 = isVideo4;
                    } else {
                        String pathObject = null;
                        boolean isAnimation = false;
                        if (object instanceof MediaController.PhotoEntry) {
                            MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                            pathObject = photoEntry.path;
                            isVideo4 = photoEntry.isVideo;
                        } else if (object instanceof MediaController.SearchImage) {
                            MediaController.SearchImage searchImage = (MediaController.SearchImage) object;
                            pathObject = searchImage.getPathToAttach();
                            if (searchImage.type != 1) {
                                isVideo4 = false;
                            } else {
                                isAnimation = true;
                                isVideo4 = false;
                            }
                        }
                        if (isVideo4) {
                            this.muteItem.setVisibility(0);
                            this.compressItem.setVisibility(0);
                            this.isCurrentVideo = true;
                            updateAccessibilityOverlayVisibility();
                            float start = 0.0f;
                            boolean isMuted2 = object instanceof MediaController.PhotoEntry;
                            if (!isMuted2) {
                                isVideo2 = isVideo4;
                            } else {
                                MediaController.PhotoEntry photoEntry2 = (MediaController.PhotoEntry) object;
                                isVideo2 = isVideo4;
                                if (photoEntry2.editedInfo != null) {
                                    boolean isMuted3 = photoEntry2.editedInfo.muted;
                                    start = photoEntry2.editedInfo.start;
                                    end = photoEntry2.editedInfo.end;
                                    isMuted = isMuted3;
                                }
                                processOpenVideo(pathObject, isMuted, start, end);
                                this.videoTimelineView.setVisibility(0);
                                this.muteItem.setVisibility(0);
                                this.compressItem.setVisibility(0);
                                this.paintItem.setVisibility(8);
                                this.cropItem.setVisibility(8);
                                this.tuneItem.setVisibility(8);
                                this.rotateItem.setVisibility(8);
                            }
                            end = 1.0f;
                            isMuted = false;
                            processOpenVideo(pathObject, isMuted, start, end);
                            this.videoTimelineView.setVisibility(0);
                            this.muteItem.setVisibility(0);
                            this.compressItem.setVisibility(0);
                            this.paintItem.setVisibility(8);
                            this.cropItem.setVisibility(8);
                            this.tuneItem.setVisibility(8);
                            this.rotateItem.setVisibility(8);
                        } else {
                            isVideo2 = isVideo4;
                            this.videoTimelineView.setVisibility(8);
                            this.muteItem.setVisibility(8);
                            this.isCurrentVideo = false;
                            updateAccessibilityOverlayVisibility();
                            this.compressItem.setVisibility(8);
                            if (isAnimation) {
                                this.paintItem.setVisibility(8);
                                this.cropItem.setVisibility(8);
                                this.rotateItem.setVisibility(8);
                                this.tuneItem.setVisibility(8);
                            } else {
                                int i = this.sendPhotoType;
                                if (i == 4 || i == 5) {
                                    this.paintItem.setVisibility(8);
                                    this.tuneItem.setVisibility(8);
                                } else {
                                    this.paintItem.setVisibility(0);
                                    this.tuneItem.setVisibility(0);
                                }
                                this.cropItem.setVisibility(this.sendPhotoType != 1 ? 0 : 8);
                                this.rotateItem.setVisibility(this.sendPhotoType != 1 ? 8 : 0);
                            }
                            this.actionBar.setSubtitle(null);
                        }
                        if (object instanceof MediaController.PhotoEntry) {
                            MediaController.PhotoEntry photoEntry3 = (MediaController.PhotoEntry) object;
                            this.fromCamera = photoEntry3.bucketId == 0 && photoEntry3.dateTaken == 0 && this.imagesArrLocals.size() == 1;
                            CharSequence caption3 = photoEntry3.caption;
                            int ttl2 = photoEntry3.ttl;
                            isFiltered = photoEntry3.isFiltered;
                            isPainted = photoEntry3.isPainted;
                            isCropped = photoEntry3.isCropped;
                            caption2 = caption3;
                            ttl = ttl2;
                        } else if (!(object instanceof MediaController.SearchImage)) {
                            ttl = 0;
                        } else {
                            MediaController.SearchImage searchImage2 = (MediaController.SearchImage) object;
                            CharSequence caption4 = searchImage2.caption;
                            int ttl3 = searchImage2.ttl;
                            isFiltered = searchImage2.isFiltered;
                            isPainted = searchImage2.isPainted;
                            isCropped = searchImage2.isCropped;
                            caption2 = caption4;
                            ttl = ttl3;
                        }
                    }
                    if (this.bottomLayout.getVisibility() != 8) {
                        this.bottomLayout.setVisibility(8);
                    }
                    this.bottomLayout.setTag(null);
                    if (this.fromCamera) {
                        if (isVideo2) {
                            this.actionBar.setTitle(LocaleController.getString("AttachVideo", R.string.AttachVideo));
                        } else {
                            this.actionBar.setTitle(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
                        }
                    } else {
                        this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(this.switchingToIndex + 1), Integer.valueOf(this.imagesArrLocals.size())));
                    }
                    ChatActivity chatActivity = this.parentChatActivity;
                    if (chatActivity != null) {
                        TLRPC.Chat chat = chatActivity.getCurrentChat();
                        if (chat != null) {
                            this.actionBar.setTitle(chat.title);
                        } else {
                            TLRPC.User user = this.parentChatActivity.getCurrentUser();
                            if (user != null) {
                                if (user.self) {
                                    this.actionBar.setTitle(LocaleController.getString("SavedMessages", R.string.SavedMessages));
                                } else {
                                    this.actionBar.setTitle(ContactsController.formatName(user.first_name, user.last_name));
                                }
                            }
                        }
                    }
                    int i2 = this.sendPhotoType;
                    if (i2 == 0 || i2 == 4 || ((i2 == 2 || i2 == 5) && this.imagesArrLocals.size() > 1)) {
                        this.checkImageView.setChecked(this.placeProvider.isPhotoChecked(this.switchingToIndex), false);
                    }
                    updateCaptionTextForCurrentPhoto(object);
                    PorterDuffColorFilter filter = new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY);
                    this.timeItem.setColorFilter(ttl != 0 ? filter : null);
                    this.paintItem.setColorFilter(isPainted ? filter : null);
                    this.cropItem.setColorFilter(isCropped ? filter : null);
                    this.tuneItem.setColorFilter(isFiltered ? filter : null);
                    caption = caption2;
                    isVideo3 = isVideo2;
                }
                return;
            }
            isVideo3 = isVideo;
            caption = null;
        } else {
            int i3 = this.switchingToIndex;
            if (i3 >= 0 && i3 < this.imagesArr.size()) {
                newMessageObject = this.imagesArr.get(this.switchingToIndex);
                boolean isVideo5 = newMessageObject.isVideo();
                boolean isInvoice = newMessageObject.isInvoice();
                if (isInvoice) {
                    this.masksItem.setVisibility(8);
                    this.menuItem.hideSubItem(6);
                    this.menuItem.hideSubItem(11);
                    caption = newMessageObject.messageOwner.media.description;
                    this.allowShare = false;
                    this.bottomLayout.setTranslationY(AndroidUtilities.dp(48.0f));
                    this.captionTextView.setTranslationY(AndroidUtilities.dp(48.0f));
                    isVideo3 = isVideo5;
                } else {
                    this.masksItem.setVisibility((!newMessageObject.hasPhotoStickers() || ((int) newMessageObject.getDialogId()) == 0) ? 8 : 0);
                    ChatActivity chatActivity2 = this.parentChatActivity;
                    if (!newMessageObject.canDeleteMessage(chatActivity2 != null && chatActivity2.isInScheduleMode(), null) || this.slideshowMessageId != 0) {
                        this.menuItem.hideSubItem(6);
                    } else {
                        this.menuItem.showSubItem(6);
                    }
                    if (isVideo5) {
                        this.menuItem.showSubItem(11);
                        if (this.pipItem.getVisibility() == 0) {
                            z = false;
                        } else {
                            z = false;
                            this.pipItem.setVisibility(0);
                        }
                        if (!this.pipAvailable) {
                            this.pipItem.setEnabled(z);
                            this.pipItem.setAlpha(0.5f);
                        }
                    } else {
                        this.menuItem.hideSubItem(11);
                        if (this.pipItem.getVisibility() != 8) {
                            this.pipItem.setVisibility(8);
                        }
                    }
                    String str = this.nameOverride;
                    if (str != null) {
                        this.nameTextView.setText(str);
                    } else if (newMessageObject.isFromUser()) {
                        TLRPC.User user2 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(newMessageObject.messageOwner.from_id));
                        if (user2 != null) {
                            this.nameTextView.setText(UserObject.getName(user2));
                        } else {
                            this.nameTextView.setText("");
                        }
                    } else {
                        TLRPC.Chat chat2 = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(newMessageObject.messageOwner.to_id.channel_id));
                        if (ChatObject.isChannel(chat2) && chat2.megagroup && newMessageObject.isForwardedChannelPost()) {
                            chat2 = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(newMessageObject.messageOwner.fwd_from.channel_id));
                        }
                        if (chat2 != null) {
                            this.nameTextView.setText(chat2.title);
                        } else {
                            this.nameTextView.setText("");
                        }
                    }
                    int i4 = this.dateOverride;
                    if (i4 != 0) {
                        date = ((long) i4) * 1000;
                    } else {
                        date = ((long) newMessageObject.messageOwner.date) * 1000;
                    }
                    String dateString = LocaleController.formatString("formatDateAtTime", R.string.formatDateAtTime, LocaleController.getInstance().formatterYear.format(new Date(date)), LocaleController.getInstance().formatterDay.format(new Date(date)));
                    if (newFileName == null || !isVideo5) {
                        isVideo3 = isVideo5;
                        this.dateTextView.setText(dateString);
                    } else {
                        isVideo3 = isVideo5;
                        this.dateTextView.setText(String.format("%s (%s)", dateString, AndroidUtilities.formatFileSize(newMessageObject.getDocument().size)));
                    }
                    caption = newMessageObject.caption;
                }
                if (this.currentAnimation == null) {
                    if (this.totalImagesCount + this.totalImagesCountMerge != 0 && !this.needSearchImageInArr) {
                        if (this.opennedFromMedia) {
                            if (this.imagesArr.size() < this.totalImagesCount + this.totalImagesCountMerge && !this.loadingMoreImages && this.switchingToIndex > this.imagesArr.size() - 5) {
                                if (this.imagesArr.isEmpty()) {
                                    loadFromMaxId = 0;
                                } else {
                                    ArrayList<MessageObject> arrayList = this.imagesArr;
                                    loadFromMaxId = arrayList.get(arrayList.size() - 1).getId();
                                }
                                int loadIndex = 0;
                                if (this.endReached[0] && this.mergeDialogId != 0) {
                                    loadIndex = 1;
                                    if (!this.imagesArr.isEmpty()) {
                                        ArrayList<MessageObject> arrayList2 = this.imagesArr;
                                        if (arrayList2.get(arrayList2.size() - 1).getDialogId() != this.mergeDialogId) {
                                            loadFromMaxId = 0;
                                        }
                                    }
                                }
                                MediaDataController.getInstance(this.currentAccount).loadMedia(loadIndex == 0 ? this.currentDialogId : this.mergeDialogId, 80, loadFromMaxId, this.sharedMediaType, 1, this.classGuid);
                                this.loadingMoreImages = true;
                            }
                            this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(this.switchingToIndex + 1), Integer.valueOf(this.totalImagesCount + this.totalImagesCountMerge)));
                        } else {
                            if (this.imagesArr.size() < this.totalImagesCount + this.totalImagesCountMerge && !this.loadingMoreImages && this.switchingToIndex < 5) {
                                int loadFromMaxId2 = this.imagesArr.isEmpty() ? 0 : this.imagesArr.get(0).getId();
                                int loadIndex2 = 0;
                                if (this.endReached[0] && this.mergeDialogId != 0) {
                                    loadIndex2 = 1;
                                    if (!this.imagesArr.isEmpty() && this.imagesArr.get(0).getDialogId() != this.mergeDialogId) {
                                        loadFromMaxId2 = 0;
                                    }
                                }
                                MediaDataController.getInstance(this.currentAccount).loadMedia(loadIndex2 == 0 ? this.currentDialogId : this.mergeDialogId, 80, loadFromMaxId2, this.sharedMediaType, 1, this.classGuid);
                                this.loadingMoreImages = true;
                            } else if (this.imagesArr.size() > 0) {
                                this.totalImagesCount = this.imagesArr.size();
                            }
                            this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(((this.totalImagesCount + this.totalImagesCountMerge) - this.imagesArr.size()) + this.switchingToIndex + 1), Integer.valueOf(this.totalImagesCount + this.totalImagesCountMerge)));
                        }
                    } else if (this.slideshowMessageId == 0 && (newMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage)) {
                        if (newMessageObject.canPreviewDocument()) {
                            this.actionBar.setTitle(LocaleController.getString("AttachDocument", R.string.AttachDocument));
                        } else if (newMessageObject.isVideo()) {
                            this.actionBar.setTitle(LocaleController.getString("AttachVideo", R.string.AttachVideo));
                        } else {
                            this.actionBar.setTitle(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
                        }
                    } else if (isInvoice) {
                        this.actionBar.setTitle(newMessageObject.messageOwner.media.title);
                    } else if (newMessageObject.isVideo()) {
                        this.actionBar.setTitle(LocaleController.getString("AttachVideo", R.string.AttachVideo));
                    } else if (newMessageObject.getDocument() != null) {
                        this.actionBar.setTitle(LocaleController.getString("AttachDocument", R.string.AttachDocument));
                    }
                    if (((int) this.currentDialogId) == 0) {
                        this.sendItem.setVisibility(8);
                    }
                    if (newMessageObject.messageOwner.ttl == 0 || newMessageObject.messageOwner.ttl >= 3600) {
                        this.allowShare = true;
                        this.menuItem.showSubItem(1);
                        this.shareButton.setVisibility(this.videoPlayerControlFrameLayout.getVisibility() != 0 ? 0 : 8);
                        if (this.shareButton.getVisibility() == 0) {
                            this.menuItem.hideSubItem(10);
                        } else {
                            this.menuItem.showSubItem(10);
                        }
                    } else {
                        this.allowShare = false;
                        this.menuItem.hideSubItem(1);
                        this.shareButton.setVisibility(8);
                        this.menuItem.hideSubItem(10);
                    }
                } else {
                    this.menuItem.hideSubItem(1);
                    this.menuItem.hideSubItem(10);
                    ChatActivity chatActivity3 = this.parentChatActivity;
                    if (!newMessageObject.canDeleteMessage(chatActivity3 != null && chatActivity3.isInScheduleMode(), null)) {
                        this.menuItem.hideSubItem(6);
                    }
                    this.allowShare = true;
                    this.shareButton.setVisibility(0);
                    this.actionBar.setTitle(LocaleController.getString("AttachGif", R.string.AttachGif));
                }
                this.groupedPhotosListView.fillList();
            }
            return;
        }
        if (isVideo3) {
            this.allowShare = false;
            this.shareButton.setVisibility(0);
            this.menuItem.setVisibility(0);
            this.sendItem.setVisibility(0);
        } else {
            this.shareButton.setVisibility(0);
            this.menuItem.setVisibility(0);
            this.sendItem.setVisibility(0);
        }
        setCurrentCaption(newMessageObject, caption, !init);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.FileLocation getFileLocation(ImageLocation location) {
        if (location == null) {
            return null;
        }
        return location.location;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setImageIndex(int index, boolean init) {
        MessageObject messageObject;
        ImageReceiver.BitmapHolder bitmapHolder;
        if (this.currentIndex == index || this.placeProvider == null) {
            return;
        }
        if (!init && (bitmapHolder = this.currentThumb) != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        this.currentFileNames[0] = getFileName(index);
        this.currentFileNames[1] = getFileName(index + 1);
        this.currentFileNames[2] = getFileName(index - 1);
        this.placeProvider.willSwitchFromPhoto(this.currentMessageObject, getFileLocation(this.currentFileLocation), this.currentIndex);
        int prevIndex = this.currentIndex;
        this.currentIndex = index;
        setIsAboutToSwitchToIndex(index, init);
        boolean isVideo = false;
        boolean sameImage = false;
        Uri videoPath = null;
        if (!this.imagesArr.isEmpty()) {
            int i = this.currentIndex;
            if (i >= 0 && i < this.imagesArr.size()) {
                MessageObject newMessageObject = this.imagesArr.get(this.currentIndex);
                sameImage = init && (messageObject = this.currentMessageObject) != null && messageObject.getId() == newMessageObject.getId();
                this.currentMessageObject = newMessageObject;
                isVideo = newMessageObject.isVideo();
                if (this.sharedMediaType == 1) {
                    boolean zCanPreviewDocument = newMessageObject.canPreviewDocument();
                    this.canZoom = zCanPreviewDocument;
                    if (zCanPreviewDocument) {
                        this.menuItem.showSubItem(1);
                        setDoubleTapEnabled(true);
                    } else {
                        this.menuItem.hideSubItem(1);
                        setDoubleTapEnabled(false);
                    }
                }
            } else {
                closePhoto(false, false);
                return;
            }
        } else if (!this.secureDocuments.isEmpty()) {
            if (index >= 0 && index < this.secureDocuments.size()) {
                this.currentSecureDocument = this.secureDocuments.get(index);
            } else {
                closePhoto(false, false);
                return;
            }
        } else if (!this.imagesArrLocations.isEmpty()) {
            if (index < 0 || index >= this.imagesArrLocations.size()) {
                closePhoto(false, false);
                return;
            }
            ImageLocation old = this.currentFileLocation;
            ImageLocation newLocation = this.imagesArrLocations.get(index);
            if (init && old != null && newLocation != null && old.location.local_id == newLocation.location.local_id && old.location.volume_id == newLocation.location.volume_id) {
                sameImage = true;
            }
            this.currentFileLocation = this.imagesArrLocations.get(index);
        } else if (!this.imagesArrLocals.isEmpty()) {
            if (index < 0 || index >= this.imagesArrLocals.size()) {
                closePhoto(false, false);
                return;
            }
            Object object = this.imagesArrLocals.get(index);
            if (object instanceof TLRPC.BotInlineResult) {
                TLRPC.BotInlineResult botInlineResult = (TLRPC.BotInlineResult) object;
                this.currentBotInlineResult = botInlineResult;
                if (botInlineResult.document != null) {
                    this.currentPathObject = FileLoader.getPathToAttach(botInlineResult.document).getAbsolutePath();
                    isVideo = MessageObject.isVideoDocument(botInlineResult.document);
                } else if (botInlineResult.photo != null) {
                    this.currentPathObject = FileLoader.getPathToAttach(FileLoader.getClosestPhotoSizeWithSize(botInlineResult.photo.sizes, AndroidUtilities.getPhotoSize())).getAbsolutePath();
                } else if (botInlineResult.content instanceof TLRPC.TL_webDocument) {
                    this.currentPathObject = botInlineResult.content.url;
                    isVideo = botInlineResult.type.equals("video");
                }
            } else if (object instanceof MediaController.PhotoEntry) {
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                String str = photoEntry.path;
                this.currentPathObject = str;
                if (str == null) {
                    closePhoto(false, false);
                    return;
                } else {
                    isVideo = photoEntry.isVideo;
                    videoPath = Uri.fromFile(new File(photoEntry.path));
                }
            } else if (object instanceof MediaController.SearchImage) {
                MediaController.SearchImage searchImage = (MediaController.SearchImage) object;
                this.currentPathObject = searchImage.getPathToAttach();
            }
        }
        PlaceProviderObject placeProviderObject = this.currentPlaceObject;
        if (placeProviderObject != null) {
            if (this.animationInProgress == 0) {
                placeProviderObject.imageReceiver.setVisible(true, true);
            } else {
                this.showAfterAnimation = placeProviderObject;
            }
        }
        PlaceProviderObject placeForPhoto = this.placeProvider.getPlaceForPhoto(this.currentMessageObject, getFileLocation(this.currentFileLocation), this.currentIndex, false);
        this.currentPlaceObject = placeForPhoto;
        if (placeForPhoto != null) {
            if (this.animationInProgress == 0) {
                placeForPhoto.imageReceiver.setVisible(false, true);
            } else {
                this.hideAfterAnimation = placeForPhoto;
            }
        }
        if (!sameImage) {
            this.draggingDown = false;
            this.translationX = 0.0f;
            this.translationY = 0.0f;
            this.scale = 1.0f;
            this.animateToX = 0.0f;
            this.animateToY = 0.0f;
            this.animateToScale = 1.0f;
            this.animationStartTime = 0L;
            this.imageMoveAnimation = null;
            this.changeModeAnimation = null;
            AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
            if (aspectRatioFrameLayout != null) {
                aspectRatioFrameLayout.setVisibility(4);
            }
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
            this.changingPage = false;
            this.switchImageAfterAnimation = 0;
            if (this.sharedMediaType != 1) {
                this.canZoom = (this.imagesArrLocals.isEmpty() && (this.currentFileNames[0] == null || this.photoProgressViews[0].backgroundState == 0)) ? false : true;
            }
            updateMinMax(this.scale);
            releasePlayer(false);
        }
        if (isVideo && videoPath != null) {
            this.isStreaming = false;
            preparePlayer(videoPath, false, false);
        }
        if (prevIndex == -1) {
            setImages();
            for (int a = 0; a < 3; a++) {
                checkProgress(a, false);
            }
            return;
        }
        checkProgress(0, false);
        int i2 = this.currentIndex;
        if (prevIndex > i2) {
            ImageReceiver temp = this.rightImage;
            this.rightImage = this.centerImage;
            this.centerImage = this.leftImage;
            this.leftImage = temp;
            PhotoProgressView[] photoProgressViewArr = this.photoProgressViews;
            PhotoProgressView tempProgress = photoProgressViewArr[0];
            photoProgressViewArr[0] = photoProgressViewArr[2];
            photoProgressViewArr[2] = tempProgress;
            setIndexToImage(temp, i2 - 1);
            checkProgress(1, false);
            checkProgress(2, false);
            return;
        }
        if (prevIndex < i2) {
            ImageReceiver temp2 = this.leftImage;
            this.leftImage = this.centerImage;
            this.centerImage = this.rightImage;
            this.rightImage = temp2;
            PhotoProgressView[] photoProgressViewArr2 = this.photoProgressViews;
            PhotoProgressView tempProgress2 = photoProgressViewArr2[0];
            photoProgressViewArr2[0] = photoProgressViewArr2[1];
            photoProgressViewArr2[1] = tempProgress2;
            setIndexToImage(temp2, i2 + 1);
            checkProgress(1, false);
            checkProgress(2, false);
        }
    }

    private void setCurrentCaption(MessageObject messageObject, CharSequence caption, boolean animated) {
        CharSequence str;
        if (this.needCaptionLayout) {
            if (this.captionTextView.getParent() != this.pickerView) {
                this.captionTextView.setBackgroundDrawable(null);
                this.containerView.removeView(this.captionTextView);
                this.pickerView.addView(this.captionTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 0.0f, 0.0f, 76.0f, 48.0f));
            }
        } else if (this.captionTextView.getParent() != this.containerView) {
            this.captionTextView.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
            this.pickerView.removeView(this.captionTextView);
            this.containerView.addView(this.captionTextView, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
        }
        if (this.isCurrentVideo) {
            if (this.captionTextView.getMaxLines() != 1) {
                this.captionTextView.setMaxLines(1);
            }
            if (!this.isSingleLine) {
                TextView textView = this.captionTextView;
                this.isSingleLine = true;
                textView.setSingleLine(true);
            }
        } else {
            if (this.isSingleLine) {
                TextView textView2 = this.captionTextView;
                this.isSingleLine = false;
                textView2.setSingleLine(false);
            }
            int newCount = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? 5 : 10;
            if (this.captionTextView.getMaxLines() != newCount) {
                this.captionTextView.setMaxLines(newCount);
            }
        }
        boolean wasVisisble = this.captionTextView.getTag() != null;
        if (TextUtils.isEmpty(caption)) {
            if (this.needCaptionLayout) {
                this.captionTextView.setText(LocaleController.getString("AddCaption", R.string.AddCaption));
                this.captionTextView.setTag("empty");
                this.captionTextView.setVisibility(0);
                this.captionTextView.setTextColor(-1291845633);
                return;
            }
            this.captionTextView.setTextColor(-1);
            this.captionTextView.setTag(null);
            if (animated && wasVisisble) {
                AnimatorSet animatorSet = new AnimatorSet();
                this.currentCaptionAnimation = animatorSet;
                animatorSet.setDuration(200L);
                this.currentCaptionAnimation.setInterpolator(decelerateInterpolator);
                this.currentCaptionAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.40
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(PhotoViewer.this.currentCaptionAnimation)) {
                            PhotoViewer.this.captionTextView.setVisibility(4);
                            PhotoViewer.this.currentCaptionAnimation = null;
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (animation.equals(PhotoViewer.this.currentCaptionAnimation)) {
                            PhotoViewer.this.currentCaptionAnimation = null;
                        }
                    }
                });
                this.currentCaptionAnimation.playTogether(ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(5.0f)));
                this.currentCaptionAnimation.start();
                return;
            }
            this.captionTextView.setVisibility(4);
            return;
        }
        Theme.createChatResources(null, true);
        if (messageObject == null || messageObject.messageOwner.entities.isEmpty()) {
            str = Emoji.replaceEmoji(new SpannableStringBuilder(caption), this.captionTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
        } else {
            Spannable spannableString = SpannableString.valueOf(caption.toString());
            messageObject.addEntitiesToText(spannableString, true, false);
            CharSequence str2 = Emoji.replaceEmoji(spannableString, this.captionTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            str = str2;
        }
        this.captionTextView.setTag(str);
        AnimatorSet animatorSet2 = this.currentCaptionAnimation;
        if (animatorSet2 != null) {
            animatorSet2.cancel();
            this.currentCaptionAnimation = null;
        }
        try {
            this.captionTextView.setText(str);
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.captionTextView.setScrollY(0);
        this.captionTextView.setTextColor(-1);
        boolean visible = this.isActionBarVisible && (this.bottomLayout.getVisibility() == 0 || this.pickerView.getVisibility() == 0);
        if (visible) {
            this.captionTextView.setVisibility(0);
            if (animated && !wasVisisble) {
                AnimatorSet animatorSet3 = new AnimatorSet();
                this.currentCaptionAnimation = animatorSet3;
                animatorSet3.setDuration(200L);
                this.currentCaptionAnimation.setInterpolator(decelerateInterpolator);
                this.currentCaptionAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.39
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(PhotoViewer.this.currentCaptionAnimation)) {
                            PhotoViewer.this.currentCaptionAnimation = null;
                        }
                    }
                });
                this.currentCaptionAnimation.playTogether(ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.captionTextView, (Property<TextView, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(5.0f), 0.0f));
                this.currentCaptionAnimation.start();
                return;
            }
            this.captionTextView.setAlpha(1.0f);
            return;
        }
        if (this.captionTextView.getVisibility() == 0) {
            this.captionTextView.setVisibility(4);
            this.captionTextView.setAlpha(0.0f);
        }
    }

    private void checkProgress(final int a, final boolean animated) {
        int index;
        File f1;
        File f2;
        boolean isVideo;
        boolean canStream;
        File f22;
        int index2 = this.currentIndex;
        if (a == 1) {
            index = index2 + 1;
        } else if (a != 2) {
            index = index2;
        } else {
            index = index2 - 1;
        }
        if (this.currentFileNames[a] != null) {
            File f12 = null;
            boolean isVideo2 = false;
            if (this.currentMessageObject != null) {
                if (index < 0 || index >= this.imagesArr.size()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                }
                MessageObject messageObject = this.imagesArr.get(index);
                if (this.sharedMediaType == 1 && !messageObject.canPreviewDocument()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                }
                if (!TextUtils.isEmpty(messageObject.messageOwner.attachPath)) {
                    f12 = new File(messageObject.messageOwner.attachPath);
                }
                if ((messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && messageObject.messageOwner.media.webpage != null && messageObject.messageOwner.media.webpage.document == null) {
                    TLObject fileLocation = getFileLocation(index, null);
                    File f23 = FileLoader.getPathToAttach(fileLocation, true);
                    f22 = f23;
                } else {
                    f22 = FileLoader.getPathToMessage(messageObject.messageOwner);
                }
                boolean canStream2 = SharedConfig.streamMedia && messageObject.isVideo() && messageObject.canStreamVideo() && ((int) messageObject.getDialogId()) != 0;
                f1 = f12;
                f2 = f22;
                isVideo = messageObject.isVideo();
                canStream = canStream2;
            } else if (this.currentBotInlineResult != null) {
                if (index < 0 || index >= this.imagesArrLocals.size()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                }
                TLRPC.BotInlineResult botInlineResult = (TLRPC.BotInlineResult) this.imagesArrLocals.get(index);
                if (botInlineResult.type.equals("video") || MessageObject.isVideoDocument(botInlineResult.document)) {
                    if (botInlineResult.document != null) {
                        f12 = FileLoader.getPathToAttach(botInlineResult.document);
                    } else if (botInlineResult.content instanceof TLRPC.TL_webDocument) {
                        f12 = new File(FileLoader.getDirectory(4), Utilities.MD5(botInlineResult.content.url) + "." + ImageLoader.getHttpUrlExtension(botInlineResult.content.url, "mp4"));
                    }
                    isVideo2 = true;
                } else if (botInlineResult.document != null) {
                    f12 = new File(FileLoader.getDirectory(3), this.currentFileNames[a]);
                } else if (botInlineResult.photo != null) {
                    f12 = new File(FileLoader.getDirectory(0), this.currentFileNames[a]);
                }
                File f24 = new File(FileLoader.getDirectory(4), this.currentFileNames[a]);
                f1 = f12;
                f2 = f24;
                isVideo = isVideo2;
                canStream = false;
            } else if (this.currentFileLocation != null) {
                if (index < 0 || index >= this.imagesArrLocations.size()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                }
                ImageLocation location = this.imagesArrLocations.get(index);
                TLRPC.TL_fileLocationToBeDeprecated tL_fileLocationToBeDeprecated = location.location;
                if (this.avatarsDialogId == 0 && !this.isEvent) {
                    z = false;
                }
                f1 = FileLoader.getPathToAttach(tL_fileLocationToBeDeprecated, z);
                f2 = null;
                isVideo = false;
                canStream = false;
            } else {
                if (this.currentSecureDocument != null) {
                    if (index < 0 || index >= this.secureDocuments.size()) {
                        this.photoProgressViews[a].setBackgroundState(-1, animated);
                        return;
                    } else {
                        SecureDocument location2 = this.secureDocuments.get(index);
                        f12 = FileLoader.getPathToAttach(location2, true);
                    }
                } else if (this.currentPathObject != null) {
                    File f13 = new File(FileLoader.getDirectory(3), this.currentFileNames[a]);
                    File f25 = new File(FileLoader.getDirectory(4), this.currentFileNames[a]);
                    f1 = f13;
                    f2 = f25;
                    isVideo = false;
                    canStream = false;
                }
                f1 = f12;
                f2 = null;
                isVideo = false;
                canStream = false;
            }
            final File f1Final = f1;
            final File f2Final = f2;
            final boolean canStreamFinal = canStream;
            final boolean isVideoFianl = isVideo;
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$voJKHfzmg8v7XNrMI9GZx_o0MtU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$checkProgress$45$PhotoViewer(f1Final, f2Final, canStreamFinal, isVideoFianl, a, animated);
                }
            });
            return;
        }
        boolean isLocalVideo = false;
        if (!this.imagesArrLocals.isEmpty() && index >= 0 && index < this.imagesArrLocals.size()) {
            Object object = this.imagesArrLocals.get(index);
            if (object instanceof MediaController.PhotoEntry) {
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                isLocalVideo = photoEntry.isVideo;
            }
        }
        if (isLocalVideo) {
            this.photoProgressViews[a].setBackgroundState(3, animated);
        } else {
            this.photoProgressViews[a].setBackgroundState(-1, animated);
        }
    }

    public /* synthetic */ void lambda$checkProgress$45$PhotoViewer(final File f1Final, final File f2Final, final boolean canStreamFinal, final boolean isVideoFianl, final int a, final boolean animated) {
        boolean exists = false;
        if (f1Final != null) {
            exists = f1Final.exists();
        }
        if (!exists && f2Final != null) {
            exists = f2Final.exists();
        }
        final boolean existsFinal = exists;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$t1-qqhAJGvt0EQdR_1F5-rbDH3M
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$44$PhotoViewer(f1Final, f2Final, existsFinal, canStreamFinal, isVideoFianl, a, animated);
            }
        });
    }

    public /* synthetic */ void lambda$null$44$PhotoViewer(File f1Final, File f2Final, boolean existsFinal, boolean canStreamFinal, boolean isVideoFianl, int a, boolean animated) {
        boolean z = true;
        if ((f1Final != null || f2Final != null) && (existsFinal || canStreamFinal)) {
            if (isVideoFianl) {
                this.photoProgressViews[a].setBackgroundState(3, animated);
            } else {
                this.photoProgressViews[a].setBackgroundState(-1, animated);
            }
            if (a == 0) {
                if (existsFinal || !FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[a])) {
                    this.menuItem.hideSubItem(7);
                } else {
                    this.menuItem.showSubItem(7);
                }
            }
        } else {
            if (isVideoFianl) {
                if (FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[a])) {
                    this.photoProgressViews[a].setBackgroundState(1, false);
                } else {
                    this.photoProgressViews[a].setBackgroundState(2, false);
                }
            } else {
                this.photoProgressViews[a].setBackgroundState(0, animated);
            }
            Float progress = ImageLoader.getInstance().getFileProgress(this.currentFileNames[a]);
            if (progress == null) {
                progress = Float.valueOf(0.0f);
            }
            this.photoProgressViews[a].setProgress(progress.floatValue(), false);
        }
        if (a == 0) {
            if (this.imagesArrLocals.isEmpty() && (this.currentFileNames[0] == null || this.photoProgressViews[0].backgroundState == 0)) {
                z = false;
            }
            this.canZoom = z;
        }
    }

    public int getSelectiongLength() {
        PhotoViewerCaptionEnterView photoViewerCaptionEnterView = this.captionEditText;
        if (photoViewerCaptionEnterView != null) {
            return photoViewerCaptionEnterView.getSelectionLength();
        }
        return 0;
    }

    private void setIndexToImage(ImageReceiver imageReceiver, int index) {
        MessageObject messageObject;
        ImageReceiver.BitmapHolder placeHolder;
        TLRPC.PhotoSize thumbLocation;
        TLObject photoObject;
        TLRPC.PhotoSize thumbLocation2;
        Object parentObject;
        ImageReceiver.BitmapHolder placeHolder2;
        ImageReceiver.BitmapHolder placeHolder3;
        ImageReceiver.BitmapHolder placeHolder4;
        String path;
        String path2;
        int cacheType;
        boolean isVideo;
        String filter;
        int imageSize;
        WebFile webDocument;
        TLObject photoObject2;
        TLRPC.Document document;
        String filter2;
        Drawable drawable;
        Activity activity;
        Drawable drawable2;
        Drawable drawable3;
        Activity activity2;
        Drawable drawable4;
        String path3;
        String path4;
        ImageReceiver.BitmapHolder placeHolder5;
        imageReceiver.setOrientation(0, false);
        if (!this.secureDocuments.isEmpty()) {
            if (index >= 0 && index < this.secureDocuments.size()) {
                this.secureDocuments.get(index);
                ImageReceiver.BitmapHolder placeHolder6 = null;
                if (this.currentThumb != null && imageReceiver == this.centerImage) {
                    placeHolder6 = this.currentThumb;
                }
                if (placeHolder6 != null) {
                    placeHolder5 = placeHolder6;
                } else {
                    ImageReceiver.BitmapHolder placeHolder7 = this.placeProvider.getThumbForPhoto(null, null, index);
                    placeHolder5 = placeHolder7;
                }
                SecureDocument document2 = this.secureDocuments.get(index);
                imageReceiver.setImage(ImageLocation.getForSecureDocument(document2), "d", null, null, placeHolder5 != null ? new BitmapDrawable(placeHolder5.bitmap) : null, document2.secureFile.size, null, null, 0);
                return;
            }
            return;
        }
        if (!this.imagesArrLocals.isEmpty()) {
            if (index >= 0 && index < this.imagesArrLocals.size()) {
                Object object = this.imagesArrLocals.get(index);
                int size = (int) (AndroidUtilities.getPhotoSize() / AndroidUtilities.density);
                ImageReceiver.BitmapHolder placeHolder8 = null;
                if (this.currentThumb != null && imageReceiver == this.centerImage) {
                    placeHolder8 = this.currentThumb;
                }
                if (placeHolder8 != null) {
                    placeHolder4 = placeHolder8;
                } else {
                    ImageReceiver.BitmapHolder placeHolder9 = this.placeProvider.getThumbForPhoto(null, null, index);
                    placeHolder4 = placeHolder9;
                }
                TLRPC.Document document3 = null;
                WebFile webDocument2 = null;
                TLRPC.PhotoSize photo = null;
                TLObject photoObject3 = null;
                int imageSize2 = 0;
                String filter3 = null;
                int cacheType2 = 0;
                if (object instanceof MediaController.PhotoEntry) {
                    MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                    boolean isVideo2 = photoEntry.isVideo;
                    if (!photoEntry.isVideo) {
                        if (photoEntry.imagePath != null) {
                            path4 = photoEntry.imagePath;
                        } else {
                            imageReceiver.setOrientation(photoEntry.orientation, false);
                            path4 = photoEntry.path;
                        }
                        filter3 = String.format(Locale.US, "%d_%d", Integer.valueOf(size), Integer.valueOf(size));
                        path3 = path4;
                    } else if (photoEntry.thumbPath != null) {
                        path3 = photoEntry.thumbPath;
                    } else {
                        path3 = "vthumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path;
                    }
                    path = path3;
                    filter = filter3;
                    cacheType = 0;
                    isVideo = isVideo2;
                    imageSize = 0;
                    webDocument = null;
                    photoObject2 = null;
                    document = null;
                } else {
                    if (object instanceof TLRPC.BotInlineResult) {
                        cacheType2 = 1;
                        TLRPC.BotInlineResult botInlineResult = (TLRPC.BotInlineResult) object;
                        if (botInlineResult.type.equals("video") || MessageObject.isVideoDocument(botInlineResult.document)) {
                            path = null;
                            if (botInlineResult.document != null) {
                                photo = FileLoader.getClosestPhotoSizeWithSize(botInlineResult.document.thumbs, 90);
                                photoObject3 = botInlineResult.document;
                            } else if (botInlineResult.thumb instanceof TLRPC.TL_webDocument) {
                                webDocument2 = WebFile.createWithWebDocument(botInlineResult.thumb);
                            }
                        } else if (botInlineResult.type.equals("gif") && botInlineResult.document != null) {
                            path = null;
                            document3 = botInlineResult.document;
                            imageSize2 = botInlineResult.document.size;
                            filter3 = "d";
                        } else if (botInlineResult.photo == null) {
                            path = null;
                            if (botInlineResult.content instanceof TLRPC.TL_webDocument) {
                                if (botInlineResult.type.equals("gif")) {
                                    filter2 = "d";
                                } else {
                                    filter2 = String.format(Locale.US, "%d_%d", Integer.valueOf(size), Integer.valueOf(size));
                                }
                                filter3 = filter2;
                                webDocument2 = WebFile.createWithWebDocument(botInlineResult.content);
                            }
                        } else {
                            TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(botInlineResult.photo.sizes, AndroidUtilities.getPhotoSize());
                            TLObject photoObject4 = botInlineResult.photo;
                            int imageSize3 = sizeFull.size;
                            path = null;
                            filter3 = String.format(Locale.US, "%d_%d", Integer.valueOf(size), Integer.valueOf(size));
                            photoObject3 = photoObject4;
                            imageSize2 = imageSize3;
                            photo = sizeFull;
                        }
                    } else {
                        path = null;
                        if (object instanceof MediaController.SearchImage) {
                            MediaController.SearchImage photoEntry2 = (MediaController.SearchImage) object;
                            if (photoEntry2.photoSize != null) {
                                TLRPC.PhotoSize photo2 = photoEntry2.photoSize;
                                TLObject photoObject5 = photoEntry2.photo;
                                photo = photo2;
                                photoObject3 = photoObject5;
                                imageSize2 = photoEntry2.photoSize.size;
                                path2 = null;
                            } else if (photoEntry2.imagePath != null) {
                                path2 = photoEntry2.imagePath;
                            } else if (photoEntry2.document != null) {
                                document3 = photoEntry2.document;
                                imageSize2 = photoEntry2.document.size;
                                path2 = null;
                            } else {
                                path2 = photoEntry2.imageUrl;
                                imageSize2 = photoEntry2.size;
                            }
                            path = path2;
                            cacheType = 1;
                            isVideo = false;
                            filter = "d";
                            imageSize = imageSize2;
                            webDocument = null;
                            photoObject2 = photoObject3;
                            document = document3;
                        }
                    }
                    cacheType = cacheType2;
                    isVideo = false;
                    filter = filter3;
                    imageSize = imageSize2;
                    webDocument = webDocument2;
                    photoObject2 = photoObject3;
                    document = document3;
                }
                if (document != null) {
                    TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
                    imageReceiver.setImage(ImageLocation.getForDocument(document), "d", placeHolder4 == null ? ImageLocation.getForDocument(thumb, document) : null, String.format(Locale.US, "%d_%d", Integer.valueOf(size), Integer.valueOf(size)), placeHolder4 != null ? new BitmapDrawable(placeHolder4.bitmap) : null, imageSize, null, object, cacheType);
                    return;
                }
                TLObject photoObject6 = photoObject2;
                if (photo != null) {
                    imageReceiver.setImage(ImageLocation.getForObject(photo, photoObject6), filter, placeHolder4 != null ? new BitmapDrawable(placeHolder4.bitmap) : null, imageSize, (String) null, object, cacheType);
                    return;
                }
                if (webDocument != null) {
                    ImageLocation forWebFile = ImageLocation.getForWebFile(webDocument);
                    if (placeHolder4 != null) {
                        drawable4 = new BitmapDrawable(placeHolder4.bitmap);
                    } else if (isVideo && (activity2 = this.parentActivity) != null) {
                        drawable4 = activity2.getResources().getDrawable(R.drawable.nophotos);
                    } else {
                        drawable3 = null;
                        imageReceiver.setImage(forWebFile, filter, drawable3, null, object, cacheType);
                        return;
                    }
                    drawable3 = drawable4;
                    imageReceiver.setImage(forWebFile, filter, drawable3, null, object, cacheType);
                    return;
                }
                if (placeHolder4 != null) {
                    drawable2 = new BitmapDrawable(placeHolder4.bitmap);
                } else if (isVideo && (activity = this.parentActivity) != null) {
                    drawable2 = activity.getResources().getDrawable(R.drawable.nophotos);
                } else {
                    drawable = null;
                    imageReceiver.setImage(path, filter, drawable, null, imageSize);
                    return;
                }
                drawable = drawable2;
                imageReceiver.setImage(path, filter, drawable, null, imageSize);
                return;
            }
            imageReceiver.setImageBitmap((Bitmap) null);
            return;
        }
        if (!this.imagesArr.isEmpty() && index >= 0 && index < this.imagesArr.size()) {
            MessageObject messageObject2 = this.imagesArr.get(index);
            imageReceiver.setShouldGenerateQualityThumb(true);
            messageObject = messageObject2;
        } else {
            messageObject = null;
        }
        if (messageObject != null) {
            if (messageObject.isVideo()) {
                imageReceiver.setNeedsQualityThumb(true);
                if (messageObject.photoThumbs == null || messageObject.photoThumbs.isEmpty()) {
                    imageReceiver.setImageBitmap(this.parentActivity.getResources().getDrawable(R.drawable.photoview_placeholder));
                    return;
                }
                if (this.currentThumb != null && imageReceiver == this.centerImage) {
                    ImageReceiver.BitmapHolder placeHolder10 = this.currentThumb;
                    placeHolder3 = placeHolder10;
                } else {
                    placeHolder3 = null;
                }
                TLRPC.PhotoSize thumbLocation3 = FileLoader.getClosestPhotoSizeWithSize(messageObject.photoThumbs, 100);
                imageReceiver.setImage(null, null, placeHolder3 == null ? ImageLocation.getForObject(thumbLocation3, messageObject.photoThumbsObject) : null, "b", placeHolder3 != null ? new BitmapDrawable(placeHolder3.bitmap) : null, 0, null, messageObject, 1);
                return;
            }
            AnimatedFileDrawable animatedFileDrawable = this.currentAnimation;
            if (animatedFileDrawable != null) {
                imageReceiver.setImageBitmap(animatedFileDrawable);
                this.currentAnimation.setSecondParentView(this.containerView);
                return;
            }
            if (this.sharedMediaType == 1) {
                if (messageObject.canPreviewDocument()) {
                    TLRPC.Document document4 = messageObject.getDocument();
                    imageReceiver.setNeedsQualityThumb(true);
                    if (this.currentThumb != null && imageReceiver == this.centerImage) {
                        ImageReceiver.BitmapHolder placeHolder11 = this.currentThumb;
                        placeHolder2 = placeHolder11;
                    } else {
                        placeHolder2 = null;
                    }
                    TLRPC.PhotoSize thumbLocation4 = messageObject != null ? FileLoader.getClosestPhotoSizeWithSize(messageObject.photoThumbs, 100) : null;
                    int size2 = (int) (2048.0f / AndroidUtilities.density);
                    imageReceiver.setImage(ImageLocation.getForDocument(document4), String.format(Locale.US, "%d_%d", Integer.valueOf(size2), Integer.valueOf(size2)), placeHolder2 == null ? ImageLocation.getForDocument(thumbLocation4, document4) : null, "b", placeHolder2 != null ? new BitmapDrawable(placeHolder2.bitmap) : null, document4.size, null, messageObject, 0);
                    return;
                }
                OtherDocumentPlaceholderDrawable drawable5 = new OtherDocumentPlaceholderDrawable(this.parentActivity, this.containerView, messageObject);
                imageReceiver.setImageBitmap(drawable5);
                return;
            }
        }
        int[] size3 = new int[1];
        ImageLocation imageLocation = getImageLocation(index, size3);
        TLObject fileLocation = getFileLocation(index, size3);
        if (imageLocation != null) {
            imageReceiver.setNeedsQualityThumb(true);
            if (this.currentThumb != null && imageReceiver == this.centerImage) {
                ImageReceiver.BitmapHolder placeHolder12 = this.currentThumb;
                placeHolder = placeHolder12;
            } else {
                placeHolder = null;
            }
            if (size3[0] == 0) {
                size3[0] = -1;
            }
            if (messageObject != null) {
                thumbLocation = FileLoader.getClosestPhotoSizeWithSize(messageObject.photoThumbs, 100);
                photoObject = messageObject.photoThumbsObject;
            } else {
                thumbLocation = null;
                photoObject = null;
            }
            if (thumbLocation != null && thumbLocation == fileLocation) {
                thumbLocation2 = null;
            } else {
                thumbLocation2 = thumbLocation;
            }
            boolean cacheOnly = (messageObject != null && messageObject.isWebpage()) || this.avatarsDialogId != 0 || this.isEvent;
            if (messageObject != null) {
                parentObject = messageObject;
            } else {
                int i = this.avatarsDialogId;
                if (i != 0) {
                    parentObject = i > 0 ? MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.avatarsDialogId)) : MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-this.avatarsDialogId));
                } else {
                    parentObject = null;
                }
            }
            imageReceiver.setImage(imageLocation, null, placeHolder == null ? ImageLocation.getForObject(thumbLocation2, photoObject) : null, "b", placeHolder != null ? new BitmapDrawable(placeHolder.bitmap) : null, size3[0], null, parentObject, cacheOnly ? 1 : 0);
            return;
        }
        imageReceiver.setNeedsQualityThumb(true);
        if (size3[0] != 0) {
            imageReceiver.setImageBitmap(this.parentActivity.getResources().getDrawable(R.drawable.photoview_placeholder));
        } else {
            imageReceiver.setImageBitmap((Bitmap) null);
        }
    }

    public static boolean isShowingImage(MessageObject object) {
        boolean result = false;
        if (Instance != null) {
            result = (Instance.pipAnimationInProgress || !Instance.isVisible || Instance.disableShowCheck || object == null || Instance.currentMessageObject == null || Instance.currentMessageObject.getId() != object.getId() || Instance.currentMessageObject.getDialogId() != object.getDialogId()) ? false : true;
        }
        if (!result && PipInstance != null) {
            boolean result2 = PipInstance.isVisible && !PipInstance.disableShowCheck && object != null && PipInstance.currentMessageObject != null && PipInstance.currentMessageObject.getId() == object.getId() && PipInstance.currentMessageObject.getDialogId() == object.getDialogId();
            return result2;
        }
        return result;
    }

    public static boolean isPlayingMessageInPip(MessageObject object) {
        return (PipInstance == null || object == null || PipInstance.currentMessageObject == null || PipInstance.currentMessageObject.getId() != object.getId() || PipInstance.currentMessageObject.getDialogId() != object.getDialogId()) ? false : true;
    }

    public static boolean isPlayingMessage(MessageObject object) {
        return (Instance == null || Instance.pipAnimationInProgress || !Instance.isVisible || object == null || Instance.currentMessageObject == null || Instance.currentMessageObject.getId() != object.getId() || Instance.currentMessageObject.getDialogId() != object.getDialogId()) ? false : true;
    }

    public static boolean isShowingImage(TLRPC.FileLocation object) {
        if (Instance == null) {
            return false;
        }
        boolean result = Instance.isVisible && !Instance.disableShowCheck && object != null && Instance.currentFileLocation != null && object.local_id == Instance.currentFileLocation.location.local_id && object.volume_id == Instance.currentFileLocation.location.volume_id && object.dc_id == Instance.currentFileLocation.dc_id;
        return result;
    }

    public static boolean isShowingImage(TLRPC.BotInlineResult object) {
        if (Instance == null) {
            return false;
        }
        boolean result = (!Instance.isVisible || Instance.disableShowCheck || object == null || Instance.currentBotInlineResult == null || object.id != Instance.currentBotInlineResult.id) ? false : true;
        return result;
    }

    public static boolean isShowingImage(String object) {
        if (Instance == null) {
            return false;
        }
        boolean result = Instance.isVisible && !Instance.disableShowCheck && object != null && object.equals(Instance.currentPathObject);
        return result;
    }

    public void setParentChatActivity(ChatActivity chatActivity) {
        this.parentChatActivity = chatActivity;
    }

    public void setMaxSelectedPhotos(int value, boolean order) {
        this.maxSelectedPhotos = value;
        this.allowOrder = order;
    }

    public boolean openPhoto(MessageObject messageObject, long dialogId, long mergeDialogId, PhotoViewerProvider provider) {
        return openPhoto(messageObject, null, null, null, null, null, 0, provider, null, dialogId, mergeDialogId, true);
    }

    public boolean openPhoto(MessageObject messageObject, long dialogId, long mergeDialogId, PhotoViewerProvider provider, boolean fullScreenVideo) {
        return openPhoto(messageObject, null, null, null, null, null, 0, provider, null, dialogId, mergeDialogId, fullScreenVideo);
    }

    public boolean openPhoto(TLRPC.FileLocation fileLocation, PhotoViewerProvider provider) {
        return openPhoto(null, fileLocation, null, null, null, null, 0, provider, null, 0L, 0L, true);
    }

    public boolean openPhoto(TLRPC.FileLocation fileLocation, ImageLocation imageLocation, PhotoViewerProvider provider) {
        return openPhoto(null, fileLocation, imageLocation, null, null, null, 0, provider, null, 0L, 0L, true);
    }

    public boolean openPhoto(ArrayList<MessageObject> messages, int index, long dialogId, long mergeDialogId, PhotoViewerProvider provider) {
        return openPhoto(messages.get(index), null, null, messages, null, null, index, provider, null, dialogId, mergeDialogId, true);
    }

    public boolean openPhoto(ArrayList<SecureDocument> documents, int index, PhotoViewerProvider provider) {
        return openPhoto(null, null, null, null, documents, null, index, provider, null, 0L, 0L, true);
    }

    public boolean openPhotoForSelect(ArrayList<Object> photos, int index, int type, PhotoViewerProvider provider, ChatActivity chatActivity, boolean need) {
        return openPhotoForSelect(photos, index, type, provider, chatActivity);
    }

    public void setIsFcCrop(boolean isFcCrop) {
        this.isFcCrop = isFcCrop;
    }

    public boolean openPhotoForSelect(ArrayList<Object> photos, int index, int type, PhotoViewerProvider provider, ChatActivity chatActivity) {
        this.sendPhotoType = type;
        ImageView imageView = this.pickerViewSendButton;
        if (imageView != null) {
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) imageView.getLayoutParams();
            int i = this.sendPhotoType;
            if (i == 4 || i == 5) {
                this.pickerViewSendButton.setImageResource(R.drawable.attach_send);
                layoutParams2.bottomMargin = AndroidUtilities.dp(19.0f);
            } else if (i == 1 || i == 3) {
                this.pickerViewSendButton.setImageResource(R.drawable.floating_check);
                this.pickerViewSendButton.setPadding(0, AndroidUtilities.dp(1.0f), 0, 0);
                layoutParams2.bottomMargin = AndroidUtilities.dp(19.0f);
            } else {
                this.pickerViewSendButton.setImageResource(R.drawable.attach_send);
                layoutParams2.bottomMargin = AndroidUtilities.dp(14.0f);
            }
            this.pickerViewSendButton.setLayoutParams(layoutParams2);
        }
        return openPhoto(null, null, null, null, null, photos, index, provider, chatActivity, 0L, 0L, true);
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

    /* JADX INFO: Access modifiers changed from: private */
    public void setCropTranslations(boolean animated) {
        if (this.sendPhotoType != 1) {
            return;
        }
        int bitmapWidth = this.centerImage.getBitmapWidth();
        int bitmapHeight = this.centerImage.getBitmapHeight();
        if (bitmapWidth == 0 || bitmapHeight == 0) {
            return;
        }
        float scaleX = getContainerViewWidth() / bitmapWidth;
        float scaleY = getContainerViewHeight() / bitmapHeight;
        float scaleFinal = scaleX > scaleY ? scaleY : scaleX;
        float minSide = Math.min(getContainerViewWidth(1), getContainerViewHeight(1));
        float newScaleX = minSide / bitmapWidth;
        float newScaleY = minSide / bitmapHeight;
        float newScale = newScaleX > newScaleY ? newScaleX : newScaleY;
        if (animated) {
            this.animationStartTime = System.currentTimeMillis();
            this.animateToX = (getLeftInset() / 2) - (getRightInset() / 2);
            int i = this.currentEditMode;
            if (i == 2) {
                this.animateToY = AndroidUtilities.dp(92.0f) - AndroidUtilities.dp(56.0f);
            } else if (i == 3) {
                this.animateToY = AndroidUtilities.dp(44.0f) - AndroidUtilities.dp(56.0f);
            }
            this.animateToScale = newScale / scaleFinal;
            this.zoomAnimation = true;
            return;
        }
        this.animationStartTime = 0L;
        this.translationX = (getLeftInset() / 2) - (getRightInset() / 2);
        this.translationY = (-AndroidUtilities.dp(56.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
        float f = newScale / scaleFinal;
        this.scale = f;
        updateMinMax(f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCropBitmap() {
        if (this.sendPhotoType != 1) {
            return;
        }
        Bitmap bitmap = this.centerImage.getBitmap();
        int orientation = this.centerImage.getOrientation();
        if (bitmap == null) {
            bitmap = this.animatingImageView.getBitmap();
            orientation = this.animatingImageView.getOrientation();
        }
        if (bitmap != null) {
            this.photoCropView.setBitmap(bitmap, orientation, false, false);
            if (this.currentEditMode == 0) {
                setCropTranslations(false);
            }
        }
    }

    private void initCropView() {
        if (this.sendPhotoType != 1) {
            return;
        }
        this.photoCropView.setBitmap(null, 0, false, false);
        this.photoCropView.onAppear();
        this.photoCropView.setVisibility(0);
        this.photoCropView.setAlpha(1.0f);
        this.photoCropView.onAppeared();
        this.padImageForHorizontalInsets = true;
    }

    public boolean openPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, ImageLocation imageLocation, ArrayList<MessageObject> messages, ArrayList<SecureDocument> documents, ArrayList<Object> photos, int index, PhotoViewerProvider provider, ChatActivity chatActivity, long dialogId, long mDialogId, boolean fullScreenVideo) throws JSONException {
        int orientation;
        float f;
        if (this.parentActivity == null || this.isVisible) {
            return false;
        }
        if ((provider == null && checkAnimation()) || (messageObject == null && fileLocation == null && messages == null && photos == null && documents == null && imageLocation == null)) {
            return false;
        }
        PlaceProviderObject object = provider.getPlaceForPhoto(messageObject, fileLocation, index, true);
        this.lastInsets = null;
        WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
        if (this.attachedToWindow) {
            try {
                wm.removeView(this.windowView);
            } catch (Exception e) {
            }
        }
        try {
            this.windowLayoutParams.type = 99;
            if (Build.VERSION.SDK_INT >= 21) {
                try {
                    this.windowLayoutParams.flags = -2147286784;
                } catch (Exception e2) {
                    e = e2;
                    FileLog.e(e);
                    return false;
                }
            } else {
                this.windowLayoutParams.flags = 131072;
            }
            if (chatActivity == null || chatActivity.getCurrentEncryptedChat() == null) {
                this.windowLayoutParams.flags &= -8193;
            } else {
                this.windowLayoutParams.flags |= 8192;
            }
            this.windowLayoutParams.softInputMode = 272;
            this.windowView.setFocusable(false);
            this.containerView.setFocusable(false);
            wm.addView(this.windowView, this.windowLayoutParams);
            this.doneButtonPressed = false;
            this.parentChatActivity = chatActivity;
            this.actionBar.setTitle(LocaleController.formatString("Of", R.string.Of, 1, 1));
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidFailToLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileLoadProgressChanged);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.mediaCountDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.mediaDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.dialogPhotosLoaded);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.filePreparingFailed);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileNewChunkAvailable);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.saveGallerySetChanged);
            this.placeProvider = provider;
            this.mergeDialogId = mDialogId;
            this.currentDialogId = dialogId;
            this.selectedPhotosAdapter.notifyDataSetChanged();
            if (this.velocityTracker == null) {
                this.velocityTracker = VelocityTracker.obtain();
            }
            this.isVisible = true;
            togglePhotosListView(false, false);
            boolean z = !fullScreenVideo;
            this.openedFullScreenVideo = z;
            if (!z) {
                if (this.sendPhotoType == 1) {
                    createCropView();
                    toggleActionBar(false, false);
                } else {
                    toggleActionBar(true, false);
                }
            } else {
                toggleActionBar(false, false);
            }
            this.seekToProgressPending2 = 0.0f;
            this.skipFirstBufferingProgress = false;
            this.playerInjected = false;
            if (object == null) {
                if (photos != null && this.sendPhotoType != 3) {
                    if (Build.VERSION.SDK_INT >= 21) {
                        this.windowLayoutParams.flags = -2147417856;
                    } else {
                        this.windowLayoutParams.flags = 0;
                    }
                    this.windowLayoutParams.softInputMode = 272;
                    wm.updateViewLayout(this.windowView, this.windowLayoutParams);
                    this.windowView.setFocusable(true);
                    this.containerView.setFocusable(true);
                }
                this.backgroundDrawable.setAlpha(255);
                this.containerView.setAlpha(1.0f);
                onPhotoShow(messageObject, fileLocation, imageLocation, messages, documents, photos, index, object);
                initCropView();
                setCropBitmap();
            } else {
                this.disableShowCheck = true;
                this.animationInProgress = 1;
                if (messageObject != null) {
                    AnimatedFileDrawable animation = object.imageReceiver.getAnimation();
                    this.currentAnimation = animation;
                    if (animation != null) {
                        if (!messageObject.isVideo()) {
                            if (messageObject.getWebPagePhotos(null, null).size() > 1) {
                                this.currentAnimation = null;
                            }
                        } else {
                            object.imageReceiver.setAllowStartAnimation(false);
                            object.imageReceiver.stopAnimation();
                            if (MediaController.getInstance().isPlayingMessage(messageObject)) {
                                this.seekToProgressPending2 = messageObject.audioProgress;
                            }
                            this.skipFirstBufferingProgress = this.injectingVideoPlayer == null && !FileLoader.getInstance(messageObject.currentAccount).isLoadingVideo(messageObject.getDocument(), true) && (this.currentAnimation.hasBitmap() || !FileLoader.getInstance(messageObject.currentAccount).isLoadingVideo(messageObject.getDocument(), false));
                            this.currentAnimation = null;
                        }
                    }
                }
                int i = 1;
                onPhotoShow(messageObject, fileLocation, imageLocation, messages, documents, photos, index, object);
                if (this.sendPhotoType == 1) {
                    this.photoCropView.setVisibility(0);
                    this.photoCropView.setAlpha(0.0f);
                    this.photoCropView.setFreeform(false);
                }
                RectF drawRegion = object.imageReceiver.getDrawRegion();
                float left = drawRegion.left;
                float f2 = drawRegion.top;
                int orientation2 = object.imageReceiver.getOrientation();
                int animatedOrientation = object.imageReceiver.getAnimatedOrientation();
                if (animatedOrientation == 0) {
                    orientation = orientation2;
                } else {
                    orientation = animatedOrientation;
                }
                ClippingImageView[] animatingImageViews = getAnimatingImageViews(object);
                for (int i2 = 0; i2 < animatingImageViews.length; i2++) {
                    animatingImageViews[i2].setAnimationValues(this.animationValues);
                    animatingImageViews[i2].setVisibility(0);
                    animatingImageViews[i2].setRadius(object.radius);
                    animatingImageViews[i2].setOrientation(orientation);
                    animatingImageViews[i2].setNeedRadius(object.radius != 0);
                    animatingImageViews[i2].setImageBitmap(object.thumb);
                }
                initCropView();
                if (this.sendPhotoType == 1) {
                    this.photoCropView.hideBackView();
                    this.photoCropView.setAspectRatio(1.0f);
                }
                ViewGroup.LayoutParams layoutParams = this.animatingImageView.getLayoutParams();
                layoutParams.width = (int) drawRegion.width();
                layoutParams.height = (int) drawRegion.height();
                if (layoutParams.width == 0) {
                    layoutParams.width = 1;
                }
                if (layoutParams.height == 0) {
                    layoutParams.height = 1;
                }
                int i3 = 0;
                while (i3 < animatingImageViews.length) {
                    if (animatingImageViews.length > i) {
                        f = 0.0f;
                        animatingImageViews[i3].setAlpha(0.0f);
                    } else {
                        f = 0.0f;
                        animatingImageViews[i3].setAlpha(1.0f);
                    }
                    animatingImageViews[i3].setPivotX(f);
                    animatingImageViews[i3].setPivotY(f);
                    animatingImageViews[i3].setScaleX(object.scale);
                    animatingImageViews[i3].setScaleY(object.scale);
                    animatingImageViews[i3].setTranslationX(object.viewX + (drawRegion.left * object.scale));
                    animatingImageViews[i3].setTranslationY(object.viewY + (drawRegion.top * object.scale));
                    animatingImageViews[i3].setLayoutParams(layoutParams);
                    i3++;
                    orientation = orientation;
                    i = 1;
                }
                this.windowView.getViewTreeObserver().addOnPreDrawListener(new AnonymousClass41(animatingImageViews, layoutParams, left, object, f2, photos));
            }
            AccessibilityManager am = (AccessibilityManager) this.parentActivity.getSystemService("accessibility");
            if (am.isTouchExplorationEnabled()) {
                AccessibilityEvent event = AccessibilityEvent.obtain();
                event.setEventType(16384);
                event.getText().add(LocaleController.getString("AccDescrPhotoViewer", R.string.AccDescrPhotoViewer));
                am.sendAccessibilityEvent(event);
                return true;
            }
            return true;
        } catch (Exception e3) {
            e = e3;
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$41, reason: invalid class name */
    class AnonymousClass41 implements ViewTreeObserver.OnPreDrawListener {
        final /* synthetic */ ClippingImageView[] val$animatingImageViews;
        final /* synthetic */ ViewGroup.LayoutParams val$layoutParams;
        final /* synthetic */ float val$left;
        final /* synthetic */ PlaceProviderObject val$object;
        final /* synthetic */ ArrayList val$photos;
        final /* synthetic */ float val$top;

        AnonymousClass41(ClippingImageView[] clippingImageViewArr, ViewGroup.LayoutParams layoutParams, float f, PlaceProviderObject placeProviderObject, float f2, ArrayList arrayList) {
            this.val$animatingImageViews = clippingImageViewArr;
            this.val$layoutParams = layoutParams;
            this.val$left = f;
            this.val$object = placeProviderObject;
            this.val$top = f2;
            this.val$photos = arrayList;
        }

        @Override // android.view.ViewTreeObserver.OnPreDrawListener
        public boolean onPreDraw() {
            float scale;
            float yPos;
            float xPos;
            ClippingImageView[] clippingImageViewArr;
            int i;
            ClippingImageView[] clippingImageViewArr2 = this.val$animatingImageViews;
            if (clippingImageViewArr2.length > 1) {
                clippingImageViewArr2[1].setAlpha(1.0f);
            }
            PhotoViewer.this.windowView.getViewTreeObserver().removeOnPreDrawListener(this);
            if (PhotoViewer.this.sendPhotoType != 1) {
                float scaleX = PhotoViewer.this.windowView.getMeasuredWidth() / this.val$layoutParams.width;
                float scaleY = (AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) / this.val$layoutParams.height;
                scale = scaleX > scaleY ? scaleY : scaleX;
                yPos = ((AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - (this.val$layoutParams.height * scale)) / 2.0f;
                xPos = (PhotoViewer.this.windowView.getMeasuredWidth() - (this.val$layoutParams.width * scale)) / 2.0f;
            } else {
                float statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
                float measuredHeight = (PhotoViewer.this.photoCropView.getMeasuredHeight() - AndroidUtilities.dp(64.0f)) - statusBarHeight;
                float minSide = Math.min(PhotoViewer.this.photoCropView.getMeasuredWidth(), measuredHeight) - (AndroidUtilities.dp(16.0f) * 2);
                float centerX = PhotoViewer.this.photoCropView.getMeasuredWidth() / 2.0f;
                float centerY = (measuredHeight / 2.0f) + statusBarHeight;
                float left = centerX - (minSide / 2.0f);
                float top = centerY - (minSide / 2.0f);
                float right = (minSide / 2.0f) + centerX;
                float bottom = (minSide / 2.0f) + centerY;
                scale = Math.max((right - left) / this.val$layoutParams.width, (bottom - top) / this.val$layoutParams.height);
                yPos = top + (((bottom - top) - (this.val$layoutParams.height * scale)) / 2.0f);
                xPos = ((((PhotoViewer.this.windowView.getMeasuredWidth() - PhotoViewer.this.getLeftInset()) - PhotoViewer.this.getRightInset()) - (this.val$layoutParams.width * scale)) / 2.0f) + PhotoViewer.this.getLeftInset();
            }
            int clipHorizontal = (int) Math.abs(this.val$left - this.val$object.imageReceiver.getImageX());
            int clipVertical = (int) Math.abs(this.val$top - this.val$object.imageReceiver.getImageY());
            int[] coords2 = new int[2];
            this.val$object.parentView.getLocationInWindow(coords2);
            int clipTop = (int) (((coords2[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight)) - (this.val$object.viewY + this.val$top)) + this.val$object.clipTopAddition);
            if (clipTop < 0) {
                clipTop = 0;
            }
            int clipBottom = (int) ((((this.val$object.viewY + this.val$top) + this.val$layoutParams.height) - ((coords2[1] + this.val$object.parentView.getHeight()) - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight))) + this.val$object.clipBottomAddition);
            if (clipBottom < 0) {
                clipBottom = 0;
            }
            int clipTop2 = Math.max(clipTop, clipVertical);
            int clipBottom2 = Math.max(clipBottom, clipVertical);
            PhotoViewer.this.animationValues[0][0] = PhotoViewer.this.animatingImageView.getScaleX();
            PhotoViewer.this.animationValues[0][1] = PhotoViewer.this.animatingImageView.getScaleY();
            PhotoViewer.this.animationValues[0][2] = PhotoViewer.this.animatingImageView.getTranslationX();
            PhotoViewer.this.animationValues[0][3] = PhotoViewer.this.animatingImageView.getTranslationY();
            PhotoViewer.this.animationValues[0][4] = clipHorizontal * this.val$object.scale;
            PhotoViewer.this.animationValues[0][5] = clipTop2 * this.val$object.scale;
            PhotoViewer.this.animationValues[0][6] = clipBottom2 * this.val$object.scale;
            PhotoViewer.this.animationValues[0][7] = PhotoViewer.this.animatingImageView.getRadius();
            PhotoViewer.this.animationValues[0][8] = clipVertical * this.val$object.scale;
            PhotoViewer.this.animationValues[0][9] = clipHorizontal * this.val$object.scale;
            PhotoViewer.this.animationValues[1][0] = scale;
            PhotoViewer.this.animationValues[1][1] = scale;
            PhotoViewer.this.animationValues[1][2] = xPos;
            PhotoViewer.this.animationValues[1][3] = yPos;
            PhotoViewer.this.animationValues[1][4] = 0.0f;
            PhotoViewer.this.animationValues[1][5] = 0.0f;
            PhotoViewer.this.animationValues[1][6] = 0.0f;
            PhotoViewer.this.animationValues[1][7] = 0.0f;
            PhotoViewer.this.animationValues[1][8] = 0.0f;
            PhotoViewer.this.animationValues[1][9] = 0.0f;
            int i2 = 0;
            while (true) {
                ClippingImageView[] clippingImageViewArr3 = this.val$animatingImageViews;
                if (i2 >= clippingImageViewArr3.length) {
                    break;
                }
                clippingImageViewArr3[i2].setAnimationProgress(0.0f);
                i2++;
            }
            PhotoViewer.this.backgroundDrawable.setAlpha(0);
            PhotoViewer.this.containerView.setAlpha(0.0f);
            PhotoViewer photoViewer = PhotoViewer.this;
            final ClippingImageView[] clippingImageViewArr4 = this.val$animatingImageViews;
            final ArrayList arrayList = this.val$photos;
            photoViewer.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$41$pRs1v65xsuno1wZ1-Uh92ow6ZWE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPreDraw$0$PhotoViewer$41(clippingImageViewArr4, arrayList);
                }
            };
            if (PhotoViewer.this.openedFullScreenVideo) {
                if (PhotoViewer.this.animationEndRunnable != null) {
                    PhotoViewer.this.animationEndRunnable.run();
                    PhotoViewer.this.animationEndRunnable = null;
                }
                PhotoViewer.this.containerView.setAlpha(1.0f);
                PhotoViewer.this.backgroundDrawable.setAlpha(255);
                int i3 = 0;
                while (true) {
                    ClippingImageView[] clippingImageViewArr5 = this.val$animatingImageViews;
                    if (i3 >= clippingImageViewArr5.length) {
                        break;
                    }
                    clippingImageViewArr5[i3].setAnimationProgress(1.0f);
                    i3++;
                }
                if (PhotoViewer.this.sendPhotoType == 1) {
                    PhotoViewer.this.photoCropView.setAlpha(1.0f);
                }
            } else {
                final AnimatorSet animatorSet = new AnimatorSet();
                int i4 = PhotoViewer.this.sendPhotoType != 1 ? 2 : 3;
                ClippingImageView[] clippingImageViewArr6 = this.val$animatingImageViews;
                ArrayList<Animator> animators = new ArrayList<>(i4 + clippingImageViewArr6.length + (clippingImageViewArr6.length > 1 ? 1 : 0));
                int i5 = 0;
                while (true) {
                    clippingImageViewArr = this.val$animatingImageViews;
                    if (i5 >= clippingImageViewArr.length) {
                        break;
                    }
                    animators.add(ObjectAnimator.ofFloat(clippingImageViewArr[i5], AnimationProperties.CLIPPING_IMAGE_VIEW_PROGRESS, 0.0f, 1.0f));
                    i5++;
                }
                if (clippingImageViewArr.length > 1) {
                    i = 2;
                    animators.add(ObjectAnimator.ofFloat(PhotoViewer.this.animatingImageView, (Property<ClippingImageView, Float>) View.ALPHA, 0.0f, 1.0f));
                } else {
                    i = 2;
                }
                int[] iArr = new int[i];
                // fill-array-data instruction
                iArr[0] = 0;
                iArr[1] = 255;
                animators.add(ObjectAnimator.ofInt(PhotoViewer.this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, iArr));
                float[] fArr = new float[i];
                // fill-array-data instruction
                fArr[0] = 0.0f;
                fArr[1] = 1.0f;
                animators.add(ObjectAnimator.ofFloat(PhotoViewer.this.containerView, (Property<FrameLayoutDrawer, Float>) View.ALPHA, fArr));
                if (PhotoViewer.this.sendPhotoType == 1) {
                    animators.add(ObjectAnimator.ofFloat(PhotoViewer.this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f, 1.0f));
                }
                animatorSet.playTogether(animators);
                animatorSet.setDuration(200L);
                animatorSet.addListener(new AnonymousClass1());
                if (Build.VERSION.SDK_INT >= 18) {
                    PhotoViewer.this.containerView.setLayerType(2, null);
                }
                PhotoViewer.this.transitionAnimationStartTime = System.currentTimeMillis();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$41$-0E52-Sd83g6puDkw2L994ukp4A
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onPreDraw$1$PhotoViewer$41(animatorSet);
                    }
                });
            }
            BackgroundDrawable backgroundDrawable = PhotoViewer.this.backgroundDrawable;
            final PlaceProviderObject placeProviderObject = this.val$object;
            backgroundDrawable.drawRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$41$SgFlCxBNmmbv2PLW1kqF-wTm1IQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPreDraw$2$PhotoViewer$41(placeProviderObject);
                }
            };
            return true;
        }

        public /* synthetic */ void lambda$onPreDraw$0$PhotoViewer$41(ClippingImageView[] animatingImageViews, ArrayList photos) {
            if (PhotoViewer.this.containerView == null || PhotoViewer.this.windowView == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 18) {
                PhotoViewer.this.containerView.setLayerType(0, null);
            }
            PhotoViewer.this.animationInProgress = 0;
            PhotoViewer.this.transitionAnimationStartTime = 0L;
            PhotoViewer.this.setImages();
            PhotoViewer.this.setCropBitmap();
            if (PhotoViewer.this.sendPhotoType == 1) {
                PhotoViewer.this.photoCropView.showBackView();
            }
            PhotoViewer.this.containerView.invalidate();
            for (ClippingImageView clippingImageView : animatingImageViews) {
                clippingImageView.setVisibility(8);
            }
            if (PhotoViewer.this.showAfterAnimation != null) {
                PhotoViewer.this.showAfterAnimation.imageReceiver.setVisible(true, true);
            }
            if (PhotoViewer.this.hideAfterAnimation != null) {
                PhotoViewer.this.hideAfterAnimation.imageReceiver.setVisible(false, true);
            }
            if (photos != null && PhotoViewer.this.sendPhotoType != 3) {
                if (Build.VERSION.SDK_INT >= 21) {
                    PhotoViewer.this.windowLayoutParams.flags = -2147417856;
                } else {
                    PhotoViewer.this.windowLayoutParams.flags = 0;
                }
                PhotoViewer.this.windowLayoutParams.softInputMode = 272;
                WindowManager wm1 = (WindowManager) PhotoViewer.this.parentActivity.getSystemService("window");
                wm1.updateViewLayout(PhotoViewer.this.windowView, PhotoViewer.this.windowLayoutParams);
                PhotoViewer.this.windowView.setFocusable(true);
                PhotoViewer.this.containerView.setFocusable(true);
            }
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$41$1, reason: invalid class name */
        class AnonymousClass1 extends AnimatorListenerAdapter {
            AnonymousClass1() {
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$41$1$yjHg65WYTG0atXKLNoAu8G9DtdM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onAnimationEnd$0$PhotoViewer$41$1();
                    }
                });
            }

            public /* synthetic */ void lambda$onAnimationEnd$0$PhotoViewer$41$1() {
                NotificationCenter.getInstance(PhotoViewer.this.currentAccount).setAnimationInProgress(false);
                if (PhotoViewer.this.animationEndRunnable != null) {
                    PhotoViewer.this.animationEndRunnable.run();
                    PhotoViewer.this.animationEndRunnable = null;
                }
            }
        }

        public /* synthetic */ void lambda$onPreDraw$1$PhotoViewer$41(AnimatorSet animatorSet) {
            NotificationCenter.getInstance(PhotoViewer.this.currentAccount).setAllowedNotificationsDutingAnimation(new int[]{NotificationCenter.dialogsNeedReload, NotificationCenter.closeChats, NotificationCenter.mediaCountDidLoad, NotificationCenter.mediaDidLoad, NotificationCenter.dialogPhotosLoaded});
            NotificationCenter.getInstance(PhotoViewer.this.currentAccount).setAnimationInProgress(true);
            animatorSet.start();
        }

        public /* synthetic */ void lambda$onPreDraw$2$PhotoViewer$41(PlaceProviderObject object) {
            PhotoViewer.this.disableShowCheck = false;
            object.imageReceiver.setVisible(false, true);
        }
    }

    public void injectVideoPlayerToMediaController() {
        if (this.videoPlayer.isPlaying()) {
            MediaController.getInstance().injectVideoPlayer(this.videoPlayer, this.currentMessageObject);
            this.videoPlayer = null;
            updateAccessibilityOverlayVisibility();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v12 */
    /* JADX WARN: Type inference failed for: r4v15 */
    /* JADX WARN: Type inference failed for: r4v8, types: [android.view.View, im.uwrkaxlmjj.ui.components.AnimatedFileDrawable] */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public void closePhoto(boolean z, boolean z2) {
        boolean z3;
        ?? r4;
        RectF rectF;
        int i;
        AnimatedFileDrawable animation;
        Bitmap animatedBitmap;
        int systemUiVisibility;
        int i2;
        PhotoPaintView photoPaintView;
        if (!z2 && (i2 = this.currentEditMode) != 0) {
            if (i2 == 3 && (photoPaintView = this.photoPaintView) != null) {
                photoPaintView.maybeShowDismissalAlert(this, this.parentActivity, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$Box2-RjzSAa0i6DGPYbbyvRvmx8
                    @Override // java.lang.Runnable
                    public final void run() throws JSONException {
                        this.f$0.lambda$closePhoto$46$PhotoViewer();
                    }
                });
                return;
            } else {
                switchToEditMode(0);
                return;
            }
        }
        QualityChooseView qualityChooseView = this.qualityChooseView;
        if (qualityChooseView != null && qualityChooseView.getTag() != null) {
            this.qualityPicker.cancelButton.callOnClick();
            return;
        }
        this.openedFullScreenVideo = false;
        try {
            if (this.visibleDialog != null) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (Build.VERSION.SDK_INT >= 21 && this.actionBar != null && (systemUiVisibility = this.containerView.getSystemUiVisibility() & 4102) != 0) {
            FrameLayoutDrawer frameLayoutDrawer = this.containerView;
            frameLayoutDrawer.setSystemUiVisibility(frameLayoutDrawer.getSystemUiVisibility() & (~systemUiVisibility));
        }
        int i3 = this.currentEditMode;
        if (i3 != 0) {
            if (i3 == 2) {
                this.photoFilterView.shutdown();
                this.containerView.removeView(this.photoFilterView);
                this.photoFilterView = null;
            } else if (i3 == 1) {
                this.editorDoneLayout.setVisibility(8);
                this.photoCropView.setVisibility(8);
            } else if (i3 == 3) {
                this.photoPaintView.shutdown();
                this.containerView.removeView(this.photoPaintView);
                this.photoPaintView = null;
            }
            this.currentEditMode = 0;
        } else if (this.sendPhotoType == 1) {
            this.photoCropView.setVisibility(8);
        }
        if (this.parentActivity != null) {
            if ((!this.isInline && !this.isVisible) || checkAnimation() || this.placeProvider == null) {
                return;
            }
            if (!this.captionEditText.hideActionMode() || z2) {
                final PlaceProviderObject placeForPhoto = this.placeProvider.getPlaceForPhoto(this.currentMessageObject, getFileLocation(this.currentFileLocation), this.currentIndex, true);
                if (this.videoPlayer != null && placeForPhoto != null && (animation = placeForPhoto.imageReceiver.getAnimation()) != null) {
                    if (this.textureUploaded && (animatedBitmap = animation.getAnimatedBitmap()) != null) {
                        try {
                            Bitmap bitmap = this.videoTextureView.getBitmap(animatedBitmap.getWidth(), animatedBitmap.getHeight());
                            new Canvas(animatedBitmap).drawBitmap(bitmap, 0.0f, 0.0f, (Paint) null);
                            bitmap.recycle();
                        } catch (Throwable th) {
                            FileLog.e(th);
                        }
                    }
                    animation.seekTo(this.videoPlayer.getCurrentPosition(), !FileLoader.getInstance(this.currentMessageObject.currentAccount).isLoadingVideo(this.currentMessageObject.getDocument(), true));
                    placeForPhoto.imageReceiver.setAllowStartAnimation(true);
                    placeForPhoto.imageReceiver.startAnimation();
                }
                releasePlayer(true);
                this.captionEditText.onDestroy();
                this.parentChatActivity = null;
                removeObservers();
                this.isActionBarVisible = false;
                VelocityTracker velocityTracker = this.velocityTracker;
                if (velocityTracker != null) {
                    velocityTracker.recycle();
                    this.velocityTracker = null;
                }
                if (this.isInline) {
                    this.isInline = false;
                    this.animationInProgress = 0;
                    onPhotoClosed(placeForPhoto);
                    this.containerView.setScaleX(1.0f);
                    this.containerView.setScaleY(1.0f);
                    return;
                }
                if (z) {
                    ClippingImageView[] animatingImageViews = getAnimatingImageViews(placeForPhoto);
                    for (int i4 = 0; i4 < animatingImageViews.length; i4++) {
                        animatingImageViews[i4].setAnimationValues(this.animationValues);
                        animatingImageViews[i4].setVisibility(0);
                    }
                    this.animationInProgress = 3;
                    this.containerView.invalidate();
                    AnimatorSet animatorSet = new AnimatorSet();
                    ViewGroup.LayoutParams layoutParams = this.animatingImageView.getLayoutParams();
                    if (placeForPhoto != null) {
                        RectF drawRegion = placeForPhoto.imageReceiver.getDrawRegion();
                        layoutParams.width = (int) drawRegion.width();
                        layoutParams.height = (int) drawRegion.height();
                        int orientation = placeForPhoto.imageReceiver.getOrientation();
                        int animatedOrientation = placeForPhoto.imageReceiver.getAnimatedOrientation();
                        if (animatedOrientation != 0) {
                            orientation = animatedOrientation;
                        }
                        for (int i5 = 0; i5 < animatingImageViews.length; i5++) {
                            animatingImageViews[i5].setNeedRadius(placeForPhoto.radius != 0);
                            animatingImageViews[i5].setOrientation(orientation);
                            animatingImageViews[i5].setImageBitmap(placeForPhoto.thumb);
                        }
                        rectF = drawRegion;
                    } else {
                        layoutParams.width = this.centerImage.getImageWidth();
                        layoutParams.height = this.centerImage.getImageHeight();
                        for (int i6 = 0; i6 < animatingImageViews.length; i6++) {
                            animatingImageViews[i6].setNeedRadius(false);
                            animatingImageViews[i6].setOrientation(this.centerImage.getOrientation());
                            animatingImageViews[i6].setImageBitmap(this.centerImage.getBitmapSafe());
                        }
                        rectF = null;
                    }
                    if (layoutParams.width == 0) {
                        layoutParams.width = 1;
                    }
                    if (layoutParams.height == 0) {
                        layoutParams.height = 1;
                    }
                    float measuredWidth = this.windowView.getMeasuredWidth() / layoutParams.width;
                    float f = (AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) / layoutParams.height;
                    float f2 = measuredWidth > f ? f : measuredWidth;
                    float f3 = layoutParams.width * this.scale * f2;
                    float measuredWidth2 = (this.windowView.getMeasuredWidth() - f3) / 2.0f;
                    float f4 = ((AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - ((layoutParams.height * this.scale) * f2)) / 2.0f;
                    for (int i7 = 0; i7 < animatingImageViews.length; i7++) {
                        try {
                            animatingImageViews[i7].setLayoutParams(layoutParams);
                            animatingImageViews[i7].setTranslationX(Math.max(Float.MIN_VALUE, Math.min(measuredWidth2 + this.translationX, Float.MAX_VALUE)));
                            animatingImageViews[i7].setTranslationY(Math.max(Float.MIN_VALUE, Math.min(this.translationY + f4, Float.MAX_VALUE)));
                            animatingImageViews[i7].setScaleX(Math.max(Float.MIN_VALUE, Math.min(this.scale * f2, Float.MAX_VALUE)));
                            animatingImageViews[i7].setScaleY(Math.max(Float.MIN_VALUE, Math.min(this.scale * f2, Float.MAX_VALUE)));
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                    }
                    if (placeForPhoto != null) {
                        placeForPhoto.imageReceiver.setVisible(false, true);
                        int iAbs = (int) Math.abs(rectF.left - placeForPhoto.imageReceiver.getImageX());
                        int iAbs2 = (int) Math.abs(rectF.top - placeForPhoto.imageReceiver.getImageY());
                        placeForPhoto.parentView.getLocationInWindow(new int[2]);
                        int i8 = (int) (((r8[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight)) - (placeForPhoto.viewY + rectF.top)) + placeForPhoto.clipTopAddition);
                        if (i8 < 0) {
                            i8 = 0;
                        }
                        int height = (int) ((((placeForPhoto.viewY + rectF.top) + (rectF.bottom - rectF.top)) - ((r8[1] + placeForPhoto.parentView.getHeight()) - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight))) + placeForPhoto.clipBottomAddition);
                        if (height < 0) {
                            height = 0;
                        }
                        int iMax = Math.max(i8, iAbs2);
                        int iMax2 = Math.max(height, iAbs2);
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
                        fArr[1][0] = placeForPhoto.scale;
                        this.animationValues[1][1] = placeForPhoto.scale;
                        this.animationValues[1][2] = placeForPhoto.viewX + (rectF.left * placeForPhoto.scale);
                        this.animationValues[1][3] = placeForPhoto.viewY + (rectF.top * placeForPhoto.scale);
                        this.animationValues[1][4] = iAbs * placeForPhoto.scale;
                        this.animationValues[1][5] = iMax * placeForPhoto.scale;
                        this.animationValues[1][6] = iMax2 * placeForPhoto.scale;
                        this.animationValues[1][7] = placeForPhoto.radius;
                        this.animationValues[1][8] = iAbs2 * placeForPhoto.scale;
                        this.animationValues[1][9] = iAbs * placeForPhoto.scale;
                        ArrayList arrayList = new ArrayList((this.sendPhotoType == 1 ? 3 : 2) + animatingImageViews.length + (animatingImageViews.length > 1 ? 1 : 0));
                        int i9 = 0;
                        while (i9 < animatingImageViews.length) {
                            arrayList.add(ObjectAnimator.ofFloat(animatingImageViews[i9], AnimationProperties.CLIPPING_IMAGE_VIEW_PROGRESS, 0.0f, 1.0f));
                            i9++;
                            iMax = iMax;
                            iAbs = iAbs;
                        }
                        if (animatingImageViews.length > 1) {
                            i = 0;
                            arrayList.add(ObjectAnimator.ofFloat(this.animatingImageView, (Property<ClippingImageView, Float>) View.ALPHA, 0.0f));
                        } else {
                            i = 0;
                        }
                        BackgroundDrawable backgroundDrawable = this.backgroundDrawable;
                        Property<ColorDrawable, Integer> property = AnimationProperties.COLOR_DRAWABLE_ALPHA;
                        int[] iArr = new int[1];
                        iArr[i] = i;
                        arrayList.add(ObjectAnimator.ofInt(backgroundDrawable, (Property<BackgroundDrawable, Integer>) property, iArr));
                        FrameLayoutDrawer frameLayoutDrawer2 = this.containerView;
                        Property property2 = View.ALPHA;
                        float[] fArr2 = new float[1];
                        fArr2[i] = 0.0f;
                        arrayList.add(ObjectAnimator.ofFloat(frameLayoutDrawer2, (Property<FrameLayoutDrawer, Float>) property2, fArr2));
                        if (this.sendPhotoType == 1) {
                            PhotoCropView photoCropView = this.photoCropView;
                            Property property3 = View.ALPHA;
                            float[] fArr3 = new float[1];
                            fArr3[i] = 0.0f;
                            arrayList.add(ObjectAnimator.ofFloat(photoCropView, (Property<PhotoCropView, Float>) property3, fArr3));
                        }
                        animatorSet.playTogether(arrayList);
                    } else {
                        int i10 = AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                        Animator[] animatorArr = new Animator[4];
                        animatorArr[0] = ObjectAnimator.ofInt(this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0);
                        animatorArr[1] = ObjectAnimator.ofFloat(this.animatingImageView, (Property<ClippingImageView, Float>) View.ALPHA, 0.0f);
                        ClippingImageView clippingImageView = this.animatingImageView;
                        Property property4 = View.TRANSLATION_Y;
                        float[] fArr4 = new float[1];
                        fArr4[0] = this.translationY >= 0.0f ? i10 : -i10;
                        animatorArr[2] = ObjectAnimator.ofFloat(clippingImageView, (Property<ClippingImageView, Float>) property4, fArr4);
                        animatorArr[3] = ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayoutDrawer, Float>) View.ALPHA, 0.0f);
                        animatorSet.playTogether(animatorArr);
                    }
                    this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$NBwxFImYdOw8hukoXDg7pPFRvy4
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$closePhoto$47$PhotoViewer(placeForPhoto);
                        }
                    };
                    animatorSet.setDuration(200L);
                    animatorSet.addListener(new AnonymousClass42());
                    this.transitionAnimationStartTime = System.currentTimeMillis();
                    if (Build.VERSION.SDK_INT >= 18) {
                        this.containerView.setLayerType(2, null);
                    }
                    animatorSet.start();
                    r4 = 0;
                } else {
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    animatorSet2.playTogether(ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayoutDrawer, Float>) View.SCALE_X, 0.9f), ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayoutDrawer, Float>) View.SCALE_Y, 0.9f), ObjectAnimator.ofInt(this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0), ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayoutDrawer, Float>) View.ALPHA, 0.0f));
                    this.animationInProgress = 2;
                    this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$FKNm5Qm1X0aPC3JzzY_84gsHw8A
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$closePhoto$48$PhotoViewer(placeForPhoto);
                        }
                    };
                    animatorSet2.setDuration(200L);
                    animatorSet2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.43
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation2) {
                            if (PhotoViewer.this.animationEndRunnable != null) {
                                PhotoViewer.this.animationEndRunnable.run();
                                PhotoViewer.this.animationEndRunnable = null;
                            }
                        }
                    });
                    this.transitionAnimationStartTime = System.currentTimeMillis();
                    if (Build.VERSION.SDK_INT < 18) {
                        z3 = false;
                    } else {
                        z3 = false;
                        this.containerView.setLayerType(2, null);
                    }
                    animatorSet2.start();
                    r4 = z3;
                }
                AnimatedFileDrawable animatedFileDrawable = this.currentAnimation;
                if (animatedFileDrawable != 0) {
                    animatedFileDrawable.setSecondParentView(r4);
                    this.currentAnimation = r4;
                    this.centerImage.setImageBitmap((Drawable) r4);
                }
                PhotoViewerProvider photoViewerProvider = this.placeProvider;
                if (photoViewerProvider != null && !photoViewerProvider.canScrollAway()) {
                    this.placeProvider.cancelButtonPressed();
                }
            }
        }
    }

    public /* synthetic */ void lambda$closePhoto$46$PhotoViewer() throws JSONException {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$closePhoto$47$PhotoViewer(PlaceProviderObject object) {
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
        onPhotoClosed(object);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$42, reason: invalid class name */
    class AnonymousClass42 extends AnimatorListenerAdapter {
        AnonymousClass42() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$42$uwNYfubK8FnOUdXwU4_bRDyLLlI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$PhotoViewer$42();
                }
            });
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$PhotoViewer$42() {
            if (PhotoViewer.this.animationEndRunnable != null) {
                PhotoViewer.this.animationEndRunnable.run();
                PhotoViewer.this.animationEndRunnable = null;
            }
        }
    }

    public /* synthetic */ void lambda$closePhoto$48$PhotoViewer(PlaceProviderObject object) {
        if (this.containerView == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
        onPhotoClosed(object);
        this.containerView.setScaleX(1.0f);
        this.containerView.setScaleY(1.0f);
    }

    private ClippingImageView[] getAnimatingImageViews(PlaceProviderObject object) {
        boolean hasSecondAnimatingImageView = (AndroidUtilities.isTablet() || object == null || object.animatingImageView == null) ? false : true;
        ClippingImageView[] animatingImageViews = new ClippingImageView[(hasSecondAnimatingImageView ? 1 : 0) + 1];
        animatingImageViews[0] = this.animatingImageView;
        if (hasSecondAnimatingImageView) {
            animatingImageViews[1] = object.animatingImageView;
        }
        return animatingImageViews;
    }

    private void removeObservers() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileLoadProgressChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mediaCountDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mediaDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.dialogPhotosLoaded);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.filePreparingFailed);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileNewChunkAvailable);
        ConnectionsManager.getInstance(this.currentAccount).cancelRequestsForGuid(this.classGuid);
    }

    public void destroyPhotoViewer() {
        if (this.parentActivity == null || this.windowView == null) {
            return;
        }
        PipVideoView pipVideoView = this.pipVideoView;
        if (pipVideoView != null) {
            pipVideoView.close();
            this.pipVideoView = null;
        }
        removeObservers();
        releasePlayer(false);
        try {
            if (this.windowView.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeViewImmediate(this.windowView);
            }
            this.windowView = null;
        } catch (Exception e) {
            FileLog.e(e);
        }
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        this.animatingImageView.setImageBitmap(null);
        PhotoViewerCaptionEnterView photoViewerCaptionEnterView = this.captionEditText;
        if (photoViewerCaptionEnterView != null) {
            photoViewerCaptionEnterView.onDestroy();
        }
        if (this == PipInstance) {
            PipInstance = null;
        } else {
            Instance = null;
        }
    }

    private void onPhotoClosed(final PlaceProviderObject object) {
        this.isVisible = false;
        this.disableShowCheck = true;
        this.currentMessageObject = null;
        this.currentBotInlineResult = null;
        this.currentFileLocation = null;
        this.currentSecureDocument = null;
        this.currentPathObject = null;
        FrameLayout frameLayout = this.videoPlayerControlFrameLayout;
        if (frameLayout != null) {
            frameLayout.setVisibility(8);
            this.dateTextView.setVisibility(0);
            this.nameTextView.setVisibility(0);
        }
        this.sendPhotoType = 0;
        ImageReceiver.BitmapHolder bitmapHolder = this.currentThumb;
        if (bitmapHolder != null) {
            bitmapHolder.release();
            this.currentThumb = null;
        }
        this.parentAlert = null;
        AnimatedFileDrawable animatedFileDrawable = this.currentAnimation;
        if (animatedFileDrawable != null) {
            animatedFileDrawable.setSecondParentView(null);
            this.currentAnimation = null;
        }
        for (int a = 0; a < 3; a++) {
            PhotoProgressView[] photoProgressViewArr = this.photoProgressViews;
            if (photoProgressViewArr[a] != null) {
                photoProgressViewArr[a].setBackgroundState(-1, false);
            }
        }
        requestVideoPreview(0);
        VideoTimelinePlayView videoTimelinePlayView = this.videoTimelineView;
        if (videoTimelinePlayView != null) {
            videoTimelinePlayView.destroy();
        }
        Bitmap bitmap = (Bitmap) null;
        this.centerImage.setImageBitmap(bitmap);
        this.leftImage.setImageBitmap(bitmap);
        this.rightImage.setImageBitmap(bitmap);
        this.containerView.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$WYdy0dSpeRAHBwglTDLo_WN1ZAg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onPhotoClosed$49$PhotoViewer(object);
            }
        });
        PhotoViewerProvider photoViewerProvider = this.placeProvider;
        if (photoViewerProvider != null) {
            photoViewerProvider.willHidePhotoViewer();
        }
        this.groupedPhotosListView.clear();
        this.placeProvider = null;
        this.selectedPhotosAdapter.notifyDataSetChanged();
        this.disableShowCheck = false;
        this.videoCutStart = 0.0f;
        this.videoCutEnd = 1.0f;
        if (object != null) {
            object.imageReceiver.setVisible(true, true);
        }
    }

    public /* synthetic */ void lambda$onPhotoClosed$49$PhotoViewer(PlaceProviderObject object) {
        this.animatingImageView.setImageBitmap(null);
        if (object != null && !AndroidUtilities.isTablet() && object.animatingImageView != null) {
            object.animatingImageView.setImageBitmap(null);
        }
        try {
            if (this.windowView.getParent() != null) {
                WindowManager wm = (WindowManager) this.parentActivity.getSystemService("window");
                wm.removeView(this.windowView);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void redraw(final int count) {
        FrameLayoutDrawer frameLayoutDrawer;
        if (count < 6 && (frameLayoutDrawer = this.containerView) != null) {
            frameLayoutDrawer.invalidate();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$WStMoWbeWtP7H2LvJe2WMlVij7o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$redraw$50$PhotoViewer(count);
                }
            }, 100L);
        }
    }

    public /* synthetic */ void lambda$redraw$50$PhotoViewer(int count) {
        redraw(count + 1);
    }

    public void onResume() {
        redraw(0);
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.seekTo(videoPlayer.getCurrentPosition() + 1);
        }
    }

    public void onConfigurationChanged(Configuration newConfig) {
        PipVideoView pipVideoView = this.pipVideoView;
        if (pipVideoView != null) {
            pipVideoView.onConfigurationChanged();
        }
    }

    public void onPause() {
        if (this.currentAnimation != null) {
            closePhoto(false, false);
        } else if (this.lastTitle != null) {
            closeCaptionEnter(true);
        }
    }

    public boolean isVisible() {
        return this.isVisible && this.placeProvider != null;
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

    private int getAdditionX() {
        int i = this.currentEditMode;
        if (i != 0 && i != 3) {
            return AndroidUtilities.dp(14.0f);
        }
        return 0;
    }

    private int getAdditionY() {
        int i = this.currentEditMode;
        if (i == 3) {
            return AndroidUtilities.dp(8.0f) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
        }
        if (i != 0) {
            return AndroidUtilities.dp(14.0f) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getContainerViewWidth() {
        return getContainerViewWidth(this.currentEditMode);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getContainerViewWidth(int mode) {
        int width = this.containerView.getWidth();
        if (mode != 0 && mode != 3) {
            return width - AndroidUtilities.dp(28.0f);
        }
        return width;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getContainerViewHeight() {
        return getContainerViewHeight(this.currentEditMode);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getContainerViewHeight(int mode) {
        int height = AndroidUtilities.displaySize.y;
        if (mode == 0 && Build.VERSION.SDK_INT >= 21) {
            height += AndroidUtilities.statusBarHeight;
        }
        if (mode == 1) {
            return height - AndroidUtilities.dp(144.0f);
        }
        if (mode == 2) {
            return height - AndroidUtilities.dp(214.0f);
        }
        if (mode == 3) {
            return height - (AndroidUtilities.dp(48.0f) + ActionBar.getCurrentActionBarHeight());
        }
        return height;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:136:0x0256  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r13) {
        /*
            Method dump skipped, instruction units count: 1174
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PhotoViewer.onTouchEvent(android.view.MotionEvent):boolean");
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
        animatorSet.playTogether(ObjectAnimator.ofFloat(this, AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
        this.imageMoveAnimation.setInterpolator(this.interpolator);
        this.imageMoveAnimation.setDuration(duration);
        this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.44
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                PhotoViewer.this.imageMoveAnimation = null;
                PhotoViewer.this.containerView.invalidate();
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

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0314  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onDraw(android.graphics.Canvas r32) {
        /*
            Method dump skipped, instruction units count: 1753
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PhotoViewer.onDraw(android.graphics.Canvas):void");
    }

    public /* synthetic */ void lambda$onDraw$51$PhotoViewer() {
        setImageIndex(this.currentIndex + 1, false);
    }

    public /* synthetic */ void lambda$onDraw$52$PhotoViewer() {
        setImageIndex(this.currentIndex - 1, false);
    }

    private void onActionClick(boolean download) {
        if ((this.currentMessageObject == null && this.currentBotInlineResult == null) || this.currentFileNames[0] == null) {
            return;
        }
        Uri uri = null;
        File file = null;
        this.isStreaming = false;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null) {
            if (messageObject.messageOwner.attachPath != null && this.currentMessageObject.messageOwner.attachPath.length() != 0) {
                file = new File(this.currentMessageObject.messageOwner.attachPath);
                if (!file.exists()) {
                    file = null;
                }
            }
            if (file == null) {
                file = FileLoader.getPathToMessage(this.currentMessageObject.messageOwner);
                if (!file.exists()) {
                    file = null;
                    if (SharedConfig.streamMedia && ((int) this.currentMessageObject.getDialogId()) != 0 && this.currentMessageObject.isVideo() && this.currentMessageObject.canStreamVideo()) {
                        try {
                            int reference = FileLoader.getInstance(this.currentMessageObject.currentAccount).getFileReference(this.currentMessageObject);
                            FileLoader.getInstance(this.currentAccount).loadFile(this.currentMessageObject.getDocument(), this.currentMessageObject, 1, 0);
                            TLRPC.Document document = this.currentMessageObject.getDocument();
                            StringBuilder sb = new StringBuilder();
                            sb.append("?account=");
                            sb.append(this.currentMessageObject.currentAccount);
                            sb.append("&id=");
                            sb.append(document.id);
                            sb.append("&hash=");
                            sb.append(document.access_hash);
                            sb.append("&dc=");
                            sb.append(document.dc_id);
                            sb.append("&size=");
                            sb.append(document.size);
                            sb.append("&mime=");
                            sb.append(URLEncoder.encode(document.mime_type, "UTF-8"));
                            sb.append("&rid=");
                            sb.append(reference);
                            sb.append("&name=");
                            sb.append(URLEncoder.encode(FileLoader.getDocumentFileName(document), "UTF-8"));
                            sb.append("&reference=");
                            sb.append(Utilities.bytesToHex(document.file_reference != null ? document.file_reference : new byte[0]));
                            String params = sb.toString();
                            uri = Uri.parse("hchat://" + this.currentMessageObject.getFileName() + params);
                            this.isStreaming = true;
                            checkProgress(0, false);
                        } catch (Exception e) {
                        }
                    }
                }
            }
        } else {
            TLRPC.BotInlineResult botInlineResult = this.currentBotInlineResult;
            if (botInlineResult != null) {
                if (botInlineResult.document != null) {
                    file = FileLoader.getPathToAttach(this.currentBotInlineResult.document);
                    if (!file.exists()) {
                        file = null;
                    }
                } else if (this.currentBotInlineResult.content instanceof TLRPC.TL_webDocument) {
                    file = new File(FileLoader.getDirectory(4), Utilities.MD5(this.currentBotInlineResult.content.url) + "." + ImageLoader.getHttpUrlExtension(this.currentBotInlineResult.content.url, "mp4"));
                    if (!file.exists()) {
                        file = null;
                    }
                }
            }
        }
        if (file != null && uri == null) {
            uri = Uri.fromFile(file);
        }
        if (uri == null) {
            if (download) {
                if (this.currentMessageObject != null) {
                    if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[0])) {
                        FileLoader.getInstance(this.currentAccount).loadFile(this.currentMessageObject.getDocument(), this.currentMessageObject, 1, 0);
                    } else {
                        FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.currentMessageObject.getDocument());
                    }
                } else {
                    TLRPC.BotInlineResult botInlineResult2 = this.currentBotInlineResult;
                    if (botInlineResult2 != null) {
                        if (botInlineResult2.document != null) {
                            if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[0])) {
                                FileLoader.getInstance(this.currentAccount).loadFile(this.currentBotInlineResult.document, this.currentMessageObject, 1, 0);
                            } else {
                                FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.currentBotInlineResult.document);
                            }
                        } else if (this.currentBotInlineResult.content instanceof TLRPC.TL_webDocument) {
                            if (!ImageLoader.getInstance().isLoadingHttpFile(this.currentBotInlineResult.content.url)) {
                                ImageLoader.getInstance().loadHttpFile(this.currentBotInlineResult.content.url, "mp4", this.currentAccount);
                            } else {
                                ImageLoader.getInstance().cancelLoadHttpFile(this.currentBotInlineResult.content.url);
                            }
                        }
                    }
                }
                Drawable drawable = this.centerImage.getStaticThumb();
                if (drawable instanceof OtherDocumentPlaceholderDrawable) {
                    ((OtherDocumentPlaceholderDrawable) drawable).checkFileExist();
                    return;
                }
                return;
            }
            return;
        }
        if (this.sharedMediaType == 1 && !this.currentMessageObject.canPreviewDocument()) {
            AndroidUtilities.openDocument(this.currentMessageObject, this.parentActivity, null);
        } else {
            preparePlayer(uri, true, false);
        }
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
        if (!this.canZoom && !this.doubleTapEnabled) {
            return onSingleTapConfirmed(e);
        }
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
        int state;
        MessageObject messageObject;
        if (this.discardTap) {
            return false;
        }
        if (this.containerView.getTag() != null) {
            AspectRatioFrameLayout aspectRatioFrameLayout = this.aspectRatioFrameLayout;
            boolean drawTextureView = aspectRatioFrameLayout != null && aspectRatioFrameLayout.getVisibility() == 0;
            float x = e.getX();
            float y = e.getY();
            if (this.sharedMediaType == 1 && (messageObject = this.currentMessageObject) != null) {
                if (!messageObject.canPreviewDocument()) {
                    float vy = (getContainerViewHeight() - AndroidUtilities.dp(360.0f)) / 2.0f;
                    if (y >= vy && y <= AndroidUtilities.dp(360.0f) + vy) {
                        onActionClick(true);
                        return true;
                    }
                }
            } else {
                PhotoProgressView[] photoProgressViewArr = this.photoProgressViews;
                if (photoProgressViewArr[0] != null && this.containerView != null && !drawTextureView && (state = photoProgressViewArr[0].backgroundState) > 0 && state <= 3 && x >= (getContainerViewWidth() - AndroidUtilities.dp(100.0f)) / 2.0f && x <= (getContainerViewWidth() + AndroidUtilities.dp(100.0f)) / 2.0f && y >= (getContainerViewHeight() - AndroidUtilities.dp(100.0f)) / 2.0f && y <= (getContainerViewHeight() + AndroidUtilities.dp(100.0f)) / 2.0f) {
                    onActionClick(true);
                    checkProgress(0, true);
                    return true;
                }
            }
            toggleActionBar(!this.isActionBarVisible, true);
        } else {
            int i = this.sendPhotoType;
            if (i == 0 || i == 4) {
                if (this.isCurrentVideo) {
                    this.videoPlayButton.callOnClick();
                } else {
                    this.checkImageView.performClick();
                }
            } else {
                TLRPC.BotInlineResult botInlineResult = this.currentBotInlineResult;
                if (botInlineResult != null && (botInlineResult.type.equals("video") || MessageObject.isVideoDocument(this.currentBotInlineResult.document))) {
                    int state2 = this.photoProgressViews[0].backgroundState;
                    if (state2 > 0 && state2 <= 3) {
                        float x2 = e.getX();
                        float y2 = e.getY();
                        if (x2 >= (getContainerViewWidth() - AndroidUtilities.dp(100.0f)) / 2.0f && x2 <= (getContainerViewWidth() + AndroidUtilities.dp(100.0f)) / 2.0f && y2 >= (getContainerViewHeight() - AndroidUtilities.dp(100.0f)) / 2.0f && y2 <= (getContainerViewHeight() + AndroidUtilities.dp(100.0f)) / 2.0f) {
                            onActionClick(true);
                            checkProgress(0, true);
                            return true;
                        }
                    }
                } else if (this.sendPhotoType == 2 && this.isCurrentVideo) {
                    this.videoPlayButton.callOnClick();
                }
            }
        }
        return true;
    }

    @Override // android.view.GestureDetector.OnDoubleTapListener
    public boolean onDoubleTap(MotionEvent e) {
        if (this.videoPlayer != null && this.videoPlayerControlFrameLayout.getVisibility() == 0) {
            long current = this.videoPlayer.getCurrentPosition();
            long total = this.videoPlayer.getDuration();
            if (total >= 0 && current >= 0 && total != C.TIME_UNSET && current != C.TIME_UNSET) {
                int width = getContainerViewWidth();
                float x = e.getX();
                if (x >= (width / 3) * 2) {
                    current += OkHttpUtils.DEFAULT_MILLISECONDS;
                } else if (x < width / 3) {
                    current -= OkHttpUtils.DEFAULT_MILLISECONDS;
                }
                if (current != current) {
                    if (current > total) {
                        current = total;
                    } else if (current < 0) {
                        current = 0;
                    }
                    this.videoForwardDrawable.setLeftSide(x < ((float) (width / 3)));
                    this.videoPlayer.seekTo(current);
                    this.containerView.invalidate();
                    this.videoPlayerSeekbar.setProgress(current / total);
                    this.videoPlayerControlFrameLayout.invalidate();
                    return true;
                }
            }
        }
        if (!this.canZoom || ((this.scale == 1.0f && (this.translationY != 0.0f || this.translationX != 0.0f)) || this.animationStartTime != 0 || this.animationInProgress != 0)) {
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

    private class QualityChooseView extends View {
        private int circleSize;
        private int gapSize;
        private int lineSize;
        private boolean moving;
        private Paint paint;
        private int sideSide;
        private boolean startMoving;
        private int startMovingQuality;
        private float startX;
        private TextPaint textPaint;

        public QualityChooseView(Context context) {
            super(context);
            this.paint = new Paint(1);
            TextPaint textPaint = new TextPaint(1);
            this.textPaint = textPaint;
            textPaint.setTextSize(AndroidUtilities.dp(12.0f));
            this.textPaint.setColor(-3289651);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            float x = event.getX();
            if (event.getAction() == 0) {
                getParent().requestDisallowInterceptTouchEvent(true);
                int a = 0;
                while (true) {
                    if (a >= PhotoViewer.this.compressionsCount) {
                        break;
                    }
                    int i = this.sideSide;
                    int i2 = this.lineSize + (this.gapSize * 2);
                    int i3 = this.circleSize;
                    int cx = i + ((i2 + i3) * a) + (i3 / 2);
                    if (x > cx - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx) {
                        this.startMoving = a == PhotoViewer.this.selectedCompression;
                        this.startX = x;
                        this.startMovingQuality = PhotoViewer.this.selectedCompression;
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
                        if (a2 >= PhotoViewer.this.compressionsCount) {
                            break;
                        }
                        int i4 = this.sideSide;
                        int i5 = this.lineSize;
                        int i6 = this.gapSize;
                        int i7 = this.circleSize;
                        int cx2 = i4 + (((i6 * 2) + i5 + i7) * a2) + (i7 / 2);
                        int diff = (i5 / 2) + (i7 / 2) + i6;
                        if (x > cx2 - diff && x < cx2 + diff) {
                            if (PhotoViewer.this.selectedCompression != a2) {
                                PhotoViewer.this.selectedCompression = a2;
                                PhotoViewer.this.didChangedCompressionLevel(false);
                                invalidate();
                            }
                        } else {
                            a2++;
                        }
                    }
                }
            } else if (event.getAction() == 1 || event.getAction() == 3) {
                if (this.moving) {
                    if (PhotoViewer.this.selectedCompression != this.startMovingQuality) {
                        PhotoViewer.this.requestVideoPreview(1);
                    }
                } else {
                    int a3 = 0;
                    while (true) {
                        if (a3 >= PhotoViewer.this.compressionsCount) {
                            break;
                        }
                        int i8 = this.sideSide;
                        int i9 = this.lineSize + (this.gapSize * 2);
                        int i10 = this.circleSize;
                        int cx3 = i8 + ((i9 + i10) * a3) + (i10 / 2);
                        if (x > cx3 - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx3) {
                            if (PhotoViewer.this.selectedCompression != a3) {
                                PhotoViewer.this.selectedCompression = a3;
                                PhotoViewer.this.didChangedCompressionLevel(true);
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
            this.circleSize = AndroidUtilities.dp(12.0f);
            this.gapSize = AndroidUtilities.dp(2.0f);
            this.sideSide = AndroidUtilities.dp(18.0f);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            String text;
            if (PhotoViewer.this.compressionsCount != 1) {
                this.lineSize = (((getMeasuredWidth() - (this.circleSize * PhotoViewer.this.compressionsCount)) - (this.gapSize * 8)) - (this.sideSide * 2)) / (PhotoViewer.this.compressionsCount - 1);
            } else {
                this.lineSize = ((getMeasuredWidth() - (this.circleSize * PhotoViewer.this.compressionsCount)) - (this.gapSize * 8)) - (this.sideSide * 2);
            }
            int cy = (getMeasuredHeight() / 2) + AndroidUtilities.dp(6.0f);
            int a = 0;
            while (a < PhotoViewer.this.compressionsCount) {
                int i = this.sideSide;
                int i2 = this.lineSize + (this.gapSize * 2);
                int i3 = this.circleSize;
                int cx = i + ((i2 + i3) * a) + (i3 / 2);
                if (a <= PhotoViewer.this.selectedCompression) {
                    this.paint.setColor(-11292945);
                } else {
                    this.paint.setColor(1728053247);
                }
                if (a == PhotoViewer.this.compressionsCount - 1) {
                    text = Math.min(PhotoViewer.this.originalWidth, PhotoViewer.this.originalHeight) + TtmlNode.TAG_P;
                } else if (a == 0) {
                    text = "240p";
                } else if (a == 1) {
                    text = "360p";
                } else if (a == 2) {
                    text = "480p";
                } else {
                    text = "720p";
                }
                float width = this.textPaint.measureText(text);
                canvas.drawCircle(cx, cy, a == PhotoViewer.this.selectedCompression ? AndroidUtilities.dp(8.0f) : this.circleSize / 2, this.paint);
                canvas.drawText(text, cx - (width / 2.0f), cy - AndroidUtilities.dp(16.0f), this.textPaint);
                if (a != 0) {
                    int x = ((cx - (this.circleSize / 2)) - this.gapSize) - this.lineSize;
                    canvas.drawRect(x, cy - AndroidUtilities.dp(1.0f), this.lineSize + x, AndroidUtilities.dp(2.0f) + cy, this.paint);
                }
                a++;
            }
        }
    }

    public void updateMuteButton() {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.setMute(this.muteVideo);
        }
        if (!this.videoHasAudio) {
            this.muteItem.setEnabled(false);
            this.muteItem.setClickable(false);
            this.muteItem.animate().alpha(0.5f).setDuration(180L).start();
            return;
        }
        this.muteItem.setEnabled(true);
        this.muteItem.setClickable(true);
        this.muteItem.animate().alpha(1.0f).setDuration(180L).start();
        if (this.muteVideo) {
            this.actionBar.setSubtitle(null);
            this.muteItem.setImageResource(R.drawable.volume_off);
            this.muteItem.setColorFilter(new PorterDuffColorFilter(-12734994, PorterDuff.Mode.MULTIPLY));
            if (this.compressItem.getTag() != null) {
                this.compressItem.setClickable(false);
                this.compressItem.setAlpha(0.5f);
                this.compressItem.setEnabled(false);
            }
            this.videoTimelineView.setMaxProgressDiff(30000.0f / this.videoDuration);
            this.muteItem.setContentDescription(LocaleController.getString("NoSound", R.string.NoSound));
            return;
        }
        this.muteItem.setColorFilter((ColorFilter) null);
        this.actionBar.setSubtitle(this.currentSubtitle);
        this.muteItem.setImageResource(R.drawable.volume_on);
        this.muteItem.setContentDescription(LocaleController.getString("Sound", R.string.Sound));
        if (this.compressItem.getTag() != null) {
            this.compressItem.setClickable(true);
            this.compressItem.setAlpha(1.0f);
            this.compressItem.setEnabled(true);
        }
        this.videoTimelineView.setMaxProgressDiff(1.0f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void didChangedCompressionLevel(boolean request) {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("compress_video2", this.selectedCompression);
        editor.commit();
        updateWidthHeightBitrateForCompression();
        updateVideoInfo();
        if (request) {
            requestVideoPreview(1);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVideoInfo() {
        int width;
        int height;
        ActionBar actionBar = this.actionBar;
        if (actionBar == null) {
            return;
        }
        if (this.compressionsCount == 0) {
            actionBar.setSubtitle(null);
            return;
        }
        int i = this.selectedCompression;
        if (i == 0) {
            this.compressItem.setImageResource(R.drawable.video_240);
        } else if (i == 1) {
            this.compressItem.setImageResource(R.drawable.video_360);
        } else if (i == 2) {
            this.compressItem.setImageResource(R.drawable.video_480);
        } else if (i == 3) {
            this.compressItem.setImageResource(R.drawable.video_720);
        } else if (i == 4) {
            this.compressItem.setImageResource(R.drawable.video_1080);
        }
        String[] compressionStrings = {"240", "360", "480", "720", "1080"};
        this.compressItem.setContentDescription(LocaleController.getString("AccDescrVideoQuality", R.string.AccDescrVideoQuality) + ", " + compressionStrings[Math.max(0, this.selectedCompression)]);
        this.estimatedDuration = (long) Math.ceil((double) ((this.videoTimelineView.getRightProgress() - this.videoTimelineView.getLeftProgress()) * this.videoDuration));
        if (this.compressItem.getTag() == null || this.selectedCompression == this.compressionsCount - 1) {
            int width2 = this.rotationValue;
            width = (width2 == 90 || width2 == 270) ? this.originalHeight : this.originalWidth;
            int i2 = this.rotationValue;
            height = (i2 == 90 || i2 == 270) ? this.originalWidth : this.originalHeight;
            this.estimatedSize = (int) (this.originalSize * (this.estimatedDuration / this.videoDuration));
        } else {
            int i3 = this.rotationValue;
            width = (i3 == 90 || i3 == 270) ? this.resultHeight : this.resultWidth;
            int i4 = this.rotationValue;
            height = (i4 == 90 || i4 == 270) ? this.resultWidth : this.resultHeight;
            int i5 = (int) ((this.audioFramesSize + this.videoFramesSize) * (this.estimatedDuration / this.videoDuration));
            this.estimatedSize = i5;
            this.estimatedSize = i5 + ((i5 / 32768) * 16);
        }
        this.videoCutStart = this.videoTimelineView.getLeftProgress();
        this.videoCutEnd = this.videoTimelineView.getRightProgress();
        float f = this.videoCutStart;
        if (f != 0.0f) {
            this.startTime = ((long) (f * this.videoDuration)) * 1000;
        } else {
            this.startTime = -1L;
        }
        float f2 = this.videoCutEnd;
        if (f2 != 1.0f) {
            this.endTime = ((long) (f2 * this.videoDuration)) * 1000;
        } else {
            this.endTime = -1L;
        }
        String videoDimension = String.format("%dx%d", Integer.valueOf(width), Integer.valueOf(height));
        long j = this.estimatedDuration;
        int minutes = (int) ((j / 1000) / 60);
        int seconds = ((int) Math.ceil(j / 1000.0d)) - (minutes * 60);
        String videoTimeSize = String.format("%d:%02d, ~%s", Integer.valueOf(minutes), Integer.valueOf(seconds), AndroidUtilities.formatFileSize(this.estimatedSize));
        String str = String.format("%s, %s", videoDimension, videoTimeSize);
        this.currentSubtitle = str;
        ActionBar actionBar2 = this.actionBar;
        if (this.muteVideo) {
            str = null;
        }
        actionBar2.setSubtitle(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void requestVideoPreview(int request) {
        if (this.videoPreviewMessageObject != null) {
            MediaController.getInstance().cancelVideoConvert(this.videoPreviewMessageObject);
        }
        boolean z = true;
        boolean wasRequestingPreview = this.requestingPreview && !this.tryStartRequestPreviewOnFinish;
        this.requestingPreview = false;
        this.loadInitialVideo = false;
        this.progressView.setVisibility(4);
        if (request == 1) {
            if (this.resultHeight == this.originalHeight && this.resultWidth == this.originalWidth) {
                this.tryStartRequestPreviewOnFinish = false;
                PhotoProgressView[] photoProgressViewArr = this.photoProgressViews;
                photoProgressViewArr[0].setProgress(0.0f, photoProgressViewArr[0].backgroundState == 0 || this.photoProgressViews[0].previousBackgroundState == 0);
                this.photoProgressViews[0].setBackgroundState(3, false);
                if (!wasRequestingPreview) {
                    preparePlayer(this.currentPlayingVideoFile, false, false);
                    this.videoPlayer.seekTo((long) (this.videoTimelineView.getLeftProgress() * this.videoDuration));
                } else {
                    this.progressView.setVisibility(0);
                    this.loadInitialVideo = true;
                }
            } else {
                this.requestingPreview = true;
                releasePlayer(false);
                if (this.videoPreviewMessageObject == null) {
                    TLRPC.TL_message message = new TLRPC.TL_message();
                    message.id = 0;
                    message.message = "";
                    message.media = new TLRPC.TL_messageMediaEmpty();
                    message.action = new TLRPC.TL_messageActionEmpty();
                    message.dialog_id = this.currentDialogId;
                    MessageObject messageObject = new MessageObject(UserConfig.selectedAccount, message, false);
                    this.videoPreviewMessageObject = messageObject;
                    messageObject.messageOwner.attachPath = new File(FileLoader.getDirectory(4), "video_preview.mp4").getAbsolutePath();
                    this.videoPreviewMessageObject.videoEditedInfo = new VideoEditedInfo();
                    this.videoPreviewMessageObject.videoEditedInfo.rotationValue = this.rotationValue;
                    this.videoPreviewMessageObject.videoEditedInfo.originalWidth = this.originalWidth;
                    this.videoPreviewMessageObject.videoEditedInfo.originalHeight = this.originalHeight;
                    this.videoPreviewMessageObject.videoEditedInfo.framerate = this.videoFramerate;
                    this.videoPreviewMessageObject.videoEditedInfo.originalPath = this.currentPlayingVideoFile.getPath();
                }
                VideoEditedInfo videoEditedInfo = this.videoPreviewMessageObject.videoEditedInfo;
                long j = this.startTime;
                videoEditedInfo.startTime = j;
                long start = j;
                VideoEditedInfo videoEditedInfo2 = this.videoPreviewMessageObject.videoEditedInfo;
                long j2 = this.endTime;
                videoEditedInfo2.endTime = j2;
                long end = j2;
                if (start == -1) {
                    start = 0;
                }
                if (end == -1) {
                    end = (long) (this.videoDuration * 1000.0f);
                }
                if (end - start > 5000000) {
                    this.videoPreviewMessageObject.videoEditedInfo.endTime = 5000000 + start;
                }
                this.videoPreviewMessageObject.videoEditedInfo.bitrate = this.bitrate;
                this.videoPreviewMessageObject.videoEditedInfo.resultWidth = this.resultWidth;
                this.videoPreviewMessageObject.videoEditedInfo.resultHeight = this.resultHeight;
                if (!MediaController.getInstance().scheduleVideoConvert(this.videoPreviewMessageObject, true)) {
                    this.tryStartRequestPreviewOnFinish = true;
                }
                this.requestingPreview = true;
                PhotoProgressView[] photoProgressViewArr2 = this.photoProgressViews;
                PhotoProgressView photoProgressView = photoProgressViewArr2[0];
                if (photoProgressViewArr2[0].backgroundState != 0 && this.photoProgressViews[0].previousBackgroundState != 0) {
                    z = false;
                }
                photoProgressView.setProgress(0.0f, z);
                this.photoProgressViews[0].setBackgroundState(0, false);
            }
        } else {
            this.tryStartRequestPreviewOnFinish = false;
            this.photoProgressViews[0].setBackgroundState(3, false);
            if (request == 2) {
                preparePlayer(this.currentPlayingVideoFile, false, false);
                this.videoPlayer.seekTo((long) (this.videoTimelineView.getLeftProgress() * this.videoDuration));
            }
        }
        this.containerView.invalidate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateWidthHeightBitrateForCompression() {
        float maxSize;
        int targetBitrate;
        int i = this.compressionsCount;
        if (i <= 0) {
            return;
        }
        if (this.selectedCompression >= i) {
            this.selectedCompression = i - 1;
        }
        int i2 = this.selectedCompression;
        if (i2 != this.compressionsCount - 1) {
            if (i2 == 0) {
                maxSize = 426.0f;
                targetBitrate = 400000;
            } else if (i2 != 1) {
                if (i2 == 2) {
                    maxSize = 854.0f;
                    targetBitrate = 1100000;
                } else {
                    targetBitrate = 2621440;
                    maxSize = 1280.0f;
                }
            } else {
                maxSize = 640.0f;
                targetBitrate = 900000;
            }
            int i3 = this.originalWidth;
            int i4 = this.originalHeight;
            float scale = maxSize / (i3 > i4 ? i3 : i4);
            if (this.selectedCompression == this.compressionsCount - 1 && scale >= 1.0f) {
                this.resultWidth = this.originalWidth;
                this.resultHeight = this.originalHeight;
            } else {
                this.resultWidth = Math.round((this.originalWidth * scale) / 2.0f) * 2;
                this.resultHeight = Math.round((this.originalHeight * scale) / 2.0f) * 2;
            }
            if (this.bitrate != 0) {
                this.bitrate = Math.min(targetBitrate, (int) (this.originalBitrate / scale));
                this.videoFramesSize = (long) (((r1 / 8) * this.videoDuration) / 1000.0f);
            }
        }
    }

    private void showQualityView(final boolean show) {
        if (show) {
            this.previousCompression = this.selectedCompression;
        }
        AnimatorSet animatorSet = this.qualityChooseViewAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.qualityChooseViewAnimation = new AnimatorSet();
        if (show) {
            this.qualityChooseView.setTag(1);
            this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(152.0f)), ObjectAnimator.ofFloat(this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(152.0f)), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f), AndroidUtilities.dp(104.0f)));
        } else {
            this.qualityChooseView.setTag(null);
            this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(this.qualityChooseView, (Property<QualityChooseView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(166.0f)), ObjectAnimator.ofFloat(this.qualityPicker, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(166.0f)), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f), AndroidUtilities.dp(118.0f)));
        }
        this.qualityChooseViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.45
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(PhotoViewer.this.qualityChooseViewAnimation)) {
                    PhotoViewer.this.qualityChooseViewAnimation = new AnimatorSet();
                    if (show) {
                        PhotoViewer.this.qualityChooseView.setVisibility(0);
                        PhotoViewer.this.qualityPicker.setVisibility(0);
                        PhotoViewer.this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this.qualityChooseView, (Property<QualityChooseView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(PhotoViewer.this.qualityPicker, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(PhotoViewer.this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)));
                    } else {
                        PhotoViewer.this.qualityChooseView.setVisibility(4);
                        PhotoViewer.this.qualityPicker.setVisibility(4);
                        PhotoViewer.this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(PhotoViewer.this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(PhotoViewer.this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(PhotoViewer.this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)));
                    }
                    PhotoViewer.this.qualityChooseViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PhotoViewer.45.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation2) {
                            if (animation2.equals(PhotoViewer.this.qualityChooseViewAnimation)) {
                                PhotoViewer.this.qualityChooseViewAnimation = null;
                            }
                        }
                    });
                    PhotoViewer.this.qualityChooseViewAnimation.setDuration(200L);
                    PhotoViewer.this.qualityChooseViewAnimation.setInterpolator(new AccelerateInterpolator());
                    PhotoViewer.this.qualityChooseViewAnimation.start();
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                PhotoViewer.this.qualityChooseViewAnimation = null;
            }
        });
        this.qualityChooseViewAnimation.setDuration(200L);
        this.qualityChooseViewAnimation.setInterpolator(new DecelerateInterpolator());
        this.qualityChooseViewAnimation.start();
        if (this.cameraItem.getVisibility() == 0) {
            this.cameraItem.animate().scaleX(show ? 0.25f : 1.0f).scaleY(show ? 0.25f : 1.0f).alpha(show ? 0.0f : 1.0f).setDuration(200L);
        }
    }

    private ByteArrayInputStream cleanBuffer(byte[] data) {
        byte[] output = new byte[data.length];
        int inPos = 0;
        int outPos = 0;
        while (inPos < data.length) {
            if (data[inPos] == 0 && data[inPos + 1] == 0 && data[inPos + 2] == 3) {
                output[outPos] = 0;
                output[outPos + 1] = 0;
                inPos += 3;
                outPos += 2;
            } else {
                output[outPos] = data[inPos];
                inPos++;
                outPos++;
            }
        }
        return new ByteArrayInputStream(output, 0, outPos);
    }

    private void processOpenVideo(String videoPath, boolean muted, float start, float end) {
        if (this.currentLoadingVideoRunnable != null) {
            Utilities.globalQueue.cancelRunnable(this.currentLoadingVideoRunnable);
            this.currentLoadingVideoRunnable = null;
        }
        this.videoTimelineView.setVideoPath(videoPath, start, end);
        this.videoPreviewMessageObject = null;
        setCompressItemEnabled(false, true);
        this.muteVideo = muted;
        Object object = this.imagesArrLocals.get(this.currentIndex);
        if (object instanceof MediaController.PhotoEntry) {
            ((MediaController.PhotoEntry) object).editedInfo = getCurrentVideoEditedInfo();
        }
        this.compressionsCount = -1;
        this.rotationValue = 0;
        this.videoFramerate = 25;
        File file = new File(videoPath);
        this.originalSize = file.length();
        DispatchQueue dispatchQueue = Utilities.globalQueue;
        AnonymousClass46 anonymousClass46 = new AnonymousClass46(videoPath);
        this.currentLoadingVideoRunnable = anonymousClass46;
        dispatchQueue.postRunnable(anonymousClass46);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PhotoViewer$46, reason: invalid class name */
    class AnonymousClass46 implements Runnable {
        final /* synthetic */ String val$videoPath;

        AnonymousClass46(String str) {
            this.val$videoPath = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (PhotoViewer.this.currentLoadingVideoRunnable != this) {
                return;
            }
            final int[] params = new int[9];
            AnimatedFileDrawable.getVideoInfo(this.val$videoPath, params);
            if (PhotoViewer.this.currentLoadingVideoRunnable == this) {
                PhotoViewer.this.currentLoadingVideoRunnable = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$46$Q7I9NoB1RykBiAbxjPxNEEVWaqM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$0$PhotoViewer$46(params);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$run$0$PhotoViewer$46(int[] params) {
            if (PhotoViewer.this.parentActivity == null) {
                return;
            }
            PhotoViewer.this.videoHasAudio = params[0] != 0;
            PhotoViewer.this.audioFramesSize = params[5];
            PhotoViewer.this.videoFramesSize = params[6];
            PhotoViewer.this.videoDuration = params[4];
            PhotoViewer photoViewer = PhotoViewer.this;
            photoViewer.originalBitrate = photoViewer.bitrate = params[3];
            PhotoViewer.this.videoFramerate = params[7];
            if (PhotoViewer.this.bitrate > 900000) {
                PhotoViewer.this.bitrate = 900000;
            }
            if (PhotoViewer.this.videoHasAudio) {
                PhotoViewer.this.rotationValue = params[8];
                PhotoViewer photoViewer2 = PhotoViewer.this;
                photoViewer2.resultWidth = photoViewer2.originalWidth = params[1];
                PhotoViewer photoViewer3 = PhotoViewer.this;
                photoViewer3.resultHeight = photoViewer3.originalHeight = params[2];
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                PhotoViewer.this.selectedCompression = preferences.getInt("compress_video2", 1);
                if (PhotoViewer.this.originalWidth > 1280 || PhotoViewer.this.originalHeight > 1280) {
                    PhotoViewer.this.compressionsCount = 5;
                } else if (PhotoViewer.this.originalWidth > 854 || PhotoViewer.this.originalHeight > 854) {
                    PhotoViewer.this.compressionsCount = 4;
                } else if (PhotoViewer.this.originalWidth > 640 || PhotoViewer.this.originalHeight > 640) {
                    PhotoViewer.this.compressionsCount = 3;
                } else if (PhotoViewer.this.originalWidth > 480 || PhotoViewer.this.originalHeight > 480) {
                    PhotoViewer.this.compressionsCount = 2;
                } else {
                    PhotoViewer.this.compressionsCount = 1;
                }
                PhotoViewer.this.updateWidthHeightBitrateForCompression();
                PhotoViewer photoViewer4 = PhotoViewer.this;
                photoViewer4.setCompressItemEnabled(photoViewer4.compressionsCount > 1, true);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("compressionsCount = " + PhotoViewer.this.compressionsCount + " w = " + PhotoViewer.this.originalWidth + " h = " + PhotoViewer.this.originalHeight);
                }
                if (Build.VERSION.SDK_INT < 18 && PhotoViewer.this.compressItem.getTag() != null) {
                    try {
                        MediaCodecInfo codecInfo = MediaController.selectCodec("video/avc");
                        if (codecInfo == null) {
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("no codec info for video/avc");
                            }
                            PhotoViewer.this.setCompressItemEnabled(false, true);
                        } else {
                            String name = codecInfo.getName();
                            if (name.equals("OMX.google.h264.encoder") || name.equals("OMX.ST.VFM.H264Enc") || name.equals("OMX.Exynos.avc.enc") || name.equals("OMX.MARVELL.VIDEO.HW.CODA7542ENCODER") || name.equals("OMX.MARVELL.VIDEO.H264ENCODER") || name.equals("OMX.k3.video.encoder.avc") || name.equals("OMX.TI.DUCATI1.VIDEO.H264E")) {
                                if (BuildVars.LOGS_ENABLED) {
                                    FileLog.d("unsupported encoder = " + name);
                                }
                                PhotoViewer.this.setCompressItemEnabled(false, true);
                            } else if (MediaController.selectColorFormat(codecInfo, "video/avc") == 0) {
                                if (BuildVars.LOGS_ENABLED) {
                                    FileLog.d("no color format for video/avc");
                                }
                                PhotoViewer.this.setCompressItemEnabled(false, true);
                            }
                        }
                    } catch (Exception e) {
                        PhotoViewer.this.setCompressItemEnabled(false, true);
                        FileLog.e(e);
                    }
                }
                PhotoViewer.this.qualityChooseView.invalidate();
            } else {
                PhotoViewer.this.compressionsCount = 0;
            }
            PhotoViewer.this.updateVideoInfo();
            PhotoViewer.this.updateMuteButton();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCompressItemEnabled(boolean enabled, boolean animated) {
        ImageView imageView = this.compressItem;
        if (imageView == null) {
            return;
        }
        if (!enabled || imageView.getTag() == null) {
            if (!enabled && this.compressItem.getTag() == null) {
                return;
            }
            this.compressItem.setTag(enabled ? 1 : null);
            this.compressItem.setEnabled(enabled);
            this.compressItem.setClickable(enabled);
            AnimatorSet animatorSet = this.compressItemAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.compressItemAnimation = null;
            }
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.compressItemAnimation = animatorSet2;
                Animator[] animatorArr = new Animator[1];
                ImageView imageView2 = this.compressItem;
                Property property = View.ALPHA;
                float[] fArr = new float[1];
                fArr[0] = enabled ? 1.0f : 0.5f;
                animatorArr[0] = ObjectAnimator.ofFloat(imageView2, (Property<ImageView, Float>) property, fArr);
                animatorSet2.playTogether(animatorArr);
                this.compressItemAnimation.setDuration(180L);
                this.compressItemAnimation.setInterpolator(decelerateInterpolator);
                this.compressItemAnimation.start();
                return;
            }
            this.compressItem.setAlpha(enabled ? 1.0f : 0.5f);
        }
    }

    private void updateAccessibilityOverlayVisibility() {
        VideoPlayer videoPlayer;
        if (this.playButtonAccessibilityOverlay == null) {
            return;
        }
        if (this.isCurrentVideo && ((videoPlayer = this.videoPlayer) == null || !videoPlayer.isPlaying())) {
            this.playButtonAccessibilityOverlay.setVisibility(0);
        } else {
            this.playButtonAccessibilityOverlay.setVisibility(4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (PhotoViewer.this.placeProvider != null && PhotoViewer.this.placeProvider.getSelectedPhotosOrder() != null) {
                return PhotoViewer.this.placeProvider.getSelectedPhotosOrder().size();
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            PhotoPickerPhotoCell cell = new PhotoPickerPhotoCell(this.mContext, false);
            cell.checkFrame.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhotoViewer$ListAdapter$iqbxIkiEJAYoYHHHV6sUGHRb_9w
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onCreateViewHolder$0$PhotoViewer$ListAdapter(view);
                }
            });
            return new RecyclerListView.Holder(cell);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$PhotoViewer$ListAdapter(View v) {
            Object photoEntry = ((View) v.getParent()).getTag();
            int idx = PhotoViewer.this.imagesArrLocals.indexOf(photoEntry);
            if (idx >= 0) {
                int num = PhotoViewer.this.placeProvider.setPhotoChecked(idx, PhotoViewer.this.getCurrentVideoEditedInfo());
                PhotoViewer.this.placeProvider.isPhotoChecked(idx);
                if (idx == PhotoViewer.this.currentIndex) {
                    PhotoViewer.this.checkImageView.setChecked(-1, false, true);
                }
                if (num >= 0) {
                    PhotoViewer.this.selectedPhotosAdapter.notifyItemRemoved(num);
                }
                PhotoViewer.this.updateSelectedCount();
                return;
            }
            int num2 = PhotoViewer.this.placeProvider.setPhotoUnchecked(photoEntry);
            if (num2 >= 0) {
                PhotoViewer.this.selectedPhotosAdapter.notifyItemRemoved(num2);
                PhotoViewer.this.updateSelectedCount();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            PhotoPickerPhotoCell cell = (PhotoPickerPhotoCell) holder.itemView;
            cell.itemWidth = AndroidUtilities.dp(82.0f);
            BackupImageView imageView = cell.imageView;
            imageView.setOrientation(0, true);
            ArrayList<Object> order = PhotoViewer.this.placeProvider.getSelectedPhotosOrder();
            Object object = PhotoViewer.this.placeProvider.getSelectedPhotos().get(order.get(position));
            if (object instanceof MediaController.PhotoEntry) {
                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                cell.setTag(photoEntry);
                cell.videoInfoContainer.setVisibility(4);
                if (photoEntry.thumbPath != null) {
                    imageView.setImage(photoEntry.thumbPath, null, this.mContext.getResources().getDrawable(R.drawable.nophotos));
                } else if (photoEntry.path != null) {
                    imageView.setOrientation(photoEntry.orientation, true);
                    if (photoEntry.isVideo) {
                        cell.videoInfoContainer.setVisibility(0);
                        int minutes = photoEntry.duration / 60;
                        int seconds = photoEntry.duration - (minutes * 60);
                        cell.videoTextView.setText(String.format("%d:%02d", Integer.valueOf(minutes), Integer.valueOf(seconds)));
                        imageView.setImage("vthumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path, null, this.mContext.getResources().getDrawable(R.drawable.nophotos));
                    } else {
                        imageView.setImage("thumb://" + photoEntry.imageId + LogUtils.COLON + photoEntry.path, null, this.mContext.getResources().getDrawable(R.drawable.nophotos));
                    }
                } else {
                    imageView.setImageResource(R.drawable.nophotos);
                }
                cell.setChecked(-1, true, false);
                cell.checkBox.setVisibility(0);
                return;
            }
            if (object instanceof MediaController.SearchImage) {
                MediaController.SearchImage photoEntry2 = (MediaController.SearchImage) object;
                cell.setTag(photoEntry2);
                cell.setImage(photoEntry2);
                cell.videoInfoContainer.setVisibility(4);
                cell.setChecked(-1, true, false);
                cell.checkBox.setVisibility(0);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            return 0;
        }
    }
}
