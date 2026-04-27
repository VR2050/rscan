package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

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
import android.graphics.Color;
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
import android.util.Property;
import android.util.SparseArray;
import android.view.ActionMode;
import android.view.ContextThemeWrapper;
import android.view.GestureDetector;
import android.view.KeyEvent;
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
import androidx.appcompat.widget.AppCompatTextView;
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
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.Bitmaps;
import im.uwrkaxlmjj.messenger.BringAppForegroundService;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
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
import im.uwrkaxlmjj.messenger.utils.SelectorUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.MediaActivity;
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
import im.uwrkaxlmjj.ui.components.URLSpanUserMentionPhotoViewer;
import im.uwrkaxlmjj.ui.components.VideoForwardDrawable;
import im.uwrkaxlmjj.ui.components.VideoPlayer;
import im.uwrkaxlmjj.ui.components.VideoSeekPreviewImage;
import im.uwrkaxlmjj.ui.components.VideoTimelinePlayView;
import im.uwrkaxlmjj.ui.components.paint.views.ColorPicker;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Array;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ImagePreviewActivity extends PhotoViewer implements NotificationCenter.NotificationCenterDelegate, GestureDetector.OnGestureListener, GestureDetector.OnDoubleTapListener {
    private static volatile ImagePreviewActivity Instance = null;
    private static volatile ImagePreviewActivity PipInstance = null;
    public static final int SELECT_TYPE_AVATAR = 1;
    public static final int SELECT_TYPE_GIF = 3;
    public static final int SELECT_TYPE_IMG = 1;
    public static final int SELECT_TYPE_NONE = 0;
    public static final int SELECT_TYPE_VIDEO = 2;
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
    private boolean isFirstLoading;
    private boolean isInline;
    private boolean isPhotosListViewVisible;
    private boolean isPlaying;
    private boolean isStreaming;
    private boolean isVisible;
    private LinearLayout itemsLayout;
    private boolean keepScreenOnFlagSet;
    private long lastBufferedPositionCheck;
    private Object lastInsets;
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
    private String mstrPath;
    private TextView mtvCancel;
    private TextView mtvFinish;
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
    private PlaceProviderObject showAfterAnimation;
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
    private Runnable miniProgressShowRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$DakTS7f24w0MynLbpWm7pwoKkXE
        @Override // java.lang.Runnable
        public final void run() {
            this.f$0.lambda$new$0$ImagePreviewActivity();
        }
    };
    private boolean isActionBarVisible = true;
    private BackgroundDrawable backgroundDrawable = new BackgroundDrawable(-16777216);
    private Paint blackPaint = new Paint();
    private PhotoProgressView[] photoProgressViews = new PhotoProgressView[3];
    private boolean mblnIsHiddenActionBar = false;
    private Runnable setLoadingRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.1
        @Override // java.lang.Runnable
        public void run() {
            if (ImagePreviewActivity.this.currentMessageObject != null) {
                FileLoader.getInstance(ImagePreviewActivity.this.currentMessageObject.currentAccount).setLoadingVideo(ImagePreviewActivity.this.currentMessageObject.getDocument(), true, false);
            }
        }
    };
    private int[] pipPosition = new int[2];
    private boolean mblnSelectPreview = true;
    private boolean selectSameMediaType = false;
    private int selectedMediaType = 0;
    private Runnable updateProgressRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.2
        @Override // java.lang.Runnable
        public void run() {
            float bufferedProgress;
            float bufferedProgress2;
            if (ImagePreviewActivity.this.videoPlayer != null) {
                if (ImagePreviewActivity.this.isCurrentVideo) {
                    if (!ImagePreviewActivity.this.videoTimelineView.isDragging()) {
                        float progress = ImagePreviewActivity.this.videoPlayer.getCurrentPosition() / ImagePreviewActivity.this.videoPlayer.getDuration();
                        if (ImagePreviewActivity.this.inPreview || ImagePreviewActivity.this.videoTimelineView.getVisibility() != 0) {
                            ImagePreviewActivity.this.videoTimelineView.setProgress(progress);
                        } else if (progress >= ImagePreviewActivity.this.videoTimelineView.getRightProgress()) {
                            ImagePreviewActivity.this.videoTimelineView.setProgress(0.0f);
                            ImagePreviewActivity.this.videoPlayer.seekTo((int) (ImagePreviewActivity.this.videoTimelineView.getLeftProgress() * ImagePreviewActivity.this.videoPlayer.getDuration()));
                            if (ImagePreviewActivity.this.muteVideo) {
                                ImagePreviewActivity.this.videoPlayer.play();
                            } else {
                                ImagePreviewActivity.this.videoPlayer.pause();
                            }
                            ImagePreviewActivity.this.containerView.invalidate();
                        } else {
                            float progress2 = progress - ImagePreviewActivity.this.videoTimelineView.getLeftProgress();
                            if (progress2 < 0.0f) {
                                progress2 = 0.0f;
                            }
                            float progress3 = progress2 / (ImagePreviewActivity.this.videoTimelineView.getRightProgress() - ImagePreviewActivity.this.videoTimelineView.getLeftProgress());
                            if (progress3 > 1.0f) {
                                progress3 = 1.0f;
                            }
                            ImagePreviewActivity.this.videoTimelineView.setProgress(progress3);
                        }
                        ImagePreviewActivity.this.updateVideoPlayerTime();
                    }
                } else {
                    float progress4 = ImagePreviewActivity.this.videoPlayer.getCurrentPosition() / ImagePreviewActivity.this.videoPlayer.getDuration();
                    if (ImagePreviewActivity.this.currentVideoFinishedLoading) {
                        bufferedProgress = 1.0f;
                    } else {
                        long newTime = SystemClock.elapsedRealtime();
                        if (Math.abs(newTime - ImagePreviewActivity.this.lastBufferedPositionCheck) >= 500) {
                            if (ImagePreviewActivity.this.isStreaming) {
                                bufferedProgress2 = FileLoader.getInstance(ImagePreviewActivity.this.currentAccount).getBufferedProgressFromPosition(ImagePreviewActivity.this.seekToProgressPending != 0.0f ? ImagePreviewActivity.this.seekToProgressPending : progress4, ImagePreviewActivity.this.currentFileNames[0]);
                            } else {
                                bufferedProgress2 = 1.0f;
                            }
                            ImagePreviewActivity.this.lastBufferedPositionCheck = newTime;
                            bufferedProgress = bufferedProgress2;
                        } else {
                            bufferedProgress = -1.0f;
                        }
                    }
                    if (ImagePreviewActivity.this.inPreview || ImagePreviewActivity.this.videoTimelineView.getVisibility() != 0) {
                        if (ImagePreviewActivity.this.seekToProgressPending == 0.0f) {
                            ImagePreviewActivity.this.videoPlayerSeekbar.setProgress(progress4);
                        }
                        if (bufferedProgress != -1.0f) {
                            ImagePreviewActivity.this.videoPlayerSeekbar.setBufferedProgress(bufferedProgress);
                            if (ImagePreviewActivity.this.pipVideoView != null) {
                                ImagePreviewActivity.this.pipVideoView.setBufferedProgress(bufferedProgress);
                            }
                        }
                    } else if (progress4 >= ImagePreviewActivity.this.videoTimelineView.getRightProgress()) {
                        ImagePreviewActivity.this.videoPlayer.pause();
                        ImagePreviewActivity.this.videoPlayerSeekbar.setProgress(0.0f);
                        ImagePreviewActivity.this.videoPlayer.seekTo((int) (ImagePreviewActivity.this.videoTimelineView.getLeftProgress() * ImagePreviewActivity.this.videoPlayer.getDuration()));
                        ImagePreviewActivity.this.containerView.invalidate();
                    } else {
                        float progress5 = progress4 - ImagePreviewActivity.this.videoTimelineView.getLeftProgress();
                        if (progress5 < 0.0f) {
                            progress5 = 0.0f;
                        }
                        float progress6 = progress5 / (ImagePreviewActivity.this.videoTimelineView.getRightProgress() - ImagePreviewActivity.this.videoTimelineView.getLeftProgress());
                        if (progress6 > 1.0f) {
                            progress6 = 1.0f;
                        }
                        ImagePreviewActivity.this.videoPlayerSeekbar.setProgress(progress6);
                    }
                    ImagePreviewActivity.this.videoPlayerControlFrameLayout.invalidate();
                    ImagePreviewActivity.this.updateVideoPlayerTime();
                }
            }
            if (ImagePreviewActivity.this.isPlaying) {
                AndroidUtilities.runOnUIThread(ImagePreviewActivity.this.updateProgressRunnable, 17L);
            }
        }
    };
    private Runnable switchToInlineRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.3
        @Override // java.lang.Runnable
        public void run() {
            ImagePreviewActivity.this.switchingInlineMode = false;
            if (ImagePreviewActivity.this.currentBitmap != null) {
                ImagePreviewActivity.this.currentBitmap.recycle();
                ImagePreviewActivity.this.currentBitmap = null;
            }
            ImagePreviewActivity.this.changingTextureView = true;
            if (ImagePreviewActivity.this.textureImageView != null) {
                try {
                    ImagePreviewActivity.this.currentBitmap = Bitmaps.createBitmap(ImagePreviewActivity.this.videoTextureView.getWidth(), ImagePreviewActivity.this.videoTextureView.getHeight(), Bitmap.Config.ARGB_8888);
                    ImagePreviewActivity.this.videoTextureView.getBitmap(ImagePreviewActivity.this.currentBitmap);
                } catch (Throwable e) {
                    if (ImagePreviewActivity.this.currentBitmap != null) {
                        ImagePreviewActivity.this.currentBitmap.recycle();
                        ImagePreviewActivity.this.currentBitmap = null;
                    }
                    FileLog.e(e);
                }
                if (ImagePreviewActivity.this.currentBitmap != null) {
                    ImagePreviewActivity.this.textureImageView.setVisibility(0);
                    ImagePreviewActivity.this.textureImageView.setImageBitmap(ImagePreviewActivity.this.currentBitmap);
                } else {
                    ImagePreviewActivity.this.textureImageView.setImageDrawable(null);
                }
            }
            ImagePreviewActivity.this.isInline = true;
            ImagePreviewActivity.this.pipVideoView = new PipVideoView();
            ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
            PipVideoView pipVideoView = imagePreviewActivity.pipVideoView;
            Activity activity = ImagePreviewActivity.this.parentActivity;
            ImagePreviewActivity imagePreviewActivity2 = ImagePreviewActivity.this;
            imagePreviewActivity.changedTextureView = pipVideoView.show(activity, imagePreviewActivity2, imagePreviewActivity2.aspectRatioFrameLayout.getAspectRatio(), ImagePreviewActivity.this.aspectRatioFrameLayout.getVideoRotation());
            ImagePreviewActivity.this.changedTextureView.setVisibility(4);
            ImagePreviewActivity.this.aspectRatioFrameLayout.removeView(ImagePreviewActivity.this.videoTextureView);
        }
    };
    private TextureView.SurfaceTextureListener surfaceTextureListener = new TextureView.SurfaceTextureListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.4
        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureAvailable(SurfaceTexture surface, int width, int height) {
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureSizeChanged(SurfaceTexture surface, int width, int height) {
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public boolean onSurfaceTextureDestroyed(SurfaceTexture surface) {
            if (ImagePreviewActivity.this.videoTextureView == null || !ImagePreviewActivity.this.changingTextureView) {
                return true;
            }
            if (ImagePreviewActivity.this.switchingInlineMode) {
                ImagePreviewActivity.this.waitingForFirstTextureUpload = 2;
            }
            ImagePreviewActivity.this.videoTextureView.setSurfaceTexture(surface);
            ImagePreviewActivity.this.videoTextureView.setVisibility(0);
            ImagePreviewActivity.this.changingTextureView = false;
            ImagePreviewActivity.this.containerView.invalidate();
            return false;
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$4$1, reason: invalid class name */
        class AnonymousClass1 implements ViewTreeObserver.OnPreDrawListener {
            AnonymousClass1() {
            }

            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                ImagePreviewActivity.this.changedTextureView.getViewTreeObserver().removeOnPreDrawListener(this);
                if (ImagePreviewActivity.this.textureImageView != null) {
                    ImagePreviewActivity.this.textureImageView.setVisibility(4);
                    ImagePreviewActivity.this.textureImageView.setImageDrawable(null);
                    if (ImagePreviewActivity.this.currentBitmap != null) {
                        ImagePreviewActivity.this.currentBitmap.recycle();
                        ImagePreviewActivity.this.currentBitmap = null;
                    }
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$4$1$OkLqZVkDnnpwvvaKcTCPqwDEGYc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onPreDraw$0$ImagePreviewActivity$4$1();
                    }
                });
                ImagePreviewActivity.this.waitingForFirstTextureUpload = 0;
                return true;
            }

            public /* synthetic */ void lambda$onPreDraw$0$ImagePreviewActivity$4$1() {
                if (ImagePreviewActivity.this.isInline) {
                    ImagePreviewActivity.this.dismissInternal();
                }
            }
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureUpdated(SurfaceTexture surface) {
            if (ImagePreviewActivity.this.waitingForFirstTextureUpload == 1) {
                ImagePreviewActivity.this.changedTextureView.getViewTreeObserver().addOnPreDrawListener(new AnonymousClass1());
                ImagePreviewActivity.this.changedTextureView.invalidate();
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
    private AlertDialog progressDialog = null;
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

    public /* synthetic */ void lambda$new$0$ImagePreviewActivity() {
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
                        if (url.startsWith("video") && ImagePreviewActivity.this.videoPlayer != null && ImagePreviewActivity.this.currentMessageObject != null) {
                            int seconds = Utilities.parseInt(url).intValue();
                            if (ImagePreviewActivity.this.videoPlayer.getDuration() != C.TIME_UNSET) {
                                ImagePreviewActivity.this.videoPlayer.seekTo(((long) seconds) * 1000);
                            } else {
                                ImagePreviewActivity.this.seekToProgressPending = seconds / ImagePreviewActivity.this.currentMessageObject.getDuration();
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

    /* JADX INFO: Access modifiers changed from: private */
    class BackgroundDrawable extends ColorDrawable {
        private boolean allowDrawContent;
        private Runnable drawRunnable;

        public BackgroundDrawable(int color) {
            super(color);
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
            if (ImagePreviewActivity.this.parentActivity instanceof LaunchActivity) {
                this.allowDrawContent = (ImagePreviewActivity.this.isVisible && alpha == 255) ? false : true;
                if (ImagePreviewActivity.this.parentAlert != null) {
                    if (this.allowDrawContent) {
                        if (ImagePreviewActivity.this.parentAlert != null) {
                            ImagePreviewActivity.this.parentAlert.setAllowDrawContent(this.allowDrawContent);
                        }
                    } else {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$BackgroundDrawable$l19-Sfb_9F3rJTlkdq-hMXZK10Y
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$setAlpha$0$ImagePreviewActivity$BackgroundDrawable();
                            }
                        }, 50L);
                    }
                }
            }
            super.setAlpha(alpha);
        }

        public /* synthetic */ void lambda$setAlpha$0$ImagePreviewActivity$BackgroundDrawable() {
            if (ImagePreviewActivity.this.parentAlert != null) {
                ImagePreviewActivity.this.parentAlert.setAllowDrawContent(this.allowDrawContent);
            }
        }

        @Override // android.graphics.drawable.ColorDrawable, android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            Runnable runnable;
            super.draw(canvas);
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
            if (ImagePreviewActivity.decelerateInterpolator == null) {
                DecelerateInterpolator unused = ImagePreviewActivity.decelerateInterpolator = new DecelerateInterpolator(1.5f);
                Paint unused2 = ImagePreviewActivity.progressPaint = new Paint(1);
                ImagePreviewActivity.progressPaint.setStyle(Paint.Style.STROKE);
                ImagePreviewActivity.progressPaint.setStrokeCap(Paint.Cap.ROUND);
                ImagePreviewActivity.progressPaint.setStrokeWidth(AndroidUtilities.dp(3.0f));
                ImagePreviewActivity.progressPaint.setColor(-1);
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
            if (this.animatedProgressValue != 1.0f) {
                this.radOffset += (360 * dt) / 3000.0f;
                float f = this.currentProgress;
                float f2 = this.animationProgressStart;
                float progressDiff = f - f2;
                if (progressDiff > 0.0f) {
                    long j = this.currentProgressTime + dt;
                    this.currentProgressTime = j;
                    if (j < 300) {
                        this.animatedProgressValue = f2 + (ImagePreviewActivity.decelerateInterpolator.getInterpolation(this.currentProgressTime / 300.0f) * progressDiff);
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
            if (this.backgroundState == state && animated) {
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
            int x = (ImagePreviewActivity.this.getContainerViewWidth() - sizeScaled) / 2;
            int y = (ImagePreviewActivity.this.getContainerViewHeight() - sizeScaled) / 2;
            int i2 = this.previousBackgroundState;
            if (i2 >= 0 && i2 < 4 && (drawable2 = ImagePreviewActivity.progressDrawables[this.previousBackgroundState]) != null) {
                drawable2.setAlpha((int) (this.animatedAlphaValue * 255.0f * this.alpha));
                drawable2.setBounds(x, y, x + sizeScaled, y + sizeScaled);
                drawable2.draw(canvas);
            }
            int i3 = this.backgroundState;
            if (i3 >= 0 && i3 < 4 && (drawable = ImagePreviewActivity.progressDrawables[this.backgroundState]) != null) {
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
                    ImagePreviewActivity.progressPaint.setAlpha((int) (this.animatedAlphaValue * 255.0f * this.alpha));
                } else {
                    ImagePreviewActivity.progressPaint.setAlpha((int) (this.alpha * 255.0f));
                }
                this.progressRect.set(x + diff, y + diff, (x + sizeScaled) - diff, (y + sizeScaled) - diff);
                canvas.drawArc(this.progressRect, (-90.0f) + this.radOffset, Math.max(4.0f, this.animatedProgressValue * 360.0f), false, ImagePreviewActivity.progressPaint);
                updateAnimation();
            }
        }
    }

    public static class EmptyPhotoViewerProvider implements PhotoViewerProvider {
        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void willSwitchFromPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void willHidePhotoViewer() {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int setPhotoUnchecked(Object photoEntry) {
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean isPhotoChecked(int index) {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int setPhotoChecked(int index, VideoEditedInfo videoEditedInfo) {
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean cancelButtonPressed() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int getSelectedCount() {
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void updatePhotoAtIndex(int index) {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean allowCaption() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean scaleToFill() {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public ArrayList<Object> getSelectedPhotosOrder() {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public HashMap<Object, Object> getSelectedPhotos() {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public boolean canScrollAway() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void needAddMorePhotos() {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public int getPhotoIndex(int index) {
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public void deleteImageAtIndex(int index) {
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
        public String getDeleteMessageString() {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PhotoViewerProvider
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
            ImagePreviewActivity.this.captionTextView.setMaxLines(AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? 5 : 10);
            this.ignoreLayout = false;
            measureChildWithMargins(ImagePreviewActivity.this.captionEditText, widthMeasureSpec, 0, heightMeasureSpec, 0);
            int inputFieldHeight = ImagePreviewActivity.this.captionEditText.getMeasuredHeight();
            int widthSize2 = widthSize - (getPaddingRight() + getPaddingLeft());
            int heightSize2 = heightSize - getPaddingBottom();
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8 && child != ImagePreviewActivity.this.captionEditText) {
                    if (child != ImagePreviewActivity.this.aspectRatioFrameLayout) {
                        if (ImagePreviewActivity.this.captionEditText.isPopupView(child)) {
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
            int paddingBottom2 = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : ImagePreviewActivity.this.captionEditText.getEmojiPadding();
            int i = 0;
            while (i < count2) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8) {
                    if (child == ImagePreviewActivity.this.aspectRatioFrameLayout) {
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
                    } else if (verticalGravity != 48 && verticalGravity == 80) {
                        int childTop3 = b - paddingBottom2;
                        childTop = ((childTop3 - t) - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (child == ImagePreviewActivity.this.mentionListView) {
                        childTop -= ImagePreviewActivity.this.captionEditText.getMeasuredHeight();
                        paddingBottom = paddingBottom2;
                    } else if (!ImagePreviewActivity.this.captionEditText.isPopupView(child)) {
                        if (child == ImagePreviewActivity.this.selectedPhotosListView) {
                            childTop = ImagePreviewActivity.this.actionBar.getMeasuredHeight();
                            paddingBottom = paddingBottom2;
                        } else if (child == ImagePreviewActivity.this.captionTextView || child == ImagePreviewActivity.this.switchCaptionTextView) {
                            paddingBottom = paddingBottom2;
                            if (!ImagePreviewActivity.this.groupedPhotosListView.currentPhotos.isEmpty()) {
                                childTop -= ImagePreviewActivity.this.groupedPhotosListView.getMeasuredHeight();
                            }
                        } else if (child == ImagePreviewActivity.this.cameraItem) {
                            paddingBottom = paddingBottom2;
                            childTop = (ImagePreviewActivity.this.pickerView.getTop() - AndroidUtilities.dp((ImagePreviewActivity.this.sendPhotoType == 4 || ImagePreviewActivity.this.sendPhotoType == 5) ? 40.0f : 15.0f)) - ImagePreviewActivity.this.cameraItem.getMeasuredHeight();
                        } else {
                            paddingBottom = paddingBottom2;
                            if (child == ImagePreviewActivity.this.videoPreviewFrame) {
                                if (!ImagePreviewActivity.this.groupedPhotosListView.currentPhotos.isEmpty()) {
                                    childTop -= ImagePreviewActivity.this.groupedPhotosListView.getMeasuredHeight();
                                }
                                if (ImagePreviewActivity.this.captionTextView.getVisibility() == 0) {
                                    childTop -= ImagePreviewActivity.this.captionTextView.getMeasuredHeight();
                                }
                            }
                        }
                    } else if (AndroidUtilities.isInMultiwindow) {
                        childTop = (ImagePreviewActivity.this.captionEditText.getTop() - child.getMeasuredHeight()) + AndroidUtilities.dp(1.0f);
                        paddingBottom = paddingBottom2;
                    } else {
                        childTop = ImagePreviewActivity.this.captionEditText.getBottom();
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
            ImagePreviewActivity.this.onDraw(canvas);
            if (Build.VERSION.SDK_INT >= 21 && AndroidUtilities.statusBarHeight != 0 && ImagePreviewActivity.this.actionBar != null) {
                this.paint.setAlpha((int) (ImagePreviewActivity.this.actionBar.getAlpha() * 255.0f * 0.2f));
                canvas.drawRect(0.0f, 0.0f, getMeasuredWidth(), AndroidUtilities.statusBarHeight, this.paint);
                this.paint.setAlpha((int) (ImagePreviewActivity.this.actionBar.getAlpha() * 255.0f * 0.498f));
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
            if (child == ImagePreviewActivity.this.mentionListView || child == ImagePreviewActivity.this.captionEditText) {
                if (!ImagePreviewActivity.this.captionEditText.isPopupShowing() && ImagePreviewActivity.this.captionEditText.getEmojiPadding() == 0 && ((AndroidUtilities.usingHardwareInput && ImagePreviewActivity.this.captionEditText.getTag() == null) || getKeyboardHeight() == 0)) {
                    return false;
                }
            } else if (child != ImagePreviewActivity.this.cameraItem && child != ImagePreviewActivity.this.pickerView && child != ImagePreviewActivity.this.pickerViewSendButton && child != ImagePreviewActivity.this.captionTextView && (ImagePreviewActivity.this.muteItem.getVisibility() != 0 || child != ImagePreviewActivity.this.bottomLayout)) {
                if (child == ImagePreviewActivity.this.checkImageView || child == ImagePreviewActivity.this.photosCounterView) {
                    if (ImagePreviewActivity.this.captionEditText.getTag() != null) {
                        ImagePreviewActivity.this.bottomTouchEnabled = false;
                        return false;
                    }
                    ImagePreviewActivity.this.bottomTouchEnabled = true;
                } else if (child == ImagePreviewActivity.this.miniProgressView) {
                    return false;
                }
            } else {
                int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : ImagePreviewActivity.this.captionEditText.getEmojiPadding();
                if (!ImagePreviewActivity.this.captionEditText.isPopupShowing() && ((!AndroidUtilities.usingHardwareInput || ImagePreviewActivity.this.captionEditText.getTag() == null) && getKeyboardHeight() <= AndroidUtilities.dp(80.0f) && paddingBottom == 0)) {
                    ImagePreviewActivity.this.bottomTouchEnabled = true;
                } else {
                    if (BuildVars.DEBUG_VERSION) {
                        FileLog.d("keyboard height = " + getKeyboardHeight() + " padding = " + paddingBottom);
                    }
                    ImagePreviewActivity.this.bottomTouchEnabled = false;
                    return false;
                }
            }
            try {
                if (child != ImagePreviewActivity.this.aspectRatioFrameLayout) {
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

    public static ImagePreviewActivity getPipInstance() {
        return PipInstance;
    }

    public static ImagePreviewActivity getInstance() {
        ImagePreviewActivity localInstance = Instance;
        if (localInstance == null) {
            synchronized (ImagePreviewActivity.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    ImagePreviewActivity imagePreviewActivity = new ImagePreviewActivity();
                    localInstance = imagePreviewActivity;
                    Instance = imagePreviewActivity;
                }
            }
        }
        return localInstance;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public boolean isOpenedFullScreenVideo() {
        return this.openedFullScreenVideo;
    }

    public static boolean hasInstance() {
        return Instance != null;
    }

    public ImagePreviewActivity() {
        this.blackPaint.setColor(-16777216);
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int loadFromMaxId;
        boolean z;
        ImageLocation location;
        int did;
        float bufferedProgress;
        float progress;
        MessageObject messageObject;
        TLRPC.BotInlineResult botInlineResult;
        int i = 3;
        if (id == NotificationCenter.fileDidFailToLoad) {
            String location2 = (String) args[0];
            for (int a = 0; a < 3; a++) {
                String[] strArr = this.currentFileNames;
                if (strArr[a] != null && strArr[a].equals(location2)) {
                    this.photoProgressViews[a].setProgress(1.0f, true);
                    checkProgress(a, true);
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.fileDidLoad) {
            String location3 = (String) args[0];
            for (int a2 = 0; a2 < 3; a2++) {
                String[] strArr2 = this.currentFileNames;
                if (strArr2[a2] != null && strArr2[a2].equals(location3)) {
                    this.photoProgressViews[a2].setProgress(1.0f, true);
                    checkProgress(a2, true);
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
                    Float loadProgress = (Float) args[1];
                    this.photoProgressViews[a3].setProgress(loadProgress.floatValue(), true);
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
                j = 0;
            }
            return;
        }
        int i2 = -1;
        if (id == NotificationCenter.dialogPhotosLoaded) {
            int guid = ((Integer) args[3]).intValue();
            int did2 = ((Integer) args[0]).intValue();
            if (this.avatarsDialogId == did2 && this.classGuid == guid) {
                boolean fromCache = ((Boolean) args[2]).booleanValue();
                int setToImage = -1;
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
                    if (photo == null || (photo instanceof TLRPC.TL_photoEmpty)) {
                        did = did2;
                    } else if (photo.sizes == null) {
                        did = did2;
                    } else {
                        TLRPC.PhotoSize sizeFull = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 640);
                        if (sizeFull == null) {
                            did = did2;
                        } else {
                            if (setToImage != i2 || this.currentFileLocation == null) {
                                did = did2;
                            } else {
                                int b = 0;
                                while (true) {
                                    if (b >= photo.sizes.size()) {
                                        did = did2;
                                        break;
                                    }
                                    TLRPC.PhotoSize size = photo.sizes.get(b);
                                    if (size.location.local_id == this.currentFileLocation.location.local_id) {
                                        did = did2;
                                        if (size.location.volume_id == this.currentFileLocation.location.volume_id) {
                                            setToImage = this.imagesArrLocations.size();
                                            break;
                                        }
                                    } else {
                                        did = did2;
                                    }
                                    b++;
                                    did2 = did;
                                }
                            }
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
                        }
                    }
                    a4++;
                    did2 = did;
                    i2 = -1;
                }
                if (!this.avatarsArr.isEmpty()) {
                    this.menuItem.showSubItem(6);
                } else {
                    this.menuItem.hideSubItem(6);
                }
                this.needSearchImageInArr = false;
                this.currentIndex = -1;
                if (setToImage != -1) {
                    setImageIndex(setToImage, true);
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
                        this.progressView.setVisibility(4);
                        preparePlayer(Uri.fromFile(new File(finalPath)), false, true);
                    }
                }
                if (messageObject3.messageOwner.attachPath.equals(this.mstrPath)) {
                    long finalSize2 = ((Long) args[3]).longValue();
                    if (finalSize2 != 0) {
                        this.progressDialog.dismiss();
                        messageObject3.videoEditedInfo.originalPath = this.mstrPath;
                        this.placeProvider.sendButtonPressed(this.currentIndex, messageObject3.videoEditedInfo, true, 0);
                        this.doneButtonPressed = true;
                        closePhoto(false, false);
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
                        loadFromMaxId = 0;
                    } else {
                        ArrayList<MessageObject> arrayList = this.imagesArrTemp;
                        loadFromMaxId = arrayList.get(arrayList.size() - 1).getId();
                    }
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void setParentAlert(ChatAttachAlert alert) {
        this.parentAlert = alert;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void setParentActivity(Activity activity) {
        int i = 0;
        this.mblnIsHiddenActionBar = false;
        int i2 = UserConfig.selectedAccount;
        this.currentAccount = i2;
        this.centerImage.setCurrentAccount(i2);
        this.leftImage.setCurrentAccount(this.currentAccount);
        this.rightImage.setCurrentAccount(this.currentAccount);
        if (this.parentActivity == activity || activity == null) {
            return;
        }
        this.parentActivity = activity;
        this.actvityContext = new ContextThemeWrapper(this.parentActivity, 2131755390);
        this.progressDialog = new AlertDialog(this.parentActivity, 3);
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
            this.containerView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$wi8c3qs4MmngePiMMJafRjbwKfs
                @Override // android.view.View.OnApplyWindowInsetsListener
                public final WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                    return this.f$0.lambda$setParentActivity$1$ImagePreviewActivity(view, windowInsets);
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
        ActionBar actionBar = new ActionBar(activity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.6
            @Override // android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                ImagePreviewActivity.this.containerView.invalidate();
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
        this.groupedPhotosListView.setDelegate(new GroupedPhotosListView.GroupedPhotosListViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.8
            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getCurrentIndex() {
                return ImagePreviewActivity.this.currentIndex;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getCurrentAccount() {
                return ImagePreviewActivity.this.currentAccount;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getAvatarsDialogId() {
                return ImagePreviewActivity.this.avatarsDialogId;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public int getSlideshowMessageId() {
                return ImagePreviewActivity.this.slideshowMessageId;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<ImageLocation> getImagesArrLocations() {
                return ImagePreviewActivity.this.imagesArrLocations;
            }

            @Override // im.uwrkaxlmjj.ui.components.GroupedPhotosListView.GroupedPhotosListViewDelegate
            public ArrayList<MessageObject> getImagesArr() {
                return ImagePreviewActivity.this.imagesArr;
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
                ImagePreviewActivity.this.currentIndex = -1;
                if (ImagePreviewActivity.this.currentThumb != null) {
                    ImagePreviewActivity.this.currentThumb.release();
                    ImagePreviewActivity.this.currentThumb = null;
                }
                ImagePreviewActivity.this.setImageIndex(index, true);
            }
        });
        this.captionTextView = createCaptionTextView();
        this.switchCaptionTextView = createCaptionTextView();
        for (int i3 = 0; i3 < 3; i3++) {
            this.photoProgressViews[i3] = new PhotoProgressView(this.containerView.getContext(), this.containerView);
            this.photoProgressViews[i3].setBackgroundState(0, false);
        }
        RadialProgressView radialProgressView = new RadialProgressView(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.9
            @Override // im.uwrkaxlmjj.ui.components.RadialProgressView, android.view.View
            public void setAlpha(float alpha) {
                super.setAlpha(alpha);
                if (ImagePreviewActivity.this.containerView != null) {
                    ImagePreviewActivity.this.containerView.invalidate();
                }
            }

            @Override // android.view.View
            public void invalidate() {
                super.invalidate();
                if (ImagePreviewActivity.this.containerView != null) {
                    ImagePreviewActivity.this.containerView.invalidate();
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
        this.shareButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$e1jxsCD0TpJIjKSNzrpMTBnZdvA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$2$ImagePreviewActivity(view);
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
        this.qualityPicker.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$6BMwbC0ep2S6cAJ_4CUW0Gaeh-c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$3$ImagePreviewActivity(view);
            }
        });
        this.qualityPicker.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$nqPcCI8G2eNOMqMC65R8GDD4duw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$4$ImagePreviewActivity(view);
            }
        });
        VideoForwardDrawable videoForwardDrawable = new VideoForwardDrawable();
        this.videoForwardDrawable = videoForwardDrawable;
        videoForwardDrawable.setDelegate(new VideoForwardDrawable.VideoForwardDrawableDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.10
            @Override // im.uwrkaxlmjj.ui.components.VideoForwardDrawable.VideoForwardDrawableDelegate
            public void onAnimationEnd() {
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoForwardDrawable.VideoForwardDrawableDelegate
            public void invalidate() {
                ImagePreviewActivity.this.containerView.invalidate();
            }
        });
        QualityChooseView qualityChooseView = new QualityChooseView(this.parentActivity);
        this.qualityChooseView = qualityChooseView;
        qualityChooseView.setTranslationY(AndroidUtilities.dp(120.0f));
        this.qualityChooseView.setVisibility(4);
        this.qualityChooseView.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.containerView.addView(this.qualityChooseView, LayoutHelper.createFrame(-1.0f, 70.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
        FrameLayout frameLayout2 = new FrameLayout(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.11
            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                return ImagePreviewActivity.this.bottomTouchEnabled && super.dispatchTouchEvent(ev);
            }

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                return ImagePreviewActivity.this.bottomTouchEnabled && super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return ImagePreviewActivity.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.pickerView = frameLayout2;
        frameLayout2.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.containerView.addView(this.pickerView, LayoutHelper.createFrame(-1, -2, 83));
        VideoTimelinePlayView videoTimelinePlayView = new VideoTimelinePlayView(this.parentActivity);
        this.videoTimelineView = videoTimelinePlayView;
        videoTimelinePlayView.setDelegate(new VideoTimelinePlayView.VideoTimelineViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.12
            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void onLeftProgressChanged(float progress) {
                if (ImagePreviewActivity.this.videoPlayer != null) {
                    if (ImagePreviewActivity.this.videoPlayer.isPlaying()) {
                        ImagePreviewActivity.this.videoPlayer.pause();
                        ImagePreviewActivity.this.containerView.invalidate();
                    }
                    ImagePreviewActivity.this.videoPlayer.seekTo((int) (ImagePreviewActivity.this.videoDuration * progress));
                    ImagePreviewActivity.this.videoPlayerSeekbar.setProgress(0.0f);
                    ImagePreviewActivity.this.videoTimelineView.setProgress(0.0f);
                    ImagePreviewActivity.this.updateVideoInfo();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void onRightProgressChanged(float progress) {
                if (ImagePreviewActivity.this.videoPlayer != null) {
                    if (ImagePreviewActivity.this.videoPlayer.isPlaying()) {
                        ImagePreviewActivity.this.videoPlayer.pause();
                        ImagePreviewActivity.this.containerView.invalidate();
                    }
                    ImagePreviewActivity.this.videoPlayer.seekTo((int) (ImagePreviewActivity.this.videoDuration * progress));
                    ImagePreviewActivity.this.videoPlayerSeekbar.setProgress(0.0f);
                    ImagePreviewActivity.this.videoTimelineView.setProgress(0.0f);
                    ImagePreviewActivity.this.updateVideoInfo();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void onPlayProgressChanged(float progress) {
                if (ImagePreviewActivity.this.videoPlayer != null) {
                    ImagePreviewActivity.this.videoPlayer.seekTo((int) (ImagePreviewActivity.this.videoDuration * progress));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void didStartDragging() {
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelinePlayView.VideoTimelineViewDelegate
            public void didStopDragging() {
            }
        });
        this.pickerView.addView(this.videoTimelineView, LayoutHelper.createFrame(-1.0f, 58.0f, 51, 50.0f, 8.0f, 50.0f, 88.0f));
        ImageView imageView2 = new ImageView(this.parentActivity);
        this.pickerViewSendButton = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER);
        this.pickerViewSendButton.setBackgroundDrawable(Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), -10043398, -10043398));
        this.pickerViewSendButton.setColorFilter(new PorterDuffColorFilter(-1, PorterDuff.Mode.MULTIPLY));
        this.pickerViewSendButton.setImageResource(R.drawable.attach_send);
        this.containerView.addView(this.pickerViewSendButton, LayoutHelper.createFrame(56.0f, 56.0f, 85, 0.0f, 0.0f, 14.0f, 14.0f));
        this.pickerViewSendButton.setContentDescription(LocaleController.getString("Send", R.string.Send));
        this.pickerViewSendButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$ETwY9jAiWpeDy4dMY5JhQQNw74g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$5$ImagePreviewActivity(view);
            }
        });
        TextView textView3 = new TextView(this.parentActivity);
        this.mtvFinish = textView3;
        textView3.setBackground(this.parentActivity.getResources().getDrawable(R.drawable.shape_rect_round_blue));
        this.mtvFinish.setTextColor(-1);
        this.mtvFinish.setGravity(17);
        this.mtvFinish.setTextSize(1, 14.0f);
        this.mtvFinish.setText(LocaleController.getString("Done", R.string.Done));
        this.mtvFinish.setOnClickListener(new AnonymousClass13());
        SelectorUtils.addSelectorFromDrawable(this.parentActivity, R.drawable.shape_rect_round_blue, R.drawable.shape_rect_round_gray, Color.rgb(133, 203, 231), this.mtvFinish);
        this.containerView.addView(this.mtvFinish, LayoutHelper.createFrame(70.0f, 30.0f, 85, 0.0f, 0.0f, 6.0f, 10.0f));
        TextView textView4 = new TextView(this.parentActivity);
        this.mtvCancel = textView4;
        textView4.setText(LocaleController.getString("Cancel", R.string.Cancel));
        this.mtvCancel.setTextSize(1, 14.0f);
        this.mtvCancel.setTextColor(-1);
        this.mtvCancel.setGravity(17);
        this.mtvCancel.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.14
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                ImagePreviewActivity.this.closePhoto(true, false);
            }
        });
        this.containerView.addView(this.mtvCancel, LayoutHelper.createFrame(70.0f, 30.0f, 83, 6.0f, 0.0f, 6.0f, 10.0f));
        LinearLayout linearLayout = new LinearLayout(this.parentActivity);
        this.itemsLayout = linearLayout;
        linearLayout.setOrientation(0);
        this.pickerView.addView(this.itemsLayout, LayoutHelper.createFrame(-2.0f, 48.0f, 81, 0.0f, 0.0f, 0.0f, 0.0f));
        ImageView imageView3 = new ImageView(this.parentActivity);
        this.cropItem = imageView3;
        imageView3.setScaleType(ImageView.ScaleType.CENTER);
        this.cropItem.setImageResource(R.drawable.photo_crop);
        this.cropItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.itemsLayout.addView(this.cropItem, LayoutHelper.createLinear(70, 48));
        this.cropItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$auAgu3UReD510mjbZuPAO7RqiDk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$6$ImagePreviewActivity(view);
            }
        });
        this.cropItem.setContentDescription(LocaleController.getString("CropImage", R.string.CropImage));
        ImageView imageView4 = new ImageView(this.parentActivity);
        this.rotateItem = imageView4;
        imageView4.setScaleType(ImageView.ScaleType.CENTER);
        this.rotateItem.setImageResource(R.drawable.tool_rotate);
        this.rotateItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.itemsLayout.addView(this.rotateItem, LayoutHelper.createLinear(70, 48));
        this.rotateItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$oLLdzsNqHHBPxkMcpIp3GJq-F5w
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$7$ImagePreviewActivity(view);
            }
        });
        this.rotateItem.setContentDescription(LocaleController.getString("AccDescrRotate", R.string.AccDescrRotate));
        ImageView imageView5 = new ImageView(this.parentActivity);
        this.paintItem = imageView5;
        imageView5.setScaleType(ImageView.ScaleType.CENTER);
        this.paintItem.setImageResource(R.drawable.photo_paint);
        this.paintItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.itemsLayout.addView(this.paintItem, LayoutHelper.createLinear(70, 48));
        this.paintItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$_ZoyPYzis23EJt8t9t8boW2pPio
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$8$ImagePreviewActivity(view);
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
        this.itemsLayout.addView(this.compressItem, LayoutHelper.createLinear(70, 48));
        this.compressItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$8ExcNYsW81O0lVXlEdbUaX5J5lU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$9$ImagePreviewActivity(view);
            }
        });
        this.compressItem.setContentDescription(LocaleController.getString("AccDescrVideoQuality", R.string.AccDescrVideoQuality) + ", " + new String[]{"240", "360", "480", "720", "1080"}[Math.max(0, this.selectedCompression)]);
        ImageView imageView7 = new ImageView(this.parentActivity);
        this.muteItem = imageView7;
        imageView7.setScaleType(ImageView.ScaleType.CENTER);
        this.muteItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.itemsLayout.addView(this.muteItem, LayoutHelper.createLinear(70, 48));
        this.muteItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$PEfsF-CX_lkJbNxqyKzN4sDTYc0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$10$ImagePreviewActivity(view);
            }
        });
        ImageView imageView8 = new ImageView(this.parentActivity);
        this.cameraItem = imageView8;
        imageView8.setScaleType(ImageView.ScaleType.CENTER);
        this.cameraItem.setImageResource(R.drawable.photo_add);
        this.cameraItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.cameraItem.setContentDescription(LocaleController.getString("AccDescrTakeMorePics", R.string.AccDescrTakeMorePics));
        this.cameraItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$m3YJWE8BDpoTXkOxU3rz0H9rZXM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$11$ImagePreviewActivity(view);
            }
        });
        ImageView imageView9 = new ImageView(this.parentActivity);
        this.tuneItem = imageView9;
        imageView9.setScaleType(ImageView.ScaleType.CENTER);
        this.tuneItem.setVisibility(8);
        this.tuneItem.setImageResource(R.drawable.photo_tools);
        this.tuneItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.itemsLayout.addView(this.tuneItem, LayoutHelper.createLinear(70, 48));
        this.tuneItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$gRjz7gNl9Gij_GYja5Or9u35UgU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$12$ImagePreviewActivity(view);
            }
        });
        this.tuneItem.setContentDescription(LocaleController.getString("AccDescrPhotoAdjust", R.string.AccDescrPhotoAdjust));
        ImageView imageView10 = new ImageView(this.parentActivity);
        this.timeItem = imageView10;
        imageView10.setScaleType(ImageView.ScaleType.CENTER);
        this.timeItem.setImageResource(R.drawable.photo_timer);
        this.timeItem.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_WHITE_SELECTOR_COLOR));
        this.timeItem.setContentDescription(LocaleController.getString("SetTimer", R.string.SetTimer));
        this.itemsLayout.addView(this.timeItem, LayoutHelper.createLinear(70, 48));
        this.timeItem.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$HiY2XRHGCU4INIPgIltpra_EgJ4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$18$ImagePreviewActivity(view);
            }
        });
        PickerBottomLayoutViewer pickerBottomLayoutViewer2 = new PickerBottomLayoutViewer(this.actvityContext);
        this.editorDoneLayout = pickerBottomLayoutViewer2;
        pickerBottomLayoutViewer2.setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        this.editorDoneLayout.updateSelectedCount(0, false);
        this.editorDoneLayout.setVisibility(8);
        this.containerView.addView(this.editorDoneLayout, LayoutHelper.createFrame(-1, 48, 83));
        this.editorDoneLayout.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$cBbkCCsS9fhQZMQ8ic-WFxfTshM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$19$ImagePreviewActivity(view);
            }
        });
        this.editorDoneLayout.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$f4EevWhzeBpM8t8pzSOSCN3gIkk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$20$ImagePreviewActivity(view);
            }
        });
        TextView textView5 = new TextView(this.actvityContext);
        this.resetButton = textView5;
        textView5.setVisibility(8);
        this.resetButton.setTextSize(1, 14.0f);
        this.resetButton.setTextColor(-1);
        this.resetButton.setGravity(17);
        this.resetButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_PICKER_SELECTOR_COLOR, 0));
        this.resetButton.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.resetButton.setText(LocaleController.getString("Reset", R.string.CropReset).toUpperCase());
        this.resetButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.editorDoneLayout.addView(this.resetButton, LayoutHelper.createFrame(-2, -1, 49));
        this.resetButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$koaEjAMOUyvnM7nIsR9PgzOZjwY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$21$ImagePreviewActivity(view);
            }
        });
        this.gestureDetector = new GestureDetector(this.containerView.getContext(), this);
        setDoubleTapEnabled(true);
        ImageReceiver.ImageReceiverDelegate imageReceiverDelegate = new ImageReceiver.ImageReceiverDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$PhzXJXil1d_0c17jHnvlZcvApRc
            @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
            public final void didSetImage(ImageReceiver imageReceiver, boolean z, boolean z2) {
                this.f$0.lambda$setParentActivity$22$ImagePreviewActivity(imageReceiver, z, z2);
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
        CheckBox checkBox = new CheckBox(this.containerView.getContext(), R.drawable.selectphoto_large) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.16
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return ImagePreviewActivity.this.bottomTouchEnabled && super.onTouchEvent(event);
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
        this.checkImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$eny4FWnO92oCeNL4TH3lNbOPWXo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$23$ImagePreviewActivity(view);
            }
        });
        CounterView counterView = new CounterView(this.parentActivity);
        this.photosCounterView = counterView;
        this.containerView.addView(counterView, LayoutHelper.createFrame(40.0f, 40.0f, 53, 0.0f, (rotation == 3 || rotation == 1) ? 58.0f : 68.0f, 66.0f, 0.0f));
        if (Build.VERSION.SDK_INT >= 21) {
            ((FrameLayout.LayoutParams) this.photosCounterView.getLayoutParams()).topMargin += AndroidUtilities.statusBarHeight;
        }
        this.photosCounterView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$HlEYgoBgH4GrtoMb8LQrBV13Z2U
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$setParentActivity$24$ImagePreviewActivity(view);
            }
        });
        RecyclerListView recyclerListView = new RecyclerListView(this.parentActivity);
        this.selectedPhotosListView = recyclerListView;
        recyclerListView.setVisibility(8);
        this.selectedPhotosListView.setAlpha(0.0f);
        this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
        this.selectedPhotosListView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.17
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
        this.selectedPhotosListView.setLayoutManager(new LinearLayoutManager(this.parentActivity, i, null == true ? 1 : 0) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.18
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
        this.selectedPhotosListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$zHl2vwv_YbGfD2SJbfmslaHdEl4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i5) {
                this.f$0.lambda$setParentActivity$25$ImagePreviewActivity(view, i5);
            }
        });
        PhotoViewerCaptionEnterView photoViewerCaptionEnterView = new PhotoViewerCaptionEnterView(this.actvityContext, this.containerView, this.windowView) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.19
            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                try {
                    if (ImagePreviewActivity.this.bottomTouchEnabled) {
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
                    if (ImagePreviewActivity.this.bottomTouchEnabled) {
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
                return !ImagePreviewActivity.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.captionEditText = photoViewerCaptionEnterView;
        photoViewerCaptionEnterView.setDelegate(new PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.20
            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate
            public void onCaptionEnter() {
                ImagePreviewActivity.this.closeCaptionEnter(true);
            }

            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate
            public void onTextChanged(CharSequence text) {
                if (ImagePreviewActivity.this.mentionsAdapter != null && ImagePreviewActivity.this.captionEditText != null) {
                    ChatActivity unused = ImagePreviewActivity.this.parentChatActivity;
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.PhotoViewerCaptionEnterViewDelegate
            public void onWindowSizeChanged(int size) {
                int height = AndroidUtilities.dp((Math.min(3, ImagePreviewActivity.this.mentionsAdapter.getItemCount()) * 36) + (ImagePreviewActivity.this.mentionsAdapter.getItemCount() > 3 ? 18 : 0));
                if (size - (ActionBar.getCurrentActionBarHeight() * 2) < height) {
                    ImagePreviewActivity.this.allowMentions = false;
                    if (ImagePreviewActivity.this.mentionListView != null && ImagePreviewActivity.this.mentionListView.getVisibility() == 0) {
                        ImagePreviewActivity.this.mentionListView.setVisibility(4);
                        return;
                    }
                    return;
                }
                ImagePreviewActivity.this.allowMentions = true;
                if (ImagePreviewActivity.this.mentionListView != null && ImagePreviewActivity.this.mentionListView.getVisibility() == 4) {
                    ImagePreviewActivity.this.mentionListView.setVisibility(0);
                }
            }
        });
        if (Build.VERSION.SDK_INT >= 19) {
            this.captionEditText.setImportantForAccessibility(4);
        }
        this.containerView.addView(this.captionEditText, LayoutHelper.createFrame(-1, -2, 83));
        RecyclerListView recyclerListView3 = new RecyclerListView(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.21
            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                return !ImagePreviewActivity.this.bottomTouchEnabled && super.dispatchTouchEvent(ev);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                return !ImagePreviewActivity.this.bottomTouchEnabled && super.onInterceptTouchEvent(ev);
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return !ImagePreviewActivity.this.bottomTouchEnabled && super.onTouchEvent(event);
            }
        };
        this.mentionListView = recyclerListView3;
        recyclerListView3.setTag(5);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.22
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
        MentionsAdapter mentionsAdapter = new MentionsAdapter(this.actvityContext, true, 0L, new MentionsAdapter.MentionsAdapterDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.23
            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void needChangePanelVisibility(boolean show) {
                if (show) {
                    FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) ImagePreviewActivity.this.mentionListView.getLayoutParams();
                    int height = (Math.min(3, ImagePreviewActivity.this.mentionsAdapter.getItemCount()) * 36) + (ImagePreviewActivity.this.mentionsAdapter.getItemCount() > 3 ? 18 : 0);
                    layoutParams3.height = AndroidUtilities.dp(height);
                    layoutParams3.topMargin = -AndroidUtilities.dp(height);
                    ImagePreviewActivity.this.mentionListView.setLayoutParams(layoutParams3);
                    if (ImagePreviewActivity.this.mentionListAnimation != null) {
                        ImagePreviewActivity.this.mentionListAnimation.cancel();
                        ImagePreviewActivity.this.mentionListAnimation = null;
                    }
                    if (ImagePreviewActivity.this.mentionListView.getVisibility() == 0) {
                        ImagePreviewActivity.this.mentionListView.setAlpha(1.0f);
                        return;
                    }
                    ImagePreviewActivity.this.mentionLayoutManager.scrollToPositionWithOffset(0, 10000);
                    if (ImagePreviewActivity.this.allowMentions) {
                        ImagePreviewActivity.this.mentionListView.setVisibility(0);
                        ImagePreviewActivity.this.mentionListAnimation = new AnimatorSet();
                        ImagePreviewActivity.this.mentionListAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this.mentionListView, (Property<RecyclerListView, Float>) View.ALPHA, 0.0f, 1.0f));
                        ImagePreviewActivity.this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.23.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (ImagePreviewActivity.this.mentionListAnimation != null && ImagePreviewActivity.this.mentionListAnimation.equals(animation)) {
                                    ImagePreviewActivity.this.mentionListAnimation = null;
                                }
                            }
                        });
                        ImagePreviewActivity.this.mentionListAnimation.setDuration(200L);
                        ImagePreviewActivity.this.mentionListAnimation.start();
                        return;
                    }
                    ImagePreviewActivity.this.mentionListView.setAlpha(1.0f);
                    ImagePreviewActivity.this.mentionListView.setVisibility(4);
                    return;
                }
                if (ImagePreviewActivity.this.mentionListAnimation != null) {
                    ImagePreviewActivity.this.mentionListAnimation.cancel();
                    ImagePreviewActivity.this.mentionListAnimation = null;
                }
                if (ImagePreviewActivity.this.mentionListView.getVisibility() != 8) {
                    if (ImagePreviewActivity.this.allowMentions) {
                        ImagePreviewActivity.this.mentionListAnimation = new AnimatorSet();
                        ImagePreviewActivity.this.mentionListAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this.mentionListView, (Property<RecyclerListView, Float>) View.ALPHA, 0.0f));
                        ImagePreviewActivity.this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.23.2
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (ImagePreviewActivity.this.mentionListAnimation != null && ImagePreviewActivity.this.mentionListAnimation.equals(animation)) {
                                    ImagePreviewActivity.this.mentionListView.setVisibility(8);
                                    ImagePreviewActivity.this.mentionListAnimation = null;
                                }
                            }
                        });
                        ImagePreviewActivity.this.mentionListAnimation.setDuration(200L);
                        ImagePreviewActivity.this.mentionListAnimation.start();
                        return;
                    }
                    ImagePreviewActivity.this.mentionListView.setVisibility(8);
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
        this.mentionListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$b4o9ib0hSvwhsD1A5bQ8tnDtzDI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i5) {
                this.f$0.lambda$setParentActivity$26$ImagePreviewActivity(view, i5);
            }
        });
        this.mentionListView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$5993E43Yhwh9Zg8xsdXk_lfNIqg
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i5) {
                return this.f$0.lambda$setParentActivity$28$ImagePreviewActivity(view, i5);
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

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$5, reason: invalid class name */
    class AnonymousClass5 extends FrameLayout {
        private Runnable attachRunnable;

        AnonymousClass5(Context arg0) {
            super(arg0);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent ev) {
            return ImagePreviewActivity.this.isVisible && super.onInterceptTouchEvent(ev);
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            return ImagePreviewActivity.this.isVisible && ImagePreviewActivity.this.onTouchEvent(event);
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            boolean result;
            try {
                result = super.drawChild(canvas, child, drawingTime);
            } catch (Throwable th) {
                result = false;
            }
            if (Build.VERSION.SDK_INT >= 21 && child == ImagePreviewActivity.this.animatingImageView && ImagePreviewActivity.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) ImagePreviewActivity.this.lastInsets;
                canvas.drawRect(0.0f, getMeasuredHeight(), getMeasuredWidth(), getMeasuredHeight() + insets.getSystemWindowInsetBottom(), ImagePreviewActivity.this.blackPaint);
            }
            return result;
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
            if (Build.VERSION.SDK_INT >= 21 && ImagePreviewActivity.this.lastInsets != null) {
                WindowInsets insets = (WindowInsets) ImagePreviewActivity.this.lastInsets;
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
            ViewGroup.LayoutParams layoutParams = ImagePreviewActivity.this.animatingImageView.getLayoutParams();
            ImagePreviewActivity.this.animatingImageView.measure(View.MeasureSpec.makeMeasureSpec(layoutParams.width, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(layoutParams.height, Integer.MIN_VALUE));
            ImagePreviewActivity.this.containerView.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            if (Build.VERSION.SDK_INT >= 21) {
                Object unused = ImagePreviewActivity.this.lastInsets;
            }
            ImagePreviewActivity.this.animatingImageView.layout(0, 0, ImagePreviewActivity.this.animatingImageView.getMeasuredWidth() + 0, ImagePreviewActivity.this.animatingImageView.getMeasuredHeight());
            ImagePreviewActivity.this.containerView.layout(0, 0, ImagePreviewActivity.this.containerView.getMeasuredWidth() + 0, ImagePreviewActivity.this.containerView.getMeasuredHeight());
            ImagePreviewActivity.this.wasLayout = true;
            if (changed) {
                if (!ImagePreviewActivity.this.dontResetZoomOnFirstLayout) {
                    ImagePreviewActivity.this.scale = 1.0f;
                    ImagePreviewActivity.this.translationX = 0.0f;
                    ImagePreviewActivity.this.translationY = 0.0f;
                    ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
                    imagePreviewActivity.updateMinMax(imagePreviewActivity.scale);
                }
                if (ImagePreviewActivity.this.checkImageView != null) {
                    ImagePreviewActivity.this.checkImageView.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$5$uXNLiTWIjXDb4-TeGZ821gdBdlo
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onLayout$0$ImagePreviewActivity$5();
                        }
                    });
                }
            }
            if (ImagePreviewActivity.this.dontResetZoomOnFirstLayout) {
                ImagePreviewActivity.this.setScaleToFill();
                ImagePreviewActivity.this.dontResetZoomOnFirstLayout = false;
            }
        }

        public /* synthetic */ void lambda$onLayout$0$ImagePreviewActivity$5() {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ImagePreviewActivity.this.checkImageView.getLayoutParams();
            WindowManager manager = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
            manager.getDefaultDisplay().getRotation();
            layoutParams.topMargin = ((ActionBar.getCurrentActionBarHeight() - AndroidUtilities.dp(40.0f)) / 2) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
            ImagePreviewActivity.this.checkImageView.setLayoutParams(layoutParams);
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) ImagePreviewActivity.this.photosCounterView.getLayoutParams();
            layoutParams2.topMargin = ((ActionBar.getCurrentActionBarHeight() - AndroidUtilities.dp(40.0f)) / 2) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
            ImagePreviewActivity.this.photosCounterView.setLayoutParams(layoutParams2);
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            ImagePreviewActivity.this.attachedToWindow = true;
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            ImagePreviewActivity.this.attachedToWindow = false;
            ImagePreviewActivity.this.wasLayout = false;
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchKeyEventPreIme(KeyEvent event) {
            if (event != null && event.getKeyCode() == 4 && event.getAction() == 1) {
                if (ImagePreviewActivity.this.captionEditText.isPopupShowing() || ImagePreviewActivity.this.captionEditText.isKeyboardVisible()) {
                    ImagePreviewActivity.this.closeCaptionEnter(false);
                    return false;
                }
                ImagePreviewActivity.getInstance().closePhoto(true, false);
                return true;
            }
            return super.dispatchKeyEventPreIme(event);
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public ActionMode startActionModeForChild(View originalView, ActionMode.Callback callback, int type) {
            if (Build.VERSION.SDK_INT >= 23) {
                View view = ImagePreviewActivity.this.parentActivity.findViewById(android.R.id.content);
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

    public /* synthetic */ WindowInsets lambda$setParentActivity$1$ImagePreviewActivity(View v, WindowInsets insets) {
        WindowInsets oldInsets = (WindowInsets) this.lastInsets;
        this.lastInsets = insets;
        if (oldInsets == null || !oldInsets.toString().equals(insets.toString())) {
            if (this.animationInProgress == 1) {
                ClippingImageView clippingImageView = this.animatingImageView;
                clippingImageView.setTranslationX(clippingImageView.getTranslationX() - getLeftInset());
                this.animationValues[0][2] = this.animatingImageView.getTranslationX();
            }
            this.windowView.requestLayout();
        }
        this.containerView.setPadding(insets.getSystemWindowInsetLeft(), 0, insets.getSystemWindowInsetRight(), 0);
        return insets.consumeSystemWindowInsets();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$7, reason: invalid class name */
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
                if (ImagePreviewActivity.this.needCaptionLayout && (ImagePreviewActivity.this.captionEditText.isPopupShowing() || ImagePreviewActivity.this.captionEditText.isKeyboardVisible())) {
                    ImagePreviewActivity.this.closeCaptionEnter(false);
                    return;
                } else {
                    ImagePreviewActivity.this.closePhoto(true, false);
                    return;
                }
            }
            if (id == 1) {
                if (Build.VERSION.SDK_INT >= 23 && ImagePreviewActivity.this.parentActivity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
                    ImagePreviewActivity.this.parentActivity.requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 4);
                    return;
                }
                File f = null;
                if (ImagePreviewActivity.this.currentMessageObject != null) {
                    if (!(ImagePreviewActivity.this.currentMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) || ImagePreviewActivity.this.currentMessageObject.messageOwner.media.webpage == null || ImagePreviewActivity.this.currentMessageObject.messageOwner.media.webpage.document != null) {
                        f = FileLoader.getPathToMessage(ImagePreviewActivity.this.currentMessageObject.messageOwner);
                    } else {
                        ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
                        TLObject fileLocation = imagePreviewActivity.getFileLocation(imagePreviewActivity.currentIndex, null);
                        f = FileLoader.getPathToAttach(fileLocation, true);
                    }
                } else if (ImagePreviewActivity.this.currentFileLocation != null) {
                    f = FileLoader.getPathToAttach(ImagePreviewActivity.this.currentFileLocation.location, ImagePreviewActivity.this.avatarsDialogId != 0 || ImagePreviewActivity.this.isEvent);
                }
                if (f == null || !f.exists()) {
                    ImagePreviewActivity.this.showDownloadAlert();
                    return;
                } else {
                    MediaController.saveFile(f.toString(), ImagePreviewActivity.this.parentActivity, (ImagePreviewActivity.this.currentMessageObject == null || !ImagePreviewActivity.this.currentMessageObject.isVideo()) ? 0 : 1, null, null);
                    return;
                }
            }
            if (id == 2) {
                if (ImagePreviewActivity.this.currentDialogId != 0) {
                    ImagePreviewActivity.this.disableShowCheck = true;
                    Bundle args2 = new Bundle();
                    args2.putLong("dialog_id", ImagePreviewActivity.this.currentDialogId);
                    MediaActivity mediaActivity = new MediaActivity(args2, new int[]{-1, -1, -1, -1, -1}, null, ImagePreviewActivity.this.sharedMediaType);
                    if (ImagePreviewActivity.this.parentChatActivity != null) {
                        mediaActivity.setChatInfo(ImagePreviewActivity.this.parentChatActivity.getCurrentChatInfo());
                    }
                    ImagePreviewActivity.this.closePhoto(false, false);
                    ((LaunchActivity) ImagePreviewActivity.this.parentActivity).presentFragment(mediaActivity, false, true);
                    return;
                }
                return;
            }
            if (id == 4) {
                if (ImagePreviewActivity.this.currentMessageObject == null) {
                    return;
                }
                Bundle args = new Bundle();
                int lower_part = (int) ImagePreviewActivity.this.currentDialogId;
                int high_id = (int) (ImagePreviewActivity.this.currentDialogId >> 32);
                if (lower_part != 0) {
                    if (lower_part > 0) {
                        args.putInt("user_id", lower_part);
                    } else if (lower_part < 0) {
                        TLRPC.Chat chat = MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).getChat(Integer.valueOf(-lower_part));
                        if (chat != null && chat.migrated_to != null) {
                            args.putInt("migrated_to", lower_part);
                            lower_part = -chat.migrated_to.channel_id;
                        }
                        args.putInt("chat_id", -lower_part);
                    }
                } else {
                    args.putInt("enc_id", high_id);
                }
                args.putInt("message_id", ImagePreviewActivity.this.currentMessageObject.getId());
                NotificationCenter.getInstance(ImagePreviewActivity.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
                LaunchActivity launchActivity = (LaunchActivity) ImagePreviewActivity.this.parentActivity;
                boolean remove = launchActivity.getMainFragmentsCount() > 1 || AndroidUtilities.isTablet();
                launchActivity.presentFragment(new ChatActivity(args), remove, true);
                ImagePreviewActivity.this.currentMessageObject = null;
                ImagePreviewActivity.this.closePhoto(false, false);
                return;
            }
            if (id == 3) {
                if (ImagePreviewActivity.this.currentMessageObject != null && ImagePreviewActivity.this.parentActivity != null) {
                    ((LaunchActivity) ImagePreviewActivity.this.parentActivity).switchToAccount(ImagePreviewActivity.this.currentMessageObject.currentAccount, true);
                    Bundle args3 = new Bundle();
                    args3.putBoolean("onlySelect", true);
                    args3.putInt("dialogsType", 3);
                    DialogsActivity fragment = new DialogsActivity(args3);
                    final ArrayList<MessageObject> fmessages = new ArrayList<>();
                    fmessages.add(ImagePreviewActivity.this.currentMessageObject);
                    fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$7$g7QHi4mB7TDLIc403V18L6U1psY
                        @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                        public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                            this.f$0.lambda$onItemClick$0$ImagePreviewActivity$7(fmessages, dialogsActivity, arrayList, charSequence, z);
                        }
                    });
                    ((LaunchActivity) ImagePreviewActivity.this.parentActivity).presentFragment(fragment, false, true);
                    ImagePreviewActivity.this.closePhoto(false, false);
                    return;
                }
                return;
            }
            if (id == 6) {
                if (ImagePreviewActivity.this.parentActivity == null || ImagePreviewActivity.this.placeProvider == null) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(ImagePreviewActivity.this.parentActivity);
                String text = ImagePreviewActivity.this.placeProvider.getDeleteMessageString();
                if (text == null) {
                    if (ImagePreviewActivity.this.currentMessageObject == null || !ImagePreviewActivity.this.currentMessageObject.isVideo()) {
                        if (ImagePreviewActivity.this.currentMessageObject != null && ImagePreviewActivity.this.currentMessageObject.isGif()) {
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
                if (ImagePreviewActivity.this.currentMessageObject != null && !ImagePreviewActivity.this.currentMessageObject.scheduled && (lower_id = (int) ImagePreviewActivity.this.currentMessageObject.getDialogId()) != 0) {
                    if (lower_id > 0) {
                        currentUser = MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).getUser(Integer.valueOf(lower_id));
                        currentChat = null;
                    } else {
                        currentUser = null;
                        currentChat = MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).getChat(Integer.valueOf(-lower_id));
                    }
                    if (currentUser != null || !ChatObject.isChannel(currentChat)) {
                        int currentDate = ConnectionsManager.getInstance(ImagePreviewActivity.this.currentAccount).getCurrentTime();
                        int revokeTimeLimit = currentUser != null ? MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).revokeTimePmLimit : MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).revokeTimeLimit;
                        if (((currentUser != null && currentUser.id != UserConfig.getInstance(ImagePreviewActivity.this.currentAccount).getClientUserId()) || currentChat != null) && ((ImagePreviewActivity.this.currentMessageObject.messageOwner.action == null || (ImagePreviewActivity.this.currentMessageObject.messageOwner.action instanceof TLRPC.TL_messageActionEmpty)) && ImagePreviewActivity.this.currentMessageObject.isOut() && currentDate - ImagePreviewActivity.this.currentMessageObject.messageOwner.date <= revokeTimeLimit)) {
                            FrameLayout frameLayout = new FrameLayout(ImagePreviewActivity.this.parentActivity);
                            CheckBoxCell cell = new CheckBoxCell(ImagePreviewActivity.this.parentActivity, 1);
                            cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
                            if (currentChat != null) {
                                cell.setText(LocaleController.getString("DeleteForAll", R.string.DeleteForAll), "", false, false);
                            } else {
                                cell.setText(LocaleController.formatString("DeleteForUser", R.string.DeleteForUser, UserObject.getFirstName(currentUser)), "", false, false);
                            }
                            cell.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : AndroidUtilities.dp(8.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(8.0f) : AndroidUtilities.dp(16.0f), 0);
                            frameLayout.addView(cell, LayoutHelper.createFrame(-1.0f, 48.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$7$QKNYaRIhLdTfw2aNEnS1oLufCO4
                                @Override // android.view.View.OnClickListener
                                public final void onClick(View view) {
                                    ImagePreviewActivity.AnonymousClass7.lambda$onItemClick$1(deleteForAll, view);
                                }
                            });
                            builder.setView(frameLayout);
                        }
                    }
                }
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$7$lKmik_Cn0RhZ4GwVHVllq2dNE-A
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onItemClick$2$ImagePreviewActivity$7(deleteForAll, dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                ImagePreviewActivity.this.showAlertDialog(builder);
                return;
            }
            if (id == 10) {
                ImagePreviewActivity.this.onSharePressed();
                return;
            }
            if (id == 11) {
                try {
                    AndroidUtilities.openForView(ImagePreviewActivity.this.currentMessageObject, ImagePreviewActivity.this.parentActivity);
                    ImagePreviewActivity.this.closePhoto(false, false);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            if (id == 13) {
                if (ImagePreviewActivity.this.parentActivity == null || ImagePreviewActivity.this.currentMessageObject == null || ImagePreviewActivity.this.currentMessageObject.messageOwner.media == null || ImagePreviewActivity.this.currentMessageObject.messageOwner.media.photo == null) {
                    return;
                }
                StickersAlert stickersAlert = new StickersAlert(ImagePreviewActivity.this.parentActivity, ImagePreviewActivity.this.currentMessageObject, ImagePreviewActivity.this.currentMessageObject.messageOwner.media.photo);
                stickersAlert.show();
                return;
            }
            if (id == 5) {
                if (ImagePreviewActivity.this.pipItem.getAlpha() == 1.0f) {
                    ImagePreviewActivity.this.switchToPip();
                }
            } else if (id == 7 && ImagePreviewActivity.this.currentMessageObject != null) {
                FileLoader.getInstance(ImagePreviewActivity.this.currentAccount).cancelLoadFile(ImagePreviewActivity.this.currentMessageObject.getDocument());
                ImagePreviewActivity.this.releasePlayer(false);
                ImagePreviewActivity.this.bottomLayout.setTag(1);
                ImagePreviewActivity.this.bottomLayout.setVisibility(0);
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$ImagePreviewActivity$7(ArrayList fmessages, DialogsActivity fragment1, ArrayList dids, CharSequence message, boolean param) {
            if (dids.size() > 1 || ((Long) dids.get(0)).longValue() == UserConfig.getInstance(ImagePreviewActivity.this.currentAccount).getClientUserId() || message != null) {
                for (int a = 0; a < dids.size(); a++) {
                    long did = ((Long) dids.get(a)).longValue();
                    if (message != null) {
                        SendMessagesHelper.getInstance(ImagePreviewActivity.this.currentAccount).sendMessage(message.toString(), did, null, null, true, null, null, null, true, 0);
                    }
                    SendMessagesHelper.getInstance(ImagePreviewActivity.this.currentAccount).sendMessage(fmessages, did, true, 0);
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
            NotificationCenter.getInstance(ImagePreviewActivity.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            ChatActivity chatActivity = new ChatActivity(args1);
            if (((LaunchActivity) ImagePreviewActivity.this.parentActivity).presentFragment(chatActivity, true, false)) {
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

        public /* synthetic */ void lambda$onItemClick$2$ImagePreviewActivity$7(boolean[] deleteForAll, DialogInterface dialogInterface, int i) {
            ArrayList<Long> random_ids;
            TLRPC.EncryptedChat encryptedChat;
            if (!ImagePreviewActivity.this.imagesArr.isEmpty()) {
                if (ImagePreviewActivity.this.currentIndex >= 0 && ImagePreviewActivity.this.currentIndex < ImagePreviewActivity.this.imagesArr.size()) {
                    MessageObject obj = (MessageObject) ImagePreviewActivity.this.imagesArr.get(ImagePreviewActivity.this.currentIndex);
                    if (obj.isSent()) {
                        ImagePreviewActivity.this.closePhoto(false, false);
                        ArrayList<Integer> arr = new ArrayList<>();
                        if (ImagePreviewActivity.this.slideshowMessageId != 0) {
                            arr.add(Integer.valueOf(ImagePreviewActivity.this.slideshowMessageId));
                        } else {
                            arr.add(Integer.valueOf(obj.getId()));
                        }
                        if (((int) obj.getDialogId()) == 0 && obj.messageOwner.random_id != 0) {
                            ArrayList<Long> random_ids2 = new ArrayList<>();
                            random_ids2.add(Long.valueOf(obj.messageOwner.random_id));
                            TLRPC.EncryptedChat encryptedChat2 = MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).getEncryptedChat(Integer.valueOf((int) (obj.getDialogId() >> 32)));
                            random_ids = random_ids2;
                            encryptedChat = encryptedChat2;
                        } else {
                            random_ids = null;
                            encryptedChat = null;
                        }
                        MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).deleteMessages(arr, random_ids, encryptedChat, obj.getDialogId(), obj.messageOwner.to_id.channel_id, deleteForAll[0], obj.scheduled);
                        return;
                    }
                    return;
                }
                return;
            }
            if (!ImagePreviewActivity.this.avatarsArr.isEmpty()) {
                if (ImagePreviewActivity.this.currentIndex >= 0 && ImagePreviewActivity.this.currentIndex < ImagePreviewActivity.this.avatarsArr.size()) {
                    TLRPC.Photo photo = (TLRPC.Photo) ImagePreviewActivity.this.avatarsArr.get(ImagePreviewActivity.this.currentIndex);
                    ImageLocation currentLocation = (ImageLocation) ImagePreviewActivity.this.imagesArrLocations.get(ImagePreviewActivity.this.currentIndex);
                    if (photo instanceof TLRPC.TL_photoEmpty) {
                        photo = null;
                    }
                    boolean current = false;
                    if (ImagePreviewActivity.this.currentUserAvatarLocation != null) {
                        if (photo == null) {
                            if (currentLocation.location.local_id == ImagePreviewActivity.this.currentUserAvatarLocation.location.local_id && currentLocation.location.volume_id == ImagePreviewActivity.this.currentUserAvatarLocation.location.volume_id) {
                                current = true;
                            }
                        } else {
                            Iterator<TLRPC.PhotoSize> it = photo.sizes.iterator();
                            while (true) {
                                if (!it.hasNext()) {
                                    break;
                                }
                                TLRPC.PhotoSize size = it.next();
                                if (size.location.local_id == ImagePreviewActivity.this.currentUserAvatarLocation.location.local_id && size.location.volume_id == ImagePreviewActivity.this.currentUserAvatarLocation.location.volume_id) {
                                    current = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (current) {
                        MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).deleteUserPhoto(null);
                        ImagePreviewActivity.this.closePhoto(false, false);
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
                        MessagesController.getInstance(ImagePreviewActivity.this.currentAccount).deleteUserPhoto(inputPhoto);
                        MessagesStorage.getInstance(ImagePreviewActivity.this.currentAccount).clearUserPhoto(ImagePreviewActivity.this.avatarsDialogId, photo.id);
                        ImagePreviewActivity.this.imagesArrLocations.remove(ImagePreviewActivity.this.currentIndex);
                        ImagePreviewActivity.this.imagesArrLocationsSizes.remove(ImagePreviewActivity.this.currentIndex);
                        ImagePreviewActivity.this.avatarsArr.remove(ImagePreviewActivity.this.currentIndex);
                        if (!ImagePreviewActivity.this.imagesArrLocations.isEmpty()) {
                            int index = ImagePreviewActivity.this.currentIndex;
                            if (index >= ImagePreviewActivity.this.avatarsArr.size()) {
                                index = ImagePreviewActivity.this.avatarsArr.size() - 1;
                            }
                            ImagePreviewActivity.this.currentIndex = -1;
                            ImagePreviewActivity.this.setImageIndex(index, true);
                            return;
                        }
                        ImagePreviewActivity.this.closePhoto(false, false);
                        return;
                    }
                    return;
                }
                return;
            }
            if (!ImagePreviewActivity.this.secureDocuments.isEmpty() && ImagePreviewActivity.this.placeProvider != null) {
                ImagePreviewActivity.this.secureDocuments.remove(ImagePreviewActivity.this.currentIndex);
                ImagePreviewActivity.this.placeProvider.deleteImageAtIndex(ImagePreviewActivity.this.currentIndex);
                if (!ImagePreviewActivity.this.secureDocuments.isEmpty()) {
                    int index2 = ImagePreviewActivity.this.currentIndex;
                    if (index2 >= ImagePreviewActivity.this.secureDocuments.size()) {
                        index2 = ImagePreviewActivity.this.secureDocuments.size() - 1;
                    }
                    ImagePreviewActivity.this.currentIndex = -1;
                    ImagePreviewActivity.this.setImageIndex(index2, true);
                    return;
                }
                ImagePreviewActivity.this.closePhoto(false, false);
            }
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public boolean canOpenMenu() {
            if (ImagePreviewActivity.this.currentMessageObject != null) {
                File f = FileLoader.getPathToMessage(ImagePreviewActivity.this.currentMessageObject.messageOwner);
                return f.exists();
            }
            if (ImagePreviewActivity.this.currentFileLocation == null) {
                return false;
            }
            ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
            File f2 = FileLoader.getPathToAttach(imagePreviewActivity.getFileLocation(imagePreviewActivity.currentFileLocation), ImagePreviewActivity.this.avatarsDialogId != 0 || ImagePreviewActivity.this.isEvent);
            return f2.exists();
        }
    }

    public /* synthetic */ void lambda$setParentActivity$2$ImagePreviewActivity(View v) {
        onSharePressed();
    }

    public /* synthetic */ void lambda$setParentActivity$3$ImagePreviewActivity(View view) {
        this.selectedCompression = this.previousCompression;
        didChangedCompressionLevel(false);
        showQualityView(false);
        requestVideoPreview(2);
    }

    public /* synthetic */ void lambda$setParentActivity$4$ImagePreviewActivity(View view) {
        showQualityView(false);
        requestVideoPreview(2);
    }

    public /* synthetic */ void lambda$setParentActivity$5$ImagePreviewActivity(View v) {
        ChatActivity chatActivity = this.parentChatActivity;
        if (chatActivity != null && chatActivity.isInScheduleMode() && !this.parentChatActivity.isEditingMessageMedia()) {
            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(this.parentChatActivity.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$b62XtAY_dOvcCBeoeXE_JvwCPXM
                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                public final void didSelectDate(boolean z, int i) {
                    this.f$0.sendPressed(z, i);
                }
            });
        } else {
            sendPressed(true, 0);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$13, reason: invalid class name */
    class AnonymousClass13 implements View.OnClickListener {
        AnonymousClass13() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (ImagePreviewActivity.this.isCurrentVideo) {
                int seconds = (int) (ImagePreviewActivity.this.estimatedDuration / 1000);
                if (seconds <= 60) {
                    if (ImagePreviewActivity.this.estimatedSize > 62914560) {
                        XDialog.Builder builder = new XDialog.Builder(ImagePreviewActivity.this.parentActivity);
                        builder.setTitle(LocaleController.getString("image_select_tip", R.string.image_select_tip));
                        builder.setMessage(LocaleController.formatString("friendscircle_video_max_tip", R.string.friendscircle_video_max_tip, AndroidUtilities.formatFileSize(ImagePreviewActivity.this.estimatedSize)));
                        builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$13$DGJacjCbmArvUleKvWYDNEYAWqY
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                ImagePreviewActivity.AnonymousClass13.lambda$onClick$0(dialogInterface, i);
                            }
                        });
                        builder.show();
                        return;
                    }
                } else {
                    XDialog.Builder builder2 = new XDialog.Builder(ImagePreviewActivity.this.parentActivity);
                    builder2.setTitle(LocaleController.getString("image_select_tip", R.string.image_select_tip));
                    builder2.setMessage(LocaleController.formatString("friendscircle_publish_video_tip", R.string.friendscircle_publish_video_tip, new Object[0]));
                    builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                    builder2.show();
                    return;
                }
            }
            ImagePreviewActivity.this.sendPressed(true, 0);
        }

        static /* synthetic */ void lambda$onClick$0(DialogInterface dialogInterface, int i) {
        }
    }

    public /* synthetic */ void lambda$setParentActivity$6$ImagePreviewActivity(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        switchToEditMode(1);
    }

    public /* synthetic */ void lambda$setParentActivity$7$ImagePreviewActivity(View v) {
        PhotoCropView photoCropView = this.photoCropView;
        if (photoCropView == null) {
            return;
        }
        photoCropView.rotate();
    }

    public /* synthetic */ void lambda$setParentActivity$8$ImagePreviewActivity(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        switchToEditMode(3);
    }

    public /* synthetic */ void lambda$setParentActivity$9$ImagePreviewActivity(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        showQualityView(true);
        requestVideoPreview(1);
    }

    public /* synthetic */ void lambda$setParentActivity$10$ImagePreviewActivity(View v) {
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

    public /* synthetic */ void lambda$setParentActivity$11$ImagePreviewActivity(View v) {
        if (this.placeProvider == null || this.captionEditText.getTag() != null) {
            return;
        }
        this.placeProvider.needAddMorePhotos();
        closePhoto(true, false);
    }

    public /* synthetic */ void lambda$setParentActivity$12$ImagePreviewActivity(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        switchToEditMode(2);
    }

    public /* synthetic */ void lambda$setParentActivity$18$ImagePreviewActivity(View v) {
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
        titleView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$Cb-LpCoTlYpmQ-AVmZceHcxBdEo
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ImagePreviewActivity.lambda$null$13(view, motionEvent);
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
        titleView2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$I5_YlKDLWbr7E1HYNL4chqCG21Q
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ImagePreviewActivity.lambda$null$14(view, motionEvent);
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
        numberPicker.setFormatter(new NumberPicker.Formatter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$g6dpO6jwrkFPIi4y7WvaykniyRM
            @Override // im.uwrkaxlmjj.ui.components.NumberPicker.Formatter
            public final String format(int i2) {
                return ImagePreviewActivity.lambda$null$15(i2);
            }
        });
        linearLayout.addView(numberPicker, LayoutHelper.createLinear(-1, -2));
        FrameLayout buttonsLayout = new FrameLayout(this.parentActivity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.15
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
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$8zcn_cAkI-nmxWY81OV29ALlPCg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$null$16$ImagePreviewActivity(numberPicker, bottomSheet, view);
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
        textView2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$zdP719IKXOJQhhbRH-C5LmlTUkM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                bottomSheet.dismiss();
            }
        });
        bottomSheet.show();
        bottomSheet.setBackgroundColor(-16777216);
    }

    static /* synthetic */ boolean lambda$null$13(View v13, MotionEvent event) {
        return true;
    }

    static /* synthetic */ boolean lambda$null$14(View v12, MotionEvent event) {
        return true;
    }

    static /* synthetic */ String lambda$null$15(int value) {
        if (value == 0) {
            return LocaleController.getString("ShortMessageLifetimeForever", R.string.ShortMessageLifetimeForever);
        }
        if (value >= 1 && value < 21) {
            return LocaleController.formatTTLString(value);
        }
        return LocaleController.formatTTLString((value - 16) * 5);
    }

    public /* synthetic */ void lambda$null$16$ImagePreviewActivity(NumberPicker numberPicker, BottomSheet bottomSheet, View v1) {
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

    public /* synthetic */ void lambda$setParentActivity$19$ImagePreviewActivity(View view) {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$setParentActivity$20$ImagePreviewActivity(View view) {
        if (this.currentEditMode == 1 && !this.photoCropView.isReady()) {
            return;
        }
        applyCurrentEditMode();
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$setParentActivity$21$ImagePreviewActivity(View v) {
        this.photoCropView.reset();
    }

    public /* synthetic */ void lambda$setParentActivity$22$ImagePreviewActivity(ImageReceiver imageReceiver, boolean set, boolean thumb) {
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

    public /* synthetic */ void lambda$setParentActivity$23$ImagePreviewActivity(View v) {
        if (this.captionEditText.getTag() != null) {
            return;
        }
        setPhotoChecked();
    }

    public /* synthetic */ void lambda$setParentActivity$24$ImagePreviewActivity(View v) {
        PhotoViewerProvider photoViewerProvider;
        if (this.captionEditText.getTag() != null || (photoViewerProvider = this.placeProvider) == null || photoViewerProvider.getSelectedPhotosOrder() == null || this.placeProvider.getSelectedPhotosOrder().isEmpty()) {
            return;
        }
        togglePhotosListView(!this.isPhotosListViewVisible, true);
    }

    public /* synthetic */ void lambda$setParentActivity$25$ImagePreviewActivity(View view, int position) {
        this.ignoreDidSetImage = true;
        int idx = this.imagesArrLocals.indexOf(view.getTag());
        if (idx >= 0) {
            this.currentIndex = -1;
            setImageIndex(idx, true);
        }
        this.ignoreDidSetImage = false;
    }

    public /* synthetic */ void lambda$setParentActivity$26$ImagePreviewActivity(View view, int position) {
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
        if (user.username != null) {
            this.captionEditText.replaceWithText(start, len, "@" + user.username + " ", false);
            return;
        }
        String name = UserObject.getFirstName(user);
        Spannable spannable = new SpannableString(name + " ");
        spannable.setSpan(new URLSpanUserMentionPhotoViewer("" + user.id, true), 0, spannable.length(), 33);
        this.captionEditText.replaceWithText(start, len, spannable, false);
    }

    public /* synthetic */ boolean lambda$setParentActivity$28$ImagePreviewActivity(View view, int position) {
        Object object = this.mentionsAdapter.getItem(position);
        if (object instanceof String) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this.parentActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("ClearSearch", R.string.ClearSearch));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$en4hgwGaBRPWwKT1HeDQ-M8h5No
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$27$ImagePreviewActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showAlertDialog(builder);
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$null$27$ImagePreviewActivity(DialogInterface dialogInterface, int i) {
        this.mentionsAdapter.clearRecentHashtags();
    }

    public void setActionBarVisible(boolean blnVisible) {
        this.actionBar.setAlpha(blnVisible ? 1.0f : 0.0f);
        this.checkImageView.setAlpha(blnVisible ? 1.0f : 0.0f);
        this.photosCounterView.setAlpha(blnVisible ? 1.0f : 0.0f);
        boolean z = !blnVisible;
        this.mblnIsHiddenActionBar = z;
        if (z) {
            this.mtvCancel.setVisibility(0);
            this.mtvFinish.setVisibility(0);
        }
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
            if (this.selectSameMediaType && checkSelectedIsSameType()) {
                return;
            }
            VideoEditedInfo videoEditedInfo = getCurrentVideoEditedInfo();
            this.mstrPath = "";
            if (videoEditedInfo != null && videoEditedInfo.needConvert()) {
                videoConvert(videoEditedInfo);
                return;
            }
            this.placeProvider.sendButtonPressed(this.currentIndex, videoEditedInfo, notify, scheduleDate);
            this.doneButtonPressed = true;
            closePhoto(false, false);
        }
    }

    private void videoConvert(VideoEditedInfo videoEditedInfo) {
        TLRPC.TL_message message = new TLRPC.TL_message();
        message.id = 0;
        message.message = "";
        message.media = new TLRPC.TL_messageMediaEmpty();
        message.action = new TLRPC.TL_messageActionEmpty();
        final MessageObject obj = new MessageObject(UserConfig.selectedAccount, message, false);
        obj.videoEditedInfo = videoEditedInfo;
        if (videoEditedInfo != null && videoEditedInfo.needConvert()) {
            String fileName = "-2147483648_" + SharedConfig.getLastLocalId() + ".mp4";
            File cacheFile = new File(FileLoader.getDirectory(4), fileName);
            SharedConfig.saveConfig();
            this.mstrPath = cacheFile.getAbsolutePath();
        }
        obj.messageOwner.attachPath = this.mstrPath;
        this.progressDialog.setCanCancel(true);
        this.progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.24
            @Override // android.content.DialogInterface.OnCancelListener
            public void onCancel(DialogInterface dialogInterface) {
                MediaController.getInstance().cancelVideoConvert(obj);
            }
        });
        try {
            this.progressDialog.show();
            FcToastUtils.show(R.string.friendscircle_publish_video_compress_tip);
        } catch (Exception e) {
            e.printStackTrace();
        }
        MediaController.getInstance().scheduleVideoConvert(obj);
    }

    private boolean checkInlinePermissions() {
        if (this.parentActivity == null) {
            return false;
        }
        if (Build.VERSION.SDK_INT < 23 || Settings.canDrawOverlays(this.parentActivity)) {
            return true;
        }
        new AlertDialog.Builder(this.parentActivity).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("PermissionDrawAboveOtherApps", R.string.PermissionDrawAboveOtherApps)).setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$gbl7wosugzEhrMUtDgm7aBlhqPc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$checkInlinePermissions$29$ImagePreviewActivity(dialogInterface, i);
            }
        }).show();
        return false;
    }

    public /* synthetic */ void lambda$checkInlinePermissions$29$ImagePreviewActivity(DialogInterface dialog, int which) {
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
        TextView textView = new AppCompatTextView(this.actvityContext) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.25
            @Override // android.widget.TextView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                return ImagePreviewActivity.this.bottomTouchEnabled && super.onTouchEvent(event);
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
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$DNODo52i421K2yOXwkd48SHK04Y
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createCaptionTextView$30$ImagePreviewActivity(view);
            }
        });
        return textView;
    }

    public /* synthetic */ void lambda$createCaptionTextView$30$ImagePreviewActivity(View v) {
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
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.26
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation2) {
                    ImagePreviewActivity.this.pipAnimationInProgress = false;
                    ImagePreviewActivity.this.switchToInlineRunnable.run();
                }
            });
            animatorSet.start();
            return;
        }
        this.switchToInlineRunnable.run();
        dismissInternal();
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public VideoPlayer getVideoPlayer() {
        return this.videoPlayer;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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
            this.videoPreviewFrameAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.27
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    ImagePreviewActivity.this.videoPreviewFrameAnimation = null;
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
        this.videoPlayerSeekbar.setDelegate(new SeekBar.SeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.28
            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public void onSeekBarDrag(float progress) {
                if (ImagePreviewActivity.this.videoPlayer != null) {
                    if (!ImagePreviewActivity.this.inPreview && ImagePreviewActivity.this.videoTimelineView.getVisibility() == 0) {
                        progress = ImagePreviewActivity.this.videoTimelineView.getLeftProgress() + ((ImagePreviewActivity.this.videoTimelineView.getRightProgress() - ImagePreviewActivity.this.videoTimelineView.getLeftProgress()) * progress);
                    }
                    long duration = ImagePreviewActivity.this.videoPlayer.getDuration();
                    if (duration == C.TIME_UNSET) {
                        ImagePreviewActivity.this.seekToProgressPending = progress;
                    } else {
                        ImagePreviewActivity.this.videoPlayer.seekTo((int) (duration * progress));
                    }
                    ImagePreviewActivity.this.showVideoSeekPreviewPosition(false);
                    ImagePreviewActivity.this.needShowOnReady = false;
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public void onSeekBarContinuousDrag(float progress) {
                if (ImagePreviewActivity.this.videoPlayer != null && ImagePreviewActivity.this.videoPreviewFrame != null) {
                    ImagePreviewActivity.this.videoPreviewFrame.setProgress(progress, ImagePreviewActivity.this.videoPlayerSeekbar.getWidth());
                }
                ImagePreviewActivity.this.showVideoSeekPreviewPosition(true);
                ImagePreviewActivity.this.updateVideoSeekPreviewPosition();
            }
        });
        FrameLayout frameLayout = new FrameLayout(this.containerView.getContext()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.29
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (!ImagePreviewActivity.this.videoPlayerSeekbar.onTouch(event.getAction(), event.getX() - AndroidUtilities.dp(48.0f), event.getY())) {
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
                if (ImagePreviewActivity.this.videoPlayer != null) {
                    duration = ImagePreviewActivity.this.videoPlayer.getDuration();
                    if (duration == C.TIME_UNSET) {
                        duration = 0;
                    }
                } else {
                    duration = 0;
                }
                long duration2 = duration / 1000;
                int size = (int) Math.ceil(ImagePreviewActivity.this.videoPlayerTime.getPaint().measureText(String.format("%02d:%02d / %02d:%02d", Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60), Long.valueOf(duration2 / 60), Long.valueOf(duration2 % 60))));
                ImagePreviewActivity.this.videoPlayerSeekbar.setSize((getMeasuredWidth() - AndroidUtilities.dp(64.0f)) - size, getMeasuredHeight());
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                float progress = 0.0f;
                if (ImagePreviewActivity.this.videoPlayer != null) {
                    progress = ImagePreviewActivity.this.videoPlayer.getCurrentPosition() / ImagePreviewActivity.this.videoPlayer.getDuration();
                    if (!ImagePreviewActivity.this.inPreview && ImagePreviewActivity.this.videoTimelineView.getVisibility() == 0) {
                        float progress2 = progress - ImagePreviewActivity.this.videoTimelineView.getLeftProgress();
                        if (progress2 < 0.0f) {
                            progress2 = 0.0f;
                        }
                        progress = progress2 / (ImagePreviewActivity.this.videoTimelineView.getRightProgress() - ImagePreviewActivity.this.videoTimelineView.getLeftProgress());
                        if (progress > 1.0f) {
                            progress = 1.0f;
                        }
                    }
                }
                ImagePreviewActivity.this.videoPlayerSeekbar.setProgress(progress);
                ImagePreviewActivity.this.videoTimelineView.setProgress(progress);
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                canvas.save();
                canvas.translate(AndroidUtilities.dp(48.0f), 0.0f);
                ImagePreviewActivity.this.videoPlayerSeekbar.draw(canvas);
                canvas.restore();
            }
        };
        this.videoPlayerControlFrameLayout = frameLayout;
        frameLayout.setWillNotDraw(false);
        this.bottomLayout.addView(this.videoPlayerControlFrameLayout, LayoutHelper.createFrame(-1, -1, 51));
        VideoSeekPreviewImage videoSeekPreviewImage = new VideoSeekPreviewImage(this.containerView.getContext(), new VideoSeekPreviewImage.VideoSeekPreviewImageDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$3AusYhmp7tyKqdJU4uoiLYwI3_4
            @Override // im.uwrkaxlmjj.ui.components.VideoSeekPreviewImage.VideoSeekPreviewImageDelegate
            public final void onReady() {
                this.f$0.lambda$createVideoControlsInterface$31$ImagePreviewActivity();
            }
        }) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.30
            @Override // android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                ImagePreviewActivity.this.updateVideoSeekPreviewPosition();
            }

            @Override // android.view.View
            public void setVisibility(int visibility) {
                super.setVisibility(visibility);
                if (visibility == 0) {
                    ImagePreviewActivity.this.updateVideoSeekPreviewPosition();
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
        this.videoPlayButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$nKe2z7j_hcwrtrNY7EQIMx_X3uI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createVideoControlsInterface$32$ImagePreviewActivity(view);
            }
        });
        SimpleTextView simpleTextView = new SimpleTextView(this.containerView.getContext());
        this.videoPlayerTime = simpleTextView;
        simpleTextView.setTextColor(-1);
        this.videoPlayerTime.setGravity(53);
        this.videoPlayerTime.setTextSize(13);
        this.videoPlayerControlFrameLayout.addView(this.videoPlayerTime, LayoutHelper.createFrame(-2.0f, -1.0f, 53, 0.0f, 17.0f, 7.0f, 0.0f));
    }

    public /* synthetic */ void lambda$createVideoControlsInterface$31$ImagePreviewActivity() {
        if (this.needShowOnReady) {
            showVideoSeekPreviewPosition(true);
        }
    }

    public /* synthetic */ void lambda$createVideoControlsInterface$32$ImagePreviewActivity(View v) {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer == null) {
            return;
        }
        if (this.isPlaying) {
            videoPlayer.pause();
        } else {
            if (this.isCurrentVideo) {
                if (Math.abs(this.videoTimelineView.getProgress() - 1.0f) < 0.01f || this.videoPlayer.getCurrentPosition() == this.videoPlayer.getDuration()) {
                    this.videoPlayer.seekTo(0L);
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
                    FcToastUtils.show(R.string.VideoDoesNotSupportStreaming);
                }
                this.streamingAlertShown = true;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void injectVideoPlayer(VideoPlayer player) {
        this.injectingVideoPlayer = player;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void injectVideoPlayerSurface(SurfaceTexture surface) {
        this.injectingVideoPlayerSurface = surface;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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
            AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(this.parentActivity) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.31
                @Override // com.google.android.exoplayer2.ui.AspectRatioFrameLayout, android.widget.FrameLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                    if (ImagePreviewActivity.this.textureImageView != null) {
                        ViewGroup.LayoutParams layoutParams = ImagePreviewActivity.this.textureImageView.getLayoutParams();
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
            this.videoPlayer.setDelegate(new AnonymousClass32());
        }
        if (newPlayerCreated) {
            this.seekToProgressPending = this.seekToProgressPending2;
            this.videoPlayer.preparePlayer(uri, "other");
            this.videoPlayerSeekbar.setProgress(0.0f);
            this.videoTimelineView.setProgress(0.0f);
            this.videoPlayerSeekbar.setBufferedProgress(0.0f);
            this.videoPlayer.setPlayWhenReady(playWhenReady);
        }
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && messageObject.forceSeekTo >= 0.0f) {
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

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$32, reason: invalid class name */
    class AnonymousClass32 implements VideoPlayer.VideoPlayerDelegate {
        AnonymousClass32() {
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onStateChanged(boolean playWhenReady, int playbackState) {
            ImagePreviewActivity.this.updatePlayerState(playWhenReady, playbackState);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onError(Exception e) {
            if (ImagePreviewActivity.this.videoPlayer == null) {
                return;
            }
            FileLog.e(e);
            if (!ImagePreviewActivity.this.menuItem.isSubItemVisible(11)) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(ImagePreviewActivity.this.parentActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("CantPlayVideo", R.string.CantPlayVideo));
            builder.setPositiveButton(LocaleController.getString("Open", R.string.Open), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$32$NSJBqwQjiFPOtWcc3TNV8e1j6Jc
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onError$0$ImagePreviewActivity$32(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            ImagePreviewActivity.this.showAlertDialog(builder);
        }

        public /* synthetic */ void lambda$onError$0$ImagePreviewActivity$32(DialogInterface dialog, int which) {
            try {
                AndroidUtilities.openForView(ImagePreviewActivity.this.currentMessageObject, ImagePreviewActivity.this.parentActivity);
                ImagePreviewActivity.this.closePhoto(false, false);
            } catch (Exception e1) {
                FileLog.e(e1);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
            if (ImagePreviewActivity.this.aspectRatioFrameLayout != null) {
                if (unappliedRotationDegrees == 90 || unappliedRotationDegrees == 270) {
                    width = height;
                    height = width;
                }
                ImagePreviewActivity.this.aspectRatioFrameLayout.setAspectRatio(height == 0 ? 1.0f : (width * pixelWidthHeightRatio) / height, unappliedRotationDegrees);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onRenderedFirstFrame() {
            if (!ImagePreviewActivity.this.textureUploaded) {
                ImagePreviewActivity.this.textureUploaded = true;
                ImagePreviewActivity.this.containerView.invalidate();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
            if (ImagePreviewActivity.this.changingTextureView) {
                ImagePreviewActivity.this.changingTextureView = false;
                if (ImagePreviewActivity.this.isInline) {
                    if (ImagePreviewActivity.this.isInline) {
                        ImagePreviewActivity.this.waitingForFirstTextureUpload = 1;
                    }
                    ImagePreviewActivity.this.changedTextureView.setSurfaceTexture(surfaceTexture);
                    ImagePreviewActivity.this.changedTextureView.setSurfaceTextureListener(ImagePreviewActivity.this.surfaceTextureListener);
                    ImagePreviewActivity.this.changedTextureView.setVisibility(0);
                    return true;
                }
            }
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
            if (ImagePreviewActivity.this.waitingForFirstTextureUpload == 2) {
                if (ImagePreviewActivity.this.textureImageView != null) {
                    ImagePreviewActivity.this.textureImageView.setVisibility(4);
                    ImagePreviewActivity.this.textureImageView.setImageDrawable(null);
                    if (ImagePreviewActivity.this.currentBitmap != null) {
                        ImagePreviewActivity.this.currentBitmap.recycle();
                        ImagePreviewActivity.this.currentBitmap = null;
                    }
                }
                ImagePreviewActivity.this.switchingInlineMode = false;
                if (Build.VERSION.SDK_INT >= 21) {
                    ImagePreviewActivity.this.aspectRatioFrameLayout.getLocationInWindow(ImagePreviewActivity.this.pipPosition);
                    ImagePreviewActivity.this.pipPosition[1] = (int) (r0[1] - ImagePreviewActivity.this.containerView.getTranslationY());
                    ImagePreviewActivity.this.textureImageView.setTranslationX(ImagePreviewActivity.this.textureImageView.getTranslationX() + ImagePreviewActivity.this.getLeftInset());
                    ImagePreviewActivity.this.videoTextureView.setTranslationX((ImagePreviewActivity.this.videoTextureView.getTranslationX() + ImagePreviewActivity.this.getLeftInset()) - ImagePreviewActivity.this.aspectRatioFrameLayout.getX());
                    AnimatorSet animatorSet = new AnimatorSet();
                    animatorSet.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this.textureImageView, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.textureImageView, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.textureImageView, (Property<ImageView, Float>) View.TRANSLATION_X, ImagePreviewActivity.this.pipPosition[0]), ObjectAnimator.ofFloat(ImagePreviewActivity.this.textureImageView, (Property<ImageView, Float>) View.TRANSLATION_Y, ImagePreviewActivity.this.pipPosition[1]), ObjectAnimator.ofFloat(ImagePreviewActivity.this.videoTextureView, (Property<TextureView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.videoTextureView, (Property<TextureView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.videoTextureView, (Property<TextureView, Float>) View.TRANSLATION_X, ImagePreviewActivity.this.pipPosition[0] - ImagePreviewActivity.this.aspectRatioFrameLayout.getX()), ObjectAnimator.ofFloat(ImagePreviewActivity.this.videoTextureView, (Property<TextureView, Float>) View.TRANSLATION_Y, ImagePreviewActivity.this.pipPosition[1] - ImagePreviewActivity.this.aspectRatioFrameLayout.getY()), ObjectAnimator.ofInt(ImagePreviewActivity.this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 255), ObjectAnimator.ofFloat(ImagePreviewActivity.this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.bottomLayout, (Property<FrameLayout, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.captionTextView, (Property<TextView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.groupedPhotosListView, (Property<GroupedPhotosListView, Float>) View.ALPHA, 1.0f));
                    animatorSet.setInterpolator(new DecelerateInterpolator());
                    animatorSet.setDuration(250L);
                    animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.32.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ImagePreviewActivity.this.pipAnimationInProgress = false;
                        }
                    });
                    animatorSet.start();
                }
                ImagePreviewActivity.this.waitingForFirstTextureUpload = 0;
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
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$8SEWusWYUdnbo8FQxc4XTdqmtco
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showAlertDialog$33$ImagePreviewActivity(dialogInterface);
                }
            });
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public /* synthetic */ void lambda$showAlertDialog$33$ImagePreviewActivity(DialogInterface dialog) {
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
            if (this.selectSameMediaType && checkSelectedIsSameType()) {
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

    private boolean checkSelectedIsSameType() {
        boolean isSame;
        ArrayList<Object> order;
        Object o;
        boolean isSame2 = false;
        PhotoViewerProvider photoViewerProvider = this.placeProvider;
        if (photoViewerProvider == null) {
            return false;
        }
        ArrayList<Object> order2 = photoViewerProvider.getSelectedPhotosOrder();
        MediaController.PhotoEntry currentPhotoEntry = null;
        if (!this.imagesArrLocals.isEmpty() && (o = this.imagesArrLocals.get(this.currentIndex)) != null && (o instanceof MediaController.PhotoEntry)) {
            currentPhotoEntry = (MediaController.PhotoEntry) o;
        }
        if (order2 != null && order2.size() > 0) {
            int gifs = 0;
            int mp4s = 0;
            int imgs = 0;
            boolean isCurrentAdd = false;
            int i = 0;
            while (i < order2.size()) {
                Object object = this.placeProvider.getSelectedPhotos().get(order2.get(i));
                if (object == null || !(object instanceof MediaController.PhotoEntry)) {
                    isSame = isSame2;
                    order = order2;
                } else {
                    MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) object;
                    if (currentPhotoEntry == null || isCurrentAdd) {
                        isSame = isSame2;
                        order = order2;
                    } else {
                        isSame = isSame2;
                        order = order2;
                        if (photoEntry.imageId == currentPhotoEntry.imageId) {
                            isCurrentAdd = true;
                        }
                    }
                    if (photoEntry.path.endsWith(".gif")) {
                        gifs++;
                    } else if (photoEntry.isVideo) {
                        mp4s++;
                    } else {
                        imgs++;
                    }
                    if (imgs > 0 && gifs > 0) {
                        FcToastUtils.show((CharSequence) "不能同时选择图片和gif动图");
                        isSame2 = true;
                    } else if ((imgs > 0 && mp4s > 0) || (gifs > 0 && mp4s > 0)) {
                        FcToastUtils.show((CharSequence) "不能同时选择视频和图片");
                        isSame2 = true;
                    } else if (gifs > 1 && photoEntry.path.endsWith(".gif")) {
                        FcToastUtils.show((CharSequence) "最多只能选择一张gif动图");
                        isSame2 = true;
                    } else if (mp4s > 1 && photoEntry.isVideo) {
                        FcToastUtils.show((CharSequence) "最多只能选择一个视频");
                        isSame2 = true;
                    }
                    i++;
                    order2 = order;
                }
                isSame2 = isSame;
                i++;
                order2 = order;
            }
            boolean isSame3 = isSame2;
            if (currentPhotoEntry != null && !isCurrentAdd) {
                if (currentPhotoEntry.path.endsWith(".gif")) {
                    gifs++;
                } else if (currentPhotoEntry.isVideo) {
                    mp4s++;
                } else {
                    imgs++;
                }
                if (imgs > 0 && gifs > 0) {
                    FcToastUtils.show((CharSequence) "不能同时选择图片和gif动图");
                    return true;
                }
                if ((imgs > 0 && mp4s > 0) || (gifs > 0 && mp4s > 0)) {
                    FcToastUtils.show((CharSequence) "不能同时选择视频和图片");
                    return true;
                }
                if (gifs > 1 && currentPhotoEntry.path.endsWith(".gif")) {
                    FcToastUtils.show((CharSequence) "最多只能选择一张gif动图");
                    return true;
                }
                if (mp4s > 1 && currentPhotoEntry.isVideo) {
                    FcToastUtils.show((CharSequence) "最多只能选择一个视频");
                    return true;
                }
            }
            return isSame3;
        }
        if (this.maxSelectedPhotos >= 9 || this.selectedMediaType != 1) {
            return false;
        }
        if (currentPhotoEntry.path.endsWith(".gif")) {
            FcToastUtils.show((CharSequence) "不能同时选择图片和gif动图");
            return true;
        }
        if (!currentPhotoEntry.isVideo) {
            return false;
        }
        FcToastUtils.show((CharSequence) "不能同时选择视频和图片");
        return true;
    }

    private void createCropView() {
        if (this.photoCropView != null) {
            return;
        }
        PhotoCropView photoCropView = new PhotoCropView(this.actvityContext);
        this.photoCropView = photoCropView;
        photoCropView.setVisibility(8);
        int index = this.containerView.indexOfChild(this.pickerViewSendButton);
        this.containerView.addView(this.photoCropView, index - 1, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 48.0f));
        this.photoCropView.setDelegate(new PhotoCropView.PhotoCropViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$kCkk74cX4WGeNRkK-9GhOXygGX0
            @Override // im.uwrkaxlmjj.ui.components.PhotoCropView.PhotoCropViewDelegate
            public final void onChange(boolean z) {
                this.f$0.lambda$createCropView$34$ImagePreviewActivity(z);
            }
        });
    }

    public /* synthetic */ void lambda$createCropView$34$ImagePreviewActivity(boolean reset) {
        this.resetButton.setVisibility(reset ? 8 : 0);
    }

    private void switchToEditMode(final int mode) {
        Bitmap bitmap;
        if (this.currentEditMode != mode && this.centerImage.getBitmap() != null && this.changeModeAnimation == null && this.imageMoveAnimation == null && this.photoProgressViews[0].backgroundState == -1 && this.captionEditText.getTag() == null) {
            if (mode == 0) {
                this.mtvFinish.setVisibility(0);
                this.mtvCancel.setVisibility(0);
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
                    animators.add(ObjectAnimator.ofFloat(this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
                    animators.add(ObjectAnimator.ofFloat(this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f));
                } else if (i2 == 2) {
                    this.photoFilterView.shutdown();
                    animators.add(ObjectAnimator.ofFloat(this.photoFilterView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(186.0f)));
                    animators.add(ObjectAnimator.ofFloat(this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
                } else if (i2 == 3) {
                    this.photoPaintView.shutdown();
                    animators.add(ObjectAnimator.ofFloat(this.photoPaintView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f)));
                    animators.add(ObjectAnimator.ofFloat(this.photoPaintView.getColorPicker(), (Property<ColorPicker, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f)));
                    animators.add(ObjectAnimator.ofFloat(this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
                }
                this.imageMoveAnimation.playTogether(animators);
                this.imageMoveAnimation.setDuration(200L);
                this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.33
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ImagePreviewActivity.this.currentEditMode == 1) {
                            ImagePreviewActivity.this.editorDoneLayout.setVisibility(8);
                            ImagePreviewActivity.this.photoCropView.setVisibility(8);
                        } else if (ImagePreviewActivity.this.currentEditMode == 2) {
                            ImagePreviewActivity.this.containerView.removeView(ImagePreviewActivity.this.photoFilterView);
                            ImagePreviewActivity.this.photoFilterView = null;
                        } else if (ImagePreviewActivity.this.currentEditMode == 3) {
                            ImagePreviewActivity.this.containerView.removeView(ImagePreviewActivity.this.photoPaintView);
                            ImagePreviewActivity.this.photoPaintView = null;
                        }
                        ImagePreviewActivity.this.imageMoveAnimation = null;
                        ImagePreviewActivity.this.currentEditMode = mode;
                        ImagePreviewActivity.this.applying = false;
                        if (ImagePreviewActivity.this.sendPhotoType != 1) {
                            ImagePreviewActivity.this.animateToScale = 1.0f;
                            ImagePreviewActivity.this.animateToX = 0.0f;
                            ImagePreviewActivity.this.animateToY = 0.0f;
                            ImagePreviewActivity.this.scale = 1.0f;
                        }
                        ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
                        imagePreviewActivity.updateMinMax(imagePreviewActivity.scale);
                        ImagePreviewActivity.this.containerView.invalidate();
                        AnimatorSet animatorSet = new AnimatorSet();
                        ArrayList<Animator> arrayList = new ArrayList<>();
                        arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
                        arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f));
                        if (ImagePreviewActivity.this.sendPhotoType != 1) {
                            arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f));
                        }
                        if (ImagePreviewActivity.this.needCaptionLayout) {
                            arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.captionTextView, (Property<TextView, Float>) View.TRANSLATION_Y, 0.0f));
                        }
                        if (ImagePreviewActivity.this.sendPhotoType == 0 || ImagePreviewActivity.this.sendPhotoType == 4) {
                            arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.checkImageView, (Property<CheckBox, Float>) View.ALPHA, 1.0f));
                            arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.photosCounterView, (Property<CounterView, Float>) View.ALPHA, 1.0f));
                        } else if (ImagePreviewActivity.this.sendPhotoType == 1) {
                            arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 1.0f));
                        }
                        if (ImagePreviewActivity.this.cameraItem.getTag() != null) {
                            ImagePreviewActivity.this.cameraItem.setVisibility(0);
                            arrayList.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                        }
                        animatorSet.playTogether(arrayList);
                        animatorSet.setDuration(200L);
                        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.33.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                                ImagePreviewActivity.this.pickerView.setVisibility(0);
                                ImagePreviewActivity.this.pickerViewSendButton.setVisibility(4);
                                ImagePreviewActivity.this.actionBar.setVisibility(0);
                                if (ImagePreviewActivity.this.needCaptionLayout) {
                                    ImagePreviewActivity.this.captionTextView.setVisibility(ImagePreviewActivity.this.captionTextView.getTag() != null ? 0 : 4);
                                }
                                if (ImagePreviewActivity.this.sendPhotoType == 0 || ImagePreviewActivity.this.sendPhotoType == 4 || ((ImagePreviewActivity.this.sendPhotoType == 2 || ImagePreviewActivity.this.sendPhotoType == 5) && ImagePreviewActivity.this.imagesArrLocals.size() > 1)) {
                                    if (!ImagePreviewActivity.this.mblnIsHiddenActionBar) {
                                        ImagePreviewActivity.this.checkImageView.setVisibility(0);
                                        ImagePreviewActivity.this.photosCounterView.setVisibility(0);
                                        return;
                                    }
                                    return;
                                }
                                if (ImagePreviewActivity.this.sendPhotoType == 1) {
                                    ImagePreviewActivity.this.setCropTranslations(false);
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
                this.mtvFinish.setVisibility(8);
                this.mtvCancel.setVisibility(8);
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
                if (this.cameraItem.getTag() != null) {
                    arrayList.add(ObjectAnimator.ofFloat(this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.changeModeAnimation.playTogether(arrayList);
                this.changeModeAnimation.setDuration(200L);
                this.changeModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.34
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ImagePreviewActivity.this.changeModeAnimation = null;
                        ImagePreviewActivity.this.pickerView.setVisibility(8);
                        ImagePreviewActivity.this.pickerViewSendButton.setVisibility(8);
                        ImagePreviewActivity.this.cameraItem.setVisibility(8);
                        ImagePreviewActivity.this.selectedPhotosListView.setVisibility(8);
                        ImagePreviewActivity.this.selectedPhotosListView.setAlpha(0.0f);
                        ImagePreviewActivity.this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
                        ImagePreviewActivity.this.photosCounterView.setRotationX(0.0f);
                        ImagePreviewActivity.this.selectedPhotosListView.setEnabled(false);
                        ImagePreviewActivity.this.isPhotosListViewVisible = false;
                        if (ImagePreviewActivity.this.needCaptionLayout) {
                            ImagePreviewActivity.this.captionTextView.setVisibility(4);
                        }
                        if (ImagePreviewActivity.this.sendPhotoType == 0 || ImagePreviewActivity.this.sendPhotoType == 4 || ((ImagePreviewActivity.this.sendPhotoType == 2 || ImagePreviewActivity.this.sendPhotoType == 5) && ImagePreviewActivity.this.imagesArrLocals.size() > 1)) {
                            ImagePreviewActivity.this.checkImageView.setVisibility(8);
                            ImagePreviewActivity.this.photosCounterView.setVisibility(8);
                        }
                        Bitmap bitmap3 = ImagePreviewActivity.this.centerImage.getBitmap();
                        if (bitmap3 != null) {
                            ImagePreviewActivity.this.photoCropView.setBitmap(bitmap3, ImagePreviewActivity.this.centerImage.getOrientation(), ImagePreviewActivity.this.sendPhotoType != 1, false);
                            ImagePreviewActivity.this.photoCropView.onDisappear();
                            int bitmapWidth2 = ImagePreviewActivity.this.centerImage.getBitmapWidth();
                            int bitmapHeight2 = ImagePreviewActivity.this.centerImage.getBitmapHeight();
                            float scaleX2 = ImagePreviewActivity.this.getContainerViewWidth() / bitmapWidth2;
                            float scaleY2 = ImagePreviewActivity.this.getContainerViewHeight() / bitmapHeight2;
                            float newScaleX2 = ImagePreviewActivity.this.getContainerViewWidth(1) / bitmapWidth2;
                            float newScaleY2 = ImagePreviewActivity.this.getContainerViewHeight(1) / bitmapHeight2;
                            float scale2 = scaleX2 > scaleY2 ? scaleY2 : scaleX2;
                            float newScale2 = newScaleX2 > newScaleY2 ? newScaleY2 : newScaleX2;
                            if (ImagePreviewActivity.this.sendPhotoType == 1) {
                                float minSide = Math.min(ImagePreviewActivity.this.getContainerViewWidth(1), ImagePreviewActivity.this.getContainerViewHeight(1));
                                float newScaleX3 = minSide / bitmapWidth2;
                                float newScaleY3 = minSide / bitmapHeight2;
                                newScale2 = newScaleX3 > newScaleY3 ? newScaleX3 : newScaleY3;
                            }
                            ImagePreviewActivity.this.animateToScale = newScale2 / scale2;
                            ImagePreviewActivity.this.animateToX = (r14.getLeftInset() / 2) - (ImagePreviewActivity.this.getRightInset() / 2);
                            ImagePreviewActivity.this.animateToY = (-AndroidUtilities.dp(56.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
                            ImagePreviewActivity.this.animationStartTime = System.currentTimeMillis();
                            ImagePreviewActivity.this.zoomAnimation = true;
                        }
                        ImagePreviewActivity.this.imageMoveAnimation = new AnimatorSet();
                        ImagePreviewActivity.this.imageMoveAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this.editorDoneLayout, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(48.0f), 0.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f, 1.0f));
                        ImagePreviewActivity.this.imageMoveAnimation.setDuration(200L);
                        ImagePreviewActivity.this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.34.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                                ImagePreviewActivity.this.editorDoneLayout.setVisibility(0);
                                ImagePreviewActivity.this.photoCropView.setVisibility(0);
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                ImagePreviewActivity.this.photoCropView.onAppeared();
                                ImagePreviewActivity.this.imageMoveAnimation = null;
                                ImagePreviewActivity.this.currentEditMode = mode;
                                ImagePreviewActivity.this.animateToScale = 1.0f;
                                ImagePreviewActivity.this.animateToX = 0.0f;
                                ImagePreviewActivity.this.animateToY = 0.0f;
                                ImagePreviewActivity.this.scale = 1.0f;
                                ImagePreviewActivity.this.updateMinMax(ImagePreviewActivity.this.scale);
                                ImagePreviewActivity.this.padImageForHorizontalInsets = true;
                                ImagePreviewActivity.this.containerView.invalidate();
                            }
                        });
                        ImagePreviewActivity.this.imageMoveAnimation.start();
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
                    this.photoFilterView.getDoneTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$SfTJx1SjaoXWA3gCmIcPr8GpW8A
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$switchToEditMode$35$ImagePreviewActivity(view);
                        }
                    });
                    this.photoFilterView.getCancelTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$PQ3Wk8UQikeXxtx5vZ0X6eo3uGI
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$switchToEditMode$37$ImagePreviewActivity(view);
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
                if (this.cameraItem.getTag() != null) {
                    arrayList2.add(ObjectAnimator.ofFloat(this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.changeModeAnimation.playTogether(arrayList2);
                this.changeModeAnimation.setDuration(200L);
                this.changeModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.35
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ImagePreviewActivity.this.changeModeAnimation = null;
                        ImagePreviewActivity.this.pickerView.setVisibility(8);
                        ImagePreviewActivity.this.pickerViewSendButton.setVisibility(8);
                        ImagePreviewActivity.this.actionBar.setVisibility(8);
                        ImagePreviewActivity.this.cameraItem.setVisibility(8);
                        ImagePreviewActivity.this.selectedPhotosListView.setVisibility(8);
                        ImagePreviewActivity.this.selectedPhotosListView.setAlpha(0.0f);
                        ImagePreviewActivity.this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
                        ImagePreviewActivity.this.photosCounterView.setRotationX(0.0f);
                        ImagePreviewActivity.this.selectedPhotosListView.setEnabled(false);
                        ImagePreviewActivity.this.isPhotosListViewVisible = false;
                        if (ImagePreviewActivity.this.needCaptionLayout) {
                            ImagePreviewActivity.this.captionTextView.setVisibility(4);
                        }
                        if (ImagePreviewActivity.this.sendPhotoType == 0 || ImagePreviewActivity.this.sendPhotoType == 4 || ((ImagePreviewActivity.this.sendPhotoType == 2 || ImagePreviewActivity.this.sendPhotoType == 5) && ImagePreviewActivity.this.imagesArrLocals.size() > 1)) {
                            ImagePreviewActivity.this.checkImageView.setVisibility(8);
                            ImagePreviewActivity.this.photosCounterView.setVisibility(8);
                        }
                        Bitmap bitmap3 = ImagePreviewActivity.this.centerImage.getBitmap();
                        if (bitmap3 != null) {
                            int bitmapWidth2 = ImagePreviewActivity.this.centerImage.getBitmapWidth();
                            int bitmapHeight2 = ImagePreviewActivity.this.centerImage.getBitmapHeight();
                            float scaleX2 = ImagePreviewActivity.this.getContainerViewWidth() / bitmapWidth2;
                            float scaleY2 = ImagePreviewActivity.this.getContainerViewHeight() / bitmapHeight2;
                            float newScaleX2 = ImagePreviewActivity.this.getContainerViewWidth(2) / bitmapWidth2;
                            float newScaleY2 = ImagePreviewActivity.this.getContainerViewHeight(2) / bitmapHeight2;
                            float scale2 = scaleX2 > scaleY2 ? scaleY2 : scaleX2;
                            float newScale2 = newScaleX2 > newScaleY2 ? newScaleY2 : newScaleX2;
                            ImagePreviewActivity.this.animateToScale = newScale2 / scale2;
                            ImagePreviewActivity.this.animateToX = (r14.getLeftInset() / 2) - (ImagePreviewActivity.this.getRightInset() / 2);
                            ImagePreviewActivity.this.animateToY = (-AndroidUtilities.dp(92.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
                            ImagePreviewActivity.this.animationStartTime = System.currentTimeMillis();
                            ImagePreviewActivity.this.zoomAnimation = true;
                        }
                        ImagePreviewActivity.this.imageMoveAnimation = new AnimatorSet();
                        ImagePreviewActivity.this.imageMoveAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.photoFilterView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(186.0f), 0.0f));
                        ImagePreviewActivity.this.imageMoveAnimation.setDuration(200L);
                        ImagePreviewActivity.this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.35.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                ImagePreviewActivity.this.photoFilterView.init();
                                ImagePreviewActivity.this.imageMoveAnimation = null;
                                ImagePreviewActivity.this.currentEditMode = mode;
                                ImagePreviewActivity.this.animateToScale = 1.0f;
                                ImagePreviewActivity.this.animateToX = 0.0f;
                                ImagePreviewActivity.this.animateToY = 0.0f;
                                ImagePreviewActivity.this.scale = 1.0f;
                                ImagePreviewActivity.this.updateMinMax(ImagePreviewActivity.this.scale);
                                ImagePreviewActivity.this.padImageForHorizontalInsets = true;
                                ImagePreviewActivity.this.containerView.invalidate();
                                if (ImagePreviewActivity.this.sendPhotoType == 1) {
                                    ImagePreviewActivity.this.photoCropView.reset();
                                }
                            }
                        });
                        ImagePreviewActivity.this.imageMoveAnimation.start();
                    }
                });
                this.changeModeAnimation.start();
                return;
            }
            if (mode == 3) {
                this.mtvFinish.setVisibility(8);
                this.mtvCancel.setVisibility(8);
                if (this.photoPaintView == null) {
                    PhotoPaintView photoPaintView = new PhotoPaintView(this.parentActivity, this.centerImage.getBitmap(), this.centerImage.getOrientation());
                    this.photoPaintView = photoPaintView;
                    this.containerView.addView(photoPaintView, LayoutHelper.createFrame(-1, -1.0f));
                    this.photoPaintView.getDoneTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$-ofKe1yHq86x1XUA0OOcR-TZhMM
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$switchToEditMode$38$ImagePreviewActivity(view);
                        }
                    });
                    this.photoPaintView.getCancelTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$EN0nY8lqw9_O5RdzUGTSN9Txj0Y
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$switchToEditMode$40$ImagePreviewActivity(view);
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
                if (this.cameraItem.getTag() != null) {
                    arrayList3.add(ObjectAnimator.ofFloat(this.cameraItem, (Property<ImageView, Float>) View.ALPHA, 1.0f, 0.0f));
                }
                this.changeModeAnimation.playTogether(arrayList3);
                this.changeModeAnimation.setDuration(200L);
                this.changeModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.36
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ImagePreviewActivity.this.changeModeAnimation = null;
                        ImagePreviewActivity.this.pickerView.setVisibility(8);
                        ImagePreviewActivity.this.pickerViewSendButton.setVisibility(8);
                        ImagePreviewActivity.this.cameraItem.setVisibility(8);
                        ImagePreviewActivity.this.selectedPhotosListView.setVisibility(8);
                        ImagePreviewActivity.this.selectedPhotosListView.setAlpha(0.0f);
                        ImagePreviewActivity.this.selectedPhotosListView.setTranslationY(-AndroidUtilities.dp(10.0f));
                        ImagePreviewActivity.this.photosCounterView.setRotationX(0.0f);
                        ImagePreviewActivity.this.selectedPhotosListView.setEnabled(false);
                        ImagePreviewActivity.this.isPhotosListViewVisible = false;
                        if (ImagePreviewActivity.this.needCaptionLayout) {
                            ImagePreviewActivity.this.captionTextView.setVisibility(4);
                        }
                        if (ImagePreviewActivity.this.sendPhotoType == 0 || ImagePreviewActivity.this.sendPhotoType == 4 || ((ImagePreviewActivity.this.sendPhotoType == 2 || ImagePreviewActivity.this.sendPhotoType == 5) && ImagePreviewActivity.this.imagesArrLocals.size() > 1)) {
                            ImagePreviewActivity.this.checkImageView.setVisibility(8);
                            ImagePreviewActivity.this.photosCounterView.setVisibility(8);
                        }
                        Bitmap bitmap3 = ImagePreviewActivity.this.centerImage.getBitmap();
                        if (bitmap3 != null) {
                            int bitmapWidth2 = ImagePreviewActivity.this.centerImage.getBitmapWidth();
                            int bitmapHeight2 = ImagePreviewActivity.this.centerImage.getBitmapHeight();
                            float scaleX2 = ImagePreviewActivity.this.getContainerViewWidth() / bitmapWidth2;
                            float scaleY2 = ImagePreviewActivity.this.getContainerViewHeight() / bitmapHeight2;
                            float newScaleX2 = ImagePreviewActivity.this.getContainerViewWidth(3) / bitmapWidth2;
                            float newScaleY2 = ImagePreviewActivity.this.getContainerViewHeight(3) / bitmapHeight2;
                            float scale2 = scaleX2 > scaleY2 ? scaleY2 : scaleX2;
                            float newScale2 = newScaleX2 > newScaleY2 ? newScaleY2 : newScaleX2;
                            ImagePreviewActivity.this.animateToScale = newScale2 / scale2;
                            ImagePreviewActivity.this.animateToX = (r3.getLeftInset() / 2) - (ImagePreviewActivity.this.getRightInset() / 2);
                            ImagePreviewActivity.this.animateToY = (-AndroidUtilities.dp(44.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight / 2 : 0);
                            ImagePreviewActivity.this.animationStartTime = System.currentTimeMillis();
                            ImagePreviewActivity.this.zoomAnimation = true;
                        }
                        ImagePreviewActivity.this.imageMoveAnimation = new AnimatorSet();
                        ImagePreviewActivity.this.imageMoveAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.photoPaintView.getColorPicker(), (Property<ColorPicker, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f), 0.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.photoPaintView.getToolsView(), (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(126.0f), 0.0f));
                        ImagePreviewActivity.this.imageMoveAnimation.setDuration(200L);
                        ImagePreviewActivity.this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.36.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationStart(Animator animation2) {
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                ImagePreviewActivity.this.photoPaintView.init();
                                ImagePreviewActivity.this.imageMoveAnimation = null;
                                ImagePreviewActivity.this.currentEditMode = mode;
                                ImagePreviewActivity.this.animateToScale = 1.0f;
                                ImagePreviewActivity.this.animateToX = 0.0f;
                                ImagePreviewActivity.this.animateToY = 0.0f;
                                ImagePreviewActivity.this.scale = 1.0f;
                                ImagePreviewActivity.this.updateMinMax(ImagePreviewActivity.this.scale);
                                ImagePreviewActivity.this.padImageForHorizontalInsets = true;
                                ImagePreviewActivity.this.containerView.invalidate();
                                if (ImagePreviewActivity.this.sendPhotoType == 1) {
                                    ImagePreviewActivity.this.photoCropView.reset();
                                }
                            }
                        });
                        ImagePreviewActivity.this.imageMoveAnimation.start();
                    }
                });
                this.changeModeAnimation.start();
            }
        }
    }

    public /* synthetic */ void lambda$switchToEditMode$35$ImagePreviewActivity(View v) {
        applyCurrentEditMode();
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$switchToEditMode$37$ImagePreviewActivity(View v) {
        if (this.photoFilterView.hasChanges()) {
            Activity activity = this.parentActivity;
            if (activity == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(activity);
            builder.setMessage(LocaleController.getString("DiscardChanges", R.string.DiscardChanges));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$msOI9abJVDzjzXrQNPll8lIQ9uM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$36$ImagePreviewActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showAlertDialog(builder);
            return;
        }
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$null$36$ImagePreviewActivity(DialogInterface dialogInterface, int i) {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$switchToEditMode$38$ImagePreviewActivity(View v) {
        applyCurrentEditMode();
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$null$39$ImagePreviewActivity() {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$switchToEditMode$40$ImagePreviewActivity(View v) {
        this.photoPaintView.maybeShowDismissalAlert(this, this.parentActivity, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$XnvU3XamdCObl4Gq0UIPm4EwpAE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$39$ImagePreviewActivity();
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
        this.miniProgressAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.37
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(ImagePreviewActivity.this.miniProgressAnimator)) {
                    if (!show) {
                        ImagePreviewActivity.this.miniProgressView.setVisibility(4);
                    }
                    ImagePreviewActivity.this.miniProgressAnimator = null;
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (animation.equals(ImagePreviewActivity.this.miniProgressAnimator)) {
                    ImagePreviewActivity.this.miniProgressAnimator = null;
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
            this.actionBarAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.38
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(ImagePreviewActivity.this.actionBarAnimator)) {
                        if (!show) {
                            ImagePreviewActivity.this.actionBar.setVisibility(4);
                            if (ImagePreviewActivity.this.bottomLayout.getTag() != null) {
                                ImagePreviewActivity.this.bottomLayout.setVisibility(4);
                            }
                            if (ImagePreviewActivity.this.captionTextView.getTag() != null) {
                                ImagePreviewActivity.this.captionTextView.setVisibility(4);
                            }
                        }
                        ImagePreviewActivity.this.actionBarAnimator = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (animation.equals(ImagePreviewActivity.this.actionBarAnimator)) {
                        ImagePreviewActivity.this.actionBarAnimator = null;
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
                this.currentListViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.39
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ImagePreviewActivity.this.currentListViewAnimation != null && ImagePreviewActivity.this.currentListViewAnimation.equals(animation)) {
                            ImagePreviewActivity.this.selectedPhotosListView.setVisibility(8);
                            ImagePreviewActivity.this.currentListViewAnimation = null;
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

    /* JADX WARN: Removed duplicated region for block: B:207:0x0589  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x05d0  */
    /* JADX WARN: Removed duplicated region for block: B:270:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void onPhotoShow(im.uwrkaxlmjj.messenger.MessageObject r30, im.uwrkaxlmjj.tgnet.TLRPC.FileLocation r31, im.uwrkaxlmjj.messenger.ImageLocation r32, java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r33, java.util.ArrayList<im.uwrkaxlmjj.messenger.SecureDocument> r34, java.util.ArrayList<java.lang.Object> r35, int r36, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.PlaceProviderObject r37) {
        /*
            Method dump skipped, instruction units count: 1606
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.onPhotoShow(im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.tgnet.TLRPC$FileLocation, im.uwrkaxlmjj.messenger.ImageLocation, java.util.ArrayList, java.util.ArrayList, java.util.ArrayList, int, im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$PlaceProviderObject):void");
    }

    private void setDoubleTapEnabled(boolean value) {
        this.doubleTapEnabled = value;
        this.gestureDetector.setOnDoubleTapListener(value ? this : null);
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0109  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0187  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x018b  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01ec  */
    /* JADX WARN: Type inference failed for: r9v5 */
    /* JADX WARN: Type inference failed for: r9v6, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r9v7 */
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
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void setIsAboutToSwitchToIndex(int r32, boolean r33) {
        /*
            Method dump skipped, instruction units count: 2280
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.setIsAboutToSwitchToIndex(int, boolean):void");
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
                        if (SharedConfig.saveToGallery) {
                            this.menuItem.showSubItem(1);
                        }
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
            this.captionTextView.setMaxLines(1);
            this.captionTextView.setSingleLine(true);
        } else {
            this.captionTextView.setSingleLine(false);
            this.captionTextView.setMaxLines(AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? 5 : 10);
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
                this.currentCaptionAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.41
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(ImagePreviewActivity.this.currentCaptionAnimation)) {
                            ImagePreviewActivity.this.captionTextView.setVisibility(4);
                            ImagePreviewActivity.this.currentCaptionAnimation = null;
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (animation.equals(ImagePreviewActivity.this.currentCaptionAnimation)) {
                            ImagePreviewActivity.this.currentCaptionAnimation = null;
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
                this.currentCaptionAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.40
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(ImagePreviewActivity.this.currentCaptionAnimation)) {
                            ImagePreviewActivity.this.currentCaptionAnimation = null;
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

    private void checkProgress(int a, boolean animated) {
        char c;
        int index = this.currentIndex;
        boolean z = true;
        if (a == 1) {
            index++;
        } else if (a == 2) {
            index--;
        }
        if (this.currentFileNames[a] != null) {
            File f = null;
            boolean isVideo = false;
            boolean canStream = false;
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
                    f = new File(messageObject.messageOwner.attachPath);
                    if (!f.exists()) {
                        f = null;
                    }
                }
                if (f == null) {
                    if ((messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && messageObject.messageOwner.media.webpage != null && messageObject.messageOwner.media.webpage.document == null) {
                        TLObject fileLocation = getFileLocation(index, null);
                        f = FileLoader.getPathToAttach(fileLocation, true);
                    } else {
                        f = FileLoader.getPathToMessage(messageObject.messageOwner);
                    }
                }
                canStream = SharedConfig.streamMedia && messageObject.isVideo() && messageObject.canStreamVideo() && ((int) messageObject.getDialogId()) != 0;
                isVideo = messageObject.isVideo();
            } else if (this.currentBotInlineResult != null) {
                if (index < 0 || index >= this.imagesArrLocals.size()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                }
                TLRPC.BotInlineResult botInlineResult = (TLRPC.BotInlineResult) this.imagesArrLocals.get(index);
                if (botInlineResult.type.equals("video") || MessageObject.isVideoDocument(botInlineResult.document)) {
                    if (botInlineResult.document != null) {
                        f = FileLoader.getPathToAttach(botInlineResult.document);
                    } else if (botInlineResult.content instanceof TLRPC.TL_webDocument) {
                        f = new File(FileLoader.getDirectory(4), Utilities.MD5(botInlineResult.content.url) + "." + ImageLoader.getHttpUrlExtension(botInlineResult.content.url, "mp4"));
                    }
                    isVideo = true;
                } else if (botInlineResult.document != null) {
                    f = new File(FileLoader.getDirectory(3), this.currentFileNames[a]);
                } else if (botInlineResult.photo != null) {
                    f = new File(FileLoader.getDirectory(0), this.currentFileNames[a]);
                }
                if (f == null || !f.exists()) {
                    f = new File(FileLoader.getDirectory(4), this.currentFileNames[a]);
                }
            } else if (this.currentFileLocation != null) {
                if (index < 0 || index >= this.imagesArrLocations.size()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                } else {
                    ImageLocation location = this.imagesArrLocations.get(index);
                    f = FileLoader.getPathToAttach(location.location, this.avatarsDialogId != 0 || this.isEvent);
                }
            } else if (this.currentSecureDocument != null) {
                if (index < 0 || index >= this.secureDocuments.size()) {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                    return;
                } else {
                    SecureDocument location2 = this.secureDocuments.get(index);
                    f = FileLoader.getPathToAttach(location2, true);
                }
            } else if (this.currentPathObject != null) {
                f = new File(FileLoader.getDirectory(3), this.currentFileNames[a]);
                if (!f.exists()) {
                    f = new File(FileLoader.getDirectory(4), this.currentFileNames[a]);
                }
            }
            boolean exists = f != null && f.exists();
            if (f != null && (exists || canStream)) {
                if (isVideo) {
                    this.photoProgressViews[a].setBackgroundState(3, animated);
                } else {
                    this.photoProgressViews[a].setBackgroundState(-1, animated);
                }
                if (a == 0) {
                    if (exists || !FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[a])) {
                        this.menuItem.hideSubItem(7);
                        c = 0;
                    } else {
                        this.menuItem.showSubItem(7);
                        c = 0;
                    }
                } else {
                    c = 0;
                }
            } else {
                if (isVideo) {
                    if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(this.currentFileNames[a])) {
                        this.photoProgressViews[a].setBackgroundState(2, false);
                    } else {
                        this.photoProgressViews[a].setBackgroundState(1, false);
                    }
                } else {
                    this.photoProgressViews[a].setBackgroundState(0, animated);
                }
                Float progress = ImageLoader.getInstance().getFileProgress(this.currentFileNames[a]);
                if (progress == null) {
                    progress = Float.valueOf(0.0f);
                }
                c = 0;
                this.photoProgressViews[a].setProgress(progress.floatValue(), false);
            }
            if (a == 0) {
                if (this.imagesArrLocals.isEmpty() && (this.currentFileNames[c] == null || this.photoProgressViews[c].backgroundState == 0)) {
                    z = false;
                }
                this.canZoom = z;
                return;
            }
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void setParentChatActivity(ChatActivity chatActivity) {
        this.parentChatActivity = chatActivity;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void setMaxSelectedPhotos(int value, boolean order) {
        this.maxSelectedPhotos = value;
        this.allowOrder = order;
    }

    public boolean openPhoto(MessageObject messageObject, long dialogId, long mergeDialogId, PhotoViewerProvider provider) {
        return openPhoto(messageObject, (TLRPC.FileLocation) null, (ImageLocation) null, (ArrayList<MessageObject>) null, (ArrayList<SecureDocument>) null, (ArrayList<Object>) null, 0, provider, (ChatActivity) null, dialogId, mergeDialogId, true);
    }

    public boolean openPhoto(MessageObject messageObject, long dialogId, long mergeDialogId, PhotoViewerProvider provider, boolean fullScreenVideo) {
        return openPhoto(messageObject, (TLRPC.FileLocation) null, (ImageLocation) null, (ArrayList<MessageObject>) null, (ArrayList<SecureDocument>) null, (ArrayList<Object>) null, 0, provider, (ChatActivity) null, dialogId, mergeDialogId, fullScreenVideo);
    }

    public boolean openPhoto(TLRPC.FileLocation fileLocation, PhotoViewerProvider provider) {
        return openPhoto((MessageObject) null, fileLocation, (ImageLocation) null, (ArrayList<MessageObject>) null, (ArrayList<SecureDocument>) null, (ArrayList<Object>) null, 0, provider, (ChatActivity) null, 0L, 0L, true);
    }

    public boolean openPhoto(TLRPC.FileLocation fileLocation, ImageLocation imageLocation, PhotoViewerProvider provider) {
        return openPhoto((MessageObject) null, fileLocation, imageLocation, (ArrayList<MessageObject>) null, (ArrayList<SecureDocument>) null, (ArrayList<Object>) null, 0, provider, (ChatActivity) null, 0L, 0L, true);
    }

    public boolean openPhoto(ArrayList<MessageObject> messages, int index, long dialogId, long mergeDialogId, PhotoViewerProvider provider) {
        return openPhoto(messages.get(index), (TLRPC.FileLocation) null, (ImageLocation) null, messages, (ArrayList<SecureDocument>) null, (ArrayList<Object>) null, index, provider, (ChatActivity) null, dialogId, mergeDialogId, true);
    }

    public boolean openPhoto(ArrayList<SecureDocument> documents, int index, PhotoViewerProvider provider) {
        return openPhoto((MessageObject) null, (TLRPC.FileLocation) null, (ImageLocation) null, (ArrayList<MessageObject>) null, documents, (ArrayList<Object>) null, index, provider, (ChatActivity) null, 0L, 0L, true);
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
        return openPhoto((MessageObject) null, (TLRPC.FileLocation) null, (ImageLocation) null, (ArrayList<MessageObject>) null, (ArrayList<SecureDocument>) null, photos, index, provider, chatActivity, 0L, 0L, true);
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

    /* JADX INFO: Access modifiers changed from: private */
    public void initCropView() {
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

    public boolean openPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, ImageLocation imageLocation, ArrayList<MessageObject> messages, ArrayList<SecureDocument> documents, ArrayList<Object> photos, int index, PhotoViewerProvider provider, ChatActivity chatActivity, long dialogId, long mDialogId, boolean fullScreenVideo) {
        boolean z;
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
            boolean z2 = !fullScreenVideo;
            this.openedFullScreenVideo = z2;
            if (!z2) {
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
                z = true;
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
                        if (messageObject.isVideo()) {
                            object.imageReceiver.setAllowStartAnimation(false);
                            object.imageReceiver.stopAnimation();
                            if (MediaController.getInstance().isPlayingMessage(messageObject)) {
                                this.seekToProgressPending2 = messageObject.audioProgress;
                            }
                            this.skipFirstBufferingProgress = this.injectingVideoPlayer == null && !FileLoader.getInstance(messageObject.currentAccount).isLoadingVideo(messageObject.getDocument(), true) && (this.currentAnimation.hasBitmap() || !FileLoader.getInstance(messageObject.currentAccount).isLoadingVideo(messageObject.getDocument(), false));
                            this.currentAnimation = null;
                        } else if (messageObject.getWebPagePhotos(null, null).size() > 1) {
                            this.currentAnimation = null;
                        }
                    }
                }
                z = true;
                onPhotoShow(messageObject, fileLocation, imageLocation, messages, documents, photos, index, object);
                if (this.sendPhotoType == 1) {
                    this.photoCropView.setVisibility(0);
                    this.photoCropView.setAlpha(0.0f);
                    this.photoCropView.setFreeform(false);
                }
                this.windowView.getViewTreeObserver().addOnPreDrawListener(new AnonymousClass42(object, photos));
            }
            AccessibilityManager am = (AccessibilityManager) this.parentActivity.getSystemService("accessibility");
            if (am.isTouchExplorationEnabled()) {
                AccessibilityEvent event = AccessibilityEvent.obtain();
                event.setEventType(16384);
                event.getText().add(LocaleController.getString("AccDescrPhotoViewer", R.string.AccDescrPhotoViewer));
                am.sendAccessibilityEvent(event);
            }
            return z;
        } catch (Exception e3) {
            e = e3;
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$42, reason: invalid class name */
    class AnonymousClass42 implements ViewTreeObserver.OnPreDrawListener {
        final /* synthetic */ PlaceProviderObject val$object;
        final /* synthetic */ ArrayList val$photos;

        AnonymousClass42(PlaceProviderObject placeProviderObject, ArrayList arrayList) {
            this.val$object = placeProviderObject;
            this.val$photos = arrayList;
        }

        @Override // android.view.ViewTreeObserver.OnPreDrawListener
        public boolean onPreDraw() {
            float scale;
            float yPos;
            float xPos;
            ImagePreviewActivity.this.windowView.getViewTreeObserver().removeOnPreDrawListener(this);
            RectF drawRegion = this.val$object.imageReceiver.getDrawRegion();
            int orientation = this.val$object.imageReceiver.getOrientation();
            int animatedOrientation = this.val$object.imageReceiver.getAnimatedOrientation();
            if (animatedOrientation != 0) {
                orientation = animatedOrientation;
            }
            ImagePreviewActivity.this.animatingImageView.setVisibility(0);
            ImagePreviewActivity.this.animatingImageView.setRadius(this.val$object.radius);
            ImagePreviewActivity.this.animatingImageView.setOrientation(orientation);
            ImagePreviewActivity.this.animatingImageView.setNeedRadius(this.val$object.radius != 0);
            ImagePreviewActivity.this.animatingImageView.setImageBitmap(this.val$object.thumb);
            ImagePreviewActivity.this.initCropView();
            if (ImagePreviewActivity.this.sendPhotoType == 1) {
                ImagePreviewActivity.this.photoCropView.hideBackView();
                ImagePreviewActivity.this.photoCropView.setAspectRatio(1.0f);
            }
            ImagePreviewActivity.this.animatingImageView.setAlpha(1.0f);
            ImagePreviewActivity.this.animatingImageView.setPivotX(0.0f);
            ImagePreviewActivity.this.animatingImageView.setPivotY(0.0f);
            ImagePreviewActivity.this.animatingImageView.setScaleX(this.val$object.scale);
            ImagePreviewActivity.this.animatingImageView.setScaleY(this.val$object.scale);
            ImagePreviewActivity.this.animatingImageView.setTranslationX(this.val$object.viewX + (drawRegion.left * this.val$object.scale));
            ImagePreviewActivity.this.animatingImageView.setTranslationY(this.val$object.viewY + (drawRegion.top * this.val$object.scale));
            ViewGroup.LayoutParams layoutParams = ImagePreviewActivity.this.animatingImageView.getLayoutParams();
            layoutParams.width = (int) drawRegion.width();
            layoutParams.height = (int) drawRegion.height();
            ImagePreviewActivity.this.animatingImageView.setLayoutParams(layoutParams);
            if (ImagePreviewActivity.this.sendPhotoType != 1) {
                float scaleX = ImagePreviewActivity.this.windowView.getMeasuredWidth() / layoutParams.width;
                float scaleY = (AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) / layoutParams.height;
                scale = scaleX > scaleY ? scaleY : scaleX;
                yPos = ((AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - (layoutParams.height * scale)) / 2.0f;
                xPos = (ImagePreviewActivity.this.windowView.getMeasuredWidth() - (layoutParams.width * scale)) / 2.0f;
            } else {
                float statusBarHeight = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
                float measuredHeight = (ImagePreviewActivity.this.photoCropView.getMeasuredHeight() - AndroidUtilities.dp(64.0f)) - statusBarHeight;
                float minSide = Math.min(ImagePreviewActivity.this.photoCropView.getMeasuredWidth(), measuredHeight) - (AndroidUtilities.dp(16.0f) * 2);
                float centerX = ImagePreviewActivity.this.photoCropView.getMeasuredWidth() / 2.0f;
                float centerY = statusBarHeight + (measuredHeight / 2.0f);
                float left = centerX - (minSide / 2.0f);
                float top = centerY - (minSide / 2.0f);
                float right = centerX + (minSide / 2.0f);
                float bottom = centerY + (minSide / 2.0f);
                scale = Math.max((right - left) / layoutParams.width, (bottom - top) / layoutParams.height);
                yPos = top + (((bottom - top) - (layoutParams.height * scale)) / 2.0f);
                xPos = ((((ImagePreviewActivity.this.windowView.getMeasuredWidth() - ImagePreviewActivity.this.getLeftInset()) - ImagePreviewActivity.this.getRightInset()) - (layoutParams.width * scale)) / 2.0f) + ImagePreviewActivity.this.getLeftInset();
            }
            int clipHorizontal = (int) Math.abs(drawRegion.left - this.val$object.imageReceiver.getImageX());
            int clipVertical = (int) Math.abs(drawRegion.top - this.val$object.imageReceiver.getImageY());
            int[] coords2 = new int[2];
            this.val$object.parentView.getLocationInWindow(coords2);
            int clipTop = (int) (((coords2[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight)) - (this.val$object.viewY + drawRegion.top)) + this.val$object.clipTopAddition);
            if (clipTop < 0) {
                clipTop = 0;
            }
            int clipBottom = (int) ((((this.val$object.viewY + drawRegion.top) + layoutParams.height) - ((coords2[1] + this.val$object.parentView.getHeight()) - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight))) + this.val$object.clipBottomAddition);
            if (clipBottom < 0) {
                clipBottom = 0;
            }
            int clipTop2 = Math.max(clipTop, clipVertical);
            int clipBottom2 = Math.max(clipBottom, clipVertical);
            ImagePreviewActivity.this.animationValues[0][0] = ImagePreviewActivity.this.animatingImageView.getScaleX();
            ImagePreviewActivity.this.animationValues[0][1] = ImagePreviewActivity.this.animatingImageView.getScaleY();
            ImagePreviewActivity.this.animationValues[0][2] = ImagePreviewActivity.this.animatingImageView.getTranslationX();
            ImagePreviewActivity.this.animationValues[0][3] = ImagePreviewActivity.this.animatingImageView.getTranslationY();
            ImagePreviewActivity.this.animationValues[0][4] = clipHorizontal * this.val$object.scale;
            ImagePreviewActivity.this.animationValues[0][5] = clipTop2 * this.val$object.scale;
            ImagePreviewActivity.this.animationValues[0][6] = clipBottom2 * this.val$object.scale;
            ImagePreviewActivity.this.animationValues[0][7] = ImagePreviewActivity.this.animatingImageView.getRadius();
            ImagePreviewActivity.this.animationValues[0][8] = clipVertical * this.val$object.scale;
            ImagePreviewActivity.this.animationValues[0][9] = clipHorizontal * this.val$object.scale;
            ImagePreviewActivity.this.animationValues[1][0] = scale;
            ImagePreviewActivity.this.animationValues[1][1] = scale;
            ImagePreviewActivity.this.animationValues[1][2] = xPos;
            ImagePreviewActivity.this.animationValues[1][3] = yPos;
            ImagePreviewActivity.this.animationValues[1][4] = 0.0f;
            ImagePreviewActivity.this.animationValues[1][5] = 0.0f;
            ImagePreviewActivity.this.animationValues[1][6] = 0.0f;
            ImagePreviewActivity.this.animationValues[1][7] = 0.0f;
            ImagePreviewActivity.this.animationValues[1][8] = 0.0f;
            ImagePreviewActivity.this.animationValues[1][9] = 0.0f;
            ImagePreviewActivity.this.animatingImageView.setAnimationProgress(0.0f);
            ImagePreviewActivity.this.backgroundDrawable.setAlpha(0);
            ImagePreviewActivity.this.containerView.setAlpha(0.0f);
            ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
            final ArrayList arrayList = this.val$photos;
            imagePreviewActivity.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$42$7U2CRnyrY_UcTR-4KZa8dWvN8Kw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPreDraw$0$ImagePreviewActivity$42(arrayList);
                }
            };
            if (ImagePreviewActivity.this.openedFullScreenVideo) {
                if (ImagePreviewActivity.this.animationEndRunnable != null) {
                    ImagePreviewActivity.this.animationEndRunnable.run();
                    ImagePreviewActivity.this.animationEndRunnable = null;
                }
                ImagePreviewActivity.this.containerView.setAlpha(1.0f);
                ImagePreviewActivity.this.backgroundDrawable.setAlpha(255);
                ImagePreviewActivity.this.animatingImageView.setAnimationProgress(1.0f);
                if (ImagePreviewActivity.this.sendPhotoType == 1) {
                    ImagePreviewActivity.this.photoCropView.setAlpha(1.0f);
                }
            } else {
                final AnimatorSet animatorSet = new AnimatorSet();
                ArrayList<Animator> animators = new ArrayList<>(ImagePreviewActivity.this.sendPhotoType == 1 ? 4 : 3);
                animators.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.animatingImageView, AnimationProperties.CLIPPING_IMAGE_VIEW_PROGRESS, 0.0f, 1.0f));
                animators.add(ObjectAnimator.ofInt(ImagePreviewActivity.this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0, 255));
                animators.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.containerView, (Property<FrameLayoutDrawer, Float>) View.ALPHA, 0.0f, 1.0f));
                if (ImagePreviewActivity.this.sendPhotoType == 1) {
                    animators.add(ObjectAnimator.ofFloat(ImagePreviewActivity.this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f, 1.0f));
                }
                animatorSet.playTogether(animators);
                animatorSet.setDuration(200L);
                animatorSet.addListener(new AnonymousClass1());
                if (Build.VERSION.SDK_INT >= 18) {
                    ImagePreviewActivity.this.containerView.setLayerType(2, null);
                }
                ImagePreviewActivity.this.transitionAnimationStartTime = System.currentTimeMillis();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$42$Lw_4EMvdi0YKWqw8u9HcHkv5UfI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onPreDraw$1$ImagePreviewActivity$42(animatorSet);
                    }
                });
            }
            BackgroundDrawable backgroundDrawable = ImagePreviewActivity.this.backgroundDrawable;
            final PlaceProviderObject placeProviderObject = this.val$object;
            backgroundDrawable.drawRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$42$pcYbJvlYCld1-0d6IkWLmY7trn0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPreDraw$2$ImagePreviewActivity$42(placeProviderObject);
                }
            };
            return true;
        }

        public /* synthetic */ void lambda$onPreDraw$0$ImagePreviewActivity$42(ArrayList photos) {
            if (ImagePreviewActivity.this.containerView == null || ImagePreviewActivity.this.windowView == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 18) {
                ImagePreviewActivity.this.containerView.setLayerType(0, null);
            }
            ImagePreviewActivity.this.animationInProgress = 0;
            ImagePreviewActivity.this.transitionAnimationStartTime = 0L;
            ImagePreviewActivity.this.setImages();
            ImagePreviewActivity.this.setCropBitmap();
            if (ImagePreviewActivity.this.sendPhotoType == 1) {
                ImagePreviewActivity.this.photoCropView.showBackView();
            }
            ImagePreviewActivity.this.containerView.invalidate();
            ImagePreviewActivity.this.animatingImageView.setVisibility(8);
            if (ImagePreviewActivity.this.showAfterAnimation != null) {
                ImagePreviewActivity.this.showAfterAnimation.imageReceiver.setVisible(true, true);
            }
            if (ImagePreviewActivity.this.hideAfterAnimation != null) {
                ImagePreviewActivity.this.hideAfterAnimation.imageReceiver.setVisible(false, true);
            }
            if (photos != null && ImagePreviewActivity.this.sendPhotoType != 3) {
                if (Build.VERSION.SDK_INT >= 21) {
                    ImagePreviewActivity.this.windowLayoutParams.flags = -2147417856;
                } else {
                    ImagePreviewActivity.this.windowLayoutParams.flags = 0;
                }
                ImagePreviewActivity.this.windowLayoutParams.softInputMode = 272;
                WindowManager wm1 = (WindowManager) ImagePreviewActivity.this.parentActivity.getSystemService("window");
                wm1.updateViewLayout(ImagePreviewActivity.this.windowView, ImagePreviewActivity.this.windowLayoutParams);
                ImagePreviewActivity.this.windowView.setFocusable(true);
                ImagePreviewActivity.this.containerView.setFocusable(true);
            }
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$42$1, reason: invalid class name */
        class AnonymousClass1 extends AnimatorListenerAdapter {
            AnonymousClass1() {
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$42$1$BeAb5zmqOYqmYqum2-lWOZvOTMI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onAnimationEnd$0$ImagePreviewActivity$42$1();
                    }
                });
            }

            public /* synthetic */ void lambda$onAnimationEnd$0$ImagePreviewActivity$42$1() {
                NotificationCenter.getInstance(ImagePreviewActivity.this.currentAccount).setAnimationInProgress(false);
                if (ImagePreviewActivity.this.animationEndRunnable != null) {
                    ImagePreviewActivity.this.animationEndRunnable.run();
                    ImagePreviewActivity.this.animationEndRunnable = null;
                }
            }
        }

        public /* synthetic */ void lambda$onPreDraw$1$ImagePreviewActivity$42(AnimatorSet animatorSet) {
            NotificationCenter.getInstance(ImagePreviewActivity.this.currentAccount).setAllowedNotificationsDutingAnimation(new int[]{NotificationCenter.dialogsNeedReload, NotificationCenter.closeChats, NotificationCenter.mediaCountDidLoad, NotificationCenter.mediaDidLoad, NotificationCenter.dialogPhotosLoaded});
            NotificationCenter.getInstance(ImagePreviewActivity.this.currentAccount).setAnimationInProgress(true);
            animatorSet.start();
        }

        public /* synthetic */ void lambda$onPreDraw$2$ImagePreviewActivity$42(PlaceProviderObject object) {
            ImagePreviewActivity.this.disableShowCheck = false;
            object.imageReceiver.setVisible(false, true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void injectVideoPlayerToMediaController() {
        if (this.videoPlayer.isPlaying()) {
            MediaController.getInstance().injectVideoPlayer(this.videoPlayer, this.currentMessageObject);
            this.videoPlayer = null;
            updateAccessibilityOverlayVisibility();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v25 */
    /* JADX WARN: Type inference failed for: r4v42 */
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
    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void closePhoto(boolean z, boolean z2) {
        boolean z3;
        ?? r4;
        RectF rectF;
        AnimatedFileDrawable animation;
        Bitmap animatedBitmap;
        int systemUiVisibility;
        int i;
        PhotoPaintView photoPaintView;
        if (!z2 && (i = this.currentEditMode) != 0) {
            if (i == 3 && (photoPaintView = this.photoPaintView) != null) {
                photoPaintView.maybeShowDismissalAlert(this, this.parentActivity, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$rLN3n-cJryGRY-BiTaXLQWbfBjE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$closePhoto$41$ImagePreviewActivity();
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
        int i2 = this.currentEditMode;
        if (i2 != 0) {
            if (i2 == 2) {
                this.photoFilterView.shutdown();
                this.containerView.removeView(this.photoFilterView);
                this.photoFilterView = null;
            } else if (i2 == 1) {
                this.editorDoneLayout.setVisibility(8);
                this.photoCropView.setVisibility(8);
            } else if (i2 == 3) {
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
                    this.animationInProgress = 1;
                    this.animatingImageView.setVisibility(0);
                    this.containerView.invalidate();
                    AnimatorSet animatorSet = new AnimatorSet();
                    ViewGroup.LayoutParams layoutParams = this.animatingImageView.getLayoutParams();
                    if (placeForPhoto != null) {
                        this.animatingImageView.setNeedRadius(placeForPhoto.radius != 0);
                        RectF drawRegion = placeForPhoto.imageReceiver.getDrawRegion();
                        layoutParams.width = (int) drawRegion.width();
                        layoutParams.height = (int) drawRegion.height();
                        int orientation = placeForPhoto.imageReceiver.getOrientation();
                        int animatedOrientation = placeForPhoto.imageReceiver.getAnimatedOrientation();
                        if (animatedOrientation != 0) {
                            orientation = animatedOrientation;
                        }
                        this.animatingImageView.setOrientation(orientation);
                        this.animatingImageView.setImageBitmap(placeForPhoto.thumb);
                        rectF = drawRegion;
                    } else {
                        this.animatingImageView.setNeedRadius(false);
                        layoutParams.width = this.centerImage.getImageWidth();
                        layoutParams.height = this.centerImage.getImageHeight();
                        this.animatingImageView.setOrientation(this.centerImage.getOrientation());
                        this.animatingImageView.setImageBitmap(this.centerImage.getBitmapSafe());
                        rectF = null;
                    }
                    this.animatingImageView.setLayoutParams(layoutParams);
                    float measuredWidth = this.windowView.getMeasuredWidth() / layoutParams.width;
                    float f = (AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) / layoutParams.height;
                    float f2 = measuredWidth > f ? f : measuredWidth;
                    float f3 = layoutParams.width * this.scale * f2;
                    float f4 = layoutParams.height * this.scale * f2;
                    float measuredWidth2 = (this.windowView.getMeasuredWidth() - f3) / 2.0f;
                    int i3 = AndroidUtilities.displaySize.y;
                    int i4 = Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0;
                    this.animatingImageView.setTranslationX(this.translationX + measuredWidth2);
                    this.animatingImageView.setTranslationY(this.translationY + (((i3 + i4) - f4) / 2.0f));
                    this.animatingImageView.setScaleX(this.scale * f2);
                    this.animatingImageView.setScaleY(this.scale * f2);
                    if (placeForPhoto != null) {
                        placeForPhoto.imageReceiver.setVisible(false, true);
                        int iAbs = (int) Math.abs(rectF.left - placeForPhoto.imageReceiver.getImageX());
                        int iAbs2 = (int) Math.abs(rectF.top - placeForPhoto.imageReceiver.getImageY());
                        placeForPhoto.parentView.getLocationInWindow(new int[2]);
                        int i5 = (int) (((r8[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight)) - (placeForPhoto.viewY + rectF.top)) + placeForPhoto.clipTopAddition);
                        if (i5 < 0) {
                            i5 = 0;
                        }
                        int height = (int) ((((placeForPhoto.viewY + rectF.top) + (rectF.bottom - rectF.top)) - ((r8[1] + placeForPhoto.parentView.getHeight()) - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight))) + placeForPhoto.clipBottomAddition);
                        if (height < 0) {
                            height = 0;
                        }
                        int iMax = Math.max(i5, iAbs2);
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
                        ArrayList arrayList = new ArrayList(this.sendPhotoType == 1 ? 4 : 3);
                        arrayList.add(ObjectAnimator.ofFloat(this.animatingImageView, AnimationProperties.CLIPPING_IMAGE_VIEW_PROGRESS, 0.0f, 1.0f));
                        arrayList.add(ObjectAnimator.ofInt(this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0));
                        arrayList.add(ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayoutDrawer, Float>) View.ALPHA, 0.0f));
                        if (this.sendPhotoType == 1) {
                            arrayList.add(ObjectAnimator.ofFloat(this.photoCropView, (Property<PhotoCropView, Float>) View.ALPHA, 0.0f));
                        }
                        animatorSet.playTogether(arrayList);
                    } else {
                        int i6 = AndroidUtilities.displaySize.y + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                        Animator[] animatorArr = new Animator[4];
                        animatorArr[0] = ObjectAnimator.ofInt(this.backgroundDrawable, (Property<BackgroundDrawable, Integer>) AnimationProperties.COLOR_DRAWABLE_ALPHA, 0);
                        animatorArr[1] = ObjectAnimator.ofFloat(this.animatingImageView, (Property<ClippingImageView, Float>) View.ALPHA, 0.0f);
                        ClippingImageView clippingImageView = this.animatingImageView;
                        Property property = View.TRANSLATION_Y;
                        float[] fArr2 = new float[1];
                        fArr2[0] = this.translationY >= 0.0f ? i6 : -i6;
                        animatorArr[2] = ObjectAnimator.ofFloat(clippingImageView, (Property<ClippingImageView, Float>) property, fArr2);
                        animatorArr[3] = ObjectAnimator.ofFloat(this.containerView, (Property<FrameLayoutDrawer, Float>) View.ALPHA, 0.0f);
                        animatorSet.playTogether(animatorArr);
                    }
                    this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$Oem6lkMOuGAw8cRUj0KymrdLRE8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$closePhoto$42$ImagePreviewActivity(placeForPhoto);
                        }
                    };
                    animatorSet.setDuration(200L);
                    animatorSet.addListener(new AnonymousClass43());
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
                    this.animationEndRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$3ze5XfxDASrK84xWIDOTWXgk-j8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$closePhoto$43$ImagePreviewActivity(placeForPhoto);
                        }
                    };
                    animatorSet2.setDuration(200L);
                    animatorSet2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.44
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation2) {
                            if (ImagePreviewActivity.this.animationEndRunnable != null) {
                                ImagePreviewActivity.this.animationEndRunnable.run();
                                ImagePreviewActivity.this.animationEndRunnable = null;
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

    public /* synthetic */ void lambda$closePhoto$41$ImagePreviewActivity() {
        switchToEditMode(0);
    }

    public /* synthetic */ void lambda$closePhoto$42$ImagePreviewActivity(PlaceProviderObject object) {
        if (Build.VERSION.SDK_INT >= 18) {
            this.containerView.setLayerType(0, null);
        }
        this.animationInProgress = 0;
        onPhotoClosed(object);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$43, reason: invalid class name */
    class AnonymousClass43 extends AnimatorListenerAdapter {
        AnonymousClass43() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$43$sv1qSx2dhnO5HaEnnMWEWs2lkYY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ImagePreviewActivity$43();
                }
            });
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ImagePreviewActivity$43() {
            if (ImagePreviewActivity.this.animationEndRunnable != null) {
                ImagePreviewActivity.this.animationEndRunnable.run();
                ImagePreviewActivity.this.animationEndRunnable = null;
            }
        }
    }

    public /* synthetic */ void lambda$closePhoto$43$ImagePreviewActivity(PlaceProviderObject object) {
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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

    private void onPhotoClosed(PlaceProviderObject object) {
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
        this.containerView.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$y1faHae1GfaAGrMoaEGUTi_Icd0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onPhotoClosed$44$ImagePreviewActivity();
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
        if (object != null) {
            object.imageReceiver.setVisible(true, true);
        }
    }

    public /* synthetic */ void lambda$onPhotoClosed$44$ImagePreviewActivity() {
        this.animatingImageView.setImageBitmap(null);
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
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$43qe_83zWTZTTr3T3JhPtu216KE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$redraw$45$ImagePreviewActivity(count);
                }
            }, 100L);
        }
    }

    public /* synthetic */ void lambda$redraw$45$ImagePreviewActivity(int count) {
        redraw(count + 1);
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void onResume() {
        redraw(0);
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.seekTo(videoPlayer.getCurrentPosition() + 1);
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void onConfigurationChanged(Configuration newConfig) {
        PipVideoView pipVideoView = this.pipVideoView;
        if (pipVideoView != null) {
            pipVideoView.onConfigurationChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void onPause() {
        if (this.currentAnimation != null) {
            closePhoto(false, false);
        } else if (this.lastTitle != null) {
            closeCaptionEnter(true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
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
    /* JADX WARN: Removed duplicated region for block: B:140:0x025d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r13) {
        /*
            Method dump skipped, instruction units count: 1181
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.onTouchEvent(android.view.MotionEvent):boolean");
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
        animatorSet.playTogether(ObjectAnimator.ofFloat(this, (Property<ImagePreviewActivity, Float>) AnimationProperties.PHOTO_VIEWER_ANIMATION_VALUE, 0.0f, 1.0f));
        this.imageMoveAnimation.setInterpolator(this.interpolator);
        this.imageMoveAnimation.setDuration(duration);
        this.imageMoveAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.45
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ImagePreviewActivity.this.imageMoveAnimation = null;
                ImagePreviewActivity.this.containerView.invalidate();
            }
        });
        this.imageMoveAnimation.start();
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void setAnimationValue(float value) {
        this.animationValue = value;
        this.containerView.invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public float getAnimationValue() {
        return this.animationValue;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:112:0x0214  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0301  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x03c3  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x045f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onDraw(android.graphics.Canvas r31) {
        /*
            Method dump skipped, instruction units count: 1658
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.onDraw(android.graphics.Canvas):void");
    }

    public /* synthetic */ void lambda$onDraw$46$ImagePreviewActivity() {
        setImageIndex(this.currentIndex + 1, false);
    }

    public /* synthetic */ void lambda$onDraw$47$ImagePreviewActivity() {
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
                            uri = Uri.parse("bchat://" + this.currentMessageObject.getFileName() + params);
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnGestureListener
    public boolean onDown(MotionEvent e) {
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnGestureListener
    public void onShowPress(MotionEvent e) {
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnGestureListener
    public boolean onSingleTapUp(MotionEvent e) {
        if (!this.canZoom && !this.doubleTapEnabled) {
            return onSingleTapConfirmed(e);
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnGestureListener
    public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX, float distanceY) {
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnGestureListener
    public void onLongPress(MotionEvent e) {
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnGestureListener
    public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
        if (this.scale != 1.0f) {
            this.scroller.abortAnimation();
            this.scroller.fling(Math.round(this.translationX), Math.round(this.translationY), Math.round(velocityX), Math.round(velocityY), (int) this.minX, (int) this.maxX, (int) this.minY, (int) this.maxY);
            this.containerView.postInvalidate();
            return false;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnDoubleTapListener
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnDoubleTapListener
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

    @Override // im.uwrkaxlmjj.ui.PhotoViewer, android.view.GestureDetector.OnDoubleTapListener
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
                    if (a >= ImagePreviewActivity.this.compressionsCount) {
                        break;
                    }
                    int i = this.sideSide;
                    int i2 = this.lineSize + (this.gapSize * 2);
                    int i3 = this.circleSize;
                    int cx = i + ((i2 + i3) * a) + (i3 / 2);
                    if (x > cx - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx) {
                        this.startMoving = a == ImagePreviewActivity.this.selectedCompression;
                        this.startX = x;
                        this.startMovingQuality = ImagePreviewActivity.this.selectedCompression;
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
                        if (a2 >= ImagePreviewActivity.this.compressionsCount) {
                            break;
                        }
                        int i4 = this.sideSide;
                        int i5 = this.lineSize;
                        int i6 = this.gapSize;
                        int i7 = this.circleSize;
                        int cx2 = i4 + (((i6 * 2) + i5 + i7) * a2) + (i7 / 2);
                        int diff = (i5 / 2) + (i7 / 2) + i6;
                        if (x > cx2 - diff && x < cx2 + diff) {
                            if (ImagePreviewActivity.this.selectedCompression != a2) {
                                ImagePreviewActivity.this.selectedCompression = a2;
                                ImagePreviewActivity.this.didChangedCompressionLevel(false);
                                invalidate();
                            }
                        } else {
                            a2++;
                        }
                    }
                }
            } else if (event.getAction() == 1 || event.getAction() == 3) {
                if (this.moving) {
                    if (ImagePreviewActivity.this.selectedCompression != this.startMovingQuality) {
                        ImagePreviewActivity.this.requestVideoPreview(1);
                    }
                } else {
                    int a3 = 0;
                    while (true) {
                        if (a3 >= ImagePreviewActivity.this.compressionsCount) {
                            break;
                        }
                        int i8 = this.sideSide;
                        int i9 = this.lineSize + (this.gapSize * 2);
                        int i10 = this.circleSize;
                        int cx3 = i8 + ((i9 + i10) * a3) + (i10 / 2);
                        if (x > cx3 - AndroidUtilities.dp(15.0f) && x < AndroidUtilities.dp(15.0f) + cx3) {
                            if (ImagePreviewActivity.this.selectedCompression != a3) {
                                ImagePreviewActivity.this.selectedCompression = a3;
                                ImagePreviewActivity.this.didChangedCompressionLevel(true);
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
            if (ImagePreviewActivity.this.compressionsCount != 1) {
                this.lineSize = (((getMeasuredWidth() - (this.circleSize * ImagePreviewActivity.this.compressionsCount)) - (this.gapSize * 8)) - (this.sideSide * 2)) / (ImagePreviewActivity.this.compressionsCount - 1);
            } else {
                this.lineSize = ((getMeasuredWidth() - (this.circleSize * ImagePreviewActivity.this.compressionsCount)) - (this.gapSize * 8)) - (this.sideSide * 2);
            }
            int cy = (getMeasuredHeight() / 2) + AndroidUtilities.dp(6.0f);
            int a = 0;
            while (a < ImagePreviewActivity.this.compressionsCount) {
                int i = this.sideSide;
                int i2 = this.lineSize + (this.gapSize * 2);
                int i3 = this.circleSize;
                int cx = i + ((i2 + i3) * a) + (i3 / 2);
                if (a <= ImagePreviewActivity.this.selectedCompression) {
                    this.paint.setColor(-11292945);
                } else {
                    this.paint.setColor(1728053247);
                }
                if (a == ImagePreviewActivity.this.compressionsCount - 1) {
                    text = Math.min(ImagePreviewActivity.this.originalWidth, ImagePreviewActivity.this.originalHeight) + TtmlNode.TAG_P;
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
                canvas.drawCircle(cx, cy, a == ImagePreviewActivity.this.selectedCompression ? AndroidUtilities.dp(8.0f) : this.circleSize / 2, this.paint);
                canvas.drawText(text, cx - (width / 2.0f), cy - AndroidUtilities.dp(16.0f), this.textPaint);
                if (a != 0) {
                    int x = ((cx - (this.circleSize / 2)) - this.gapSize) - this.lineSize;
                    canvas.drawRect(x, cy - AndroidUtilities.dp(1.0f), this.lineSize + x, AndroidUtilities.dp(2.0f) + cy, this.paint);
                }
                a++;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.PhotoViewer
    public void updateMuteButton() {
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.setMute(this.muteVideo);
        }
        if (!this.videoHasAudio) {
            this.muteItem.setEnabled(false);
            this.muteItem.setClickable(false);
            this.muteItem.setAlpha(0.5f);
            return;
        }
        this.muteItem.setEnabled(true);
        this.muteItem.setClickable(true);
        this.muteItem.setAlpha(1.0f);
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
        if (!this.mblnSelectPreview) {
            this.actionBar.setSubtitle(null);
        } else {
            this.actionBar.setSubtitle(this.currentSubtitle);
        }
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
        if (this.mblnSelectPreview) {
            ActionBar actionBar2 = this.actionBar;
            if (this.muteVideo) {
                str = null;
            }
            actionBar2.setSubtitle(str);
            return;
        }
        this.actionBar.setSubtitle(null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void requestVideoPreview(int request) {
        if (this.videoPreviewMessageObject != null) {
            MediaController.getInstance().cancelVideoConvert(this.videoPreviewMessageObject);
        }
        boolean wasRequestingPreview = this.requestingPreview && !this.tryStartRequestPreviewOnFinish;
        this.requestingPreview = false;
        this.loadInitialVideo = false;
        this.progressView.setVisibility(4);
        if (request == 1) {
            if (this.selectedCompression == this.compressionsCount - 1) {
                this.tryStartRequestPreviewOnFinish = false;
                if (!wasRequestingPreview) {
                    preparePlayer(this.currentPlayingVideoFile, false, false);
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
                this.progressView.setVisibility(0);
            }
        } else {
            this.tryStartRequestPreviewOnFinish = false;
            if (request == 2) {
                preparePlayer(this.currentPlayingVideoFile, false, false);
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
            this.resultWidth = Math.round((this.originalWidth * scale) / 2.0f) * 2;
            this.resultHeight = Math.round((this.originalHeight * scale) / 2.0f) * 2;
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
            this.mtvCancel.setVisibility(4);
            this.mtvFinish.setVisibility(4);
            this.qualityChooseView.setTag(1);
            this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(152.0f)), ObjectAnimator.ofFloat(this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(152.0f)), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f), AndroidUtilities.dp(104.0f)));
        } else {
            this.mtvCancel.setVisibility(0);
            this.mtvFinish.setVisibility(0);
            this.qualityChooseView.setTag(null);
            this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(this.qualityChooseView, (Property<QualityChooseView, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(166.0f)), ObjectAnimator.ofFloat(this.qualityPicker, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, 0.0f, AndroidUtilities.dp(166.0f)), ObjectAnimator.ofFloat(this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f), AndroidUtilities.dp(118.0f)));
        }
        this.qualityChooseViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.46
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(ImagePreviewActivity.this.qualityChooseViewAnimation)) {
                    ImagePreviewActivity.this.qualityChooseViewAnimation = new AnimatorSet();
                    if (show) {
                        ImagePreviewActivity.this.qualityChooseView.setVisibility(0);
                        ImagePreviewActivity.this.qualityPicker.setVisibility(0);
                        ImagePreviewActivity.this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this.qualityChooseView, (Property<QualityChooseView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.qualityPicker, (Property<PickerBottomLayoutViewer, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)));
                    } else {
                        ImagePreviewActivity.this.qualityChooseView.setVisibility(4);
                        ImagePreviewActivity.this.qualityPicker.setVisibility(4);
                        ImagePreviewActivity.this.qualityChooseViewAnimation.playTogether(ObjectAnimator.ofFloat(ImagePreviewActivity.this.pickerView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.pickerViewSendButton, (Property<ImageView, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(ImagePreviewActivity.this.bottomLayout, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)));
                    }
                    ImagePreviewActivity.this.qualityChooseViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity.46.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation2) {
                            if (animation2.equals(ImagePreviewActivity.this.qualityChooseViewAnimation)) {
                                ImagePreviewActivity.this.qualityChooseViewAnimation = null;
                            }
                        }
                    });
                    ImagePreviewActivity.this.qualityChooseViewAnimation.setDuration(200L);
                    ImagePreviewActivity.this.qualityChooseViewAnimation.setInterpolator(new AccelerateInterpolator());
                    ImagePreviewActivity.this.qualityChooseViewAnimation.start();
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                ImagePreviewActivity.this.qualityChooseViewAnimation = null;
            }
        });
        this.qualityChooseViewAnimation.setDuration(200L);
        this.qualityChooseViewAnimation.setInterpolator(new DecelerateInterpolator());
        this.qualityChooseViewAnimation.start();
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
        AnonymousClass47 anonymousClass47 = new AnonymousClass47(videoPath);
        this.currentLoadingVideoRunnable = anonymousClass47;
        dispatchQueue.postRunnable(anonymousClass47);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreviewActivity$47, reason: invalid class name */
    class AnonymousClass47 implements Runnable {
        final /* synthetic */ String val$videoPath;

        AnonymousClass47(String str) {
            this.val$videoPath = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (ImagePreviewActivity.this.currentLoadingVideoRunnable != this) {
                return;
            }
            final int[] params = new int[9];
            AnimatedFileDrawable.getVideoInfo(this.val$videoPath, params);
            if (ImagePreviewActivity.this.currentLoadingVideoRunnable == this) {
                ImagePreviewActivity.this.currentLoadingVideoRunnable = null;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$47$7bRDJ3aDGkceYu4Tc0hh3f-eJa8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$0$ImagePreviewActivity$47(params);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$run$0$ImagePreviewActivity$47(int[] params) {
            if (ImagePreviewActivity.this.parentActivity == null) {
                return;
            }
            ImagePreviewActivity.this.videoHasAudio = params[0] != 0;
            ImagePreviewActivity.this.audioFramesSize = params[5];
            ImagePreviewActivity.this.videoFramesSize = params[6];
            ImagePreviewActivity.this.videoDuration = params[4];
            ImagePreviewActivity imagePreviewActivity = ImagePreviewActivity.this;
            imagePreviewActivity.originalBitrate = imagePreviewActivity.bitrate = params[3];
            ImagePreviewActivity.this.videoFramerate = params[7];
            if (ImagePreviewActivity.this.bitrate > 900000) {
                ImagePreviewActivity.this.bitrate = 900000;
            }
            ImagePreviewActivity.this.videoHasAudio = true;
            if (ImagePreviewActivity.this.videoHasAudio) {
                ImagePreviewActivity.this.rotationValue = params[8];
                ImagePreviewActivity imagePreviewActivity2 = ImagePreviewActivity.this;
                imagePreviewActivity2.resultWidth = imagePreviewActivity2.originalWidth = params[1];
                ImagePreviewActivity imagePreviewActivity3 = ImagePreviewActivity.this;
                imagePreviewActivity3.resultHeight = imagePreviewActivity3.originalHeight = params[2];
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                ImagePreviewActivity.this.selectedCompression = preferences.getInt("compress_video2", 1);
                if (ImagePreviewActivity.this.originalWidth > 1280 || ImagePreviewActivity.this.originalHeight > 1280) {
                    ImagePreviewActivity.this.compressionsCount = 5;
                } else if (ImagePreviewActivity.this.originalWidth > 854 || ImagePreviewActivity.this.originalHeight > 854) {
                    ImagePreviewActivity.this.compressionsCount = 4;
                } else if (ImagePreviewActivity.this.originalWidth > 640 || ImagePreviewActivity.this.originalHeight > 640) {
                    ImagePreviewActivity.this.compressionsCount = 3;
                } else if (ImagePreviewActivity.this.originalWidth > 480 || ImagePreviewActivity.this.originalHeight > 480) {
                    ImagePreviewActivity.this.compressionsCount = 2;
                } else {
                    ImagePreviewActivity.this.compressionsCount = 1;
                }
                ImagePreviewActivity.this.updateWidthHeightBitrateForCompression();
                ImagePreviewActivity imagePreviewActivity4 = ImagePreviewActivity.this;
                imagePreviewActivity4.setCompressItemEnabled(imagePreviewActivity4.compressionsCount > 1, true);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("compressionsCount = " + ImagePreviewActivity.this.compressionsCount + " w = " + ImagePreviewActivity.this.originalWidth + " h = " + ImagePreviewActivity.this.originalHeight);
                }
                if (Build.VERSION.SDK_INT < 18 && ImagePreviewActivity.this.compressItem.getTag() != null) {
                    try {
                        MediaCodecInfo codecInfo = MediaController.selectCodec("video/avc");
                        if (codecInfo == null) {
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("no codec info for video/avc");
                            }
                            ImagePreviewActivity.this.setCompressItemEnabled(false, true);
                        } else {
                            String name = codecInfo.getName();
                            if (name.equals("OMX.google.h264.encoder") || name.equals("OMX.ST.VFM.H264Enc") || name.equals("OMX.Exynos.avc.enc") || name.equals("OMX.MARVELL.VIDEO.HW.CODA7542ENCODER") || name.equals("OMX.MARVELL.VIDEO.H264ENCODER") || name.equals("OMX.k3.video.encoder.avc") || name.equals("OMX.TI.DUCATI1.VIDEO.H264E")) {
                                if (BuildVars.LOGS_ENABLED) {
                                    FileLog.d("unsupported encoder = " + name);
                                }
                                ImagePreviewActivity.this.setCompressItemEnabled(false, true);
                            } else if (MediaController.selectColorFormat(codecInfo, "video/avc") == 0) {
                                if (BuildVars.LOGS_ENABLED) {
                                    FileLog.d("no color format for video/avc");
                                }
                                ImagePreviewActivity.this.setCompressItemEnabled(false, true);
                            }
                        }
                    } catch (Exception e) {
                        ImagePreviewActivity.this.setCompressItemEnabled(false, true);
                        FileLog.e(e);
                    }
                }
                ImagePreviewActivity.this.qualityChooseView.invalidate();
            } else {
                ImagePreviewActivity.this.compressionsCount = 0;
            }
            ImagePreviewActivity.this.updateVideoInfo();
            ImagePreviewActivity.this.updateMuteButton();
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
            if (ImagePreviewActivity.this.placeProvider != null && ImagePreviewActivity.this.placeProvider.getSelectedPhotosOrder() != null) {
                return ImagePreviewActivity.this.placeProvider.getSelectedPhotosOrder().size();
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            PhotoPickerPhotoCell cell = new PhotoPickerPhotoCell(this.mContext, false);
            cell.checkFrame.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ImagePreviewActivity$ListAdapter$KPS3-_rkKyQn7H3IKZddlcS_Qr4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onCreateViewHolder$0$ImagePreviewActivity$ListAdapter(view);
                }
            });
            return new RecyclerListView.Holder(cell);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$ImagePreviewActivity$ListAdapter(View v) {
            Object photoEntry = ((View) v.getParent()).getTag();
            int idx = ImagePreviewActivity.this.imagesArrLocals.indexOf(photoEntry);
            if (idx >= 0) {
                int num = ImagePreviewActivity.this.placeProvider.setPhotoChecked(idx, ImagePreviewActivity.this.getCurrentVideoEditedInfo());
                ImagePreviewActivity.this.placeProvider.isPhotoChecked(idx);
                if (idx == ImagePreviewActivity.this.currentIndex) {
                    ImagePreviewActivity.this.checkImageView.setChecked(-1, false, true);
                }
                if (num >= 0) {
                    ImagePreviewActivity.this.selectedPhotosAdapter.notifyItemRemoved(num);
                }
                ImagePreviewActivity.this.updateSelectedCount();
                return;
            }
            int num2 = ImagePreviewActivity.this.placeProvider.setPhotoUnchecked(photoEntry);
            if (num2 >= 0) {
                ImagePreviewActivity.this.selectedPhotosAdapter.notifyItemRemoved(num2);
                ImagePreviewActivity.this.updateSelectedCount();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            PhotoPickerPhotoCell cell = (PhotoPickerPhotoCell) holder.itemView;
            cell.itemWidth = AndroidUtilities.dp(82.0f);
            BackupImageView imageView = cell.imageView;
            imageView.setOrientation(0, true);
            ArrayList<Object> order = ImagePreviewActivity.this.placeProvider.getSelectedPhotosOrder();
            Object object = ImagePreviewActivity.this.placeProvider.getSelectedPhotos().get(order.get(position));
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

    public void setSelectPreviewMode(boolean blnMode) {
        this.mblnSelectPreview = blnMode;
    }

    public void setCurrentSelectMediaType(boolean showSingleType, int selectedMediaType) {
        this.selectSameMediaType = showSingleType;
        this.selectedMediaType = selectedMediaType;
    }
}
