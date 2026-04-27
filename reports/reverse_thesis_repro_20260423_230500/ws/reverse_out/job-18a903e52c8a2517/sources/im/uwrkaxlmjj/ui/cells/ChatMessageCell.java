package im.uwrkaxlmjj.ui.cells;

import android.R;
import android.animation.TypeEvaluator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.Layout;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.CharacterStyle;
import android.text.style.ClickableSpan;
import android.text.style.URLSpan;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.SparseArray;
import android.util.StateSet;
import android.view.Display;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStructure;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import android.widget.RelativeLayout;
import com.blankj.utilcode.util.TimeUtils;
import com.google.android.exoplayer2.C;
import com.google.android.gms.common.internal.ImagesContract;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
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
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.WebFile;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.SecretMediaViewer;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AnimatedFileDrawable;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.CheckBoxBase;
import im.uwrkaxlmjj.ui.components.LinkPath;
import im.uwrkaxlmjj.ui.components.RadialProgress2;
import im.uwrkaxlmjj.ui.components.RoundVideoPlayingDrawable;
import im.uwrkaxlmjj.ui.components.SeekBar;
import im.uwrkaxlmjj.ui.components.SeekBarWaveform;
import im.uwrkaxlmjj.ui.components.StaticLayoutEx;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;
import im.uwrkaxlmjj.ui.components.TypefaceSpan;
import im.uwrkaxlmjj.ui.components.URLSpanBotCommand;
import im.uwrkaxlmjj.ui.components.URLSpanBrowser;
import im.uwrkaxlmjj.ui.components.URLSpanMono;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ChatMessageCell extends BaseCell implements SeekBar.SeekBarDelegate, ImageReceiver.ImageReceiverDelegate, DownloadController.FileDownloadProgressListener, NotificationCenter.NotificationCenterDelegate {
    private static final int DOCUMENT_ATTACH_TYPE_AUDIO = 3;
    private static final int DOCUMENT_ATTACH_TYPE_DOCUMENT = 1;
    private static final int DOCUMENT_ATTACH_TYPE_GIF = 2;
    private static final int DOCUMENT_ATTACH_TYPE_MUSIC = 5;
    private static final int DOCUMENT_ATTACH_TYPE_NONE = 0;
    private static final int DOCUMENT_ATTACH_TYPE_ROUND = 7;
    private static final int DOCUMENT_ATTACH_TYPE_STICKER = 6;
    private static final int DOCUMENT_ATTACH_TYPE_THEME = 9;
    private static final int DOCUMENT_ATTACH_TYPE_VIDEO = 4;
    private static final int DOCUMENT_ATTACH_TYPE_WALLPAPER = 8;
    private static final int mOffset = AndroidUtilities.dp(4.5f);
    private int TAG;
    private SparseArray<Rect> accessibilityVirtualViewBounds;
    private int addedCaptionHeight;
    private boolean addedForTest;
    private StaticLayout adminLayout;
    private boolean allowAssistant;
    private boolean animatePollAnswer;
    private boolean animatePollAnswerAlpha;
    private int animatingDrawVideoImageButton;
    private float animatingDrawVideoImageButtonProgress;
    private int animatingNoSound;
    private boolean animatingNoSoundPlaying;
    private float animatingNoSoundProgress;
    private boolean attachedToWindow;
    private StaticLayout authorLayout;
    private int authorX;
    private boolean autoPlayingMedia;
    private int availableTimeWidth;
    private AvatarDrawable avatarDrawable;
    private ImageReceiver avatarImage;
    private boolean avatarPressed;
    private int backgroundDrawableLeft;
    private int backgroundDrawableRight;
    private int backgroundWidth;
    private boolean blnAttachFileLoaded;
    private boolean blnImgExchanged;
    private ArrayList<BotButton> botButtons;
    private HashMap<String, BotButton> botButtonsByData;
    private HashMap<String, BotButton> botButtonsByPosition;
    private String botButtonsLayout;
    private boolean bottomNearToSet;
    private int buttonPressed;
    private int buttonState;
    private int buttonX;
    private int buttonY;
    private boolean canStreamVideo;
    private boolean cancelLoading;
    private int captionHeight;
    private StaticLayout captionLayout;
    private int captionOffsetX;
    private int captionWidth;
    private int captionX;
    private int captionY;
    private CheckBoxBase checkBox;
    private boolean checkBoxAnimationInProgress;
    private float checkBoxAnimationProgress;
    private int checkBoxTranslation;
    private boolean checkBoxVisible;
    private boolean checkOnlyButtonPressed;
    private boolean clickSysNotifyItem;
    private int clickSysNotifyPhotoImageViewIndex;
    private boolean clickSysNotifyVideoView;
    private AvatarDrawable contactAvatarDrawable;
    private float controlsAlpha;
    private int currentAccount;
    private Drawable currentBackgroundDrawable;
    private CharSequence currentCaption;
    private TLRPC.Chat currentChat;
    private int currentFocusedVirtualView;
    private TLRPC.Chat currentForwardChannel;
    private String currentForwardName;
    private String currentForwardNameString;
    private TLRPC.User currentForwardUser;
    private int currentMapProvider;
    private MessageObject currentMessageObject;
    private MessageObject.GroupedMessages currentMessagesGroup;
    private String currentNameString;
    private TLRPC.FileLocation currentPhoto;
    private String currentPhotoFilter;
    private String currentPhotoFilterThumb;
    private TLRPC.PhotoSize currentPhotoObject;
    private TLRPC.PhotoSize currentPhotoObjectThumb;
    private MessageObject.GroupedMessagePosition currentPosition;
    private TLRPC.PhotoSize currentReplyPhoto;
    private String currentTimeString;
    private String currentUrl;
    private TLRPC.User currentUser;
    private TLRPC.User currentViaBotUser;
    private String currentViewsString;
    private WebFile currentWebFile;
    private ChatMessageCellDelegate delegate;
    private RectF deleteProgressRect;
    private StaticLayout descriptionLayout;
    private int descriptionX;
    private int descriptionY;
    private boolean disallowLongPress;
    private StaticLayout docTitleLayout;
    private int docTitleOffsetX;
    private int docTitleWidth;
    private TLRPC.Document documentAttach;
    private int documentAttachType;
    private boolean drawBackground;
    private boolean drawForwardedName;
    private boolean drawImageButton;
    private boolean drawInstantView;
    private int drawInstantViewType;
    private boolean drawJoinChannelView;
    private boolean drawJoinGroupView;
    private boolean drawName;
    private boolean drawNameLayout;
    private boolean drawPhotoCheckBox;
    private boolean drawPhotoImage;
    private boolean drawPinnedBottom;
    private boolean drawPinnedTop;
    private boolean drawRadialCheckBackground;
    private boolean drawSelectionBackground;
    private boolean drawShareButton;
    private boolean drawTime;
    private boolean drawVideoImageButton;
    private boolean drawVideoSize;
    private boolean drwaShareGoIcon;
    private StaticLayout durationLayout;
    private int durationWidth;
    private boolean firstCircleLength;
    private int firstVisibleBlockNum;
    private boolean forceNotDrawTime;
    private boolean forwardBotPressed;
    private boolean forwardName;
    private int forwardNameCenterX;
    private float[] forwardNameOffsetX;
    private boolean forwardNamePressed;
    private int forwardNameX;
    private int forwardNameY;
    private StaticLayout[] forwardedNameLayout;
    private int forwardedNameWidth;
    private boolean fullyDraw;
    private boolean gamePreviewPressed;
    private boolean groupPhotoInvisible;
    private MessageObject.GroupedMessages groupedMessagesToSet;
    private boolean hasEmbed;
    private boolean hasGamePreview;
    private boolean hasInvoicePreview;
    private boolean hasLinkPreview;
    private int hasMiniProgress;
    private boolean hasNewLineForTime;
    private boolean hasOldCaptionPreview;
    private int highlightProgress;
    private int imageBackgroundColor;
    private int imageBackgroundSideColor;
    private int imageBackgroundSideWidth;
    private boolean imagePressed;
    private boolean inLayout;
    private StaticLayout infoLayout;
    private int infoWidth;
    private int infoX;
    private boolean instantButtonPressed;
    private RectF instantButtonRect;
    private boolean instantPressed;
    private int instantTextLeftX;
    private int instantTextX;
    private StaticLayout instantViewLayout;
    private int instantWidth;
    private Runnable invalidateRunnable;
    private boolean invalidatesParent;
    private boolean isAvatarVisible;
    public boolean isChat;
    private boolean isCheckPressed;
    private boolean isFirst;
    private boolean isHighlighted;
    private boolean isHighlightedAnimated;
    private boolean isLast;
    public boolean isMegagroup;
    private boolean isPressed;
    private boolean isSmallImage;
    private int keyboardHeight;
    private long lastAnimationTime;
    private long lastCheckBoxAnimationTime;
    private long lastControlsAlphaChangeTime;
    private int lastDeleteDate;
    private int lastHeight;
    private long lastHighlightProgressTime;
    private TLRPC.TL_poll lastPoll;
    private ArrayList<TLRPC.TL_pollAnswerVoters> lastPollResults;
    private int lastPollResultsVoters;
    private TLRPC.TL_messageReactions lastReactions;
    private int lastSendState;
    private int lastTime;
    private float lastTouchX;
    private float lastTouchY;
    private String lastTranslate;
    private int lastViewsCount;
    private int lastVisibleBlockNum;
    private int layoutHeight;
    private int layoutWidth;
    private View line;
    private int linkBlockNum;
    private int linkPreviewHeight;
    private boolean linkPreviewPressed;
    private int linkSelectionBlockNum;
    private boolean locationExpired;
    private ImageReceiver locationImageReceiver;
    private BaseFragment mBaseFragment;
    private Map<Integer, TLRPCContacts.NotifyMsg> mSysNotifyData;
    private int measuredAtWidth;
    private boolean mediaBackground;
    private int mediaOffsetY;
    private boolean mediaWasInvisible;
    private MessageObject messageObjectToSet;
    private int miniButtonPressed;
    private int miniButtonState;
    private StaticLayout nameLayout;
    private float nameOffsetX;
    private int nameWidth;
    private float nameX;
    private float nameY;
    private int namesOffset;
    private boolean needNewVisiblePart;
    private boolean needReplyImage;
    private int noSoundCenterX;
    private boolean otherPressed;
    private int otherX;
    private int otherY;
    private StaticLayout performerLayout;
    private int performerX;
    private float photo1Height;
    private float photo2Height;
    private float photo3Height;
    private float photo4Height;
    private float photo5Height;
    private CheckBoxBase photoCheckBox;
    private ImageReceiver photoFCImage;
    private ImageReceiver photoImage;
    public ImageReceiver photoImage1;
    public ImageReceiver photoImage2;
    public ImageReceiver photoImage3;
    public ImageReceiver photoImage4;
    public ImageReceiver photoImage5;
    private boolean photoNotSet;
    private TLObject photoParentObject;
    private StaticLayout photosCountLayout;
    private int photosCountWidth;
    private boolean pinnedBottom;
    private boolean pinnedTop;
    private float pollAnimationProgress;
    private float pollAnimationProgressTime;
    private ArrayList<PollButton> pollButtons;
    private boolean pollClosed;
    private boolean pollUnvoteInProgress;
    private boolean pollVoteInProgress;
    private int pollVoteInProgressNum;
    private boolean pollVoted;
    private int pressedBotButton;
    private CharacterStyle pressedLink;
    private int pressedLinkType;
    private int[] pressedState;
    private int pressedVoteButton;
    private RadialProgress2 radialProgress;
    private int radius;
    private RectF rect;
    private ImageReceiver replyImageReceiver;
    private StaticLayout replyNameLayout;
    private float replyNameOffset;
    private int replyNameWidth;
    private boolean replyPressed;
    private int replyStartX;
    private int replyStartY;
    private StaticLayout replyTextLayout;
    private float replyTextOffset;
    private int replyTextWidth;
    private RelativeLayout rlContainer;
    private RoundVideoPlayingDrawable roundVideoPlayingDrawable;
    private boolean scheduledInvalidate;
    private int[] screenSize;
    private Rect scrollRect;
    private SeekBar seekBar;
    private SeekBarWaveform seekBarWaveform;
    private int seekBarX;
    private int seekBarY;
    private Drawable selectorDrawable;
    private int selectorDrawableMaskType;
    private boolean sharePressed;
    private int shareStartX;
    private int shareStartY;
    private StaticLayout siteNameLayout;
    private boolean siteNameRtl;
    private int siteNameWidth;
    private StaticLayout songLayout;
    private int songX;
    private int substractBackgroundHeight;
    private StaticLayout textInfoLayout1;
    private StaticLayout textInfoLayout2;
    private StaticLayout textInfoLayout3;
    private StaticLayout textInfoLayout4;
    private StaticLayout textInfoLayout5;
    private int textX;
    private int textY;
    private float timeAlpha;
    private int timeAudioX;
    private StaticLayout timeLayout;
    private int timeTextWidth;
    private boolean timeWasInvisible;
    private int timeWidth;
    private int timeWidthAudio;
    private int timeX;
    private StaticLayout titleLayout;
    private int titleX;
    private boolean topNearToSet;
    private long totalChangeTime;
    private int totalHeight;
    private int totalVisibleBlocksCount;
    private Drawable transDrawable;
    private long transLastTime;
    private StaticLayout transLayout;
    private StaticLayout transLayoutDesc;
    private int transLoadingRencntcount;
    private int unmovedTextX;
    private ArrayList<LinkPath> urlPath;
    private ArrayList<LinkPath> urlPathCache;
    private ArrayList<LinkPath> urlPathSelection;
    private boolean useSeekBarWaweform;
    private int viaNameWidth;
    private TypefaceSpan viaSpan1;
    private TypefaceSpan viaSpan2;
    private int viaWidth;
    private int videoButtonPressed;
    private int videoButtonX;
    private int videoButtonY;
    private StaticLayout videoInfoLayout;
    private RadialProgress2 videoRadialProgress;
    private StaticLayout viewsLayout;
    private int viewsTextWidth;
    private float voteCurrentCircleLength;
    private float voteCurrentProgressTime;
    private long voteLastUpdateTime;
    private float voteRadOffset;
    private boolean voteRisingCircleLength;
    private boolean wasLayout;
    private boolean wasSending;
    private int widthBeforeNewTimeLine;
    private int widthForButtons;

    @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
    public /* synthetic */ void onSeekBarContinuousDrag(float f) {
        SeekBar.SeekBarDelegate.CC.$default$onSeekBarContinuousDrag(this, f);
    }

    public int getClickSysNotifyPhotoImageViewIndex() {
        return this.clickSysNotifyPhotoImageViewIndex;
    }

    public boolean isClickSysNotifyItem() {
        return this.clickSysNotifyItem;
    }

    public void setIsFirstOrLast(boolean isFirst, boolean isLast) {
        this.isFirst = isFirst;
        this.isLast = isLast;
    }

    public static int[] getRawScreenSize(Context context) {
        int[] size = new int[2];
        WindowManager w = (WindowManager) context.getSystemService("window");
        Display d = w.getDefaultDisplay();
        DisplayMetrics metrics = new DisplayMetrics();
        d.getMetrics(metrics);
        int widthPixels = metrics.widthPixels;
        int heightPixels = metrics.heightPixels;
        if (Build.VERSION.SDK_INT >= 14 && Build.VERSION.SDK_INT < 17) {
            try {
                widthPixels = ((Integer) Display.class.getMethod("getRawWidth", new Class[0]).invoke(d, new Object[0])).intValue();
                heightPixels = ((Integer) Display.class.getMethod("getRawHeight", new Class[0]).invoke(d, new Object[0])).intValue();
            } catch (Exception e) {
            }
        }
        if (Build.VERSION.SDK_INT >= 17) {
            try {
                Point realSize = new Point();
                Display.class.getMethod("getRealSize", Point.class).invoke(d, realSize);
                widthPixels = realSize.x;
                heightPixels = realSize.y;
            } catch (Exception e2) {
            }
        }
        size[0] = widthPixels;
        size[1] = heightPixels;
        return size;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidLoad) {
            File fine = (File) args[1];
            File f = null;
            if (this.currentMessageObject.messageOwner.attachPath != null && this.currentMessageObject.messageOwner.attachPath.length() != 0) {
                f = new File(this.currentMessageObject.messageOwner.attachPath);
            }
            if (f == null || !f.exists()) {
                f = FileLoader.getPathToMessage(this.currentMessageObject.messageOwner);
            }
            if (fine.getPath().equals(f.getPath())) {
                this.blnAttachFileLoaded = true;
                setMessageObject(this.currentMessageObject, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
            }
        }
    }

    public interface ChatMessageCellDelegate {
        boolean canPerformActions();

        void didLongPress(ChatMessageCell chatMessageCell, float f, float f2);

        void didLongPressUserAvatar(ChatMessageCell chatMessageCell, TLRPC.User user, float f, float f2);

        void didPressBotButton(ChatMessageCell chatMessageCell, TLRPC.KeyboardButton keyboardButton);

        void didPressCancelSendButton(ChatMessageCell chatMessageCell);

        void didPressChannelAvatar(ChatMessageCell chatMessageCell, TLRPC.Chat chat, int i, float f, float f2);

        void didPressHiddenForward(ChatMessageCell chatMessageCell);

        void didPressImage(ChatMessageCell chatMessageCell, float f, float f2);

        void didPressInstantButton(ChatMessageCell chatMessageCell, int i);

        void didPressOther(ChatMessageCell chatMessageCell, float f, float f2);

        void didPressReaction(ChatMessageCell chatMessageCell, TLRPC.TL_reactionCount tL_reactionCount);

        void didPressRedpkgTransfer(ChatMessageCell chatMessageCell, MessageObject messageObject);

        void didPressReplyMessage(ChatMessageCell chatMessageCell, int i);

        void didPressShare(ChatMessageCell chatMessageCell);

        void didPressSysNotifyVideoFullPlayer(ChatMessageCell chatMessageCell);

        void didPressUrl(ChatMessageCell chatMessageCell, CharacterStyle characterStyle, boolean z);

        void didPressUserAvatar(ChatMessageCell chatMessageCell, TLRPC.User user, float f, float f2);

        void didPressViaBot(ChatMessageCell chatMessageCell, String str);

        void didPressVoteButton(ChatMessageCell chatMessageCell, TLRPC.TL_pollAnswer tL_pollAnswer);

        void didStartVideoStream(MessageObject messageObject);

        String getAdminRank(int i);

        void needOpenWebView(String str, String str2, String str3, String str4, int i, int i2);

        boolean needPlayMessage(MessageObject messageObject);

        void setShouldNotRepeatSticker(MessageObject messageObject);

        boolean shouldRepeatSticker(MessageObject messageObject);

        void videoTimerReached();

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.cells.ChatMessageCell$ChatMessageCellDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$didPressRedpkgTransfer(ChatMessageCellDelegate _this, ChatMessageCell cell, MessageObject object) {
            }

            public static void $default$didPressUserAvatar(ChatMessageCellDelegate _this, ChatMessageCell cell, TLRPC.User user, float touchX, float touchY) {
            }

            public static void $default$didLongPressUserAvatar(ChatMessageCellDelegate _this, ChatMessageCell cell, TLRPC.User user, float touchX, float touchY) {
            }

            public static void $default$didPressHiddenForward(ChatMessageCellDelegate _this, ChatMessageCell cell) {
            }

            public static void $default$didPressViaBot(ChatMessageCellDelegate _this, ChatMessageCell cell, String username) {
            }

            public static void $default$didPressChannelAvatar(ChatMessageCellDelegate _this, ChatMessageCell cell, TLRPC.Chat chat, int postId, float touchX, float touchY) {
            }

            public static void $default$didPressCancelSendButton(ChatMessageCellDelegate _this, ChatMessageCell cell) {
            }

            public static void $default$didLongPress(ChatMessageCellDelegate _this, ChatMessageCell cell, float x, float y) {
            }

            public static void $default$didPressReplyMessage(ChatMessageCellDelegate _this, ChatMessageCell cell, int id) {
            }

            public static void $default$didPressUrl(ChatMessageCellDelegate _this, ChatMessageCell cell, CharacterStyle url, boolean longPress) {
            }

            public static void $default$needOpenWebView(ChatMessageCellDelegate _this, String url, String title, String description, String originalUrl, int w, int h) {
            }

            public static void $default$didPressImage(ChatMessageCellDelegate _this, ChatMessageCell cell, float x, float y) {
            }

            public static void $default$didPressShare(ChatMessageCellDelegate _this, ChatMessageCell cell) {
            }

            public static void $default$didPressOther(ChatMessageCellDelegate _this, ChatMessageCell cell, float otherX, float otherY) {
            }

            public static void $default$didPressBotButton(ChatMessageCellDelegate _this, ChatMessageCell cell, TLRPC.KeyboardButton button) {
            }

            public static void $default$didPressReaction(ChatMessageCellDelegate _this, ChatMessageCell cell, TLRPC.TL_reactionCount reaction) {
            }

            public static void $default$didPressVoteButton(ChatMessageCellDelegate _this, ChatMessageCell cell, TLRPC.TL_pollAnswer button) {
            }

            public static void $default$didPressInstantButton(ChatMessageCellDelegate _this, ChatMessageCell cell, int type) {
            }

            public static String $default$getAdminRank(ChatMessageCellDelegate _this, int uid) {
                return null;
            }

            public static boolean $default$needPlayMessage(ChatMessageCellDelegate _this, MessageObject messageObject) {
                return false;
            }

            public static boolean $default$canPerformActions(ChatMessageCellDelegate _this) {
                return false;
            }

            public static void $default$videoTimerReached(ChatMessageCellDelegate _this) {
            }

            public static void $default$didStartVideoStream(ChatMessageCellDelegate _this, MessageObject message) {
            }

            public static boolean $default$shouldRepeatSticker(ChatMessageCellDelegate _this, MessageObject message) {
                return true;
            }

            public static void $default$setShouldNotRepeatSticker(ChatMessageCellDelegate _this, MessageObject message) {
            }

            public static void $default$didPressSysNotifyVideoFullPlayer(ChatMessageCellDelegate _this, ChatMessageCell cell) {
            }
        }
    }

    private class BotButton {
        private int angle;
        private TLRPC.KeyboardButton button;
        private int height;
        private long lastUpdateTime;
        private float progressAlpha;
        private TLRPC.TL_reactionCount reaction;
        private StaticLayout title;
        private int width;
        private int x;
        private int y;

        private BotButton() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class PollButton {
        private TLRPC.TL_pollAnswer answer;
        private float decimal;
        private int height;
        private int percent;
        private float percentProgress;
        private int prevPercent;
        private float prevPercentProgress;
        private StaticLayout title;
        private int x;
        private int y;

        private PollButton() {
        }
    }

    public ChatMessageCell(Context context) {
        super(context);
        this.scrollRect = new Rect();
        this.instantButtonRect = new RectF();
        this.pressedState = new int[]{R.attr.state_enabled, R.attr.state_pressed};
        this.deleteProgressRect = new RectF();
        this.rect = new RectF();
        this.timeAlpha = 1.0f;
        this.controlsAlpha = 1.0f;
        this.urlPathCache = new ArrayList<>();
        this.urlPath = new ArrayList<>();
        this.urlPathSelection = new ArrayList<>();
        this.pollButtons = new ArrayList<>();
        this.botButtons = new ArrayList<>();
        this.botButtonsByData = new HashMap<>();
        this.botButtonsByPosition = new HashMap<>();
        this.currentAccount = UserConfig.selectedAccount;
        this.isCheckPressed = true;
        this.drawBackground = true;
        this.backgroundWidth = 100;
        this.forwardedNameLayout = new StaticLayout[2];
        this.forwardNameOffsetX = new float[2];
        this.drawTime = true;
        this.blnImgExchanged = false;
        this.blnAttachFileLoaded = false;
        this.transLoadingRencntcount = 0;
        this.radius = AndroidUtilities.dp(10.0f);
        this.invalidateRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.ChatMessageCell.1
            @Override // java.lang.Runnable
            public void run() {
                ChatMessageCell.this.checkLocationExpired();
                if (ChatMessageCell.this.locationExpired) {
                    ChatMessageCell.this.invalidate();
                    ChatMessageCell.this.scheduledInvalidate = false;
                    return;
                }
                ChatMessageCell.this.invalidate(((int) r0.rect.left) - 5, ((int) ChatMessageCell.this.rect.top) - 5, ((int) ChatMessageCell.this.rect.right) + 5, ((int) ChatMessageCell.this.rect.bottom) + 5);
                if (ChatMessageCell.this.scheduledInvalidate) {
                    AndroidUtilities.runOnUIThread(ChatMessageCell.this.invalidateRunnable, 1000L);
                }
            }
        };
        this.accessibilityVirtualViewBounds = new SparseArray<>();
        this.currentFocusedVirtualView = -1;
        setPadding(0, AndroidUtilities.dp(7.0f), 0, AndroidUtilities.dp(7.0f));
        ImageReceiver imageReceiver = new ImageReceiver();
        this.avatarImage = imageReceiver;
        imageReceiver.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.avatarDrawable = new AvatarDrawable();
        this.replyImageReceiver = new ImageReceiver(this);
        ImageReceiver imageReceiver2 = new ImageReceiver(this);
        this.locationImageReceiver = imageReceiver2;
        imageReceiver2.setRoundRadius(AndroidUtilities.dp(26.1f));
        this.TAG = DownloadController.getInstance(this.currentAccount).generateObserverTag();
        this.contactAvatarDrawable = new AvatarDrawable();
        ImageReceiver imageReceiver3 = new ImageReceiver(this);
        this.photoImage = imageReceiver3;
        imageReceiver3.setDelegate(this);
        this.radialProgress = new RadialProgress2(this);
        RadialProgress2 radialProgress2 = new RadialProgress2(this);
        this.videoRadialProgress = radialProgress2;
        radialProgress2.setDrawBackground(false);
        this.videoRadialProgress.setCircleRadius(AndroidUtilities.dp(15.0f));
        SeekBar seekBar = new SeekBar(context);
        this.seekBar = seekBar;
        seekBar.setDelegate(this);
        SeekBarWaveform seekBarWaveform = new SeekBarWaveform(context);
        this.seekBarWaveform = seekBarWaveform;
        seekBarWaveform.setDelegate(this);
        this.seekBarWaveform.setParentView(this);
        this.roundVideoPlayingDrawable = new RoundVideoPlayingDrawable(this);
        this.screenSize = getRawScreenSize(context);
    }

    public ChatMessageCell(Context context, BaseFragment baseFragment) {
        super(context);
        this.scrollRect = new Rect();
        this.instantButtonRect = new RectF();
        this.pressedState = new int[]{R.attr.state_enabled, R.attr.state_pressed};
        this.deleteProgressRect = new RectF();
        this.rect = new RectF();
        this.timeAlpha = 1.0f;
        this.controlsAlpha = 1.0f;
        this.urlPathCache = new ArrayList<>();
        this.urlPath = new ArrayList<>();
        this.urlPathSelection = new ArrayList<>();
        this.pollButtons = new ArrayList<>();
        this.botButtons = new ArrayList<>();
        this.botButtonsByData = new HashMap<>();
        this.botButtonsByPosition = new HashMap<>();
        this.currentAccount = UserConfig.selectedAccount;
        this.isCheckPressed = true;
        this.drawBackground = true;
        this.backgroundWidth = 100;
        this.forwardedNameLayout = new StaticLayout[2];
        this.forwardNameOffsetX = new float[2];
        this.drawTime = true;
        this.blnImgExchanged = false;
        this.blnAttachFileLoaded = false;
        this.transLoadingRencntcount = 0;
        this.radius = AndroidUtilities.dp(10.0f);
        this.invalidateRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.cells.ChatMessageCell.1
            @Override // java.lang.Runnable
            public void run() {
                ChatMessageCell.this.checkLocationExpired();
                if (ChatMessageCell.this.locationExpired) {
                    ChatMessageCell.this.invalidate();
                    ChatMessageCell.this.scheduledInvalidate = false;
                    return;
                }
                ChatMessageCell.this.invalidate(((int) r0.rect.left) - 5, ((int) ChatMessageCell.this.rect.top) - 5, ((int) ChatMessageCell.this.rect.right) + 5, ((int) ChatMessageCell.this.rect.bottom) + 5);
                if (ChatMessageCell.this.scheduledInvalidate) {
                    AndroidUtilities.runOnUIThread(ChatMessageCell.this.invalidateRunnable, 1000L);
                }
            }
        };
        this.accessibilityVirtualViewBounds = new SparseArray<>();
        this.currentFocusedVirtualView = -1;
        setPadding(0, AndroidUtilities.dp(7.0f), 0, AndroidUtilities.dp(7.0f));
        ImageReceiver imageReceiver = new ImageReceiver();
        this.avatarImage = imageReceiver;
        imageReceiver.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.avatarDrawable = new AvatarDrawable();
        this.replyImageReceiver = new ImageReceiver(this);
        ImageReceiver imageReceiver2 = new ImageReceiver(this);
        this.locationImageReceiver = imageReceiver2;
        imageReceiver2.setRoundRadius(AndroidUtilities.dp(26.1f));
        this.TAG = DownloadController.getInstance(this.currentAccount).generateObserverTag();
        this.contactAvatarDrawable = new AvatarDrawable();
        ImageReceiver imageReceiver3 = new ImageReceiver(this);
        this.photoImage = imageReceiver3;
        imageReceiver3.setDelegate(this);
        this.radialProgress = new RadialProgress2(this);
        RadialProgress2 radialProgress2 = new RadialProgress2(this);
        this.videoRadialProgress = radialProgress2;
        radialProgress2.setDrawBackground(false);
        this.videoRadialProgress.setCircleRadius(AndroidUtilities.dp(15.0f));
        SeekBar seekBar = new SeekBar(context);
        this.seekBar = seekBar;
        seekBar.setDelegate(this);
        SeekBarWaveform seekBarWaveform = new SeekBarWaveform(context);
        this.seekBarWaveform = seekBarWaveform;
        seekBarWaveform.setDelegate(this);
        this.seekBarWaveform.setParentView(this);
        this.roundVideoPlayingDrawable = new RoundVideoPlayingDrawable(this);
        this.screenSize = getRawScreenSize(context);
        this.mBaseFragment = baseFragment;
    }

    private void resetPressedLink(int type) {
        if (this.pressedLink != null) {
            if (this.pressedLinkType != type && type != -1) {
                return;
            }
            resetUrlPaths(false);
            this.pressedLink = null;
            this.pressedLinkType = -1;
            invalidate();
        }
    }

    private void resetUrlPaths(boolean text) {
        if (text) {
            if (this.urlPathSelection.isEmpty()) {
                return;
            }
            this.urlPathCache.addAll(this.urlPathSelection);
            this.urlPathSelection.clear();
            return;
        }
        if (this.urlPath.isEmpty()) {
            return;
        }
        this.urlPathCache.addAll(this.urlPath);
        this.urlPath.clear();
    }

    private LinkPath obtainNewUrlPath(boolean text) {
        LinkPath linkPath;
        if (!this.urlPathCache.isEmpty()) {
            linkPath = this.urlPathCache.get(0);
            this.urlPathCache.remove(0);
        } else {
            linkPath = new LinkPath();
        }
        linkPath.reset();
        if (text) {
            this.urlPathSelection.add(linkPath);
        } else {
            this.urlPath.add(linkPath);
        }
        return linkPath;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int[] getRealSpanStartAndEnd(Spannable buffer, CharacterStyle link) {
        int start = 0;
        int end = 0;
        boolean ok = false;
        if (link instanceof URLSpanBrowser) {
            URLSpanBrowser span = (URLSpanBrowser) link;
            TextStyleSpan.TextStyleRun style = span.getStyle();
            if (style != null && style.urlEntity != null) {
                start = style.urlEntity.offset;
                end = style.urlEntity.offset + style.urlEntity.length;
                ok = true;
            }
        }
        if (!ok) {
            start = buffer.getSpanStart(link);
            end = buffer.getSpanEnd(link);
        }
        return new int[]{start, end};
    }

    /* JADX WARN: Not initialized variable reg: 17, insn: 0x02a6: MOVE (r5 I:??[int, float, boolean, short, byte, char, OBJECT, ARRAY]) = (r17 I:??[int, float, boolean, short, byte, char, OBJECT, ARRAY] A[D('y' int)]), block:B:152:0x02a6 */
    /* JADX WARN: Not initialized variable reg: 18, insn: 0x02a8: MOVE (r4 I:??[int, float, boolean, short, byte, char, OBJECT, ARRAY]) = (r18 I:??[int, float, boolean, short, byte, char, OBJECT, ARRAY] A[D('x' int)]), block:B:152:0x02a6 */
    /* JADX WARN: Removed duplicated region for block: B:153:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x010d A[Catch: Exception -> 0x02c1, TRY_ENTER, TryCatch #12 {Exception -> 0x02c1, blocks: (B:42:0x00a9, B:44:0x00c4, B:46:0x00d0, B:54:0x00f5, B:66:0x010d, B:68:0x0113, B:53:0x00e9), top: B:191:0x00a9 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean checkTextBlockMotionEvent(android.view.MotionEvent r26) {
        /*
            Method dump skipped, instruction units count: 733
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.checkTextBlockMotionEvent(android.view.MotionEvent):boolean");
    }

    private boolean checkCaptionMotionEvent(MotionEvent event) {
        int i;
        boolean ignore;
        if (!(this.currentCaption instanceof Spannable) || this.captionLayout == null) {
            return false;
        }
        if (event.getAction() == 0 || ((this.linkPreviewPressed || this.pressedLink != null) && event.getAction() == 1)) {
            int x = (int) event.getX();
            int y = (int) event.getY();
            int i2 = this.captionX;
            if (x >= i2 && x <= i2 + this.captionWidth && y >= (i = this.captionY) && y <= i + this.captionHeight) {
                if (event.getAction() == 0) {
                    try {
                        int x2 = x - this.captionX;
                        int line = this.captionLayout.getLineForVertical(y - this.captionY);
                        int off = this.captionLayout.getOffsetForHorizontal(line, x2);
                        float left = this.captionLayout.getLineLeft(line);
                        if (left <= x2 && this.captionLayout.getLineWidth(line) + left >= x2) {
                            Spannable buffer = (Spannable) this.currentCaption;
                            CharacterStyle[] link = (CharacterStyle[]) buffer.getSpans(off, off, ClickableSpan.class);
                            CharacterStyle[] link2 = (link == null || link.length == 0) ? (CharacterStyle[]) buffer.getSpans(off, off, URLSpanMono.class) : link;
                            if (link2.length == 0 || (link2.length != 0 && (link2[0] instanceof URLSpanBotCommand) && !URLSpanBotCommand.enabled)) {
                                ignore = true;
                            } else {
                                ignore = false;
                            }
                            if (!ignore) {
                                this.pressedLink = link2[0];
                                this.pressedLinkType = 3;
                                resetUrlPaths(false);
                                try {
                                    LinkPath path = obtainNewUrlPath(false);
                                    int[] pos = getRealSpanStartAndEnd(buffer, this.pressedLink);
                                    path.setCurrentLayout(this.captionLayout, pos[0], 0.0f);
                                    this.captionLayout.getSelectionPath(pos[0], pos[1], path);
                                } catch (Exception e) {
                                    FileLog.e(e);
                                }
                                if (this.currentMessagesGroup != null && getParent() != null) {
                                    ((ViewGroup) getParent()).invalidate();
                                }
                                invalidate();
                                return true;
                            }
                        }
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                } else if (this.pressedLinkType == 3) {
                    this.delegate.didPressUrl(this, this.pressedLink, false);
                    resetPressedLink(3);
                    return true;
                }
            } else {
                resetPressedLink(3);
            }
        }
        return false;
    }

    private boolean checkGameMotionEvent(MotionEvent event) {
        boolean ignore;
        int i;
        int i2;
        if (!this.hasGamePreview) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        if (event.getAction() == 0) {
            if (this.drawPhotoImage && this.drawImageButton && this.buttonState != -1 && x >= (i = this.buttonX) && x <= i + AndroidUtilities.dp(48.0f) && y >= (i2 = this.buttonY) && y <= i2 + AndroidUtilities.dp(48.0f) && this.radialProgress.getIcon() != 4) {
                this.buttonPressed = 1;
                invalidate();
                return true;
            }
            if (this.drawPhotoImage && this.photoImage.isInsideImage(x, y)) {
                this.gamePreviewPressed = true;
                return true;
            }
            if (this.descriptionLayout != null && y >= this.descriptionY) {
                try {
                    int x2 = x - ((this.unmovedTextX + AndroidUtilities.dp(10.0f)) + this.descriptionX);
                    int line = this.descriptionLayout.getLineForVertical(y - this.descriptionY);
                    int off = this.descriptionLayout.getOffsetForHorizontal(line, x2);
                    float left = this.descriptionLayout.getLineLeft(line);
                    if (left <= x2 && this.descriptionLayout.getLineWidth(line) + left >= x2) {
                        Spannable buffer = (Spannable) this.currentMessageObject.linkDescription;
                        ClickableSpan[] link = (ClickableSpan[]) buffer.getSpans(off, off, ClickableSpan.class);
                        if (link.length == 0 || (link.length != 0 && (link[0] instanceof URLSpanBotCommand) && !URLSpanBotCommand.enabled)) {
                            ignore = true;
                        } else {
                            ignore = false;
                        }
                        if (!ignore) {
                            this.pressedLink = link[0];
                            this.linkBlockNum = -10;
                            this.pressedLinkType = 2;
                            resetUrlPaths(false);
                            try {
                                LinkPath path = obtainNewUrlPath(false);
                                int[] pos = getRealSpanStartAndEnd(buffer, this.pressedLink);
                                path.setCurrentLayout(this.descriptionLayout, pos[0], 0.0f);
                                this.descriptionLayout.getSelectionPath(pos[0], pos[1], path);
                            } catch (Exception e) {
                                FileLog.e(e);
                            }
                            invalidate();
                            return true;
                        }
                    }
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
        } else if (event.getAction() == 1) {
            if (this.pressedLinkType == 2 || this.gamePreviewPressed || this.buttonPressed != 0) {
                if (this.buttonPressed != 0) {
                    this.buttonPressed = 0;
                    playSoundEffect(0);
                    didPressButton(true, false);
                    invalidate();
                } else {
                    CharacterStyle characterStyle = this.pressedLink;
                    if (characterStyle != null) {
                        if (characterStyle instanceof URLSpan) {
                            Browser.openUrl(getContext(), ((URLSpan) this.pressedLink).getURL());
                        } else if (characterStyle instanceof ClickableSpan) {
                            ((ClickableSpan) characterStyle).onClick(this);
                        }
                        resetPressedLink(2);
                    } else {
                        this.gamePreviewPressed = false;
                        int a = 0;
                        while (true) {
                            if (a >= this.botButtons.size()) {
                                break;
                            }
                            BotButton button = this.botButtons.get(a);
                            if (!(button.button instanceof TLRPC.TL_keyboardButtonGame)) {
                                a++;
                            } else {
                                playSoundEffect(0);
                                this.delegate.didPressBotButton(this, button.button);
                                invalidate();
                                break;
                            }
                        }
                        resetPressedLink(2);
                        return true;
                    }
                }
            } else {
                resetPressedLink(2);
            }
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:73:0x012b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean checkLinkPreviewMotionEvent(android.view.MotionEvent r18) {
        /*
            Method dump skipped, instruction units count: 956
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.checkLinkPreviewMotionEvent(android.view.MotionEvent):boolean");
    }

    private boolean checkPollButtonMotionEvent(MotionEvent event) {
        Drawable drawable;
        Drawable drawable2;
        Drawable drawable3;
        if (this.currentMessageObject.eventId != 0 || this.pollVoted || this.pollClosed || this.pollVoteInProgress || this.pollUnvoteInProgress || this.pollButtons.isEmpty() || this.currentMessageObject.type != 17 || !this.currentMessageObject.isSent()) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        if (event.getAction() == 0) {
            this.pressedVoteButton = -1;
            for (int a = 0; a < this.pollButtons.size(); a++) {
                PollButton button = this.pollButtons.get(a);
                int y2 = (button.y + this.namesOffset) - AndroidUtilities.dp(13.0f);
                if (x >= button.x && x <= (button.x + this.backgroundWidth) - AndroidUtilities.dp(31.0f) && y >= y2 && y <= button.height + y2 + AndroidUtilities.dp(26.0f)) {
                    this.pressedVoteButton = a;
                    if (Build.VERSION.SDK_INT >= 21 && (drawable3 = this.selectorDrawable) != null) {
                        drawable3.setBounds(button.x - AndroidUtilities.dp(9.0f), y2, (button.x + this.backgroundWidth) - AndroidUtilities.dp(22.0f), button.height + y2 + AndroidUtilities.dp(26.0f));
                        this.selectorDrawable.setState(this.pressedState);
                        this.selectorDrawable.setHotspot(x, y);
                    }
                    invalidate();
                    return true;
                }
            }
            return false;
        }
        if (event.getAction() == 1) {
            if (this.pressedVoteButton == -1) {
                return false;
            }
            playSoundEffect(0);
            if (Build.VERSION.SDK_INT >= 21 && (drawable2 = this.selectorDrawable) != null) {
                drawable2.setState(StateSet.NOTHING);
            }
            if (this.currentMessageObject.scheduled) {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.MessageScheduledVote);
            } else {
                int i = this.pressedVoteButton;
                this.pollVoteInProgressNum = i;
                this.pollVoteInProgress = true;
                this.voteCurrentProgressTime = 0.0f;
                this.firstCircleLength = true;
                this.voteCurrentCircleLength = 360.0f;
                this.voteRisingCircleLength = false;
                this.delegate.didPressVoteButton(this, this.pollButtons.get(i).answer);
            }
            this.pressedVoteButton = -1;
            invalidate();
            return false;
        }
        if (event.getAction() != 2 || this.pressedVoteButton == -1 || Build.VERSION.SDK_INT < 21 || (drawable = this.selectorDrawable) == null) {
            return false;
        }
        drawable.setHotspot(x, y);
        return false;
    }

    private boolean checkInstantButtonMotionEvent(MotionEvent event) {
        Drawable drawable;
        Drawable drawable2;
        Drawable drawable3;
        if (!this.drawInstantView || this.currentMessageObject.type == 0) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        if (event.getAction() == 0) {
            if (this.drawInstantView && this.instantButtonRect.contains(x, y)) {
                this.instantPressed = true;
                if (Build.VERSION.SDK_INT >= 21 && (drawable3 = this.selectorDrawable) != null && drawable3.getBounds().contains(x, y)) {
                    this.selectorDrawable.setState(this.pressedState);
                    this.selectorDrawable.setHotspot(x, y);
                    this.instantButtonPressed = true;
                }
                invalidate();
                return true;
            }
        } else if (event.getAction() == 1) {
            if (this.instantPressed) {
                ChatMessageCellDelegate chatMessageCellDelegate = this.delegate;
                if (chatMessageCellDelegate != null) {
                    chatMessageCellDelegate.didPressInstantButton(this, this.drawInstantViewType);
                }
                playSoundEffect(0);
                if (Build.VERSION.SDK_INT >= 21 && (drawable2 = this.selectorDrawable) != null) {
                    drawable2.setState(StateSet.NOTHING);
                }
                this.instantButtonPressed = false;
                this.instantPressed = false;
                invalidate();
            }
        } else if (event.getAction() == 2 && this.instantButtonPressed && Build.VERSION.SDK_INT >= 21 && (drawable = this.selectorDrawable) != null) {
            drawable.setHotspot(x, y);
        }
        return false;
    }

    private boolean checkRedpkgTransferMotionEvent(MotionEvent event) {
        Drawable drawable;
        ChatMessageCellDelegate chatMessageCellDelegate;
        if (this.currentMessageObject.type != 101 && this.currentMessageObject.type != 102) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        int right = (this.backgroundDrawableLeft + this.backgroundDrawableRight) - AndroidUtilities.dp(8.0f);
        if (event.getAction() == 0) {
            if (x >= this.backgroundDrawableLeft && x <= right && y >= AndroidUtilities.dp(3.0f) && y < this.totalHeight) {
                this.instantPressed = true;
                return true;
            }
        } else if (event.getAction() == 1) {
            if (this.instantPressed && (chatMessageCellDelegate = this.delegate) != null) {
                chatMessageCellDelegate.didPressRedpkgTransfer(this, this.currentMessageObject);
                this.instantPressed = false;
            }
        } else if (event.getAction() == 2 && this.instantButtonPressed && Build.VERSION.SDK_INT >= 21 && (drawable = this.selectorDrawable) != null) {
            drawable.setHotspot(x, y);
        }
        return false;
    }

    private boolean checkOtherButtonMotionEvent(MotionEvent event) {
        int i;
        boolean allow = this.currentMessageObject.type == 16;
        if (!allow) {
            allow = ((this.documentAttachType != 1 && this.currentMessageObject.type != 12 && (i = this.documentAttachType) != 5 && i != 4 && i != 2 && this.currentMessageObject.type != 8) || this.hasGamePreview || this.hasInvoicePreview) ? false : true;
        }
        if (!allow) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        if (event.getAction() == 0) {
            if (this.currentMessageObject.type == 16) {
                int i2 = this.otherX;
                if (x < i2 || x > i2 + AndroidUtilities.dp(200.0f) || y < this.otherY - AndroidUtilities.dp(14.0f) || y > this.otherY + AndroidUtilities.dp(50.0f)) {
                    return false;
                }
                this.otherPressed = true;
                invalidate();
                return true;
            }
            if (x < this.otherX - AndroidUtilities.dp(20.0f) || x > this.otherX + AndroidUtilities.dp(20.0f) || y < this.otherY - AndroidUtilities.dp(4.0f) || y > this.otherY + AndroidUtilities.dp(30.0f)) {
                return false;
            }
            this.otherPressed = true;
            invalidate();
            return true;
        }
        if (event.getAction() != 1 || !this.otherPressed) {
            return false;
        }
        this.otherPressed = false;
        playSoundEffect(0);
        this.delegate.didPressOther(this, this.otherX, this.otherY);
        invalidate();
        return true;
    }

    private boolean checkSysNotifyMotionEvent(MotionEvent event) {
        ChatMessageCellDelegate chatMessageCellDelegate;
        ChatMessageCellDelegate chatMessageCellDelegate2;
        ChatMessageCellDelegate chatMessageCellDelegate3;
        if (this.currentMessageObject.type != 105) {
            return false;
        }
        if (this.currentMessageObject.isOutOwner() && (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing())) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        boolean hasEntities = false;
        TLRPCContacts.TL_messageMediaSysNotify sysNotify = (TLRPCContacts.TL_messageMediaSysNotify) this.currentMessageObject.messageOwner.media;
        if (sysNotify.business_code >= 4 && sysNotify.business_code != 10) {
            int right = (this.backgroundDrawableLeft + this.backgroundDrawableRight) - AndroidUtilities.dp(8.0f);
            int left = this.backgroundDrawableRight - AndroidUtilities.dp(80.0f);
            int clickLeft = this.backgroundDrawableLeft + AndroidUtilities.dp(70.0f);
            int clickRight = this.backgroundDrawableLeft + this.measuredAtWidth + AndroidUtilities.dp(70.0f);
            int clickTop = this.totalHeight - AndroidUtilities.dp(52.0f);
            int clickBottom = this.totalHeight - AndroidUtilities.dp(35.0f);
            if (this.currentMessageObject.messageOwner instanceof TLRPC.TL_message) {
                TLRPC.TL_message messageOwner = (TLRPC.TL_message) this.currentMessageObject.messageOwner;
                ArrayList<TLRPC.MessageEntity> entities = messageOwner.entities;
                if (entities.size() > 0) {
                    hasEntities = true;
                } else {
                    hasEntities = false;
                }
            }
            if (event.getAction() == 0) {
                if (x >= clickLeft && x <= clickRight && y >= clickTop && y < clickBottom && hasEntities) {
                    this.instantPressed = true;
                    this.disallowLongPress = true;
                    return true;
                }
                if (x >= left && x <= right && y >= AndroidUtilities.dp(3.0f) && y < this.totalHeight && sysNotify.business_code == 8) {
                    this.clickSysNotifyItem = false;
                    this.instantPressed = true;
                    return true;
                }
                this.clickSysNotifyItem = true;
                this.instantPressed = true;
                return true;
            }
            if (event.getAction() == 1 && this.instantPressed && (chatMessageCellDelegate3 = this.delegate) != null) {
                chatMessageCellDelegate3.didPressOther(this, this.otherX, this.otherY);
                this.instantPressed = false;
            }
        } else {
            int right2 = this.backgroundDrawableRight - AndroidUtilities.dp(20.0f);
            int left2 = this.backgroundDrawableLeft + AndroidUtilities.dp(30.0f);
            if (event.getAction() == 0) {
                if (x >= left2 && x <= right2 && y >= this.totalHeight - AndroidUtilities.dp(75.0f) && y < this.totalHeight - AndroidUtilities.dp(30.0f) && this.photoFCImage != null) {
                    this.clickSysNotifyItem = false;
                    this.instantPressed = true;
                    return true;
                }
                ImageReceiver imageReceiver = this.photoImage1;
                if (imageReceiver != null && imageReceiver.getMediaLocation() != null && this.photoImage1.getMediaLocation().document != null && x >= this.photoImage1.getImageX() && x <= this.photoImage1.getImageX() + this.photoImage1.getImageWidth() && y >= this.photoImage1.getImageY() && y <= this.photoImage1.getImageY() + this.photoImage1.getImageHeight()) {
                    this.clickSysNotifyItem = false;
                    this.clickSysNotifyVideoView = true;
                    this.clickSysNotifyPhotoImageViewIndex = 1;
                    return true;
                }
                ImageReceiver imageReceiver2 = this.photoImage2;
                if (imageReceiver2 != null && imageReceiver2.getMediaLocation() != null && this.photoImage2.getMediaLocation().document != null && x >= this.photoImage2.getImageX() && x <= this.photoImage2.getImageX() + this.photoImage2.getImageWidth() && y >= this.photoImage2.getImageY() && y <= this.photoImage2.getImageY() + this.photoImage2.getImageHeight()) {
                    this.clickSysNotifyItem = false;
                    this.clickSysNotifyVideoView = true;
                    this.clickSysNotifyPhotoImageViewIndex = 2;
                    return true;
                }
                ImageReceiver imageReceiver3 = this.photoImage3;
                if (imageReceiver3 != null && imageReceiver3.getMediaLocation() != null && this.photoImage3.getMediaLocation().document != null && x >= this.photoImage3.getImageX() && x <= this.photoImage3.getImageX() + this.photoImage3.getImageWidth() && y >= this.photoImage3.getImageY() && y <= this.photoImage3.getImageY() + this.photoImage3.getImageHeight()) {
                    this.clickSysNotifyItem = false;
                    this.clickSysNotifyVideoView = true;
                    this.clickSysNotifyPhotoImageViewIndex = 3;
                    return true;
                }
                ImageReceiver imageReceiver4 = this.photoImage4;
                if (imageReceiver4 != null && imageReceiver4.getMediaLocation() != null && this.photoImage4.getMediaLocation().document != null && x >= this.photoImage4.getImageX() && x <= this.photoImage4.getImageX() + this.photoImage4.getImageWidth() && y >= this.photoImage4.getImageY() && y <= this.photoImage4.getImageY() + this.photoImage4.getImageHeight()) {
                    this.clickSysNotifyItem = false;
                    this.clickSysNotifyVideoView = true;
                    this.clickSysNotifyPhotoImageViewIndex = 4;
                    return true;
                }
                ImageReceiver imageReceiver5 = this.photoImage5;
                if (imageReceiver5 != null && imageReceiver5.getMediaLocation() != null && this.photoImage5.getMediaLocation().document != null && x >= this.photoImage5.getImageX() && x <= this.photoImage5.getImageX() + this.photoImage5.getImageWidth() && y >= this.photoImage5.getImageY() && y <= this.photoImage5.getImageY() + this.photoImage5.getImageHeight()) {
                    this.clickSysNotifyItem = false;
                    this.clickSysNotifyVideoView = true;
                    this.clickSysNotifyPhotoImageViewIndex = 5;
                    return true;
                }
                this.clickSysNotifyItem = true;
                this.instantPressed = true;
                return true;
            }
            if (event.getAction() == 1) {
                if (this.instantPressed && (chatMessageCellDelegate2 = this.delegate) != null) {
                    chatMessageCellDelegate2.didPressOther(this, this.otherX, this.otherY);
                    this.instantPressed = false;
                } else if (this.clickSysNotifyVideoView && (chatMessageCellDelegate = this.delegate) != null) {
                    chatMessageCellDelegate.didPressSysNotifyVideoFullPlayer(this);
                    this.instantPressed = false;
                }
            }
        }
        return false;
    }

    private boolean checkCardMotionEvent(MotionEvent event) {
        ChatMessageCellDelegate chatMessageCellDelegate;
        if (this.currentMessageObject.type != 103) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        int right = (this.backgroundDrawableLeft + this.backgroundDrawableRight) - AndroidUtilities.dp(8.0f);
        if (event.getAction() == 0) {
            if (x >= this.backgroundDrawableLeft && x <= right && y >= AndroidUtilities.dp(3.0f) && y < this.totalHeight) {
                this.instantPressed = true;
                return true;
            }
        } else if (event.getAction() == 1 && this.instantPressed && (chatMessageCellDelegate = this.delegate) != null) {
            chatMessageCellDelegate.didPressOther(this, this.otherX, this.otherY);
            this.instantPressed = false;
        }
        return false;
    }

    private boolean checkLiveMotionEvent(MotionEvent event) {
        ChatMessageCellDelegate chatMessageCellDelegate;
        if (this.currentMessageObject.type != 207) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        int right = (this.backgroundDrawableLeft + this.backgroundDrawableRight) - AndroidUtilities.dp(8.0f);
        if (event.getAction() == 0) {
            if (x >= this.backgroundDrawableLeft && x <= right && y >= AndroidUtilities.dp(3.0f) && y < this.totalHeight) {
                this.instantPressed = true;
                return true;
            }
        } else if (event.getAction() == 1 && this.instantPressed && (chatMessageCellDelegate = this.delegate) != null) {
            chatMessageCellDelegate.didPressOther(this, this.otherX, this.otherY);
            this.instantPressed = false;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0066  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean checkPhotoImageMotionEvent(android.view.MotionEvent r12) {
        /*
            Method dump skipped, instruction units count: 515
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.checkPhotoImageMotionEvent(android.view.MotionEvent):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x010c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean checkAudioMotionEvent(android.view.MotionEvent r14) {
        /*
            Method dump skipped, instruction units count: 388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.checkAudioMotionEvent(android.view.MotionEvent):boolean");
    }

    private boolean checkBotButtonMotionEvent(MotionEvent event) {
        int addX;
        if (this.botButtons.isEmpty() || this.currentMessageObject.eventId != 0) {
            return false;
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        if (event.getAction() == 0) {
            if (this.currentMessageObject.isOutOwner()) {
                addX = (getMeasuredWidth() - this.widthForButtons) - AndroidUtilities.dp(10.0f);
            } else {
                int addX2 = this.backgroundDrawableLeft;
                addX = addX2 + AndroidUtilities.dp(this.mediaBackground ? 1.0f : 7.0f);
            }
            for (int a = 0; a < this.botButtons.size(); a++) {
                BotButton button = this.botButtons.get(a);
                int y2 = (button.y + this.layoutHeight) - AndroidUtilities.dp(2.0f);
                if (x >= button.x + addX && x <= button.x + addX + button.width && y >= y2 && y <= button.height + y2) {
                    this.pressedBotButton = a;
                    invalidate();
                    return true;
                }
            }
            return false;
        }
        if (event.getAction() != 1 || this.pressedBotButton == -1) {
            return false;
        }
        playSoundEffect(0);
        if (this.currentMessageObject.scheduled) {
            ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.MessageScheduledBotAction);
        } else {
            BotButton button2 = this.botButtons.get(this.pressedBotButton);
            if (button2.button != null) {
                this.delegate.didPressBotButton(this, button2.button);
            } else if (button2.reaction != null) {
                this.delegate.didPressReaction(this, button2.reaction);
            }
        }
        this.pressedBotButton = -1;
        invalidate();
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x01ad  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x02d4  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x0337  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x03cf  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x041a  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0146  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r14) {
        /*
            Method dump skipped, instruction units count: 1061
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public void updatePlayingMessageProgress() {
        String timeString;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null) {
            return;
        }
        if (this.documentAttachType == 4) {
            if (this.infoLayout != null && (PhotoViewer.isPlayingMessage(messageObject) || MediaController.getInstance().isGoingToShowMessageObject(this.currentMessageObject))) {
                return;
            }
            int duration = 0;
            AnimatedFileDrawable animation = this.photoImage.getAnimation();
            if (animation != null) {
                MessageObject messageObject2 = this.currentMessageObject;
                int durationMs = animation.getDurationMs() / 1000;
                messageObject2.audioPlayerDuration = durationMs;
                duration = durationMs;
                if (this.currentMessageObject.messageOwner.ttl > 0 && this.currentMessageObject.messageOwner.destroyTime == 0 && !this.currentMessageObject.needDrawBluredPreview() && this.currentMessageObject.isVideo() && animation.hasBitmap()) {
                    this.delegate.didStartVideoStream(this.currentMessageObject);
                }
            }
            if (duration == 0) {
                duration = this.currentMessageObject.getDuration();
            }
            if (MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                duration = (int) (duration - (duration * this.currentMessageObject.audioProgress));
            } else if (animation != null) {
                if (duration != 0) {
                    duration -= animation.getCurrentProgressMs() / 1000;
                }
                if (this.delegate != null && animation.getCurrentProgressMs() >= 3000) {
                    this.delegate.videoTimerReached();
                }
            }
            int minutes = duration / 60;
            int seconds = duration - (minutes * 60);
            if (minutes == 0 && seconds == 0) {
                seconds = 1;
            }
            if (this.lastTime != duration) {
                String str = String.format("%d:%02d", Integer.valueOf(minutes), Integer.valueOf(seconds));
                this.infoWidth = (int) Math.ceil(Theme.chat_infoPaint.measureText(str));
                this.infoLayout = new StaticLayout(str, Theme.chat_infoPaint, this.infoWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                this.lastTime = duration;
                return;
            }
            return;
        }
        if (messageObject.isRoundVideo()) {
            int duration2 = 0;
            TLRPC.Document document = this.currentMessageObject.getDocument();
            int a = 0;
            while (true) {
                if (a >= document.attributes.size()) {
                    break;
                }
                TLRPC.DocumentAttribute attribute = document.attributes.get(a);
                if (!(attribute instanceof TLRPC.TL_documentAttributeVideo)) {
                    a++;
                } else {
                    duration2 = attribute.duration;
                    break;
                }
            }
            if (MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                duration2 = Math.max(0, duration2 - this.currentMessageObject.audioProgressSec);
            }
            if (this.lastTime != duration2) {
                this.lastTime = duration2;
                String timeString2 = String.format("%02d:%02d", Integer.valueOf(duration2 / 60), Integer.valueOf(duration2 % 60));
                this.timeWidthAudio = (int) Math.ceil(Theme.chat_timePaint.measureText(timeString2));
                this.durationLayout = new StaticLayout(timeString2, Theme.chat_timePaint, this.timeWidthAudio, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                invalidate();
                return;
            }
            return;
        }
        if (this.documentAttach != null) {
            if (this.useSeekBarWaweform) {
                if (!this.seekBarWaveform.isDragging()) {
                    this.seekBarWaveform.setProgress(this.currentMessageObject.audioProgress);
                }
            } else if (!this.seekBar.isDragging()) {
                this.seekBar.setProgress(this.currentMessageObject.audioProgress);
                this.seekBar.setBufferedProgress(this.currentMessageObject.bufferedProgress);
            }
            int duration3 = 0;
            if (this.documentAttachType == 3) {
                if (!MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                    int a2 = 0;
                    while (true) {
                        if (a2 >= this.documentAttach.attributes.size()) {
                            break;
                        }
                        TLRPC.DocumentAttribute attribute2 = this.documentAttach.attributes.get(a2);
                        if (!(attribute2 instanceof TLRPC.TL_documentAttributeAudio)) {
                            a2++;
                        } else {
                            duration3 = attribute2.duration;
                            break;
                        }
                    }
                } else {
                    duration3 = this.currentMessageObject.audioProgressSec;
                }
                if (this.lastTime != duration3) {
                    this.lastTime = duration3;
                    String timeString3 = String.format("%02d:%02d", Integer.valueOf(duration3 / 60), Integer.valueOf(duration3 % 60));
                    this.timeWidthAudio = (int) Math.ceil(Theme.chat_audioTimePaint.measureText(timeString3));
                    this.durationLayout = new StaticLayout(timeString3, Theme.chat_audioTimePaint, this.timeWidthAudio, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                }
            } else {
                int currentProgress = 0;
                int duration4 = this.currentMessageObject.getDuration();
                if (MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                    currentProgress = this.currentMessageObject.audioProgressSec;
                }
                if (this.lastTime != currentProgress) {
                    this.lastTime = currentProgress;
                    if (duration4 == 0) {
                        timeString = String.format("%d:%02d / -:--", Integer.valueOf(currentProgress / 60), Integer.valueOf(currentProgress % 60));
                    } else {
                        timeString = String.format("%d:%02d / %d:%02d", Integer.valueOf(currentProgress / 60), Integer.valueOf(currentProgress % 60), Integer.valueOf(duration4 / 60), Integer.valueOf(duration4 % 60));
                    }
                    int timeWidth = (int) Math.ceil(Theme.chat_audioTimePaint.measureText(timeString));
                    this.durationLayout = new StaticLayout(timeString, Theme.chat_audioTimePaint, timeWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                }
            }
            invalidate();
        }
    }

    public void setFullyDraw(boolean draw) {
        this.fullyDraw = draw;
    }

    public void setVisiblePart(int position, int height) {
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null || messageObject.textLayoutBlocks == null) {
            return;
        }
        int position2 = position - this.textY;
        int newFirst = -1;
        int newLast = -1;
        int newCount = 0;
        int startBlock = 0;
        for (int a = 0; a < this.currentMessageObject.textLayoutBlocks.size() && this.currentMessageObject.textLayoutBlocks.get(a).textYOffset <= position2; a++) {
            startBlock = a;
        }
        for (int a2 = startBlock; a2 < this.currentMessageObject.textLayoutBlocks.size(); a2++) {
            MessageObject.TextLayoutBlock block = this.currentMessageObject.textLayoutBlocks.get(a2);
            float y = block.textYOffset;
            if (!intersect(y, block.height + y, position2, position2 + height)) {
                if (y > position2) {
                    break;
                }
            } else {
                if (newFirst == -1) {
                    newFirst = a2;
                }
                newLast = a2;
                newCount++;
            }
        }
        int a3 = this.lastVisibleBlockNum;
        if (a3 != newLast || this.firstVisibleBlockNum != newFirst || this.totalVisibleBlocksCount != newCount) {
            this.lastVisibleBlockNum = newLast;
            this.firstVisibleBlockNum = newFirst;
            this.totalVisibleBlocksCount = newCount;
            invalidate();
        }
    }

    private boolean intersect(float left1, float right1, float left2, float right2) {
        return left1 <= left2 ? right1 >= left2 : left1 <= right2;
    }

    public static StaticLayout generateStaticLayout(CharSequence text, TextPaint paint, int maxWidth, int smallWidth, int linesCount, int maxLines) {
        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(text);
        int addedChars = 0;
        StaticLayout layout = new StaticLayout(text, paint, smallWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
        int maxWidth2 = maxWidth;
        for (int a = 0; a < linesCount; a++) {
            layout.getLineDirections(a);
            if (layout.getLineLeft(a) != 0.0f || layout.isRtlCharAt(layout.getLineStart(a)) || layout.isRtlCharAt(layout.getLineEnd(a))) {
                maxWidth2 = smallWidth;
            }
            int pos = layout.getLineEnd(a);
            if (pos == text.length()) {
                break;
            }
            int pos2 = pos - 1;
            if (stringBuilder.charAt(pos2 + addedChars) == ' ') {
                stringBuilder.replace(pos2 + addedChars, pos2 + addedChars + 1, (CharSequence) ShellAdbUtils.COMMAND_LINE_END);
            } else if (stringBuilder.charAt(pos2 + addedChars) != '\n') {
                stringBuilder.insert(pos2 + addedChars, (CharSequence) ShellAdbUtils.COMMAND_LINE_END);
                addedChars++;
            }
            if (a == layout.getLineCount() - 1 || a == maxLines - 1) {
                break;
            }
        }
        return StaticLayoutEx.createStaticLayout(stringBuilder, paint, maxWidth2, Layout.Alignment.ALIGN_NORMAL, 1.0f, AndroidUtilities.dp(1.0f), false, TextUtils.TruncateAt.END, maxWidth2, maxLines, true);
    }

    private void didClickedImage() {
        TLRPC.WebPage webPage;
        if (this.currentMessageObject.type == 1 || this.currentMessageObject.isAnyKindOfSticker()) {
            int i = this.buttonState;
            if (i == -1) {
                this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
                return;
            } else {
                if (i == 0) {
                    didPressButton(true, false);
                    return;
                }
                return;
            }
        }
        if (this.currentMessageObject.type == 12) {
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.currentMessageObject.messageOwner.media.user_id));
            this.delegate.didPressUserAvatar(this, user, this.lastTouchX, this.lastTouchY);
            return;
        }
        if (this.currentMessageObject.type == 5) {
            if (this.buttonState != -1) {
                didPressButton(true, false);
                return;
            } else if (!MediaController.getInstance().isPlayingMessage(this.currentMessageObject) || MediaController.getInstance().isMessagePaused()) {
                this.delegate.needPlayMessage(this.currentMessageObject);
                return;
            } else {
                MediaController.getInstance().lambda$startAudioAgain$5$MediaController(this.currentMessageObject);
                return;
            }
        }
        if (this.currentMessageObject.type == 8) {
            int i2 = this.buttonState;
            if (i2 == -1 || (i2 == 1 && this.canStreamVideo && this.autoPlayingMedia)) {
                this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
                return;
            }
            int i3 = this.buttonState;
            if (i3 == 2 || i3 == 0) {
                didPressButton(true, false);
                return;
            }
            return;
        }
        if (this.documentAttachType == 4) {
            if (this.buttonState == -1 || (this.drawVideoImageButton && (this.autoPlayingMedia || (SharedConfig.streamMedia && this.canStreamVideo)))) {
                this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
                return;
            }
            if (this.drawVideoImageButton) {
                didPressButton(true, true);
                return;
            }
            int i4 = this.buttonState;
            if (i4 == 0 || i4 == 3) {
                didPressButton(true, false);
                return;
            }
            return;
        }
        if (this.currentMessageObject.type == 4) {
            this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
            return;
        }
        int i5 = this.documentAttachType;
        if (i5 == 1) {
            if (this.buttonState == -1) {
                this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
                return;
            }
            return;
        }
        if (i5 == 2) {
            if (this.buttonState == -1 && (webPage = this.currentMessageObject.messageOwner.media.webpage) != null) {
                if (webPage.embed_url != null && webPage.embed_url.length() != 0) {
                    this.delegate.needOpenWebView(webPage.embed_url, webPage.site_name, webPage.description, webPage.url, webPage.embed_width, webPage.embed_height);
                    return;
                } else {
                    Browser.openUrl(getContext(), webPage.url);
                    return;
                }
            }
            return;
        }
        if (this.hasInvoicePreview) {
            if (this.buttonState == -1) {
                this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
            }
        } else if (this.currentMessageObject.type == 105) {
            this.delegate.didPressImage(this, this.lastTouchX, this.lastTouchY);
        }
    }

    private void updateSecretTimeText(MessageObject messageObject) {
        String str;
        if (messageObject == null || !messageObject.needDrawBluredPreview() || (str = messageObject.getSecretTimeString()) == null) {
            return;
        }
        this.infoWidth = (int) Math.ceil(Theme.chat_infoPaint.measureText(str));
        CharSequence str2 = TextUtils.ellipsize(str, Theme.chat_infoPaint, this.infoWidth, TextUtils.TruncateAt.END);
        this.infoLayout = new StaticLayout(str2, Theme.chat_infoPaint, this.infoWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
        invalidate();
    }

    private boolean isPhotoDataChanged(MessageObject object) {
        if (object.type == 0 || object.type == 14) {
            return false;
        }
        if (object.type == 4) {
            if (this.currentUrl == null) {
                return true;
            }
            double lat = object.messageOwner.media.geo.lat;
            double d = object.messageOwner.media.geo._long;
            if (object.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive) {
                int iDp = this.backgroundWidth - AndroidUtilities.dp(21.0f);
                AndroidUtilities.dp(195.0f);
                double rad = ((double) C.ENCODING_PCM_MU_LAW) / 3.141592653589793d;
                double y = Math.round(((double) C.ENCODING_PCM_MU_LAW) - ((Math.log((Math.sin((lat * 3.141592653589793d) / 180.0d) + 1.0d) / (1.0d - Math.sin((lat * 3.141592653589793d) / 180.0d))) * rad) / 2.0d)) - ((long) (AndroidUtilities.dp(10.3f) << 6));
                double lat2 = ((1.5707963267948966d - (Math.atan(Math.exp((y - ((double) C.ENCODING_PCM_MU_LAW)) / rad)) * 2.0d)) * 180.0d) / 3.141592653589793d;
                return false;
            }
            if (!TextUtils.isEmpty(object.messageOwner.media.title)) {
                int iDp2 = this.backgroundWidth - AndroidUtilities.dp(21.0f);
                AndroidUtilities.dp(195.0f);
                return false;
            }
            int iDp3 = this.backgroundWidth - AndroidUtilities.dp(12.0f);
            AndroidUtilities.dp(195.0f);
            return false;
        }
        TLRPC.PhotoSize photoSize = this.currentPhotoObject;
        if (photoSize == null || (photoSize.location instanceof TLRPC.TL_fileLocationUnavailable)) {
            return object.type == 1 || object.type == 5 || object.type == 3 || object.type == 8 || object.isAnyKindOfSticker();
        }
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && this.photoNotSet) {
            File cacheFile = FileLoader.getPathToMessage(messageObject.messageOwner);
            return cacheFile.exists();
        }
        return false;
    }

    private boolean isUserDataChanged() {
        TLRPC.FileLocation fileLocation;
        String str;
        TLRPC.PhotoSize photoSize;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && !this.hasLinkPreview && messageObject.messageOwner.media != null && (this.currentMessageObject.messageOwner.media.webpage instanceof TLRPC.TL_webPage)) {
            return true;
        }
        if (this.currentMessageObject == null || (this.currentUser == null && this.currentChat == null)) {
            return false;
        }
        if (this.lastSendState != this.currentMessageObject.messageOwner.send_state || this.lastDeleteDate != this.currentMessageObject.messageOwner.destroyTime || this.lastViewsCount != this.currentMessageObject.messageOwner.views || this.lastReactions != this.currentMessageObject.messageOwner.reactions) {
            return true;
        }
        updateCurrentUserAndChat();
        TLRPC.FileLocation newPhoto = null;
        if (this.isAvatarVisible) {
            TLRPC.User user = this.currentUser;
            if (user != null && user.photo != null) {
                newPhoto = this.currentUser.photo.photo_small;
            } else {
                TLRPC.Chat chat = this.currentChat;
                if (chat != null && chat.photo != null) {
                    newPhoto = this.currentChat.photo.photo_small;
                }
            }
        }
        if (this.replyTextLayout == null && this.currentMessageObject.replyMessageObject != null) {
            return true;
        }
        if ((this.currentPhoto == null && newPhoto != null) || ((this.currentPhoto != null && newPhoto == null) || ((fileLocation = this.currentPhoto) != null && newPhoto != null && (fileLocation.local_id != newPhoto.local_id || this.currentPhoto.volume_id != newPhoto.volume_id)))) {
            return true;
        }
        TLRPC.PhotoSize newReplyPhoto = null;
        if (this.replyNameLayout != null && (photoSize = FileLoader.getClosestPhotoSizeWithSize(this.currentMessageObject.replyMessageObject.photoThumbs, 40)) != null && !this.currentMessageObject.replyMessageObject.isAnyKindOfSticker()) {
            newReplyPhoto = photoSize;
        }
        if (this.currentReplyPhoto == null && newReplyPhoto != null) {
            return true;
        }
        String newNameString = null;
        if (this.drawName && this.isChat && !this.currentMessageObject.isOutOwner()) {
            TLRPC.User user2 = this.currentUser;
            if (user2 != null) {
                newNameString = UserObject.getName(user2);
            } else {
                TLRPC.Chat chat2 = this.currentChat;
                if (chat2 != null) {
                    newNameString = chat2.title;
                }
            }
        }
        if ((this.currentNameString == null && newNameString != null) || ((this.currentNameString != null && newNameString == null) || ((str = this.currentNameString) != null && newNameString != null && !str.equals(newNameString)))) {
            return true;
        }
        if (!this.drawForwardedName || !this.currentMessageObject.needDrawForwarded()) {
            return false;
        }
        String newNameString2 = this.currentMessageObject.getForwardedName();
        if (this.currentForwardNameString == null && newNameString2 != null) {
            return true;
        }
        if (this.currentForwardNameString != null && newNameString2 == null) {
            return true;
        }
        String str2 = this.currentForwardNameString;
        return (str2 == null || newNameString2 == null || str2.equals(newNameString2)) ? false : true;
    }

    public ImageReceiver getPhotoImage() {
        return this.photoImage;
    }

    public int getNoSoundIconCenterX() {
        return this.noSoundCenterX;
    }

    public int getForwardNameCenterX() {
        TLRPC.User user = this.currentUser;
        if (user != null && user.id == 0) {
            return (int) this.avatarImage.getCenterX();
        }
        return this.forwardNameX + this.forwardNameCenterX;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.fileDidLoad);
        CheckBoxBase checkBoxBase = this.checkBox;
        if (checkBoxBase != null) {
            checkBoxBase.onDetachedFromWindow();
        }
        CheckBoxBase checkBoxBase2 = this.photoCheckBox;
        if (checkBoxBase2 != null) {
            checkBoxBase2.onDetachedFromWindow();
        }
        this.attachedToWindow = false;
        this.radialProgress.onDetachedFromWindow();
        this.videoRadialProgress.onDetachedFromWindow();
        this.avatarImage.onDetachedFromWindow();
        this.replyImageReceiver.onDetachedFromWindow();
        this.locationImageReceiver.onDetachedFromWindow();
        this.photoImage.onDetachedFromWindow();
        if (this.addedForTest && this.currentUrl != null && this.currentWebFile != null) {
            ImageLoader.getInstance().removeTestWebFile(this.currentUrl);
            this.addedForTest = false;
        }
        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.fileDidLoad);
        MessageObject messageObject = this.messageObjectToSet;
        if (messageObject != null) {
            setMessageContent(messageObject, this.groupedMessagesToSet, this.bottomNearToSet, this.topNearToSet);
            this.messageObjectToSet = null;
            this.groupedMessagesToSet = null;
        }
        CheckBoxBase checkBoxBase = this.checkBox;
        if (checkBoxBase != null) {
            checkBoxBase.onAttachedToWindow();
        }
        CheckBoxBase checkBoxBase2 = this.photoCheckBox;
        if (checkBoxBase2 != null) {
            checkBoxBase2.onAttachedToWindow();
        }
        this.attachedToWindow = true;
        setTranslationX(0.0f);
        this.radialProgress.onAttachedToWindow();
        this.videoRadialProgress.onAttachedToWindow();
        this.avatarImage.onAttachedToWindow();
        this.avatarImage.setParentView((View) getParent());
        this.replyImageReceiver.onAttachedToWindow();
        this.locationImageReceiver.onAttachedToWindow();
        if (!this.photoImage.onAttachedToWindow() || this.drawPhotoImage) {
            updateButtonState(false, false, false);
        }
        MessageObject messageObject2 = this.currentMessageObject;
        if (messageObject2 != null && (messageObject2.isRoundVideo() || this.currentMessageObject.isVideo())) {
            checkVideoPlayback(true);
        }
        if (this.documentAttachType == 4 && this.autoPlayingMedia) {
            boolean zIsPlayingMessage = MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
            this.animatingNoSoundPlaying = zIsPlayingMessage;
            this.animatingNoSoundProgress = zIsPlayingMessage ? 0.0f : 1.0f;
            this.animatingNoSound = 0;
            return;
        }
        this.animatingNoSoundPlaying = false;
        this.animatingNoSoundProgress = 0.0f;
        int i = this.documentAttachType;
        if ((i == 4 || i == 2) && this.drawVideoSize) {
            f = 1.0f;
        }
        this.animatingDrawVideoImageButtonProgress = f;
    }

    /* JADX WARN: Multi-variable search skipped. Vars limit reached: 7002 (expected less than 5000) */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:1014:0x1590  */
    /* JADX WARN: Removed duplicated region for block: B:1017:0x15a4  */
    /* JADX WARN: Removed duplicated region for block: B:1018:0x15ad  */
    /* JADX WARN: Removed duplicated region for block: B:1040:0x1600  */
    /* JADX WARN: Removed duplicated region for block: B:1041:0x1607  */
    /* JADX WARN: Removed duplicated region for block: B:1044:0x1613  */
    /* JADX WARN: Removed duplicated region for block: B:1047:0x161d  */
    /* JADX WARN: Removed duplicated region for block: B:1050:0x1624  */
    /* JADX WARN: Removed duplicated region for block: B:1052:0x1630  */
    /* JADX WARN: Removed duplicated region for block: B:1083:0x16cb  */
    /* JADX WARN: Removed duplicated region for block: B:1086:0x16d5  */
    /* JADX WARN: Removed duplicated region for block: B:1090:0x1704  */
    /* JADX WARN: Removed duplicated region for block: B:1096:0x1732  */
    /* JADX WARN: Removed duplicated region for block: B:1099:0x1771  */
    /* JADX WARN: Removed duplicated region for block: B:1100:0x17b9  */
    /* JADX WARN: Removed duplicated region for block: B:1199:0x1b79  */
    /* JADX WARN: Removed duplicated region for block: B:1201:0x1b7e  */
    /* JADX WARN: Removed duplicated region for block: B:1206:0x1bbc  */
    /* JADX WARN: Removed duplicated region for block: B:1223:0x1ca6  */
    /* JADX WARN: Removed duplicated region for block: B:1226:0x1cab  */
    /* JADX WARN: Removed duplicated region for block: B:1230:0x1ccc  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0043  */
    /* JADX WARN: Removed duplicated region for block: B:2540:0x4787  */
    /* JADX WARN: Removed duplicated region for block: B:2541:0x478c  */
    /* JADX WARN: Removed duplicated region for block: B:2576:0x4811  */
    /* JADX WARN: Removed duplicated region for block: B:2577:0x4815  */
    /* JADX WARN: Removed duplicated region for block: B:2602:0x4863  */
    /* JADX WARN: Removed duplicated region for block: B:2618:0x48b8 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:2619:0x48ba  */
    /* JADX WARN: Removed duplicated region for block: B:2627:0x48e0  */
    /* JADX WARN: Removed duplicated region for block: B:2636:0x4935  */
    /* JADX WARN: Removed duplicated region for block: B:2639:0x4947  */
    /* JADX WARN: Removed duplicated region for block: B:2642:0x496e  */
    /* JADX WARN: Removed duplicated region for block: B:2643:0x4971  */
    /* JADX WARN: Removed duplicated region for block: B:2646:0x497d  */
    /* JADX WARN: Removed duplicated region for block: B:2649:0x4984  */
    /* JADX WARN: Removed duplicated region for block: B:2650:0x4997  */
    /* JADX WARN: Removed duplicated region for block: B:2658:0x49cc  */
    /* JADX WARN: Removed duplicated region for block: B:2820:0x4db6  */
    /* JADX WARN: Removed duplicated region for block: B:2905:0x4f6d  */
    /* JADX WARN: Removed duplicated region for block: B:2907:0x4f74  */
    /* JADX WARN: Removed duplicated region for block: B:2916:0x4fa2  */
    /* JADX WARN: Removed duplicated region for block: B:2929:0x4fed  */
    /* JADX WARN: Removed duplicated region for block: B:2930:0x5018  */
    /* JADX WARN: Removed duplicated region for block: B:2933:0x5033  */
    /* JADX WARN: Removed duplicated region for block: B:2939:0x5042 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:2943:0x504b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:2949:0x505a A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:2953:0x5066  */
    /* JADX WARN: Removed duplicated region for block: B:2968:0x5094  */
    /* JADX WARN: Removed duplicated region for block: B:2975:0x50a8  */
    /* JADX WARN: Removed duplicated region for block: B:2979:0x50b1  */
    /* JADX WARN: Removed duplicated region for block: B:2980:0x5114  */
    /* JADX WARN: Removed duplicated region for block: B:3264:0x57b6  */
    /* JADX WARN: Removed duplicated region for block: B:3267:0x57bc  */
    /* JADX WARN: Removed duplicated region for block: B:3274:0x57db  */
    /* JADX WARN: Removed duplicated region for block: B:3281:0x5836  */
    /* JADX WARN: Removed duplicated region for block: B:3282:0x5838  */
    /* JADX WARN: Removed duplicated region for block: B:3290:0x585f A[Catch: Exception -> 0x58c9, TryCatch #24 {Exception -> 0x58c9, blocks: (B:3288:0x5859, B:3290:0x585f, B:3291:0x5868, B:3292:0x589e, B:3294:0x58a6, B:3296:0x58b4, B:3298:0x58b8, B:3299:0x58bc), top: B:3509:0x5859 }] */
    /* JADX WARN: Removed duplicated region for block: B:3294:0x58a6 A[Catch: Exception -> 0x58c9, TryCatch #24 {Exception -> 0x58c9, blocks: (B:3288:0x5859, B:3290:0x585f, B:3291:0x5868, B:3292:0x589e, B:3294:0x58a6, B:3296:0x58b4, B:3298:0x58b8, B:3299:0x58bc), top: B:3509:0x5859 }] */
    /* JADX WARN: Removed duplicated region for block: B:3306:0x58da  */
    /* JADX WARN: Removed duplicated region for block: B:3311:0x58f4  */
    /* JADX WARN: Removed duplicated region for block: B:3312:0x5902  */
    /* JADX WARN: Removed duplicated region for block: B:3315:0x5907  */
    /* JADX WARN: Removed duplicated region for block: B:3402:0x5c88 A[ADDED_TO_REGION, REMOVE] */
    /* JADX WARN: Removed duplicated region for block: B:3406:0x5c93  */
    /* JADX WARN: Removed duplicated region for block: B:3409:0x5ca1  */
    /* JADX WARN: Removed duplicated region for block: B:3411:0x5ca5  */
    /* JADX WARN: Removed duplicated region for block: B:3412:0x5caf  */
    /* JADX WARN: Removed duplicated region for block: B:341:0x05f5  */
    /* JADX WARN: Removed duplicated region for block: B:3426:0x5ce1  */
    /* JADX WARN: Removed duplicated region for block: B:3428:0x5ce7  */
    /* JADX WARN: Removed duplicated region for block: B:3431:0x5cf6  */
    /* JADX WARN: Removed duplicated region for block: B:3434:0x5d04  */
    /* JADX WARN: Removed duplicated region for block: B:3442:0x5d3a  */
    /* JADX WARN: Removed duplicated region for block: B:3445:0x5d47  */
    /* JADX WARN: Removed duplicated region for block: B:3448:0x5d4d  */
    /* JADX WARN: Removed duplicated region for block: B:3451:0x5d58  */
    /* JADX WARN: Removed duplicated region for block: B:345:0x0624 A[Catch: Exception -> 0x0667, TryCatch #18 {Exception -> 0x0667, blocks: (B:344:0x0612, B:345:0x0624, B:347:0x062c, B:349:0x0633), top: B:3497:0x05f3 }] */
    /* JADX WARN: Removed duplicated region for block: B:3485:0x0aeb A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:3503:0x4e25 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:383:0x073d A[PHI: r3 r36
      0x073d: PHI (r3v790 java.lang.String) = 
      (r3v646 java.lang.String)
      (r3v647 java.lang.String)
      (r3v647 java.lang.String)
      (r3v647 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
      (r3v646 java.lang.String)
     binds: [B:358:0x0674, B:366:0x069c, B:370:0x06b6, B:364:0x0690, B:356:0x066e, B:354:0x066a, B:351:0x0667, B:3496:0x073d, B:339:0x05ef, B:315:0x055a, B:312:0x054a, B:309:0x053a] A[DONT_GENERATE, DONT_INLINE]
      0x073d: PHI (r36v71 boolean) = 
      (r36v23 boolean)
      (r36v23 boolean)
      (r36v23 boolean)
      (r36v23 boolean)
      (r36v72 boolean)
      (r36v73 boolean)
      (r36v76 boolean)
      (r36v76 boolean)
      (r36v78 boolean)
      (r36v80 boolean)
      (r36v81 boolean)
      (r36v82 boolean)
     binds: [B:358:0x0674, B:366:0x069c, B:370:0x06b6, B:364:0x0690, B:356:0x066e, B:354:0x066a, B:351:0x0667, B:3496:0x073d, B:339:0x05ef, B:315:0x055a, B:312:0x054a, B:309:0x053a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:386:0x0749  */
    /* JADX WARN: Removed duplicated region for block: B:398:0x077e  */
    /* JADX WARN: Removed duplicated region for block: B:401:0x07a9  */
    /* JADX WARN: Removed duplicated region for block: B:412:0x07dd  */
    /* JADX WARN: Removed duplicated region for block: B:415:0x07fc  */
    /* JADX WARN: Removed duplicated region for block: B:422:0x0899  */
    /* JADX WARN: Removed duplicated region for block: B:431:0x08e1  */
    /* JADX WARN: Removed duplicated region for block: B:433:0x08e7  */
    /* JADX WARN: Removed duplicated region for block: B:441:0x0911  */
    /* JADX WARN: Removed duplicated region for block: B:451:0x093e  */
    /* JADX WARN: Removed duplicated region for block: B:454:0x0949  */
    /* JADX WARN: Removed duplicated region for block: B:457:0x0954  */
    /* JADX WARN: Removed duplicated region for block: B:495:0x09de  */
    /* JADX WARN: Removed duplicated region for block: B:497:0x09e1  */
    /* JADX WARN: Removed duplicated region for block: B:502:0x09ed  */
    /* JADX WARN: Removed duplicated region for block: B:505:0x09f2  */
    /* JADX WARN: Removed duplicated region for block: B:514:0x0a08  */
    /* JADX WARN: Removed duplicated region for block: B:517:0x0a22  */
    /* JADX WARN: Removed duplicated region for block: B:531:0x0aa6  */
    /* JADX WARN: Removed duplicated region for block: B:532:0x0ab0  */
    /* JADX WARN: Removed duplicated region for block: B:538:0x0ac8  */
    /* JADX WARN: Removed duplicated region for block: B:539:0x0aca  */
    /* JADX WARN: Removed duplicated region for block: B:544:0x0ae7  */
    /* JADX WARN: Removed duplicated region for block: B:559:0x0b6d  */
    /* JADX WARN: Removed duplicated region for block: B:562:0x0b78  */
    /* JADX WARN: Removed duplicated region for block: B:607:0x0c67 A[Catch: Exception -> 0x0c86, TryCatch #35 {Exception -> 0x0c86, blocks: (B:605:0x0c63, B:608:0x0c6e, B:607:0x0c67, B:602:0x0c5a), top: B:3531:0x0c63 }] */
    /* JADX WARN: Removed duplicated region for block: B:623:0x0cb6  */
    /* JADX WARN: Removed duplicated region for block: B:626:0x0cc8  */
    /* JADX WARN: Removed duplicated region for block: B:627:0x0ccf  */
    /* JADX WARN: Removed duplicated region for block: B:630:0x0cdd A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:649:0x0d88  */
    /* JADX WARN: Removed duplicated region for block: B:651:0x0d8d  */
    /* JADX WARN: Removed duplicated region for block: B:743:0x0f49  */
    /* JADX WARN: Removed duplicated region for block: B:751:0x0f66  */
    /* JADX WARN: Removed duplicated region for block: B:753:0x0f69  */
    /* JADX WARN: Removed duplicated region for block: B:754:0x0f70  */
    /* JADX WARN: Removed duplicated region for block: B:756:0x0f74  */
    /* JADX WARN: Removed duplicated region for block: B:945:0x149c  */
    /* JADX WARN: Removed duplicated region for block: B:958:0x14bd  */
    /* JADX WARN: Removed duplicated region for block: B:960:0x14c3  */
    /* JADX WARN: Removed duplicated region for block: B:961:0x14c5  */
    /* JADX WARN: Removed duplicated region for block: B:964:0x14d2  */
    /* JADX WARN: Removed duplicated region for block: B:965:0x14d4  */
    /* JADX WARN: Removed duplicated region for block: B:968:0x14e5  */
    /* JADX WARN: Removed duplicated region for block: B:980:0x150b  */
    /* JADX WARN: Type inference failed for: r15v109 */
    /* JADX WARN: Type inference failed for: r15v112 */
    /* JADX WARN: Type inference failed for: r15v114 */
    /* JADX WARN: Type inference failed for: r15v115 */
    /* JADX WARN: Type inference failed for: r15v116 */
    /* JADX WARN: Type inference failed for: r15v117 */
    /* JADX WARN: Type inference failed for: r15v118, types: [boolean] */
    /* JADX WARN: Type inference failed for: r15v119 */
    /* JADX WARN: Type inference failed for: r15v152 */
    /* JADX WARN: Type inference failed for: r15v153 */
    /* JADX WARN: Type inference failed for: r15v154 */
    /* JADX WARN: Type inference failed for: r15v155 */
    /* JADX WARN: Type inference failed for: r15v156 */
    /* JADX WARN: Type inference failed for: r15v157 */
    /* JADX WARN: Type inference failed for: r2v491 */
    /* JADX WARN: Type inference failed for: r2v492, types: [android.text.StaticLayout, im.uwrkaxlmjj.messenger.ImageReceiver] */
    /* JADX WARN: Type inference failed for: r2v578 */
    /* JADX WARN: Type inference failed for: r6v328, types: [android.view.ViewGroup] */
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
    /*  JADX ERROR: NullPointerException in pass: LoopRegionVisitor
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.SSAVar.use(jadx.core.dex.instructions.args.RegisterArg)" because "ssaVar" is null
        	at jadx.core.dex.nodes.InsnNode.rebindArgs(InsnNode.java:506)
        	at jadx.core.dex.nodes.InsnNode.rebindArgs(InsnNode.java:509)
        */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void setMessageContent(im.uwrkaxlmjj.messenger.MessageObject r88, im.uwrkaxlmjj.messenger.MessageObject.GroupedMessages r89, boolean r90, boolean r91) {
        /*
            Method dump skipped, instruction units count: 23962
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.setMessageContent(im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.messenger.MessageObject$GroupedMessages, boolean, boolean):void");
    }

    static /* synthetic */ int lambda$setMessageContent$0(PollButton o1, PollButton o2) {
        if (o1.decimal > o2.decimal) {
            return -1;
        }
        if (o1.decimal < o2.decimal) {
            return 1;
        }
        return 0;
    }

    public void checkVideoPlayback(boolean allowStart) {
        if (this.currentMessageObject.isVideo()) {
            if (MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                this.photoImage.setAllowStartAnimation(false);
                this.photoImage.stopAnimation();
                return;
            } else {
                this.photoImage.setAllowStartAnimation(true);
                this.photoImage.startAnimation();
                return;
            }
        }
        if (allowStart) {
            MessageObject playingMessage = MediaController.getInstance().getPlayingMessageObject();
            allowStart = playingMessage == null || !playingMessage.isRoundVideo();
        }
        this.photoImage.setAllowStartAnimation(allowStart);
        if (allowStart) {
            this.photoImage.startAnimation();
        } else {
            this.photoImage.stopAnimation();
        }
    }

    @Override // im.uwrkaxlmjj.ui.cells.BaseCell
    protected void onLongPress() {
        Drawable drawable;
        Drawable drawable2;
        if (this.avatarPressed) {
            this.delegate.didLongPressUserAvatar(this, this.currentUser, this.lastTouchX, this.lastTouchY);
            return;
        }
        CharacterStyle characterStyle = this.pressedLink;
        if (characterStyle instanceof URLSpanMono) {
            this.delegate.didPressUrl(this, characterStyle, true);
            return;
        }
        if (characterStyle instanceof URLSpanNoUnderline) {
            URLSpanNoUnderline url = (URLSpanNoUnderline) characterStyle;
            if (url.getURL().startsWith("/")) {
                this.delegate.didPressUrl(this, this.pressedLink, true);
                return;
            }
        } else if (characterStyle instanceof URLSpan) {
            this.delegate.didPressUrl(this, characterStyle, true);
            return;
        }
        resetPressedLink(-1);
        if (this.buttonPressed != 0 || this.miniButtonPressed != 0 || this.videoButtonPressed != 0 || this.pressedBotButton != -1) {
            this.buttonPressed = 0;
            this.miniButtonPressed = 0;
            this.videoButtonPressed = 0;
            this.pressedBotButton = -1;
            invalidate();
        }
        this.linkPreviewPressed = false;
        this.otherPressed = false;
        this.sharePressed = false;
        this.imagePressed = false;
        this.gamePreviewPressed = false;
        if (this.instantPressed) {
            this.instantButtonPressed = false;
            this.instantPressed = false;
            if (Build.VERSION.SDK_INT >= 21 && (drawable2 = this.selectorDrawable) != null) {
                drawable2.setState(StateSet.NOTHING);
            }
            invalidate();
        }
        if (this.pressedVoteButton != -1) {
            this.pressedVoteButton = -1;
            if (Build.VERSION.SDK_INT >= 21 && (drawable = this.selectorDrawable) != null) {
                drawable.setState(StateSet.NOTHING);
            }
            invalidate();
        }
        ChatMessageCellDelegate chatMessageCellDelegate = this.delegate;
        if (chatMessageCellDelegate != null) {
            chatMessageCellDelegate.didLongPress(this, this.lastTouchX, this.lastTouchY);
        }
    }

    public void setCheckPressed(boolean value, boolean pressed) {
        this.isCheckPressed = value;
        this.isPressed = pressed;
        updateRadialProgressBackground();
        if (this.useSeekBarWaweform) {
            this.seekBarWaveform.setSelected(isDrawSelectionBackground());
        } else {
            this.seekBar.setSelected(isDrawSelectionBackground());
        }
        invalidate();
    }

    public void setInvalidatesParent(boolean value) {
        this.invalidatesParent = value;
    }

    @Override // android.view.View
    public void invalidate() {
        super.invalidate();
        if (this.invalidatesParent && getParent() != null) {
            View parent = (View) getParent();
            if (parent.getParent() != null) {
                ((View) parent.getParent()).invalidate();
            }
        }
    }

    public void setHighlightedAnimated() {
        this.isHighlightedAnimated = true;
        this.highlightProgress = 1000;
        this.lastHighlightProgressTime = System.currentTimeMillis();
        invalidate();
        if (getParent() != null) {
            ((View) getParent()).invalidate();
        }
    }

    public boolean isHighlighted() {
        return this.isHighlighted;
    }

    public void setHighlighted(boolean value) {
        if (this.isHighlighted == value) {
            return;
        }
        this.isHighlighted = value;
        if (!value) {
            this.lastHighlightProgressTime = System.currentTimeMillis();
            this.isHighlightedAnimated = true;
            this.highlightProgress = 300;
        } else {
            this.isHighlightedAnimated = false;
            this.highlightProgress = 0;
        }
        updateRadialProgressBackground();
        if (this.useSeekBarWaweform) {
            this.seekBarWaveform.setSelected(isDrawSelectionBackground());
        } else {
            this.seekBar.setSelected(isDrawSelectionBackground());
        }
        invalidate();
        if (getParent() != null) {
            ((View) getParent()).invalidate();
        }
    }

    @Override // android.view.View
    public void setPressed(boolean pressed) {
        super.setPressed(pressed);
        updateRadialProgressBackground();
        if (this.useSeekBarWaweform) {
            this.seekBarWaveform.setSelected(isDrawSelectionBackground());
        } else {
            this.seekBar.setSelected(isDrawSelectionBackground());
        }
        invalidate();
    }

    private void updateRadialProgressBackground() {
        if (this.drawRadialCheckBackground) {
            return;
        }
        boolean z = true;
        boolean forcePressed = (this.isHighlighted || this.isPressed || isPressed()) && !(this.drawPhotoImage && this.photoImage.hasBitmapImage());
        this.radialProgress.setPressed(forcePressed || this.buttonPressed != 0, false);
        if (this.hasMiniProgress != 0) {
            this.radialProgress.setPressed(forcePressed || this.miniButtonPressed != 0, true);
        }
        RadialProgress2 radialProgress2 = this.videoRadialProgress;
        if (!forcePressed && this.videoButtonPressed == 0) {
            z = false;
        }
        radialProgress2.setPressed(z, false);
    }

    @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
    public void onSeekBarDrag(float progress) {
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null) {
            return;
        }
        messageObject.audioProgress = progress;
        MediaController.getInstance().seekToProgress(this.currentMessageObject, progress);
    }

    private void updateWaveform() {
        if (this.currentMessageObject == null || this.documentAttachType != 3) {
            return;
        }
        for (int a = 0; a < this.documentAttach.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = this.documentAttach.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeAudio) {
                if (attribute.waveform == null || attribute.waveform.length == 0) {
                    MediaController.getInstance().generateWaveform(this.currentMessageObject);
                }
                this.useSeekBarWaweform = attribute.waveform != null;
                this.seekBarWaveform.setWaveform(attribute.waveform);
                return;
            }
        }
    }

    private int createDocumentLayout(int maxWidth, MessageObject messageObject) {
        int maxWidth2;
        int width;
        if (messageObject.type == 0) {
            this.documentAttach = messageObject.messageOwner.media.webpage.document;
        } else {
            this.documentAttach = messageObject.getDocument();
        }
        TLRPC.Document document = this.documentAttach;
        if (document == null) {
            return 0;
        }
        if (MessageObject.isVoiceDocument(document)) {
            this.documentAttachType = 3;
            int duration = 0;
            int a = 0;
            while (true) {
                if (a >= this.documentAttach.attributes.size()) {
                    break;
                }
                TLRPC.DocumentAttribute attribute = this.documentAttach.attributes.get(a);
                if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                    a++;
                } else {
                    duration = attribute.duration;
                    break;
                }
            }
            this.widthBeforeNewTimeLine = (maxWidth - AndroidUtilities.dp(94.0f)) - ((int) Math.ceil(Theme.chat_audioTimePaint.measureText("00:00")));
            this.availableTimeWidth = maxWidth - AndroidUtilities.dp(18.0f);
            measureTime(messageObject);
            int minSize = AndroidUtilities.dp(174.0f) + this.timeWidth;
            if (!this.hasLinkPreview) {
                this.backgroundWidth = Math.min(maxWidth, (AndroidUtilities.dp(10.0f) * duration) + minSize);
            }
            this.seekBarWaveform.setMessageObject(messageObject);
            return 0;
        }
        if (MessageObject.isMusicDocument(this.documentAttach)) {
            this.documentAttachType = 5;
            int maxWidth3 = maxWidth - AndroidUtilities.dp(86.0f);
            if (maxWidth3 < 0) {
                maxWidth3 = AndroidUtilities.dp(100.0f);
            }
            CharSequence stringFinal = TextUtils.ellipsize(messageObject.getMusicTitle().replace('\n', ' '), Theme.chat_audioTitlePaint, maxWidth3 - AndroidUtilities.dp(12.0f), TextUtils.TruncateAt.END);
            StaticLayout staticLayout = new StaticLayout(stringFinal, Theme.chat_audioTitlePaint, maxWidth3, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.songLayout = staticLayout;
            if (staticLayout.getLineCount() > 0) {
                this.songX = -((int) Math.ceil(this.songLayout.getLineLeft(0)));
            }
            CharSequence stringFinal2 = TextUtils.ellipsize(messageObject.getMusicAuthor().replace('\n', ' '), Theme.chat_audioPerformerPaint, maxWidth3, TextUtils.TruncateAt.END);
            StaticLayout staticLayout2 = new StaticLayout(stringFinal2, Theme.chat_audioPerformerPaint, maxWidth3, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.performerLayout = staticLayout2;
            if (staticLayout2.getLineCount() > 0) {
                this.performerX = -((int) Math.ceil(this.performerLayout.getLineLeft(0)));
            }
            int duration2 = 0;
            int a2 = 0;
            while (true) {
                if (a2 >= this.documentAttach.attributes.size()) {
                    break;
                }
                TLRPC.DocumentAttribute attribute2 = this.documentAttach.attributes.get(a2);
                if (!(attribute2 instanceof TLRPC.TL_documentAttributeAudio)) {
                    a2++;
                } else {
                    duration2 = attribute2.duration;
                    break;
                }
            }
            int durationWidth = (int) Math.ceil(Theme.chat_audioTimePaint.measureText(String.format("%d:%02d / %d:%02d", Integer.valueOf(duration2 / 60), Integer.valueOf(duration2 % 60), Integer.valueOf(duration2 / 60), Integer.valueOf(duration2 % 60))));
            this.widthBeforeNewTimeLine = (this.backgroundWidth - AndroidUtilities.dp(86.0f)) - durationWidth;
            this.availableTimeWidth = this.backgroundWidth - AndroidUtilities.dp(28.0f);
            return durationWidth;
        }
        if (MessageObject.isVideoDocument(this.documentAttach) || (this.documentAttach.mime_type != null && this.documentAttach.mime_type.toLowerCase().startsWith("video/"))) {
            this.documentAttachType = 4;
            if (!messageObject.needDrawBluredPreview()) {
                updatePlayingMessageProgress();
                String str = String.format("%s", AndroidUtilities.formatFileSize(this.documentAttach.size));
                this.docTitleWidth = (int) Math.ceil(Theme.chat_infoPaint.measureText(str));
                this.docTitleLayout = new StaticLayout(str, Theme.chat_infoPaint, this.docTitleWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            }
            return 0;
        }
        if (MessageObject.isGifDocument(this.documentAttach)) {
            this.documentAttachType = 2;
            if (!messageObject.needDrawBluredPreview()) {
                String str2 = LocaleController.getString("AttachGif", mpEIGo.juqQQs.esbSDO.R.string.AttachGif);
                this.infoWidth = (int) Math.ceil(Theme.chat_infoPaint.measureText(str2));
                this.infoLayout = new StaticLayout(str2, Theme.chat_infoPaint, this.infoWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                String str3 = String.format("%s", AndroidUtilities.formatFileSize(this.documentAttach.size));
                this.docTitleWidth = (int) Math.ceil(Theme.chat_infoPaint.measureText(str3));
                this.docTitleLayout = new StaticLayout(str3, Theme.chat_infoPaint, this.docTitleWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            }
            return 0;
        }
        boolean z = (this.documentAttach.mime_type != null && this.documentAttach.mime_type.toLowerCase().startsWith("image/")) || MessageObject.isDocumentHasThumb(this.documentAttach);
        this.drawPhotoImage = z;
        if (z) {
            maxWidth2 = maxWidth;
        } else {
            maxWidth2 = maxWidth + AndroidUtilities.dp(10.0f);
        }
        this.documentAttachType = 1;
        String name = FileLoader.getDocumentFileName(this.documentAttach);
        StaticLayout staticLayoutCreateStaticLayoutMiddle = StaticLayoutEx.createStaticLayoutMiddle((name == null || name.length() == 0) ? LocaleController.getString("AttachDocument", mpEIGo.juqQQs.esbSDO.R.string.AttachDocument) : name, Theme.chat_docNamePaint, maxWidth2, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false, TextUtils.TruncateAt.MIDDLE, maxWidth2, 2, false);
        this.docTitleLayout = staticLayoutCreateStaticLayoutMiddle;
        this.docTitleOffsetX = Integer.MIN_VALUE;
        if (staticLayoutCreateStaticLayoutMiddle != null && staticLayoutCreateStaticLayoutMiddle.getLineCount() > 0) {
            int maxLineWidth = 0;
            for (int a3 = 0; a3 < this.docTitleLayout.getLineCount(); a3++) {
                maxLineWidth = Math.max(maxLineWidth, (int) Math.ceil(this.docTitleLayout.getLineWidth(a3)));
                this.docTitleOffsetX = Math.max(this.docTitleOffsetX, (int) Math.ceil(-this.docTitleLayout.getLineLeft(a3)));
            }
            width = Math.min(maxWidth2, maxLineWidth);
        } else {
            int width2 = maxWidth2;
            this.docTitleOffsetX = 0;
            width = width2;
        }
        String str4 = AndroidUtilities.formatFileSize(this.documentAttach.size);
        this.infoWidth = Math.min(maxWidth2 - AndroidUtilities.dp(30.0f), (int) Math.ceil(Theme.chat_infoPaint.measureText(str4)));
        CharSequence str22 = TextUtils.ellipsize(str4, Theme.chat_infoPaint, this.infoWidth, TextUtils.TruncateAt.END);
        try {
            if (this.infoWidth < 0) {
                this.infoWidth = AndroidUtilities.dp(10.0f);
            }
            this.infoLayout = new StaticLayout(str22, Theme.chat_infoPaint, this.infoWidth + AndroidUtilities.dp(6.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (this.drawPhotoImage) {
            this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(messageObject.photoThumbs, 320);
            this.currentPhotoObjectThumb = FileLoader.getClosestPhotoSizeWithSize(messageObject.photoThumbs, 40);
            if ((DownloadController.getInstance(this.currentAccount).getAutodownloadMask() & 1) == 0) {
                this.currentPhotoObject = null;
            }
            TLRPC.PhotoSize photoSize = this.currentPhotoObject;
            if (photoSize == null || photoSize == this.currentPhotoObjectThumb) {
                this.currentPhotoObject = null;
                this.photoImage.setNeedsQualityThumb(true);
                this.photoImage.setShouldGenerateQualityThumb(true);
            }
            this.currentPhotoFilter = "86_86_b";
            this.photoImage.setImage(ImageLocation.getForObject(this.currentPhotoObject, messageObject.photoThumbsObject), "86_86", ImageLocation.getForObject(this.currentPhotoObjectThumb, messageObject.photoThumbsObject), this.currentPhotoFilter, 0, null, messageObject, 1);
        }
        return width;
    }

    private void calcBackgroundWidth(int maxWidth, int timeMore, int maxChildWidth) {
        if (this.hasLinkPreview || this.hasOldCaptionPreview || this.hasGamePreview || this.hasInvoicePreview || maxWidth - this.currentMessageObject.lastLineWidth < timeMore || this.currentMessageObject.hasRtl) {
            this.totalHeight += AndroidUtilities.dp(14.0f);
            this.hasNewLineForTime = true;
            int iMax = Math.max(maxChildWidth, this.currentMessageObject.lastLineWidth) + AndroidUtilities.dp(31.0f);
            this.backgroundWidth = iMax;
            this.backgroundWidth = Math.max(iMax, (this.currentMessageObject.isOutOwner() ? this.timeWidth + AndroidUtilities.dp(17.0f) : this.timeWidth) + AndroidUtilities.dp(31.0f));
            return;
        }
        int diff = maxChildWidth - this.currentMessageObject.lastLineWidth;
        if (diff >= 0 && diff <= timeMore) {
            this.backgroundWidth = ((maxChildWidth + timeMore) - diff) + AndroidUtilities.dp(31.0f);
        } else {
            this.backgroundWidth = Math.max(maxChildWidth, this.currentMessageObject.lastLineWidth + timeMore) + AndroidUtilities.dp(31.0f);
        }
    }

    public void setHighlightedText(String text) {
        MessageObject messageObject = this.messageObjectToSet;
        if (messageObject == null) {
            messageObject = this.currentMessageObject;
        }
        MessageObject messageObject2 = messageObject;
        boolean z = true;
        if (messageObject2 == null || messageObject2.messageOwner.message == null || TextUtils.isEmpty(text)) {
            if (!this.urlPathSelection.isEmpty()) {
                this.linkSelectionBlockNum = -1;
                resetUrlPaths(true);
                invalidate();
                return;
            }
            return;
        }
        String text2 = text.toLowerCase();
        String message = messageObject2.messageOwner.message.toLowerCase();
        int start = -1;
        int length = -1;
        int N1 = message.length();
        for (int a = 0; a < N1; a++) {
            int currentLen = 0;
            int N2 = Math.min(text2.length(), N1 - a);
            for (int b = 0; b < N2; b++) {
                boolean match = message.charAt(a + b) == text2.charAt(b);
                if (match) {
                    if (currentLen != 0 || a == 0 || " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n".indexOf(message.charAt(a - 1)) >= 0) {
                        currentLen++;
                    } else {
                        match = false;
                    }
                }
                if (!match || b == N2 - 1) {
                    if (currentLen > 0 && currentLen > length) {
                        length = currentLen;
                        start = a;
                    }
                }
            }
        }
        if (start == -1) {
            if (!this.urlPathSelection.isEmpty()) {
                this.linkSelectionBlockNum = -1;
                resetUrlPaths(true);
                invalidate();
                return;
            }
            return;
        }
        int N = message.length();
        for (int a2 = start + length; a2 < N && " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n".indexOf(message.charAt(a2)) < 0; a2++) {
            length++;
        }
        int N3 = start + length;
        if (this.captionLayout != null && !TextUtils.isEmpty(messageObject2.caption)) {
            resetUrlPaths(true);
            try {
                LinkPath path = obtainNewUrlPath(true);
                path.setCurrentLayout(this.captionLayout, start, 0.0f);
                this.captionLayout.getSelectionPath(start, N3, path);
            } catch (Exception e) {
                FileLog.e(e);
            }
            invalidate();
            return;
        }
        if (messageObject2.textLayoutBlocks != null) {
            int c = 0;
            while (c < messageObject2.textLayoutBlocks.size()) {
                MessageObject.TextLayoutBlock block = messageObject2.textLayoutBlocks.get(c);
                if (start < block.charactersOffset || start >= block.charactersOffset + block.textLayout.getText().length()) {
                    c++;
                    z = true;
                } else {
                    this.linkSelectionBlockNum = c;
                    resetUrlPaths(z);
                    try {
                        LinkPath path2 = obtainNewUrlPath(z);
                        path2.setCurrentLayout(block.textLayout, start, 0.0f);
                        block.textLayout.getSelectionPath(start, N3 - block.charactersOffset, path2);
                        if (N3 >= block.charactersOffset + length) {
                            int a3 = c + 1;
                            while (a3 < messageObject2.textLayoutBlocks.size()) {
                                MessageObject.TextLayoutBlock nextBlock = messageObject2.textLayoutBlocks.get(a3);
                                int length2 = nextBlock.textLayout.getText().length();
                                LinkPath path3 = obtainNewUrlPath(z);
                                path3.setCurrentLayout(nextBlock.textLayout, 0, nextBlock.height);
                                nextBlock.textLayout.getSelectionPath(0, N3 - nextBlock.charactersOffset, path3);
                                if (N3 < (block.charactersOffset + length2) - 1) {
                                    break;
                                }
                                a3++;
                                z = true;
                            }
                        }
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                    invalidate();
                    return;
                }
            }
        }
    }

    @Override // android.view.View
    protected boolean verifyDrawable(Drawable who) {
        return super.verifyDrawable(who) || who == this.selectorDrawable;
    }

    private boolean isCurrentLocationTimeExpired(MessageObject messageObject) {
        return this.currentMessageObject.messageOwner.media.period % 60 == 0 ? Math.abs(ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() - messageObject.messageOwner.date) > messageObject.messageOwner.media.period : Math.abs(ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() - messageObject.messageOwner.date) > messageObject.messageOwner.media.period + (-5);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkLocationExpired() {
        boolean newExpired;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && (newExpired = isCurrentLocationTimeExpired(messageObject)) != this.locationExpired) {
            this.locationExpired = newExpired;
            if (!newExpired) {
                AndroidUtilities.runOnUIThread(this.invalidateRunnable, 1000L);
                this.scheduledInvalidate = true;
                int maxWidth = this.backgroundWidth - AndroidUtilities.dp(91.0f);
                this.docTitleLayout = new StaticLayout(TextUtils.ellipsize(LocaleController.getString("AttachLiveLocation", mpEIGo.juqQQs.esbSDO.R.string.AttachLiveLocation), Theme.chat_locationTitlePaint, maxWidth, TextUtils.TruncateAt.END), Theme.chat_locationTitlePaint, maxWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                return;
            }
            MessageObject messageObject2 = this.currentMessageObject;
            this.currentMessageObject = null;
            setMessageObject(messageObject2, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
        }
    }

    public void setMessageObject(MessageObject messageObject, MessageObject.GroupedMessages groupedMessages, boolean bottomNear, boolean topNear) {
        if (this.attachedToWindow) {
            setMessageContent(messageObject, groupedMessages, bottomNear, topNear);
            return;
        }
        this.messageObjectToSet = messageObject;
        this.groupedMessagesToSet = groupedMessages;
        this.bottomNearToSet = bottomNear;
        this.topNearToSet = topNear;
    }

    private int getAdditionalWidthForPosition(MessageObject.GroupedMessagePosition position) {
        if (position != null) {
            int w = (position.flags & 2) == 0 ? 0 + AndroidUtilities.dp(4.0f) : 0;
            if ((position.flags & 1) == 0) {
                return w + AndroidUtilities.dp(4.0f);
            }
            return w;
        }
        return 0;
    }

    private void createSelectorDrawable() {
        if (Build.VERSION.SDK_INT < 21) {
            return;
        }
        Drawable drawable = this.selectorDrawable;
        String str = Theme.key_chat_outPreviewInstantText;
        if (drawable == null) {
            final Paint maskPaint = new Paint(1);
            maskPaint.setColor(-1);
            Drawable maskDrawable = new Drawable() { // from class: im.uwrkaxlmjj.ui.cells.ChatMessageCell.2
                RectF rect = new RectF();

                @Override // android.graphics.drawable.Drawable
                public void draw(Canvas canvas) {
                    Rect bounds = getBounds();
                    this.rect.set(bounds.left, bounds.top, bounds.right, bounds.bottom);
                    canvas.drawRoundRect(this.rect, ChatMessageCell.this.selectorDrawableMaskType == 0 ? AndroidUtilities.dp(6.0f) : 0.0f, ChatMessageCell.this.selectorDrawableMaskType == 0 ? AndroidUtilities.dp(6.0f) : 0.0f, maskPaint);
                }

                @Override // android.graphics.drawable.Drawable
                public void setAlpha(int alpha) {
                }

                @Override // android.graphics.drawable.Drawable
                public void setColorFilter(ColorFilter colorFilter) {
                }

                @Override // android.graphics.drawable.Drawable
                public int getOpacity() {
                    return -2;
                }
            };
            int[][] iArr = {StateSet.WILD_CARD};
            int[] iArr2 = new int[1];
            if (!this.currentMessageObject.isOutOwner()) {
                str = Theme.key_chat_inPreviewInstantText;
            }
            iArr2[0] = 1610612735 & Theme.getColor(str);
            ColorStateList colorStateList = new ColorStateList(iArr, iArr2);
            RippleDrawable rippleDrawable = new RippleDrawable(colorStateList, null, maskDrawable);
            this.selectorDrawable = rippleDrawable;
            rippleDrawable.setCallback(this);
        } else {
            if (!this.currentMessageObject.isOutOwner()) {
                str = Theme.key_chat_inPreviewInstantText;
            }
            Theme.setSelectorDrawableColor(drawable, 1610612735 & Theme.getColor(str), true);
        }
        this.selectorDrawable.setVisible(true, false);
    }

    private void createInstantViewButton() {
        String str;
        if (Build.VERSION.SDK_INT >= 21 && this.drawInstantView) {
            createSelectorDrawable();
        }
        if (this.drawInstantView && this.instantViewLayout == null) {
            this.instantWidth = AndroidUtilities.dp(33.0f);
            int i = this.drawInstantViewType;
            if (i == 1) {
                str = LocaleController.getString("OpenChannel", mpEIGo.juqQQs.esbSDO.R.string.OpenChannel);
            } else if (i == 2) {
                str = LocaleController.getString("OpenGroup", mpEIGo.juqQQs.esbSDO.R.string.OpenGroup);
            } else if (i == 3) {
                str = LocaleController.getString("OpenMessage", mpEIGo.juqQQs.esbSDO.R.string.OpenMessage);
            } else if (i == 5) {
                str = LocaleController.getString("ViewContact", mpEIGo.juqQQs.esbSDO.R.string.ViewContact);
            } else if (i == 6) {
                str = LocaleController.getString("OpenBackground", mpEIGo.juqQQs.esbSDO.R.string.OpenBackground);
            } else if (i == 7) {
                str = LocaleController.getString("OpenTheme", mpEIGo.juqQQs.esbSDO.R.string.OpenTheme);
            } else {
                str = LocaleController.getString("InstantView", mpEIGo.juqQQs.esbSDO.R.string.InstantView);
            }
            int mWidth = this.backgroundWidth - AndroidUtilities.dp(75.0f);
            this.instantViewLayout = new StaticLayout(TextUtils.ellipsize(str, Theme.chat_instantViewPaint, mWidth, TextUtils.TruncateAt.END), Theme.chat_instantViewPaint, mWidth + AndroidUtilities.dp(2.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.instantWidth = this.backgroundWidth - AndroidUtilities.dp(34.0f);
            this.totalHeight += AndroidUtilities.dp(46.0f);
            if (this.currentMessageObject.type == 12) {
                this.totalHeight += AndroidUtilities.dp(14.0f);
            }
            StaticLayout staticLayout = this.instantViewLayout;
            if (staticLayout != null && staticLayout.getLineCount() > 0) {
                this.instantTextX = (((int) (((double) this.instantWidth) - Math.ceil(this.instantViewLayout.getLineWidth(0)))) / 2) + (this.drawInstantViewType == 0 ? AndroidUtilities.dp(8.0f) : 0);
                int lineLeft = (int) this.instantViewLayout.getLineLeft(0);
                this.instantTextLeftX = lineLeft;
                this.instantTextX += -lineLeft;
            }
        }
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (this.inLayout) {
            return;
        }
        super.requestLayout();
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && (messageObject.checkLayout() || this.lastHeight != AndroidUtilities.displaySize.y)) {
            this.inLayout = true;
            MessageObject messageObject2 = this.currentMessageObject;
            this.currentMessageObject = null;
            setMessageObject(messageObject2, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
            this.inLayout = false;
        }
        int count = getChildCount();
        for (int i = 0; i < count; i++) {
            getChildAt(i).measure(widthMeasureSpec, heightMeasureSpec);
        }
        int i2 = View.MeasureSpec.getSize(widthMeasureSpec);
        setMeasuredDimension(i2, this.totalHeight + this.keyboardHeight);
    }

    public void forceResetMessageObject() {
        MessageObject messageObject = this.messageObjectToSet;
        if (messageObject == null) {
            messageObject = this.currentMessageObject;
        }
        this.currentMessageObject = null;
        setMessageObject(messageObject, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
    }

    private int getGroupPhotosWidth() {
        if (!AndroidUtilities.isInMultiwindow && AndroidUtilities.isTablet() && (!AndroidUtilities.isSmallTablet() || getResources().getConfiguration().orientation == 2)) {
            int leftWidth = (AndroidUtilities.displaySize.x / 100) * 35;
            if (leftWidth < AndroidUtilities.dp(320.0f)) {
                leftWidth = AndroidUtilities.dp(320.0f);
            }
            return AndroidUtilities.displaySize.x - leftWidth;
        }
        return AndroidUtilities.displaySize.x;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int x;
        int x2;
        MessageObject.GroupedMessagePosition groupedMessagePosition;
        MessageObject.GroupedMessages groupedMessages;
        int linkX;
        int x3;
        int x4;
        int x5;
        if (this.currentMessageObject != null) {
            float f = 40.0f;
            if (changed || !this.wasLayout) {
                this.layoutWidth = getMeasuredWidth();
                this.layoutHeight = getMeasuredHeight() - this.substractBackgroundHeight;
                if (this.timeTextWidth < 0) {
                    this.timeTextWidth = AndroidUtilities.dp(10.0f);
                }
                if (this.currentMessageObject.type != 105) {
                    this.timeLayout = new StaticLayout(this.currentTimeString, Theme.chat_timePaint, this.timeTextWidth + AndroidUtilities.dp(100.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                }
                if (!this.mediaBackground) {
                    if (!this.currentMessageObject.isOutOwner()) {
                        this.timeX = ((this.backgroundWidth - AndroidUtilities.dp(9.0f)) - this.timeWidth) + (this.isAvatarVisible ? AndroidUtilities.dp(48.0f) : 0);
                    } else {
                        this.timeX = ((this.layoutWidth - this.timeWidth) - AndroidUtilities.dp(38.5f)) - (this.isAvatarVisible ? AndroidUtilities.dp(48.0f) : 0);
                    }
                } else if (!this.currentMessageObject.isOutOwner()) {
                    this.timeX = ((this.backgroundWidth - AndroidUtilities.dp(4.0f)) - this.timeWidth) + (this.isAvatarVisible ? AndroidUtilities.dp(48.0f) : 0);
                    MessageObject.GroupedMessagePosition groupedMessagePosition2 = this.currentPosition;
                    if (groupedMessagePosition2 != null && groupedMessagePosition2.leftSpanOffset != 0) {
                        this.timeX += (int) Math.ceil((this.currentPosition.leftSpanOffset / 1000.0f) * getGroupPhotosWidth());
                    }
                } else {
                    this.timeX = ((this.layoutWidth - this.timeWidth) - AndroidUtilities.dp(42.0f)) - AndroidUtilities.dp(48.0f);
                }
                if ((this.currentMessageObject.messageOwner.flags & 1024) != 0) {
                    this.viewsLayout = new StaticLayout(this.currentViewsString, Theme.chat_timePaint, this.viewsTextWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                } else {
                    this.viewsLayout = null;
                }
                if (this.isAvatarVisible) {
                    if (this.currentMessageObject.isOutOwner()) {
                        this.avatarImage.setImageCoords(AndroidUtilities.displaySize.x - AndroidUtilities.dp(47.5f), this.avatarImage.getImageY(), AndroidUtilities.dp(40.0f), AndroidUtilities.dp(40.0f));
                    } else {
                        this.avatarImage.setImageCoords(AndroidUtilities.dp(7.5f), this.avatarImage.getImageY(), AndroidUtilities.dp(40.0f), AndroidUtilities.dp(40.0f));
                    }
                }
                this.wasLayout = true;
            }
            if (this.currentMessageObject.type == 0) {
                this.textY = AndroidUtilities.dp(10.0f) + this.namesOffset;
            }
            if (this.currentMessageObject.isRoundVideo()) {
                updatePlayingMessageProgress();
            }
            int i = this.documentAttachType;
            if (i == 3) {
                if (this.currentMessageObject.isOutOwner()) {
                    this.seekBarX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(57.0f)) - AndroidUtilities.dp(66.0f);
                    this.buttonX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(14.0f)) - AndroidUtilities.dp(54.0f);
                    this.timeAudioX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(67.0f)) - AndroidUtilities.dp(66.0f);
                } else if (!this.isAvatarVisible || !this.currentMessageObject.needDrawAvatar()) {
                    this.seekBarX = AndroidUtilities.dp(54.0f);
                    this.buttonX = AndroidUtilities.dp(23.0f);
                    this.timeAudioX = AndroidUtilities.dp(64.0f);
                } else {
                    this.seekBarX = AndroidUtilities.dp(102.0f);
                    this.buttonX = AndroidUtilities.dp(71.0f);
                    this.timeAudioX = AndroidUtilities.dp(112.0f);
                }
                if (this.hasLinkPreview) {
                    this.seekBarX += AndroidUtilities.dp(10.0f);
                    this.buttonX += AndroidUtilities.dp(10.0f);
                    this.timeAudioX += AndroidUtilities.dp(10.0f);
                }
                this.seekBarWaveform.setSize(this.backgroundWidth - AndroidUtilities.dp((this.hasLinkPreview ? 10 : 0) + 72), AndroidUtilities.dp(30.0f));
                this.seekBar.setSize(this.backgroundWidth - AndroidUtilities.dp((this.hasLinkPreview ? 10 : 0) + 52), AndroidUtilities.dp(30.0f));
                this.seekBarY = (((AndroidUtilities.dp(13.0f) + this.namesOffset) + this.mediaOffsetY) + mOffset) - AndroidUtilities.dp(10.0f);
                this.buttonY = AndroidUtilities.dp(13.0f) + this.namesOffset + this.mediaOffsetY + mOffset;
                this.radialProgress.setCircleRadius(AndroidUtilities.dp(16.0f));
                this.radialProgress.setDrawRoundRect(false);
                RadialProgress2 radialProgress2 = this.radialProgress;
                int i2 = this.buttonX;
                radialProgress2.setProgressRect(i2, this.buttonY, AndroidUtilities.dp(32.0f) + i2, this.buttonY + AndroidUtilities.dp(32.0f));
                updatePlayingMessageProgress();
            } else if (i == 5) {
                if (this.currentMessageObject.isOutOwner()) {
                    this.seekBarX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(56.0f)) - AndroidUtilities.dp(56.0f);
                    this.buttonX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(14.0f)) - AndroidUtilities.dp(56.0f);
                    this.timeAudioX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(67.0f)) - AndroidUtilities.dp(56.0f);
                } else if (!this.isChat || !this.currentMessageObject.needDrawAvatar()) {
                    this.seekBarX = AndroidUtilities.dp(65.0f) + AndroidUtilities.dp(48.0f);
                    this.buttonX = AndroidUtilities.dp(23.0f) + AndroidUtilities.dp(48.0f);
                    this.timeAudioX = AndroidUtilities.dp(76.0f) + AndroidUtilities.dp(48.0f);
                } else {
                    this.seekBarX = AndroidUtilities.dp(113.0f);
                    this.buttonX = AndroidUtilities.dp(71.0f);
                    this.timeAudioX = AndroidUtilities.dp(124.0f);
                }
                if (this.hasLinkPreview) {
                    this.seekBarX += AndroidUtilities.dp(10.0f);
                    this.buttonX += AndroidUtilities.dp(10.0f);
                    this.timeAudioX += AndroidUtilities.dp(10.0f);
                }
                this.seekBar.setSize(this.backgroundWidth - AndroidUtilities.dp((this.hasLinkPreview ? 10 : 0) + 65), AndroidUtilities.dp(30.0f));
                this.seekBarY = AndroidUtilities.dp(29.0f) + this.namesOffset + this.mediaOffsetY;
                int iDp = AndroidUtilities.dp(13.0f) + this.namesOffset + this.mediaOffsetY;
                this.buttonY = iDp;
                RadialProgress2 radialProgress22 = this.radialProgress;
                int i3 = this.buttonX;
                radialProgress22.setProgressRect(i3, iDp, AndroidUtilities.dp(44.0f) + i3, this.buttonY + AndroidUtilities.dp(44.0f));
                updatePlayingMessageProgress();
            } else if (i == 1 && !this.drawPhotoImage) {
                if (this.currentMessageObject.isOutOwner()) {
                    this.buttonX = ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(14.0f)) - AndroidUtilities.dp(54.0f);
                } else if (this.currentMessageObject.needDrawAvatar()) {
                    this.buttonX = AndroidUtilities.dp(71.0f);
                } else {
                    this.buttonX = AndroidUtilities.dp(23.0f);
                }
                if (this.hasLinkPreview) {
                    this.buttonX += AndroidUtilities.dp(10.0f);
                }
                int iDp2 = AndroidUtilities.dp(13.0f) + this.namesOffset + this.mediaOffsetY + mOffset;
                this.buttonY = iDp2;
                RadialProgress2 radialProgress23 = this.radialProgress;
                int i4 = this.buttonX;
                radialProgress23.setProgressRect(i4, iDp2, AndroidUtilities.dp(44.0f) + i4, this.buttonY + AndroidUtilities.dp(44.0f));
                this.radialProgress.setCircleRadius(AndroidUtilities.dp(22.0f));
                this.radialProgress.setDrawRoundRect(true);
                this.photoImage.setImageCoords(this.buttonX - AndroidUtilities.dp(10.0f), this.buttonY - AndroidUtilities.dp(10.0f), this.photoImage.getImageWidth(), this.photoImage.getImageHeight());
            } else if (this.currentMessageObject.type != 12) {
                if (this.currentMessageObject.type == 101 || this.currentMessageObject.type == 102) {
                    if (this.currentMessageObject.isOutOwner()) {
                        x = (this.layoutWidth - this.backgroundWidth) - AndroidUtilities.dp(42.0f);
                    } else if (this.isAvatarVisible) {
                        x = AndroidUtilities.dp(68.0f);
                    } else {
                        x = AndroidUtilities.dp(19.0f);
                    }
                    if (this.currentMessageObject.type == 101) {
                        this.photoImage.setImageCoords(x, AndroidUtilities.dp(18.0f) + this.namesOffset, AndroidUtilities.dp(44.0f), AndroidUtilities.dp(49.0f));
                    } else {
                        this.photoImage.setImageCoords(x, AndroidUtilities.dp(18.0f) + this.namesOffset, this.photoImage.getBitmapWidth(), this.photoImage.getBitmapHeight());
                    }
                } else {
                    int i5 = 4;
                    if (this.currentMessageObject.type != 105) {
                        if (this.currentMessageObject.type != 103) {
                            if (this.currentMessageObject.type == 207) {
                                if (this.currentMessageObject.isOutOwner()) {
                                    x3 = (this.layoutWidth - this.backgroundWidth) - AndroidUtilities.dp(40.0f);
                                } else if (!this.isChat || this.currentMessageObject.needDrawAvatar()) {
                                    x3 = AndroidUtilities.dp(73.0f);
                                } else {
                                    x3 = AndroidUtilities.dp(73.0f);
                                }
                                if (ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup) {
                                    x3 -= AndroidUtilities.dp(53.0f);
                                }
                                this.photoImage.setImageCoords(x3 - AndroidUtilities.dp(5.0f), AndroidUtilities.dp(70.0f) + this.namesOffset, this.backgroundWidth - AndroidUtilities.dp(25.0f), AndroidUtilities.dp(150.0f));
                            } else {
                                if (this.currentMessageObject.type == 0 && (this.hasLinkPreview || this.hasGamePreview || this.hasInvoicePreview)) {
                                    if (this.hasGamePreview) {
                                        linkX = this.unmovedTextX - AndroidUtilities.dp(10.0f);
                                    } else if (this.hasInvoicePreview) {
                                        linkX = this.unmovedTextX + AndroidUtilities.dp(1.0f);
                                    } else {
                                        int linkX2 = this.unmovedTextX;
                                        linkX = linkX2 + AndroidUtilities.dp(1.0f);
                                    }
                                    x2 = this.isSmallImage ? (this.backgroundWidth + linkX) - AndroidUtilities.dp(81.0f) : (this.hasInvoicePreview ? -AndroidUtilities.dp(6.3f) : AndroidUtilities.dp(10.0f)) + linkX;
                                } else if (this.currentMessageObject.isOutOwner()) {
                                    x2 = this.mediaBackground ? ((this.layoutWidth - this.backgroundWidth) - AndroidUtilities.dp(3.0f)) - AndroidUtilities.dp((this.isAvatarVisible || ((groupedMessagePosition = this.currentPosition) != null && groupedMessagePosition.edge)) ? 48.0f : 0.0f) : ((this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(6.0f)) - AndroidUtilities.dp(54.0f);
                                } else if (this.isAvatarVisible) {
                                    x2 = AndroidUtilities.dp(63.0f);
                                } else {
                                    MessageObject.GroupedMessagePosition groupedMessagePosition3 = this.currentPosition;
                                    if (groupedMessagePosition3 != null) {
                                        if (groupedMessagePosition3.edge) {
                                            updateCurrentUserAndChat();
                                            x2 = (this.isAvatarVisible || ChatObject.isChannel(this.currentChat)) ? AndroidUtilities.dp(15.0f) : AndroidUtilities.dp(63.0f);
                                        } else {
                                            x2 = AndroidUtilities.dp(5.0f);
                                        }
                                    } else {
                                        x2 = AndroidUtilities.dp(15.0f);
                                    }
                                }
                                MessageObject.GroupedMessagePosition groupedMessagePosition4 = this.currentPosition;
                                if (groupedMessagePosition4 != null) {
                                    if ((groupedMessagePosition4.flags & 1) == 0) {
                                        x2 -= AndroidUtilities.dp(2.0f);
                                    }
                                    if (this.currentPosition.leftSpanOffset != 0) {
                                        x2 += (int) Math.ceil((this.currentPosition.leftSpanOffset / 1000.0f) * getGroupPhotosWidth());
                                    }
                                }
                                if (this.currentMessageObject.type != 0) {
                                    x2 -= AndroidUtilities.dp(2.0f);
                                }
                                if (BuildVars.DEBUG_VERSION) {
                                    int pcIndex = -1;
                                    if (this.currentMessageObject != null && (groupedMessages = this.currentMessagesGroup) != null) {
                                        for (int i6 = groupedMessages.messages.size() - 1; i6 >= 0; i6--) {
                                            if (this.currentMessagesGroup.messages.get(i6) == this.currentMessageObject) {
                                                pcIndex = i6;
                                            }
                                        }
                                    }
                                    if (BuildVars.DEBUG_VERSION) {
                                        StringBuilder sb = new StringBuilder();
                                        sb.append("onLayout() ===>  , pcIndex=");
                                        sb.append(pcIndex);
                                        sb.append(" , isAvatarVisible=");
                                        sb.append(this.isAvatarVisible);
                                        sb.append(" , edge=");
                                        MessageObject.GroupedMessagePosition groupedMessagePosition5 = this.currentPosition;
                                        sb.append(groupedMessagePosition5 != null ? Boolean.valueOf(groupedMessagePosition5.edge) : "false");
                                        sb.append(" , pc id=");
                                        MessageObject messageObject = this.currentMessageObject;
                                        sb.append((messageObject == null || messageObject.messageOwner == null || this.currentMessageObject.messageOwner.media == null || this.currentMessageObject.messageOwner.media.photo == null) ? "null" : Long.valueOf(this.currentMessageObject.messageOwner.media.photo.id));
                                        sb.append(" , x=");
                                        sb.append(x2);
                                        sb.append(" , y=");
                                        sb.append(this.photoImage.getImageY());
                                        sb.append(" , w=");
                                        sb.append(this.photoImage.getImageWidth());
                                        sb.append(" , h=");
                                        sb.append(this.photoImage.getImageHeight());
                                        Log.i("CMCell", sb.toString());
                                    }
                                }
                                ImageReceiver imageReceiver = this.photoImage;
                                imageReceiver.setImageCoords(x2, imageReceiver.getImageY(), this.photoImage.getImageWidth(), this.photoImage.getImageHeight());
                                this.buttonX = (int) (x2 + ((this.photoImage.getImageWidth() - AndroidUtilities.dp(48.0f)) / 2.0f));
                                int imageY = this.photoImage.getImageY() + ((this.photoImage.getImageHeight() - AndroidUtilities.dp(48.0f)) / 2);
                                this.buttonY = imageY;
                                RadialProgress2 radialProgress24 = this.radialProgress;
                                int i7 = this.buttonX;
                                radialProgress24.setProgressRect(i7, imageY, AndroidUtilities.dp(48.0f) + i7, this.buttonY + AndroidUtilities.dp(48.0f));
                                this.radialProgress.setDrawRoundRect(false);
                                this.deleteProgressRect.set(this.buttonX + AndroidUtilities.dp(5.0f), this.buttonY + AndroidUtilities.dp(5.0f), this.buttonX + AndroidUtilities.dp(43.0f), this.buttonY + AndroidUtilities.dp(43.0f));
                                int i8 = this.documentAttachType;
                                if (i8 == 4 || i8 == 2) {
                                    this.videoButtonX = this.photoImage.getImageX() + AndroidUtilities.dp(8.0f);
                                    int imageY2 = this.photoImage.getImageY() + AndroidUtilities.dp(8.0f);
                                    this.videoButtonY = imageY2;
                                    RadialProgress2 radialProgress25 = this.videoRadialProgress;
                                    int i9 = this.videoButtonX;
                                    radialProgress25.setProgressRect(i9, imageY2, AndroidUtilities.dp(24.0f) + i9, this.videoButtonY + AndroidUtilities.dp(24.0f));
                                }
                            }
                        } else {
                            if (this.currentMessageObject.isOutOwner()) {
                                x4 = (this.layoutWidth - this.backgroundWidth) - AndroidUtilities.dp(40.0f);
                            } else if (!this.isChat || this.currentMessageObject.needDrawAvatar()) {
                                x4 = AndroidUtilities.dp(73.0f);
                            } else {
                                x4 = AndroidUtilities.dp(73.0f);
                            }
                            if (ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup) {
                                x4 -= AndroidUtilities.dp(50.0f);
                            }
                            this.photoImage.setImageCoords(x4, AndroidUtilities.dp(20.0f) + this.namesOffset, AndroidUtilities.dp(44.0f), AndroidUtilities.dp(44.0f));
                        }
                    } else {
                        TLRPCContacts.TL_messageMediaSysNotify sysNotify = (TLRPCContacts.TL_messageMediaSysNotify) this.currentMessageObject.messageOwner.media;
                        if (sysNotify.business_code == 1 || sysNotify.business_code == 2 || sysNotify.business_code == 3 || sysNotify.business_code == 10) {
                            ImageReceiver imageReceiver2 = this.photoFCImage;
                            float f2 = 60.0f;
                            if (imageReceiver2 != null) {
                                imageReceiver2.setImageCoords(AndroidUtilities.dp(40.0f), (this.totalHeight - AndroidUtilities.dp(30.0f)) - AndroidUtilities.dp(46.0f), this.backgroundWidth - AndroidUtilities.dp(60.0f), AndroidUtilities.dp(46.0f));
                            }
                            int m = 0;
                            int n = 0;
                            int spacingHeight = AndroidUtilities.dp(15.0f);
                            int i10 = 0;
                            while (i10 < this.mSysNotifyData.size()) {
                                TLRPCContacts.NotifyMsg msgData = this.mSysNotifyData.get(Integer.valueOf(i10));
                                if (msgData instanceof TLRPCContacts.NotifyMsgText) {
                                    m++;
                                } else if (msgData instanceof TLRPCContacts.NotifyMsgMedia) {
                                    if (i10 == 0) {
                                        ImageReceiver imageReceiver3 = this.photoImage1;
                                        if (imageReceiver3 != null) {
                                            imageReceiver3.setImageCoords(AndroidUtilities.dp(f), (int) (AndroidUtilities.dp(45.0f) * 2.5f), this.backgroundWidth - AndroidUtilities.dp(f2), (int) this.photo1Height);
                                            n++;
                                        }
                                    } else {
                                        TLRPCContacts.NotifyMsg lastData = this.mSysNotifyData.get(Integer.valueOf(i10 - 1));
                                        if (lastData instanceof TLRPCContacts.NotifyMsgText) {
                                            if (m != 1) {
                                                if (m != 2) {
                                                    if (m != 3) {
                                                        if (m != i5) {
                                                            if (m == 5) {
                                                                if (n == 0) {
                                                                    this.photoImage1.setImageCoords(AndroidUtilities.dp(40.0f), this.textInfoLayout1.getHeight() + this.textInfoLayout2.getHeight() + this.textInfoLayout3.getHeight() + this.textInfoLayout4.getHeight() + this.textInfoLayout5.getHeight() + AndroidUtilities.dp(95.0f) + (spacingHeight * 5), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo1Height);
                                                                } else if (n == 1) {
                                                                    this.photoImage2.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage1.getImageY() + this.photo1Height + this.textInfoLayout5.getHeight() + (spacingHeight * 2)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo2Height);
                                                                } else if (n == 2) {
                                                                    this.photoImage3.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage2.getImageY() + this.photo2Height + this.textInfoLayout5.getHeight() + (spacingHeight * 3)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo3Height);
                                                                } else if (n == 3) {
                                                                    this.photoImage4.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage3.getImageY() + this.photo3Height + this.textInfoLayout5.getHeight() + (spacingHeight * 4)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo4Height);
                                                                } else if (n == i5) {
                                                                    this.photoImage5.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage4.getImageY() + this.photo4Height + this.textInfoLayout5.getHeight() + (spacingHeight * 5)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo5Height);
                                                                }
                                                            }
                                                        } else if (n == 0) {
                                                            this.photoImage1.setImageCoords(AndroidUtilities.dp(40.0f), this.textInfoLayout1.getHeight() + this.textInfoLayout2.getHeight() + this.textInfoLayout3.getHeight() + this.textInfoLayout4.getHeight() + AndroidUtilities.dp(95.0f) + (spacingHeight * 4), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo1Height);
                                                        } else if (n == 1) {
                                                            this.photoImage2.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage1.getImageY() + this.photo1Height + this.textInfoLayout4.getHeight() + (spacingHeight * 2)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo2Height);
                                                        } else if (n == 2) {
                                                            this.photoImage3.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage2.getImageY() + this.photo2Height + this.textInfoLayout4.getHeight() + (spacingHeight * 3)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo3Height);
                                                        } else if (n == 3) {
                                                            this.photoImage4.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage3.getImageY() + this.photo3Height + this.textInfoLayout4.getHeight() + (spacingHeight * 4)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo4Height);
                                                        } else if (n == 4) {
                                                            this.photoImage5.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage4.getImageY() + this.photo4Height + this.textInfoLayout4.getHeight() + (spacingHeight * 5)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo5Height);
                                                        }
                                                    } else if (n == 0) {
                                                        this.photoImage1.setImageCoords(AndroidUtilities.dp(40.0f), this.textInfoLayout1.getHeight() + this.textInfoLayout2.getHeight() + this.textInfoLayout3.getHeight() + AndroidUtilities.dp(95.0f) + (spacingHeight * 3), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo1Height);
                                                    } else if (n == 1) {
                                                        this.photoImage2.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage1.getImageY() + this.photo1Height + this.textInfoLayout3.getHeight() + (spacingHeight * 2)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo2Height);
                                                    } else if (n == 2) {
                                                        this.photoImage3.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage2.getImageY() + this.photo2Height + this.textInfoLayout3.getHeight() + (spacingHeight * 3)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo3Height);
                                                    } else if (n == 3) {
                                                        this.photoImage4.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage3.getImageY() + this.photo3Height + this.textInfoLayout3.getHeight() + (spacingHeight * 4)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo4Height);
                                                    } else if (n == 4) {
                                                        this.photoImage5.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage4.getImageY() + this.photo4Height + this.textInfoLayout3.getHeight() + (spacingHeight * 5)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo5Height);
                                                    }
                                                } else if (n == 0) {
                                                    this.photoImage1.setImageCoords(AndroidUtilities.dp(40.0f), this.textInfoLayout1.getHeight() + this.textInfoLayout2.getHeight() + AndroidUtilities.dp(95.0f) + (spacingHeight * 2), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo1Height);
                                                } else if (n == 1) {
                                                    this.photoImage2.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage1.getImageY() + this.photo1Height + this.textInfoLayout2.getHeight() + (spacingHeight * 2)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo2Height);
                                                } else if (n == 2) {
                                                    this.photoImage3.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage2.getImageY() + this.photo2Height + this.textInfoLayout2.getHeight() + (spacingHeight * 3)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo3Height);
                                                } else if (n == 3) {
                                                    this.photoImage4.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage3.getImageY() + this.photo3Height + this.textInfoLayout2.getHeight() + (spacingHeight * 4)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo4Height);
                                                } else if (n == 4) {
                                                    this.photoImage5.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage4.getImageY() + this.photo4Height + this.textInfoLayout2.getHeight() + (spacingHeight * 5)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo5Height);
                                                }
                                            } else if (n == 0) {
                                                this.photoImage1.setImageCoords(AndroidUtilities.dp(40.0f), this.textInfoLayout1.getHeight() + AndroidUtilities.dp(95.0f) + spacingHeight, this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo1Height);
                                            } else if (n == 1) {
                                                this.photoImage2.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage1.getImageY() + this.photo1Height + this.textInfoLayout1.getHeight() + (spacingHeight * 2)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo2Height);
                                            } else if (n == 2) {
                                                this.photoImage3.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage2.getImageY() + this.photo2Height + this.textInfoLayout1.getHeight() + (spacingHeight * 3)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo3Height);
                                            } else if (n == 3) {
                                                this.photoImage4.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage3.getImageY() + this.photo3Height + this.textInfoLayout1.getHeight() + (spacingHeight * 4)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo4Height);
                                            } else if (n == 4) {
                                                this.photoImage5.setImageCoords(AndroidUtilities.dp(40.0f), (int) (this.photoImage4.getImageY() + this.photo4Height + this.textInfoLayout1.getHeight() + (spacingHeight * 5)), this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo5Height);
                                            }
                                            n++;
                                        } else if (lastData instanceof TLRPCContacts.NotifyMsgMedia) {
                                            if (n == 1) {
                                                this.photoImage2.setImageCoords(AndroidUtilities.dp(40.0f), this.photoImage1.getImageY() + this.photoImage1.getImageHeight() + spacingHeight, this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo2Height);
                                            } else if (n == 2) {
                                                this.photoImage3.setImageCoords(AndroidUtilities.dp(40.0f), this.photoImage2.getImageY() + this.photoImage2.getImageHeight() + spacingHeight, this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo3Height);
                                            } else if (n == 3) {
                                                this.photoImage4.setImageCoords(AndroidUtilities.dp(40.0f), this.photoImage3.getImageY() + this.photoImage3.getImageHeight() + spacingHeight, this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo4Height);
                                            } else if (n == 4) {
                                                this.photoImage5.setImageCoords(AndroidUtilities.dp(40.0f), this.photoImage4.getImageY() + this.photoImage4.getImageHeight() + spacingHeight, this.backgroundWidth - AndroidUtilities.dp(60.0f), (int) this.photo5Height);
                                            }
                                            n++;
                                        }
                                    }
                                }
                                i10++;
                                f = 40.0f;
                                f2 = 60.0f;
                                i5 = 4;
                            }
                        } else {
                            ImageReceiver imageReceiver4 = this.photoImage;
                            if (imageReceiver4 != null) {
                                imageReceiver4.setImageCoords(AndroidUtilities.dp(30.0f), AndroidUtilities.dp(12.0f), AndroidUtilities.dp(44.0f), AndroidUtilities.dp(44.0f));
                            }
                            ImageReceiver imageReceiver5 = this.photoFCImage;
                            if (imageReceiver5 != null) {
                                imageReceiver5.setImageCoords(this.backgroundWidth - AndroidUtilities.dp(76.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(66.0f), AndroidUtilities.dp(66.0f));
                            }
                        }
                    }
                }
            } else {
                if (this.currentMessageObject.isOutOwner()) {
                    x5 = (this.layoutWidth - this.backgroundWidth) + AndroidUtilities.dp(14.0f);
                } else if (this.isChat && this.currentMessageObject.needDrawAvatar()) {
                    x5 = AndroidUtilities.dp(72.0f);
                } else {
                    x5 = AndroidUtilities.dp(23.0f);
                }
                this.photoImage.setImageCoords(x5, AndroidUtilities.dp(13.0f) + this.namesOffset, AndroidUtilities.dp(44.0f), AndroidUtilities.dp(44.0f));
            }
            int childCount = getChildCount();
            if (this.currentMessageObject.type == 105) {
                TLRPCContacts.TL_messageMediaSysNotify sysNotify2 = (TLRPCContacts.TL_messageMediaSysNotify) this.currentMessageObject.messageOwner.media;
                if (sysNotify2.business_code == 1 || sysNotify2.business_code == 2 || sysNotify2.business_code == 3 || sysNotify2.business_code == 10) {
                    for (int i11 = 0; i11 < childCount; i11++) {
                        View view = getChildAt(i11);
                        view.layout((int) (-AndroidUtilities.dpf2(5.0f)), (int) (-AndroidUtilities.dpf2(9.0f)), view.getMeasuredWidth(), view.getMeasuredHeight());
                    }
                    return;
                }
                for (int i12 = 0; i12 < childCount; i12++) {
                    getChildAt(i12).layout(AndroidUtilities.dp(9.0f), 0, this.backgroundWidth + AndroidUtilities.dp(9.0f), this.totalHeight + AndroidUtilities.dp(9.0f));
                }
            }
        }
    }

    public boolean needDelayRoundProgressDraw() {
        int i = this.documentAttachType;
        return (i == 7 || i == 4) && this.currentMessageObject.type != 5 && MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
    }

    public void drawRoundProgress(Canvas canvas) {
        this.rect.set(this.photoImage.getImageX() + AndroidUtilities.dpf2(1.5f), this.photoImage.getImageY() + AndroidUtilities.dpf2(1.5f), this.photoImage.getImageX2() - AndroidUtilities.dpf2(1.5f), this.photoImage.getImageY2() - AndroidUtilities.dpf2(1.5f));
        canvas.drawArc(this.rect, -90.0f, this.currentMessageObject.audioProgress * 360.0f, false, Theme.chat_radialProgressPaint);
    }

    private void updatePollAnimations() {
        long newTime = System.currentTimeMillis();
        long dt = newTime - this.voteLastUpdateTime;
        if (dt > 17) {
            dt = 17;
        }
        this.voteLastUpdateTime = newTime;
        if (this.pollVoteInProgress) {
            float f = this.voteRadOffset + ((360 * dt) / 2000.0f);
            this.voteRadOffset = f;
            int count = (int) (f / 360.0f);
            this.voteRadOffset = f - (count * 360);
            float f2 = this.voteCurrentProgressTime + dt;
            this.voteCurrentProgressTime = f2;
            if (f2 >= 500.0f) {
                this.voteCurrentProgressTime = 500.0f;
            }
            if (!this.voteRisingCircleLength) {
                this.voteCurrentCircleLength = 4.0f - ((this.firstCircleLength ? 360 : JavaScreenCapturer.DEGREE_270) * (1.0f - AndroidUtilities.decelerateInterpolator.getInterpolation(this.voteCurrentProgressTime / 500.0f)));
            } else {
                this.voteCurrentCircleLength = (AndroidUtilities.accelerateInterpolator.getInterpolation(this.voteCurrentProgressTime / 500.0f) * 266.0f) + 4.0f;
            }
            if (this.voteCurrentProgressTime == 500.0f) {
                if (this.voteRisingCircleLength) {
                    this.voteRadOffset += 270.0f;
                    this.voteCurrentCircleLength = -266.0f;
                }
                this.voteRisingCircleLength = !this.voteRisingCircleLength;
                if (this.firstCircleLength) {
                    this.firstCircleLength = false;
                }
                this.voteCurrentProgressTime = 0.0f;
            }
            invalidate();
        }
        if (this.animatePollAnswer) {
            float f3 = this.pollAnimationProgressTime + dt;
            this.pollAnimationProgressTime = f3;
            if (f3 >= 300.0f) {
                this.pollAnimationProgressTime = 300.0f;
            }
            float interpolation = AndroidUtilities.decelerateInterpolator.getInterpolation(this.pollAnimationProgressTime / 300.0f);
            this.pollAnimationProgress = interpolation;
            if (interpolation >= 1.0f) {
                this.pollAnimationProgress = 1.0f;
                this.animatePollAnswer = false;
                this.animatePollAnswerAlpha = false;
                this.pollVoteInProgress = false;
                this.pollUnvoteInProgress = false;
            }
            invalidate();
        }
    }

    private void drawContent(Canvas canvas) {
        int i;
        ViewGroup viewGroup;
        MessageObject.GroupedMessages groupedMessages;
        float f;
        Drawable audio;
        Drawable translate;
        int x1;
        int y1;
        int i2;
        int addX;
        int x;
        int titleY;
        int subtitleY;
        int linkX;
        int x2;
        int x3;
        boolean z;
        int startY;
        int linkX2;
        int i3;
        int i4;
        float f2;
        Drawable instantDrawable;
        int x4;
        int y;
        int x5;
        Drawable translate2;
        if (this.needNewVisiblePart && this.currentMessageObject.type == 0) {
            getLocalVisibleRect(this.scrollRect);
            setVisiblePart(this.scrollRect.top, this.scrollRect.bottom - this.scrollRect.top);
            this.needNewVisiblePart = false;
        }
        this.forceNotDrawTime = this.currentMessagesGroup != null;
        this.photoImage.setVisible((PhotoViewer.isShowingImage(this.currentMessageObject) || SecretMediaViewer.getInstance().isShowingImage(this.currentMessageObject)) ? false : true, false);
        if (!this.photoImage.getVisible()) {
            this.mediaWasInvisible = true;
            this.timeWasInvisible = true;
            int i5 = this.animatingNoSound;
            if (i5 == 1) {
                this.animatingNoSoundProgress = 0.0f;
                this.animatingNoSound = 0;
            } else if (i5 == 2) {
                this.animatingNoSoundProgress = 1.0f;
                this.animatingNoSound = 0;
            }
        } else if (this.groupPhotoInvisible) {
            this.timeWasInvisible = true;
        } else if (this.mediaWasInvisible || this.timeWasInvisible) {
            if (this.mediaWasInvisible) {
                this.controlsAlpha = 0.0f;
                this.mediaWasInvisible = false;
            }
            if (this.timeWasInvisible) {
                this.timeAlpha = 0.0f;
                this.timeWasInvisible = false;
            }
            this.lastControlsAlphaChangeTime = System.currentTimeMillis();
            this.totalChangeTime = 0L;
        }
        this.radialProgress.setProgressColor(Theme.getColor(Theme.key_chat_mediaProgress));
        this.videoRadialProgress.setProgressColor(Theme.getColor(Theme.key_chat_mediaProgress));
        boolean imageDrawn = false;
        if (this.currentMessageObject.type == 0) {
            if (this.currentMessageObject.isOutOwner()) {
                this.textX = this.currentBackgroundDrawable.getBounds().left + AndroidUtilities.dp(11.0f);
            } else {
                int i6 = this.currentBackgroundDrawable.getBounds().left;
                if (this.mediaBackground || this.drawPinnedBottom) {
                }
                this.textX = i6 + AndroidUtilities.dp(11.0f);
            }
            if (this.hasGamePreview) {
                this.textX += AndroidUtilities.dp(11.0f);
                int iDp = AndroidUtilities.dp(14.0f) + this.namesOffset;
                this.textY = iDp;
                StaticLayout staticLayout = this.siteNameLayout;
                if (staticLayout != null) {
                    this.textY = iDp + staticLayout.getLineBottom(staticLayout.getLineCount() - 1);
                }
            } else if (this.hasInvoicePreview) {
                int iDp2 = AndroidUtilities.dp(14.0f) + this.namesOffset;
                this.textY = iDp2;
                StaticLayout staticLayout2 = this.siteNameLayout;
                if (staticLayout2 != null) {
                    this.textY = iDp2 + staticLayout2.getLineBottom(staticLayout2.getLineCount() - 1);
                }
            } else {
                int iDp3 = AndroidUtilities.dp(10.0f) + this.namesOffset;
                this.textY = iDp3;
                this.textY = iDp3 + mOffset;
            }
            this.unmovedTextX = this.textX;
            if (this.currentMessageObject.textXOffset != 0.0f && this.replyNameLayout != null) {
                int diff = (this.backgroundWidth - AndroidUtilities.dp(31.0f)) - this.currentMessageObject.textWidth;
                if (!this.hasNewLineForTime) {
                    diff -= this.timeWidth + AndroidUtilities.dp((this.currentMessageObject.isOutOwner() ? 20 : 0) + 4);
                }
                if (diff > 0) {
                    this.textX += diff;
                }
            }
            if (this.currentMessageObject.textLayoutBlocks != null && !this.currentMessageObject.textLayoutBlocks.isEmpty()) {
                if (this.fullyDraw) {
                    this.firstVisibleBlockNum = 0;
                    this.lastVisibleBlockNum = this.currentMessageObject.textLayoutBlocks.size();
                }
                if (this.firstVisibleBlockNum >= 0) {
                    for (int a = this.firstVisibleBlockNum; a <= this.lastVisibleBlockNum && a < this.currentMessageObject.textLayoutBlocks.size(); a++) {
                        MessageObject.TextLayoutBlock block = this.currentMessageObject.textLayoutBlocks.get(a);
                        canvas.save();
                        canvas.translate(this.textX - (block.isRtl() ? (int) Math.ceil(this.currentMessageObject.textXOffset) : 0), this.textY + block.textYOffset);
                        if (this.pressedLink != null && a == this.linkBlockNum) {
                            for (int b = 0; b < this.urlPath.size(); b++) {
                                canvas.drawPath(this.urlPath.get(b), Theme.chat_urlPaint);
                            }
                        }
                        int b2 = this.linkSelectionBlockNum;
                        if (a == b2 && !this.urlPathSelection.isEmpty()) {
                            for (int b3 = 0; b3 < this.urlPathSelection.size(); b3++) {
                                canvas.drawPath(this.urlPathSelection.get(b3), Theme.chat_textSearchSelectionPaint);
                            }
                        }
                        try {
                            block.textLayout.draw(canvas);
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                        canvas.restore();
                    }
                }
            }
            if (this.currentMessageObject.transHeight != 0 && this.transLayout != null) {
                if (this.currentMessageObject.isTranslating() && System.currentTimeMillis() - this.transLastTime > 150) {
                    this.transLastTime = System.currentTimeMillis();
                    RectF rectF = new RectF(this.radius - 3, AndroidUtilities.dp(15.0f), this.radius + 3, AndroidUtilities.dp(22.0f));
                    canvas.save();
                    if (this.hasNewLineForTime) {
                        canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(15.0f), this.textY + this.currentMessageObject.textHeight + AndroidUtilities.dp(36.0f));
                    } else {
                        canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(15.0f), this.textY + this.currentMessageObject.textHeight + AndroidUtilities.dp(23.0f));
                    }
                    if (this.currentMessageObject.isOutOwner()) {
                        Theme.chat_translationPaint.setColor(-12216004);
                    } else {
                        Theme.chat_translationPaint.setColor(-6710887);
                    }
                    float f3 = this.transLoadingRencntcount * 45;
                    int i7 = this.radius;
                    canvas.rotate(f3, i7, i7);
                    for (int i8 = 0; i8 < 8; i8++) {
                        Theme.chat_translationPaint.setAlpha(255 - (i8 * 20));
                        canvas.drawRoundRect(rectF, 10.0f, 10.0f, Theme.chat_translationPaint);
                        int i9 = this.radius;
                        canvas.rotate(45.0f, i9, i9);
                    }
                    int i10 = this.transLoadingRencntcount;
                    int i11 = i10 + 1;
                    this.transLoadingRencntcount = i11;
                    if (i11 > 8) {
                        this.transLoadingRencntcount = 0;
                    }
                    canvas.restore();
                    postInvalidateDelayed(150L);
                } else {
                    canvas.save();
                    if (this.hasNewLineForTime) {
                        canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(10.0f), this.textY + this.currentMessageObject.textHeight + AndroidUtilities.dp(27.0f));
                    } else {
                        canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(10.0f), this.textY + this.currentMessageObject.textHeight + AndroidUtilities.dp(15.0f));
                    }
                    this.transLayout.draw(canvas);
                    canvas.restore();
                    if (this.currentMessageObject.isOutOwner()) {
                        translate2 = Theme.chat_msgOutTranslateIcon;
                        Theme.chat_translationPaint.setColor(-12216004);
                    } else {
                        translate2 = Theme.chat_msgInTranslateIcon;
                        Theme.chat_translationPaint.setColor(-6710887);
                    }
                    setDrawableBounds(translate2, this.transDrawable.getBounds().left + AndroidUtilities.dp(10.0f), this.transDrawable.getBounds().bottom - AndroidUtilities.dp(20.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f));
                    translate2.draw(canvas);
                    canvas.save();
                    canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(25.0f), this.transDrawable.getBounds().bottom - AndroidUtilities.dp(20.0f));
                    this.transLayoutDesc.draw(canvas);
                    canvas.restore();
                }
            }
            if (this.hasLinkPreview || this.hasGamePreview || this.hasInvoicePreview) {
                if (this.hasGamePreview) {
                    startY = AndroidUtilities.dp(14.0f) + this.namesOffset;
                    linkX2 = this.unmovedTextX - AndroidUtilities.dp(10.0f);
                } else if (this.hasInvoicePreview) {
                    startY = AndroidUtilities.dp(14.0f) + this.namesOffset;
                    linkX2 = this.unmovedTextX + AndroidUtilities.dp(1.0f);
                } else {
                    int startY2 = this.textY;
                    startY = startY2 + this.currentMessageObject.textHeight + AndroidUtilities.dp(8.0f);
                    linkX2 = this.unmovedTextX + AndroidUtilities.dp(1.0f);
                }
                int linkPreviewY = startY;
                int smallImageStartY = 0;
                if (this.hasInvoicePreview) {
                    i3 = 4;
                    i = 255;
                    i4 = 8;
                    f2 = 10.0f;
                } else {
                    Theme.chat_replyLinePaint.setColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outPreviewLine : Theme.key_chat_inPreviewLine));
                    f2 = 10.0f;
                    i3 = 4;
                    i = 255;
                    i4 = 8;
                    canvas.drawRect(linkX2, linkPreviewY - AndroidUtilities.dp(3.0f), AndroidUtilities.dp(2.0f) + linkX2, this.linkPreviewHeight + linkPreviewY + AndroidUtilities.dp(3.0f), Theme.chat_replyLinePaint);
                }
                if (this.siteNameLayout != null) {
                    Theme.chat_replyNamePaint.setColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outSiteNameText : Theme.key_chat_inSiteNameText));
                    canvas.save();
                    if (this.siteNameRtl) {
                        x5 = (this.backgroundWidth - this.siteNameWidth) - AndroidUtilities.dp(32.0f);
                    } else {
                        x5 = this.hasInvoicePreview ? 0 : AndroidUtilities.dp(f2);
                    }
                    canvas.translate(linkX2 + x5, linkPreviewY - AndroidUtilities.dp(3.0f));
                    this.siteNameLayout.draw(canvas);
                    canvas.restore();
                    StaticLayout staticLayout3 = this.siteNameLayout;
                    linkPreviewY += staticLayout3.getLineBottom(staticLayout3.getLineCount() - 1);
                }
                if ((this.hasGamePreview || this.hasInvoicePreview) && this.currentMessageObject.textHeight != 0) {
                    startY += this.currentMessageObject.textHeight + AndroidUtilities.dp(4.0f);
                    linkPreviewY += this.currentMessageObject.textHeight + AndroidUtilities.dp(4.0f);
                }
                if ((this.drawPhotoImage && this.drawInstantView) || (this.drawInstantViewType == 6 && this.imageBackgroundColor != 0)) {
                    if (linkPreviewY != startY) {
                        linkPreviewY += AndroidUtilities.dp(2.0f);
                    }
                    if (this.imageBackgroundSideColor == 0) {
                        this.photoImage.setImageCoords(AndroidUtilities.dp(f2) + linkX2, linkPreviewY, this.photoImage.getImageWidth(), this.photoImage.getImageHeight());
                    } else {
                        int x6 = AndroidUtilities.dp(f2) + linkX2;
                        ImageReceiver imageReceiver = this.photoImage;
                        imageReceiver.setImageCoords(((this.imageBackgroundSideWidth - imageReceiver.getImageWidth()) / 2) + x6, linkPreviewY, this.photoImage.getImageWidth(), this.photoImage.getImageHeight());
                        this.rect.set(x6, this.photoImage.getImageY(), this.imageBackgroundSideWidth + x6, this.photoImage.getImageY2());
                        Theme.chat_instantViewPaint.setColor(this.imageBackgroundSideColor);
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_instantViewPaint);
                    }
                    if (this.imageBackgroundColor != 0) {
                        Theme.chat_instantViewPaint.setColor(this.imageBackgroundColor);
                        this.rect.set(this.photoImage.getImageX(), this.photoImage.getImageY(), this.photoImage.getImageX2(), this.photoImage.getImageY2());
                        if (this.imageBackgroundSideColor != 0) {
                            canvas.drawRect(this.photoImage.getImageX(), this.photoImage.getImageY(), this.photoImage.getImageX2(), this.photoImage.getImageY2(), Theme.chat_instantViewPaint);
                        } else {
                            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_instantViewPaint);
                        }
                    }
                    if (this.drawPhotoImage && this.drawInstantView) {
                        if (this.drawImageButton) {
                            int size = AndroidUtilities.dp(48.0f);
                            this.buttonX = (int) (this.photoImage.getImageX() + ((this.photoImage.getImageWidth() - size) / 2.0f));
                            int imageY = (int) (this.photoImage.getImageY() + ((this.photoImage.getImageHeight() - size) / 2.0f));
                            this.buttonY = imageY;
                            RadialProgress2 radialProgress2 = this.radialProgress;
                            int i12 = this.buttonX;
                            radialProgress2.setProgressRect(i12, imageY, i12 + size, imageY + size);
                        }
                        imageDrawn = this.photoImage.draw(canvas);
                    }
                    linkPreviewY += this.photoImage.getImageHeight() + AndroidUtilities.dp(6.0f);
                }
                if (this.currentMessageObject.isOutOwner()) {
                    Theme.chat_replyNamePaint.setColor(Theme.getColor(Theme.key_chat_messageTextOut));
                    Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextOut));
                } else {
                    Theme.chat_replyNamePaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
                    Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
                }
                if (this.titleLayout != null) {
                    if (linkPreviewY != startY) {
                        linkPreviewY += AndroidUtilities.dp(2.0f);
                    }
                    smallImageStartY = linkPreviewY - AndroidUtilities.dp(1.0f);
                    canvas.save();
                    canvas.translate(AndroidUtilities.dp(f2) + linkX2 + this.titleX, linkPreviewY - AndroidUtilities.dp(3.0f));
                    this.titleLayout.draw(canvas);
                    canvas.restore();
                    StaticLayout staticLayout4 = this.titleLayout;
                    linkPreviewY += staticLayout4.getLineBottom(staticLayout4.getLineCount() - 1);
                }
                if (this.authorLayout != null) {
                    if (linkPreviewY != startY) {
                        linkPreviewY += AndroidUtilities.dp(2.0f);
                    }
                    if (smallImageStartY == 0) {
                        smallImageStartY = linkPreviewY - AndroidUtilities.dp(1.0f);
                    }
                    canvas.save();
                    canvas.translate(AndroidUtilities.dp(f2) + linkX2 + this.authorX, linkPreviewY - AndroidUtilities.dp(3.0f));
                    this.authorLayout.draw(canvas);
                    canvas.restore();
                    StaticLayout staticLayout5 = this.authorLayout;
                    linkPreviewY += staticLayout5.getLineBottom(staticLayout5.getLineCount() - 1);
                }
                if (this.descriptionLayout != null) {
                    if (linkPreviewY != startY) {
                        linkPreviewY += AndroidUtilities.dp(2.0f);
                    }
                    if (smallImageStartY == 0) {
                        smallImageStartY = linkPreviewY - AndroidUtilities.dp(1.0f);
                    }
                    this.descriptionY = linkPreviewY - AndroidUtilities.dp(3.0f);
                    canvas.save();
                    canvas.translate((this.hasInvoicePreview ? 0 : AndroidUtilities.dp(f2)) + linkX2 + this.descriptionX, this.descriptionY);
                    if (this.pressedLink != null && this.linkBlockNum == -10) {
                        for (int b4 = 0; b4 < this.urlPath.size(); b4++) {
                            canvas.drawPath(this.urlPath.get(b4), Theme.chat_urlPaint);
                        }
                    }
                    this.descriptionLayout.draw(canvas);
                    canvas.restore();
                    StaticLayout staticLayout6 = this.descriptionLayout;
                    linkPreviewY += staticLayout6.getLineBottom(staticLayout6.getLineCount() - 1);
                }
                if (this.drawPhotoImage && !this.drawInstantView) {
                    if (linkPreviewY != startY) {
                        linkPreviewY += AndroidUtilities.dp(2.0f);
                    }
                    if (this.isSmallImage) {
                        this.photoImage.setImageCoords((this.backgroundWidth + linkX2) - AndroidUtilities.dp(81.0f), smallImageStartY, this.photoImage.getImageWidth(), this.photoImage.getImageHeight());
                    } else {
                        this.photoImage.setImageCoords((this.hasInvoicePreview ? -AndroidUtilities.dp(6.3f) : AndroidUtilities.dp(f2)) + linkX2, linkPreviewY, this.photoImage.getImageWidth(), this.photoImage.getImageHeight());
                        if (this.drawImageButton) {
                            int size2 = AndroidUtilities.dp(48.0f);
                            this.buttonX = (int) (this.photoImage.getImageX() + ((this.photoImage.getImageWidth() - size2) / 2.0f));
                            int imageY2 = (int) (this.photoImage.getImageY() + ((this.photoImage.getImageHeight() - size2) / 2.0f));
                            this.buttonY = imageY2;
                            RadialProgress2 radialProgress22 = this.radialProgress;
                            int i13 = this.buttonX;
                            radialProgress22.setProgressRect(i13, imageY2, i13 + size2, imageY2 + size2);
                        }
                    }
                    if (this.currentMessageObject.isRoundVideo() && MediaController.getInstance().isPlayingMessage(this.currentMessageObject) && MediaController.getInstance().isVideoDrawingReady()) {
                        imageDrawn = true;
                        this.drawTime = true;
                    } else {
                        imageDrawn = this.photoImage.draw(canvas);
                    }
                }
                int i14 = this.documentAttachType;
                if (i14 == i3 || i14 == 2) {
                    this.videoButtonX = this.photoImage.getImageX() + AndroidUtilities.dp(8.0f);
                    int imageY3 = this.photoImage.getImageY() + AndroidUtilities.dp(8.0f);
                    this.videoButtonY = imageY3;
                    RadialProgress2 radialProgress23 = this.videoRadialProgress;
                    int i15 = this.videoButtonX;
                    radialProgress23.setProgressRect(i15, imageY3, AndroidUtilities.dp(24.0f) + i15, this.videoButtonY + AndroidUtilities.dp(24.0f));
                }
                if (this.photosCountLayout != null && this.photoImage.getVisible()) {
                    int x7 = ((this.photoImage.getImageX() + this.photoImage.getImageWidth()) - AndroidUtilities.dp(8.0f)) - this.photosCountWidth;
                    int y2 = (this.photoImage.getImageY() + this.photoImage.getImageHeight()) - AndroidUtilities.dp(19.0f);
                    this.rect.set(x7 - AndroidUtilities.dp(4.0f), y2 - AndroidUtilities.dp(1.5f), this.photosCountWidth + x7 + AndroidUtilities.dp(4.0f), y2 + AndroidUtilities.dp(14.5f));
                    int oldAlpha = Theme.chat_timeBackgroundPaint.getAlpha();
                    Theme.chat_timeBackgroundPaint.setAlpha((int) (oldAlpha * this.controlsAlpha));
                    Theme.chat_durationPaint.setAlpha((int) (this.controlsAlpha * 255.0f));
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_timeBackgroundPaint);
                    Theme.chat_timeBackgroundPaint.setAlpha(oldAlpha);
                    canvas.save();
                    canvas.translate(x7, y2);
                    this.photosCountLayout.draw(canvas);
                    canvas.restore();
                    Theme.chat_durationPaint.setAlpha(i);
                }
                if (this.videoInfoLayout != null && ((!this.drawPhotoImage || this.photoImage.getVisible()) && this.imageBackgroundSideColor == 0)) {
                    if (!this.hasGamePreview && !this.hasInvoicePreview && this.documentAttachType != i4) {
                        x4 = ((this.photoImage.getImageX() + this.photoImage.getImageWidth()) - AndroidUtilities.dp(8.0f)) - this.durationWidth;
                        y = (this.photoImage.getImageY() + this.photoImage.getImageHeight()) - AndroidUtilities.dp(19.0f);
                        this.rect.set(x4 - AndroidUtilities.dp(4.0f), y - AndroidUtilities.dp(1.5f), this.durationWidth + x4 + AndroidUtilities.dp(4.0f), AndroidUtilities.dp(14.5f) + y);
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_timeBackgroundPaint);
                    } else if (this.drawPhotoImage) {
                        x4 = this.photoImage.getImageX() + AndroidUtilities.dp(8.5f);
                        y = this.photoImage.getImageY() + AndroidUtilities.dp(6.0f);
                        int height = AndroidUtilities.dp(this.documentAttachType == i4 ? 14.5f : 16.5f);
                        this.rect.set(x4 - AndroidUtilities.dp(4.0f), y - AndroidUtilities.dp(1.5f), this.durationWidth + x4 + AndroidUtilities.dp(4.0f), y + height);
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_timeBackgroundPaint);
                    } else {
                        x4 = linkX2;
                        y = linkPreviewY;
                    }
                    canvas.save();
                    canvas.translate(x4, y);
                    if (this.hasInvoicePreview) {
                        if (this.drawPhotoImage) {
                            Theme.chat_shipmentPaint.setColor(Theme.getColor(Theme.key_chat_previewGameText));
                        } else if (this.currentMessageObject.isOutOwner()) {
                            Theme.chat_shipmentPaint.setColor(Theme.getColor(Theme.key_chat_messageTextOut));
                        } else {
                            Theme.chat_shipmentPaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
                        }
                    }
                    this.videoInfoLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.drawInstantView) {
                    int instantY = this.linkPreviewHeight + startY + AndroidUtilities.dp(f2);
                    Paint backPaint = Theme.chat_instantViewRectPaint;
                    if (this.currentMessageObject.isOutOwner()) {
                        instantDrawable = Theme.chat_msgOutInstantDrawable;
                        Theme.chat_instantViewPaint.setColor(Theme.getColor(Theme.key_chat_outPreviewInstantText));
                        backPaint.setColor(Theme.getColor(Theme.key_chat_outPreviewInstantText));
                    } else {
                        instantDrawable = Theme.chat_msgInInstantDrawable;
                        Theme.chat_instantViewPaint.setColor(Theme.getColor(Theme.key_chat_inPreviewInstantText));
                        backPaint.setColor(Theme.getColor(Theme.key_chat_inPreviewInstantText));
                    }
                    if (Build.VERSION.SDK_INT >= 21) {
                        this.selectorDrawableMaskType = 0;
                        this.selectorDrawable.setBounds(linkX2, instantY, this.instantWidth + linkX2, AndroidUtilities.dp(36.0f) + instantY);
                        this.selectorDrawable.draw(canvas);
                    }
                    this.rect.set(linkX2, instantY, this.instantWidth + linkX2, instantY + AndroidUtilities.dp(36.0f));
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), backPaint);
                    if (this.drawInstantViewType == 0) {
                        setDrawableBounds(instantDrawable, ((this.instantTextLeftX + this.instantTextX) + linkX2) - AndroidUtilities.dp(15.0f), AndroidUtilities.dp(11.5f) + instantY, AndroidUtilities.dp(9.0f), AndroidUtilities.dp(13.0f));
                        instantDrawable.draw(canvas);
                    }
                    if (this.instantViewLayout != null) {
                        canvas.save();
                        canvas.translate(this.instantTextX + linkX2, AndroidUtilities.dp(10.5f) + instantY);
                        this.instantViewLayout.draw(canvas);
                        canvas.restore();
                    }
                }
            } else {
                i = 255;
            }
            this.drawTime = true;
        } else {
            i = 255;
            if (this.drawPhotoImage) {
                if (this.currentMessageObject.isRoundVideo() && MediaController.getInstance().isPlayingMessage(this.currentMessageObject) && MediaController.getInstance().isVideoDrawingReady()) {
                    imageDrawn = true;
                    this.drawTime = true;
                } else {
                    if (this.currentMessageObject.type == 5 && Theme.chat_roundVideoShadow != null) {
                        int x8 = this.photoImage.getImageX() - AndroidUtilities.dp(3.0f);
                        int y3 = this.photoImage.getImageY() - AndroidUtilities.dp(2.0f);
                        Theme.chat_roundVideoShadow.setAlpha(255);
                        Theme.chat_roundVideoShadow.setBounds(x8, y3, AndroidUtilities.roundMessageSize + x8 + AndroidUtilities.dp(6.0f), AndroidUtilities.roundMessageSize + y3 + AndroidUtilities.dp(6.0f));
                        Theme.chat_roundVideoShadow.draw(canvas);
                        if (!this.photoImage.hasBitmapImage() || this.photoImage.getCurrentAlpha() != 1.0f) {
                            Theme.chat_docBackPaint.setColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outBubble : Theme.key_chat_inBubble));
                            canvas.drawCircle(this.photoImage.getCenterX(), this.photoImage.getCenterY(), this.photoImage.getImageWidth() / 2, Theme.chat_docBackPaint);
                        }
                    }
                    CheckBoxBase checkBoxBase = this.photoCheckBox;
                    boolean z2 = checkBoxBase != null && (this.checkBoxVisible || checkBoxBase.getProgress() != 0.0f || this.checkBoxAnimationInProgress) && (groupedMessages = this.currentMessagesGroup) != null && groupedMessages.messages.size() > 1;
                    this.drawPhotoCheckBox = z2;
                    if (z2 && (this.photoCheckBox.isChecked() || this.photoCheckBox.getProgress() != 0.0f || this.checkBoxAnimationInProgress)) {
                        Theme.chat_replyLinePaint.setColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outBubbleSelected : Theme.key_chat_inBubbleSelected));
                        this.rect.set(this.photoImage.getImageX(), this.photoImage.getImageY(), this.photoImage.getImageX2(), this.photoImage.getImageY2());
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_replyLinePaint);
                        this.photoImage.setSideClip(AndroidUtilities.dp(14.0f) * this.photoCheckBox.getProgress());
                        if (this.checkBoxAnimationInProgress) {
                            this.photoCheckBox.setBackgroundAlpha(this.checkBoxAnimationProgress);
                        } else {
                            CheckBoxBase checkBoxBase2 = this.photoCheckBox;
                            checkBoxBase2.setBackgroundAlpha(this.checkBoxVisible ? 1.0f : checkBoxBase2.getProgress());
                        }
                    } else {
                        this.photoImage.setSideClip(0.0f);
                    }
                    imageDrawn = this.photoImage.draw(canvas);
                    boolean drawTimeOld = this.drawTime;
                    boolean visible = this.photoImage.getVisible();
                    this.drawTime = visible;
                    if (this.currentPosition != null && drawTimeOld != visible && (viewGroup = (ViewGroup) getParent()) != null) {
                        if (!this.currentPosition.last) {
                            int count = viewGroup.getChildCount();
                            for (int a2 = 0; a2 < count; a2++) {
                                View child = viewGroup.getChildAt(a2);
                                if (child != this && (child instanceof ChatMessageCell)) {
                                    ChatMessageCell cell = (ChatMessageCell) child;
                                    if (cell.getCurrentMessagesGroup() == this.currentMessagesGroup) {
                                        MessageObject.GroupedMessagePosition position = cell.getCurrentPosition();
                                        if (position.last && position.maxY == this.currentPosition.maxY && (cell.timeX - AndroidUtilities.dp(4.0f)) + cell.getLeft() < getRight()) {
                                            cell.groupPhotoInvisible = !this.drawTime;
                                            cell.invalidate();
                                            viewGroup.invalidate();
                                        }
                                    }
                                }
                            }
                        } else {
                            viewGroup.invalidate();
                        }
                    }
                }
            }
        }
        int i16 = this.documentAttachType;
        float f4 = 12.0f;
        if (i16 == 2) {
            f = 10.0f;
        } else if (i16 == 7) {
            if (this.durationLayout != null) {
                boolean playing = MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
                if (playing && this.currentMessageObject.type == 5) {
                    drawRoundProgress(canvas);
                    drawOverlays(canvas);
                }
                if (this.currentMessageObject.type == 5) {
                    int x12 = this.backgroundDrawableLeft + AndroidUtilities.dp(8.0f);
                    int y12 = this.layoutHeight - AndroidUtilities.dp(28 - (this.drawPinnedBottom ? 2 : 0));
                    this.rect.set(x12, y12, this.timeWidthAudio + x12 + AndroidUtilities.dp(22.0f), AndroidUtilities.dp(17.0f) + y12);
                    int oldAlpha2 = Theme.chat_actionBackgroundPaint.getAlpha();
                    Theme.chat_actionBackgroundPaint.setAlpha((int) (oldAlpha2 * this.timeAlpha));
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Theme.chat_actionBackgroundPaint);
                    Theme.chat_actionBackgroundPaint.setAlpha(oldAlpha2);
                    if (!playing && this.currentMessageObject.isContentUnread()) {
                        Theme.chat_docBackPaint.setColor(Theme.getColor(Theme.key_chat_mediaTimeText));
                        Theme.chat_docBackPaint.setAlpha((int) (this.timeAlpha * 255.0f));
                        canvas.drawCircle(this.timeWidthAudio + x12 + AndroidUtilities.dp(12.0f), AndroidUtilities.dp(8.3f) + y12, AndroidUtilities.dp(3.0f), Theme.chat_docBackPaint);
                    } else {
                        if (playing && !MediaController.getInstance().isMessagePaused()) {
                            this.roundVideoPlayingDrawable.start();
                        } else {
                            this.roundVideoPlayingDrawable.stop();
                        }
                        setDrawableBounds((Drawable) this.roundVideoPlayingDrawable, this.timeWidthAudio + x12 + AndroidUtilities.dp(6.0f), AndroidUtilities.dp(2.3f) + y12);
                        this.roundVideoPlayingDrawable.draw(canvas);
                    }
                    x1 = x12 + AndroidUtilities.dp(4.0f);
                    y1 = y12 + AndroidUtilities.dp(1.7f);
                } else {
                    int x13 = this.backgroundDrawableLeft;
                    x1 = x13 + AndroidUtilities.dp((this.currentMessageObject.isOutOwner() || this.drawPinnedBottom) ? 12.0f : 18.0f);
                    y1 = (this.layoutHeight - AndroidUtilities.dp(6.3f - (this.drawPinnedBottom ? 2 : 0))) - this.timeLayout.getHeight();
                }
                Theme.chat_timePaint.setAlpha((int) (this.timeAlpha * 255.0f));
                canvas.save();
                canvas.translate(x1, y1);
                this.durationLayout.draw(canvas);
                canvas.restore();
                Theme.chat_timePaint.setAlpha(i);
                f = 10.0f;
            } else {
                f = 10.0f;
            }
        } else if (i16 == 5) {
            if (this.currentMessageObject.isOutOwner()) {
                Theme.chat_audioTitlePaint.setColor(Theme.getColor(Theme.key_chat_outAudioTitleText));
                Theme.chat_audioPerformerPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outAudioPerformerSelectedText : Theme.key_chat_outAudioPerformerText));
                Theme.chat_audioTimePaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outAudioDurationSelectedText : Theme.key_chat_outAudioDurationText));
                this.radialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.buttonPressed != 0) ? Theme.key_chat_outAudioSelectedProgress : Theme.key_chat_outAudioProgress));
            } else {
                Theme.chat_audioTitlePaint.setColor(Theme.getColor(Theme.key_chat_inAudioTitleText));
                Theme.chat_audioPerformerPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inAudioPerformerSelectedText : Theme.key_chat_inAudioPerformerText));
                Theme.chat_audioTimePaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inAudioDurationSelectedText : Theme.key_chat_inAudioDurationText));
                this.radialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.buttonPressed != 0) ? Theme.key_chat_inAudioSelectedProgress : Theme.key_chat_inAudioProgress));
            }
            this.radialProgress.draw(canvas);
            canvas.save();
            canvas.translate(this.timeAudioX + this.songX, AndroidUtilities.dp(13.0f) + this.namesOffset + this.mediaOffsetY);
            this.songLayout.draw(canvas);
            canvas.restore();
            canvas.save();
            if (MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                canvas.translate(this.seekBarX, this.seekBarY);
                this.seekBar.draw(canvas);
            } else {
                canvas.translate(this.timeAudioX + this.performerX, AndroidUtilities.dp(35.0f) + this.namesOffset + this.mediaOffsetY);
                this.performerLayout.draw(canvas);
            }
            canvas.restore();
            canvas.save();
            canvas.translate(this.timeAudioX, AndroidUtilities.dp(57.0f) + this.namesOffset + this.mediaOffsetY);
            this.durationLayout.draw(canvas);
            canvas.restore();
            f = 10.0f;
        } else if (i16 != 3) {
            f = 10.0f;
        } else {
            if (this.currentMessageObject.isOutOwner()) {
                Theme.chat_audioTimePaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outAudioDurationSelectedText : Theme.key_chat_outAudioDurationText));
                this.radialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.buttonPressed != 0) ? Theme.key_chat_outAudioSelectedProgress : Theme.key_chat_outAudioProgress));
            } else {
                Theme.chat_audioTimePaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inAudioDurationSelectedText : Theme.key_chat_inAudioDurationText));
                this.radialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.buttonPressed != 0) ? Theme.key_chat_inAudioSelectedProgress : Theme.key_chat_inAudioProgress));
            }
            this.radialProgress.draw(canvas);
            canvas.save();
            if (this.useSeekBarWaweform) {
                canvas.translate(this.seekBarX + AndroidUtilities.dp(13.0f), this.seekBarY);
                this.seekBarWaveform.draw(canvas);
            } else {
                canvas.translate(this.seekBarX, this.seekBarY);
                this.seekBar.draw(canvas);
            }
            canvas.restore();
            canvas.save();
            canvas.translate(this.timeAudioX + AndroidUtilities.dp(12.0f), AndroidUtilities.dp(38.0f) + this.namesOffset + this.mediaOffsetY);
            this.durationLayout.draw(canvas);
            canvas.restore();
            if (this.currentMessageObject.isOutOwner()) {
                audio = Theme.chat_msgOutAudioFlagIcon;
            } else {
                audio = Theme.chat_msgInAudioFlagIcon;
            }
            setDrawableBounds(audio, this.timeAudioX, AndroidUtilities.dp(39.0f) + this.namesOffset + this.mediaOffsetY, AndroidUtilities.dp(8.25f), AndroidUtilities.dp(10.75f));
            audio.draw(canvas);
            if (this.currentMessageObject.transHeight == 0 || this.transLayout == null) {
                f = 10.0f;
            } else if (this.currentMessageObject.isTranslating() && System.currentTimeMillis() - this.transLastTime > 150) {
                this.transLastTime = System.currentTimeMillis();
                RectF rectF2 = new RectF(this.radius - 3, AndroidUtilities.dp(15.0f), this.radius + 3, AndroidUtilities.dp(22.0f));
                canvas.save();
                int startY3 = AndroidUtilities.dp(45.0f) + this.namesOffset + (mOffset * 2);
                canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(15.0f), AndroidUtilities.dp(23.0f) + startY3);
                float f5 = this.transLoadingRencntcount * 36;
                int i17 = this.radius;
                canvas.rotate(f5, i17, i17);
                if (this.currentMessageObject.isOutOwner()) {
                    Theme.chat_translationPaint.setColor(-12216004);
                } else {
                    Theme.chat_translationPaint.setColor(-6710887);
                }
                for (int i18 = 0; i18 < 10; i18++) {
                    Theme.chat_translationPaint.setAlpha(255 - (i18 * 20));
                    canvas.drawRoundRect(rectF2, 10.0f, 10.0f, Theme.chat_translationPaint);
                    int i19 = this.radius;
                    canvas.rotate(36.0f, i19, i19);
                }
                f = 10.0f;
                int i20 = this.transLoadingRencntcount;
                int i21 = i20 + 1;
                this.transLoadingRencntcount = i21;
                if (i21 > 10) {
                    this.transLoadingRencntcount = 0;
                }
                canvas.restore();
                postInvalidateDelayed(150L);
            } else {
                f = 10.0f;
                int startY4 = AndroidUtilities.dp(45.0f) + this.namesOffset + (mOffset * 2);
                canvas.save();
                canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(10.0f), AndroidUtilities.dp(15.0f) + startY4);
                this.transLayout.draw(canvas);
                canvas.restore();
                if (this.currentMessageObject.isOutOwner()) {
                    translate = Theme.chat_msgOutTranslateIcon;
                    Theme.chat_translationPaint.setColor(-12216004);
                } else {
                    translate = Theme.chat_msgInTranslateIcon;
                    Theme.chat_translationPaint.setColor(-6710887);
                }
                setDrawableBounds(translate, this.transDrawable.getBounds().left + AndroidUtilities.dp(10.0f), this.transDrawable.getBounds().bottom - AndroidUtilities.dp(20.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f));
                translate.draw(canvas);
                canvas.save();
                canvas.translate(this.transDrawable.getBounds().left + AndroidUtilities.dp(25.0f), this.transDrawable.getBounds().bottom - AndroidUtilities.dp(20.0f));
                this.transLayoutDesc.draw(canvas);
                canvas.restore();
            }
        }
        if (this.captionLayout != null) {
            if (this.currentMessageObject.type == 1 || this.documentAttachType == 4 || this.currentMessageObject.type == 8) {
                this.captionX = this.photoImage.getImageX() + AndroidUtilities.dp(5.0f) + this.captionOffsetX;
                this.captionY = this.photoImage.getImageY() + this.photoImage.getImageHeight() + AndroidUtilities.dp(6.0f);
            } else if (this.hasOldCaptionPreview) {
                this.captionX = this.backgroundDrawableLeft + AndroidUtilities.dp(this.currentMessageObject.isOutOwner() ? 11.0f : 17.0f) + this.captionOffsetX;
                this.captionY = (((this.totalHeight - this.captionHeight) - AndroidUtilities.dp(this.drawPinnedTop ? 9.0f : 10.0f)) - this.linkPreviewHeight) - AndroidUtilities.dp(17.0f);
            } else {
                this.captionX = this.backgroundDrawableLeft + AndroidUtilities.dp((this.currentMessageObject.isOutOwner() || (z = this.mediaBackground) || (!z && this.drawPinnedBottom)) ? 11.0f : 17.0f) + this.captionOffsetX;
                this.captionY = (this.totalHeight - this.captionHeight) - AndroidUtilities.dp(this.drawPinnedTop ? 9.0f : 10.0f);
            }
        }
        if (this.currentPosition == null) {
            drawCaptionLayout(canvas, false);
        }
        if (!this.hasOldCaptionPreview) {
            i2 = 1;
        } else {
            if (this.currentMessageObject.type == 1 || this.documentAttachType == 4 || this.currentMessageObject.type == 8) {
                linkX = this.photoImage.getImageX() + AndroidUtilities.dp(5.0f);
            } else {
                linkX = this.backgroundDrawableLeft + AndroidUtilities.dp(this.currentMessageObject.isOutOwner() ? 11.0f : 17.0f);
            }
            int startY5 = ((this.totalHeight - AndroidUtilities.dp(this.drawPinnedTop ? 9.0f : 10.0f)) - this.linkPreviewHeight) - AndroidUtilities.dp(8.0f);
            Theme.chat_replyLinePaint.setColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outPreviewLine : Theme.key_chat_inPreviewLine));
            canvas.drawRect(linkX, startY5 - AndroidUtilities.dp(3.0f), AndroidUtilities.dp(2.0f) + linkX, startY5 + this.linkPreviewHeight, Theme.chat_replyLinePaint);
            if (this.siteNameLayout == null) {
                x2 = startY5;
            } else {
                Theme.chat_replyNamePaint.setColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outSiteNameText : Theme.key_chat_inSiteNameText));
                canvas.save();
                if (this.siteNameRtl) {
                    x3 = (this.backgroundWidth - this.siteNameWidth) - AndroidUtilities.dp(32.0f);
                } else {
                    x3 = this.hasInvoicePreview ? 0 : AndroidUtilities.dp(f);
                }
                canvas.translate(linkX + x3, startY5 - AndroidUtilities.dp(3.0f));
                this.siteNameLayout.draw(canvas);
                canvas.restore();
                StaticLayout staticLayout7 = this.siteNameLayout;
                x2 = startY5 + staticLayout7.getLineBottom(staticLayout7.getLineCount() - 1);
            }
            if (this.currentMessageObject.isOutOwner()) {
                Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextOut));
            } else {
                Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
            }
            if (this.descriptionLayout != null) {
                if (x2 != startY5) {
                    x2 += AndroidUtilities.dp(2.0f);
                }
                this.descriptionY = x2 - AndroidUtilities.dp(3.0f);
                canvas.save();
                canvas.translate(AndroidUtilities.dp(f) + linkX + this.descriptionX, this.descriptionY);
                this.descriptionLayout.draw(canvas);
                canvas.restore();
            }
            i2 = 1;
            this.drawTime = true;
        }
        if (this.documentAttachType == i2) {
            if (this.currentMessageObject.isOutOwner()) {
                Theme.chat_docNamePaint.setColor(Theme.getColor(Theme.key_chat_outFileNameText));
                Theme.chat_infoPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outFileInfoSelectedText : Theme.key_chat_outFileInfoText));
                Theme.chat_docBackPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outFileBackgroundSelected : Theme.key_chat_outFileBackground));
            } else {
                Theme.chat_docNamePaint.setColor(Theme.getColor(Theme.key_chat_inFileNameText));
                Theme.chat_infoPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inFileInfoSelectedText : Theme.key_chat_inFileInfoText));
                Theme.chat_docBackPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inFileBackgroundSelected : Theme.key_chat_inFileBackground));
            }
            if (this.drawPhotoImage) {
                x = this.photoImage.getImageX() + this.photoImage.getImageWidth() + AndroidUtilities.dp(f);
                titleY = this.photoImage.getImageY() + AndroidUtilities.dp(8.0f);
                int imageY4 = this.photoImage.getImageY();
                StaticLayout staticLayout8 = this.docTitleLayout;
                subtitleY = imageY4 + (staticLayout8 != null ? staticLayout8.getLineBottom(staticLayout8.getLineCount() - 1) + AndroidUtilities.dp(13.0f) : AndroidUtilities.dp(8.0f));
                if (!imageDrawn) {
                    if (this.currentMessageObject.isOutOwner()) {
                        this.radialProgress.setColors(Theme.key_chat_outLoader, Theme.key_chat_outLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
                        this.radialProgress.setProgressColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outFileProgressSelected : Theme.key_chat_outFileProgress));
                        this.videoRadialProgress.setColors(Theme.key_chat_outLoader, Theme.key_chat_outLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
                        this.videoRadialProgress.setProgressColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outFileProgressSelected : Theme.key_chat_outFileProgress));
                    } else {
                        this.radialProgress.setColors(Theme.key_chat_inLoader, Theme.key_chat_inLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
                        this.radialProgress.setProgressColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inFileProgressSelected : Theme.key_chat_inFileProgress));
                        this.videoRadialProgress.setColors(Theme.key_chat_inLoader, Theme.key_chat_inLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
                        this.videoRadialProgress.setProgressColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inFileProgressSelected : Theme.key_chat_inFileProgress));
                    }
                    this.rect.set(this.photoImage.getImageX(), this.photoImage.getImageY(), this.photoImage.getImageX() + this.photoImage.getImageWidth(), this.photoImage.getImageY() + this.photoImage.getImageHeight());
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(3.0f), AndroidUtilities.dp(3.0f), Theme.chat_docBackPaint);
                } else {
                    this.radialProgress.setColors(Theme.key_chat_mediaLoaderPhoto, Theme.key_chat_mediaLoaderPhotoSelected, Theme.key_chat_mediaLoaderPhotoIcon, Theme.key_chat_mediaLoaderPhotoIconSelected);
                    this.radialProgress.setProgressColor(Theme.getColor(Theme.key_chat_mediaProgress));
                    this.videoRadialProgress.setColors(Theme.key_chat_mediaLoaderPhoto, Theme.key_chat_mediaLoaderPhotoSelected, Theme.key_chat_mediaLoaderPhotoIcon, Theme.key_chat_mediaLoaderPhotoIconSelected);
                    this.videoRadialProgress.setProgressColor(Theme.getColor(Theme.key_chat_mediaProgress));
                    if (this.buttonState == -1 && this.radialProgress.getIcon() != 4) {
                        this.radialProgress.setIcon(4, true, true);
                    }
                }
            } else {
                x = this.buttonX + AndroidUtilities.dp(53.0f);
                titleY = this.buttonY + AndroidUtilities.dp(2.0f);
                subtitleY = this.buttonY + AndroidUtilities.dp(36.0f);
                if (this.currentMessageObject.isOutOwner()) {
                    this.radialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.buttonPressed != 0) ? Theme.key_chat_outAudioSelectedProgress : Theme.key_chat_outAudioProgress));
                    this.videoRadialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.videoButtonPressed != 0) ? Theme.key_chat_outAudioSelectedProgress : Theme.key_chat_outAudioProgress));
                } else {
                    this.radialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.buttonPressed != 0) ? Theme.key_chat_inAudioSelectedProgress : Theme.key_chat_inAudioProgress));
                    this.videoRadialProgress.setProgressColor(Theme.getColor((isDrawSelectionBackground() || this.videoButtonPressed != 0) ? Theme.key_chat_inAudioSelectedProgress : Theme.key_chat_inAudioProgress));
                }
            }
            int subtitleY2 = subtitleY;
            int subtitleY3 = titleY;
            int titleY2 = x;
            try {
                if (this.docTitleLayout != null) {
                    canvas.save();
                    canvas.translate(this.docTitleOffsetX + titleY2, subtitleY3);
                    this.docTitleLayout.draw(canvas);
                    canvas.restore();
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            try {
                if (this.infoLayout != null) {
                    canvas.save();
                    canvas.translate(titleY2, subtitleY2);
                    this.infoLayout.draw(canvas);
                    canvas.restore();
                }
            } catch (Exception e3) {
                FileLog.e(e3);
            }
        }
        if (this.buttonState == -1 && this.currentMessageObject.needDrawBluredPreview() && !MediaController.getInstance().isPlayingMessage(this.currentMessageObject) && this.photoImage.getVisible() && this.currentMessageObject.messageOwner.destroyTime != 0) {
            if (!this.currentMessageObject.isOutOwner()) {
                long msTime = System.currentTimeMillis() + ((long) (ConnectionsManager.getInstance(this.currentAccount).getTimeDifference() * 1000));
                float progress = Math.max(0L, (((long) this.currentMessageObject.messageOwner.destroyTime) * 1000) - msTime) / (this.currentMessageObject.messageOwner.ttl * 1000.0f);
                Theme.chat_deleteProgressPaint.setAlpha((int) (this.controlsAlpha * 255.0f));
                canvas.drawArc(this.deleteProgressRect, -90.0f, progress * (-360.0f), true, Theme.chat_deleteProgressPaint);
                if (progress != 0.0f) {
                    int offset = AndroidUtilities.dp(2.0f);
                    invalidate(((int) this.deleteProgressRect.left) - offset, ((int) this.deleteProgressRect.top) - offset, ((int) this.deleteProgressRect.right) + (offset * 2), ((int) this.deleteProgressRect.bottom) + (offset * 2));
                }
            }
            updateSecretTimeText(this.currentMessageObject);
        }
        if (this.currentMessageObject.type == 4 && !(this.currentMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGeoLive) && this.currentMapProvider == 2 && this.photoImage.hasNotThumb()) {
            int w = (int) (Theme.chat_redLocationIcon.getIntrinsicWidth() * 0.8f);
            int h = (int) (Theme.chat_redLocationIcon.getIntrinsicHeight() * 0.8f);
            int x9 = this.photoImage.getImageX() + ((this.photoImage.getImageWidth() - w) / 2);
            int y4 = this.photoImage.getImageY() + ((this.photoImage.getImageHeight() / 2) - h);
            Theme.chat_redLocationIcon.setAlpha((int) (this.photoImage.getCurrentAlpha() * 255.0f));
            Theme.chat_redLocationIcon.setBounds(x9, y4, x9 + w, y4 + h);
            Theme.chat_redLocationIcon.draw(canvas);
        }
        if (!this.botButtons.isEmpty()) {
            if (this.currentMessageObject.isOutOwner()) {
                addX = (getMeasuredWidth() - this.widthForButtons) - AndroidUtilities.dp(f);
            } else {
                int addX2 = this.backgroundDrawableLeft;
                addX = addX2 + AndroidUtilities.dp((this.mediaBackground || this.drawPinnedBottom) ? 1.0f : 7.0f);
            }
            int a3 = 0;
            while (a3 < this.botButtons.size()) {
                BotButton button = this.botButtons.get(a3);
                int y5 = (button.y + this.layoutHeight) - AndroidUtilities.dp(2.0f);
                Theme.chat_systemDrawable.setColorFilter(a3 == this.pressedBotButton ? Theme.colorPressedFilter : Theme.colorFilter);
                Theme.chat_systemDrawable.setBounds(button.x + addX, y5, button.x + addX + button.width, button.height + y5);
                Theme.chat_systemDrawable.draw(canvas);
                canvas.save();
                canvas.translate(button.x + addX + AndroidUtilities.dp(5.0f), ((AndroidUtilities.dp(44.0f) - button.title.getLineBottom(button.title.getLineCount() - 1)) / 2) + y5);
                button.title.draw(canvas);
                canvas.restore();
                if (!(button.button instanceof TLRPC.TL_keyboardButtonUrl)) {
                    if (!(button.button instanceof TLRPC.TL_keyboardButtonSwitchInline)) {
                        if ((button.button instanceof TLRPC.TL_keyboardButtonCallback) || (button.button instanceof TLRPC.TL_keyboardButtonRequestGeoLocation) || (button.button instanceof TLRPC.TL_keyboardButtonGame) || (button.button instanceof TLRPC.TL_keyboardButtonBuy) || (button.button instanceof TLRPC.TL_keyboardButtonUrlAuth)) {
                            boolean drawProgress = (((button.button instanceof TLRPC.TL_keyboardButtonCallback) || (button.button instanceof TLRPC.TL_keyboardButtonGame) || (button.button instanceof TLRPC.TL_keyboardButtonBuy) || (button.button instanceof TLRPC.TL_keyboardButtonUrlAuth)) && SendMessagesHelper.getInstance(this.currentAccount).isSendingCallback(this.currentMessageObject, button.button)) || ((button.button instanceof TLRPC.TL_keyboardButtonRequestGeoLocation) && SendMessagesHelper.getInstance(this.currentAccount).isSendingCurrentLocation(this.currentMessageObject, button.button));
                            if (drawProgress || (!drawProgress && button.progressAlpha != 0.0f)) {
                                Theme.chat_botProgressPaint.setAlpha(Math.min(i, (int) (button.progressAlpha * 255.0f)));
                                int x10 = ((button.x + button.width) - AndroidUtilities.dp(f4)) + addX;
                                this.rect.set(x10, AndroidUtilities.dp(4.0f) + y5, AndroidUtilities.dp(8.0f) + x10, y5 + AndroidUtilities.dp(f4));
                                canvas.drawArc(this.rect, button.angle, 220.0f, false, Theme.chat_botProgressPaint);
                                invalidate();
                                long newTime = System.currentTimeMillis();
                                if (Math.abs(button.lastUpdateTime - System.currentTimeMillis()) < 1000) {
                                    long delta = newTime - button.lastUpdateTime;
                                    float dt = (360 * delta) / 2000.0f;
                                    button.angle = (int) (button.angle + dt);
                                    button.angle -= (button.angle / 360) * 360;
                                    if (drawProgress) {
                                        if (button.progressAlpha < 1.0f) {
                                            button.progressAlpha += delta / 200.0f;
                                            if (button.progressAlpha > 1.0f) {
                                                button.progressAlpha = 1.0f;
                                            }
                                        }
                                    } else if (button.progressAlpha > 0.0f) {
                                        button.progressAlpha -= delta / 200.0f;
                                        if (button.progressAlpha < 0.0f) {
                                            button.progressAlpha = 0.0f;
                                        }
                                    }
                                }
                                button.lastUpdateTime = newTime;
                            }
                        }
                    } else {
                        setDrawableBounds(Theme.chat_botInlineDrawable, (((button.x + button.width) - AndroidUtilities.dp(3.0f)) - Theme.chat_botInlineDrawable.getIntrinsicWidth()) + addX, AndroidUtilities.dp(3.0f) + y5);
                        Theme.chat_botInlineDrawable.draw(canvas);
                    }
                } else {
                    setDrawableBounds(Theme.chat_botLinkDrawalbe, (((button.x + button.width) - AndroidUtilities.dp(3.0f)) - Theme.chat_botLinkDrawalbe.getIntrinsicWidth()) + addX, AndroidUtilities.dp(3.0f) + y5);
                    Theme.chat_botLinkDrawalbe.draw(canvas);
                }
                a3++;
                f4 = 12.0f;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getMiniIconForCurrentState() {
        int i = this.miniButtonState;
        if (i < 0) {
            return 4;
        }
        if (i == 0) {
            return 2;
        }
        return 3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getIconForCurrentState() {
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outLoader, Theme.key_chat_outLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_inLoader, Theme.key_chat_inLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i2 = this.buttonState;
            if (i2 == 1) {
                return 1;
            }
            if (i2 == 2) {
                return 2;
            }
            return i2 == 4 ? 3 : 0;
        }
        TLRPC.Document document = this.currentMessageObject.getDocument();
        String ext = document == null ? "" : FileLoader.getDocumentExtension(document);
        if (!TextUtils.isEmpty(ext) && (ext.equals("ZIP") || ext.equals("RAR") || ext.equals("7Z"))) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i3 = this.buttonState;
            if (i3 == -1) {
                return 15;
            }
            if (i3 == 0) {
                return 2;
            }
            if (i3 == 1) {
                return 3;
            }
        } else if (!TextUtils.isEmpty(ext) && (ext.equals("DOC") || ext.equals("DOCX"))) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i4 = this.buttonState;
            if (i4 == -1) {
                return 16;
            }
            if (i4 == 0) {
                return 2;
            }
            if (i4 == 1) {
                return 3;
            }
        } else if (!TextUtils.isEmpty(ext) && (ext.equals("XLS") || ext.equals("XLSX"))) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i5 = this.buttonState;
            if (i5 == -1) {
                return 17;
            }
            if (i5 == 0) {
                return 2;
            }
            if (i5 == 1) {
                return 3;
            }
        } else if (!TextUtils.isEmpty(ext) && ext.equals("PDF")) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i6 = this.buttonState;
            if (i6 == -1) {
                return 19;
            }
            if (i6 == 0) {
                return 2;
            }
            if (i6 == 1) {
                return 3;
            }
        } else if (!TextUtils.isEmpty(ext) && ext.equals("TXT")) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i7 = this.buttonState;
            if (i7 == -1) {
                return 18;
            }
            if (i7 == 0) {
                return 2;
            }
            if (i7 == 1) {
                return 3;
            }
        } else if (!TextUtils.isEmpty(ext) && ext.equals("APK")) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i8 = this.buttonState;
            if (i8 == -1) {
                return 20;
            }
            if (i8 == 0) {
                return 2;
            }
            if (i8 == 1) {
                return 3;
            }
        } else if (!TextUtils.isEmpty(ext) && ext.equals("IPA")) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i9 = this.buttonState;
            if (i9 == -1) {
                return 21;
            }
            if (i9 == 0) {
                return 2;
            }
            if (i9 == 1) {
                return 3;
            }
        } else if (this.documentAttachType == 1 && !this.drawPhotoImage) {
            if (this.currentMessageObject.isOutOwner()) {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_outMediaIcon, Theme.key_chat_outMediaIconSelected);
            } else {
                this.radialProgress.setColors(Theme.key_chat_outDocumentLoader, Theme.key_chat_outDocumentLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            }
            int i10 = this.buttonState;
            if (i10 == -1) {
                return 5;
            }
            if (i10 == 0) {
                return 2;
            }
            if (i10 == 1) {
                return 3;
            }
        } else {
            this.radialProgress.setColors(Theme.key_chat_mediaLoaderPhoto, Theme.key_chat_mediaLoaderPhotoSelected, Theme.key_chat_mediaLoaderPhotoIcon, Theme.key_chat_mediaLoaderPhotoIconSelected);
            this.videoRadialProgress.setColors(Theme.key_chat_mediaLoaderPhoto, Theme.key_chat_mediaLoaderPhotoSelected, Theme.key_chat_mediaLoaderPhotoIcon, Theme.key_chat_mediaLoaderPhotoIconSelected);
            int i11 = this.buttonState;
            if (i11 >= 0 && i11 < 4) {
                if (i11 == 0) {
                    return 2;
                }
                if (i11 == 1) {
                    return 3;
                }
                if (i11 == 2) {
                    return 0;
                }
                return (i11 != 3 || this.autoPlayingMedia) ? 4 : 0;
            }
            if (this.buttonState == -1) {
                if (this.documentAttachType == 1) {
                    return (!this.drawPhotoImage || (this.currentPhotoObject == null && this.currentPhotoObjectThumb == null) || !(this.photoImage.hasBitmapImage() || this.currentMessageObject.mediaExists || this.currentMessageObject.attachPathExists)) ? 5 : 4;
                }
                if (this.currentMessageObject.needDrawBluredPreview()) {
                    if (this.currentMessageObject.messageOwner.destroyTime != 0) {
                        if (this.currentMessageObject.isOutOwner()) {
                            return 9;
                        }
                        return 11;
                    }
                    return 7;
                }
                if (this.hasEmbed) {
                    return 0;
                }
            }
        }
        return 4;
    }

    private int getMaxNameWidth() {
        int maxWidth;
        int dWidth;
        int i = this.documentAttachType;
        if (i == 6 || i == 8 || this.currentMessageObject.type == 5 || this.currentMessageObject.type == 101) {
            if (AndroidUtilities.isTablet()) {
                if (this.isChat && !this.currentMessageObject.isOutOwner() && this.currentMessageObject.needDrawAvatar()) {
                    maxWidth = AndroidUtilities.getMinTabletSide() - AndroidUtilities.dp(42.0f);
                } else {
                    maxWidth = AndroidUtilities.getMinTabletSide();
                }
            } else if (this.isChat && !this.currentMessageObject.isOutOwner() && this.currentMessageObject.needDrawAvatar()) {
                maxWidth = Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) - AndroidUtilities.dp(42.0f);
            } else {
                maxWidth = Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y);
            }
            return (maxWidth - this.backgroundWidth) - AndroidUtilities.dp(57.0f);
        }
        if (this.currentMessagesGroup != null) {
            if (AndroidUtilities.isTablet()) {
                dWidth = AndroidUtilities.getMinTabletSide();
            } else {
                dWidth = AndroidUtilities.displaySize.x;
            }
            int firstLineWidth = 0;
            for (int a = 0; a < this.currentMessagesGroup.posArray.size(); a++) {
                MessageObject.GroupedMessagePosition position = this.currentMessagesGroup.posArray.get(a);
                if (position.minY != 0) {
                    break;
                }
                firstLineWidth = (int) (((double) firstLineWidth) + Math.ceil(((position.pw + position.leftSpanOffset) / 1000.0f) * dWidth));
            }
            return firstLineWidth - AndroidUtilities.dp((this.isAvatarVisible ? 48 : 0) + 31);
        }
        int dWidth2 = this.backgroundWidth;
        return dWidth2 - AndroidUtilities.dp(this.mediaBackground ? 22.0f : 31.0f);
    }

    public void updateButtonState(boolean ifSame, boolean animated, boolean fromSet) {
        boolean animated2;
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        MessageObject.GroupedMessagePosition groupedMessagePosition;
        int i7;
        int i8;
        if (animated && (PhotoViewer.isShowingImage(this.currentMessageObject) || !this.attachedToWindow)) {
            animated2 = false;
        } else {
            animated2 = animated;
        }
        this.drawRadialCheckBackground = false;
        String fileName = null;
        boolean fileExists = false;
        if (this.currentMessageObject.type == 1) {
            TLRPC.PhotoSize photoSize = this.currentPhotoObject;
            if (photoSize == null) {
                this.radialProgress.setIcon(4, ifSame, animated2);
                return;
            }
            if (!this.blnImgExchanged) {
                fileName = FileLoader.getAttachFileName(photoSize);
                fileExists = this.currentMessageObject.mediaExists;
            } else if (this.currentMessageObject.attachPathExists && !TextUtils.isEmpty(this.currentMessageObject.messageOwner.attachPath)) {
                fileName = this.currentMessageObject.messageOwner.attachPath;
                fileExists = true;
            } else if (!this.currentMessageObject.isSendError() || (i8 = this.documentAttachType) == 3 || i8 == 5) {
                fileName = this.currentMessageObject.getFileName();
                fileExists = this.currentMessageObject.mediaExists;
            }
        } else if (this.currentMessageObject.type == 8 || (i2 = this.documentAttachType) == 7 || i2 == 4 || i2 == 8 || this.currentMessageObject.type == 9 || (i3 = this.documentAttachType) == 3 || i3 == 5) {
            if (this.currentMessageObject.useCustomPhoto) {
                this.buttonState = 1;
                this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                return;
            } else if (this.currentMessageObject.attachPathExists && !TextUtils.isEmpty(this.currentMessageObject.messageOwner.attachPath)) {
                fileName = this.currentMessageObject.messageOwner.attachPath;
                fileExists = true;
            } else if (!this.currentMessageObject.isSendError() || (i = this.documentAttachType) == 3 || i == 5) {
                fileName = this.currentMessageObject.getFileName();
                fileExists = this.currentMessageObject.mediaExists;
            }
        } else if (i3 != 0) {
            fileName = FileLoader.getAttachFileName(this.documentAttach);
            fileExists = this.currentMessageObject.mediaExists;
        } else {
            TLRPC.PhotoSize photoSize2 = this.currentPhotoObject;
            if (photoSize2 != null) {
                fileName = FileLoader.getAttachFileName(photoSize2);
                fileExists = this.currentMessageObject.mediaExists;
            }
        }
        boolean autoDownload = DownloadController.getInstance(this.currentAccount).canDownloadMedia(this.currentMessageObject);
        this.canStreamVideo = this.currentMessageObject.isSent() && ((i7 = this.documentAttachType) == 4 || i7 == 7 || (i7 == 2 && autoDownload)) && this.currentMessageObject.canStreamVideo() && !this.currentMessageObject.needDrawBluredPreview();
        if (SharedConfig.streamMedia && ((int) this.currentMessageObject.getDialogId()) != 0 && !this.currentMessageObject.isSecretMedia() && (this.documentAttachType == 5 || (this.canStreamVideo && (groupedMessagePosition = this.currentPosition) != null && ((groupedMessagePosition.flags & 1) == 0 || (this.currentPosition.flags & 2) == 0)))) {
            this.hasMiniProgress = fileExists ? 1 : 2;
            fileExists = true;
        }
        if (!this.currentMessageObject.isSendError()) {
            if (!TextUtils.isEmpty(fileName) || this.currentMessageObject.isSending() || this.currentMessageObject.isEditing()) {
                boolean fromBot = this.currentMessageObject.messageOwner.params != null && this.currentMessageObject.messageOwner.params.containsKey("query_id");
                int i9 = this.documentAttachType;
                if (i9 == 3 || i9 == 5) {
                    if ((this.currentMessageObject.isOut() && (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing())) || (this.currentMessageObject.isSendError() && fromBot)) {
                        if (!TextUtils.isEmpty(this.currentMessageObject.messageOwner.attachPath)) {
                            DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(this.currentMessageObject.messageOwner.attachPath, this.currentMessageObject, this);
                            this.wasSending = true;
                            this.buttonState = 4;
                            this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                            if (!fromBot) {
                                Float progress = ImageLoader.getInstance().getFileProgress(this.currentMessageObject.messageOwner.attachPath);
                                if (progress == null && SendMessagesHelper.getInstance(this.currentAccount).isSendingMessage(this.currentMessageObject.getId())) {
                                    progress = Float.valueOf(1.0f);
                                }
                                this.radialProgress.setProgress(progress != null ? progress.floatValue() : 0.0f, false);
                            } else {
                                this.radialProgress.setProgress(0.0f, false);
                            }
                        } else {
                            this.buttonState = -1;
                            getIconForCurrentState();
                            this.radialProgress.setIcon(12, ifSame, false);
                            this.radialProgress.setProgress(0.0f, false);
                        }
                    } else if (this.hasMiniProgress != 0) {
                        this.radialProgress.setMiniProgressBackgroundColor(Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outLoader : Theme.key_chat_inLoader));
                        boolean playing = MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
                        if (!playing || (playing && MediaController.getInstance().isMessagePaused())) {
                            this.buttonState = 0;
                        } else {
                            this.buttonState = 1;
                        }
                        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        if (this.hasMiniProgress == 1) {
                            DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
                            this.miniButtonState = -1;
                        } else {
                            DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this.currentMessageObject, this);
                            if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName)) {
                                this.miniButtonState = 0;
                            } else {
                                this.miniButtonState = 1;
                                Float progress2 = ImageLoader.getInstance().getFileProgress(fileName);
                                if (progress2 != null) {
                                    this.radialProgress.setProgress(progress2.floatValue(), animated2);
                                } else {
                                    this.radialProgress.setProgress(0.0f, animated2);
                                }
                            }
                        }
                        this.radialProgress.setMiniIcon(getMiniIconForCurrentState(), ifSame, animated2);
                    } else if (fileExists) {
                        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
                        boolean playing2 = MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
                        if (!playing2 || (playing2 && MediaController.getInstance().isMessagePaused())) {
                            this.buttonState = 0;
                        } else {
                            this.buttonState = 1;
                        }
                        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                    } else {
                        DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this.currentMessageObject, this);
                        if (FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName)) {
                            this.buttonState = 4;
                            Float progress3 = ImageLoader.getInstance().getFileProgress(fileName);
                            if (progress3 != null) {
                                this.radialProgress.setProgress(progress3.floatValue(), animated2);
                            } else {
                                this.radialProgress.setProgress(0.0f, animated2);
                            }
                            this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        } else {
                            this.buttonState = 2;
                            this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        }
                    }
                    updatePlayingMessageProgress();
                } else if (this.currentMessageObject.type == 0 && (i6 = this.documentAttachType) != 1 && i6 != 2 && i6 != 7 && i6 != 4 && i6 != 8 && i6 != 9) {
                    if (this.currentPhotoObject == null || !this.drawImageButton) {
                        return;
                    }
                    if (!fileExists) {
                        DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this.currentMessageObject, this);
                        float setProgress = 0.0f;
                        if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName)) {
                            if (!this.cancelLoading && ((this.documentAttachType == 0 && autoDownload) || (this.documentAttachType == 2 && MessageObject.isGifDocument(this.documentAttach) && autoDownload))) {
                                this.buttonState = 1;
                            } else {
                                this.buttonState = 0;
                            }
                        } else {
                            this.buttonState = 1;
                            Float progress4 = ImageLoader.getInstance().getFileProgress(fileName);
                            setProgress = progress4 != null ? progress4.floatValue() : 0.0f;
                        }
                        this.radialProgress.setProgress(setProgress, false);
                        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        invalidate();
                    } else {
                        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
                        if (this.documentAttachType != 2 || this.photoImage.isAllowStartAnimation()) {
                            this.buttonState = -1;
                        } else {
                            this.buttonState = 2;
                        }
                        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        invalidate();
                    }
                } else if (this.currentMessageObject.isOut() && (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing())) {
                    if (!TextUtils.isEmpty(this.currentMessageObject.messageOwner.attachPath)) {
                        DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(this.currentMessageObject.messageOwner.attachPath, this.currentMessageObject, this);
                        this.wasSending = true;
                        boolean needProgress = this.currentMessageObject.messageOwner.attachPath == null || !this.currentMessageObject.messageOwner.attachPath.startsWith("http");
                        HashMap<String, String> params = this.currentMessageObject.messageOwner.params;
                        if (this.currentMessageObject.messageOwner.message != null && params != null && (params.containsKey(ImagesContract.URL) || params.containsKey("bot"))) {
                            needProgress = false;
                            this.buttonState = -1;
                        } else {
                            this.buttonState = 1;
                        }
                        boolean sending = SendMessagesHelper.getInstance(this.currentAccount).isSendingMessage(this.currentMessageObject.getId());
                        if (this.currentPosition != null && sending && this.buttonState == 1) {
                            this.drawRadialCheckBackground = true;
                            getIconForCurrentState();
                            this.radialProgress.setIcon(6, ifSame, animated2);
                        } else {
                            this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        }
                        if (needProgress) {
                            Float progress5 = ImageLoader.getInstance().getFileProgress(this.currentMessageObject.messageOwner.attachPath);
                            if (progress5 == null && sending) {
                                progress5 = Float.valueOf(1.0f);
                            }
                            this.radialProgress.setProgress(progress5 != null ? progress5.floatValue() : 0.0f, false);
                        } else {
                            this.radialProgress.setProgress(0.0f, false);
                        }
                        invalidate();
                    } else {
                        this.buttonState = -1;
                        getIconForCurrentState();
                        this.radialProgress.setIcon((this.currentMessageObject.isSticker() || this.currentMessageObject.isAnimatedSticker() || this.currentMessageObject.isLocation()) ? 4 : 12, ifSame, false);
                        this.radialProgress.setProgress(0.0f, false);
                    }
                    this.videoRadialProgress.setIcon(4, ifSame, false);
                } else {
                    if (this.wasSending && !TextUtils.isEmpty(this.currentMessageObject.messageOwner.attachPath)) {
                        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
                    }
                    boolean isLoadingVideo = false;
                    int i10 = this.documentAttachType;
                    if ((i10 == 4 || i10 == 2 || i10 == 7) && this.autoPlayingMedia) {
                        isLoadingVideo = FileLoader.getInstance(this.currentAccount).isLoadingVideo(this.documentAttach, MediaController.getInstance().isPlayingMessage(this.currentMessageObject));
                        AnimatedFileDrawable animation = this.photoImage.getAnimation();
                        if (animation != null) {
                            if (this.currentMessageObject.hadAnimationNotReadyLoading) {
                                if (animation.hasBitmap()) {
                                    this.currentMessageObject.hadAnimationNotReadyLoading = false;
                                }
                            } else {
                                this.currentMessageObject.hadAnimationNotReadyLoading = isLoadingVideo && !animation.hasBitmap();
                            }
                        } else if (this.documentAttachType == 2 && !fileExists) {
                            this.currentMessageObject.hadAnimationNotReadyLoading = true;
                        }
                    }
                    if (this.hasMiniProgress != 0) {
                        this.radialProgress.setMiniProgressBackgroundColor(Theme.getColor(Theme.key_chat_inLoaderPhoto));
                        this.buttonState = 3;
                        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        if (this.hasMiniProgress == 1) {
                            DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
                            this.miniButtonState = -1;
                        } else {
                            DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this.currentMessageObject, this);
                            if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName)) {
                                this.miniButtonState = 0;
                            } else {
                                this.miniButtonState = 1;
                                Float progress6 = ImageLoader.getInstance().getFileProgress(fileName);
                                if (progress6 != null) {
                                    this.radialProgress.setProgress(progress6.floatValue(), animated2);
                                } else {
                                    this.radialProgress.setProgress(0.0f, animated2);
                                }
                            }
                        }
                        this.radialProgress.setMiniIcon(getMiniIconForCurrentState(), ifSame, animated2);
                    } else if (fileExists || (((i5 = this.documentAttachType) == 4 || i5 == 2 || i5 == 7) && this.autoPlayingMedia && !this.currentMessageObject.hadAnimationNotReadyLoading && !isLoadingVideo)) {
                        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
                        if (this.drawVideoImageButton && animated2) {
                            int i11 = this.animatingDrawVideoImageButton;
                            if (i11 != 1 && this.animatingDrawVideoImageButtonProgress > 0.0f) {
                                if (i11 == 0) {
                                    this.animatingDrawVideoImageButtonProgress = 1.0f;
                                }
                                this.animatingDrawVideoImageButton = 1;
                            }
                        } else if (this.animatingDrawVideoImageButton == 0) {
                            this.animatingDrawVideoImageButtonProgress = 0.0f;
                        }
                        this.drawVideoImageButton = false;
                        this.drawVideoSize = false;
                        if (this.currentMessageObject.needDrawBluredPreview()) {
                            this.buttonState = -1;
                        } else if (this.currentMessageObject.type == 8 && this.currentMessageObject.gifState == 1.0f) {
                            this.buttonState = 2;
                        } else if (this.documentAttachType != 4) {
                            this.buttonState = -1;
                        } else {
                            this.buttonState = 3;
                        }
                        this.videoRadialProgress.setIcon(4, ifSame, this.animatingDrawVideoImageButton != 0);
                        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                        if (!fromSet && this.photoNotSet) {
                            setMessageObject(this.currentMessageObject, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
                        }
                        invalidate();
                    } else {
                        int i12 = this.documentAttachType;
                        this.drawVideoSize = i12 == 4 || i12 == 2;
                        int i13 = this.documentAttachType;
                        if ((i13 == 4 || i13 == 2 || i13 == 7) && this.canStreamVideo && !this.drawVideoImageButton && animated2) {
                            int i14 = this.animatingDrawVideoImageButton;
                            if (i14 != 2 && this.animatingDrawVideoImageButtonProgress < 1.0f) {
                                if (i14 == 0) {
                                    this.animatingDrawVideoImageButtonProgress = 0.0f;
                                }
                                this.animatingDrawVideoImageButton = 2;
                            }
                        } else if (this.animatingDrawVideoImageButton == 0) {
                            this.animatingDrawVideoImageButtonProgress = 1.0f;
                        }
                        DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this.currentMessageObject, this);
                        if (!FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName)) {
                            if (!this.cancelLoading && autoDownload) {
                                this.buttonState = 1;
                            } else {
                                this.buttonState = 0;
                            }
                            int i15 = this.documentAttachType;
                            if ((i15 == 4 || (i15 == 2 && autoDownload)) && this.canStreamVideo) {
                                this.drawVideoImageButton = true;
                                getIconForCurrentState();
                                this.radialProgress.setIcon(this.autoPlayingMedia ? 4 : 0, ifSame, animated2);
                                this.videoRadialProgress.setIcon(2, ifSame, animated2);
                            } else {
                                this.drawVideoImageButton = false;
                                this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                                this.videoRadialProgress.setIcon(4, ifSame, false);
                                if (!this.drawVideoSize && this.animatingDrawVideoImageButton == 0) {
                                    this.animatingDrawVideoImageButtonProgress = 0.0f;
                                }
                            }
                        } else {
                            this.buttonState = 1;
                            Float progress7 = ImageLoader.getInstance().getFileProgress(fileName);
                            int i16 = this.documentAttachType;
                            if ((i16 == 4 || (i16 == 2 && autoDownload)) && this.canStreamVideo) {
                                this.drawVideoImageButton = true;
                                getIconForCurrentState();
                                this.radialProgress.setIcon((this.autoPlayingMedia || this.documentAttachType == 2) ? 4 : 0, ifSame, animated2);
                                this.videoRadialProgress.setProgress(progress7 != null ? progress7.floatValue() : 0.0f, animated2);
                                this.videoRadialProgress.setIcon(14, ifSame, animated2);
                            } else {
                                this.drawVideoImageButton = false;
                                this.radialProgress.setProgress(progress7 != null ? progress7.floatValue() : 0.0f, animated2);
                                this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated2);
                                this.videoRadialProgress.setIcon(4, ifSame, false);
                                if (!this.drawVideoSize && this.animatingDrawVideoImageButton == 0) {
                                    this.animatingDrawVideoImageButtonProgress = 0.0f;
                                }
                            }
                        }
                        invalidate();
                    }
                }
                if (this.hasMiniProgress == 0) {
                    this.radialProgress.setMiniIcon(4, false, animated2);
                    return;
                }
                return;
            }
            i4 = 4;
        } else {
            i4 = 4;
        }
        this.radialProgress.setIcon(i4, ifSame, false);
        this.radialProgress.setMiniIcon(i4, ifSame, false);
        this.videoRadialProgress.setIcon(i4, ifSame, false);
        this.videoRadialProgress.setMiniIcon(i4, ifSame, false);
    }

    private void didPressMiniButton(boolean animated) {
        int i = this.miniButtonState;
        if (i == 0) {
            this.miniButtonState = 1;
            this.radialProgress.setProgress(0.0f, false);
            int i2 = this.documentAttachType;
            if (i2 == 3 || i2 == 5) {
                FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.currentMessageObject, 1, 0);
            } else if (i2 == 4) {
                FileLoader fileLoader = FileLoader.getInstance(this.currentAccount);
                TLRPC.Document document = this.documentAttach;
                MessageObject messageObject = this.currentMessageObject;
                fileLoader.loadFile(document, messageObject, 1, messageObject.shouldEncryptPhotoOrVideo() ? 2 : 0);
            }
            this.radialProgress.setMiniIcon(getMiniIconForCurrentState(), false, true);
            invalidate();
            return;
        }
        if (i == 1) {
            int i3 = this.documentAttachType;
            if ((i3 == 3 || i3 == 5) && MediaController.getInstance().isPlayingMessage(this.currentMessageObject)) {
                MediaController.getInstance().cleanupPlayer(true, true);
            }
            this.miniButtonState = 0;
            FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.documentAttach);
            this.radialProgress.setMiniIcon(getMiniIconForCurrentState(), false, true);
            invalidate();
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
    private void didPressButton(boolean animated, boolean video) {
        MessageObject playingMessage;
        TLRPC.PhotoSize thumb;
        String thumbFilter;
        int i;
        if (this.buttonState == 0 && (!this.drawVideoImageButton || video)) {
            int i2 = this.documentAttachType;
            if (i2 == 3 || i2 == 5) {
                if (this.miniButtonState == 0) {
                    FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.currentMessageObject, 1, 0);
                }
                if (this.delegate.needPlayMessage(this.currentMessageObject)) {
                    if (this.hasMiniProgress == 2 && this.miniButtonState != 1) {
                        this.miniButtonState = 1;
                        this.radialProgress.setProgress(0.0f, false);
                        this.radialProgress.setMiniIcon(getMiniIconForCurrentState(), false, true);
                    }
                    updatePlayingMessageProgress();
                    this.buttonState = 1;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, true);
                    invalidate();
                    return;
                }
                return;
            }
            this.cancelLoading = false;
            if (video) {
                this.videoRadialProgress.setProgress(0.0f, false);
            } else {
                this.radialProgress.setProgress(0.0f, false);
            }
            if (this.currentPhotoObject != null && (this.photoImage.hasNotThumb() || this.currentPhotoObjectThumb == null)) {
                thumb = this.currentPhotoObject;
                thumbFilter = ((thumb instanceof TLRPC.TL_photoStrippedSize) || "s".equals(thumb.type)) ? this.currentPhotoFilterThumb : this.currentPhotoFilter;
            } else {
                thumb = this.currentPhotoObjectThumb;
                thumbFilter = this.currentPhotoFilterThumb;
            }
            if (this.currentMessageObject.type == 1) {
                if (this.blnImgExchanged) {
                    FileLoader.getInstance(this.currentAccount).loadFile(this.currentMessageObject.getDocument(), this.currentMessageObject, 1, 0);
                } else {
                    this.photoImage.setForceLoading(true);
                    ImageReceiver imageReceiver = this.photoImage;
                    ImageLocation forObject = ImageLocation.getForObject(this.currentPhotoObject, this.photoParentObject);
                    String str = this.currentPhotoFilter;
                    ImageLocation forObject2 = ImageLocation.getForObject(this.currentPhotoObjectThumb, this.photoParentObject);
                    String str2 = this.currentPhotoFilterThumb;
                    int i3 = this.currentPhotoObject.size;
                    MessageObject messageObject = this.currentMessageObject;
                    imageReceiver.setImage(forObject, str, forObject2, str2, i3, null, messageObject, messageObject.shouldEncryptPhotoOrVideo() ? 2 : 0);
                }
            } else if (this.currentMessageObject.type == 8) {
                FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.currentMessageObject, 1, 0);
            } else if (this.currentMessageObject.isRoundVideo()) {
                if (this.currentMessageObject.isSecretMedia()) {
                    FileLoader.getInstance(this.currentAccount).loadFile(this.currentMessageObject.getDocument(), this.currentMessageObject, 1, 1);
                } else {
                    this.currentMessageObject.gifState = 2.0f;
                    TLRPC.Document document = this.currentMessageObject.getDocument();
                    this.photoImage.setForceLoading(true);
                    this.photoImage.setImage(ImageLocation.getForDocument(document), null, ImageLocation.getForObject(thumb, document), thumbFilter, document.size, null, this.currentMessageObject, 0);
                }
            } else if (this.currentMessageObject.type == 9) {
                FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.currentMessageObject, 1, 0);
            } else if (this.documentAttachType == 4) {
                FileLoader fileLoader = FileLoader.getInstance(this.currentAccount);
                TLRPC.Document document2 = this.documentAttach;
                MessageObject messageObject2 = this.currentMessageObject;
                fileLoader.loadFile(document2, messageObject2, 1, messageObject2.shouldEncryptPhotoOrVideo() ? 2 : 0);
            } else if (this.currentMessageObject.type == 0 && (i = this.documentAttachType) != 0) {
                if (i == 2) {
                    this.photoImage.setForceLoading(true);
                    this.photoImage.setImage(ImageLocation.getForDocument(this.documentAttach), null, ImageLocation.getForDocument(this.currentPhotoObject, this.documentAttach), this.currentPhotoFilterThumb, this.documentAttach.size, null, this.currentMessageObject, 0);
                    this.currentMessageObject.gifState = 2.0f;
                } else if (i == 1) {
                    FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.currentMessageObject, 0, 0);
                } else if (i == 8) {
                    this.photoImage.setImage(ImageLocation.getForDocument(this.documentAttach), this.currentPhotoFilter, ImageLocation.getForDocument(this.currentPhotoObject, this.documentAttach), "b1", 0, "jpg", this.currentMessageObject, 1);
                }
            } else {
                this.photoImage.setForceLoading(true);
                this.photoImage.setImage(ImageLocation.getForObject(this.currentPhotoObject, this.photoParentObject), this.currentPhotoFilter, ImageLocation.getForObject(this.currentPhotoObjectThumb, this.photoParentObject), this.currentPhotoFilterThumb, 0, null, this.currentMessageObject, 0);
            }
            this.buttonState = 1;
            if (video) {
                this.videoRadialProgress.setIcon(14, false, animated);
            } else {
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
            }
            invalidate();
            return;
        }
        if (this.buttonState == 1 && (!this.drawVideoImageButton || video)) {
            this.photoImage.setForceLoading(false);
            int i4 = this.documentAttachType;
            if (i4 == 3 || i4 == 5) {
                boolean result = MediaController.getInstance().lambda$startAudioAgain$5$MediaController(this.currentMessageObject);
                if (result) {
                    this.buttonState = 0;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                    invalidate();
                    return;
                }
                return;
            }
            if (this.currentMessageObject.isOut() && (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing())) {
                if (this.radialProgress.getIcon() != 6) {
                    this.delegate.didPressCancelSendButton(this);
                    return;
                }
                return;
            }
            this.cancelLoading = true;
            int i5 = this.documentAttachType;
            if (i5 == 2 || i5 == 4 || i5 == 1 || i5 == 8) {
                FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.documentAttach);
            } else if (this.currentMessageObject.type == 0 || this.currentMessageObject.type == 1 || this.currentMessageObject.type == 8 || this.currentMessageObject.type == 5) {
                ImageLoader.getInstance().cancelForceLoadingForImageReceiver(this.photoImage);
                this.photoImage.cancelLoadImage();
                if (this.blnImgExchanged) {
                    FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.currentMessageObject.getDocument());
                }
            } else if (this.currentMessageObject.type == 9) {
                FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.currentMessageObject.getDocument());
            }
            this.buttonState = 0;
            if (video) {
                this.videoRadialProgress.setIcon(2, false, animated);
            } else {
                this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
            }
            invalidate();
            return;
        }
        int i6 = this.buttonState;
        if (i6 == 2) {
            int i7 = this.documentAttachType;
            if (i7 == 3 || i7 == 5) {
                this.radialProgress.setProgress(0.0f, false);
                FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.currentMessageObject, 1, 0);
                this.buttonState = 4;
                this.radialProgress.setIcon(getIconForCurrentState(), true, animated);
                invalidate();
                return;
            }
            if (!this.currentMessageObject.isRoundVideo() || (playingMessage = MediaController.getInstance().getPlayingMessageObject()) == null || !playingMessage.isRoundVideo()) {
                this.photoImage.setAllowStartAnimation(true);
                this.photoImage.startAnimation();
            }
            this.currentMessageObject.gifState = 0.0f;
            this.buttonState = -1;
            this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
            return;
        }
        if (i6 == 3 || (i6 == 0 && this.drawVideoImageButton)) {
            if (this.hasMiniProgress == 2 && this.miniButtonState != 1) {
                this.miniButtonState = 1;
                this.radialProgress.setProgress(0.0f, false);
                this.radialProgress.setMiniIcon(getMiniIconForCurrentState(), false, animated);
            }
            this.delegate.didPressImage(this, 0.0f, 0.0f);
            return;
        }
        if (this.buttonState == 4) {
            int i8 = this.documentAttachType;
            if (i8 == 3 || i8 == 5) {
                if ((!this.currentMessageObject.isOut() || (!this.currentMessageObject.isSending() && !this.currentMessageObject.isEditing())) && !this.currentMessageObject.isSendError()) {
                    FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.documentAttach);
                    this.buttonState = 2;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, animated);
                    invalidate();
                    return;
                }
                ChatMessageCellDelegate chatMessageCellDelegate = this.delegate;
                if (chatMessageCellDelegate != null) {
                    chatMessageCellDelegate.didPressCancelSendButton(this);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onFailedDownload(String fileName, boolean canceled) {
        int i = this.documentAttachType;
        updateButtonState(true, i == 3 || i == 5, false);
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onSuccessDownload(String fileName) {
        TLRPC.Document document;
        MessageObject.GroupedMessagePosition groupedMessagePosition;
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            updateButtonState(false, true, false);
            updateWaveform();
            return;
        }
        if (this.drawVideoImageButton) {
            this.videoRadialProgress.setProgress(1.0f, true);
        } else {
            this.radialProgress.setProgress(1.0f, true);
        }
        if (!this.currentMessageObject.needDrawBluredPreview() && !this.autoPlayingMedia && (document = this.documentAttach) != null) {
            if (this.documentAttachType == 7) {
                ImageReceiver imageReceiver = this.photoImage;
                ImageLocation forDocument = ImageLocation.getForDocument(document);
                ImageLocation forObject = ImageLocation.getForObject(this.currentPhotoObject, this.photoParentObject);
                TLRPC.PhotoSize photoSize = this.currentPhotoObject;
                imageReceiver.setImage(forDocument, ImageLoader.AUTOPLAY_FILTER, forObject, ((photoSize instanceof TLRPC.TL_photoStrippedSize) || (photoSize != null && "s".equals(photoSize.type))) ? this.currentPhotoFilterThumb : this.currentPhotoFilter, ImageLocation.getForObject(this.currentPhotoObjectThumb, this.photoParentObject), this.currentPhotoFilterThumb, null, this.documentAttach.size, null, this.currentMessageObject, 0);
                this.photoImage.setAllowStartAnimation(true);
                this.photoImage.startAnimation();
                this.autoPlayingMedia = true;
            } else if (SharedConfig.autoplayVideo && this.documentAttachType == 4 && ((groupedMessagePosition = this.currentPosition) == null || ((groupedMessagePosition.flags & 1) != 0 && (this.currentPosition.flags & 2) != 0))) {
                this.animatingNoSound = 2;
                ImageReceiver imageReceiver2 = this.photoImage;
                ImageLocation forDocument2 = ImageLocation.getForDocument(this.documentAttach);
                ImageLocation forObject2 = ImageLocation.getForObject(this.currentPhotoObject, this.photoParentObject);
                TLRPC.PhotoSize photoSize2 = this.currentPhotoObject;
                imageReceiver2.setImage(forDocument2, ImageLoader.AUTOPLAY_FILTER, forObject2, ((photoSize2 instanceof TLRPC.TL_photoStrippedSize) || (photoSize2 != null && "s".equals(photoSize2.type))) ? this.currentPhotoFilterThumb : this.currentPhotoFilter, ImageLocation.getForObject(this.currentPhotoObjectThumb, this.photoParentObject), this.currentPhotoFilterThumb, null, this.documentAttach.size, null, this.currentMessageObject, 0);
                if (!PhotoViewer.isPlayingMessage(this.currentMessageObject)) {
                    this.photoImage.setAllowStartAnimation(true);
                    this.photoImage.startAnimation();
                } else {
                    this.photoImage.setAllowStartAnimation(false);
                }
                this.autoPlayingMedia = true;
            } else if (this.documentAttachType == 2) {
                ImageReceiver imageReceiver3 = this.photoImage;
                ImageLocation forDocument3 = ImageLocation.getForDocument(this.documentAttach);
                ImageLocation forObject3 = ImageLocation.getForObject(this.currentPhotoObject, this.photoParentObject);
                TLRPC.PhotoSize photoSize3 = this.currentPhotoObject;
                imageReceiver3.setImage(forDocument3, ImageLoader.AUTOPLAY_FILTER, forObject3, ((photoSize3 instanceof TLRPC.TL_photoStrippedSize) || (photoSize3 != null && "s".equals(photoSize3.type))) ? this.currentPhotoFilterThumb : this.currentPhotoFilter, ImageLocation.getForObject(this.currentPhotoObjectThumb, this.photoParentObject), this.currentPhotoFilterThumb, null, this.documentAttach.size, null, this.currentMessageObject, 0);
                if (SharedConfig.autoplayGifs) {
                    this.photoImage.setAllowStartAnimation(true);
                    this.photoImage.startAnimation();
                } else {
                    this.photoImage.setAllowStartAnimation(false);
                    this.photoImage.stopAnimation();
                }
                this.autoPlayingMedia = true;
            }
        }
        if (this.currentMessageObject.type == 0) {
            if (!this.autoPlayingMedia && this.documentAttachType == 2 && this.currentMessageObject.gifState != 1.0f) {
                this.buttonState = 2;
                didPressButton(true, false);
                return;
            } else if (this.photoNotSet) {
                setMessageObject(this.currentMessageObject, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
                return;
            } else {
                updateButtonState(false, true, false);
                return;
            }
        }
        if (!this.photoNotSet) {
            updateButtonState(false, true, false);
        }
        if (this.photoNotSet) {
            setMessageObject(this.currentMessageObject, this.currentMessagesGroup, this.pinnedBottom, this.pinnedTop);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
    public void didSetImage(ImageReceiver imageReceiver, boolean set, boolean thumb) {
        int i;
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null || !set || thumb || messageObject.mediaExists || this.currentMessageObject.attachPathExists) {
            return;
        }
        if ((this.currentMessageObject.type == 0 && ((i = this.documentAttachType) == 8 || i == 0 || i == 6)) || this.currentMessageObject.type == 1) {
            this.currentMessageObject.mediaExists = true;
            updateButtonState(false, true, false);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
    public void onAnimationReady(ImageReceiver imageReceiver) {
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject != null && imageReceiver == this.photoImage && messageObject.isAnimatedSticker()) {
            this.delegate.setShouldNotRepeatSticker(this.currentMessageObject);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressDownload(String fileName, float progress) {
        if (this.drawVideoImageButton) {
            this.videoRadialProgress.setProgress(progress, true);
        } else {
            this.radialProgress.setProgress(progress, true);
        }
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            if (this.hasMiniProgress != 0) {
                if (this.miniButtonState != 1) {
                    updateButtonState(false, false, false);
                    return;
                }
                return;
            } else {
                if (this.buttonState != 4) {
                    updateButtonState(false, false, false);
                    return;
                }
                return;
            }
        }
        if (this.hasMiniProgress != 0) {
            if (this.miniButtonState != 1) {
                updateButtonState(false, false, false);
            }
        } else if (this.buttonState != 1) {
            updateButtonState(false, false, false);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
        this.radialProgress.setProgress(progress, true);
        if (progress == 1.0f && this.currentPosition != null) {
            boolean sending = SendMessagesHelper.getInstance(this.currentAccount).isSendingMessage(this.currentMessageObject.getId());
            if (sending && this.buttonState == 1) {
                this.drawRadialCheckBackground = true;
                getIconForCurrentState();
                this.radialProgress.setIcon(6, false, true);
            }
        }
    }

    @Override // android.view.View
    public void onProvideStructure(ViewStructure structure) {
        super.onProvideStructure(structure);
        if (this.allowAssistant && Build.VERSION.SDK_INT >= 23) {
            if (this.currentMessageObject.messageText != null && this.currentMessageObject.messageText.length() > 0) {
                structure.setText(this.currentMessageObject.messageText);
            } else if (this.currentMessageObject.caption != null && this.currentMessageObject.caption.length() > 0) {
                structure.setText(this.currentMessageObject.caption);
            }
        }
    }

    public void setDelegate(ChatMessageCellDelegate chatMessageCellDelegate) {
        this.delegate = chatMessageCellDelegate;
    }

    public void setAllowAssistant(boolean value) {
        this.allowAssistant = value;
    }

    private void measureTime(MessageObject messageObject) {
        CharSequence signString;
        MessageObject.GroupedMessages groupedMessages;
        if (messageObject.scheduled) {
            signString = null;
        } else if (messageObject.messageOwner.post_author != null) {
            signString = messageObject.messageOwner.post_author.replace(ShellAdbUtils.COMMAND_LINE_END, "");
        } else if (messageObject.messageOwner.fwd_from != null && messageObject.messageOwner.fwd_from.post_author != null) {
            signString = messageObject.messageOwner.fwd_from.post_author.replace(ShellAdbUtils.COMMAND_LINE_END, "");
        } else if (!messageObject.isOutOwner() && messageObject.messageOwner.from_id > 0 && messageObject.messageOwner.post) {
            TLRPC.User signUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(messageObject.messageOwner.from_id));
            if (signUser != null) {
                signString = ContactsController.formatName(signUser.first_name, signUser.last_name).replace('\n', ' ');
            } else {
                signString = null;
            }
        } else {
            signString = null;
        }
        TLRPC.User author = null;
        if (this.currentMessageObject.isFromUser()) {
            author = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(messageObject.messageOwner.from_id));
        }
        if (!messageObject.scheduled && !messageObject.isLiveLocation() && !messageObject.messageOwner.edit_hide && messageObject.getDialogId() != 777000 && messageObject.messageOwner.via_bot_id == 0 && messageObject.messageOwner.via_bot_name == null && (author == null || !author.bot)) {
            if (this.currentPosition == null || (groupedMessages = this.currentMessagesGroup) == null) {
                boolean z = (messageObject.messageOwner.flags & 32768) != 0 || messageObject.isEditing();
            } else {
                int size = groupedMessages.messages.size();
                for (int a = 0; a < size; a++) {
                    MessageObject object = this.currentMessagesGroup.messages.get(a);
                    if ((object.messageOwner.flags & 32768) != 0 || object.isEditing()) {
                        break;
                    }
                }
            }
        }
        long longFormat = ((long) messageObject.messageOwner.date) * 1000;
        String timeString = LocaleController.getInstance().formatterDayNoly.format(longFormat);
        String timeString2 = TimeUtils.isAm(longFormat) ? LocaleController.getString("AM", mpEIGo.juqQQs.esbSDO.R.string.formatterDayAM) + "  " + timeString : LocaleController.getString("PM", mpEIGo.juqQQs.esbSDO.R.string.formatterDayPM) + "  " + timeString;
        if (signString != null) {
            this.currentTimeString = ", " + timeString2;
        } else {
            this.currentTimeString = timeString2;
        }
        Log.d("bond", timeString2);
        int iCeil = (int) Math.ceil(Theme.chat_timePaint.measureText(this.currentTimeString));
        this.timeWidth = iCeil;
        this.timeTextWidth = iCeil;
        if ((messageObject.messageOwner.flags & 1024) != 0) {
            this.currentViewsString = String.format("%s", LocaleController.formatShortNumber(Math.max(1, messageObject.messageOwner.views), null));
            int iCeil2 = (int) Math.ceil(Theme.chat_timePaint.measureText(this.currentViewsString));
            this.viewsTextWidth = iCeil2;
            this.timeWidth += iCeil2 + Theme.chat_msgInViewsDrawable.getIntrinsicWidth() + AndroidUtilities.dp(10.0f);
        }
        if (messageObject.scheduled && messageObject.isSendError()) {
            this.timeWidth += AndroidUtilities.dp(18.0f);
        }
        if (signString != null) {
            if (this.availableTimeWidth == 0) {
                this.availableTimeWidth = AndroidUtilities.dp(1000.0f);
            }
            int widthForSign = this.availableTimeWidth - this.timeWidth;
            if (messageObject.isOutOwner()) {
                if (messageObject.type == 5) {
                    widthForSign -= AndroidUtilities.dp(20.0f);
                } else {
                    widthForSign -= AndroidUtilities.dp(96.0f);
                }
            }
            int width = (int) Math.ceil(Theme.chat_timePaint.measureText(signString, 0, signString.length()));
            if (width > widthForSign) {
                if (widthForSign <= 0) {
                    signString = "";
                    width = 0;
                } else {
                    signString = TextUtils.ellipsize(signString, Theme.chat_timePaint, widthForSign, TextUtils.TruncateAt.END);
                    width = widthForSign;
                }
            }
            this.currentTimeString = ((Object) signString) + this.currentTimeString;
            this.timeTextWidth = this.timeTextWidth + width;
            this.timeWidth = this.timeWidth + width;
        }
    }

    private boolean isDrawSelectionBackground() {
        return (isPressed() && this.isCheckPressed) || (!this.isCheckPressed && this.isPressed) || this.isHighlighted;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isOpenChatByShare(MessageObject messageObject) {
        return (messageObject.messageOwner.fwd_from == null || messageObject.messageOwner.fwd_from.saved_from_peer == null) ? false : true;
    }

    private boolean checkNeedDrawShareButton(MessageObject messageObject) {
        MessageObject.GroupedMessagePosition groupedMessagePosition = this.currentPosition;
        if ((groupedMessagePosition != null && !groupedMessagePosition.last) || messageObject.type == 101 || messageObject.type == 102) {
            return false;
        }
        if (messageObject.messageOwner.fwd_from != null && !messageObject.isOutOwner() && messageObject.messageOwner.fwd_from.saved_from_peer != null && messageObject.getDialogId() == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
            this.drwaShareGoIcon = true;
        }
        return messageObject.needDrawShareButton();
    }

    public boolean isInsideBackground(float x, float y) {
        if (this.currentBackgroundDrawable != null) {
            if (x >= this.backgroundDrawableLeft && x <= r0 + this.backgroundDrawableRight) {
                return true;
            }
        }
        return false;
    }

    private void updateCurrentUserAndChat() {
        MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null || messageObject.messageOwner == null) {
            return;
        }
        TLRPC.MessageFwdHeader fwd_from = this.currentMessageObject.messageOwner.fwd_from;
        int currentUserId = UserConfig.getInstance(this.currentAccount).getClientUserId();
        if (fwd_from != null && fwd_from.channel_id != 0 && this.currentMessageObject.getDialogId() == currentUserId) {
            this.currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(fwd_from.channel_id));
            return;
        }
        if (fwd_from != null && fwd_from.saved_from_peer != null) {
            if (fwd_from.saved_from_peer.user_id != 0) {
                if (fwd_from.from_id != 0) {
                    this.currentUser = messagesController.getUser(Integer.valueOf(fwd_from.from_id));
                    return;
                } else {
                    this.currentUser = messagesController.getUser(Integer.valueOf(fwd_from.saved_from_peer.user_id));
                    return;
                }
            }
            if (fwd_from.saved_from_peer.channel_id != 0) {
                if (this.currentMessageObject.isSavedFromMegagroup() && fwd_from.from_id != 0) {
                    this.currentUser = messagesController.getUser(Integer.valueOf(fwd_from.from_id));
                    return;
                } else {
                    this.currentChat = messagesController.getChat(Integer.valueOf(fwd_from.saved_from_peer.channel_id));
                    return;
                }
            }
            if (fwd_from.saved_from_peer.chat_id != 0) {
                if (fwd_from.from_id != 0) {
                    this.currentUser = messagesController.getUser(Integer.valueOf(fwd_from.from_id));
                    return;
                } else {
                    this.currentChat = messagesController.getChat(Integer.valueOf(fwd_from.saved_from_peer.chat_id));
                    return;
                }
            }
            return;
        }
        if (fwd_from != null && fwd_from.from_id != 0 && fwd_from.channel_id == 0 && this.currentMessageObject.getDialogId() == currentUserId) {
            this.currentUser = messagesController.getUser(Integer.valueOf(fwd_from.from_id));
            return;
        }
        if (fwd_from != null && !TextUtils.isEmpty(fwd_from.from_name) && this.currentMessageObject.getDialogId() == currentUserId) {
            TLRPC.TL_user tL_user = new TLRPC.TL_user();
            this.currentUser = tL_user;
            tL_user.first_name = fwd_from.from_name;
        } else if (this.currentMessageObject.isFromUser()) {
            this.currentUser = messagesController.getUser(Integer.valueOf(this.currentMessageObject.messageOwner.from_id));
        } else if (this.currentMessageObject.messageOwner.from_id < 0) {
            this.currentChat = messagesController.getChat(Integer.valueOf(-this.currentMessageObject.messageOwner.from_id));
        } else if (this.currentMessageObject.messageOwner.post) {
            this.currentChat = messagesController.getChat(Integer.valueOf(this.currentMessageObject.messageOwner.to_id.channel_id));
        }
    }

    public float setImageReceiverHeightAutoSize(TLRPCContacts.NotifyMsgMedia mediaData, int width) {
        int photoWidth;
        int photoHeight;
        if (mediaData != null) {
            if (mediaData.media.document != null) {
                TLRPC.DocumentAttribute attribute = mediaData.media.document.attributes.get(1);
                photoWidth = attribute.w;
                photoHeight = attribute.h;
                if (photoWidth < (this.backgroundWidth - AndroidUtilities.dp(60.0f)) / 3) {
                    photoWidth = (this.backgroundWidth - AndroidUtilities.dp(60.0f)) / 3;
                }
            } else {
                TLRPC.Photo photo = mediaData.media.photo;
                TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
                photoWidth = photoSize.w;
                photoHeight = photoSize.h;
            }
            DecimalFormat df = new DecimalFormat("0.0");
            String sysSize = df.format((this.backgroundWidth - AndroidUtilities.dp(60.0f)) / photoWidth);
            Float height = Float.valueOf(sysSize);
            return photoHeight * height.floatValue();
        }
        return 0.0f;
    }

    private StaticLayout setSysNotifyTextInfo(StaticLayout layout, TLRPCContacts.NotifyMsgText textData, int maxWidth) {
        Theme.chat_redpkgTextPaint.setTextSize(AndroidUtilities.dp(16.0f));
        if (textData != null) {
            String textInfo = textData.msg;
            StaticLayout layout2 = new StaticLayout(textInfo, Theme.chat_redpkgTextPaint, maxWidth, Layout.Alignment.ALIGN_NORMAL, 1.5f, 0.0f, false);
            return layout2;
        }
        return null;
    }

    private ImageReceiver setSysNotifyPhotoInfo(ImageReceiver image, TLRPCContacts.NotifyMsgMedia mediaData, MessageObject messageObject) {
        int photoWidth;
        if (mediaData != null) {
            if (mediaData.media.document != null) {
                TLRPC.DocumentAttribute attribute = mediaData.media.document.attributes.get(1);
                int photoWidth2 = attribute.w;
                int photoHeight = attribute.h;
                if (photoWidth2 >= (this.backgroundWidth - AndroidUtilities.dp(60.0f)) / 3) {
                    photoWidth = photoWidth2;
                } else {
                    photoWidth = (this.backgroundWidth - AndroidUtilities.dp(60.0f)) / 3;
                }
                String str = String.format(Locale.US, "%d_%d_nr_%s", Integer.valueOf(photoWidth), Integer.valueOf(photoHeight), messageObject.toString());
                this.currentPhotoFilter = str;
                this.currentPhotoFilterThumb = str;
                this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(mediaData.media.document.thumbs, AndroidUtilities.getPhotoSize());
                this.currentPhotoObjectThumb = FileLoader.getClosestPhotoSizeWithSize(mediaData.media.document.thumbs, AndroidUtilities.getPhotoSize());
                image.setNeedsQualityThumb(true);
                image.setShouldGenerateQualityThumb(true);
                image.setImage(ImageLocation.getForDocument(mediaData.media.document), ImageLoader.AUTOPLAY_FILTER, ImageLocation.getForObject(this.currentPhotoObject, this.photoParentObject), this.currentPhotoFilter, ImageLocation.getForDocument(this.currentPhotoObjectThumb, mediaData.media.document), this.currentPhotoFilterThumb, null, mediaData.media.document.size, null, messageObject, 0);
            } else {
                TLRPC.Photo photo = mediaData.media.photo;
                TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
                image.setNeedsQualityThumb(true);
                image.setShouldGenerateQualityThumb(true);
                image.setImage(ImageLocation.getForPhoto(photoSize, photo), null, null, "null", null, 1);
            }
            return image;
        }
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v1 */
    /* JADX WARN: Type inference failed for: r5v2 */
    /* JADX WARN: Type inference failed for: r5v24, types: [im.uwrkaxlmjj.tgnet.TLRPC$Chat, im.uwrkaxlmjj.tgnet.TLRPC$User, java.lang.String] */
    /* JADX WARN: Type inference failed for: r5v33 */
    private void setMessageObjectInternal(MessageObject messageObject) {
        CharSequence viaString;
        String viaUsername;
        String str;
        int adminWidth;
        String adminString;
        String str2;
        CharSequence nameStringFinal;
        ?? r5;
        int color;
        CharSequence nameStringFinal2;
        MessageObject.GroupedMessagePosition groupedMessagePosition;
        int maxWidth;
        String name;
        CharSequence stringFinalText;
        MessageObject.GroupedMessagePosition groupedMessagePosition2;
        String fromString;
        int i;
        SpannableStringBuilder stringBuilder;
        if ((messageObject.messageOwner.flags & 1024) != 0 && !this.currentMessageObject.scheduled && !this.currentMessageObject.viewsReloaded) {
            MessagesController.getInstance(this.currentAccount).addToViewsQueue(this.currentMessageObject);
            this.currentMessageObject.viewsReloaded = true;
        }
        updateCurrentUserAndChat();
        if (this.isAvatarVisible) {
            TLRPC.User user = this.currentUser;
            if (user != null) {
                if (user.photo != null) {
                    this.currentPhoto = this.currentUser.photo.photo_small;
                } else {
                    this.currentPhoto = null;
                }
                this.avatarDrawable.setInfo(this.currentUser);
                this.avatarImage.setImage(ImageLocation.getForUser(this.currentUser, false), "50_50", this.avatarDrawable, null, this.currentUser, 0);
            } else {
                TLRPC.Chat chat = this.currentChat;
                if (chat != null) {
                    if (chat.photo != null) {
                        this.currentPhoto = this.currentChat.photo.photo_small;
                    } else {
                        this.currentPhoto = null;
                    }
                    this.avatarDrawable.setInfo(this.currentChat);
                    this.avatarImage.setImage(ImageLocation.getForChat(this.currentChat, false), "50_50", this.avatarDrawable, null, this.currentChat, 0);
                } else {
                    this.currentPhoto = null;
                    this.avatarDrawable.setInfo(messageObject.messageOwner.from_id, null, null);
                    this.avatarImage.setImage(null, null, this.avatarDrawable, null, null, 0);
                }
            }
        } else {
            this.currentPhoto = null;
        }
        measureTime(messageObject);
        this.namesOffset = 0;
        String viaUsername2 = null;
        CharSequence viaString2 = null;
        if (messageObject.messageOwner.via_bot_id != 0) {
            TLRPC.User botUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(messageObject.messageOwner.via_bot_id));
            if (botUser != null && botUser.username != null && botUser.username.length() > 0) {
                viaUsername2 = "@" + botUser.username;
                viaString2 = AndroidUtilities.replaceTags(String.format(" %s <b>%s</b>", LocaleController.getString("ViaBot", mpEIGo.juqQQs.esbSDO.R.string.ViaBot), viaUsername2));
                this.viaWidth = (int) Math.ceil(Theme.chat_replyNamePaint.measureText(viaString2, 0, viaString2.length()));
                this.currentViaBotUser = botUser;
            }
            viaString = viaString2;
            viaUsername = viaUsername2;
        } else if (messageObject.messageOwner.via_bot_name != null && messageObject.messageOwner.via_bot_name.length() > 0) {
            String viaUsername3 = "@" + messageObject.messageOwner.via_bot_name;
            CharSequence viaString3 = AndroidUtilities.replaceTags(String.format(" %s <b>%s</b>", LocaleController.getString("ViaBot", mpEIGo.juqQQs.esbSDO.R.string.ViaBot), viaUsername3));
            this.viaWidth = (int) Math.ceil(Theme.chat_replyNamePaint.measureText(viaString3, 0, viaString3.length()));
            viaString = viaString3;
            viaUsername = viaUsername3;
        } else {
            viaString = null;
            viaUsername = null;
        }
        boolean authorName = this.drawName && this.isChat && !this.currentMessageObject.isOutOwner();
        boolean viaBot = (messageObject.messageOwner.fwd_from == null || messageObject.type == 14) && viaUsername != null;
        if (authorName || viaBot) {
            this.drawNameLayout = true;
            int maxNameWidth = getMaxNameWidth();
            this.nameWidth = maxNameWidth;
            if (maxNameWidth < 0) {
                this.nameWidth = AndroidUtilities.dp(100.0f);
            }
            if (!this.isMegagroup || this.currentChat == null || !this.currentMessageObject.isForwardedChannelPost()) {
                str = "%s %s %s";
                adminWidth = 0;
                adminString = null;
            } else {
                String adminString2 = LocaleController.getString("DiscussChannel", mpEIGo.juqQQs.esbSDO.R.string.DiscussChannel);
                str = "%s %s %s";
                int adminWidth2 = (int) Math.ceil(Theme.chat_adminPaint.measureText(adminString2));
                this.nameWidth -= adminWidth2;
                adminWidth = adminWidth2;
                adminString = adminString2;
            }
            if (!authorName) {
                this.currentNameString = "";
            } else {
                TLRPC.User user2 = this.currentUser;
                if (user2 != null) {
                    this.currentNameString = UserObject.getName(user2);
                } else {
                    TLRPC.Chat chat2 = this.currentChat;
                    if (chat2 != null) {
                        this.currentNameString = chat2.title;
                    } else {
                        this.currentNameString = "DELETED";
                    }
                }
            }
            CharSequence nameStringFinal3 = TextUtils.ellipsize(this.currentNameString.replace('\n', ' '), Theme.chat_namePaint, this.nameWidth - (viaBot ? this.viaWidth : 0), TextUtils.TruncateAt.END);
            if (viaBot) {
                int iCeil = (int) Math.ceil(Theme.chat_namePaint.measureText(nameStringFinal3, 0, nameStringFinal3.length()));
                this.viaNameWidth = iCeil;
                if (iCeil != 0) {
                    this.viaNameWidth = iCeil + AndroidUtilities.dp(4.0f);
                }
                if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                    color = Theme.getColor(Theme.key_chat_stickerViaBotNameText);
                } else {
                    color = Theme.getColor(this.currentMessageObject.isOutOwner() ? Theme.key_chat_outViaBotNameText : Theme.key_chat_inViaBotNameText);
                }
                String viaBotString = LocaleController.getString("ViaBot", mpEIGo.juqQQs.esbSDO.R.string.ViaBot);
                if (this.currentNameString.length() > 0) {
                    str2 = str;
                    SpannableStringBuilder stringBuilder2 = new SpannableStringBuilder(String.format(str2, nameStringFinal3, viaBotString, viaUsername));
                    TypefaceSpan typefaceSpan = new TypefaceSpan(Typeface.DEFAULT, 0, color);
                    this.viaSpan1 = typefaceSpan;
                    stringBuilder2.setSpan(typefaceSpan, nameStringFinal3.length() + 1, nameStringFinal3.length() + 1 + viaBotString.length(), 33);
                    TypefaceSpan typefaceSpan2 = new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf"), 0, color);
                    this.viaSpan2 = typefaceSpan2;
                    stringBuilder2.setSpan(typefaceSpan2, nameStringFinal3.length() + 2 + viaBotString.length(), stringBuilder2.length(), 33);
                    nameStringFinal2 = stringBuilder2;
                } else {
                    str2 = str;
                    SpannableStringBuilder stringBuilder3 = new SpannableStringBuilder(String.format("%s %s", viaBotString, viaUsername));
                    TypefaceSpan typefaceSpan3 = new TypefaceSpan(Typeface.DEFAULT, 0, color);
                    this.viaSpan1 = typefaceSpan3;
                    stringBuilder3.setSpan(typefaceSpan3, 0, viaBotString.length() + 1, 33);
                    TypefaceSpan typefaceSpan4 = new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf"), 0, color);
                    this.viaSpan2 = typefaceSpan4;
                    stringBuilder3.setSpan(typefaceSpan4, viaBotString.length() + 1, stringBuilder3.length(), 33);
                    nameStringFinal2 = stringBuilder3;
                }
                nameStringFinal = TextUtils.ellipsize(nameStringFinal2, Theme.chat_namePaint, this.nameWidth, TextUtils.TruncateAt.END);
            } else {
                str2 = str;
                nameStringFinal = nameStringFinal3;
            }
            try {
                StaticLayout staticLayout = new StaticLayout(nameStringFinal, Theme.chat_namePaint, this.nameWidth + AndroidUtilities.dp(2.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                this.nameLayout = staticLayout;
                if (staticLayout == null || staticLayout.getLineCount() <= 0) {
                    this.nameWidth = 0;
                } else {
                    this.nameWidth = (int) Math.ceil(this.nameLayout.getLineWidth(0));
                    if (!messageObject.isAnyKindOfSticker()) {
                        this.namesOffset += AndroidUtilities.dp(10.0f);
                    }
                    this.nameOffsetX = this.nameLayout.getLineLeft(0);
                }
                if (adminString == null) {
                    this.adminLayout = null;
                } else {
                    StaticLayout staticLayout2 = new StaticLayout(adminString, Theme.chat_adminPaint, adminWidth + AndroidUtilities.dp(2.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    this.adminLayout = staticLayout2;
                    this.nameWidth = (int) (this.nameWidth + staticLayout2.getLineWidth(0) + AndroidUtilities.dp(8.0f));
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            if (this.currentNameString.length() != 0) {
                r5 = 0;
            } else {
                r5 = 0;
                this.currentNameString = null;
            }
        } else {
            this.currentNameString = null;
            this.nameLayout = null;
            this.nameWidth = 0;
            r5 = 0;
            str2 = "%s %s %s";
        }
        this.currentForwardUser = r5;
        this.currentForwardNameString = r5;
        this.currentForwardChannel = r5;
        this.currentForwardName = r5;
        StaticLayout[] staticLayoutArr = this.forwardedNameLayout;
        staticLayoutArr[0] = r5;
        staticLayoutArr[1] = r5;
        this.forwardedNameWidth = 0;
        if (this.drawForwardedName && messageObject.needDrawForwarded() && ((groupedMessagePosition2 = this.currentPosition) == null || groupedMessagePosition2.minY == 0)) {
            if (messageObject.messageOwner.fwd_from.channel_id != 0) {
                this.currentForwardChannel = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(messageObject.messageOwner.fwd_from.channel_id));
            }
            if (messageObject.messageOwner.fwd_from.from_id != 0) {
                this.currentForwardUser = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(messageObject.messageOwner.fwd_from.from_id));
            }
            if (messageObject.messageOwner.fwd_from.from_name != null) {
                this.currentForwardName = messageObject.messageOwner.fwd_from.from_name;
            }
            if (this.currentForwardUser != null || this.currentForwardChannel != null || this.currentForwardName != null) {
                TLRPC.Chat chat3 = this.currentForwardChannel;
                if (chat3 != null) {
                    if (this.currentForwardUser != null) {
                        this.currentForwardNameString = String.format("%s (%s)", chat3.title, UserObject.getName(this.currentForwardUser));
                    } else {
                        this.currentForwardNameString = chat3.title;
                    }
                } else {
                    TLRPC.User user3 = this.currentForwardUser;
                    if (user3 != null) {
                        this.currentForwardNameString = UserObject.getName(user3);
                    } else {
                        String str3 = this.currentForwardName;
                        if (str3 != null) {
                            this.currentForwardNameString = str3;
                        }
                    }
                }
                this.forwardedNameWidth = getMaxNameWidth();
                String from = LocaleController.getString("From", mpEIGo.juqQQs.esbSDO.R.string.From);
                String fromFormattedString = LocaleController.getString("FromFormatted", mpEIGo.juqQQs.esbSDO.R.string.FromFormatted);
                int idx = fromFormattedString.indexOf("%1$s");
                TextPaint textPaint = Theme.chat_forwardNamePaint;
                int fromWidth = (int) Math.ceil(textPaint.measureText(from + " "));
                CharSequence name2 = TextUtils.ellipsize(this.currentForwardNameString.replace('\n', ' '), Theme.chat_replyNamePaint, (float) ((this.forwardedNameWidth - fromWidth) - this.viaWidth), TextUtils.TruncateAt.END);
                try {
                    String fromString2 = String.format(fromFormattedString, name2);
                    fromString = fromString2;
                } catch (Exception e2) {
                    fromString = name2.toString();
                }
                if (viaString != null) {
                    SpannableStringBuilder stringBuilder4 = new SpannableStringBuilder(String.format(str2, fromString, LocaleController.getString("ViaBot", mpEIGo.juqQQs.esbSDO.R.string.ViaBot), viaUsername));
                    this.viaNameWidth = (int) Math.ceil(Theme.chat_forwardNamePaint.measureText(fromString));
                    stringBuilder4.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf")), (stringBuilder4.length() - viaUsername.length()) - 1, stringBuilder4.length(), 33);
                    stringBuilder = stringBuilder4;
                    i = 0;
                } else {
                    i = 0;
                    stringBuilder = new SpannableStringBuilder(String.format(fromFormattedString, name2));
                }
                this.forwardNameCenterX = (((int) Math.ceil(Theme.chat_forwardNamePaint.measureText(name2, i, name2.length()))) / 2) + fromWidth;
                if (idx >= 0 && (this.currentForwardName == null || messageObject.messageOwner.fwd_from.from_id != 0)) {
                    stringBuilder.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf")), idx, name2.length() + idx, 33);
                }
                CharSequence lastLine = stringBuilder;
                try {
                    this.forwardedNameLayout[1] = new StaticLayout(TextUtils.ellipsize(lastLine, Theme.chat_forwardNamePaint, this.forwardedNameWidth, TextUtils.TruncateAt.END), Theme.chat_forwardNamePaint, this.forwardedNameWidth + AndroidUtilities.dp(2.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    CharSequence lastLine2 = TextUtils.ellipsize(AndroidUtilities.replaceTags(LocaleController.getString("ForwardedMessage", mpEIGo.juqQQs.esbSDO.R.string.ForwardedMessage)), Theme.chat_forwardNamePaint, this.forwardedNameWidth, TextUtils.TruncateAt.END);
                    try {
                        this.forwardedNameLayout[0] = new StaticLayout(lastLine2, Theme.chat_forwardNamePaint, this.forwardedNameWidth + AndroidUtilities.dp(2.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                        this.forwardedNameWidth = Math.max((int) Math.ceil(this.forwardedNameLayout[0].getLineWidth(0)), (int) Math.ceil(this.forwardedNameLayout[1].getLineWidth(0)));
                        this.forwardNameOffsetX[0] = this.forwardedNameLayout[0].getLineLeft(0);
                        this.forwardNameOffsetX[1] = this.forwardedNameLayout[1].getLineLeft(0);
                        if (messageObject.type != 5) {
                            this.namesOffset += AndroidUtilities.dp(36.0f);
                        }
                    } catch (Exception e3) {
                        e = e3;
                        FileLog.e(e);
                    }
                } catch (Exception e4) {
                    e = e4;
                }
            }
        }
        if (messageObject.hasValidReplyMessageObject() && ((groupedMessagePosition = this.currentPosition) == null || groupedMessagePosition.minY == 0)) {
            if (!messageObject.isAnyKindOfSticker() && messageObject.type != 5) {
                this.namesOffset += AndroidUtilities.dp(42.0f);
                if (messageObject.type != 0) {
                    this.namesOffset += AndroidUtilities.dp(5.0f);
                }
            }
            int maxWidth2 = getMaxNameWidth();
            if (!messageObject.shouldDrawWithoutBackground()) {
                maxWidth2 -= AndroidUtilities.dp(10.0f);
            } else if (messageObject.type == 5) {
                maxWidth2 += AndroidUtilities.dp(13.0f);
            }
            int cacheType = 1;
            int size = 0;
            TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(messageObject.replyMessageObject.photoThumbs2, 320);
            TLRPC.PhotoSize thumbPhotoSize = FileLoader.getClosestPhotoSizeWithSize(messageObject.replyMessageObject.photoThumbs2, 40);
            TLObject photoObject = messageObject.replyMessageObject.photoThumbsObject2;
            if (photoSize == null) {
                if (messageObject.replyMessageObject.mediaExists) {
                    if (messageObject.replyMessageObject.type == 9 || messageObject.replyMessageObject.type == 1) {
                        TLRPC.Document documentAttach = messageObject.replyMessageObject.getDocument();
                        int iSide = AndroidUtilities.getPhotoSize();
                        if (documentAttach != null) {
                            if (MessageObject.isVoiceDocument(documentAttach) || MessageObject.isMusicDocument(documentAttach) || ((documentAttach.mime_type != null && documentAttach.mime_type.toLowerCase().startsWith("video/")) || MessageObject.isGifDocument(documentAttach))) {
                                iSide = AndroidUtilities.getPhotoSize();
                            } else if ((documentAttach.mime_type != null && documentAttach.mime_type.toLowerCase().startsWith("image/")) || MessageObject.isDocumentHasThumb(documentAttach)) {
                                iSide = 80000;
                            }
                        }
                        photoSize = FileLoader.getClosestPhotoSizeWithSize(messageObject.replyMessageObject.photoThumbs, iSide);
                    } else {
                        photoSize = FileLoader.getClosestPhotoSizeWithSize(messageObject.replyMessageObject.photoThumbs, AndroidUtilities.getPhotoSize());
                    }
                    if (photoSize != null) {
                        size = photoSize.size;
                    }
                    cacheType = 0;
                } else {
                    photoSize = FileLoader.getClosestPhotoSizeWithSize(messageObject.replyMessageObject.photoThumbs, 320);
                }
                thumbPhotoSize = FileLoader.getClosestPhotoSizeWithSize(messageObject.replyMessageObject.photoThumbs, 40);
                photoObject = messageObject.replyMessageObject.photoThumbsObject;
            }
            if (thumbPhotoSize == photoSize) {
                thumbPhotoSize = null;
            }
            if (photoSize == null || messageObject.replyMessageObject.isAnyKindOfSticker() || ((messageObject.isAnyKindOfSticker() && !AndroidUtilities.isTablet()) || messageObject.replyMessageObject.isSecretMedia())) {
                this.replyImageReceiver.setImageBitmap((Drawable) null);
                this.needReplyImage = false;
                maxWidth = maxWidth2;
            } else {
                if (messageObject.replyMessageObject.isRoundVideo()) {
                    this.replyImageReceiver.setRoundRadius(AndroidUtilities.dp(22.0f));
                } else {
                    this.replyImageReceiver.setRoundRadius(0);
                }
                this.currentReplyPhoto = photoSize;
                this.replyImageReceiver.setImage(ImageLocation.getForObject(photoSize, photoObject), "50_50", ImageLocation.getForObject(thumbPhotoSize, photoObject), "50_50_b", size, null, messageObject.replyMessageObject, cacheType);
                this.needReplyImage = true;
                maxWidth = maxWidth2 - AndroidUtilities.dp(44.0f);
            }
            String name3 = null;
            if (messageObject.customReplyName != null) {
                name3 = messageObject.customReplyName;
            } else if (messageObject.replyMessageObject.isFromUser()) {
                TLRPC.User user4 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(messageObject.replyMessageObject.messageOwner.from_id));
                if (user4 != null) {
                    name3 = UserObject.getName(user4);
                }
            } else if (messageObject.replyMessageObject.messageOwner.from_id < 0) {
                TLRPC.Chat chat4 = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-messageObject.replyMessageObject.messageOwner.from_id));
                if (chat4 != null) {
                    name3 = chat4.title;
                }
            } else {
                TLRPC.Chat chat5 = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(messageObject.replyMessageObject.messageOwner.to_id.channel_id));
                if (chat5 != null) {
                    name3 = chat5.title;
                }
            }
            if (name3 != null) {
                name = name3;
            } else {
                name = LocaleController.getString("Loading", mpEIGo.juqQQs.esbSDO.R.string.Loading);
            }
            CharSequence stringFinalName = TextUtils.ellipsize(name.replace('\n', ' '), Theme.chat_replyNamePaint, maxWidth, TextUtils.TruncateAt.END);
            if (messageObject.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                CharSequence stringFinalText2 = Emoji.replaceEmoji(messageObject.replyMessageObject.messageOwner.media.game.title, Theme.chat_replyTextPaint.getFontMetricsInt(), AndroidUtilities.dp(14.0f), false);
                stringFinalText = TextUtils.ellipsize(stringFinalText2, Theme.chat_replyTextPaint, maxWidth, TextUtils.TruncateAt.END);
            } else if (messageObject.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice) {
                CharSequence stringFinalText3 = Emoji.replaceEmoji(messageObject.replyMessageObject.messageOwner.media.title, Theme.chat_replyTextPaint.getFontMetricsInt(), AndroidUtilities.dp(14.0f), false);
                stringFinalText = TextUtils.ellipsize(stringFinalText3, Theme.chat_replyTextPaint, maxWidth, TextUtils.TruncateAt.END);
            } else if (messageObject.replyMessageObject.messageText != null && messageObject.replyMessageObject.messageText.length() > 0) {
                String mess = messageObject.replyMessageObject.messageText.toString();
                if (mess.length() > 150) {
                    mess = mess.substring(0, 150);
                }
                CharSequence stringFinalText4 = Emoji.replaceEmoji(mess.replace('\n', ' '), Theme.chat_replyTextPaint.getFontMetricsInt(), AndroidUtilities.dp(14.0f), false);
                stringFinalText = TextUtils.ellipsize(stringFinalText4, Theme.chat_replyTextPaint, maxWidth, TextUtils.TruncateAt.END);
            } else {
                stringFinalText = null;
            }
            try {
                this.replyNameWidth = AndroidUtilities.dp((this.needReplyImage ? 44 : 0) + 4);
                if (stringFinalName != null) {
                    StaticLayout staticLayout3 = new StaticLayout(stringFinalName, Theme.chat_replyNamePaint, maxWidth + AndroidUtilities.dp(6.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    this.replyNameLayout = staticLayout3;
                    if (staticLayout3.getLineCount() > 0) {
                        this.replyNameWidth += ((int) Math.ceil(this.replyNameLayout.getLineWidth(0))) + AndroidUtilities.dp(8.0f);
                        this.replyNameOffset = this.replyNameLayout.getLineLeft(0);
                    }
                }
            } catch (Exception e5) {
                FileLog.e(e5);
            }
            try {
                this.replyTextWidth = AndroidUtilities.dp(4 + (this.needReplyImage ? 44 : 0));
                if (stringFinalText != null) {
                    StaticLayout staticLayout4 = new StaticLayout(stringFinalText, Theme.chat_replyTextPaint, maxWidth + AndroidUtilities.dp(10.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    this.replyTextLayout = staticLayout4;
                    if (staticLayout4.getLineCount() > 0) {
                        this.replyTextWidth += ((int) Math.ceil(this.replyTextLayout.getLineWidth(0))) + AndroidUtilities.dp(8.0f);
                        this.replyTextOffset = this.replyTextLayout.getLineLeft(0);
                    }
                }
            } catch (Exception e6) {
                FileLog.e(e6);
            }
        }
        requestLayout();
    }

    public int getCaptionHeight() {
        return this.addedCaptionHeight;
    }

    public ImageReceiver getAvatarImage() {
        if (this.isAvatarVisible) {
            return this.avatarImage;
        }
        return null;
    }

    public float getCheckBoxTranslation() {
        return this.checkBoxTranslation;
    }

    public void drawCheckBox(Canvas canvas) {
        MessageObject messageObject = this.currentMessageObject;
        if (messageObject == null || messageObject.isSending() || this.currentMessageObject.isSendError() || this.checkBox == null) {
            return;
        }
        if (this.checkBoxVisible || this.checkBoxAnimationInProgress) {
            MessageObject.GroupedMessagePosition groupedMessagePosition = this.currentPosition;
            if (groupedMessagePosition == null || ((groupedMessagePosition.flags & 8) != 0 && (this.currentPosition.flags & 1) != 0)) {
                canvas.save();
                canvas.translate(0.0f, getTop());
                this.checkBox.draw(canvas);
                canvas.restore();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:148:0x0352  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void onDraw(android.graphics.Canvas r44) {
        /*
            Method dump skipped, instruction units count: 3959
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.onDraw(android.graphics.Canvas):void");
    }

    public void setTimeAlpha(float value) {
        this.timeAlpha = value;
    }

    public float getTimeAlpha() {
        return this.timeAlpha;
    }

    public int getBackgroundDrawableLeft() {
        MessageObject.GroupedMessagePosition groupedMessagePosition;
        if (this.currentMessageObject.isOutOwner()) {
            return ((this.layoutWidth - this.backgroundWidth) - (this.mediaBackground ? AndroidUtilities.dp(9.0f) : 0)) - AndroidUtilities.dp((this.isAvatarVisible || ((groupedMessagePosition = this.currentPosition) != null && groupedMessagePosition.edge)) ? 48.0f : 0.0f);
        }
        if (this.isChat && this.isAvatarVisible) {
            i = 48;
        }
        return AndroidUtilities.dp(i + (!this.mediaBackground ? 3 : 9));
    }

    public boolean hasNameLayout() {
        if (this.drawNameLayout && this.nameLayout != null) {
            return true;
        }
        if (this.drawForwardedName) {
            StaticLayout[] staticLayoutArr = this.forwardedNameLayout;
            if (staticLayoutArr[0] != null && staticLayoutArr[1] != null) {
                MessageObject.GroupedMessagePosition groupedMessagePosition = this.currentPosition;
                if (groupedMessagePosition == null) {
                    return true;
                }
                if (groupedMessagePosition.minY == 0 && this.currentPosition.minX == 0) {
                    return true;
                }
            }
        }
        return this.replyNameLayout != null;
    }

    public boolean isDrawNameLayout() {
        return this.drawNameLayout && this.nameLayout != null;
    }

    public void drawNamesLayout(Canvas canvas) {
        MessageObject.GroupedMessagePosition groupedMessagePosition;
        if (this.drawNameLayout && this.nameLayout != null) {
            canvas.save();
            if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                if (this.currentMessageObject.isOutOwner()) {
                    this.nameX = (this.backgroundDrawableLeft + AndroidUtilities.dp(11.0f)) - this.nameOffsetX;
                } else {
                    this.nameX = (this.backgroundDrawableLeft + AndroidUtilities.dp(5.0f)) - this.nameOffsetX;
                }
                if (this.currentUser != null) {
                    Theme.chat_namePaint.setColor(Theme.getColor(Theme.key_chat_adminText));
                } else {
                    TLRPC.Chat chat = this.currentChat;
                    if (chat != null) {
                        if (ChatObject.isChannel(chat) && !this.currentChat.megagroup) {
                            Theme.chat_namePaint.setColor(Theme.changeColorAccent(AvatarDrawable.getNameColorForId(5)));
                        } else {
                            Theme.chat_namePaint.setColor(AvatarDrawable.getNameColorForId(this.currentChat.id));
                        }
                    } else {
                        Theme.chat_namePaint.setColor(AvatarDrawable.getNameColorForId(0));
                    }
                }
                this.nameY = AndroidUtilities.dp(this.drawPinnedTop ? 9.0f : 10.0f) - mOffset;
            } else {
                if (this.currentMessageObject.isOutOwner()) {
                    this.nameX = (this.backgroundDrawableLeft + AndroidUtilities.dp(11.0f)) - this.nameOffsetX;
                } else {
                    this.nameX = (this.backgroundDrawableLeft + AndroidUtilities.dp(5.0f)) - this.nameOffsetX;
                }
                if (this.currentUser != null) {
                    Theme.chat_namePaint.setColor(Theme.getColor(Theme.key_chat_adminText));
                } else {
                    TLRPC.Chat chat2 = this.currentChat;
                    if (chat2 != null) {
                        if (ChatObject.isChannel(chat2) && !this.currentChat.megagroup) {
                            Theme.chat_namePaint.setColor(Theme.changeColorAccent(AvatarDrawable.getNameColorForId(5)));
                        } else {
                            Theme.chat_namePaint.setColor(AvatarDrawable.getNameColorForId(this.currentChat.id));
                        }
                    } else {
                        Theme.chat_namePaint.setColor(AvatarDrawable.getNameColorForId(0));
                    }
                }
                this.nameY = AndroidUtilities.dp(this.drawPinnedTop ? 9.0f : 10.0f) - mOffset;
            }
            canvas.translate(this.nameX, this.nameY);
            this.nameLayout.draw(canvas);
            canvas.restore();
        }
        if (this.drawForwardedName) {
            StaticLayout[] staticLayoutArr = this.forwardedNameLayout;
            if (staticLayoutArr[0] != null && staticLayoutArr[1] != null && ((groupedMessagePosition = this.currentPosition) == null || (groupedMessagePosition.minY == 0 && this.currentPosition.minX == 0))) {
                if (this.currentMessageObject.type == 5) {
                    Theme.chat_forwardNamePaint.setColor(Theme.getColor(Theme.key_chat_stickerReplyNameText));
                    if (this.currentMessageObject.isOutOwner()) {
                        this.forwardNameX = AndroidUtilities.dp(23.0f);
                    } else {
                        this.forwardNameX = this.backgroundDrawableLeft + this.backgroundDrawableRight + AndroidUtilities.dp(17.0f);
                    }
                    this.forwardNameY = AndroidUtilities.dp(12.0f);
                    int backWidth = this.forwardedNameWidth + AndroidUtilities.dp(14.0f);
                    Theme.chat_systemDrawable.setColorFilter(Theme.colorFilter);
                    Theme.chat_systemDrawable.setBounds(this.forwardNameX - AndroidUtilities.dp(7.0f), this.forwardNameY - AndroidUtilities.dp(6.0f), (this.forwardNameX - AndroidUtilities.dp(7.0f)) + backWidth, this.forwardNameY + AndroidUtilities.dp(38.0f));
                    Theme.chat_systemDrawable.draw(canvas);
                } else {
                    this.forwardNameY = AndroidUtilities.dp((this.drawNameLayout ? 19 : 0) + 10);
                    if (this.currentMessageObject.isOutOwner()) {
                        Theme.chat_forwardNamePaint.setColor(Theme.getColor(Theme.key_chat_outForwardedNameText));
                        this.forwardNameX = this.backgroundDrawableLeft + AndroidUtilities.dp(11.0f);
                    } else {
                        Theme.chat_forwardNamePaint.setColor(Theme.getColor(Theme.key_chat_inForwardedNameText));
                        boolean z = this.mediaBackground;
                        if (z) {
                            this.forwardNameX = this.backgroundDrawableLeft + AndroidUtilities.dp(11.0f);
                        } else {
                            this.forwardNameX = this.backgroundDrawableLeft + AndroidUtilities.dp((z || !this.drawPinnedBottom) ? 17.0f : 11.0f);
                        }
                    }
                }
                for (int a = 0; a < 2; a++) {
                    canvas.save();
                    canvas.translate(this.forwardNameX - this.forwardNameOffsetX[a], this.forwardNameY + (AndroidUtilities.dp(16.0f) * a));
                    this.forwardedNameLayout[a].draw(canvas);
                    canvas.restore();
                }
            }
        }
        if (this.replyNameLayout != null) {
            if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                Theme.chat_replyLinePaint.setColor(Theme.getColor(Theme.key_chat_stickerReplyLine));
                Theme.chat_replyNamePaint.setColor(Theme.getColor(Theme.key_chat_stickerReplyNameText));
                Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_stickerReplyMessageText));
                int backWidth2 = Math.max(this.replyNameWidth, this.replyTextWidth) + AndroidUtilities.dp(14.0f);
                Theme.chat_systemDrawable.setColorFilter(Theme.colorFilter);
                Theme.chat_systemDrawable.setBounds(this.replyStartX - AndroidUtilities.dp(7.0f), this.replyStartY - AndroidUtilities.dp(6.0f), (this.replyStartX - AndroidUtilities.dp(7.0f)) + backWidth2, this.replyStartY + AndroidUtilities.dp(41.0f));
                Theme.chat_systemDrawable.draw(canvas);
            } else if (this.currentMessageObject.isOutOwner()) {
                Theme.chat_replyLinePaint.setColor(Theme.getColor(Theme.key_chat_outReplyLine));
                Theme.chat_replyNamePaint.setColor(Theme.getColor(Theme.key_chat_outReplyNameText));
                if (this.currentMessageObject.hasValidReplyMessageObject() && this.currentMessageObject.replyMessageObject.type == 0 && !(this.currentMessageObject.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGame) && !(this.currentMessageObject.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
                    Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_outReplyMessageText));
                } else {
                    Theme.chat_replyTextPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outReplyMediaMessageSelectedText : Theme.key_chat_outReplyMediaMessageText));
                }
            } else {
                Theme.chat_replyLinePaint.setColor(Theme.getColor(Theme.key_chat_inReplyLine));
                Theme.chat_replyNamePaint.setColor(Theme.getColor(Theme.key_chat_inReplyNameText));
                if (this.currentMessageObject.hasValidReplyMessageObject() && this.currentMessageObject.replyMessageObject.type == 0 && !(this.currentMessageObject.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGame) && !(this.currentMessageObject.replyMessageObject.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
                    Theme.chat_replyTextPaint.setColor(Theme.getColor(Theme.key_chat_inReplyMessageText));
                } else {
                    Theme.chat_replyTextPaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inReplyMediaMessageSelectedText : Theme.key_chat_inReplyMediaMessageText));
                }
            }
            MessageObject.GroupedMessagePosition groupedMessagePosition2 = this.currentPosition;
            if (groupedMessagePosition2 == null || (groupedMessagePosition2.minY == 0 && this.currentPosition.minX == 0)) {
                canvas.drawRect(this.replyStartX, this.replyStartY, r0 + AndroidUtilities.dp(2.0f), this.replyStartY + AndroidUtilities.dp(35.0f), Theme.chat_replyLinePaint);
                if (this.needReplyImage) {
                    this.replyImageReceiver.setImageCoords(this.replyStartX + AndroidUtilities.dp(6.0f), this.replyStartY + AndroidUtilities.dp(1.0f), AndroidUtilities.dp(33.0f), AndroidUtilities.dp(33.0f));
                    this.replyImageReceiver.draw(canvas);
                }
                if (this.replyNameLayout != null) {
                    canvas.save();
                    canvas.translate((this.replyStartX - this.replyNameOffset) + AndroidUtilities.dp((this.needReplyImage ? 44 : 0) + 6), this.replyStartY);
                    this.replyNameLayout.draw(canvas);
                    canvas.restore();
                }
                if (this.replyTextLayout != null) {
                    canvas.save();
                    canvas.translate((this.replyStartX - this.replyTextOffset) + AndroidUtilities.dp((this.needReplyImage ? 44 : 0) + 6), this.replyStartY + AndroidUtilities.dp(19.0f));
                    this.replyTextLayout.draw(canvas);
                    canvas.restore();
                }
            }
        }
    }

    public boolean hasCaptionLayout() {
        return this.captionLayout != null;
    }

    public void setDrawSelectionBackground(boolean value) {
        this.drawSelectionBackground = value;
        invalidate();
    }

    public boolean isDrawingSelectionBackground() {
        return this.drawSelectionBackground || this.isHighlightedAnimated || this.isHighlighted;
    }

    public float getHightlightAlpha() {
        int i;
        if (this.drawSelectionBackground || !this.isHighlightedAnimated || (i = this.highlightProgress) >= 300) {
            return 1.0f;
        }
        return i / 300.0f;
    }

    public void setCheckBoxVisible(boolean visible, boolean animated) {
        MessageObject.GroupedMessages groupedMessages;
        if (visible && this.checkBox == null) {
            CheckBoxBase checkBoxBase = new CheckBoxBase(this, 21);
            this.checkBox = checkBoxBase;
            if (this.attachedToWindow) {
                checkBoxBase.onAttachedToWindow();
            }
        }
        if (visible && this.photoCheckBox == null && (groupedMessages = this.currentMessagesGroup) != null && groupedMessages.messages.size() > 1) {
            CheckBoxBase checkBoxBase2 = new CheckBoxBase(this, 21);
            this.photoCheckBox = checkBoxBase2;
            checkBoxBase2.setUseDefaultCheck(true);
            if (this.attachedToWindow) {
                this.photoCheckBox.onAttachedToWindow();
            }
        }
        if (this.checkBoxVisible == visible) {
            if (animated != this.checkBoxAnimationInProgress && !animated) {
                this.checkBoxAnimationProgress = visible ? 1.0f : 0.0f;
                invalidate();
                return;
            }
            return;
        }
        this.checkBoxAnimationInProgress = animated;
        this.checkBoxVisible = visible;
        if (animated) {
            this.lastCheckBoxAnimationTime = SystemClock.uptimeMillis();
        } else {
            this.checkBoxAnimationProgress = visible ? 1.0f : 0.0f;
        }
        invalidate();
    }

    public void setChecked(boolean checked, boolean allChecked, boolean animated) {
        CheckBoxBase checkBoxBase = this.checkBox;
        if (checkBoxBase != null) {
            checkBoxBase.setChecked(allChecked, animated);
        }
        CheckBoxBase checkBoxBase2 = this.photoCheckBox;
        if (checkBoxBase2 != null) {
            checkBoxBase2.setChecked(checked, animated);
        }
    }

    public void drawCaptionLayout(Canvas canvas, boolean selectionOnly) {
        if (this.captionLayout != null) {
            if (selectionOnly && this.pressedLink == null) {
                return;
            }
            if (this.currentMessageObject.isOutOwner()) {
                if (this.documentAttachType == 1) {
                    Theme.chat_msgTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
                    Theme.chat_msgTextPaint.linkColor = Theme.getColor(Theme.key_chat_messageLinkIn);
                } else {
                    Theme.chat_msgTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextOut));
                    Theme.chat_msgTextPaint.linkColor = Theme.getColor(Theme.key_chat_messageLinkOut);
                }
            } else {
                Theme.chat_msgTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
                Theme.chat_msgTextPaint.linkColor = Theme.getColor(Theme.key_chat_messageLinkIn);
            }
            canvas.save();
            canvas.translate(this.captionX, this.captionY);
            if (this.pressedLink != null) {
                for (int b = 0; b < this.urlPath.size(); b++) {
                    canvas.drawPath(this.urlPath.get(b), Theme.chat_urlPaint);
                }
            }
            if (!this.urlPathSelection.isEmpty()) {
                for (int b2 = 0; b2 < this.urlPathSelection.size(); b2++) {
                    canvas.drawPath(this.urlPathSelection.get(b2), Theme.chat_textSearchSelectionPaint);
                }
            }
            if (!selectionOnly) {
                try {
                    this.captionLayout.draw(canvas);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
            canvas.restore();
        }
    }

    public boolean needDrawTime() {
        return !this.forceNotDrawTime;
    }

    public void drawTime(Canvas canvas) {
        int additionOffset;
        int i;
        boolean isBroadcast;
        Drawable drawable;
        Drawable drawable2;
        Drawable drawable3;
        Drawable drawable4;
        int x;
        int y;
        int x2;
        int y2;
        Paint paint;
        int y1;
        int oldAlpha;
        Paint paint2;
        int i2;
        Drawable viewsDrawable;
        if (((!this.drawTime || this.groupPhotoInvisible) && this.mediaBackground && this.captionLayout == null) || this.timeLayout == null) {
            return;
        }
        if (this.currentMessageObject.type == 5) {
            Theme.chat_timePaint.setColor(Theme.getColor(Theme.key_chat_mediaTimeText));
        } else if (this.mediaBackground && this.captionLayout == null) {
            if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                Theme.chat_timePaint.setColor(Theme.getColor(Theme.key_chat_serviceText));
            } else {
                Theme.chat_timePaint.setColor(Theme.getColor(Theme.key_chat_mediaTimeText));
            }
        } else if (this.currentMessageObject.isOutOwner()) {
            Theme.chat_timePaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_outTimeSelectedText : Theme.key_chat_outTimeText));
        } else {
            Theme.chat_timePaint.setColor(Theme.getColor(isDrawSelectionBackground() ? Theme.key_chat_inTimeSelectedText : Theme.key_chat_inTimeText));
        }
        if (this.drawPinnedBottom) {
            canvas.translate(0.0f, AndroidUtilities.dp(2.0f));
        }
        if (this.currentMessageObject.transHeight == 0) {
            additionOffset = 0;
        } else {
            int additionOffset2 = this.currentMessageObject.transHeight + AndroidUtilities.dp(35.0f);
            additionOffset = additionOffset2;
        }
        if (!this.mediaBackground || this.captionLayout != null) {
            i = MessageObject.TYPE_LIVE;
            int additionalX = (int) (-this.timeLayout.getLineLeft(0));
            if ((ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup) || (this.currentMessageObject.messageOwner.flags & 1024) != 0) {
                isBroadcast = false;
                additionalX += (int) (this.timeWidth - this.timeLayout.getLineWidth(0));
                if (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing()) {
                    if (!this.currentMessageObject.isOutOwner()) {
                        Drawable clockDrawable = isDrawSelectionBackground() ? Theme.chat_msgInSelectedClockDrawable : Theme.chat_msgInClockDrawable;
                        setDrawableBounds(clockDrawable, this.timeX + (this.currentMessageObject.scheduled ? 0 : AndroidUtilities.dp(11.0f)), (this.layoutHeight - AndroidUtilities.dp(8.5f)) - clockDrawable.getIntrinsicHeight());
                        clockDrawable.draw(canvas);
                    }
                } else if (this.currentMessageObject.isSendError()) {
                    if (!this.currentMessageObject.isOutOwner()) {
                        int x3 = this.timeX + (this.currentMessageObject.scheduled ? 0 : AndroidUtilities.dp(11.0f));
                        int y3 = this.layoutHeight - AndroidUtilities.dp(20.5f);
                        this.rect.set(x3, y3, AndroidUtilities.dp(14.0f) + x3, AndroidUtilities.dp(14.0f) + y3);
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), Theme.chat_msgErrorPaint);
                        setDrawableBounds(Theme.chat_msgErrorDrawable, AndroidUtilities.dp(6.0f) + x3, AndroidUtilities.dp(2.0f) + y3);
                        Theme.chat_msgErrorDrawable.draw(canvas);
                    }
                } else if (this.viewsLayout != null) {
                    if (!this.currentMessageObject.isOutOwner()) {
                        Drawable viewsDrawable2 = isDrawSelectionBackground() ? Theme.chat_msgInViewsSelectedDrawable : Theme.chat_msgInViewsDrawable;
                        setDrawableBounds(viewsDrawable2, this.timeX, ((this.layoutHeight - AndroidUtilities.dp(4.5f)) - mOffset) - this.timeLayout.getHeight());
                        viewsDrawable2.draw(canvas);
                    } else {
                        Drawable viewsDrawable3 = isDrawSelectionBackground() ? Theme.chat_msgOutViewsSelectedDrawable : Theme.chat_msgOutViewsDrawable;
                        setDrawableBounds(viewsDrawable3, this.timeX, (this.layoutHeight - AndroidUtilities.dp(4.5f)) - this.timeLayout.getHeight());
                        viewsDrawable3.draw(canvas);
                    }
                    canvas.save();
                    if (!this.currentMessageObject.isOutOwner()) {
                        canvas.translate(this.timeX + Theme.chat_msgInViewsDrawable.getIntrinsicWidth() + AndroidUtilities.dp(3.0f), ((this.layoutHeight - AndroidUtilities.dp(6.5f)) - mOffset) - this.timeLayout.getHeight());
                    } else {
                        canvas.translate(this.timeX + Theme.chat_msgInViewsDrawable.getIntrinsicWidth() + AndroidUtilities.dp(3.0f), (this.layoutHeight - AndroidUtilities.dp(6.5f)) - this.timeLayout.getHeight());
                    }
                    this.viewsLayout.draw(canvas);
                    canvas.restore();
                }
            } else {
                isBroadcast = false;
            }
            canvas.save();
            if (this.currentMessageObject.type != 101 && this.currentMessageObject.type != 102 && this.currentMessageObject.type != 9) {
                canvas.translate(this.timeX + additionalX, (((this.layoutHeight - AndroidUtilities.dp(6.5f)) - mOffset) - this.timeLayout.getHeight()) - additionOffset);
            } else {
                Theme.chat_timePaint.setColor(-5197648);
                canvas.translate(this.timeX + additionalX, ((this.layoutHeight - AndroidUtilities.dp(6.5f)) - mOffset) - this.timeLayout.getHeight());
            }
            if (this.currentMessageObject.type != 105) {
                this.timeLayout.draw(canvas);
                canvas.restore();
            }
        } else {
            if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                paint = Theme.chat_actionBackgroundPaint;
            } else {
                Paint paint3 = Theme.chat_timeBackgroundPaint;
                paint = paint3;
            }
            int oldAlpha2 = paint.getAlpha();
            paint.setAlpha((int) (oldAlpha2 * this.timeAlpha));
            Theme.chat_timePaint.setAlpha((int) (this.timeAlpha * 255.0f));
            int x1 = this.timeX - AndroidUtilities.dp(4.0f);
            int y12 = this.layoutHeight - AndroidUtilities.dp(28.0f);
            if (this.currentMessageObject.type == 5) {
                y1 = y12;
            } else {
                y1 = y12 - mOffset;
            }
            this.rect.set(x1, y1, this.timeWidth + x1 + AndroidUtilities.dp((this.currentMessageObject.isOutOwner() ? 20 : 0) + 8), AndroidUtilities.dp(17.0f) + y1);
            if (this.currentMessageObject.type != 103 && this.currentMessageObject.type != 207) {
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), paint);
                oldAlpha = oldAlpha2;
                paint2 = paint;
                i2 = 0;
                i = MessageObject.TYPE_LIVE;
            } else if (this.currentMessageObject.type == 103) {
                float imageX = this.photoImage.getImageX();
                float imageY = this.photoImage.getImageY() + this.photoImage.getImageHeight() + AndroidUtilities.dp(10.0f);
                float fDp = this.timeWidth + x1 + AndroidUtilities.dp(this.currentMessageObject.isOutOwner() ? 18 : 0);
                float imageY2 = this.photoImage.getImageY() + this.photoImage.getImageHeight() + AndroidUtilities.dp(10.0f);
                oldAlpha = oldAlpha2;
                paint2 = paint;
                i2 = 0;
                i = MessageObject.TYPE_LIVE;
                canvas.drawLine(imageX, imageY, fDp, imageY2, paint2);
            } else {
                oldAlpha = oldAlpha2;
                paint2 = paint;
                i2 = 0;
                i = MessageObject.TYPE_LIVE;
                if (this.currentMessageObject.type == 207) {
                    canvas.drawLine(this.photoImage.getImageX(), this.photoImage.getImageY() + this.photoImage.getImageHeight() + AndroidUtilities.dp(10.0f), x1 + this.timeWidth + AndroidUtilities.dp(this.currentMessageObject.isOutOwner() ? 18 : 0), this.photoImage.getImageY() + this.photoImage.getImageHeight() + AndroidUtilities.dp(10.0f), paint2);
                }
            }
            paint2.setAlpha(oldAlpha);
            int additionalX2 = (int) (-this.timeLayout.getLineLeft(i2));
            if ((ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup) || (this.currentMessageObject.messageOwner.flags & 1024) != 0) {
                additionalX2 += (int) (this.timeWidth - this.timeLayout.getLineWidth(i2));
                if (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing()) {
                    if (!this.currentMessageObject.isOutOwner()) {
                        setDrawableBounds(Theme.chat_msgMediaClockDrawable, this.timeX + (this.currentMessageObject.scheduled ? 0 : AndroidUtilities.dp(11.0f)), (this.layoutHeight - AndroidUtilities.dp(14.0f)) - Theme.chat_msgMediaClockDrawable.getIntrinsicHeight());
                        Theme.chat_msgMediaClockDrawable.draw(canvas);
                    }
                } else if (this.currentMessageObject.isSendError()) {
                    if (!this.currentMessageObject.isOutOwner()) {
                        int x4 = this.timeX + (this.currentMessageObject.scheduled ? 0 : AndroidUtilities.dp(11.0f));
                        int y4 = this.layoutHeight - AndroidUtilities.dp(26.5f);
                        this.rect.set(x4, y4, x4 + AndroidUtilities.dp(14.0f), y4 + AndroidUtilities.dp(14.0f));
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), Theme.chat_msgErrorPaint);
                        setDrawableBounds(Theme.chat_msgErrorDrawable, AndroidUtilities.dp(6.0f) + x4, AndroidUtilities.dp(2.0f) + y4);
                        Theme.chat_msgErrorDrawable.draw(canvas);
                    }
                } else if (this.viewsLayout != null) {
                    if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                        viewsDrawable = Theme.chat_msgStickerViewsDrawable;
                    } else {
                        viewsDrawable = Theme.chat_msgMediaViewsDrawable;
                    }
                    int oldAlpha3 = ((BitmapDrawable) viewsDrawable).getPaint().getAlpha();
                    viewsDrawable.setAlpha((int) (this.timeAlpha * oldAlpha3));
                    if (this.currentMessageObject.type == 5) {
                        setDrawableBounds(viewsDrawable, this.timeX, (this.layoutHeight - AndroidUtilities.dp(10.5f)) - this.timeLayout.getHeight());
                    } else {
                        setDrawableBounds(viewsDrawable, this.timeX, ((this.layoutHeight - AndroidUtilities.dp(10.5f)) - mOffset) - this.timeLayout.getHeight());
                    }
                    viewsDrawable.draw(canvas);
                    viewsDrawable.setAlpha(oldAlpha3);
                    canvas.save();
                    if (this.currentMessageObject.type == 5) {
                        canvas.translate(this.timeX + viewsDrawable.getIntrinsicWidth() + AndroidUtilities.dp(3.0f), (this.layoutHeight - AndroidUtilities.dp(12.3f)) - this.timeLayout.getHeight());
                    } else {
                        canvas.translate(this.timeX + viewsDrawable.getIntrinsicWidth() + AndroidUtilities.dp(3.0f), ((this.layoutHeight - AndroidUtilities.dp(12.3f)) - mOffset) - this.timeLayout.getHeight());
                    }
                    this.viewsLayout.draw(canvas);
                    canvas.restore();
                }
            }
            if (this.currentMessageObject.type != 103 || this.currentMessageObject.type != 105) {
                canvas.save();
                if (this.currentMessageObject.type == 5) {
                    canvas.translate(this.timeX + additionalX2, (this.layoutHeight - AndroidUtilities.dp(12.3f)) - this.timeLayout.getHeight());
                } else if (this.currentMessageObject.type != i) {
                    canvas.translate(this.timeX + additionalX2, ((this.layoutHeight - AndroidUtilities.dp(12.3f)) - mOffset) - this.timeLayout.getHeight());
                } else {
                    Theme.chat_timePaint.setColor(Color.parseColor("#B3B3B3"));
                    canvas.translate(this.timeX + additionalX2, ((this.layoutHeight - AndroidUtilities.dp(12.3f)) - mOffset) - this.timeLayout.getHeight());
                }
                this.timeLayout.draw(canvas);
                canvas.restore();
            }
            Theme.chat_timePaint.setAlpha(255);
            isBroadcast = false;
        }
        if (this.currentMessageObject.isOutOwner()) {
            boolean drawCheck1 = false;
            boolean drawCheck2 = false;
            boolean drawClock = false;
            boolean drawError = false;
            if (((int) (this.currentMessageObject.getDialogId() >> 32)) == 1) {
                isBroadcast = true;
            }
            if (this.currentMessageObject.isSending() || this.currentMessageObject.isEditing()) {
                drawCheck1 = false;
                drawCheck2 = false;
                drawClock = true;
                drawError = false;
            } else if (this.currentMessageObject.isSendError()) {
                drawCheck1 = false;
                drawCheck2 = false;
                drawClock = false;
                drawError = true;
            } else if (this.currentMessageObject.isSent()) {
                if (!this.currentMessageObject.scheduled && !this.currentMessageObject.isUnread()) {
                    drawCheck1 = true;
                    drawCheck2 = true;
                } else {
                    drawCheck1 = false;
                    drawCheck2 = true;
                }
                drawClock = false;
                drawError = false;
            }
            if (drawClock) {
                if (this.mediaBackground && this.captionLayout == null) {
                    if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                        Theme.chat_msgStickerClockDrawable.setAlpha((int) (this.timeAlpha * 255.0f));
                        setDrawableBounds(Theme.chat_msgStickerClockDrawable, ((this.layoutWidth - AndroidUtilities.dp(22.0f)) - AndroidUtilities.dp(50.0f)) - Theme.chat_msgStickerClockDrawable.getIntrinsicWidth(), (this.layoutHeight - AndroidUtilities.dp(13.5f)) - Theme.chat_msgStickerClockDrawable.getIntrinsicHeight());
                        Theme.chat_msgStickerClockDrawable.draw(canvas);
                        Theme.chat_msgStickerClockDrawable.setAlpha(255);
                    } else {
                        setDrawableBounds(Theme.chat_msgMediaClockDrawable, (this.layoutWidth - AndroidUtilities.dp(70.0f)) - Theme.chat_msgMediaClockDrawable.getIntrinsicWidth(), ((this.layoutHeight - AndroidUtilities.dp(13.5f)) - mOffset) - Theme.chat_msgMediaClockDrawable.getIntrinsicHeight());
                        Theme.chat_msgMediaClockDrawable.draw(canvas);
                    }
                } else {
                    setDrawableBounds(Theme.chat_msgOutClockDrawable, ((this.layoutWidth - AndroidUtilities.dp(18.5f)) - AndroidUtilities.dp(50.0f)) - Theme.chat_msgOutClockDrawable.getIntrinsicWidth(), ((this.layoutHeight - AndroidUtilities.dp(8.5f)) - mOffset) - Theme.chat_msgOutClockDrawable.getIntrinsicHeight());
                    Theme.chat_msgOutClockDrawable.draw(canvas);
                }
            }
            if (isBroadcast) {
                if (drawCheck1 || drawCheck2) {
                    if (this.mediaBackground && this.captionLayout == null) {
                        setDrawableBounds(Theme.chat_msgBroadcastMediaDrawable, (this.layoutWidth - AndroidUtilities.dp(24.0f)) - Theme.chat_msgBroadcastMediaDrawable.getIntrinsicWidth(), (this.layoutHeight - AndroidUtilities.dp(14.0f)) - Theme.chat_msgBroadcastMediaDrawable.getIntrinsicHeight());
                        Theme.chat_msgBroadcastMediaDrawable.draw(canvas);
                    } else {
                        setDrawableBounds(Theme.chat_msgBroadcastDrawable, (this.layoutWidth - AndroidUtilities.dp(20.5f)) - Theme.chat_msgBroadcastDrawable.getIntrinsicWidth(), (this.layoutHeight - AndroidUtilities.dp(8.0f)) - Theme.chat_msgBroadcastDrawable.getIntrinsicHeight());
                        Theme.chat_msgBroadcastDrawable.draw(canvas);
                    }
                }
            } else {
                if (drawCheck2) {
                    if (this.mediaBackground && this.captionLayout == null) {
                        if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                            if (drawCheck1) {
                                setDrawableBounds(Theme.chat_msgStickerCheckDrawable, ((this.layoutWidth - AndroidUtilities.dp(26.3f)) - AndroidUtilities.dp(48.0f)) - Theme.chat_msgStickerCheckDrawable.getIntrinsicWidth(), (this.layoutHeight - AndroidUtilities.dp(13.5f)) - Theme.chat_msgStickerCheckDrawable.getIntrinsicHeight());
                            } else {
                                setDrawableBounds(Theme.chat_msgStickerCheckDrawable, ((this.layoutWidth - AndroidUtilities.dp(21.5f)) - AndroidUtilities.dp(48.0f)) - Theme.chat_msgStickerCheckDrawable.getIntrinsicWidth(), (this.layoutHeight - AndroidUtilities.dp(13.5f)) - Theme.chat_msgStickerCheckDrawable.getIntrinsicHeight());
                            }
                            Theme.chat_msgStickerCheckDrawable.draw(canvas);
                        } else {
                            if (this.currentMessageObject.type == i) {
                                drawable4 = isDrawSelectionBackground() ? Theme.chat_msgOutCheckReadGraySelectedDrawable : Theme.chat_msgOutCheckReadGrayDrawable;
                            } else {
                                drawable4 = Theme.chat_msgMediaCheckDrawable;
                            }
                            if (drawCheck1) {
                                setDrawableBounds(drawable4, ((this.layoutWidth - AndroidUtilities.dp(26.3f)) - AndroidUtilities.dp(48.0f)) - drawable4.getIntrinsicWidth(), ((this.layoutHeight - AndroidUtilities.dp(13.5f)) - mOffset) - drawable4.getIntrinsicHeight());
                            } else {
                                setDrawableBounds(drawable4, ((this.layoutWidth - AndroidUtilities.dp(21.5f)) - AndroidUtilities.dp(48.0f)) - drawable4.getIntrinsicWidth(), ((this.layoutHeight - AndroidUtilities.dp(13.5f)) - mOffset) - drawable4.getIntrinsicHeight());
                            }
                            drawable4.setAlpha((int) (this.timeAlpha * 255.0f));
                            drawable4.draw(canvas);
                            drawable4.setAlpha(255);
                        }
                    } else {
                        if (drawCheck1) {
                            if (this.currentMessageObject.type == 101 || this.currentMessageObject.type == 102 || this.currentMessageObject.type == 9) {
                                drawable3 = isDrawSelectionBackground() ? Theme.chat_msgOutCheckReadGraySelectedDrawable : Theme.chat_msgOutCheckReadGrayDrawable;
                            } else {
                                drawable3 = isDrawSelectionBackground() ? Theme.chat_msgOutCheckReadSelectedDrawable : Theme.chat_msgOutCheckReadDrawable;
                            }
                            setDrawableBounds(drawable3, ((this.layoutWidth - AndroidUtilities.dp(22.5f)) - AndroidUtilities.dp(48.0f)) - drawable3.getIntrinsicWidth(), (((this.layoutHeight - AndroidUtilities.dp(8.0f)) - mOffset) - drawable3.getIntrinsicHeight()) - additionOffset);
                        } else {
                            if (this.currentMessageObject.type == 101 || this.currentMessageObject.type == 102 || this.currentMessageObject.type == 9) {
                                drawable3 = isDrawSelectionBackground() ? Theme.chat_msgOutCheckGraySelectedDrawable : Theme.chat_msgOutCheckGrayDrawable;
                            } else {
                                drawable3 = isDrawSelectionBackground() ? Theme.chat_msgOutCheckSelectedDrawable : Theme.chat_msgOutCheckDrawable;
                            }
                            setDrawableBounds(drawable3, ((this.layoutWidth - AndroidUtilities.dp(18.5f)) - AndroidUtilities.dp(48.0f)) - drawable3.getIntrinsicWidth(), (((this.layoutHeight - AndroidUtilities.dp(8.0f)) - mOffset) - drawable3.getIntrinsicHeight()) - additionOffset);
                        }
                        drawable3.draw(canvas);
                    }
                }
                if (drawCheck1) {
                    if (this.mediaBackground && this.captionLayout == null) {
                        if (this.currentMessageObject.shouldDrawWithoutBackground()) {
                            setDrawableBounds(Theme.chat_msgStickerHalfCheckDrawable, ((this.layoutWidth - AndroidUtilities.dp(21.5f)) - AndroidUtilities.dp(48.0f)) - Theme.chat_msgStickerHalfCheckDrawable.getIntrinsicWidth(), (this.layoutHeight - AndroidUtilities.dp(13.5f)) - Theme.chat_msgStickerHalfCheckDrawable.getIntrinsicHeight());
                            Theme.chat_msgStickerHalfCheckDrawable.draw(canvas);
                        } else {
                            if (this.currentMessageObject.type == i) {
                                drawable2 = isDrawSelectionBackground() ? Theme.chat_msgOutHalfCheckSelectedDrawable : Theme.chat_msgOutHalfCheckDrawable;
                            } else {
                                drawable2 = Theme.chat_msgMediaHalfCheckDrawable;
                            }
                            setDrawableBounds(drawable2, ((this.layoutWidth - AndroidUtilities.dp(21.5f)) - AndroidUtilities.dp(48.0f)) - drawable2.getIntrinsicWidth(), ((this.layoutHeight - AndroidUtilities.dp(13.5f)) - mOffset) - drawable2.getIntrinsicHeight());
                            drawable2.setAlpha((int) (this.timeAlpha * 255.0f));
                            drawable2.draw(canvas);
                            drawable2.setAlpha(255);
                        }
                    } else {
                        if (this.currentMessageObject.type == 101 || this.currentMessageObject.type == 102 || this.currentMessageObject.type == 9) {
                            drawable = isDrawSelectionBackground() ? Theme.chat_msgOutHalfGrayCheckSelectedDrawable : Theme.chat_msgOutHalfGrayCheckDrawable;
                        } else {
                            drawable = isDrawSelectionBackground() ? Theme.chat_msgOutHalfCheckSelectedDrawable : Theme.chat_msgOutHalfCheckDrawable;
                        }
                        setDrawableBounds(drawable, ((this.layoutWidth - AndroidUtilities.dp(18.0f)) - AndroidUtilities.dp(48.0f)) - drawable.getIntrinsicWidth(), (((this.layoutHeight - AndroidUtilities.dp(8.0f)) - mOffset) - drawable.getIntrinsicHeight()) - additionOffset);
                        drawable.draw(canvas);
                    }
                }
            }
            if (drawError) {
                if (this.currentPosition != null) {
                    if (!this.mediaBackground || this.captionLayout != null) {
                        x2 = (AndroidUtilities.displaySize.x - this.currentMessagesGroup.getMaxSizeWidth()) - AndroidUtilities.dp(120.0f);
                        y2 = this.layoutHeight - AndroidUtilities.dp(21.0f);
                    } else {
                        x2 = (this.layoutWidth - this.currentMessagesGroup.getMaxSizeWidth()) - AndroidUtilities.dp(46.0f);
                        y2 = this.layoutHeight - AndroidUtilities.dp(26.5f);
                    }
                    int y5 = y2 - (mOffset * 2);
                    canvas.drawCircle(AndroidUtilities.dp(9.0f) + x2, AndroidUtilities.dp(9.0f) + y5, AndroidUtilities.dp(9.0f), Theme.chat_msgErrorPaint);
                    setDrawableBounds(Theme.chat_msgErrorDrawable, AndroidUtilities.dp(7.5f) + x2, AndroidUtilities.dp(3.0f) + y5);
                    Theme.chat_msgErrorDrawable.draw(canvas);
                    return;
                }
                if (this.mediaBackground && this.captionLayout == null) {
                    x = this.currentBackgroundDrawable.getBounds().left - AndroidUtilities.dp(23.0f);
                    y = this.layoutHeight - AndroidUtilities.dp(26.5f);
                } else {
                    x = this.currentBackgroundDrawable.getBounds().left - AndroidUtilities.dp(23.0f);
                    y = this.layoutHeight - AndroidUtilities.dp(21.0f);
                }
                int y6 = y - (mOffset + AndroidUtilities.dp(3.0f));
                canvas.drawCircle(AndroidUtilities.dp(9.0f) + x, AndroidUtilities.dp(9.0f) + y6, AndroidUtilities.dp(9.0f), Theme.chat_msgErrorPaint);
                setDrawableBounds(Theme.chat_msgErrorDrawable, AndroidUtilities.dp(7.5f) + x, AndroidUtilities.dp(3.0f) + y6);
                Theme.chat_msgErrorDrawable.draw(canvas);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:672:0x1655  */
    /* JADX WARN: Removed duplicated region for block: B:682:0x1677  */
    /* JADX WARN: Removed duplicated region for block: B:686:0x1685  */
    /* JADX WARN: Removed duplicated region for block: B:702:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void drawOverlays(android.graphics.Canvas r27) {
        /*
            Method dump skipped, instruction units count: 5828
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ChatMessageCell.drawOverlays(android.graphics.Canvas):void");
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public int getObserverTag() {
        return this.TAG;
    }

    public MessageObject getMessageObject() {
        MessageObject messageObject = this.messageObjectToSet;
        return messageObject != null ? messageObject : this.currentMessageObject;
    }

    public TLRPC.Document getStreamingMedia() {
        int i = this.documentAttachType;
        if (i == 4 || i == 7 || i == 2) {
            return this.documentAttach;
        }
        return null;
    }

    public boolean isPinnedBottom() {
        return this.pinnedBottom;
    }

    public boolean isPinnedTop() {
        return this.pinnedTop;
    }

    public MessageObject.GroupedMessages getCurrentMessagesGroup() {
        return this.currentMessagesGroup;
    }

    public MessageObject.GroupedMessagePosition getCurrentPosition() {
        return this.currentPosition;
    }

    public int getLayoutHeight() {
        return this.layoutHeight;
    }

    @Override // android.view.View
    public boolean performAccessibilityAction(int action, Bundle arguments) {
        if (action == 16) {
            int icon = getIconForCurrentState();
            if (icon != 4) {
                didPressButton(true, false);
            } else if (this.currentMessageObject.type == 16) {
                this.delegate.didPressOther(this, this.otherX, this.otherY);
            } else {
                didClickedImage();
            }
            return true;
        }
        if (action == mpEIGo.juqQQs.esbSDO.R.attr.acc_action_small_button) {
            didPressMiniButton(true);
        } else if (action == mpEIGo.juqQQs.esbSDO.R.attr.acc_action_msg_options && this.delegate != null) {
            if (this.currentMessageObject.type == 16) {
                this.delegate.didLongPress(this, 0.0f, 0.0f);
            } else {
                this.delegate.didPressOther(this, this.otherX, this.otherY);
            }
        }
        return super.performAccessibilityAction(action, arguments);
    }

    @Override // android.view.View
    public boolean onHoverEvent(MotionEvent event) {
        int x = (int) event.getX();
        int y = (int) event.getY();
        if (event.getAction() == 9 || event.getAction() == 7) {
            for (int i = 0; i < this.accessibilityVirtualViewBounds.size(); i++) {
                Rect rect = this.accessibilityVirtualViewBounds.valueAt(i);
                if (rect.contains(x, y)) {
                    int id = this.accessibilityVirtualViewBounds.keyAt(i);
                    if (id != this.currentFocusedVirtualView) {
                        this.currentFocusedVirtualView = id;
                        sendAccessibilityEventForVirtualView(id, 32768);
                        return true;
                    }
                    return true;
                }
            }
        } else if (event.getAction() == 10) {
            this.currentFocusedVirtualView = 0;
        }
        return super.onHoverEvent(event);
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
    }

    @Override // android.view.View
    public AccessibilityNodeProvider getAccessibilityNodeProvider() {
        return new MessageAccessibilityNodeProvider();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendAccessibilityEventForVirtualView(int viewId, int eventType) {
        AccessibilityManager am = (AccessibilityManager) getContext().getSystemService("accessibility");
        if (am.isTouchExplorationEnabled()) {
            AccessibilityEvent event = AccessibilityEvent.obtain(eventType);
            event.setPackageName(getContext().getPackageName());
            event.setSource(this, viewId);
            getParent().requestSendAccessibilityEvent(this, event);
        }
    }

    private class MessageAccessibilityNodeProvider extends AccessibilityNodeProvider {
        private final int BOT_BUTTONS_START;
        private final int INSTANT_VIEW;
        private final int LINK_IDS_START;
        private final int POLL_BUTTONS_START;
        private final int REPLY;
        private final int SHARE;
        private Path linkPath;
        private Rect rect;
        private RectF rectF;

        private MessageAccessibilityNodeProvider() {
            this.LINK_IDS_START = 2000;
            this.BOT_BUTTONS_START = 1000;
            this.POLL_BUTTONS_START = SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION;
            this.INSTANT_VIEW = 499;
            this.SHARE = 498;
            this.REPLY = 497;
            this.linkPath = new Path();
            this.rectF = new RectF();
            this.rect = new Rect();
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public AccessibilityNodeInfo createAccessibilityNodeInfo(int virtualViewId) {
            boolean z;
            AccessibilityNodeInfo.CollectionItemInfo itemInfo;
            int i;
            String str;
            int[] pos = {0, 0};
            ChatMessageCell.this.getLocationOnScreen(pos);
            if (virtualViewId == -1) {
                AccessibilityNodeInfo info = AccessibilityNodeInfo.obtain(ChatMessageCell.this);
                ChatMessageCell.this.onInitializeAccessibilityNodeInfo(info);
                StringBuilder sb = new StringBuilder();
                if (ChatMessageCell.this.isChat && ChatMessageCell.this.currentUser != null && !ChatMessageCell.this.currentMessageObject.isOut()) {
                    sb.append(UserObject.getName(ChatMessageCell.this.currentUser));
                    sb.append('\n');
                }
                if (!TextUtils.isEmpty(ChatMessageCell.this.currentMessageObject.messageText)) {
                    sb.append(ChatMessageCell.this.currentMessageObject.messageText);
                }
                if (!ChatMessageCell.this.currentMessageObject.isMusic()) {
                    if (ChatMessageCell.this.currentMessageObject.isVoice() || ChatMessageCell.this.currentMessageObject.isRoundVideo()) {
                        sb.append(", ");
                        sb.append(LocaleController.formatCallDuration(ChatMessageCell.this.currentMessageObject.getDuration()));
                        if (ChatMessageCell.this.currentMessageObject.isContentUnread()) {
                            sb.append(", ");
                            sb.append(LocaleController.getString("AccDescrMsgNotPlayed", mpEIGo.juqQQs.esbSDO.R.string.AccDescrMsgNotPlayed));
                        }
                    }
                } else {
                    sb.append(ShellAdbUtils.COMMAND_LINE_END);
                    sb.append(LocaleController.formatString("AccDescrMusicInfo", mpEIGo.juqQQs.esbSDO.R.string.AccDescrMusicInfo, ChatMessageCell.this.currentMessageObject.getMusicAuthor(), ChatMessageCell.this.currentMessageObject.getMusicTitle()));
                }
                if (ChatMessageCell.this.lastPoll != null) {
                    sb.append(", ");
                    sb.append(ChatMessageCell.this.lastPoll.question);
                    sb.append(", ");
                    sb.append(LocaleController.getString("AnonymousPoll", mpEIGo.juqQQs.esbSDO.R.string.AnonymousPoll));
                }
                if (ChatMessageCell.this.currentMessageObject.messageOwner.media != null && !TextUtils.isEmpty(ChatMessageCell.this.currentMessageObject.caption)) {
                    sb.append(ShellAdbUtils.COMMAND_LINE_END);
                    sb.append(ChatMessageCell.this.currentMessageObject.caption);
                }
                sb.append(ShellAdbUtils.COMMAND_LINE_END);
                CharSequence time = LocaleController.getString("TodayAt", mpEIGo.juqQQs.esbSDO.R.string.TodayAt) + " " + ChatMessageCell.this.currentTimeString;
                if (ChatMessageCell.this.currentMessageObject.isOut()) {
                    sb.append(LocaleController.formatString("AccDescrSentDate", mpEIGo.juqQQs.esbSDO.R.string.AccDescrSentDate, time));
                    sb.append(", ");
                    if (ChatMessageCell.this.currentMessageObject.isUnread()) {
                        i = mpEIGo.juqQQs.esbSDO.R.string.AccDescrMsgUnread;
                        str = "AccDescrMsgUnread";
                    } else {
                        i = mpEIGo.juqQQs.esbSDO.R.string.AccDescrMsgRead;
                        str = "AccDescrMsgRead";
                    }
                    sb.append(LocaleController.getString(str, i));
                } else {
                    sb.append(LocaleController.formatString("AccDescrReceivedDate", mpEIGo.juqQQs.esbSDO.R.string.AccDescrReceivedDate, time));
                }
                info.setContentDescription(sb.toString());
                info.setEnabled(true);
                if (Build.VERSION.SDK_INT >= 19 && (itemInfo = info.getCollectionItemInfo()) != null) {
                    info.setCollectionItemInfo(AccessibilityNodeInfo.CollectionItemInfo.obtain(itemInfo.getRowIndex(), 1, 0, 1, false));
                }
                if (Build.VERSION.SDK_INT >= 21) {
                    info.addAction(new AccessibilityNodeInfo.AccessibilityAction(mpEIGo.juqQQs.esbSDO.R.attr.acc_action_msg_options, LocaleController.getString("AccActionMessageOptions", mpEIGo.juqQQs.esbSDO.R.string.AccActionMessageOptions)));
                    int icon = ChatMessageCell.this.getIconForCurrentState();
                    CharSequence actionLabel = null;
                    if (icon == 0) {
                        actionLabel = LocaleController.getString("AccActionPlay", mpEIGo.juqQQs.esbSDO.R.string.AccActionPlay);
                    } else if (icon == 1) {
                        actionLabel = LocaleController.getString("AccActionPause", mpEIGo.juqQQs.esbSDO.R.string.AccActionPause);
                    } else if (icon == 2) {
                        actionLabel = LocaleController.getString("AccActionDownload", mpEIGo.juqQQs.esbSDO.R.string.AccActionDownload);
                    } else if (icon == 3) {
                        actionLabel = LocaleController.getString("AccActionCancelDownload", mpEIGo.juqQQs.esbSDO.R.string.AccActionCancelDownload);
                    } else if (icon != 5) {
                        if (ChatMessageCell.this.currentMessageObject.type == 16) {
                            actionLabel = LocaleController.getString("CallAgain", mpEIGo.juqQQs.esbSDO.R.string.CallAgain);
                        }
                    } else {
                        actionLabel = LocaleController.getString("AccActionOpenFile", mpEIGo.juqQQs.esbSDO.R.string.AccActionOpenFile);
                    }
                    info.addAction(new AccessibilityNodeInfo.AccessibilityAction(16, actionLabel));
                    info.addAction(new AccessibilityNodeInfo.AccessibilityAction(32, LocaleController.getString("AccActionEnterSelectionMode", mpEIGo.juqQQs.esbSDO.R.string.AccActionEnterSelectionMode)));
                    int smallIcon = ChatMessageCell.this.getMiniIconForCurrentState();
                    if (smallIcon == 2) {
                        info.addAction(new AccessibilityNodeInfo.AccessibilityAction(mpEIGo.juqQQs.esbSDO.R.attr.acc_action_small_button, LocaleController.getString("AccActionDownload", mpEIGo.juqQQs.esbSDO.R.string.AccActionDownload)));
                    }
                } else {
                    info.addAction(16);
                    info.addAction(32);
                }
                if (ChatMessageCell.this.currentMessageObject.messageText instanceof Spannable) {
                    Spannable buffer = (Spannable) ChatMessageCell.this.currentMessageObject.messageText;
                    CharacterStyle[] links = (CharacterStyle[]) buffer.getSpans(0, buffer.length(), ClickableSpan.class);
                    int i2 = 0;
                    for (CharacterStyle characterStyle : links) {
                        info.addChild(ChatMessageCell.this, i2 + 2000);
                        i2++;
                    }
                }
                int i3 = 0;
                for (BotButton botButton : ChatMessageCell.this.botButtons) {
                    info.addChild(ChatMessageCell.this, i3 + 1000);
                    i3++;
                }
                int i4 = 0;
                for (PollButton pollButton : ChatMessageCell.this.pollButtons) {
                    info.addChild(ChatMessageCell.this, i4 + SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    i4++;
                }
                if (ChatMessageCell.this.drawInstantView) {
                    info.addChild(ChatMessageCell.this, 499);
                }
                if (ChatMessageCell.this.drawShareButton) {
                    info.addChild(ChatMessageCell.this, 498);
                }
                if (ChatMessageCell.this.replyNameLayout != null) {
                    info.addChild(ChatMessageCell.this, 497);
                }
                if (ChatMessageCell.this.drawSelectionBackground || ChatMessageCell.this.getBackground() != null) {
                    info.setSelected(true);
                }
                return info;
            }
            AccessibilityNodeInfo info2 = AccessibilityNodeInfo.obtain();
            info2.setSource(ChatMessageCell.this, virtualViewId);
            info2.setParent(ChatMessageCell.this);
            info2.setPackageName(ChatMessageCell.this.getContext().getPackageName());
            if (virtualViewId >= 2000) {
                Spannable buffer2 = (Spannable) ChatMessageCell.this.currentMessageObject.messageText;
                ClickableSpan link = getLinkById(virtualViewId);
                if (link == null) {
                    return null;
                }
                int[] linkPos = ChatMessageCell.this.getRealSpanStartAndEnd(buffer2, link);
                String content = buffer2.subSequence(linkPos[0], linkPos[1]).toString();
                info2.setText(content);
                Iterator<MessageObject.TextLayoutBlock> it = ChatMessageCell.this.currentMessageObject.textLayoutBlocks.iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    MessageObject.TextLayoutBlock block = it.next();
                    int length = block.textLayout.getText().length();
                    if (block.charactersOffset <= linkPos[0] && block.charactersOffset + length >= linkPos[1]) {
                        block.textLayout.getSelectionPath(linkPos[0] - block.charactersOffset, linkPos[1] - block.charactersOffset, this.linkPath);
                        this.linkPath.computeBounds(this.rectF, true);
                        this.rect.set((int) this.rectF.left, (int) this.rectF.top, (int) this.rectF.right, (int) this.rectF.bottom);
                        this.rect.offset(0, (int) block.textYOffset);
                        this.rect.offset(ChatMessageCell.this.textX, ChatMessageCell.this.textY);
                        info2.setBoundsInParent(this.rect);
                        if (ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId) == null) {
                            ChatMessageCell.this.accessibilityVirtualViewBounds.put(virtualViewId, new Rect(this.rect));
                        }
                        this.rect.offset(pos[0], pos[1]);
                        info2.setBoundsInScreen(this.rect);
                    }
                }
                info2.setClassName("android.widget.TextView");
                info2.setEnabled(true);
                info2.setClickable(true);
                info2.setLongClickable(true);
                info2.addAction(16);
                info2.addAction(32);
                z = true;
            } else if (virtualViewId >= 1000) {
                int buttonIndex = virtualViewId - 1000;
                if (buttonIndex >= ChatMessageCell.this.botButtons.size()) {
                    return null;
                }
                BotButton button = (BotButton) ChatMessageCell.this.botButtons.get(buttonIndex);
                info2.setText(button.title.getText());
                info2.setClassName("android.widget.Button");
                info2.setEnabled(true);
                info2.setClickable(true);
                info2.addAction(16);
                this.rect.set(button.x, button.y, button.x + button.width, button.y + button.height);
                this.rect.offset(ChatMessageCell.this.currentMessageObject.isOutOwner() ? (ChatMessageCell.this.getMeasuredWidth() - ChatMessageCell.this.widthForButtons) - AndroidUtilities.dp(10.0f) : AndroidUtilities.dp(ChatMessageCell.this.mediaBackground ? 1.0f : 7.0f) + ChatMessageCell.this.backgroundDrawableLeft, ChatMessageCell.this.layoutHeight);
                info2.setBoundsInParent(this.rect);
                if (ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId) == null) {
                    ChatMessageCell.this.accessibilityVirtualViewBounds.put(virtualViewId, new Rect(this.rect));
                }
                this.rect.offset(pos[0], pos[1]);
                info2.setBoundsInScreen(this.rect);
                z = true;
            } else if (virtualViewId >= 500) {
                int buttonIndex2 = virtualViewId - 500;
                if (buttonIndex2 >= ChatMessageCell.this.pollButtons.size()) {
                    return null;
                }
                PollButton button2 = (PollButton) ChatMessageCell.this.pollButtons.get(buttonIndex2);
                info2.setText(button2.title.getText());
                if (ChatMessageCell.this.pollVoted) {
                    info2.setText(((Object) info2.getText()) + ", " + button2.percent + "%");
                } else {
                    info2.setClassName("android.widget.Button");
                }
                info2.setEnabled(true);
                info2.addAction(16);
                int width = ChatMessageCell.this.backgroundWidth - AndroidUtilities.dp(76.0f);
                this.rect.set(button2.x, button2.y, button2.x + width, button2.y + button2.height);
                info2.setBoundsInParent(this.rect);
                if (ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId) == null) {
                    ChatMessageCell.this.accessibilityVirtualViewBounds.put(virtualViewId, new Rect(this.rect));
                }
                this.rect.offset(pos[0], pos[1]);
                info2.setBoundsInScreen(this.rect);
                info2.setClickable(true);
                z = true;
            } else if (virtualViewId == 499) {
                info2.setClassName("android.widget.Button");
                info2.setEnabled(true);
                if (ChatMessageCell.this.instantViewLayout != null) {
                    info2.setText(ChatMessageCell.this.instantViewLayout.getText());
                }
                info2.addAction(16);
                int textX = ChatMessageCell.this.photoImage.getImageX();
                int instantY = ChatMessageCell.this.getMeasuredHeight() - AndroidUtilities.dp(64.0f);
                int addX = ChatMessageCell.this.currentMessageObject.isOutOwner() ? (ChatMessageCell.this.getMeasuredWidth() - ChatMessageCell.this.widthForButtons) - AndroidUtilities.dp(10.0f) : AndroidUtilities.dp(ChatMessageCell.this.mediaBackground ? 1.0f : 7.0f) + ChatMessageCell.this.backgroundDrawableLeft;
                this.rect.set(textX + addX, instantY, ChatMessageCell.this.instantWidth + textX + addX, AndroidUtilities.dp(38.0f) + instantY);
                info2.setBoundsInParent(this.rect);
                if (ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId) == null || !((Rect) ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId)).equals(this.rect)) {
                    ChatMessageCell.this.accessibilityVirtualViewBounds.put(virtualViewId, new Rect(this.rect));
                }
                this.rect.offset(pos[0], pos[1]);
                info2.setBoundsInScreen(this.rect);
                info2.setClickable(true);
                z = true;
            } else if (virtualViewId == 498) {
                info2.setClassName("android.widget.ImageButton");
                info2.setEnabled(true);
                ChatMessageCell chatMessageCell = ChatMessageCell.this;
                if (chatMessageCell.isOpenChatByShare(chatMessageCell.currentMessageObject)) {
                    info2.setContentDescription(LocaleController.getString("AccDescrOpenChat", mpEIGo.juqQQs.esbSDO.R.string.AccDescrOpenChat));
                } else {
                    info2.setContentDescription(LocaleController.getString("ShareFile", mpEIGo.juqQQs.esbSDO.R.string.ShareFile));
                }
                info2.addAction(16);
                this.rect.set(ChatMessageCell.this.shareStartX, ChatMessageCell.this.shareStartY, ChatMessageCell.this.shareStartX + AndroidUtilities.dp(40.0f), ChatMessageCell.this.shareStartY + AndroidUtilities.dp(32.0f));
                info2.setBoundsInParent(this.rect);
                if (ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId) == null || !((Rect) ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId)).equals(this.rect)) {
                    ChatMessageCell.this.accessibilityVirtualViewBounds.put(virtualViewId, new Rect(this.rect));
                }
                this.rect.offset(pos[0], pos[1]);
                info2.setBoundsInScreen(this.rect);
                info2.setClickable(true);
                z = true;
            } else if (virtualViewId != 497) {
                z = true;
            } else {
                info2.setEnabled(true);
                StringBuilder sb2 = new StringBuilder();
                sb2.append(LocaleController.getString("Reply", mpEIGo.juqQQs.esbSDO.R.string.Reply));
                sb2.append(", ");
                if (ChatMessageCell.this.replyNameLayout != null) {
                    sb2.append(ChatMessageCell.this.replyNameLayout.getText());
                    sb2.append(", ");
                }
                if (ChatMessageCell.this.replyTextLayout != null) {
                    sb2.append(ChatMessageCell.this.replyTextLayout.getText());
                }
                info2.setContentDescription(sb2.toString());
                info2.addAction(16);
                this.rect.set(ChatMessageCell.this.replyStartX, ChatMessageCell.this.replyStartY, ChatMessageCell.this.replyStartX + Math.max(ChatMessageCell.this.replyNameWidth, ChatMessageCell.this.replyTextWidth), ChatMessageCell.this.replyStartY + AndroidUtilities.dp(35.0f));
                info2.setBoundsInParent(this.rect);
                if (ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId) == null || !((Rect) ChatMessageCell.this.accessibilityVirtualViewBounds.get(virtualViewId)).equals(this.rect)) {
                    ChatMessageCell.this.accessibilityVirtualViewBounds.put(virtualViewId, new Rect(this.rect));
                }
                z = true;
                this.rect.offset(pos[0], pos[1]);
                info2.setBoundsInScreen(this.rect);
                info2.setClickable(true);
            }
            info2.setFocusable(z);
            info2.setVisibleToUser(z);
            return info2;
        }

        @Override // android.view.accessibility.AccessibilityNodeProvider
        public boolean performAction(int virtualViewId, int action, Bundle arguments) {
            ClickableSpan link;
            if (virtualViewId == -1) {
                ChatMessageCell.this.performAccessibilityAction(action, arguments);
            } else if (action == 64) {
                ChatMessageCell.this.sendAccessibilityEventForVirtualView(virtualViewId, 32768);
            } else if (action == 16) {
                if (virtualViewId >= 2000) {
                    ClickableSpan link2 = getLinkById(virtualViewId);
                    if (link2 != null) {
                        ChatMessageCell.this.delegate.didPressUrl(ChatMessageCell.this, link2, false);
                        ChatMessageCell.this.sendAccessibilityEventForVirtualView(virtualViewId, 1);
                    }
                } else if (virtualViewId >= 1000) {
                    int buttonIndex = virtualViewId - 1000;
                    if (buttonIndex >= ChatMessageCell.this.botButtons.size()) {
                        return false;
                    }
                    BotButton button = (BotButton) ChatMessageCell.this.botButtons.get(buttonIndex);
                    if (ChatMessageCell.this.delegate != null) {
                        if (button.button != null) {
                            ChatMessageCell.this.delegate.didPressBotButton(ChatMessageCell.this, button.button);
                        } else if (button.reaction != null) {
                            ChatMessageCell.this.delegate.didPressReaction(ChatMessageCell.this, button.reaction);
                        }
                    }
                    ChatMessageCell.this.sendAccessibilityEventForVirtualView(virtualViewId, 1);
                } else if (virtualViewId >= 500) {
                    int buttonIndex2 = virtualViewId - 500;
                    if (buttonIndex2 >= ChatMessageCell.this.pollButtons.size()) {
                        return false;
                    }
                    PollButton button2 = (PollButton) ChatMessageCell.this.pollButtons.get(buttonIndex2);
                    if (ChatMessageCell.this.delegate != null) {
                        ChatMessageCell.this.delegate.didPressVoteButton(ChatMessageCell.this, button2.answer);
                    }
                    ChatMessageCell.this.sendAccessibilityEventForVirtualView(virtualViewId, 1);
                } else if (virtualViewId == 499) {
                    if (ChatMessageCell.this.delegate != null) {
                        ChatMessageCellDelegate chatMessageCellDelegate = ChatMessageCell.this.delegate;
                        ChatMessageCell chatMessageCell = ChatMessageCell.this;
                        chatMessageCellDelegate.didPressInstantButton(chatMessageCell, chatMessageCell.drawInstantViewType);
                    }
                } else if (virtualViewId == 498) {
                    if (ChatMessageCell.this.delegate != null) {
                        ChatMessageCell.this.delegate.didPressShare(ChatMessageCell.this);
                    }
                } else if (virtualViewId == 497 && ChatMessageCell.this.delegate != null) {
                    ChatMessageCellDelegate chatMessageCellDelegate2 = ChatMessageCell.this.delegate;
                    ChatMessageCell chatMessageCell2 = ChatMessageCell.this;
                    chatMessageCellDelegate2.didPressReplyMessage(chatMessageCell2, chatMessageCell2.currentMessageObject.messageOwner.reply_to_msg_id);
                }
            } else if (action == 32 && (link = getLinkById(virtualViewId)) != null) {
                ChatMessageCell.this.delegate.didPressUrl(ChatMessageCell.this, link, true);
                ChatMessageCell.this.sendAccessibilityEventForVirtualView(virtualViewId, 2);
            }
            return true;
        }

        private ClickableSpan getLinkById(int id) {
            int id2 = id - 2000;
            if (!(ChatMessageCell.this.currentMessageObject.messageText instanceof Spannable)) {
                return null;
            }
            Spannable buffer = (Spannable) ChatMessageCell.this.currentMessageObject.messageText;
            ClickableSpan[] links = (ClickableSpan[]) buffer.getSpans(0, buffer.length(), ClickableSpan.class);
            if (links.length <= id2) {
                return null;
            }
            return links[id2];
        }
    }

    private void setTransValues() {
    }

    private String getLiveState(int iState) {
        switch (iState) {
        }
        return "直播中";
    }

    private class MyTypeEvaluator implements TypeEvaluator {
        private MyTypeEvaluator() {
        }

        @Override // android.animation.TypeEvaluator
        public Object evaluate(float fraction, Object startValue, Object endValue) {
            return null;
        }
    }
}
