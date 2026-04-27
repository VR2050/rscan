package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.DatePickerDialog;
import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.media.ThumbnailUtils;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.text.Layout;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.CharacterStyle;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.URLSpan;
import android.util.Base64;
import android.util.Log;
import android.util.LongSparseArray;
import android.util.Property;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MotionEvent;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.ViewTreeObserver;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.DecelerateInterpolator;
import android.webkit.URLUtil;
import android.widget.DatePicker;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.core.content.FileProvider;
import androidx.core.net.MailTo;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.GridLayoutManagerFixed;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSmoothScrollerMiddle;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.ResponseAccessTokenBean;
import com.bjz.comm.net.bean.ResponseBaiduTranslateBean;
import com.bjz.comm.net.factory.ApiTranslateAudioFactory;
import com.bjz.comm.net.utils.RxHelper;
import com.blankj.utilcode.util.GsonUtils;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.ui.AspectRatioFrameLayout;
import com.google.gson.Gson;
import com.just.agentweb.DefaultWebClient;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.javaBean.ChatFCAttentionBean;
import im.uwrkaxlmjj.javaBean.hongbao.RedTransOperation;
import im.uwrkaxlmjj.javaBean.hongbao.UnifyBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.sqlite.SQLiteException;
import im.uwrkaxlmjj.sqlite.SQLitePreparedStatement;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.ParamsUtil;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.AudioSelectActivity;
import im.uwrkaxlmjj.ui.ContentPreviewViewer;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.DocumentSelectActivity;
import im.uwrkaxlmjj.ui.PhoneBookSelectActivity;
import im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.PollCreateActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarLayout;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.ChatActionBarMenuPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.ChatActionBarMenuSubItem;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.adapters.MentionsAdapter;
import im.uwrkaxlmjj.ui.adapters.StickersAdapter;
import im.uwrkaxlmjj.ui.cells.BotHelpCell;
import im.uwrkaxlmjj.ui.cells.BotSwitchCell;
import im.uwrkaxlmjj.ui.cells.ChatActionCell;
import im.uwrkaxlmjj.ui.cells.ChatLoadingCell;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import im.uwrkaxlmjj.ui.cells.ChatUnreadCell;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.ContextLinkCell;
import im.uwrkaxlmjj.ui.cells.MentionCell;
import im.uwrkaxlmjj.ui.cells.StickerCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AnimatedFileDrawable;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ChatActivityEnterView;
import im.uwrkaxlmjj.ui.components.ChatAttachAlert;
import im.uwrkaxlmjj.ui.components.ChatAvatarContainer;
import im.uwrkaxlmjj.ui.components.ChatBigEmptyView;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.CorrectlyMeasuringTextView;
import im.uwrkaxlmjj.ui.components.EditTextCaption;
import im.uwrkaxlmjj.ui.components.EmbedBottomSheet;
import im.uwrkaxlmjj.ui.components.EmojiView;
import im.uwrkaxlmjj.ui.components.EnterMenuView;
import im.uwrkaxlmjj.ui.components.ExtendedGridLayoutManager;
import im.uwrkaxlmjj.ui.components.FragmentContextView;
import im.uwrkaxlmjj.ui.components.HintView;
import im.uwrkaxlmjj.ui.components.InstantCameraView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberTextView;
import im.uwrkaxlmjj.ui.components.PipRoundVideoView;
import im.uwrkaxlmjj.ui.components.RLottieDrawable;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.ShareAlert;
import im.uwrkaxlmjj.ui.components.Size;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;
import im.uwrkaxlmjj.ui.components.TypefaceSpan;
import im.uwrkaxlmjj.ui.components.URLSpanBotCommand;
import im.uwrkaxlmjj.ui.components.URLSpanMono;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import im.uwrkaxlmjj.ui.components.URLSpanReplacement;
import im.uwrkaxlmjj.ui.components.URLSpanUserMention;
import im.uwrkaxlmjj.ui.components.UndoView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import im.uwrkaxlmjj.ui.constants.ChatEnterMenuType;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.hui.CameraViewActivity;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.contacts.AddContactsInfoActivity;
import im.uwrkaxlmjj.ui.hui.discovery.QrScanResultActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageDetailActivity;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.packet.BillDetailsActivity;
import im.uwrkaxlmjj.ui.hui.packet.RedpktDetailActivity;
import im.uwrkaxlmjj.ui.hui.packet.RedpktDetailReceiverActivity;
import im.uwrkaxlmjj.ui.hui.packet.RedpktGroupDetailActivity;
import im.uwrkaxlmjj.ui.hui.packet.RedpktGroupSendActivity;
import im.uwrkaxlmjj.ui.hui.packet.RedpktSendActivity;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketBean;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketResponse;
import im.uwrkaxlmjj.ui.hui.packet.pop.DialogRedpkg;
import im.uwrkaxlmjj.ui.hui.packet.pop.OnRedPacketDialogClickListener;
import im.uwrkaxlmjj.ui.hui.packet.pop.RedPacketViewHolder;
import im.uwrkaxlmjj.ui.hui.transfer.TransferSendActivity;
import im.uwrkaxlmjj.ui.hui.transfer.TransferStatusActivity;
import im.uwrkaxlmjj.ui.hui.transfer.bean.TransferResponse;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import im.uwrkaxlmjj.ui.utils.ChatActionBarHelper;
import im.uwrkaxlmjj.ui.utils.QrCodeParseUtil;
import im.uwrkaxlmjj.ui.utils.number.MoneyUtil;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import im.uwrkaxlmjj.ui.utils.number.StringUtils;
import im.uwrkaxlmjj.ui.utils.translate.DecodeEngine;
import im.uwrkaxlmjj.ui.utils.translate.callback.DecodeOperateInterface;
import im.uwrkaxlmjj.ui.utils.translate.common.AudioEditConstant;
import im.uwrkaxlmjj.ui.utils.translate.utils.AudioFileUtils;
import im.uwrkaxlmjj.ui.wallet.WalletActivity;
import im.uwrkaxlmjj.ui.wallet.WalletPaymentPasswordActivity;
import io.reactivex.Observable;
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import io.reactivex.schedulers.Schedulers;
import java.io.File;
import java.math.BigDecimal;
import java.net.FileNameMap;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import mpEIGo.juqQQs.esbSDO.R;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class ChatActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, DialogsActivity.DialogsActivityDelegate {
    private static final String PREFIX_VIDEO = "video/";
    private static final int add_shortcut = 24;
    private static final int attach_audio = 3;
    private static final int attach_contact = 5;
    private static final int attach_document = 4;
    private static final int attach_gallery = 1;
    private static final int attach_group_live = 1012;
    private static final int attach_location = 6;
    private static final int attach_photo = 0;
    private static final int attach_poll = 9;
    private static final int attach_video = 2;
    private static final int attach_video_call = 1011;
    private static final int attach_voice_call = 1010;
    private static final int bot_help = 30;
    private static final int bot_settings = 31;
    private static final int call = 32;
    private static final int chat_enc_timer = 13;
    private static final int chat_menu_attach = 14;
    private static final int clear_history = 15;
    private static final int copy = 10;
    private static final int delete = 12;
    private static final int delete_chat = 16;
    private static final int edit = 23;
    private static final int forward = 11;
    private static final int id_chat_compose_panel = 1000;
    private static final int live = 33;
    private static final int more = 0;
    private static final int mute = 18;
    private static final int report = 21;
    private static final int search = 40;
    private static final int share_contact = 17;
    private static final int star = 22;
    private static final int text_bold = 50;
    private static final int text_italic = 51;
    private static final int text_link = 53;
    private static final int text_mono = 52;
    private static final int text_regular = 54;
    private static final int text_strike = 55;
    private static final int text_underline = 56;
    private String TAG;
    private ChatActionBarHelper actionBarHelper;
    private ArrayList<View> actionModeViews;
    private ChatActionBarMenuSubItem addContactItem;
    private TextView addToContactsButton;
    private TextView alertNameTextView;
    private TextView alertTextView;
    private FrameLayout alertView;
    private AnimatorSet alertViewAnimator;
    private boolean allowContextBotPanel;
    private boolean allowContextBotPanelSecond;
    private boolean allowStickersPanel;
    private HashMap<MessageObject, Boolean> alredyPlayedStickers;
    private ArrayList<MessageObject> animatingMessageObjects;
    private Paint aspectPaint;
    private Path aspectPath;
    private AspectRatioFrameLayout aspectRatioFrameLayout;
    private ActionBarMenuItem attachItem;
    private ChatAvatarContainer avatarContainer;
    private ChatBigEmptyView bigEmptyView;
    private MessageObject botButtons;
    private PhotoViewer.PhotoViewerProvider botContextProvider;
    private ArrayList<Object> botContextResults;
    private SparseArray<TLRPC.BotInfo> botInfo;
    private MessageObject botReplyButtons;
    private String botUser;
    private int botsCount;
    private FrameLayout bottomMessagesActionContainer;
    private FrameLayout bottomOverlay;
    private AnimatorSet bottomOverlayAnimation;
    private FrameLayout bottomOverlayChat;
    private TextView bottomOverlayChatText;
    private UnreadCounterTextView bottomOverlayChatText2;
    private RadialProgressView bottomOverlayProgress;
    private TextView bottomOverlayText;
    private boolean[] cacheEndReached;
    private ActionBarMenuItem callItem;
    private int canEditMessagesCount;
    private int canForwardMessagesCount;
    private int cantCopyMessageCount;
    private int cantDeleteMessagesCount;
    private int cantForwardMessagesCount;
    private ChatActionBarMenuPopupWindow chatActionBarMenuPop;
    private ChatActivityDelegate chatActivityDelegate;
    public ChatActivityEnterView chatActivityEnterView;
    private ChatActivityAdapter chatAdapter;
    private ChatAttachAlert chatAttachAlert;
    private long chatEnterTime;
    protected TLRPC.ChatFull chatInfo;
    private GridLayoutManagerFixed chatLayoutManager;
    private long chatLeaveTime;
    private RecyclerListView chatListView;
    private int chatListViewClipTop;
    private ArrayList<ChatMessageCell> chatMessageCellsCache;
    private boolean checkTextureViewPosition;
    private boolean clearingHistory;
    private Dialog closeChatDialog;
    private ImageView closeLivePinned;
    private ImageView closePinned;
    private ImageView closeReportSpam;
    private SizeNotifierFrameLayout contentView;
    private int createUnreadMessageAfterId;
    private boolean createUnreadMessageAfterIdLoading;
    protected TLRPC.Chat currentChat;
    protected TLRPC.EncryptedChat currentEncryptedChat;
    private boolean currentFloatingDateOnScreen;
    private boolean currentFloatingTopIsNotMessage;
    private String currentPicturePath;
    protected TLRPC.User currentUser;
    private AlertDialog dialogEnterRoomLoading;
    private long dialog_id;
    private ChatMessageCell drawLaterRoundProgressCell;
    private AnimatorSet editButtonAnimation;
    private int editTextEnd;
    private ActionBarMenuItem editTextItem;
    private int editTextStart;
    private MessageObject editingMessageObject;
    private int editingMessageObjectReqId;
    private View emojiButtonRed;
    private TextView emptyView;
    private FrameLayout emptyViewContainer;
    private boolean[] endReached;
    private boolean first;
    private boolean firstLoading;
    boolean firstOpen;
    private boolean firstUnreadSent;
    private int first_unread_id;
    private boolean fixPaddingsInLayout;
    private AnimatorSet floatingDateAnimation;
    private ChatActionCell floatingDateView;
    private boolean forceScrollToTop;
    private TextView forwardButton;
    private AnimatorSet forwardButtonAnimation;
    private boolean[] forwardEndReached;
    private HintView forwardHintView;
    private MessageObject forwardingMessage;
    private MessageObject.GroupedMessages forwardingMessageGroup;
    private ArrayList<MessageObject> forwardingMessages;
    private ArrayList<CharSequence> foundUrls;
    private TLRPC.WebPage foundWebPage;
    private FragmentContextView fragmentContextView;
    private TextView gifHintTextView;
    private boolean globalIgnoreLayout;
    private LongSparseArray<MessageObject.GroupedMessages> groupedMessagesMap;
    private boolean hasAllMentionsLocal;
    private boolean hasBotsCommands;
    private boolean hasUnfavedSelected;
    private ActionBarMenuItem headerItem;
    private Runnable hideAlertViewRunnable;
    private int hideDateDelay;
    private int highlightMessageId;
    private boolean ignoreAttachOnPause;
    private boolean inScheduleMode;
    private long inlineReturn;
    private InstantCameraView instantCameraView;
    private int lastLoadIndex;
    private int last_message_id;
    private int linkSearchRequestId;
    private boolean loading;
    private boolean loadingForward;
    private boolean loadingFromOldPosition;
    private int loadingPinnedMessage;
    private int loadsCount;
    private boolean locationAlertShown;
    private DialogRedpkg mRedPacketDialog;
    View mRedPacketDialogView;
    private RedPacketViewHolder mRedPacketViewHolder;
    private HashMap<String, CompositeDisposable> mTaskDisposable;
    private int[] maxDate;
    private int[] maxMessageId;
    private TextView mediaBanTooltip;
    private FrameLayout mentionContainer;
    private ExtendedGridLayoutManager mentionGridLayoutManager;
    private LinearLayoutManager mentionLayoutManager;
    private AnimatorSet mentionListAnimation;
    private RecyclerListView mentionListView;
    private boolean mentionListViewIgnoreLayout;
    private boolean mentionListViewIsScrolling;
    private int mentionListViewLastViewPosition;
    private int mentionListViewLastViewTop;
    private int mentionListViewScrollOffsetY;
    private FrameLayout mentiondownButton;
    private ObjectAnimator mentiondownButtonAnimation;
    private TextView mentiondownButtonCounter;
    private ImageView mentiondownButtonImage;
    private MentionsAdapter mentionsAdapter;
    private RecyclerListView.OnItemClickListener mentionsOnItemClickListener;
    private long mergeDialogId;
    protected ArrayList<MessageObject> messages;
    private HashMap<String, ArrayList<MessageObject>> messagesByDays;
    private SparseArray<MessageObject>[] messagesDict;
    private int[] minDate;
    private int[] minMessageId;
    private ChatActionBarMenuSubItem muteItem;
    private MessageObject needAnimateToMessage;
    private boolean needSelectFromMessageId;
    private int newMentionsCount;
    private int newUnreadMessageCount;
    private HintView noSoundHintView;
    RecyclerListView.OnItemClickListenerExtended onItemClickListener;
    RecyclerListView.OnItemLongClickListenerExtended onItemLongClickListener;
    private boolean openAnimationEnded;
    private boolean openKeyboardOnAttachMenuClose;
    private boolean openSearchKeyboard;
    private View overlayView;
    private FrameLayout pagedownButton;
    private AnimatorSet pagedownButtonAnimation;
    private TextView pagedownButtonCounter;
    private ImageView pagedownButtonImage;
    private boolean pagedownButtonShowedByScroll;
    private boolean paused;
    private boolean pausedOnLastMessage;
    private String pendingLinkSearchString;
    private Runnable pendingWebPageTimeoutRunnable;
    private PhotoViewer.PhotoViewerProvider photoViewerProvider;
    private int pinnedImageCacheType;
    private TLRPC.PhotoSize pinnedImageLocation;
    private TLObject pinnedImageLocationObject;
    private int pinnedImageSize;
    private TLRPC.PhotoSize pinnedImageThumbLocation;
    private View pinnedLineView;
    private MessageObject pinnedLiveMessage;
    private SimpleTextView pinnedLiveMessageNameTextView;
    private SimpleTextView pinnedLiveMessageTextView;
    private FrameLayout pinnedLiveMessageView;
    private BackupImageView pinnedLiveUserImageView;
    private BackupImageView pinnedMessageImageView;
    private SimpleTextView pinnedMessageNameTextView;
    private MessageObject pinnedMessageObject;
    private SimpleTextView pinnedMessageTextView;
    private FrameLayout pinnedMessageView;
    private AnimatorSet pinnedMessageViewAnimator;
    private LongSparseArray<ArrayList<MessageObject>> polls;
    ArrayList<MessageObject> pollsToCheck;
    private int prevSetUnreadCount;
    private RadialProgressView progressBar;
    private FrameLayout progressView;
    private View progressView2;
    private XAlertDialog redTransAlert;
    private TextView replyButton;
    private AnimatorSet replyButtonAnimation;
    private ImageView replyCloseImageView;
    private ImageView replyIconImageView;
    private int replyImageCacheType;
    private TLRPC.PhotoSize replyImageLocation;
    private TLObject replyImageLocationObject;
    private int replyImageSize;
    private TLRPC.PhotoSize replyImageThumbLocation;
    private BackupImageView replyImageView;
    private View replyLineView;
    private SimpleTextView replyNameTextView;
    private SimpleTextView replyObjectTextView;
    private MessageObject replyingMessageObject;
    private TextView reportSpamButton;
    private AnimatorSet reportSpamViewAnimator;
    private int reqId;
    private int returnToLoadIndex;
    private int returnToMessageId;
    private AnimatorSet runningAnimation;
    private int scheduledMessagesCount;
    private AnimatorSet scrimAnimatorSet;
    private Paint scrimPaint;
    private ActionBarPopupWindow scrimPopupWindow;
    private View scrimView;
    private MessageObject scrollToMessage;
    private int scrollToMessagePosition;
    private int scrollToOffsetOnRecreate;
    private int scrollToPositionOnRecreate;
    private boolean scrollToTopOnResume;
    private boolean scrollToTopUnReadOnResume;
    private boolean scrollToVideo;
    private boolean scrollingChatListView;
    private boolean scrollingFloatingDate;
    private ImageView searchCalendarButton;
    private FrameLayout searchContainer;
    private SimpleTextView searchCountText;
    private ImageView searchDownButton;
    private ActionBarMenuItem searchItem;
    private ImageView searchUpButton;
    private ImageView searchUserButton;
    private boolean searchingForUser;
    private TLRPC.User searchingUserMessages;
    private SparseArray<MessageObject>[] selectedMessagesCanCopyIds;
    private SparseArray<MessageObject>[] selectedMessagesCanStarIds;
    private NumberTextView selectedMessagesCountTextView;
    private SparseArray<MessageObject>[] selectedMessagesIds;
    private MessageObject selectedObject;
    private MessageObject.GroupedMessages selectedObjectGroup;
    private MessageObject selectedObjectToEditCaption;
    private boolean showScrollToMessageError;
    private HintView slowModeHint;
    private int startLoadFromMessageId;
    private int startLoadFromMessageIdSaved;
    private int startLoadFromMessageOffset;
    private String startVideoEdit;
    private StickersAdapter stickersAdapter;
    private RecyclerListView stickersListView;
    private RecyclerListView.OnItemClickListener stickersOnItemClickListener;
    private FrameLayout stickersPanel;
    private ImageView stickersPanelArrow;
    private View timeItem2;
    private FrameLayout topChatPanelView;
    private int topViewWasVisible;
    private UndoView undoView;
    private MessageObject unreadMessageObject;
    private Runnable unselectRunnable;
    private boolean userBlocked;
    protected TLRPC.UserFull userInfo;
    private FrameLayout videoPlayerContainer;
    private TextureView videoTextureView;
    private AnimatorSet voiceHintAnimation;
    private Runnable voiceHintHideRunnable;
    private TextView voiceHintTextView;
    private Runnable waitingForCharaterEnterRunnable;
    private ArrayList<Integer> waitingForLoad;
    private boolean waitingForReplyMessageLoad;
    private boolean wasManualScroll;
    private boolean wasPaused;

    /* JADX INFO: Access modifiers changed from: private */
    interface ChatActivityDelegate {
        void openReplyMessage(int i);
    }

    static /* synthetic */ int access$16110(ChatActivity x0) {
        int i = x0.newMentionsCount;
        x0.newMentionsCount = i - 1;
        return i;
    }

    static /* synthetic */ int access$18008(ChatActivity x0) {
        int i = x0.scheduledMessagesCount;
        x0.scheduledMessagesCount = i + 1;
        return i;
    }

    private class UnreadCounterTextView extends AppCompatTextView {
        private int circleWidth;
        private int currentCounter;
        private String currentCounterString;
        private Paint paint;
        private RectF rect;
        private TextPaint textPaint;
        private int textWidth;

        public UnreadCounterTextView(Context context) {
            super(context);
            this.textPaint = new TextPaint(1);
            this.paint = new Paint(1);
            this.rect = new RectF();
            this.textPaint.setTextSize(AndroidUtilities.dp(13.0f));
            this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        }

        @Override // android.widget.TextView
        public void setTextColor(int color) {
            super.setTextColor(color);
            this.textPaint.setColor(Theme.getColor(Theme.key_chat_messagePanelBackground));
            this.paint.setColor(Theme.getColor(Theme.key_chat_goDownButtonCounterBackground));
        }

        public void updateCounter() {
            int newCount;
            TLRPC.Dialog dialog;
            if (ChatObject.isChannel(ChatActivity.this.currentChat) && !ChatActivity.this.currentChat.megagroup && ChatActivity.this.chatInfo != null && ChatActivity.this.chatInfo.linked_chat_id != 0 && (dialog = ChatActivity.this.getMessagesController().dialogs_dict.get(-ChatActivity.this.chatInfo.linked_chat_id)) != null) {
                newCount = dialog.unread_count;
            } else {
                newCount = 0;
            }
            if (this.currentCounter != newCount) {
                this.currentCounter = newCount;
                if (newCount == 0) {
                    this.currentCounterString = null;
                    this.circleWidth = 0;
                    setPadding(0, 0, 0, 0);
                } else {
                    this.currentCounterString = String.format("%d", Integer.valueOf(newCount));
                    this.textWidth = (int) Math.ceil(this.textPaint.measureText(r2));
                    int newWidth = Math.max(AndroidUtilities.dp(20.0f), AndroidUtilities.dp(12.0f) + this.textWidth);
                    if (this.circleWidth != newWidth) {
                        this.circleWidth = newWidth;
                        setPadding(0, 0, (newWidth / 2) + AndroidUtilities.dp(7.0f), 0);
                    }
                }
                invalidate();
            }
        }

        @Override // android.widget.TextView, android.view.View
        protected void onDraw(Canvas canvas) {
            Layout layout;
            super.onDraw(canvas);
            if (this.currentCounterString != null && (layout = getLayout()) != null && getLineCount() > 0) {
                int lineWidth = (int) Math.ceil(layout.getLineWidth(0));
                int x = ((getMeasuredWidth() + (lineWidth - this.circleWidth)) / 2) + AndroidUtilities.dp(8.0f);
                this.rect.set(x, (getMeasuredHeight() / 2) - AndroidUtilities.dp(10.0f), this.circleWidth + x, (getMeasuredHeight() / 2) + AndroidUtilities.dp(10.0f));
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), this.paint);
                canvas.drawText(this.currentCounterString, this.rect.centerX() - (this.textWidth / 2.0f), this.rect.top + AndroidUtilities.dp(14.5f), this.textPaint);
            }
        }
    }

    public Boolean isSysNotifyMessage() {
        if (Constants.DialogsFragmentTopMenuConfig.isSystemCode(this.dialog_id)) {
            return true;
        }
        return false;
    }

    public ChatActivity(Bundle args) {
        super(args);
        this.chatMessageCellsCache = new ArrayList<>();
        this.alredyPlayedStickers = new HashMap<>();
        this.actionModeViews = new ArrayList<>();
        this.hideDateDelay = SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION;
        this.scheduledMessagesCount = -1;
        this.animatingMessageObjects = new ArrayList<>();
        this.scrollToPositionOnRecreate = -1;
        this.scrollToOffsetOnRecreate = 0;
        this.pollsToCheck = new ArrayList<>(10);
        this.allowContextBotPanelSecond = true;
        this.paused = true;
        this.firstOpen = true;
        this.selectedMessagesIds = new SparseArray[]{new SparseArray<>(), new SparseArray<>()};
        this.selectedMessagesCanCopyIds = new SparseArray[]{new SparseArray<>(), new SparseArray<>()};
        this.selectedMessagesCanStarIds = new SparseArray[]{new SparseArray<>(), new SparseArray<>()};
        this.waitingForLoad = new ArrayList<>();
        this.prevSetUnreadCount = Integer.MIN_VALUE;
        this.messagesDict = new SparseArray[]{new SparseArray<>(), new SparseArray<>()};
        this.messagesByDays = new HashMap<>();
        this.messages = new ArrayList<>();
        this.polls = new LongSparseArray<>();
        this.groupedMessagesMap = new LongSparseArray<>();
        this.maxMessageId = new int[]{Integer.MAX_VALUE, Integer.MAX_VALUE};
        this.minMessageId = new int[]{Integer.MIN_VALUE, Integer.MIN_VALUE};
        this.maxDate = new int[]{Integer.MIN_VALUE, Integer.MIN_VALUE};
        this.minDate = new int[2];
        this.endReached = new boolean[2];
        this.cacheEndReached = new boolean[2];
        this.forwardEndReached = new boolean[]{true, true};
        this.firstLoading = true;
        this.firstUnreadSent = false;
        this.last_message_id = 0;
        this.startLoadFromMessageOffset = Integer.MAX_VALUE;
        this.first = true;
        this.highlightMessageId = Integer.MAX_VALUE;
        this.scrollToMessagePosition = -10000;
        this.botInfo = new SparseArray<>();
        this.TAG = ChatActivity.class.getSimpleName();
        this.photoViewerProvider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.ChatActivity.1
            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                ChatActionCell cell;
                MessageObject message;
                ChatMessageCell cell2;
                MessageObject message2;
                int count = ChatActivity.this.chatListView.getChildCount();
                for (int a = 0; a < count; a++) {
                    ImageReceiver imageReceiver = null;
                    View view = ChatActivity.this.chatListView.getChildAt(a);
                    if (view instanceof ChatMessageCell) {
                        if (messageObject != null && messageObject.type == 105) {
                            ChatMessageCell cell3 = (ChatMessageCell) view;
                            int photoImageViewIndex = cell3.getClickSysNotifyPhotoImageViewIndex();
                            if (photoImageViewIndex == 1) {
                                imageReceiver = cell3.photoImage1;
                            } else if (photoImageViewIndex == 2) {
                                imageReceiver = cell3.photoImage2;
                            } else if (photoImageViewIndex == 3) {
                                imageReceiver = cell3.photoImage3;
                            } else if (photoImageViewIndex == 4) {
                                imageReceiver = cell3.photoImage4;
                            } else if (photoImageViewIndex == 5) {
                                imageReceiver = cell3.photoImage5;
                            }
                        } else if (messageObject != null && (message2 = (cell2 = (ChatMessageCell) view).getMessageObject()) != null && message2.getId() == messageObject.getId()) {
                            imageReceiver = cell2.getPhotoImage();
                        }
                    } else if ((view instanceof ChatActionCell) && (message = (cell = (ChatActionCell) view).getMessageObject()) != null) {
                        if (messageObject != null) {
                            if (message.getId() == messageObject.getId()) {
                                imageReceiver = cell.getPhotoImage();
                            }
                        } else if (fileLocation != null && message.photoThumbs != null) {
                            int b = 0;
                            while (true) {
                                if (b >= message.photoThumbs.size()) {
                                    break;
                                }
                                TLRPC.PhotoSize photoSize = message.photoThumbs.get(b);
                                MessageObject message3 = message;
                                if (photoSize.location.volume_id != fileLocation.volume_id || photoSize.location.local_id != fileLocation.local_id) {
                                    b++;
                                    message = message3;
                                } else {
                                    imageReceiver = cell.getPhotoImage();
                                    break;
                                }
                            }
                        }
                    }
                    if (imageReceiver != null) {
                        int[] coords = new int[2];
                        view.getLocationInWindow(coords);
                        PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                        object.viewX = coords[0];
                        object.viewY = coords[1] - (Build.VERSION.SDK_INT < 21 ? AndroidUtilities.statusBarHeight : 0);
                        object.parentView = ChatActivity.this.chatListView;
                        object.imageReceiver = imageReceiver;
                        if (needPreview) {
                            object.thumb = imageReceiver.getBitmapSafe();
                        }
                        object.radius = imageReceiver.getRoundRadius();
                        if ((view instanceof ChatActionCell) && ChatActivity.this.currentChat != null) {
                            object.dialogId = -ChatActivity.this.currentChat.id;
                        }
                        if ((ChatActivity.this.pinnedMessageView != null && ChatActivity.this.pinnedMessageView.getTag() == null) || (ChatActivity.this.topChatPanelView != null && ChatActivity.this.topChatPanelView.getTag() == null)) {
                            object.clipTopAddition = AndroidUtilities.dp(48.0f);
                        }
                        object.clipTopAddition += ChatActivity.this.chatListViewClipTop;
                        return object;
                    }
                }
                return null;
            }
        };
        this.botContextProvider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.ChatActivity.2
            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                if (index >= 0 && index < ChatActivity.this.botContextResults.size()) {
                    int count = ChatActivity.this.mentionListView.getChildCount();
                    Object result = ChatActivity.this.botContextResults.get(index);
                    for (int a = 0; a < count; a++) {
                        ImageReceiver imageReceiver = null;
                        View view = ChatActivity.this.mentionListView.getChildAt(a);
                        if (view instanceof ContextLinkCell) {
                            ContextLinkCell cell = (ContextLinkCell) view;
                            if (cell.getResult() == result) {
                                imageReceiver = cell.getPhotoImage();
                            }
                        }
                        if (imageReceiver != null) {
                            int[] coords = new int[2];
                            view.getLocationInWindow(coords);
                            PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                            object.viewX = coords[0];
                            object.viewY = coords[1] - (Build.VERSION.SDK_INT < 21 ? AndroidUtilities.statusBarHeight : 0);
                            object.parentView = ChatActivity.this.mentionListView;
                            object.imageReceiver = imageReceiver;
                            object.thumb = imageReceiver.getBitmapSafe();
                            object.radius = imageReceiver.getRoundRadius();
                            return object;
                        }
                    }
                    return null;
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
                if (index < 0 || index >= ChatActivity.this.botContextResults.size()) {
                    return;
                }
                ChatActivity chatActivity = ChatActivity.this;
                chatActivity.lambda$null$20$ChatActivity((TLRPC.BotInlineResult) chatActivity.botContextResults.get(index), notify, scheduleDate);
            }
        };
        this.onItemLongClickListener = new RecyclerListView.OnItemLongClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.ChatActivity.3
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public boolean onItemClick(View view, int position, float x, float y) {
                ChatActivity.this.wasManualScroll = true;
                if (!ChatActivity.this.actionBar.isActionModeShowed()) {
                    ChatActivity.this.createMenu(view, false, true, x, y);
                } else {
                    boolean outside = false;
                    if (view instanceof ChatMessageCell) {
                        outside = !((ChatMessageCell) view).isInsideBackground(x, y);
                    }
                    ChatActivity.this.processRowSelect(view, outside, x, y);
                }
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onLongClickRelease() {
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListenerExtended
            public void onMove(float dx, float dy) {
            }
        };
        this.onItemClickListener = new RecyclerListView.OnItemClickListenerExtended() { // from class: im.uwrkaxlmjj.ui.ChatActivity.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListenerExtended
            public void onItemClick(View view, int position, float x, float y) {
                ChatActivity.this.wasManualScroll = true;
                if (!ChatActivity.this.actionBar.isActionModeShowed()) {
                    ChatActivity.this.createMenu(view, true, false, x, y);
                    return;
                }
                boolean outside = false;
                if (view instanceof ChatMessageCell) {
                    outside = true ^ ((ChatMessageCell) view).isInsideBackground(x, y);
                }
                ChatActivity.this.processRowSelect(view, outside, x, y);
            }
        };
        this.mTaskDisposable = new HashMap<>();
        this.reqId = -1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        final int chatId = this.arguments.getInt("chat_id", 0);
        final int userId = this.arguments.getInt("user_id", 0);
        final int encId = this.arguments.getInt("enc_id", 0);
        this.inScheduleMode = this.arguments.getBoolean("scheduled", false);
        this.inlineReturn = this.arguments.getLong("inline_return", 0L);
        String inlineQuery = this.arguments.getString("inline_query");
        this.startLoadFromMessageId = this.arguments.getInt("message_id", 0);
        int migrated_to = this.arguments.getInt("migrated_to", 0);
        this.scrollToTopOnResume = this.arguments.getBoolean("scrollToTopOnResume", false);
        if (chatId != 0) {
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(chatId));
            this.currentChat = chat;
            if (chat == null) {
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                final MessagesStorage messagesStorage = getMessagesStorage();
                messagesStorage.getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$e_LLnfm5U-sFr3R9PkBDZkIUMUE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onFragmentCreate$0$ChatActivity(messagesStorage, chatId, countDownLatch);
                    }
                });
                try {
                    countDownLatch.await();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                if (this.currentChat == null) {
                    return false;
                }
                getMessagesController().putChat(this.currentChat, true);
            }
            this.dialog_id = -chatId;
            if (ChatObject.isChannel(this.currentChat)) {
                getMessagesController().startShortPoll(this.currentChat, false);
            }
        } else if (userId != 0) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(userId));
            this.currentUser = user;
            if (user == null) {
                final MessagesStorage messagesStorage2 = getMessagesStorage();
                final CountDownLatch countDownLatch2 = new CountDownLatch(1);
                messagesStorage2.getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$0CkV9Z5CLm29duba8daPAB20vfs
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onFragmentCreate$1$ChatActivity(messagesStorage2, userId, countDownLatch2);
                    }
                });
                try {
                    countDownLatch2.await();
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                if (this.currentUser == null) {
                    return false;
                }
                getMessagesController().putUser(this.currentUser, true);
            }
            this.dialog_id = userId;
            this.botUser = this.arguments.getString("botUser");
            if (inlineQuery != null) {
                getMessagesController().sendBotStart(this.currentUser, inlineQuery);
            }
        } else {
            if (encId == 0) {
                return false;
            }
            this.currentEncryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(encId));
            final MessagesStorage messagesStorage3 = getMessagesStorage();
            if (this.currentEncryptedChat == null) {
                final CountDownLatch countDownLatch3 = new CountDownLatch(1);
                messagesStorage3.getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$dJ0Fbno7QHztG1_ykgCtNOnzPkY
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onFragmentCreate$2$ChatActivity(messagesStorage3, encId, countDownLatch3);
                    }
                });
                try {
                    countDownLatch3.await();
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
                if (this.currentEncryptedChat == null) {
                    return false;
                }
                getMessagesController().putEncryptedChat(this.currentEncryptedChat, true);
            }
            TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(this.currentEncryptedChat.user_id));
            this.currentUser = user2;
            if (user2 == null) {
                final CountDownLatch countDownLatch4 = new CountDownLatch(1);
                messagesStorage3.getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$7EYEyxaWUih0iCR-rtcOkBgBr1M
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onFragmentCreate$3$ChatActivity(messagesStorage3, countDownLatch4);
                    }
                });
                try {
                    countDownLatch4.await();
                } catch (Exception e4) {
                    FileLog.e(e4);
                }
                if (this.currentUser == null) {
                    return false;
                }
                getMessagesController().putUser(this.currentUser, true);
            }
            this.dialog_id = ((long) encId) << 32;
            int[] iArr = this.maxMessageId;
            iArr[1] = Integer.MIN_VALUE;
            iArr[0] = Integer.MIN_VALUE;
            int[] iArr2 = this.minMessageId;
            iArr2[1] = Integer.MAX_VALUE;
            iArr2[0] = Integer.MAX_VALUE;
        }
        if (this.currentUser != null) {
            MediaController.getInstance().startMediaObserver();
        }
        if (!this.inScheduleMode) {
            getNotificationCenter().addObserver(this, NotificationCenter.messagesRead);
            getNotificationCenter().addObserver(this, NotificationCenter.screenshotTook);
            getNotificationCenter().addObserver(this, NotificationCenter.encryptedChatUpdated);
            getNotificationCenter().addObserver(this, NotificationCenter.messagesReadEncrypted);
            getNotificationCenter().addObserver(this, NotificationCenter.removeAllMessagesFromDialog);
            getNotificationCenter().addObserver(this, NotificationCenter.messagesReadContent);
            getNotificationCenter().addObserver(this, NotificationCenter.botKeyboardDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.chatSearchResultsAvailable);
            getNotificationCenter().addObserver(this, NotificationCenter.chatSearchResultsLoading);
            getNotificationCenter().addObserver(this, NotificationCenter.didUpdatedMessagesViews);
            getNotificationCenter().addObserver(this, NotificationCenter.pinnedMessageDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.peerSettingsDidLoad);
            getNotificationCenter().addObserver(this, NotificationCenter.newDraftReceived);
            getNotificationCenter().addObserver(this, NotificationCenter.updateMentionsCount);
            getNotificationCenter().addObserver(this, NotificationCenter.didUpdatePollResults);
            getNotificationCenter().addObserver(this, NotificationCenter.chatOnlineCountDidLoad);
        }
        getNotificationCenter().addObserver(this, NotificationCenter.messagesDidLoad);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.didUpdateConnectionState);
        getNotificationCenter().addObserver(this, NotificationCenter.updateInterfaces);
        getNotificationCenter().addObserver(this, NotificationCenter.didReceiveNewMessages);
        getNotificationCenter().addObserver(this, NotificationCenter.closeChats);
        getNotificationCenter().addObserver(this, NotificationCenter.messagesDeleted);
        getNotificationCenter().addObserver(this, NotificationCenter.historyCleared);
        getNotificationCenter().addObserver(this, NotificationCenter.messageReceivedByServer);
        getNotificationCenter().addObserver(this, NotificationCenter.messageReceivedByAck);
        getNotificationCenter().addObserver(this, NotificationCenter.messageSendError);
        getNotificationCenter().addObserver(this, NotificationCenter.chatInfoDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.contactsDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        getNotificationCenter().addObserver(this, NotificationCenter.messagePlayingDidReset);
        getNotificationCenter().addObserver(this, NotificationCenter.messagePlayingGoingToStop);
        getNotificationCenter().addObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        getNotificationCenter().addObserver(this, NotificationCenter.blockedUsersDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.fileNewChunkAvailable);
        getNotificationCenter().addObserver(this, NotificationCenter.didCreatedNewDeleteTask);
        getNotificationCenter().addObserver(this, NotificationCenter.messagePlayingDidStart);
        getNotificationCenter().addObserver(this, NotificationCenter.updateMessageMedia);
        getNotificationCenter().addObserver(this, NotificationCenter.replaceMessagesObjects);
        getNotificationCenter().addObserver(this, NotificationCenter.notificationsSettingsUpdated);
        getNotificationCenter().addObserver(this, NotificationCenter.replyMessagesDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.didReceivedWebpages);
        getNotificationCenter().addObserver(this, NotificationCenter.didReceivedWebpagesInUpdates);
        getNotificationCenter().addObserver(this, NotificationCenter.botInfoDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.chatInfoCantLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.pinnedLiveMessage);
        getNotificationCenter().addObserver(this, NotificationCenter.userInfoDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetNewWallpapper);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.goingToPreviewTheme);
        getNotificationCenter().addObserver(this, NotificationCenter.channelRightsUpdated);
        getNotificationCenter().addObserver(this, NotificationCenter.audioRecordTooShort);
        getNotificationCenter().addObserver(this, NotificationCenter.didUpdateReactions);
        getNotificationCenter().addObserver(this, NotificationCenter.videoLoadingStateChanged);
        getNotificationCenter().addObserver(this, NotificationCenter.scheduledMessagesUpdated);
        getNotificationCenter().addObserver(this, NotificationCenter.livestatechange);
        getNotificationCenter().addObserver(this, NotificationCenter.contactRelationShip);
        getNotificationCenter().addObserver(this, NotificationCenter.updateChatNewmsgMentionText);
        getNotificationCenter().addObserver(this, NotificationCenter.liverestartnotify);
        super.onFragmentCreate();
        this.loading = true;
        if (!this.inScheduleMode) {
            if (this.currentEncryptedChat == null) {
                getMediaDataController().loadBotKeyboard(this.dialog_id);
            }
            getMessagesController().loadPeerSettings(this.currentUser, this.currentChat);
            getMessagesController().setLastCreatedDialogId(this.dialog_id, this.inScheduleMode, true);
            if (this.startLoadFromMessageId == 0) {
                SharedPreferences sharedPreferences = MessagesController.getNotificationsSettings(this.currentAccount);
                int messageId = sharedPreferences.getInt("diditem" + this.dialog_id, 0);
                if (messageId != 0) {
                    this.wasManualScroll = true;
                    this.loadingFromOldPosition = true;
                    this.startLoadFromMessageOffset = sharedPreferences.getInt("diditemo" + this.dialog_id, 0);
                    this.startLoadFromMessageId = messageId;
                }
            } else {
                this.showScrollToMessageError = true;
                this.needSelectFromMessageId = true;
            }
        }
        this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
        int i = this.startLoadFromMessageId;
        if (i != 0) {
            this.startLoadFromMessageIdSaved = i;
            if (migrated_to != 0) {
                this.mergeDialogId = migrated_to;
                MessagesController messagesController = getMessagesController();
                long j = this.mergeDialogId;
                int i2 = this.loadingFromOldPosition ? 50 : AndroidUtilities.isTablet() ? 30 : 20;
                int i3 = this.startLoadFromMessageId;
                int i4 = this.classGuid;
                boolean zIsChannel = ChatObject.isChannel(this.currentChat);
                boolean z = this.inScheduleMode;
                int i5 = this.lastLoadIndex;
                this.lastLoadIndex = i5 + 1;
                messagesController.loadMessages(j, i2, i3, 0, true, 0, i4, 3, 0, zIsChannel, z, i5);
            } else {
                MessagesController messagesController2 = getMessagesController();
                long j2 = this.dialog_id;
                int i6 = this.loadingFromOldPosition ? 50 : AndroidUtilities.isTablet() ? 30 : 20;
                int i7 = this.startLoadFromMessageId;
                int i8 = this.classGuid;
                boolean zIsChannel2 = ChatObject.isChannel(this.currentChat);
                boolean z2 = this.inScheduleMode;
                int i9 = this.lastLoadIndex;
                this.lastLoadIndex = i9 + 1;
                messagesController2.loadMessages(j2, i6, i7, 0, true, 0, i8, 3, 0, zIsChannel2, z2, i9);
            }
        } else {
            MessagesController messagesController3 = getMessagesController();
            long j3 = this.dialog_id;
            int i10 = AndroidUtilities.isTablet() ? 30 : 20;
            int i11 = this.classGuid;
            boolean zIsChannel3 = ChatObject.isChannel(this.currentChat);
            int i12 = this.lastLoadIndex;
            this.lastLoadIndex = i12 + 1;
            messagesController3.loadMessages(j3, i10, 0, 0, true, 0, i11, 2, 0, zIsChannel3, false, i12);
        }
        if (this.currentChat != null) {
            this.chatInfo = getMessagesController().getChatFull(this.currentChat.id);
            if (this.currentChat.megagroup && !getMessagesController().isChannelAdminsLoaded(this.currentChat.id)) {
                getMessagesController().loadChannelAdmins(this.currentChat.id, true);
            }
            TLRPC.ChatFull info = getMessagesStorage().loadChatInfo(this.currentChat.id, null, true, false);
            if (this.chatInfo == null) {
                this.chatInfo = info;
            }
            if (!this.inScheduleMode && this.chatInfo != null && ChatObject.isChannel(this.currentChat) && this.chatInfo.migrated_from_chat_id != 0) {
                this.mergeDialogId = -this.chatInfo.migrated_from_chat_id;
                this.maxMessageId[1] = this.chatInfo.migrated_from_max_id;
            }
        } else if (this.currentUser != null) {
            getMessagesController().loadUserInfo(this.currentUser, true, this.classGuid);
        }
        if (!this.inScheduleMode) {
            if (userId != 0 && this.currentUser.bot) {
                getMediaDataController().loadBotInfo(userId, true, this.classGuid);
            } else if (this.chatInfo instanceof TLRPC.TL_chatFull) {
                for (int a = 0; a < this.chatInfo.participants.participants.size(); a++) {
                    TLRPC.ChatParticipant participant = this.chatInfo.participants.participants.get(a);
                    TLRPC.User user3 = getMessagesController().getUser(Integer.valueOf(participant.user_id));
                    if (user3 != null && user3.bot) {
                        getMediaDataController().loadBotInfo(user3.id, true, this.classGuid);
                    }
                }
            }
            if (AndroidUtilities.isTablet()) {
                getNotificationCenter().postNotificationName(NotificationCenter.openedChatChanged, Long.valueOf(this.dialog_id), false);
            }
            if (this.currentUser != null) {
                this.userBlocked = getMessagesController().blockedUsers.indexOfKey(this.currentUser.id) >= 0;
            }
            TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
            if (encryptedChat != null && AndroidUtilities.getMyLayerVersion(encryptedChat.layer) != 101) {
                getSecretChatHelper().sendNotifyLayerMessage(this.currentEncryptedChat, null);
            }
        }
        return true;
    }

    public /* synthetic */ void lambda$onFragmentCreate$0$ChatActivity(MessagesStorage messagesStorage, int chatId, CountDownLatch countDownLatch) {
        this.currentChat = messagesStorage.getChat(chatId);
        countDownLatch.countDown();
    }

    public /* synthetic */ void lambda$onFragmentCreate$1$ChatActivity(MessagesStorage messagesStorage, int userId, CountDownLatch countDownLatch) {
        this.currentUser = messagesStorage.getUser(userId);
        countDownLatch.countDown();
    }

    public /* synthetic */ void lambda$onFragmentCreate$2$ChatActivity(MessagesStorage messagesStorage, int encId, CountDownLatch countDownLatch) {
        this.currentEncryptedChat = messagesStorage.getEncryptedChat(encId);
        countDownLatch.countDown();
    }

    public /* synthetic */ void lambda$onFragmentCreate$3$ChatActivity(MessagesStorage messagesStorage, CountDownLatch countDownLatch) {
        this.currentUser = messagesStorage.getUser(this.currentEncryptedChat.user_id);
        countDownLatch.countDown();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onDestroy();
        }
        MentionsAdapter mentionsAdapter = this.mentionsAdapter;
        if (mentionsAdapter != null) {
            mentionsAdapter.onDestroy();
        }
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            chatAttachAlert.dismissInternal();
        }
        UndoView undoView = this.undoView;
        if (undoView != null) {
            undoView.hide(true, 0);
        }
        getMessagesController().setLastCreatedDialogId(this.dialog_id, this.inScheduleMode, false);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagesDidLoad);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.didUpdateConnectionState);
        getNotificationCenter().removeObserver(this, NotificationCenter.updateInterfaces);
        getNotificationCenter().removeObserver(this, NotificationCenter.didReceiveNewMessages);
        getNotificationCenter().removeObserver(this, NotificationCenter.closeChats);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagesRead);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagesDeleted);
        getNotificationCenter().removeObserver(this, NotificationCenter.historyCleared);
        getNotificationCenter().removeObserver(this, NotificationCenter.messageReceivedByServer);
        getNotificationCenter().removeObserver(this, NotificationCenter.messageReceivedByAck);
        getNotificationCenter().removeObserver(this, NotificationCenter.messageSendError);
        getNotificationCenter().removeObserver(this, NotificationCenter.chatInfoDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.encryptedChatUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagesReadEncrypted);
        getNotificationCenter().removeObserver(this, NotificationCenter.removeAllMessagesFromDialog);
        getNotificationCenter().removeObserver(this, NotificationCenter.contactsDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagePlayingDidReset);
        getNotificationCenter().removeObserver(this, NotificationCenter.screenshotTook);
        getNotificationCenter().removeObserver(this, NotificationCenter.blockedUsersDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.fileNewChunkAvailable);
        getNotificationCenter().removeObserver(this, NotificationCenter.didCreatedNewDeleteTask);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagePlayingDidStart);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagePlayingGoingToStop);
        getNotificationCenter().removeObserver(this, NotificationCenter.updateMessageMedia);
        getNotificationCenter().removeObserver(this, NotificationCenter.replaceMessagesObjects);
        getNotificationCenter().removeObserver(this, NotificationCenter.notificationsSettingsUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.replyMessagesDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.didReceivedWebpages);
        getNotificationCenter().removeObserver(this, NotificationCenter.didReceivedWebpagesInUpdates);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagesReadContent);
        getNotificationCenter().removeObserver(this, NotificationCenter.botInfoDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.botKeyboardDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.chatSearchResultsAvailable);
        getNotificationCenter().removeObserver(this, NotificationCenter.chatSearchResultsLoading);
        getNotificationCenter().removeObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        getNotificationCenter().removeObserver(this, NotificationCenter.didUpdatedMessagesViews);
        getNotificationCenter().removeObserver(this, NotificationCenter.chatInfoCantLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.pinnedLiveMessage);
        getNotificationCenter().removeObserver(this, NotificationCenter.pinnedMessageDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.peerSettingsDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.newDraftReceived);
        getNotificationCenter().removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetNewWallpapper);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.goingToPreviewTheme);
        getNotificationCenter().removeObserver(this, NotificationCenter.channelRightsUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.updateMentionsCount);
        getNotificationCenter().removeObserver(this, NotificationCenter.audioRecordTooShort);
        getNotificationCenter().removeObserver(this, NotificationCenter.didUpdatePollResults);
        getNotificationCenter().removeObserver(this, NotificationCenter.didUpdateReactions);
        getNotificationCenter().removeObserver(this, NotificationCenter.chatOnlineCountDidLoad);
        getNotificationCenter().removeObserver(this, NotificationCenter.videoLoadingStateChanged);
        getNotificationCenter().removeObserver(this, NotificationCenter.scheduledMessagesUpdated);
        getNotificationCenter().removeObserver(this, NotificationCenter.livestatechange);
        getNotificationCenter().removeObserver(this, NotificationCenter.contactRelationShip);
        getNotificationCenter().removeObserver(this, NotificationCenter.updateChatNewmsgMentionText);
        getNotificationCenter().removeObserver(this, NotificationCenter.liverestartnotify);
        if (!this.inScheduleMode && AndroidUtilities.isTablet()) {
            getNotificationCenter().postNotificationName(NotificationCenter.openedChatChanged, Long.valueOf(this.dialog_id), true);
        }
        if (this.currentUser != null) {
            MediaController.getInstance().stopMediaObserver();
        }
        if (this.currentEncryptedChat != null) {
            try {
                if (Build.VERSION.SDK_INT >= 23 && (SharedConfig.passcodeHash.length() == 0 || SharedConfig.allowScreenCapture)) {
                    MediaController.getInstance().setFlagSecure(this, false);
                }
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        if (this.currentUser != null) {
            getMessagesController().cancelLoadFullUser(this.currentUser.id);
        }
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
        StickersAdapter stickersAdapter = this.stickersAdapter;
        if (stickersAdapter != null) {
            stickersAdapter.onDestroy();
        }
        ChatAttachAlert chatAttachAlert2 = this.chatAttachAlert;
        if (chatAttachAlert2 != null) {
            chatAttachAlert2.onDestroy();
        }
        AndroidUtilities.unlockOrientation(getParentActivity());
        if (ChatObject.isChannel(this.currentChat)) {
            getMessagesController().startShortPoll(this.currentChat, true);
        }
        translateUnSubscribeAllAudioTask();
    }

    private void animLivePinClose(final View view) {
        AnimatorSet currentAnimation = new AnimatorSet();
        currentAnimation.setDuration(1000L);
        currentAnimation.playTogether(ObjectAnimator.ofFloat(view, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(view, "scaleX", 1.0f, 0.01f), ObjectAnimator.ofFloat(view, "scaleY", 1.0f, 0.01f), ObjectAnimator.ofFloat(view, "translationX", (AndroidUtilities.getRealScreenSize().y - AndroidUtilities.dp(100.0f)) - view.getLeft()), ObjectAnimator.ofFloat(view, "translationY", -AndroidUtilities.dp(80.0f)));
        currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                view.setVisibility(4);
                ChatActivity.this.resetLivePinClose(view);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animator) {
            }
        });
        currentAnimation.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetLivePinClose(View view) {
        AnimatorSet currentAnimation = new AnimatorSet();
        currentAnimation.setDuration(100L);
        currentAnimation.playTogether(ObjectAnimator.ofFloat(view, "alpha", 0.0f, 1.0f), ObjectAnimator.ofFloat(view, "scaleX", 0.01f, 1.0f), ObjectAnimator.ofFloat(view, "scaleY", 0.01f, 1.0f), ObjectAnimator.ofFloat(view, "translationX", 0.0f), ObjectAnimator.ofFloat(view, "translationY", 0.0f));
        currentAnimation.start();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        CharSequence oldMessage;
        boolean z;
        TLRPC.Chat chat;
        TLRPC.User user;
        TLRPC.Chat chat2;
        TLRPC.Chat chat3;
        if (this.chatMessageCellsCache.isEmpty()) {
            for (int a = 0; a < 8; a++) {
                this.chatMessageCellsCache.add(new ChatMessageCell(context, this));
            }
        }
        for (int a2 = 1; a2 >= 0; a2--) {
            this.selectedMessagesIds[a2].clear();
            this.selectedMessagesCanCopyIds[a2].clear();
            this.selectedMessagesCanStarIds[a2].clear();
        }
        this.cantDeleteMessagesCount = 0;
        this.canEditMessagesCount = 0;
        this.cantForwardMessagesCount = 0;
        this.canForwardMessagesCount = 0;
        this.cantCopyMessageCount = 0;
        this.videoPlayerContainer = null;
        this.voiceHintTextView = null;
        this.hasOwnBackground = true;
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            try {
                if (chatAttachAlert.isShowing()) {
                    this.chatAttachAlert.dismiss();
                }
            } catch (Exception e) {
            }
            this.chatAttachAlert.onDestroy();
            this.chatAttachAlert = null;
        }
        StickersAdapter stickersAdapter = this.stickersAdapter;
        if (stickersAdapter != null) {
            stickersAdapter.onDestroy();
            this.stickersAdapter = null;
        }
        Theme.createChatResources(context, false);
        this.actionBar.setAddToContainer(false);
        if (this.inPreviewMode) {
            this.actionBar.setBackButtonImage(0);
        } else {
            this.actionBar.setBackButtonImage(R.id.ic_back);
        }
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass6());
        this.actionBarHelper = new ChatActionBarHelper(this, this.actionBar, this.currentEncryptedChat != null, this.inPreviewMode);
        TLRPC.Chat chat4 = this.currentChat;
        if (chat4 != null && !ChatObject.isChannel(chat4)) {
            int i = this.currentChat.participants_count;
            TLRPC.ChatFull chatFull = this.chatInfo;
            if (chatFull != null) {
                chatFull.participants.participants.size();
            }
        }
        ActionBarMenu menu = this.actionBar.createMenu();
        if (this.currentEncryptedChat == null && !this.inScheduleMode) {
            ActionBarMenuItem actionBarMenuItemSearchListener = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new AnonymousClass7());
            this.searchItem = actionBarMenuItemSearchListener;
            actionBarMenuItemSearchListener.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
            this.searchItem.setVisibility(8);
        }
        if (!this.inScheduleMode) {
            TLRPC.User user2 = this.currentUser;
            if (isSysNotifyMessage().booleanValue()) {
                this.headerItem = menu.addItem(18, R.id.iv_chat_sys_notify_msg_unmute);
            } else {
                ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(0, R.drawable.bar_right_menu);
                this.headerItem = actionBarMenuItemAddItem;
                actionBarMenuItemAddItem.setContentDescription(LocaleController.getString("AccDescrMoreOptions", R.string.AccDescrMoreOptions));
            }
            createActionBarMenuPop();
            ActionBarMenuItem actionBarMenuItemAddItem2 = menu.addItem(0, R.drawable.ic_ab_other);
            this.editTextItem = actionBarMenuItemAddItem2;
            actionBarMenuItemAddItem2.setTag(null);
            this.editTextItem.setVisibility(8);
            SpannableStringBuilder stringBuilder = new SpannableStringBuilder(LocaleController.getString("Bold", R.string.Bold));
            stringBuilder.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf")), 0, stringBuilder.length(), 33);
            this.editTextItem.addSubItem(50, stringBuilder);
            SpannableStringBuilder stringBuilder2 = new SpannableStringBuilder(LocaleController.getString("Italic", R.string.Italic));
            stringBuilder2.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/ritalic.ttf")), 0, stringBuilder2.length(), 33);
            this.editTextItem.addSubItem(51, stringBuilder2);
            SpannableStringBuilder stringBuilder3 = new SpannableStringBuilder(LocaleController.getString("Mono", R.string.Mono));
            stringBuilder3.setSpan(new TypefaceSpan(Typeface.MONOSPACE), 0, stringBuilder3.length(), 33);
            this.editTextItem.addSubItem(52, stringBuilder3);
            TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
            if (encryptedChat == null || (encryptedChat != null && AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) >= 101)) {
                SpannableStringBuilder stringBuilder4 = new SpannableStringBuilder(LocaleController.getString("Strike", R.string.Strike));
                TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
                run.flags |= 8;
                stringBuilder4.setSpan(new TextStyleSpan(run), 0, stringBuilder4.length(), 33);
                this.editTextItem.addSubItem(55, stringBuilder4);
                SpannableStringBuilder stringBuilder5 = new SpannableStringBuilder(LocaleController.getString("Underline", R.string.Underline));
                TextStyleSpan.TextStyleRun run2 = new TextStyleSpan.TextStyleRun();
                run2.flags |= 16;
                stringBuilder5.setSpan(new TextStyleSpan(run2), 0, stringBuilder5.length(), 33);
                this.editTextItem.addSubItem(56, stringBuilder5);
            }
            this.editTextItem.addSubItem(53, LocaleController.getString("CreateLink", R.string.CreateLink));
            this.editTextItem.addSubItem(54, LocaleController.getString("Regular", R.string.Regular));
            if (this.searchItem != null) {
                this.chatActionBarMenuPop.addSubItem(40, R.drawable.msg_search, LocaleController.getString("Search", R.string.Search));
            }
            TLRPC.Chat chat5 = this.currentChat;
            if (chat5 != null && !chat5.creator) {
                this.chatActionBarMenuPop.addSubItem(21, R.drawable.msg_report, LocaleController.getString("ReportChat", R.string.ReportChat));
            }
            if (this.currentUser != null) {
                this.addContactItem = this.chatActionBarMenuPop.addSubItem(17, R.drawable.msg_addcontact, "");
            }
            if (this.currentEncryptedChat != null) {
                this.timeItem2 = this.chatActionBarMenuPop.addSubItem(13, R.drawable.msg_timer, LocaleController.getString("SetTimer", R.string.SetTimer));
            }
            if (!ChatObject.isChannel(this.currentChat) || ((chat3 = this.currentChat) != null && chat3.megagroup && TextUtils.isEmpty(this.currentChat.username))) {
                this.chatActionBarMenuPop.addSubItem(15, R.drawable.msg_clear, LocaleController.getString("ClearHistory", R.string.ClearHistory));
            }
            TLRPC.User user3 = this.currentUser;
            if (user3 == null || !user3.self) {
                this.muteItem = this.chatActionBarMenuPop.addSubItem(18, R.drawable.msg_mute, null);
            }
            if (ChatObject.isChannel(this.currentChat) && !this.currentChat.creator) {
                if (!ChatObject.isNotInChat(this.currentChat)) {
                    if (this.currentChat.megagroup) {
                        this.chatActionBarMenuPop.addSubItem(16, R.drawable.msg_leave, LocaleController.getString("DeleteAndExit", R.string.DeleteAndExit));
                    } else {
                        this.chatActionBarMenuPop.addSubItem(16, R.drawable.msg_leave, LocaleController.getString("LeaveChannelMenu", R.string.LeaveChannelMenu));
                    }
                }
            } else if (!ChatObject.isChannel(this.currentChat)) {
                if (this.currentChat != null) {
                    this.chatActionBarMenuPop.addSubItem(16, R.drawable.msg_leave, LocaleController.getString("DeleteAndExit", R.string.DeleteAndExit));
                } else {
                    this.chatActionBarMenuPop.addSubItem(16, R.drawable.msg_delete, LocaleController.getString("DeleteChatUser", R.string.DeleteChatUser));
                }
            }
            TLRPC.User user4 = this.currentUser;
            if (user4 != null && user4.self) {
                this.chatActionBarMenuPop.addSubItem(24, R.drawable.msg_home, LocaleController.getString("AddShortcut", R.string.AddShortcut));
            }
            TLRPC.User user5 = this.currentUser;
            if (user5 != null && this.currentEncryptedChat == null && user5.bot) {
                this.chatActionBarMenuPop.addSubItem(31, R.drawable.menu_settings, LocaleController.getString("BotSettings", R.string.BotSettings));
                this.chatActionBarMenuPop.addSubItem(30, R.drawable.menu_help, LocaleController.getString("BotHelp", R.string.BotHelp));
                updateBotButtons();
            }
        }
        this.actionBarHelper.update();
        updateTitleIcons();
        if (!this.inScheduleMode) {
            ActionBarMenuItem allowCloseAnimation = menu.addItem(14, R.drawable.ic_ab_other).setOverrideMenuClick(true).setAllowCloseAnimation(false);
            this.attachItem = allowCloseAnimation;
            allowCloseAnimation.setVisibility(8);
        }
        this.actionModeViews.clear();
        if (this.inPreviewMode) {
            this.headerItem.setAlpha(0.0f);
            this.attachItem.setAlpha(0.0f);
        }
        ActionBarMenu actionMode = this.actionBar.createActionMode();
        NumberTextView numberTextView = new NumberTextView(actionMode.getContext());
        this.selectedMessagesCountTextView = numberTextView;
        numberTextView.setTextSize(18);
        this.selectedMessagesCountTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.selectedMessagesCountTextView.setTextColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon));
        actionMode.addView(this.selectedMessagesCountTextView, LayoutHelper.createLinear(0, -1, 1.0f, 65, 0, 0, 0));
        this.selectedMessagesCountTextView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$QgcPjdSnunVfuKOSMpgdoKMRyEg
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ChatActivity.lambda$createView$4(view, motionEvent);
            }
        });
        if (this.currentEncryptedChat != null || isSysNotifyMessage().booleanValue()) {
            this.actionModeViews.add(actionMode.addItemWithWidth(22, R.drawable.msg_fave, AndroidUtilities.dp(54.0f), LocaleController.getString("AddToFavorites", R.string.AddToFavorites)));
            this.actionModeViews.add(actionMode.addItemWithWidth(10, R.drawable.msg_copy, AndroidUtilities.dp(54.0f), LocaleController.getString("Copy", R.string.Copy)));
        } else {
            this.actionModeViews.add(actionMode.addItemWithWidth(22, R.drawable.msg_fave, AndroidUtilities.dp(54.0f), LocaleController.getString("AddToFavorites", R.string.AddToFavorites)));
            this.actionModeViews.add(actionMode.addItemWithWidth(10, R.drawable.msg_copy, AndroidUtilities.dp(54.0f), LocaleController.getString("Copy", R.string.Copy)));
            this.actionModeViews.add(actionMode.addItemWithWidth(11, R.drawable.msg_forward, AndroidUtilities.dp(54.0f), LocaleController.getString("Forward", R.string.Forward)));
        }
        actionMode.getItem(10).setVisibility((this.currentEncryptedChat == null || this.selectedMessagesCanCopyIds[0].size() + this.selectedMessagesCanCopyIds[1].size() == 0) ? 8 : 0);
        actionMode.getItem(22).setVisibility(this.selectedMessagesCanStarIds[0].size() + this.selectedMessagesCanStarIds[1].size() != 0 ? 0 : 8);
        checkActionBarMenu();
        this.scrimPaint = new Paint() { // from class: im.uwrkaxlmjj.ui.ChatActivity.8
            @Override // android.graphics.Paint
            public void setAlpha(int a3) {
                super.setAlpha(a3);
                if (ChatActivity.this.fragmentView != null) {
                    ChatActivity.this.fragmentView.invalidate();
                }
            }
        };
        this.fragmentView = new AnonymousClass9(context);
        SizeNotifierFrameLayout sizeNotifierFrameLayout = (SizeNotifierFrameLayout) this.fragmentView;
        this.contentView = sizeNotifierFrameLayout;
        sizeNotifierFrameLayout.setBackgroundImage(Theme.getCachedWallpaper(), Theme.isWallpaperMotion());
        FrameLayout frameLayout = new FrameLayout(context);
        this.emptyViewContainer = frameLayout;
        frameLayout.setVisibility(4);
        this.contentView.addView(this.emptyViewContainer, LayoutHelper.createFrame(-1, -2, 17));
        this.emptyViewContainer.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$IIF-GbXsAT7yZZ2tFmpaAH8Qhjk
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ChatActivity.lambda$createView$5(view, motionEvent);
            }
        });
        if (this.currentEncryptedChat != null) {
            this.bigEmptyView = new ChatBigEmptyView(context, 0);
            if (this.currentEncryptedChat.admin_id == getUserConfig().getClientUserId()) {
                this.bigEmptyView.setStatusText(LocaleController.formatString("EncryptedPlaceholderTitleOutgoing", R.string.EncryptedPlaceholderTitleOutgoing, UserObject.getFirstName(this.currentUser)));
            } else {
                this.bigEmptyView.setStatusText(LocaleController.formatString("EncryptedPlaceholderTitleIncoming", R.string.EncryptedPlaceholderTitleIncoming, UserObject.getFirstName(this.currentUser)));
            }
            this.emptyViewContainer.addView(this.bigEmptyView, new FrameLayout.LayoutParams(-2, -2, 17));
        } else if (!this.inScheduleMode && (((user = this.currentUser) != null && user.self) || ((chat2 = this.currentChat) != null && chat2.creator))) {
            ChatBigEmptyView chatBigEmptyView = new ChatBigEmptyView(context, this.currentChat != null ? 1 : 2);
            this.bigEmptyView = chatBigEmptyView;
            this.emptyViewContainer.addView(chatBigEmptyView, new FrameLayout.LayoutParams(-2, -2, 17));
            if (this.currentChat != null) {
                this.bigEmptyView.setStatusText(AndroidUtilities.replaceTags(LocaleController.getString("GroupEmptyTitle1", R.string.GroupEmptyTitle1)));
            }
        } else {
            TextView textView = new TextView(context);
            this.emptyView = textView;
            if (this.inScheduleMode) {
                textView.setText(LocaleController.getString("NoScheduledMessages", R.string.NoScheduledMessages));
            } else {
                TLRPC.User user6 = this.currentUser;
                if (user6 != null && user6.id != 777000 && this.currentUser.id != 429000 && this.currentUser.id != 4244000 && MessagesController.isSupportUser(this.currentUser)) {
                    this.emptyView.setText(LocaleController.getString("GotAQuestion", R.string.GotAQuestion));
                } else {
                    this.emptyView.setText(LocaleController.getString("NoMessages", R.string.NoMessages));
                }
            }
            this.emptyView.setTextSize(1, 14.0f);
            this.emptyView.setGravity(17);
            this.emptyView.setTextColor(Theme.getColor(Theme.key_chat_serviceText));
            this.emptyView.setBackgroundResource(R.drawable.system);
            this.emptyView.getBackground().setColorFilter(Theme.colorFilter);
            this.emptyView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.emptyView.setPadding(AndroidUtilities.dp(10.0f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(3.0f));
            this.emptyViewContainer.addView(this.emptyView, new FrameLayout.LayoutParams(-2, -2, 17));
        }
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onDestroy();
            if (!this.chatActivityEnterView.isEditingMessage()) {
                oldMessage = this.chatActivityEnterView.getFieldText();
            } else {
                oldMessage = null;
            }
        } else {
            oldMessage = null;
        }
        MentionsAdapter mentionsAdapter = this.mentionsAdapter;
        if (mentionsAdapter != null) {
            mentionsAdapter.onDestroy();
        }
        this.chatListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.10
            private float endedTrackingX;
            private long lastReplyButtonAnimationTime;
            private long lastTrackingAnimationTime;
            private int lastWidth;
            private boolean maybeStartTracking;
            private float replyButtonProgress;
            private boolean slideAnimationInProgress;
            private ChatMessageCell slidingView;
            private boolean startedTracking;
            private int startedTrackingPointerId;
            private int startedTrackingX;
            private int startedTrackingY;
            private float trackAnimationProgress;
            private boolean wasTrackingVibrate;
            ArrayList<ChatMessageCell> drawTimeAfter = new ArrayList<>();
            ArrayList<ChatMessageCell> drawNamesAfter = new ArrayList<>();
            ArrayList<ChatMessageCell> drawCaptionAfter = new ArrayList<>();

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                super.onLayout(changed, l, t, r, b);
                if (this.lastWidth != r - l) {
                    this.lastWidth = r - l;
                    if (ChatActivity.this.noSoundHintView != null) {
                        ChatActivity.this.noSoundHintView.hide();
                    }
                    if (ChatActivity.this.forwardHintView != null) {
                        ChatActivity.this.forwardHintView.hide();
                    }
                    if (ChatActivity.this.slowModeHint != null) {
                        ChatActivity.this.slowModeHint.hide();
                    }
                }
                ChatActivity.this.forceScrollToTop = false;
                if (ChatActivity.this.chatAdapter.isBot) {
                    int childCount = getChildCount();
                    for (int a3 = 0; a3 < childCount; a3++) {
                        View child = getChildAt(a3);
                        if (child instanceof BotHelpCell) {
                            int height = b - t;
                            int top = (height / 2) - (child.getMeasuredHeight() / 2);
                            if (child.getTop() > top) {
                                child.layout(0, top, r - l, child.getMeasuredHeight() + top);
                                return;
                            }
                            return;
                        }
                    }
                }
            }

            private void setGroupTranslationX(ChatMessageCell view, float dx) {
                MessageObject.GroupedMessages group = view.getCurrentMessagesGroup();
                if (group == null) {
                    return;
                }
                int count = getChildCount();
                for (int a3 = 0; a3 < count; a3++) {
                    View child = getChildAt(a3);
                    if (child != this && (child instanceof ChatMessageCell)) {
                        ChatMessageCell cell = (ChatMessageCell) child;
                        if (cell.getCurrentMessagesGroup() == group) {
                            cell.setTranslationX(dx);
                            cell.invalidate();
                        }
                    }
                }
                invalidate();
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.ViewParent
            public boolean requestChildRectangleOnScreen(View child, Rect rect, boolean immediate) {
                if (ChatActivity.this.scrimPopupWindow != null) {
                    return false;
                }
                return super.requestChildRectangleOnScreen(child, rect, immediate);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent e2) {
                boolean result = super.onInterceptTouchEvent(e2);
                if (ChatActivity.this.actionBar.isActionModeShowed()) {
                    return result;
                }
                processTouchEvent(e2);
                return result;
            }

            private void drawReplyButton(Canvas canvas) {
                float scale;
                int alpha;
                ChatMessageCell chatMessageCell = this.slidingView;
                if (chatMessageCell == null) {
                    return;
                }
                float translationX = chatMessageCell.getTranslationX();
                long newTime = System.currentTimeMillis();
                long dt = Math.min(17L, newTime - this.lastReplyButtonAnimationTime);
                this.lastReplyButtonAnimationTime = newTime;
                boolean z2 = translationX <= ((float) (-AndroidUtilities.dp(50.0f)));
                boolean showing = z2;
                if (z2) {
                    float f = this.replyButtonProgress;
                    if (f < 1.0f) {
                        float f2 = f + (dt / 180.0f);
                        this.replyButtonProgress = f2;
                        if (f2 > 1.0f) {
                            this.replyButtonProgress = 1.0f;
                        } else {
                            invalidate();
                        }
                    }
                } else {
                    float f3 = this.replyButtonProgress;
                    if (f3 > 0.0f) {
                        float f4 = f3 - (dt / 180.0f);
                        this.replyButtonProgress = f4;
                        if (f4 < 0.0f) {
                            this.replyButtonProgress = 0.0f;
                        } else {
                            invalidate();
                        }
                    }
                }
                if (showing) {
                    float scale2 = this.replyButtonProgress;
                    if (scale2 <= 0.8f) {
                        scale = (scale2 / 0.8f) * 1.2f;
                    } else {
                        scale = 1.2f - (((scale2 - 0.8f) / 0.2f) * 0.2f);
                    }
                    alpha = (int) Math.min(255.0f, (this.replyButtonProgress / 0.8f) * 255.0f);
                } else {
                    scale = this.replyButtonProgress;
                    alpha = (int) Math.min(255.0f, this.replyButtonProgress * 255.0f);
                }
                Theme.chat_shareDrawable.setAlpha(alpha);
                Theme.chat_replyIconDrawable.setAlpha(alpha);
                float x = getMeasuredWidth() + (this.slidingView.getTranslationX() / 2.0f);
                float y = this.slidingView.getTop() + (this.slidingView.getMeasuredHeight() / 2);
                if (!Theme.isCustomTheme() || Theme.hasThemeKey(Theme.key_chat_shareBackground)) {
                    Theme.chat_shareDrawable.setColorFilter(Theme.getShareColorFilter(Theme.getColor(Theme.key_chat_shareBackground), false));
                } else {
                    Theme.chat_shareDrawable.setColorFilter(Theme.colorFilter2);
                }
                Theme.chat_shareDrawable.setBounds((int) (x - (AndroidUtilities.dp(14.0f) * scale)), (int) (y - (AndroidUtilities.dp(14.0f) * scale)), (int) ((AndroidUtilities.dp(14.0f) * scale) + x), (int) ((AndroidUtilities.dp(14.0f) * scale) + y));
                Theme.chat_shareDrawable.draw(canvas);
                Theme.chat_replyIconDrawable.setBounds((int) (x - (AndroidUtilities.dp(7.0f) * scale)), (int) (y - (AndroidUtilities.dp(6.0f) * scale)), (int) ((AndroidUtilities.dp(7.0f) * scale) + x), (int) ((AndroidUtilities.dp(5.0f) * scale) + y));
                Theme.chat_replyIconDrawable.draw(canvas);
                Theme.chat_shareDrawable.setAlpha(255);
                Theme.chat_replyIconDrawable.setAlpha(255);
            }

            private void processTouchEvent(MotionEvent e2) {
                ChatActivity.this.wasManualScroll = true;
                if (e2.getAction() != 0 || this.startedTracking || this.maybeStartTracking) {
                    if (this.slidingView != null && e2.getAction() == 2 && e2.getPointerId(0) == this.startedTrackingPointerId) {
                        int dx = Math.max(AndroidUtilities.dp(-80.0f), Math.min(0, (int) (e2.getX() - this.startedTrackingX)));
                        int dy = Math.abs(((int) e2.getY()) - this.startedTrackingY);
                        if (getScrollState() == 0 && this.maybeStartTracking && !this.startedTracking && dx <= (-AndroidUtilities.getPixelsInCM(0.4f, true)) && Math.abs(dx) / 3 > dy) {
                            MotionEvent event = MotionEvent.obtain(0L, 0L, 3, 0.0f, 0.0f, 0);
                            this.slidingView.onTouchEvent(event);
                            super.onInterceptTouchEvent(event);
                            event.recycle();
                            ChatActivity.this.chatLayoutManager.setCanScrollVertically(false);
                            this.maybeStartTracking = false;
                            this.startedTracking = true;
                            this.startedTrackingX = (int) e2.getX();
                            if (getParent() != null) {
                                getParent().requestDisallowInterceptTouchEvent(true);
                                return;
                            }
                            return;
                        }
                        if (this.startedTracking) {
                            if (Math.abs(dx) >= AndroidUtilities.dp(50.0f)) {
                                if (!this.wasTrackingVibrate) {
                                    try {
                                        performHapticFeedback(3, 2);
                                    } catch (Exception e3) {
                                    }
                                    this.wasTrackingVibrate = true;
                                }
                            } else {
                                this.wasTrackingVibrate = false;
                            }
                            this.slidingView.setTranslationX(dx);
                            MessageObject messageObject = this.slidingView.getMessageObject();
                            if (messageObject.isRoundVideo() || messageObject.isVideo()) {
                                ChatActivity.this.updateTextureViewPosition(false);
                            }
                            setGroupTranslationX(this.slidingView, dx);
                            invalidate();
                            return;
                        }
                        return;
                    }
                    if (this.slidingView == null || e2.getPointerId(0) != this.startedTrackingPointerId) {
                        return;
                    }
                    if (e2.getAction() == 3 || e2.getAction() == 1 || e2.getAction() == 6) {
                        if (Math.abs(this.slidingView.getTranslationX()) >= AndroidUtilities.dp(50.0f)) {
                            ChatActivity.this.showFieldPanelForReply(this.slidingView.getMessageObject());
                        }
                        this.endedTrackingX = this.slidingView.getTranslationX();
                        this.lastTrackingAnimationTime = System.currentTimeMillis();
                        this.trackAnimationProgress = 0.0f;
                        invalidate();
                        this.maybeStartTracking = false;
                        this.startedTracking = false;
                        ChatActivity.this.chatLayoutManager.setCanScrollVertically(true);
                        return;
                    }
                    return;
                }
                View view = getPressedChildView();
                if (view instanceof ChatMessageCell) {
                    ChatMessageCell chatMessageCell = (ChatMessageCell) view;
                    this.slidingView = chatMessageCell;
                    MessageObject message = chatMessageCell.getMessageObject();
                    if (ChatActivity.this.inScheduleMode || ((ChatActivity.this.currentEncryptedChat != null && AndroidUtilities.getPeerLayerVersion(ChatActivity.this.currentEncryptedChat.layer) < 46) || ((ChatActivity.this.getMessageType(message) == 1 && (message.getDialogId() == ChatActivity.this.mergeDialogId || message.needDrawBluredPreview())) || ((ChatActivity.this.currentEncryptedChat == null && message.getId() < 0) || message.type == 101 || message.type == 102 || message.type == 105 || ((ChatActivity.this.bottomOverlayChat != null && ChatActivity.this.bottomOverlayChat.getVisibility() == 0) || (ChatActivity.this.currentChat != null && (ChatObject.isNotInChat(ChatActivity.this.currentChat) || ((ChatObject.isChannel(ChatActivity.this.currentChat) && !ChatObject.canPost(ChatActivity.this.currentChat) && !ChatActivity.this.currentChat.megagroup) || !ChatObject.canSendMessages(ChatActivity.this.currentChat))))))))) {
                        this.slidingView = null;
                        return;
                    }
                    this.startedTrackingPointerId = e2.getPointerId(0);
                    this.maybeStartTracking = true;
                    this.startedTrackingX = (int) e2.getX();
                    this.startedTrackingY = (int) e2.getY();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent e2) {
                boolean result = super.onTouchEvent(e2);
                if (ChatActivity.this.actionBar.isActionModeShowed()) {
                    return result;
                }
                processTouchEvent(e2);
                return this.startedTracking || result;
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.ViewParent
            public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
                super.requestDisallowInterceptTouchEvent(disallowIntercept);
                ChatMessageCell chatMessageCell = this.slidingView;
                if (chatMessageCell != null) {
                    this.endedTrackingX = chatMessageCell.getTranslationX();
                    this.lastTrackingAnimationTime = System.currentTimeMillis();
                    this.trackAnimationProgress = 0.0f;
                    invalidate();
                    this.maybeStartTracking = false;
                    this.startedTracking = false;
                    ChatActivity.this.chatLayoutManager.setCanScrollVertically(true);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView
            protected void onChildPressed(View child, boolean pressed) {
                MessageObject.GroupedMessages groupedMessages;
                super.onChildPressed(child, pressed);
                if ((child instanceof ChatMessageCell) && (groupedMessages = ((ChatMessageCell) child).getCurrentMessagesGroup()) != null) {
                    int count = getChildCount();
                    for (int a3 = 0; a3 < count; a3++) {
                        View item = getChildAt(a3);
                        if (item != child && (item instanceof ChatMessageCell)) {
                            ChatMessageCell cell = (ChatMessageCell) item;
                            if (((ChatMessageCell) item).getCurrentMessagesGroup() == groupedMessages) {
                                cell.setPressed(pressed);
                            }
                        }
                    }
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public void onDraw(Canvas c) {
                super.onDraw(c);
                ChatMessageCell chatMessageCell = this.slidingView;
                if (chatMessageCell != null) {
                    float translationX = chatMessageCell.getTranslationX();
                    if (!this.maybeStartTracking && !this.startedTracking && this.endedTrackingX != 0.0f && translationX != 0.0f) {
                        long newTime = System.currentTimeMillis();
                        long dt = newTime - this.lastTrackingAnimationTime;
                        float f = this.trackAnimationProgress + (dt / 180.0f);
                        this.trackAnimationProgress = f;
                        if (f > 1.0f) {
                            this.trackAnimationProgress = 1.0f;
                        }
                        this.lastTrackingAnimationTime = newTime;
                        float translationX2 = this.endedTrackingX * (1.0f - AndroidUtilities.decelerateInterpolator.getInterpolation(this.trackAnimationProgress));
                        if (translationX2 == 0.0f) {
                            this.endedTrackingX = 0.0f;
                        }
                        setGroupTranslationX(this.slidingView, translationX2);
                        this.slidingView.setTranslationX(translationX2);
                        MessageObject messageObject = this.slidingView.getMessageObject();
                        if (messageObject.isRoundVideo() || messageObject.isVideo()) {
                            ChatActivity.this.updateTextureViewPosition(false);
                        }
                        invalidate();
                    }
                    drawReplyButton(c);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.ViewGroup, android.view.View
            protected void dispatchDraw(Canvas canvas) {
                ChatActivity.this.drawLaterRoundProgressCell = null;
                int count = getChildCount();
                for (int a3 = 0; a3 < count; a3++) {
                    View child = getChildAt(a3);
                    if (child instanceof ChatMessageCell) {
                        ChatMessageCell cell = (ChatMessageCell) child;
                        MessageObject.GroupedMessagePosition position = cell.getCurrentPosition();
                        if (cell.isDrawingSelectionBackground() && (position == null || (position.flags & 2) != 0)) {
                            int color = Theme.getColor(Theme.key_chat_selectedBackground);
                            int alpha = Color.alpha(color);
                            Theme.chat_replyLinePaint.setColor(Theme.getColor(Theme.key_chat_selectedBackground));
                            Theme.chat_replyLinePaint.setAlpha((int) (alpha * cell.getHightlightAlpha()));
                            canvas.drawRect(0.0f, cell.getTop(), getMeasuredWidth(), cell.getBottom(), Theme.chat_replyLinePaint);
                        }
                    }
                }
                super.dispatchDraw(canvas);
            }

            /* JADX WARN: Code restructure failed: missing block: B:192:0x03e6, code lost:
            
                r7 = r19;
             */
            /* JADX WARN: Removed duplicated region for block: B:198:0x03fe  */
            /* JADX WARN: Removed duplicated region for block: B:201:0x0409  */
            /* JADX WARN: Removed duplicated region for block: B:204:0x0424  */
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public boolean drawChild(android.graphics.Canvas r31, android.view.View r32, long r33) {
                /*
                    Method dump skipped, instruction units count: 1076
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.AnonymousClass10.drawChild(android.graphics.Canvas, android.view.View, long):boolean");
            }

            @Override // android.view.View
            public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
                AccessibilityNodeInfo.CollectionInfo collection;
                if (ChatActivity.this.currentEncryptedChat != null) {
                    return;
                }
                super.onInitializeAccessibilityNodeInfo(info);
                if (Build.VERSION.SDK_INT >= 19 && (collection = info.getCollectionInfo()) != null) {
                    info.setCollectionInfo(AccessibilityNodeInfo.CollectionInfo.obtain(collection.getRowCount(), 1, false));
                }
            }

            @Override // android.view.View
            public AccessibilityNodeInfo createAccessibilityNodeInfo() {
                if (ChatActivity.this.currentEncryptedChat != null) {
                    return null;
                }
                return super.createAccessibilityNodeInfo();
            }
        };
        if (this.currentEncryptedChat != null && Build.VERSION.SDK_INT >= 19) {
            this.chatListView.setImportantForAccessibility(4);
        }
        this.chatListView.setInstantClick(true);
        this.chatListView.setDisableHighlightState(true);
        this.chatListView.setTag(1);
        this.chatListView.setVerticalScrollBarEnabled(true);
        RecyclerListView recyclerListView = this.chatListView;
        ChatActivityAdapter chatActivityAdapter = new ChatActivityAdapter(context);
        this.chatAdapter = chatActivityAdapter;
        recyclerListView.setAdapter(chatActivityAdapter);
        this.chatListView.setClipToPadding(false);
        this.chatListView.setPadding(0, AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(3.0f));
        this.chatListView.setItemAnimator(null);
        this.chatListView.setLayoutAnimation(null);
        CharSequence oldMessage2 = oldMessage;
        GridLayoutManagerFixed gridLayoutManagerFixed = new GridLayoutManagerFixed(context, 1000, 1, true) { // from class: im.uwrkaxlmjj.ui.ChatActivity.11
            @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }

            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public void smoothScrollToPosition(RecyclerView recyclerView, RecyclerView.State state, int position) {
                LinearSmoothScrollerMiddle linearSmoothScroller = new LinearSmoothScrollerMiddle(recyclerView.getContext());
                linearSmoothScroller.setTargetPosition(position);
                startSmoothScroll(linearSmoothScroller);
            }

            @Override // androidx.recyclerview.widget.GridLayoutManagerFixed
            public boolean shouldLayoutChildFromOpositeSide(View child) {
                if (child instanceof ChatMessageCell) {
                    return !((ChatMessageCell) child).getMessageObject().isOutOwner();
                }
                return false;
            }

            @Override // androidx.recyclerview.widget.GridLayoutManagerFixed
            protected boolean hasSiblingChild(int position) {
                int index;
                if (position >= ChatActivity.this.chatAdapter.messagesStartRow && position < ChatActivity.this.chatAdapter.messagesEndRow && (index = position - ChatActivity.this.chatAdapter.messagesStartRow) >= 0 && index < ChatActivity.this.messages.size()) {
                    MessageObject message = ChatActivity.this.messages.get(index);
                    MessageObject.GroupedMessages group = ChatActivity.this.getValidGroupedMessage(message);
                    if (group != null) {
                        MessageObject.GroupedMessagePosition pos = group.positions.get(message);
                        if (pos.minX == pos.maxX || pos.minY != pos.maxY || pos.minY == 0) {
                            return false;
                        }
                        int count = group.posArray.size();
                        for (int a3 = 0; a3 < count; a3++) {
                            MessageObject.GroupedMessagePosition p = group.posArray.get(a3);
                            if (p != pos && p.minY <= pos.minY && p.maxY >= pos.minY) {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
        };
        this.chatLayoutManager = gridLayoutManagerFixed;
        gridLayoutManagerFixed.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.ChatActivity.12
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                int idx;
                if (position >= ChatActivity.this.chatAdapter.messagesStartRow && position < ChatActivity.this.chatAdapter.messagesEndRow && (idx = position - ChatActivity.this.chatAdapter.messagesStartRow) >= 0 && idx < ChatActivity.this.messages.size()) {
                    MessageObject message = ChatActivity.this.messages.get(idx);
                    MessageObject.GroupedMessages groupedMessages = ChatActivity.this.getValidGroupedMessage(message);
                    if (groupedMessages != null) {
                        return groupedMessages.positions.get(message).spanSize;
                    }
                    return 1000;
                }
                return 1000;
            }
        });
        this.chatListView.setLayoutManager(this.chatLayoutManager);
        this.chatListView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.ChatActivity.13
            @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
            public void getItemOffsets(Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
                ChatMessageCell cell;
                MessageObject.GroupedMessages group;
                MessageObject.GroupedMessagePosition position;
                outRect.bottom = 0;
                if ((view instanceof ChatMessageCell) && (group = (cell = (ChatMessageCell) view).getCurrentMessagesGroup()) != null && (position = cell.getCurrentPosition()) != null && position.siblingHeights != null) {
                    float maxHeight = Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.5f;
                    int h = cell.getCaptionHeight();
                    for (int a3 = 0; a3 < position.siblingHeights.length; a3++) {
                        h += (int) Math.ceil(position.siblingHeights[a3] * maxHeight);
                    }
                    int a4 = position.maxY;
                    int h2 = h + ((a4 - position.minY) * Math.round(AndroidUtilities.density * 7.0f));
                    int count = group.posArray.size();
                    int a5 = 0;
                    while (true) {
                        if (a5 >= count) {
                            break;
                        }
                        MessageObject.GroupedMessagePosition pos = group.posArray.get(a5);
                        if (pos.minY != position.minY || ((pos.minX == position.minX && pos.maxX == position.maxX && pos.minY == position.minY && pos.maxY == position.maxY) || pos.minY != position.minY)) {
                            a5++;
                        } else {
                            h2 -= ((int) Math.ceil(pos.ph * maxHeight)) - AndroidUtilities.dp(4.0f);
                            break;
                        }
                    }
                    int a6 = -h2;
                    outRect.bottom = a6;
                }
            }
        });
        this.contentView.addView(this.chatListView, LayoutHelper.createFrame(-1, -1.0f));
        this.chatListView.setOnItemLongClickListener(this.onItemLongClickListener);
        this.chatListView.setOnItemClickListener(this.onItemClickListener);
        this.chatListView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.ChatActivity.14
            private boolean scrollUp;
            private float totalDy = 0.0f;
            private final int scrollValue = AndroidUtilities.dp(100.0f);

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 0) {
                    ChatActivity.this.scrollingFloatingDate = false;
                    ChatActivity.this.scrollingChatListView = false;
                    ChatActivity.this.checkTextureViewPosition = false;
                    ChatActivity.this.hideFloatingDateView(true);
                    ChatActivity.this.checkAutoDownloadMessages(this.scrollUp);
                    if (SharedConfig.getDevicePerfomanceClass() == 0) {
                        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
                        return;
                    }
                    return;
                }
                if (newState == 2) {
                    ChatActivity.this.wasManualScroll = true;
                    ChatActivity.this.scrollingChatListView = true;
                } else if (newState == 1) {
                    ChatActivity.this.wasManualScroll = true;
                    ChatActivity.this.scrollingFloatingDate = true;
                    ChatActivity.this.checkTextureViewPosition = true;
                    ChatActivity.this.scrollingChatListView = true;
                }
                if (SharedConfig.getDevicePerfomanceClass() == 0) {
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                ChatActivity.this.chatListView.invalidate();
                this.scrollUp = dy < 0;
                if (!ChatActivity.this.wasManualScroll && dy != 0) {
                    ChatActivity.this.wasManualScroll = true;
                }
                if (dy != 0) {
                    if (ChatActivity.this.noSoundHintView != null) {
                        ChatActivity.this.noSoundHintView.hide();
                    }
                    if (ChatActivity.this.forwardHintView != null) {
                        ChatActivity.this.forwardHintView.hide();
                    }
                }
                if (dy != 0 && ChatActivity.this.scrollingFloatingDate && !ChatActivity.this.currentFloatingTopIsNotMessage) {
                    if (ChatActivity.this.highlightMessageId != Integer.MAX_VALUE) {
                        ChatActivity.this.removeSelectedMessageHighlight();
                        ChatActivity.this.updateVisibleRows();
                    }
                    ChatActivity.this.showFloatingDateView(true);
                }
                ChatActivity.this.checkScrollForLoad(true);
                int firstVisibleItem = ChatActivity.this.chatLayoutManager.findFirstVisibleItemPosition();
                if (firstVisibleItem != -1) {
                    ChatActivity.this.chatAdapter.getItemCount();
                    if (firstVisibleItem == 0 && ChatActivity.this.forwardEndReached[0]) {
                        ChatActivity.this.showPagedownButton(false, true);
                    } else if (dy > 0) {
                        if (ChatActivity.this.pagedownButton.getTag() == null) {
                            float f = this.totalDy + dy;
                            this.totalDy = f;
                            if (f > this.scrollValue) {
                                this.totalDy = 0.0f;
                                ChatActivity.this.showPagedownButton(true, true);
                                ChatActivity.this.pagedownButtonShowedByScroll = true;
                            }
                        }
                    } else if (ChatActivity.this.pagedownButtonShowedByScroll && ChatActivity.this.pagedownButton.getTag() != null) {
                        float f2 = this.totalDy + dy;
                        this.totalDy = f2;
                        if (f2 < (-this.scrollValue)) {
                            ChatActivity.this.showPagedownButton(false, true);
                            this.totalDy = 0.0f;
                        }
                    }
                }
                ChatActivity.this.updateMessagesVisiblePart(true);
            }
        });
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.progressView = frameLayout2;
        frameLayout2.setVisibility(4);
        this.contentView.addView(this.progressView, LayoutHelper.createFrame(-1, -1, 51));
        View view = new View(context);
        this.progressView2 = view;
        view.setBackgroundResource(R.drawable.system_loader);
        this.progressView2.getBackground().setColorFilter(Theme.colorFilter);
        this.progressView.addView(this.progressView2, LayoutHelper.createFrame(36, 36, 17));
        RadialProgressView radialProgressView = new RadialProgressView(context);
        this.progressBar = radialProgressView;
        radialProgressView.setSize(AndroidUtilities.dp(28.0f));
        this.progressBar.setProgressColor(Theme.getColor(Theme.key_chat_serviceText));
        this.progressView.addView(this.progressBar, LayoutHelper.createFrame(32, 32, 17));
        ChatActionCell chatActionCell = new ChatActionCell(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.15
            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (getAlpha() == 0.0f || ChatActivity.this.actionBar.isActionModeShowed()) {
                    return false;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (getAlpha() == 0.0f || ChatActivity.this.actionBar.isActionModeShowed()) {
                    return false;
                }
                return super.onTouchEvent(event);
            }
        };
        this.floatingDateView = chatActionCell;
        chatActionCell.setAlpha(0.0f);
        this.contentView.addView(this.floatingDateView, LayoutHelper.createFrame(-2.0f, -2.0f, 49, 0.0f, 4.0f, 0.0f, 0.0f));
        this.floatingDateView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$5e8qTaz-0Wgxocx7EDJDQDSY-3k
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$createView$6$ChatActivity(view2);
            }
        });
        if (this.currentEncryptedChat == null) {
            FrameLayout frameLayout3 = new FrameLayout(context);
            this.pinnedMessageView = frameLayout3;
            frameLayout3.setTag(1);
            this.pinnedMessageView.setTranslationY(-AndroidUtilities.dp(50.0f));
            this.pinnedMessageView.setVisibility(8);
            this.pinnedMessageView.setBackgroundResource(R.drawable.blockpanel);
            this.pinnedMessageView.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelBackground), PorterDuff.Mode.MULTIPLY));
            this.contentView.addView(this.pinnedMessageView, LayoutHelper.createFrame(-1, 50, 51));
            this.pinnedMessageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$M2ZaOIZsHfUfrGuDM2-GRUOFgaU
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$createView$7$ChatActivity(view2);
                }
            });
            FrameLayout frameLayout4 = new FrameLayout(context);
            this.pinnedLiveMessageView = frameLayout4;
            frameLayout4.setTag(2);
            this.pinnedLiveMessageView.setTranslationY(-AndroidUtilities.dp(50.0f));
            this.pinnedLiveMessageView.setVisibility(8);
            this.pinnedLiveMessageView.setBackgroundResource(R.drawable.blockpanel);
            TextView tvLine = new TextView(context);
            tvLine.setBackgroundColor(Color.parseColor("#CFD0D1"));
            this.pinnedLiveMessageView.addView(tvLine, LayoutHelper.createFrame(-1.0f, 0.5f, 51));
            this.pinnedLiveMessageView.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelBackground), PorterDuff.Mode.MULTIPLY));
            this.contentView.addView(this.pinnedLiveMessageView, LayoutHelper.createFrame(-1, 50, 51));
            this.pinnedLiveMessageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$h_3uh3LGwVGW1lA7K4ZoAIbVdc4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    ChatActivity.lambda$createView$8(view2);
                }
            });
            View view2 = new View(context);
            this.pinnedLineView = view2;
            view2.setBackgroundColor(Theme.getColor(Theme.key_chat_topPanelLine));
            this.pinnedMessageView.addView(this.pinnedLineView, LayoutHelper.createFrame(2.0f, 32.0f, 51, 8.0f, 8.0f, 0.0f, 0.0f));
            BackupImageView backupImageView = new BackupImageView(context);
            this.pinnedMessageImageView = backupImageView;
            this.pinnedMessageView.addView(backupImageView, LayoutHelper.createFrame(32.0f, 32.0f, 51, 17.0f, 8.0f, 0.0f, 0.0f));
            SimpleTextView simpleTextView = new SimpleTextView(context);
            this.pinnedMessageNameTextView = simpleTextView;
            simpleTextView.setTextSize(14);
            this.pinnedMessageNameTextView.setTextColor(Theme.getColor(Theme.key_chat_topPanelTitle));
            this.pinnedMessageNameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.pinnedMessageView.addView(this.pinnedMessageNameTextView, LayoutHelper.createFrame(-1.0f, AndroidUtilities.dp(18.0f), 51, 18.0f, 7.3f, 40.0f, 0.0f));
            SimpleTextView simpleTextView2 = new SimpleTextView(context);
            this.pinnedLiveMessageNameTextView = simpleTextView2;
            simpleTextView2.setTextSize(14);
            this.pinnedLiveMessageNameTextView.setTextColor(Theme.getColor(Theme.key_chat_topPanelTitle));
            this.pinnedLiveMessageNameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.pinnedLiveMessageView.addView(this.pinnedLiveMessageNameTextView, LayoutHelper.createFrame(-1.0f, AndroidUtilities.dp(18.0f), 51, 18.0f, 7.3f, 40.0f, 0.0f));
            SimpleTextView simpleTextView3 = new SimpleTextView(context);
            this.pinnedMessageTextView = simpleTextView3;
            simpleTextView3.setTextSize(14);
            this.pinnedMessageTextView.setTextColor(Theme.getColor(Theme.key_chat_topPanelMessage));
            this.pinnedMessageView.addView(this.pinnedMessageTextView, LayoutHelper.createFrame(-1.0f, AndroidUtilities.dp(18.0f), 51, 18.0f, 25.3f, 40.0f, 0.0f));
            SimpleTextView simpleTextView4 = new SimpleTextView(context);
            this.pinnedLiveMessageTextView = simpleTextView4;
            simpleTextView4.setTextSize(14);
            this.pinnedLiveMessageTextView.setTextColor(Theme.getColor(Theme.key_chat_topPanelMessage));
            this.pinnedLiveMessageView.addView(this.pinnedLiveMessageTextView, LayoutHelper.createFrame(-1.0f, AndroidUtilities.dp(18.0f), 51, 18.0f, 25.3f, 40.0f, 0.0f));
            ImageView imageView = new ImageView(context);
            this.closePinned = imageView;
            imageView.setImageResource(R.drawable.miniplayer_close);
            this.closePinned.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelClose), PorterDuff.Mode.MULTIPLY));
            this.closePinned.setScaleType(ImageView.ScaleType.CENTER);
            this.closePinned.setContentDescription(LocaleController.getString("Close", R.string.Close));
            this.pinnedMessageView.addView(this.closePinned, LayoutHelper.createFrame(36, 48, 53));
            this.closePinned.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$glvFVc2tPYkaJ27xL64uE9p4dT4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view3) {
                    this.f$0.lambda$createView$10$ChatActivity(view3);
                }
            });
            ImageView imageView2 = new ImageView(context);
            this.closeLivePinned = imageView2;
            imageView2.setImageResource(R.drawable.miniplayer_close);
            this.closeLivePinned.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelClose), PorterDuff.Mode.MULTIPLY));
            this.closeLivePinned.setScaleType(ImageView.ScaleType.CENTER);
            this.closeLivePinned.setContentDescription(LocaleController.getString("Close", R.string.Close));
            this.pinnedLiveMessageView.addView(this.closeLivePinned, LayoutHelper.createFrame(36, 48, 53));
            this.closeLivePinned.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$UBQUGWsCEAfyVWZwFjwFMq21Vqc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view3) {
                    this.f$0.lambda$createView$11$ChatActivity(view3);
                }
            });
        }
        FrameLayout frameLayout5 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.16
            private boolean ignoreLayout;

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int width = View.MeasureSpec.getSize(widthMeasureSpec);
                if (ChatActivity.this.addToContactsButton != null && ChatActivity.this.addToContactsButton.getVisibility() == 0 && ChatActivity.this.reportSpamButton != null && ChatActivity.this.reportSpamButton.getVisibility() == 0) {
                    width = (width - AndroidUtilities.dp(31.0f)) / 2;
                }
                this.ignoreLayout = true;
                if (ChatActivity.this.reportSpamButton != null && ChatActivity.this.reportSpamButton.getVisibility() == 0) {
                    FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ChatActivity.this.reportSpamButton.getLayoutParams();
                    layoutParams.width = width;
                    if (ChatActivity.this.addToContactsButton == null || ChatActivity.this.addToContactsButton.getVisibility() != 0) {
                        ChatActivity.this.reportSpamButton.setPadding(AndroidUtilities.dp(48.0f), 0, AndroidUtilities.dp(48.0f), 0);
                        layoutParams.leftMargin = 0;
                    } else {
                        ChatActivity.this.reportSpamButton.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(19.0f), 0);
                        layoutParams.leftMargin = width;
                    }
                }
                if (ChatActivity.this.addToContactsButton != null && ChatActivity.this.addToContactsButton.getVisibility() == 0) {
                    FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) ChatActivity.this.addToContactsButton.getLayoutParams();
                    layoutParams2.width = width;
                    if (ChatActivity.this.reportSpamButton == null || ChatActivity.this.reportSpamButton.getVisibility() != 0) {
                        ChatActivity.this.addToContactsButton.setPadding(AndroidUtilities.dp(48.0f), 0, AndroidUtilities.dp(48.0f), 0);
                        layoutParams2.leftMargin = 0;
                    } else {
                        ChatActivity.this.addToContactsButton.setPadding(AndroidUtilities.dp(11.0f), 0, AndroidUtilities.dp(4.0f), 0);
                    }
                }
                this.ignoreLayout = false;
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.topChatPanelView = frameLayout5;
        frameLayout5.setTag(1);
        this.topChatPanelView.setTranslationY(-AndroidUtilities.dp(50.0f));
        this.topChatPanelView.setVisibility(8);
        this.topChatPanelView.setBackgroundResource(R.drawable.blockpanel);
        this.topChatPanelView.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelBackground), PorterDuff.Mode.MULTIPLY));
        this.contentView.addView(this.topChatPanelView, LayoutHelper.createFrame(-1, 50, 51));
        TextView textView2 = new TextView(context);
        this.reportSpamButton = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_chat_reportSpam));
        this.reportSpamButton.setTag(Theme.key_chat_reportSpam);
        this.reportSpamButton.setTextSize(1, 14.0f);
        this.reportSpamButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.reportSpamButton.setSingleLine(true);
        this.reportSpamButton.setMaxLines(1);
        this.reportSpamButton.setGravity(17);
        this.topChatPanelView.addView(this.reportSpamButton, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, AndroidUtilities.dp(1.0f)));
        this.reportSpamButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$4CpkWuj6ogFE0Pt7o5H-5agNJuk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$13$ChatActivity(view3);
            }
        });
        TextView textView3 = new TextView(context);
        this.addToContactsButton = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_chat_addContact));
        this.addToContactsButton.setVisibility(8);
        this.addToContactsButton.setTextSize(1, 14.0f);
        this.addToContactsButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.addToContactsButton.setSingleLine(true);
        this.addToContactsButton.setMaxLines(1);
        this.addToContactsButton.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
        this.addToContactsButton.setGravity(17);
        this.topChatPanelView.addView(this.addToContactsButton, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, AndroidUtilities.dp(1.0f)));
        this.addToContactsButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ax9qvswSDVSvhqVsuE2cCxlHf0c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$14$ChatActivity(view3);
            }
        });
        ImageView imageView3 = new ImageView(context);
        this.closeReportSpam = imageView3;
        imageView3.setImageResource(R.drawable.miniplayer_close);
        this.closeReportSpam.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelClose), PorterDuff.Mode.MULTIPLY));
        this.closeReportSpam.setScaleType(ImageView.ScaleType.CENTER);
        this.topChatPanelView.addView(this.closeReportSpam, LayoutHelper.createFrame(48, 48, 53));
        this.closeReportSpam.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ngAt_9ADTxACJcDndRqqTpV9G2w
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$15$ChatActivity(view3);
            }
        });
        FrameLayout frameLayout6 = new FrameLayout(context);
        this.alertView = frameLayout6;
        frameLayout6.setTag(1);
        this.alertView.setTranslationY(-AndroidUtilities.dp(50.0f));
        this.alertView.setVisibility(8);
        this.alertView.setBackgroundResource(R.drawable.blockpanel);
        this.alertView.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_topPanelBackground), PorterDuff.Mode.MULTIPLY));
        this.contentView.addView(this.alertView, LayoutHelper.createFrame(-1, 50, 51));
        TextView textView4 = new TextView(context);
        this.alertNameTextView = textView4;
        textView4.setTextSize(1, 14.0f);
        this.alertNameTextView.setTextColor(Theme.getColor(Theme.key_chat_topPanelTitle));
        this.alertNameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.alertNameTextView.setSingleLine(true);
        this.alertNameTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.alertNameTextView.setMaxLines(1);
        this.alertView.addView(this.alertNameTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 8.0f, 5.0f, 8.0f, 0.0f));
        TextView textView5 = new TextView(context);
        this.alertTextView = textView5;
        textView5.setTextSize(1, 14.0f);
        this.alertTextView.setTextColor(Theme.getColor(Theme.key_chat_topPanelMessage));
        this.alertTextView.setSingleLine(true);
        this.alertTextView.setEllipsize(TextUtils.TruncateAt.END);
        this.alertTextView.setMaxLines(1);
        this.alertView.addView(this.alertTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 8.0f, 23.0f, 8.0f, 0.0f));
        FrameLayout frameLayout7 = new FrameLayout(context);
        this.pagedownButton = frameLayout7;
        frameLayout7.setVisibility(4);
        this.contentView.addView(this.pagedownButton, LayoutHelper.createFrame(66.0f, 59.0f, 85, 0.0f, 0.0f, -3.0f, 5.0f));
        this.pagedownButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$kPY6jxF1znNQPnPAz9c8oyWNjlk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$createView$16$ChatActivity(view3);
            }
        });
        FrameLayout frameLayout8 = new FrameLayout(context);
        this.mentiondownButton = frameLayout8;
        frameLayout8.setVisibility(4);
        this.contentView.addView(this.mentiondownButton, LayoutHelper.createFrame(46.0f, 59.0f, 85, 0.0f, 0.0f, 7.0f, 5.0f));
        this.mentiondownButton.setOnClickListener(new AnonymousClass17());
        this.mentiondownButton.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$PIZC6q35Wg-gPvJJpTVgjSBHEMM
            @Override // android.view.View.OnLongClickListener
            public final boolean onLongClick(View view3) {
                return this.f$0.lambda$createView$17$ChatActivity(view3);
            }
        });
        FrameLayout frameLayout9 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.18
            @Override // android.view.View
            public void onDraw(Canvas canvas) {
                if (ChatActivity.this.mentionListView.getChildCount() > 0) {
                    if (ChatActivity.this.mentionLayoutManager.getReverseLayout()) {
                        int top = ChatActivity.this.mentionListViewScrollOffsetY + AndroidUtilities.dp(2.0f);
                        Theme.chat_composeShadowDrawable.setBounds(0, Theme.chat_composeShadowDrawable.getIntrinsicHeight() + top, getMeasuredWidth(), top);
                        Theme.chat_composeShadowDrawable.draw(canvas);
                        canvas.drawRect(0.0f, 0.0f, getMeasuredWidth(), top, Theme.chat_composeBackgroundPaint);
                        return;
                    }
                    int top2 = (ChatActivity.this.mentionsAdapter.isBotContext() && ChatActivity.this.mentionsAdapter.isMediaLayout() && ChatActivity.this.mentionsAdapter.getBotContextSwitch() == null) ? ChatActivity.this.mentionListViewScrollOffsetY - AndroidUtilities.dp(4.0f) : ChatActivity.this.mentionListViewScrollOffsetY - AndroidUtilities.dp(2.0f);
                    int bottom = Theme.chat_composeShadowDrawable.getIntrinsicHeight() + top2;
                    Theme.chat_composeShadowDrawable.setBounds(0, top2, getMeasuredWidth(), bottom);
                    Theme.chat_composeShadowDrawable.draw(canvas);
                    canvas.drawRect(0.0f, bottom, getMeasuredWidth(), getMeasuredHeight(), Theme.chat_composeBackgroundPaint);
                }
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (ChatActivity.this.mentionListViewIgnoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.mentionContainer = frameLayout9;
        frameLayout9.setVisibility(8);
        updateMessageListAccessibilityVisibility();
        this.mentionContainer.setWillNotDraw(false);
        this.contentView.addView(this.mentionContainer, LayoutHelper.createFrame(-1, 110, 83));
        RecyclerListView recyclerListView2 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.19
            private int lastHeight;
            private int lastWidth;

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent event) {
                if (ChatActivity.this.mentionLayoutManager.getReverseLayout()) {
                    if (!ChatActivity.this.mentionListViewIsScrolling && ChatActivity.this.mentionListViewScrollOffsetY != 0 && event.getY() > ChatActivity.this.mentionListViewScrollOffsetY) {
                        return false;
                    }
                } else if (!ChatActivity.this.mentionListViewIsScrolling && ChatActivity.this.mentionListViewScrollOffsetY != 0 && event.getY() < ChatActivity.this.mentionListViewScrollOffsetY) {
                    return false;
                }
                boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, ChatActivity.this.mentionListView, 0, null);
                return super.onInterceptTouchEvent(event) || result;
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (ChatActivity.this.mentionLayoutManager.getReverseLayout()) {
                    if (!ChatActivity.this.mentionListViewIsScrolling && ChatActivity.this.mentionListViewScrollOffsetY != 0 && event.getY() > ChatActivity.this.mentionListViewScrollOffsetY) {
                        return false;
                    }
                } else if (!ChatActivity.this.mentionListViewIsScrolling && ChatActivity.this.mentionListViewScrollOffsetY != 0 && event.getY() < ChatActivity.this.mentionListViewScrollOffsetY) {
                    return false;
                }
                return super.onTouchEvent(event);
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (ChatActivity.this.mentionListViewIgnoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                int newPosition;
                int newTop;
                int width = r - l;
                int height = b - t;
                if (!ChatActivity.this.mentionLayoutManager.getReverseLayout() && ChatActivity.this.mentionListView != null && ChatActivity.this.mentionListViewLastViewPosition >= 0 && width == this.lastWidth && height - this.lastHeight != 0) {
                    int newPosition2 = ChatActivity.this.mentionListViewLastViewPosition;
                    int newTop2 = ((ChatActivity.this.mentionListViewLastViewTop + height) - this.lastHeight) - getPaddingTop();
                    newPosition = newPosition2;
                    newTop = newTop2;
                } else {
                    newPosition = -1;
                    newTop = 0;
                }
                super.onLayout(changed, l, t, r, b);
                if (newPosition != -1) {
                    ChatActivity.this.mentionListViewIgnoreLayout = true;
                    if (!ChatActivity.this.mentionsAdapter.isBotContext() || !ChatActivity.this.mentionsAdapter.isMediaLayout()) {
                        ChatActivity.this.mentionLayoutManager.scrollToPositionWithOffset(newPosition, newTop);
                    } else {
                        ChatActivity.this.mentionGridLayoutManager.scrollToPositionWithOffset(newPosition, newTop);
                    }
                    super.onLayout(false, l, t, r, b);
                    ChatActivity.this.mentionListViewIgnoreLayout = false;
                }
                this.lastHeight = height;
                this.lastWidth = width;
                ChatActivity.this.mentionListViewUpdateLayout();
            }
        };
        this.mentionListView = recyclerListView2;
        recyclerListView2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Eh8LZo3KKPhZ7GBnYmXtvqIhHx4
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view3, MotionEvent motionEvent) {
                return this.f$0.lambda$createView$18$ChatActivity(view3, motionEvent);
            }
        });
        this.mentionListView.setTag(2);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.20
            @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        };
        this.mentionLayoutManager = linearLayoutManager;
        linearLayoutManager.setOrientation(1);
        ExtendedGridLayoutManager extendedGridLayoutManager = new ExtendedGridLayoutManager(context, 100) { // from class: im.uwrkaxlmjj.ui.ChatActivity.21
            private Size size = new Size();

            @Override // im.uwrkaxlmjj.ui.components.ExtendedGridLayoutManager
            protected Size getSizeForItem(int i2) {
                TLRPC.PhotoSize photoSize;
                if (ChatActivity.this.mentionsAdapter.getBotContextSwitch() != null) {
                    i2++;
                }
                this.size.width = 0.0f;
                this.size.height = 0.0f;
                Object object = ChatActivity.this.mentionsAdapter.getItem(i2);
                if (object instanceof TLRPC.BotInlineResult) {
                    TLRPC.BotInlineResult inlineResult = (TLRPC.BotInlineResult) object;
                    if (inlineResult.document != null) {
                        TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(inlineResult.document.thumbs, 90);
                        this.size.width = thumb != null ? thumb.w : 100.0f;
                        this.size.height = thumb != null ? thumb.h : 100.0f;
                        for (int b = 0; b < inlineResult.document.attributes.size(); b++) {
                            TLRPC.DocumentAttribute attribute = inlineResult.document.attributes.get(b);
                            if ((attribute instanceof TLRPC.TL_documentAttributeImageSize) || (attribute instanceof TLRPC.TL_documentAttributeVideo)) {
                                this.size.width = attribute.w;
                                this.size.height = attribute.h;
                                break;
                            }
                        }
                    } else if (inlineResult.content != null) {
                        for (int b2 = 0; b2 < inlineResult.content.attributes.size(); b2++) {
                            TLRPC.DocumentAttribute attribute2 = inlineResult.content.attributes.get(b2);
                            if ((attribute2 instanceof TLRPC.TL_documentAttributeImageSize) || (attribute2 instanceof TLRPC.TL_documentAttributeVideo)) {
                                this.size.width = attribute2.w;
                                this.size.height = attribute2.h;
                                break;
                            }
                        }
                    } else if (inlineResult.thumb != null) {
                        for (int b3 = 0; b3 < inlineResult.thumb.attributes.size(); b3++) {
                            TLRPC.DocumentAttribute attribute3 = inlineResult.thumb.attributes.get(b3);
                            if ((attribute3 instanceof TLRPC.TL_documentAttributeImageSize) || (attribute3 instanceof TLRPC.TL_documentAttributeVideo)) {
                                this.size.width = attribute3.w;
                                this.size.height = attribute3.h;
                                break;
                            }
                        }
                    } else if (inlineResult.photo != null && (photoSize = FileLoader.getClosestPhotoSizeWithSize(inlineResult.photo.sizes, AndroidUtilities.photoSize.intValue())) != null) {
                        this.size.width = photoSize.w;
                        this.size.height = photoSize.h;
                    }
                }
                return this.size;
            }

            @Override // im.uwrkaxlmjj.ui.components.ExtendedGridLayoutManager
            protected int getFlowItemCount() {
                if (ChatActivity.this.mentionsAdapter.getBotContextSwitch() != null) {
                    return getItemCount() - 1;
                }
                return super.getFlowItemCount();
            }
        };
        this.mentionGridLayoutManager = extendedGridLayoutManager;
        extendedGridLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.ChatActivity.22
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                Object object = ChatActivity.this.mentionsAdapter.getItem(position);
                if (!(object instanceof TLRPC.TL_inlineBotSwitchPM)) {
                    if (ChatActivity.this.mentionsAdapter.getBotContextSwitch() != null) {
                        position--;
                    }
                    return ChatActivity.this.mentionGridLayoutManager.getSpanSizeForItem(position);
                }
                return 100;
            }
        });
        this.mentionListView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.ChatActivity.23
            @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
            public void getItemOffsets(Rect outRect, View view3, RecyclerView parent, RecyclerView.State state) {
                outRect.left = 0;
                outRect.right = 0;
                outRect.top = 0;
                outRect.bottom = 0;
                if (parent.getLayoutManager() == ChatActivity.this.mentionGridLayoutManager) {
                    int position = parent.getChildAdapterPosition(view3);
                    if (ChatActivity.this.mentionsAdapter.getBotContextSwitch() != null) {
                        if (position == 0) {
                            return;
                        }
                        position--;
                        if (!ChatActivity.this.mentionGridLayoutManager.isFirstRow(position)) {
                            outRect.top = AndroidUtilities.dp(2.0f);
                        }
                    } else {
                        outRect.top = AndroidUtilities.dp(2.0f);
                    }
                    outRect.right = ChatActivity.this.mentionGridLayoutManager.isLastInRow(position) ? 0 : AndroidUtilities.dp(2.0f);
                }
            }
        });
        this.mentionListView.setItemAnimator(null);
        this.mentionListView.setLayoutAnimation(null);
        this.mentionListView.setClipToPadding(false);
        this.mentionListView.setLayoutManager(this.mentionLayoutManager);
        this.mentionListView.setOverScrollMode(2);
        this.mentionContainer.addView(this.mentionListView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView3 = this.mentionListView;
        MentionsAdapter mentionsAdapter2 = new MentionsAdapter(context, false, this.dialog_id, new MentionsAdapter.MentionsAdapterDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.24
            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void needChangePanelVisibility(boolean show) {
                if (!ChatActivity.this.mentionsAdapter.isBotContext() || !ChatActivity.this.mentionsAdapter.isMediaLayout()) {
                    ChatActivity.this.mentionListView.setLayoutManager(ChatActivity.this.mentionLayoutManager);
                } else {
                    ChatActivity.this.mentionListView.setLayoutManager(ChatActivity.this.mentionGridLayoutManager);
                }
                if (show && ChatActivity.this.bottomOverlay.getVisibility() == 0) {
                    show = false;
                }
                if (show) {
                    if (ChatActivity.this.mentionListAnimation != null) {
                        ChatActivity.this.mentionListAnimation.cancel();
                        ChatActivity.this.mentionListAnimation = null;
                    }
                    if (ChatActivity.this.mentionContainer.getVisibility() == 0) {
                        ChatActivity.this.mentionContainer.setAlpha(1.0f);
                        return;
                    }
                    if (!ChatActivity.this.mentionsAdapter.isBotContext() || !ChatActivity.this.mentionsAdapter.isMediaLayout()) {
                        if (!ChatActivity.this.mentionLayoutManager.getReverseLayout()) {
                            ChatActivity.this.mentionLayoutManager.scrollToPositionWithOffset(0, ChatActivity.this.mentionLayoutManager.getReverseLayout() ? -10000 : 10000);
                        }
                    } else {
                        ChatActivity.this.mentionGridLayoutManager.scrollToPositionWithOffset(0, 10000);
                    }
                    if (!ChatActivity.this.allowStickersPanel || (ChatActivity.this.mentionsAdapter.isBotContext() && !ChatActivity.this.allowContextBotPanel && !ChatActivity.this.allowContextBotPanelSecond)) {
                        ChatActivity.this.mentionContainer.setAlpha(1.0f);
                        ChatActivity.this.mentionContainer.setVisibility(4);
                        ChatActivity.this.updateMessageListAccessibilityVisibility();
                        return;
                    }
                    if (ChatActivity.this.currentEncryptedChat != null && ChatActivity.this.mentionsAdapter.isBotContext()) {
                        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                        if (!preferences.getBoolean("secretbot", false)) {
                            AlertDialog.Builder builder = new AlertDialog.Builder(ChatActivity.this.getParentActivity());
                            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                            builder.setMessage(LocaleController.getString("SecretChatContextBotAlert", R.string.SecretChatContextBotAlert));
                            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                            ChatActivity.this.showDialog(builder.create());
                            preferences.edit().putBoolean("secretbot", true).commit();
                        }
                    }
                    ChatActivity.this.mentionContainer.setVisibility(0);
                    ChatActivity.this.updateMessageListAccessibilityVisibility();
                    ChatActivity.this.mentionContainer.setTag(null);
                    ChatActivity.this.mentionListAnimation = new AnimatorSet();
                    ChatActivity.this.mentionListAnimation.playTogether(ObjectAnimator.ofFloat(ChatActivity.this.mentionContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f));
                    ChatActivity.this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.24.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                                ChatActivity.this.mentionListAnimation = null;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                                ChatActivity.this.mentionListAnimation = null;
                            }
                        }
                    });
                    ChatActivity.this.mentionListAnimation.setDuration(200L);
                    ChatActivity.this.mentionListAnimation.start();
                    return;
                }
                if (ChatActivity.this.mentionListAnimation != null) {
                    ChatActivity.this.mentionListAnimation.cancel();
                    ChatActivity.this.mentionListAnimation = null;
                }
                if (ChatActivity.this.mentionContainer.getVisibility() != 8) {
                    if (ChatActivity.this.allowStickersPanel) {
                        ChatActivity.this.mentionListAnimation = new AnimatorSet();
                        ChatActivity.this.mentionListAnimation.playTogether(ObjectAnimator.ofFloat(ChatActivity.this.mentionContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                        ChatActivity.this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.24.2
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                                    ChatActivity.this.mentionContainer.setVisibility(8);
                                    ChatActivity.this.mentionContainer.setTag(null);
                                    ChatActivity.this.updateMessageListAccessibilityVisibility();
                                    ChatActivity.this.mentionListAnimation = null;
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                                    ChatActivity.this.mentionListAnimation = null;
                                }
                            }
                        });
                        ChatActivity.this.mentionListAnimation.setDuration(200L);
                        ChatActivity.this.mentionListAnimation.start();
                        return;
                    }
                    ChatActivity.this.mentionContainer.setTag(null);
                    ChatActivity.this.mentionContainer.setVisibility(8);
                    ChatActivity.this.updateMessageListAccessibilityVisibility();
                }
            }

            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void onContextSearch(boolean searching) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.setCaption(ChatActivity.this.mentionsAdapter.getBotCaption());
                    ChatActivity.this.chatActivityEnterView.showContextProgress(searching);
                }
            }

            @Override // im.uwrkaxlmjj.ui.adapters.MentionsAdapter.MentionsAdapterDelegate
            public void onContextClick(TLRPC.BotInlineResult result) {
                if (ChatActivity.this.getParentActivity() == null || result.content == null) {
                    return;
                }
                if (result.type.equals("video") || result.type.equals("web_player_video")) {
                    int[] size = MessageObject.getInlineResultWidthAndHeight(result);
                    EmbedBottomSheet.show(ChatActivity.this.getParentActivity(), result.title != null ? result.title : "", result.description, result.content.url, result.content.url, size[0], size[1]);
                } else {
                    Browser.openUrl(ChatActivity.this.getParentActivity(), result.content.url);
                }
            }
        });
        this.mentionsAdapter = mentionsAdapter2;
        recyclerListView3.setAdapter(mentionsAdapter2);
        if (!ChatObject.isChannel(this.currentChat) || ((chat = this.currentChat) != null && chat.megagroup)) {
            this.mentionsAdapter.setBotInfo(this.botInfo);
        }
        this.mentionsAdapter.setParentFragment(this);
        this.mentionsAdapter.setChatInfo(this.chatInfo);
        this.mentionsAdapter.setNeedUsernames(this.currentChat != null);
        MentionsAdapter mentionsAdapter3 = this.mentionsAdapter;
        TLRPC.EncryptedChat encryptedChat2 = this.currentEncryptedChat;
        mentionsAdapter3.setNeedBotContext(encryptedChat2 == null || AndroidUtilities.getPeerLayerVersion(encryptedChat2.layer) >= 46);
        this.mentionsAdapter.setBotsCount(this.currentChat != null ? this.botsCount : 1);
        RecyclerListView recyclerListView4 = this.mentionListView;
        RecyclerListView.OnItemClickListener onItemClickListener = new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$3EFaBLjpEFDwGIpYrWOD2BeE04Q
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view3, int i2) {
                this.f$0.lambda$createView$21$ChatActivity(view3, i2);
            }
        };
        this.mentionsOnItemClickListener = onItemClickListener;
        recyclerListView4.setOnItemClickListener(onItemClickListener);
        this.mentionListView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$tirY_4CP4Sqkzlk8VbPS0Fwbd5A
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view3, int i2) {
                return this.f$0.lambda$createView$23$ChatActivity(view3, i2);
            }
        });
        this.mentionListView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.ChatActivity.25
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                ChatActivity.this.mentionListViewIsScrolling = newState == 1;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                int lastVisibleItem = (ChatActivity.this.mentionsAdapter.isBotContext() && ChatActivity.this.mentionsAdapter.isMediaLayout()) ? ChatActivity.this.mentionGridLayoutManager.findLastVisibleItemPosition() : ChatActivity.this.mentionLayoutManager.findLastVisibleItemPosition();
                int visibleItemCount = lastVisibleItem == -1 ? 0 : lastVisibleItem;
                if (visibleItemCount > 0 && lastVisibleItem > ChatActivity.this.mentionsAdapter.getItemCount() - 5) {
                    ChatActivity.this.mentionsAdapter.searchForContextBotForNextOffset();
                }
                ChatActivity.this.mentionListViewUpdateLayout();
            }
        });
        ImageView imageView4 = new ImageView(context);
        this.pagedownButtonImage = imageView4;
        imageView4.setImageResource(R.drawable.pagedown);
        this.pagedownButtonImage.setScaleType(ImageView.ScaleType.CENTER);
        this.pagedownButtonImage.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_goDownButtonIcon), PorterDuff.Mode.MULTIPLY));
        this.pagedownButtonImage.setPadding(0, AndroidUtilities.dp(2.0f), 0, 0);
        Drawable drawable = Theme.createCircleDrawable(AndroidUtilities.dp(42.0f), Theme.getColor(Theme.key_chat_goDownButton));
        Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.pagedown_shadow).mutate();
        shadowDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_goDownButtonShadow), PorterDuff.Mode.MULTIPLY));
        CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable, 0, 0);
        combinedDrawable.setIconSize(AndroidUtilities.dp(42.0f), AndroidUtilities.dp(42.0f));
        this.pagedownButtonImage.setBackgroundDrawable(combinedDrawable);
        this.pagedownButton.addView(this.pagedownButtonImage, LayoutHelper.createFrame(46, 46, 81));
        this.pagedownButton.setContentDescription(LocaleController.getString("AccDescrPageDown", R.string.AccDescrPageDown));
        TextView textView6 = new TextView(context);
        this.pagedownButtonCounter = textView6;
        textView6.setVisibility(4);
        this.pagedownButtonCounter.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.pagedownButtonCounter.setTextSize(1, 13.0f);
        this.pagedownButtonCounter.setTextColor(Theme.getColor(Theme.key_chat_goDownButtonCounter));
        this.pagedownButtonCounter.setGravity(17);
        this.pagedownButtonCounter.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(11.5f), Theme.getColor(Theme.key_chat_goDownButtonCounterBackground)));
        this.pagedownButtonCounter.setMinWidth(AndroidUtilities.dp(23.0f));
        this.pagedownButtonCounter.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), AndroidUtilities.dp(1.0f));
        this.pagedownButton.addView(this.pagedownButtonCounter, LayoutHelper.createFrame(-2, 23, 49));
        ImageView imageView5 = new ImageView(context);
        this.mentiondownButtonImage = imageView5;
        imageView5.setImageResource(R.drawable.mentionbutton);
        this.mentiondownButtonImage.setScaleType(ImageView.ScaleType.CENTER);
        this.mentiondownButtonImage.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_goDownButtonIcon), PorterDuff.Mode.MULTIPLY));
        this.mentiondownButtonImage.setPadding(0, AndroidUtilities.dp(2.0f), 0, 0);
        Drawable drawable2 = Theme.createCircleDrawable(AndroidUtilities.dp(42.0f), Theme.getColor(Theme.key_chat_goDownButton));
        Drawable shadowDrawable2 = context.getResources().getDrawable(R.drawable.pagedown_shadow).mutate();
        shadowDrawable2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_goDownButtonShadow), PorterDuff.Mode.MULTIPLY));
        CombinedDrawable combinedDrawable2 = new CombinedDrawable(shadowDrawable2, drawable2, 0, 0);
        combinedDrawable2.setIconSize(AndroidUtilities.dp(42.0f), AndroidUtilities.dp(42.0f));
        this.mentiondownButtonImage.setBackgroundDrawable(combinedDrawable2);
        this.mentiondownButton.addView(this.mentiondownButtonImage, LayoutHelper.createFrame(46, 46, 83));
        TextView textView7 = new TextView(context);
        this.mentiondownButtonCounter = textView7;
        textView7.setVisibility(4);
        this.mentiondownButtonCounter.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.mentiondownButtonCounter.setTextSize(1, 13.0f);
        this.mentiondownButtonCounter.setTextColor(Theme.getColor(Theme.key_chat_goDownButtonCounter));
        this.mentiondownButtonCounter.setGravity(17);
        this.mentiondownButtonCounter.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(11.5f), Theme.getColor(Theme.key_chat_goDownButtonCounterBackground)));
        this.mentiondownButtonCounter.setMinWidth(AndroidUtilities.dp(23.0f));
        this.mentiondownButtonCounter.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), AndroidUtilities.dp(1.0f));
        this.mentiondownButton.addView(this.mentiondownButtonCounter, LayoutHelper.createFrame(-2, 23, 49));
        this.mentiondownButton.setContentDescription(LocaleController.getString("AccDescrMentionDown", R.string.AccDescrMentionDown));
        if (!AndroidUtilities.isTablet() || AndroidUtilities.isSmallTablet()) {
            FragmentContextView fragmentLocationContextView = new FragmentContextView(context, this, true);
            this.contentView.addView(fragmentLocationContextView, LayoutHelper.createFrame(-1.0f, 39.0f, 51, 0.0f, -36.0f, 0.0f, 0.0f));
            SizeNotifierFrameLayout sizeNotifierFrameLayout2 = this.contentView;
            FragmentContextView fragmentContextView = new FragmentContextView(context, this, false);
            this.fragmentContextView = fragmentContextView;
            sizeNotifierFrameLayout2.addView(fragmentContextView, LayoutHelper.createFrame(-1.0f, 39.0f, 51, 0.0f, -36.0f, 0.0f, 0.0f));
            this.fragmentContextView.setAdditionalContextView(fragmentLocationContextView);
            fragmentLocationContextView.setAdditionalContextView(this.fragmentContextView);
        }
        this.contentView.addView(this.actionBar);
        this.pinnedLiveUserImageView = new BackupImageView(context);
        TLRPC.User user7 = getUserConfig().getCurrentUser();
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setInfo(user7);
        this.pinnedLiveUserImageView.setVisibility(8);
        this.pinnedLiveUserImageView.setRoundRadius(AndroidUtilities.dp(5.0f));
        this.pinnedLiveUserImageView.setImage(ImageLocation.getForUser(user7, false), "50_50", avatarDrawable, user7);
        this.contentView.addView(this.pinnedLiveUserImageView, LayoutHelper.createFrame(32.0f, 32.0f, 51, 17.0f, 8.0f, 0.0f, 0.0f));
        View view3 = new View(context);
        this.overlayView = view3;
        view3.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Pvn3xxtQ8xWuA4w5Rh_ofwXUcRk
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view4, MotionEvent motionEvent) {
                return this.f$0.lambda$createView$24$ChatActivity(view4, motionEvent);
            }
        });
        this.contentView.addView(this.overlayView, LayoutHelper.createFrame(-1, -1, 51));
        this.overlayView.setVisibility(8);
        InstantCameraView instantCameraView = new InstantCameraView(context, this);
        this.instantCameraView = instantCameraView;
        this.contentView.addView(instantCameraView, LayoutHelper.createFrame(-1, -1, 51));
        FrameLayout frameLayout10 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.26
            @Override // android.view.View
            public void onDraw(Canvas canvas) {
                int bottom = Theme.chat_composeShadowDrawable.getIntrinsicHeight();
                Theme.chat_composeShadowDrawable.setBounds(0, 0, getMeasuredWidth(), bottom);
                Theme.chat_composeShadowDrawable.draw(canvas);
                canvas.drawRect(0.0f, bottom, getMeasuredWidth(), getMeasuredHeight(), Theme.chat_composeBackgroundPaint);
            }
        };
        this.bottomMessagesActionContainer = frameLayout10;
        frameLayout10.setVisibility(4);
        this.bottomMessagesActionContainer.setWillNotDraw(false);
        this.bottomMessagesActionContainer.setPadding(0, AndroidUtilities.dp(2.0f), 0, 0);
        this.contentView.addView(this.bottomMessagesActionContainer, LayoutHelper.createFrame(-1, 51, 80));
        this.bottomMessagesActionContainer.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Evg5mGw4mThS7myPfiUOCvorDvc
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view4, MotionEvent motionEvent) {
                return ChatActivity.lambda$createView$25(view4, motionEvent);
            }
        });
        ChatActivityEnterView chatActivityEnterView2 = new ChatActivityEnterView(getParentActivity(), this.contentView, this, true) { // from class: im.uwrkaxlmjj.ui.ChatActivity.27
            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (getAlpha() != 1.0f) {
                    return false;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (getAlpha() != 1.0f) {
                    return false;
                }
                return super.onTouchEvent(event);
            }

            @Override // android.view.ViewGroup, android.view.View
            public boolean dispatchTouchEvent(MotionEvent ev) {
                if (getAlpha() != 1.0f) {
                    return false;
                }
                return super.dispatchTouchEvent(ev);
            }
        };
        this.chatActivityEnterView = chatActivityEnterView2;
        chatActivityEnterView2.setDelegate(new ChatActivityEnterView.ChatActivityEnterViewDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.28
            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onMessageSend(CharSequence message, boolean notify, int scheduleDate) {
                Bundle bundle = new Bundle();
                int chatId = ChatActivity.this.arguments.getInt("chat_id", 0);
                int userId = ChatActivity.this.arguments.getInt("user_id", 0);
                bundle.putInt("user_id", userId);
                bundle.putInt("chat_id", chatId);
                if (ChatActivity.this.getMessagesController().checkCanOpenChat2(bundle, ChatActivity.this)) {
                    if (!ChatActivity.this.inScheduleMode) {
                        ChatActivity.this.moveScrollToLastMessage();
                    }
                    if (ChatActivity.this.mentionsAdapter != null) {
                        ChatActivity.this.mentionsAdapter.addHashtagsFromMessage(message);
                    }
                    if (scheduleDate != 0) {
                        if (ChatActivity.this.scheduledMessagesCount == -1) {
                            ChatActivity.this.scheduledMessagesCount = 0;
                        }
                        if (message != null) {
                            ChatActivity.access$18008(ChatActivity.this);
                        }
                        if (ChatActivity.this.forwardingMessages != null && !ChatActivity.this.forwardingMessages.isEmpty()) {
                            ChatActivity.this.scheduledMessagesCount += ChatActivity.this.forwardingMessages.size();
                        }
                        ChatActivity.this.updateScheduledInterface(false);
                    }
                    ChatActivity.this.hideFieldPanel(notify, scheduleDate, false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onSwitchRecordMode(boolean video) {
                ChatActivity.this.showVoiceHint(false, video);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onPreAudioVideoRecord() {
                ChatActivity.this.showVoiceHint(true, false);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onUpdateSlowModeButton(View button, boolean show, CharSequence time) {
                ChatActivity.this.showSlowModeHint(button, show, time);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onTextSelectionChanged(int start, int end) {
                if (ChatActivity.this.editTextItem == null) {
                    return;
                }
                if (end - start > 0) {
                    if (ChatActivity.this.editTextItem.getTag() == null) {
                        ChatActivity.this.editTextItem.setTag(1);
                        ChatActivity.this.editTextItem.setVisibility(0);
                        ChatActivity.this.headerItem.setVisibility(8);
                        ChatActivity.this.attachItem.setVisibility(8);
                    }
                    ChatActivity.this.editTextStart = start;
                    ChatActivity.this.editTextEnd = end;
                    return;
                }
                if (ChatActivity.this.editTextItem.getTag() != null) {
                    ChatActivity.this.editTextItem.setTag(null);
                    ChatActivity.this.editTextItem.setVisibility(8);
                    if (ChatActivity.this.chatActivityEnterView.hasText()) {
                        ChatActivity.this.headerItem.setVisibility(8);
                        ChatActivity.this.attachItem.setVisibility(0);
                    } else {
                        ChatActivity.this.headerItem.setVisibility(0);
                        ChatActivity.this.attachItem.setVisibility(8);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onTextChanged(final CharSequence text, boolean bigChange) {
                MediaController.getInstance().setInputFieldHasText(!TextUtils.isEmpty(text) || ChatActivity.this.chatActivityEnterView.isEditingMessage());
                if (ChatActivity.this.stickersAdapter != null && ChatActivity.this.chatActivityEnterView != null && ChatActivity.this.chatActivityEnterView.getVisibility() == 0 && (ChatActivity.this.bottomOverlay == null || ChatActivity.this.bottomOverlay.getVisibility() != 0)) {
                    ChatActivity.this.stickersAdapter.loadStikersForEmoji(text, !(ChatActivity.this.currentChat == null || ChatObject.canSendStickers(ChatActivity.this.currentChat)) || ChatActivity.this.chatActivityEnterView.isEditingMessage());
                }
                if (ChatActivity.this.mentionsAdapter != null) {
                    ChatActivity.this.mentionsAdapter.searchUsernameOrHashtag(text.toString(), ChatActivity.this.chatActivityEnterView.getCursorPosition(), ChatActivity.this.messages, false);
                }
                if (ChatActivity.this.waitingForCharaterEnterRunnable != null) {
                    AndroidUtilities.cancelRunOnUIThread(ChatActivity.this.waitingForCharaterEnterRunnable);
                    ChatActivity.this.waitingForCharaterEnterRunnable = null;
                }
                if ((ChatActivity.this.currentChat == null || ChatObject.canSendEmbed(ChatActivity.this.currentChat)) && ChatActivity.this.chatActivityEnterView.isMessageWebPageSearchEnabled()) {
                    if (!ChatActivity.this.chatActivityEnterView.isEditingMessage() || !ChatActivity.this.chatActivityEnterView.isEditingCaption()) {
                        if (bigChange) {
                            ChatActivity.this.searchLinks(text, true);
                        } else {
                            ChatActivity.this.waitingForCharaterEnterRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.ChatActivity.28.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    if (this == ChatActivity.this.waitingForCharaterEnterRunnable) {
                                        ChatActivity.this.searchLinks(text, false);
                                        ChatActivity.this.waitingForCharaterEnterRunnable = null;
                                    }
                                }
                            };
                            AndroidUtilities.runOnUIThread(ChatActivity.this.waitingForCharaterEnterRunnable, AndroidUtilities.WEB_URL == null ? 3000L : 1000L);
                        }
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onTextSpansChanged(CharSequence text) {
                ChatActivity.this.searchLinks(text, true);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needSendTyping() {
                ChatActivity.this.getMessagesController().sendTyping(ChatActivity.this.dialog_id, 0, ChatActivity.this.classGuid);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onAttachButtonHidden() {
                if (!ChatActivity.this.actionBar.isSearchFieldVisible()) {
                    if (ChatActivity.this.headerItem != null) {
                        ChatActivity.this.headerItem.setVisibility(8);
                    }
                    if (ChatActivity.this.editTextItem != null) {
                        ChatActivity.this.editTextItem.setVisibility(8);
                    }
                    if (ChatActivity.this.attachItem != null) {
                        ChatActivity.this.attachItem.setVisibility(0);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onAttachButtonShow() {
                if (!ChatActivity.this.actionBar.isSearchFieldVisible()) {
                    if (ChatActivity.this.headerItem != null) {
                        ChatActivity.this.headerItem.setVisibility(0);
                    }
                    if (ChatActivity.this.editTextItem != null) {
                        ChatActivity.this.editTextItem.setVisibility(8);
                    }
                    if (ChatActivity.this.attachItem != null) {
                        ChatActivity.this.attachItem.setVisibility(8);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onMessageEditEnd(boolean loading) {
                if (!loading) {
                    ChatActivity.this.mentionsAdapter.setNeedBotContext(ChatActivity.this.currentEncryptedChat == null || AndroidUtilities.getPeerLayerVersion(ChatActivity.this.currentEncryptedChat.layer) >= 46);
                    if (ChatActivity.this.editingMessageObject != null) {
                        ChatActivity.this.hideFieldPanel(false);
                    }
                    ChatActivity.this.chatActivityEnterView.setAllowStickersAndGifs(ChatActivity.this.currentEncryptedChat == null || AndroidUtilities.getPeerLayerVersion(ChatActivity.this.currentEncryptedChat.layer) >= 23, ChatActivity.this.currentEncryptedChat == null || AndroidUtilities.getPeerLayerVersion(ChatActivity.this.currentEncryptedChat.layer) >= 46);
                    if (ChatActivity.this.editingMessageObjectReqId != 0) {
                        ChatActivity.this.getConnectionsManager().cancelRequest(ChatActivity.this.editingMessageObjectReqId, true);
                        ChatActivity.this.editingMessageObjectReqId = 0;
                    }
                    ChatActivity.this.updatePinnedMessageView(true);
                    ChatActivity.this.updateBottomOverlay();
                    ChatActivity.this.updateVisibleRows();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onWindowSizeChanged(int size) {
                if (size < AndroidUtilities.dp(72.0f) + ActionBar.getCurrentActionBarHeight()) {
                    ChatActivity.this.allowStickersPanel = false;
                    if (ChatActivity.this.stickersPanel.getVisibility() == 0) {
                        ChatActivity.this.stickersPanel.setVisibility(4);
                    }
                    if (ChatActivity.this.mentionContainer != null && ChatActivity.this.mentionContainer.getVisibility() == 0) {
                        ChatActivity.this.mentionContainer.setVisibility(4);
                        ChatActivity.this.updateMessageListAccessibilityVisibility();
                    }
                } else {
                    ChatActivity.this.allowStickersPanel = true;
                    if (ChatActivity.this.stickersPanel.getVisibility() == 4) {
                        ChatActivity.this.stickersPanel.setVisibility(0);
                    }
                    if (ChatActivity.this.mentionContainer != null && ChatActivity.this.mentionContainer.getVisibility() == 4 && (!ChatActivity.this.mentionsAdapter.isBotContext() || ChatActivity.this.allowContextBotPanel || ChatActivity.this.allowContextBotPanelSecond)) {
                        ChatActivity.this.mentionContainer.setVisibility(0);
                        ChatActivity.this.mentionContainer.setTag(null);
                        ChatActivity.this.updateMessageListAccessibilityVisibility();
                    }
                }
                ChatActivity chatActivity = ChatActivity.this;
                chatActivity.allowContextBotPanel = true ^ chatActivity.chatActivityEnterView.isPopupShowing();
                ChatActivity.this.checkContextBotPanel();
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onStickersTab(boolean opened) {
                if (ChatActivity.this.emojiButtonRed != null) {
                    ChatActivity.this.emojiButtonRed.setVisibility(8);
                }
                ChatActivity.this.allowContextBotPanelSecond = !opened;
                ChatActivity.this.checkContextBotPanel();
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void didPressedAttachButton(int positon, ChatEnterMenuType menuType) {
                if (positon == 100) {
                    return;
                }
                int button = 0;
                if (ChatActivity.this.currentUser != null) {
                    if (menuType == ChatEnterMenuType.ALBUM) {
                        button = 1;
                    } else if (menuType == ChatEnterMenuType.CAMERA) {
                        if (SharedConfig.inappCamera) {
                            ChatActivity.this.openCameraView();
                            return;
                        }
                    } else if (menuType == ChatEnterMenuType.DOCUMENT) {
                        button = 4;
                    } else if (menuType == ChatEnterMenuType.LOCATION) {
                        button = 6;
                    } else if (menuType == ChatEnterMenuType.CONTACTS) {
                        button = 5;
                    } else if (menuType == ChatEnterMenuType.MUSIC) {
                        button = 3;
                    } else {
                        if (menuType == ChatEnterMenuType.TRANSFER) {
                            ChatActivity.this.getAccountInfo(false);
                            return;
                        }
                        if (menuType == ChatEnterMenuType.REDPACKET) {
                            ChatActivity.this.getAccountInfo(true);
                            return;
                        }
                        if (menuType == ChatEnterMenuType.FAVORITE) {
                            ToastUtils.show((CharSequence) "devoping....");
                            return;
                        }
                        if (positon == 7) {
                            button = 3;
                        } else if (menuType == ChatEnterMenuType.VOICECALL) {
                            button = 1010;
                        } else if (menuType == ChatEnterMenuType.VIDEOCALL) {
                            button = 1011;
                        } else if (menuType == ChatEnterMenuType.GROUP_LIVE) {
                            button = 1012;
                        }
                    }
                } else if (menuType == ChatEnterMenuType.ALBUM) {
                    button = 1;
                } else if (menuType != ChatEnterMenuType.CAMERA) {
                    if (menuType == ChatEnterMenuType.DOCUMENT) {
                        button = 4;
                    } else if (menuType == ChatEnterMenuType.LOCATION) {
                        button = 6;
                    } else if (menuType == ChatEnterMenuType.CONTACTS) {
                        button = 5;
                    } else if (menuType == ChatEnterMenuType.POLL) {
                        button = 9;
                    } else if (menuType == ChatEnterMenuType.MUSIC) {
                        button = 3;
                    } else {
                        if (menuType == ChatEnterMenuType.REDPACKET) {
                            ChatActivity.this.getAccountInfo(true);
                            return;
                        }
                        if (menuType == ChatEnterMenuType.FAVORITE) {
                            ToastUtils.show((CharSequence) "devoping....");
                            return;
                        } else if (menuType == ChatEnterMenuType.VOICECALL) {
                            button = 1010;
                        } else if (menuType == ChatEnterMenuType.VIDEOCALL) {
                            button = 1011;
                        } else if (menuType == ChatEnterMenuType.GROUP_LIVE) {
                            button = 1012;
                        }
                    }
                }
                ChatActivity.this.processSelectedAttach(button);
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needStartRecordVideo(int state, boolean notify, int scheduleDate) {
                if (ChatActivity.this.instantCameraView != null) {
                    if (state == 0) {
                        ChatActivity.this.instantCameraView.showCamera();
                        return;
                    }
                    if (state == 1 || state == 3 || state == 4) {
                        ChatActivity.this.instantCameraView.send(state, notify, scheduleDate);
                    } else if (state == 2) {
                        ChatActivity.this.instantCameraView.cancel();
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needChangeVideoPreviewState(int state, float seekProgress) {
                if (ChatActivity.this.instantCameraView != null) {
                    ChatActivity.this.instantCameraView.changeVideoPreviewState(state, seekProgress);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needStartRecordAudio(int state) {
                int visibility = state == 0 ? 8 : 0;
                if (ChatActivity.this.overlayView.getVisibility() != visibility) {
                    ChatActivity.this.overlayView.setVisibility(visibility);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void needShowMediaBanHint() {
                ChatActivity.this.showMediaBannedHint();
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void onStickersExpandedChange() {
                ChatActivity.this.checkRaiseSensors();
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void scrollToSendingMessage() {
                int id = ChatActivity.this.getSendMessagesHelper().getSendingMessageId(ChatActivity.this.dialog_id);
                if (id != 0) {
                    ChatActivity.this.scrollToMessageId(id, 0, true, 0, false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public boolean hasScheduledMessages() {
                return ChatActivity.this.scheduledMessagesCount > 0 && !ChatActivity.this.inScheduleMode;
            }

            @Override // im.uwrkaxlmjj.ui.components.ChatActivityEnterView.ChatActivityEnterViewDelegate
            public void openScheduledMessages() {
                ChatActivity.this.openScheduledMessages();
            }
        });
        this.chatActivityEnterView.setDialogId(this.dialog_id, this.currentAccount);
        TLRPC.ChatFull chatFull2 = this.chatInfo;
        if (chatFull2 != null) {
            this.chatActivityEnterView.setChatInfo(chatFull2);
        }
        this.chatActivityEnterView.setId(1000);
        this.chatActivityEnterView.setBotsCount(this.botsCount, this.hasBotsCommands);
        this.chatActivityEnterView.setMinimumHeight(AndroidUtilities.dp(51.0f));
        ChatActivityEnterView chatActivityEnterView3 = this.chatActivityEnterView;
        TLRPC.EncryptedChat encryptedChat3 = this.currentEncryptedChat;
        boolean z2 = encryptedChat3 == null || AndroidUtilities.getPeerLayerVersion(encryptedChat3.layer) >= 23;
        TLRPC.EncryptedChat encryptedChat4 = this.currentEncryptedChat;
        chatActivityEnterView3.setAllowStickersAndGifs(z2, encryptedChat4 == null || AndroidUtilities.getPeerLayerVersion(encryptedChat4.layer) >= 46);
        if (this.inPreviewMode) {
            this.chatActivityEnterView.setVisibility(4);
        }
        SizeNotifierFrameLayout sizeNotifierFrameLayout3 = this.contentView;
        sizeNotifierFrameLayout3.addView(this.chatActivityEnterView, sizeNotifierFrameLayout3.getChildCount() - 1, LayoutHelper.createFrame(-1, -2, 83));
        FrameLayout replyLayout = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.29
            @Override // android.view.View
            public void setTranslationY(float translationY) {
                super.setTranslationY(translationY);
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.invalidate();
                }
                if (getVisibility() != 8) {
                    if (ChatActivity.this.chatListView != null) {
                        ChatActivity.this.chatListView.setTranslationY(translationY);
                    }
                    if (ChatActivity.this.progressView != null) {
                        ChatActivity.this.progressView.setTranslationY(translationY);
                    }
                    if (ChatActivity.this.mentionContainer != null) {
                        ChatActivity.this.mentionContainer.setTranslationY(translationY);
                    }
                    if (ChatActivity.this.pagedownButton != null) {
                        ChatActivity.this.pagedownButton.setTranslationY(translationY);
                    }
                    if (ChatActivity.this.mentiondownButton != null) {
                        ChatActivity.this.mentiondownButton.setTranslationY(ChatActivity.this.pagedownButton.getVisibility() != 0 ? translationY : translationY - AndroidUtilities.dp(72.0f));
                    }
                    ChatActivity.this.updateMessagesVisiblePart(false);
                    if (ChatActivity.this.fragmentView != null) {
                        ChatActivity.this.fragmentView.invalidate();
                    }
                }
            }

            @Override // android.view.View
            public boolean hasOverlappingRendering() {
                return false;
            }

            @Override // android.view.View
            public void setVisibility(int visibility) {
                int iDp;
                super.setVisibility(visibility);
                if (visibility == 8) {
                    if (ChatActivity.this.chatListView != null) {
                        ChatActivity.this.chatListView.setTranslationY(0.0f);
                    }
                    if (ChatActivity.this.progressView != null) {
                        ChatActivity.this.progressView.setTranslationY(0.0f);
                    }
                    if (ChatActivity.this.mentionContainer != null) {
                        ChatActivity.this.mentionContainer.setTranslationY(0.0f);
                    }
                    if (ChatActivity.this.pagedownButton != null) {
                        ChatActivity.this.pagedownButton.setTranslationY(ChatActivity.this.pagedownButton.getTag() == null ? AndroidUtilities.dp(100.0f) : 0.0f);
                    }
                    if (ChatActivity.this.mentiondownButton != null) {
                        FrameLayout frameLayout11 = ChatActivity.this.mentiondownButton;
                        if (ChatActivity.this.mentiondownButton.getTag() == null) {
                            iDp = AndroidUtilities.dp(100.0f);
                        } else {
                            iDp = ChatActivity.this.pagedownButton.getVisibility() == 0 ? -AndroidUtilities.dp(72.0f) : 0;
                        }
                        frameLayout11.setTranslationY(iDp);
                    }
                }
            }
        };
        View view4 = new View(context);
        this.replyLineView = view4;
        view4.setBackgroundColor(Theme.getColor(Theme.key_chat_replyPanelLine));
        this.chatActivityEnterView.addTopView(replyLayout, this.replyLineView, 48);
        replyLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$zDcrHHA-6uib-yvKCuLDxLZS0ek
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$26$ChatActivity(view5);
            }
        });
        ImageView imageView6 = new ImageView(context);
        this.replyIconImageView = imageView6;
        imageView6.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_replyPanelIcons), PorterDuff.Mode.MULTIPLY));
        this.replyIconImageView.setScaleType(ImageView.ScaleType.CENTER);
        replyLayout.addView(this.replyIconImageView, LayoutHelper.createFrame(52, 46, 51));
        ImageView imageView7 = new ImageView(context);
        this.replyCloseImageView = imageView7;
        imageView7.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_replyPanelClose), PorterDuff.Mode.MULTIPLY));
        this.replyCloseImageView.setImageResource(R.drawable.input_clear);
        this.replyCloseImageView.setScaleType(ImageView.ScaleType.CENTER);
        replyLayout.addView(this.replyCloseImageView, LayoutHelper.createFrame(52.0f, 46.0f, 53, 0.0f, 0.5f, 0.0f, 0.0f));
        this.replyCloseImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$v1TG-ZpKwT3NJduBtv5N8jCGlsM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$27$ChatActivity(view5);
            }
        });
        SimpleTextView simpleTextView5 = new SimpleTextView(context);
        this.replyNameTextView = simpleTextView5;
        simpleTextView5.setTextSize(14);
        this.replyNameTextView.setTextColor(Theme.getColor(Theme.key_chat_replyPanelName));
        this.replyNameTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        replyLayout.addView(this.replyNameTextView, LayoutHelper.createFrame(-1.0f, 18.0f, 51, 52.0f, 6.0f, 52.0f, 0.0f));
        SimpleTextView simpleTextView6 = new SimpleTextView(context);
        this.replyObjectTextView = simpleTextView6;
        simpleTextView6.setTextSize(14);
        this.replyObjectTextView.setTextColor(Theme.getColor(Theme.key_chat_replyPanelMessage));
        replyLayout.addView(this.replyObjectTextView, LayoutHelper.createFrame(-1.0f, 18.0f, 51, 52.0f, 24.0f, 52.0f, 0.0f));
        BackupImageView backupImageView2 = new BackupImageView(context);
        this.replyImageView = backupImageView2;
        replyLayout.addView(backupImageView2, LayoutHelper.createFrame(34.0f, 34.0f, 51, 52.0f, 6.0f, 0.0f, 0.0f));
        FrameLayout frameLayout11 = new FrameLayout(context);
        this.stickersPanel = frameLayout11;
        frameLayout11.setVisibility(8);
        this.contentView.addView(this.stickersPanel, LayoutHelper.createFrame(-2.0f, 81.5f, 83, 0.0f, 0.0f, 0.0f, 38.0f));
        final ContentPreviewViewer.ContentPreviewViewerDelegate contentPreviewViewerDelegate = new ContentPreviewViewer.ContentPreviewViewerDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.30
            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ void gifAddedOrDeleted() {
                ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$gifAddedOrDeleted(this);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ boolean needOpen() {
                return ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$needOpen(this);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ void sendGif(Object obj, boolean z3, int i2) {
                ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$sendGif(this, obj, z3, i2);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void sendSticker(TLRPC.Document sticker, Object parent, boolean notify, int scheduleDate) {
                ChatActivity.this.chatActivityEnterView.lambda$onStickerSelected$28$ChatActivityEnterView(sticker, parent, true, notify, scheduleDate);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean needSend() {
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean canSchedule() {
                return ChatActivity.this.canScheduleMessage();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean isInScheduleMode() {
                return ChatActivity.this.inScheduleMode;
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void openSet(TLRPC.InputStickerSet set, boolean clearsInputField) {
                if (set == null || ChatActivity.this.getParentActivity() == null) {
                    return;
                }
                TLRPC.TL_inputStickerSetID inputStickerSet = new TLRPC.TL_inputStickerSetID();
                inputStickerSet.access_hash = set.access_hash;
                inputStickerSet.id = set.id;
                FragmentActivity parentActivity = ChatActivity.this.getParentActivity();
                ChatActivity chatActivity = ChatActivity.this;
                StickersAlert alert = new StickersAlert(parentActivity, chatActivity, inputStickerSet, null, chatActivity.chatActivityEnterView);
                alert.setClearsInputField(clearsInputField);
                ChatActivity.this.showDialog(alert);
            }
        };
        RecyclerListView recyclerListView5 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.31
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent event) {
                boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, ChatActivity.this.stickersListView, 0, contentPreviewViewerDelegate);
                return super.onInterceptTouchEvent(event) || result;
            }
        };
        this.stickersListView = recyclerListView5;
        recyclerListView5.setTag(3);
        this.stickersListView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$o52qWzHBS6KOR3ExYu2eDnk25hs
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view5, MotionEvent motionEvent) {
                return this.f$0.lambda$createView$28$ChatActivity(contentPreviewViewerDelegate, view5, motionEvent);
            }
        });
        this.stickersListView.setDisallowInterceptTouchEvents(true);
        LinearLayoutManager layoutManager = new LinearLayoutManager(context);
        layoutManager.setOrientation(0);
        this.stickersListView.setLayoutManager(layoutManager);
        this.stickersListView.setClipToPadding(false);
        this.stickersListView.setOverScrollMode(2);
        this.stickersPanel.addView(this.stickersListView, LayoutHelper.createFrame(-1, 78.0f));
        initStickers();
        ImageView imageView8 = new ImageView(context);
        this.stickersPanelArrow = imageView8;
        imageView8.setImageResource(R.drawable.stickers_back_arrow);
        this.stickersPanelArrow.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_stickersHintPanel), PorterDuff.Mode.MULTIPLY));
        this.stickersPanel.addView(this.stickersPanelArrow, LayoutHelper.createFrame(-2.0f, -2.0f, 83, 53.0f, 0.0f, 53.0f, 0.0f));
        FrameLayout frameLayout12 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.32
            @Override // android.view.View
            public void onDraw(Canvas canvas) {
                int bottom = Theme.chat_composeShadowDrawable.getIntrinsicHeight();
                Theme.chat_composeShadowDrawable.setBounds(0, 0, getMeasuredWidth(), bottom);
                Theme.chat_composeShadowDrawable.draw(canvas);
                canvas.drawRect(0.0f, bottom, getMeasuredWidth(), getMeasuredHeight(), Theme.chat_composeBackgroundPaint);
            }
        };
        this.searchContainer = frameLayout12;
        frameLayout12.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$cPlM_eDJ-2-6uzWzuvhbr_2vTBs
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view5, MotionEvent motionEvent) {
                return ChatActivity.lambda$createView$29(view5, motionEvent);
            }
        });
        this.searchContainer.setWillNotDraw(false);
        this.searchContainer.setVisibility(4);
        this.searchContainer.setFocusable(true);
        this.searchContainer.setFocusableInTouchMode(true);
        this.searchContainer.setClickable(true);
        this.searchContainer.setPadding(0, AndroidUtilities.dp(3.0f), 0, 0);
        ImageView imageView9 = new ImageView(context);
        this.searchUpButton = imageView9;
        imageView9.setScaleType(ImageView.ScaleType.CENTER);
        this.searchUpButton.setImageResource(R.drawable.msg_go_up);
        this.searchUpButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_searchPanelIcons), PorterDuff.Mode.MULTIPLY));
        this.searchUpButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), 1));
        this.searchContainer.addView(this.searchUpButton, LayoutHelper.createFrame(48.0f, 48.0f, 53, 0.0f, 0.0f, 48.0f, 0.0f));
        this.searchUpButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$PToHrPozdloDAGCXOHoYvR5SWfo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$30$ChatActivity(view5);
            }
        });
        this.searchUpButton.setContentDescription(LocaleController.getString("AccDescrSearchNext", R.string.AccDescrSearchNext));
        ImageView imageView10 = new ImageView(context);
        this.searchDownButton = imageView10;
        imageView10.setScaleType(ImageView.ScaleType.CENTER);
        this.searchDownButton.setImageResource(R.drawable.msg_go_down);
        this.searchDownButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_searchPanelIcons), PorterDuff.Mode.MULTIPLY));
        this.searchDownButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), 1));
        this.searchContainer.addView(this.searchDownButton, LayoutHelper.createFrame(48.0f, 48.0f, 53, 0.0f, 0.0f, 0.0f, 0.0f));
        this.searchDownButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$6kGZXOTe30b7XKWNcNc9MV4sqnA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$31$ChatActivity(view5);
            }
        });
        this.searchDownButton.setContentDescription(LocaleController.getString("AccDescrSearchPrev", R.string.AccDescrSearchPrev));
        TLRPC.Chat chat6 = this.currentChat;
        if (chat6 != null && (!ChatObject.isChannel(chat6) || this.currentChat.megagroup)) {
            ImageView imageView11 = new ImageView(context);
            this.searchUserButton = imageView11;
            imageView11.setScaleType(ImageView.ScaleType.CENTER);
            this.searchUserButton.setImageResource(R.drawable.msg_usersearch);
            this.searchUserButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_searchPanelIcons), PorterDuff.Mode.MULTIPLY));
            this.searchUserButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), 1));
            this.searchContainer.addView(this.searchUserButton, LayoutHelper.createFrame(48.0f, 48.0f, 51, 48.0f, 0.0f, 0.0f, 0.0f));
            this.searchUserButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$emjukZVx07pGY-K2oEKxWcO5wJw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view5) {
                    this.f$0.lambda$createView$32$ChatActivity(view5);
                }
            });
            this.searchUserButton.setContentDescription(LocaleController.getString("AccDescrSearchByUser", R.string.AccDescrSearchByUser));
        }
        ImageView imageView12 = new ImageView(context);
        this.searchCalendarButton = imageView12;
        imageView12.setScaleType(ImageView.ScaleType.CENTER);
        this.searchCalendarButton.setImageResource(R.drawable.msg_calendar);
        this.searchCalendarButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_searchPanelIcons), PorterDuff.Mode.MULTIPLY));
        this.searchCalendarButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), 1));
        this.searchContainer.addView(this.searchCalendarButton, LayoutHelper.createFrame(48, 48, 51));
        this.searchCalendarButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$_saXA__2HPGI7NX6qZOdq3qIAMA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$36$ChatActivity(view5);
            }
        });
        this.searchCalendarButton.setContentDescription(LocaleController.getString("JumpToDate", R.string.JumpToDate));
        SimpleTextView simpleTextView7 = new SimpleTextView(context);
        this.searchCountText = simpleTextView7;
        simpleTextView7.setTextColor(Theme.getColor(Theme.key_chat_searchPanelText));
        this.searchCountText.setTextSize(15);
        this.searchCountText.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.searchCountText.setGravity(5);
        this.searchContainer.addView(this.searchCountText, LayoutHelper.createFrame(-2.0f, -2.0f, 21, 0.0f, 0.0f, 108.0f, 0.0f));
        FrameLayout frameLayout13 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.33
            @Override // android.view.View
            public void onDraw(Canvas canvas) {
                int bottom = Theme.chat_composeShadowDrawable.getIntrinsicHeight();
                Theme.chat_composeShadowDrawable.setBounds(0, 0, getMeasuredWidth(), bottom);
                Theme.chat_composeShadowDrawable.draw(canvas);
                canvas.drawRect(0.0f, bottom, getMeasuredWidth(), getMeasuredHeight(), Theme.chat_composeBackgroundPaint);
            }
        };
        this.bottomOverlay = frameLayout13;
        frameLayout13.setWillNotDraw(false);
        this.bottomOverlay.setVisibility(4);
        this.bottomOverlay.setFocusable(true);
        this.bottomOverlay.setFocusableInTouchMode(true);
        this.bottomOverlay.setClickable(true);
        this.bottomOverlay.setPadding(0, AndroidUtilities.dp(2.0f), 0, 0);
        this.contentView.addView(this.bottomOverlay, LayoutHelper.createFrame(-1, 51, 80));
        TextView textView8 = new TextView(context);
        this.bottomOverlayText = textView8;
        textView8.setTextSize(1, 14.0f);
        this.bottomOverlayText.setGravity(17);
        this.bottomOverlayText.setMaxLines(2);
        this.bottomOverlayText.setEllipsize(TextUtils.TruncateAt.END);
        this.bottomOverlayText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
        this.bottomOverlayText.setTextColor(Theme.getColor(Theme.key_chat_secretChatStatusText));
        this.bottomOverlay.addView(this.bottomOverlayText, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 14.0f, 0.0f, 14.0f, 0.0f));
        FrameLayout frameLayout14 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ChatActivity.34
            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int allWidth = View.MeasureSpec.getSize(widthMeasureSpec);
                if (ChatActivity.this.bottomOverlayChatText.getVisibility() != 0 || ChatActivity.this.bottomOverlayChatText2.getVisibility() != 0) {
                    FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ChatActivity.this.bottomOverlayChatText.getLayoutParams();
                    layoutParams.width = allWidth;
                } else {
                    FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) ChatActivity.this.bottomOverlayChatText.getLayoutParams();
                    layoutParams2.width = allWidth / 2;
                    FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) ChatActivity.this.bottomOverlayChatText2.getLayoutParams();
                    layoutParams3.width = allWidth / 2;
                    layoutParams3.leftMargin = allWidth / 2;
                }
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            }

            @Override // android.view.View
            public void onDraw(Canvas canvas) {
                int bottom = Theme.chat_composeShadowDrawable.getIntrinsicHeight();
                Theme.chat_composeShadowDrawable.setBounds(0, 0, getMeasuredWidth(), bottom);
                Theme.chat_composeShadowDrawable.draw(canvas);
                canvas.drawRect(0.0f, bottom, getMeasuredWidth(), getMeasuredHeight(), Theme.chat_composeBackgroundPaint);
            }
        };
        this.bottomOverlayChat = frameLayout14;
        frameLayout14.setWillNotDraw(false);
        this.bottomOverlayChat.setPadding(0, AndroidUtilities.dp(3.0f), 0, 0);
        this.bottomOverlayChat.setVisibility(4);
        this.contentView.addView(this.bottomOverlayChat, LayoutHelper.createFrame(-1, 51, 80));
        TextView textView9 = new TextView(context);
        this.bottomOverlayChatText = textView9;
        textView9.setTextSize(1, 15.0f);
        this.bottomOverlayChatText.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.bottomOverlayChatText.setTextColor(Theme.getColor(Theme.key_chat_fieldOverlayText));
        this.bottomOverlayChatText.setGravity(17);
        this.bottomOverlayChat.addView(this.bottomOverlayChatText, LayoutHelper.createFrame(-1, -1.0f));
        this.bottomOverlayChatText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$1njaU93raoe0pgYZ3TRDpFNU0-Q
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$39$ChatActivity(view5);
            }
        });
        UnreadCounterTextView unreadCounterTextView = new UnreadCounterTextView(context);
        this.bottomOverlayChatText2 = unreadCounterTextView;
        unreadCounterTextView.setTextSize(1, 15.0f);
        this.bottomOverlayChatText2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.bottomOverlayChatText2.setTextColor(Theme.getColor(Theme.key_chat_fieldOverlayText));
        this.bottomOverlayChatText2.setGravity(17);
        this.bottomOverlayChatText2.setVisibility(8);
        this.bottomOverlayChat.addView(this.bottomOverlayChatText2, LayoutHelper.createFrame(-1, -1.0f));
        this.bottomOverlayChatText2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$hJT6f1XGyXJaT8v1WaBBvxRZfqU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$40$ChatActivity(view5);
            }
        });
        RadialProgressView radialProgressView2 = new RadialProgressView(context);
        this.bottomOverlayProgress = radialProgressView2;
        radialProgressView2.setSize(AndroidUtilities.dp(22.0f));
        this.bottomOverlayProgress.setProgressColor(Theme.getColor(Theme.key_chat_fieldOverlayText));
        this.bottomOverlayProgress.setVisibility(4);
        this.bottomOverlayProgress.setScaleX(0.1f);
        this.bottomOverlayProgress.setScaleY(0.1f);
        this.bottomOverlayProgress.setAlpha(1.0f);
        this.bottomOverlayChat.addView(this.bottomOverlayProgress, LayoutHelper.createFrame(30, 30, 17));
        TextView textView10 = new TextView(context);
        this.replyButton = textView10;
        textView10.setText(LocaleController.getString("Reply", R.string.Reply));
        this.replyButton.setGravity(16);
        this.replyButton.setTextSize(1, 15.0f);
        this.replyButton.setPadding(AndroidUtilities.dp(14.0f), 0, AndroidUtilities.dp(21.0f), 0);
        this.replyButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), 3));
        this.replyButton.setTextColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon));
        this.replyButton.setCompoundDrawablePadding(AndroidUtilities.dp(7.0f));
        this.replyButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        Drawable image = context.getResources().getDrawable(R.drawable.input_reply).mutate();
        image.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon), PorterDuff.Mode.MULTIPLY));
        this.replyButton.setCompoundDrawablesWithIntrinsicBounds(image, (Drawable) null, (Drawable) null, (Drawable) null);
        this.replyButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$HDA6u0qnteMhIO1amxyLesMnmwc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$41$ChatActivity(view5);
            }
        });
        this.bottomMessagesActionContainer.addView(this.replyButton, LayoutHelper.createFrame(-2, -1, 51));
        TextView textView11 = new TextView(context);
        this.forwardButton = textView11;
        textView11.setText(LocaleController.getString("Forward", R.string.Forward));
        this.forwardButton.setGravity(16);
        this.forwardButton.setTextSize(1, 15.0f);
        this.forwardButton.setPadding(AndroidUtilities.dp(21.0f), 0, AndroidUtilities.dp(21.0f), 0);
        this.forwardButton.setCompoundDrawablePadding(AndroidUtilities.dp(6.0f));
        this.forwardButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarActionModeDefaultSelector), 3));
        this.forwardButton.setTextColor(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon));
        this.forwardButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        Drawable image2 = context.getResources().getDrawable(R.drawable.input_forward).mutate();
        image2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarActionModeDefaultIcon), PorterDuff.Mode.MULTIPLY));
        this.forwardButton.setCompoundDrawablesWithIntrinsicBounds(image2, (Drawable) null, (Drawable) null, (Drawable) null);
        this.forwardButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$baa881G54MYI1ixIg00n11natRk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view5) {
                this.f$0.lambda$createView$42$ChatActivity(view5);
            }
        });
        this.bottomMessagesActionContainer.addView(this.forwardButton, LayoutHelper.createFrame(-2, -1, 53));
        this.contentView.addView(this.searchContainer, LayoutHelper.createFrame(-1, 51, 80));
        UndoView undoView = new UndoView(context);
        this.undoView = undoView;
        this.contentView.addView(undoView, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 8.0f, 0.0f, 8.0f, 8.0f));
        if (this.currentChat != null) {
            HintView hintView = new HintView(getParentActivity(), 2);
            this.slowModeHint = hintView;
            hintView.setAlpha(0.0f);
            this.slowModeHint.setVisibility(4);
            this.contentView.addView(this.slowModeHint, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 19.0f, 0.0f, 19.0f, 0.0f));
        }
        this.chatAdapter.updateRows();
        if (this.loading && this.messages.isEmpty()) {
            listViewShowEmptyView(true, this.chatAdapter.botInfoRow == -1);
            z = false;
        } else {
            z = false;
            listViewShowEmptyView(false, false);
        }
        checkBotKeyboard();
        updateBottomOverlay();
        updateSecretStatus();
        updateTopPanel(z);
        updatePinnedMessageView(true);
        try {
            if (this.currentEncryptedChat != null && Build.VERSION.SDK_INT >= 23 && (SharedConfig.passcodeHash.length() == 0 || SharedConfig.allowScreenCapture)) {
                MediaController.getInstance().setFlagSecure(this, true);
            }
        } catch (Throwable e2) {
            FileLog.e(e2);
        }
        if (oldMessage2 != null) {
            this.chatActivityEnterView.setFieldText(oldMessage2);
        }
        fixLayoutInternal();
        if (isSysNotifyMessage().booleanValue()) {
            int i2 = this.createUnreadMessageAfterId;
            if (i2 == 0) {
                int i3 = this.returnToMessageId;
                if (i3 <= 0) {
                    scrollToLastMessage(true);
                } else {
                    scrollToMessageId(i3, 0, true, this.returnToLoadIndex, false);
                }
            } else {
                scrollToMessageId(i2, 0, false, this.returnToLoadIndex, false);
            }
        }
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$6, reason: invalid class name */
    class AnonymousClass6 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass6() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(final int id) {
            if (id == -1) {
                if (ChatActivity.this.actionBar.isActionModeShowed()) {
                    for (int a = 1; a >= 0; a--) {
                        ChatActivity.this.selectedMessagesIds[a].clear();
                        ChatActivity.this.selectedMessagesCanCopyIds[a].clear();
                        ChatActivity.this.selectedMessagesCanStarIds[a].clear();
                    }
                    ChatActivity.this.hideActionMode();
                    ChatActivity.this.updatePinnedMessageView(true);
                    ChatActivity.this.updateVisibleRows();
                    return;
                }
                ChatActivity.this.finishFragment();
                return;
            }
            if (id == 0) {
                ChatActivity.this.showOrUpdateActionBarMenuPop();
                return;
            }
            if (id == 10) {
                String str = "";
                int previousUid = 0;
                for (int a2 = 1; a2 >= 0; a2--) {
                    ArrayList<Integer> ids = new ArrayList<>();
                    for (int b = 0; b < ChatActivity.this.selectedMessagesCanCopyIds[a2].size(); b++) {
                        ids.add(Integer.valueOf(ChatActivity.this.selectedMessagesCanCopyIds[a2].keyAt(b)));
                    }
                    if (ChatActivity.this.currentEncryptedChat == null) {
                        Collections.sort(ids);
                    } else {
                        Collections.sort(ids, Collections.reverseOrder());
                    }
                    for (int b2 = 0; b2 < ids.size(); b2++) {
                        Integer messageId = ids.get(b2);
                        MessageObject messageObject = (MessageObject) ChatActivity.this.selectedMessagesCanCopyIds[a2].get(messageId.intValue());
                        if (str.length() != 0) {
                            str = str + "\n\n";
                        }
                        StringBuilder sb = new StringBuilder();
                        sb.append(str);
                        sb.append(ChatActivity.this.getMessageContent(messageObject, previousUid, ids.size() != 1 && (ChatActivity.this.currentUser == null || !ChatActivity.this.currentUser.self)));
                        str = sb.toString();
                        previousUid = messageObject.messageOwner.from_id;
                    }
                }
                if (str.length() != 0) {
                    AndroidUtilities.addToClipboard(str);
                }
                for (int a3 = 1; a3 >= 0; a3--) {
                    ChatActivity.this.selectedMessagesIds[a3].clear();
                    ChatActivity.this.selectedMessagesCanCopyIds[a3].clear();
                    ChatActivity.this.selectedMessagesCanStarIds[a3].clear();
                }
                ChatActivity.this.hideActionMode();
                ChatActivity.this.updatePinnedMessageView(true);
                ChatActivity.this.updateVisibleRows();
                return;
            }
            if (id == 12) {
                if (ChatActivity.this.getParentActivity() != null) {
                    ChatActivity.this.createDeleteMessagesAlert(null, null);
                    return;
                }
                return;
            }
            if (id == 11) {
                ChatActivity.this.openForward();
                return;
            }
            if (id == 13) {
                if (ChatActivity.this.getParentActivity() == null) {
                    return;
                }
                ChatActivity chatActivity = ChatActivity.this;
                chatActivity.showDialog(AlertsCreator.createTTLAlert(chatActivity.getParentActivity(), ChatActivity.this.currentEncryptedChat).create());
                return;
            }
            if (id == 15 || id == 16) {
                if (ChatActivity.this.getParentActivity() != null) {
                    final boolean isChat = ((int) ChatActivity.this.dialog_id) < 0 && ((int) (ChatActivity.this.dialog_id >> 32)) != 1;
                    AlertsCreator.createClearOrDeleteDialogAlert(ChatActivity.this, id == 15, ChatActivity.this.currentChat, ChatActivity.this.currentUser, ChatActivity.this.currentEncryptedChat != null, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$6$cEdHGS10KXqEY6hBf8O9LMnU25Y
                        @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                        public final void run(boolean z) throws Exception {
                            this.f$0.lambda$onItemClick$2$ChatActivity$6(id, isChat, z);
                        }
                    });
                    return;
                }
                return;
            }
            if (id == 17) {
                if (ChatActivity.this.currentUser != null && ChatActivity.this.getParentActivity() != null) {
                    if (ChatActivity.this.addToContactsButton.getTag() != null) {
                        ChatActivity chatActivity2 = ChatActivity.this;
                        chatActivity2.shareMyContact(((Integer) chatActivity2.addToContactsButton.getTag()).intValue(), null);
                        return;
                    } else {
                        if (ChatActivity.this.currentUser != null) {
                            ChatActivity chatActivity3 = ChatActivity.this;
                            chatActivity3.presentFragment(new AddContactsInfoActivity(null, chatActivity3.currentUser));
                            return;
                        }
                        return;
                    }
                }
                return;
            }
            if (id == 18) {
                ChatActivity.this.toggleMute(false);
                return;
            }
            if (id == 24) {
                try {
                    ChatActivity.this.getMediaDataController().installShortcut(ChatActivity.this.currentUser.id);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            if (id == 21) {
                AlertsCreator.createReportAlert(ChatActivity.this.getParentActivity(), ChatActivity.this.dialog_id, 0, ChatActivity.this);
                return;
            }
            if (id == 22) {
                for (int a4 = 0; a4 < 2; a4++) {
                    for (int b3 = 0; b3 < ChatActivity.this.selectedMessagesCanStarIds[a4].size(); b3++) {
                        MessageObject msg = (MessageObject) ChatActivity.this.selectedMessagesCanStarIds[a4].valueAt(b3);
                        ChatActivity.this.getMediaDataController().addRecentSticker(2, msg, msg.getDocument(), (int) (System.currentTimeMillis() / 1000), !ChatActivity.this.hasUnfavedSelected);
                    }
                }
                for (int a5 = 1; a5 >= 0; a5--) {
                    ChatActivity.this.selectedMessagesIds[a5].clear();
                    ChatActivity.this.selectedMessagesCanCopyIds[a5].clear();
                    ChatActivity.this.selectedMessagesCanStarIds[a5].clear();
                }
                ChatActivity.this.hideActionMode();
                ChatActivity.this.updatePinnedMessageView(true);
                ChatActivity.this.updateVisibleRows();
                return;
            }
            if (id == 23) {
                MessageObject messageObject2 = null;
                for (int a6 = 1; a6 >= 0; a6--) {
                    if (messageObject2 == null && ChatActivity.this.selectedMessagesIds[a6].size() == 1) {
                        ArrayList<Integer> ids2 = new ArrayList<>();
                        for (int b4 = 0; b4 < ChatActivity.this.selectedMessagesIds[a6].size(); b4++) {
                            ids2.add(Integer.valueOf(ChatActivity.this.selectedMessagesIds[a6].keyAt(b4)));
                        }
                        messageObject2 = (MessageObject) ChatActivity.this.messagesDict[a6].get(ids2.get(0).intValue());
                    }
                    ChatActivity.this.selectedMessagesIds[a6].clear();
                    ChatActivity.this.selectedMessagesCanCopyIds[a6].clear();
                    ChatActivity.this.selectedMessagesCanStarIds[a6].clear();
                }
                ChatActivity.this.startEditingMessageObject(messageObject2);
                ChatActivity.this.hideActionMode();
                ChatActivity.this.updatePinnedMessageView(true);
                ChatActivity.this.updateVisibleRows();
                return;
            }
            if (id == 14) {
                if (ChatActivity.this.chatAttachAlert != null) {
                    ChatActivity.this.chatAttachAlert.setEditingMessageObject(null);
                }
                ChatActivity.this.openAttachMenu();
                return;
            }
            if (id == 30) {
                ChatActivity.this.getSendMessagesHelper().sendMessage("/help", ChatActivity.this.dialog_id, null, null, false, null, null, null, true, 0);
                return;
            }
            if (id == 31) {
                ChatActivity.this.getSendMessagesHelper().sendMessage("/settings", ChatActivity.this.dialog_id, null, null, false, null, null, null, true, 0);
                return;
            }
            if (id == 40) {
                ChatActivity.this.openSearchWithText(null);
                return;
            }
            if (id == 32) {
                if (ChatActivity.this.currentUser != null && ChatActivity.this.actionBarHelper != null) {
                    ChatActivity.this.actionBarHelper.startCall(ChatActivity.this.currentUser);
                    return;
                }
                return;
            }
            if (id == 50) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                    ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedBold();
                    return;
                }
                return;
            }
            if (id == 51) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                    ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedItalic();
                    return;
                }
                return;
            }
            if (id == 52) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                    ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedMono();
                    return;
                }
                return;
            }
            if (id == 55) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                    ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedStrike();
                    return;
                }
                return;
            }
            if (id == 56) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                    ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedUnderline();
                    return;
                }
                return;
            }
            if (id == 53) {
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                    ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedUrl();
                    return;
                }
                return;
            }
            if (id == 54 && ChatActivity.this.chatActivityEnterView != null) {
                ChatActivity.this.chatActivityEnterView.getEditField().setSelectionOverride(ChatActivity.this.editTextStart, ChatActivity.this.editTextEnd);
                ChatActivity.this.chatActivityEnterView.getEditField().makeSelectedRegular();
            }
        }

        public /* synthetic */ void lambda$onItemClick$2$ChatActivity$6(final int id, final boolean isChat, final boolean param) throws Exception {
            if (id == 15 && ChatObject.isChannel(ChatActivity.this.currentChat) && (!ChatActivity.this.currentChat.megagroup || !TextUtils.isEmpty(ChatActivity.this.currentChat.username))) {
                ChatActivity.this.getMessagesController().deleteDialog(ChatActivity.this.dialog_id, 2, param);
                return;
            }
            if (id == 15) {
                ChatActivity.this.clearingHistory = true;
                ChatActivity.this.undoView.setAdditionalTranslationY(0.0f);
                ChatActivity.this.undoView.showWithAction(ChatActivity.this.dialog_id, id == 15 ? 0 : 1, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$6$I0E8jGHVApQWxXV2HpCU_LGuA9w
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        this.f$0.lambda$null$0$ChatActivity$6(id, param, isChat);
                    }
                }, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$6$9acpXu9dhOyXd0WWpBErF2rbJ4k
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$ChatActivity$6();
                    }
                });
                ChatActivity.this.chatAdapter.notifyDataSetChanged();
                return;
            }
            ChatActivity.this.getNotificationCenter().removeObserver(ChatActivity.this, NotificationCenter.closeChats);
            ChatActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
            ChatActivity.this.finishFragment();
            ChatActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.needDeleteDialog, Long.valueOf(ChatActivity.this.dialog_id), ChatActivity.this.currentUser, ChatActivity.this.currentChat, Boolean.valueOf(param));
        }

        public /* synthetic */ void lambda$null$0$ChatActivity$6(int id, boolean param, boolean isChat) throws Exception {
            if (id == 15) {
                if (ChatActivity.this.chatInfo != null && ChatActivity.this.chatInfo.pinned_msg_id != 0) {
                    SharedPreferences preferences = MessagesController.getNotificationsSettings(ChatActivity.this.currentAccount);
                    preferences.edit().putInt("pin_" + ChatActivity.this.dialog_id, ChatActivity.this.chatInfo.pinned_msg_id).commit();
                    ChatActivity.this.updatePinnedMessageView(true);
                } else if (ChatActivity.this.userInfo != null && ChatActivity.this.userInfo.pinned_msg_id != 0) {
                    SharedPreferences preferences2 = MessagesController.getNotificationsSettings(ChatActivity.this.currentAccount);
                    preferences2.edit().putInt("pin_" + ChatActivity.this.dialog_id, ChatActivity.this.userInfo.pinned_msg_id).commit();
                    ChatActivity.this.updatePinnedMessageView(true);
                }
                ChatActivity.this.getMessagesController().deleteDialog(ChatActivity.this.dialog_id, 1, param);
                ChatActivity.this.clearingHistory = false;
                ChatActivity.this.clearHistory(false);
                ChatActivity.this.chatAdapter.notifyDataSetChanged();
                return;
            }
            if (isChat && !ChatObject.isNotInChat(ChatActivity.this.currentChat)) {
                ChatActivity.this.getMessagesController().deleteUserFromChat((int) (-ChatActivity.this.dialog_id), ChatActivity.this.getMessagesController().getUser(Integer.valueOf(ChatActivity.this.getUserConfig().getClientUserId())), null);
            } else {
                ChatActivity.this.getMessagesController().deleteDialog(ChatActivity.this.dialog_id, 0, param);
            }
            ChatActivity.this.finishFragment();
        }

        public /* synthetic */ void lambda$null$1$ChatActivity$6() {
            ChatActivity.this.clearingHistory = false;
            ChatActivity.this.chatAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$7, reason: invalid class name */
    class AnonymousClass7 extends ActionBarMenuItem.ActionBarMenuItemSearchListener {
        boolean searchWas;

        AnonymousClass7() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
        public void onSearchCollapse() {
            ChatActivity.this.searchCalendarButton.setVisibility(0);
            if (ChatActivity.this.searchUserButton != null) {
                ChatActivity.this.searchUserButton.setVisibility(0);
            }
            if (ChatActivity.this.searchingForUser) {
                ChatActivity.this.mentionsAdapter.searchUsernameOrHashtag(null, 0, null, false);
                ChatActivity.this.searchingForUser = false;
            }
            ChatActivity.this.mentionLayoutManager.setReverseLayout(false);
            ChatActivity.this.mentionsAdapter.setSearchingMentions(false);
            ChatActivity.this.searchingUserMessages = null;
            ChatActivity.this.searchItem.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
            ChatActivity.this.searchItem.setSearchFieldCaption(null);
            if (ChatActivity.this.editTextItem.getTag() != null) {
                if (ChatActivity.this.headerItem != null) {
                    ChatActivity.this.headerItem.setVisibility(8);
                }
                if (ChatActivity.this.editTextItem != null) {
                    ChatActivity.this.editTextItem.setVisibility(0);
                }
                if (ChatActivity.this.attachItem != null) {
                    ChatActivity.this.attachItem.setVisibility(8);
                }
            } else if (ChatActivity.this.chatActivityEnterView.hasText()) {
                if (ChatActivity.this.headerItem != null) {
                    ChatActivity.this.headerItem.setVisibility(8);
                }
                if (ChatActivity.this.editTextItem != null) {
                    ChatActivity.this.editTextItem.setVisibility(8);
                }
                if (ChatActivity.this.attachItem != null) {
                    ChatActivity.this.attachItem.setVisibility(0);
                }
            } else {
                if (ChatActivity.this.headerItem != null) {
                    ChatActivity.this.headerItem.setVisibility(0);
                }
                if (ChatActivity.this.editTextItem != null) {
                    ChatActivity.this.editTextItem.setVisibility(8);
                }
                if (ChatActivity.this.attachItem != null) {
                    ChatActivity.this.attachItem.setVisibility(8);
                }
            }
            ChatActivity.this.searchItem.setVisibility(8);
            ChatActivity.this.removeSelectedMessageHighlight();
            ChatActivity.this.updateBottomOverlay();
            ChatActivity.this.updatePinnedMessageView(true);
            ChatActivity.this.updateVisibleRows();
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
        public void onSearchExpand() {
            if (!ChatActivity.this.openSearchKeyboard) {
                return;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$7$RBBHFN-ITOVih7Gm19t4Vjh6Bw4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onSearchExpand$0$ChatActivity$7();
                }
            }, 300L);
        }

        public /* synthetic */ void lambda$onSearchExpand$0$ChatActivity$7() {
            this.searchWas = false;
            ChatActivity.this.searchItem.getSearchField().requestFocus();
            AndroidUtilities.showKeyboard(ChatActivity.this.searchItem.getSearchField());
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
        public void onSearchPressed(EditText editText) {
            this.searchWas = true;
            ChatActivity.this.updateSearchButtons(0, 0, -1);
            ChatActivity.this.getMediaDataController().searchMessagesInChat(editText.getText().toString(), ChatActivity.this.dialog_id, ChatActivity.this.mergeDialogId, ChatActivity.this.classGuid, 0, ChatActivity.this.searchingUserMessages);
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
        public void onTextChanged(EditText editText) {
            if (ChatActivity.this.searchingForUser) {
                ChatActivity.this.mentionsAdapter.searchUsernameOrHashtag("@" + editText.getText().toString(), 0, ChatActivity.this.messages, true);
                return;
            }
            if (!ChatActivity.this.searchingForUser && ChatActivity.this.searchingUserMessages == null && ChatActivity.this.searchUserButton != null && TextUtils.equals(editText.getText(), LocaleController.getString("SearchFrom", R.string.SearchFrom))) {
                ChatActivity.this.searchUserButton.callOnClick();
            }
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
        public void onCaptionCleared() {
            if (ChatActivity.this.searchingUserMessages != null) {
                ChatActivity.this.searchUserButton.callOnClick();
                return;
            }
            if (ChatActivity.this.searchingForUser) {
                ChatActivity.this.mentionsAdapter.searchUsernameOrHashtag(null, 0, null, false);
                ChatActivity.this.searchingForUser = false;
                ChatActivity.this.searchItem.setSearchFieldText("", true);
            }
            ChatActivity.this.searchItem.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
            ChatActivity.this.searchCalendarButton.setVisibility(0);
            ChatActivity.this.searchUserButton.setVisibility(0);
            ChatActivity.this.searchingUserMessages = null;
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
        public boolean forceShowClear() {
            return ChatActivity.this.searchingForUser;
        }
    }

    static /* synthetic */ boolean lambda$createView$4(View v, MotionEvent event) {
        return true;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$9, reason: invalid class name */
    class AnonymousClass9 extends SizeNotifierFrameLayout {
        ArrayList<ChatMessageCell> drawCaptionAfter;
        ArrayList<ChatMessageCell> drawNamesAfter;
        ArrayList<ChatMessageCell> drawTimeAfter;
        int inputFieldHeight;

        AnonymousClass9(Context context) {
            super(context);
            this.inputFieldHeight = 0;
            this.drawTimeAfter = new ArrayList<>();
            this.drawNamesAfter = new ArrayList<>();
            this.drawCaptionAfter = new ArrayList<>();
        }

        @Override // android.view.ViewGroup, android.view.View
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
            if (messageObject != null) {
                if ((messageObject.isRoundVideo() || messageObject.isVideo()) && messageObject.eventId == 0 && messageObject.getDialogId() == ChatActivity.this.dialog_id) {
                    MediaController.getInstance().setTextureView(ChatActivity.this.createTextureView(false), ChatActivity.this.aspectRatioFrameLayout, ChatActivity.this.videoPlayerContainer, true);
                }
            }
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchTouchEvent(MotionEvent ev) {
            if (ChatActivity.this.scrimView != null) {
                return false;
            }
            if (ChatActivity.this.chatActivityEnterView != null && ChatActivity.this.chatActivityEnterView.isStickersExpanded() && ev.getY() < ChatActivity.this.chatActivityEnterView.getY()) {
                return false;
            }
            return super.dispatchTouchEvent(ev);
        }

        /* JADX WARN: Removed duplicated region for block: B:20:0x0044 A[PHI: r2
          0x0044: PHI (r2v1 'isRoundVideo' boolean) = (r2v0 'isRoundVideo' boolean), (r2v0 'isRoundVideo' boolean), (r2v3 'isRoundVideo' boolean) binds: [B:12:0x002b, B:14:0x0033, B:18:0x0040] A[DONT_GENERATE, DONT_INLINE]] */
        @Override // android.view.ViewGroup
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        protected boolean drawChild(android.graphics.Canvas r11, android.view.View r12, long r13) {
            /*
                Method dump skipped, instruction units count: 411
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.AnonymousClass9.drawChild(android.graphics.Canvas, android.view.View, long):boolean");
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout
        protected boolean isActionBarVisible() {
            return ChatActivity.this.actionBar.getVisibility() == 0;
        }

        private void drawChildElement(Canvas canvas, float listTop, ChatMessageCell cell, int type) {
            canvas.save();
            canvas.clipRect(ChatActivity.this.chatListView.getLeft(), listTop, ChatActivity.this.chatListView.getRight(), ChatActivity.this.chatListView.getY() + ChatActivity.this.chatListView.getMeasuredHeight());
            canvas.translate(ChatActivity.this.chatListView.getLeft() + cell.getLeft(), ChatActivity.this.chatListView.getY() + cell.getTop());
            if (type == 0) {
                cell.drawTime(canvas);
            } else {
                if (type != 1) {
                    cell.drawCaptionLayout(canvas, (cell.getCurrentPosition().flags & 1) == 0);
                } else {
                    cell.drawNamesLayout(canvas);
                }
            }
            canvas.restore();
        }

        /* JADX WARN: Removed duplicated region for block: B:20:0x00c6  */
        @Override // android.view.ViewGroup, android.view.View
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        protected void dispatchDraw(android.graphics.Canvas r24) {
            /*
                Method dump skipped, instruction units count: 1013
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.AnonymousClass9.dispatchDraw(android.graphics.Canvas):void");
        }

        /* JADX WARN: Type inference failed for: r0v49 */
        /* JADX WARN: Type inference failed for: r0v50 */
        /* JADX WARN: Type inference failed for: r0v53, types: [boolean, int] */
        /* JADX WARN: Type inference failed for: r0v65 */
        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int listViewTopHeight;
            int i;
            int maxHeight;
            int height;
            ?? r0;
            int height2;
            int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
            int allHeight = View.MeasureSpec.getSize(heightMeasureSpec);
            setMeasuredDimension(widthSize, allHeight);
            int heightSize = allHeight - getPaddingTop();
            measureChildWithMargins(ChatActivity.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
            int actionBarHeight = ChatActivity.this.actionBar.getMeasuredHeight();
            if (ChatActivity.this.actionBar.getVisibility() == 0) {
                heightSize -= actionBarHeight;
            }
            int keyboardSize = getKeyboardHeight();
            boolean isShowMenuEmojiView = isShowMenuEmojiView();
            if (!isShowMenuEmojiView && keyboardSize > AndroidUtilities.dp(20.0f)) {
                ChatActivity.this.globalIgnoreLayout = true;
                ChatActivity.this.chatActivityEnterView.hideEmojiView();
                ChatActivity.this.globalIgnoreLayout = false;
            } else if (!AndroidUtilities.isInMultiwindow) {
                heightSize -= ChatActivity.this.chatActivityEnterView.getEmojiPadding();
                allHeight -= ChatActivity.this.chatActivityEnterView.getEmojiPadding();
            }
            int childCount = getChildCount();
            measureChildWithMargins(ChatActivity.this.chatActivityEnterView, widthMeasureSpec, 0, heightMeasureSpec, 0);
            if (!ChatActivity.this.isSysNotifyMessage().booleanValue()) {
                if (!ChatActivity.this.inPreviewMode) {
                    this.inputFieldHeight = ChatActivity.this.chatActivityEnterView.getMeasuredHeight();
                    listViewTopHeight = AndroidUtilities.dp(49.0f);
                } else {
                    this.inputFieldHeight = 0;
                    listViewTopHeight = 0;
                }
            } else {
                this.inputFieldHeight = ChatActivity.this.chatActivityEnterView.getMeasuredHeight();
                listViewTopHeight = 0;
            }
            int i2 = 0;
            while (i2 < childCount) {
                View child = getChildAt(i2);
                if (child == null || child.getVisibility() == 8 || child == ChatActivity.this.chatActivityEnterView) {
                    i = i2;
                } else if (child != ChatActivity.this.actionBar) {
                    if (child != ChatActivity.this.chatListView) {
                        if (child != ChatActivity.this.progressView) {
                            if (child != ChatActivity.this.instantCameraView && child != ChatActivity.this.overlayView) {
                                if (child != ChatActivity.this.emptyViewContainer) {
                                    if (!ChatActivity.this.chatActivityEnterView.isPopupView(child)) {
                                        if (child == ChatActivity.this.mentionContainer) {
                                            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ChatActivity.this.mentionContainer.getLayoutParams();
                                            if (!ChatActivity.this.mentionsAdapter.isBannedInline()) {
                                                ChatActivity.this.mentionListViewIgnoreLayout = true;
                                                if (!ChatActivity.this.mentionsAdapter.isBotContext() || !ChatActivity.this.mentionsAdapter.isMediaLayout()) {
                                                    int size = ChatActivity.this.mentionsAdapter.getItemCount();
                                                    int maxHeight2 = 0;
                                                    if (ChatActivity.this.mentionsAdapter.isBotContext()) {
                                                        if (ChatActivity.this.mentionsAdapter.getBotContextSwitch() != null) {
                                                            maxHeight2 = 0 + 36;
                                                            size--;
                                                        }
                                                        maxHeight = maxHeight2 + (size * 68);
                                                    } else {
                                                        maxHeight = 0 + (size * 36);
                                                    }
                                                    height = (maxHeight != 0 ? AndroidUtilities.dp(2.0f) : 0) + (heightSize - ChatActivity.this.chatActivityEnterView.getMeasuredHeight());
                                                    int padding = Math.max(0, height - AndroidUtilities.dp(Math.min(maxHeight, 122.399994f)));
                                                    if (ChatActivity.this.mentionLayoutManager.getReverseLayout()) {
                                                        r0 = 0;
                                                        ChatActivity.this.mentionListView.setPadding(0, 0, 0, padding);
                                                    } else {
                                                        r0 = 0;
                                                        ChatActivity.this.mentionListView.setPadding(0, padding, 0, 0);
                                                    }
                                                } else {
                                                    int maxHeight3 = ChatActivity.this.mentionGridLayoutManager.getRowsCount(widthSize) * 102;
                                                    if (ChatActivity.this.mentionsAdapter.isBotContext() && ChatActivity.this.mentionsAdapter.getBotContextSwitch() != null) {
                                                        maxHeight3 += 34;
                                                    }
                                                    int height3 = (heightSize - ChatActivity.this.chatActivityEnterView.getMeasuredHeight()) + (maxHeight3 != 0 ? AndroidUtilities.dp(2.0f) : 0);
                                                    int padding2 = Math.max(0, height3 - AndroidUtilities.dp(Math.min(maxHeight3, 122.399994f)));
                                                    if (ChatActivity.this.mentionLayoutManager.getReverseLayout()) {
                                                        height2 = height3;
                                                        ChatActivity.this.mentionListView.setPadding(0, 0, 0, padding2);
                                                    } else {
                                                        height2 = height3;
                                                        ChatActivity.this.mentionListView.setPadding(0, padding2, 0, 0);
                                                    }
                                                    height = height2;
                                                    r0 = 0;
                                                }
                                                layoutParams.height = height;
                                                layoutParams.topMargin = r0;
                                                ChatActivity.this.mentionListViewIgnoreLayout = r0;
                                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(layoutParams.height, 1073741824));
                                            } else {
                                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, Integer.MIN_VALUE));
                                            }
                                            i = i2;
                                        } else {
                                            i = i2;
                                            measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                                        }
                                    } else if (AndroidUtilities.isInMultiwindow) {
                                        if (AndroidUtilities.isTablet()) {
                                            child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(320.0f), (((heightSize - this.inputFieldHeight) + actionBarHeight) - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                                            i = i2;
                                        } else {
                                            child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec((((heightSize - this.inputFieldHeight) + actionBarHeight) - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
                                            i = i2;
                                        }
                                    } else {
                                        int i3 = child.getLayoutParams().height;
                                        child.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                                        i = i2;
                                    }
                                } else {
                                    int contentWidthSpec = View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824);
                                    int contentHeightSpec = View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824);
                                    child.measure(contentWidthSpec, contentHeightSpec);
                                    i = i2;
                                }
                            } else {
                                View child2 = child;
                                i = i2;
                                int contentWidthSpec2 = View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824);
                                int contentHeightSpec2 = View.MeasureSpec.makeMeasureSpec((allHeight - this.inputFieldHeight) + AndroidUtilities.dp(3.0f), 1073741824);
                                child2.measure(contentWidthSpec2, contentHeightSpec2);
                            }
                        } else {
                            int contentWidthSpec3 = View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824);
                            int contentHeightSpec3 = View.MeasureSpec.makeMeasureSpec(Math.max(AndroidUtilities.dp(10.0f), ((heightSize - this.inputFieldHeight) - ((!ChatActivity.this.inPreviewMode || Build.VERSION.SDK_INT < 21) ? 0 : AndroidUtilities.statusBarHeight)) + AndroidUtilities.dp((ChatActivity.this.chatActivityEnterView.isTopViewVisible() ? 48 : 0) + 2)), 1073741824);
                            child.measure(contentWidthSpec3, contentHeightSpec3);
                            i = i2;
                        }
                    } else {
                        if (ChatActivity.this.chatActivityEnterView.getAlpha() != 1.0f) {
                            ChatActivity.this.chatListView.setTranslationY(this.inputFieldHeight - AndroidUtilities.dp(51.0f));
                        }
                        ChatActivity chatActivity = ChatActivity.this;
                        chatActivity.chatListViewClipTop = chatActivity.inPreviewMode ? 0 : this.inputFieldHeight - AndroidUtilities.dp(51.0f);
                        int contentWidthSpec4 = View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824);
                        int contentHeightSpec4 = View.MeasureSpec.makeMeasureSpec(Math.max(AndroidUtilities.dp(10.0f), (heightSize - listViewTopHeight) - ((!ChatActivity.this.inPreviewMode || Build.VERSION.SDK_INT < 21) ? 0 : AndroidUtilities.statusBarHeight)), 1073741824);
                        child.measure(contentWidthSpec4, contentHeightSpec4);
                        i = i2;
                    }
                } else {
                    i = i2;
                }
                i2 = i + 1;
            }
            if (ChatActivity.this.fixPaddingsInLayout) {
                ChatActivity.this.globalIgnoreLayout = true;
                ChatActivity.this.checkListViewPaddingsInternal();
                ChatActivity.this.fixPaddingsInLayout = false;
                ChatActivity.this.chatListView.measure(View.MeasureSpec.makeMeasureSpec(ChatActivity.this.chatListView.getMeasuredWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(ChatActivity.this.chatListView.getMeasuredHeight(), 1073741824));
                ChatActivity.this.globalIgnoreLayout = false;
            }
            if (ChatActivity.this.scrollToPositionOnRecreate != -1) {
                final int scrollTo = ChatActivity.this.scrollToPositionOnRecreate;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$9$fjiZMk_F79xWUPJ6umiS7fUG98g
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onMeasure$0$ChatActivity$9(scrollTo);
                    }
                });
                ChatActivity.this.scrollToPositionOnRecreate = -1;
            }
        }

        public /* synthetic */ void lambda$onMeasure$0$ChatActivity$9(int scrollTo) {
            ChatActivity.this.chatLayoutManager.scrollToPositionWithOffset(scrollTo, ChatActivity.this.scrollToOffsetOnRecreate);
        }

        @Override // android.view.View, android.view.ViewParent
        public void requestLayout() {
            if (ChatActivity.this.globalIgnoreLayout) {
                return;
            }
            super.requestLayout();
        }

        @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int childLeft;
            int childTop;
            int count = getChildCount();
            int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow) ? 0 : ChatActivity.this.chatActivityEnterView.getEmojiPadding();
            if (isShowMenuEmojiView()) {
                paddingBottom = ChatActivity.this.chatActivityEnterView.getEmojiPadding();
            }
            setBottomClip(paddingBottom);
            for (int i = 0; i < count; i++) {
                View child = getChildAt(i);
                if (child != null && child.getVisibility() != 8) {
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
                    if (i2 == 1) {
                        int childLeft2 = r - l;
                        childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                    } else if (i2 == 5) {
                        int childLeft3 = r - width;
                        childLeft = childLeft3 - lp.rightMargin;
                    } else {
                        childLeft = lp.leftMargin;
                    }
                    if (verticalGravity == 16) {
                        int childTop2 = b - paddingBottom;
                        childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                    } else if (verticalGravity == 48) {
                        int childTop3 = lp.topMargin;
                        childTop = childTop3 + getPaddingTop();
                        if (child != ChatActivity.this.actionBar && ChatActivity.this.actionBar.getVisibility() == 0) {
                            childTop += ChatActivity.this.actionBar.getMeasuredHeight();
                            if (ChatActivity.this.inPreviewMode && Build.VERSION.SDK_INT >= 21) {
                                childTop += AndroidUtilities.statusBarHeight;
                            }
                        }
                    } else if (verticalGravity == 80) {
                        int childTop4 = b - paddingBottom;
                        childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                    } else {
                        childTop = lp.topMargin;
                    }
                    if (child != ChatActivity.this.mentionContainer) {
                        if (child == ChatActivity.this.pagedownButton) {
                            if (!ChatActivity.this.inPreviewMode) {
                                childTop -= ChatActivity.this.chatActivityEnterView.getMeasuredHeight();
                            }
                        } else if (child == ChatActivity.this.mentiondownButton) {
                            if (!ChatActivity.this.inPreviewMode) {
                                childTop -= ChatActivity.this.chatActivityEnterView.getMeasuredHeight();
                            }
                        } else if (child == ChatActivity.this.emptyViewContainer) {
                            childTop -= (this.inputFieldHeight / 2) - (ChatActivity.this.actionBar.getVisibility() == 0 ? ChatActivity.this.actionBar.getMeasuredHeight() / 2 : 0);
                        } else if (!ChatActivity.this.chatActivityEnterView.isPopupView(child)) {
                            if (child != ChatActivity.this.gifHintTextView && child != ChatActivity.this.voiceHintTextView && child != ChatActivity.this.mediaBanTooltip) {
                                if (child == ChatActivity.this.chatListView) {
                                    if (!ChatActivity.this.inPreviewMode) {
                                        childTop -= this.inputFieldHeight - AndroidUtilities.dp(51.0f);
                                    }
                                } else if (child != ChatActivity.this.progressView) {
                                    if (child == ChatActivity.this.actionBar) {
                                        if (ChatActivity.this.inPreviewMode && Build.VERSION.SDK_INT >= 21) {
                                            childTop += AndroidUtilities.statusBarHeight;
                                        }
                                        childTop -= getPaddingTop();
                                    } else if (child == ChatActivity.this.videoPlayerContainer) {
                                        childTop = ChatActivity.this.actionBar.getMeasuredHeight();
                                    } else if (child == ChatActivity.this.instantCameraView || child == ChatActivity.this.overlayView) {
                                        childTop = 0;
                                    }
                                } else if (ChatActivity.this.chatActivityEnterView.isTopViewVisible()) {
                                    childTop -= AndroidUtilities.dp(48.0f);
                                }
                            } else {
                                childTop -= this.inputFieldHeight;
                            }
                        } else if (AndroidUtilities.isInMultiwindow) {
                            childTop = (ChatActivity.this.chatActivityEnterView.getTop() - child.getMeasuredHeight()) + AndroidUtilities.dp(1.0f);
                        } else {
                            childTop = ChatActivity.this.chatActivityEnterView.getBottom();
                        }
                    } else {
                        childTop -= ChatActivity.this.chatActivityEnterView.getMeasuredHeight() - AndroidUtilities.dp(2.0f);
                    }
                    child.layout(childLeft, childTop, childLeft + width, childTop + height);
                }
            }
            ChatActivity.this.updateMessagesVisiblePart(true);
            ChatActivity.this.updateTextureViewPosition(false);
            if (!ChatActivity.this.scrollingChatListView) {
                ChatActivity.this.checkAutoDownloadMessages(false);
            }
            notifyHeightChanged();
        }

        private boolean isShowMenuEmojiView() {
            int count = getChildCount();
            return (getChildAt(count + (-2)) instanceof EnterMenuView) || (getChildAt(count + (-2)) instanceof EmojiView);
        }
    }

    static /* synthetic */ boolean lambda$createView$5(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$6$ChatActivity(View view) {
        if (this.floatingDateView.getAlpha() == 0.0f || this.actionBar.isActionModeShowed()) {
            return;
        }
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(((long) this.floatingDateView.getCustomDate()) * 1000);
        int year = calendar.get(1);
        int monthOfYear = calendar.get(2);
        int dayOfMonth = calendar.get(5);
        calendar.clear();
        calendar.set(year, monthOfYear, dayOfMonth);
        jumpToDate((int) (calendar.getTime().getTime() / 1000));
    }

    public /* synthetic */ void lambda$createView$7$ChatActivity(View v) {
        this.wasManualScroll = true;
        TLRPC.ChatFull chatFull = this.chatInfo;
        if (chatFull != null) {
            scrollToMessageId(chatFull.pinned_msg_id, 0, true, 0, false);
            return;
        }
        TLRPC.UserFull userFull = this.userInfo;
        if (userFull != null) {
            scrollToMessageId(userFull.pinned_msg_id, 0, true, 0, false);
        }
    }

    static /* synthetic */ void lambda$createView$8(View v) {
    }

    public /* synthetic */ void lambda$createView$10$ChatActivity(View v) {
        boolean allowPin;
        TLRPC.UserFull userFull;
        if (getParentActivity() == null) {
            return;
        }
        TLRPC.Chat chat = this.currentChat;
        if (chat != null) {
            allowPin = ChatObject.canPinMessages(chat);
            if (this.pinnedMessageObject.type == 207) {
                allowPin = false;
            }
        } else if (this.currentEncryptedChat == null && (userFull = this.userInfo) != null) {
            allowPin = userFull.can_pin_message;
        } else {
            allowPin = false;
        }
        if (allowPin) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("UnpinMessageAlertTitle", R.string.UnpinMessageAlertTitle));
            builder.setMessage(LocaleController.getString("UnpinMessageAlert", R.string.UnpinMessageAlert));
            builder.setPositiveButton(LocaleController.getString("UnpinMessage", R.string.UnpinMessage), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$lkSNlsZBUtk2n9ue5DyAw5xTXM8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$9$ChatActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
            return;
        }
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        if (this.chatInfo != null) {
            preferences.edit().putInt("pin_" + this.dialog_id, this.chatInfo.pinned_msg_id).commit();
        } else if (this.userInfo != null) {
            preferences.edit().putInt("pin_" + this.dialog_id, this.userInfo.pinned_msg_id).commit();
        }
        updatePinnedMessageView(true);
    }

    public /* synthetic */ void lambda$null$9$ChatActivity(DialogInterface dialogInterface, int i) {
        getMessagesController().pinMessage(this.currentChat, this.currentUser, 0, false);
    }

    public /* synthetic */ void lambda$createView$11$ChatActivity(View v) {
        if (getParentActivity() == null) {
            return;
        }
        updatePinnedLiveMessageView(false, 0, false);
        animLivePinClose(this.pinnedLiveUserImageView);
    }

    public /* synthetic */ void lambda$createView$13$ChatActivity(View v2) {
        AlertsCreator.showBlockReportSpamAlert(this, this.dialog_id, this.currentUser, this.currentChat, this.currentEncryptedChat, this.reportSpamButton.getTag(R.attr.object_tag) != null, this.chatInfo, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$cNpplrktK2vHF2FIqj0yzwyh3hA
            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
            public final void run(int i) {
                this.f$0.lambda$null$12$ChatActivity(i);
            }
        });
    }

    public /* synthetic */ void lambda$null$12$ChatActivity(int param) {
        if (param == 0) {
            updateTopPanel(true);
        } else {
            finishFragment();
        }
    }

    public /* synthetic */ void lambda$createView$14$ChatActivity(View v) {
        if (this.addToContactsButton.getTag() != null) {
            shareMyContact(1, null);
            return;
        }
        TLRPC.User user = this.currentUser;
        if (user != null) {
            presentFragment(new AddContactsInfoActivity(null, user));
        }
    }

    public /* synthetic */ void lambda$createView$15$ChatActivity(View v) {
        getMessagesController().hidePeerSettingsBar(this.dialog_id, this.currentUser, this.currentChat);
        updateTopPanel(true);
    }

    public /* synthetic */ void lambda$createView$16$ChatActivity(View view) {
        this.wasManualScroll = true;
        this.checkTextureViewPosition = true;
        int i = this.createUnreadMessageAfterId;
        if (i != 0) {
            scrollToMessageId(i, 0, false, this.returnToLoadIndex, false);
            return;
        }
        int i2 = this.returnToMessageId;
        if (i2 > 0) {
            scrollToMessageId(i2, 0, true, this.returnToLoadIndex, false);
        } else {
            scrollToLastMessage(true);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$17, reason: invalid class name */
    class AnonymousClass17 implements View.OnClickListener {
        AnonymousClass17() {
        }

        private void loadLastUnreadMention() {
            ChatActivity.this.wasManualScroll = true;
            if (ChatActivity.this.hasAllMentionsLocal) {
                ChatActivity.this.getMessagesStorage().getUnreadMention(ChatActivity.this.dialog_id, new MessagesStorage.IntCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$17$keAHBrcsYZz229v67KXiy7qRwmw
                    @Override // im.uwrkaxlmjj.messenger.MessagesStorage.IntCallback
                    public final void run(int i) {
                        this.f$0.lambda$loadLastUnreadMention$0$ChatActivity$17(i);
                    }
                });
                return;
            }
            final MessagesStorage messagesStorage = ChatActivity.this.getMessagesStorage();
            TLRPC.TL_messages_getUnreadMentions req = new TLRPC.TL_messages_getUnreadMentions();
            req.peer = ChatActivity.this.getMessagesController().getInputPeer((int) ChatActivity.this.dialog_id);
            req.limit = 1;
            req.add_offset = ChatActivity.this.newMentionsCount - 1;
            ChatActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$17$43rgsaoy9UjH_i-ceCL4jkcdbT8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadLastUnreadMention$2$ChatActivity$17(messagesStorage, tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$loadLastUnreadMention$0$ChatActivity$17(int param) {
            if (param == 0) {
                ChatActivity.this.hasAllMentionsLocal = false;
                loadLastUnreadMention();
            } else {
                ChatActivity.this.scrollToMessageId(param, 0, false, 0, false);
            }
        }

        public /* synthetic */ void lambda$loadLastUnreadMention$2$ChatActivity$17(final MessagesStorage messagesStorage, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$17$-OGtvajAbunuD4WvtHOAj3d1mxw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$ChatActivity$17(response, error, messagesStorage);
                }
            });
        }

        public /* synthetic */ void lambda$null$1$ChatActivity$17(TLObject response, TLRPC.TL_error error, MessagesStorage messagesStorage) {
            long mid;
            TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            if (error != null || res.messages.isEmpty()) {
                if (res != null) {
                    ChatActivity.this.newMentionsCount = res.count;
                } else {
                    ChatActivity.this.newMentionsCount = 0;
                }
                messagesStorage.resetMentionsCount(ChatActivity.this.dialog_id, ChatActivity.this.newMentionsCount);
                if (ChatActivity.this.newMentionsCount == 0) {
                    ChatActivity.this.hasAllMentionsLocal = true;
                    ChatActivity.this.showMentionDownButton(false, true);
                    return;
                } else {
                    ChatActivity.this.mentiondownButtonCounter.setText(String.format("%d", Integer.valueOf(ChatActivity.this.newMentionsCount)));
                    loadLastUnreadMention();
                    return;
                }
            }
            int id = res.messages.get(0).id;
            long mid2 = id;
            if (!ChatObject.isChannel(ChatActivity.this.currentChat)) {
                mid = mid2;
            } else {
                mid = mid2 | (((long) ChatActivity.this.currentChat.id) << 32);
            }
            MessageObject object = (MessageObject) ChatActivity.this.messagesDict[0].get(id);
            messagesStorage.markMessageAsMention(mid);
            if (object != null) {
                object.messageOwner.media_unread = true;
                object.messageOwner.mentioned = true;
            }
            ChatActivity.this.scrollToMessageId(id, 0, false, 0, false);
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            loadLastUnreadMention();
        }
    }

    public /* synthetic */ boolean lambda$createView$17$ChatActivity(View view) {
        for (int a = 0; a < this.messages.size(); a++) {
            MessageObject messageObject = this.messages.get(a);
            if (messageObject.messageOwner.mentioned && !messageObject.isContentUnread()) {
                messageObject.setContentIsRead();
            }
        }
        this.newMentionsCount = 0;
        getMessagesController().markMentionsAsRead(this.dialog_id);
        this.hasAllMentionsLocal = true;
        showMentionDownButton(false, true);
        return true;
    }

    public /* synthetic */ boolean lambda$createView$18$ChatActivity(View v, MotionEvent event) {
        return ContentPreviewViewer.getInstance().onTouch(event, this.mentionListView, 0, this.mentionsOnItemClickListener, null);
    }

    public /* synthetic */ void lambda$createView$21$ChatActivity(View view, int position) {
        if (this.mentionsAdapter.isBannedInline()) {
            return;
        }
        final Object object = this.mentionsAdapter.getItem(position);
        int start = this.mentionsAdapter.getResultStartPosition();
        int len = this.mentionsAdapter.getResultLength();
        if (object instanceof TLRPC.User) {
            if (this.searchingForUser && this.searchContainer.getVisibility() == 0) {
                TLRPC.User user = (TLRPC.User) object;
                this.searchingUserMessages = user;
                if (user == null) {
                    return;
                }
                String name = user.first_name;
                if (TextUtils.isEmpty(name)) {
                    name = this.searchingUserMessages.last_name;
                }
                this.searchingForUser = false;
                String from = LocaleController.getString("SearchFrom", R.string.SearchFrom);
                Spannable spannable = new SpannableString(from + " " + name);
                spannable.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_chat_messagePanelMetionText)), from.length() + 1, spannable.length(), 33);
                this.searchItem.setSearchFieldCaption(spannable);
                this.mentionsAdapter.searchUsernameOrHashtag(null, 0, null, false);
                this.searchItem.setSearchFieldHint(null);
                this.searchItem.clearSearchText();
                getMediaDataController().searchMessagesInChat("", this.dialog_id, this.mergeDialogId, this.classGuid, 0, this.searchingUserMessages);
                return;
            }
            TLRPC.User user2 = (TLRPC.User) object;
            if (user2 != null) {
                String name2 = UserObject.getName(user2) + " ";
                if ("all".equals(name2.trim()) && user2.id == -1) {
                    Spannable spannable2 = new SpannableString("@" + name2);
                    spannable2.setSpan(new URLSpanUserMention("-1", 1), 0, spannable2.length(), 33);
                    spannable2.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_chat_messagePanelMetionText)), 0, spannable2.length(), 33);
                    this.chatActivityEnterView.addMentionText1(start, len, spannable2, false);
                    return;
                }
                Spannable spannable3 = new SpannableString("@" + name2);
                spannable3.setSpan(new URLSpanUserMention("" + user2.id, 1), 0, spannable3.length(), 33);
                spannable3.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_chat_messagePanelMetionText)), 0, spannable3.length(), 33);
                this.chatActivityEnterView.addMentionText1(start, len, spannable3, false);
                return;
            }
            return;
        }
        if (object instanceof String) {
            if (this.mentionsAdapter.isBotCommands()) {
                if (this.inScheduleMode) {
                    AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.currentUser), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$D5dar8O7eXKrS37yLatZDrMM1OQ
                        @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                        public final void didSelectDate(boolean z, int i) {
                            this.f$0.lambda$null$19$ChatActivity(object, z, i);
                        }
                    });
                    return;
                } else {
                    if (!checkSlowMode(view)) {
                        getSendMessagesHelper().sendMessage((String) object, this.dialog_id, this.replyingMessageObject, null, false, null, null, null, true, 0);
                        this.chatActivityEnterView.setFieldText("");
                        hideFieldPanel(false);
                        return;
                    }
                    return;
                }
            }
            this.chatActivityEnterView.replaceWithText(start, len, object + " ", false);
            return;
        }
        if (object instanceof TLRPC.BotInlineResult) {
            if (this.chatActivityEnterView.getFieldText() != null) {
                if (!this.inScheduleMode && checkSlowMode(view)) {
                    return;
                }
                final TLRPC.BotInlineResult result = (TLRPC.BotInlineResult) object;
                if ((result.type.equals("photo") && (result.photo != null || result.content != null)) || ((result.type.equals("gif") && (result.document != null || result.content != null)) || (result.type.equals("video") && result.document != null))) {
                    ArrayList<Object> arrayList = new ArrayList<>(this.mentionsAdapter.getSearchResultBotContext());
                    this.botContextResults = arrayList;
                    PhotoViewer.getInstance().setParentActivity(getParentActivity());
                    PhotoViewer.getInstance().openPhotoForSelect(arrayList, this.mentionsAdapter.getItemPosition(position), 3, this.botContextProvider, this);
                    return;
                }
                if (this.inScheduleMode) {
                    AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.currentUser), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$IAPRgxSgSt62x5xBi4_4nJKx3ik
                        @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                        public final void didSelectDate(boolean z, int i) {
                            this.f$0.lambda$null$20$ChatActivity(result, z, i);
                        }
                    });
                    return;
                } else {
                    lambda$null$20$ChatActivity(result, true, 0);
                    return;
                }
            }
            return;
        }
        if (object instanceof TLRPC.TL_inlineBotSwitchPM) {
            processInlineBotContextPM((TLRPC.TL_inlineBotSwitchPM) object);
        } else if (object instanceof MediaDataController.KeywordResult) {
            String code = ((MediaDataController.KeywordResult) object).emoji;
            this.chatActivityEnterView.addEmojiToRecent(code);
            this.chatActivityEnterView.replaceWithText(start, len, code, true);
        }
    }

    public /* synthetic */ void lambda$null$19$ChatActivity(Object object, boolean notify, int scheduleDate) {
        getSendMessagesHelper().sendMessage((String) object, this.dialog_id, this.replyingMessageObject, null, false, null, null, null, notify, scheduleDate);
        this.chatActivityEnterView.setFieldText("");
        hideFieldPanel(false);
    }

    public /* synthetic */ boolean lambda$createView$23$ChatActivity(View view, int position) {
        boolean z = false;
        if (getParentActivity() == null || !this.mentionsAdapter.isLongClickEnabled()) {
            return false;
        }
        Object object = this.mentionsAdapter.getItem(position);
        if (!(object instanceof String)) {
            return false;
        }
        if (this.mentionsAdapter.isBotCommands()) {
            if (!URLSpanBotCommand.enabled) {
                return false;
            }
            this.chatActivityEnterView.setFieldText("");
            ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
            String str = (String) object;
            TLRPC.Chat chat = this.currentChat;
            if (chat != null && chat.megagroup) {
                z = true;
            }
            chatActivityEnterView.setCommand(null, str, true, z);
            return true;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("ClearSearch", R.string.ClearSearch));
        builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$JOHxqmwPBnIj6vrdYNj_hHFdkHs
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$22$ChatActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
        return true;
    }

    public /* synthetic */ void lambda$null$22$ChatActivity(DialogInterface dialogInterface, int i) {
        this.mentionsAdapter.clearRecentHashtags();
    }

    public /* synthetic */ boolean lambda$createView$24$ChatActivity(View v, MotionEvent event) {
        if (event.getAction() == 0) {
            checkRecordLocked();
        }
        this.overlayView.getParent().requestDisallowInterceptTouchEvent(true);
        return true;
    }

    static /* synthetic */ boolean lambda$createView$25(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$26$ChatActivity(View v) {
        ArrayList<MessageObject> arrayList = this.forwardingMessages;
        if (arrayList == null || arrayList.isEmpty()) {
            MessageObject messageObject = this.replyingMessageObject;
            if (messageObject != null) {
                scrollToMessageId(messageObject.getId(), 0, true, 0, false);
                return;
            }
            MessageObject messageObject2 = this.editingMessageObject;
            if (messageObject2 != null && messageObject2.canEditMedia() && this.editingMessageObjectReqId == 0) {
                if (this.chatAttachAlert == null) {
                    createChatAttachView();
                }
                this.chatAttachAlert.setEditingMessageObject(this.editingMessageObject);
                openAttachMenu();
                return;
            }
            return;
        }
        int N = this.forwardingMessages.size();
        for (int a = 0; a < N; a++) {
            MessageObject messageObject3 = this.forwardingMessages.get(a);
            this.selectedMessagesIds[0].put(messageObject3.getId(), messageObject3);
        }
        Bundle args = new Bundle();
        args.putBoolean("onlySelect", true);
        args.putInt("dialogsType", 3);
        args.putInt("messagesCount", this.forwardingMessages.size());
        DialogsActivity fragment = new DialogsActivity(args);
        fragment.setDelegate(this);
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$createView$27$ChatActivity(View v) {
        ArrayList<MessageObject> arrayList = this.forwardingMessages;
        if (arrayList != null) {
            arrayList.clear();
        }
        showFieldPanel(false, null, null, null, this.foundWebPage, true, 0, true, true);
    }

    public /* synthetic */ boolean lambda$createView$28$ChatActivity(ContentPreviewViewer.ContentPreviewViewerDelegate contentPreviewViewerDelegate, View v, MotionEvent event) {
        return ContentPreviewViewer.getInstance().onTouch(event, this.stickersListView, 0, this.stickersOnItemClickListener, contentPreviewViewerDelegate);
    }

    static /* synthetic */ boolean lambda$createView$29(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$30$ChatActivity(View view) {
        getMediaDataController().searchMessagesInChat(null, this.dialog_id, this.mergeDialogId, this.classGuid, 1, this.searchingUserMessages);
    }

    public /* synthetic */ void lambda$createView$31$ChatActivity(View view) {
        getMediaDataController().searchMessagesInChat(null, this.dialog_id, this.mergeDialogId, this.classGuid, 2, this.searchingUserMessages);
    }

    public /* synthetic */ void lambda$createView$32$ChatActivity(View view) {
        this.mentionLayoutManager.setReverseLayout(true);
        this.mentionsAdapter.setSearchingMentions(true);
        this.searchCalendarButton.setVisibility(8);
        this.searchUserButton.setVisibility(8);
        this.searchingForUser = true;
        this.searchingUserMessages = null;
        this.searchItem.setSearchFieldHint(LocaleController.getString("SearchMembers", R.string.SearchMembers));
        this.searchItem.setSearchFieldCaption(LocaleController.getString("SearchFrom", R.string.SearchFrom));
        AndroidUtilities.showKeyboard(this.searchItem.getSearchField());
        this.searchItem.clearSearchText();
    }

    public /* synthetic */ void lambda$createView$36$ChatActivity(View view) {
        if (getParentActivity() == null) {
            return;
        }
        AndroidUtilities.hideKeyboard(this.searchItem.getSearchField());
        Calendar calendar = Calendar.getInstance();
        int year = calendar.get(1);
        int monthOfYear = calendar.get(2);
        int dayOfMonth = calendar.get(5);
        try {
            DatePickerDialog datePickerDialog = new DatePickerDialog(getParentActivity(), new DatePickerDialog.OnDateSetListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$1GoJ--ru-N5OezDxVUguV1NYU7g
                @Override // android.app.DatePickerDialog.OnDateSetListener
                public final void onDateSet(DatePicker datePicker, int i, int i2, int i3) {
                    this.f$0.lambda$null$33$ChatActivity(datePicker, i, i2, i3);
                }
            }, year, monthOfYear, dayOfMonth);
            final DatePicker datePicker = datePickerDialog.getDatePicker();
            datePicker.setMinDate(1375315200000L);
            datePicker.setMaxDate(System.currentTimeMillis());
            datePickerDialog.setButton(-1, LocaleController.getString("JumpToDate", R.string.JumpToDate), datePickerDialog);
            datePickerDialog.setButton(-2, LocaleController.getString("Cancel", R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$UnkIksU3UPmPLzUPL7Jl2o2Kj8I
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    ChatActivity.lambda$null$34(dialogInterface, i);
                }
            });
            if (Build.VERSION.SDK_INT >= 21) {
                datePickerDialog.setOnShowListener(new DialogInterface.OnShowListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$vIvDWUKBx1ADPsBRILphxSFiFvk
                    @Override // android.content.DialogInterface.OnShowListener
                    public final void onShow(DialogInterface dialogInterface) {
                        ChatActivity.lambda$null$35(datePicker, dialogInterface);
                    }
                });
            }
            showDialog(datePickerDialog);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$33$ChatActivity(DatePicker view1, int year1, int month, int dayOfMonth1) {
        Calendar calendar1 = Calendar.getInstance();
        calendar1.clear();
        calendar1.set(year1, month, dayOfMonth1);
        int date = (int) (calendar1.getTime().getTime() / 1000);
        clearChatData();
        this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
        MessagesController messagesController = getMessagesController();
        long j = this.dialog_id;
        int i = this.classGuid;
        boolean zIsChannel = ChatObject.isChannel(this.currentChat);
        boolean z = this.inScheduleMode;
        int i2 = this.lastLoadIndex;
        this.lastLoadIndex = i2 + 1;
        messagesController.loadMessages(j, 30, 0, date, true, 0, i, 4, 0, zIsChannel, z, i2);
    }

    static /* synthetic */ void lambda$null$34(DialogInterface dialog1, int which) {
    }

    static /* synthetic */ void lambda$null$35(DatePicker datePicker, DialogInterface dialog12) {
        int count = datePicker.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = datePicker.getChildAt(a);
            ViewGroup.LayoutParams layoutParams = child.getLayoutParams();
            layoutParams.width = -1;
            child.setLayoutParams(layoutParams);
        }
    }

    public /* synthetic */ void lambda$createView$39$ChatActivity(View view) {
        String str;
        if (getParentActivity() == null) {
            return;
        }
        TLRPC.User user = this.currentUser;
        if (user != null && this.userBlocked) {
            if (user.bot) {
                String botUserLast = this.botUser;
                this.botUser = null;
                getMessagesController().unblockUser(this.currentUser.id);
                if (botUserLast == null || botUserLast.length() == 0) {
                    getSendMessagesHelper().sendMessage("/start", this.dialog_id, null, null, false, null, null, null, true, 0);
                    return;
                } else {
                    getMessagesController().sendBotStart(this.currentUser, botUserLast);
                    return;
                }
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setMessage(LocaleController.getString("AreYouSureUnblockContact", R.string.AreYouSureUnblockContact));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$qutY9wTRP_pcL9alXyx6Vp3Czro
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$37$ChatActivity(dialogInterface, i);
                }
            });
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
            return;
        }
        TLRPC.User user2 = this.currentUser;
        if (user2 != null && user2.bot && (str = this.botUser) != null) {
            if (str.length() != 0) {
                getMessagesController().sendBotStart(this.currentUser, this.botUser);
            } else {
                getSendMessagesHelper().sendMessage("/start", this.dialog_id, null, null, false, null, null, null, true, 0);
            }
            this.botUser = null;
            updateBottomOverlay();
            return;
        }
        if (ChatObject.isChannel(this.currentChat)) {
            TLRPC.Chat chat = this.currentChat;
            if (!(chat instanceof TLRPC.TL_channelForbidden)) {
                if (ChatObject.isNotInChat(chat)) {
                    showBottomOverlayProgress(true, true);
                    getMessagesController().addUserToChat(this.currentChat.id, getUserConfig().getCurrentUser(), null, 0, null, this, null);
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.closeSearchByActiveAction, new Object[0]);
                    if (hasReportSpam() && this.reportSpamButton.getTag(R.attr.object_tag) != null) {
                        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
                        preferences.edit().putInt("dialog_bar_vis3" + this.dialog_id, 3).commit();
                        getNotificationCenter().postNotificationName(NotificationCenter.peerSettingsDidLoad, Long.valueOf(this.dialog_id));
                        return;
                    }
                    return;
                }
                toggleMute(true);
                return;
            }
        }
        AlertsCreator.createClearOrDeleteDialogAlert(this, false, this.currentChat, this.currentUser, this.currentEncryptedChat != null, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$KE0l2l28tbDQv6QTYWX1kmXXI3A
            @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
            public final void run(boolean z) {
                this.f$0.lambda$null$38$ChatActivity(z);
            }
        });
    }

    public /* synthetic */ void lambda$null$37$ChatActivity(DialogInterface dialogInterface, int i) {
        getMessagesController().unblockUser(this.currentUser.id);
    }

    public /* synthetic */ void lambda$null$38$ChatActivity(boolean param) {
        getNotificationCenter().removeObserver(this, NotificationCenter.closeChats);
        getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
        finishFragment();
        getNotificationCenter().postNotificationName(NotificationCenter.needDeleteDialog, Long.valueOf(this.dialog_id), this.currentUser, this.currentChat, Boolean.valueOf(param));
    }

    public /* synthetic */ void lambda$createView$40$ChatActivity(View v) {
        if (this.chatInfo == null) {
            return;
        }
        Bundle args = new Bundle();
        args.putInt("chat_id", this.chatInfo.linked_chat_id);
        if (!getMessagesController().checkCanOpenChat(args, this)) {
            return;
        }
        presentFragment(new ChatActivity(args));
    }

    public /* synthetic */ void lambda$createView$41$ChatActivity(View v) {
        MessageObject messageObject = null;
        for (int a = 1; a >= 0; a--) {
            if (messageObject == null && this.selectedMessagesIds[a].size() != 0) {
                MessageObject messageObject2 = this.messagesDict[a].get(this.selectedMessagesIds[a].keyAt(0));
                messageObject = messageObject2;
            }
            this.selectedMessagesIds[a].clear();
            this.selectedMessagesCanCopyIds[a].clear();
            this.selectedMessagesCanStarIds[a].clear();
        }
        hideActionMode();
        if (messageObject != null && (messageObject.messageOwner.id > 0 || (messageObject.messageOwner.id < 0 && this.currentEncryptedChat != null))) {
            showFieldPanelForReply(messageObject);
        }
        updatePinnedMessageView(true);
        updateVisibleRows();
    }

    public /* synthetic */ void lambda$createView$42$ChatActivity(View v) {
        openForward();
    }

    private void createActionBarMenuPop() {
        ChatActionBarMenuPopupWindow chatActionBarMenuPopupWindow = new ChatActionBarMenuPopupWindow(getParentActivity());
        this.chatActionBarMenuPop = chatActionBarMenuPopupWindow;
        chatActionBarMenuPopupWindow.setBackgroundDrawable(new ColorDrawable());
        this.chatActionBarMenuPop.setOutsideTouchable(true);
        this.chatActionBarMenuPop.setFocusable(true);
        this.chatActionBarMenuPop.setInputMethodMode(1);
        this.chatActionBarMenuPop.setSoftInputMode(48);
        this.chatActionBarMenuPop.setOnSubItemClickListener(new ChatActionBarMenuPopupWindow.OnSubItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$GDDhXeSag6XamSIeDjf60wz522A
            @Override // im.uwrkaxlmjj.ui.actionbar.ChatActionBarMenuPopupWindow.OnSubItemClickListener
            public final void onClick(int i) {
                this.f$0.lambda$createActionBarMenuPop$46$ChatActivity(i);
            }
        });
    }

    public /* synthetic */ void lambda$createActionBarMenuPop$46$ChatActivity(final int id) {
        if (id == 40) {
            openSearchWithText(null);
        } else if (id == 21) {
            AlertsCreator.createReportAlert(getParentActivity(), this.dialog_id, 0, this);
        } else if (id == 17) {
            if (this.currentUser == null || getParentActivity() == null) {
                return;
            }
            if (this.addToContactsButton.getTag() != null) {
                shareMyContact(((Integer) this.addToContactsButton.getTag()).intValue(), null);
            } else {
                TLRPC.User user = this.currentUser;
                if (user != null) {
                    presentFragment(new AddContactsInfoActivity(null, user));
                }
            }
        } else if (id == 18) {
            toggleMute(false);
        } else if (id == 13) {
            if (getParentActivity() == null) {
                return;
            } else {
                showDialog(AlertsCreator.createTTLAlert(getParentActivity(), this.currentEncryptedChat).create());
            }
        } else if (id == 15 || id == 16) {
            if (getParentActivity() == null) {
                return;
            }
            long j = this.dialog_id;
            final boolean isChat = ((int) j) < 0 && ((int) (j >> 32)) != 1;
            AlertsCreator.createClearOrDeleteDialogAlert(this, id == 15, this.currentChat, this.currentUser, this.currentEncryptedChat != null, new MessagesStorage.BooleanCallback() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$t9gHM4s9-pe5pfR4E0RQHCw01nY
                @Override // im.uwrkaxlmjj.messenger.MessagesStorage.BooleanCallback
                public final void run(boolean z) throws Exception {
                    this.f$0.lambda$null$45$ChatActivity(id, isChat, z);
                }
            });
        } else if (id == 30) {
            getSendMessagesHelper().sendMessage("/help", this.dialog_id, null, null, false, null, null, null, true, 0);
        } else if (id == 31) {
            getSendMessagesHelper().sendMessage("/settings", this.dialog_id, null, null, false, null, null, null, true, 0);
        } else if (id == 24) {
            try {
                getMediaDataController().installShortcut(this.currentUser.id);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        this.chatActionBarMenuPop.dismiss();
    }

    public /* synthetic */ void lambda$null$45$ChatActivity(final int id, final boolean isChat, final boolean param) throws Exception {
        if (id == 15 && ChatObject.isChannel(this.currentChat) && (!this.currentChat.megagroup || !TextUtils.isEmpty(this.currentChat.username))) {
            getMessagesController().deleteDialog(this.dialog_id, 2, param);
            return;
        }
        if (id != 15) {
            getNotificationCenter().removeObserver(this, NotificationCenter.closeChats);
            getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
            finishFragment();
            getNotificationCenter().postNotificationName(NotificationCenter.needDeleteDialog, Long.valueOf(this.dialog_id), this.currentUser, this.currentChat, Boolean.valueOf(param));
            return;
        }
        this.clearingHistory = true;
        this.undoView.setAdditionalTranslationY(0.0f);
        this.undoView.showWithAction(this.dialog_id, id == 15 ? 0 : 1, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Zc_0BSbwAM8cKE2eyqC6oR18e8c
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                this.f$0.lambda$null$43$ChatActivity(id, param, isChat);
            }
        }, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$m9Dx_k9gdwU6_I26TkDXvCVTNj0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$44$ChatActivity();
            }
        });
        this.chatAdapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$null$43$ChatActivity(int id, boolean param, boolean isChat) throws Exception {
        if (id == 15) {
            TLRPC.ChatFull chatFull = this.chatInfo;
            if (chatFull != null && chatFull.pinned_msg_id != 0) {
                SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
                preferences.edit().putInt("pin_" + this.dialog_id, this.chatInfo.pinned_msg_id).commit();
                updatePinnedMessageView(true);
            } else {
                TLRPC.UserFull userFull = this.userInfo;
                if (userFull != null && userFull.pinned_msg_id != 0) {
                    SharedPreferences preferences2 = MessagesController.getNotificationsSettings(this.currentAccount);
                    preferences2.edit().putInt("pin_" + this.dialog_id, this.userInfo.pinned_msg_id).commit();
                    updatePinnedMessageView(true);
                }
            }
            getMessagesController().deleteDialog(this.dialog_id, 1, param);
            this.clearingHistory = false;
            clearHistory(false);
            this.chatAdapter.notifyDataSetChanged();
            return;
        }
        if (!isChat || ChatObject.isNotInChat(this.currentChat)) {
            getMessagesController().deleteDialog(this.dialog_id, 0, param);
        } else {
            getMessagesController().deleteUserFromChat((int) (-this.dialog_id), getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId())), null);
        }
        finishFragment();
    }

    public /* synthetic */ void lambda$null$44$ChatActivity() {
        this.clearingHistory = false;
        this.chatAdapter.notifyDataSetChanged();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showOrUpdateActionBarMenuPop() {
        ChatActionBarMenuPopupWindow chatActionBarMenuPopupWindow = this.chatActionBarMenuPop;
        if (chatActionBarMenuPopupWindow != null) {
            if (!chatActionBarMenuPopupWindow.isShowing()) {
                this.chatActionBarMenuPop.showAsDropDown(this.actionBar);
            } else {
                this.chatActionBarMenuPop.update();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TextureView createTextureView(boolean add) {
        if (this.parentLayout == null) {
            return null;
        }
        if (this.videoPlayerContainer == null) {
            if (Build.VERSION.SDK_INT >= 21) {
                FrameLayout frameLayout = new FrameLayout(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.ChatActivity.35
                    @Override // android.view.View
                    public void setTranslationY(float translationY) {
                        super.setTranslationY(translationY);
                        ChatActivity.this.contentView.invalidate();
                    }
                };
                this.videoPlayerContainer = frameLayout;
                frameLayout.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.ChatActivity.36
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        if (view.getTag(R.attr.parent_tag) != null) {
                            outline.setRoundRect(0, 0, view.getMeasuredWidth(), view.getMeasuredHeight(), AndroidUtilities.dp(4.0f));
                        } else {
                            outline.setOval(0, 0, AndroidUtilities.roundMessageSize, AndroidUtilities.roundMessageSize);
                        }
                    }
                });
                this.videoPlayerContainer.setClipToOutline(true);
            } else {
                this.videoPlayerContainer = new FrameLayout(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.ChatActivity.37
                    RectF rect = new RectF();

                    @Override // android.view.View
                    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
                        super.onSizeChanged(w, h, oldw, oldh);
                        ChatActivity.this.aspectPath.reset();
                        if (getTag(R.attr.parent_tag) == null) {
                            ChatActivity.this.aspectPath.addCircle(w / 2, h / 2, w / 2, Path.Direction.CW);
                        } else {
                            this.rect.set(0.0f, 0.0f, w, h);
                            ChatActivity.this.aspectPath.addRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), Path.Direction.CW);
                        }
                        ChatActivity.this.aspectPath.toggleInverseFillType();
                    }

                    @Override // android.view.View
                    public void setTranslationY(float translationY) {
                        super.setTranslationY(translationY);
                        ChatActivity.this.contentView.invalidate();
                    }

                    @Override // android.view.View
                    public void setVisibility(int visibility) {
                        super.setVisibility(visibility);
                        if (visibility == 0) {
                            setLayerType(2, null);
                        }
                    }

                    @Override // android.view.ViewGroup, android.view.View
                    protected void dispatchDraw(Canvas canvas) {
                        super.dispatchDraw(canvas);
                        if (getTag() == null) {
                            canvas.drawPath(ChatActivity.this.aspectPath, ChatActivity.this.aspectPaint);
                        }
                    }
                };
                this.aspectPath = new Path();
                Paint paint = new Paint(1);
                this.aspectPaint = paint;
                paint.setColor(-16777216);
                this.aspectPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
            }
            this.videoPlayerContainer.setWillNotDraw(false);
            AspectRatioFrameLayout aspectRatioFrameLayout = new AspectRatioFrameLayout(getParentActivity());
            this.aspectRatioFrameLayout = aspectRatioFrameLayout;
            aspectRatioFrameLayout.setBackgroundColor(0);
            if (add) {
                this.videoPlayerContainer.addView(this.aspectRatioFrameLayout, LayoutHelper.createFrame(-1, -1, 17));
            }
            TextureView textureView = new TextureView(getParentActivity());
            this.videoTextureView = textureView;
            textureView.setOpaque(false);
            this.aspectRatioFrameLayout.addView(this.videoTextureView, LayoutHelper.createFrame(-1, -1.0f));
        }
        ViewGroup parent = (ViewGroup) this.videoPlayerContainer.getParent();
        if (parent != null && parent != this.contentView) {
            parent.removeView(this.videoPlayerContainer);
            parent = null;
        }
        if (parent == null) {
            this.contentView.addView(this.videoPlayerContainer, 1, new FrameLayout.LayoutParams(AndroidUtilities.roundMessageSize, AndroidUtilities.roundMessageSize));
        }
        this.videoPlayerContainer.setTag(null);
        this.aspectRatioFrameLayout.setDrawingReady(false);
        return this.videoTextureView;
    }

    private void destroyTextureView() {
        FrameLayout frameLayout = this.videoPlayerContainer;
        if (frameLayout == null || frameLayout.getParent() == null) {
            return;
        }
        this.contentView.removeView(this.videoPlayerContainer);
        this.aspectRatioFrameLayout.setDrawingReady(false);
        this.videoPlayerContainer.setTag(null);
        if (Build.VERSION.SDK_INT < 21) {
            this.videoPlayerContainer.setLayerType(0, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openForward() {
        Bundle args = new Bundle();
        int dialogType = 3;
        args.putBoolean("onlySelect", true);
        for (SparseArray<MessageObject> selectedMessagesId : this.selectedMessagesIds) {
            int i = 0;
            while (true) {
                if (i >= selectedMessagesId.size()) {
                    break;
                }
                MessageObject mess = selectedMessagesId.valueAt(i);
                if (mess == null || !(mess.messageOwner.media instanceof TLRPC.TL_messageMediaShareContact)) {
                    i++;
                } else {
                    dialogType = 7;
                    break;
                }
            }
            if (dialogType == 7) {
                break;
            }
        }
        args.putInt("dialogsType", dialogType);
        args.putInt("messagesCount", this.canForwardMessagesCount);
        DialogsActivity fragment = new DialogsActivity(args);
        fragment.setDelegate(this);
        presentFragment(fragment);
    }

    private void showBottomOverlayProgress(final boolean show, boolean animated) {
        if (!show || this.bottomOverlayProgress.getTag() == null) {
            if (!show && this.bottomOverlayProgress.getTag() == null) {
                return;
            }
            AnimatorSet animatorSet = this.bottomOverlayAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.bottomOverlayAnimation = null;
            }
            this.bottomOverlayProgress.setTag(show ? 1 : null);
            if (animated) {
                this.bottomOverlayAnimation = new AnimatorSet();
                if (show) {
                    this.bottomOverlayProgress.setVisibility(0);
                    this.bottomOverlayAnimation.playTogether(ObjectAnimator.ofFloat(this.bottomOverlayChatText, (Property<TextView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.bottomOverlayChatText, (Property<TextView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.bottomOverlayChatText, (Property<TextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText2, (Property<UnreadCounterTextView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.bottomOverlayChatText2, (Property<UnreadCounterTextView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.bottomOverlayChatText2, (Property<UnreadCounterTextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.bottomOverlayProgress, (Property<RadialProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayProgress, (Property<RadialProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayProgress, (Property<RadialProgressView, Float>) View.ALPHA, 1.0f));
                } else {
                    this.bottomOverlayChatText.setVisibility(0);
                    this.bottomOverlayAnimation.playTogether(ObjectAnimator.ofFloat(this.bottomOverlayProgress, (Property<RadialProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.bottomOverlayProgress, (Property<RadialProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.bottomOverlayProgress, (Property<RadialProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText, (Property<TextView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText, (Property<TextView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText, (Property<TextView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText2, (Property<UnreadCounterTextView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText2, (Property<UnreadCounterTextView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.bottomOverlayChatText2, (Property<UnreadCounterTextView, Float>) View.ALPHA, 1.0f));
                }
                this.bottomOverlayAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.38
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ChatActivity.this.bottomOverlayAnimation != null && ChatActivity.this.bottomOverlayAnimation.equals(animation)) {
                            if (!show) {
                                ChatActivity.this.bottomOverlayProgress.setVisibility(4);
                            } else {
                                ChatActivity.this.bottomOverlayChatText.setVisibility(4);
                            }
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (ChatActivity.this.bottomOverlayAnimation != null && ChatActivity.this.bottomOverlayAnimation.equals(animation)) {
                            ChatActivity.this.bottomOverlayAnimation = null;
                        }
                    }
                });
                this.bottomOverlayAnimation.setDuration(150L);
                this.bottomOverlayAnimation.start();
                return;
            }
            this.bottomOverlayProgress.setVisibility(show ? 0 : 4);
            this.bottomOverlayProgress.setScaleX(show ? 1.0f : 0.1f);
            this.bottomOverlayProgress.setScaleY(show ? 1.0f : 0.1f);
            this.bottomOverlayProgress.setAlpha(1.0f);
            this.bottomOverlayChatText.setVisibility(show ? 4 : 0);
            this.bottomOverlayChatText.setScaleX(show ? 0.1f : 1.0f);
            this.bottomOverlayChatText.setScaleY(show ? 0.1f : 1.0f);
            this.bottomOverlayChatText.setAlpha(show ? 0.0f : 1.0f);
            this.bottomOverlayChatText2.setScaleX(show ? 0.1f : 1.0f);
            this.bottomOverlayChatText2.setScaleY(show ? 0.1f : 1.0f);
            this.bottomOverlayChatText2.setAlpha(show ? 0.0f : 1.0f);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: sendBotInlineResult, reason: merged with bridge method [inline-methods] */
    public void lambda$null$20$ChatActivity(TLRPC.BotInlineResult result, boolean notify, int scheduleDate) {
        int uid = this.mentionsAdapter.getContextBotId();
        HashMap<String, String> params = new HashMap<>();
        params.put(TtmlNode.ATTR_ID, result.id);
        params.put("query_id", "" + result.query_id);
        params.put("bot", "" + uid);
        params.put("bot_name", this.mentionsAdapter.getContextBotName());
        SendMessagesHelper.prepareSendingBotContextResult(getAccountInstance(), result, params, this.dialog_id, this.replyingMessageObject, notify, scheduleDate);
        this.chatActivityEnterView.setFieldText("");
        hideFieldPanel(false);
        getMediaDataController().increaseInlineRaiting(uid);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void mentionListViewUpdateLayout() {
        if (this.mentionListView.getChildCount() <= 0) {
            this.mentionListViewScrollOffsetY = 0;
            this.mentionListViewLastViewPosition = -1;
            return;
        }
        View child = this.mentionListView.getChildAt(r0.getChildCount() - 1);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.mentionListView.findContainingViewHolder(child);
        if (this.mentionLayoutManager.getReverseLayout()) {
            if (holder != null) {
                this.mentionListViewLastViewPosition = holder.getAdapterPosition();
                this.mentionListViewLastViewTop = child.getBottom();
            } else {
                this.mentionListViewLastViewPosition = -1;
            }
            View child2 = this.mentionListView.getChildAt(0);
            RecyclerListView.Holder holder2 = (RecyclerListView.Holder) this.mentionListView.findContainingViewHolder(child2);
            int newOffset = (child2.getBottom() >= this.mentionListView.getMeasuredHeight() || holder2 == null || holder2.getAdapterPosition() != 0) ? this.mentionListView.getMeasuredHeight() : child2.getBottom();
            if (this.mentionListViewScrollOffsetY != newOffset) {
                RecyclerListView recyclerListView = this.mentionListView;
                this.mentionListViewScrollOffsetY = newOffset;
                recyclerListView.setBottomGlowOffset(newOffset);
                this.mentionListView.setTopGlowOffset(0);
                this.mentionListView.invalidate();
                this.mentionContainer.invalidate();
                return;
            }
            return;
        }
        if (holder != null) {
            this.mentionListViewLastViewPosition = holder.getAdapterPosition();
            this.mentionListViewLastViewTop = child.getTop();
        } else {
            this.mentionListViewLastViewPosition = -1;
        }
        View child3 = this.mentionListView.getChildAt(0);
        RecyclerListView.Holder holder3 = (RecyclerListView.Holder) this.mentionListView.findContainingViewHolder(child3);
        int newOffset2 = (child3.getTop() <= 0 || holder3 == null || holder3.getAdapterPosition() != 0) ? 0 : child3.getTop();
        if (this.mentionListViewScrollOffsetY != newOffset2) {
            RecyclerListView recyclerListView2 = this.mentionListView;
            this.mentionListViewScrollOffsetY = newOffset2;
            recyclerListView2.setTopGlowOffset(newOffset2);
            this.mentionListView.setBottomGlowOffset(0);
            this.mentionListView.invalidate();
            this.mentionContainer.invalidate();
        }
    }

    private void checkBotCommands() {
        TLRPC.Chat chat;
        boolean z = false;
        URLSpanBotCommand.enabled = false;
        TLRPC.User user = this.currentUser;
        if (user != null && user.bot) {
            URLSpanBotCommand.enabled = true;
            return;
        }
        TLRPC.ChatFull chatFull = this.chatInfo;
        if (chatFull instanceof TLRPC.TL_chatFull) {
            for (int a = 0; a < this.chatInfo.participants.participants.size(); a++) {
                TLRPC.ChatParticipant participant = this.chatInfo.participants.participants.get(a);
                TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(participant.user_id));
                if (user2 != null && user2.bot) {
                    URLSpanBotCommand.enabled = true;
                    return;
                }
            }
            return;
        }
        if (chatFull instanceof TLRPC.TL_channelFull) {
            if (!chatFull.bot_info.isEmpty() && (chat = this.currentChat) != null && chat.megagroup) {
                z = true;
            }
            URLSpanBotCommand.enabled = z;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public MessageObject.GroupedMessages getValidGroupedMessage(MessageObject message) {
        if (message.getGroupId() == 0) {
            return null;
        }
        MessageObject.GroupedMessages groupedMessages = this.groupedMessagesMap.get(message.getGroupId());
        if (groupedMessages == null) {
            return groupedMessages;
        }
        if (groupedMessages.messages.size() <= 1 || groupedMessages.positions.get(message) == null) {
            return null;
        }
        return groupedMessages;
    }

    private void jumpToDate(int date) {
        if (this.messages.isEmpty()) {
            return;
        }
        MessageObject firstMessage = this.messages.get(0);
        ArrayList<MessageObject> arrayList = this.messages;
        MessageObject lastMessage = arrayList.get(arrayList.size() - 1);
        if (firstMessage.messageOwner.date >= date && lastMessage.messageOwner.date <= date) {
            int a = this.messages.size() - 1;
            while (true) {
                if (a < 0) {
                    break;
                }
                MessageObject message = this.messages.get(a);
                if (message.messageOwner.date < date || message.getId() == 0) {
                    a--;
                } else {
                    scrollToMessageId(message.getId(), 0, false, message.getDialogId() == this.mergeDialogId ? 1 : 0, false);
                }
            }
            return;
        }
        if (((int) this.dialog_id) != 0) {
            clearChatData();
            this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
            MessagesController messagesController = getMessagesController();
            long j = this.dialog_id;
            int i = this.classGuid;
            boolean zIsChannel = ChatObject.isChannel(this.currentChat);
            boolean z = this.inScheduleMode;
            int i2 = this.lastLoadIndex;
            this.lastLoadIndex = i2 + 1;
            messagesController.loadMessages(j, 30, 0, date, true, 0, i, 4, 0, zIsChannel, z, i2);
            this.floatingDateView.setAlpha(0.0f);
            this.floatingDateView.setTag(null);
        }
    }

    public void processInlineBotContextPM(TLRPC.TL_inlineBotSwitchPM object) {
        TLRPC.User user;
        if (object == null || (user = this.mentionsAdapter.getContextBotUser()) == null) {
            return;
        }
        this.chatActivityEnterView.setFieldText("");
        if (this.dialog_id == user.id) {
            this.inlineReturn = this.dialog_id;
            getMessagesController().sendBotStart(this.currentUser, object.start_param);
            return;
        }
        Bundle args = new Bundle();
        args.putInt("user_id", user.id);
        args.putString("inline_query", object.start_param);
        args.putLong("inline_return", this.dialog_id);
        if (!getMessagesController().checkCanOpenChat(args, this)) {
            return;
        }
        presentFragment(new ChatActivity(args));
    }

    private void createChatAttachView() {
        if (getParentActivity() != null && this.chatAttachAlert == null) {
            AnonymousClass39 anonymousClass39 = new AnonymousClass39(getParentActivity(), this);
            this.chatAttachAlert = anonymousClass39;
            anonymousClass39.setDelegate(new ChatAttachAlert.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.40
                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                    if (ChatActivity.this.getParentActivity() != null && ChatActivity.this.chatAttachAlert != null) {
                        if (ChatActivity.this.chatAttachAlert == null) {
                            ChatActivity.this.editingMessageObject = null;
                        } else {
                            ChatActivity chatActivity = ChatActivity.this;
                            chatActivity.editingMessageObject = chatActivity.chatAttachAlert.getEditingMessageObject();
                        }
                        if (button != 8 && button != 7 && (button != 4 || ChatActivity.this.chatAttachAlert.getSelectedPhotos().isEmpty())) {
                            if (ChatActivity.this.chatAttachAlert != null) {
                                ChatActivity.this.chatAttachAlert.dismissWithButtonClick(button);
                            }
                            ChatActivity.this.processSelectedAttach(button);
                            return;
                        }
                        if (button != 8) {
                            ChatActivity.this.chatAttachAlert.dismiss();
                        }
                        HashMap<Object, Object> selectedPhotos = ChatActivity.this.chatAttachAlert.getSelectedPhotos();
                        ArrayList<Object> selectedPhotosOrder = ChatActivity.this.chatAttachAlert.getSelectedPhotosOrder();
                        if (!selectedPhotos.isEmpty()) {
                            ArrayList<SendMessagesHelper.SendingMediaInfo> photos = new ArrayList<>();
                            for (int a = 0; a < selectedPhotosOrder.size(); a++) {
                                MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) selectedPhotos.get(selectedPhotosOrder.get(a));
                                SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                                if (photoEntry.imagePath != null) {
                                    info.path = photoEntry.imagePath;
                                } else if (photoEntry.path != null) {
                                    info.path = photoEntry.path;
                                }
                                info.isVideo = photoEntry.isVideo;
                                info.caption = photoEntry.caption != null ? photoEntry.caption.toString() : null;
                                info.entities = photoEntry.entities;
                                info.masks = !photoEntry.stickers.isEmpty() ? new ArrayList<>(photoEntry.stickers) : null;
                                info.ttl = photoEntry.ttl;
                                info.videoEditedInfo = photoEntry.editedInfo;
                                info.canDeleteAfter = photoEntry.canDeleteAfter;
                                photos.add(info);
                                photoEntry.reset();
                            }
                            ChatActivity.this.fillEditingMediaWithCaption(photos.get(0).caption, photos.get(0).entities);
                            SendMessagesHelper.prepareSendingMedia(ChatActivity.this.getAccountInstance(), photos, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, null, button == 4, arg, ChatActivity.this.editingMessageObject, notify, scheduleDate, false);
                            ChatActivity.this.afterMessageSend();
                        }
                        if (scheduleDate != 0) {
                            if (ChatActivity.this.scheduledMessagesCount == -1) {
                                ChatActivity.this.scheduledMessagesCount = 0;
                            }
                            ChatActivity.this.scheduledMessagesCount += selectedPhotos.size();
                            ChatActivity.this.updateScheduledInterface(true);
                        }
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public View getRevealView() {
                    return ChatActivity.this.chatActivityEnterView.getAttachButton();
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void didSelectBot(TLRPC.User user) {
                    if (ChatActivity.this.chatActivityEnterView == null || TextUtils.isEmpty(user.username)) {
                        return;
                    }
                    ChatActivity.this.chatActivityEnterView.setFieldText("@" + user.username + " ");
                    ChatActivity.this.chatActivityEnterView.openKeyboard();
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void onCameraOpened() {
                    ChatActivity.this.chatActivityEnterView.closeKeyboard();
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void needEnterComment() {
                    if (ChatActivity.this.chatActivityEnterView.isKeyboardVisible()) {
                        ChatActivity.this.chatActivityEnterView.showEmojiView();
                        ChatActivity.this.openKeyboardOnAttachMenuClose = true;
                    }
                    AndroidUtilities.setAdjustResizeToNothing(ChatActivity.this.getParentActivity(), ChatActivity.this.classGuid);
                    ChatActivity.this.fragmentView.requestLayout();
                }
            });
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$39, reason: invalid class name */
    class AnonymousClass39 extends ChatAttachAlert {
        AnonymousClass39(Context context, BaseFragment parentFragment) {
            super(context, parentFragment);
        }

        @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert, im.uwrkaxlmjj.ui.actionbar.BottomSheet
        public void dismissInternal() {
            if (ChatActivity.this.chatAttachAlert.isShowing()) {
                AndroidUtilities.requestAdjustResize(ChatActivity.this.getParentActivity(), ChatActivity.this.classGuid);
                if (ChatActivity.this.chatActivityEnterView.getVisibility() == 0 && ChatActivity.this.fragmentView != null) {
                    ChatActivity.this.fragmentView.requestLayout();
                }
            }
            super.dismissInternal();
            if (ChatActivity.this.openKeyboardOnAttachMenuClose) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$39$D7otIHAS3jMygCSyQwe0KwZ1uq4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$dismissInternal$0$ChatActivity$39();
                    }
                }, 50L);
                ChatActivity.this.openKeyboardOnAttachMenuClose = false;
            }
        }

        public /* synthetic */ void lambda$dismissInternal$0$ChatActivity$39() {
            ChatActivity.this.chatActivityEnterView.openKeyboard();
        }
    }

    public long getDialogId() {
        return this.dialog_id;
    }

    public boolean hasReportSpam() {
        FrameLayout frameLayout = this.topChatPanelView;
        return (frameLayout == null || frameLayout.getTag() != null || this.reportSpamButton.getVisibility() == 8) ? false : true;
    }

    public void setBotUser(String value) {
        if (this.inlineReturn != 0) {
            getMessagesController().sendBotStart(this.currentUser, value);
        } else {
            this.botUser = value;
            updateBottomOverlay();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void afterMessageSend() {
        hideFieldPanel(false);
        if (!this.inScheduleMode) {
            getMediaDataController().cleanDraft(this.dialog_id, true);
        }
    }

    public boolean playFirstUnreadVoiceMessage() {
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null && chatActivityEnterView.isRecordingAudioVideo()) {
            return true;
        }
        for (int a = this.messages.size() - 1; a >= 0; a--) {
            MessageObject messageObject = this.messages.get(a);
            if ((messageObject.isVoice() || messageObject.isRoundVideo()) && messageObject.isContentUnread() && !messageObject.isOut()) {
                MediaController.getInstance().setVoiceMessagesPlaylist(MediaController.getInstance().playMessage(messageObject) ? createVoiceMessagesPlaylist(messageObject, true) : null, true);
                return true;
            }
        }
        int a2 = Build.VERSION.SDK_INT;
        if (a2 >= 23 && getParentActivity() != null && getParentActivity().checkSelfPermission("android.permission.RECORD_AUDIO") != 0) {
            getParentActivity().requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 3);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openScheduledMessages() {
        if (this.parentLayout == null || this.parentLayout.getLastFragment() != this) {
            return;
        }
        Bundle bundle = new Bundle();
        TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
        if (encryptedChat != null) {
            bundle.putInt("enc_id", encryptedChat.id);
        } else {
            TLRPC.Chat chat = this.currentChat;
            if (chat != null) {
                bundle.putInt("chat_id", chat.id);
            } else {
                bundle.putInt("user_id", this.currentUser.id);
            }
        }
        bundle.putBoolean("scheduled", true);
        ChatActivity fragment = new ChatActivity(bundle);
        fragment.chatActivityDelegate = new ChatActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ZicBWzbCjWR6VmY-pWpkempDusM
            @Override // im.uwrkaxlmjj.ui.ChatActivity.ChatActivityDelegate
            public final void openReplyMessage(int i) {
                this.f$0.lambda$openScheduledMessages$47$ChatActivity(i);
            }
        };
        presentFragment(fragment, false);
    }

    public /* synthetic */ void lambda$openScheduledMessages$47$ChatActivity(int mid) {
        scrollToMessageId(mid, 0, true, 0, false);
    }

    private void initStickers() {
        if (this.chatActivityEnterView == null || getParentActivity() == null || this.stickersAdapter != null) {
            return;
        }
        TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
        if (encryptedChat != null && AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) < 23) {
            return;
        }
        this.stickersListView.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
        RecyclerListView recyclerListView = this.stickersListView;
        StickersAdapter stickersAdapter = new StickersAdapter(getParentActivity(), new StickersAdapter.StickersAdapterDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$VOv0hlfu-wSHRekxqvFgb2lAyII
            @Override // im.uwrkaxlmjj.ui.adapters.StickersAdapter.StickersAdapterDelegate
            public final void needChangePanelVisibility(boolean z) {
                this.f$0.lambda$initStickers$48$ChatActivity(z);
            }
        });
        this.stickersAdapter = stickersAdapter;
        recyclerListView.setAdapter(stickersAdapter);
        RecyclerListView recyclerListView2 = this.stickersListView;
        RecyclerListView.OnItemClickListener onItemClickListener = new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$xm5PYLmJNO1e0fzi1CJMHuGzKMo
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initStickers$50$ChatActivity(view, i);
            }
        };
        this.stickersOnItemClickListener = onItemClickListener;
        recyclerListView2.setOnItemClickListener(onItemClickListener);
    }

    public /* synthetic */ void lambda$initStickers$48$ChatActivity(final boolean show) {
        if (show) {
            int newPadding = this.stickersAdapter.isShowingKeywords() ? AndroidUtilities.dp(24.0f) : 0;
            if (newPadding != this.stickersListView.getPaddingTop() || this.stickersPanel.getTag() == null) {
                this.stickersListView.setPadding(AndroidUtilities.dp(18.0f), newPadding, AndroidUtilities.dp(18.0f), 0);
                this.stickersListView.scrollToPosition(0);
                boolean isRtl = this.chatActivityEnterView.isRtlText();
                FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.stickersPanelArrow.getLayoutParams();
                layoutParams.gravity = (isRtl ? 5 : 3) | 80;
                this.stickersPanelArrow.requestLayout();
            }
        }
        if (!show || this.stickersPanel.getTag() == null) {
            if (!show && this.stickersPanel.getTag() == null) {
                return;
            }
            if (show) {
                this.stickersPanel.setVisibility(this.allowStickersPanel ? 0 : 4);
                this.stickersPanel.setTag(1);
            } else {
                this.stickersPanel.setTag(null);
            }
            AnimatorSet animatorSet = this.runningAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.runningAnimation = null;
            }
            if (this.stickersPanel.getVisibility() != 4) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.runningAnimation = animatorSet2;
                Animator[] animatorArr = new Animator[1];
                FrameLayout frameLayout = this.stickersPanel;
                Property property = View.ALPHA;
                float[] fArr = new float[2];
                fArr[0] = show ? 0.0f : 1.0f;
                fArr[1] = show ? 1.0f : 0.0f;
                animatorArr[0] = ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr);
                animatorSet2.playTogether(animatorArr);
                this.runningAnimation.setDuration(150L);
                this.runningAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.41
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ChatActivity.this.runningAnimation != null && ChatActivity.this.runningAnimation.equals(animation)) {
                            if (!show) {
                                ChatActivity.this.stickersAdapter.clearStickers();
                                ChatActivity.this.stickersPanel.setVisibility(8);
                                if (ContentPreviewViewer.getInstance().isVisible()) {
                                    ContentPreviewViewer.getInstance().close();
                                }
                                ContentPreviewViewer.getInstance().reset();
                            }
                            ChatActivity.this.runningAnimation = null;
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (ChatActivity.this.runningAnimation != null && ChatActivity.this.runningAnimation.equals(animation)) {
                            ChatActivity.this.runningAnimation = null;
                        }
                    }
                });
                this.runningAnimation.start();
                return;
            }
            if (!show) {
                this.stickersPanel.setVisibility(8);
            }
        }
    }

    public /* synthetic */ void lambda$initStickers$50$ChatActivity(View view, int position) {
        Object item = this.stickersAdapter.getItem(position);
        final Object parent = this.stickersAdapter.getItemParent(position);
        if (item instanceof TLRPC.TL_document) {
            if (!this.inScheduleMode && checkSlowMode(view)) {
                return;
            }
            final TLRPC.TL_document document = (TLRPC.TL_document) item;
            if (this.inScheduleMode) {
                AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.currentUser), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$DS2xBc1ulyniObjuLXI4QwIFGow
                    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                    public final void didSelectDate(boolean z, int i) {
                        this.f$0.lambda$null$49$ChatActivity(document, parent, z, i);
                    }
                });
            } else {
                getSendMessagesHelper().sendSticker(document, this.dialog_id, this.replyingMessageObject, parent, true, 0);
            }
            hideFieldPanel(false);
            this.chatActivityEnterView.addStickerToRecent(document);
            this.chatActivityEnterView.setFieldText("");
            return;
        }
        if (item instanceof String) {
            String emoji = (String) item;
            SpannableString string = new SpannableString(emoji);
            Emoji.replaceEmoji(string, this.chatActivityEnterView.getEditField().getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            this.chatActivityEnterView.setFieldText(string, false);
        }
    }

    public /* synthetic */ void lambda$null$49$ChatActivity(TLRPC.TL_document document, Object parent, boolean notify, int scheduleDate) {
        SendMessagesHelper.getInstance(this.currentAccount).sendSticker(document, this.dialog_id, this.replyingMessageObject, parent, notify, scheduleDate);
    }

    public void shareMyContact(final int type, final MessageObject messageObject) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("ShareYouPhoneNumberTitle", R.string.ShareYouPhoneNumberTitle));
        TLRPC.User user = this.currentUser;
        if (user != null) {
            if (user.bot) {
                builder.setMessage(LocaleController.getString("AreYouSureShareMyContactInfoBot", R.string.AreYouSureShareMyContactInfoBot));
            } else {
                builder.setMessage(AndroidUtilities.replaceTags(LocaleController.formatString("AreYouSureShareMyContactInfoUser", R.string.AreYouSureShareMyContactInfoUser, PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + getUserConfig().getCurrentUser().phone), ContactsController.formatName(this.currentUser.first_name, this.currentUser.last_name))));
            }
        } else {
            builder.setMessage(LocaleController.getString("AreYouSureShareMyContactInfo", R.string.AreYouSureShareMyContactInfo));
        }
        builder.setPositiveButton(LocaleController.getString("ShareContact", R.string.ShareContact), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$C4IYBZffyUeLVCCV_lI56RIO94Y
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$shareMyContact$52$ChatActivity(type, messageObject, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$shareMyContact$52$ChatActivity(int type, MessageObject messageObject, DialogInterface dialogInterface, int i) {
        if (type == 1) {
            TLRPC.TL_contacts_acceptContact req = new TLRPC.TL_contacts_acceptContact();
            req.id = getMessagesController().getInputUser(this.currentUser);
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$KKKTY-QcqzBWhELTM23KBYFnHrc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$51$ChatActivity(tLObject, tL_error);
                }
            });
        } else {
            SendMessagesHelper.getInstance(this.currentAccount).sendMessage(getUserConfig().getCurrentUser(), this.dialog_id, messageObject, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, true, 0);
            if (!this.inScheduleMode) {
                moveScrollToLastMessage();
            }
            hideFieldPanel(false);
        }
    }

    public /* synthetic */ void lambda$null$51$ChatActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            return;
        }
        getMessagesController().processUpdates((TLRPC.Updates) response, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideVoiceHint() {
        if (this.voiceHintTextView == null) {
            return;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        this.voiceHintAnimation = animatorSet;
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.voiceHintTextView, (Property<TextView, Float>) View.ALPHA, 0.0f));
        this.voiceHintAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.42
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(ChatActivity.this.voiceHintAnimation)) {
                    ChatActivity.this.voiceHintAnimation = null;
                    ChatActivity.this.voiceHintHideRunnable = null;
                    if (ChatActivity.this.voiceHintTextView != null) {
                        ChatActivity.this.voiceHintTextView.setVisibility(8);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (animation.equals(ChatActivity.this.voiceHintAnimation)) {
                    ChatActivity.this.voiceHintAnimation = null;
                    ChatActivity.this.voiceHintHideRunnable = null;
                }
            }
        });
        this.voiceHintAnimation.setDuration(300L);
        this.voiceHintAnimation.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showVoiceHint(boolean hide, boolean video) {
        int i;
        String str;
        if (getParentActivity() == null || this.fragmentView == null) {
            return;
        }
        if ((hide && this.voiceHintTextView == null) || this.inScheduleMode) {
            return;
        }
        if (this.voiceHintTextView == null) {
            SizeNotifierFrameLayout frameLayout = (SizeNotifierFrameLayout) this.fragmentView;
            int index = frameLayout.indexOfChild(this.chatActivityEnterView);
            if (index == -1) {
                return;
            }
            TextView textView = new TextView(getParentActivity());
            this.voiceHintTextView = textView;
            textView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(3.0f), Theme.getColor(Theme.key_chat_gifSaveHintBackground)));
            this.voiceHintTextView.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
            this.voiceHintTextView.setTextSize(1, 14.0f);
            this.voiceHintTextView.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f));
            this.voiceHintTextView.setGravity(16);
            this.voiceHintTextView.setAlpha(0.0f);
            frameLayout.addView(this.voiceHintTextView, index + 1, LayoutHelper.createFrame(-2.0f, -2.0f, 85, 5.0f, 0.0f, 5.0f, 3.0f));
        }
        if (hide) {
            AnimatorSet animatorSet = this.voiceHintAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.voiceHintAnimation = null;
            }
            AndroidUtilities.cancelRunOnUIThread(this.voiceHintHideRunnable);
            this.voiceHintHideRunnable = null;
            if (this.voiceHintTextView.getVisibility() == 0) {
                hideVoiceHint();
                return;
            }
            return;
        }
        TextView textView2 = this.voiceHintTextView;
        if (video) {
            i = R.string.HoldToVideo;
            str = "HoldToVideo";
        } else {
            i = R.string.HoldToAudio;
            str = "HoldToAudio";
        }
        textView2.setText(LocaleController.getString(str, i));
        Runnable runnable = this.voiceHintHideRunnable;
        if (runnable != null) {
            AnimatorSet animatorSet2 = this.voiceHintAnimation;
            if (animatorSet2 != null) {
                animatorSet2.cancel();
                this.voiceHintAnimation = null;
            } else {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$wf9A745SuHLSST5l8sjUOkekvAc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.hideVoiceHint();
                    }
                };
                this.voiceHintHideRunnable = runnable2;
                AndroidUtilities.runOnUIThread(runnable2, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                return;
            }
        } else if (this.voiceHintAnimation != null) {
            return;
        }
        this.voiceHintTextView.setVisibility(0);
        AnimatorSet animatorSet3 = new AnimatorSet();
        this.voiceHintAnimation = animatorSet3;
        animatorSet3.playTogether(ObjectAnimator.ofFloat(this.voiceHintTextView, (Property<TextView, Float>) View.ALPHA, 1.0f));
        this.voiceHintAnimation.addListener(new AnonymousClass43());
        this.voiceHintAnimation.setDuration(300L);
        this.voiceHintAnimation.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$43, reason: invalid class name */
    class AnonymousClass43 extends AnimatorListenerAdapter {
        AnonymousClass43() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            if (animation.equals(ChatActivity.this.voiceHintAnimation)) {
                ChatActivity.this.voiceHintAnimation = null;
                AndroidUtilities.runOnUIThread(ChatActivity.this.voiceHintHideRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$43$pnKYjsWbaOpRswDXRpsyzME2IL4
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onAnimationEnd$0$ChatActivity$43();
                    }
                }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            }
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ChatActivity$43() {
            ChatActivity.this.hideVoiceHint();
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animation) {
            if (animation.equals(ChatActivity.this.voiceHintAnimation)) {
                ChatActivity.this.voiceHintAnimation = null;
            }
        }
    }

    private boolean checkSlowMode(View view) {
        CharSequence time = this.chatActivityEnterView.getSlowModeTimer();
        if (time != null) {
            showSlowModeHint(view, true, time);
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSlowModeHint(View view, boolean show, CharSequence time) {
        HintView hintView;
        if (getParentActivity() == null || this.fragmentView == null) {
            return;
        }
        if (!show && ((hintView = this.slowModeHint) == null || hintView.getVisibility() != 0)) {
            return;
        }
        this.slowModeHint.setText(AndroidUtilities.replaceTags(LocaleController.formatString("SlowModeHint", R.string.SlowModeHint, time)));
        if (show) {
            this.slowModeHint.showForView(view, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showMediaBannedHint() {
        SizeNotifierFrameLayout frameLayout;
        int index;
        if (getParentActivity() == null || this.currentChat == null || this.fragmentView == null) {
            return;
        }
        TextView textView = this.mediaBanTooltip;
        if ((textView != null && textView.getVisibility() == 0) || (index = (frameLayout = (SizeNotifierFrameLayout) this.fragmentView).indexOfChild(this.chatActivityEnterView)) == -1) {
            return;
        }
        if (this.mediaBanTooltip == null) {
            CorrectlyMeasuringTextView correctlyMeasuringTextView = new CorrectlyMeasuringTextView(getParentActivity());
            this.mediaBanTooltip = correctlyMeasuringTextView;
            correctlyMeasuringTextView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(3.0f), Theme.getColor(Theme.key_chat_gifSaveHintBackground)));
            this.mediaBanTooltip.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
            this.mediaBanTooltip.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f));
            this.mediaBanTooltip.setGravity(16);
            this.mediaBanTooltip.setTextSize(1, 14.0f);
            this.mediaBanTooltip.setVisibility(8);
            frameLayout.addView(this.mediaBanTooltip, index + 1, LayoutHelper.createFrame(-2.0f, -2.0f, 85, 30.0f, 0.0f, 5.0f, 3.0f));
        }
        if (ChatObject.isActionBannedByDefault(this.currentChat, 7)) {
            this.mediaBanTooltip.setText(LocaleController.getString("GlobalAttachMediaRestricted", R.string.GlobalAttachMediaRestricted));
        } else {
            if (this.currentChat.banned_rights == null) {
                return;
            }
            if (AndroidUtilities.isBannedForever(this.currentChat.banned_rights)) {
                this.mediaBanTooltip.setText(LocaleController.getString("AttachMediaRestrictedForever", R.string.AttachMediaRestrictedForever));
            } else {
                this.mediaBanTooltip.setText(LocaleController.formatString("AttachMediaRestricted", R.string.AttachMediaRestricted, LocaleController.formatDateForBan(this.currentChat.banned_rights.until_date)));
            }
        }
        this.mediaBanTooltip.setVisibility(0);
        AnimatorSet AnimatorSet = new AnimatorSet();
        AnimatorSet.playTogether(ObjectAnimator.ofFloat(this.mediaBanTooltip, (Property<TextView, Float>) View.ALPHA, 0.0f, 1.0f));
        AnimatorSet.addListener(new AnonymousClass44());
        AnimatorSet.setDuration(300L);
        AnimatorSet.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$44, reason: invalid class name */
    class AnonymousClass44 extends AnimatorListenerAdapter {
        AnonymousClass44() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$44$l90yAdYAEUgQdCoRo2hhWKX7Zc4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ChatActivity$44();
                }
            }, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ChatActivity$44() {
            if (ChatActivity.this.mediaBanTooltip == null) {
                return;
            }
            AnimatorSet AnimatorSet = new AnimatorSet();
            AnimatorSet.playTogether(ObjectAnimator.ofFloat(ChatActivity.this.mediaBanTooltip, (Property<TextView, Float>) View.ALPHA, 0.0f));
            AnimatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.44.1
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatActivity.this.mediaBanTooltip != null) {
                        ChatActivity.this.mediaBanTooltip.setVisibility(8);
                    }
                }
            });
            AnimatorSet.setDuration(300L);
            AnimatorSet.start();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showNoSoundHint() {
        ChatMessageCell messageCell;
        MessageObject messageObject;
        if (this.scrollingChatListView || SharedConfig.noSoundHintShowed || this.chatListView == null || getParentActivity() == null || this.fragmentView == null) {
            return;
        }
        HintView hintView = this.noSoundHintView;
        if (hintView != null && hintView.getTag() != null) {
            return;
        }
        if (this.noSoundHintView == null) {
            SizeNotifierFrameLayout frameLayout = (SizeNotifierFrameLayout) this.fragmentView;
            int index = frameLayout.indexOfChild(this.chatActivityEnterView);
            if (index == -1) {
                return;
            }
            HintView hintView2 = new HintView(getParentActivity(), 0);
            this.noSoundHintView = hintView2;
            frameLayout.addView(hintView2, index + 1, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 19.0f, 0.0f, 19.0f, 0.0f));
            this.noSoundHintView.setAlpha(0.0f);
            this.noSoundHintView.setVisibility(4);
        }
        int count = this.chatListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.chatListView.getChildAt(a);
            if ((child instanceof ChatMessageCell) && (messageObject = (messageCell = (ChatMessageCell) child).getMessageObject()) != null && messageObject.isVideo()) {
                ImageReceiver imageReceiver = messageCell.getPhotoImage();
                AnimatedFileDrawable animation = imageReceiver.getAnimation();
                if (animation != null && animation.getCurrentProgressMs() >= 3000 && this.noSoundHintView.showForMessageCell(messageCell, true)) {
                    SharedConfig.setNoSoundHintShowed(true);
                    return;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showForwardHint(ChatMessageCell cell) {
        if (this.scrollingChatListView || this.chatListView == null || getParentActivity() == null || this.fragmentView == null) {
            return;
        }
        if (this.forwardHintView == null) {
            SizeNotifierFrameLayout frameLayout = (SizeNotifierFrameLayout) this.fragmentView;
            int index = frameLayout.indexOfChild(this.chatActivityEnterView);
            if (index == -1) {
                return;
            }
            HintView hintView = new HintView(getParentActivity(), 1);
            this.forwardHintView = hintView;
            frameLayout.addView(hintView, index + 1, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 19.0f, 0.0f, 19.0f, 0.0f));
            this.forwardHintView.setAlpha(0.0f);
            this.forwardHintView.setVisibility(4);
        }
        this.forwardHintView.showForMessageCell(cell, true);
    }

    private void showGifHint() {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        if (preferences.getBoolean("gifhint", false)) {
            return;
        }
        preferences.edit().putBoolean("gifhint", true).commit();
        if (getParentActivity() == null || this.fragmentView == null || this.gifHintTextView != null) {
            return;
        }
        if (!this.allowContextBotPanelSecond) {
            ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
            if (chatActivityEnterView != null) {
                chatActivityEnterView.setOpenGifsTabFirst();
                return;
            }
            return;
        }
        SizeNotifierFrameLayout frameLayout = (SizeNotifierFrameLayout) this.fragmentView;
        int index = frameLayout.indexOfChild(this.chatActivityEnterView);
        if (index == -1) {
            return;
        }
        this.chatActivityEnterView.setOpenGifsTabFirst();
        View view = new View(getParentActivity());
        this.emojiButtonRed = view;
        view.setBackgroundResource(R.drawable.redcircle);
        frameLayout.addView(this.emojiButtonRed, index + 1, LayoutHelper.createFrame(10.0f, 10.0f, 83, 30.0f, 0.0f, 0.0f, 27.0f));
        TextView textView = new TextView(getParentActivity());
        this.gifHintTextView = textView;
        textView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(3.0f), Theme.getColor(Theme.key_chat_gifSaveHintBackground)));
        this.gifHintTextView.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
        this.gifHintTextView.setTextSize(1, 14.0f);
        this.gifHintTextView.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f));
        this.gifHintTextView.setText(LocaleController.getString("TapHereGifs", R.string.TapHereGifs));
        this.gifHintTextView.setGravity(16);
        frameLayout.addView(this.gifHintTextView, index + 1, LayoutHelper.createFrame(-2.0f, -2.0f, 83, 5.0f, 0.0f, 5.0f, 3.0f));
        AnimatorSet AnimatorSet = new AnimatorSet();
        AnimatorSet.playTogether(ObjectAnimator.ofFloat(this.gifHintTextView, (Property<TextView, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.emojiButtonRed, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f));
        AnimatorSet.addListener(new AnonymousClass45());
        AnimatorSet.setDuration(300L);
        AnimatorSet.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$45, reason: invalid class name */
    class AnonymousClass45 extends AnimatorListenerAdapter {
        AnonymousClass45() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$45$DooXdM3uzKBkWDvWbjy01COaTP4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$ChatActivity$45();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$ChatActivity$45() {
            if (ChatActivity.this.gifHintTextView == null) {
                return;
            }
            AnimatorSet AnimatorSet = new AnimatorSet();
            AnimatorSet.playTogether(ObjectAnimator.ofFloat(ChatActivity.this.gifHintTextView, (Property<TextView, Float>) View.ALPHA, 0.0f));
            AnimatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.45.1
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatActivity.this.gifHintTextView != null) {
                        ChatActivity.this.gifHintTextView.setVisibility(8);
                    }
                }
            });
            AnimatorSet.setDuration(300L);
            AnimatorSet.start();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openAttachMenu() {
        if (getParentActivity() == null) {
            return;
        }
        createChatAttachView();
        this.chatAttachAlert.loadGalleryPhotos();
        if (Build.VERSION.SDK_INT == 21 || Build.VERSION.SDK_INT == 22) {
            this.chatActivityEnterView.closeKeyboard();
        }
        TLRPC.Chat chat = this.currentChat;
        if (chat != null && !ChatObject.hasAdminRights(chat) && this.currentChat.slowmode_enabled) {
            this.chatAttachAlert.setMaxSelectedPhotos(10, true);
        } else {
            this.chatAttachAlert.setMaxSelectedPhotos(-1, true);
        }
        this.chatAttachAlert.init();
        showDialog(this.chatAttachAlert);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openCameraView() {
        if (getParentActivity() == null) {
            return;
        }
        final CameraViewActivity cameraViewActivity = new CameraViewActivity(getParentActivity(), this);
        cameraViewActivity.setDelegate(new CameraViewActivity.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.46
            @Override // im.uwrkaxlmjj.ui.hui.CameraViewActivity.ChatAttachViewDelegate
            public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                HashMap<Object, Object> selectedPhotos = cameraViewActivity.getSelectedPhotos();
                ArrayList<Object> selectedPhotosOrder = cameraViewActivity.getSelectedPhotosOrder();
                if (!selectedPhotos.isEmpty()) {
                    ArrayList<SendMessagesHelper.SendingMediaInfo> photos = new ArrayList<>();
                    for (int a = 0; a < selectedPhotosOrder.size(); a++) {
                        MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) selectedPhotos.get(selectedPhotosOrder.get(a));
                        SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                        if (photoEntry.imagePath != null) {
                            info.path = photoEntry.imagePath;
                        } else if (photoEntry.path != null) {
                            info.path = photoEntry.path;
                        }
                        info.isVideo = photoEntry.isVideo;
                        ArrayList<TLRPC.InputDocument> arrayList = null;
                        info.caption = photoEntry.caption != null ? photoEntry.caption.toString() : null;
                        info.entities = photoEntry.entities;
                        if (!photoEntry.stickers.isEmpty()) {
                            arrayList = new ArrayList<>(photoEntry.stickers);
                        }
                        info.masks = arrayList;
                        info.ttl = photoEntry.ttl;
                        info.videoEditedInfo = photoEntry.editedInfo;
                        info.canDeleteAfter = photoEntry.canDeleteAfter;
                        photos.add(info);
                        photoEntry.reset();
                    }
                    ChatActivity.this.fillEditingMediaWithCaption(photos.get(0).caption, photos.get(0).entities);
                    SendMessagesHelper.prepareSendingMedia(ChatActivity.this.getAccountInstance(), photos, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, null, button == 4, arg, ChatActivity.this.editingMessageObject, notify, scheduleDate, false);
                    ChatActivity.this.afterMessageSend();
                }
                if (scheduleDate != 0) {
                    if (ChatActivity.this.scheduledMessagesCount == -1) {
                        ChatActivity.this.scheduledMessagesCount = 0;
                    }
                    ChatActivity.this.scheduledMessagesCount += selectedPhotos.size();
                    ChatActivity.this.updateScheduledInterface(true);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hui.CameraViewActivity.ChatAttachViewDelegate
            public View getRevealView() {
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.hui.CameraViewActivity.ChatAttachViewDelegate
            public void didSelectBot(TLRPC.User user) {
            }

            @Override // im.uwrkaxlmjj.ui.hui.CameraViewActivity.ChatAttachViewDelegate
            public void onCameraOpened() {
                ChatActivity.this.chatActivityEnterView.hidePopup(true);
            }

            @Override // im.uwrkaxlmjj.ui.hui.CameraViewActivity.ChatAttachViewDelegate
            public void needEnterComment() {
            }
        });
        showDialog(cameraViewActivity);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkContextBotPanel() {
        MentionsAdapter mentionsAdapter;
        if (this.allowStickersPanel && (mentionsAdapter = this.mentionsAdapter) != null && mentionsAdapter.isBotContext()) {
            if (!this.allowContextBotPanel && !this.allowContextBotPanelSecond) {
                if (this.mentionContainer.getVisibility() == 0 && this.mentionContainer.getTag() == null) {
                    AnimatorSet animatorSet = this.mentionListAnimation;
                    if (animatorSet != null) {
                        animatorSet.cancel();
                    }
                    this.mentionContainer.setTag(1);
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.mentionListAnimation = animatorSet2;
                    animatorSet2.playTogether(ObjectAnimator.ofFloat(this.mentionContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                    this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.47
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                                ChatActivity.this.mentionContainer.setVisibility(4);
                                ChatActivity.this.mentionListAnimation = null;
                                ChatActivity.this.updateMessageListAccessibilityVisibility();
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                                ChatActivity.this.mentionListAnimation = null;
                            }
                        }
                    });
                    this.mentionListAnimation.setDuration(200L);
                    this.mentionListAnimation.start();
                    return;
                }
                return;
            }
            if (this.mentionContainer.getVisibility() == 4 || this.mentionContainer.getTag() != null) {
                AnimatorSet animatorSet3 = this.mentionListAnimation;
                if (animatorSet3 != null) {
                    animatorSet3.cancel();
                }
                this.mentionContainer.setTag(null);
                this.mentionContainer.setVisibility(0);
                updateMessageListAccessibilityVisibility();
                AnimatorSet animatorSet4 = new AnimatorSet();
                this.mentionListAnimation = animatorSet4;
                animatorSet4.playTogether(ObjectAnimator.ofFloat(this.mentionContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f));
                this.mentionListAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.48
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                            ChatActivity.this.mentionListAnimation = null;
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (ChatActivity.this.mentionListAnimation != null && ChatActivity.this.mentionListAnimation.equals(animation)) {
                            ChatActivity.this.mentionListAnimation = null;
                        }
                    }
                });
                this.mentionListAnimation.setDuration(200L);
                this.mentionListAnimation.start();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkAutoDownloadMessages(boolean scrollUp) {
        int firstMessagePosition;
        TLRPC.Document document;
        int canDownload;
        RecyclerListView recyclerListView = this.chatListView;
        if (recyclerListView == null) {
            return;
        }
        int count = recyclerListView.getChildCount();
        int firstMessagePosition2 = -1;
        int lastMessagePosition = -1;
        for (int a = 0; a < count; a++) {
            View child = this.chatListView.getChildAt(a);
            if (child instanceof ChatMessageCell) {
                RecyclerView.ViewHolder holder = this.chatListView.findContainingViewHolder(child);
                if (holder != null) {
                    int p = holder.getAdapterPosition();
                    if (firstMessagePosition2 == -1) {
                        firstMessagePosition2 = p;
                    }
                    lastMessagePosition = p;
                }
                ChatMessageCell cell = (ChatMessageCell) child;
                MessageObject object = cell.getMessageObject();
                if (object != null && !object.mediaExists && object.isSent() && (document = object.getDocument()) != null && !MessageObject.isStickerDocument(document) && !MessageObject.isAnimatedStickerDocument(document) && !MessageObject.isGifDocument(document) && !MessageObject.isRoundVideoDocument(document) && (canDownload = getDownloadController().canDownloadMedia(object.messageOwner)) != 0) {
                    if (canDownload == 2) {
                        if (this.currentEncryptedChat == null && !object.shouldEncryptPhotoOrVideo() && object.canStreamVideo()) {
                            getFileLoader().loadFile(document, object, 0, 10);
                        }
                    } else {
                        getFileLoader().loadFile(document, object, 0, (MessageObject.isVideoDocument(document) && object.shouldEncryptPhotoOrVideo()) ? 2 : 0);
                        cell.updateButtonState(false, true, false);
                    }
                }
            }
        }
        if (firstMessagePosition2 != -1) {
            if (scrollUp) {
                int lastPosition = lastMessagePosition;
                int firstMessagePosition3 = lastMessagePosition;
                if (firstMessagePosition3 + 10 < this.chatAdapter.messagesEndRow) {
                    firstMessagePosition = firstMessagePosition3 + 10;
                } else {
                    firstMessagePosition = this.chatAdapter.messagesEndRow;
                }
                int N = this.messages.size();
                for (int a2 = lastPosition; a2 < firstMessagePosition; a2++) {
                    int n = a2 - this.chatAdapter.messagesStartRow;
                    if (n >= 0 && n < N) {
                        checkAutoDownloadMessage(this.messages.get(n));
                    }
                }
            } else {
                int lastPosition2 = firstMessagePosition2 - 20;
                int lastPosition3 = lastPosition2 > this.chatAdapter.messagesStartRow ? firstMessagePosition2 - 20 : this.chatAdapter.messagesStartRow;
                int N2 = this.messages.size();
                for (int a3 = firstMessagePosition2 - 1; a3 >= lastPosition3; a3--) {
                    int n2 = a3 - this.chatAdapter.messagesStartRow;
                    if (n2 >= 0 && n2 < N2) {
                        checkAutoDownloadMessage(this.messages.get(n2));
                    }
                }
            }
        }
        showNoSoundHint();
    }

    private void checkAutoDownloadMessage(MessageObject object) {
        if (object.mediaExists) {
            return;
        }
        TLRPC.Message message = object.messageOwner;
        int canDownload = getDownloadController().canDownloadMedia(message);
        if (canDownload == 0) {
            return;
        }
        TLRPC.Document document = object.getDocument();
        TLRPC.PhotoSize photo = document == null ? FileLoader.getClosestPhotoSizeWithSize(object.photoThumbs, AndroidUtilities.getPhotoSize()) : null;
        if (document == null && photo == null) {
            return;
        }
        if (canDownload == 2 || (canDownload == 1 && object.isVideo())) {
            if (document != null && this.currentEncryptedChat == null && !object.shouldEncryptPhotoOrVideo() && object.canStreamVideo()) {
                getFileLoader().loadFile(document, object, 0, 10);
                return;
            }
            return;
        }
        if (document != null) {
            getFileLoader().loadFile(document, object, 0, (MessageObject.isVideoDocument(document) && object.shouldEncryptPhotoOrVideo()) ? 2 : 0);
        } else {
            getFileLoader().loadFile(ImageLocation.getForObject(photo, object.photoThumbsObject), object, null, 0, object.shouldEncryptPhotoOrVideo() ? 2 : 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showFloatingDateView(boolean scroll) {
        if (this.floatingDateView.getTag() == null) {
            AnimatorSet animatorSet = this.floatingDateAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            this.floatingDateView.setTag(1);
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.floatingDateAnimation = animatorSet2;
            animatorSet2.setDuration(150L);
            this.floatingDateAnimation.playTogether(ObjectAnimator.ofFloat(this.floatingDateView, (Property<ChatActionCell, Float>) View.ALPHA, 1.0f));
            this.floatingDateAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.49
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(ChatActivity.this.floatingDateAnimation)) {
                        ChatActivity.this.floatingDateAnimation = null;
                    }
                }
            });
            this.floatingDateAnimation.start();
        }
        if (!scroll) {
            updateMessagesVisiblePart(false);
            this.hideDateDelay = 1000;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideFloatingDateView(boolean animated) {
        if (this.floatingDateView.getTag() == null || this.currentFloatingDateOnScreen) {
            return;
        }
        if (!this.scrollingFloatingDate || this.currentFloatingTopIsNotMessage) {
            this.floatingDateView.setTag(null);
            if (animated) {
                AnimatorSet animatorSet = new AnimatorSet();
                this.floatingDateAnimation = animatorSet;
                animatorSet.setDuration(150L);
                this.floatingDateAnimation.playTogether(ObjectAnimator.ofFloat(this.floatingDateView, (Property<ChatActionCell, Float>) View.ALPHA, 0.0f));
                this.floatingDateAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.50
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (animation.equals(ChatActivity.this.floatingDateAnimation)) {
                            ChatActivity.this.floatingDateAnimation = null;
                        }
                    }
                });
                this.floatingDateAnimation.setStartDelay(this.hideDateDelay);
                this.floatingDateAnimation.start();
            } else {
                AnimatorSet animatorSet2 = this.floatingDateAnimation;
                if (animatorSet2 != null) {
                    animatorSet2.cancel();
                    this.floatingDateAnimation = null;
                }
                this.floatingDateView.setAlpha(0.0f);
            }
            this.hideDateDelay = SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onRemoveFromParent() {
        MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
        if (messageObject != null && messageObject.isVideo()) {
            MediaController.getInstance().cleanupPlayer(true, true);
        } else {
            MediaController.getInstance().setTextureView(this.videoTextureView, null, null, false);
        }
    }

    protected void setIgnoreAttachOnPause(boolean value) {
        this.ignoreAttachOnPause = value;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkScrollForLoad(boolean scroll) {
        int checkLoadCount;
        GridLayoutManagerFixed gridLayoutManagerFixed = this.chatLayoutManager;
        if (gridLayoutManagerFixed == null || this.paused) {
            return;
        }
        int firstVisibleItem = gridLayoutManagerFixed.findFirstVisibleItemPosition();
        int visibleItemCount = firstVisibleItem == -1 ? 0 : Math.abs(this.chatLayoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
        int totalItemCount = this.chatAdapter.getItemCount();
        if (scroll) {
            checkLoadCount = 25;
        } else {
            checkLoadCount = 5;
        }
        if ((totalItemCount - firstVisibleItem) - visibleItemCount <= checkLoadCount && !this.loading) {
            boolean[] zArr = this.endReached;
            if (!zArr[0]) {
                this.loading = true;
                this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
                if (this.messagesByDays.size() != 0) {
                    MessagesController messagesController = getMessagesController();
                    long j = this.dialog_id;
                    int i = this.maxMessageId[0];
                    boolean z = !this.cacheEndReached[0];
                    int i2 = this.minDate[0];
                    int i3 = this.classGuid;
                    boolean zIsChannel = ChatObject.isChannel(this.currentChat);
                    boolean z2 = this.inScheduleMode;
                    int i4 = this.lastLoadIndex;
                    this.lastLoadIndex = i4 + 1;
                    messagesController.loadMessages(j, 50, i, 0, z, i2, i3, 0, 0, zIsChannel, z2, i4);
                } else {
                    MessagesController messagesController2 = getMessagesController();
                    long j2 = this.dialog_id;
                    boolean z3 = !this.cacheEndReached[0];
                    int i5 = this.minDate[0];
                    int i6 = this.classGuid;
                    boolean zIsChannel2 = ChatObject.isChannel(this.currentChat);
                    boolean z4 = this.inScheduleMode;
                    int i7 = this.lastLoadIndex;
                    this.lastLoadIndex = i7 + 1;
                    messagesController2.loadMessages(j2, 50, 0, 0, z3, i5, i6, 0, 0, zIsChannel2, z4, i7);
                }
            } else if (this.mergeDialogId != 0 && !zArr[1]) {
                this.loading = true;
                this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
                MessagesController messagesController3 = getMessagesController();
                long j3 = this.mergeDialogId;
                int i8 = this.maxMessageId[1];
                boolean z5 = !this.cacheEndReached[1];
                int i9 = this.minDate[1];
                int i10 = this.classGuid;
                boolean z6 = this.inScheduleMode;
                int i11 = this.lastLoadIndex;
                this.lastLoadIndex = i11 + 1;
                messagesController3.loadMessages(j3, 50, i8, 0, z5, i9, i10, 0, 0, false, z6, i11);
            }
        }
        if (visibleItemCount > 0 && !this.loadingForward && firstVisibleItem <= 10) {
            if (this.mergeDialogId != 0 && !this.forwardEndReached[1]) {
                this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
                MessagesController messagesController4 = getMessagesController();
                long j4 = this.mergeDialogId;
                int i12 = this.minMessageId[1];
                int i13 = this.maxDate[1];
                int i14 = this.classGuid;
                boolean z7 = this.inScheduleMode;
                int i15 = this.lastLoadIndex;
                this.lastLoadIndex = i15 + 1;
                messagesController4.loadMessages(j4, 50, i12, 0, true, i13, i14, 1, 0, false, z7, i15);
                this.loadingForward = true;
                return;
            }
            if (!this.forwardEndReached[0]) {
                this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
                MessagesController messagesController5 = getMessagesController();
                long j5 = this.dialog_id;
                int i16 = this.minMessageId[0];
                int i17 = this.maxDate[0];
                int i18 = this.classGuid;
                boolean zIsChannel3 = ChatObject.isChannel(this.currentChat);
                boolean z8 = this.inScheduleMode;
                int i19 = this.lastLoadIndex;
                this.lastLoadIndex = i19 + 1;
                messagesController5.loadMessages(j5, 50, i16, 0, true, i17, i18, 1, 0, zIsChannel3, z8, i19);
                this.loadingForward = true;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Type inference failed for: r0v45, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r0v55, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r0v74, types: [java.lang.Throwable] */
    public void processSelectedAttach(int i) {
        TLRPC.Chat chat;
        boolean z;
        int i2 = 1;
        i2 = 1;
        if ((i == 4 || i == 1 || i == 3 || i == 2 || i == 0) && (chat = this.currentChat) != null) {
            if (!ChatObject.hasAdminRights(chat) && this.currentChat.default_banned_rights != null && this.currentChat.default_banned_rights.send_media) {
                AlertsCreator.showSendMediaAlert(5, this);
                return;
            } else if (!ChatObject.canSendMedia(this.currentChat)) {
                AlertsCreator.showSendMediaAlert(2, this);
                return;
            }
        }
        if (i == 0) {
            if (SharedConfig.inappCamera) {
                openCameraView();
                return;
            }
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
                getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 19);
                return;
            }
            try {
                Intent intent = new Intent("android.media.action.IMAGE_CAPTURE");
                File fileGeneratePicturePath = AndroidUtilities.generatePicturePath();
                if (fileGeneratePicturePath != null) {
                    if (Build.VERSION.SDK_INT >= 24) {
                        intent.putExtra("output", FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", fileGeneratePicturePath));
                        intent.addFlags(2);
                        intent.addFlags(1);
                    } else {
                        intent.putExtra("output", Uri.fromFile(fileGeneratePicturePath));
                    }
                    this.currentPicturePath = fileGeneratePicturePath.getAbsolutePath();
                }
                startActivityForResult(intent, 0);
                return;
            } catch (Exception e) {
                FileLog.e(e);
                return;
            }
        }
        if (i == 1) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
                try {
                    getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
                    return;
                } catch (Throwable th) {
                    return;
                }
            }
            if (ChatObject.isChannel(this.currentChat) && this.currentChat.banned_rights != null && this.currentChat.banned_rights.send_gifs) {
                z = false;
            } else {
                TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
                z = encryptedChat == null || AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) >= 46;
            }
            PhotoAlbumPickerActivity photoAlbumPickerActivity = new PhotoAlbumPickerActivity(0, z, true, this);
            TLRPC.Chat chat2 = this.currentChat;
            if (chat2 == null || ChatObject.hasAdminRights(chat2) || !this.currentChat.slowmode_enabled) {
                photoAlbumPickerActivity.setMaxSelectedPhotos(this.editingMessageObject != null ? 1 : 0, this.editingMessageObject == null);
            } else {
                photoAlbumPickerActivity.setMaxSelectedPhotos(10, true);
            }
            photoAlbumPickerActivity.setDelegate(new PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.51
                @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
                public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate, boolean blnOriginalImg) {
                    boolean hasNoGifs;
                    if (photos.isEmpty()) {
                        return;
                    }
                    int a = 0;
                    while (true) {
                        if (a >= photos.size()) {
                            hasNoGifs = false;
                            break;
                        } else if (photos.get(a).inlineResult != null) {
                            a++;
                        } else {
                            hasNoGifs = true;
                            break;
                        }
                    }
                    if (!hasNoGifs && !TextUtils.isEmpty(photos.get(0).caption)) {
                        SendMessagesHelper.getInstance(ChatActivity.this.currentAccount).sendMessage(photos.get(0).caption, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, null, false, photos.get(0).entities, null, null, notify, scheduleDate);
                    }
                    int a2 = 0;
                    while (a2 < photos.size()) {
                        SendMessagesHelper.SendingMediaInfo info = photos.get(a2);
                        if (info.inlineResult != null) {
                            SendMessagesHelper.prepareSendingBotContextResult(ChatActivity.this.getAccountInstance(), info.inlineResult, info.params, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, notify, scheduleDate);
                            photos.remove(a2);
                            a2--;
                        }
                        a2++;
                    }
                    if (!photos.isEmpty()) {
                        ChatActivity.this.fillEditingMediaWithCaption(photos.get(0).caption, photos.get(0).entities);
                        if (!blnOriginalImg) {
                            SendMessagesHelper.prepareSendingMedia(ChatActivity.this.getAccountInstance(), photos, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, null, false, true, ChatActivity.this.editingMessageObject, notify, scheduleDate, blnOriginalImg);
                        } else {
                            int count = photos.size();
                            for (int a3 = 0; a3 < count; a3++) {
                                SendMessagesHelper.SendingMediaInfo info2 = photos.get(a3);
                                if (info2.searchImage == null && !info2.isVideo) {
                                    SendMessagesHelper.prepareSendingDocument(ChatActivity.this.getAccountInstance(), info2.path, info2.path, null, null, null, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, null, ChatActivity.this.editingMessageObject, true, 0);
                                }
                            }
                        }
                        ChatActivity.this.afterMessageSend();
                        if (scheduleDate != 0) {
                            if (ChatActivity.this.scheduledMessagesCount == -1) {
                                ChatActivity.this.scheduledMessagesCount = 0;
                            }
                            ChatActivity.this.scheduledMessagesCount += photos.size();
                            ChatActivity.this.updateScheduledInterface(true);
                        }
                    }
                }

                @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
                public void startPhotoSelectActivity() {
                    try {
                        Intent videoPickerIntent = new Intent();
                        videoPickerIntent.setType("video/*");
                        videoPickerIntent.setAction("android.intent.action.GET_CONTENT");
                        videoPickerIntent.putExtra("android.intent.extra.sizeLimit", 1610612736L);
                        Intent photoPickerIntent = new Intent("android.intent.action.PICK");
                        photoPickerIntent.setType("image/*");
                        Intent chooserIntent = Intent.createChooser(photoPickerIntent, null);
                        chooserIntent.putExtra("android.intent.extra.INITIAL_INTENTS", new Intent[]{videoPickerIntent});
                        ChatActivity.this.startActivityForResult(chooserIntent, 1);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }
            });
            presentFragment(photoAlbumPickerActivity);
            return;
        }
        if (i == 2) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
                try {
                    getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 20);
                    return;
                } catch (Throwable th2) {
                    return;
                }
            }
            try {
                Intent intent2 = new Intent("android.media.action.VIDEO_CAPTURE");
                File fileGenerateVideoPath = AndroidUtilities.generateVideoPath();
                if (fileGenerateVideoPath != null) {
                    if (Build.VERSION.SDK_INT >= 24) {
                        intent2.putExtra("output", FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", fileGenerateVideoPath));
                        intent2.addFlags(2);
                        intent2.addFlags(1);
                    } else if (Build.VERSION.SDK_INT >= 18) {
                        intent2.putExtra("output", Uri.fromFile(fileGenerateVideoPath));
                    }
                    intent2.putExtra("android.intent.extra.sizeLimit", 1610612736L);
                    this.currentPicturePath = fileGenerateVideoPath.getAbsolutePath();
                }
                startActivityForResult(intent2, 2);
                return;
            } catch (Exception e2) {
                FileLog.e(e2);
                return;
            }
        }
        if (i == 6) {
            if (!isSecretChat()) {
                getLocationController().isSharingLocation(this.dialog_id);
                return;
            }
            return;
        }
        if (i == 4) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
                try {
                    getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
                    return;
                } catch (Throwable th3) {
                    return;
                }
            }
            DocumentSelectActivity documentSelectActivity = new DocumentSelectActivity(true);
            documentSelectActivity.setChatActivity(this);
            TLRPC.Chat chat3 = this.currentChat;
            if ((chat3 == null || ChatObject.hasAdminRights(chat3) || !this.currentChat.slowmode_enabled) && this.editingMessageObject == null) {
                i2 = -1;
            }
            documentSelectActivity.setMaxSelectedFiles(i2);
            documentSelectActivity.setDelegate(new AnonymousClass52());
            presentFragment(documentSelectActivity);
            return;
        }
        if (i == 3) {
            if (Build.VERSION.SDK_INT < 23 || getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) == 0) {
                AudioSelectActivity audioSelectActivity = new AudioSelectActivity(this);
                audioSelectActivity.setDelegate(new AudioSelectActivity.AudioSelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$w85xvnCAOLyGempL1kq1jeYqj2w
                    @Override // im.uwrkaxlmjj.ui.AudioSelectActivity.AudioSelectActivityDelegate
                    public final void didSelectAudio(ArrayList arrayList, boolean z2, int i3) {
                        this.f$0.lambda$processSelectedAttach$53$ChatActivity(arrayList, z2, i3);
                    }
                });
                presentFragment(audioSelectActivity);
                return;
            }
            getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
            return;
        }
        if (i == 5) {
            PhoneBookSelectActivity phoneBookSelectActivity = new PhoneBookSelectActivity(this);
            phoneBookSelectActivity.setDelegate(new PhoneBookSelectActivity.PhoneBookSelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$fn_3vhUE3mU5g0r52_8w6fIuYDU
                @Override // im.uwrkaxlmjj.ui.PhoneBookSelectActivity.PhoneBookSelectActivityDelegate
                public final void didSelectContact(TLRPC.User user, boolean z2, int i3) {
                    this.f$0.lambda$processSelectedAttach$54$ChatActivity(user, z2, i3);
                }
            });
            presentFragment(phoneBookSelectActivity);
            return;
        }
        if (i == 9) {
            TLRPC.Chat chat4 = this.currentChat;
            if (chat4 == null) {
                AlertsCreator.showSendMediaAlert(3, this);
                return;
            }
            if (!ChatObject.hasAdminRights(chat4) && this.currentChat.default_banned_rights != null && this.currentChat.default_banned_rights.send_polls) {
                AlertsCreator.showSendMediaAlert(6, this);
                return;
            } else {
                if (ChatObject.canSendPolls(this.currentChat)) {
                    PollCreateActivity pollCreateActivity = new PollCreateActivity(this);
                    pollCreateActivity.setDelegate(new PollCreateActivity.PollCreateActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$msDIqDpTesHgMOHkIX2u7sk9JJY
                        @Override // im.uwrkaxlmjj.ui.PollCreateActivity.PollCreateActivityDelegate
                        public final void sendPoll(TLRPC.TL_messageMediaPoll tL_messageMediaPoll, boolean z2, int i3) {
                            this.f$0.lambda$processSelectedAttach$55$ChatActivity(tL_messageMediaPoll, z2, i3);
                        }
                    });
                    presentFragment(pollCreateActivity);
                    return;
                }
                AlertsCreator.showSendMediaAlert(3, this);
                return;
            }
        }
        if (i == 1010) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if ((this.currentEncryptedChat == null ? MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.arguments.getInt("user_id", 0))) : MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.currentEncryptedChat.user_id))).mutual_contact) {
                    int connectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (connectionState == 2 || connectionState == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent3 = new Intent();
                    intent3.setClass(getParentActivity(), VisualCallActivity.class);
                    intent3.putExtra("CallType", 1);
                    ArrayList arrayList = new ArrayList();
                    arrayList.add(Integer.valueOf(this.arguments.getInt("user_id", 0)));
                    intent3.putExtra("ArrayUser", arrayList);
                    intent3.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent3);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            if (ApplicationLoader.mbytAVideoCallBusy == 3 || ApplicationLoader.mbytAVideoCallBusy == 4) {
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
                return;
            }
            return;
        }
        if (i == 1011) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.arguments.getInt("user_id", 0))).mutual_contact) {
                    int connectionState2 = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (connectionState2 == 2 || connectionState2 == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent4 = new Intent();
                    intent4.setClass(getParentActivity(), VisualCallActivity.class);
                    intent4.putExtra("CallType", 2);
                    ArrayList arrayList2 = new ArrayList();
                    arrayList2.add(Integer.valueOf(this.arguments.getInt("user_id", 0)));
                    intent4.putExtra("ArrayUser", arrayList2);
                    intent4.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent4);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            if (ApplicationLoader.mbytAVideoCallBusy == 3 || ApplicationLoader.mbytAVideoCallBusy == 4) {
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$52, reason: invalid class name */
    class AnonymousClass52 implements DocumentSelectActivity.DocumentSelectActivityDelegate {
        AnonymousClass52() {
        }

        @Override // im.uwrkaxlmjj.ui.DocumentSelectActivity.DocumentSelectActivityDelegate
        public void didSelectFiles(DocumentSelectActivity activity, ArrayList<String> files, boolean notify, int scheduleDate) {
            activity.finishFragment();
            ChatActivity.this.fillEditingMediaWithCaption(null, null);
            SendMessagesHelper.prepareSendingDocuments(ChatActivity.this.getAccountInstance(), files, files, null, null, null, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, null, ChatActivity.this.editingMessageObject, notify, scheduleDate);
            ChatActivity.this.afterMessageSend();
        }

        @Override // im.uwrkaxlmjj.ui.DocumentSelectActivity.DocumentSelectActivityDelegate
        public void startDocumentSelectActivity() {
            try {
                Intent photoPickerIntent = new Intent("android.intent.action.GET_CONTENT");
                if (Build.VERSION.SDK_INT >= 18) {
                    photoPickerIntent.putExtra("android.intent.extra.ALLOW_MULTIPLE", true);
                }
                photoPickerIntent.setType("*/*");
                ChatActivity.this.startActivityForResult(photoPickerIntent, 21);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // im.uwrkaxlmjj.ui.DocumentSelectActivity.DocumentSelectActivityDelegate
        public void startMusicSelectActivity(final BaseFragment parentFragment) {
            AudioSelectActivity fragment = new AudioSelectActivity(ChatActivity.this);
            fragment.setDelegate(new AudioSelectActivity.AudioSelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$52$57vsHoJctZMA4QB0gk1CKLxY_MY
                @Override // im.uwrkaxlmjj.ui.AudioSelectActivity.AudioSelectActivityDelegate
                public final void didSelectAudio(ArrayList arrayList, boolean z, int i) {
                    this.f$0.lambda$startMusicSelectActivity$0$ChatActivity$52(parentFragment, arrayList, z, i);
                }
            });
            ChatActivity.this.presentFragment(fragment);
        }

        public /* synthetic */ void lambda$startMusicSelectActivity$0$ChatActivity$52(BaseFragment parentFragment, ArrayList audios, boolean notify, int scheduleDate) {
            parentFragment.removeSelfFromStack();
            ChatActivity.this.fillEditingMediaWithCaption(null, null);
            SendMessagesHelper.prepareSendingAudioDocuments(ChatActivity.this.getAccountInstance(), audios, ChatActivity.this.dialog_id, ChatActivity.this.replyingMessageObject, ChatActivity.this.editingMessageObject, notify, scheduleDate);
            ChatActivity.this.afterMessageSend();
        }
    }

    public /* synthetic */ void lambda$processSelectedAttach$53$ChatActivity(ArrayList audios, boolean notify, int scheduleDate) {
        fillEditingMediaWithCaption(null, null);
        SendMessagesHelper.prepareSendingAudioDocuments(getAccountInstance(), audios, this.dialog_id, this.replyingMessageObject, this.editingMessageObject, notify, scheduleDate);
        afterMessageSend();
    }

    public /* synthetic */ void lambda$processSelectedAttach$54$ChatActivity(TLRPC.User user, boolean notify, int scheduleDate) {
        getSendMessagesHelper().sendMessage(user, this.dialog_id, this.replyingMessageObject, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, notify, scheduleDate);
        afterMessageSend();
    }

    public /* synthetic */ void lambda$processSelectedAttach$55$ChatActivity(TLRPC.TL_messageMediaPoll poll, boolean notify, int scheduleDate) {
        getSendMessagesHelper().sendMessage(poll, this.dialog_id, this.replyingMessageObject, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, notify, scheduleDate);
        afterMessageSend();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean dismissDialogOnPause(Dialog dialog) {
        return dialog != this.chatAttachAlert && super.dismissDialogOnPause(dialog);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void searchLinks(final CharSequence charSequence, final boolean force) {
        TLRPC.WebPage webPage;
        if (this.currentEncryptedChat != null && (getMessagesController().secretWebpagePreview == 0 || AndroidUtilities.getPeerLayerVersion(this.currentEncryptedChat.layer) < 46)) {
            return;
        }
        if (force && (webPage = this.foundWebPage) != null) {
            if (webPage.url != null) {
                int index = TextUtils.indexOf(charSequence, this.foundWebPage.url);
                char lastChar = 0;
                boolean lenEqual = false;
                if (index == -1) {
                    if (this.foundWebPage.display_url != null) {
                        index = TextUtils.indexOf(charSequence, this.foundWebPage.display_url);
                        lenEqual = index != -1 && this.foundWebPage.display_url.length() + index == charSequence.length();
                        lastChar = (index == -1 || lenEqual) ? (char) 0 : charSequence.charAt(this.foundWebPage.display_url.length() + index);
                    }
                } else {
                    lenEqual = this.foundWebPage.url.length() + index == charSequence.length();
                    lastChar = !lenEqual ? charSequence.charAt(this.foundWebPage.url.length() + index) : (char) 0;
                }
                if (index != -1 && (lenEqual || lastChar == ' ' || lastChar == ',' || lastChar == '.' || lastChar == '!' || lastChar == '/')) {
                    return;
                }
            }
            this.pendingLinkSearchString = null;
            this.foundUrls = null;
            showFieldPanelForWebPage(false, this.foundWebPage, false);
        }
        final MessagesController messagesController = getMessagesController();
        Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$x7Dl5xajaPaLZJdMzsiV2b_5tQA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$searchLinks$62$ChatActivity(charSequence, messagesController, force);
            }
        });
    }

    public /* synthetic */ void lambda$searchLinks$62$ChatActivity(final CharSequence charSequence, final MessagesController messagesController, final boolean force) {
        CharSequence textToCheck;
        URLSpanReplacement[] spans;
        if (this.linkSearchRequestId != 0) {
            getConnectionsManager().cancelRequest(this.linkSearchRequestId, true);
            this.linkSearchRequestId = 0;
        }
        ArrayList<CharSequence> urls = null;
        try {
            Matcher m = AndroidUtilities.WEB_URL.matcher(charSequence);
            while (m.find()) {
                if (m.start() <= 0 || charSequence.charAt(m.start() - 1) != '@') {
                    if (urls == null) {
                        urls = new ArrayList<>();
                    }
                    urls.add(charSequence.subSequence(m.start(), m.end()));
                }
            }
            if ((charSequence instanceof Spannable) && (spans = (URLSpanReplacement[]) ((Spannable) charSequence).getSpans(0, charSequence.length(), URLSpanReplacement.class)) != null && spans.length > 0) {
                if (urls == null) {
                    urls = new ArrayList<>();
                }
                for (URLSpanReplacement uRLSpanReplacement : spans) {
                    urls.add(uRLSpanReplacement.getURL());
                }
            }
            if (urls != null && this.foundUrls != null && urls.size() == this.foundUrls.size()) {
                boolean clear = true;
                for (int a = 0; a < urls.size(); a++) {
                    if (!TextUtils.equals(urls.get(a), this.foundUrls.get(a))) {
                        clear = false;
                    }
                }
                if (clear) {
                    return;
                }
            }
            this.foundUrls = urls;
        } catch (Exception e) {
            FileLog.e(e);
            String text = charSequence.toString().toLowerCase();
            if (charSequence.length() < 13 || (!text.contains(DefaultWebClient.HTTP_SCHEME) && !text.contains(DefaultWebClient.HTTPS_SCHEME))) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$s9XA9quLEbKl3TJTfkZlkbhfXaU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$57$ChatActivity();
                    }
                });
                return;
            }
            textToCheck = charSequence;
        }
        if (urls == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$8EczLhV12T_LT6NYQa4XOlZjERg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$56$ChatActivity();
                }
            });
            return;
        }
        textToCheck = TextUtils.join(" ", urls);
        if (this.currentEncryptedChat != null && messagesController.secretWebpagePreview == 2) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$oBBAyjMGKeN5tGmPkbspsTybkxQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$59$ChatActivity(messagesController, charSequence, force);
                }
            });
            return;
        }
        final TLRPC.TL_messages_getWebPagePreview req = new TLRPC.TL_messages_getWebPagePreview();
        if (textToCheck instanceof String) {
            req.message = (String) textToCheck;
        } else {
            req.message = textToCheck.toString();
        }
        this.linkSearchRequestId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$X03p294Cd3ll3wSduEd9ysN0T64
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$61$ChatActivity(req, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(this.linkSearchRequestId, this.classGuid);
    }

    public /* synthetic */ void lambda$null$56$ChatActivity() {
        TLRPC.WebPage webPage = this.foundWebPage;
        if (webPage != null) {
            showFieldPanelForWebPage(false, webPage, false);
            this.foundWebPage = null;
        }
    }

    public /* synthetic */ void lambda$null$57$ChatActivity() {
        TLRPC.WebPage webPage = this.foundWebPage;
        if (webPage != null) {
            showFieldPanelForWebPage(false, webPage, false);
            this.foundWebPage = null;
        }
    }

    public /* synthetic */ void lambda$null$59$ChatActivity(final MessagesController messagesController, final CharSequence charSequence, final boolean force) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$aW-xG4GHc_RhdPWIvAwxQxPM2uc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$58$ChatActivity(messagesController, charSequence, force, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setMessage(LocaleController.getString("SecretLinkPreviewAlert", R.string.SecretLinkPreviewAlert));
        showDialog(builder.create());
        messagesController.secretWebpagePreview = 0;
        MessagesController.getGlobalMainSettings().edit().putInt("secretWebpage2", messagesController.secretWebpagePreview).commit();
    }

    public /* synthetic */ void lambda$null$58$ChatActivity(MessagesController messagesController, CharSequence charSequence, boolean force, DialogInterface dialog, int which) {
        messagesController.secretWebpagePreview = 1;
        MessagesController.getGlobalMainSettings().edit().putInt("secretWebpage2", getMessagesController().secretWebpagePreview).commit();
        this.foundUrls = null;
        searchLinks(charSequence, force);
    }

    public /* synthetic */ void lambda$null$61$ChatActivity(final TLRPC.TL_messages_getWebPagePreview req, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$E7QbmrjRM36oAa67hQpq1e1r5gM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$60$ChatActivity(error, response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$60$ChatActivity(TLRPC.TL_error error, TLObject response, TLRPC.TL_messages_getWebPagePreview req) {
        this.linkSearchRequestId = 0;
        if (error == null) {
            if (response instanceof TLRPC.TL_messageMediaWebPage) {
                TLRPC.WebPage webPage = ((TLRPC.TL_messageMediaWebPage) response).webpage;
                this.foundWebPage = webPage;
                if ((webPage instanceof TLRPC.TL_webPage) || (webPage instanceof TLRPC.TL_webPagePending)) {
                    if (this.foundWebPage instanceof TLRPC.TL_webPagePending) {
                        this.pendingLinkSearchString = req.message;
                    }
                    if (this.currentEncryptedChat != null) {
                        TLRPC.WebPage webPage2 = this.foundWebPage;
                        if (webPage2 instanceof TLRPC.TL_webPagePending) {
                            webPage2.url = req.message;
                        }
                    }
                    showFieldPanelForWebPage(true, this.foundWebPage, false);
                    return;
                }
                if (webPage != null) {
                    showFieldPanelForWebPage(false, webPage, false);
                    this.foundWebPage = null;
                    return;
                }
                return;
            }
            TLRPC.WebPage webPage3 = this.foundWebPage;
            if (webPage3 != null) {
                showFieldPanelForWebPage(false, webPage3, false);
                this.foundWebPage = null;
            }
        }
    }

    private void forwardMessages(ArrayList<MessageObject> arrayList, boolean fromMyName, boolean notify, int scheduleDate) {
        if (arrayList == null || arrayList.isEmpty()) {
            return;
        }
        if (!fromMyName) {
            AlertsCreator.showSendMediaAlert(getSendMessagesHelper().sendMessage(arrayList, this.dialog_id, notify, scheduleDate), this);
            return;
        }
        for (MessageObject object : arrayList) {
            getSendMessagesHelper().processForwardFromMyName(object, this.dialog_id);
        }
    }

    private void checkBotKeyboard() {
        MessageObject messageObject;
        if (this.chatActivityEnterView == null || (messageObject = this.botButtons) == null || this.userBlocked) {
            return;
        }
        if (messageObject.messageOwner.reply_markup instanceof TLRPC.TL_replyKeyboardForceReply) {
            SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
            if (preferences.getInt("answered_" + this.dialog_id, 0) != this.botButtons.getId()) {
                if (this.replyingMessageObject == null || this.chatActivityEnterView.getFieldText() == null) {
                    MessageObject messageObject2 = this.botButtons;
                    this.botReplyButtons = messageObject2;
                    this.chatActivityEnterView.setButtons(messageObject2);
                    showFieldPanelForReply(this.botButtons);
                    return;
                }
                return;
            }
            return;
        }
        MessageObject messageObject3 = this.replyingMessageObject;
        if (messageObject3 != null && this.botReplyButtons == messageObject3) {
            this.botReplyButtons = null;
            hideFieldPanel(true);
        }
        this.chatActivityEnterView.setButtons(this.botButtons);
    }

    public void hideFieldPanel(boolean animated) {
        showFieldPanel(false, null, null, null, null, true, 0, false, animated);
    }

    public void hideFieldPanel(boolean notify, int scheduleDate, boolean animated) {
        showFieldPanel(false, null, null, null, null, notify, scheduleDate, false, animated);
    }

    public void showFieldPanelForWebPage(boolean show, TLRPC.WebPage webPage, boolean cancel) {
        showFieldPanel(show, null, null, null, webPage, true, 0, cancel, true);
    }

    public void showFieldPanelForForward(boolean show, ArrayList<MessageObject> messageObjectsToForward) {
        showFieldPanel(show, null, null, messageObjectsToForward, null, true, 0, false, true);
    }

    public void showFieldPanelForReply(MessageObject messageObjectToReply) {
        showFieldPanel(true, messageObjectToReply, null, null, null, true, 0, false, true);
    }

    public void showFieldPanelForEdit(boolean show, MessageObject messageObjectToEdit) {
        showFieldPanel(show, null, messageObjectToEdit, null, null, true, 0, false, true);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v0 */
    /* JADX WARN: Type inference failed for: r3v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r3v2 */
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
    public void showFieldPanel(boolean show, MessageObject messageObjectToReply, MessageObject messageObjectToEdit, ArrayList<MessageObject> messageObjectsToForward, TLRPC.WebPage webPage, boolean notify, int scheduleDate, boolean cancel, boolean animated) {
        ?? r3;
        ArrayList<MessageObject> messageObjectsToForward2;
        TLRPC.Chat chat;
        TLRPC.User user;
        MessageObject object;
        int uid;
        TLRPC.Chat chat2;
        String name;
        MessageObject thumbMediaMessageObject;
        MessageObject object2;
        int size;
        TLRPC.PhotoSize photoSize;
        MessageObject messageObjectToReply2 = messageObjectToReply;
        if (this.chatActivityEnterView == null) {
            return;
        }
        if (show) {
            if (messageObjectToReply2 == null && messageObjectsToForward == null && messageObjectToEdit == null && webPage == null) {
                return;
            }
            HintView hintView = this.noSoundHintView;
            if (hintView != null) {
                hintView.hide();
            }
            HintView hintView2 = this.forwardHintView;
            if (hintView2 != null) {
                hintView2.hide();
            }
            HintView hintView3 = this.slowModeHint;
            if (hintView3 != null) {
                hintView3.hide();
            }
            if (this.searchItem != null && this.actionBar.isSearchFieldVisible()) {
                this.actionBar.closeSearchField(false);
                this.chatActivityEnterView.setFieldFocused();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$BhNSC0LGTOoyfkKI9BxMVP0NBps
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$showFieldPanel$63$ChatActivity();
                    }
                }, 100L);
            }
            boolean openKeyboard = false;
            if (messageObjectToReply2 != null && messageObjectToReply.getDialogId() != this.dialog_id) {
                messageObjectsToForward2 = new ArrayList<>();
                messageObjectsToForward2.add(messageObjectToReply2);
                openKeyboard = true;
                messageObjectToReply2 = null;
            } else {
                messageObjectsToForward2 = messageObjectsToForward;
            }
            if (messageObjectToEdit != null) {
                this.forwardingMessages = null;
                this.replyingMessageObject = null;
                this.editingMessageObject = messageObjectToEdit;
                this.chatActivityEnterView.setReplyingMessageObject(null);
                this.chatActivityEnterView.setEditingMessageObject(messageObjectToEdit, !messageObjectToEdit.isMediaEmpty());
                if (this.foundWebPage != null) {
                    return;
                }
                this.chatActivityEnterView.setForceShowSendButton(false, false);
                this.replyIconImageView.setImageResource(R.drawable.group_edit);
                this.replyIconImageView.setContentDescription(LocaleController.getString("AccDescrEditing", R.string.AccDescrEditing));
                this.replyCloseImageView.setContentDescription(LocaleController.getString("AccDescrCancelEdit", R.string.AccDescrCancelEdit));
                if (messageObjectToEdit.isMediaEmpty()) {
                    this.replyNameTextView.setText(LocaleController.getString("EditMessage", R.string.EditMessage));
                } else {
                    this.replyNameTextView.setText(LocaleController.getString("EditCaption", R.string.EditCaption));
                }
                if (messageObjectToEdit.canEditMedia()) {
                    this.replyObjectTextView.setText(LocaleController.getString("EditMessageMedia", R.string.EditMessageMedia));
                } else if (messageObjectToEdit.messageText != null) {
                    String mess = messageObjectToEdit.messageText.toString();
                    if (mess.length() > 150) {
                        mess = mess.substring(0, 150);
                    }
                    String mess2 = mess.replace('\n', ' ');
                    SimpleTextView simpleTextView = this.replyObjectTextView;
                    simpleTextView.setText(Emoji.replaceEmoji(mess2, simpleTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(14.0f), false));
                }
            } else if (messageObjectToReply2 != null) {
                this.forwardingMessages = null;
                this.editingMessageObject = null;
                this.replyingMessageObject = messageObjectToReply2;
                this.chatActivityEnterView.setReplyingMessageObject(messageObjectToReply2);
                this.chatActivityEnterView.setEditingMessageObject(null, false);
                if (this.foundWebPage != null) {
                    return;
                }
                this.chatActivityEnterView.setForceShowSendButton(false, false);
                if (messageObjectToReply2.isFromUser()) {
                    TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(messageObjectToReply2.messageOwner.from_id));
                    if (user2 == null) {
                        return;
                    } else {
                        name = UserObject.getName(user2);
                    }
                } else {
                    if (ChatObject.isChannel(this.currentChat) && this.currentChat.megagroup && messageObjectToReply2.isForwardedChannelPost()) {
                        chat2 = getMessagesController().getChat(Integer.valueOf(messageObjectToReply2.messageOwner.fwd_from.channel_id));
                    } else {
                        chat2 = getMessagesController().getChat(Integer.valueOf(messageObjectToReply2.messageOwner.to_id.channel_id));
                    }
                    if (chat2 == null) {
                        return;
                    } else {
                        name = chat2.title;
                    }
                }
                this.replyIconImageView.setImageResource(R.drawable.msg_panel_reply);
                this.replyNameTextView.setText(name);
                this.replyIconImageView.setContentDescription(LocaleController.getString("AccDescrReplying", R.string.AccDescrReplying));
                this.replyCloseImageView.setContentDescription(LocaleController.getString("AccDescrCancelReply", R.string.AccDescrCancelReply));
                if (messageObjectToReply2.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                    this.replyObjectTextView.setText(Emoji.replaceEmoji(messageObjectToReply2.messageOwner.media.game.title, this.replyObjectTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(14.0f), false));
                } else if (messageObjectToReply2.messageText != null) {
                    String mess3 = messageObjectToReply2.messageText.toString();
                    if (mess3.length() > 150) {
                        mess3 = mess3.substring(0, 150);
                    }
                    String mess4 = mess3.replace('\n', ' ');
                    SimpleTextView simpleTextView2 = this.replyObjectTextView;
                    simpleTextView2.setText(Emoji.replaceEmoji(mess4, simpleTextView2.getPaint().getFontMetricsInt(), AndroidUtilities.dp(14.0f), false));
                }
            } else if (messageObjectsToForward2 != null) {
                if (messageObjectsToForward2.isEmpty()) {
                    return;
                }
                this.replyingMessageObject = null;
                this.editingMessageObject = null;
                this.chatActivityEnterView.setReplyingMessageObject(null);
                this.chatActivityEnterView.setEditingMessageObject(null, false);
                this.forwardingMessages = messageObjectsToForward2;
                if (this.foundWebPage != null) {
                    return;
                }
                this.chatActivityEnterView.setForceShowSendButton(true, false);
                ArrayList<Integer> uids = new ArrayList<>();
                this.replyIconImageView.setImageResource(R.drawable.msg_panel_forward);
                this.replyIconImageView.setContentDescription(LocaleController.getString("AccDescrForwarding", R.string.AccDescrForwarding));
                this.replyCloseImageView.setContentDescription(LocaleController.getString("AccDescrCancelForward", R.string.AccDescrCancelForward));
                MessageObject object3 = messageObjectsToForward2.get(0);
                if (object3.isFromUser()) {
                    uids.add(Integer.valueOf(object3.messageOwner.from_id));
                } else {
                    TLRPC.Chat chat3 = getMessagesController().getChat(Integer.valueOf(object3.messageOwner.to_id.channel_id));
                    if (ChatObject.isChannel(chat3) && chat3.megagroup && object3.isForwardedChannelPost()) {
                        uids.add(Integer.valueOf(-object3.messageOwner.fwd_from.channel_id));
                    } else {
                        uids.add(Integer.valueOf(-object3.messageOwner.to_id.channel_id));
                    }
                }
                int type = object3.isAnimatedEmoji() ? 0 : object3.type;
                for (int a = 1; a < messageObjectsToForward2.size(); a++) {
                    object3 = messageObjectsToForward2.get(a);
                    if (object3.isFromUser()) {
                        uid = object3.messageOwner.from_id;
                    } else {
                        TLRPC.Chat chat4 = getMessagesController().getChat(Integer.valueOf(object3.messageOwner.to_id.channel_id));
                        if (ChatObject.isChannel(chat4) && chat4.megagroup && object3.isForwardedChannelPost()) {
                            uid = -object3.messageOwner.fwd_from.channel_id;
                        } else {
                            uid = -object3.messageOwner.to_id.channel_id;
                        }
                    }
                    if (!uids.contains(Integer.valueOf(uid))) {
                        uids.add(Integer.valueOf(uid));
                    }
                    if (messageObjectsToForward2.get(a).type != type) {
                        type = -1;
                    }
                }
                StringBuilder userNames = new StringBuilder();
                int a2 = 0;
                while (true) {
                    if (a2 >= uids.size()) {
                        break;
                    }
                    Integer uid2 = uids.get(a2);
                    if (uid2.intValue() > 0) {
                        TLRPC.User user3 = getMessagesController().getUser(uid2);
                        chat = null;
                        user = user3;
                    } else {
                        chat = getMessagesController().getChat(Integer.valueOf(-uid2.intValue()));
                        user = null;
                    }
                    if (user == null && chat == null) {
                        object = object3;
                    } else if (uids.size() == 1) {
                        if (user != null) {
                            userNames.append(UserObject.getName(user));
                            object = object3;
                        } else {
                            userNames.append(chat.title);
                            object = object3;
                        }
                    } else {
                        object = object3;
                        if (uids.size() == 2 || userNames.length() == 0) {
                            if (userNames.length() > 0) {
                                userNames.append(", ");
                            }
                            if (user != null) {
                                if (!TextUtils.isEmpty(user.first_name)) {
                                    userNames.append(user.first_name);
                                } else if (!TextUtils.isEmpty(user.last_name)) {
                                    userNames.append(user.last_name);
                                } else {
                                    userNames.append(" ");
                                }
                            } else {
                                userNames.append(chat.title);
                            }
                        } else {
                            userNames.append(" ");
                            userNames.append(LocaleController.formatPluralString("AndOther", uids.size() - 1));
                            break;
                        }
                    }
                    a2++;
                    object3 = object;
                }
                this.replyNameTextView.setText(userNames);
                if (type == -1 || type == 0 || type == 10 || type == 11) {
                    if (messageObjectsToForward2.size() == 1 && messageObjectsToForward2.get(0).messageText != null) {
                        MessageObject messageObject = messageObjectsToForward2.get(0);
                        if (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGame) {
                            this.replyObjectTextView.setText(Emoji.replaceEmoji(messageObject.messageOwner.media.game.title, this.replyObjectTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(14.0f), false));
                        } else {
                            String mess5 = messageObject.messageText.toString();
                            if (mess5.length() > 150) {
                                mess5 = mess5.substring(0, 150);
                            }
                            String mess6 = mess5.replace('\n', ' ');
                            SimpleTextView simpleTextView3 = this.replyObjectTextView;
                            simpleTextView3.setText(Emoji.replaceEmoji(mess6, simpleTextView3.getPaint().getFontMetricsInt(), AndroidUtilities.dp(14.0f), false));
                        }
                    } else {
                        this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedMessageCount", messageObjectsToForward2.size()));
                    }
                } else if (type == 1) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedPhoto", messageObjectsToForward2.size()));
                    if (messageObjectsToForward2.size() == 1) {
                        messageObjectToReply2 = messageObjectsToForward2.get(0);
                    }
                } else if (type == 4) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedLocation", messageObjectsToForward2.size()));
                } else if (type == 3) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedVideo", messageObjectsToForward2.size()));
                    if (messageObjectsToForward2.size() == 1) {
                        messageObjectToReply2 = messageObjectsToForward2.get(0);
                    }
                } else if (type == 12) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedContact", messageObjectsToForward2.size()));
                } else if (type == 2) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedAudio", messageObjectsToForward2.size()));
                } else if (type == 5) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedRound", messageObjectsToForward2.size()));
                } else if (type == 14) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedMusic", messageObjectsToForward2.size()));
                } else if (type == 13 || type == 15) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedSticker", messageObjectsToForward2.size()));
                } else if (type == 17) {
                    this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedPoll", messageObjectsToForward2.size()));
                } else if (type == 8 || type == 9) {
                    if (messageObjectsToForward2.size() == 1) {
                        if (type == 8) {
                            this.replyObjectTextView.setText(LocaleController.getString("AttachGif", R.string.AttachGif));
                        } else {
                            String name2 = FileLoader.getDocumentFileName(messageObjectsToForward2.get(0).getDocument());
                            if (name2.length() != 0) {
                                this.replyObjectTextView.setText(name2);
                            }
                            messageObjectToReply2 = messageObjectsToForward2.get(0);
                        }
                    } else {
                        this.replyObjectTextView.setText(LocaleController.formatPluralString("ForwardedFile", messageObjectsToForward2.size()));
                    }
                }
            } else {
                this.replyIconImageView.setImageResource(R.drawable.msg_link);
                if (webPage instanceof TLRPC.TL_webPagePending) {
                    this.replyNameTextView.setText(LocaleController.getString("GettingLinkInfo", R.string.GettingLinkInfo));
                    this.replyObjectTextView.setText(this.pendingLinkSearchString);
                } else {
                    if (webPage.site_name != null) {
                        this.replyNameTextView.setText(webPage.site_name);
                    } else if (webPage.title != null) {
                        this.replyNameTextView.setText(webPage.title);
                    } else {
                        this.replyNameTextView.setText(LocaleController.getString("LinkPreview", R.string.LinkPreview));
                    }
                    if (webPage.title != null) {
                        this.replyObjectTextView.setText(webPage.title);
                    } else if (webPage.description != null) {
                        this.replyObjectTextView.setText(webPage.description);
                    } else if (webPage.author != null) {
                        this.replyObjectTextView.setText(webPage.author);
                    } else {
                        this.replyObjectTextView.setText(webPage.display_url);
                    }
                    this.chatActivityEnterView.setWebPage(webPage, true);
                }
            }
            if (messageObjectToReply2 != null) {
                thumbMediaMessageObject = messageObjectToReply2;
            } else if (messageObjectToEdit != null) {
                thumbMediaMessageObject = messageObjectToEdit;
            } else {
                thumbMediaMessageObject = null;
            }
            FrameLayout.LayoutParams layoutParams1 = (FrameLayout.LayoutParams) this.replyNameTextView.getLayoutParams();
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.replyObjectTextView.getLayoutParams();
            int cacheType = 1;
            int size2 = 0;
            TLRPC.PhotoSize photoSize2 = null;
            TLRPC.PhotoSize thumbPhotoSize = null;
            TLObject photoSizeObject = null;
            if (thumbMediaMessageObject != null) {
                photoSize2 = FileLoader.getClosestPhotoSizeWithSize(thumbMediaMessageObject.photoThumbs2, 320);
                thumbPhotoSize = FileLoader.getClosestPhotoSizeWithSize(thumbMediaMessageObject.photoThumbs2, AndroidUtilities.dp(40.0f));
                photoSizeObject = thumbMediaMessageObject.photoThumbsObject2;
                if (photoSize2 == null) {
                    if (thumbMediaMessageObject.mediaExists) {
                        if (thumbMediaMessageObject.type != 1) {
                            size = 0;
                            photoSize = FileLoader.getClosestPhotoSizeWithSize(thumbMediaMessageObject.photoThumbs, AndroidUtilities.getPhotoSize());
                        } else {
                            TLRPC.Document documentAttach = thumbMediaMessageObject.getDocument();
                            int iSide = AndroidUtilities.getPhotoSize();
                            if (documentAttach == null) {
                                size = 0;
                            } else {
                                if (MessageObject.isVoiceDocument(documentAttach) || MessageObject.isMusicDocument(documentAttach)) {
                                    size = 0;
                                } else {
                                    if (documentAttach.mime_type != null) {
                                        size = 0;
                                        if (!documentAttach.mime_type.toLowerCase().startsWith(PREFIX_VIDEO)) {
                                        }
                                    } else {
                                        size = 0;
                                    }
                                    if (!MessageObject.isGifDocument(documentAttach)) {
                                        if ((documentAttach.mime_type != null && documentAttach.mime_type.toLowerCase().startsWith("image/")) || MessageObject.isDocumentHasThumb(documentAttach)) {
                                            iSide = 80000;
                                        }
                                    }
                                }
                                iSide = AndroidUtilities.getPhotoSize();
                            }
                            photoSize = FileLoader.getClosestPhotoSizeWithSize(thumbMediaMessageObject.photoThumbs, iSide);
                        }
                        if (photoSize == null) {
                            size2 = size;
                        } else {
                            size2 = photoSize.size;
                        }
                        photoSize2 = photoSize;
                        cacheType = 0;
                    } else {
                        photoSize2 = FileLoader.getClosestPhotoSizeWithSize(thumbMediaMessageObject.photoThumbs, 320);
                        cacheType = 1;
                        size2 = 0;
                    }
                    thumbPhotoSize = FileLoader.getClosestPhotoSizeWithSize(thumbMediaMessageObject.photoThumbs, AndroidUtilities.dp(40.0f));
                    photoSizeObject = thumbMediaMessageObject.photoThumbsObject;
                }
            }
            if (photoSize2 == thumbPhotoSize) {
                thumbPhotoSize = null;
            }
            if (photoSize2 == null || (photoSize2 instanceof TLRPC.TL_photoSizeEmpty) || (photoSize2.location instanceof TLRPC.TL_fileLocationUnavailable) || thumbMediaMessageObject.isAnyKindOfSticker() || (thumbMediaMessageObject != null && thumbMediaMessageObject.isSecretMedia())) {
                this.replyImageView.setImageBitmap(null);
                this.replyImageLocation = null;
                this.replyImageLocationObject = null;
                boolean isLiveMsg = false;
                if (messageObjectsToForward2 != null && (object2 = messageObjectsToForward2.get(0)) != null && object2.type == 207) {
                    isLiveMsg = true;
                }
                if (!isLiveMsg) {
                    this.replyImageView.setVisibility(4);
                    int iDp = AndroidUtilities.dp(52.0f);
                    layoutParams2.leftMargin = iDp;
                    layoutParams1.leftMargin = iDp;
                }
            } else {
                if (thumbMediaMessageObject != null && thumbMediaMessageObject.isRoundVideo()) {
                    this.replyImageView.setRoundRadius(AndroidUtilities.dp(17.0f));
                } else {
                    this.replyImageView.setRoundRadius(0);
                }
                this.replyImageSize = size2;
                this.replyImageCacheType = cacheType;
                this.replyImageLocation = photoSize2;
                this.replyImageThumbLocation = thumbPhotoSize;
                this.replyImageLocationObject = photoSizeObject;
                this.replyImageView.setImage(ImageLocation.getForObject(photoSize2, photoSizeObject), "50_50", ImageLocation.getForObject(thumbPhotoSize, photoSizeObject), "50_50_b", null, size2, cacheType, thumbMediaMessageObject);
                this.replyImageView.setVisibility(0);
                int iDp2 = AndroidUtilities.dp(96.0f);
                layoutParams2.leftMargin = iDp2;
                layoutParams1.leftMargin = iDp2;
            }
            this.replyNameTextView.setLayoutParams(layoutParams1);
            this.replyObjectTextView.setLayoutParams(layoutParams2);
            this.chatActivityEnterView.showTopView(true, openKeyboard);
            return;
        }
        if (this.replyingMessageObject == null && this.forwardingMessages == null && this.foundWebPage == null && this.editingMessageObject == null) {
            return;
        }
        MessageObject messageObject2 = this.replyingMessageObject;
        if (messageObject2 != null && (messageObject2.messageOwner.reply_markup instanceof TLRPC.TL_replyKeyboardForceReply)) {
            SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
            preferences.edit().putInt("answered_" + this.dialog_id, this.replyingMessageObject.getId()).commit();
        }
        if (this.foundWebPage != null) {
            this.foundWebPage = null;
            this.chatActivityEnterView.setWebPage(null, !cancel);
            if (webPage != null && (this.replyingMessageObject != null || this.forwardingMessages != null || this.editingMessageObject != null)) {
                showFieldPanel(true, this.replyingMessageObject, this.editingMessageObject, this.forwardingMessages, null, notify, scheduleDate, false, true);
                return;
            }
        }
        if (this.forwardingMessages != null) {
            ArrayList<MessageObject> messagesToForward = this.forwardingMessages;
            this.forwardingMessages = null;
            r3 = 0;
            forwardMessages(messagesToForward, false, notify, scheduleDate != 0 ? scheduleDate + 1 : 0);
        } else {
            r3 = 0;
        }
        this.chatActivityEnterView.setForceShowSendButton(r3, r3);
        this.chatActivityEnterView.hideTopView(animated);
        this.chatActivityEnterView.setReplyingMessageObject(null);
        this.chatActivityEnterView.setEditingMessageObject(null, r3);
        this.topViewWasVisible = r3;
        this.replyingMessageObject = null;
        this.editingMessageObject = null;
        this.replyImageLocation = null;
        this.replyImageLocationObject = null;
    }

    public /* synthetic */ void lambda$showFieldPanel$63$ChatActivity() {
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.openKeyboard();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void moveScrollToLastMessage() {
        if (this.chatListView != null && !this.messages.isEmpty()) {
            this.chatLayoutManager.scrollToPositionWithOffset(0, 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean sendSecretMessageRead(MessageObject messageObject) {
        if (messageObject == null || messageObject.isOut() || !messageObject.isSecretMedia() || messageObject.messageOwner.destroyTime != 0 || messageObject.messageOwner.ttl <= 0) {
            return false;
        }
        if (this.currentEncryptedChat != null) {
            getMessagesController().markMessageAsRead(this.dialog_id, messageObject.messageOwner.random_id, messageObject.messageOwner.ttl);
        } else {
            getMessagesController().markMessageAsRead(messageObject.getId(), ChatObject.isChannel(this.currentChat) ? this.currentChat.id : 0, null, messageObject.messageOwner.ttl, 0L);
        }
        messageObject.messageOwner.destroyTime = messageObject.messageOwner.ttl + getConnectionsManager().getCurrentTime();
        return true;
    }

    private void clearChatData() {
        this.messages.clear();
        this.messagesByDays.clear();
        this.waitingForLoad.clear();
        this.groupedMessagesMap.clear();
        listViewShowEmptyView(true, this.chatAdapter.botInfoRow == -1);
        for (int a = 0; a < 2; a++) {
            this.messagesDict[a].clear();
            if (this.currentEncryptedChat == null) {
                this.maxMessageId[a] = Integer.MAX_VALUE;
                this.minMessageId[a] = Integer.MIN_VALUE;
            } else {
                this.maxMessageId[a] = Integer.MIN_VALUE;
                this.minMessageId[a] = Integer.MAX_VALUE;
            }
            this.maxDate[a] = Integer.MIN_VALUE;
            this.minDate[a] = 0;
            this.endReached[a] = false;
            this.cacheEndReached[a] = false;
            this.forwardEndReached[a] = true;
        }
        this.first = true;
        this.firstLoading = true;
        this.loading = true;
        this.loadingForward = false;
        this.waitingForReplyMessageLoad = false;
        this.startLoadFromMessageId = 0;
        this.showScrollToMessageError = false;
        this.last_message_id = 0;
        this.unreadMessageObject = null;
        this.createUnreadMessageAfterId = 0;
        this.createUnreadMessageAfterIdLoading = false;
        this.needSelectFromMessageId = false;
        this.chatAdapter.notifyDataSetChanged();
    }

    private void scrollToLastMessage(boolean pagedown) {
        if (this.forwardEndReached[0] && this.first_unread_id == 0 && this.startLoadFromMessageId == 0) {
            if (pagedown && this.chatLayoutManager.findFirstCompletelyVisibleItemPosition() == 0) {
                showPagedownButton(false, true);
                removeSelectedMessageHighlight();
                updateVisibleRows();
                return;
            }
            this.chatLayoutManager.scrollToPositionWithOffset(0, 0);
            return;
        }
        clearChatData();
        this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
        MessagesController messagesController = getMessagesController();
        long j = this.dialog_id;
        int i = this.classGuid;
        boolean zIsChannel = ChatObject.isChannel(this.currentChat);
        boolean z = this.inScheduleMode;
        int i2 = this.lastLoadIndex;
        this.lastLoadIndex = i2 + 1;
        messagesController.loadMessages(j, 30, 0, 0, true, 0, i, 0, 0, zIsChannel, z, i2);
    }

    public void updateTextureViewPosition(boolean needScroll) {
        MessageObject messageObject;
        if (this.fragmentView == null || this.paused) {
            return;
        }
        boolean foundTextureViewMessage = false;
        int count = this.chatListView.getChildCount();
        int a = 0;
        while (true) {
            if (a >= count) {
                break;
            }
            View view = this.chatListView.getChildAt(a);
            if (view instanceof ChatMessageCell) {
                ChatMessageCell messageCell = (ChatMessageCell) view;
                MessageObject messageObject2 = messageCell.getMessageObject();
                if (this.videoPlayerContainer != null && ((messageObject2.isRoundVideo() || messageObject2.isVideo()) && MediaController.getInstance().isPlayingMessage(messageObject2))) {
                    ImageReceiver imageReceiver = messageCell.getPhotoImage();
                    this.videoPlayerContainer.setTranslationX(imageReceiver.getImageX() + messageCell.getX());
                    this.videoPlayerContainer.setTranslationY((((this.fragmentView.getPaddingTop() + messageCell.getTop()) + imageReceiver.getImageY()) - this.chatListViewClipTop) + this.chatListView.getTranslationY() + (this.inPreviewMode ? AndroidUtilities.statusBarHeight : 0));
                    FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.videoPlayerContainer.getLayoutParams();
                    if (messageObject2.isRoundVideo()) {
                        this.videoPlayerContainer.setTag(R.attr.parent_tag, null);
                        if (layoutParams.width != AndroidUtilities.roundMessageSize || layoutParams.height != AndroidUtilities.roundMessageSize) {
                            int i = AndroidUtilities.roundMessageSize;
                            layoutParams.height = i;
                            layoutParams.width = i;
                            this.aspectRatioFrameLayout.setResizeMode(0);
                            this.videoPlayerContainer.setLayoutParams(layoutParams);
                        }
                    } else {
                        this.videoPlayerContainer.setTag(R.attr.parent_tag, 1);
                        if (layoutParams.width != imageReceiver.getImageWidth() || layoutParams.height != imageReceiver.getImageHeight()) {
                            this.aspectRatioFrameLayout.setResizeMode(3);
                            layoutParams.width = imageReceiver.getImageWidth();
                            layoutParams.height = imageReceiver.getImageHeight();
                            this.videoPlayerContainer.setLayoutParams(layoutParams);
                        }
                    }
                    this.fragmentView.invalidate();
                    this.videoPlayerContainer.invalidate();
                    foundTextureViewMessage = true;
                }
            }
            a++;
        }
        if (needScroll && this.videoPlayerContainer != null && (messageObject = MediaController.getInstance().getPlayingMessageObject()) != null && messageObject.eventId == 0) {
            if (!foundTextureViewMessage) {
                if (this.checkTextureViewPosition && messageObject.isVideo()) {
                    MediaController.getInstance().cleanupPlayer(true, true);
                    return;
                }
                this.videoPlayerContainer.setTranslationY((-AndroidUtilities.roundMessageSize) - 100);
                this.fragmentView.invalidate();
                if (messageObject != null) {
                    if (messageObject.isRoundVideo() || messageObject.isVideo()) {
                        if (this.checkTextureViewPosition || PipRoundVideoView.getInstance() != null) {
                            MediaController.getInstance().setCurrentVideoVisible(false);
                            return;
                        } else {
                            scrollToMessageId(messageObject.getId(), 0, false, 0, true);
                            return;
                        }
                    }
                    return;
                }
                return;
            }
            MediaController.getInstance().setCurrentVideoVisible(true);
            if (messageObject.isRoundVideo() || this.scrollToVideo) {
                scrollToMessageId(messageObject.getId(), 0, false, 0, true);
            } else {
                this.chatListView.invalidate();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0329  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x017f  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x019f  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x01cf  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void updateMessagesVisiblePart(boolean r45) {
        /*
            Method dump skipped, instruction units count: 1129
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.updateMessagesVisiblePart(boolean):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void inlineUpdate1() {
        int i = this.prevSetUnreadCount;
        int i2 = this.newUnreadMessageCount;
        if (i != i2) {
            this.prevSetUnreadCount = i2;
            this.pagedownButtonCounter.setText(String.format("%d", Integer.valueOf(i2)));
        }
        if (this.newUnreadMessageCount <= 0) {
            if (this.pagedownButtonCounter.getVisibility() != 4) {
                this.pagedownButtonCounter.setVisibility(4);
            }
        } else if (this.pagedownButtonCounter.getVisibility() != 0) {
            this.pagedownButtonCounter.setVisibility(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void inlineUpdate2() {
        int i = this.prevSetUnreadCount;
        int i2 = this.newUnreadMessageCount;
        if (i != i2) {
            this.prevSetUnreadCount = i2;
            this.pagedownButtonCounter.setText(String.format("%d", Integer.valueOf(i2)));
        }
        if (this.pagedownButtonCounter.getVisibility() != 4) {
            this.pagedownButtonCounter.setVisibility(4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void toggleMute(boolean instant) {
        boolean muted = getMessagesController().isDialogMuted(this.dialog_id);
        if (!muted) {
            if (instant) {
                SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
                SharedPreferences.Editor editor = preferences.edit();
                editor.putInt("notify2_" + this.dialog_id, 2);
                getMessagesStorage().setDialogFlags(this.dialog_id, 1L);
                editor.commit();
                TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(this.dialog_id);
                if (dialog != null) {
                    dialog.notify_settings = new TLRPC.TL_peerNotifySettings();
                    dialog.notify_settings.mute_until = Integer.MAX_VALUE;
                }
                getNotificationsController().updateServerNotificationsSettings(this.dialog_id);
                getNotificationsController().removeNotificationsForDialog(this.dialog_id);
                return;
            }
            if (isSysNotifyMessage().booleanValue()) {
                NotificationsController.getInstance(UserConfig.selectedAccount).setDialogNotificationsSettings(this.dialog_id, 3);
                return;
            } else {
                showDialog(AlertsCreator.createMuteAlert(getParentActivity(), this.dialog_id));
                return;
            }
        }
        SharedPreferences preferences2 = MessagesController.getNotificationsSettings(this.currentAccount);
        SharedPreferences.Editor editor2 = preferences2.edit();
        editor2.putInt("notify2_" + this.dialog_id, 0);
        getMessagesStorage().setDialogFlags(this.dialog_id, 0L);
        editor2.commit();
        TLRPC.Dialog dialog2 = getMessagesController().dialogs_dict.get(this.dialog_id);
        if (dialog2 != null) {
            dialog2.notify_settings = new TLRPC.TL_peerNotifySettings();
        }
        getNotificationsController().updateServerNotificationsSettings(this.dialog_id);
    }

    private int getScrollOffsetForMessage(MessageObject object) {
        float itemHeight;
        int offset = Integer.MAX_VALUE;
        MessageObject.GroupedMessages groupedMessages = getValidGroupedMessage(object);
        if (groupedMessages != null) {
            MessageObject.GroupedMessagePosition currentPosition = groupedMessages.positions.get(object);
            float maxH = Math.max(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.5f;
            if (currentPosition.siblingHeights != null) {
                itemHeight = currentPosition.siblingHeights[0];
            } else {
                itemHeight = currentPosition.ph;
            }
            float totalHeight = 0.0f;
            float moveDiff = 0.0f;
            SparseBooleanArray array = new SparseBooleanArray();
            for (int a = 0; a < groupedMessages.posArray.size(); a++) {
                MessageObject.GroupedMessagePosition pos = groupedMessages.posArray.get(a);
                if (array.indexOfKey(pos.minY) < 0 && pos.siblingHeights == null) {
                    array.put(pos.minY, true);
                    if (pos.minY < currentPosition.minY) {
                        moveDiff -= pos.ph;
                    } else if (pos.minY > currentPosition.minY) {
                        moveDiff += pos.ph;
                    }
                    totalHeight += pos.ph;
                }
            }
            if (Math.abs(totalHeight - itemHeight) < 0.02f) {
                offset = ((((int) (this.chatListView.getMeasuredHeight() - (totalHeight * maxH))) / 2) - this.chatListView.getPaddingTop()) - AndroidUtilities.dp(7.0f);
            } else {
                offset = ((((int) (this.chatListView.getMeasuredHeight() - ((itemHeight + moveDiff) * maxH))) / 2) - this.chatListView.getPaddingTop()) - AndroidUtilities.dp(7.0f);
            }
        }
        return Math.max(0, offset == Integer.MAX_VALUE ? (this.chatListView.getMeasuredHeight() - object.getApproximateHeight()) / 2 : offset);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startMessageUnselect() {
        Runnable runnable = this.unselectRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
        }
        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$0maglw2N_VwxEfeDoa9iAJ2JCoc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startMessageUnselect$64$ChatActivity();
            }
        };
        this.unselectRunnable = runnable2;
        AndroidUtilities.runOnUIThread(runnable2, 1000L);
    }

    public /* synthetic */ void lambda$startMessageUnselect$64$ChatActivity() {
        this.highlightMessageId = Integer.MAX_VALUE;
        updateVisibleRows();
        this.unselectRunnable = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeSelectedMessageHighlight() {
        Runnable runnable = this.unselectRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.unselectRunnable = null;
        }
        this.highlightMessageId = Integer.MAX_VALUE;
    }

    public void scrollToMessageId(int id, int fromMessageId, boolean select, int loadIndex, boolean smooth) {
        this.wasManualScroll = true;
        MessageObject object = this.messagesDict[loadIndex].get(id);
        boolean query = false;
        if (object != null) {
            int index = this.messages.indexOf(object);
            if (index != -1) {
                removeSelectedMessageHighlight();
                if (select) {
                    this.highlightMessageId = id;
                }
                int yOffset = getScrollOffsetForMessage(object);
                if (smooth) {
                    ArrayList<MessageObject> arrayList = this.messages;
                    if (arrayList.get(arrayList.size() - 1) == object) {
                        this.chatListView.smoothScrollToPosition(this.chatAdapter.getItemCount() - 1);
                    } else {
                        this.chatListView.smoothScrollToPosition(this.chatAdapter.messagesStartRow + this.messages.indexOf(object));
                    }
                } else {
                    ArrayList<MessageObject> arrayList2 = this.messages;
                    if (arrayList2.get(arrayList2.size() - 1) == object) {
                        this.chatLayoutManager.scrollToPositionWithOffset(this.chatAdapter.getItemCount() - 1, yOffset, false);
                    } else {
                        this.chatLayoutManager.scrollToPositionWithOffset(this.chatAdapter.messagesStartRow + this.messages.indexOf(object), yOffset, false);
                    }
                }
                updateVisibleRows();
                boolean found = false;
                int count = this.chatListView.getChildCount();
                int a = 0;
                while (true) {
                    if (a >= count) {
                        break;
                    }
                    View view = this.chatListView.getChildAt(a);
                    if (view instanceof ChatMessageCell) {
                        ChatMessageCell cell = (ChatMessageCell) view;
                        MessageObject messageObject = cell.getMessageObject();
                        if (messageObject == null || messageObject.getId() != object.getId()) {
                            a++;
                        } else {
                            found = true;
                            view.sendAccessibilityEvent(8);
                            break;
                        }
                    } else {
                        if (view instanceof ChatActionCell) {
                            ChatActionCell cell2 = (ChatActionCell) view;
                            MessageObject messageObject2 = cell2.getMessageObject();
                            if (messageObject2 != null && messageObject2.getId() == object.getId()) {
                                found = true;
                                view.sendAccessibilityEvent(8);
                                break;
                            }
                        } else {
                            continue;
                        }
                        a++;
                    }
                }
                if (!found) {
                    showPagedownButton(true, true);
                }
            } else {
                query = true;
            }
        } else {
            query = true;
        }
        if (query) {
            if (this.currentEncryptedChat != null && !getMessagesStorage().checkMessageId(this.dialog_id, this.startLoadFromMessageId)) {
                return;
            }
            this.waitingForLoad.clear();
            this.waitingForReplyMessageLoad = true;
            removeSelectedMessageHighlight();
            this.scrollToMessagePosition = -10000;
            this.startLoadFromMessageId = id;
            this.showScrollToMessageError = true;
            if (id == this.createUnreadMessageAfterId) {
                this.createUnreadMessageAfterIdLoading = true;
            }
            this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
            MessagesController messagesController = getMessagesController();
            long j = loadIndex == 0 ? this.dialog_id : this.mergeDialogId;
            int i = AndroidUtilities.isTablet() ? 30 : 20;
            int i2 = this.startLoadFromMessageId;
            int i3 = this.classGuid;
            boolean zIsChannel = ChatObject.isChannel(this.currentChat);
            boolean z = this.inScheduleMode;
            int i4 = this.lastLoadIndex;
            this.lastLoadIndex = i4 + 1;
            messagesController.loadMessages(j, i, i2, 0, true, 0, i3, 3, 0, zIsChannel, z, i4);
        } else {
            View child = this.chatListView.getChildAt(0);
            if (child != null && child.getTop() <= 0) {
                showFloatingDateView(false);
            }
        }
        this.returnToMessageId = fromMessageId;
        this.returnToLoadIndex = loadIndex;
        this.needSelectFromMessageId = select;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showPagedownButton(boolean show, boolean animated) {
        FrameLayout frameLayout = this.pagedownButton;
        if (frameLayout == null) {
            return;
        }
        if (show) {
            this.pagedownButtonShowedByScroll = false;
            if (frameLayout.getTag() == null) {
                AnimatorSet animatorSet = this.pagedownButtonAnimation;
                if (animatorSet != null) {
                    animatorSet.cancel();
                    this.pagedownButtonAnimation = null;
                }
                if (animated) {
                    if (this.pagedownButton.getTranslationY() == 0.0f) {
                        this.pagedownButton.setTranslationY(AndroidUtilities.dp(100.0f));
                    }
                    if (isSysNotifyMessage().booleanValue() && this.dialog_id == 773000) {
                        this.pagedownButton.setVisibility(4);
                    } else {
                        this.pagedownButton.setVisibility(0);
                    }
                    this.pagedownButton.setTag(1);
                    this.pagedownButtonAnimation = new AnimatorSet();
                    if (this.mentiondownButton.getVisibility() == 0) {
                        this.pagedownButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.pagedownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(72.0f)));
                    } else {
                        this.pagedownButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.pagedownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
                    }
                    this.pagedownButtonAnimation.setDuration(200L);
                    this.pagedownButtonAnimation.start();
                    return;
                }
                this.pagedownButton.setVisibility(0);
                return;
            }
            return;
        }
        this.returnToMessageId = 0;
        this.newUnreadMessageCount = 0;
        if (frameLayout.getTag() != null) {
            this.pagedownButton.setTag(null);
            AnimatorSet animatorSet2 = this.pagedownButtonAnimation;
            if (animatorSet2 != null) {
                animatorSet2.cancel();
                this.pagedownButtonAnimation = null;
            }
            if (animated) {
                this.pagedownButtonAnimation = new AnimatorSet();
                if (this.mentiondownButton.getVisibility() == 0) {
                    this.pagedownButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.pagedownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(100.0f)), ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
                } else {
                    this.pagedownButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.pagedownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(100.0f)));
                }
                this.pagedownButtonAnimation.setDuration(200L);
                this.pagedownButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.53
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ChatActivity.this.pagedownButtonCounter.setVisibility(4);
                        ChatActivity.this.pagedownButton.setVisibility(4);
                    }
                });
                this.pagedownButtonAnimation.start();
                return;
            }
            this.pagedownButton.setVisibility(4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showMentionDownButton(boolean show, boolean animated) {
        FrameLayout frameLayout = this.mentiondownButton;
        if (frameLayout == null) {
            return;
        }
        if (show) {
            if (frameLayout.getTag() == null) {
                ObjectAnimator objectAnimator = this.mentiondownButtonAnimation;
                if (objectAnimator != null) {
                    objectAnimator.cancel();
                    this.mentiondownButtonAnimation = null;
                }
                if (animated) {
                    this.mentiondownButton.setVisibility(0);
                    this.mentiondownButton.setTag(1);
                    if (this.pagedownButton.getVisibility() == 0) {
                        this.mentiondownButton.setTranslationY(-AndroidUtilities.dp(72.0f));
                        this.mentiondownButtonAnimation = ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.ALPHA, 0.0f, 1.0f).setDuration(200L);
                    } else {
                        if (this.mentiondownButton.getTranslationY() == 0.0f) {
                            this.mentiondownButton.setTranslationY(AndroidUtilities.dp(100.0f));
                        }
                        this.mentiondownButtonAnimation = ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f).setDuration(200L);
                    }
                    this.mentiondownButtonAnimation.start();
                    return;
                }
                this.mentiondownButton.setVisibility(0);
                return;
            }
            return;
        }
        this.returnToMessageId = 0;
        if (frameLayout.getTag() != null) {
            this.mentiondownButton.setTag(null);
            ObjectAnimator objectAnimator2 = this.mentiondownButtonAnimation;
            if (objectAnimator2 != null) {
                objectAnimator2.cancel();
                this.mentiondownButtonAnimation = null;
            }
            if (animated) {
                if (this.pagedownButton.getVisibility() == 0) {
                    this.mentiondownButtonAnimation = ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.ALPHA, 1.0f, 0.0f).setDuration(200L);
                } else {
                    this.mentiondownButtonAnimation = ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(100.0f)).setDuration(200L);
                }
                this.mentiondownButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.54
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        ChatActivity.this.mentiondownButtonCounter.setVisibility(4);
                        ChatActivity.this.mentiondownButton.setVisibility(4);
                    }
                });
                this.mentiondownButtonAnimation.start();
                return;
            }
            this.mentiondownButton.setVisibility(4);
        }
    }

    private void updateSecretStatus() {
        ChatActivityEnterView chatActivityEnterView;
        if (this.bottomOverlay == null) {
            return;
        }
        boolean hideKeyboard = false;
        TLRPC.Chat chat = this.currentChat;
        if (chat != null && !ChatObject.canSendMessages(chat) && (!ChatObject.isChannel(this.currentChat) || this.currentChat.megagroup)) {
            if (this.currentChat.default_banned_rights != null && this.currentChat.default_banned_rights.send_messages) {
                this.bottomOverlayText.setText(LocaleController.getString("GlobalSendMessageRestricted", R.string.GlobalSendMessageRestricted));
            } else if (AndroidUtilities.isBannedForever(this.currentChat.banned_rights)) {
                this.bottomOverlayText.setText(LocaleController.getString("SendMessageRestrictedForever", R.string.SendMessageRestrictedForever));
            } else {
                this.bottomOverlayText.setText(LocaleController.formatString("SendMessageRestricted", R.string.SendMessageRestricted, LocaleController.formatDateForBan(this.currentChat.banned_rights.until_date)));
            }
            this.bottomOverlay.setVisibility(0);
            AnimatorSet animatorSet = this.mentionListAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.mentionListAnimation = null;
            }
            this.mentionContainer.setVisibility(8);
            this.mentionContainer.setTag(null);
            updateMessageListAccessibilityVisibility();
            hideKeyboard = true;
            StickersAdapter stickersAdapter = this.stickersAdapter;
            if (stickersAdapter != null) {
                stickersAdapter.hide();
            }
        } else {
            TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
            if (encryptedChat == null || this.bigEmptyView == null) {
                this.bottomOverlay.setVisibility(4);
                if (this.stickersAdapter != null && (chatActivityEnterView = this.chatActivityEnterView) != null && chatActivityEnterView.hasText()) {
                    this.stickersAdapter.loadStikersForEmoji(this.chatActivityEnterView.getFieldText(), false);
                }
                ChatActivityEnterView chatActivityEnterView2 = this.chatActivityEnterView;
                if (chatActivityEnterView2 != null) {
                    chatActivityEnterView2.updateMenuViewStatus();
                    return;
                }
                return;
            }
            if (encryptedChat instanceof TLRPC.TL_encryptedChatRequested) {
                this.bottomOverlayText.setText(LocaleController.getString("EncryptionProcessing", R.string.EncryptionProcessing));
                this.bottomOverlay.setVisibility(0);
                hideKeyboard = true;
            } else if (encryptedChat instanceof TLRPC.TL_encryptedChatWaiting) {
                this.bottomOverlayText.setText(AndroidUtilities.replaceTags(LocaleController.formatString("AwaitingEncryption", R.string.AwaitingEncryption, "<b>" + this.currentUser.first_name + "</b>")));
                this.bottomOverlay.setVisibility(0);
                hideKeyboard = true;
            } else if (encryptedChat instanceof TLRPC.TL_encryptedChatDiscarded) {
                this.bottomOverlayText.setText(LocaleController.getString("EncryptionRejected", R.string.EncryptionRejected));
                this.bottomOverlay.setVisibility(0);
                this.chatActivityEnterView.setFieldText("");
                getMediaDataController().cleanDraft(this.dialog_id, false);
                hideKeyboard = true;
            } else if (encryptedChat instanceof TLRPC.TL_encryptedChat) {
                this.bottomOverlay.setVisibility(4);
            }
            checkRaiseSensors();
            checkActionBarMenu();
        }
        if (this.inPreviewMode) {
            this.bottomOverlay.setVisibility(4);
        }
        if (hideKeyboard) {
            this.chatActivityEnterView.hidePopup(false);
            if (getParentActivity() != null) {
                AndroidUtilities.hideKeyboard(getParentActivity().getCurrentFocus());
            }
        }
        ChatActivityEnterView chatActivityEnterView3 = this.chatActivityEnterView;
        if (chatActivityEnterView3 != null) {
            chatActivityEnterView3.updateMenuViewStatus();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        ChatAttachAlert chatAttachAlert;
        TLRPC.User user;
        ChatAttachAlert chatAttachAlert2;
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        }
        MentionsAdapter mentionsAdapter = this.mentionsAdapter;
        if (mentionsAdapter != null) {
            mentionsAdapter.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        }
        if (requestCode == 4 && (chatAttachAlert2 = this.chatAttachAlert) != null) {
            chatAttachAlert2.checkStorage();
            return;
        }
        boolean z = false;
        if ((requestCode == 17 || requestCode == 18) && (chatAttachAlert = this.chatAttachAlert) != null) {
            if (grantResults.length > 0 && grantResults[0] == 0) {
                z = true;
            }
            chatAttachAlert.checkCamera(z);
            return;
        }
        if (requestCode == 21) {
            if (getParentActivity() != null && grantResults != null && grantResults.length != 0 && grantResults[0] != 0) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("PermissionNoAudioVideo", R.string.PermissionNoAudioVideo));
                builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ORTIDflo7_nlRk86DI4UkJcB-d4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onRequestPermissionsResultFragment$65$ChatActivity(dialogInterface, i);
                    }
                });
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                builder.show();
                return;
            }
            return;
        }
        if (requestCode == 19 && grantResults != null && grantResults.length > 0 && grantResults[0] == 0) {
            processSelectedAttach(0);
            return;
        }
        if (requestCode == 20 && grantResults != null && grantResults.length > 0 && grantResults[0] == 0) {
            processSelectedAttach(2);
            return;
        }
        if (requestCode == 101 && (user = this.currentUser) != null) {
            if (grantResults.length > 0 && grantResults[0] == 0) {
                VoIPHelper.startCall(user, getParentActivity(), getMessagesController().getUserFull(this.currentUser.id));
            } else {
                VoIPHelper.permissionDenied(getParentActivity(), null);
            }
        }
    }

    public /* synthetic */ void lambda$onRequestPermissionsResultFragment$65$ChatActivity(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            getParentActivity().startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void checkActionBarMenu() {
        TLRPC.Chat chat;
        TLRPC.User user;
        TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
        if ((encryptedChat != null && !(encryptedChat instanceof TLRPC.TL_encryptedChat)) || (((chat = this.currentChat) != null && ChatObject.isNotInChat(chat)) || ((user = this.currentUser) != null && UserObject.isDeleted(user)))) {
            View view = this.timeItem2;
            if (view != null) {
                view.setVisibility(8);
            }
        } else {
            View view2 = this.timeItem2;
            if (view2 != null) {
                view2.setVisibility(0);
            }
        }
        checkAndUpdateAvatar();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getMessageType(MessageObject messageObject) {
        String mime;
        String mime2;
        if (messageObject == null) {
            return -1;
        }
        if (this.currentEncryptedChat == null) {
            if (messageObject.isEditing()) {
                return -1;
            }
            if (messageObject.getId() <= 0 && messageObject.isOut()) {
                if (messageObject.isSendError()) {
                    return !messageObject.isMediaEmpty() ? 0 : 20;
                }
                return -1;
            }
            if (messageObject.isAnimatedEmoji()) {
                return 2;
            }
            if (messageObject.type == 6) {
                return -1;
            }
            if (messageObject.type == 10 || messageObject.type == 11) {
                return messageObject.getId() == 0 ? -1 : 1;
            }
            if (messageObject.isVoice()) {
                return 2;
            }
            if (messageObject.isSticker() || messageObject.isAnimatedSticker()) {
                TLRPC.InputStickerSet inputStickerSet = messageObject.getInputStickerSet();
                return inputStickerSet instanceof TLRPC.TL_inputStickerSetID ? !getMediaDataController().isStickerPackInstalled(inputStickerSet.id) ? 7 : 9 : (!(inputStickerSet instanceof TLRPC.TL_inputStickerSetShortName) || getMediaDataController().isStickerPackInstalled(inputStickerSet.short_name)) ? 9 : 7;
            }
            if (messageObject.isRoundVideo() || (!(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) && messageObject.getDocument() == null && !messageObject.isMusic() && !messageObject.isVideo())) {
                if (messageObject.type == 12) {
                    return 8;
                }
                if (messageObject.isMediaEmpty()) {
                    return 3;
                }
            } else {
                boolean canSave = false;
                if (!TextUtils.isEmpty(messageObject.messageOwner.attachPath)) {
                    File f = new File(messageObject.messageOwner.attachPath);
                    if (f.exists()) {
                        canSave = true;
                    }
                }
                if (!canSave) {
                    File f2 = FileLoader.getPathToMessage(messageObject.messageOwner);
                    if (f2.exists()) {
                        canSave = true;
                    }
                }
                if (canSave) {
                    if (messageObject.getDocument() != null && (mime2 = messageObject.getDocument().mime_type) != null) {
                        if (messageObject.getDocumentName().toLowerCase().endsWith("attheme")) {
                            return 10;
                        }
                        if (mime2.endsWith("/xml")) {
                            return 5;
                        }
                        if (mime2.endsWith("/png") || mime2.endsWith("/jpg") || mime2.endsWith("/jpeg")) {
                            return 6;
                        }
                    }
                    return 4;
                }
            }
            return 2;
        }
        if (messageObject.isSending()) {
            return -1;
        }
        if (messageObject.isAnimatedEmoji()) {
            return 2;
        }
        if (messageObject.type == 6) {
            return -1;
        }
        if (messageObject.isSendError()) {
            return !messageObject.isMediaEmpty() ? 0 : 20;
        }
        if (messageObject.type == 10 || messageObject.type == 11) {
            return (messageObject.getId() == 0 || messageObject.isSending()) ? -1 : 1;
        }
        if (messageObject.isVoice()) {
            return 2;
        }
        if (messageObject.isAnimatedEmoji() || (!messageObject.isSticker() && !messageObject.isAnimatedSticker())) {
            if (messageObject.isRoundVideo() || (!(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaPhoto) && messageObject.getDocument() == null && !messageObject.isMusic() && !messageObject.isVideo())) {
                if (messageObject.type == 12) {
                    return 8;
                }
                if (messageObject.isMediaEmpty()) {
                    return 3;
                }
            } else {
                boolean canSave2 = false;
                if (!TextUtils.isEmpty(messageObject.messageOwner.attachPath)) {
                    File f3 = new File(messageObject.messageOwner.attachPath);
                    if (f3.exists()) {
                        canSave2 = true;
                    }
                }
                if (!canSave2) {
                    File f4 = FileLoader.getPathToMessage(messageObject.messageOwner);
                    if (f4.exists()) {
                        canSave2 = true;
                    }
                }
                if (canSave2) {
                    if (messageObject.getDocument() != null && (mime = messageObject.getDocument().mime_type) != null && mime.endsWith("text/xml")) {
                        return 5;
                    }
                    if (messageObject.messageOwner.ttl <= 0) {
                        return 4;
                    }
                }
            }
        } else {
            TLRPC.InputStickerSet inputStickerSet2 = messageObject.getInputStickerSet();
            if ((inputStickerSet2 instanceof TLRPC.TL_inputStickerSetShortName) && !getMediaDataController().isStickerPackInstalled(inputStickerSet2.short_name)) {
                return 7;
            }
        }
        return 2;
    }

    private void addToSelectedMessages(MessageObject messageObject, boolean outside) {
        addToSelectedMessages(messageObject, outside, true);
    }

    /* JADX WARN: Removed duplicated region for block: B:307:0x0526  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void addToSelectedMessages(im.uwrkaxlmjj.messenger.MessageObject r31, boolean r32, boolean r33) {
        /*
            Method dump skipped, instruction units count: 1619
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.addToSelectedMessages(im.uwrkaxlmjj.messenger.MessageObject, boolean, boolean):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processRowSelect(View view, boolean outside, float touchX, float touchY) {
        MessageObject message = null;
        if (view instanceof ChatMessageCell) {
            message = ((ChatMessageCell) view).getMessageObject();
        } else if (view instanceof ChatActionCell) {
            message = ((ChatActionCell) view).getMessageObject();
        }
        int type = getMessageType(message);
        if (type < 2 || type == 20) {
            return;
        }
        addToSelectedMessages(message, outside);
        updateActionModeTitle();
        updateVisibleRows();
    }

    private void updateActionModeTitle() {
        if (!this.actionBar.isActionModeShowed()) {
            return;
        }
        if (this.selectedMessagesIds[0].size() != 0 || this.selectedMessagesIds[1].size() != 0) {
            this.selectedMessagesCountTextView.setNumber(this.selectedMessagesIds[0].size() + this.selectedMessagesIds[1].size(), true);
        }
    }

    @Deprecated
    private void updateTitle() {
    }

    private void updateBotButtons() {
        TLRPC.User user;
        int a;
        if (this.headerItem == null || (user = this.currentUser) == null || this.currentEncryptedChat != null || !user.bot) {
            return;
        }
        boolean hasHelp = false;
        boolean hasSettings = false;
        if (this.botInfo.size() != 0) {
            for (int b = 0; b < this.botInfo.size(); b++) {
                TLRPC.BotInfo info = this.botInfo.valueAt(b);
                while (a < info.commands.size()) {
                    TLRPC.TL_botCommand command = info.commands.get(a);
                    if (command.command.toLowerCase().equals("help")) {
                        hasHelp = true;
                    } else if (command.command.toLowerCase().equals("settings")) {
                        hasSettings = true;
                    }
                    a = (hasSettings && hasHelp) ? 0 : a + 1;
                }
            }
        }
        if (hasHelp) {
            this.headerItem.showSubItem(30);
        } else {
            this.headerItem.hideSubItem(30);
        }
        if (hasSettings) {
            this.headerItem.showSubItem(31);
        } else {
            this.headerItem.hideSubItem(31);
        }
    }

    private void updateTitleIcons() {
        if (this.inScheduleMode) {
            return;
        }
        boolean dialogMuted = getMessagesController().isDialogMuted(this.dialog_id);
        Drawable rightIcon = getMessagesController().isDialogMuted(this.dialog_id) ? Theme.chat_muteIconDrawable : null;
        Drawable encryptedIcon = null;
        if (this.currentEncryptedChat != null) {
            encryptedIcon = Theme.getThemedDrawable(getParentActivity(), R.drawable.ic_lock_header, Theme.key_actionBarDefaultTitle);
        }
        if (isSysNotifyMessage().booleanValue()) {
            if (this.headerItem instanceof ActionBarMenuItem) {
                ActionBarMenuItem headerItem = this.headerItem;
                if (dialogMuted) {
                    headerItem.setIcon(R.id.iv_chat_sys_notify_msg_mute);
                    return;
                } else {
                    headerItem.setIcon(R.id.iv_chat_sys_notify_msg_unmute);
                    return;
                }
            }
            return;
        }
        this.actionBarHelper.setTitleIcons(encryptedIcon, rightIcon);
        ChatActionBarMenuSubItem chatActionBarMenuSubItem = this.muteItem;
        if (chatActionBarMenuSubItem != null) {
            if (rightIcon != null) {
                chatActionBarMenuSubItem.setTextAndIcon(LocaleController.getString("UnmuteNotifications", R.string.UnmuteNotifications), R.drawable.msg_unmute);
            } else {
                chatActionBarMenuSubItem.setTextAndIcon(LocaleController.getString("MuteNotifications", R.string.MuteNotifications), R.drawable.msg_mute);
            }
        }
    }

    private void checkAndUpdateAvatar() {
        TLRPC.Chat chat;
        if (this.currentUser != null) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(this.currentUser.id));
            if (user == null) {
                return;
            }
            this.currentUser = user;
            return;
        }
        if (this.currentChat == null || (chat = getMessagesController().getChat(Integer.valueOf(this.currentChat.id))) == null) {
            return;
        }
        this.currentChat = chat;
    }

    public void openVideoEditor(String videoPath, String caption) {
        if (getParentActivity() == null) {
            fillEditingMediaWithCaption(caption, null);
            SendMessagesHelper.prepareSendingVideo(getAccountInstance(), videoPath, 0L, 0L, 0, 0, null, this.dialog_id, this.replyingMessageObject, null, null, 0, this.editingMessageObject, true, 0);
            afterMessageSend();
            return;
        }
        final Bitmap thumb = ThumbnailUtils.createVideoThumbnail(videoPath, 1);
        PhotoViewer.getInstance().setParentActivity(getParentActivity());
        final ArrayList<Object> cameraPhoto = new ArrayList<>();
        MediaController.PhotoEntry entry = new MediaController.PhotoEntry(0, 0, 0L, videoPath, 0, true);
        entry.caption = caption;
        cameraPhoto.add(entry);
        PhotoViewer.getInstance().openPhotoForSelect(cameraPhoto, 0, 2, new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.ChatActivity.58
            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public ImageReceiver.BitmapHolder getThumbForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index) {
                return new ImageReceiver.BitmapHolder(thumb, null);
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
                ChatActivity.this.sendMedia((MediaController.PhotoEntry) cameraPhoto.get(0), videoEditedInfo, notify, scheduleDate);
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public boolean canScrollAway() {
                return false;
            }
        }, this);
    }

    private void showAttachmentError() {
        if (getParentActivity() == null) {
            return;
        }
        ToastUtils.show(R.string.UnsupportedAttachment);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fillEditingMediaWithCaption(CharSequence caption, ArrayList<TLRPC.MessageEntity> entities) {
        if (this.editingMessageObject == null) {
            return;
        }
        if (!TextUtils.isEmpty(caption)) {
            this.editingMessageObject.editingMessage = caption;
            this.editingMessageObject.editingMessageEntities = entities;
            return;
        }
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            this.editingMessageObject.editingMessage = chatActivityEnterView.getFieldText();
            if (this.editingMessageObject.editingMessage == null && !TextUtils.isEmpty(this.editingMessageObject.messageOwner.message)) {
                this.editingMessageObject.editingMessage = "";
            }
        }
    }

    private void sendUriAsDocument(Uri uri) {
        Uri uri2;
        if (uri == null) {
            return;
        }
        String extractUriFrom = uri.toString();
        if (extractUriFrom.contains("com.google.android.apps.photos.contentprovider")) {
            try {
                String firstExtraction = extractUriFrom.split("/1/")[1];
                int index = firstExtraction.indexOf("/ACTUAL");
                if (index == -1) {
                    uri2 = uri;
                } else {
                    String secondExtraction = URLDecoder.decode(firstExtraction.substring(0, index), "UTF-8");
                    uri2 = Uri.parse(secondExtraction);
                }
            } catch (Exception e) {
                FileLog.e(e);
                uri2 = uri;
            }
        } else {
            uri2 = uri;
        }
        String tempPath = AndroidUtilities.getPath(uri2);
        String originalPath = tempPath;
        if (tempPath == null) {
            originalPath = uri2.toString();
            tempPath = MediaController.copyFileToCache(uri2, "file");
        }
        if (tempPath != null) {
            fillEditingMediaWithCaption(null, null);
            isVedioFile(tempPath);
            SendMessagesHelper.prepareSendingDocument(getAccountInstance(), tempPath, originalPath, null, null, null, this.dialog_id, this.replyingMessageObject, null, this.editingMessageObject, true, 0);
            hideFieldPanel(false);
            return;
        }
        showAttachmentError();
    }

    private String getMimeType(String fileName) {
        FileNameMap fileNameMap = URLConnection.getFileNameMap();
        return fileNameMap.getContentTypeFor(fileName);
    }

    public boolean isVedioFile(String fileName) {
        String mimeType = getMimeType(fileName);
        if (!TextUtils.isEmpty(fileName) && mimeType.contains(PREFIX_VIDEO)) {
            return true;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        if (resultCode == -1) {
            if (requestCode == 0 || requestCode == 2) {
                createChatAttachView();
                ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
                if (chatAttachAlert != null) {
                    chatAttachAlert.onActivityResultFragment(requestCode, data, this.currentPicturePath);
                }
                this.currentPicturePath = null;
                return;
            }
            if (requestCode == 1) {
                if (data == null || data.getData() == null) {
                    showAttachmentError();
                    return;
                }
                final Uri uri = data.getData();
                if (uri.toString().contains("video")) {
                    String videoPath = null;
                    try {
                        videoPath = AndroidUtilities.getPath(uri);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                    if (videoPath == null) {
                        showAttachmentError();
                    }
                    if (this.paused) {
                        this.startVideoEdit = videoPath;
                    } else {
                        openVideoEditor(videoPath, null);
                    }
                } else if (this.editingMessageObject == null && this.inScheduleMode) {
                    AlertsCreator.createScheduleDatePickerDialog(getParentActivity(), UserObject.isUserSelf(this.currentUser), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$nZcUV7qe7qMmIbOhAQ8wRSqkPls
                        @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                        public final void didSelectDate(boolean z, int i) {
                            this.f$0.lambda$onActivityResultFragment$66$ChatActivity(uri, z, i);
                        }
                    });
                } else {
                    fillEditingMediaWithCaption(null, null);
                    SendMessagesHelper.prepareSendingPhoto(getAccountInstance(), null, uri, this.dialog_id, this.replyingMessageObject, null, null, null, null, 0, this.editingMessageObject, true, 0);
                }
                afterMessageSend();
                return;
            }
            if (requestCode == 21) {
                if (data == null) {
                    showAttachmentError();
                    return;
                }
                if (data.getData() != null) {
                    sendUriAsDocument(data.getData());
                } else if (data.getClipData() != null) {
                    ClipData clipData = data.getClipData();
                    for (int i = 0; i < clipData.getItemCount(); i++) {
                        sendUriAsDocument(clipData.getItemAt(i).getUri());
                    }
                } else {
                    showAttachmentError();
                }
                afterMessageSend();
            }
        }
    }

    public /* synthetic */ void lambda$onActivityResultFragment$66$ChatActivity(Uri uri, boolean notify, int scheduleDate) {
        fillEditingMediaWithCaption(null, null);
        SendMessagesHelper.prepareSendingPhoto(getAccountInstance(), null, uri, this.dialog_id, this.replyingMessageObject, null, null, null, null, 0, this.editingMessageObject, notify, scheduleDate);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        String str = this.currentPicturePath;
        if (str != null) {
            args.putString("path", str);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        this.currentPicturePath = args.getString("path");
    }

    private void removeUnreadPlane(boolean scrollToEnd) {
        if (this.unreadMessageObject != null) {
            if (scrollToEnd) {
                boolean[] zArr = this.forwardEndReached;
                zArr[1] = true;
                zArr[0] = true;
                this.first_unread_id = 0;
                this.last_message_id = 0;
            }
            this.createUnreadMessageAfterId = 0;
            this.createUnreadMessageAfterIdLoading = false;
            removeMessageObject(this.unreadMessageObject);
            this.unreadMessageObject = null;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:1063:0x13ec  */
    /* JADX WARN: Removed duplicated region for block: B:1092:0x1483  */
    /* JADX WARN: Removed duplicated region for block: B:1095:0x1488  */
    /* JADX WARN: Removed duplicated region for block: B:1122:0x14f6  */
    /* JADX WARN: Removed duplicated region for block: B:1127:0x1511  */
    /* JADX WARN: Removed duplicated region for block: B:1129:0x1517  */
    /* JADX WARN: Removed duplicated region for block: B:1130:0x151a  */
    /* JADX WARN: Removed duplicated region for block: B:1137:0x155a  */
    /* JADX WARN: Removed duplicated region for block: B:1139:0x1562  */
    /* JADX WARN: Removed duplicated region for block: B:1140:0x1569  */
    /* JADX WARN: Removed duplicated region for block: B:1148:0x1588  */
    /* JADX WARN: Removed duplicated region for block: B:1151:0x159e  */
    /* JADX WARN: Removed duplicated region for block: B:1162:0x15d2  */
    /* JADX WARN: Removed duplicated region for block: B:1522:0x1cc3 A[PHI: r18
      0x1cc3: PHI (r18v5 'markAsDeletedMessages' java.util.ArrayList<java.lang.Integer>) = 
      (r18v4 'markAsDeletedMessages' java.util.ArrayList<java.lang.Integer>)
      (r18v6 'markAsDeletedMessages' java.util.ArrayList<java.lang.Integer>)
     binds: [B:1521:0x1cc1, B:1515:0x1cb2] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:1698:0x207d  */
    /* JADX WARN: Removed duplicated region for block: B:1704:0x208e  */
    /* JADX WARN: Removed duplicated region for block: B:1708:0x20a2  */
    /* JADX WARN: Removed duplicated region for block: B:1712:0x20bf  */
    /* JADX WARN: Removed duplicated region for block: B:1719:0x20de  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x0522  */
    /* JADX WARN: Removed duplicated region for block: B:2686:0x15b9 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:568:0x0b45  */
    /* JADX WARN: Removed duplicated region for block: B:594:0x0be3  */
    /* JADX WARN: Removed duplicated region for block: B:597:0x0bed  */
    /* JADX WARN: Removed duplicated region for block: B:644:0x0ca2  */
    /* JADX WARN: Removed duplicated region for block: B:646:0x0ca8  */
    /* JADX WARN: Removed duplicated region for block: B:651:0x0ce7  */
    /* JADX WARN: Removed duplicated region for block: B:652:0x0cec  */
    /* JADX WARN: Removed duplicated region for block: B:655:0x0cf8  */
    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void didReceivedNotification(int r62, int r63, java.lang.Object... r64) {
        /*
            Method dump skipped, instruction units count: 12477
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.didReceivedNotification(int, int, java.lang.Object[]):void");
    }

    public /* synthetic */ void lambda$didReceivedNotification$67$ChatActivity() {
        if (this.parentLayout != null) {
            this.parentLayout.resumeDelayedFragmentAnimation();
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$68$ChatActivity(DialogInterface dialogInterface, int i) {
        TLRPC.User user = this.currentUser;
        if (user != null) {
            presentFragment(new AddContactsInfoActivity(null, user));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0038  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void listViewShowEmptyView(boolean r4, boolean r5) {
        /*
            r3 = this;
            im.uwrkaxlmjj.ui.components.RecyclerListView r0 = r3.chatListView
            r1 = 0
            if (r0 == 0) goto L3f
            r2 = 0
            if (r4 == 0) goto Lc
            r0.setEmptyView(r2)
            goto L3f
        Lc:
            java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r0 = r3.messages
            if (r0 == 0) goto L1d
            boolean r0 = r0.isEmpty()
            if (r0 == 0) goto L17
            goto L1d
        L17:
            im.uwrkaxlmjj.ui.components.RecyclerListView r0 = r3.chatListView
            r0.setEmptyView(r2)
            goto L3f
        L1d:
            android.widget.FrameLayout r0 = r3.emptyViewContainer
            if (r0 == 0) goto L3f
            im.uwrkaxlmjj.ui.components.RecyclerListView r0 = r3.chatListView
            android.view.View r0 = r0.getEmptyView()
            if (r0 == 0) goto L38
            im.uwrkaxlmjj.ui.components.RecyclerListView r0 = r3.chatListView
            android.view.View r0 = r0.getEmptyView()
            android.widget.FrameLayout r2 = r3.emptyViewContainer
            if (r0 == r2) goto L34
            goto L38
        L34:
            r2.setVisibility(r1)
            goto L3f
        L38:
            im.uwrkaxlmjj.ui.components.RecyclerListView r0 = r3.chatListView
            android.widget.FrameLayout r2 = r3.emptyViewContainer
            r0.setEmptyView(r2)
        L3f:
            android.widget.FrameLayout r0 = r3.progressView
            if (r0 == 0) goto L4a
            if (r5 == 0) goto L46
            goto L47
        L46:
            r1 = 4
        L47:
            r0.setVisibility(r1)
        L4a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.listViewShowEmptyView(boolean, boolean):void");
    }

    private void checkSecretMessageForLocation(MessageObject messageObject) {
        if (messageObject.type != 4 || this.locationAlertShown || SharedConfig.isSecretMapPreviewSet()) {
            return;
        }
        this.locationAlertShown = true;
        AlertsCreator.showSecretLocationAlert(getParentActivity(), this.currentAccount, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$3yFZeWSsITjSDb3qRTutDwvZSAk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkSecretMessageForLocation$69$ChatActivity();
            }
        }, true);
    }

    public /* synthetic */ void lambda$checkSecretMessageForLocation$69$ChatActivity() {
        int count = this.chatListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View view = this.chatListView.getChildAt(a);
            if (view instanceof ChatMessageCell) {
                ChatMessageCell cell = (ChatMessageCell) view;
                MessageObject message = cell.getMessageObject();
                if (message.type == 4) {
                    cell.forceResetMessageObject();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clearHistory(boolean overwrite) {
        TLRPC.User user;
        this.messages.clear();
        this.waitingForLoad.clear();
        this.messagesByDays.clear();
        this.groupedMessagesMap.clear();
        for (int a = 1; a >= 0; a--) {
            this.messagesDict[a].clear();
            if (this.currentEncryptedChat == null) {
                this.maxMessageId[a] = Integer.MAX_VALUE;
                this.minMessageId[a] = Integer.MIN_VALUE;
            } else {
                this.maxMessageId[a] = Integer.MIN_VALUE;
                this.minMessageId[a] = Integer.MAX_VALUE;
            }
            this.maxDate[a] = Integer.MIN_VALUE;
            this.minDate[a] = 0;
            this.selectedMessagesIds[a].clear();
            this.selectedMessagesCanCopyIds[a].clear();
            this.selectedMessagesCanStarIds[a].clear();
        }
        hideActionMode();
        updatePinnedMessageView(true);
        if (this.botButtons != null) {
            this.botButtons = null;
            ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
            if (chatActivityEnterView != null) {
                chatActivityEnterView.setButtons(null, false);
            }
        }
        if (overwrite) {
            ChatActivityAdapter chatActivityAdapter = this.chatAdapter;
            if (chatActivityAdapter != null) {
                listViewShowEmptyView(true, chatActivityAdapter.botInfoRow == -1);
            }
            for (int a2 = 0; a2 < 2; a2++) {
                this.endReached[a2] = false;
                this.cacheEndReached[a2] = false;
                this.forwardEndReached[a2] = true;
            }
            this.first = true;
            this.firstLoading = true;
            this.loading = true;
            this.startLoadFromMessageId = 0;
            this.needSelectFromMessageId = false;
            this.waitingForLoad.add(Integer.valueOf(this.lastLoadIndex));
            int i = this.startLoadFromMessageIdSaved;
            if (i != 0) {
                this.startLoadFromMessageId = i;
                this.startLoadFromMessageIdSaved = 0;
                MessagesController messagesController = getMessagesController();
                long j = this.dialog_id;
                int i2 = AndroidUtilities.isTablet() ? 30 : 20;
                int i3 = this.startLoadFromMessageId;
                int i4 = this.classGuid;
                boolean zIsChannel = ChatObject.isChannel(this.currentChat);
                boolean z = this.inScheduleMode;
                int i5 = this.lastLoadIndex;
                this.lastLoadIndex = i5 + 1;
                messagesController.loadMessages(j, i2, i3, 0, true, 0, i4, 3, 0, zIsChannel, z, i5);
            } else {
                MessagesController messagesController2 = getMessagesController();
                long j2 = this.dialog_id;
                int i6 = AndroidUtilities.isTablet() ? 30 : 20;
                int i7 = this.classGuid;
                boolean zIsChannel2 = ChatObject.isChannel(this.currentChat);
                boolean z2 = this.inScheduleMode;
                int i8 = this.lastLoadIndex;
                this.lastLoadIndex = i8 + 1;
                messagesController2.loadMessages(j2, i6, 0, 0, true, 0, i7, 2, 0, zIsChannel2, z2, i8);
            }
        } else {
            listViewShowEmptyView(false, false);
        }
        ChatActivityAdapter chatActivityAdapter2 = this.chatAdapter;
        if (chatActivityAdapter2 != null) {
            chatActivityAdapter2.notifyDataSetChanged();
        }
        if (this.currentEncryptedChat == null && (user = this.currentUser) != null && user.bot && this.botUser == null) {
            this.botUser = "";
            updateBottomOverlay();
        }
    }

    public boolean processSwitchButton(TLRPC.TL_keyboardButtonSwitchInline button) {
        if (this.inlineReturn == 0 || button.same_peer || this.parentLayout == null) {
            return false;
        }
        String query = "@" + this.currentUser.username + " " + button.query;
        if (this.inlineReturn == this.dialog_id) {
            this.inlineReturn = 0L;
            this.chatActivityEnterView.setFieldText(query);
        } else {
            getMediaDataController().saveDraft(this.inlineReturn, query, null, null, false);
            if (this.parentLayout.fragmentsStack.size() > 1) {
                BaseFragment prevFragment = this.parentLayout.fragmentsStack.get(this.parentLayout.fragmentsStack.size() - 2);
                if ((prevFragment instanceof ChatActivity) && ((ChatActivity) prevFragment).dialog_id == this.inlineReturn) {
                    finishFragment();
                } else {
                    Bundle bundle = new Bundle();
                    long j = this.inlineReturn;
                    int lower_part = (int) j;
                    int high_part = (int) (j >> 32);
                    if (lower_part != 0) {
                        if (lower_part > 0) {
                            bundle.putInt("user_id", lower_part);
                        } else if (lower_part < 0) {
                            bundle.putInt("chat_id", -lower_part);
                        }
                    } else {
                        bundle.putInt("enc_id", high_part);
                    }
                    presentFragment(new ChatActivity(bundle), true);
                }
            }
        }
        return true;
    }

    private void replaceMessageObjects(ArrayList<MessageObject> messageObjects, int loadIndex, boolean remove) {
        ChatActivityAdapter chatActivityAdapter;
        MessageObject.GroupedMessages groupedMessages;
        int idx;
        LongSparseArray<MessageObject.GroupedMessages> newGroups = null;
        int a = 0;
        while (a < messageObjects.size()) {
            MessageObject messageObject = messageObjects.get(a);
            MessageObject old = this.messagesDict[loadIndex].get(messageObject.getId());
            MessageObject messageObject2 = this.pinnedMessageObject;
            if (messageObject2 != null && messageObject2.getId() == messageObject.getId()) {
                this.pinnedMessageObject = messageObject;
                updatePinnedMessageView(true);
            }
            if (old != null && (!remove || old.messageOwner.date == messageObject.messageOwner.date)) {
                if (remove) {
                    messageObjects.remove(a);
                    a--;
                }
                addToPolls(messageObject, old);
                if (messageObject.type >= 0) {
                    if (old.replyMessageObject != null) {
                        messageObject.replyMessageObject = old.replyMessageObject;
                        if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionGameScore) {
                            messageObject.generateGameMessageText(null);
                        } else if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionPaymentSent) {
                            messageObject.generatePaymentSentMessageText(null);
                        }
                    }
                    if (!old.isEditing()) {
                        if (old.getFileName().equals(messageObject.getFileName())) {
                            messageObject.messageOwner.attachPath = old.messageOwner.attachPath;
                            messageObject.attachPathExists = old.attachPathExists;
                            messageObject.mediaExists = old.mediaExists;
                        } else {
                            messageObject.checkMediaExistance();
                        }
                    }
                    this.messagesDict[loadIndex].put(old.getId(), messageObject);
                } else {
                    this.messagesDict[loadIndex].remove(old.getId());
                }
                int index = this.messages.indexOf(old);
                if (index >= 0) {
                    ArrayList<MessageObject> dayArr = this.messagesByDays.get(old.dateKey);
                    int index2 = -1;
                    if (dayArr != null) {
                        index2 = dayArr.indexOf(old);
                    }
                    if (old.getGroupId() != 0 && (groupedMessages = this.groupedMessagesMap.get(old.getGroupId())) != null && (idx = groupedMessages.messages.indexOf(old)) >= 0) {
                        if (old.getGroupId() != messageObject.getGroupId()) {
                            this.groupedMessagesMap.put(messageObject.getGroupId(), groupedMessages);
                        }
                        if (messageObject.photoThumbs == null || messageObject.photoThumbs.isEmpty()) {
                            if (newGroups == null) {
                                newGroups = new LongSparseArray<>();
                            }
                            newGroups.put(groupedMessages.groupId, groupedMessages);
                            if (idx > 0 && idx < groupedMessages.messages.size() - 1) {
                                MessageObject.GroupedMessages slicedGroup = new MessageObject.GroupedMessages();
                                slicedGroup.groupId = Utilities.random.nextLong();
                                slicedGroup.messages.addAll(groupedMessages.messages.subList(idx + 1, groupedMessages.messages.size()));
                                for (int b = 0; b < slicedGroup.messages.size(); b++) {
                                    slicedGroup.messages.get(b).localGroupId = slicedGroup.groupId;
                                    groupedMessages.messages.remove(idx + 1);
                                }
                                newGroups.put(slicedGroup.groupId, slicedGroup);
                                this.groupedMessagesMap.put(slicedGroup.groupId, slicedGroup);
                            }
                            groupedMessages.messages.remove(idx);
                        } else {
                            groupedMessages.messages.set(idx, messageObject);
                            MessageObject.GroupedMessagePosition oldPosition = groupedMessages.positions.remove(old);
                            if (oldPosition != null) {
                                groupedMessages.positions.put(messageObject, oldPosition);
                            }
                            if (newGroups == null) {
                                newGroups = new LongSparseArray<>();
                            }
                            newGroups.put(groupedMessages.groupId, groupedMessages);
                        }
                    }
                    if (messageObject.type >= 0) {
                        this.messages.set(index, messageObject);
                        ChatActivityAdapter chatActivityAdapter2 = this.chatAdapter;
                        if (chatActivityAdapter2 != null) {
                            chatActivityAdapter2.updateRowAtPosition(chatActivityAdapter2.messagesStartRow + index);
                        }
                        if (index2 >= 0) {
                            dayArr.set(index2, messageObject);
                        }
                    } else {
                        this.messages.remove(index);
                        ChatActivityAdapter chatActivityAdapter3 = this.chatAdapter;
                        if (chatActivityAdapter3 != null) {
                            chatActivityAdapter3.notifyItemRemoved(chatActivityAdapter3.messagesStartRow + index);
                        }
                        if (index2 >= 0) {
                            dayArr.remove(index2);
                            if (dayArr.isEmpty()) {
                                this.messagesByDays.remove(old.dateKey);
                                this.messages.remove(index);
                                ChatActivityAdapter chatActivityAdapter4 = this.chatAdapter;
                                chatActivityAdapter4.notifyItemRemoved(chatActivityAdapter4.messagesStartRow);
                            }
                        }
                    }
                }
            }
            a++;
        }
        if (newGroups != null) {
            for (int b2 = 0; b2 < newGroups.size(); b2++) {
                MessageObject.GroupedMessages groupedMessages2 = newGroups.valueAt(b2);
                if (groupedMessages2.messages.isEmpty()) {
                    this.groupedMessagesMap.remove(groupedMessages2.groupId);
                } else {
                    groupedMessages2.calculate();
                    int index3 = this.messages.indexOf(groupedMessages2.messages.get(groupedMessages2.messages.size() - 1));
                    if (index3 >= 0 && (chatActivityAdapter = this.chatAdapter) != null) {
                        chatActivityAdapter.notifyItemRangeChanged(chatActivityAdapter.messagesStartRow + index3, groupedMessages2.messages.size());
                    }
                }
            }
        }
    }

    private void migrateToNewChat(final MessageObject obj) {
        if (this.parentLayout == null) {
            return;
        }
        final int channelId = obj.messageOwner.action.channel_id;
        final BaseFragment lastFragment = this.parentLayout.fragmentsStack.size() > 0 ? this.parentLayout.fragmentsStack.get(this.parentLayout.fragmentsStack.size() - 1) : null;
        int index = this.parentLayout.fragmentsStack.indexOf(this);
        final ActionBarLayout actionBarLayout = this.parentLayout;
        if (index > 0 && !(lastFragment instanceof ChatActivity) && !(lastFragment instanceof ProfileActivity) && this.currentChat.creator) {
            int N = actionBarLayout.fragmentsStack.size() - 1;
            for (int a = index; a < N; a++) {
                BaseFragment fragment = actionBarLayout.fragmentsStack.get(a);
                if (fragment instanceof ChatActivity) {
                    Bundle bundle = new Bundle();
                    bundle.putInt("chat_id", channelId);
                    actionBarLayout.addFragmentToStack(new ChatActivity(bundle), a);
                    fragment.removeSelfFromStack();
                } else if (fragment instanceof ProfileActivity) {
                    Bundle args = new Bundle();
                    args.putInt("chat_id", channelId);
                    actionBarLayout.addFragmentToStack(new ProfileActivity(args), a);
                    fragment.removeSelfFromStack();
                } else if (fragment instanceof ChatEditActivity) {
                    Bundle args2 = new Bundle();
                    args2.putInt("chat_id", channelId);
                    actionBarLayout.addFragmentToStack(new ChatEditActivity(args2), a);
                    fragment.removeSelfFromStack();
                } else if (fragment instanceof ChatUsersActivity) {
                    ChatUsersActivity usersActivity = (ChatUsersActivity) fragment;
                    if (!usersActivity.hasSelectType()) {
                        Bundle args3 = fragment.getArguments();
                        args3.putInt("chat_id", channelId);
                        actionBarLayout.addFragmentToStack(new ChatUsersActivity(args3), a);
                    }
                    fragment.removeSelfFromStack();
                }
            }
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$k1bSeCRhY8T-Zd-jFu-VGGIC0jw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$migrateToNewChat$70$ChatActivity(lastFragment, obj, actionBarLayout);
                }
            });
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$AIRU1j28V3QInX73GR-l4YhRhKs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$migrateToNewChat$71$ChatActivity(channelId);
            }
        }, 1000L);
    }

    public /* synthetic */ void lambda$migrateToNewChat$70$ChatActivity(BaseFragment lastFragment, MessageObject obj, ActionBarLayout actionBarLayout) {
        if (lastFragment != null) {
            getNotificationCenter().removeObserver(lastFragment, NotificationCenter.closeChats);
        }
        getNotificationCenter().postNotificationName(NotificationCenter.closeChats, new Object[0]);
        Bundle bundle = new Bundle();
        bundle.putInt("chat_id", obj.messageOwner.action.channel_id);
        actionBarLayout.presentFragment(new ChatActivity(bundle), true);
    }

    public /* synthetic */ void lambda$migrateToNewChat$71$ChatActivity(int channelId) {
        getMessagesController().loadFullChat(channelId, 0, true);
    }

    private void addToPolls(MessageObject obj, MessageObject old) {
        long pollId = obj.getPollId();
        if (pollId != 0) {
            ArrayList<MessageObject> arrayList = this.polls.get(pollId);
            if (arrayList == null) {
                arrayList = new ArrayList<>();
                this.polls.put(pollId, arrayList);
            }
            arrayList.add(obj);
            if (old != null) {
                arrayList.remove(old);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSearchButtons(int mask, int num, int count) {
        ImageView imageView = this.searchUpButton;
        if (imageView != null) {
            imageView.setEnabled((mask & 1) != 0);
            this.searchDownButton.setEnabled((mask & 2) != 0);
            ImageView imageView2 = this.searchUpButton;
            imageView2.setAlpha(imageView2.isEnabled() ? 1.0f : 0.5f);
            ImageView imageView3 = this.searchDownButton;
            imageView3.setAlpha(imageView3.isEnabled() ? 1.0f : 0.5f);
            if (count < 0) {
                this.searchCountText.setText("");
            } else if (count == 0) {
                this.searchCountText.setText(LocaleController.getString("NoResult", R.string.NoResult));
            } else {
                this.searchCountText.setText(LocaleController.formatString("Of", R.string.Of, Integer.valueOf(num + 1), Integer.valueOf(count)));
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean needDelayOpenAnimation() {
        return this.firstLoading;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onBecomeFullyHidden() {
        UndoView undoView = this.undoView;
        if (undoView != null) {
            undoView.hide(true, 0);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationStart(boolean isOpen, boolean backward) {
        if (isOpen) {
            getNotificationCenter().setAllowedNotificationsDutingAnimation(new int[]{NotificationCenter.chatInfoDidLoad, NotificationCenter.dialogsNeedReload, NotificationCenter.scheduledMessagesUpdated, NotificationCenter.closeChats, NotificationCenter.messagesDidLoad, NotificationCenter.botKeyboardDidLoad, NotificationCenter.userFullInfoDidLoad, NotificationCenter.needDeleteDialog});
            this.openAnimationEnded = false;
        } else {
            ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
            if (chatActivityEnterView != null) {
                chatActivityEnterView.onBeginHide();
            }
        }
        getNotificationCenter().setAnimationInProgress(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        getNotificationCenter().setAnimationInProgress(false);
        if (isOpen) {
            this.openAnimationEnded = true;
            if (Build.VERSION.SDK_INT >= 21) {
                createChatAttachView();
            }
            if (this.chatActivityEnterView.hasRecordVideo() && !this.chatActivityEnterView.isSendButtonVisible()) {
                boolean isChannel = false;
                TLRPC.Chat chat = this.currentChat;
                if (chat != null) {
                    isChannel = ChatObject.isChannel(chat) && !this.currentChat.megagroup;
                }
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                String key = isChannel ? "needShowRoundHintChannel" : "needShowRoundHint";
                if (preferences.getBoolean(key, true) && Utilities.random.nextFloat() < 0.2f) {
                    showVoiceHint(false, this.chatActivityEnterView.isInVideoMode());
                    preferences.edit().putBoolean(key, false).commit();
                }
            }
            if (!backward && this.parentLayout != null) {
                int a = 0;
                int N = this.parentLayout.fragmentsStack.size() - 1;
                while (true) {
                    if (a >= N) {
                        break;
                    }
                    BaseFragment fragment = this.parentLayout.fragmentsStack.get(a);
                    if (fragment != this && (fragment instanceof ChatActivity)) {
                        ChatActivity chatActivity = (ChatActivity) fragment;
                        if (chatActivity.dialog_id == this.dialog_id && chatActivity.inScheduleMode == this.inScheduleMode) {
                            fragment.removeSelfFromStack();
                            break;
                        }
                    }
                    a++;
                }
            }
            if (!isFinishing() && getParentActivity() != null && this.parentLayout != null && !this.parentLayout.fragmentsStack.isEmpty() && this.parentLayout.fragmentsStack.get(this.parentLayout.fragmentsStack.size() - 1) == this) {
                TLRPC.Chat chat2 = this.currentChat;
                if ((chat2 instanceof TLRPC.TL_channelForbidden) || (chat2 instanceof TLRPC.TL_chatForbidden)) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    builder.setMessage(LocaleController.getString("ChannelCantOpenNa", R.string.ChannelCantOpenNa));
                    builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                    AlertDialog alertDialogCreate = builder.create();
                    this.closeChatDialog = alertDialogCreate;
                    showDialog(alertDialogCreate);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) throws Exception {
        Dialog dialog2 = this.closeChatDialog;
        if (dialog2 != null && dialog == dialog2) {
            getMessagesController().deleteDialog(this.dialog_id, 0);
            if (this.parentLayout != null && !this.parentLayout.fragmentsStack.isEmpty() && this.parentLayout.fragmentsStack.get(this.parentLayout.fragmentsStack.size() - 1) != this) {
                BaseFragment fragment = this.parentLayout.fragmentsStack.get(this.parentLayout.fragmentsStack.size() - 1);
                removeSelfFromStack();
                fragment.finishFragment();
                return;
            }
            finishFragment();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean extendActionMode(Menu menu) {
        if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isVisible()) {
            if (PhotoViewer.getInstance().getSelectiongLength() == 0 || menu.findItem(android.R.id.copy) == null) {
                return true;
            }
        } else if (this.chatActivityEnterView.getSelectionLength() == 0 || menu.findItem(android.R.id.copy) == null) {
            return true;
        }
        if (Build.VERSION.SDK_INT >= 23) {
            menu.removeItem(android.R.id.shareText);
        }
        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(LocaleController.getString("Bold", R.string.Bold));
        stringBuilder.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf")), 0, stringBuilder.length(), 33);
        menu.add(R.attr.menu_groupbolditalic, R.attr.menu_bold, 6, stringBuilder);
        SpannableStringBuilder stringBuilder2 = new SpannableStringBuilder(LocaleController.getString("Italic", R.string.Italic));
        stringBuilder2.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/ritalic.ttf")), 0, stringBuilder2.length(), 33);
        menu.add(R.attr.menu_groupbolditalic, R.attr.menu_italic, 7, stringBuilder2);
        SpannableStringBuilder stringBuilder3 = new SpannableStringBuilder(LocaleController.getString("Mono", R.string.Mono));
        stringBuilder3.setSpan(new TypefaceSpan(Typeface.MONOSPACE), 0, stringBuilder3.length(), 33);
        menu.add(R.attr.menu_groupbolditalic, R.attr.menu_mono, 8, stringBuilder3);
        TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
        if (encryptedChat == null || (encryptedChat != null && AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) >= 101)) {
            SpannableStringBuilder stringBuilder4 = new SpannableStringBuilder(LocaleController.getString("Strike", R.string.Strike));
            TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
            run.flags = 8 | run.flags;
            stringBuilder4.setSpan(new TextStyleSpan(run), 0, stringBuilder4.length(), 33);
            menu.add(R.attr.menu_groupbolditalic, R.attr.menu_strike, 9, stringBuilder4);
            SpannableStringBuilder stringBuilder5 = new SpannableStringBuilder(LocaleController.getString("Underline", R.string.Underline));
            TextStyleSpan.TextStyleRun run2 = new TextStyleSpan.TextStyleRun();
            run2.flags |= 16;
            stringBuilder5.setSpan(new TextStyleSpan(run2), 0, stringBuilder5.length(), 33);
            menu.add(R.attr.menu_groupbolditalic, R.attr.menu_underline, 10, stringBuilder5);
        }
        menu.add(R.attr.menu_groupbolditalic, R.attr.menu_link, 11, LocaleController.getString("CreateLink", R.string.CreateLink));
        menu.add(R.attr.menu_groupbolditalic, R.attr.menu_regular, 12, LocaleController.getString("Regular", R.string.Regular));
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateScheduledInterface(boolean animated) {
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.updateScheduleButton(animated);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00cc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void updateBottomOverlay() {
        /*
            Method dump skipped, instruction units count: 741
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.updateBottomOverlay():void");
    }

    public /* synthetic */ void lambda$updateBottomOverlay$72$ChatActivity() {
        this.chatActivityEnterView.openKeyboard();
    }

    public void showAlert(String name, String message) {
        FrameLayout frameLayout = this.alertView;
        if (frameLayout == null || name == null || message == null) {
            return;
        }
        if (frameLayout.getTag() != null) {
            this.alertView.setTag(null);
            AnimatorSet animatorSet = this.alertViewAnimator;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.alertViewAnimator = null;
            }
            this.alertView.setVisibility(0);
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.alertViewAnimator = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.alertView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
            this.alertViewAnimator.setDuration(200L);
            this.alertViewAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.59
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatActivity.this.alertViewAnimator != null && ChatActivity.this.alertViewAnimator.equals(animation)) {
                        ChatActivity.this.alertViewAnimator = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (ChatActivity.this.alertViewAnimator != null && ChatActivity.this.alertViewAnimator.equals(animation)) {
                        ChatActivity.this.alertViewAnimator = null;
                    }
                }
            });
            this.alertViewAnimator.start();
        }
        this.alertNameTextView.setText(name);
        this.alertTextView.setText(Emoji.replaceEmoji(message.replace('\n', ' '), this.alertTextView.getPaint().getFontMetricsInt(), AndroidUtilities.dp(14.0f), false));
        Runnable runnable = this.hideAlertViewRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
        }
        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.ChatActivity.60
            @Override // java.lang.Runnable
            public void run() {
                if (ChatActivity.this.hideAlertViewRunnable == this && ChatActivity.this.alertView.getTag() == null) {
                    ChatActivity.this.alertView.setTag(1);
                    if (ChatActivity.this.alertViewAnimator != null) {
                        ChatActivity.this.alertViewAnimator.cancel();
                        ChatActivity.this.alertViewAnimator = null;
                    }
                    ChatActivity.this.alertViewAnimator = new AnimatorSet();
                    ChatActivity.this.alertViewAnimator.playTogether(ObjectAnimator.ofFloat(ChatActivity.this.alertView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(50.0f)));
                    ChatActivity.this.alertViewAnimator.setDuration(200L);
                    ChatActivity.this.alertViewAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.60.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (ChatActivity.this.alertViewAnimator != null && ChatActivity.this.alertViewAnimator.equals(animation)) {
                                ChatActivity.this.alertView.setVisibility(8);
                                ChatActivity.this.alertViewAnimator = null;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (ChatActivity.this.alertViewAnimator != null && ChatActivity.this.alertViewAnimator.equals(animation)) {
                                ChatActivity.this.alertViewAnimator = null;
                            }
                        }
                    });
                    ChatActivity.this.alertViewAnimator.start();
                }
            }
        };
        this.hideAlertViewRunnable = runnable2;
        AndroidUtilities.runOnUIThread(runnable2, 3000L);
    }

    private void hidePinnedMessageView(boolean animated) {
        if (this.pinnedMessageView.getTag() == null) {
            this.pinnedMessageView.setTag(1);
            AnimatorSet animatorSet = this.pinnedMessageViewAnimator;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.pinnedMessageViewAnimator = null;
            }
            if (!animated) {
                this.pinnedMessageView.setTranslationY(-AndroidUtilities.dp(50.0f));
                this.pinnedMessageView.setVisibility(8);
                if (this.pinnedLiveMessage != null) {
                    this.pinnedLiveMessageView.setTranslationY(0.0f);
                    this.pinnedLiveUserImageView.setTranslationY(0.0f);
                    return;
                }
                return;
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.pinnedMessageViewAnimator = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.pinnedMessageView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(50.0f)));
            this.pinnedMessageViewAnimator.setDuration(200L);
            this.pinnedMessageViewAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.61
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatActivity.this.pinnedMessageViewAnimator != null && ChatActivity.this.pinnedMessageViewAnimator.equals(animation)) {
                        ChatActivity.this.pinnedMessageView.setVisibility(8);
                        if (ChatActivity.this.pinnedLiveMessage != null) {
                            ChatActivity.this.pinnedLiveMessageView.setTranslationY(0.0f);
                            ChatActivity.this.pinnedLiveUserImageView.setTranslationY(0.0f);
                        }
                        ChatActivity.this.pinnedMessageViewAnimator = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (ChatActivity.this.pinnedMessageViewAnimator != null && ChatActivity.this.pinnedMessageViewAnimator.equals(animation)) {
                        ChatActivity.this.pinnedMessageViewAnimator = null;
                    }
                }
            });
            this.pinnedMessageViewAnimator.start();
        }
    }

    private void hidePinnedLiveMessageView(boolean animated) {
        this.pinnedLiveMessage = null;
        if (this.pinnedLiveMessageView.getTag() == null) {
            this.pinnedLiveMessageView.setTag(2);
            AnimatorSet animatorSet = this.pinnedMessageViewAnimator;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.pinnedMessageViewAnimator = null;
            }
            if (!animated) {
                this.pinnedLiveMessageView.setTranslationY(-AndroidUtilities.dp(50.0f));
                this.pinnedLiveMessageView.setVisibility(8);
                return;
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.pinnedMessageViewAnimator = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.pinnedLiveMessageView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(50.0f)));
            this.pinnedMessageViewAnimator.setDuration(200L);
            this.pinnedMessageViewAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.62
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatActivity.this.pinnedMessageViewAnimator != null && ChatActivity.this.pinnedMessageViewAnimator.equals(animation)) {
                        ChatActivity.this.pinnedLiveMessageView.setVisibility(8);
                        ChatActivity.this.pinnedMessageViewAnimator = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (ChatActivity.this.pinnedMessageViewAnimator != null && ChatActivity.this.pinnedMessageViewAnimator.equals(animation)) {
                        ChatActivity.this.pinnedMessageViewAnimator = null;
                    }
                }
            });
            this.pinnedMessageViewAnimator.start();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0385  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void updatePinnedMessageView(boolean r25) {
        /*
            Method dump skipped, instruction units count: 909
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.updatePinnedMessageView(boolean):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x00ac  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void updatePinnedLiveMessageView(boolean r8, int r9, boolean r10) {
        /*
            Method dump skipped, instruction units count: 251
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.updatePinnedLiveMessageView(boolean, int, boolean):void");
    }

    private void updateTopPanel(boolean animated) {
        boolean show;
        int i;
        int i2;
        if (this.topChatPanelView == null || this.inScheduleMode) {
            return;
        }
        SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
        long did = this.dialog_id;
        TLRPC.EncryptedChat encryptedChat = this.currentEncryptedChat;
        if (encryptedChat != null) {
            show = (encryptedChat.admin_id == getUserConfig().getClientUserId() || getContactsController().isLoadingContacts() || getContactsController().contactsDict.get(Integer.valueOf(this.currentUser.id)) != null) ? false : true;
            did = this.currentUser.id;
            int vis = preferences.getInt("dialog_bar_vis3" + did, 0);
            if (show && (vis == 1 || vis == 3)) {
                show = false;
            }
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("dialog_bar_vis3");
            sb.append(did);
            show = preferences.getInt(sb.toString(), 0) == 2;
        }
        boolean showShare = preferences.getBoolean("dialog_bar_share" + did, false);
        boolean showReport = preferences.getBoolean("dialog_bar_report" + did, false);
        boolean showBlock = preferences.getBoolean("dialog_bar_block" + did, false);
        boolean showAdd = preferences.getBoolean("dialog_bar_add" + did, false);
        boolean showGeo = preferences.getBoolean("dialog_bar_location" + did, false);
        if (!showReport && !showBlock && !showGeo) {
            this.reportSpamButton.setVisibility(8);
        } else {
            this.reportSpamButton.setVisibility(0);
        }
        TLRPC.User user = this.currentUser != null ? getMessagesController().getUser(Integer.valueOf(this.currentUser.id)) : null;
        if (user != null) {
            if (!user.contact && showAdd) {
                this.addContactItem.setVisibility(0);
                this.addToContactsButton.setVisibility(0);
                this.addContactItem.setText(LocaleController.getString("AddToContacts", R.string.AddToContacts));
                if (this.reportSpamButton.getVisibility() == 0) {
                    this.addToContactsButton.setText(LocaleController.getString("AddContactChat", R.string.AddContactChat));
                } else {
                    this.addToContactsButton.setText(LocaleController.formatString("AddContactFullChat", R.string.AddContactFullChat, UserObject.getFirstName(user)).toUpperCase());
                }
                this.addToContactsButton.setTag(null);
                this.addToContactsButton.setVisibility(0);
            } else if (showShare) {
                this.addContactItem.setVisibility(0);
                this.addToContactsButton.setVisibility(0);
                this.addContactItem.setText(LocaleController.getString("ShareMyContactInfo", R.string.ShareMyContactInfo));
                this.addToContactsButton.setText(LocaleController.getString("ShareMyPhone", R.string.ShareMyPhone).toUpperCase());
                this.addToContactsButton.setTag(1);
                this.addToContactsButton.setVisibility(0);
            } else {
                if (!user.contact && !show) {
                    this.addContactItem.setVisibility(0);
                    this.addContactItem.setText(LocaleController.getString("ShareMyContactInfo", R.string.ShareMyContactInfo));
                    this.addToContactsButton.setTag(2);
                    i2 = 8;
                } else {
                    i2 = 8;
                    this.addContactItem.setVisibility(8);
                }
                this.addToContactsButton.setVisibility(i2);
            }
            this.reportSpamButton.setText(LocaleController.getString("ReportSpamUser", R.string.ReportSpamUser));
            i = 8;
        } else {
            if (showGeo) {
                this.reportSpamButton.setText(LocaleController.getString("ReportSpamLocation", R.string.ReportSpamLocation));
                this.reportSpamButton.setTag(R.attr.object_tag, 1);
                this.reportSpamButton.setTextColor(Theme.getColor(Theme.key_chat_addContact));
                this.reportSpamButton.setTag(Theme.key_chat_addContact);
            } else {
                this.reportSpamButton.setText(LocaleController.getString("ReportSpamAndLeave", R.string.ReportSpamAndLeave));
                this.reportSpamButton.setTag(R.attr.object_tag, null);
                this.reportSpamButton.setTextColor(Theme.getColor(Theme.key_chat_reportSpam));
                this.reportSpamButton.setTag(Theme.key_chat_reportSpam);
            }
            ChatActionBarMenuSubItem chatActionBarMenuSubItem = this.addContactItem;
            if (chatActionBarMenuSubItem == null) {
                i = 8;
            } else {
                i = 8;
                chatActionBarMenuSubItem.setVisibility(8);
            }
            this.addToContactsButton.setVisibility(i);
        }
        if (this.userBlocked || (this.addToContactsButton.getVisibility() == i && this.reportSpamButton.getVisibility() == i)) {
            show = false;
        }
        if (!show) {
            if (this.topChatPanelView.getTag() == null) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("hide spam button");
                }
                this.topChatPanelView.setTag(1);
                AnimatorSet animatorSet = this.reportSpamViewAnimator;
                if (animatorSet != null) {
                    animatorSet.cancel();
                    this.reportSpamViewAnimator = null;
                }
                if (!animated) {
                    this.topChatPanelView.setTranslationY(-AndroidUtilities.dp(50.0f));
                } else {
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.reportSpamViewAnimator = animatorSet2;
                    animatorSet2.playTogether(ObjectAnimator.ofFloat(this.topChatPanelView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(50.0f)));
                    this.reportSpamViewAnimator.setDuration(200L);
                    this.reportSpamViewAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.66
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (ChatActivity.this.reportSpamViewAnimator != null && ChatActivity.this.reportSpamViewAnimator.equals(animation)) {
                                ChatActivity.this.topChatPanelView.setVisibility(8);
                                ChatActivity.this.reportSpamViewAnimator = null;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (ChatActivity.this.reportSpamViewAnimator != null && ChatActivity.this.reportSpamViewAnimator.equals(animation)) {
                                ChatActivity.this.reportSpamViewAnimator = null;
                            }
                        }
                    });
                    this.reportSpamViewAnimator.start();
                }
            }
        } else if (this.topChatPanelView.getTag() != null) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("show spam button");
            }
            this.topChatPanelView.setTag(null);
            this.topChatPanelView.setVisibility(0);
            AnimatorSet animatorSet3 = this.reportSpamViewAnimator;
            if (animatorSet3 != null) {
                animatorSet3.cancel();
                this.reportSpamViewAnimator = null;
            }
            if (!animated) {
                this.topChatPanelView.setTranslationY(0.0f);
            } else {
                AnimatorSet animatorSet4 = new AnimatorSet();
                this.reportSpamViewAnimator = animatorSet4;
                animatorSet4.playTogether(ObjectAnimator.ofFloat(this.topChatPanelView, (Property<FrameLayout, Float>) View.TRANSLATION_Y, 0.0f));
                this.reportSpamViewAnimator.setDuration(200L);
                this.reportSpamViewAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.65
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ChatActivity.this.reportSpamViewAnimator != null && ChatActivity.this.reportSpamViewAnimator.equals(animation)) {
                            ChatActivity.this.reportSpamViewAnimator = null;
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (ChatActivity.this.reportSpamViewAnimator != null && ChatActivity.this.reportSpamViewAnimator.equals(animation)) {
                            ChatActivity.this.reportSpamViewAnimator = null;
                        }
                    }
                });
                this.reportSpamViewAnimator.start();
            }
        }
        checkListViewPaddings();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkListViewPaddingsInternal() {
        int pos;
        GridLayoutManagerFixed gridLayoutManagerFixed = this.chatLayoutManager;
        if (gridLayoutManagerFixed == null) {
            return;
        }
        try {
            int firstVisPos = gridLayoutManagerFixed.findFirstVisibleItemPosition();
            int lastVisPos = -1;
            if (!this.wasManualScroll && this.unreadMessageObject != null && (pos = this.messages.indexOf(this.unreadMessageObject)) >= 0) {
                lastVisPos = pos + this.chatAdapter.messagesStartRow;
                firstVisPos = -1;
            }
            int top = 0;
            if (firstVisPos != -1) {
                View firstVisView = this.chatLayoutManager.findViewByPosition(firstVisPos);
                top = firstVisView == null ? 0 : (this.chatListView.getMeasuredHeight() - firstVisView.getBottom()) - this.chatListView.getPaddingBottom();
            }
            if (this.chatListView.getPaddingTop() != AndroidUtilities.dp(52.0f) && ((this.pinnedMessageView != null && this.pinnedMessageView.getTag() == null) || (this.topChatPanelView != null && this.topChatPanelView.getTag() == null))) {
                this.chatListView.setPadding(0, AndroidUtilities.dp(52.0f), 0, AndroidUtilities.dp(3.0f));
                FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.floatingDateView.getLayoutParams();
                layoutParams.topMargin = AndroidUtilities.dp(52.0f);
                this.floatingDateView.setLayoutParams(layoutParams);
                this.chatListView.setTopGlowOffset(AndroidUtilities.dp(48.0f));
            } else if (this.chatListView.getPaddingTop() != AndroidUtilities.dp(4.0f) && ((this.pinnedMessageView == null || this.pinnedMessageView.getTag() != null) && (this.topChatPanelView == null || this.topChatPanelView.getTag() != null))) {
                this.chatListView.setPadding(0, AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(3.0f));
                FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.floatingDateView.getLayoutParams();
                layoutParams2.topMargin = AndroidUtilities.dp(4.0f);
                this.floatingDateView.setLayoutParams(layoutParams2);
                this.chatListView.setTopGlowOffset(0);
            } else {
                firstVisPos = -1;
            }
            if (firstVisPos != -1) {
                this.chatLayoutManager.scrollToPositionWithOffset(firstVisPos, top);
            } else if (lastVisPos != -1) {
                int top2 = ((this.chatListView.getMeasuredHeight() - this.chatListView.getPaddingBottom()) - this.chatListView.getPaddingTop()) - AndroidUtilities.dp(29.0f);
                this.chatLayoutManager.scrollToPositionWithOffset(lastVisPos, top2);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void checkListViewPaddings() {
        MessageObject messageObject;
        if (!this.wasManualScroll && (messageObject = this.unreadMessageObject) != null) {
            int pos = this.messages.indexOf(messageObject);
            if (pos >= 0) {
                this.fixPaddingsInLayout = true;
                if (this.fragmentView != null) {
                    this.fragmentView.requestLayout();
                    return;
                }
                return;
            }
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$LG-WxdS_8D1ersZOLWXYyAlYIHo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.checkListViewPaddingsInternal();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkRaiseSensors() {
        FrameLayout frameLayout;
        FrameLayout frameLayout2;
        FrameLayout frameLayout3;
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null && chatActivityEnterView.isStickersExpanded()) {
            MediaController.getInstance().setAllowStartRecord(false);
            return;
        }
        TLRPC.Chat chat = this.currentChat;
        if (chat != null && !ChatObject.canSendMedia(chat)) {
            MediaController.getInstance().setAllowStartRecord(false);
            return;
        }
        if (!ApplicationLoader.mainInterfacePaused && (((frameLayout = this.bottomOverlayChat) == null || frameLayout.getVisibility() != 0) && (((frameLayout2 = this.bottomOverlay) == null || frameLayout2.getVisibility() != 0) && ((frameLayout3 = this.searchContainer) == null || frameLayout3.getVisibility() != 0)))) {
            MediaController.getInstance().setAllowStartRecord(true);
        } else {
            MediaController.getInstance().setAllowStartRecord(false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void dismissCurrentDialog() {
        if (this.chatAttachAlert != null) {
            Dialog dialog = this.visibleDialog;
            ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
            if (dialog == chatAttachAlert) {
                chatAttachAlert.closeCamera(false);
                this.chatAttachAlert.dismissInternal();
                this.chatAttachAlert.hideCamera(true);
                return;
            }
        }
        super.dismissCurrentDialog();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void setInPreviewMode(boolean value) {
        super.setInPreviewMode(value);
        ChatActionBarHelper chatActionBarHelper = this.actionBarHelper;
        if (chatActionBarHelper != null) {
            chatActionBarHelper.setInPreviewMode(value);
        }
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.setVisibility(!value ? 0 : 4);
        }
        if (this.actionBar != null) {
            this.actionBar.setBackButtonImage(!value ? R.id.ic_back : 0);
            this.headerItem.setAlpha(!value ? 1.0f : 0.0f);
            this.attachItem.setAlpha(value ? 0.0f : 1.0f);
        }
        RecyclerListView recyclerListView = this.chatListView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View view = this.chatListView.getChildAt(a);
                MessageObject message = null;
                if (view instanceof ChatMessageCell) {
                    message = ((ChatMessageCell) view).getMessageObject();
                } else if (view instanceof ChatActionCell) {
                    message = ((ChatActionCell) view).getMessageObject();
                }
                if (message != null && message.messageOwner != null && message.messageOwner.media_unread && message.messageOwner.mentioned) {
                    if (!message.isVoice() && !message.isRoundVideo()) {
                        int i = this.newMentionsCount - 1;
                        this.newMentionsCount = i;
                        if (i <= 0) {
                            this.newMentionsCount = 0;
                            this.hasAllMentionsLocal = true;
                            showMentionDownButton(false, true);
                        } else {
                            this.mentiondownButtonCounter.setText(String.format("%d", Integer.valueOf(i)));
                        }
                        getMessagesController().markMentionMessageAsRead(message.getId(), ChatObject.isChannel(this.currentChat) ? this.currentChat.id : 0, this.dialog_id);
                        message.setContentIsRead();
                    }
                    if (view instanceof ChatMessageCell) {
                        ((ChatMessageCell) view).setHighlighted(false);
                        ((ChatMessageCell) view).setHighlightedAnimated();
                    }
                }
            }
        }
        updateBottomOverlay();
        updateSecretStatus();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        ChatActivityEnterView chatActivityEnterView;
        MessageObject messageObject;
        int yOffset;
        BackupImageView backupImageView;
        BackupImageView backupImageView2;
        super.onResume();
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
        MediaController.getInstance().startRaiseToEarSensors(this);
        checkRaiseSensors();
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            chatAttachAlert.onResume();
        }
        SizeNotifierFrameLayout sizeNotifierFrameLayout = this.contentView;
        if (sizeNotifierFrameLayout != null) {
            sizeNotifierFrameLayout.onResume();
        }
        if (this.firstOpen && getMessagesController().isProxyDialog(this.dialog_id, true)) {
            SharedPreferences preferences = MessagesController.getGlobalNotificationsSettings();
            if (preferences.getLong("proxychannel", 0L) != this.dialog_id) {
                preferences.edit().putLong("proxychannel", this.dialog_id).commit();
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("UseProxySponsorInfo", R.string.UseProxySponsorInfo));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                showDialog(builder.create());
            }
        }
        checkActionBarMenu();
        TLRPC.PhotoSize photoSize = this.replyImageLocation;
        if (photoSize != null && (backupImageView2 = this.replyImageView) != null) {
            backupImageView2.setImage(ImageLocation.getForObject(photoSize, this.replyImageLocationObject), "50_50", ImageLocation.getForObject(this.replyImageThumbLocation, this.replyImageLocationObject), "50_50_b", null, this.replyImageSize, this.replyImageCacheType, this.replyingMessageObject);
        }
        TLRPC.PhotoSize photoSize2 = this.pinnedImageLocation;
        if (photoSize2 != null && (backupImageView = this.pinnedMessageImageView) != null) {
            backupImageView.setImage(ImageLocation.getForObject(photoSize2, this.pinnedImageLocationObject), "50_50", ImageLocation.getForObject(this.pinnedImageThumbLocation, this.pinnedImageLocationObject), "50_50_b", null, this.pinnedImageSize, this.pinnedImageCacheType, this.pinnedMessageObject);
        }
        if (!this.inScheduleMode) {
            getNotificationsController().setOpenedDialogId(this.dialog_id);
        }
        getMessagesController().setLastVisibleDialogId(this.dialog_id, this.inScheduleMode, true);
        if (this.scrollToTopOnResume) {
            if (this.scrollToTopUnReadOnResume && (messageObject = this.scrollToMessage) != null) {
                if (this.chatListView != null) {
                    boolean bottom = true;
                    int i = this.scrollToMessagePosition;
                    if (i == -9000) {
                        yOffset = getScrollOffsetForMessage(messageObject);
                        bottom = false;
                    } else if (i == -10000) {
                        yOffset = -AndroidUtilities.dp(11.0f);
                        bottom = false;
                    } else {
                        yOffset = this.scrollToMessagePosition;
                    }
                    this.chatLayoutManager.scrollToPositionWithOffset(this.chatAdapter.messagesStartRow + this.messages.indexOf(this.scrollToMessage), yOffset, bottom);
                }
            } else {
                moveScrollToLastMessage();
            }
            this.scrollToTopUnReadOnResume = false;
            this.scrollToTopOnResume = false;
            this.scrollToMessage = null;
        }
        this.paused = false;
        this.pausedOnLastMessage = false;
        checkScrollForLoad(false);
        if (this.wasPaused) {
            this.wasPaused = false;
            ChatActivityAdapter chatActivityAdapter = this.chatAdapter;
            if (chatActivityAdapter != null) {
                chatActivityAdapter.notifyDataSetChanged();
            }
        }
        applyDraftMaybe(false);
        FrameLayout frameLayout = this.bottomOverlayChat;
        if (frameLayout != null && frameLayout.getVisibility() != 0 && !this.actionBar.isSearchFieldVisible()) {
            this.chatActivityEnterView.setFieldFocused(true);
        }
        ChatActivityEnterView chatActivityEnterView2 = this.chatActivityEnterView;
        if (chatActivityEnterView2 != null) {
            chatActivityEnterView2.onResume();
        }
        if (this.currentUser != null) {
            this.chatEnterTime = System.currentTimeMillis();
            this.chatLeaveTime = 0L;
        }
        if (this.startVideoEdit != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$0A-thKpgpHP8otqM61pHp9uSpfg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResume$73$ChatActivity();
                }
            });
        }
        if (this.chatListView != null && ((chatActivityEnterView = this.chatActivityEnterView) == null || !chatActivityEnterView.isEditingMessage())) {
            this.chatListView.setOnItemLongClickListener(this.onItemLongClickListener);
            this.chatListView.setOnItemClickListener(this.onItemClickListener);
            this.chatListView.setLongClickable(true);
        }
        checkBotCommands();
        ChatActionBarHelper chatActionBarHelper = this.actionBarHelper;
        if (chatActionBarHelper != null) {
            chatActionBarHelper.updateTitle();
        }
    }

    public /* synthetic */ void lambda$onResume$73$ChatActivity() {
        openVideoEditor(this.startVideoEdit, null);
        this.startVideoEdit = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void finishFragment() {
        super.finishFragment();
        ActionBarPopupWindow actionBarPopupWindow = this.scrimPopupWindow;
        if (actionBarPopupWindow != null) {
            actionBarPopupWindow.dismiss();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        int position;
        RecyclerListView.Holder holder;
        CharSequence draftMessage;
        super.onPause();
        ActionBarPopupWindow actionBarPopupWindow = this.scrimPopupWindow;
        if (actionBarPopupWindow != null) {
            actionBarPopupWindow.dismiss();
        }
        getMessagesController().markDialogAsReadNow(this.dialog_id);
        MediaController.getInstance().stopRaiseToEarSensors(this, true);
        this.paused = true;
        this.wasPaused = true;
        if (!this.inScheduleMode) {
            getNotificationsController().setOpenedDialogId(0L);
        }
        getMessagesController().setLastVisibleDialogId(this.dialog_id, this.inScheduleMode, false);
        CharSequence draftMessage2 = null;
        MessageObject replyMessage = null;
        boolean searchWebpage = true;
        if (!this.ignoreAttachOnPause && this.chatActivityEnterView != null && this.bottomOverlayChat.getVisibility() != 0) {
            this.chatActivityEnterView.onPause();
            replyMessage = this.replyingMessageObject;
            if (!this.chatActivityEnterView.isEditingMessage()) {
                CharSequence fieldText = this.chatActivityEnterView.getFieldText();
                if (!TextUtils.isEmpty(fieldText)) {
                    if (fieldText.toString().endsWith(" ")) {
                        SpannableStringBuilder builder = new SpannableStringBuilder(AndroidUtilities.getTrimmedString(fieldText));
                        builder.append((CharSequence) " ");
                        draftMessage2 = builder;
                    } else {
                        draftMessage2 = AndroidUtilities.getTrimmedString(this.chatActivityEnterView.getFieldText());
                    }
                }
            }
            searchWebpage = this.chatActivityEnterView.isMessageWebPageSearchEnabled();
            this.chatActivityEnterView.setFieldFocused(false);
        }
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            if (!this.ignoreAttachOnPause) {
                chatAttachAlert.onPause();
            } else {
                this.ignoreAttachOnPause = false;
            }
        }
        SizeNotifierFrameLayout sizeNotifierFrameLayout = this.contentView;
        if (sizeNotifierFrameLayout != null) {
            sizeNotifierFrameLayout.onPause();
        }
        if (!this.inScheduleMode) {
            CharSequence[] message = {draftMessage2};
            ArrayList<TLRPC.MessageEntity> entities = getMediaDataController().getEntities(message);
            getMediaDataController().saveDraft(this.dialog_id, message[0], entities, replyMessage != null ? replyMessage.messageOwner : null, !searchWebpage);
            getMessagesController().cancelTyping(0, this.dialog_id);
            if (!this.pausedOnLastMessage) {
                SharedPreferences.Editor editor = MessagesController.getNotificationsSettings(this.currentAccount).edit();
                int messageId = 0;
                int offset = 0;
                GridLayoutManagerFixed gridLayoutManagerFixed = this.chatLayoutManager;
                if (gridLayoutManagerFixed != null && (position = gridLayoutManagerFixed.findFirstVisibleItemPosition()) != 0 && (holder = (RecyclerListView.Holder) this.chatListView.findViewHolderForAdapterPosition(position)) != null) {
                    int mid = 0;
                    if (holder.itemView instanceof ChatMessageCell) {
                        mid = ((ChatMessageCell) holder.itemView).getMessageObject().getId();
                    } else if (holder.itemView instanceof ChatActionCell) {
                        mid = ((ChatActionCell) holder.itemView).getMessageObject().getId();
                    }
                    if (mid == 0) {
                        holder = (RecyclerListView.Holder) this.chatListView.findViewHolderForAdapterPosition(position + 1);
                    }
                    boolean ignore = false;
                    int count = 0;
                    int a = position - 1;
                    while (a >= this.chatAdapter.messagesStartRow) {
                        int num = a - this.chatAdapter.messagesStartRow;
                        if (num >= 0) {
                            draftMessage = draftMessage2;
                            if (num >= this.messages.size()) {
                                continue;
                            } else {
                                MessageObject messageObject = this.messages.get(num);
                                if (messageObject.getId() != 0) {
                                    if (!messageObject.isOut() || messageObject.messageOwner.from_scheduled) {
                                        if (messageObject.isUnread()) {
                                            ignore = true;
                                            messageId = 0;
                                        }
                                    }
                                    if (count > 2) {
                                        break;
                                    } else {
                                        count++;
                                    }
                                } else {
                                    continue;
                                }
                            }
                        } else {
                            draftMessage = draftMessage2;
                        }
                        a--;
                        draftMessage2 = draftMessage;
                    }
                    if (holder != null && !ignore) {
                        if (holder.itemView instanceof ChatMessageCell) {
                            messageId = ((ChatMessageCell) holder.itemView).getMessageObject().getId();
                        } else if (holder.itemView instanceof ChatActionCell) {
                            messageId = ((ChatActionCell) holder.itemView).getMessageObject().getId();
                        }
                        if ((messageId > 0 && this.currentEncryptedChat == null) || (messageId < 0 && this.currentEncryptedChat != null)) {
                            offset = holder.itemView.getBottom() - this.chatListView.getMeasuredHeight();
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("save offset = " + offset + " for mid " + messageId);
                            }
                        } else {
                            messageId = 0;
                        }
                    }
                }
                if (messageId == 0) {
                    this.pausedOnLastMessage = true;
                    editor.remove("diditem" + this.dialog_id);
                    editor.remove("diditemo" + this.dialog_id);
                } else {
                    editor.putInt("diditem" + this.dialog_id, messageId);
                    editor.putInt("diditemo" + this.dialog_id, offset);
                }
                editor.commit();
            }
            if (this.currentUser != null) {
                this.chatLeaveTime = System.currentTimeMillis();
                updateInformationForScreenshotDetector();
            }
            UndoView undoView = this.undoView;
            if (undoView != null) {
                undoView.hide(true, 0);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v10, types: [android.text.Spannable, android.text.SpannableStringBuilder] */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r1v8, types: [java.lang.CharSequence] */
    /* JADX WARN: Type inference failed for: r3v4, types: [im.uwrkaxlmjj.ui.components.ChatActivityEnterView] */
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
    private void applyDraftMaybe(boolean canClear) {
        ?? ValueOf;
        int user_id;
        if (this.chatActivityEnterView == null || this.inScheduleMode) {
            return;
        }
        TLRPC.DraftMessage draftMessage = getMediaDataController().getDraft(this.dialog_id);
        TLRPC.Message draftReplyMessage = (draftMessage == null || draftMessage.reply_to_msg_id == 0) ? null : getMediaDataController().getDraftMessage(this.dialog_id);
        if (this.chatActivityEnterView.getFieldText() == null) {
            if (draftMessage != null) {
                this.chatActivityEnterView.setWebPage(null, !draftMessage.no_webpage);
                if (!draftMessage.entities.isEmpty()) {
                    ValueOf = SpannableStringBuilder.valueOf(draftMessage.message);
                    MediaDataController.sortEntities(draftMessage.entities);
                    for (int a = 0; a < draftMessage.entities.size(); a++) {
                        TLRPC.MessageEntity entity = draftMessage.entities.get(a);
                        if ((entity instanceof TLRPC.TL_inputMessageEntityMentionName) || (entity instanceof TLRPC.TL_messageEntityMentionName)) {
                            if (entity instanceof TLRPC.TL_inputMessageEntityMentionName) {
                                user_id = ((TLRPC.TL_inputMessageEntityMentionName) entity).user_id.user_id;
                            } else {
                                user_id = ((TLRPC.TL_messageEntityMentionName) entity).user_id;
                            }
                            if (entity.offset + entity.length < ValueOf.length() && ValueOf.charAt(entity.offset + entity.length) == ' ') {
                                entity.length++;
                            }
                            ValueOf.setSpan(new URLSpanUserMention("" + user_id, 1), entity.offset, entity.offset + entity.length, 33);
                        } else if ((entity instanceof TLRPC.TL_messageEntityCode) || (entity instanceof TLRPC.TL_messageEntityPre)) {
                            TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
                            run.flags |= 4;
                            MediaDataController.addStyleToText(new TextStyleSpan(run), entity.offset, entity.offset + entity.length, ValueOf, true);
                        } else if (entity instanceof TLRPC.TL_messageEntityBold) {
                            TextStyleSpan.TextStyleRun run2 = new TextStyleSpan.TextStyleRun();
                            run2.flags |= 1;
                            MediaDataController.addStyleToText(new TextStyleSpan(run2), entity.offset, entity.offset + entity.length, ValueOf, true);
                        } else if (entity instanceof TLRPC.TL_messageEntityItalic) {
                            TextStyleSpan.TextStyleRun run3 = new TextStyleSpan.TextStyleRun();
                            run3.flags |= 2;
                            MediaDataController.addStyleToText(new TextStyleSpan(run3), entity.offset, entity.offset + entity.length, ValueOf, true);
                        } else if (entity instanceof TLRPC.TL_messageEntityStrike) {
                            TextStyleSpan.TextStyleRun run4 = new TextStyleSpan.TextStyleRun();
                            run4.flags |= 8;
                            MediaDataController.addStyleToText(new TextStyleSpan(run4), entity.offset, entity.offset + entity.length, ValueOf, true);
                        } else if (entity instanceof TLRPC.TL_messageEntityUnderline) {
                            TextStyleSpan.TextStyleRun run5 = new TextStyleSpan.TextStyleRun();
                            run5.flags |= 16;
                            MediaDataController.addStyleToText(new TextStyleSpan(run5), entity.offset, entity.offset + entity.length, ValueOf, true);
                        } else if (entity instanceof TLRPC.TL_messageEntityTextUrl) {
                            ValueOf.setSpan(new URLSpanReplacement(entity.url), entity.offset, entity.offset + entity.length, 33);
                        }
                    }
                } else {
                    ValueOf = draftMessage.message;
                }
                this.chatActivityEnterView.setFieldText(ValueOf);
                if (getArguments().getBoolean("hasUrl", false)) {
                    this.chatActivityEnterView.setSelection(draftMessage.message.indexOf(10) + 1);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$5rmNMSnqPxk1FMupZ-r6Z-csCTc
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$applyDraftMaybe$74$ChatActivity();
                        }
                    }, 700L);
                }
            }
        } else if (canClear && draftMessage == null) {
            this.chatActivityEnterView.setFieldText("");
            hideFieldPanel(true);
        }
        if (this.replyingMessageObject == null && draftReplyMessage != null) {
            MessageObject messageObject = new MessageObject(this.currentAccount, draftReplyMessage, (AbstractMap<Integer, TLRPC.User>) getMessagesController().getUsers(), false);
            this.replyingMessageObject = messageObject;
            showFieldPanelForReply(messageObject);
        }
    }

    public /* synthetic */ void lambda$applyDraftMaybe$74$ChatActivity() {
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.setFieldFocused(true);
            this.chatActivityEnterView.openKeyboard();
        }
    }

    private void updateInformationForScreenshotDetector() {
        if (this.currentUser == null) {
            return;
        }
        if (this.currentEncryptedChat != null) {
            ArrayList<Long> visibleMessages = new ArrayList<>();
            RecyclerListView recyclerListView = this.chatListView;
            if (recyclerListView != null) {
                int count = recyclerListView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View view = this.chatListView.getChildAt(a);
                    MessageObject object = null;
                    if (view instanceof ChatMessageCell) {
                        ChatMessageCell cell = (ChatMessageCell) view;
                        object = cell.getMessageObject();
                    }
                    if (object != null && object.getId() < 0 && object.messageOwner.random_id != 0) {
                        visibleMessages.add(Long.valueOf(object.messageOwner.random_id));
                    }
                }
            }
            MediaController.getInstance().setLastVisibleMessageIds(this.currentAccount, this.chatEnterTime, this.chatLeaveTime, this.currentUser, this.currentEncryptedChat, visibleMessages, 0);
            return;
        }
        SecretMediaViewer viewer = SecretMediaViewer.getInstance();
        MessageObject messageObject = viewer.getCurrentMessageObject();
        if (messageObject != null && !messageObject.isOut()) {
            MediaController.getInstance().setLastVisibleMessageIds(this.currentAccount, viewer.getOpenTime(), viewer.getCloseTime(), this.currentUser, null, null, messageObject.getId());
        }
    }

    private boolean fixLayoutInternal() {
        MessageObject.GroupedMessages groupedMessages;
        if (!AndroidUtilities.isTablet() && ApplicationLoader.applicationContext.getResources().getConfiguration().orientation == 2) {
            this.selectedMessagesCountTextView.setTextSize(18);
        } else {
            this.selectedMessagesCountTextView.setTextSize(20);
        }
        HashMap<Long, MessageObject.GroupedMessages> newGroups = null;
        int count = this.chatListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.chatListView.getChildAt(a);
            if ((child instanceof ChatMessageCell) && (groupedMessages = ((ChatMessageCell) child).getCurrentMessagesGroup()) != null && groupedMessages.hasSibling) {
                if (newGroups == null) {
                    newGroups = new HashMap<>();
                }
                if (!newGroups.containsKey(Long.valueOf(groupedMessages.groupId))) {
                    newGroups.put(Long.valueOf(groupedMessages.groupId), groupedMessages);
                    MessageObject messageObject = groupedMessages.messages.get(groupedMessages.messages.size() - 1);
                    int idx = this.messages.indexOf(messageObject);
                    if (idx >= 0) {
                        ChatActivityAdapter chatActivityAdapter = this.chatAdapter;
                        chatActivityAdapter.notifyItemRangeChanged(chatActivityAdapter.messagesStartRow + idx, groupedMessages.messages.size());
                    }
                }
            }
        }
        if (!AndroidUtilities.isTablet()) {
            return true;
        }
        if (AndroidUtilities.isSmallTablet() && ApplicationLoader.applicationContext.getResources().getConfiguration().orientation == 1) {
            this.actionBar.setBackButtonImage(R.id.ic_back);
            FragmentContextView fragmentContextView = this.fragmentContextView;
            if (fragmentContextView != null && fragmentContextView.getParent() == null) {
                ((ViewGroup) this.fragmentView).addView(this.fragmentContextView, LayoutHelper.createFrame(-1.0f, 39.0f, 51, 0.0f, -36.0f, 0.0f, 0.0f));
            }
        } else {
            this.actionBar.setBackButtonImage(R.id.ic_back);
            FragmentContextView fragmentContextView2 = this.fragmentContextView;
            if (fragmentContextView2 != null && fragmentContextView2.getParent() != null) {
                this.fragmentView.setPadding(0, 0, 0, 0);
                ((ViewGroup) this.fragmentView).removeView(this.fragmentContextView);
            }
        }
        return false;
    }

    private void fixLayout() {
    }

    public boolean maybePlayVisibleVideo() {
        ImageReceiver imageReceiver;
        AnimatedFileDrawable animation;
        int top;
        int bottom;
        ChatMessageCell cell;
        ImageReceiver imageReceiver2;
        if (this.chatListView == null) {
            return false;
        }
        MessageObject playingMessage = MediaController.getInstance().getPlayingMessageObject();
        if (playingMessage != null && !playingMessage.isVideo()) {
            return false;
        }
        MessageObject visibleMessage = null;
        AnimatedFileDrawable visibleAnimation = null;
        HintView hintView = this.noSoundHintView;
        if (hintView != null && hintView.getTag() != null && (visibleAnimation = (imageReceiver2 = (cell = this.noSoundHintView.getMessageCell()).getPhotoImage()).getAnimation()) != null) {
            visibleMessage = cell.getMessageObject();
            this.scrollToVideo = cell.getTop() + imageReceiver2.getImageY2() > this.chatListView.getMeasuredHeight();
        }
        if (visibleMessage == null) {
            int count = this.chatListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.chatListView.getChildAt(a);
                if (child instanceof ChatMessageCell) {
                    ChatMessageCell messageCell = (ChatMessageCell) child;
                    MessageObject messageObject = messageCell.getMessageObject();
                    boolean isRoundVideo = messageObject.isRoundVideo();
                    if ((messageObject.isVideo() || isRoundVideo) && (animation = (imageReceiver = messageCell.getPhotoImage()).getAnimation()) != null && (bottom = imageReceiver.getImageHeight() + (top = child.getTop() + imageReceiver.getImageY())) >= 0 && top <= this.chatListView.getMeasuredHeight()) {
                        if (visibleMessage != null && top < 0) {
                            break;
                        }
                        visibleMessage = messageObject;
                        visibleAnimation = animation;
                        this.scrollToVideo = top < 0 || bottom > this.chatListView.getMeasuredHeight();
                        if (top >= 0 && bottom <= this.chatListView.getMeasuredHeight()) {
                            break;
                        }
                    }
                }
            }
        }
        if (visibleMessage == null || MediaController.getInstance().isPlayingMessage(visibleMessage)) {
            return false;
        }
        HintView hintView2 = this.noSoundHintView;
        if (hintView2 != null) {
            hintView2.hide();
        }
        HintView hintView3 = this.forwardHintView;
        if (hintView3 != null) {
            hintView3.hide();
        }
        if (visibleMessage.isRoundVideo()) {
            boolean result = MediaController.getInstance().playMessage(visibleMessage);
            MediaController.getInstance().setVoiceMessagesPlaylist(result ? createVoiceMessagesPlaylist(visibleMessage, false) : null, false);
            return result;
        }
        SharedConfig.setNoSoundHintShowed(true);
        visibleMessage.audioProgress = visibleAnimation.getCurrentProgress();
        visibleMessage.audioProgressMs = visibleAnimation.getCurrentProgressMs();
        visibleAnimation.stop();
        if (PhotoViewer.isPlayingMessageInPip(visibleMessage)) {
            PhotoViewer.getPipInstance().destroyPhotoViewer();
        }
        return MediaController.getInstance().playMessage(visibleMessage);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        MessageObject message;
        if (this.visibleDialog instanceof DatePickerDialog) {
            this.visibleDialog.dismiss();
        }
        ActionBarPopupWindow actionBarPopupWindow = this.scrimPopupWindow;
        if (actionBarPopupWindow != null) {
            actionBarPopupWindow.dismiss();
        }
        if (!AndroidUtilities.isTablet()) {
            if (newConfig.orientation == 2) {
                if ((!PhotoViewer.hasInstance() || !PhotoViewer.getInstance().isVisible()) && (message = MediaController.getInstance().getPlayingMessageObject()) != null && message.isVideo()) {
                    PhotoViewer.getInstance().setParentActivity(getParentActivity());
                    getFileLoader().setLoadingVideoForPlayer(message.getDocument(), false);
                    MediaController.getInstance().cleanupPlayer(true, true, false, true);
                    if (PhotoViewer.getInstance().openPhoto(message, message.type != 0 ? this.dialog_id : 0L, message.type != 0 ? this.mergeDialogId : 0L, this.photoViewerProvider, false)) {
                        PhotoViewer.getInstance().setParentChatActivity(this);
                    }
                    HintView hintView = this.noSoundHintView;
                    if (hintView != null) {
                        hintView.hide();
                    }
                    HintView hintView2 = this.forwardHintView;
                    if (hintView2 != null) {
                        hintView2.hide();
                    }
                    HintView hintView3 = this.slowModeHint;
                    if (hintView3 != null) {
                        hintView3.hide();
                    }
                    MediaController.getInstance().resetGoingToShowMessageObject();
                    return;
                }
                return;
            }
            if (PhotoViewer.hasInstance() && PhotoViewer.getInstance().isOpenedFullScreenVideo()) {
                PhotoViewer.getInstance().injectVideoPlayerToMediaController();
                PhotoViewer.getInstance().closePhoto(false, true);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createDeleteMessagesAlert(MessageObject finalSelectedObject, MessageObject.GroupedMessages selectedGroup) {
        createDeleteMessagesAlert(finalSelectedObject, selectedGroup, 1);
    }

    private void createDeleteMessagesAlert(MessageObject finalSelectedObject, MessageObject.GroupedMessages finalSelectedGroup, int loadParticipant) {
        AlertsCreator.createDeleteMessagesAlert(this, this.currentUser, this.currentChat, this.currentEncryptedChat, this.chatInfo, this.mergeDialogId, finalSelectedObject, this.selectedMessagesIds, finalSelectedGroup, this.inScheduleMode, loadParticipant, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$usxt5J6HAgL88L9xC4UAq6DrCso
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createDeleteMessagesAlert$75$ChatActivity();
            }
        });
    }

    public /* synthetic */ void lambda$createDeleteMessagesAlert$75$ChatActivity() {
        hideActionMode();
        updatePinnedMessageView(true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideActionMode() {
        if (!this.actionBar.isActionModeShowed()) {
            return;
        }
        if (this.actionBar != null) {
            this.actionBar.hideActionMode();
            this.actionBar.setBackButtonImage(R.id.ic_back);
        }
        this.cantDeleteMessagesCount = 0;
        this.canEditMessagesCount = 0;
        this.cantForwardMessagesCount = 0;
        this.cantCopyMessageCount = 0;
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            EditTextCaption editTextCaption = chatActivityEnterView.getEditField();
            editTextCaption.requestFocus();
            editTextCaption.setAllowDrawCursor(true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createMenu(View v, boolean single, boolean listView, float x, float y) {
        createMenu(v, single, listView, x, y, true);
    }

    private CharSequence getMessageCaption(MessageObject messageObject, MessageObject.GroupedMessages group) {
        if (messageObject.caption != null) {
            return messageObject.caption;
        }
        if (group == null) {
            return null;
        }
        CharSequence caption = null;
        int N = group.messages.size();
        for (int a = 0; a < N; a++) {
            MessageObject message = group.messages.get(a);
            if (message.caption != null) {
                if (caption != null) {
                    return null;
                }
                caption = message.caption;
            }
        }
        return caption;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void createMenu(final View v, boolean single, boolean listView, float x, float y, boolean searchGroup) {
        MessageObject message;
        MessageObject.GroupedMessages groupedMessages;
        boolean allowPin;
        TLRPC.UserFull userFull;
        boolean allowEdit;
        boolean allowChatActions;
        TLRPC.User user;
        TLRPC.Chat chat;
        TLRPC.User user2;
        Rect backgroundPaddings;
        ArrayList<Constants.ChatSelectionPopMenuEnum> options;
        ArrayList<CharSequence> items;
        ArrayList<Integer> icons;
        ScrollView scrollView;
        int popupY;
        TLRPC.EncryptedChat encryptedChat;
        FrameLayout frameLayout;
        TLRPC.Chat chat2;
        TLRPC.ChatFull chatFull;
        TLRPC.UserFull userFull2;
        if (this.actionBar.isActionModeShowed()) {
            return;
        }
        if (v instanceof ChatMessageCell) {
            MessageObject message2 = ((ChatMessageCell) v).getMessageObject();
            message = message2;
        } else if (!(v instanceof ChatActionCell)) {
            message = null;
        } else {
            MessageObject message3 = ((ChatActionCell) v).getMessageObject();
            message = message3;
        }
        if (message == null) {
            return;
        }
        if (message.messageOwner != null && message.messageOwner.action != null && (message.messageOwner.action instanceof TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer)) {
            return;
        }
        int type = getMessageType(message);
        if (!single || !(message.messageOwner.action instanceof TLRPC.TL_messageActionPinMessage)) {
            this.selectedObject = null;
            this.selectedObjectGroup = null;
            this.forwardingMessage = null;
            this.forwardingMessageGroup = null;
            this.selectedObjectToEditCaption = null;
            for (int a = 1; a >= 0; a--) {
                this.selectedMessagesCanCopyIds[a].clear();
                this.selectedMessagesCanStarIds[a].clear();
                this.selectedMessagesIds[a].clear();
            }
            hideActionMode();
            updatePinnedMessageView(true);
            if (searchGroup) {
                groupedMessages = getValidGroupedMessage(message);
            } else {
                groupedMessages = null;
            }
            if (this.inScheduleMode) {
                allowPin = false;
            } else if (this.currentChat != null) {
                allowPin = message.getDialogId() != this.mergeDialogId && ChatObject.canPinMessages(this.currentChat);
            } else if (this.currentEncryptedChat == null && (userFull = this.userInfo) != null) {
                allowPin = userFull.can_pin_message;
            } else {
                allowPin = false;
            }
            boolean allowPin2 = allowPin && message.getId() > 0 && (message.messageOwner.action == null || (message.messageOwner.action instanceof TLRPC.TL_messageActionEmpty));
            boolean allowUnpin = message.getDialogId() != this.mergeDialogId && allowPin2 && (((chatFull = this.chatInfo) != null && chatFull.pinned_msg_id == message.getId()) || ((userFull2 = this.userInfo) != null && userFull2.pinned_msg_id == message.getId()));
            boolean allowEdit2 = (!message.canEditMessage(this.currentChat) || this.chatActivityEnterView.hasAudioToSend() || message.getDialogId() == this.mergeDialogId) ? false : true;
            if (allowEdit2 && groupedMessages != null) {
                int captionsCount = 0;
                int N = groupedMessages.messages.size();
                for (int a2 = 0; a2 < N; a2++) {
                    MessageObject messageObject = groupedMessages.messages.get(a2);
                    if (a2 == 0 || !TextUtils.isEmpty(messageObject.caption)) {
                        this.selectedObjectToEditCaption = messageObject;
                        if (!TextUtils.isEmpty(messageObject.caption)) {
                            captionsCount++;
                        }
                    }
                }
                allowEdit = captionsCount < 2;
            } else {
                allowEdit = allowEdit2;
            }
            if (this.inScheduleMode || (((encryptedChat = this.currentEncryptedChat) != null && AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) < 46) || ((type == 1 && (message.getDialogId() == this.mergeDialogId || message.needDrawBluredPreview())) || (message.messageOwner.action instanceof TLRPC.TL_messageActionSecureValuesSent) || ((this.currentEncryptedChat == null && message.getId() < 0) || (((frameLayout = this.bottomOverlayChat) != null && frameLayout.getVisibility() == 0) || ((chat2 = this.currentChat) != null && (ChatObject.isNotInChat(chat2) || ((ChatObject.isChannel(this.currentChat) && !ChatObject.canPost(this.currentChat) && !this.currentChat.megagroup) || !ChatObject.canSendMessages(this.currentChat))))))))) {
                allowChatActions = false;
            } else {
                allowChatActions = true;
            }
            if (single || type < 2 || type == 20) {
                if (getParentActivity() == null) {
                    return;
                }
                ArrayList<Integer> icons2 = new ArrayList<>();
                ArrayList<CharSequence> items2 = new ArrayList<>();
                ArrayList<Constants.ChatSelectionPopMenuEnum> options2 = new ArrayList<>();
                if (type >= 0 || (type == -1 && single && ((message.isSending() || message.isEditing()) && this.currentEncryptedChat == null))) {
                    this.selectedObject = message;
                    this.selectedObjectGroup = groupedMessages;
                    if (type == -1) {
                        if (message.type == 0 || this.selectedObject.isAnimatedEmoji() || getMessageCaption(this.selectedObject, this.selectedObjectGroup) != null) {
                            items2.add(LocaleController.getString("Copy", R.string.Copy));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_COPY1);
                            icons2.add(Integer.valueOf(R.drawable.msg_copy));
                        }
                        items2.add(LocaleController.getString("CancelSending", R.string.CancelSending));
                        options2.add(Constants.ChatSelectionPopMenuEnum.MSG_CANCEL_SENDING);
                        icons2.add(Integer.valueOf(R.drawable.msg_delete));
                    } else if (type == 0) {
                        items2.add(LocaleController.getString("Retry", R.string.Retry));
                        options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SEND_RETRY);
                        icons2.add(Integer.valueOf(R.drawable.msg_retry));
                    } else if (type == 1) {
                        if (this.currentChat != null) {
                            if (allowChatActions) {
                                items2.add(LocaleController.getString("Reply", R.string.Reply));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_REPLAY);
                                icons2.add(Integer.valueOf(R.drawable.msg_reply));
                            }
                            if (allowUnpin) {
                                items2.add(LocaleController.getString("UnpinMessage", R.string.UnpinMessage));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_UNPIN);
                                icons2.add(Integer.valueOf(R.drawable.msg_unpin));
                            } else if (allowPin2) {
                                items2.add(LocaleController.getString("PinMessage", R.string.PinMessage));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_PIN);
                                icons2.add(Integer.valueOf(R.drawable.msg_pin));
                            }
                            if (this.selectedObject.contentType == 0 && !this.selectedObject.isMediaEmptyWebpage() && this.selectedObject.getId() > 0 && !this.selectedObject.isOut() && (this.currentChat != null || ((user2 = this.currentUser) != null && user2.bot))) {
                                items2.add(LocaleController.getString("ReportChat", R.string.ReportChat));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_REPORT);
                                icons2.add(Integer.valueOf(R.drawable.msg_report));
                            }
                        } else if (message.getId() > 0 && allowChatActions && !isSysNotifyMessage().booleanValue()) {
                            items2.add(LocaleController.getString("Reply", R.string.Reply));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_REPLAY);
                            icons2.add(Integer.valueOf(R.drawable.msg_reply));
                        }
                    } else if (type == 20) {
                        items2.add(LocaleController.getString("Retry", R.string.Retry));
                        options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SEND_RETRY);
                        icons2.add(Integer.valueOf(R.drawable.msg_retry));
                        items2.add(LocaleController.getString("Copy", R.string.Copy));
                        options2.add(Constants.ChatSelectionPopMenuEnum.MSG_COPY1);
                        icons2.add(Integer.valueOf(R.drawable.msg_copy));
                    } else if (this.currentEncryptedChat == null) {
                        if (this.inScheduleMode) {
                            items2.add(LocaleController.getString("MessageScheduleSend", R.string.MessageScheduleSend));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SEND_NOW);
                            icons2.add(Integer.valueOf(R.drawable.outline_send));
                        }
                        if (this.selectedObject.messageOwner.action instanceof TLRPC.TL_messageActionPhoneCall) {
                            TLRPC.TL_messageActionPhoneCall call2 = (TLRPC.TL_messageActionPhoneCall) message.messageOwner.action;
                            items2.add((((call2.reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed) || (call2.reason instanceof TLRPC.TL_phoneCallDiscardReasonBusy)) && !message.isOutOwner()) ? LocaleController.getString("CallBack", R.string.CallBack) : LocaleController.getString("CallAgain", R.string.CallAgain));
                            options2.add(Constants.ChatSelectionPopMenuEnum.CALL_BACK_OR_CALL_AGAIN);
                            icons2.add(Integer.valueOf(R.drawable.msg_callback));
                            if (VoIPHelper.canRateCall(call2)) {
                                items2.add(LocaleController.getString("CallMessageReportProblem", R.string.CallMessageReportProblem));
                                options2.add(Constants.ChatSelectionPopMenuEnum.CALL1);
                                icons2.add(Integer.valueOf(R.drawable.msg_callback));
                            }
                        }
                        if (allowChatActions && message.type != 101 && message.type != 102) {
                            items2.add(LocaleController.getString("Reply", R.string.Reply));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_REPLAY);
                            icons2.add(Integer.valueOf(R.drawable.msg_reply));
                        }
                        if (this.selectedObject.type == 0 || this.selectedObject.isAnimatedEmoji() || getMessageCaption(this.selectedObject, this.selectedObjectGroup) != null) {
                            items2.add(LocaleController.getString("Copy", R.string.Copy));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_COPY1);
                            icons2.add(Integer.valueOf(R.drawable.msg_copy));
                        }
                        if (!this.inScheduleMode && ChatObject.isChannel(this.currentChat)) {
                            this.selectedObject.getDialogId();
                        }
                        if (type == 2) {
                            if (!this.inScheduleMode && this.selectedObject.type == 17 && !message.isPollClosed()) {
                                if (message.isVoted()) {
                                    items2.add(LocaleController.getString("Unvote", R.string.Unvote));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.POLL_CANCEL);
                                    icons2.add(Integer.valueOf(R.drawable.msg_unvote));
                                }
                                if (!message.isForwarded() && ((message.isOut() && (!ChatObject.isChannel(this.currentChat) || this.currentChat.megagroup)) || (ChatObject.isChannel(this.currentChat) && !this.currentChat.megagroup && (this.currentChat.creator || (this.currentChat.admin_rights != null && this.currentChat.admin_rights.edit_messages))))) {
                                    items2.add(LocaleController.getString("StopPoll", R.string.StopPoll));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.POLL_STOP);
                                    icons2.add(Integer.valueOf(R.drawable.msg_pollstop));
                                }
                            }
                        } else if (type == 3) {
                            if ((this.selectedObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && MessageObject.isNewGifDocument(this.selectedObject.messageOwner.media.webpage.document)) {
                                items2.add(LocaleController.getString("SaveToGIFs", R.string.SaveToGIFs));
                                options2.add(Constants.ChatSelectionPopMenuEnum.GIF_SAVE);
                                icons2.add(Integer.valueOf(R.drawable.msg_gif));
                            }
                        } else if (type == 4) {
                            if (this.selectedObject.isVideo()) {
                                if (!this.selectedObject.needDrawBluredPreview()) {
                                    items2.add(LocaleController.getString("SaveToGallery", R.string.SaveToGallery));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY1);
                                    icons2.add(Integer.valueOf(R.drawable.msg_gallery));
                                    TLRPC.Chat chat3 = this.currentChat;
                                    if (chat3 == null || !chat3.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                        items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                        options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                        icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                                    }
                                }
                            } else if (this.selectedObject.isMusic()) {
                                items2.add(LocaleController.getString("SaveToMusic", R.string.SaveToMusic));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                                icons2.add(Integer.valueOf(R.drawable.msg_download));
                                TLRPC.Chat chat4 = this.currentChat;
                                if (chat4 == null || !chat4.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                    items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                    icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                                }
                            } else if (this.selectedObject.getDocument() != null) {
                                if (MessageObject.isNewGifDocument(this.selectedObject.getDocument())) {
                                    if (getMediaDataController().hasRecentGifNoChangeINdex(this.selectedObject.getDocument())) {
                                        items2.add(LocaleController.getString("RemoveFromGIFs", R.string.RemoveFromGIFs));
                                        options2.add(Constants.ChatSelectionPopMenuEnum.GIF_REMOVE);
                                        icons2.add(Integer.valueOf(R.drawable.msg_gif));
                                    } else {
                                        items2.add(LocaleController.getString("SaveToGIFs", R.string.SaveToGIFs));
                                        options2.add(Constants.ChatSelectionPopMenuEnum.GIF_SAVE);
                                        icons2.add(Integer.valueOf(R.drawable.msg_gif));
                                    }
                                }
                                items2.add(LocaleController.getString("SaveToDownloads", R.string.SaveToDownloads));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                                icons2.add(Integer.valueOf(R.drawable.msg_download));
                                TLRPC.Chat chat5 = this.currentChat;
                                if (chat5 == null || !chat5.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                    items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                    icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                                }
                            } else {
                                if (!this.selectedObject.needDrawBluredPreview()) {
                                    items2.add(LocaleController.getString("SaveToGallery", R.string.SaveToGallery));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY1);
                                    icons2.add(Integer.valueOf(R.drawable.msg_gallery));
                                }
                                String path = FileLoader.getPathToMessage(message.messageOwner).toString();
                                String result = CodeUtils.parseCode(path);
                                if (result != null) {
                                    items2.add(LocaleController.getString("ParseQRCode", R.string.ParseQRCode));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.QR_CODE_PARSE);
                                    icons2.add(Integer.valueOf(R.id.fmt_me_qrcode));
                                }
                            }
                        } else if (type == 5) {
                            items2.add(LocaleController.getString("ApplyLocalizationFile", R.string.ApplyLocalizationFile));
                            options2.add(Constants.ChatSelectionPopMenuEnum.LANGUAGE_OR_THEME);
                            icons2.add(Integer.valueOf(R.drawable.msg_language));
                            items2.add(LocaleController.getString("SaveToDownloads", R.string.SaveToDownloads));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                            icons2.add(Integer.valueOf(R.drawable.msg_download));
                            TLRPC.Chat chat6 = this.currentChat;
                            if (chat6 == null || !chat6.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                            }
                        } else if (type == 10) {
                            items2.add(LocaleController.getString("ApplyThemeFile", R.string.ApplyThemeFile));
                            options2.add(Constants.ChatSelectionPopMenuEnum.LANGUAGE_OR_THEME);
                            icons2.add(Integer.valueOf(R.drawable.msg_theme));
                            items2.add(LocaleController.getString("SaveToDownloads", R.string.SaveToDownloads));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                            icons2.add(Integer.valueOf(R.drawable.msg_download));
                            TLRPC.Chat chat7 = this.currentChat;
                            if (chat7 == null || !chat7.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                            }
                        } else if (type == 6) {
                            items2.add(LocaleController.getString("SaveToGallery", R.string.SaveToGallery));
                            options2.add(Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY2);
                            icons2.add(Integer.valueOf(R.drawable.msg_gallery));
                            items2.add(LocaleController.getString("SaveToDownloads", R.string.SaveToDownloads));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                            icons2.add(Integer.valueOf(R.drawable.msg_download));
                            TLRPC.Chat chat8 = this.currentChat;
                            if (chat8 == null || !chat8.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                            }
                        } else if (type == 7) {
                            if (this.selectedObject.isMask()) {
                                items2.add(LocaleController.getString("AddToMasks", R.string.AddToMasks));
                                options2.add(Constants.ChatSelectionPopMenuEnum.STICKER_OR_MASKS);
                                icons2.add(Integer.valueOf(R.drawable.msg_sticker));
                            } else {
                                items2.add(LocaleController.getString("AddToStickers", R.string.AddToStickers));
                                options2.add(Constants.ChatSelectionPopMenuEnum.STICKER_OR_MASKS);
                                icons2.add(Integer.valueOf(R.drawable.msg_sticker));
                                if (!getMediaDataController().isStickerInFavorites(this.selectedObject.getDocument())) {
                                    if (getMediaDataController().canAddStickerToFavorites()) {
                                        items2.add(LocaleController.getString("AddToFavorites", R.string.AddToFavorites));
                                        options2.add(Constants.ChatSelectionPopMenuEnum.MSG_FAVE_ADD);
                                        icons2.add(Integer.valueOf(R.drawable.msg_fave));
                                    }
                                } else {
                                    items2.add(LocaleController.getString("DeleteFromFavorites", R.string.DeleteFromFavorites));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.MSG_FAVE_REMOVE);
                                    icons2.add(Integer.valueOf(R.drawable.msg_unfave));
                                }
                            }
                        } else if (type == 8) {
                            TLRPC.User user3 = getMessagesController().getUser(Integer.valueOf(this.selectedObject.messageOwner.media.user_id));
                            if (user3 != null && user3.id != getUserConfig().getClientUserId() && getContactsController().contactsDict.get(Integer.valueOf(user3.id)) == null) {
                                items2.add(LocaleController.getString("AddContactTitle", R.string.AddContactTitle));
                                options2.add(Constants.ChatSelectionPopMenuEnum.CONTACT_ADD);
                                icons2.add(Integer.valueOf(R.drawable.msg_addcontact));
                            }
                            if (!TextUtils.isEmpty(this.selectedObject.messageOwner.media.phone_number)) {
                                items2.add(LocaleController.getString("Copy", R.string.Copy));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_COPY2);
                                icons2.add(Integer.valueOf(R.drawable.msg_copy));
                                items2.add(LocaleController.getString("Call", R.string.Call));
                                options2.add(Constants.ChatSelectionPopMenuEnum.CALL2);
                                icons2.add(Integer.valueOf(R.drawable.msg_callback));
                            }
                        } else if (type == 9) {
                            if (!getMediaDataController().isStickerInFavorites(this.selectedObject.getDocument())) {
                                items2.add(LocaleController.getString("AddToFavorites", R.string.AddToFavorites));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_FAVE_ADD);
                                icons2.add(Integer.valueOf(R.drawable.msg_fave));
                            } else {
                                items2.add(LocaleController.getString("DeleteFromFavorites", R.string.DeleteFromFavorites));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_FAVE_REMOVE);
                                icons2.add(Integer.valueOf(R.drawable.msg_unfave));
                            }
                        }
                        if (!this.inScheduleMode && !this.selectedObject.needDrawBluredPreview() && !this.selectedObject.isLiveLocation() && this.selectedObject.type != 16 && this.selectedObject.type != 101 && this.selectedObject.type != 102 && ((chat = this.currentChat) == null || !chat.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat))) {
                            items2.add(LocaleController.getString("Forward", R.string.Forward));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_FORWARD);
                            icons2.add(Integer.valueOf(R.drawable.msg_forward));
                        }
                        if (allowUnpin) {
                            items2.add(LocaleController.getString("UnpinMessage", R.string.UnpinMessage));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_UNPIN);
                            icons2.add(Integer.valueOf(R.drawable.msg_unpin));
                        } else if (allowPin2) {
                            items2.add(LocaleController.getString("PinMessage", R.string.PinMessage));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_PIN);
                            icons2.add(Integer.valueOf(R.drawable.msg_pin));
                        }
                        if (this.inScheduleMode && this.selectedObject.canEditMessageScheduleTime(this.currentChat)) {
                            items2.add(LocaleController.getString("MessageScheduleEditTime", R.string.MessageScheduleEditTime));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SCHEDULE_EDIT_TIME);
                            icons2.add(Integer.valueOf(R.drawable.msg_schedule));
                        }
                        if (!this.inScheduleMode && this.selectedObject.contentType == 0 && this.selectedObject.getId() > 0 && !this.selectedObject.isOut() && (this.currentChat != null || ((user = this.currentUser) != null && user.bot))) {
                            items2.add(LocaleController.getString("ReportChat", R.string.ReportChat));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_REPORT);
                            icons2.add(Integer.valueOf(R.drawable.msg_report));
                        }
                    } else {
                        if (allowChatActions) {
                            items2.add(LocaleController.getString("Reply", R.string.Reply));
                            options2.add(Constants.ChatSelectionPopMenuEnum.MSG_REPLAY);
                            icons2.add(Integer.valueOf(R.drawable.msg_reply));
                        }
                        if (type == 4) {
                            if (this.selectedObject.isVideo()) {
                                items2.add(LocaleController.getString("SaveToGallery", R.string.SaveToGallery));
                                options2.add(Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY1);
                                icons2.add(Integer.valueOf(R.drawable.msg_gallery));
                                TLRPC.Chat chat9 = this.currentChat;
                                if (chat9 == null || !chat9.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                    items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                    icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                                }
                            } else if (this.selectedObject.isMusic()) {
                                items2.add(LocaleController.getString("SaveToMusic", R.string.SaveToMusic));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                                icons2.add(Integer.valueOf(R.drawable.msg_download));
                                TLRPC.Chat chat10 = this.currentChat;
                                if (chat10 == null || !chat10.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                    items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                    icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                                }
                            } else if (!this.selectedObject.isVideo() && this.selectedObject.getDocument() != null) {
                                items2.add(LocaleController.getString("SaveToDownloads", R.string.SaveToDownloads));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD);
                                icons2.add(Integer.valueOf(R.drawable.msg_download));
                                TLRPC.Chat chat11 = this.currentChat;
                                if (chat11 == null || !chat11.megagroup || (this.currentChat.flags & ConnectionsManager.FileTypeVideo) == 0 || ChatObject.hasAdminRights(this.currentChat)) {
                                    items2.add(LocaleController.getString("ShareFile", R.string.ShareFile));
                                    options2.add(Constants.ChatSelectionPopMenuEnum.MSG_SHARE);
                                    icons2.add(Integer.valueOf(R.drawable.msg_shareout));
                                }
                            } else {
                                items2.add(LocaleController.getString("SaveToGallery", R.string.SaveToGallery));
                                options2.add(Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY1);
                                icons2.add(Integer.valueOf(R.drawable.msg_gallery));
                            }
                        } else if (type == 5) {
                            items2.add(LocaleController.getString("ApplyLocalizationFile", R.string.ApplyLocalizationFile));
                            options2.add(Constants.ChatSelectionPopMenuEnum.LANGUAGE_OR_THEME);
                            icons2.add(Integer.valueOf(R.drawable.msg_language));
                        } else if (type == 10) {
                            items2.add(LocaleController.getString("ApplyThemeFile", R.string.ApplyThemeFile));
                            options2.add(Constants.ChatSelectionPopMenuEnum.LANGUAGE_OR_THEME);
                            icons2.add(Integer.valueOf(R.drawable.msg_theme));
                        } else if (type == 7) {
                            items2.add(LocaleController.getString("AddToStickers", R.string.AddToStickers));
                            options2.add(Constants.ChatSelectionPopMenuEnum.STICKER_OR_MASKS);
                            icons2.add(Integer.valueOf(R.drawable.msg_sticker));
                        } else if (type == 8) {
                            TLRPC.User user4 = getMessagesController().getUser(Integer.valueOf(this.selectedObject.messageOwner.media.user_id));
                            if (user4 != null && user4.id != getUserConfig().getClientUserId() && getContactsController().contactsDict.get(Integer.valueOf(user4.id)) == null) {
                                items2.add(LocaleController.getString("AddContactTitle", R.string.AddContactTitle));
                                options2.add(Constants.ChatSelectionPopMenuEnum.CONTACT_ADD);
                                icons2.add(Integer.valueOf(R.drawable.msg_addcontact));
                            }
                            if (!TextUtils.isEmpty(this.selectedObject.messageOwner.media.phone_number)) {
                                items2.add(LocaleController.getString("Copy", R.string.Copy));
                                options2.add(Constants.ChatSelectionPopMenuEnum.MSG_COPY2);
                                icons2.add(Integer.valueOf(R.drawable.msg_copy));
                                items2.add(LocaleController.getString("Call", R.string.Call));
                                options2.add(Constants.ChatSelectionPopMenuEnum.CALL2);
                                icons2.add(Integer.valueOf(R.drawable.msg_callback));
                            }
                        }
                    }
                }
                if (options2.isEmpty()) {
                    return;
                }
                ActionBarPopupWindow actionBarPopupWindow = this.scrimPopupWindow;
                if (actionBarPopupWindow != null) {
                    actionBarPopupWindow.dismiss();
                    this.scrimPopupWindow = null;
                    return;
                }
                final Rect rect = new Rect();
                ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = new ActionBarPopupWindow.ActionBarPopupWindowLayout(getParentActivity());
                actionBarPopupWindowLayout.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$gC3quQSh_BS4RBjsdFRgIR_2Q3k
                    @Override // android.view.View.OnTouchListener
                    public final boolean onTouch(View view, MotionEvent motionEvent) {
                        return this.f$0.lambda$createMenu$76$ChatActivity(v, rect, view, motionEvent);
                    }
                });
                actionBarPopupWindowLayout.setDispatchKeyEventListener(new ActionBarPopupWindow.OnDispatchKeyEventListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$fWuSTtTiYC5u2UXQ9f_mHs7uaEU
                    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.OnDispatchKeyEventListener
                    public final void onDispatchKeyEvent(KeyEvent keyEvent) {
                        this.f$0.lambda$createMenu$77$ChatActivity(keyEvent);
                    }
                });
                Rect backgroundPaddings2 = new Rect();
                Drawable shadowDrawable = getParentActivity().getResources().getDrawable(R.drawable.popup_fixed_alert).mutate();
                shadowDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
                shadowDrawable.getPadding(backgroundPaddings2);
                actionBarPopupWindowLayout.setBackgroundDrawable(shadowDrawable);
                final LinearLayout linearLayout = new LinearLayout(getParentActivity());
                if (Build.VERSION.SDK_INT >= 21) {
                    backgroundPaddings = backgroundPaddings2;
                    options = options2;
                    items = items2;
                    icons = icons2;
                    scrollView = new ScrollView(getParentActivity(), null, 0, R.plurals.scrollbarShapeStyle) { // from class: im.uwrkaxlmjj.ui.ChatActivity.67
                        @Override // android.widget.ScrollView, android.widget.FrameLayout, android.view.View
                        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                            setMeasuredDimension(linearLayout.getMeasuredWidth(), getMeasuredHeight());
                        }
                    };
                } else {
                    backgroundPaddings = backgroundPaddings2;
                    options = options2;
                    items = items2;
                    icons = icons2;
                    scrollView = new ScrollView(getParentActivity());
                }
                scrollView.setClipToPadding(false);
                actionBarPopupWindowLayout.addView(scrollView, LayoutHelper.createFrame(-2, -2.0f));
                linearLayout.setMinimumWidth(AndroidUtilities.dp(200.0f));
                linearLayout.setOrientation(1);
                int N2 = items.size();
                for (int a3 = 0; a3 < N2; a3++) {
                    ActionBarMenuSubItem cell = new ActionBarMenuSubItem(getParentActivity());
                    cell.setTextAndIcon(items.get(a3), icons.get(a3).intValue());
                    linearLayout.addView(cell);
                    final int i = a3;
                    final ArrayList<Constants.ChatSelectionPopMenuEnum> options3 = options;
                    cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$H4-55QUhZC-kTgo2BK6AW501l-c
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$createMenu$78$ChatActivity(i, options3, view);
                        }
                    });
                }
                int i2 = -2;
                scrollView.addView(linearLayout, LayoutHelper.createScroll(-2, -2, 51));
                ActionBarPopupWindow actionBarPopupWindow2 = new ActionBarPopupWindow(actionBarPopupWindowLayout, i2, i2) { // from class: im.uwrkaxlmjj.ui.ChatActivity.68
                    @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow, android.widget.PopupWindow
                    public void dismiss() {
                        super.dismiss();
                        if (ChatActivity.this.scrimPopupWindow == this) {
                            ChatActivity.this.scrimPopupWindow = null;
                            if (ChatActivity.this.scrimAnimatorSet != null) {
                                ChatActivity.this.scrimAnimatorSet.cancel();
                                ChatActivity.this.scrimAnimatorSet = null;
                            }
                            if (ChatActivity.this.scrimView instanceof ChatMessageCell) {
                                ChatMessageCell cell2 = (ChatMessageCell) ChatActivity.this.scrimView;
                                cell2.setInvalidatesParent(false);
                            }
                            ChatActivity.this.chatLayoutManager.setCanScrollVertically(true);
                            ChatActivity.this.scrimAnimatorSet = new AnimatorSet();
                            ArrayList<Animator> animators = new ArrayList<>();
                            animators.add(ObjectAnimator.ofInt(ChatActivity.this.scrimPaint, AnimationProperties.PAINT_ALPHA, 0));
                            if (ChatActivity.this.pagedownButton.getTag() != null) {
                                animators.add(ObjectAnimator.ofFloat(ChatActivity.this.pagedownButton, (Property<FrameLayout, Float>) View.ALPHA, 1.0f));
                            }
                            if (ChatActivity.this.mentiondownButton.getTag() != null) {
                                animators.add(ObjectAnimator.ofFloat(ChatActivity.this.mentiondownButton, (Property<FrameLayout, Float>) View.ALPHA, 1.0f));
                            }
                            ChatActivity.this.scrimAnimatorSet.playTogether(animators);
                            ChatActivity.this.scrimAnimatorSet.setDuration(220L);
                            ChatActivity.this.scrimAnimatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.68.1
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animation) {
                                    ChatActivity.this.scrimView = null;
                                    ChatActivity.this.contentView.invalidate();
                                    ChatActivity.this.chatListView.invalidate();
                                }
                            });
                            ChatActivity.this.scrimAnimatorSet.start();
                            if (ChatActivity.this.chatActivityEnterView != null) {
                                ChatActivity.this.chatActivityEnterView.getEditField().setAllowDrawCursor(true);
                            }
                            if (Build.VERSION.SDK_INT >= 19) {
                                ChatActivity.this.getParentActivity().getWindow().getDecorView().setImportantForAccessibility(0);
                            }
                        }
                    }
                };
                this.scrimPopupWindow = actionBarPopupWindow2;
                actionBarPopupWindow2.setDismissAnimationDuration(220);
                this.scrimPopupWindow.setOutsideTouchable(true);
                this.scrimPopupWindow.setClippingEnabled(true);
                this.scrimPopupWindow.setAnimationStyle(R.plurals.PopupContextAnimation);
                this.scrimPopupWindow.setFocusable(true);
                actionBarPopupWindowLayout.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE));
                this.scrimPopupWindow.setInputMethodMode(2);
                this.scrimPopupWindow.setSoftInputMode(0);
                this.scrimPopupWindow.getContentView().setFocusableInTouchMode(true);
                Rect backgroundPaddings3 = backgroundPaddings;
                int popupX = (((v.getLeft() + ((int) x)) - actionBarPopupWindowLayout.getMeasuredWidth()) + backgroundPaddings3.left) - AndroidUtilities.dp(28.0f);
                if (popupX >= AndroidUtilities.dp(6.0f)) {
                    if (popupX > (this.chatListView.getMeasuredWidth() - AndroidUtilities.dp(6.0f)) - actionBarPopupWindowLayout.getMeasuredWidth()) {
                        popupX = (this.chatListView.getMeasuredWidth() - AndroidUtilities.dp(6.0f)) - actionBarPopupWindowLayout.getMeasuredWidth();
                    }
                } else {
                    popupX = AndroidUtilities.dp(6.0f);
                }
                if (AndroidUtilities.isTablet()) {
                    int[] location = new int[2];
                    this.fragmentView.getLocationInWindow(location);
                    popupX += location[0];
                }
                int totalHeight = this.contentView.getHeight();
                int height = actionBarPopupWindowLayout.getMeasuredHeight();
                int keyboardHeight = this.contentView.getKeyboardHeight();
                if (keyboardHeight > AndroidUtilities.dp(20.0f)) {
                    totalHeight += keyboardHeight;
                }
                if (height < totalHeight) {
                    popupY = (int) (this.chatListView.getY() + v.getTop() + y);
                    if ((height - backgroundPaddings3.top) - backgroundPaddings3.bottom > AndroidUtilities.dp(240.0f)) {
                        popupY += AndroidUtilities.dp(240.0f) - height;
                    }
                    if (popupY < this.chatListView.getY() + AndroidUtilities.dp(24.0f)) {
                        popupY = (int) (this.chatListView.getY() + AndroidUtilities.dp(24.0f));
                    } else if (popupY > (totalHeight - height) - AndroidUtilities.dp(8.0f)) {
                        popupY = (totalHeight - height) - AndroidUtilities.dp(8.0f);
                    }
                } else {
                    popupY = AndroidUtilities.statusBarHeight;
                }
                this.scrimPopupWindow.showAtLocation(this.chatListView, 51, popupX, popupY);
                this.chatListView.stopScroll();
                this.chatLayoutManager.setCanScrollVertically(false);
                this.scrimView = v;
                if (v instanceof ChatMessageCell) {
                    ChatMessageCell cell2 = (ChatMessageCell) v;
                    cell2.setInvalidatesParent(true);
                    restartSticker(cell2);
                }
                this.contentView.invalidate();
                this.chatListView.invalidate();
                AnimatorSet animatorSet = this.scrimAnimatorSet;
                if (animatorSet != null) {
                    animatorSet.cancel();
                }
                this.scrimAnimatorSet = new AnimatorSet();
                ArrayList<Animator> animators = new ArrayList<>();
                animators.add(ObjectAnimator.ofInt(this.scrimPaint, AnimationProperties.PAINT_ALPHA, 0, 50));
                if (this.pagedownButton.getTag() != null) {
                    animators.add(ObjectAnimator.ofFloat(this.pagedownButton, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                }
                if (this.mentiondownButton.getTag() != null) {
                    animators.add(ObjectAnimator.ofFloat(this.mentiondownButton, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                }
                this.scrimAnimatorSet.playTogether(animators);
                this.scrimAnimatorSet.setDuration(150L);
                this.scrimAnimatorSet.start();
                HintView hintView = this.forwardHintView;
                if (hintView != null) {
                    hintView.hide();
                }
                HintView hintView2 = this.noSoundHintView;
                if (hintView2 != null) {
                    hintView2.hide();
                }
                HintView hintView3 = this.slowModeHint;
                if (hintView3 != null) {
                    hintView3.hide();
                }
                ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
                if (chatActivityEnterView != null) {
                    chatActivityEnterView.getEditField().setAllowDrawCursor(false);
                }
                if (Build.VERSION.SDK_INT >= 19) {
                    getParentActivity().getWindow().getDecorView().setImportantForAccessibility(4);
                    return;
                }
                return;
            }
            ChatActivityEnterView chatActivityEnterView2 = this.chatActivityEnterView;
            if (chatActivityEnterView2 != null && (chatActivityEnterView2.isRecordingAudioVideo() || this.chatActivityEnterView.isRecordLocked())) {
                return;
            }
            ActionBarMenu actionMode = this.actionBar.createActionMode();
            View item = actionMode.getItem(12);
            if (item != null) {
                item.setVisibility(0);
            }
            if (isSysNotifyMessage().booleanValue()) {
                this.bottomMessagesActionContainer.setVisibility(8);
            } else {
                this.bottomMessagesActionContainer.setVisibility(0);
            }
            int translationY = this.chatActivityEnterView.getMeasuredHeight() - AndroidUtilities.dp(51.0f);
            if (this.chatActivityEnterView.getVisibility() != 0) {
                if (this.bottomOverlayChat.getVisibility() == 0) {
                    this.actionBar.showActionMode(this.bottomMessagesActionContainer, null, new View[]{this.bottomOverlayChat}, new boolean[]{true}, this.chatListView, translationY);
                    if (!Theme.getCurrentTheme().isDark()) {
                        this.actionBar.setBackButtonImage(R.drawable.back_black);
                    }
                } else if (this.searchContainer.getVisibility() == 0) {
                    this.actionBar.showActionMode(this.bottomMessagesActionContainer, null, new View[]{this.searchContainer}, new boolean[]{true}, this.chatListView, translationY);
                    if (!Theme.getCurrentTheme().isDark()) {
                        this.actionBar.setBackButtonImage(R.drawable.back_black);
                    }
                } else {
                    this.actionBar.showActionMode(this.bottomMessagesActionContainer, null, null, null, this.chatListView, translationY);
                    if (!Theme.getCurrentTheme().isDark()) {
                        this.actionBar.setBackButtonImage(R.drawable.back_black);
                    }
                }
            } else {
                ArrayList<View> views = new ArrayList<>();
                views.add(this.chatActivityEnterView);
                FrameLayout frameLayout2 = this.mentionContainer;
                if (frameLayout2 != null && frameLayout2.getVisibility() == 0) {
                    views.add(this.mentionContainer);
                }
                FrameLayout frameLayout3 = this.stickersPanel;
                if (frameLayout3 != null && frameLayout3.getVisibility() == 0) {
                    views.add(this.stickersPanel);
                }
                this.actionBar.showActionMode(this.bottomMessagesActionContainer, null, (View[]) views.toArray(new View[0]), new boolean[]{false, true, true}, this.chatListView, translationY);
                if (!Theme.getCurrentTheme().isDark()) {
                    this.actionBar.setBackButtonImage(R.drawable.back_black);
                }
                if (getParentActivity() != null) {
                    ((LaunchActivity) getParentActivity()).hideVisibleActionMode();
                }
                this.chatActivityEnterView.getEditField().setAllowDrawCursor(false);
            }
            ActionBarPopupWindow actionBarPopupWindow3 = this.scrimPopupWindow;
            if (actionBarPopupWindow3 != null) {
                actionBarPopupWindow3.dismiss();
            }
            this.chatLayoutManager.setCanScrollVertically(true);
            updatePinnedMessageView(true);
            AnimatorSet animatorSet2 = new AnimatorSet();
            ArrayList<Animator> animators2 = new ArrayList<>();
            int a4 = 0;
            while (a4 < this.actionModeViews.size()) {
                View view = this.actionModeViews.get(a4);
                view.setPivotY(ActionBar.getCurrentActionBarHeight() / 2);
                AndroidUtilities.clearDrawableAnimation(view);
                animators2.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) View.SCALE_Y, 0.1f, 1.0f));
                a4++;
                actionMode = actionMode;
                item = item;
            }
            animatorSet2.playTogether(animators2);
            animatorSet2.setDuration(250L);
            animatorSet2.start();
            addToSelectedMessages(message, listView);
            this.selectedMessagesCountTextView.setNumber(this.selectedMessagesIds[0].size() + this.selectedMessagesIds[1].size(), false);
            updateVisibleRows();
            return;
        }
        scrollToMessageId(message.messageOwner.reply_to_msg_id, message.messageOwner.id, true, 0, false);
    }

    public /* synthetic */ boolean lambda$createMenu$76$ChatActivity(View v, Rect rect, View view, MotionEvent event) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (event.getActionMasked() == 0) {
            ActionBarPopupWindow actionBarPopupWindow2 = this.scrimPopupWindow;
            if (actionBarPopupWindow2 != null && actionBarPopupWindow2.isShowing()) {
                v.getHitRect(rect);
                if (!rect.contains((int) event.getX(), (int) event.getY())) {
                    this.scrimPopupWindow.dismiss();
                    return false;
                }
                return false;
            }
            return false;
        }
        if (event.getActionMasked() == 4 && (actionBarPopupWindow = this.scrimPopupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.scrimPopupWindow.dismiss();
            return false;
        }
        return false;
    }

    public /* synthetic */ void lambda$createMenu$77$ChatActivity(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.scrimPopupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.scrimPopupWindow.dismiss();
        }
    }

    public /* synthetic */ void lambda$createMenu$78$ChatActivity(int i, ArrayList options, View v1) {
        if (this.selectedObject == null || i < 0 || i >= options.size()) {
            return;
        }
        processSelectedOption((Constants.ChatSelectionPopMenuEnum) options.get(i));
        ActionBarPopupWindow actionBarPopupWindow = this.scrimPopupWindow;
        if (actionBarPopupWindow != null) {
            actionBarPopupWindow.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startEditingMessageObject(MessageObject messageObject) {
        if (messageObject == null || getParentActivity() == null) {
            return;
        }
        if (this.searchItem != null && this.actionBar.isSearchFieldVisible()) {
            this.actionBar.closeSearchField();
            this.chatActivityEnterView.setFieldFocused();
        }
        this.mentionsAdapter.setNeedBotContext(false);
        this.chatActivityEnterView.setVisibility(0);
        showFieldPanelForEdit(true, messageObject);
        updateBottomOverlay();
        checkEditTimer();
        this.chatActivityEnterView.setAllowStickersAndGifs(false, false);
        updatePinnedMessageView(true);
        updateVisibleRows();
        if (messageObject.scheduled) {
            this.chatActivityEnterView.showEditDoneProgress(false, true);
            return;
        }
        TLRPC.TL_messages_getMessageEditData req = new TLRPC.TL_messages_getMessageEditData();
        req.peer = getMessagesController().getInputPeer((int) this.dialog_id);
        req.id = messageObject.getId();
        this.editingMessageObjectReqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ZBVDOxZiAbWAtoyJNYVqKnFgnf4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$startEditingMessageObject$80$ChatActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$startEditingMessageObject$80$ChatActivity(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$OQLqg_g9whdyZkNYF6CWdAYBrCo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$79$ChatActivity(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$79$ChatActivity(TLObject response) {
        this.editingMessageObjectReqId = 0;
        if (response == null) {
            if (getParentActivity() == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("EditMessageError", R.string.EditMessageError));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            showDialog(builder.create());
            ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
            if (chatActivityEnterView != null) {
                chatActivityEnterView.setEditingMessageObject(null, false);
                hideFieldPanel(true);
                return;
            }
            return;
        }
        ChatActivityEnterView chatActivityEnterView2 = this.chatActivityEnterView;
        if (chatActivityEnterView2 != null) {
            chatActivityEnterView2.showEditDoneProgress(false, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void restartSticker(ChatMessageCell cell) {
        MessageObject message = cell.getMessageObject();
        TLRPC.Document document = message.getDocument();
        if (message.isAnimatedEmoji() || (MessageObject.isAnimatedStickerDocument(document) && !SharedConfig.loopStickers)) {
            ImageReceiver imageReceiver = cell.getPhotoImage();
            RLottieDrawable drawable = imageReceiver.getLottieAnimation();
            if (drawable != null) {
                drawable.restart();
                if (message.isAnimatedEmoji()) {
                    String emoji = message.getStickerEmoji();
                    if ("❤".equals(emoji)) {
                        HashMap<Integer, Integer> pattern = new HashMap<>();
                        pattern.put(1, 1);
                        pattern.put(13, 0);
                        pattern.put(59, 1);
                        pattern.put(71, 0);
                        pattern.put(128, 1);
                        pattern.put(140, 0);
                        drawable.setVibrationPattern(pattern);
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getMessageContent(MessageObject messageObject, int previousUid, boolean name) {
        TLRPC.Chat chat;
        String str = "";
        if (name && previousUid != messageObject.messageOwner.from_id) {
            if (messageObject.messageOwner.from_id > 0) {
                TLRPC.User user = getMessagesController().getUser(Integer.valueOf(messageObject.messageOwner.from_id));
                if (user != null) {
                    str = ContactsController.formatName(user.first_name, user.last_name) + ":\n";
                }
            } else if (messageObject.messageOwner.from_id < 0 && (chat = getMessagesController().getChat(Integer.valueOf(-messageObject.messageOwner.from_id))) != null) {
                str = chat.title + ":\n";
            }
        }
        if ((messageObject.type == 0 || messageObject.isAnimatedEmoji()) && messageObject.messageOwner.message != null) {
            return str + ((Object) messageObject.messageText);
        }
        if (messageObject.messageOwner.media != null && messageObject.messageOwner.message != null) {
            return str + ((Object) messageObject.messageText);
        }
        return str + ((Object) messageObject.messageText);
    }

    private void saveMessageToGallery(MessageObject messageObject) {
        String string = messageObject.messageOwner.attachPath;
        if (!TextUtils.isEmpty(string) && !new File(string).exists()) {
            string = null;
        }
        if (TextUtils.isEmpty(string)) {
            string = FileLoader.getPathToMessage(messageObject.messageOwner).toString();
        }
        MediaController.saveFile(string, getParentActivity(), messageObject.isVideo() ? 1 : 0, null, null);
    }

    public void parseQRCodeResult(String result, boolean forceJumpOutBrowser) {
        String result2;
        String result3;
        String result4;
        if (result != null) {
            result2 = result;
        } else {
            result2 = "";
        }
        String preStr = getMessagesController().sharePrefix + "&Key=";
        String originResult = result2;
        if (result2.startsWith(preStr) || result2.startsWith("https://m12345.com") || result2.startsWith("http://m12345.com") || result2.startsWith("m12345.com") || result2.startsWith("m12345.com")) {
            if (result2.startsWith(preStr)) {
                String result5 = result2.substring(preStr.length()).replace("%3D", "=");
                byte[] decode = Base64.decode(result5, 0);
                String ret = new String(decode);
                String[] split = ret.split("#");
                String pUid = split[0].split("=")[1];
                String hash = split[1].split("=")[1];
                if (ret.contains("Uname")) {
                    String uName = split[2].split("=")[1];
                    getMessagesController().openByUserName(uName, (BaseFragment) this, 1, true);
                    result4 = result5;
                } else {
                    TLRPC.User user = new TLRPC.TL_user();
                    try {
                        user.id = Integer.parseInt(pUid);
                        result4 = result5;
                        try {
                            user.access_hash = Long.parseLong(hash);
                            getUserInfo(user);
                        } catch (NumberFormatException e) {
                            e = e;
                            FileLog.e("parse qr code err:" + e);
                        }
                    } catch (NumberFormatException e2) {
                        e = e2;
                        result4 = result5;
                    }
                }
                return;
            }
            if (result2.startsWith("http://m12345.com")) {
                result3 = result2.substring("http://m12345.com".length());
            } else if (result2.startsWith("https://m12345.com")) {
                result3 = result2.substring("https://m12345.com".length());
            } else if (result2.startsWith("m12345.com")) {
                result3 = result2.substring("m12345.com".length());
            } else {
                result3 = result2.substring("m12345.com".length());
            }
            boolean isGroup = result3.startsWith("/g/");
            boolean isUser = result3.startsWith("/u/");
            if (isGroup || isUser) {
                byte[] decode2 = Base64.decode(result3.substring(result3.lastIndexOf("/") + 1), 0);
                String ret2 = new String(decode2);
                if (isGroup) {
                    getMessagesController().openByUserName(ret2.substring(ret2.lastIndexOf("/") + 1), (BaseFragment) this, 1, true);
                } else {
                    String[] split2 = ret2.substring(0, ret2.length() - 4).split("&", 2);
                    String uid = split2[0];
                    String uhash = split2[1];
                    TLRPC.User user2 = new TLRPC.TL_user();
                    try {
                        try {
                            user2.id = Integer.parseInt(uid);
                            try {
                                user2.access_hash = Long.parseLong(uhash);
                                getUserInfo(user2);
                            } catch (NumberFormatException e3) {
                                e = e3;
                                FileLog.e("parse qr code err:" + e);
                            }
                        } catch (NumberFormatException e4) {
                            e = e4;
                        }
                    } catch (NumberFormatException e5) {
                        e = e5;
                    }
                }
                return;
            }
            if (result3.contains("joinchat/")) {
                isGroup = true;
            }
            String result6 = result3.substring(result3.lastIndexOf("/") + 1);
            if (!isGroup) {
                getMessagesController().openByUserName(result6, (BaseFragment) this, 1, true);
            } else {
                Browser.openUrl(getParentActivity(), originResult, this.inlineReturn == 0);
            }
            return;
        }
        if (!result2.startsWith("https://m12345.com/authtoken/")) {
            if (!URLUtil.isNetworkUrl(result2)) {
                presentFragment(new QrScanResultActivity(result2), true);
            } else if (SharedConfig.customTabs) {
                presentFragment(new WebviewActivity(result2, (String) null));
            } else {
                Browser.openUrl(getParentActivity(), result2, this.inlineReturn == 0);
            }
        }
    }

    private void getUserInfo(TLRPC.User user) {
        TLRPC.TL_users_getFullUser req = new TLRPC.TL_users_getFullUser();
        req.id = getMessagesController().getInputUser(user);
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$zgMqy_F0K1S4oMX4xdrepjav-jY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getUserInfo$82$ChatActivity(tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$getUserInfo$82$ChatActivity(final TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$RG20oKtWMrQRAsRhRev1GJb0sp8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$81$ChatActivity(response);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$81$ChatActivity(TLObject response) {
        TLRPC.UserFull userFull = (TLRPC.UserFull) response;
        getMessagesController().putUser(userFull.user, false);
        if (userFull.user.self || userFull.user.contact) {
            Bundle bundle = new Bundle();
            bundle.putInt("user_id", userFull.user.id);
            presentFragment(new NewProfileActivity(bundle));
        } else {
            Bundle bundle2 = new Bundle();
            bundle2.putInt("from_type", 1);
            presentFragment(new AddContactsInfoActivity(bundle2, userFull.user));
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00c4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void processSelectedOption(im.uwrkaxlmjj.ui.constants.Constants.ChatSelectionPopMenuEnum r28) {
        /*
            Method dump skipped, instruction units count: 2234
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.processSelectedOption(im.uwrkaxlmjj.ui.constants.Constants$ChatSelectionPopMenuEnum):void");
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$76, reason: invalid class name */
    static /* synthetic */ class AnonymousClass76 {
        static final /* synthetic */ int[] $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum;

        static {
            int[] iArr = new int[Constants.ChatSelectionPopMenuEnum.values().length];
            $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum = iArr;
            try {
                iArr[Constants.ChatSelectionPopMenuEnum.MSG_SEND_RETRY.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_DELETE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_FORWARD.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_COPY1.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_COPY2.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY1.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.PIC_SAVE_TO_GALLERY2.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.LANGUAGE_OR_THEME.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_SHARE.ordinal()] = 9;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_REPLAY.ordinal()] = 10;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.STICKER_OR_MASKS.ordinal()] = 11;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_DOWNLOAD.ordinal()] = 12;
            } catch (NoSuchFieldError e12) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.GIF_SAVE.ordinal()] = 13;
            } catch (NoSuchFieldError e13) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.GIF_REMOVE.ordinal()] = 14;
            } catch (NoSuchFieldError e14) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_EDIT.ordinal()] = 15;
            } catch (NoSuchFieldError e15) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_PIN.ordinal()] = 16;
            } catch (NoSuchFieldError e16) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_UNPIN.ordinal()] = 17;
            } catch (NoSuchFieldError e17) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.CONTACT_ADD.ordinal()] = 18;
            } catch (NoSuchFieldError e18) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.CALL_BACK_OR_CALL_AGAIN.ordinal()] = 19;
            } catch (NoSuchFieldError e19) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.CALL2.ordinal()] = 20;
            } catch (NoSuchFieldError e20) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.CALL1.ordinal()] = 21;
            } catch (NoSuchFieldError e21) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_FAVE_ADD.ordinal()] = 22;
            } catch (NoSuchFieldError e22) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_FAVE_REMOVE.ordinal()] = 23;
            } catch (NoSuchFieldError e23) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_COPY_LINK.ordinal()] = 24;
            } catch (NoSuchFieldError e24) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_REPORT.ordinal()] = 25;
            } catch (NoSuchFieldError e25) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_CANCEL_SENDING.ordinal()] = 26;
            } catch (NoSuchFieldError e26) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.POLL_CANCEL.ordinal()] = 27;
            } catch (NoSuchFieldError e27) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.POLL_STOP.ordinal()] = 28;
            } catch (NoSuchFieldError e28) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.QR_CODE_PARSE.ordinal()] = 29;
            } catch (NoSuchFieldError e29) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_SEND_NOW.ordinal()] = 30;
            } catch (NoSuchFieldError e30) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.MSG_SCHEDULE_EDIT_TIME.ordinal()] = 31;
            } catch (NoSuchFieldError e31) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.TRANSLATE.ordinal()] = 32;
            } catch (NoSuchFieldError e32) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$Constants$ChatSelectionPopMenuEnum[Constants.ChatSelectionPopMenuEnum.TRANSLATE_CANCEL.ordinal()] = 33;
            } catch (NoSuchFieldError e33) {
            }
        }
    }

    static /* synthetic */ void lambda$processSelectedOption$83(boolean[] checks, View v) {
        CheckBoxCell cell1 = (CheckBoxCell) v;
        checks[0] = !checks[0];
        cell1.setChecked(checks[0], true);
    }

    public /* synthetic */ void lambda$processSelectedOption$84$ChatActivity(int mid, boolean[] checks, DialogInterface dialogInterface, int i) {
        getMessagesController().pinMessage(this.currentChat, this.currentUser, mid, checks[0]);
    }

    public /* synthetic */ void lambda$processSelectedOption$85$ChatActivity(DialogInterface dialogInterface, int i) {
        getMessagesController().pinMessage(this.currentChat, this.currentUser, 0, false);
    }

    static /* synthetic */ void lambda$null$86(TLObject response) {
        if (response != null) {
            TLRPC.TL_exportedMessageLink exportedMessageLink = (TLRPC.TL_exportedMessageLink) response;
            try {
                ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
                ClipData clip = ClipData.newPlainText("label", exportedMessageLink.link);
                clipboard.setPrimaryClip(clip);
                if (exportedMessageLink.link.contains("/c/")) {
                    ToastUtils.show(R.string.LinkCopiedPrivate);
                } else {
                    ToastUtils.show(R.string.LinkCopied);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    static /* synthetic */ void lambda$processSelectedOption$88(AlertDialog[] progressDialog) {
        try {
            progressDialog[0].dismiss();
        } catch (Throwable th) {
        }
        progressDialog[0] = null;
    }

    public /* synthetic */ void lambda$processSelectedOption$90$ChatActivity(AlertDialog[] progressDialog, final int requestId) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$vPu2nrQzXZKXEiLtyR11Tgcd_Pw
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$89$ChatActivity(requestId, dialogInterface);
            }
        });
        showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$89$ChatActivity(int requestId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(requestId, true);
    }

    public /* synthetic */ void lambda$processSelectedOption$96$ChatActivity(MessageObject object, DialogInterface dialogInterface, int i) {
        final AlertDialog[] progressDialog = {new AlertDialog(getParentActivity(), 3)};
        final TLRPC.TL_messages_editMessage req = new TLRPC.TL_messages_editMessage();
        TLRPC.TL_messageMediaPoll mediaPoll = (TLRPC.TL_messageMediaPoll) object.messageOwner.media;
        TLRPC.TL_inputMediaPoll poll = new TLRPC.TL_inputMediaPoll();
        poll.poll = new TLRPC.TL_poll();
        poll.poll.id = mediaPoll.poll.id;
        poll.poll.question = mediaPoll.poll.question;
        poll.poll.answers = mediaPoll.poll.answers;
        poll.poll.closed = true;
        req.media = poll;
        req.peer = getMessagesController().getInputPeer((int) this.dialog_id);
        req.id = object.getId();
        req.flags |= 16384;
        final int requestId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$C1EFxi2LRX_xkoWwJu5zHer7cU8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$93$ChatActivity(progressDialog, req, tLObject, tL_error);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$RrgquE6LsNBNe-C2wJ28jEJTly8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$95$ChatActivity(progressDialog, requestId);
            }
        }, 500L);
    }

    public /* synthetic */ void lambda$null$93$ChatActivity(final AlertDialog[] progressDialog, final TLRPC.TL_messages_editMessage req, TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$BXHToDJv6dTJqF4IUrI_hj5ID50
            @Override // java.lang.Runnable
            public final void run() {
                ChatActivity.lambda$null$91(progressDialog);
            }
        });
        if (error == null) {
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$NzJNij5Bsme5vSXbvKsCeODnfmw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$92$ChatActivity(error, req);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$91(AlertDialog[] progressDialog) {
        try {
            progressDialog[0].dismiss();
        } catch (Throwable th) {
        }
        progressDialog[0] = null;
    }

    public /* synthetic */ void lambda$null$92$ChatActivity(TLRPC.TL_error error, TLRPC.TL_messages_editMessage req) {
        AlertsCreator.processError(this.currentAccount, error, this, req, new Object[0]);
    }

    public /* synthetic */ void lambda$null$95$ChatActivity(AlertDialog[] progressDialog, final int requestId) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$-CbkAZ7tkGWpViUIALwjxqkhnVQ
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$94$ChatActivity(requestId, dialogInterface);
            }
        });
        showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$94$ChatActivity(int requestId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(requestId, true);
    }

    public /* synthetic */ void lambda$processSelectedOption$99$ChatActivity(final TLRPC.TL_messages_sendScheduledMessages req, TLObject response, final TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            MessagesController.getInstance(this.currentAccount).processUpdates(updates, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$cPxg4tAiIghsZZAZzdJRdBcVXSY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$97$ChatActivity(req);
                }
            });
        } else if (error.text != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$oTMPB7lwBT18yewJBT4Lv6f6X3Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$98$ChatActivity(error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$97$ChatActivity(TLRPC.TL_messages_sendScheduledMessages req) {
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.messagesDeleted, req.id, Integer.valueOf((int) (-this.dialog_id)), true);
    }

    public /* synthetic */ void lambda$null$98$ChatActivity(TLRPC.TL_error error) {
        if (error.text.startsWith("SLOWMODE_WAIT_")) {
            AlertsCreator.showSimpleToast(this, LocaleController.getString("SlowmodeSendError", R.string.SlowmodeSendError));
        } else if (error.text.equals("CHAT_SEND_MEDIA_FORBIDDEN")) {
            AlertsCreator.showSimpleToast(this, LocaleController.getString("AttachMediaRestrictedForever", R.string.AttachMediaRestrictedForever));
        } else {
            AlertsCreator.showSimpleToast(this, error.text);
        }
    }

    public /* synthetic */ void lambda$processSelectedOption$100$ChatActivity(MessageObject.GroupedMessages group, MessageObject message, boolean notify, int scheduleDate) {
        if (group != null) {
            SendMessagesHelper.getInstance(this.currentAccount).editMessage(group.messages.get(0), null, false, this, null, scheduleDate, null);
        } else {
            SendMessagesHelper.getInstance(this.currentAccount).editMessage(message, null, false, this, null, scheduleDate, null);
        }
    }

    private void translateStart(MessageObject message) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void translateCancel(MessageObject message) {
    }

    private void convertAudioFile(final MessageObject message) {
        message.messageOwner.trans = "   ";
        message.messageOwner.istransing = true;
        updateVisibleRows();
        Disposable subscribe = Observable.create(new ObservableOnSubscribe<String>() { // from class: im.uwrkaxlmjj.ui.ChatActivity.69
            @Override // io.reactivex.ObservableOnSubscribe
            public void subscribe(final ObservableEmitter<String> e) throws Exception {
                File cacheFile = FileLoader.getPathToMessage(message.messageOwner);
                String fileName1 = cacheFile.getName();
                String fileName12 = fileName1.substring(0, fileName1.lastIndexOf(46)) + AudioEditConstant.SUFFIX_PCM;
                String path = cacheFile.getPath();
                final String convertPath = AudioFileUtils.getAudioEditStorageDirectory() + File.separator + fileName12;
                if (AudioFileUtils.checkFileExist(convertPath)) {
                    e.onNext(convertPath);
                } else {
                    AudioFileUtils.confirmFolderExist(new File(convertPath).getParent());
                    DecodeEngine.getInstance().convertMusicFileToPcmFile(path, convertPath, new DecodeOperateInterface() { // from class: im.uwrkaxlmjj.ui.ChatActivity.69.1
                        @Override // im.uwrkaxlmjj.ui.utils.translate.callback.DecodeOperateInterface
                        public void updateDecodeProgress(int decodeProgress) {
                        }

                        @Override // im.uwrkaxlmjj.ui.utils.translate.callback.DecodeOperateInterface
                        public void decodeSuccess() {
                            Log.e("TAG", "解碼完成 Path == " + convertPath);
                            e.onNext(convertPath);
                        }

                        @Override // im.uwrkaxlmjj.ui.utils.translate.callback.DecodeOperateInterface
                        public void decodeFail() {
                            Log.e("TAG", "文件解析失败 Path == " + convertPath);
                            e.onError(new Throwable("文件解析失败"));
                        }
                    });
                }
            }
        }).subscribeOn(Schedulers.io()).subscribe(new Consumer() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$HsK9Hnr6rrSQM02PrlPAVhTLpL4
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$convertAudioFile$101$ChatActivity(message, (String) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$5ESvgqhvC0We4mR4O6cly3JJHNM
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) {
                ToastUtils.show((CharSequence) ((Throwable) obj).getMessage());
            }
        });
        if (subscribe != null) {
            translateAddTaskDisposable(String.valueOf(message.getId()), subscribe);
        }
    }

    public /* synthetic */ void lambda$convertAudioFile$101$ChatActivity(MessageObject message, String path) throws Exception {
        if (!TextUtils.isEmpty(path) && AudioFileUtils.checkFileExist(path)) {
            translateAccessToken(message, path);
        }
    }

    private void translateAddTaskDisposable(String tag, Disposable disposable) {
        if (this.mTaskDisposable.get(tag) != null) {
            this.mTaskDisposable.get(tag).add(disposable);
            return;
        }
        CompositeDisposable compositeDisposable = new CompositeDisposable();
        compositeDisposable.add(disposable);
        this.mTaskDisposable.put(tag, compositeDisposable);
    }

    private void translateUnSubscribeAllAudioTask() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(this.TAG);
        this.mTaskDisposable.clear();
        HashMap<String, CompositeDisposable> map = this.mTaskDisposable;
        if (map != null && map.size() > 0) {
            Set<Map.Entry<String, CompositeDisposable>> entries = this.mTaskDisposable.entrySet();
            Iterator<Map.Entry<String, CompositeDisposable>> iterator = entries.iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, CompositeDisposable> next = iterator.next();
                CompositeDisposable value = next.getValue();
                if (value != null) {
                    value.clear();
                    iterator.remove();
                }
            }
            this.mTaskDisposable.clear();
            this.mTaskDisposable = null;
        }
    }

    private void translateAccessToken(final MessageObject message, final String path) {
        Observable<ResponseAccessTokenBean> observable = ApiTranslateAudioFactory.getInstance().getApiTranslate().accessToken("https://openapi.baidu.com/oauth/2.0/token", "client_credentials", "5elX69KjdF5FkuwcYSOdNTYs", "pE5eNoBQIFVcd9IEuyIhvopfgS1RSj5C");
        RxHelper.getInstance().sendSimpleRequest(this.TAG, observable, new Consumer<ResponseAccessTokenBean>() { // from class: im.uwrkaxlmjj.ui.ChatActivity.70
            @Override // io.reactivex.functions.Consumer
            public void accept(ResponseAccessTokenBean tokenBean) throws Exception {
                if (tokenBean != null && !TextUtils.isEmpty(tokenBean.getAccess_token())) {
                    ChatActivity.this.translateAudio(message, tokenBean.getAccess_token(), path);
                }
            }
        }, new Consumer<Throwable>() { // from class: im.uwrkaxlmjj.ui.ChatActivity.71
            @Override // io.reactivex.functions.Consumer
            public void accept(Throwable throwable) throws Exception {
                ToastUtils.show((CharSequence) "翻译失败");
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void translateAudio(final MessageObject message, String token, String path) {
        final File file = new File(path);
        RequestBody fileBody = RequestBody.create(MediaType.parse("audio/pcm;rate=16000"), file);
        Observable<ResponseBaiduTranslateBean> observable = ApiTranslateAudioFactory.getInstance().getApiTranslate().translate("https://vop.baidu.com/pro_api", fileBody, "baidu_workshop", token, 80001, file.length());
        RxHelper.getInstance().sendSimpleRequest(this.TAG, observable, new Consumer<ResponseBaiduTranslateBean>() { // from class: im.uwrkaxlmjj.ui.ChatActivity.72
            @Override // io.reactivex.functions.Consumer
            public void accept(ResponseBaiduTranslateBean translateBean) throws Exception {
                if (translateBean != null && translateBean.getResult() != null && translateBean.getResult().length > 0) {
                    AudioFileUtils.deleteFileSafely(file);
                    int channelId = 0;
                    try {
                        long messageId = message.getId();
                        if (0 == 0) {
                            channelId = message.getChannelId();
                        }
                        if (message.getChannelId() != 0) {
                            messageId |= ((long) channelId) << 32;
                        }
                        StringBuilder responseresultBuilder = new StringBuilder();
                        for (int i = 0; i < translateBean.getResult().length; i++) {
                            String responseresult = translateBean.getResult()[i];
                            responseresultBuilder.append(responseresult);
                        }
                        if (!TextUtils.isEmpty(responseresultBuilder.toString())) {
                            SQLitePreparedStatement sqLitePreparedStatement1 = ChatActivity.this.getMessagesStorage().getDatabase().executeFast("UPDATE messages SET trans_dst = ? WHERE mid = ? ");
                            sqLitePreparedStatement1.bindString(1, responseresultBuilder.toString());
                            sqLitePreparedStatement1.bindLong(2, messageId);
                            sqLitePreparedStatement1.step();
                            sqLitePreparedStatement1.dispose();
                            message.messageOwner.trans = responseresultBuilder.toString();
                            message.messageOwner.istransing = false;
                        } else {
                            ToastUtils.show((CharSequence) "翻译失败");
                            ChatActivity.this.translateCancel(message);
                        }
                    } catch (SQLiteException e) {
                        e.printStackTrace();
                    }
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.ChatActivity.72.1
                        @Override // java.lang.Runnable
                        public void run() {
                            ChatActivity.this.updateVisibleRows();
                        }
                    });
                }
            }
        }, new Consumer<Throwable>() { // from class: im.uwrkaxlmjj.ui.ChatActivity.73
            @Override // io.reactivex.functions.Consumer
            public void accept(Throwable throwable) throws Exception {
                ToastUtils.show((CharSequence) throwable.getMessage());
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
    public void didSelectDialogs(DialogsActivity fragment, ArrayList<Long> dids, CharSequence message, boolean param) {
        if (this.forwardingMessage == null && this.selectedMessagesIds[0].size() == 0 && this.selectedMessagesIds[1].size() == 0) {
            return;
        }
        ArrayList<MessageObject> fmessages = new ArrayList<>();
        MessageObject messageObject = this.forwardingMessage;
        if (messageObject != null) {
            MessageObject.GroupedMessages groupedMessages = this.forwardingMessageGroup;
            if (groupedMessages != null) {
                fmessages.addAll(groupedMessages.messages);
            } else {
                fmessages.add(messageObject);
            }
            this.forwardingMessage = null;
            this.forwardingMessageGroup = null;
        } else {
            for (int a = 1; a >= 0; a--) {
                ArrayList<Integer> ids = new ArrayList<>();
                for (int b = 0; b < this.selectedMessagesIds[a].size(); b++) {
                    ids.add(Integer.valueOf(this.selectedMessagesIds[a].keyAt(b)));
                }
                Collections.sort(ids);
                for (int b2 = 0; b2 < ids.size(); b2++) {
                    Integer id = ids.get(b2);
                    MessageObject messageObject2 = this.selectedMessagesIds[a].get(id.intValue());
                    if (messageObject2 != null) {
                        if (messageObject2.messageOwner.media instanceof TLRPC.TL_messageMediaShare) {
                        }
                        fmessages.add(messageObject2);
                    }
                }
                this.selectedMessagesCanCopyIds[a].clear();
                this.selectedMessagesCanStarIds[a].clear();
                this.selectedMessagesIds[a].clear();
            }
            hideActionMode();
            updatePinnedMessageView(true);
        }
        if (dids.size() > 1 || dids.get(0).longValue() == getUserConfig().getClientUserId() || message != null) {
            for (int a2 = 0; a2 < dids.size(); a2++) {
                long did = dids.get(a2).longValue();
                if (message != null) {
                    getSendMessagesHelper().sendMessage(message.toString(), did, null, null, true, null, null, null, true, 0);
                }
                getSendMessagesHelper().sendMessage(fmessages, did, true, 0);
            }
            fragment.finishFragment();
            return;
        }
        long did2 = dids.get(0).longValue();
        if (did2 != this.dialog_id) {
            int lower_part = (int) did2;
            int high_part = (int) (did2 >> 32);
            Bundle args = new Bundle();
            args.putBoolean("scrollToTopOnResume", this.scrollToTopOnResume);
            if (lower_part != 0) {
                if (lower_part > 0) {
                    args.putInt("user_id", lower_part);
                } else if (lower_part < 0) {
                    args.putInt("chat_id", -lower_part);
                }
            } else {
                args.putInt("enc_id", high_part);
            }
            if (lower_part != 0 && !getMessagesController().checkCanOpenChat(args, fragment)) {
                return;
            }
            ChatActivity chatActivity = new ChatActivity(args);
            if (presentFragment(chatActivity, true)) {
                chatActivity.showFieldPanelForForward(true, fmessages);
                if (!AndroidUtilities.isTablet()) {
                    removeSelfFromStack();
                    return;
                }
                return;
            }
            fragment.finishFragment();
            return;
        }
        fragment.finishFragment();
        moveScrollToLastMessage();
        showFieldPanelForForward(true, fmessages);
        if (AndroidUtilities.isTablet()) {
            hideActionMode();
            updatePinnedMessageView(true);
        }
        updateVisibleRows();
    }

    public boolean checkRecordLocked() {
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null && chatActivityEnterView.isRecordLocked()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            if (this.chatActivityEnterView.isInVideoMode()) {
                builder.setTitle(LocaleController.getString("DiscardVideoMessageTitle", R.string.DiscardVideoMessageTitle));
                builder.setMessage(LocaleController.getString("DiscardVideoMessageDescription", R.string.DiscardVideoMessageDescription));
            } else {
                builder.setTitle(LocaleController.getString("DiscardVoiceMessageTitle", R.string.DiscardVoiceMessageTitle));
                builder.setMessage(LocaleController.getString("DiscardVoiceMessageDescription", R.string.DiscardVoiceMessageDescription));
            }
            builder.setPositiveButton(LocaleController.getString("DiscardVoiceMessageAction", R.string.DiscardVoiceMessageAction), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$srG3RIpF9nWbfQqrjcXRlP-_E6A
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkRecordLocked$103$ChatActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Continue", R.string.Continue), null);
            showDialog(builder.create());
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$checkRecordLocked$103$ChatActivity(DialogInterface dialog, int which) {
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null) {
            chatActivityEnterView.cancelRecordingAudioVideo();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        ActionBarPopupWindow actionBarPopupWindow = this.scrimPopupWindow;
        if (actionBarPopupWindow != null) {
            actionBarPopupWindow.dismiss();
            return false;
        }
        if (checkRecordLocked()) {
            return false;
        }
        if (this.actionBar != null && this.actionBar.isActionModeShowed()) {
            for (int a = 1; a >= 0; a--) {
                this.selectedMessagesIds[a].clear();
                this.selectedMessagesCanCopyIds[a].clear();
                this.selectedMessagesCanStarIds[a].clear();
            }
            hideActionMode();
            updatePinnedMessageView(true);
            updateVisibleRows();
            return false;
        }
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView == null || !chatActivityEnterView.isPopupShowing()) {
            return true;
        }
        this.chatActivityEnterView.hidePopup(true);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0110  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void updateVisibleRows() {
        /*
            Method dump skipped, instruction units count: 343
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.updateVisibleRows():void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkEditTimer() {
        MessageObject messageObject;
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView == null || (messageObject = chatActivityEnterView.getEditingMessageObject()) == null || messageObject.scheduled) {
            return;
        }
        TLRPC.User user = this.currentUser;
        if (user != null && user.self) {
            return;
        }
        int dt = messageObject.canEditMessageAnytime(this.currentChat) ? 360 : (getMessagesController().maxEditTime + 300) - Math.abs(getConnectionsManager().getCurrentTime() - messageObject.messageOwner.date);
        if (dt > 0) {
            if (dt <= 300) {
                this.replyObjectTextView.setText(LocaleController.formatString("TimeToEdit", R.string.TimeToEdit, String.format("%d:%02d", Integer.valueOf(dt / 60), Integer.valueOf(dt % 60))));
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Y03oQTeNDVrp5oeEvLvwS6r6Qqk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.checkEditTimer();
                }
            }, 1000L);
        } else {
            this.chatActivityEnterView.onEditTimeExpired();
            this.replyObjectTextView.setText(LocaleController.formatString("TimeToEditExpired", R.string.TimeToEditExpired, new Object[0]));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public ArrayList<MessageObject> createVoiceMessagesPlaylist(MessageObject startMessageObject, boolean playingUnreadMedia) {
        ArrayList<MessageObject> messageObjects = new ArrayList<>();
        messageObjects.add(startMessageObject);
        int messageId = startMessageObject.getId();
        startMessageObject.getDialogId();
        if (messageId != 0) {
            for (int a = this.messages.size() - 1; a >= 0; a--) {
                MessageObject messageObject = this.messages.get(a);
                if ((messageObject.getDialogId() != this.mergeDialogId || startMessageObject.getDialogId() == this.mergeDialogId) && (((this.currentEncryptedChat == null && messageObject.getId() > messageId) || (this.currentEncryptedChat != null && messageObject.getId() < messageId)) && ((messageObject.isVoice() || messageObject.isRoundVideo()) && (!playingUnreadMedia || (messageObject.isContentUnread() && !messageObject.isOut()))))) {
                    messageObjects.add(messageObject);
                }
            }
        }
        return messageObjects;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void alertUserOpenError(MessageObject message) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        if (message.type == 3) {
            builder.setMessage(LocaleController.getString("NoPlayerInstalled", R.string.NoPlayerInstalled));
        } else {
            builder.setMessage(LocaleController.formatString("NoHandleAppInstalled", R.string.NoHandleAppInstalled, message.getDocument().mime_type));
        }
        showDialog(builder.create());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openSearchWithText(String text) {
        if (!this.actionBar.isSearchFieldVisible()) {
            this.headerItem.setVisibility(8);
            this.attachItem.setVisibility(8);
            this.editTextItem.setVisibility(8);
            this.searchItem.setVisibility(0);
            updateSearchButtons(0, 0, -1);
            updateBottomOverlay();
        }
        boolean z = text == null;
        this.openSearchKeyboard = z;
        this.searchItem.openSearch(z);
        if (text != null) {
            this.searchItem.setSearchFieldText(text, false);
            getMediaDataController().searchMessagesInChat(text, this.dialog_id, this.mergeDialogId, this.classGuid, 0, this.searchingUserMessages);
        }
        updatePinnedMessageView(true);
    }

    public boolean isEditingMessageMedia() {
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        return (chatAttachAlert == null || chatAttachAlert.getEditingMessageObject() == null) ? false : true;
    }

    public boolean isSecretChat() {
        return this.currentEncryptedChat != null;
    }

    public boolean canScheduleMessage() {
        FrameLayout frameLayout;
        return this.currentEncryptedChat == null && ((frameLayout = this.bottomOverlayChat) == null || frameLayout.getVisibility() != 0);
    }

    public boolean isInScheduleMode() {
        return this.inScheduleMode;
    }

    public TLRPC.User getCurrentUser() {
        return this.currentUser;
    }

    public TLRPC.Chat getCurrentChat() {
        return this.currentChat;
    }

    public boolean allowGroupPhotos() {
        TLRPC.EncryptedChat encryptedChat;
        return !isEditingMessageMedia() && ((encryptedChat = this.currentEncryptedChat) == null || AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) >= 73);
    }

    public TLRPC.EncryptedChat getCurrentEncryptedChat() {
        return this.currentEncryptedChat;
    }

    public TLRPC.ChatFull getCurrentChatInfo() {
        return this.chatInfo;
    }

    public TLRPC.UserFull getCurrentUserInfo() {
        return this.userInfo;
    }

    public void sendMedia(MediaController.PhotoEntry photoEntry, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
        if (photoEntry != null) {
            fillEditingMediaWithCaption(photoEntry.caption, photoEntry.entities);
            if (photoEntry.isVideo) {
                if (videoEditedInfo != null) {
                    SendMessagesHelper.prepareSendingVideo(getAccountInstance(), photoEntry.path, videoEditedInfo.estimatedSize, videoEditedInfo.estimatedDuration, videoEditedInfo.resultWidth, videoEditedInfo.resultHeight, videoEditedInfo, this.dialog_id, this.replyingMessageObject, photoEntry.caption, photoEntry.entities, photoEntry.ttl, this.editingMessageObject, notify, scheduleDate);
                } else {
                    SendMessagesHelper.prepareSendingVideo(getAccountInstance(), photoEntry.path, 0L, 0L, 0, 0, null, this.dialog_id, this.replyingMessageObject, photoEntry.caption, photoEntry.entities, photoEntry.ttl, this.editingMessageObject, notify, scheduleDate);
                }
                afterMessageSend();
                return;
            }
            if (photoEntry.imagePath != null) {
                SendMessagesHelper.prepareSendingPhoto(getAccountInstance(), photoEntry.imagePath, null, this.dialog_id, this.replyingMessageObject, photoEntry.caption, photoEntry.entities, photoEntry.stickers, null, photoEntry.ttl, this.editingMessageObject, notify, scheduleDate);
                afterMessageSend();
            } else if (photoEntry.path != null) {
                SendMessagesHelper.prepareSendingPhoto(getAccountInstance(), photoEntry.path, null, this.dialog_id, this.replyingMessageObject, photoEntry.caption, photoEntry.entities, photoEntry.stickers, null, photoEntry.ttl, this.editingMessageObject, notify, scheduleDate);
                afterMessageSend();
            }
        }
    }

    public void showOpenGameAlert(final TLRPC.TL_game game, final MessageObject messageObject, final String urlStr, boolean ask, final int uid) {
        String name;
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(uid));
        if (ask) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            if (user != null) {
                name = ContactsController.formatName(user.first_name, user.last_name);
            } else {
                name = "";
            }
            builder.setMessage(LocaleController.formatString("BotPermissionGameAlert", R.string.BotPermissionGameAlert, name));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Tl0epWmNLoPCW-ria29HL_Xeb6k
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$showOpenGameAlert$104$ChatActivity(game, messageObject, urlStr, uid, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
            return;
        }
        String str = "";
        if (Build.VERSION.SDK_INT >= 21 && !AndroidUtilities.isTablet() && WebviewActivity.supportWebview()) {
            if (this.parentLayout.fragmentsStack.get(this.parentLayout.fragmentsStack.size() - 1) == this) {
                if (user != null && !TextUtils.isEmpty(user.username)) {
                    str = user.username;
                }
                presentFragment(new WebviewActivity(urlStr, str, game.title, game.short_name, messageObject));
                return;
            }
            return;
        }
        FragmentActivity parentActivity = getParentActivity();
        String str2 = game.short_name;
        if (user != null && user.username != null) {
            str = user.username;
        }
        WebviewActivity.openGameInBrowser(urlStr, messageObject, parentActivity, str2, str);
    }

    public /* synthetic */ void lambda$showOpenGameAlert$104$ChatActivity(TLRPC.TL_game game, MessageObject messageObject, String urlStr, int uid, DialogInterface dialogInterface, int i) {
        showOpenGameAlert(game, messageObject, urlStr, false, uid);
        MessagesController.getNotificationsSettings(this.currentAccount).edit().putBoolean("askgame_" + uid, false).commit();
    }

    public void showOpenUrlAlert(final String url, boolean ask) {
        if (Browser.isInternalUrl(url, null) || !ask) {
            Browser.openUrl(getParentActivity(), url, this.inlineReturn == 0);
            return;
        }
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("OpenUrlTitle", R.string.OpenUrlTitle));
        String format = LocaleController.getString("OpenUrlAlert2", R.string.OpenUrlAlert2);
        int index = format.indexOf("%");
        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(String.format(format, url));
        if (index >= 0) {
            stringBuilder.setSpan(new URLSpan(url), index, url.length() + index, 33);
        }
        builder.setMessage(stringBuilder);
        builder.setMessageTextViewClickable(false);
        builder.setPositiveButton(LocaleController.getString("Open", R.string.Open), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$BMv1eb2puhi8k-ucQXch2rqdseg
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showOpenUrlAlert$105$ChatActivity(url, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$showOpenUrlAlert$105$ChatActivity(String url, DialogInterface dialogInterface, int i) {
        Browser.openUrl(getParentActivity(), url, this.inlineReturn == 0);
    }

    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r4v5 */
    public void showRequestUrlAlert(final TLRPC.TL_urlAuthResultRequest request, final TLRPC.TL_messages_requestUrlAuth buttonReq, final String url) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("OpenUrlTitle", R.string.OpenUrlTitle));
        String format = LocaleController.getString("OpenUrlAlert2", R.string.OpenUrlAlert2);
        int index = format.indexOf("%");
        int i = 1;
        ?? r4 = 0;
        SpannableStringBuilder stringBuilder = new SpannableStringBuilder(String.format(format, url));
        if (index >= 0) {
            stringBuilder.setSpan(new URLSpan(url), index, url.length() + index, 33);
        }
        builder.setMessage(stringBuilder);
        builder.setMessageTextViewClickable(false);
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        int i2 = 2;
        final CheckBoxCell[] cells = new CheckBoxCell[2];
        LinearLayout linearLayout = new LinearLayout(getParentActivity());
        linearLayout.setOrientation(1);
        TLRPC.User selfUser = getUserConfig().getCurrentUser();
        int index2 = 0;
        while (true) {
            if (index2 < (request.request_write_access ? 2 : 1)) {
                cells[index2] = new CheckBoxCell(getParentActivity(), i);
                cells[index2].setBackgroundDrawable(Theme.getSelectorDrawable(r4));
                cells[index2].setMultiline(i);
                cells[index2].setTag(Integer.valueOf(index2));
                if (index2 == 0) {
                    Object[] objArr = new Object[i2];
                    objArr[r4] = request.domain;
                    objArr[i] = ContactsController.formatName(selfUser.first_name, selfUser.last_name);
                    SpannableStringBuilder stringBuilder2 = AndroidUtilities.replaceTags(LocaleController.formatString("OpenUrlOption1", R.string.OpenUrlOption1, objArr));
                    int index3 = TextUtils.indexOf(stringBuilder2, request.domain);
                    if (index3 >= 0) {
                        stringBuilder2.setSpan(new URLSpan(""), index3, request.domain.length() + index3, 33);
                    }
                    cells[index2].setText(stringBuilder2, "", i, false);
                } else if (index2 == i) {
                    CheckBoxCell checkBoxCell = cells[index2];
                    Object[] objArr2 = new Object[i];
                    objArr2[0] = UserObject.getFirstName(request.bot);
                    checkBoxCell.setText(AndroidUtilities.replaceTags(LocaleController.formatString("OpenUrlOption2", R.string.OpenUrlOption2, objArr2)), "", true, false);
                }
                r4 = 0;
                cells[index2].setPadding(LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : AndroidUtilities.dp(8.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(8.0f) : AndroidUtilities.dp(16.0f), 0);
                linearLayout.addView(cells[index2], LayoutHelper.createLinear(-1, -2));
                cells[index2].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$015D2_GTvk9A3plf-72FoMve8Gg
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        ChatActivity.lambda$showRequestUrlAlert$106(cells, view);
                    }
                });
                index2++;
                i = 1;
                i2 = 2;
            } else {
                builder.setCustomViewOffset(12);
                builder.setView(linearLayout);
                builder.setPositiveButton(LocaleController.getString("Open", R.string.Open), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$iGywOQzl9dMjtCqOPu7nOFms0YU
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i3) {
                        this.f$0.lambda$showRequestUrlAlert$111$ChatActivity(cells, url, buttonReq, request, dialogInterface, i3);
                    }
                });
                showDialog(builder.create());
                return;
            }
        }
    }

    static /* synthetic */ void lambda$showRequestUrlAlert$106(CheckBoxCell[] cells, View v) {
        if (!v.isEnabled()) {
            return;
        }
        Integer num = (Integer) v.getTag();
        cells[num.intValue()].setChecked(!cells[num.intValue()].isChecked(), true);
        if (num.intValue() == 0 && cells[1] != null) {
            if (cells[num.intValue()].isChecked()) {
                cells[1].setEnabled(true);
            } else {
                cells[1].setChecked(false, true);
                cells[1].setEnabled(false);
            }
        }
    }

    public /* synthetic */ void lambda$showRequestUrlAlert$111$ChatActivity(CheckBoxCell[] cells, final String url, TLRPC.TL_messages_requestUrlAuth buttonReq, TLRPC.TL_urlAuthResultRequest request, DialogInterface dialogInterface, int i) {
        if (!cells[0].isChecked()) {
            Browser.openUrl((Context) getParentActivity(), url, false);
            return;
        }
        final AlertDialog[] progressDialog = {new AlertDialog(getParentActivity(), 3)};
        TLRPC.TL_messages_acceptUrlAuth req = new TLRPC.TL_messages_acceptUrlAuth();
        req.button_id = buttonReq.button_id;
        req.msg_id = buttonReq.msg_id;
        req.peer = buttonReq.peer;
        if (request.request_write_access) {
            req.write_allowed = cells[1].isChecked();
        }
        try {
            progressDialog[0].dismiss();
        } catch (Throwable th) {
        }
        progressDialog[0] = null;
        final int requestId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$gmQdr7YbbheFMOBblH0qdhr20EI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$108$ChatActivity(url, tLObject, tL_error);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$5cOrjvNhKQoBnQJAR8rkyb3f6wI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$110$ChatActivity(progressDialog, requestId);
            }
        }, 500L);
    }

    public /* synthetic */ void lambda$null$108$ChatActivity(final String url, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$2AgF4zU1_xVq6oh0W0OBOdWntKU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$107$ChatActivity(response, url);
            }
        });
    }

    public /* synthetic */ void lambda$null$107$ChatActivity(TLObject response, String url) {
        if (response instanceof TLRPC.TL_urlAuthResultAccepted) {
            TLRPC.TL_urlAuthResultAccepted res = (TLRPC.TL_urlAuthResultAccepted) response;
            Browser.openUrl((Context) getParentActivity(), res.url, false);
        } else if (response instanceof TLRPC.TL_urlAuthResultDefault) {
            Browser.openUrl((Context) getParentActivity(), url, false);
        }
    }

    public /* synthetic */ void lambda$null$110$ChatActivity(AlertDialog[] progressDialog, final int requestId) {
        if (progressDialog[0] == null) {
            return;
        }
        progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$7Yb7sxnNUioQbOMH-DkZmwcZzXI
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$null$109$ChatActivity(requestId, dialogInterface);
            }
        });
        showDialog(progressDialog[0]);
    }

    public /* synthetic */ void lambda$null$109$ChatActivity(int requestId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(requestId, true);
    }

    private void removeMessageObject(MessageObject messageObject) {
        int index = this.messages.indexOf(messageObject);
        if (index == -1) {
            return;
        }
        this.messages.remove(index);
        ChatActivityAdapter chatActivityAdapter = this.chatAdapter;
        if (chatActivityAdapter == null) {
            return;
        }
        chatActivityAdapter.notifyItemRemoved(chatActivityAdapter.messagesStartRow + index);
    }

    public void viewContacts(int user_id) {
        TLRPC.User user;
        if (user_id == 0 || (user = getMessagesController().getUser(Integer.valueOf(user_id))) == null) {
            return;
        }
        if (user.self || user.contact) {
            Bundle bundle = new Bundle();
            bundle.putInt("user_id", user.id);
            presentFragment(new NewProfileActivity(bundle));
        } else {
            Bundle bundle2 = new Bundle();
            bundle2.putInt("from_type", 6);
            presentFragment(new AddContactsInfoActivity(bundle2, user));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setCellSelectionBackground(MessageObject message, ChatMessageCell messageCell, int idx, boolean animated) {
        MessageObject.GroupedMessages groupedMessages = getValidGroupedMessage(message);
        if (groupedMessages != null) {
            boolean hasUnselected = false;
            int a = 0;
            while (true) {
                if (a >= groupedMessages.messages.size()) {
                    break;
                }
                if (this.selectedMessagesIds[idx].indexOfKey(groupedMessages.messages.get(a).getId()) >= 0) {
                    a++;
                } else {
                    hasUnselected = true;
                    break;
                }
            }
            if (!hasUnselected) {
                groupedMessages = null;
            }
        }
        messageCell.setDrawSelectionBackground(groupedMessages == null);
        boolean hasUnselected2 = groupedMessages == null;
        messageCell.setChecked(true, hasUnselected2, animated);
    }

    private void setItemAnimationsEnabled(boolean enabled) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateMessageListAccessibilityVisibility() {
        ActionBarPopupWindow actionBarPopupWindow;
        if (this.currentEncryptedChat == null && Build.VERSION.SDK_INT >= 19) {
            this.chatListView.setImportantForAccessibility((this.mentionContainer.getVisibility() == 0 || ((actionBarPopupWindow = this.scrimPopupWindow) != null && actionBarPopupWindow.isShowing())) ? 4 : 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getAccountInfo(final boolean isRpk) {
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        final XAlertDialog proView = new XAlertDialog(getParentActivity(), 5);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$N_EF4-QUzf2M09MkAF5TTTMR_rg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getAccountInfo$118$ChatActivity(proView, isRpk, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
        proView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$9yH6Kip8RSVuGxQKJHEv4IvKT6Q
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getAccountInfo$119$ChatActivity(reqId, dialogInterface);
            }
        });
        proView.show();
    }

    public /* synthetic */ void lambda$getAccountInfo$118$ChatActivity(final XAlertDialog proView, final boolean isRpk, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$gTulKkYQVD_8lqgJJmYFJXQhSL0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$117$ChatActivity(error, proView, response, isRpk);
            }
        });
    }

    public /* synthetic */ void lambda$null$117$ChatActivity(TLRPC.TL_error error, XAlertDialog proView, TLObject response, boolean isRpk) {
        if (error != null) {
            proView.dismiss();
            WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text));
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            proView.dismiss();
            String string = LocaleController.getString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted);
            Object[] objArr = new Object[2];
            objArr[0] = isRpk ? LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket) : LocaleController.getString("Transfer", R.string.Transfer);
            objArr[1] = isRpk ? LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket) : LocaleController.getString("Transfer", R.string.Transfer);
            WalletDialogUtil.showWalletDialog(this, "", String.format(string, objArr), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToWalletCenter", R.string.GoToWalletCenter), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$kNCKnQz4nU0D_TqLbj_iRKuoOII
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$112$ChatActivity(dialogInterface, i);
                }
            }, null);
            return;
        }
        TLApiModel<WalletAccountInfo> model = TLJsonResolve.parse(response, (Class<?>) WalletAccountInfo.class);
        if (model.isSuccess()) {
            WalletAccountInfo accountInfo = model.model;
            WalletConfigBean.setWalletAccountInfo(accountInfo);
            WalletConfigBean.setConfigValue(model.model.getRiskList());
            if (accountInfo.isLocked()) {
                proView.dismiss();
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString("PleaseContractServerToFindPayPasswordOrTryIt24HoursLater", R.string.PleaseContractServerToFindPayPasswordOrTryIt24HoursLater), LocaleController.getString("Close", R.string.Close), LocaleController.getString("ContactCustomerService", R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$4Uok9l3DYi_VBiEBDPhm8a6SOzg
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$113$ChatActivity(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!accountInfo.hasNormalAuth()) {
                proView.dismiss();
                String string2 = LocaleController.getString(R.string.BankCardNotBindTips);
                Object[] objArr2 = new Object[1];
                objArr2[0] = isRpk ? LocaleController.getString(R.string.redpacket_send) : LocaleController.getString("Transfer", R.string.Transfer);
                WalletDialogUtil.showWalletDialog(this, "", String.format(string2, objArr2), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$0GVB6FrSgSa8xQtD6iwlfynkPzs
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        ChatActivity.lambda$null$114(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!accountInfo.hasBindBank()) {
                proView.dismiss();
                String string3 = LocaleController.getString(R.string.BankCardNotBindTips);
                Object[] objArr3 = new Object[1];
                objArr3[0] = isRpk ? LocaleController.getString(R.string.redpacket_send) : LocaleController.getString("Transfer", R.string.Transfer);
                WalletDialogUtil.showWalletDialog(this, "", String.format(string3, objArr3), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$YoIxuen1B6hOlXOroSXXb3NHJY8
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        ChatActivity.lambda$null$115(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!accountInfo.hasPaypassword()) {
                proView.dismiss();
                String string4 = LocaleController.getString(R.string.PayPasswordNotSetTips);
                Object[] objArr4 = new Object[1];
                objArr4[0] = isRpk ? LocaleController.getString(R.string.redpacket_send) : LocaleController.getString("Transfer", R.string.Transfer);
                WalletDialogUtil.showWalletDialog(this, "", String.format(string4, objArr4), LocaleController.getString("Close", R.string.Close), LocaleController.getString("redpacket_goto_set", R.string.redpacket_goto_set), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$6AMKakOfUCwem3VoSsK7Ruw__TI
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$116$ChatActivity(dialogInterface, i);
                    }
                }, null);
                return;
            }
            proView.dismiss();
            if (isRpk) {
                if (this.currentUser != null) {
                    Bundle bundle = new Bundle();
                    bundle.putInt("user_id", this.currentUser.id);
                    RedpktSendActivity redpktSendActivity = new RedpktSendActivity(bundle);
                    redpktSendActivity.setAccountInfo(accountInfo);
                    presentFragment(redpktSendActivity);
                    return;
                }
                if (this.currentChat != null) {
                    RedpktGroupSendActivity groupSendActivity = new RedpktGroupSendActivity(null);
                    groupSendActivity.setToChat(this.currentChat);
                    groupSendActivity.setParticipants(this.chatInfo);
                    groupSendActivity.setAccountInfo(accountInfo);
                    presentFragment(groupSendActivity);
                    return;
                }
                return;
            }
            Bundle bundle2 = new Bundle();
            bundle2.putInt("user_id", this.currentUser.id);
            TransferSendActivity transferSendActivity = new TransferSendActivity(bundle2);
            transferSendActivity.setAccountInfo(accountInfo);
            presentFragment(transferSendActivity);
            return;
        }
        proView.dismiss();
        WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(model.message));
    }

    public /* synthetic */ void lambda$null$112$ChatActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new WalletActivity());
    }

    public /* synthetic */ void lambda$null$113$ChatActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new AboutAppActivity());
    }

    static /* synthetic */ void lambda$null$114(DialogInterface dialogInterface, int i) {
    }

    static /* synthetic */ void lambda$null$115(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$116$ChatActivity(DialogInterface dialogInterface, int i) {
        Bundle args = new Bundle();
        args.putInt("step", 0);
        args.putInt("type", 0);
        presentFragment(new WalletPaymentPasswordActivity(args));
    }

    public /* synthetic */ void lambda$getAccountInfo$119$ChatActivity(int reqId, DialogInterface hintDialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    public void performService(final BaseFragment fragment) {
        String userString;
        final int currentAccount = fragment.getCurrentAccount();
        final SharedPreferences preferences = MessagesController.getMainSettings(currentAccount);
        int uid = preferences.getInt("support_id", 0);
        TLRPC.User supportUser = null;
        if (uid != 0 && (supportUser = MessagesController.getInstance(currentAccount).getUser(Integer.valueOf(uid))) == null && (userString = preferences.getString("support_user", null)) != null) {
            try {
                byte[] datacentersBytes = Base64.decode(userString, 0);
                if (datacentersBytes != null) {
                    SerializedData data = new SerializedData(datacentersBytes);
                    supportUser = TLRPC.User.TLdeserialize(data, data.readInt32(false), false);
                    if (supportUser != null && supportUser.id == 333000) {
                        supportUser = null;
                    }
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
                supportUser = null;
            }
        }
        if (supportUser == null) {
            final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
            progressDialog.show();
            TLRPC.TL_help_getSupport req = new TLRPC.TL_help_getSupport();
            ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$G0a07LJyU3FpJFtTejMUy7QkuGw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    ChatActivity.lambda$performService$122(preferences, progressDialog, currentAccount, fragment, tLObject, tL_error);
                }
            });
            return;
        }
        MessagesController.getInstance(currentAccount).putUser(supportUser, true);
        Bundle args = new Bundle();
        args.putInt("user_id", supportUser.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$performService$122(final SharedPreferences preferences, final XAlertDialog progressDialog, final int currentAccount, final BaseFragment fragment, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            final TLRPC.TL_help_support res = (TLRPC.TL_help_support) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$qAW-KDj6YOjDxwz58Ut2qXxGqXk
                @Override // java.lang.Runnable
                public final void run() {
                    ChatActivity.lambda$null$120(preferences, res, progressDialog, currentAccount, fragment);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$8QhuGz58af_9WWnQh0ZLOU4UAvE
                @Override // java.lang.Runnable
                public final void run() {
                    ChatActivity.lambda$null$121(progressDialog);
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$120(SharedPreferences preferences, TLRPC.TL_help_support res, XAlertDialog progressDialog, int currentAccount, BaseFragment fragment) {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putInt("support_id", res.user.id);
        SerializedData data = new SerializedData();
        res.user.serializeToStream(data);
        editor.putString("support_user", Base64.encodeToString(data.toByteArray(), 0));
        editor.commit();
        data.cleanup();
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(res.user);
        MessagesStorage.getInstance(currentAccount).putUsersAndChats(users, null, true, true);
        MessagesController.getInstance(currentAccount).putUser(res.user, false);
        Bundle args = new Bundle();
        args.putInt("user_id", res.user.id);
        fragment.presentFragment(new ChatActivity(args));
    }

    static /* synthetic */ void lambda$null$121(XAlertDialog progressDialog) {
        try {
            progressDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onRedpkgTransferClick(ChatMessageCell cell, MessageObject messageObject) {
        TLRPCRedpacket.CL_messagesRpkTransferMedia rpkTransferMedia = (TLRPCRedpacket.CL_messagesRpkTransferMedia) messageObject.messageOwner.media;
        if (rpkTransferMedia.trans == 0) {
            TLApiModel<RedpacketResponse> parse = TLJsonResolve.parse(rpkTransferMedia.data, (Class<?>) RedpacketResponse.class);
            RedpacketResponse bean = parse.model;
            if (this.currentUser != null) {
                if (messageObject.isOutOwner()) {
                    int status = Integer.parseInt(bean.getRed().getStatus());
                    if (status == 1 || status == 2) {
                        RedpktDetailActivity redpkgStateActivity = new RedpktDetailActivity();
                        redpkgStateActivity.setBean(bean);
                        presentFragment(redpkgStateActivity);
                        return;
                    }
                    checkUserRedpkgDetail(messageObject, bean);
                    return;
                }
                int status2 = Integer.parseInt(bean.getRed().getStatus());
                if (status2 == 0) {
                    checkUserRedpkgDetail(messageObject, bean);
                    return;
                } else {
                    if (status2 == 1) {
                        RedpktDetailReceiverActivity receiverActivity = new RedpktDetailReceiverActivity();
                        receiverActivity.setBean(bean);
                        presentFragment(receiverActivity);
                        return;
                    }
                    showRedPacketDialog(this.currentUser, messageObject, bean, false);
                    return;
                }
            }
            if (this.currentChat != null) {
                RedpacketBean red = bean.getRed();
                boolean isReceived = bean.isReceived();
                int status3 = Integer.parseInt(red.getStatus());
                if (messageObject.isOut()) {
                    if (status3 == 0) {
                        if (isReceived) {
                            RedpktGroupDetailActivity detailActivity = new RedpktGroupDetailActivity();
                            detailActivity.setBean(bean.getRed());
                            detailActivity.setChat(this.currentChat);
                            detailActivity.setMessageId(messageObject.messageOwner.id);
                            presentFragment(detailActivity);
                            return;
                        }
                        checkGroupRedpkgDetail(messageObject, bean);
                        return;
                    }
                    if (status3 == 1 || status3 == 2) {
                        if (isReceived || "2".equals(red.getRedType())) {
                            RedpktGroupDetailActivity detailActivity2 = new RedpktGroupDetailActivity();
                            detailActivity2.setBean(bean.getRed());
                            detailActivity2.setChat(this.currentChat);
                            detailActivity2.setMessageId(messageObject.messageOwner.id);
                            presentFragment(detailActivity2);
                            return;
                        }
                        showRedPacketDialog(getUserConfig().getCurrentUser(), messageObject, bean, true);
                        return;
                    }
                    return;
                }
                if (status3 == 0) {
                    if (isReceived) {
                        RedpktGroupDetailActivity detailActivity3 = new RedpktGroupDetailActivity();
                        detailActivity3.setBean(bean.getRed());
                        detailActivity3.setChat(this.currentChat);
                        detailActivity3.setMessageId(messageObject.messageOwner.id);
                        presentFragment(detailActivity3);
                        return;
                    }
                    checkGroupRedpkgDetail(messageObject, bean);
                    return;
                }
                if (status3 == 1) {
                    if (isReceived) {
                        RedpktGroupDetailActivity detailActivity4 = new RedpktGroupDetailActivity();
                        detailActivity4.setBean(bean.getRed());
                        detailActivity4.setChat(this.currentChat);
                        detailActivity4.setMessageId(messageObject.messageOwner.id);
                        presentFragment(detailActivity4);
                        return;
                    }
                    TLRPC.User sender = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(Integer.parseInt(red.getInitiatorUserId())));
                    showRedPacketDialog(sender, messageObject, bean, true);
                    return;
                }
                if (status3 == 2) {
                    if (isReceived) {
                        RedpktGroupDetailActivity detailActivity5 = new RedpktGroupDetailActivity();
                        detailActivity5.setBean(bean.getRed());
                        detailActivity5.setChat(this.currentChat);
                        detailActivity5.setMessageId(messageObject.messageOwner.id);
                        presentFragment(detailActivity5);
                        return;
                    }
                    TLRPC.User sender2 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(Integer.parseInt(red.getInitiatorUserId())));
                    showRedPacketDialog(sender2, messageObject, bean, true);
                    return;
                }
                return;
            }
            return;
        }
        if (rpkTransferMedia.trans == 1 || rpkTransferMedia.trans == 2) {
            TLApiModel<TransferResponse> parse2 = TLJsonResolve.parse(rpkTransferMedia.data, (Class<?>) TransferResponse.class);
            TransferResponse transferRes = parse2.model;
            if (transferRes.getState() == TransferResponse.Status.RECEIVED || transferRes.getState() == TransferResponse.Status.REFUSED || transferRes.getState() == TransferResponse.Status.TIMEOUT) {
                TransferStatusActivity transferStatusActivity = new TransferStatusActivity();
                transferStatusActivity.setMessage(messageObject.messageOwner);
                transferStatusActivity.setTargetUser(this.currentUser);
                transferStatusActivity.setSender(messageObject.isOutOwner());
                presentFragment(transferStatusActivity);
                return;
            }
            checkUserTransferDetail(messageObject, transferRes);
        }
    }

    public void showRedPacketDialog(final TLRPC.User sender, final MessageObject messageObject, final RedpacketResponse bean, final boolean isChat) {
        if (this.mRedPacketDialogView == null) {
            this.mRedPacketDialogView = View.inflate(getParentActivity(), R.layout.dialog_red_packet_layout, null);
            this.mRedPacketViewHolder = new RedPacketViewHolder(getParentActivity(), this.mRedPacketDialogView);
            DialogRedpkg dialogRedpkg = new DialogRedpkg(getParentActivity(), this.mRedPacketDialogView, R.plurals.red_pkg_dialog);
            this.mRedPacketDialog = dialogRedpkg;
            dialogRedpkg.setCancelable(false);
        }
        this.mRedPacketViewHolder.setData(sender, bean, isChat);
        this.mRedPacketViewHolder.setOnRedPacketDialogClickListener(new OnRedPacketDialogClickListener() { // from class: im.uwrkaxlmjj.ui.ChatActivity.74
            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.OnRedPacketDialogClickListener
            public void onCloseClick() {
                ChatActivity.this.mRedPacketViewHolder.stopAnim();
                ChatActivity.this.mRedPacketDialog.dismiss();
            }

            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.OnRedPacketDialogClickListener
            public void onOpenClick() {
                ChatActivity.this.getRedpacket(sender, messageObject, bean, isChat);
            }

            @Override // im.uwrkaxlmjj.ui.hui.packet.pop.OnRedPacketDialogClickListener
            public void toDetail(RedpacketResponse ret) {
                if (ChatActivity.this.currentUser != null) {
                    RedpktDetailReceiverActivity receiverActivity = new RedpktDetailReceiverActivity();
                    if (ret != null) {
                        receiverActivity.setBean(ret);
                    } else {
                        receiverActivity.setBean(bean);
                    }
                    ChatActivity.this.presentFragment(receiverActivity);
                } else {
                    RedpktGroupDetailActivity detailActivity = new RedpktGroupDetailActivity();
                    if (ret != null) {
                        detailActivity.setBean(ret.getRed());
                    } else {
                        detailActivity.setBean(bean.getRed());
                    }
                    detailActivity.setChat(ChatActivity.this.currentChat);
                    detailActivity.setMessageId(messageObject.messageOwner.id);
                    ChatActivity.this.presentFragment(detailActivity);
                }
                ChatActivity.this.mRedPacketViewHolder.stopAnim();
                ChatActivity.this.mRedPacketDialog.dismiss();
            }
        });
        this.mRedPacketDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$05xUELUNy1CjFrOCv2k1Aalm750
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$showRedPacketDialog$123$ChatActivity(dialogInterface);
            }
        });
        this.mRedPacketDialog.show();
    }

    public /* synthetic */ void lambda$showRedPacketDialog$123$ChatActivity(DialogInterface dialog) {
        this.mRedPacketViewHolder.clear();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getRedpacket(TLRPC.User target, MessageObject messageObject, RedpacketResponse bean, boolean isChat) {
        TLRPCRedpacket.CL_messages_rpkTransferReceive req = new TLRPCRedpacket.CL_messages_rpkTransferReceive();
        req.trans = 0;
        if (isChat) {
            TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerChannel();
            inputPeer.channel_id = this.currentChat.id;
            inputPeer.access_hash = this.currentChat.access_hash;
            req.peer = inputPeer;
        } else {
            req.peer = getMessagesController().getInputPeer(target.id);
        }
        req.id = messageObject.messageOwner.id;
        req.flags = 3;
        if (isChat) {
            RedpacketBean redInfo = bean.getRed();
            int redType = redInfo.getRedTypeInt();
            if (redType == 1) {
                int grantType = redInfo.getGrantTypeInt();
                if (grantType == 0) {
                    req.type = 2;
                } else if (grantType == 1) {
                    req.type = 1;
                }
            } else if (redType == 2) {
                req.type = 3;
            }
        } else {
            req.type = 0;
        }
        RedTransOperation receiveRedpacket = new RedTransOperation(bean.getRed().getSerialCode(), String.valueOf(getUserConfig().getClientUserId()), StringUtils.getNonceStr(getConnectionsManager().getCurrentTime()), UnifyBean.BUSINESS_KEY_REDPACKET_RECEIVE, "2.0.1");
        TLRPC.Chat chat = this.currentChat;
        if (chat != null) {
            receiveRedpacket.setGroups(String.valueOf(chat.id));
        }
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = new Gson().toJson(receiveRedpacket);
        req.data = dataJSON;
        Handler handler = new Handler();
        handler.postDelayed(new AnonymousClass75(req, bean, messageObject), 800L);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$75, reason: invalid class name */
    class AnonymousClass75 implements Runnable {
        final /* synthetic */ RedpacketResponse val$bean;
        final /* synthetic */ MessageObject val$messageObject;
        final /* synthetic */ TLRPCRedpacket.CL_messages_rpkTransferReceive val$req;

        AnonymousClass75(TLRPCRedpacket.CL_messages_rpkTransferReceive cL_messages_rpkTransferReceive, RedpacketResponse redpacketResponse, MessageObject messageObject) {
            this.val$req = cL_messages_rpkTransferReceive;
            this.val$bean = redpacketResponse;
            this.val$messageObject = messageObject;
        }

        @Override // java.lang.Runnable
        public void run() {
            ConnectionsManager connectionsManager = ChatActivity.this.getConnectionsManager();
            TLRPCRedpacket.CL_messages_rpkTransferReceive cL_messages_rpkTransferReceive = this.val$req;
            final RedpacketResponse redpacketResponse = this.val$bean;
            final MessageObject messageObject = this.val$messageObject;
            connectionsManager.sendRequest(cL_messages_rpkTransferReceive, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$75$AMzo9CXrALmXkWrDlnIbh1QLrbQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$run$1$ChatActivity$75(redpacketResponse, messageObject, tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$run$1$ChatActivity$75(final RedpacketResponse bean, final MessageObject messageObject, TLObject response, TLRPC.TL_error error) {
            if (error != null) {
                if ("RED_MSG_NOT_EXIST".equals(error.text)) {
                    WalletDialogUtil.showSingleBtnWalletDialog(ChatActivity.this, "红包已撤回，不能领取了", null);
                } else if ("REPEATED_REQUESTS".equals(error.text)) {
                    WalletDialogUtil.showConfirmBtnWalletDialog(ChatActivity.this, "您的其它设备正在领取红包!");
                } else if ("CHANNEL_NOT_EXIST".equals(error.text)) {
                    WalletDialogUtil.showConfirmBtnWalletDialog(ChatActivity.this, "该群已解散，不能领取红包!");
                } else {
                    AlertsCreator.showSimpleToast(ChatActivity.this, LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater));
                }
                ChatActivity.this.mRedPacketViewHolder.stopAnim();
                ChatActivity.this.mRedPacketDialog.dismiss();
                return;
            }
            if (response instanceof TLRPC.TL_updates) {
                TLRPC.TL_updates updates = (TLRPC.TL_updates) response;
                ChatActivity.this.getMessagesController().processUpdates(updates, false);
                if (0 < updates.updates.size()) {
                    TLRPC.Update update = updates.updates.get(0);
                    if (update instanceof TLRPCRedpacket.CL_updateRpkTransfer) {
                        TLRPCRedpacket.CL_updateRpkTransfer rpkUpdate = (TLRPCRedpacket.CL_updateRpkTransfer) update;
                        TLApiModel<RedpacketResponse> parse = TLJsonResolve.parse(rpkUpdate.data, (Class<?>) RedpacketResponse.class);
                        final RedpacketResponse ret = parse.model;
                        if ("20004".equals(parse.code)) {
                            ChatActivity.this.mRedPacketViewHolder.setPromtText(LocaleController.getString("RedpacketIsGone", R.string.RedpacketIsGone), true);
                            ChatActivity.this.mRedPacketViewHolder.setRet(ret);
                            return;
                        }
                        if ("20005".equals(parse.code)) {
                            ChatActivity.this.mRedPacketViewHolder.setPromtText(LocaleController.getString("RedpacketHadExpired", R.string.RedpacketHadExpired));
                            return;
                        }
                        if ("20008".equals(parse.code)) {
                            ChatActivity.this.mRedPacketViewHolder.setPromtText(LocaleController.getString("YouCantReceivedRedpacket", R.string.YouCantReceivedRedpacket));
                            return;
                        }
                        if ("50000".equals(parse.code)) {
                            ChatActivity.this.mRedPacketViewHolder.setPromtText("抢红包人数过多，请稍后在记录中查看！");
                            return;
                        }
                        if ("20003".equals(parse.code)) {
                            ChatActivity.this.mRedPacketViewHolder.setPromtText(LocaleController.getString("YouHadAlreadyReceived", R.string.YouHadAlreadyReceived), true);
                            ChatActivity.this.mRedPacketViewHolder.setRet(ret);
                            return;
                        }
                        if ("50001".equals(parse.code)) {
                            ChatActivity.this.mRedPacketViewHolder.setPromtText("您的其它设备正在领取红包");
                            return;
                        }
                        if ("0".equals(parse.code)) {
                            ret.getRed().getStatus();
                            int isReceived = ret.getRed().getIsReceived();
                            boolean received = ret.isReceived();
                            if (isReceived == 1 || received) {
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$75$BDRgwZr0BnvUYXETT6Rv45FEFkI
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$null$0$ChatActivity$75(bean, messageObject, ret);
                                    }
                                });
                                return;
                            }
                            return;
                        }
                        ToastUtils.show((CharSequence) WalletErrorUtil.getErrorDescription(parse.message));
                    }
                }
            }
        }

        public /* synthetic */ void lambda$null$0$ChatActivity$75(RedpacketResponse bean, MessageObject messageObject, RedpacketResponse ret) {
            if (ChatActivity.this.currentChat != null) {
                RedpktGroupDetailActivity detailActivity = new RedpktGroupDetailActivity();
                detailActivity.setBean(bean.getRed());
                detailActivity.setChat(ChatActivity.this.currentChat);
                detailActivity.setMessageId(messageObject.messageOwner.id);
                ChatActivity.this.presentFragment(detailActivity);
            } else {
                RedpktDetailReceiverActivity receiverActivity = new RedpktDetailReceiverActivity();
                receiverActivity.setBean(ret);
                ChatActivity.this.presentFragment(receiverActivity);
            }
            ChatActivity.this.mRedPacketViewHolder.stopAnim();
            ChatActivity.this.mRedPacketViewHolder.setRet(ret);
            ChatActivity.this.mRedPacketDialog.dismiss();
        }
    }

    private void checkGroupRedpkgDetail(final MessageObject messageObject, RedpacketResponse bean) {
        TLRPCRedpacket.CL_message_rpkTransferCheck req = new TLRPCRedpacket.CL_message_rpkTransferCheck();
        req.trans = 0;
        if (this.currentChat != null) {
            RedpacketBean redInfo = bean.getRed();
            int redType = redInfo.getRedTypeInt();
            if (redType == 1) {
                int grantType = redInfo.getGrantTypeInt();
                if (grantType == 0) {
                    req.type = 2;
                } else if (grantType == 1) {
                    req.type = 1;
                }
            } else if (redType == 2) {
                req.type = 3;
            }
        } else {
            req.type = 0;
        }
        req.flags = 2;
        TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerChannel();
        inputPeer.channel_id = this.currentChat.id;
        inputPeer.access_hash = this.currentChat.access_hash;
        req.peer = inputPeer;
        req.id = messageObject.messageOwner.id;
        String serialCode = bean.getRed().getSerialCode();
        String str = getUserConfig().clientUserId + "";
        TLRPC.Chat chat = this.currentChat;
        RedTransOperation rpkCheckRequest = new RedTransOperation(serialCode, str, chat == null ? "" : String.valueOf(chat.id), "android_" + getUserConfig().clientUserId + getConnectionsManager().getCurrentTime(), UnifyBean.BUSINESS_KEY_REDPACKET_CHECK, "2.0.1");
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = new Gson().toJson(rpkCheckRequest);
        req.data = dataJSON;
        this.redTransAlert = new XAlertDialog(getParentActivity(), 5);
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$APG2xya72HkQsm7esqqUhtNJLpg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkGroupRedpkgDetail$134$ChatActivity(messageObject, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(this.reqId, this.classGuid);
        this.redTransAlert.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$wgN6vYF9TMeO7bNjdJ0pEMUIBcU
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$checkGroupRedpkgDetail$135$ChatActivity(dialogInterface);
            }
        });
        this.redTransAlert.show();
    }

    public /* synthetic */ void lambda$checkGroupRedpkgDetail$134$ChatActivity(final MessageObject messageObject, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$c5d3EQuDeJ1eYgOR0-Y2i3px18E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$124$ChatActivity();
            }
        });
        if (error != null) {
            WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text));
            return;
        }
        if (response instanceof TLRPC.TL_updates) {
            TLRPC.TL_updates updates = (TLRPC.TL_updates) response;
            for (TLRPC.Update update : updates.updates) {
                if (update instanceof TLRPCRedpacket.CL_updateRpkTransfer) {
                    TLRPCRedpacket.CL_updateRpkTransfer rpkTransfer = (TLRPCRedpacket.CL_updateRpkTransfer) update;
                    TLApiModel<RedpacketResponse> parse = TLJsonResolve.parse(rpkTransfer.data, (Class<?>) RedpacketResponse.class);
                    if (parse.isSuccess() || "20004".equals(parse.code) || "20013".equals(parse.code) || "20008".equals(parse.code)) {
                        final RedpacketResponse retBean = parse.model;
                        RedpacketBean red = retBean.getRed();
                        if (red != null) {
                            getMessagesController().processUpdates(updates, false);
                            if (red.getStatus() != null && !TextUtils.isEmpty(red.getStatus())) {
                                final TLRPC.User sender = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(Integer.parseInt(red.getInitiatorUserId())));
                                final int isReceived = red.getIsReceived();
                                final boolean received = retBean.isReceived();
                                final int redType = Integer.parseInt(red.getRedType());
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$skU_iWnac3Zmu1bNenvdOti2pjU
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$null$125$ChatActivity(isReceived, received, redType, messageObject, retBean, sender);
                                    }
                                });
                                return;
                            }
                            return;
                        }
                        return;
                    }
                    if ("USER_INFONNOT_CODE".equals(parse.message) || "SYSTEM_ERROR_ACCOUNT_EXCEPTION_CODE".equals(parse.message)) {
                        WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket), LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket)), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.GoToWalletCenter), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$w4IZDnRxqhzSafhp4cWLTddvrbo
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Cz5yP0n_QxM8cY0ZgUzIfivznb4
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        ChatActivity.lambda$null$126();
                                    }
                                });
                            }
                        }, null);
                        return;
                    }
                    if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(parse.message)) {
                        WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString(R.string.PleaseContractServerToFindPayPasswordOrTryIt24HoursLater), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$DZkggKeWVL4etu5glLkNOovqY_8
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                this.f$0.lambda$null$129$ChatActivity(dialogInterface, i);
                            }
                        }, null);
                        return;
                    }
                    if (!"ACCOUNT_UNCERTIFIED_CODE".equals(parse.message) && !"EXCLUSIVE_PLEASE_BIND_FIRST_BANKINFO".equals(parse.message)) {
                        if ("SYSTEM_ERROR_NOT_SET_PAYWORD_COCE".equals(parse.message)) {
                            WalletDialogUtil.showWalletDialog(this, "", String.format(LocaleController.getString("PayPasswordNotSetTips", R.string.PayPasswordNotSetTips), LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket)), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.redpacket_goto_set), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$dDqz7NGenWI4xQJ7tfGfa9fJDJk
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i) {
                                    this.f$0.lambda$null$133$ChatActivity(dialogInterface, i);
                                }
                            }, null);
                            return;
                        } else if (BuildVars.RELEASE_VERSION) {
                            WalletErrorUtil.parseErrorDialog(this, LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
                            return;
                        } else {
                            WalletErrorUtil.parseErrorDialog(this, parse.code, parse.message);
                            return;
                        }
                    }
                    WalletDialogUtil.showWalletDialog(this, "", String.format(LocaleController.getString("BankCardNotBindTips", R.string.BankCardNotBindTips), LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket)), LocaleController.getString(R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$XVZxFOQfoea9_ZKfyVJNWGPmIMg
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$qXUO_AigI58XfT-kGcfZgBTjxq0
                                @Override // java.lang.Runnable
                                public final void run() {
                                    ChatActivity.lambda$null$130();
                                }
                            });
                        }
                    }, null);
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$124$ChatActivity() {
        this.redTransAlert.dismiss();
    }

    public /* synthetic */ void lambda$null$125$ChatActivity(int isReceived, boolean received, int redType, MessageObject messageObject, RedpacketResponse retBean, TLRPC.User sender) {
        if (isReceived == 1 || received || (redType == 2 && messageObject.isOutOwner())) {
            RedpktGroupDetailActivity detailActivity = new RedpktGroupDetailActivity();
            detailActivity.setBean(retBean.getRed());
            detailActivity.setChat(this.currentChat);
            detailActivity.setMessageId(messageObject.messageOwner.id);
            presentFragment(detailActivity);
            return;
        }
        showRedPacketDialog(sender, messageObject, retBean, true);
    }

    static /* synthetic */ void lambda$null$126() {
    }

    public /* synthetic */ void lambda$null$128$ChatActivity() {
        presentFragment(new AboutAppActivity());
    }

    public /* synthetic */ void lambda$null$129$ChatActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$JFUc6-S0U7VTHhAP9jUirwuBrCY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$128$ChatActivity();
            }
        });
    }

    static /* synthetic */ void lambda$null$130() {
    }

    public /* synthetic */ void lambda$null$133$ChatActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$TtZy7MVhzRTNshptpZpQlZMnzr0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$132$ChatActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$132$ChatActivity() {
        Bundle args = new Bundle();
        args.putInt("step", 0);
        args.putInt("type", 0);
        presentFragment(new WalletPaymentPasswordActivity(args));
    }

    public /* synthetic */ void lambda$checkGroupRedpkgDetail$135$ChatActivity(DialogInterface hintDialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
    }

    private void checkUserRedpkgDetail(final MessageObject messageObject, RedpacketResponse bean) {
        TLRPCRedpacket.CL_message_rpkTransferCheck req = new TLRPCRedpacket.CL_message_rpkTransferCheck();
        req.trans = 0;
        req.type = 0;
        req.flags = 2;
        req.id = messageObject.messageOwner.id;
        TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerUser();
        inputPeer.user_id = this.currentUser.id;
        inputPeer.access_hash = this.currentUser.access_hash;
        req.peer = inputPeer;
        this.redTransAlert = new XAlertDialog(getParentActivity(), 5);
        String serialCode = bean.getRed().getSerialCode();
        String str = getUserConfig().clientUserId + "";
        TLRPC.User user = this.currentUser;
        RedTransOperation rpkCheckRequest = new RedTransOperation(serialCode, str, user == null ? "" : String.valueOf(user.id), StringUtils.getRandomString(20) + getConnectionsManager().getCurrentTime(), UnifyBean.BUSINESS_KEY_REDPACKET_CHECK, "2.0.1");
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = new Gson().toJson(rpkCheckRequest);
        req.data = dataJSON;
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$kYZeNJy3m8SFf1qwDApniBtM444
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkUserRedpkgDetail$146$ChatActivity(messageObject, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(this.reqId, this.classGuid);
        this.redTransAlert.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$lBwlrMcUc4wlYzSsVOi2JBCM70Q
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$checkUserRedpkgDetail$147$ChatActivity(dialogInterface);
            }
        });
        this.redTransAlert.show();
    }

    public /* synthetic */ void lambda$checkUserRedpkgDetail$146$ChatActivity(final MessageObject messageObject, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$peIObNu7WxPo0i3iMHsykA3bXLU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$136$ChatActivity();
            }
        });
        if (error != null) {
            AlertsCreator.showSimpleToast(this, LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater));
            return;
        }
        if (response instanceof TLRPC.TL_updates) {
            TLRPC.TL_updates updates = (TLRPC.TL_updates) response;
            for (TLRPC.Update update : updates.updates) {
                if (update instanceof TLRPCRedpacket.CL_updateRpkTransfer) {
                    TLRPCRedpacket.CL_updateRpkTransfer rpkTransfer = (TLRPCRedpacket.CL_updateRpkTransfer) update;
                    TLApiModel<RedpacketResponse> parse = TLJsonResolve.parse(rpkTransfer.data, (Class<?>) RedpacketResponse.class);
                    if (parse.isSuccess() || "20004".equals(parse.code) || "20013".equals(parse.code) || "20008".equals(parse.code)) {
                        final RedpacketResponse retBean = parse.model;
                        final RedpacketBean red = retBean.getRed();
                        if (red != null) {
                            getMessagesController().processUpdates(updates, false);
                            if (red.getStatus() != null && !TextUtils.isEmpty(red.getStatus())) {
                                final TLRPC.User sender = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(Integer.parseInt(red.getInitiatorUserId())));
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$6VjfFs1n0TZUQK8Hpx__j71X6zQ
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$null$137$ChatActivity(red, messageObject, retBean, sender);
                                    }
                                });
                                return;
                            }
                            return;
                        }
                        return;
                    }
                    if ("USER_INFONNOT_CODE".equals(parse.message) || "SYSTEM_ERROR_ACCOUNT_EXCEPTION_CODE".equals(parse.message)) {
                        WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket), LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket)), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.GoToWalletCenter), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$gOWu5BA6MOW88cr_SxW37-Z9goQ
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$w8_EtPfO7xdMD-efk-xuEfmxDu8
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        ChatActivity.lambda$null$138();
                                    }
                                });
                            }
                        }, null);
                        return;
                    }
                    if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(parse.message)) {
                        WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString(R.string.PleaseContractServerToFindPayPasswordOrTryIt24HoursLater), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$zpL8wj9E5q5qzhU7hErx4jCyTaI
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                this.f$0.lambda$null$141$ChatActivity(dialogInterface, i);
                            }
                        }, null);
                        return;
                    }
                    if (!"ACCOUNT_UNCERTIFIED_CODE".equals(parse.message) && !"EXCLUSIVE_PLEASE_BIND_FIRST_BANKINFO".equals(parse.message)) {
                        if ("SYSTEM_ERROR_NOT_SET_PAYWORD_COCE".equals(parse.message)) {
                            WalletDialogUtil.showWalletDialog(this, "", String.format(LocaleController.getString("PayPasswordNotSetTips", R.string.PayPasswordNotSetTips), LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket)), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.redpacket_goto_set), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$qxH8Bl2Wy1Uiod3nrq-5yonzgzE
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i) {
                                    this.f$0.lambda$null$145$ChatActivity(dialogInterface, i);
                                }
                            }, null);
                            return;
                        } else if (BuildVars.RELEASE_VERSION) {
                            WalletErrorUtil.parseErrorDialog(this, LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
                            return;
                        } else {
                            WalletErrorUtil.parseErrorDialog(this, parse.code, parse.message);
                            return;
                        }
                    }
                    WalletDialogUtil.showWalletDialog(this, "", String.format(LocaleController.getString("BankCardNotBindTips", R.string.BankCardNotBindTips), LocaleController.getString("ReceiveRedPacket", R.string.ReceiveRedPacket)), LocaleController.getString(R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$tLnoeZahJXtT1EY3FcxqerG0vZw
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$JL--CQaXZ6dlOqyFPu6IumL3O88
                                @Override // java.lang.Runnable
                                public final void run() {
                                    ChatActivity.lambda$null$142();
                                }
                            });
                        }
                    }, null);
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$136$ChatActivity() {
        this.redTransAlert.dismiss();
    }

    public /* synthetic */ void lambda$null$137$ChatActivity(RedpacketBean red, MessageObject messageObject, RedpacketResponse retBean, TLRPC.User sender) {
        int status = Integer.parseInt(red.getStatus());
        if (messageObject.isOut()) {
            RedpktDetailActivity redpkgStateActivity = new RedpktDetailActivity();
            redpkgStateActivity.setBean(retBean);
            presentFragment(redpkgStateActivity);
        } else {
            if (status == 1) {
                RedpktDetailReceiverActivity receiverActivity = new RedpktDetailReceiverActivity();
                receiverActivity.setBean(retBean);
                presentFragment(receiverActivity);
                return;
            }
            showRedPacketDialog(sender, messageObject, retBean, false);
        }
    }

    static /* synthetic */ void lambda$null$138() {
    }

    public /* synthetic */ void lambda$null$140$ChatActivity() {
        presentFragment(new AboutAppActivity());
    }

    public /* synthetic */ void lambda$null$141$ChatActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$aECnhX9OfAtFtdy9x9Xv826JMkU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$140$ChatActivity();
            }
        });
    }

    static /* synthetic */ void lambda$null$142() {
    }

    public /* synthetic */ void lambda$null$145$ChatActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$n7A6Txp-6O9WM0Dn9eQ9-f_Pu3s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$144$ChatActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$144$ChatActivity() {
        Bundle args = new Bundle();
        args.putInt("step", 0);
        args.putInt("type", 0);
        presentFragment(new WalletPaymentPasswordActivity(args));
    }

    public /* synthetic */ void lambda$checkUserRedpkgDetail$147$ChatActivity(DialogInterface hintDialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
    }

    private void checkUserTransferDetail(final MessageObject messageObject, TransferResponse bean) {
        TLRPCRedpacket.CL_message_rpkTransferCheck req = new TLRPCRedpacket.CL_message_rpkTransferCheck();
        req.trans = 1;
        req.type = 0;
        req.flags = 2;
        req.id = messageObject.messageOwner.id;
        TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerUser();
        inputPeer.user_id = this.currentUser.id;
        inputPeer.access_hash = this.currentUser.access_hash;
        req.peer = inputPeer;
        String carry_over_details = ParamsUtil.toUserIdJson(UnifyBean.BUSINESS_KEY_TRANSFER_CHECK, new String[]{"serialCode", "nonceStr"}, bean.getSerialCode(), StringUtils.getRandomString(20) + getConnectionsManager().getCurrentTime());
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = carry_over_details;
        req.data = dataJSON;
        this.redTransAlert = new XAlertDialog(getParentActivity(), 5);
        this.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$LBmdqc1_apVqti-b5D3iy5q7tZc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$checkUserTransferDetail$159$ChatActivity(messageObject, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(this.reqId, this.classGuid);
        this.redTransAlert.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$j-Cn2jjJkt2MNPGuqYj2aAY25TA
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$checkUserTransferDetail$160$ChatActivity(dialogInterface);
            }
        });
        this.redTransAlert.show();
    }

    public /* synthetic */ void lambda$checkUserTransferDetail$159$ChatActivity(final MessageObject messageObject, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Pv5v1jMSWHIrNE1WCOgEj9SQ2eQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$148$ChatActivity();
            }
        });
        if (error != null) {
            AlertsCreator.showSimpleToast(this, LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater));
            return;
        }
        if (response instanceof TLRPC.TL_updates) {
            TLRPC.TL_updates updates = (TLRPC.TL_updates) response;
            for (TLRPC.Update update : updates.updates) {
                if (update instanceof TLRPCRedpacket.CL_updateRpkTransfer) {
                    TLRPCRedpacket.CL_updateRpkTransfer rpkTransfer = (TLRPCRedpacket.CL_updateRpkTransfer) update;
                    TLApiModel<TransferResponse> parse = TLJsonResolve.parse(rpkTransfer.data, (Class<?>) TransferResponse.class);
                    final TransferResponse transferRes = parse.model;
                    if (!parse.isSuccess()) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ZYt1C6WH7x_E1MHSOQjN1InfMcM
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$null$150$ChatActivity();
                            }
                        });
                        if ("USER_INFONNOT_CODE".equals(parse.message) || "SYSTEM_ERROR_ACCOUNT_EXCEPTION_CODE".equals(parse.message)) {
                            WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, LocaleController.getString("ReceiveTransfer", R.string.ReceiveTransfer), LocaleController.getString("ReceiveTransfer", R.string.ReceiveTransfer)), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.GoToWalletCenter), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$tCXkEU3jaxhsUkh6CgCLRC_mBVU
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i) {
                                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ZAwKyd47wOO6LiK0Gl6urqv8cmU
                                        @Override // java.lang.Runnable
                                        public final void run() {
                                            ChatActivity.lambda$null$151();
                                        }
                                    });
                                }
                            }, null);
                            return;
                        }
                        if ("ACCOUNT_HAS_BEEN_FROZEN_CODE".equals(parse.message)) {
                            WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString(R.string.PleaseContractServerToFindPayPasswordOrTryIt24HoursLater), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Wr__ZpU70qmlT6gAHsmrTHsBiWM
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i) {
                                    this.f$0.lambda$null$154$ChatActivity(dialogInterface, i);
                                }
                            }, null);
                            return;
                        }
                        if (!"ACCOUNT_UNCERTIFIED_CODE".equals(parse.message) && !"EXCLUSIVE_PLEASE_BIND_FIRST_BANKINFO".equals(parse.message)) {
                            if ("SYSTEM_ERROR_NOT_SET_PAYWORD_COCE".equals(parse.message)) {
                                WalletDialogUtil.showWalletDialog(this, "", String.format(LocaleController.getString("PayPasswordNotSetTips", R.string.PayPasswordNotSetTips), LocaleController.getString("ReceiveTransfer", R.string.ReceiveTransfer)), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.redpacket_goto_set), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$gY87fwWBurMfEzaR51moWEHlZu0
                                    @Override // android.content.DialogInterface.OnClickListener
                                    public final void onClick(DialogInterface dialogInterface, int i) {
                                        this.f$0.lambda$null$158$ChatActivity(dialogInterface, i);
                                    }
                                }, null);
                                return;
                            } else if (BuildVars.RELEASE_VERSION) {
                                WalletErrorUtil.parseErrorDialog(this, LocaleController.getString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater));
                                return;
                            } else {
                                WalletErrorUtil.parseErrorDialog(this, parse.code, parse.message);
                                return;
                            }
                        }
                        WalletDialogUtil.showWalletDialog(this, "", String.format(LocaleController.getString("BankCardNotBindTips", R.string.BankCardNotBindTips), LocaleController.getString("ReceiveTransfer", R.string.ReceiveTransfer)), LocaleController.getString(R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$Oe9d6DgkMrEZxoGTPYFo7yrifWM
                            @Override // android.content.DialogInterface.OnClickListener
                            public final void onClick(DialogInterface dialogInterface, int i) {
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$8uaQeCf2TZnGMM8NBwSLvCDwwUA
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        ChatActivity.lambda$null$155();
                                    }
                                });
                            }
                        }, null);
                        return;
                    }
                    getMessagesController().processUpdates(updates, false);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$FJZGrq_M0mLboilr7LUfcd7H_pc
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$149$ChatActivity(transferRes, messageObject);
                        }
                    });
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$148$ChatActivity() {
        this.redTransAlert.dismiss();
    }

    public /* synthetic */ void lambda$null$149$ChatActivity(TransferResponse transferRes, MessageObject messageObject) {
        TransferStatusActivity transferStatusActivity = new TransferStatusActivity();
        transferStatusActivity.setTransResponse(transferRes);
        transferStatusActivity.setMessage(messageObject.messageOwner);
        transferStatusActivity.setTargetUser(this.currentUser);
        transferStatusActivity.setSender(messageObject.isOutOwner());
        presentFragment(transferStatusActivity);
    }

    public /* synthetic */ void lambda$null$150$ChatActivity() {
        this.redTransAlert.dismiss();
    }

    static /* synthetic */ void lambda$null$151() {
    }

    public /* synthetic */ void lambda$null$153$ChatActivity() {
        presentFragment(new AboutAppActivity());
    }

    public /* synthetic */ void lambda$null$154$ChatActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$j1wB6XOoEfI_SPmJVGIH1sxuTP4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$153$ChatActivity();
            }
        });
    }

    static /* synthetic */ void lambda$null$155() {
    }

    public /* synthetic */ void lambda$null$158$ChatActivity(DialogInterface dialogInterface, int i) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$E036K-JIFBaxXkYSpF1Ttku2FIY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$157$ChatActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$157$ChatActivity() {
        Bundle args = new Bundle();
        args.putInt("step", 0);
        args.putInt("type", 0);
        presentFragment(new WalletPaymentPasswordActivity(args));
    }

    public /* synthetic */ void lambda$checkUserTransferDetail$160$ChatActivity(DialogInterface hintDialog) {
        getConnectionsManager().cancelRequest(this.reqId, true);
    }

    public String setMoneyFormat(String data) {
        if (NumberUtil.isNumber(data)) {
            if (data.contains(".")) {
                String[] split = data.split("\\.");
                String number1 = split[0];
                String number2 = split[1];
                String res = MoneyUtil.formatToString(new BigDecimal(String.valueOf(number1)).multiply(new BigDecimal("1")).toString(), 0);
                if (number2.length() > 8) {
                    number2 = number2.substring(0, 8);
                }
                return res + "." + number2;
            }
            String res2 = MoneyUtil.formatToString(new BigDecimal(String.valueOf(data)).multiply(new BigDecimal("1")).toString(), 0);
            return res2;
        }
        return "";
    }

    public void sendEditMessageMedia(MessageObject message) {
        TLRPC.TL_inputPeerUser peer = new TLRPC.TL_inputPeerUser();
        TLRPC.User currentUser = getUserConfig().getCurrentUser();
        peer.user_id = currentUser.id;
        peer.access_hash = currentUser.access_hash;
        TLRPC.TL_inputMediaEmpty media = new TLRPC.TL_inputMediaEmpty();
        getSendMessagesHelper().sendEditMessageMedia(peer, message.messageOwner.id, media);
    }

    public class ChatActivityAdapter extends RecyclerView.Adapter {
        private int botInfoRow = -1;
        private boolean isBot;
        private int loadingDownRow;
        private int loadingUpRow;
        private Context mContext;
        private int messagesEndRow;
        private int messagesStartRow;
        private int rowCount;

        public ChatActivityAdapter(Context context) {
            this.mContext = context;
            this.isBot = ChatActivity.this.currentUser != null && ChatActivity.this.currentUser.bot;
        }

        public void updateRows() {
            this.rowCount = 0;
            if (!ChatActivity.this.messages.isEmpty()) {
                if (!ChatActivity.this.forwardEndReached[0] || (ChatActivity.this.mergeDialogId != 0 && !ChatActivity.this.forwardEndReached[1])) {
                    int i = this.rowCount;
                    this.rowCount = i + 1;
                    this.loadingDownRow = i;
                } else {
                    this.loadingDownRow = -1;
                }
                int i2 = this.rowCount;
                this.messagesStartRow = i2;
                int size = i2 + ChatActivity.this.messages.size();
                this.rowCount = size;
                this.messagesEndRow = size;
                if (ChatActivity.this.currentUser != null && ChatActivity.this.currentUser.bot && !ChatActivity.this.inScheduleMode) {
                    int i3 = this.rowCount;
                    this.rowCount = i3 + 1;
                    this.botInfoRow = i3;
                } else {
                    this.botInfoRow = -1;
                }
                if (!ChatActivity.this.endReached[0] || (ChatActivity.this.mergeDialogId != 0 && !ChatActivity.this.endReached[1])) {
                    int i4 = this.rowCount;
                    this.rowCount = i4 + 1;
                    this.loadingUpRow = i4;
                    return;
                }
                this.loadingUpRow = -1;
                return;
            }
            this.loadingUpRow = -1;
            this.loadingDownRow = -1;
            this.messagesStartRow = -1;
            this.messagesEndRow = -1;
            if (ChatActivity.this.currentUser != null && ChatActivity.this.currentUser.bot && !MessagesController.isSupportUser(ChatActivity.this.currentUser) && !ChatActivity.this.inScheduleMode) {
                int i5 = this.rowCount;
                this.rowCount = i5 + 1;
                this.botInfoRow = i5;
                return;
            }
            this.botInfoRow = -1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (ChatActivity.this.clearingHistory) {
                return 0;
            }
            return this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i) {
            return -1L;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                if (!ChatActivity.this.chatMessageCellsCache.isEmpty()) {
                    view = (View) ChatActivity.this.chatMessageCellsCache.get(0);
                    ChatActivity.this.chatMessageCellsCache.remove(0);
                } else {
                    view = new ChatMessageCell(this.mContext, ChatActivity.this);
                }
                ChatMessageCell chatMessageCell = (ChatMessageCell) view;
                chatMessageCell.setDelegate(new AnonymousClass1());
                if (ChatActivity.this.currentEncryptedChat == null) {
                    chatMessageCell.setAllowAssistant(true);
                }
            } else if (viewType == 1) {
                view = new ChatActionCell(this.mContext);
                if (((ChatActionCell) view).getMessageObject() == null) {
                    View view2 = new View(this.mContext);
                    return new RecyclerListView.Holder(view2);
                }
                ((ChatActionCell) view).setDelegate(new ChatActionCell.ChatActionCellDelegate() { // from class: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.2
                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public void didClickImage(ChatActionCell cell) {
                        MessageObject message = cell.getMessageObject();
                        PhotoViewer.getInstance().setParentActivity(ChatActivity.this.getParentActivity());
                        TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(message.photoThumbs, 640);
                        if (photoSize == null) {
                            PhotoViewer.getInstance().openPhoto(message, 0L, 0L, ChatActivity.this.photoViewerProvider);
                        } else {
                            ImageLocation imageLocation = ImageLocation.getForPhoto(photoSize, message.messageOwner.action.photo);
                            PhotoViewer.getInstance().openPhoto(photoSize.location, imageLocation, ChatActivity.this.photoViewerProvider);
                        }
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public void didRedUrl(MessageObject messageObject) {
                        TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer rpkTransferMedia = (TLRPCRedpacket.CL_messagesActionReceivedRpkTransfer) messageObject.messageOwner.action;
                        if (rpkTransferMedia.trans == 0) {
                            TLApiModel<RedpacketResponse> parse = TLJsonResolve.parse(rpkTransferMedia.data, (Class<?>) RedpacketResponse.class);
                            RedpacketResponse bean = parse.model;
                            if (ChatActivity.this.currentUser != null) {
                                if (Integer.parseInt(bean.getRed().getInitiatorUserId()) == ChatActivity.this.getUserConfig().clientUserId) {
                                    RedpktDetailActivity redpkgStateActivity = new RedpktDetailActivity();
                                    redpkgStateActivity.setBean(bean);
                                    ChatActivity.this.presentFragment(redpkgStateActivity);
                                    return;
                                } else {
                                    RedpktDetailReceiverActivity receiverActivity = new RedpktDetailReceiverActivity();
                                    receiverActivity.setBean(bean);
                                    ChatActivity.this.presentFragment(receiverActivity);
                                    return;
                                }
                            }
                            if (ChatActivity.this.currentChat != null) {
                                RedpktGroupDetailActivity detailActivity = new RedpktGroupDetailActivity();
                                detailActivity.setBean(bean.getRed());
                                detailActivity.setChat(ChatActivity.this.currentChat);
                                detailActivity.setMessageId(messageObject.messageOwner.id);
                                ChatActivity.this.presentFragment(detailActivity);
                            }
                        }
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public void didLongPress(ChatActionCell cell, float x, float y) {
                        ChatActivity.this.createMenu(cell, false, false, x, y);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public void needOpenUserProfile(int uid) {
                        if (uid < 0) {
                            Bundle args = new Bundle();
                            args.putInt("chat_id", -uid);
                            if (ChatActivity.this.getMessagesController().checkCanOpenChat(args, ChatActivity.this)) {
                                ChatActivity.this.presentFragment(new ChatActivity(args));
                                return;
                            }
                            return;
                        }
                        if (uid != ChatActivity.this.getUserConfig().getClientUserId()) {
                            TLRPC.User user = ChatActivity.this.getMessagesController().getUser(Integer.valueOf(uid));
                            if (!user.self && ChatActivity.this.currentChat != null && !ChatObject.hasAdminRights(ChatActivity.this.currentChat)) {
                                if (ChatActivity.this.currentChat.megagroup && (ChatActivity.this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user.mutual_contact) {
                                    ToastUtils.show(R.string.ForbidViewUserInfoTips);
                                    return;
                                } else if (!ChatObject.canSendEmbed(ChatActivity.this.currentChat)) {
                                    ToastUtils.show(R.string.ForbidViewUserAndGroupInfoTips);
                                    return;
                                }
                            }
                            Bundle args2 = new Bundle();
                            args2.putInt("user_id", uid);
                            if (ChatActivity.this.currentEncryptedChat != null && uid == ChatActivity.this.currentUser.id) {
                                args2.putLong("dialog_id", ChatActivity.this.dialog_id);
                            }
                            if (ChatActivity.this.currentChat != null) {
                                args2.putBoolean("forbid_add_contact", ChatActivity.this.currentChat.megagroup && (33554432 & ChatActivity.this.currentChat.flags) != 0);
                                args2.putBoolean("has_admin_right", ChatObject.hasAdminRights(ChatActivity.this.currentChat));
                            }
                            args2.putInt("from_type", 2);
                            ChatActivity.this.presentFragment(new NewProfileActivity(args2));
                        }
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public void didPressReplyMessage(ChatActionCell cell, int id) {
                        MessageObject messageObject = cell.getMessageObject();
                        ChatActivity.this.scrollToMessageId(id, messageObject.getId(), true, messageObject.getDialogId() == ChatActivity.this.mergeDialogId ? 1 : 0, false);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public void didPressBotButton(MessageObject messageObject, TLRPC.KeyboardButton button) {
                        if (ChatActivity.this.getParentActivity() != null) {
                            if (ChatActivity.this.bottomOverlayChat.getVisibility() == 0 && !(button instanceof TLRPC.TL_keyboardButtonSwitchInline) && !(button instanceof TLRPC.TL_keyboardButtonCallback) && !(button instanceof TLRPC.TL_keyboardButtonGame) && !(button instanceof TLRPC.TL_keyboardButtonUrl) && !(button instanceof TLRPC.TL_keyboardButtonBuy) && !(button instanceof TLRPC.TL_keyboardButtonUrlAuth)) {
                                return;
                            }
                            ChatActivity.this.chatActivityEnterView.didPressedBotButton(button, messageObject, messageObject);
                        }
                    }
                });
            } else if (viewType == 2) {
                view = new ChatUnreadCell(this.mContext);
            } else if (viewType == 3) {
                view = new BotHelpCell(this.mContext);
                ((BotHelpCell) view).setDelegate(new BotHelpCell.BotHelpCellDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ChatActivityAdapter$nZUhZtmx_U0tsM6q2P-PslWfumM
                    @Override // im.uwrkaxlmjj.ui.cells.BotHelpCell.BotHelpCellDelegate
                    public final void didPressUrl(String str) {
                        this.f$0.lambda$onCreateViewHolder$0$ChatActivity$ChatActivityAdapter(str);
                    }
                });
            } else if (viewType == 4) {
                view = new ChatLoadingCell(this.mContext);
            } else if (viewType == 5) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_chat_pay_bill_over_message, parent, false);
            } else if (viewType == 10) {
                view = new TextView(this.mContext);
                view.setVisibility(8);
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$ChatActivityAdapter$1, reason: invalid class name */
        class AnonymousClass1 implements ChatMessageCell.ChatMessageCellDelegate {
            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public /* synthetic */ void didPressSysNotifyVideoFullPlayer(ChatMessageCell chatMessageCell) {
                ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressSysNotifyVideoFullPlayer(this, chatMessageCell);
            }

            AnonymousClass1() {
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressRedpkgTransfer(ChatMessageCell cell, MessageObject messageObject) {
                ChatActivity.this.onRedpkgTransferClick(cell, messageObject);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressShare(ChatMessageCell cell) {
                MessageObject.GroupedMessages groupedMessages;
                if (ChatActivity.this.getParentActivity() == null) {
                    return;
                }
                if (ChatActivity.this.chatActivityEnterView != null) {
                    ChatActivity.this.chatActivityEnterView.closeKeyboard();
                }
                MessageObject messageObject = cell.getMessageObject();
                if (UserObject.isUserSelf(ChatActivity.this.currentUser) && messageObject.messageOwner.fwd_from.saved_from_peer != null) {
                    Bundle args = new Bundle();
                    if (messageObject.messageOwner.fwd_from.saved_from_peer.channel_id != 0) {
                        args.putInt("chat_id", messageObject.messageOwner.fwd_from.saved_from_peer.channel_id);
                    } else if (messageObject.messageOwner.fwd_from.saved_from_peer.chat_id != 0) {
                        args.putInt("chat_id", messageObject.messageOwner.fwd_from.saved_from_peer.chat_id);
                    } else if (messageObject.messageOwner.fwd_from.saved_from_peer.user_id != 0) {
                        args.putInt("user_id", messageObject.messageOwner.fwd_from.saved_from_peer.user_id);
                    }
                    args.putInt("message_id", messageObject.messageOwner.fwd_from.saved_from_msg_id);
                    if (ChatActivity.this.getMessagesController().checkCanOpenChat(args, ChatActivity.this)) {
                        ChatActivity.this.presentFragment(new ChatActivity(args));
                        return;
                    }
                    return;
                }
                ArrayList<MessageObject> arrayList = null;
                if (messageObject.getGroupId() != 0 && (groupedMessages = (MessageObject.GroupedMessages) ChatActivity.this.groupedMessagesMap.get(messageObject.getGroupId())) != null) {
                    arrayList = groupedMessages.messages;
                }
                if (arrayList == null) {
                    arrayList = new ArrayList<>();
                    arrayList.add(messageObject);
                }
                ChatActivity.this.showDialog(new ShareAlert(ChatActivityAdapter.this.mContext, arrayList, null, ChatObject.isChannel(ChatActivity.this.currentChat), null, false) { // from class: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.1.1
                    @Override // im.uwrkaxlmjj.ui.components.ShareAlert, im.uwrkaxlmjj.ui.actionbar.BottomSheet
                    public void dismissInternal() {
                        super.dismissInternal();
                        AndroidUtilities.requestAdjustResize(ChatActivity.this.getParentActivity(), ChatActivity.this.classGuid);
                        if (ChatActivity.this.chatActivityEnterView.getVisibility() == 0) {
                            ChatActivity.this.fragmentView.requestLayout();
                        }
                    }
                });
                AndroidUtilities.setAdjustResizeToNothing(ChatActivity.this.getParentActivity(), ChatActivity.this.classGuid);
                ChatActivity.this.fragmentView.requestLayout();
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public boolean needPlayMessage(MessageObject messageObject) {
                if (messageObject.isVoice() || messageObject.isRoundVideo()) {
                    boolean result = MediaController.getInstance().playMessage(messageObject);
                    MediaController.getInstance().setVoiceMessagesPlaylist(result ? ChatActivity.this.createVoiceMessagesPlaylist(messageObject, false) : null, false);
                    return result;
                }
                if (messageObject.isMusic()) {
                    return MediaController.getInstance().setPlaylist(ChatActivity.this.messages, messageObject);
                }
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void videoTimerReached() {
                ChatActivity.this.showNoSoundHint();
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressChannelAvatar(ChatMessageCell cell, TLRPC.Chat chat, int postId, float touchX, float touchY) {
                if (ChatActivity.this.actionBar.isActionModeShowed()) {
                    ChatActivity.this.processRowSelect(cell, true, touchX, touchY);
                    return;
                }
                if (chat != null && chat != ChatActivity.this.currentChat) {
                    Bundle args = new Bundle();
                    args.putInt("chat_id", chat.id);
                    if (postId != 0) {
                        args.putInt("message_id", postId);
                    }
                    if (ChatActivity.this.getMessagesController().checkCanOpenChat(args, ChatActivity.this, cell.getMessageObject())) {
                        ChatActivity.this.presentFragment(new ChatActivity(args));
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressHiddenForward(ChatMessageCell cell) {
                ChatActivity.this.showForwardHint(cell);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressOther(ChatMessageCell cell, float otherX, float otherY) {
                int type;
                if (cell.getMessageObject().type == 16) {
                    if (ChatActivity.this.currentUser != null && (cell.getMessageObject().messageOwner.action instanceof TLRPC.TL_messageActionPhoneCall)) {
                        TLRPC.TL_messageActionPhoneCall phoneCall = (TLRPC.TL_messageActionPhoneCall) cell.getMessageObject().messageOwner.action;
                        if ((phoneCall.flags & 4) != 0) {
                            type = 2;
                        } else {
                            type = 1;
                        }
                        if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                            if (MessagesController.getInstance(ChatActivity.this.currentAccount).getUser(Integer.valueOf(ChatActivity.this.arguments.getInt("user_id", 0))).mutual_contact) {
                                int currentConnectionState = ConnectionsManager.getInstance(ChatActivity.this.currentAccount).getConnectionState();
                                if (currentConnectionState == 2 || currentConnectionState == 1) {
                                    ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                                    return;
                                }
                                Intent intent = new Intent();
                                intent.setClass(ChatActivity.this.getParentActivity(), VisualCallActivity.class);
                                intent.putExtra("CallType", type);
                                ArrayList<Integer> ArrInputPeers = new ArrayList<>();
                                ArrInputPeers.add(Integer.valueOf(ChatActivity.this.arguments.getInt("user_id", 0)));
                                intent.putExtra("ArrayUser", ArrInputPeers);
                                intent.putExtra("channel", new ArrayList());
                                ChatActivity.this.getParentActivity().startActivity(intent);
                                return;
                            }
                            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                            return;
                        }
                        if (ApplicationLoader.mbytAVideoCallBusy == 3 || ApplicationLoader.mbytAVideoCallBusy == 4) {
                            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
                            return;
                        }
                        return;
                    }
                    return;
                }
                if (cell.getMessageObject().type == 103) {
                    if (cell.getMessageObject().messageOwner.media instanceof TLRPC.TL_messageMediaShareContact) {
                        TLRPC.TL_messageMediaShareContact shareContact = (TLRPC.TL_messageMediaShareContact) cell.getMessageObject().messageOwner.media;
                        TLRPC.User user = MessagesController.getInstance(ChatActivity.this.currentAccount).getUser(Integer.valueOf(shareContact.user_id));
                        if (user != null) {
                            if (!user.self && ChatActivity.this.currentChat != null && !ChatObject.hasAdminRights(ChatActivity.this.currentChat)) {
                                if (ChatActivity.this.currentChat.megagroup && (ChatActivity.this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user.mutual_contact) {
                                    ToastUtils.show(R.string.ForbidViewUserInfoTips);
                                    return;
                                } else if (!ChatObject.canSendEmbed(ChatActivity.this.currentChat)) {
                                    ToastUtils.show(R.string.ForbidViewUserAndGroupInfoTips);
                                    return;
                                }
                            }
                            if (user.mutual_contact || user.id == UserConfig.getInstance(ChatActivity.this.currentAccount).getCurrentUser().id) {
                                Bundle args = new Bundle();
                                args.putInt("user_id", user.id);
                                if (ChatActivity.this.currentChat != null) {
                                    args.putBoolean("forbid_add_contact", ChatActivity.this.currentChat.megagroup && (ChatActivity.this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0);
                                    args.putBoolean("has_admin_right", ChatObject.hasAdminRights(ChatActivity.this.currentChat));
                                }
                                NewProfileActivity fragment = new NewProfileActivity(args);
                                ChatActivity.this.presentFragment(fragment);
                                return;
                            }
                            Bundle bundle = new Bundle();
                            bundle.putInt("from_type", 4);
                            ChatActivity.this.presentFragment(new AddContactsInfoActivity(bundle, user));
                            return;
                        }
                        XDialog.Builder builder = new XDialog.Builder(ChatActivity.this.getParentActivity());
                        builder.setTitle(LocaleController.getString(R.string.Tips));
                        builder.setMessage(LocaleController.getString(R.string.share_contact_card_info_error));
                        builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
                        XDialog xDialog = builder.create();
                        ChatActivity.this.showDialog(xDialog);
                        return;
                    }
                    return;
                }
                if (cell.getMessageObject().type == 105) {
                    MessageObject messageObject = cell.getMessageObject();
                    boolean clickSysNotifyItem = cell.isClickSysNotifyItem();
                    TLRPCContacts.TL_messageMediaSysNotify sysNotify = (TLRPCContacts.TL_messageMediaSysNotify) messageObject.messageOwner.media;
                    if (sysNotify.business_code >= 4 && sysNotify.business_code != 10) {
                        if (sysNotify.business_code == 8 && !clickSysNotifyItem) {
                            ChatActivity.this.sendEditMessageMedia(messageObject);
                            return;
                        } else {
                            if (clickSysNotifyItem && sysNotify.business_code != 8) {
                                String data = TLJsonResolve.getData(sysNotify.data);
                                ChatFCAttentionBean bean = (ChatFCAttentionBean) GsonUtils.fromJson(data, ChatFCAttentionBean.class);
                                ChatActivity.this.presentFragment(new FcPageDetailActivity(bean.interact_msg.forum_id));
                                return;
                            }
                            return;
                        }
                    }
                    return;
                }
                if (cell.getMessageObject().type != 207) {
                    ChatActivity.this.createMenu(cell, true, false, otherX, otherY, false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressUserAvatar(ChatMessageCell cell, TLRPC.User user, float touchX, float touchY) {
                if (ChatActivity.this.actionBar.isActionModeShowed()) {
                    ChatActivity.this.processRowSelect(cell, true, touchX, touchY);
                    return;
                }
                if (user != null) {
                    if (!user.self && ChatActivity.this.currentChat != null && !ChatObject.hasAdminRights(ChatActivity.this.currentChat) && ChatActivity.this.currentChat.megagroup && (ChatActivity.this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user.mutual_contact) {
                        ToastUtils.show(R.string.ForbidViewUserInfoTips);
                        return;
                    }
                    Bundle args = new Bundle();
                    args.putInt("user_id", user.id);
                    if (ChatActivity.this.currentChat != null) {
                        args.putBoolean("forbid_add_contact", ChatActivity.this.currentChat.megagroup && (33554432 & ChatActivity.this.currentChat.flags) != 0);
                        args.putBoolean("has_admin_right", ChatObject.hasAdminRights(ChatActivity.this.currentChat));
                        args.putInt("from_type", 2);
                    }
                    NewProfileActivity fragment = new NewProfileActivity(args);
                    ChatActivity.this.presentFragment(fragment);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didLongPressUserAvatar(ChatMessageCell cell, TLRPC.User user, float touchX, float touchY) {
                if (user != null) {
                    String name = UserObject.getName(user);
                    Spannable spannable = new SpannableString("@" + (name + " ") + " ");
                    StringBuilder sb = new StringBuilder();
                    sb.append("");
                    sb.append(user.id);
                    spannable.setSpan(new URLSpanUserMention(sb.toString(), 1), 0, spannable.length(), 33);
                    spannable.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_chat_messagePanelMetionText)), 0, spannable.length(), 33);
                    boolean canSolid = ChatActivity.this.currentChat == null || !(ChatActivity.this.currentChat == null || ChatObject.canSendMessages(ChatActivity.this.currentChat) || (ChatObject.isChannel(ChatActivity.this.currentChat) && !ChatActivity.this.currentChat.megagroup));
                    if (!canSolid && !user.self) {
                        ChatActivity.this.chatActivityEnterView.addMentionText(ChatActivity.this.chatActivityEnterView.getCursorPosition(), 1, spannable, false);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressBotButton(ChatMessageCell cell, TLRPC.KeyboardButton button) {
                if (ChatActivity.this.getParentActivity() != null) {
                    if (ChatActivity.this.bottomOverlayChat.getVisibility() == 0 && !(button instanceof TLRPC.TL_keyboardButtonSwitchInline) && !(button instanceof TLRPC.TL_keyboardButtonCallback) && !(button instanceof TLRPC.TL_keyboardButtonGame) && !(button instanceof TLRPC.TL_keyboardButtonUrl) && !(button instanceof TLRPC.TL_keyboardButtonBuy) && !(button instanceof TLRPC.TL_keyboardButtonUrlAuth)) {
                        return;
                    }
                    ChatActivity.this.chatActivityEnterView.didPressedBotButton(button, cell.getMessageObject(), cell.getMessageObject());
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressReaction(ChatMessageCell cell, TLRPC.TL_reactionCount reaction) {
                ChatActivity.this.getSendMessagesHelper().sendReaction(cell.getMessageObject(), reaction.reaction, ChatActivity.this);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressVoteButton(ChatMessageCell cell, TLRPC.TL_pollAnswer button) {
                ChatActivity.this.getSendMessagesHelper().sendVote(cell.getMessageObject(), button, null);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressCancelSendButton(ChatMessageCell cell) {
                MessageObject message = cell.getMessageObject();
                if (message.messageOwner.send_state != 0) {
                    ChatActivity.this.getSendMessagesHelper().cancelSendingMessage(message);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didLongPress(ChatMessageCell cell, float x, float y) {
                ChatActivity.this.createMenu(cell, false, false, x, y);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public boolean canPerformActions() {
                return (ChatActivity.this.actionBar == null || ChatActivity.this.actionBar.isActionModeShowed()) ? false : true;
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
            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressUrl(ChatMessageCell chatMessageCell, CharacterStyle characterStyle, boolean z) {
                TLRPC.WebPage webPage;
                ChatMessageCell chatMessageCell2;
                if (characterStyle == null || ChatActivity.this.getParentActivity() == null) {
                    return;
                }
                MessageObject messageObject = chatMessageCell.getMessageObject();
                if (characterStyle instanceof URLSpanMono) {
                    ((URLSpanMono) characterStyle).copyToClipboard();
                    ToastUtils.show(R.string.TextCopied);
                } else {
                    if (characterStyle instanceof URLSpanUserMention) {
                        TLRPC.User user = ChatActivity.this.getMessagesController().getUser(Utilities.parseInt(((URLSpanUserMention) characterStyle).getURL()));
                        if (user != null) {
                            if (!user.self && ChatActivity.this.currentChat != null && !ChatObject.hasAdminRights(ChatActivity.this.currentChat)) {
                                if (ChatActivity.this.currentChat.megagroup && (ChatActivity.this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0 && !user.mutual_contact) {
                                    ToastUtils.show(R.string.ForbidViewUserInfoTips);
                                    return;
                                } else if (!ChatObject.canSendEmbed(ChatActivity.this.currentChat)) {
                                    ToastUtils.show(R.string.ForbidViewUserAndGroupInfoTips);
                                    return;
                                }
                            }
                            Bundle bundle = new Bundle();
                            bundle.putInt("user_id", user.id);
                            if (ChatActivity.this.currentChat != null) {
                                bundle.putBoolean("forbid_add_contact", ChatActivity.this.currentChat.megagroup && (ChatActivity.this.currentChat.flags & ConnectionsManager.FileTypeVideo) != 0);
                                bundle.putBoolean("has_admin_right", ChatObject.hasAdminRights(ChatActivity.this.currentChat));
                            }
                            bundle.putInt("from_type", 2);
                            if (user.bot) {
                                MessagesController.openChatOrProfileWith(user, null, ChatActivity.this, 0, false);
                            } else {
                                ChatActivity.this.presentFragment(new NewProfileActivity(bundle));
                            }
                        }
                    } else {
                        if (characterStyle instanceof URLSpanNoUnderline) {
                            String url = ((URLSpanNoUnderline) characterStyle).getURL();
                            if (url.startsWith("@")) {
                                String lowerCase = url.substring(1).toLowerCase();
                                if ("all".equals(lowerCase)) {
                                    return;
                                }
                                if ((ChatActivity.this.currentChat == null || TextUtils.isEmpty(ChatActivity.this.currentChat.username) || !lowerCase.equals(ChatActivity.this.currentChat.username.toLowerCase())) && (ChatActivity.this.currentUser == null || TextUtils.isEmpty(ChatActivity.this.currentUser.username) || !lowerCase.equals(ChatActivity.this.currentUser.username.toLowerCase()))) {
                                    ChatActivity.this.getMessagesController().openByUserName(lowerCase, (BaseFragment) ChatActivity.this, ChatActivity.this.currentChat, false);
                                } else {
                                    Bundle bundle2 = new Bundle();
                                    if (ChatActivity.this.currentChat != null) {
                                        bundle2.putInt("chat_id", ChatActivity.this.currentChat.id);
                                    } else if (ChatActivity.this.currentUser != null) {
                                        bundle2.putInt("user_id", ChatActivity.this.currentUser.id);
                                        if (ChatActivity.this.currentEncryptedChat != null) {
                                            bundle2.putLong("dialog_id", ChatActivity.this.dialog_id);
                                        }
                                    }
                                    if (ChatActivity.this.currentUser != null) {
                                        ChatActivity.this.presentFragment(new NewProfileActivity(bundle2));
                                    } else {
                                        ProfileActivity profileActivity = new ProfileActivity(bundle2);
                                        profileActivity.setPlayProfileAnimation(true);
                                        profileActivity.setChatInfo(ChatActivity.this.chatInfo);
                                        profileActivity.setUserInfo(ChatActivity.this.userInfo);
                                        ChatActivity.this.presentFragment(profileActivity);
                                    }
                                }
                            } else if (url.startsWith("#") || url.startsWith("$")) {
                                if (ChatObject.isChannel(ChatActivity.this.currentChat)) {
                                    ChatActivity.this.openSearchWithText(url);
                                } else {
                                    DialogsActivity dialogsActivity = new DialogsActivity(null);
                                    dialogsActivity.setSearchString(url);
                                    ChatActivity.this.presentFragment(dialogsActivity);
                                }
                            } else if (url.startsWith("/")) {
                                if (URLSpanBotCommand.enabled) {
                                    ChatActivity.this.chatActivityEnterView.setCommand(messageObject, url, z, ChatActivity.this.currentChat != null && ChatActivity.this.currentChat.megagroup);
                                    if (!z && ChatActivity.this.chatActivityEnterView.getFieldText() == null) {
                                        ChatActivity.this.hideFieldPanel(false);
                                    }
                                }
                            } else if (url.startsWith("video")) {
                                int iIntValue = Utilities.parseInt(url).intValue();
                                if (messageObject.isYouTubeVideo()) {
                                    webPage = messageObject.messageOwner.media.webpage;
                                } else if (messageObject.replyMessageObject != null && messageObject.replyMessageObject.isYouTubeVideo()) {
                                    webPage = messageObject.replyMessageObject.messageOwner.media.webpage;
                                } else {
                                    webPage = null;
                                }
                                if (webPage != null) {
                                    EmbedBottomSheet.show(ChatActivityAdapter.this.mContext, webPage.site_name, webPage.title, webPage.url, webPage.embed_url, webPage.embed_width, webPage.embed_height, iIntValue);
                                } else {
                                    if (!messageObject.isVideo() && messageObject.replyMessageObject != null) {
                                        messageObject = (MessageObject) ChatActivity.this.messagesDict[messageObject.replyMessageObject.getDialogId() == ChatActivity.this.dialog_id ? (char) 0 : (char) 1].get(messageObject.replyMessageObject.getId());
                                        chatMessageCell2 = null;
                                    } else {
                                        chatMessageCell2 = chatMessageCell;
                                    }
                                    messageObject.forceSeekTo = iIntValue / messageObject.getDuration();
                                    openPhotoViewerForMessage(chatMessageCell2, messageObject);
                                    return;
                                }
                            }
                            return;
                        }
                        final String url2 = ((URLSpan) characterStyle).getURL();
                        if (z) {
                            BottomSheet.Builder builder = new BottomSheet.Builder(ChatActivity.this.getParentActivity());
                            builder.setTitle(url2);
                            builder.setItems(new CharSequence[]{LocaleController.getString("Open", R.string.Open), LocaleController.getString("Copy", R.string.Copy)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$ChatActivityAdapter$1$4VlRvVf649z8Li5JjATnb9IgjvE
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i) {
                                    this.f$0.lambda$didPressUrl$0$ChatActivity$ChatActivityAdapter$1(url2, dialogInterface, i);
                                }
                            });
                            ChatActivity.this.showDialog(builder.create());
                        } else if ((characterStyle instanceof URLSpanReplacement) && (url2 == null || !url2.startsWith(MailTo.MAILTO_SCHEME))) {
                            ChatActivity.this.showOpenUrlAlert(url2, true);
                        } else if (characterStyle instanceof URLSpan) {
                            if ((messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && messageObject.messageOwner.media.webpage != null && messageObject.messageOwner.media.webpage.cached_page != null) {
                                String lowerCase2 = url2.toLowerCase();
                                String lowerCase3 = messageObject.messageOwner.media.webpage.url.toLowerCase();
                                if ((lowerCase2.contains("m12345.com/blog") || lowerCase2.contains("telegra.ph") || lowerCase2.contains("m12345.com/iv")) && (lowerCase2.contains(lowerCase3) || lowerCase3.contains(lowerCase2))) {
                                    ArticleViewer.getInstance().setParentActivity(ChatActivity.this.getParentActivity(), ChatActivity.this);
                                    ArticleViewer.getInstance().open(messageObject);
                                    return;
                                }
                            }
                            if (ChatObject.canSendEmbed(ChatActivity.this.currentChat)) {
                                QrCodeParseUtil.tryParseQrCode(ChatActivity.this, ChatActivity.this.currentAccount, url2, false, false, true, ChatActivity.this.inlineReturn == 0);
                            } else {
                                ToastUtils.show(R.string.ForbidClickLink);
                            }
                        } else if (characterStyle instanceof ClickableSpan) {
                            ((ClickableSpan) characterStyle).onClick(ChatActivity.this.fragmentView);
                        }
                    }
                }
            }

            public /* synthetic */ void lambda$didPressUrl$0$ChatActivity$ChatActivityAdapter$1(String urlFinal, DialogInterface dialog, int which) {
                if (which == 0) {
                    if (ChatObject.canSendEmbed(ChatActivity.this.currentChat)) {
                        Browser.openUrl((Context) ChatActivity.this.getParentActivity(), urlFinal, ChatActivity.this.inlineReturn == 0, false);
                        return;
                    } else {
                        ToastUtils.show(R.string.ForbidClickLink);
                        return;
                    }
                }
                if (which == 1) {
                    String url1 = urlFinal;
                    if (url1.startsWith(MailTo.MAILTO_SCHEME)) {
                        url1 = url1.substring(7);
                    } else if (url1.startsWith("tel:")) {
                        url1 = url1.substring(4);
                    }
                    AndroidUtilities.addToClipboard(url1);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void needOpenWebView(String url, String title, String description, String originalUrl, int w, int h) {
                try {
                    EmbedBottomSheet.show(ChatActivityAdapter.this.mContext, title, description, originalUrl, url, w, h);
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressReplyMessage(ChatMessageCell cell, int id) {
                MessageObject messageObject = cell.getMessageObject();
                if (ChatActivity.this.inScheduleMode) {
                    ChatActivity.this.chatActivityDelegate.openReplyMessage(id);
                    ChatActivity.this.finishFragment();
                } else {
                    ChatActivity.this.scrollToMessageId(id, messageObject.getId(), true, messageObject.getDialogId() == ChatActivity.this.mergeDialogId ? 1 : 0, false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressViaBot(ChatMessageCell cell, String username) {
                if (ChatActivity.this.bottomOverlayChat == null || ChatActivity.this.bottomOverlayChat.getVisibility() != 0) {
                    if ((ChatActivity.this.bottomOverlay == null || ChatActivity.this.bottomOverlay.getVisibility() != 0) && ChatActivity.this.chatActivityEnterView != null && username != null && username.length() > 0) {
                        ChatActivity.this.chatActivityEnterView.setFieldText("@" + username + " ");
                        ChatActivity.this.chatActivityEnterView.openKeyboard();
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didStartVideoStream(MessageObject message) {
                if (message.isVideo()) {
                    ChatActivity.this.sendSecretMessageRead(message);
                }
            }

            void openPhotoViewerForMessage(ChatMessageCell cell, MessageObject message) {
                ChatMessageCell cell2;
                AnimatedFileDrawable animation;
                Bitmap bitmap;
                if (cell == null) {
                    int count = ChatActivity.this.chatListView.getChildCount();
                    for (int a = 0; a < count; a++) {
                        View child = ChatActivity.this.chatListView.getChildAt(a);
                        if (child instanceof ChatMessageCell) {
                            ChatMessageCell messageCell = (ChatMessageCell) child;
                            if (messageCell.getMessageObject().equals(message)) {
                                cell2 = messageCell;
                                break;
                            }
                        }
                    }
                    cell2 = cell;
                } else {
                    cell2 = cell;
                }
                if (message.isVideo()) {
                    ChatActivity.this.sendSecretMessageRead(message);
                }
                PhotoViewer.getInstance().setParentActivity(ChatActivity.this.getParentActivity());
                MessageObject playingObject = MediaController.getInstance().getPlayingMessageObject();
                if (cell2 != null && playingObject != null && playingObject.isVideo()) {
                    ChatActivity.this.getFileLoader().setLoadingVideoForPlayer(playingObject.getDocument(), false);
                    if (playingObject.equals(message) && (animation = cell2.getPhotoImage().getAnimation()) != null && ChatActivity.this.videoTextureView != null && ChatActivity.this.videoPlayerContainer.getTag() != null && (bitmap = animation.getAnimatedBitmap()) != null) {
                        try {
                            Bitmap src = ChatActivity.this.videoTextureView.getBitmap(bitmap.getWidth(), bitmap.getHeight());
                            Canvas canvas = new Canvas(bitmap);
                            canvas.drawBitmap(src, 0.0f, 0.0f, (Paint) null);
                            src.recycle();
                        } catch (Throwable e) {
                            FileLog.e(e);
                        }
                    }
                    MediaController.getInstance().cleanupPlayer(true, true, false, playingObject.equals(message));
                }
                if (!ChatActivity.this.inScheduleMode || (!message.isVideo() && message.type != 1)) {
                    if (PhotoViewer.getInstance().openPhoto(message, message.type != 0 ? ChatActivity.this.dialog_id : 0L, message.type != 0 ? ChatActivity.this.mergeDialogId : 0L, ChatActivity.this.photoViewerProvider)) {
                        PhotoViewer.getInstance().setParentChatActivity(ChatActivity.this);
                    }
                } else {
                    PhotoViewer.getInstance().setParentChatActivity(ChatActivity.this);
                    ArrayList<MessageObject> arrayList = new ArrayList<>();
                    int N = ChatActivity.this.messages.size();
                    for (int a2 = 0; a2 < N; a2++) {
                        MessageObject m = ChatActivity.this.messages.get(a2);
                        if (m.isVideo() || m.type == 1) {
                            arrayList.add(0, m);
                        }
                    }
                    PhotoViewer.getInstance().openPhoto(arrayList, arrayList.indexOf(message), ChatActivity.this.dialog_id, 0L, ChatActivity.this.photoViewerProvider);
                }
                if (ChatActivity.this.noSoundHintView != null) {
                    ChatActivity.this.noSoundHintView.hide();
                }
                if (ChatActivity.this.forwardHintView != null) {
                    ChatActivity.this.forwardHintView.hide();
                }
                if (ChatActivity.this.slowModeHint != null) {
                    ChatActivity.this.slowModeHint.hide();
                }
                MediaController.getInstance().resetGoingToShowMessageObject();
            }

            /* JADX WARN: Removed duplicated region for block: B:139:0x02a0  */
            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public void didPressImage(im.uwrkaxlmjj.ui.cells.ChatMessageCell r17, float r18, float r19) {
                /*
                    Method dump skipped, instruction units count: 850
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.AnonymousClass1.didPressImage(im.uwrkaxlmjj.ui.cells.ChatMessageCell, float, float):void");
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void didPressInstantButton(ChatMessageCell cell, int type) {
                MessageObject messageObject = cell.getMessageObject();
                if (type == 0) {
                    if (messageObject.messageOwner.media != null && messageObject.messageOwner.media.webpage != null && messageObject.messageOwner.media.webpage.cached_page != null) {
                        ArticleViewer.getInstance().setParentActivity(ChatActivity.this.getParentActivity(), ChatActivity.this);
                        ArticleViewer.getInstance().open(messageObject);
                        return;
                    }
                    return;
                }
                if (type == 5) {
                    ChatActivity.this.viewContacts(messageObject.messageOwner.media.user_id);
                } else if (messageObject.messageOwner.media != null && messageObject.messageOwner.media.webpage != null) {
                    Browser.openUrl(ChatActivity.this.getParentActivity(), messageObject.messageOwner.media.webpage.url);
                }
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public String getAdminRank(int uid) {
                if (ChatObject.isChannel(ChatActivity.this.currentChat) && ChatActivity.this.currentChat.megagroup) {
                    return ChatActivity.this.getMessagesController().getAdminRank(ChatActivity.this.currentChat.id, uid);
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public boolean shouldRepeatSticker(MessageObject message) {
                return !ChatActivity.this.alredyPlayedStickers.containsKey(message);
            }

            @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
            public void setShouldNotRepeatSticker(MessageObject message) {
                ChatActivity.this.alredyPlayedStickers.put(message, true);
            }
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$ChatActivity$ChatActivityAdapter(String url) {
            if (url.startsWith("@")) {
                ChatActivity.this.getMessagesController().openByUserName(url.substring(1), ChatActivity.this, 0);
                return;
            }
            if (url.startsWith("#") || url.startsWith("$")) {
                DialogsActivity fragment = new DialogsActivity(null);
                fragment.setSearchString(url);
                ChatActivity.this.presentFragment(fragment);
            } else if (url.startsWith("/")) {
                ChatActivity.this.chatActivityEnterView.setCommand(null, url, false, false);
                if (ChatActivity.this.chatActivityEnterView.getFieldText() == null) {
                    ChatActivity.this.hideFieldPanel(false);
                }
            }
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        /* JADX WARN: Removed duplicated region for block: B:110:0x01e5  */
        /* JADX WARN: Removed duplicated region for block: B:169:0x042a  */
        /* JADX WARN: Removed duplicated region for block: B:197:0x0481  */
        /* JADX WARN: Removed duplicated region for block: B:230:0x0539  */
        /* JADX WARN: Removed duplicated region for block: B:232:0x053c  */
        /* JADX WARN: Removed duplicated region for block: B:236:0x054d  */
        /* JADX WARN: Removed duplicated region for block: B:262:0x065e  */
        /* JADX WARN: Removed duplicated region for block: B:264:0x0661  */
        /* JADX WARN: Removed duplicated region for block: B:268:0x0672  */
        /* JADX WARN: Removed duplicated region for block: B:303:0x0820  */
        /* JADX WARN: Removed duplicated region for block: B:305:0x0823  */
        /* JADX WARN: Removed duplicated region for block: B:309:0x0834  */
        /* JADX WARN: Removed duplicated region for block: B:328:0x0900  */
        /* JADX WARN: Removed duplicated region for block: B:330:0x0903  */
        /* JADX WARN: Removed duplicated region for block: B:338:0x0939  */
        /* JADX WARN: Removed duplicated region for block: B:79:0x0167  */
        /* JADX WARN: Removed duplicated region for block: B:96:0x01b5  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onBindViewHolder(androidx.recyclerview.widget.RecyclerView.ViewHolder r45, int r46) {
            /*
                Method dump skipped, instruction units count: 2980
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.onBindViewHolder(androidx.recyclerview.widget.RecyclerView$ViewHolder, int):void");
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.ChatActivity$ChatActivityAdapter$3, reason: invalid class name */
        class AnonymousClass3 implements ViewTreeObserver.OnPreDrawListener {
            final /* synthetic */ ChatMessageCell val$messageCell;

            AnonymousClass3(ChatMessageCell chatMessageCell) {
                this.val$messageCell = chatMessageCell;
            }

            @Override // android.view.ViewTreeObserver.OnPreDrawListener
            public boolean onPreDraw() {
                PipRoundVideoView pipRoundVideoView = PipRoundVideoView.getInstance();
                if (pipRoundVideoView != null) {
                    pipRoundVideoView.showTemporary(true);
                }
                this.val$messageCell.getViewTreeObserver().removeOnPreDrawListener(this);
                ImageReceiver imageReceiver = this.val$messageCell.getPhotoImage();
                int w = imageReceiver.getImageWidth();
                im.uwrkaxlmjj.ui.components.Rect rect = ChatActivity.this.instantCameraView.getCameraRect();
                float scale = w / rect.width;
                int[] position = new int[2];
                this.val$messageCell.setAlpha(0.0f);
                this.val$messageCell.setTimeAlpha(0.0f);
                this.val$messageCell.getLocationOnScreen(position);
                position[0] = position[0] + imageReceiver.getImageX();
                position[1] = position[1] + imageReceiver.getImageY();
                final View cameraContainer = ChatActivity.this.instantCameraView.getCameraContainer();
                cameraContainer.setPivotX(0.0f);
                cameraContainer.setPivotY(0.0f);
                AnimatorSet animatorSet = new AnimatorSet();
                animatorSet.playTogether(ObjectAnimator.ofFloat(ChatActivity.this.instantCameraView, (Property<InstantCameraView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(cameraContainer, (Property<View, Float>) View.SCALE_X, scale), ObjectAnimator.ofFloat(cameraContainer, (Property<View, Float>) View.SCALE_Y, scale), ObjectAnimator.ofFloat(cameraContainer, (Property<View, Float>) View.TRANSLATION_X, position[0] - rect.x), ObjectAnimator.ofFloat(cameraContainer, (Property<View, Float>) View.TRANSLATION_Y, position[1] - rect.y), ObjectAnimator.ofFloat(ChatActivity.this.instantCameraView.getSwitchButtonView(), (Property<View, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofInt(ChatActivity.this.instantCameraView.getPaint(), AnimationProperties.PAINT_ALPHA, 0), ObjectAnimator.ofFloat(ChatActivity.this.instantCameraView.getMuteImageView(), (Property<View, Float>) View.ALPHA, 0.0f));
                animatorSet.setDuration(180L);
                animatorSet.setInterpolator(new DecelerateInterpolator());
                animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.3.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        AnonymousClass3.this.val$messageCell.setAlpha(1.0f);
                        Property<ChatMessageCell, Float> ALPHA = new AnimationProperties.FloatProperty<ChatMessageCell>("alpha") { // from class: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.3.1.1
                            @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
                            public void setValue(ChatMessageCell object, float value) {
                                object.setTimeAlpha(value);
                            }

                            @Override // android.util.Property
                            public Float get(ChatMessageCell object) {
                                return Float.valueOf(object.getTimeAlpha());
                            }
                        };
                        AnimatorSet animatorSet2 = new AnimatorSet();
                        animatorSet2.playTogether(ObjectAnimator.ofFloat(cameraContainer, (Property<View, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(AnonymousClass3.this.val$messageCell, ALPHA, 1.0f));
                        animatorSet2.setDuration(100L);
                        animatorSet2.setInterpolator(new DecelerateInterpolator());
                        animatorSet2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.3.1.2
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation2) {
                                ChatActivity.this.instantCameraView.hideCamera(true);
                                ChatActivity.this.instantCameraView.setVisibility(4);
                            }
                        });
                        animatorSet2.start();
                    }
                });
                animatorSet.start();
                return true;
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$1$ChatActivity$ChatActivityAdapter(MessageObject message, View v) {
            ChatActivity.this.presentFragment(new BillDetailsActivity(message));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position >= this.messagesStartRow && position < this.messagesEndRow) {
                return ChatActivity.this.messages.get(position - this.messagesStartRow).contentType;
            }
            if (position == this.botInfoRow) {
                return 3;
            }
            return 4;
        }

        /* JADX WARN: Removed duplicated region for block: B:40:0x00cb  */
        /* JADX WARN: Removed duplicated region for block: B:45:0x00e8  */
        /* JADX WARN: Removed duplicated region for block: B:50:0x0105  */
        /* JADX WARN: Removed duplicated region for block: B:53:0x0111  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onViewAttachedToWindow(androidx.recyclerview.widget.RecyclerView.ViewHolder r15) {
            /*
                Method dump skipped, instruction units count: 471
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChatActivity.ChatActivityAdapter.onViewAttachedToWindow(androidx.recyclerview.widget.RecyclerView$ViewHolder):void");
        }

        public void updateRowAtPosition(int index) {
            int pos;
            if (ChatActivity.this.chatLayoutManager == null) {
                return;
            }
            int lastVisibleItem = -1;
            if (!ChatActivity.this.wasManualScroll && ChatActivity.this.unreadMessageObject != null && (pos = ChatActivity.this.messages.indexOf(ChatActivity.this.unreadMessageObject)) >= 0) {
                lastVisibleItem = this.messagesStartRow + pos;
            }
            notifyItemChanged(index);
            if (lastVisibleItem != -1) {
                int top = ((ChatActivity.this.chatListView.getMeasuredHeight() - ChatActivity.this.chatListView.getPaddingBottom()) - ChatActivity.this.chatListView.getPaddingTop()) - AndroidUtilities.dp(29.0f);
                ChatActivity.this.chatLayoutManager.scrollToPositionWithOffset(lastVisibleItem, top);
            }
        }

        public void updateRowWithMessageObject(MessageObject messageObject, boolean allowInPlace) {
            if (allowInPlace) {
                int count = ChatActivity.this.chatListView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child = ChatActivity.this.chatListView.getChildAt(a);
                    if (child instanceof ChatMessageCell) {
                        ChatMessageCell cell = (ChatMessageCell) child;
                        if (cell.getMessageObject() == messageObject) {
                            cell.setMessageObject(messageObject, cell.getCurrentMessagesGroup(), cell.isPinnedBottom(), cell.isPinnedTop());
                            return;
                        }
                    }
                }
            }
            int index = ChatActivity.this.messages.indexOf(messageObject);
            if (index == -1) {
                return;
            }
            updateRowAtPosition(this.messagesStartRow + index);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            updateRows();
            try {
                super.notifyDataSetChanged();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemChanged(int position) {
            updateRows();
            try {
                super.notifyItemChanged(position);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeChanged(int positionStart, int itemCount) {
            updateRows();
            try {
                super.notifyItemRangeChanged(positionStart, itemCount);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemInserted(int position) {
            updateRows();
            try {
                super.notifyItemInserted(position);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemMoved(int fromPosition, int toPosition) {
            updateRows();
            try {
                super.notifyItemMoved(fromPosition, toPosition);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeInserted(int positionStart, int itemCount) {
            updateRows();
            try {
                super.notifyItemRangeInserted(positionStart, itemCount);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRemoved(int position) {
            updateRows();
            try {
                super.notifyItemRemoved(position);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyItemRangeRemoved(int positionStart, int itemCount) {
            updateRows();
            try {
                super.notifyItemRangeRemoved(positionStart, itemCount);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate themeDescriptionDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChatActivity$2DQP8Gzkq1cA66INEXJgVfphrRo
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$161$ChatActivity();
            }
        };
        ThemeDescription[] themeDescriptionArr = new ThemeDescription[392];
        themeDescriptionArr[0] = new ThemeDescription(this.fragmentView, 0, null, null, null, null, Theme.key_chat_wallpaper);
        themeDescriptionArr[1] = new ThemeDescription(this.fragmentView, 0, null, null, null, null, Theme.key_chat_wallpaper_gradient_to);
        themeDescriptionArr[2] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault);
        themeDescriptionArr[3] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault);
        themeDescriptionArr[4] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon);
        themeDescriptionArr[5] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector);
        themeDescriptionArr[6] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUBACKGROUND, null, null, null, null, Theme.key_actionBarDefaultSubmenuBackground);
        themeDescriptionArr[7] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM, null, null, null, null, Theme.key_actionBarDefaultSubmenuItem);
        themeDescriptionArr[8] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM | ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubmenuItemIcon);
        themeDescriptionArr[9] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault);
        themeDescriptionArr[10] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault);
        themeDescriptionArr[11] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon);
        themeDescriptionArr[12] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector);
        themeDescriptionArr[13] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch);
        themeDescriptionArr[14] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder);
        themeDescriptionArr[15] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultIcon);
        themeDescriptionArr[16] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_BACKGROUND, null, null, null, null, Theme.key_actionBarActionModeDefault);
        themeDescriptionArr[17] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_TOPBACKGROUND, null, null, null, null, Theme.key_actionBarActionModeDefaultTop);
        themeDescriptionArr[18] = new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultSelector);
        themeDescriptionArr[19] = new ThemeDescription(this.selectedMessagesCountTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_actionBarActionModeDefaultIcon);
        themeDescriptionArr[20] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text);
        themeDescriptionArr[21] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundRed);
        themeDescriptionArr[22] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundOrange);
        themeDescriptionArr[23] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundViolet);
        themeDescriptionArr[24] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundGreen);
        themeDescriptionArr[25] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundCyan);
        themeDescriptionArr[26] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundBlue);
        themeDescriptionArr[27] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_backgroundPink);
        themeDescriptionArr[28] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessageRed);
        themeDescriptionArr[29] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessageOrange);
        themeDescriptionArr[30] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessageViolet);
        themeDescriptionArr[31] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessageGreen);
        themeDescriptionArr[32] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessageCyan);
        themeDescriptionArr[33] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessageBlue);
        themeDescriptionArr[34] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_avatar_nameInMessagePink);
        themeDescriptionArr[35] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class, BotHelpCell.class}, null, new Drawable[]{Theme.chat_msgInDrawable, Theme.chat_msgInMediaDrawable}, null, Theme.key_chat_inBubble);
        themeDescriptionArr[36] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInSelectedDrawable, Theme.chat_msgInMediaSelectedDrawable}, null, Theme.key_chat_inBubbleSelected);
        themeDescriptionArr[37] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class, BotHelpCell.class}, null, new Drawable[]{Theme.chat_msgInShadowDrawable, Theme.chat_msgInMediaShadowDrawable}, null, Theme.key_chat_inBubbleShadow);
        themeDescriptionArr[38] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutDrawable, Theme.chat_msgOutMediaDrawable}, null, Theme.key_chat_outBubble);
        themeDescriptionArr[39] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutSelectedDrawable, Theme.chat_msgOutMediaSelectedDrawable}, null, Theme.key_chat_outBubbleSelected);
        themeDescriptionArr[40] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutShadowDrawable, Theme.chat_msgOutMediaShadowDrawable}, null, Theme.key_chat_outBubbleShadow);
        themeDescriptionArr[41] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatActionCell.class}, Theme.chat_actionTextPaint, null, null, Theme.key_chat_serviceText);
        themeDescriptionArr[42] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_LINKCOLOR, new Class[]{ChatActionCell.class}, Theme.chat_actionTextPaint, null, null, Theme.key_chat_serviceLink);
        themeDescriptionArr[43] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_shareIconDrawable, Theme.chat_replyIconDrawable, Theme.chat_botInlineDrawable, Theme.chat_botLinkDrawalbe, Theme.chat_goIconDrawable}, null, Theme.key_chat_serviceIcon);
        themeDescriptionArr[44] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class, ChatActionCell.class}, null, null, null, Theme.key_chat_serviceBackground);
        themeDescriptionArr[45] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class, ChatActionCell.class}, null, null, null, Theme.key_chat_serviceBackgroundSelected);
        themeDescriptionArr[46] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class, BotHelpCell.class}, null, null, null, Theme.key_chat_messageTextIn);
        themeDescriptionArr[47] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_messageTextOut);
        themeDescriptionArr[48] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_LINKCOLOR, new Class[]{ChatMessageCell.class, BotHelpCell.class}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messageLinkIn, (Object) null);
        themeDescriptionArr[49] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_LINKCOLOR, new Class[]{ChatMessageCell.class}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messageLinkOut, (Object) null);
        themeDescriptionArr[50] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgNoSoundDrawable}, null, Theme.key_chat_mediaTimeText);
        themeDescriptionArr[51] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckDrawable}, null, Theme.key_chat_outSentCheck);
        themeDescriptionArr[52] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckSelected);
        themeDescriptionArr[53] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckReadDrawable, Theme.chat_msgOutHalfCheckDrawable}, null, Theme.key_chat_outSentCheckRead);
        themeDescriptionArr[54] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCheckReadSelectedDrawable, Theme.chat_msgOutHalfCheckSelectedDrawable}, null, Theme.key_chat_outSentCheckReadSelected);
        themeDescriptionArr[55] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutClockDrawable}, null, Theme.key_chat_outSentClock);
        themeDescriptionArr[56] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutSelectedClockDrawable}, null, Theme.key_chat_outSentClockSelected);
        themeDescriptionArr[57] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInClockDrawable}, null, Theme.key_chat_inSentClock);
        themeDescriptionArr[58] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInSelectedClockDrawable}, null, Theme.key_chat_inSentClockSelected);
        themeDescriptionArr[59] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgMediaCheckDrawable, Theme.chat_msgMediaHalfCheckDrawable}, null, Theme.key_chat_mediaSentCheck);
        themeDescriptionArr[60] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgStickerHalfCheckDrawable, Theme.chat_msgStickerCheckDrawable, Theme.chat_msgStickerClockDrawable, Theme.chat_msgStickerViewsDrawable}, null, Theme.key_chat_serviceText);
        themeDescriptionArr[61] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgMediaClockDrawable}, null, Theme.key_chat_mediaSentClock);
        themeDescriptionArr[62] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutViewsDrawable}, null, Theme.key_chat_outViews);
        themeDescriptionArr[63] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutViewsSelectedDrawable}, null, Theme.key_chat_outViewsSelected);
        themeDescriptionArr[64] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInViewsDrawable}, null, Theme.key_chat_inViews);
        themeDescriptionArr[65] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInViewsSelectedDrawable}, null, Theme.key_chat_inViewsSelected);
        themeDescriptionArr[66] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgMediaViewsDrawable}, null, Theme.key_chat_mediaViews);
        themeDescriptionArr[67] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutMenuDrawable}, null, Theme.key_chat_outMenu);
        themeDescriptionArr[68] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutMenuSelectedDrawable}, null, Theme.key_chat_outMenuSelected);
        themeDescriptionArr[69] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInMenuDrawable}, null, Theme.key_chat_inMenu);
        themeDescriptionArr[70] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInMenuSelectedDrawable}, null, Theme.key_chat_inMenuSelected);
        themeDescriptionArr[71] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgMediaMenuDrawable}, null, Theme.key_chat_mediaMenu);
        themeDescriptionArr[72] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutInstantDrawable, Theme.chat_msgOutCallDrawable}, null, Theme.key_chat_outInstant);
        themeDescriptionArr[73] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgOutCallSelectedDrawable}, null, Theme.key_chat_outInstantSelected);
        themeDescriptionArr[74] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInInstantDrawable, Theme.chat_msgInCallDrawable}, null, Theme.key_chat_inInstant);
        themeDescriptionArr[75] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgInCallSelectedDrawable}, null, Theme.key_chat_inInstantSelected);
        themeDescriptionArr[76] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgCallUpGreenDrawable}, null, Theme.key_chat_outGreenCall);
        themeDescriptionArr[77] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgCallDownRedDrawable}, null, Theme.key_chat_inRedCall);
        themeDescriptionArr[78] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgCallDownGreenDrawable}, null, Theme.key_chat_inGreenCall);
        themeDescriptionArr[79] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_msgErrorPaint, null, null, Theme.key_chat_sentError);
        themeDescriptionArr[80] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_msgErrorDrawable}, null, Theme.key_chat_sentErrorIcon);
        themeDescriptionArr[81] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, themeDescriptionDelegate, Theme.key_chat_selectedBackground);
        themeDescriptionArr[82] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_durationPaint, null, null, Theme.key_chat_previewDurationText);
        themeDescriptionArr[83] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_gamePaint, null, null, Theme.key_chat_previewGameText);
        themeDescriptionArr[84] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inPreviewInstantText);
        themeDescriptionArr[85] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outPreviewInstantText);
        themeDescriptionArr[86] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inPreviewInstantSelectedText);
        themeDescriptionArr[87] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outPreviewInstantSelectedText);
        themeDescriptionArr[88] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_deleteProgressPaint, null, null, Theme.key_chat_secretTimeText);
        themeDescriptionArr[89] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_stickerNameText);
        themeDescriptionArr[90] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_botButtonPaint, null, null, Theme.key_chat_botButtonText);
        themeDescriptionArr[91] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_botProgressPaint, null, null, Theme.key_chat_botProgress);
        themeDescriptionArr[92] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_timeBackgroundPaint, null, null, Theme.key_chat_mediaTimeBackground);
        themeDescriptionArr[93] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inForwardedNameText);
        themeDescriptionArr[94] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outForwardedNameText);
        themeDescriptionArr[95] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inViaBotNameText);
        themeDescriptionArr[96] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outViaBotNameText);
        themeDescriptionArr[97] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_stickerViaBotNameText);
        themeDescriptionArr[98] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyLine);
        themeDescriptionArr[99] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyLine);
        themeDescriptionArr[100] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_stickerReplyLine);
        themeDescriptionArr[101] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyNameText);
        themeDescriptionArr[102] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyNameText);
        themeDescriptionArr[103] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_stickerReplyNameText);
        themeDescriptionArr[104] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyMessageText);
        themeDescriptionArr[105] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyMessageText);
        themeDescriptionArr[106] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyMediaMessageText);
        themeDescriptionArr[107] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyMediaMessageText);
        themeDescriptionArr[108] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inReplyMediaMessageSelectedText);
        themeDescriptionArr[109] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outReplyMediaMessageSelectedText);
        themeDescriptionArr[110] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_stickerReplyMessageText);
        themeDescriptionArr[111] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inPreviewLine);
        themeDescriptionArr[112] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outPreviewLine);
        themeDescriptionArr[113] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inSiteNameText);
        themeDescriptionArr[114] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outSiteNameText);
        themeDescriptionArr[115] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inContactNameText);
        themeDescriptionArr[116] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outContactNameText);
        themeDescriptionArr[117] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inContactPhoneText);
        themeDescriptionArr[118] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inContactPhoneSelectedText);
        themeDescriptionArr[119] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outContactPhoneText);
        themeDescriptionArr[120] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outContactPhoneSelectedText);
        themeDescriptionArr[121] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_mediaProgress);
        themeDescriptionArr[122] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioProgress);
        themeDescriptionArr[123] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioProgress);
        themeDescriptionArr[124] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioSelectedProgress);
        themeDescriptionArr[125] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioSelectedProgress);
        themeDescriptionArr[126] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_mediaTimeText);
        themeDescriptionArr[127] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inTimeText);
        themeDescriptionArr[128] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outTimeText);
        themeDescriptionArr[129] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inTimeSelectedText);
        themeDescriptionArr[130] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_adminText);
        themeDescriptionArr[131] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_adminSelectedText);
        themeDescriptionArr[132] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outTimeSelectedText);
        themeDescriptionArr[133] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioPerformerText);
        themeDescriptionArr[134] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioPerformerSelectedText);
        themeDescriptionArr[135] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioPerformerText);
        themeDescriptionArr[136] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioPerformerSelectedText);
        themeDescriptionArr[137] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioTitleText);
        themeDescriptionArr[138] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioTitleText);
        themeDescriptionArr[139] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioDurationText);
        themeDescriptionArr[140] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioDurationText);
        themeDescriptionArr[141] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioDurationSelectedText);
        themeDescriptionArr[142] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioDurationSelectedText);
        themeDescriptionArr[143] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioSeekbar);
        themeDescriptionArr[144] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioSeekbar);
        themeDescriptionArr[145] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioSeekbarSelected);
        themeDescriptionArr[146] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioSeekbarSelected);
        themeDescriptionArr[147] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioSeekbarFill);
        themeDescriptionArr[148] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inAudioCacheSeekbar);
        themeDescriptionArr[149] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioSeekbarFill);
        themeDescriptionArr[150] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outAudioCacheSeekbar);
        themeDescriptionArr[151] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inVoiceSeekbar);
        themeDescriptionArr[152] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outVoiceSeekbar);
        themeDescriptionArr[153] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inVoiceSeekbarSelected);
        themeDescriptionArr[154] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outVoiceSeekbarSelected);
        themeDescriptionArr[155] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inVoiceSeekbarFill);
        themeDescriptionArr[156] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outVoiceSeekbarFill);
        themeDescriptionArr[157] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileProgress);
        themeDescriptionArr[158] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileProgress);
        themeDescriptionArr[159] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileProgressSelected);
        themeDescriptionArr[160] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileProgressSelected);
        themeDescriptionArr[161] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileNameText);
        themeDescriptionArr[162] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileNameText);
        themeDescriptionArr[163] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileInfoText);
        themeDescriptionArr[164] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileInfoText);
        themeDescriptionArr[165] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileInfoSelectedText);
        themeDescriptionArr[166] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileInfoSelectedText);
        themeDescriptionArr[167] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileBackground);
        themeDescriptionArr[168] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileBackground);
        themeDescriptionArr[169] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inFileBackgroundSelected);
        themeDescriptionArr[170] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outFileBackgroundSelected);
        themeDescriptionArr[171] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inVenueInfoText);
        themeDescriptionArr[172] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outVenueInfoText);
        themeDescriptionArr[173] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inVenueInfoSelectedText);
        themeDescriptionArr[174] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outVenueInfoSelectedText);
        themeDescriptionArr[175] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_mediaInfoText);
        themeDescriptionArr[176] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_urlPaint, null, null, Theme.key_chat_linkSelectBackground);
        themeDescriptionArr[177] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, Theme.chat_textSearchSelectionPaint, null, null, Theme.key_chat_textSelectBackground);
        themeDescriptionArr[178] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outLoader);
        themeDescriptionArr[179] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outMediaIcon);
        themeDescriptionArr[180] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outLoaderSelected);
        themeDescriptionArr[181] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_outMediaIconSelected);
        themeDescriptionArr[182] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inLoader);
        themeDescriptionArr[183] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inMediaIcon);
        themeDescriptionArr[184] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inLoaderSelected);
        themeDescriptionArr[185] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, null, null, Theme.key_chat_inMediaIconSelected);
        themeDescriptionArr[186] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[0][0], Theme.chat_photoStatesDrawables[1][0], Theme.chat_photoStatesDrawables[2][0], Theme.chat_photoStatesDrawables[3][0]}, null, Theme.key_chat_mediaLoaderPhoto);
        themeDescriptionArr[187] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[0][0], Theme.chat_photoStatesDrawables[1][0], Theme.chat_photoStatesDrawables[2][0], Theme.chat_photoStatesDrawables[3][0]}, null, Theme.key_chat_mediaLoaderPhotoIcon);
        themeDescriptionArr[188] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[0][1], Theme.chat_photoStatesDrawables[1][1], Theme.chat_photoStatesDrawables[2][1], Theme.chat_photoStatesDrawables[3][1]}, null, Theme.key_chat_mediaLoaderPhotoSelected);
        themeDescriptionArr[189] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[0][1], Theme.chat_photoStatesDrawables[1][1], Theme.chat_photoStatesDrawables[2][1], Theme.chat_photoStatesDrawables[3][1]}, null, Theme.key_chat_mediaLoaderPhotoIconSelected);
        themeDescriptionArr[190] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[7][0], Theme.chat_photoStatesDrawables[8][0]}, null, Theme.key_chat_outLoaderPhoto);
        themeDescriptionArr[191] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[7][0], Theme.chat_photoStatesDrawables[8][0]}, null, Theme.key_chat_outLoaderPhotoIcon);
        themeDescriptionArr[192] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[7][1], Theme.chat_photoStatesDrawables[8][1]}, null, Theme.key_chat_outLoaderPhotoSelected);
        themeDescriptionArr[193] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[7][1], Theme.chat_photoStatesDrawables[8][1]}, null, Theme.key_chat_outLoaderPhotoIconSelected);
        themeDescriptionArr[194] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[10][0], Theme.chat_photoStatesDrawables[11][0]}, null, Theme.key_chat_inLoaderPhoto);
        themeDescriptionArr[195] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[10][0], Theme.chat_photoStatesDrawables[11][0]}, null, Theme.key_chat_inLoaderPhotoIcon);
        themeDescriptionArr[196] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[10][1], Theme.chat_photoStatesDrawables[11][1]}, null, Theme.key_chat_inLoaderPhotoSelected);
        themeDescriptionArr[197] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[10][1], Theme.chat_photoStatesDrawables[11][1]}, null, Theme.key_chat_inLoaderPhotoIconSelected);
        themeDescriptionArr[198] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[9][0]}, null, Theme.key_chat_outFileIcon);
        themeDescriptionArr[199] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[9][1]}, null, Theme.key_chat_outFileSelectedIcon);
        themeDescriptionArr[200] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[12][0]}, null, Theme.key_chat_inFileIcon);
        themeDescriptionArr[201] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_photoStatesDrawables[12][1]}, null, Theme.key_chat_inFileSelectedIcon);
        themeDescriptionArr[202] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_contactDrawable[0]}, null, Theme.key_chat_inContactBackground);
        themeDescriptionArr[203] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_contactDrawable[0]}, null, Theme.key_chat_inContactIcon);
        themeDescriptionArr[204] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_contactDrawable[1]}, null, Theme.key_chat_outContactBackground);
        themeDescriptionArr[205] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_contactDrawable[1]}, null, Theme.key_chat_outContactIcon);
        themeDescriptionArr[206] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_locationDrawable[0]}, null, Theme.key_chat_inLocationBackground);
        themeDescriptionArr[207] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_locationDrawable[0]}, null, Theme.key_chat_inLocationIcon);
        themeDescriptionArr[208] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_locationDrawable[1]}, null, Theme.key_chat_outLocationBackground);
        themeDescriptionArr[209] = new ThemeDescription(this.chatListView, 0, new Class[]{ChatMessageCell.class}, null, new Drawable[]{Theme.chat_locationDrawable[1]}, null, Theme.key_chat_outLocationIcon);
        themeDescriptionArr[210] = new ThemeDescription(this.mentionContainer, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[211] = new ThemeDescription(this.mentionContainer, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow);
        themeDescriptionArr[212] = new ThemeDescription(this.searchContainer, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[213] = new ThemeDescription(this.searchContainer, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow);
        themeDescriptionArr[214] = new ThemeDescription(this.bottomOverlay, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[215] = new ThemeDescription(this.bottomOverlay, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow);
        themeDescriptionArr[216] = new ThemeDescription(this.bottomOverlayChat, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[217] = new ThemeDescription(this.bottomOverlayChat, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow);
        themeDescriptionArr[218] = new ThemeDescription(this.bottomMessagesActionContainer, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[219] = new ThemeDescription(this.bottomMessagesActionContainer, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow);
        themeDescriptionArr[220] = new ThemeDescription(this.chatActivityEnterView, 0, null, Theme.chat_composeBackgroundPaint, null, null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[221] = new ThemeDescription(this.chatActivityEnterView, 0, null, null, new Drawable[]{Theme.chat_composeShadowDrawable}, null, Theme.key_chat_messagePanelShadow);
        themeDescriptionArr[222] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_BACKGROUND, new Class[]{ChatActivityEnterView.class}, new String[]{"audioVideoButtonContainer"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[223] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"messageEditText"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelText);
        themeDescriptionArr[224] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_CURSORCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"messageEditText"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelCursor);
        themeDescriptionArr[225] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"recordSendText"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_fieldOverlayText);
        themeDescriptionArr[226] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_HINTTEXTCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"messageEditText"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelHint);
        themeDescriptionArr[227] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"sendButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelSend);
        themeDescriptionArr[228] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"sendButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelSendPressed);
        themeDescriptionArr[229] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatActivityEnterView.class}, new String[]{"sendButton"}, null, null, 24, null, Theme.key_chat_messagePanelSend);
        themeDescriptionArr[230] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"emojiButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[231] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"botButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[232] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"notifyButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[233] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR | ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatActivityEnterView.class}, new String[]{"scheduledButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[234] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"scheduledButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoiceDot);
        themeDescriptionArr[235] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"attachButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[236] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"audioSendButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[237] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"videoSendButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelIcons);
        themeDescriptionArr[238] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"notifyButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVideoFrame);
        themeDescriptionArr[239] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"videoTimelineView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelSend);
        themeDescriptionArr[240] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"doneButtonImage"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[241] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_BACKGROUND, new Class[]{ChatActivityEnterView.class}, new String[]{"recordedAudioPanel"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[242] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"micDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoicePressed);
        themeDescriptionArr[243] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"cameraDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoicePressed);
        themeDescriptionArr[244] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"sendDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoicePressed);
        themeDescriptionArr[245] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"lockDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceLock);
        themeDescriptionArr[246] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"lockTopDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceLock);
        themeDescriptionArr[247] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"lockArrowDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceLock);
        themeDescriptionArr[248] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"lockBackgroundDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceLockBackground);
        themeDescriptionArr[249] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"lockShadowDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceLockShadow);
        themeDescriptionArr[250] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"recordDeleteImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceDelete);
        themeDescriptionArr[251] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ChatActivityEnterView.class}, new String[]{"recordedAudioBackground"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoiceBackground);
        themeDescriptionArr[252] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"recordTimeText"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordTime);
        themeDescriptionArr[253] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_BACKGROUND, new Class[]{ChatActivityEnterView.class}, new String[]{"recordTimeContainer"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[254] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"recordCancelText"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordVoiceCancel);
        themeDescriptionArr[255] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_BACKGROUND, new Class[]{ChatActivityEnterView.class}, new String[]{"recordPanel"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelBackground);
        themeDescriptionArr[256] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"recordedAudioTimeTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceDuration);
        themeDescriptionArr[257] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"recordCancelImage"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordVoiceCancel);
        themeDescriptionArr[258] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"doneButtonProgress"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_contextProgressInner1);
        themeDescriptionArr[259] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"doneButtonProgress"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_contextProgressOuter1);
        themeDescriptionArr[260] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatActivityEnterView.class}, new String[]{"cancelBotButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelCancelInlineBot);
        themeDescriptionArr[261] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"redDotPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoiceDot);
        themeDescriptionArr[262] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceBackground);
        themeDescriptionArr[263] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"paintRecord"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_messagePanelVoiceShadow);
        themeDescriptionArr[264] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"seekBarWaveform"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoiceProgress);
        themeDescriptionArr[265] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"seekBarWaveform"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoiceProgressInner);
        themeDescriptionArr[266] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"playDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoicePlayPause);
        themeDescriptionArr[267] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"pauseDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoicePlayPause);
        themeDescriptionArr[268] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, new Class[]{ChatActivityEnterView.class}, new String[]{"playDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoicePlayPausePressed);
        themeDescriptionArr[269] = new ThemeDescription(this.chatActivityEnterView, ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, new Class[]{ChatActivityEnterView.class}, new String[]{"pauseDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_recordedVoicePlayPausePressed);
        themeDescriptionArr[270] = new ThemeDescription(this.chatActivityEnterView, 0, new Class[]{ChatActivityEnterView.class}, new String[]{"dotPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_emojiPanelNewTrending);
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        ChatActivityEnterView emojiView = chatActivityEnterView;
        if (chatActivityEnterView != null) {
            emojiView = chatActivityEnterView.getEmojiView();
        }
        themeDescriptionArr[271] = new ThemeDescription(emojiView, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelBackground);
        ChatActivityEnterView chatActivityEnterView2 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView2 = chatActivityEnterView2;
        if (chatActivityEnterView2 != null) {
            emojiView2 = chatActivityEnterView2.getEmojiView();
        }
        themeDescriptionArr[272] = new ThemeDescription(emojiView2, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelShadowLine);
        ChatActivityEnterView chatActivityEnterView3 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView3 = chatActivityEnterView3;
        if (chatActivityEnterView3 != null) {
            emojiView3 = chatActivityEnterView3.getEmojiView();
        }
        themeDescriptionArr[273] = new ThemeDescription(emojiView3, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelEmptyText);
        ChatActivityEnterView chatActivityEnterView4 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView4 = chatActivityEnterView4;
        if (chatActivityEnterView4 != null) {
            emojiView4 = chatActivityEnterView4.getEmojiView();
        }
        themeDescriptionArr[274] = new ThemeDescription(emojiView4, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelIcon);
        ChatActivityEnterView chatActivityEnterView5 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView5 = chatActivityEnterView5;
        if (chatActivityEnterView5 != null) {
            emojiView5 = chatActivityEnterView5.getEmojiView();
        }
        themeDescriptionArr[275] = new ThemeDescription(emojiView5, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelIconSelected);
        ChatActivityEnterView chatActivityEnterView6 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView6 = chatActivityEnterView6;
        if (chatActivityEnterView6 != null) {
            emojiView6 = chatActivityEnterView6.getEmojiView();
        }
        themeDescriptionArr[276] = new ThemeDescription(emojiView6, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelStickerPackSelector);
        ChatActivityEnterView chatActivityEnterView7 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView7 = chatActivityEnterView7;
        if (chatActivityEnterView7 != null) {
            emojiView7 = chatActivityEnterView7.getEmojiView();
        }
        themeDescriptionArr[277] = new ThemeDescription(emojiView7, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelBackspace);
        ChatActivityEnterView chatActivityEnterView8 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView8 = chatActivityEnterView8;
        if (chatActivityEnterView8 != null) {
            emojiView8 = chatActivityEnterView8.getEmojiView();
        }
        themeDescriptionArr[278] = new ThemeDescription(emojiView8, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelTrendingTitle);
        ChatActivityEnterView chatActivityEnterView9 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView9 = chatActivityEnterView9;
        if (chatActivityEnterView9 != null) {
            emojiView9 = chatActivityEnterView9.getEmojiView();
        }
        themeDescriptionArr[279] = new ThemeDescription(emojiView9, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelTrendingDescription);
        ChatActivityEnterView chatActivityEnterView10 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView10 = chatActivityEnterView10;
        if (chatActivityEnterView10 != null) {
            emojiView10 = chatActivityEnterView10.getEmojiView();
        }
        themeDescriptionArr[280] = new ThemeDescription(emojiView10, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelBadgeText);
        ChatActivityEnterView chatActivityEnterView11 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView11 = chatActivityEnterView11;
        if (chatActivityEnterView11 != null) {
            emojiView11 = chatActivityEnterView11.getEmojiView();
        }
        themeDescriptionArr[281] = new ThemeDescription(emojiView11, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelBadgeBackground);
        ChatActivityEnterView chatActivityEnterView12 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView12 = chatActivityEnterView12;
        if (chatActivityEnterView12 != null) {
            emojiView12 = chatActivityEnterView12.getEmojiView();
        }
        themeDescriptionArr[282] = new ThemeDescription(emojiView12, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiBottomPanelIcon);
        ChatActivityEnterView chatActivityEnterView13 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView13 = chatActivityEnterView13;
        if (chatActivityEnterView13 != null) {
            emojiView13 = chatActivityEnterView13.getEmojiView();
        }
        themeDescriptionArr[283] = new ThemeDescription(emojiView13, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiSearchIcon);
        ChatActivityEnterView chatActivityEnterView14 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView14 = chatActivityEnterView14;
        if (chatActivityEnterView14 != null) {
            emojiView14 = chatActivityEnterView14.getEmojiView();
        }
        themeDescriptionArr[284] = new ThemeDescription(emojiView14, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelStickerSetNameHighlight);
        ChatActivityEnterView chatActivityEnterView15 = this.chatActivityEnterView;
        ChatActivityEnterView emojiView15 = chatActivityEnterView15;
        if (chatActivityEnterView15 != null) {
            emojiView15 = chatActivityEnterView15.getEmojiView();
        }
        themeDescriptionArr[285] = new ThemeDescription(emojiView15, 0, new Class[]{EmojiView.class}, (String[]) null, (Paint[]) null, (Drawable[]) null, themeDescriptionDelegate, Theme.key_chat_emojiPanelStickerPackSelectorLine);
        themeDescriptionArr[286] = new ThemeDescription(this.undoView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_undo_background);
        themeDescriptionArr[287] = new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"undoImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_cancelColor);
        themeDescriptionArr[288] = new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"undoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_cancelColor);
        themeDescriptionArr[289] = new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"infoTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor);
        themeDescriptionArr[290] = new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"textPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor);
        themeDescriptionArr[291] = new ThemeDescription(this.undoView, 0, new Class[]{UndoView.class}, new String[]{"progressPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor);
        themeDescriptionArr[292] = new ThemeDescription(this.undoView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{UndoView.class}, new String[]{"leftImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_undo_infoColor);
        themeDescriptionArr[293] = new ThemeDescription(null, 0, null, null, null, null, Theme.key_chat_botKeyboardButtonText);
        themeDescriptionArr[294] = new ThemeDescription(null, 0, null, null, null, null, Theme.key_chat_botKeyboardButtonBackground);
        themeDescriptionArr[295] = new ThemeDescription(null, 0, null, null, null, null, Theme.key_chat_botKeyboardButtonBackgroundPressed);
        themeDescriptionArr[296] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"frameLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerBackground);
        themeDescriptionArr[297] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{FragmentContextView.class}, new String[]{"playButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerPlayPause);
        themeDescriptionArr[298] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerTitle);
        themeDescriptionArr[299] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_FASTSCROLL, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerPerformer);
        themeDescriptionArr[300] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{FragmentContextView.class}, new String[]{"closeButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerClose);
        themeDescriptionArr[301] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"frameLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_returnToCallBackground);
        themeDescriptionArr[302] = new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_returnToCallText);
        themeDescriptionArr[303] = new ThemeDescription(this.pinnedLineView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_chat_topPanelLine);
        themeDescriptionArr[304] = new ThemeDescription(this.pinnedMessageNameTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_topPanelTitle);
        themeDescriptionArr[305] = new ThemeDescription(this.pinnedMessageTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_topPanelMessage);
        themeDescriptionArr[306] = new ThemeDescription(this.alertNameTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_topPanelTitle);
        themeDescriptionArr[307] = new ThemeDescription(this.alertTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_topPanelMessage);
        themeDescriptionArr[308] = new ThemeDescription(this.closePinned, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_topPanelClose);
        themeDescriptionArr[309] = new ThemeDescription(this.closeReportSpam, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_topPanelClose);
        themeDescriptionArr[310] = new ThemeDescription(this.topChatPanelView, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_topPanelBackground);
        themeDescriptionArr[311] = new ThemeDescription(this.alertView, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_topPanelBackground);
        themeDescriptionArr[312] = new ThemeDescription(this.pinnedMessageView, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_topPanelBackground);
        themeDescriptionArr[313] = new ThemeDescription(this.addToContactsButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_addContact);
        themeDescriptionArr[314] = new ThemeDescription(this.reportSpamButton, ThemeDescription.FLAG_CHECKTAG | ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_reportSpam);
        themeDescriptionArr[315] = new ThemeDescription(this.reportSpamButton, ThemeDescription.FLAG_CHECKTAG | ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_addContact);
        themeDescriptionArr[316] = new ThemeDescription(this.replyLineView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_chat_replyPanelLine);
        themeDescriptionArr[317] = new ThemeDescription(this.replyNameTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_replyPanelName);
        themeDescriptionArr[318] = new ThemeDescription(this.replyObjectTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_replyPanelMessage);
        themeDescriptionArr[319] = new ThemeDescription(this.replyIconImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_replyPanelIcons);
        themeDescriptionArr[320] = new ThemeDescription(this.replyCloseImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_replyPanelClose);
        themeDescriptionArr[321] = new ThemeDescription(this.searchUpButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_searchPanelIcons);
        themeDescriptionArr[322] = new ThemeDescription(this.searchDownButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_searchPanelIcons);
        themeDescriptionArr[323] = new ThemeDescription(this.searchCalendarButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_searchPanelIcons);
        themeDescriptionArr[324] = new ThemeDescription(this.searchUserButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_searchPanelIcons);
        themeDescriptionArr[325] = new ThemeDescription(this.searchCountText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_searchPanelText);
        themeDescriptionArr[326] = new ThemeDescription(this.bottomOverlayText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_secretChatStatusText);
        themeDescriptionArr[327] = new ThemeDescription(this.bottomOverlayChatText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText);
        themeDescriptionArr[328] = new ThemeDescription(this.bottomOverlayChatText2, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText);
        themeDescriptionArr[329] = new ThemeDescription(this.bottomOverlayProgress, 0, null, null, null, null, Theme.key_chat_fieldOverlayText);
        themeDescriptionArr[330] = new ThemeDescription(this.bigEmptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_serviceText);
        themeDescriptionArr[331] = new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_serviceText);
        themeDescriptionArr[332] = new ThemeDescription(this.progressBar, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_chat_serviceText);
        themeDescriptionArr[333] = new ThemeDescription(this.stickersPanelArrow, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_stickersHintPanel);
        themeDescriptionArr[334] = new ThemeDescription(this.stickersListView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{StickerCell.class}, null, null, null, Theme.key_chat_stickersHintPanel);
        themeDescriptionArr[335] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_USEBACKGROUNDDRAWABLE, new Class[]{ChatUnreadCell.class}, new String[]{"backgroundLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_unreadMessagesStartBackground);
        themeDescriptionArr[336] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{ChatUnreadCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_unreadMessagesStartArrowIcon);
        themeDescriptionArr[337] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{ChatUnreadCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_unreadMessagesStartText);
        themeDescriptionArr[338] = new ThemeDescription(this.progressView2, ThemeDescription.FLAG_SERVICEBACKGROUND, null, null, null, null, Theme.key_chat_serviceBackground);
        themeDescriptionArr[339] = new ThemeDescription(this.emptyView, ThemeDescription.FLAG_SERVICEBACKGROUND, null, null, null, null, Theme.key_chat_serviceBackground);
        themeDescriptionArr[340] = new ThemeDescription(this.bigEmptyView, ThemeDescription.FLAG_SERVICEBACKGROUND, null, null, null, null, Theme.key_chat_serviceBackground);
        themeDescriptionArr[341] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_SERVICEBACKGROUND, new Class[]{ChatLoadingCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_serviceBackground);
        themeDescriptionArr[342] = new ThemeDescription(this.chatListView, ThemeDescription.FLAG_PROGRESSBAR, new Class[]{ChatLoadingCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_serviceText);
        themeDescriptionArr[343] = new ThemeDescription(this.mentionListView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{BotSwitchCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_botSwitchToInlineText);
        themeDescriptionArr[344] = new ThemeDescription(this.mentionListView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{MentionCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText);
        themeDescriptionArr[345] = new ThemeDescription(this.mentionListView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{MentionCell.class}, new String[]{"usernameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3);
        themeDescriptionArr[346] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, new Drawable[]{Theme.chat_inlineResultFile, Theme.chat_inlineResultAudio, Theme.chat_inlineResultLocation}, null, Theme.key_chat_inlineResultIcon);
        themeDescriptionArr[347] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, null, null, Theme.key_windowBackgroundWhiteGrayText2);
        themeDescriptionArr[348] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, null, null, Theme.key_windowBackgroundWhiteLinkText);
        themeDescriptionArr[349] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, null, null, Theme.key_windowBackgroundWhiteBlackText);
        themeDescriptionArr[350] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, null, null, Theme.key_chat_inAudioProgress);
        themeDescriptionArr[351] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, null, null, Theme.key_chat_inAudioSelectedProgress);
        themeDescriptionArr[352] = new ThemeDescription(this.mentionListView, 0, new Class[]{ContextLinkCell.class}, null, null, null, Theme.key_divider);
        themeDescriptionArr[353] = new ThemeDescription(this.gifHintTextView, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_gifSaveHintBackground);
        themeDescriptionArr[354] = new ThemeDescription(this.gifHintTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_gifSaveHintText);
        themeDescriptionArr[355] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_chat_attachMediaBanBackground);
        themeDescriptionArr[356] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_chat_attachMediaBanText);
        themeDescriptionArr[357] = new ThemeDescription(this.noSoundHintView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{HintView.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_gifSaveHintText);
        themeDescriptionArr[358] = new ThemeDescription(this.noSoundHintView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{HintView.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_gifSaveHintText);
        themeDescriptionArr[359] = new ThemeDescription(this.noSoundHintView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{HintView.class}, new String[]{"arrowImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_gifSaveHintBackground);
        themeDescriptionArr[360] = new ThemeDescription(this.forwardHintView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{HintView.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_gifSaveHintText);
        themeDescriptionArr[361] = new ThemeDescription(this.forwardHintView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{HintView.class}, new String[]{"arrowImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chat_gifSaveHintBackground);
        themeDescriptionArr[362] = new ThemeDescription(this.pagedownButtonCounter, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_goDownButtonCounterBackground);
        themeDescriptionArr[363] = new ThemeDescription(this.pagedownButtonCounter, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_goDownButtonCounter);
        themeDescriptionArr[364] = new ThemeDescription(this.pagedownButtonImage, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_goDownButton);
        themeDescriptionArr[365] = new ThemeDescription(this.pagedownButtonImage, ThemeDescription.FLAG_DRAWABLESELECTEDSTATE | ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_goDownButtonShadow);
        themeDescriptionArr[366] = new ThemeDescription(this.pagedownButtonImage, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_goDownButtonIcon);
        themeDescriptionArr[367] = new ThemeDescription(this.mentiondownButtonCounter, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_goDownButtonCounterBackground);
        themeDescriptionArr[368] = new ThemeDescription(this.mentiondownButtonCounter, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_goDownButtonCounter);
        themeDescriptionArr[369] = new ThemeDescription(this.mentiondownButtonImage, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_goDownButton);
        themeDescriptionArr[370] = new ThemeDescription(this.mentiondownButtonImage, ThemeDescription.FLAG_DRAWABLESELECTEDSTATE | ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chat_goDownButtonShadow);
        themeDescriptionArr[371] = new ThemeDescription(this.mentiondownButtonImage, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_goDownButtonIcon);
        themeDescriptionArr[372] = new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[0]}, null, Theme.key_chat_attachGalleryBackground);
        themeDescriptionArr[373] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[0]}, null, Theme.key_chat_attachGalleryIcon);
        themeDescriptionArr[374] = new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[1]}, null, Theme.key_chat_attachAudioBackground);
        themeDescriptionArr[375] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[1]}, null, Theme.key_chat_attachAudioIcon);
        themeDescriptionArr[376] = new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[2]}, null, Theme.key_chat_attachFileBackground);
        themeDescriptionArr[377] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[2]}, null, Theme.key_chat_attachFileIcon);
        themeDescriptionArr[378] = new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[3]}, null, Theme.key_chat_attachContactBackground);
        themeDescriptionArr[379] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[3]}, null, Theme.key_chat_attachContactIcon);
        themeDescriptionArr[380] = new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[4]}, null, Theme.key_chat_attachLocationBackground);
        themeDescriptionArr[381] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[4]}, null, Theme.key_chat_attachLocationIcon);
        themeDescriptionArr[382] = new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[5]}, null, Theme.key_chat_attachPollBackground);
        themeDescriptionArr[383] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachButtonDrawables[5]}, null, Theme.key_chat_attachPollIcon);
        themeDescriptionArr[384] = new ThemeDescription(null, 0, null, null, new Drawable[]{Theme.chat_attachEmptyDrawable}, null, Theme.key_chat_attachEmptyImage);
        themeDescriptionArr[385] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_chat_attachPhotoBackground);
        themeDescriptionArr[386] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_dialogBackground);
        themeDescriptionArr[387] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_dialogBackgroundGray);
        themeDescriptionArr[388] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_dialogTextGray2);
        themeDescriptionArr[389] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_dialogScrollGlow);
        themeDescriptionArr[390] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_dialogGrayLine);
        themeDescriptionArr[391] = new ThemeDescription(null, 0, null, null, null, themeDescriptionDelegate, Theme.key_dialogCameraIcon);
        return themeDescriptionArr;
    }

    public /* synthetic */ void lambda$getThemeDescriptions$161$ChatActivity() {
        updateVisibleRows();
        ChatActivityEnterView chatActivityEnterView = this.chatActivityEnterView;
        if (chatActivityEnterView != null && chatActivityEnterView.getEmojiView() != null) {
            this.chatActivityEnterView.getEmojiView().updateColors();
        }
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            chatAttachAlert.checkColors();
        }
    }
}
