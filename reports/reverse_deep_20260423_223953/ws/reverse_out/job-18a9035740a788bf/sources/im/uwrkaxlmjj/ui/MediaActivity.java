package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Property;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.net.MailTo;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.cells.SharedAudioCell;
import im.uwrkaxlmjj.ui.cells.SharedDocumentCell;
import im.uwrkaxlmjj.ui.cells.SharedLinkCell;
import im.uwrkaxlmjj.ui.cells.SharedMediaSectionCell;
import im.uwrkaxlmjj.ui.cells.SharedPhotoVideoCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AnimationProperties;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.EmbedBottomSheet;
import im.uwrkaxlmjj.ui.components.FragmentContextView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.NumberTextView;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.ScrollSlidingTextTabStrip;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MediaActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int delete = 4;
    private static final int forward = 3;
    private static final int gotochat = 7;
    private static final Interpolator interpolator = new Interpolator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$QdXx6TKHCajjFBwCYsteD0F8c7k
        @Override // android.animation.TimeInterpolator
        public final float getInterpolation(float f) {
            return MediaActivity.lambda$static$0(f);
        }
    };
    public final Property<MediaActivity, Float> SCROLL_Y;
    private View actionModeBackground;
    private ArrayList<View> actionModeViews;
    private int additionalPadding;
    private boolean animatingForward;
    private SharedDocumentsAdapter audioAdapter;
    private ArrayList<SharedAudioCell> audioCache;
    private ArrayList<SharedAudioCell> audioCellCache;
    private MediaSearchAdapter audioSearchAdapter;
    private boolean backAnimation;
    private Paint backgroundPaint;
    private ArrayList<SharedPhotoVideoCell> cache;
    private int cantDeleteMessagesCount;
    private ArrayList<SharedPhotoVideoCell> cellCache;
    private int columnsCount;
    private long dialog_id;
    private SharedDocumentsAdapter documentsAdapter;
    private MediaSearchAdapter documentsSearchAdapter;
    private FragmentContextView fragmentContextView;
    private ActionBarMenuItem gotoItem;
    private int[] hasMedia;
    private boolean ignoreSearchCollapse;
    protected TLRPC.ChatFull info;
    private int initialTab;
    private SharedLinksAdapter linksAdapter;
    private MediaSearchAdapter linksSearchAdapter;
    private int maximumVelocity;
    private MediaPage[] mediaPages;
    private long mergeDialogId;
    private MrySearchView mrySearchView;
    private SharedPhotoVideoAdapter photoVideoAdapter;
    private Drawable pinnedHeaderShadowDrawable;
    private PhotoViewer.PhotoViewerProvider provider;
    private ScrollSlidingTextTabStrip scrollSlidingTextTabStrip;
    private boolean scrolling;
    private int searchItemState;
    private boolean searchWas;
    private boolean searching;
    private SparseArray<MessageObject>[] selectedFiles;
    private NumberTextView selectedMessagesCountTextView;
    SharedLinkCell.SharedLinkCellDelegate sharedLinkCellDelegate;
    private SharedMediaData[] sharedMediaData;
    private AnimatorSet tabsAnimation;
    private boolean tabsAnimationInProgress;
    private SharedDocumentsAdapter voiceAdapter;

    /* JADX INFO: Access modifiers changed from: private */
    class MediaPage extends FrameLayout {
        private ImageView emptyImageView;
        private TextView emptyTextView;
        private LinearLayout emptyView;
        private LinearLayoutManager layoutManager;
        private RecyclerListView listView;
        private RadialProgressView progressBar;
        private LinearLayout progressView;
        private int selectedType;

        public MediaPage(Context context) {
            super(context);
        }
    }

    static /* synthetic */ float lambda$static$0(float t) {
        float t2 = t - 1.0f;
        return (t2 * t2 * t2 * t2 * t2) + 1.0f;
    }

    public static class SharedMediaData {
        private boolean loading;
        private int totalCount;
        private ArrayList<MessageObject> messages = new ArrayList<>();
        private SparseArray<MessageObject>[] messagesDict = {new SparseArray<>(), new SparseArray<>()};
        private ArrayList<String> sections = new ArrayList<>();
        private HashMap<String, ArrayList<MessageObject>> sectionArrays = new HashMap<>();
        private boolean[] endReached = {false, true};
        private int[] max_id = {0, 0};

        public void setTotalCount(int count) {
            this.totalCount = count;
        }

        public void setMaxId(int num, int value) {
            this.max_id[num] = value;
        }

        public void setEndReached(int num, boolean value) {
            this.endReached[num] = value;
        }

        public boolean addMessage(MessageObject messageObject, int loadIndex, boolean isNew, boolean enc) {
            if (this.messagesDict[loadIndex].indexOfKey(messageObject.getId()) >= 0) {
                return false;
            }
            ArrayList<MessageObject> messageObjects = this.sectionArrays.get(messageObject.monthKey);
            if (messageObjects == null) {
                messageObjects = new ArrayList<>();
                this.sectionArrays.put(messageObject.monthKey, messageObjects);
                if (isNew) {
                    this.sections.add(0, messageObject.monthKey);
                } else {
                    this.sections.add(messageObject.monthKey);
                }
            }
            if (isNew) {
                messageObjects.add(0, messageObject);
                this.messages.add(0, messageObject);
            } else {
                messageObjects.add(messageObject);
                this.messages.add(messageObject);
            }
            this.messagesDict[loadIndex].put(messageObject.getId(), messageObject);
            if (!enc) {
                if (messageObject.getId() > 0) {
                    this.max_id[loadIndex] = Math.min(messageObject.getId(), this.max_id[loadIndex]);
                    return true;
                }
                return true;
            }
            this.max_id[loadIndex] = Math.max(messageObject.getId(), this.max_id[loadIndex]);
            return true;
        }

        public boolean deleteMessage(int mid, int loadIndex) {
            ArrayList<MessageObject> messageObjects;
            MessageObject messageObject = this.messagesDict[loadIndex].get(mid);
            if (messageObject == null || (messageObjects = this.sectionArrays.get(messageObject.monthKey)) == null) {
                return false;
            }
            messageObjects.remove(messageObject);
            this.messages.remove(messageObject);
            this.messagesDict[loadIndex].remove(messageObject.getId());
            if (messageObjects.isEmpty()) {
                this.sectionArrays.remove(messageObject.monthKey);
                this.sections.remove(messageObject.monthKey);
            }
            this.totalCount--;
            return true;
        }

        public void replaceMid(int oldMid, int newMid) {
            MessageObject obj = this.messagesDict[0].get(oldMid);
            if (obj != null) {
                this.messagesDict[0].remove(oldMid);
                this.messagesDict[0].put(newMid, obj);
                obj.messageOwner.id = newMid;
            }
        }
    }

    public MediaActivity(Bundle args, int[] media) {
        this(args, media, null, 0);
    }

    public MediaActivity(Bundle args, int[] media, SharedMediaData[] mediaData, int initTab) {
        super(args);
        this.mediaPages = new MediaPage[2];
        this.cellCache = new ArrayList<>(10);
        this.cache = new ArrayList<>(10);
        this.audioCellCache = new ArrayList<>(10);
        this.audioCache = new ArrayList<>(10);
        this.backgroundPaint = new Paint();
        this.selectedFiles = new SparseArray[]{new SparseArray<>(), new SparseArray<>()};
        this.actionModeViews = new ArrayList<>();
        this.info = null;
        this.columnsCount = 4;
        this.SCROLL_Y = new AnimationProperties.FloatProperty<MediaActivity>("animationValue") { // from class: im.uwrkaxlmjj.ui.MediaActivity.1
            @Override // im.uwrkaxlmjj.ui.components.AnimationProperties.FloatProperty
            public void setValue(MediaActivity object, float value) {
                object.setScrollY(value);
                for (int a = 0; a < MediaActivity.this.mediaPages.length; a++) {
                    MediaActivity.this.mediaPages[a].listView.checkSection();
                }
            }

            @Override // android.util.Property
            public Float get(MediaActivity object) {
                return Float.valueOf(MediaActivity.this.actionBar.getTranslationY());
            }
        };
        this.provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.MediaActivity.2
            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                MessageObject message;
                if (messageObject == null || !(MediaActivity.this.mediaPages[0].selectedType == 0 || MediaActivity.this.mediaPages[0].selectedType == 1)) {
                    return null;
                }
                int count = MediaActivity.this.mediaPages[0].listView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View view = MediaActivity.this.mediaPages[0].listView.getChildAt(a);
                    BackupImageView imageView = null;
                    if (view instanceof SharedPhotoVideoCell) {
                        SharedPhotoVideoCell cell = (SharedPhotoVideoCell) view;
                        for (int i = 0; i < 6 && (message = cell.getMessageObject(i)) != null; i++) {
                            if (message.getId() == messageObject.getId()) {
                                imageView = cell.getImageView(i);
                            }
                        }
                    } else if (view instanceof SharedDocumentCell) {
                        SharedDocumentCell cell2 = (SharedDocumentCell) view;
                        if (cell2.getMessage().getId() == messageObject.getId()) {
                            imageView = cell2.getImageView();
                        }
                    }
                    if (imageView != null) {
                        int[] coords = new int[2];
                        imageView.getLocationInWindow(coords);
                        PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                        object.viewX = coords[0];
                        object.viewY = coords[1] - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight);
                        object.parentView = MediaActivity.this.mediaPages[0].listView;
                        object.imageReceiver = imageView.getImageReceiver();
                        object.thumb = object.imageReceiver.getBitmapSafe();
                        object.parentView.getLocationInWindow(coords);
                        object.clipTopAddition = (int) (MediaActivity.this.actionBar.getHeight() + MediaActivity.this.actionBar.getTranslationY());
                        if (MediaActivity.this.fragmentContextView != null && MediaActivity.this.fragmentContextView.getVisibility() == 0) {
                            object.clipTopAddition += AndroidUtilities.dp(36.0f);
                        }
                        return object;
                    }
                }
                return null;
            }
        };
        this.sharedMediaData = new SharedMediaData[5];
        this.sharedLinkCellDelegate = new AnonymousClass16();
        this.hasMedia = media;
        this.initialTab = initTab;
        this.dialog_id = args.getLong("dialog_id", 0L);
        int a = 0;
        while (true) {
            SharedMediaData[] sharedMediaDataArr = this.sharedMediaData;
            if (a < sharedMediaDataArr.length) {
                sharedMediaDataArr[a] = new SharedMediaData();
                this.sharedMediaData[a].max_id[0] = ((int) this.dialog_id) == 0 ? Integer.MIN_VALUE : Integer.MAX_VALUE;
                if (this.mergeDialogId != 0 && this.info != null) {
                    this.sharedMediaData[a].max_id[1] = this.info.migrated_from_max_id;
                    this.sharedMediaData[a].endReached[1] = false;
                }
                if (mediaData != null) {
                    this.sharedMediaData[a].totalCount = mediaData[a].totalCount;
                    this.sharedMediaData[a].messages.addAll(mediaData[a].messages);
                    this.sharedMediaData[a].sections.addAll(mediaData[a].sections);
                    for (Map.Entry<String, ArrayList<MessageObject>> entry : mediaData[a].sectionArrays.entrySet()) {
                        this.sharedMediaData[a].sectionArrays.put(entry.getKey(), new ArrayList(entry.getValue()));
                    }
                    for (int i = 0; i < 2; i++) {
                        this.sharedMediaData[a].messagesDict[i] = mediaData[a].messagesDict[i].clone();
                        this.sharedMediaData[a].max_id[i] = mediaData[a].max_id[i];
                    }
                }
                a++;
            } else {
                return;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.mediaDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagesDeleted);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messageReceivedByServer);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidStart);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.mediaDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagesDeleted);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messageReceivedByServer);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidStart);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        TLRPC.User user;
        RecyclerListView.Holder holder;
        for (int a = 0; a < 10; a++) {
            this.cellCache.add(new SharedPhotoVideoCell(context));
            if (this.initialTab == 4) {
                SharedAudioCell cell = new SharedAudioCell(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.3
                    @Override // im.uwrkaxlmjj.ui.cells.SharedAudioCell
                    public boolean needPlayMessage(MessageObject messageObject) {
                        if (messageObject.isVoice() || messageObject.isRoundVideo()) {
                            boolean result = MediaController.getInstance().playMessage(messageObject);
                            MediaController.getInstance().setVoiceMessagesPlaylist(result ? MediaActivity.this.sharedMediaData[4].messages : null, false);
                            return result;
                        }
                        if (messageObject.isMusic()) {
                            return MediaController.getInstance().setPlaylist(MediaActivity.this.sharedMediaData[4].messages, messageObject);
                        }
                        return false;
                    }
                };
                cell.initStreamingIcons();
                this.audioCellCache.add(cell);
            }
        }
        ViewConfiguration configuration = ViewConfiguration.get(context);
        this.maximumVelocity = configuration.getScaledMaximumFlingVelocity();
        this.searching = false;
        this.searchWas = false;
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAddToContainer(false);
        int i = 1;
        this.actionBar.setClipContent(true);
        int lower_id = (int) this.dialog_id;
        if (lower_id == 0) {
            TLRPC.EncryptedChat encryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf((int) (this.dialog_id >> 32)));
            if (encryptedChat != null && (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(encryptedChat.user_id))) != null) {
                this.actionBar.setTitle(ContactsController.formatName(user.first_name, user.last_name));
            }
        } else if (lower_id > 0) {
            TLRPC.User user2 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(lower_id));
            if (user2 != null) {
                if (user2.self) {
                    this.actionBar.setTitle(LocaleController.getString("SavedMessages", R.string.SavedMessages));
                } else {
                    this.actionBar.setTitle(ContactsController.formatName(user2.first_name, user2.last_name));
                }
            }
        } else {
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-lower_id));
            if (chat != null) {
                this.actionBar.setTitle(chat.title);
            }
        }
        if (TextUtils.isEmpty(this.actionBar.getTitle())) {
            this.actionBar.setTitle(LocaleController.getString("SharedContentTitle", R.string.SharedContentTitle));
        }
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass4());
        Drawable drawable = context.getResources().getDrawable(R.drawable.photos_header_shadow);
        this.pinnedHeaderShadowDrawable = drawable;
        drawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundGrayShadow), PorterDuff.Mode.MULTIPLY));
        ScrollSlidingTextTabStrip scrollSlidingTextTabStrip = this.scrollSlidingTextTabStrip;
        if (scrollSlidingTextTabStrip != null) {
            this.initialTab = scrollSlidingTextTabStrip.getCurrentTabId();
        }
        ScrollSlidingTextTabStrip scrollSlidingTextTabStrip2 = new ScrollSlidingTextTabStrip(context, 2);
        this.scrollSlidingTextTabStrip = scrollSlidingTextTabStrip2;
        scrollSlidingTextTabStrip2.setColors(Theme.key_chats_pinnedIcon, Theme.key_chat_inLoader, Theme.key_windowBackgroundWhiteGrayText3, null);
        this.scrollSlidingTextTabStrip.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        int i2 = this.initialTab;
        if (i2 != -1) {
            this.scrollSlidingTextTabStrip.setInitialTabId(i2);
            this.initialTab = -1;
        }
        this.scrollSlidingTextTabStrip.setDelegate(new ScrollSlidingTextTabStrip.ScrollSlidingTabStripDelegate() { // from class: im.uwrkaxlmjj.ui.MediaActivity.5
            @Override // im.uwrkaxlmjj.ui.components.ScrollSlidingTextTabStrip.ScrollSlidingTabStripDelegate
            public void onPageSelected(int id, boolean forward2) {
                if (MediaActivity.this.mediaPages[0].selectedType == id) {
                    return;
                }
                MediaActivity mediaActivity = MediaActivity.this;
                mediaActivity.swipeBackEnabled = id == mediaActivity.scrollSlidingTextTabStrip.getFirstTabId();
                MediaActivity.this.mediaPages[1].selectedType = id;
                MediaActivity.this.mediaPages[1].setVisibility(0);
                MediaActivity.this.switchToCurrentSelectedMode(true);
                MediaActivity.this.animatingForward = forward2;
            }

            @Override // im.uwrkaxlmjj.ui.components.ScrollSlidingTextTabStrip.ScrollSlidingTabStripDelegate
            public void onPageScrolled(float progress) {
                if (progress != 1.0f || MediaActivity.this.mediaPages[1].getVisibility() == 0) {
                    if (MediaActivity.this.animatingForward) {
                        MediaActivity.this.mediaPages[0].setTranslationX((-progress) * MediaActivity.this.mediaPages[0].getMeasuredWidth());
                        MediaActivity.this.mediaPages[1].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth() - (MediaActivity.this.mediaPages[0].getMeasuredWidth() * progress));
                    } else {
                        MediaActivity.this.mediaPages[0].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth() * progress);
                        MediaActivity.this.mediaPages[1].setTranslationX((MediaActivity.this.mediaPages[0].getMeasuredWidth() * progress) - MediaActivity.this.mediaPages[0].getMeasuredWidth());
                    }
                    if (MediaActivity.this.searchItemState == 1) {
                        MediaActivity.this.mrySearchView.setAlpha(progress);
                    } else if (MediaActivity.this.searchItemState == 2) {
                        MediaActivity.this.mrySearchView.setAlpha(1.0f - progress);
                    }
                    if (progress == 1.0f) {
                        MediaPage tempPage = MediaActivity.this.mediaPages[0];
                        MediaActivity.this.mediaPages[0] = MediaActivity.this.mediaPages[1];
                        MediaActivity.this.mediaPages[1] = tempPage;
                        MediaActivity.this.mediaPages[1].setVisibility(8);
                        if (MediaActivity.this.searchItemState == 2) {
                            MediaActivity.this.mrySearchView.setVisibility(8);
                        }
                        MediaActivity.this.searchItemState = 0;
                    }
                }
            }
        });
        for (int a2 = 1; a2 >= 0; a2--) {
            this.selectedFiles[a2].clear();
        }
        this.cantDeleteMessagesCount = 0;
        this.actionModeViews.clear();
        this.searchItemState = 0;
        this.hasOwnBackground = true;
        ActionBarMenu actionMode = this.actionBar.createActionMode(false);
        actionMode.setBackgroundDrawable(null);
        this.actionBar.setItemsColor(Theme.getColor(Theme.key_actionBarDefaultIcon), true);
        this.actionBar.setItemsBackgroundColor(Theme.getColor(Theme.key_actionBarDefaultSelector), true);
        View view = new View(context);
        this.actionModeBackground = view;
        view.setBackgroundColor(Theme.getColor(Theme.key_sharedMedia_actionMode));
        this.actionModeBackground.setAlpha(0.0f);
        this.actionBar.addView(this.actionModeBackground, this.actionBar.indexOfChild(actionMode));
        NumberTextView numberTextView = new NumberTextView(actionMode.getContext());
        this.selectedMessagesCountTextView = numberTextView;
        numberTextView.setTextSize(18);
        this.selectedMessagesCountTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.selectedMessagesCountTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultIcon));
        this.selectedMessagesCountTextView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$vjaktRgITo9u1YAP9UVsjA683A0
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                return MediaActivity.lambda$createView$1(view2, motionEvent);
            }
        });
        actionMode.addView(this.selectedMessagesCountTextView, LayoutHelper.createLinear(0, -1, 1.0f, 72, 0, 0, 0));
        if (((int) this.dialog_id) != 0) {
            ArrayList<View> arrayList = this.actionModeViews;
            ActionBarMenuItem actionBarMenuItemAddItemWithWidth = actionMode.addItemWithWidth(7, R.drawable.msg_message, AndroidUtilities.dp(54.0f), LocaleController.getString("AccDescrGoToMessage", R.string.AccDescrGoToMessage));
            this.gotoItem = actionBarMenuItemAddItemWithWidth;
            arrayList.add(actionBarMenuItemAddItemWithWidth);
            this.actionModeViews.add(actionMode.addItemWithWidth(3, R.drawable.msg_forward, AndroidUtilities.dp(54.0f), LocaleController.getString("Forward", R.string.Forward)));
        }
        this.actionModeViews.add(actionMode.addItemWithWidth(4, R.drawable.msg_delete, AndroidUtilities.dp(54.0f), LocaleController.getString("Delete", R.string.Delete)));
        this.photoVideoAdapter = new SharedPhotoVideoAdapter(context);
        this.documentsAdapter = new SharedDocumentsAdapter(context, 1);
        this.voiceAdapter = new SharedDocumentsAdapter(context, 2);
        this.audioAdapter = new SharedDocumentsAdapter(context, 4);
        this.documentsSearchAdapter = new MediaSearchAdapter(context, 1);
        this.audioSearchAdapter = new MediaSearchAdapter(context, 4);
        this.linksSearchAdapter = new MediaSearchAdapter(context, 3);
        this.linksAdapter = new SharedLinksAdapter(context);
        LinearLayout linearLayout = new LinearLayout(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.6
            private boolean globalIgnoreLayout;
            private boolean maybeStartTracking;
            private boolean startedTracking;
            private int startedTrackingPointerId;
            private int startedTrackingX;
            private int startedTrackingY;
            private VelocityTracker velocityTracker;

            private boolean prepareForMoving(MotionEvent ev, boolean forward2) {
                int id = MediaActivity.this.scrollSlidingTextTabStrip.getNextPageId(forward2);
                if (id >= 0) {
                    if (MediaActivity.this.searchItemState != 0) {
                        if (MediaActivity.this.searchItemState == 2) {
                            MediaActivity.this.mrySearchView.setAlpha(1.0f);
                        } else if (MediaActivity.this.searchItemState == 1) {
                            MediaActivity.this.mrySearchView.setAlpha(0.0f);
                            MediaActivity.this.mrySearchView.setVisibility(8);
                        }
                        MediaActivity.this.searchItemState = 0;
                    }
                    getParent().requestDisallowInterceptTouchEvent(true);
                    this.maybeStartTracking = false;
                    this.startedTracking = true;
                    this.startedTrackingX = (int) ev.getX();
                    MediaActivity.this.actionBar.setEnabled(false);
                    MediaActivity.this.scrollSlidingTextTabStrip.setEnabled(false);
                    MediaActivity.this.mediaPages[1].selectedType = id;
                    MediaActivity.this.mediaPages[1].setVisibility(0);
                    MediaActivity.this.animatingForward = forward2;
                    MediaActivity.this.switchToCurrentSelectedMode(true);
                    if (forward2) {
                        MediaActivity.this.mediaPages[1].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth());
                    } else {
                        MediaActivity.this.mediaPages[1].setTranslationX(-MediaActivity.this.mediaPages[0].getMeasuredWidth());
                    }
                    return true;
                }
                return false;
            }

            @Override // android.view.View
            public void forceHasOverlappingRendering(boolean hasOverlappingRendering) {
                super.forceHasOverlappingRendering(hasOverlappingRendering);
            }

            @Override // android.widget.LinearLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            }

            @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
            }

            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
            }

            @Override // android.view.ViewGroup, android.view.View
            protected void dispatchDraw(Canvas canvas) {
                super.dispatchDraw(canvas);
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.globalIgnoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            public boolean checkTabsAnimationInProgress() {
                if (!MediaActivity.this.tabsAnimationInProgress) {
                    return false;
                }
                boolean cancel = false;
                if (MediaActivity.this.backAnimation) {
                    if (Math.abs(MediaActivity.this.mediaPages[0].getTranslationX()) < 1.0f) {
                        MediaActivity.this.mediaPages[0].setTranslationX(0.0f);
                        MediaActivity.this.mediaPages[1].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth() * (MediaActivity.this.animatingForward ? 1 : -1));
                        cancel = true;
                    }
                } else if (Math.abs(MediaActivity.this.mediaPages[1].getTranslationX()) < 1.0f) {
                    MediaActivity.this.mediaPages[0].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth() * (MediaActivity.this.animatingForward ? -1 : 1));
                    MediaActivity.this.mediaPages[1].setTranslationX(0.0f);
                    cancel = true;
                }
                if (cancel) {
                    if (MediaActivity.this.tabsAnimation != null) {
                        MediaActivity.this.tabsAnimation.cancel();
                        MediaActivity.this.tabsAnimation = null;
                    }
                    MediaActivity.this.tabsAnimationInProgress = false;
                }
                return MediaActivity.this.tabsAnimationInProgress;
            }

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                return checkTabsAnimationInProgress() || MediaActivity.this.scrollSlidingTextTabStrip.isAnimatingIndicator() || onTouchEvent(ev);
            }

            @Override // android.widget.LinearLayout, android.view.View
            protected void onDraw(Canvas canvas) {
                MediaActivity.this.backgroundPaint.setColor(Theme.getColor(Theme.key_windowBackgroundGray));
                canvas.drawRect(0.0f, MediaActivity.this.actionBar.getMeasuredHeight() + MediaActivity.this.actionBar.getTranslationY(), getMeasuredWidth(), getMeasuredHeight(), MediaActivity.this.backgroundPaint);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent ev) {
                float dx;
                int duration;
                if (MediaActivity.this.parentLayout.checkTransitionAnimation() || checkTabsAnimationInProgress()) {
                    return false;
                }
                if (ev != null && ev.getAction() == 0 && !this.startedTracking && !this.maybeStartTracking) {
                    this.startedTrackingPointerId = ev.getPointerId(0);
                    this.maybeStartTracking = true;
                    this.startedTrackingX = (int) ev.getX();
                    this.startedTrackingY = (int) ev.getY();
                    VelocityTracker velocityTracker = this.velocityTracker;
                    if (velocityTracker != null) {
                        velocityTracker.clear();
                    }
                } else if (ev != null && ev.getAction() == 2 && ev.getPointerId(0) == this.startedTrackingPointerId) {
                    if (this.velocityTracker == null) {
                        this.velocityTracker = VelocityTracker.obtain();
                    }
                    int dx2 = (int) (ev.getX() - this.startedTrackingX);
                    int dy = Math.abs(((int) ev.getY()) - this.startedTrackingY);
                    this.velocityTracker.addMovement(ev);
                    if (this.startedTracking && ((MediaActivity.this.animatingForward && dx2 > 0) || (!MediaActivity.this.animatingForward && dx2 < 0))) {
                        if (!prepareForMoving(ev, dx2 < 0)) {
                            this.maybeStartTracking = true;
                            this.startedTracking = false;
                            MediaActivity.this.mediaPages[0].setTranslationX(0.0f);
                            if (MediaActivity.this.animatingForward) {
                                MediaActivity.this.mediaPages[1].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth());
                            } else {
                                MediaActivity.this.mediaPages[1].setTranslationX(-MediaActivity.this.mediaPages[0].getMeasuredWidth());
                            }
                        }
                    }
                    if (this.maybeStartTracking && !this.startedTracking) {
                        float touchSlop = AndroidUtilities.getPixelsInCM(0.3f, true);
                        if (Math.abs(dx2) >= touchSlop && Math.abs(dx2) / 3 > dy) {
                            prepareForMoving(ev, dx2 < 0);
                        }
                    } else if (this.startedTracking) {
                        MediaActivity.this.mediaPages[0].setTranslationX(dx2);
                        if (MediaActivity.this.animatingForward) {
                            MediaActivity.this.mediaPages[1].setTranslationX(MediaActivity.this.mediaPages[0].getMeasuredWidth() + dx2);
                        } else {
                            MediaActivity.this.mediaPages[1].setTranslationX(dx2 - MediaActivity.this.mediaPages[0].getMeasuredWidth());
                        }
                        float scrollProgress = Math.abs(dx2) / MediaActivity.this.mediaPages[0].getMeasuredWidth();
                        if (MediaActivity.this.searchItemState == 2) {
                            MediaActivity.this.mrySearchView.setAlpha(1.0f - scrollProgress);
                        } else if (MediaActivity.this.searchItemState == 1) {
                            MediaActivity.this.mrySearchView.setAlpha(scrollProgress);
                        }
                        MediaActivity.this.scrollSlidingTextTabStrip.selectTabWithId(MediaActivity.this.mediaPages[1].selectedType, scrollProgress);
                    }
                } else if (ev != null && ev.getPointerId(0) == this.startedTrackingPointerId && (ev.getAction() == 3 || ev.getAction() == 1 || ev.getAction() == 6)) {
                    if (this.velocityTracker == null) {
                        this.velocityTracker = VelocityTracker.obtain();
                    }
                    this.velocityTracker.computeCurrentVelocity(1000, MediaActivity.this.maximumVelocity);
                    if (!this.startedTracking) {
                        float velX = this.velocityTracker.getXVelocity();
                        float velY = this.velocityTracker.getYVelocity();
                        if (Math.abs(velX) >= 3000.0f && Math.abs(velX) > Math.abs(velY)) {
                            prepareForMoving(ev, velX < 0.0f);
                        }
                    }
                    if (this.startedTracking) {
                        float x = MediaActivity.this.mediaPages[0].getX();
                        MediaActivity.this.tabsAnimation = new AnimatorSet();
                        float velX2 = this.velocityTracker.getXVelocity();
                        float velY2 = this.velocityTracker.getYVelocity();
                        MediaActivity.this.backAnimation = Math.abs(x) < ((float) MediaActivity.this.mediaPages[0].getMeasuredWidth()) / 3.0f && (Math.abs(velX2) < 3500.0f || Math.abs(velX2) < Math.abs(velY2));
                        if (!MediaActivity.this.backAnimation) {
                            dx = MediaActivity.this.mediaPages[0].getMeasuredWidth() - Math.abs(x);
                            if (MediaActivity.this.animatingForward) {
                                MediaActivity.this.tabsAnimation.playTogether(ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[0], (Property<MediaPage, Float>) View.TRANSLATION_X, -MediaActivity.this.mediaPages[0].getMeasuredWidth()), ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[1], (Property<MediaPage, Float>) View.TRANSLATION_X, 0.0f));
                            } else {
                                MediaActivity.this.tabsAnimation.playTogether(ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[0], (Property<MediaPage, Float>) View.TRANSLATION_X, MediaActivity.this.mediaPages[0].getMeasuredWidth()), ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[1], (Property<MediaPage, Float>) View.TRANSLATION_X, 0.0f));
                            }
                        } else {
                            dx = Math.abs(x);
                            if (MediaActivity.this.animatingForward) {
                                MediaActivity.this.tabsAnimation.playTogether(ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[0], (Property<MediaPage, Float>) View.TRANSLATION_X, 0.0f), ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[1], (Property<MediaPage, Float>) View.TRANSLATION_X, MediaActivity.this.mediaPages[1].getMeasuredWidth()));
                            } else {
                                MediaActivity.this.tabsAnimation.playTogether(ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[0], (Property<MediaPage, Float>) View.TRANSLATION_X, 0.0f), ObjectAnimator.ofFloat(MediaActivity.this.mediaPages[1], (Property<MediaPage, Float>) View.TRANSLATION_X, -MediaActivity.this.mediaPages[1].getMeasuredWidth()));
                            }
                        }
                        MediaActivity.this.tabsAnimation.setInterpolator(MediaActivity.interpolator);
                        int width = getMeasuredWidth();
                        int halfWidth = width / 2;
                        float distanceRatio = Math.min(1.0f, (dx * 1.0f) / width);
                        float distance = halfWidth + (halfWidth * AndroidUtilities.distanceInfluenceForSnapDuration(distanceRatio));
                        float velX3 = Math.abs(velX2);
                        if (velX3 > 0.0f) {
                            duration = Math.round(Math.abs(distance / velX3) * 1000.0f) * 4;
                        } else {
                            float pageDelta = dx / getMeasuredWidth();
                            duration = (int) ((1.0f + pageDelta) * 100.0f);
                        }
                        MediaActivity.this.tabsAnimation.setDuration(Math.max(150, Math.min(duration, 600)));
                        MediaActivity.this.tabsAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.MediaActivity.6.1
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animator) {
                                MediaActivity.this.tabsAnimation = null;
                                if (MediaActivity.this.backAnimation) {
                                    MediaActivity.this.mediaPages[1].setVisibility(8);
                                    if (MediaActivity.this.searchItemState == 2) {
                                        MediaActivity.this.mrySearchView.setAlpha(1.0f);
                                    } else if (MediaActivity.this.searchItemState == 1) {
                                        MediaActivity.this.mrySearchView.setAlpha(0.0f);
                                        MediaActivity.this.mrySearchView.setVisibility(8);
                                    }
                                    MediaActivity.this.searchItemState = 0;
                                } else {
                                    MediaPage tempPage = MediaActivity.this.mediaPages[0];
                                    MediaActivity.this.mediaPages[0] = MediaActivity.this.mediaPages[1];
                                    MediaActivity.this.mediaPages[1] = tempPage;
                                    MediaActivity.this.mediaPages[1].setVisibility(8);
                                    if (MediaActivity.this.searchItemState == 2) {
                                        MediaActivity.this.mrySearchView.setVisibility(8);
                                    }
                                    MediaActivity.this.searchItemState = 0;
                                    MediaActivity.this.swipeBackEnabled = MediaActivity.this.mediaPages[0].selectedType == MediaActivity.this.scrollSlidingTextTabStrip.getFirstTabId();
                                    MediaActivity.this.scrollSlidingTextTabStrip.selectTabWithId(MediaActivity.this.mediaPages[0].selectedType, 1.0f);
                                }
                                MediaActivity.this.tabsAnimationInProgress = false;
                                AnonymousClass6.this.maybeStartTracking = false;
                                AnonymousClass6.this.startedTracking = false;
                                MediaActivity.this.actionBar.setEnabled(true);
                                MediaActivity.this.scrollSlidingTextTabStrip.setEnabled(true);
                            }
                        });
                        MediaActivity.this.tabsAnimation.start();
                        MediaActivity.this.tabsAnimationInProgress = true;
                    } else {
                        this.maybeStartTracking = false;
                        this.startedTracking = false;
                        MediaActivity.this.actionBar.setEnabled(true);
                        MediaActivity.this.scrollSlidingTextTabStrip.setEnabled(true);
                    }
                    VelocityTracker velocityTracker2 = this.velocityTracker;
                    if (velocityTracker2 != null) {
                        velocityTracker2.recycle();
                        this.velocityTracker = null;
                    }
                }
                return this.startedTracking;
            }
        };
        LinearLayout linearLayout2 = linearLayout;
        this.fragmentView = linearLayout;
        linearLayout2.setWillNotDraw(false);
        linearLayout2.setOrientation(1);
        linearLayout2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        linearLayout2.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        LinearLayout.LayoutParams searchlayoutParams = LayoutHelper.createLinear(-1, 35);
        searchlayoutParams.topMargin = AndroidUtilities.dp(10.0f);
        searchlayoutParams.leftMargin = AndroidUtilities.dp(10.0f);
        searchlayoutParams.rightMargin = AndroidUtilities.dp(10.0f);
        MrySearchView mrySearchView = new MrySearchView(context);
        this.mrySearchView = mrySearchView;
        mrySearchView.setiSearchViewDelegate(new MrySearchView.ISearchViewDelegate() { // from class: im.uwrkaxlmjj.ui.MediaActivity.7
            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onStart(boolean focus) {
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchExpand() {
                MediaActivity.this.searching = true;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public boolean canCollapseSearch() {
                return false;
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onSearchCollapse() {
                MediaActivity.this.searching = false;
                MediaActivity.this.searchWas = false;
                MediaActivity.this.documentsSearchAdapter.search(null);
                MediaActivity.this.linksSearchAdapter.search(null);
                MediaActivity.this.audioSearchAdapter.search(null);
                if (MediaActivity.this.ignoreSearchCollapse) {
                    MediaActivity.this.ignoreSearchCollapse = false;
                } else {
                    MediaActivity.this.switchToCurrentSelectedMode(false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onTextChange(String text) {
                if (text.length() != 0) {
                    MediaActivity.this.searchWas = true;
                    MediaActivity.this.switchToCurrentSelectedMode(false);
                } else {
                    MediaActivity.this.searchWas = false;
                    MediaActivity.this.switchToCurrentSelectedMode(false);
                }
                if (MediaActivity.this.mediaPages[0].selectedType == 1) {
                    if (MediaActivity.this.documentsSearchAdapter != null) {
                        MediaActivity.this.documentsSearchAdapter.search(text);
                    }
                } else if (MediaActivity.this.mediaPages[0].selectedType == 3) {
                    if (MediaActivity.this.linksSearchAdapter != null) {
                        MediaActivity.this.linksSearchAdapter.search(text);
                    }
                } else if (MediaActivity.this.mediaPages[0].selectedType == 4 && MediaActivity.this.audioSearchAdapter != null) {
                    MediaActivity.this.audioSearchAdapter.search(text);
                }
            }

            @Override // im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
            public void onActionSearch(String trim) {
            }
        });
        linearLayout2.addView(this.mrySearchView, searchlayoutParams);
        LinearLayout.LayoutParams layoutParams = LayoutHelper.createLinear(-1, 44);
        layoutParams.topMargin = AndroidUtilities.dp(10.0f);
        layoutParams.bottomMargin = AndroidUtilities.dp(10.0f);
        layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
        layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
        linearLayout2.addView(this.scrollSlidingTextTabStrip, layoutParams);
        FrameLayout contentcontainer = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.8
            private boolean globalIgnoreLayout;

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int fragmentContextViewheight;
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize);
                if (MediaActivity.this.fragmentContextView.getVisibility() == 0) {
                    fragmentContextViewheight = MediaActivity.this.fragmentContextView.getMeasuredHeight();
                } else {
                    fragmentContextViewheight = 0;
                }
                this.globalIgnoreLayout = true;
                for (int a3 = 0; a3 < MediaActivity.this.mediaPages.length; a3++) {
                    if (MediaActivity.this.mediaPages[a3] != null) {
                        if (MediaActivity.this.mediaPages[a3].listView != null) {
                            MediaActivity.this.mediaPages[a3].listView.setPadding(0, MediaActivity.this.additionalPadding + fragmentContextViewheight, 0, AndroidUtilities.dp(4.0f));
                        }
                        if (MediaActivity.this.mediaPages[a3].emptyView != null) {
                            MediaActivity.this.mediaPages[a3].emptyView.setPadding(0, MediaActivity.this.additionalPadding + fragmentContextViewheight, 0, 0);
                        }
                        if (MediaActivity.this.mediaPages[a3].progressView != null) {
                            MediaActivity.this.mediaPages[a3].progressView.setPadding(0, MediaActivity.this.additionalPadding + fragmentContextViewheight, 0, 0);
                        }
                    }
                }
                this.globalIgnoreLayout = false;
                int childCount = getChildCount();
                for (int i3 = 0; i3 < childCount; i3++) {
                    View child = getChildAt(i3);
                    if (child != null && child.getVisibility() != 8 && child != MediaActivity.this.actionBar) {
                        measureChildWithMargins(child, widthMeasureSpec, 0, heightMeasureSpec, 0);
                    }
                }
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (MediaActivity.this.fragmentContextView != null) {
                    int y = MediaActivity.this.fragmentContextView.getMeasuredHeight();
                    MediaActivity.this.fragmentContextView.layout(MediaActivity.this.fragmentContextView.getLeft(), MediaActivity.this.fragmentContextView.getTop() + y, MediaActivity.this.fragmentContextView.getRight(), MediaActivity.this.fragmentContextView.getBottom() + y);
                }
            }

            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                MediaActivity.this.additionalPadding = top;
                int fragmentContextViewheight = MediaActivity.this.fragmentContextView.getMeasuredHeight();
                if (MediaActivity.this.fragmentContextView != null) {
                    MediaActivity.this.fragmentContextView.setTranslationY(MediaActivity.this.fragmentContextView.getMeasuredHeight() + top);
                }
                for (int a3 = 0; a3 < MediaActivity.this.mediaPages.length; a3++) {
                    if (MediaActivity.this.mediaPages[a3] != null) {
                        if (MediaActivity.this.mediaPages[a3].emptyView != null) {
                            MediaActivity.this.mediaPages[a3].emptyView.setPadding(0, MediaActivity.this.additionalPadding + fragmentContextViewheight, 0, 0);
                        }
                        if (MediaActivity.this.mediaPages[a3].progressView != null) {
                            MediaActivity.this.mediaPages[a3].progressView.setPadding(0, MediaActivity.this.additionalPadding + fragmentContextViewheight, 0, 0);
                        }
                        if (MediaActivity.this.mediaPages[a3].listView != null) {
                            MediaActivity.this.mediaPages[a3].listView.setPadding(0, MediaActivity.this.additionalPadding + fragmentContextViewheight, 0, AndroidUtilities.dp(4.0f));
                            MediaActivity.this.mediaPages[a3].listView.checkSection();
                        }
                    }
                }
            }

            @Override // android.view.ViewGroup, android.view.View
            protected void dispatchDraw(Canvas canvas) {
                super.dispatchDraw(canvas);
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.globalIgnoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        linearLayout2.addView(contentcontainer, LayoutHelper.createLinear(-1, -1));
        int scrollToPositionOnRecreate = -1;
        int scrollToOffsetOnRecreate = 0;
        int a3 = 0;
        while (true) {
            MediaPage[] mediaPageArr = this.mediaPages;
            if (a3 >= mediaPageArr.length) {
                break;
            }
            if (a3 == 0 && mediaPageArr[a3] != null && mediaPageArr[a3].layoutManager != null) {
                scrollToPositionOnRecreate = this.mediaPages[a3].layoutManager.findFirstVisibleItemPosition();
                if (scrollToPositionOnRecreate != this.mediaPages[a3].layoutManager.getItemCount() - i && (holder = (RecyclerListView.Holder) this.mediaPages[a3].listView.findViewHolderForAdapterPosition(scrollToPositionOnRecreate)) != null) {
                    scrollToOffsetOnRecreate = holder.itemView.getTop();
                } else {
                    scrollToPositionOnRecreate = -1;
                }
            }
            final MediaPage mediaPage = new MediaPage(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.9
                @Override // android.view.View
                public void setTranslationX(float translationX) {
                    super.setTranslationX(translationX);
                    if (MediaActivity.this.tabsAnimationInProgress && MediaActivity.this.mediaPages[0] == this) {
                        float scrollProgress = Math.abs(MediaActivity.this.mediaPages[0].getTranslationX()) / MediaActivity.this.mediaPages[0].getMeasuredWidth();
                        MediaActivity.this.scrollSlidingTextTabStrip.selectTabWithId(MediaActivity.this.mediaPages[1].selectedType, scrollProgress);
                        if (MediaActivity.this.searchItemState == 2) {
                            MediaActivity.this.mrySearchView.setAlpha(1.0f - scrollProgress);
                        } else if (MediaActivity.this.searchItemState == 1) {
                            MediaActivity.this.mrySearchView.setAlpha(scrollProgress);
                        }
                    }
                }
            };
            contentcontainer.addView(mediaPage, LayoutHelper.createFrame(-1, -1.0f));
            MediaPage[] mediaPageArr2 = this.mediaPages;
            mediaPageArr2[a3] = mediaPage;
            ViewConfiguration configuration2 = configuration;
            final LinearLayoutManager layoutManager = mediaPageArr2[a3].layoutManager = new LinearLayoutManager(context, 1, false) { // from class: im.uwrkaxlmjj.ui.MediaActivity.10
                @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
                public boolean supportsPredictiveItemAnimations() {
                    return false;
                }
            };
            this.mediaPages[a3].listView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.11
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
                protected void onLayout(boolean changed, int l, int t, int r, int b) {
                    super.onLayout(changed, l, t, r, b);
                    MediaActivity.this.updateSections(this, true);
                }
            };
            this.mediaPages[a3].listView.setItemAnimator(null);
            this.mediaPages[a3].listView.setClipToPadding(false);
            this.mediaPages[a3].listView.setSectionsType(2);
            this.mediaPages[a3].listView.setLayoutManager(layoutManager);
            MediaPage[] mediaPageArr3 = this.mediaPages;
            LinearLayout.LayoutParams searchlayoutParams2 = searchlayoutParams;
            LinearLayout linearLayout3 = linearLayout2;
            mediaPageArr3[a3].addView(mediaPageArr3[a3].listView, LayoutHelper.createFrame(-1, -1.0f));
            this.mediaPages[a3].listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$c836wLgbMocvIgpswbm9ZMXiiE4
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view2, int i3) {
                    this.f$0.lambda$createView$2$MediaActivity(mediaPage, view2, i3);
                }
            });
            this.mediaPages[a3].listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.MediaActivity.12
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                    if (newState == 1 && MediaActivity.this.searching && MediaActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(MediaActivity.this.getParentActivity().getCurrentFocus());
                    }
                    MediaActivity.this.scrolling = newState != 0;
                    if (newState != 1) {
                        int scrollY = (int) (-MediaActivity.this.actionBar.getTranslationY());
                        int actionBarHeight = ActionBar.getCurrentActionBarHeight();
                        if (scrollY != 0 && scrollY != actionBarHeight) {
                            if (scrollY < actionBarHeight / 2) {
                                MediaActivity.this.mediaPages[0].listView.smoothScrollBy(0, -scrollY);
                            } else {
                                MediaActivity.this.mediaPages[0].listView.smoothScrollBy(0, actionBarHeight - scrollY);
                            }
                        }
                    }
                }

                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                    int type;
                    if (MediaActivity.this.searching && MediaActivity.this.searchWas) {
                        return;
                    }
                    int firstVisibleItem = layoutManager.findFirstVisibleItemPosition();
                    int visibleItemCount = firstVisibleItem == -1 ? 0 : Math.abs(layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
                    int totalItemCount = recyclerView.getAdapter().getItemCount();
                    if (visibleItemCount != 0 && firstVisibleItem + visibleItemCount > totalItemCount - 2 && !MediaActivity.this.sharedMediaData[mediaPage.selectedType].loading) {
                        if (mediaPage.selectedType != 0) {
                            if (mediaPage.selectedType != 1) {
                                if (mediaPage.selectedType != 2) {
                                    if (mediaPage.selectedType == 4) {
                                        type = 4;
                                    } else {
                                        type = 3;
                                    }
                                } else {
                                    type = 2;
                                }
                            } else {
                                type = 1;
                            }
                        } else {
                            type = 0;
                        }
                        if (!MediaActivity.this.sharedMediaData[mediaPage.selectedType].endReached[0]) {
                            MediaActivity.this.sharedMediaData[mediaPage.selectedType].loading = true;
                            MediaDataController.getInstance(MediaActivity.this.currentAccount).loadMedia(MediaActivity.this.dialog_id, 50, MediaActivity.this.sharedMediaData[mediaPage.selectedType].max_id[0], type, 1, MediaActivity.this.classGuid);
                        } else if (MediaActivity.this.mergeDialogId != 0 && !MediaActivity.this.sharedMediaData[mediaPage.selectedType].endReached[1]) {
                            MediaActivity.this.sharedMediaData[mediaPage.selectedType].loading = true;
                            MediaDataController.getInstance(MediaActivity.this.currentAccount).loadMedia(MediaActivity.this.mergeDialogId, 50, MediaActivity.this.sharedMediaData[mediaPage.selectedType].max_id[1], type, 1, MediaActivity.this.classGuid);
                        }
                    }
                    MediaActivity.this.updateSections(recyclerView, false);
                }
            });
            this.mediaPages[a3].listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$_OFxntbKb9cX7nkfOc9Q7afXi3g
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
                public final boolean onItemClick(View view2, int i3) {
                    return this.f$0.lambda$createView$3$MediaActivity(mediaPage, view2, i3);
                }
            });
            if (a3 == 0 && scrollToPositionOnRecreate != -1) {
                layoutManager.scrollToPositionWithOffset(scrollToPositionOnRecreate, scrollToOffsetOnRecreate);
            }
            this.mediaPages[a3].emptyView = new LinearLayout(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.13
                @Override // android.widget.LinearLayout, android.view.View
                protected void onDraw(Canvas canvas) {
                }
            };
            this.mediaPages[a3].emptyView.setWillNotDraw(false);
            this.mediaPages[a3].emptyView.setOrientation(1);
            this.mediaPages[a3].emptyView.setGravity(17);
            this.mediaPages[a3].emptyView.setVisibility(8);
            MediaPage[] mediaPageArr4 = this.mediaPages;
            mediaPageArr4[a3].addView(mediaPageArr4[a3].emptyView, LayoutHelper.createFrame(-1, -1.0f));
            this.mediaPages[a3].emptyView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$3qv8y4EeXKvETHnRjt198W1Dc-s
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view2, MotionEvent motionEvent) {
                    return MediaActivity.lambda$createView$4(view2, motionEvent);
                }
            });
            this.mediaPages[a3].emptyImageView = new ImageView(context);
            this.mediaPages[a3].emptyView.addView(this.mediaPages[a3].emptyImageView, LayoutHelper.createLinear(-2, -2));
            this.mediaPages[a3].emptyTextView = new TextView(context);
            this.mediaPages[a3].emptyTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
            this.mediaPages[a3].emptyTextView.setGravity(17);
            this.mediaPages[a3].emptyTextView.setTextSize(1, 17.0f);
            this.mediaPages[a3].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(128.0f));
            this.mediaPages[a3].emptyView.addView(this.mediaPages[a3].emptyTextView, LayoutHelper.createLinear(-2, -2, 17, 0, 24, 0, 0));
            this.mediaPages[a3].progressView = new LinearLayout(context) { // from class: im.uwrkaxlmjj.ui.MediaActivity.14
                @Override // android.widget.LinearLayout, android.view.View
                protected void onDraw(Canvas canvas) {
                }
            };
            this.mediaPages[a3].progressView.setWillNotDraw(false);
            this.mediaPages[a3].progressView.setGravity(17);
            this.mediaPages[a3].progressView.setOrientation(1);
            this.mediaPages[a3].progressView.setVisibility(8);
            MediaPage[] mediaPageArr5 = this.mediaPages;
            mediaPageArr5[a3].addView(mediaPageArr5[a3].progressView, LayoutHelper.createFrame(-1, -1.0f));
            this.mediaPages[a3].progressBar = new RadialProgressView(context);
            this.mediaPages[a3].progressView.addView(this.mediaPages[a3].progressBar, LayoutHelper.createLinear(-2, -2));
            if (a3 != 0) {
                this.mediaPages[a3].setVisibility(8);
            }
            a3++;
            configuration = configuration2;
            searchlayoutParams = searchlayoutParams2;
            linearLayout2 = linearLayout3;
            i = 1;
        }
        if (!AndroidUtilities.isTablet()) {
            FragmentContextView fragmentContextView = new FragmentContextView(context, this, false);
            this.fragmentContextView = fragmentContextView;
            contentcontainer.addView(fragmentContextView, LayoutHelper.createFrame(-1.0f, 39.0f, 51, 0.0f, 8.0f, 0.0f, 0.0f));
        }
        updateTabs();
        switchToCurrentSelectedMode(false);
        this.swipeBackEnabled = this.scrollSlidingTextTabStrip.getCurrentTabId() == this.scrollSlidingTextTabStrip.getFirstTabId();
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.MediaActivity$4, reason: invalid class name */
    class AnonymousClass4 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass4() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                if (MediaActivity.this.actionBar.isActionModeShowed()) {
                    for (int a = 1; a >= 0; a--) {
                        MediaActivity.this.selectedFiles[a].clear();
                    }
                    MediaActivity.this.cantDeleteMessagesCount = 0;
                    MediaActivity.this.actionBar.hideActionMode();
                    MediaActivity.this.updateRowsSelection();
                    return;
                }
                MediaActivity.this.finishFragment();
                return;
            }
            if (id == 4) {
                TLRPC.Chat currentChat = null;
                TLRPC.User currentUser = null;
                TLRPC.EncryptedChat currentEncryptedChat = null;
                int lower_id = (int) MediaActivity.this.dialog_id;
                if (lower_id == 0) {
                    currentEncryptedChat = MessagesController.getInstance(MediaActivity.this.currentAccount).getEncryptedChat(Integer.valueOf((int) (MediaActivity.this.dialog_id >> 32)));
                } else if (lower_id > 0) {
                    currentUser = MessagesController.getInstance(MediaActivity.this.currentAccount).getUser(Integer.valueOf(lower_id));
                } else {
                    currentChat = MessagesController.getInstance(MediaActivity.this.currentAccount).getChat(Integer.valueOf(-lower_id));
                }
                MediaActivity mediaActivity = MediaActivity.this;
                AlertsCreator.createDeleteMessagesAlert(mediaActivity, currentUser, currentChat, currentEncryptedChat, null, mediaActivity.mergeDialogId, null, MediaActivity.this.selectedFiles, null, false, 1, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$4$KP2FHs6QumYSZxk7ZZhLUDa6RO8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onItemClick$0$MediaActivity$4();
                    }
                });
                return;
            }
            if (id == 3) {
                Bundle args = new Bundle();
                args.putBoolean("onlySelect", true);
                args.putInt("dialogsType", 3);
                DialogsActivity fragment = new DialogsActivity(args);
                fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$4$dFEpwvnID_kEPc_RvKrF5MaqvsM
                    @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
                    public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                        this.f$0.lambda$onItemClick$1$MediaActivity$4(dialogsActivity, arrayList, charSequence, z);
                    }
                });
                MediaActivity.this.presentFragment(fragment);
                return;
            }
            if (id != 7 || MediaActivity.this.selectedFiles[0].size() != 1) {
                return;
            }
            Bundle args2 = new Bundle();
            int lower_part = (int) MediaActivity.this.dialog_id;
            int high_id = (int) (MediaActivity.this.dialog_id >> 32);
            if (lower_part != 0) {
                if (lower_part > 0) {
                    args2.putInt("user_id", lower_part);
                } else if (lower_part < 0) {
                    TLRPC.Chat chat = MessagesController.getInstance(MediaActivity.this.currentAccount).getChat(Integer.valueOf(-lower_part));
                    if (chat != null && chat.migrated_to != null) {
                        args2.putInt("migrated_to", lower_part);
                        lower_part = -chat.migrated_to.channel_id;
                    }
                    args2.putInt("chat_id", -lower_part);
                }
            } else {
                args2.putInt("enc_id", high_id);
            }
            args2.putInt("message_id", MediaActivity.this.selectedFiles[0].keyAt(0));
            NotificationCenter.getInstance(MediaActivity.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            MediaActivity.this.presentFragment(new ChatActivity(args2), true);
        }

        public /* synthetic */ void lambda$onItemClick$0$MediaActivity$4() {
            MediaActivity.this.actionBar.hideActionMode();
            MediaActivity.this.actionBar.closeSearchField();
            MediaActivity.this.cantDeleteMessagesCount = 0;
        }

        /* JADX WARN: Multi-variable type inference failed */
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
        public /* synthetic */ void lambda$onItemClick$1$MediaActivity$4(DialogsActivity fragment1, ArrayList dids, CharSequence message, boolean param) {
            ArrayList arrayList = new ArrayList();
            for (int a = 1; a >= 0; a--) {
                ArrayList<Integer> ids = new ArrayList<>();
                for (int b = 0; b < MediaActivity.this.selectedFiles[a].size(); b++) {
                    ids.add(Integer.valueOf(MediaActivity.this.selectedFiles[a].keyAt(b)));
                }
                Collections.sort(ids);
                for (Integer id1 : ids) {
                    if (id1.intValue() > 0) {
                        arrayList.add(MediaActivity.this.selectedFiles[a].get(id1.intValue()));
                    }
                }
                MediaActivity.this.selectedFiles[a].clear();
            }
            MediaActivity.this.cantDeleteMessagesCount = 0;
            MediaActivity.this.actionBar.hideActionMode();
            if (dids.size() > 1 || ((Long) dids.get(0)).longValue() == UserConfig.getInstance(MediaActivity.this.currentAccount).getClientUserId() || message != null) {
                MediaActivity.this.updateRowsSelection();
                for (int a2 = 0; a2 < dids.size(); a2++) {
                    long did = ((Long) dids.get(a2)).longValue();
                    if (message != null) {
                        SendMessagesHelper.getInstance(MediaActivity.this.currentAccount).sendMessage(message.toString(), did, null, null, true, null, null, null, true, 0);
                    }
                    SendMessagesHelper.getInstance(MediaActivity.this.currentAccount).sendMessage(arrayList, did, true, 0);
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
            if (lower_part != 0 && !MessagesController.getInstance(MediaActivity.this.currentAccount).checkCanOpenChat(args1, fragment1)) {
                return;
            }
            NotificationCenter.getInstance(MediaActivity.this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
            ChatActivity chatActivity = new ChatActivity(args1);
            MediaActivity.this.presentFragment(chatActivity, true);
            chatActivity.showFieldPanelForForward(true, arrayList);
            if (!AndroidUtilities.isTablet()) {
                MediaActivity.this.removeSelfFromStack();
            }
        }
    }

    static /* synthetic */ boolean lambda$createView$1(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$createView$2$MediaActivity(MediaPage mediaPage, View view, int position) {
        if (mediaPage.selectedType != 1 || !(view instanceof SharedDocumentCell)) {
            if (mediaPage.selectedType != 3 || !(view instanceof SharedLinkCell)) {
                if ((mediaPage.selectedType == 2 || mediaPage.selectedType == 4) && (view instanceof SharedAudioCell)) {
                    onItemClick(position, view, ((SharedAudioCell) view).getMessage(), 0, mediaPage.selectedType);
                    return;
                }
                return;
            }
            onItemClick(position, view, ((SharedLinkCell) view).getMessage(), 0, mediaPage.selectedType);
            return;
        }
        onItemClick(position, view, ((SharedDocumentCell) view).getMessage(), 0, mediaPage.selectedType);
    }

    public /* synthetic */ boolean lambda$createView$3$MediaActivity(MediaPage mediaPage, View view, int position) {
        if (this.actionBar.isActionModeShowed()) {
            mediaPage.listView.getOnItemClickListener().onItemClick(view, position);
            return true;
        }
        if (mediaPage.selectedType != 1 || !(view instanceof SharedDocumentCell)) {
            if (mediaPage.selectedType != 3 || !(view instanceof SharedLinkCell)) {
                if ((mediaPage.selectedType == 2 || mediaPage.selectedType == 4) && (view instanceof SharedAudioCell)) {
                    return onItemLongClick(((SharedAudioCell) view).getMessage(), view, 0);
                }
                return false;
            }
            return onItemLongClick(((SharedLinkCell) view).getMessage(), view, 0);
        }
        return onItemLongClick(((SharedDocumentCell) view).getMessage(), view, 0);
    }

    static /* synthetic */ boolean lambda$createView$4(View v, MotionEvent event) {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setScrollY(float value) {
        this.actionBar.setTranslationY(value);
        FragmentContextView fragmentContextView = this.fragmentContextView;
        if (fragmentContextView != null) {
            fragmentContextView.setTranslationY(this.additionalPadding + value);
        }
        int a = 0;
        while (true) {
            MediaPage[] mediaPageArr = this.mediaPages;
            if (a < mediaPageArr.length) {
                mediaPageArr[a].listView.setPinnedSectionOffsetY((int) value);
                a++;
            } else {
                this.fragmentView.invalidate();
                return;
            }
        }
    }

    private void resetScroll() {
        if (this.actionBar.getTranslationY() == 0.0f) {
            return;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this, this.SCROLL_Y, 0.0f));
        animatorSet.setInterpolator(new DecelerateInterpolator());
        animatorSet.setDuration(180L);
        animatorSet.start();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        int oldItemCount;
        int i = 2;
        if (id == NotificationCenter.mediaDidLoad) {
            long uid = ((Long) args[0]).longValue();
            int guid = ((Integer) args[3]).intValue();
            if (guid == this.classGuid) {
                int type = ((Integer) args[4]).intValue();
                this.sharedMediaData[type].loading = false;
                this.sharedMediaData[type].totalCount = ((Integer) args[1]).intValue();
                ArrayList<MessageObject> arr = (ArrayList) args[2];
                boolean enc = ((int) this.dialog_id) == 0;
                int loadIndex = uid == this.dialog_id ? 0 : 1;
                RecyclerView.Adapter adapter = null;
                if (type == 0) {
                    adapter = this.photoVideoAdapter;
                } else if (type == 1) {
                    adapter = this.documentsAdapter;
                } else if (type == 2) {
                    adapter = this.voiceAdapter;
                } else if (type == 3) {
                    adapter = this.linksAdapter;
                } else if (type == 4) {
                    adapter = this.audioAdapter;
                }
                if (adapter != null) {
                    oldItemCount = adapter.getItemCount();
                    if (adapter instanceof RecyclerListView.SectionsAdapter) {
                        RecyclerListView.SectionsAdapter sectionsAdapter = (RecyclerListView.SectionsAdapter) adapter;
                        sectionsAdapter.notifySectionsChanged();
                    }
                } else {
                    oldItemCount = 0;
                }
                for (int a = 0; a < arr.size(); a++) {
                    MessageObject message = arr.get(a);
                    this.sharedMediaData[type].addMessage(message, loadIndex, false, enc);
                }
                this.sharedMediaData[type].endReached[loadIndex] = ((Boolean) args[5]).booleanValue();
                if (loadIndex == 0 && this.sharedMediaData[type].endReached[loadIndex] && this.mergeDialogId != 0) {
                    this.sharedMediaData[type].loading = true;
                    MediaDataController.getInstance(this.currentAccount).loadMedia(this.mergeDialogId, 50, this.sharedMediaData[type].max_id[1], type, 1, this.classGuid);
                }
                if (adapter != null) {
                    int a2 = 0;
                    while (true) {
                        MediaPage[] mediaPageArr = this.mediaPages;
                        if (a2 >= mediaPageArr.length) {
                            break;
                        }
                        if (mediaPageArr[a2].listView.getAdapter() == adapter) {
                            this.mediaPages[a2].listView.stopScroll();
                        }
                        a2++;
                    }
                    int newItemCount = adapter.getItemCount();
                    if (oldItemCount > 1) {
                        adapter.notifyItemChanged(oldItemCount - 2);
                    }
                    if (newItemCount > oldItemCount) {
                        adapter.notifyItemRangeInserted(oldItemCount, newItemCount);
                    } else if (newItemCount < oldItemCount) {
                        adapter.notifyItemRangeRemoved(newItemCount, oldItemCount - newItemCount);
                    }
                }
                this.scrolling = true;
                int a3 = 0;
                while (true) {
                    MediaPage[] mediaPageArr2 = this.mediaPages;
                    if (a3 < mediaPageArr2.length) {
                        if (mediaPageArr2[a3].selectedType == type && !this.sharedMediaData[type].loading) {
                            if (this.mediaPages[a3].progressView != null) {
                                this.mediaPages[a3].progressView.setVisibility(8);
                            }
                            if (this.mediaPages[a3].selectedType == type && this.mediaPages[a3].listView != null && this.mediaPages[a3].listView.getEmptyView() == null) {
                                this.mediaPages[a3].listView.setEmptyView(this.mediaPages[a3].emptyView);
                            }
                        }
                        if (oldItemCount == 0 && this.actionBar.getTranslationY() != 0.0f && this.mediaPages[a3].listView.getAdapter() == adapter) {
                            this.mediaPages[a3].layoutManager.scrollToPositionWithOffset(0, (int) this.actionBar.getTranslationY());
                        }
                        a3++;
                    } else {
                        return;
                    }
                }
            }
        } else {
            if (id == NotificationCenter.messagesDeleted) {
                boolean scheduled = ((Boolean) args[2]).booleanValue();
                if (scheduled) {
                    return;
                }
                TLRPC.Chat currentChat = null;
                if (((int) this.dialog_id) < 0) {
                    currentChat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-((int) this.dialog_id)));
                }
                int channelId = ((Integer) args[1]).intValue();
                int loadIndex2 = 0;
                if (ChatObject.isChannel(currentChat)) {
                    if (channelId == 0 && this.mergeDialogId != 0) {
                        loadIndex2 = 1;
                    } else if (channelId == currentChat.id) {
                        loadIndex2 = 0;
                    } else {
                        return;
                    }
                } else if (channelId != 0) {
                    return;
                }
                ArrayList<Integer> markAsDeletedMessages = (ArrayList) args[0];
                boolean updated = false;
                int N = markAsDeletedMessages.size();
                for (int a4 = 0; a4 < N; a4++) {
                    int b = 0;
                    while (true) {
                        SharedMediaData[] sharedMediaDataArr = this.sharedMediaData;
                        if (b < sharedMediaDataArr.length) {
                            if (sharedMediaDataArr[b].deleteMessage(markAsDeletedMessages.get(a4).intValue(), loadIndex2)) {
                                updated = true;
                            }
                            b++;
                        }
                    }
                }
                if (updated) {
                    this.scrolling = true;
                    SharedPhotoVideoAdapter sharedPhotoVideoAdapter = this.photoVideoAdapter;
                    if (sharedPhotoVideoAdapter != null) {
                        sharedPhotoVideoAdapter.notifyDataSetChanged();
                    }
                    SharedDocumentsAdapter sharedDocumentsAdapter = this.documentsAdapter;
                    if (sharedDocumentsAdapter != null) {
                        sharedDocumentsAdapter.notifyDataSetChanged();
                    }
                    SharedDocumentsAdapter sharedDocumentsAdapter2 = this.voiceAdapter;
                    if (sharedDocumentsAdapter2 != null) {
                        sharedDocumentsAdapter2.notifyDataSetChanged();
                    }
                    SharedLinksAdapter sharedLinksAdapter = this.linksAdapter;
                    if (sharedLinksAdapter != null) {
                        sharedLinksAdapter.notifyDataSetChanged();
                    }
                    SharedDocumentsAdapter sharedDocumentsAdapter3 = this.audioAdapter;
                    if (sharedDocumentsAdapter3 != null) {
                        sharedDocumentsAdapter3.notifyDataSetChanged();
                        return;
                    }
                    return;
                }
                return;
            }
            if (id == NotificationCenter.didReceiveNewMessages) {
                boolean scheduled2 = ((Boolean) args[2]).booleanValue();
                if (scheduled2) {
                    return;
                }
                long uid2 = ((Long) args[0]).longValue();
                long j = this.dialog_id;
                if (uid2 == j) {
                    ArrayList<MessageObject> arr2 = (ArrayList) args[1];
                    boolean enc2 = ((int) j) == 0;
                    boolean updated2 = false;
                    for (int a5 = 0; a5 < arr2.size(); a5++) {
                        MessageObject obj = arr2.get(a5);
                        if (obj.messageOwner.media != null && !obj.needDrawBluredPreview()) {
                            int type2 = MediaDataController.getMediaType(obj.messageOwner);
                            if (type2 == -1) {
                                return;
                            }
                            if (this.sharedMediaData[type2].addMessage(obj, obj.getDialogId() == this.dialog_id ? 0 : 1, true, enc2)) {
                                this.hasMedia[type2] = 1;
                                updated2 = true;
                            }
                        }
                    }
                    if (updated2) {
                        this.scrolling = true;
                        int a6 = 0;
                        while (true) {
                            MediaPage[] mediaPageArr3 = this.mediaPages;
                            if (a6 < mediaPageArr3.length) {
                                RecyclerView.Adapter adapter2 = null;
                                if (mediaPageArr3[a6].selectedType != 0) {
                                    if (this.mediaPages[a6].selectedType != 1) {
                                        if (this.mediaPages[a6].selectedType != i) {
                                            if (this.mediaPages[a6].selectedType != 3) {
                                                if (this.mediaPages[a6].selectedType == 4) {
                                                    adapter2 = this.audioAdapter;
                                                }
                                            } else {
                                                adapter2 = this.linksAdapter;
                                            }
                                        } else {
                                            adapter2 = this.voiceAdapter;
                                        }
                                    } else {
                                        adapter2 = this.documentsAdapter;
                                    }
                                } else {
                                    adapter2 = this.photoVideoAdapter;
                                }
                                if (adapter2 != null) {
                                    int count = adapter2.getItemCount();
                                    this.photoVideoAdapter.notifyDataSetChanged();
                                    this.documentsAdapter.notifyDataSetChanged();
                                    this.voiceAdapter.notifyDataSetChanged();
                                    this.linksAdapter.notifyDataSetChanged();
                                    this.audioAdapter.notifyDataSetChanged();
                                    if (count == 0 && this.actionBar.getTranslationY() != 0.0f) {
                                        this.mediaPages[a6].layoutManager.scrollToPositionWithOffset(0, (int) this.actionBar.getTranslationY());
                                    }
                                }
                                a6++;
                                i = 2;
                            } else {
                                updateTabs();
                                return;
                            }
                        }
                    }
                }
            } else {
                if (id == NotificationCenter.messageReceivedByServer) {
                    Boolean scheduled3 = (Boolean) args[6];
                    if (scheduled3.booleanValue()) {
                        return;
                    }
                    Integer msgId = (Integer) args[0];
                    Integer newMsgId = (Integer) args[1];
                    for (SharedMediaData data : this.sharedMediaData) {
                        data.replaceMid(msgId.intValue(), newMsgId.intValue());
                    }
                    return;
                }
                if (id == NotificationCenter.messagePlayingDidStart || id == NotificationCenter.messagePlayingPlayStateChanged || id == NotificationCenter.messagePlayingDidReset) {
                    if (id == NotificationCenter.messagePlayingDidReset || id == NotificationCenter.messagePlayingPlayStateChanged) {
                        int b2 = 0;
                        while (true) {
                            MediaPage[] mediaPageArr4 = this.mediaPages;
                            if (b2 < mediaPageArr4.length) {
                                int count2 = mediaPageArr4[b2].listView.getChildCount();
                                for (int a7 = 0; a7 < count2; a7++) {
                                    View view = this.mediaPages[b2].listView.getChildAt(a7);
                                    if (view instanceof SharedAudioCell) {
                                        SharedAudioCell cell = (SharedAudioCell) view;
                                        MessageObject messageObject = cell.getMessage();
                                        if (messageObject != null) {
                                            cell.updateButtonState(false, true);
                                        }
                                    }
                                }
                                b2++;
                            } else {
                                return;
                            }
                        }
                    } else if (id == NotificationCenter.messagePlayingDidStart) {
                        MessageObject messageObject2 = (MessageObject) args[0];
                        if (messageObject2.eventId != 0) {
                            return;
                        }
                        int b3 = 0;
                        while (true) {
                            MediaPage[] mediaPageArr5 = this.mediaPages;
                            if (b3 < mediaPageArr5.length) {
                                int count3 = mediaPageArr5[b3].listView.getChildCount();
                                for (int a8 = 0; a8 < count3; a8++) {
                                    View view2 = this.mediaPages[b3].listView.getChildAt(a8);
                                    if (view2 instanceof SharedAudioCell) {
                                        SharedAudioCell cell2 = (SharedAudioCell) view2;
                                        MessageObject messageObject1 = cell2.getMessage();
                                        if (messageObject1 != null) {
                                            cell2.updateButtonState(false, true);
                                        }
                                    }
                                }
                                b3++;
                            } else {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        this.scrolling = true;
        SharedPhotoVideoAdapter sharedPhotoVideoAdapter = this.photoVideoAdapter;
        if (sharedPhotoVideoAdapter != null) {
            sharedPhotoVideoAdapter.notifyDataSetChanged();
        }
        SharedDocumentsAdapter sharedDocumentsAdapter = this.documentsAdapter;
        if (sharedDocumentsAdapter != null) {
            sharedDocumentsAdapter.notifyDataSetChanged();
        }
        SharedLinksAdapter sharedLinksAdapter = this.linksAdapter;
        if (sharedLinksAdapter != null) {
            sharedLinksAdapter.notifyDataSetChanged();
        }
        for (int a = 0; a < this.mediaPages.length; a++) {
            fixLayoutInternal(a);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        int a = 0;
        while (true) {
            MediaPage[] mediaPageArr = this.mediaPages;
            if (a < mediaPageArr.length) {
                if (mediaPageArr[a].listView != null) {
                    final int num = a;
                    ViewTreeObserver obs = this.mediaPages[a].listView.getViewTreeObserver();
                    obs.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: im.uwrkaxlmjj.ui.MediaActivity.15
                        @Override // android.view.ViewTreeObserver.OnPreDrawListener
                        public boolean onPreDraw() {
                            MediaActivity.this.mediaPages[num].getViewTreeObserver().removeOnPreDrawListener(this);
                            MediaActivity.this.fixLayoutInternal(num);
                            return true;
                        }
                    });
                }
                a++;
            } else {
                return;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        return this.actionBar.isEnabled();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSections(ViewGroup listView, boolean checkBottom) {
        int count = listView.getChildCount();
        int minPositionDateHolder = Integer.MAX_VALUE;
        View minDateChild = null;
        float padding = listView.getPaddingTop() + this.actionBar.getTranslationY();
        int maxBottom = 0;
        for (int a = 0; a < count; a++) {
            View view = listView.getChildAt(a);
            int bottom = view.getBottom();
            maxBottom = Math.max(bottom, maxBottom);
            if (bottom > padding) {
                int position = view.getBottom();
                if ((view instanceof SharedMediaSectionCell) || (view instanceof GraySectionCell)) {
                    if (view.getAlpha() != 1.0f) {
                        view.setAlpha(1.0f);
                    }
                    if (position < minPositionDateHolder) {
                        minPositionDateHolder = position;
                        minDateChild = view;
                    }
                }
            }
        }
        if (minDateChild != null) {
            if (minDateChild.getTop() > padding) {
                if (minDateChild.getAlpha() != 1.0f) {
                    minDateChild.setAlpha(1.0f);
                }
            } else if (minDateChild.getAlpha() != 0.0f) {
                minDateChild.setAlpha(0.0f);
            }
        }
        if (checkBottom && maxBottom != 0 && maxBottom < listView.getMeasuredHeight() - listView.getPaddingBottom()) {
            resetScroll();
        }
    }

    public void setChatInfo(TLRPC.ChatFull chatInfo) {
        this.info = chatInfo;
        if (chatInfo != null && chatInfo.migrated_from_chat_id != 0 && this.mergeDialogId == 0) {
            this.mergeDialogId = -this.info.migrated_from_chat_id;
            int a = 0;
            while (true) {
                SharedMediaData[] sharedMediaDataArr = this.sharedMediaData;
                if (a < sharedMediaDataArr.length) {
                    sharedMediaDataArr[a].max_id[1] = this.info.migrated_from_max_id;
                    this.sharedMediaData[a].endReached[1] = false;
                    a++;
                } else {
                    return;
                }
            }
        }
    }

    public void updateAdapters() {
        SharedPhotoVideoAdapter sharedPhotoVideoAdapter = this.photoVideoAdapter;
        if (sharedPhotoVideoAdapter != null) {
            sharedPhotoVideoAdapter.notifyDataSetChanged();
        }
        SharedDocumentsAdapter sharedDocumentsAdapter = this.documentsAdapter;
        if (sharedDocumentsAdapter != null) {
            sharedDocumentsAdapter.notifyDataSetChanged();
        }
        SharedDocumentsAdapter sharedDocumentsAdapter2 = this.voiceAdapter;
        if (sharedDocumentsAdapter2 != null) {
            sharedDocumentsAdapter2.notifyDataSetChanged();
        }
        SharedLinksAdapter sharedLinksAdapter = this.linksAdapter;
        if (sharedLinksAdapter != null) {
            sharedLinksAdapter.notifyDataSetChanged();
        }
        SharedDocumentsAdapter sharedDocumentsAdapter3 = this.audioAdapter;
        if (sharedDocumentsAdapter3 != null) {
            sharedDocumentsAdapter3.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRowsSelection() {
        int i = 0;
        while (true) {
            MediaPage[] mediaPageArr = this.mediaPages;
            if (i < mediaPageArr.length) {
                int count = mediaPageArr[i].listView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child = this.mediaPages[i].listView.getChildAt(a);
                    if (child instanceof SharedDocumentCell) {
                        ((SharedDocumentCell) child).setChecked(false, true);
                    } else if (child instanceof SharedPhotoVideoCell) {
                        for (int b = 0; b < 6; b++) {
                            ((SharedPhotoVideoCell) child).setChecked(b, false, true);
                        }
                    } else if (child instanceof SharedLinkCell) {
                        ((SharedLinkCell) child).setChecked(false, true);
                    } else if (child instanceof SharedAudioCell) {
                        ((SharedAudioCell) child).setChecked(false, true);
                    }
                }
                i++;
            } else {
                return;
            }
        }
    }

    public void setMergeDialogId(long did) {
        this.mergeDialogId = did;
    }

    private void updateTabs() {
        if (this.scrollSlidingTextTabStrip == null) {
            return;
        }
        boolean changed = false;
        int[] iArr = this.hasMedia;
        if ((iArr[0] != 0 || (iArr[1] == 0 && iArr[2] == 0 && iArr[3] == 0 && iArr[4] == 0)) && !this.scrollSlidingTextTabStrip.hasTab(0)) {
            changed = true;
        }
        if (this.hasMedia[1] != 0 && !this.scrollSlidingTextTabStrip.hasTab(1)) {
            changed = true;
        }
        if (((int) this.dialog_id) != 0) {
            if (this.hasMedia[3] != 0 && !this.scrollSlidingTextTabStrip.hasTab(3)) {
                changed = true;
            }
            if (this.hasMedia[4] != 0 && !this.scrollSlidingTextTabStrip.hasTab(4)) {
                changed = true;
            }
        } else {
            TLRPC.EncryptedChat currentEncryptedChat = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf((int) (this.dialog_id >> 32)));
            if (currentEncryptedChat != null && AndroidUtilities.getPeerLayerVersion(currentEncryptedChat.layer) >= 46 && this.hasMedia[4] != 0 && !this.scrollSlidingTextTabStrip.hasTab(4)) {
                changed = true;
            }
        }
        if (this.hasMedia[2] != 0 && !this.scrollSlidingTextTabStrip.hasTab(2)) {
            changed = true;
        }
        if (changed) {
            this.scrollSlidingTextTabStrip.removeTabs();
            int[] iArr2 = this.hasMedia;
            if ((iArr2[0] != 0 || (iArr2[1] == 0 && iArr2[2] == 0 && iArr2[3] == 0 && iArr2[4] == 0)) && !this.scrollSlidingTextTabStrip.hasTab(0)) {
                this.scrollSlidingTextTabStrip.addTextTab(0, LocaleController.getString("SharedMediaTab", R.string.SharedMediaTab));
            }
            if (this.hasMedia[1] != 0 && !this.scrollSlidingTextTabStrip.hasTab(1)) {
                this.scrollSlidingTextTabStrip.addTextTab(1, LocaleController.getString("SharedFilesTab", R.string.SharedFilesTab));
            }
            if (((int) this.dialog_id) != 0) {
                if (this.hasMedia[3] != 0 && !this.scrollSlidingTextTabStrip.hasTab(3)) {
                    this.scrollSlidingTextTabStrip.addTextTab(3, LocaleController.getString("SharedLinksTab", R.string.SharedLinksTab));
                }
                if (this.hasMedia[4] != 0 && !this.scrollSlidingTextTabStrip.hasTab(4)) {
                    this.scrollSlidingTextTabStrip.addTextTab(4, LocaleController.getString("SharedMusicTab", R.string.SharedMusicTab));
                }
            } else {
                TLRPC.EncryptedChat currentEncryptedChat2 = MessagesController.getInstance(this.currentAccount).getEncryptedChat(Integer.valueOf((int) (this.dialog_id >> 32)));
                if (currentEncryptedChat2 != null && AndroidUtilities.getPeerLayerVersion(currentEncryptedChat2.layer) >= 46 && this.hasMedia[4] != 0 && !this.scrollSlidingTextTabStrip.hasTab(4)) {
                    this.scrollSlidingTextTabStrip.addTextTab(4, LocaleController.getString("SharedMusicTab", R.string.SharedMusicTab));
                }
            }
            if (this.hasMedia[2] != 0 && !this.scrollSlidingTextTabStrip.hasTab(2)) {
                this.scrollSlidingTextTabStrip.addTextTab(2, LocaleController.getString("SharedVoiceTab", R.string.SharedVoiceTab));
            }
        }
        if (this.scrollSlidingTextTabStrip.getTabsCount() <= 1) {
            this.scrollSlidingTextTabStrip.setVisibility(8);
        } else {
            this.scrollSlidingTextTabStrip.setVisibility(0);
        }
        int id = this.scrollSlidingTextTabStrip.getCurrentTabId();
        if (id >= 0) {
            this.mediaPages[0].selectedType = id;
        }
        this.scrollSlidingTextTabStrip.finishAddingTabs();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void switchToCurrentSelectedMode(boolean z) {
        MediaPage[] mediaPageArr;
        MediaSearchAdapter mediaSearchAdapter;
        int i = 0;
        while (true) {
            mediaPageArr = this.mediaPages;
            if (i >= mediaPageArr.length) {
                break;
            }
            mediaPageArr[i].listView.stopScroll();
            i++;
        }
        RecyclerView.Adapter adapter = mediaPageArr[z ? 1 : 0].listView.getAdapter();
        if (!this.searching || !this.searchWas) {
            this.mediaPages[z ? 1 : 0].emptyTextView.setTextSize(1, 17.0f);
            this.mediaPages[z ? 1 : 0].emptyImageView.setVisibility(0);
            this.mediaPages[z ? 1 : 0].listView.setPinnedHeaderShadowDrawable(null);
            if (this.mediaPages[z ? 1 : 0].selectedType != 0) {
                if (this.mediaPages[z ? 1 : 0].selectedType != 1) {
                    if (this.mediaPages[z ? 1 : 0].selectedType != 2) {
                        if (this.mediaPages[z ? 1 : 0].selectedType != 3) {
                            if (this.mediaPages[z ? 1 : 0].selectedType == 4) {
                                if (adapter != this.audioAdapter) {
                                    recycleAdapter(adapter);
                                    this.mediaPages[z ? 1 : 0].listView.setAdapter(this.audioAdapter);
                                }
                                this.mediaPages[z ? 1 : 0].emptyImageView.setImageResource(R.drawable.tip4);
                                if (((int) this.dialog_id) == 0) {
                                    this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedAudioSecret", R.string.NoSharedAudioSecret));
                                } else {
                                    this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedAudio", R.string.NoSharedAudio));
                                }
                            }
                        } else {
                            if (adapter != this.linksAdapter) {
                                recycleAdapter(adapter);
                                this.mediaPages[z ? 1 : 0].listView.setAdapter(this.linksAdapter);
                            }
                            this.mediaPages[z ? 1 : 0].emptyImageView.setImageResource(R.drawable.tip3);
                            if (((int) this.dialog_id) == 0) {
                                this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedLinksSecret", R.string.NoSharedLinksSecret));
                            } else {
                                this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedLinks", R.string.NoSharedLinks));
                            }
                        }
                    } else {
                        if (adapter != this.voiceAdapter) {
                            recycleAdapter(adapter);
                            this.mediaPages[z ? 1 : 0].listView.setAdapter(this.voiceAdapter);
                        }
                        this.mediaPages[z ? 1 : 0].emptyImageView.setImageResource(R.drawable.tip5);
                        if (((int) this.dialog_id) == 0) {
                            this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedVoiceSecret", R.string.NoSharedVoiceSecret));
                        } else {
                            this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedVoice", R.string.NoSharedVoice));
                        }
                    }
                } else {
                    if (adapter != this.documentsAdapter) {
                        recycleAdapter(adapter);
                        this.mediaPages[z ? 1 : 0].listView.setAdapter(this.documentsAdapter);
                    }
                    this.mediaPages[z ? 1 : 0].emptyImageView.setImageResource(R.drawable.tip2);
                    if (((int) this.dialog_id) == 0) {
                        this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedFilesSecret", R.string.NoSharedFilesSecret));
                    } else {
                        this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoSharedFiles", R.string.NoSharedFiles));
                    }
                }
            } else {
                if (adapter != this.photoVideoAdapter) {
                    recycleAdapter(adapter);
                    this.mediaPages[z ? 1 : 0].listView.setAdapter(this.photoVideoAdapter);
                }
                this.mediaPages[z ? 1 : 0].listView.setPinnedHeaderShadowDrawable(this.pinnedHeaderShadowDrawable);
                this.mediaPages[z ? 1 : 0].emptyImageView.setImageResource(R.drawable.tip1);
                if (((int) this.dialog_id) == 0) {
                    this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoMediaSecret", R.string.NoMediaSecret));
                } else {
                    this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoMedia", R.string.NoMedia));
                }
            }
            this.mediaPages[z ? 1 : 0].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(90.0f));
            if (this.mediaPages[z ? 1 : 0].selectedType == 0 || this.mediaPages[z ? 1 : 0].selectedType == 2) {
                if (z) {
                    this.searchItemState = 2;
                } else {
                    this.searchItemState = 0;
                    this.mrySearchView.setVisibility(8);
                }
            } else if (z) {
                if (this.mrySearchView.getVisibility() == 8 && !this.mrySearchView.isSearchFieldVisible()) {
                    this.searchItemState = 1;
                    this.mrySearchView.setVisibility(0);
                    this.mrySearchView.setAlpha(0.0f);
                } else {
                    this.searchItemState = 0;
                }
            } else if (this.mrySearchView.getVisibility() == 8) {
                this.searchItemState = 0;
                this.mrySearchView.setAlpha(1.0f);
                this.mrySearchView.setVisibility(0);
            }
            if (!this.sharedMediaData[this.mediaPages[z ? 1 : 0].selectedType].loading && !this.sharedMediaData[this.mediaPages[z ? 1 : 0].selectedType].endReached[0] && this.sharedMediaData[this.mediaPages[z ? 1 : 0].selectedType].messages.isEmpty()) {
                this.sharedMediaData[this.mediaPages[z ? 1 : 0].selectedType].loading = true;
                MediaDataController.getInstance(this.currentAccount).loadMedia(this.dialog_id, 50, 0, this.mediaPages[z ? 1 : 0].selectedType, 1, this.classGuid);
            }
            if (!this.sharedMediaData[this.mediaPages[z ? 1 : 0].selectedType].loading || !this.sharedMediaData[this.mediaPages[z ? 1 : 0].selectedType].messages.isEmpty()) {
                this.mediaPages[z ? 1 : 0].progressView.setVisibility(8);
                this.mediaPages[z ? 1 : 0].listView.setEmptyView(this.mediaPages[z ? 1 : 0].emptyView);
            } else {
                this.mediaPages[z ? 1 : 0].progressView.setVisibility(0);
                this.mediaPages[z ? 1 : 0].listView.setEmptyView(null);
                this.mediaPages[z ? 1 : 0].emptyView.setVisibility(8);
            }
            this.mediaPages[z ? 1 : 0].listView.setVisibility(0);
        } else if (z) {
            if (this.mediaPages[z ? 1 : 0].selectedType == 0 || this.mediaPages[z ? 1 : 0].selectedType == 2) {
                this.searching = false;
                this.searchWas = false;
                switchToCurrentSelectedMode(true);
                return;
            }
            String string = this.mrySearchView.getEditor().getText().toString();
            if (this.mediaPages[z ? 1 : 0].selectedType != 1) {
                if (this.mediaPages[z ? 1 : 0].selectedType != 3) {
                    if (this.mediaPages[z ? 1 : 0].selectedType == 4 && (mediaSearchAdapter = this.audioSearchAdapter) != null) {
                        mediaSearchAdapter.search(string);
                        if (adapter != this.audioSearchAdapter) {
                            recycleAdapter(adapter);
                            this.mediaPages[z ? 1 : 0].listView.setAdapter(this.audioSearchAdapter);
                        }
                    }
                } else {
                    MediaSearchAdapter mediaSearchAdapter2 = this.linksSearchAdapter;
                    if (mediaSearchAdapter2 != null) {
                        mediaSearchAdapter2.search(string);
                        if (adapter != this.linksSearchAdapter) {
                            recycleAdapter(adapter);
                            this.mediaPages[z ? 1 : 0].listView.setAdapter(this.linksSearchAdapter);
                        }
                    }
                }
            } else {
                MediaSearchAdapter mediaSearchAdapter3 = this.documentsSearchAdapter;
                if (mediaSearchAdapter3 != null) {
                    mediaSearchAdapter3.search(string);
                    if (adapter != this.documentsSearchAdapter) {
                        recycleAdapter(adapter);
                        this.mediaPages[z ? 1 : 0].listView.setAdapter(this.documentsSearchAdapter);
                    }
                }
            }
            if (this.searchItemState != 2 && this.mediaPages[z ? 1 : 0].emptyTextView != null) {
                this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                this.mediaPages[z ? 1 : 0].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(30.0f));
                this.mediaPages[z ? 1 : 0].emptyTextView.setTextSize(1, 20.0f);
                this.mediaPages[z ? 1 : 0].emptyImageView.setVisibility(8);
            }
        } else {
            if (this.mediaPages[z ? 1 : 0].listView != null) {
                if (this.mediaPages[z ? 1 : 0].selectedType != 1) {
                    if (this.mediaPages[z ? 1 : 0].selectedType != 3) {
                        if (this.mediaPages[z ? 1 : 0].selectedType == 4) {
                            if (adapter != this.audioSearchAdapter) {
                                recycleAdapter(adapter);
                                this.mediaPages[z ? 1 : 0].listView.setAdapter(this.audioSearchAdapter);
                            }
                            this.audioSearchAdapter.notifyDataSetChanged();
                        }
                    } else {
                        if (adapter != this.linksSearchAdapter) {
                            recycleAdapter(adapter);
                            this.mediaPages[z ? 1 : 0].listView.setAdapter(this.linksSearchAdapter);
                        }
                        this.linksSearchAdapter.notifyDataSetChanged();
                    }
                } else {
                    if (adapter != this.documentsSearchAdapter) {
                        recycleAdapter(adapter);
                        this.mediaPages[z ? 1 : 0].listView.setAdapter(this.documentsSearchAdapter);
                    }
                    this.documentsSearchAdapter.notifyDataSetChanged();
                }
            }
            if (this.searchItemState != 2 && this.mediaPages[z ? 1 : 0].emptyTextView != null) {
                this.mediaPages[z ? 1 : 0].emptyTextView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                this.mediaPages[z ? 1 : 0].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(30.0f));
                this.mediaPages[z ? 1 : 0].emptyTextView.setTextSize(1, 20.0f);
                this.mediaPages[z ? 1 : 0].emptyImageView.setVisibility(8);
            }
        }
        if (this.searchItemState == 2 && this.mrySearchView.isSearchFieldVisible()) {
            this.ignoreSearchCollapse = true;
            this.mrySearchView.closeSearchField();
        }
        if (this.actionBar.getTranslationY() != 0.0f) {
            this.mediaPages[z ? 1 : 0].layoutManager.scrollToPositionWithOffset(0, (int) this.actionBar.getTranslationY());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean onItemLongClick(MessageObject item, View view, int a) {
        if (this.actionBar.isActionModeShowed() || getParentActivity() == null) {
            return false;
        }
        AndroidUtilities.hideKeyboard(getParentActivity().getCurrentFocus());
        this.selectedFiles[item.getDialogId() == this.dialog_id ? (char) 0 : (char) 1].put(item.getId(), item);
        if (!item.canDeleteMessage(false, null)) {
            this.cantDeleteMessagesCount++;
        }
        this.actionBar.createActionMode().getItem(4).setVisibility(this.cantDeleteMessagesCount == 0 ? 0 : 8);
        ActionBarMenuItem actionBarMenuItem = this.gotoItem;
        if (actionBarMenuItem != null) {
            actionBarMenuItem.setVisibility(0);
        }
        this.selectedMessagesCountTextView.setNumber(1, false);
        AnimatorSet animatorSet = new AnimatorSet();
        ArrayList<Animator> animators = new ArrayList<>();
        for (int i = 0; i < this.actionModeViews.size(); i++) {
            View view2 = this.actionModeViews.get(i);
            AndroidUtilities.clearDrawableAnimation(view2);
            animators.add(ObjectAnimator.ofFloat(view2, (Property<View, Float>) View.SCALE_Y, 0.1f, 1.0f));
        }
        animatorSet.playTogether(animators);
        animatorSet.setDuration(250L);
        animatorSet.start();
        this.scrolling = false;
        if (view instanceof SharedDocumentCell) {
            ((SharedDocumentCell) view).setChecked(true, true);
        } else if (view instanceof SharedPhotoVideoCell) {
            ((SharedPhotoVideoCell) view).setChecked(a, true, true);
        } else if (view instanceof SharedLinkCell) {
            ((SharedLinkCell) view).setChecked(true, true);
        } else if (view instanceof SharedAudioCell) {
            ((SharedAudioCell) view).setChecked(true, true);
        }
        if (!this.actionBar.isActionModeShowed()) {
            this.actionBar.showActionMode(null, this.actionModeBackground, null, null, null, 0);
            resetScroll();
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onItemClick(int index, View view, MessageObject message, int a, int selectedMode) {
        if (message == null) {
            return;
        }
        if (this.actionBar.isActionModeShowed()) {
            int loadIndex = message.getDialogId() == this.dialog_id ? 0 : 1;
            if (this.selectedFiles[loadIndex].indexOfKey(message.getId()) < 0) {
                if (this.selectedFiles[0].size() + this.selectedFiles[1].size() >= 100) {
                    return;
                }
                this.selectedFiles[loadIndex].put(message.getId(), message);
                if (!message.canDeleteMessage(false, null)) {
                    this.cantDeleteMessagesCount++;
                }
            } else {
                this.selectedFiles[loadIndex].remove(message.getId());
                if (!message.canDeleteMessage(false, null)) {
                    this.cantDeleteMessagesCount--;
                }
            }
            if (this.selectedFiles[0].size() != 0 || this.selectedFiles[1].size() != 0) {
                this.selectedMessagesCountTextView.setNumber(this.selectedFiles[0].size() + this.selectedFiles[1].size(), true);
                this.actionBar.createActionMode().getItem(4).setVisibility(this.cantDeleteMessagesCount == 0 ? 0 : 8);
                ActionBarMenuItem actionBarMenuItem = this.gotoItem;
                if (actionBarMenuItem != null) {
                    actionBarMenuItem.setVisibility(this.selectedFiles[0].size() == 1 ? 0 : 8);
                }
            } else {
                this.actionBar.hideActionMode();
            }
            this.scrolling = false;
            if (view instanceof SharedDocumentCell) {
                ((SharedDocumentCell) view).setChecked(this.selectedFiles[loadIndex].indexOfKey(message.getId()) >= 0, true);
                return;
            }
            if (view instanceof SharedPhotoVideoCell) {
                ((SharedPhotoVideoCell) view).setChecked(a, this.selectedFiles[loadIndex].indexOfKey(message.getId()) >= 0, true);
                return;
            } else if (view instanceof SharedLinkCell) {
                ((SharedLinkCell) view).setChecked(this.selectedFiles[loadIndex].indexOfKey(message.getId()) >= 0, true);
                return;
            } else {
                if (view instanceof SharedAudioCell) {
                    ((SharedAudioCell) view).setChecked(this.selectedFiles[loadIndex].indexOfKey(message.getId()) >= 0, true);
                    return;
                }
                return;
            }
        }
        if (selectedMode == 0) {
            PhotoViewer.getInstance().setParentActivity(getParentActivity());
            PhotoViewer.getInstance().openPhoto(this.sharedMediaData[selectedMode].messages, index, this.dialog_id, this.mergeDialogId, this.provider);
            return;
        }
        if (selectedMode == 2 || selectedMode == 4) {
            if (view instanceof SharedAudioCell) {
                ((SharedAudioCell) view).didPressedButton();
                return;
            }
            return;
        }
        if (selectedMode == 1) {
            if (view instanceof SharedDocumentCell) {
                SharedDocumentCell cell = (SharedDocumentCell) view;
                TLRPC.Document document = message.getDocument();
                if (cell.isLoaded()) {
                    if (!message.canPreviewDocument()) {
                        AndroidUtilities.openDocument(message, getParentActivity(), this);
                        return;
                    }
                    PhotoViewer.getInstance().setParentActivity(getParentActivity());
                    int index2 = this.sharedMediaData[selectedMode].messages.indexOf(message);
                    if (index2 >= 0) {
                        PhotoViewer.getInstance().openPhoto(this.sharedMediaData[selectedMode].messages, index2, this.dialog_id, this.mergeDialogId, this.provider);
                        return;
                    }
                    ArrayList<MessageObject> documents = new ArrayList<>();
                    documents.add(message);
                    PhotoViewer.getInstance().openPhoto(documents, 0, 0L, 0L, this.provider);
                    return;
                }
                if (!cell.isLoading()) {
                    MessageObject messageObject = cell.getMessage();
                    FileLoader.getInstance(this.currentAccount).loadFile(document, messageObject, 0, 0);
                    cell.updateFileExistIcon();
                    return;
                } else {
                    FileLoader.getInstance(this.currentAccount).cancelLoadFile(document);
                    cell.updateFileExistIcon();
                    return;
                }
            }
            return;
        }
        if (selectedMode == 3) {
            try {
                TLRPC.WebPage webPage = message.messageOwner.media.webpage;
                String link = null;
                if (webPage != null && !(webPage instanceof TLRPC.TL_webPageEmpty)) {
                    if (webPage.cached_page != null) {
                        ArticleViewer.getInstance().setParentActivity(getParentActivity(), this);
                        ArticleViewer.getInstance().open(message);
                        return;
                    } else {
                        if (webPage.embed_url != null && webPage.embed_url.length() != 0) {
                            openWebView(webPage);
                            return;
                        }
                        link = webPage.url;
                    }
                }
                if (link == null) {
                    link = ((SharedLinkCell) view).getLink(0);
                }
                if (link != null) {
                    Browser.openUrl(getParentActivity(), link);
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openWebView(TLRPC.WebPage webPage) {
        EmbedBottomSheet.show(getParentActivity(), webPage.site_name, webPage.description, webPage.url, webPage.embed_url, webPage.embed_width, webPage.embed_height);
    }

    private void recycleAdapter(RecyclerView.Adapter adapter) {
        if (adapter instanceof SharedPhotoVideoAdapter) {
            this.cellCache.addAll(this.cache);
            this.cache.clear();
        } else if (adapter == this.audioAdapter) {
            this.audioCellCache.addAll(this.audioCache);
            this.audioCache.clear();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fixLayoutInternal(int num) {
        WindowManager manager = (WindowManager) ApplicationLoader.applicationContext.getSystemService("window");
        int rotation = manager.getDefaultDisplay().getRotation();
        if (num == 0) {
            if (!AndroidUtilities.isTablet() && ApplicationLoader.applicationContext.getResources().getConfiguration().orientation == 2) {
                this.selectedMessagesCountTextView.setTextSize(18);
            } else {
                this.selectedMessagesCountTextView.setTextSize(20);
            }
        }
        if (AndroidUtilities.isTablet()) {
            this.columnsCount = 4;
            this.mediaPages[num].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(128.0f));
        } else if (rotation == 3 || rotation == 1) {
            this.columnsCount = 6;
            this.mediaPages[num].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), 0);
        } else {
            this.columnsCount = 4;
            this.mediaPages[num].emptyTextView.setPadding(AndroidUtilities.dp(40.0f), 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(128.0f));
        }
        if (num == 0) {
            this.photoVideoAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.MediaActivity$16, reason: invalid class name */
    class AnonymousClass16 implements SharedLinkCell.SharedLinkCellDelegate {
        AnonymousClass16() {
        }

        @Override // im.uwrkaxlmjj.ui.cells.SharedLinkCell.SharedLinkCellDelegate
        public void needOpenWebView(TLRPC.WebPage webPage) {
            MediaActivity.this.openWebView(webPage);
        }

        @Override // im.uwrkaxlmjj.ui.cells.SharedLinkCell.SharedLinkCellDelegate
        public boolean canPerformActions() {
            return !MediaActivity.this.actionBar.isActionModeShowed();
        }

        @Override // im.uwrkaxlmjj.ui.cells.SharedLinkCell.SharedLinkCellDelegate
        public void onLinkLongPress(final String urlFinal) {
            BottomSheet.Builder builder = new BottomSheet.Builder(MediaActivity.this.getParentActivity());
            builder.setTitle(urlFinal);
            builder.setItems(new CharSequence[]{LocaleController.getString("Open", R.string.Open), LocaleController.getString("Copy", R.string.Copy)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$16$jvY3ATs1i-UT_nemqXzlEeqdWgE
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onLinkLongPress$0$MediaActivity$16(urlFinal, dialogInterface, i);
                }
            });
            MediaActivity.this.showDialog(builder.create());
        }

        public /* synthetic */ void lambda$onLinkLongPress$0$MediaActivity$16(String urlFinal, DialogInterface dialog, int which) {
            if (which == 0) {
                Browser.openUrl((Context) MediaActivity.this.getParentActivity(), urlFinal, true);
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
    }

    private class SharedLinksAdapter extends RecyclerListView.SectionsAdapter {
        private Context mContext;

        public SharedLinksAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return row != 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            int size = MediaActivity.this.sharedMediaData[3].sections.size();
            int i = 1;
            if (MediaActivity.this.sharedMediaData[3].sections.isEmpty() || (MediaActivity.this.sharedMediaData[3].endReached[0] && MediaActivity.this.sharedMediaData[3].endReached[1])) {
                i = 0;
            }
            return size + i;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            if (section < MediaActivity.this.sharedMediaData[3].sections.size()) {
                return ((ArrayList) MediaActivity.this.sharedMediaData[3].sectionArrays.get(MediaActivity.this.sharedMediaData[3].sections.get(section))).size() + 1;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            if (view == null) {
                view = new GraySectionCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_graySection) & (-218103809));
            }
            if (section < MediaActivity.this.sharedMediaData[3].sections.size()) {
                String name = (String) MediaActivity.this.sharedMediaData[3].sections.get(section);
                ArrayList<MessageObject> messageObjects = (ArrayList) MediaActivity.this.sharedMediaData[3].sectionArrays.get(name);
                MessageObject messageObject = messageObjects.get(0);
                ((GraySectionCell) view).setText(LocaleController.formatSectionDate(messageObject.messageOwner.date));
            }
            return view;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new GraySectionCell(this.mContext);
            } else if (viewType == 1) {
                view = new SharedLinkCell(this.mContext);
                ((SharedLinkCell) view).setDelegate(MediaActivity.this.sharedLinkCellDelegate);
            } else {
                view = new LoadingCell(this.mContext, AndroidUtilities.dp(32.0f), AndroidUtilities.dp(54.0f));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            if (holder.getItemViewType() != 2) {
                String name = (String) MediaActivity.this.sharedMediaData[3].sections.get(section);
                ArrayList<MessageObject> messageObjects = (ArrayList) MediaActivity.this.sharedMediaData[3].sectionArrays.get(name);
                int itemViewType = holder.getItemViewType();
                if (itemViewType == 0) {
                    ((GraySectionCell) holder.itemView).setText(LocaleController.formatSectionDate(messageObjects.get(0).messageOwner.date));
                    return;
                }
                if (itemViewType == 1) {
                    SharedLinkCell sharedLinkCell = (SharedLinkCell) holder.itemView;
                    MessageObject messageObject = messageObjects.get(position - 1);
                    sharedLinkCell.setLink(messageObject, position != messageObjects.size() || (section == MediaActivity.this.sharedMediaData[3].sections.size() - 1 && MediaActivity.this.sharedMediaData[3].loading));
                    if (MediaActivity.this.actionBar.isActionModeShowed()) {
                        sharedLinkCell.setChecked(MediaActivity.this.selectedFiles[(messageObject.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject.getId()) >= 0, !MediaActivity.this.scrolling);
                    } else {
                        sharedLinkCell.setChecked(false, !MediaActivity.this.scrolling);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            if (section < MediaActivity.this.sharedMediaData[3].sections.size()) {
                if (position == 0) {
                    return 0;
                }
                return 1;
            }
            return 2;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return 0;
        }
    }

    private class SharedDocumentsAdapter extends RecyclerListView.SectionsAdapter {
        private int currentType;
        private Context mContext;

        public SharedDocumentsAdapter(Context context, int type) {
            this.mContext = context;
            this.currentType = type;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return row != 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            int size = MediaActivity.this.sharedMediaData[this.currentType].sections.size();
            int i = 1;
            if (MediaActivity.this.sharedMediaData[this.currentType].sections.isEmpty() || (MediaActivity.this.sharedMediaData[this.currentType].endReached[0] && MediaActivity.this.sharedMediaData[this.currentType].endReached[1])) {
                i = 0;
            }
            return size + i;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            if (section < MediaActivity.this.sharedMediaData[this.currentType].sections.size()) {
                return ((ArrayList) MediaActivity.this.sharedMediaData[this.currentType].sectionArrays.get(MediaActivity.this.sharedMediaData[this.currentType].sections.get(section))).size() + 1;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            if (view == null) {
                view = new GraySectionCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_graySection) & (-218103809));
            }
            if (section < MediaActivity.this.sharedMediaData[this.currentType].sections.size()) {
                String name = (String) MediaActivity.this.sharedMediaData[this.currentType].sections.get(section);
                ArrayList<MessageObject> messageObjects = (ArrayList) MediaActivity.this.sharedMediaData[this.currentType].sectionArrays.get(name);
                MessageObject messageObject = messageObjects.get(0);
                ((GraySectionCell) view).setText(LocaleController.formatSectionDate(messageObject.messageOwner.date));
            }
            return view;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new GraySectionCell(this.mContext);
            } else if (viewType == 1) {
                view = new SharedDocumentCell(this.mContext);
            } else if (viewType == 2) {
                view = new LoadingCell(this.mContext, AndroidUtilities.dp(32.0f), AndroidUtilities.dp(54.0f));
            } else {
                if (this.currentType == 4 && !MediaActivity.this.audioCellCache.isEmpty()) {
                    view = (View) MediaActivity.this.audioCellCache.get(0);
                    MediaActivity.this.audioCellCache.remove(0);
                    ViewGroup p = (ViewGroup) view.getParent();
                    if (p != null) {
                        p.removeView(view);
                    }
                } else {
                    view = new SharedAudioCell(this.mContext) { // from class: im.uwrkaxlmjj.ui.MediaActivity.SharedDocumentsAdapter.1
                        @Override // im.uwrkaxlmjj.ui.cells.SharedAudioCell
                        public boolean needPlayMessage(MessageObject messageObject) {
                            if (messageObject.isVoice() || messageObject.isRoundVideo()) {
                                boolean result = MediaController.getInstance().playMessage(messageObject);
                                MediaController.getInstance().setVoiceMessagesPlaylist(result ? MediaActivity.this.sharedMediaData[SharedDocumentsAdapter.this.currentType].messages : null, false);
                                return result;
                            }
                            if (messageObject.isMusic()) {
                                return MediaController.getInstance().setPlaylist(MediaActivity.this.sharedMediaData[SharedDocumentsAdapter.this.currentType].messages, messageObject);
                            }
                            return false;
                        }
                    };
                }
                if (this.currentType == 4) {
                    MediaActivity.this.audioCache.add((SharedAudioCell) view);
                }
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            if (holder.getItemViewType() != 2) {
                String name = (String) MediaActivity.this.sharedMediaData[this.currentType].sections.get(section);
                ArrayList<MessageObject> messageObjects = (ArrayList) MediaActivity.this.sharedMediaData[this.currentType].sectionArrays.get(name);
                int itemViewType = holder.getItemViewType();
                if (itemViewType == 0) {
                    ((GraySectionCell) holder.itemView).setText(LocaleController.formatSectionDate(messageObjects.get(0).messageOwner.date));
                    return;
                }
                if (itemViewType == 1) {
                    SharedDocumentCell sharedDocumentCell = (SharedDocumentCell) holder.itemView;
                    MessageObject messageObject = messageObjects.get(position - 1);
                    sharedDocumentCell.setDocument(messageObject, position != messageObjects.size() || (section == MediaActivity.this.sharedMediaData[this.currentType].sections.size() - 1 && MediaActivity.this.sharedMediaData[this.currentType].loading));
                    if (MediaActivity.this.actionBar.isActionModeShowed()) {
                        sharedDocumentCell.setChecked(MediaActivity.this.selectedFiles[(messageObject.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject.getId()) >= 0, true ^ MediaActivity.this.scrolling);
                        return;
                    } else {
                        sharedDocumentCell.setChecked(false, true ^ MediaActivity.this.scrolling);
                        return;
                    }
                }
                if (itemViewType == 3) {
                    SharedAudioCell sharedAudioCell = (SharedAudioCell) holder.itemView;
                    MessageObject messageObject2 = messageObjects.get(position - 1);
                    sharedAudioCell.setMessageObject(messageObject2, position != messageObjects.size() || (section == MediaActivity.this.sharedMediaData[this.currentType].sections.size() - 1 && MediaActivity.this.sharedMediaData[this.currentType].loading));
                    if (MediaActivity.this.actionBar.isActionModeShowed()) {
                        sharedAudioCell.setChecked(MediaActivity.this.selectedFiles[(messageObject2.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject2.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject2.getId()) >= 0, true ^ MediaActivity.this.scrolling);
                    } else {
                        sharedAudioCell.setChecked(false, true ^ MediaActivity.this.scrolling);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            if (section >= MediaActivity.this.sharedMediaData[this.currentType].sections.size()) {
                return 2;
            }
            if (position == 0) {
                return 0;
            }
            int i = this.currentType;
            if (i == 2 || i == 4) {
                return 3;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return 0;
        }
    }

    private class SharedPhotoVideoAdapter extends RecyclerListView.SectionsAdapter {
        private Context mContext;

        public SharedPhotoVideoAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return false;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            int i = 0;
            int size = MediaActivity.this.sharedMediaData[0].sections.size();
            if (!MediaActivity.this.sharedMediaData[0].sections.isEmpty() && (!MediaActivity.this.sharedMediaData[0].endReached[0] || !MediaActivity.this.sharedMediaData[0].endReached[1])) {
                i = 1;
            }
            return size + i;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            if (section < MediaActivity.this.sharedMediaData[0].sections.size()) {
                return ((int) Math.ceil(((ArrayList) MediaActivity.this.sharedMediaData[0].sectionArrays.get(MediaActivity.this.sharedMediaData[0].sections.get(section))).size() / MediaActivity.this.columnsCount)) + 1;
            }
            return 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            if (view == null) {
                view = new SharedMediaSectionCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite) & (-436207617));
            }
            if (section < MediaActivity.this.sharedMediaData[0].sections.size()) {
                String name = (String) MediaActivity.this.sharedMediaData[0].sections.get(section);
                ArrayList<MessageObject> messageObjects = (ArrayList) MediaActivity.this.sharedMediaData[0].sectionArrays.get(name);
                MessageObject messageObject = messageObjects.get(0);
                ((SharedMediaSectionCell) view).setText(LocaleController.formatSectionDate(messageObject.messageOwner.date));
            }
            return view;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new SharedMediaSectionCell(this.mContext);
            } else if (viewType == 1) {
                if (!MediaActivity.this.cellCache.isEmpty()) {
                    view = (View) MediaActivity.this.cellCache.get(0);
                    MediaActivity.this.cellCache.remove(0);
                    ViewGroup p = (ViewGroup) view.getParent();
                    if (p != null) {
                        p.removeView(view);
                    }
                } else {
                    view = new SharedPhotoVideoCell(this.mContext);
                }
                SharedPhotoVideoCell cell = (SharedPhotoVideoCell) view;
                cell.setDelegate(new SharedPhotoVideoCell.SharedPhotoVideoCellDelegate() { // from class: im.uwrkaxlmjj.ui.MediaActivity.SharedPhotoVideoAdapter.1
                    @Override // im.uwrkaxlmjj.ui.cells.SharedPhotoVideoCell.SharedPhotoVideoCellDelegate
                    public void didClickItem(SharedPhotoVideoCell cell2, int index, MessageObject messageObject, int a) {
                        MediaActivity.this.onItemClick(index, cell2, messageObject, a, 0);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.SharedPhotoVideoCell.SharedPhotoVideoCellDelegate
                    public boolean didLongClickItem(SharedPhotoVideoCell cell2, int index, MessageObject messageObject, int a) {
                        if (!MediaActivity.this.actionBar.isActionModeShowed()) {
                            return MediaActivity.this.onItemLongClick(messageObject, cell2, a);
                        }
                        didClickItem(cell2, index, messageObject, a);
                        return true;
                    }
                });
                MediaActivity.this.cache.add((SharedPhotoVideoCell) view);
            } else {
                view = new LoadingCell(this.mContext, AndroidUtilities.dp(32.0f), AndroidUtilities.dp(74.0f));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            if (holder.getItemViewType() != 2) {
                String name = (String) MediaActivity.this.sharedMediaData[0].sections.get(section);
                ArrayList<MessageObject> messageObjects = (ArrayList) MediaActivity.this.sharedMediaData[0].sectionArrays.get(name);
                int itemViewType = holder.getItemViewType();
                if (itemViewType == 0) {
                    ((SharedMediaSectionCell) holder.itemView).setText(LocaleController.formatSectionDate(messageObjects.get(0).messageOwner.date));
                    return;
                }
                if (itemViewType == 1) {
                    SharedPhotoVideoCell cell = (SharedPhotoVideoCell) holder.itemView;
                    cell.setItemsCount(MediaActivity.this.columnsCount);
                    cell.setIsFirst(position == 1);
                    for (int a = 0; a < MediaActivity.this.columnsCount; a++) {
                        int index = ((position - 1) * MediaActivity.this.columnsCount) + a;
                        if (index < messageObjects.size()) {
                            MessageObject messageObject = messageObjects.get(index);
                            cell.setItem(a, MediaActivity.this.sharedMediaData[0].messages.indexOf(messageObject), messageObject);
                            if (MediaActivity.this.actionBar.isActionModeShowed()) {
                                cell.setChecked(a, MediaActivity.this.selectedFiles[(messageObject.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject.getId()) >= 0, !MediaActivity.this.scrolling);
                            } else {
                                cell.setChecked(a, false, !MediaActivity.this.scrolling);
                            }
                        } else {
                            cell.setItem(a, index, null);
                        }
                    }
                    cell.requestLayout();
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            if (section < MediaActivity.this.sharedMediaData[0].sections.size()) {
                return position == 0 ? 0 : 1;
            }
            return 2;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return 0;
        }
    }

    public class MediaSearchAdapter extends RecyclerListView.SelectionAdapter {
        private int currentType;
        private int lastReqId;
        private Context mContext;
        private Runnable searchRunnable;
        private int searchesInProgress;
        private ArrayList<MessageObject> searchResult = new ArrayList<>();
        protected ArrayList<MessageObject> globalSearch = new ArrayList<>();
        private int reqId = 0;

        public MediaSearchAdapter(Context context, int type) {
            this.mContext = context;
            this.currentType = type;
        }

        public void queryServerSearch(String query, final int max_id, long did) {
            int uid = (int) did;
            if (uid == 0) {
                return;
            }
            if (this.reqId != 0) {
                ConnectionsManager.getInstance(MediaActivity.this.currentAccount).cancelRequest(this.reqId, true);
                this.reqId = 0;
                this.searchesInProgress--;
            }
            if (query == null || query.length() == 0) {
                this.globalSearch.clear();
                this.lastReqId = 0;
                notifyDataSetChanged();
                return;
            }
            TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
            req.limit = 50;
            req.offset_id = max_id;
            int i = this.currentType;
            if (i == 1) {
                req.filter = new TLRPC.TL_inputMessagesFilterDocument();
            } else if (i == 3) {
                req.filter = new TLRPC.TL_inputMessagesFilterUrl();
            } else if (i == 4) {
                req.filter = new TLRPC.TL_inputMessagesFilterMusic();
            }
            req.q = query;
            req.peer = MessagesController.getInstance(MediaActivity.this.currentAccount).getInputPeer(uid);
            if (req.peer == null) {
                return;
            }
            final int currentReqId = this.lastReqId + 1;
            this.lastReqId = currentReqId;
            this.searchesInProgress++;
            this.reqId = ConnectionsManager.getInstance(MediaActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$MediaSearchAdapter$TF3G7krfy4tNpiUnLWJoSbHkJy0
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$queryServerSearch$1$MediaActivity$MediaSearchAdapter(max_id, currentReqId, tLObject, tL_error);
                }
            }, 2);
            ConnectionsManager.getInstance(MediaActivity.this.currentAccount).bindRequestToGuid(this.reqId, MediaActivity.this.classGuid);
        }

        public /* synthetic */ void lambda$queryServerSearch$1$MediaActivity$MediaSearchAdapter(int max_id, final int currentReqId, TLObject response, TLRPC.TL_error error) {
            final ArrayList<MessageObject> messageObjects = new ArrayList<>();
            if (error == null) {
                TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
                for (int a = 0; a < res.messages.size(); a++) {
                    TLRPC.Message message = res.messages.get(a);
                    if (max_id == 0 || message.id <= max_id) {
                        messageObjects.add(new MessageObject(MediaActivity.this.currentAccount, message, false));
                    }
                }
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$MediaSearchAdapter$_6H4FwJmGZWPb8ZNEWMMgPZ9KfM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$MediaActivity$MediaSearchAdapter(currentReqId, messageObjects);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$MediaActivity$MediaSearchAdapter(int currentReqId, ArrayList messageObjects) {
            if (this.reqId != 0) {
                if (currentReqId == this.lastReqId) {
                    this.globalSearch = messageObjects;
                    this.searchesInProgress--;
                    int count = getItemCount();
                    notifyDataSetChanged();
                    int a = 0;
                    while (true) {
                        if (a < MediaActivity.this.mediaPages.length) {
                            if (MediaActivity.this.mediaPages[a].listView.getAdapter() == this && count == 0 && MediaActivity.this.actionBar.getTranslationY() != 0.0f) {
                                MediaActivity.this.mediaPages[a].layoutManager.scrollToPositionWithOffset(0, (int) MediaActivity.this.actionBar.getTranslationY());
                                break;
                            }
                            a++;
                        } else {
                            break;
                        }
                    }
                }
                this.reqId = 0;
            }
        }

        public void search(final String query) {
            Runnable runnable = this.searchRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.searchRunnable = null;
            }
            if (TextUtils.isEmpty(query)) {
                if (!this.searchResult.isEmpty() || !this.globalSearch.isEmpty() || this.searchesInProgress != 0) {
                    this.searchResult.clear();
                    this.globalSearch.clear();
                    if (this.reqId != 0) {
                        ConnectionsManager.getInstance(MediaActivity.this.currentAccount).cancelRequest(this.reqId, true);
                        this.reqId = 0;
                        this.searchesInProgress--;
                    }
                }
                notifyDataSetChanged();
                return;
            }
            for (int a = 0; a < MediaActivity.this.mediaPages.length; a++) {
                if (MediaActivity.this.mediaPages[a].selectedType == this.currentType) {
                    if (getItemCount() != 0) {
                        MediaActivity.this.mediaPages[a].listView.setEmptyView(MediaActivity.this.mediaPages[a].emptyView);
                        MediaActivity.this.mediaPages[a].progressView.setVisibility(8);
                    } else {
                        MediaActivity.this.mediaPages[a].listView.setEmptyView(null);
                        MediaActivity.this.mediaPages[a].emptyView.setVisibility(8);
                        MediaActivity.this.mediaPages[a].progressView.setVisibility(0);
                    }
                }
            }
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$MediaSearchAdapter$F4fXltISIg6hpXFrzINYXYvVtJk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$search$3$MediaActivity$MediaSearchAdapter(query);
                }
            };
            this.searchRunnable = runnable2;
            AndroidUtilities.runOnUIThread(runnable2, 300L);
        }

        public /* synthetic */ void lambda$search$3$MediaActivity$MediaSearchAdapter(final String query) {
            int i;
            if (!MediaActivity.this.sharedMediaData[this.currentType].messages.isEmpty() && ((i = this.currentType) == 1 || i == 4)) {
                MessageObject messageObject = (MessageObject) MediaActivity.this.sharedMediaData[this.currentType].messages.get(MediaActivity.this.sharedMediaData[this.currentType].messages.size() - 1);
                queryServerSearch(query, messageObject.getId(), messageObject.getDialogId());
            } else if (this.currentType == 3) {
                queryServerSearch(query, 0, MediaActivity.this.dialog_id);
            }
            int i2 = this.currentType;
            if (i2 == 1 || i2 == 4) {
                final ArrayList<MessageObject> copy = new ArrayList<>(MediaActivity.this.sharedMediaData[this.currentType].messages);
                this.searchesInProgress++;
                Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$MediaSearchAdapter$FT-8XsyE3IruvRt-ocCjvnHrFkA
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$MediaActivity$MediaSearchAdapter(query, copy);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$null$2$MediaActivity$MediaSearchAdapter(String query, ArrayList copy) {
            TLRPC.Document document;
            String search1 = query.trim().toLowerCase();
            if (search1.length() == 0) {
                updateSearchResults(new ArrayList<>());
                return;
            }
            String search2 = LocaleController.getInstance().getTranslitString(search1);
            if (search1.equals(search2) || search2.length() == 0) {
                search2 = null;
            }
            String[] search = new String[(search2 != null ? 1 : 0) + 1];
            search[0] = search1;
            if (search2 != null) {
                search[1] = search2;
            }
            ArrayList<MessageObject> resultArray = new ArrayList<>();
            for (int a = 0; a < copy.size(); a++) {
                MessageObject messageObject = (MessageObject) copy.get(a);
                int b = 0;
                while (true) {
                    if (b < search.length) {
                        String q = search[b];
                        String name = messageObject.getDocumentName();
                        if (name != null && name.length() != 0) {
                            if (name.toLowerCase().contains(q)) {
                                resultArray.add(messageObject);
                                break;
                            }
                            if (this.currentType == 4) {
                                if (messageObject.type == 0) {
                                    document = messageObject.messageOwner.media.webpage.document;
                                } else {
                                    document = messageObject.messageOwner.media.document;
                                }
                                boolean ok = false;
                                int c = 0;
                                while (true) {
                                    if (c >= document.attributes.size()) {
                                        break;
                                    }
                                    TLRPC.DocumentAttribute attribute = document.attributes.get(c);
                                    if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                                        c++;
                                    } else {
                                        if (attribute.performer != null) {
                                            ok = attribute.performer.toLowerCase().contains(q);
                                        }
                                        if (!ok && attribute.title != null) {
                                            ok = attribute.title.toLowerCase().contains(q);
                                        }
                                    }
                                }
                                if (ok) {
                                    resultArray.add(messageObject);
                                    break;
                                }
                            } else {
                                continue;
                            }
                        }
                        b++;
                    }
                }
            }
            updateSearchResults(resultArray);
        }

        private void updateSearchResults(final ArrayList<MessageObject> documents) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$MediaSearchAdapter$OKETPvpvm1802Mf1ues72NonxbY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$4$MediaActivity$MediaSearchAdapter(documents);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$4$MediaActivity$MediaSearchAdapter(ArrayList documents) {
            this.searchesInProgress--;
            this.searchResult = documents;
            int count = getItemCount();
            notifyDataSetChanged();
            for (int a = 0; a < MediaActivity.this.mediaPages.length; a++) {
                if (MediaActivity.this.mediaPages[a].listView.getAdapter() == this && count == 0 && MediaActivity.this.actionBar.getTranslationY() != 0.0f) {
                    MediaActivity.this.mediaPages[a].layoutManager.scrollToPositionWithOffset(0, (int) MediaActivity.this.actionBar.getTranslationY());
                    return;
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
            if (this.searchesInProgress == 0) {
                for (int a = 0; a < MediaActivity.this.mediaPages.length; a++) {
                    if (MediaActivity.this.mediaPages[a].selectedType == this.currentType) {
                        MediaActivity.this.mediaPages[a].listView.setEmptyView(MediaActivity.this.mediaPages[a].emptyView);
                        MediaActivity.this.mediaPages[a].progressView.setVisibility(8);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != this.searchResult.size() + this.globalSearch.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = this.searchResult.size();
            int globalCount = this.globalSearch.size();
            if (globalCount != 0) {
                return count + globalCount;
            }
            return count;
        }

        public boolean isGlobalSearch(int i) {
            int localCount = this.searchResult.size();
            int globalCount = this.globalSearch.size();
            if ((i >= 0 && i < localCount) || i <= localCount || i > globalCount + localCount) {
                return false;
            }
            return true;
        }

        public MessageObject getItem(int i) {
            if (i < this.searchResult.size()) {
                return this.searchResult.get(i);
            }
            return this.globalSearch.get(i - this.searchResult.size());
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            int i = this.currentType;
            if (i == 1) {
                view = new SharedDocumentCell(this.mContext);
            } else if (i == 4) {
                view = new SharedAudioCell(this.mContext) { // from class: im.uwrkaxlmjj.ui.MediaActivity.MediaSearchAdapter.1
                    @Override // im.uwrkaxlmjj.ui.cells.SharedAudioCell
                    public boolean needPlayMessage(MessageObject messageObject) {
                        if (messageObject.isVoice() || messageObject.isRoundVideo()) {
                            boolean result = MediaController.getInstance().playMessage(messageObject);
                            MediaController.getInstance().setVoiceMessagesPlaylist(result ? MediaSearchAdapter.this.searchResult : null, false);
                            if (messageObject.isRoundVideo()) {
                                MediaController.getInstance().setCurrentVideoVisible(false);
                            }
                            return result;
                        }
                        if (messageObject.isMusic()) {
                            return MediaController.getInstance().setPlaylist(MediaSearchAdapter.this.searchResult, messageObject);
                        }
                        return false;
                    }
                };
            } else {
                view = new SharedLinkCell(this.mContext);
                ((SharedLinkCell) view).setDelegate(MediaActivity.this.sharedLinkCellDelegate);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int i = this.currentType;
            if (i == 1) {
                SharedDocumentCell sharedDocumentCell = (SharedDocumentCell) holder.itemView;
                MessageObject messageObject = getItem(position);
                sharedDocumentCell.setDocument(messageObject, position != getItemCount() - 1);
                if (MediaActivity.this.actionBar.isActionModeShowed()) {
                    sharedDocumentCell.setChecked(MediaActivity.this.selectedFiles[(messageObject.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject.getId()) >= 0, true ^ MediaActivity.this.scrolling);
                    return;
                } else {
                    sharedDocumentCell.setChecked(false, true ^ MediaActivity.this.scrolling);
                    return;
                }
            }
            if (i == 3) {
                SharedLinkCell sharedLinkCell = (SharedLinkCell) holder.itemView;
                MessageObject messageObject2 = getItem(position);
                sharedLinkCell.setLink(messageObject2, position != getItemCount() - 1);
                if (MediaActivity.this.actionBar.isActionModeShowed()) {
                    sharedLinkCell.setChecked(MediaActivity.this.selectedFiles[(messageObject2.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject2.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject2.getId()) >= 0, true ^ MediaActivity.this.scrolling);
                    return;
                } else {
                    sharedLinkCell.setChecked(false, true ^ MediaActivity.this.scrolling);
                    return;
                }
            }
            if (i == 4) {
                SharedAudioCell sharedAudioCell = (SharedAudioCell) holder.itemView;
                MessageObject messageObject3 = getItem(position);
                sharedAudioCell.setMessageObject(messageObject3, position != getItemCount() - 1);
                if (MediaActivity.this.actionBar.isActionModeShowed()) {
                    sharedAudioCell.setChecked(MediaActivity.this.selectedFiles[(messageObject3.getDialogId() > MediaActivity.this.dialog_id ? 1 : (messageObject3.getDialogId() == MediaActivity.this.dialog_id ? 0 : -1)) == 0 ? (char) 0 : (char) 1].indexOfKey(messageObject3.getId()) >= 0, true ^ MediaActivity.this.scrolling);
                } else {
                    sharedAudioCell.setChecked(false, true ^ MediaActivity.this.scrolling);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            return 0;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ArrayList<ThemeDescription> arrayList = new ArrayList<>();
        arrayList.add(new ThemeDescription(this.fragmentView, 0, null, null, null, null, Theme.key_windowBackgroundWhite));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUBACKGROUND, null, null, null, null, Theme.key_actionBarDefaultSubmenuBackground));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM, null, null, null, null, Theme.key_actionBarDefaultSubmenuItem));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SUBMENUITEM | ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubmenuItemIcon));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        arrayList.add(new ThemeDescription(this.actionModeBackground, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_sharedMedia_actionMode));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_AM_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder));
        arrayList.add(new ThemeDescription(this.selectedMessagesCountTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        arrayList.add(new ThemeDescription(this.fragmentContextView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{FragmentContextView.class}, new String[]{"frameLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerBackground));
        arrayList.add(new ThemeDescription(this.fragmentContextView, 0, new Class[]{FragmentContextView.class}, new String[]{"playButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerPlayPause));
        arrayList.add(new ThemeDescription(this.fragmentContextView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{FragmentContextView.class}, new String[]{"titleTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerTitle));
        arrayList.add(new ThemeDescription(this.fragmentContextView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{FragmentContextView.class}, new String[]{"frameLayout"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerPerformer));
        arrayList.add(new ThemeDescription(this.fragmentContextView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{FragmentContextView.class}, new String[]{"closeButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_inappPlayerClose));
        arrayList.add(new ThemeDescription(this.scrollSlidingTextTabStrip.getTabsContainer(), ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextView.class}, null, null, null, Theme.key_actionBarTabActiveText));
        arrayList.add(new ThemeDescription(this.scrollSlidingTextTabStrip.getTabsContainer(), ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextView.class}, null, null, null, Theme.key_actionBarTabUnactiveText));
        arrayList.add(new ThemeDescription(this.scrollSlidingTextTabStrip.getTabsContainer(), ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, new Class[]{TextView.class}, null, null, null, Theme.key_actionBarTabLine));
        arrayList.add(new ThemeDescription(null, 0, null, null, new Drawable[]{this.scrollSlidingTextTabStrip.getSelectorDrawable()}, null, Theme.key_actionBarTabSelector));
        for (int a = 0; a < this.mediaPages.length; a++) {
            final int num = a;
            ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$MediaActivity$1zS5jfKLU-jffLzGRROr2vfmJ5o
                @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
                public final void didSetColor() {
                    this.f$0.lambda$getThemeDescriptions$5$MediaActivity(num);
                }
            };
            arrayList.add(new ThemeDescription(this.mediaPages[a].emptyView, 0, null, null, null, null, Theme.key_windowBackgroundGray));
            arrayList.add(new ThemeDescription(this.mediaPages[a].progressView, 0, null, null, null, null, Theme.key_windowBackgroundGray));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector));
            arrayList.add(new ThemeDescription(this.mediaPages[a].emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder));
            arrayList.add(new ThemeDescription(this.mediaPages[a].progressBar, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle));
            arrayList.add(new ThemeDescription(this.mediaPages[a].emptyTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_SECTIONS, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR | ThemeDescription.FLAG_SECTIONS, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"dateTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_PROGRESSBAR, new Class[]{SharedDocumentCell.class}, new String[]{"progressView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_sharedMedia_startStopLoadIcon));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"statusImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_sharedMedia_startStopLoadIcon));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{SharedDocumentCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkbox));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{SharedDocumentCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkboxCheck));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"thumbImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_files_folderIcon));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedDocumentCell.class}, new String[]{"extTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_files_iconText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{LoadingCell.class}, new String[]{"progressBar"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_progressCircle));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{SharedAudioCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkbox));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{SharedAudioCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkboxCheck));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedAudioCell.class}, Theme.chat_contextResult_titleTextPaint, null, null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{SharedAudioCell.class}, Theme.chat_contextResult_descriptionTextPaint, null, null, Theme.key_windowBackgroundWhiteGrayText2));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{SharedLinkCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkbox));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{SharedLinkCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_checkboxCheck));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{SharedLinkCell.class}, new String[]{"titleTextPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{SharedLinkCell.class}, null, null, null, Theme.key_windowBackgroundWhiteLinkText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{SharedLinkCell.class}, Theme.linkSelectionPaint, null, null, Theme.key_windowBackgroundWhiteLinkSelection));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{SharedLinkCell.class}, new String[]{"letterDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_sharedMedia_linkPlaceholderText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{SharedLinkCell.class}, new String[]{"letterDrawable"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_sharedMedia_linkPlaceholder));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR | ThemeDescription.FLAG_SECTIONS, new Class[]{SharedMediaSectionCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_SECTIONS, new Class[]{SharedMediaSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{SharedMediaSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, new Class[]{SharedPhotoVideoCell.class}, new String[]{"backgroundPaint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_sharedMedia_photoPlaceholder));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOX, new Class[]{SharedPhotoVideoCell.class}, null, null, cellDelegate, Theme.key_checkbox));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, ThemeDescription.FLAG_CHECKBOXCHECK, new Class[]{SharedPhotoVideoCell.class}, null, null, cellDelegate, Theme.key_checkboxCheck));
            arrayList.add(new ThemeDescription(this.mediaPages[a].listView, 0, null, null, new Drawable[]{this.pinnedHeaderShadowDrawable}, null, Theme.key_windowBackgroundGrayShadow));
        }
        return (ThemeDescription[]) arrayList.toArray(new ThemeDescription[0]);
    }

    public /* synthetic */ void lambda$getThemeDescriptions$5$MediaActivity(int num) {
        if (this.mediaPages[num].listView != null) {
            int count = this.mediaPages[num].listView.getChildCount();
            for (int a1 = 0; a1 < count; a1++) {
                View child = this.mediaPages[num].listView.getChildAt(a1);
                if (child instanceof SharedPhotoVideoCell) {
                    ((SharedPhotoVideoCell) child).updateCheckboxColor();
                }
            }
        }
    }
}
