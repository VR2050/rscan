package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.database.DataSetObserver;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.ShapeDrawable;
import android.os.Build;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.LongSparseArray;
import android.util.Property;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.EmojiData;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContentPreviewViewer;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ContextLinkCell;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.FeaturedStickerSetInfoCell;
import im.uwrkaxlmjj.ui.cells.StickerEmojiCell;
import im.uwrkaxlmjj.ui.cells.StickerSetGroupInfoCell;
import im.uwrkaxlmjj.ui.cells.StickerSetNameCell;
import im.uwrkaxlmjj.ui.components.PagerSlidingTabStrip;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.ScrollSlidingTabStrip;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class EmojiViewV2 extends FrameLayout implements NotificationCenter.NotificationCenterDelegate {
    private static final ViewTreeObserver.OnScrollChangedListener NOP;
    private static final Field superListenerField;
    private ImageView backspaceButton;
    private AnimatorSet backspaceButtonAnimation;
    private boolean backspaceOnce;
    private boolean backspacePressed;
    private FrameLayout bottomTabContainer;
    private AnimatorSet bottomTabContainerAnimation;
    private View bottomTabContainerBackground;
    private ContentPreviewViewer.ContentPreviewViewerDelegate contentPreviewViewerDelegate;
    private int currentAccount;
    private int currentBackgroundType;
    private int currentChatId;
    private int currentPage;
    private EmojiViewDelegate delegate;
    private Paint dotPaint;
    private DragListener dragListener;
    private EmojiGridAdapter emojiAdapter;
    private FrameLayout emojiContainer;
    private RecyclerListView emojiGridView;
    private Drawable[] emojiIcons;
    private float emojiLastX;
    private float emojiLastY;
    private GridLayoutManager emojiLayoutManager;
    private int emojiMinusDy;
    private EmojiSearchAdapter emojiSearchAdapter;
    private SearchField emojiSearchField;
    private int emojiSize;
    private AnimatorSet emojiTabShadowAnimator;
    private ScrollSlidingTabStrip emojiTabs;
    private View emojiTabsShadow;
    private String[] emojiTitles;
    private ImageViewEmoji emojiTouchedView;
    private float emojiTouchedX;
    private float emojiTouchedY;
    private int favTabBum;
    private ArrayList<TLRPC.Document> favouriteStickers;
    private int featuredStickersHash;
    private boolean firstEmojiAttach;
    private boolean firstGifAttach;
    private boolean firstStickersAttach;
    private ImageView floatingButton;
    private boolean forseMultiwindowLayout;
    private GifAdapter gifAdapter;
    private FrameLayout gifContainer;
    private RecyclerListView gifGridView;
    private ExtendedGridLayoutManager gifLayoutManager;
    private RecyclerListView.OnItemClickListener gifOnItemClickListener;
    private GifSearchAdapter gifSearchAdapter;
    private SearchField gifSearchField;
    private int groupStickerPackNum;
    private int groupStickerPackPosition;
    private TLRPC.TL_messages_stickerSet groupStickerSet;
    private boolean groupStickersHidden;
    private int hasRecentEmoji;
    private TLRPC.ChatFull info;
    private LongSparseArray<TLRPC.StickerSetCovered> installingStickerSets;
    private boolean isLayout;
    private float lastBottomScrollDy;
    private int lastNotifyHeight;
    private int lastNotifyHeight2;
    private int lastNotifyWidth;
    private String[] lastSearchKeyboardLanguage;
    private int[] location;
    private TextView mediaBanTooltip;
    private boolean needEmojiSearch;
    private Object outlineProvider;
    private ViewPager pager;
    private EmojiColorPickerView pickerView;
    private EmojiPopupWindow pickerViewPopup;
    private int popupHeight;
    private int popupWidth;
    private ArrayList<TLRPC.Document> recentGifs;
    private ArrayList<TLRPC.Document> recentStickers;
    private int recentTabBum;
    private LongSparseArray<TLRPC.StickerSetCovered> removingStickerSets;
    private int scrolledToTrending;
    private AnimatorSet searchAnimation;
    private ImageView searchButton;
    private int searchFieldHeight;
    private View shadowLine;
    private boolean showGifs;
    private Drawable[] stickerIcons;
    private ArrayList<TLRPC.TL_messages_stickerSet> stickerSets;
    private ImageView stickerSettingsButton;
    private AnimatorSet stickersButtonAnimation;
    private FrameLayout stickersContainer;
    private TextView stickersCounter;
    private StickersGridAdapter stickersGridAdapter;
    private RecyclerListView stickersGridView;
    private GridLayoutManager stickersLayoutManager;
    private int stickersMinusDy;
    private RecyclerListView.OnItemClickListener stickersOnItemClickListener;
    private SearchField stickersSearchField;
    private StickersSearchGridAdapter stickersSearchGridAdapter;
    private ScrollSlidingTabStrip stickersTab;
    private int stickersTabOffset;
    private Drawable[] tabIcons;
    private View topShadow;
    private TrendingGridAdapter trendingGridAdapter;
    private RecyclerListView trendingGridView;
    private GridLayoutManager trendingLayoutManager;
    private boolean trendingLoaded;
    private int trendingTabNum;
    private PagerSlidingTabStrip typeTabs;
    private ArrayList<View> views;

    public interface DragListener {
        void onDrag(int i);

        void onDragCancel();

        void onDragEnd(float f);

        void onDragStart();
    }

    public interface EmojiViewDelegate {
        boolean canSchedule();

        boolean isExpanded();

        boolean isInScheduleMode();

        boolean isSearchOpened();

        boolean onBackspace();

        void onClearEmojiRecent();

        void onEmojiSelected(String str);

        void onGifSelected(View view, Object obj, Object obj2, boolean z, int i);

        void onSearchOpenClose(int i);

        void onShowStickerSet(TLRPC.StickerSet stickerSet, TLRPC.InputStickerSet inputStickerSet);

        void onStickerSelected(View view, TLRPC.Document document, Object obj, boolean z, int i);

        void onStickerSetAdd(TLRPC.StickerSetCovered stickerSetCovered);

        void onStickerSetRemove(TLRPC.StickerSetCovered stickerSetCovered);

        void onStickersGroupClick(int i);

        void onStickersSettingsClick();

        void onTabOpened(int i);

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.EmojiViewV2$EmojiViewDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static boolean $default$onBackspace(EmojiViewDelegate _this) {
                return false;
            }

            public static void $default$onEmojiSelected(EmojiViewDelegate _this, String emoji) {
            }

            public static void $default$onStickerSelected(EmojiViewDelegate _this, View view, TLRPC.Document sticker, Object parent, boolean notify, int scheduleDate) {
            }

            public static void $default$onStickersSettingsClick(EmojiViewDelegate _this) {
            }

            public static void $default$onStickersGroupClick(EmojiViewDelegate _this, int chatId) {
            }

            public static void $default$onGifSelected(EmojiViewDelegate _this, View view, Object gif, Object parent, boolean notify, int scheduleDate) {
            }

            public static void $default$onTabOpened(EmojiViewDelegate _this, int type) {
            }

            public static void $default$onClearEmojiRecent(EmojiViewDelegate _this) {
            }

            public static void $default$onShowStickerSet(EmojiViewDelegate _this, TLRPC.StickerSet stickerSet, TLRPC.InputStickerSet inputStickerSet) {
            }

            public static void $default$onStickerSetAdd(EmojiViewDelegate _this, TLRPC.StickerSetCovered stickerSet) {
            }

            public static void $default$onStickerSetRemove(EmojiViewDelegate _this, TLRPC.StickerSetCovered stickerSet) {
            }

            public static void $default$onSearchOpenClose(EmojiViewDelegate _this, int type) {
            }

            public static boolean $default$isSearchOpened(EmojiViewDelegate _this) {
                return false;
            }

            public static boolean $default$isExpanded(EmojiViewDelegate _this) {
                return false;
            }

            public static boolean $default$canSchedule(EmojiViewDelegate _this) {
                return false;
            }

            public static boolean $default$isInScheduleMode(EmojiViewDelegate _this) {
                return false;
            }
        }
    }

    static {
        Field f = null;
        try {
            f = PopupWindow.class.getDeclaredField("mOnScrollChangedListener");
            f.setAccessible(true);
        } catch (NoSuchFieldException e) {
        }
        superListenerField = f;
        NOP = new ViewTreeObserver.OnScrollChangedListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$sp-qQbvWN1U_O5LA896LH07sMqI
            @Override // android.view.ViewTreeObserver.OnScrollChangedListener
            public final void onScrollChanged() {
                EmojiViewV2.lambda$static$0();
            }
        };
    }

    static /* synthetic */ void lambda$static$0() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SearchField extends FrameLayout {
        private View backgroundView;
        private ImageView clearSearchImageView;
        private CloseProgressDrawable2 progressDrawable;
        private View searchBackground;
        private EditTextBoldCursor searchEditText;
        private ImageView searchIconImageView;
        private AnimatorSet shadowAnimator;
        private View shadowView;

        public SearchField(Context context, final int type) {
            super(context);
            View view = new View(context);
            this.shadowView = view;
            view.setAlpha(0.0f);
            this.shadowView.setTag(1);
            this.shadowView.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
            addView(this.shadowView, new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 83));
            View view2 = new View(context);
            this.backgroundView = view2;
            view2.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            addView(this.backgroundView, new FrameLayout.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
            View view3 = new View(context);
            this.searchBackground = view3;
            view3.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(18.0f), Theme.getColor(Theme.key_chat_emojiSearchBackground)));
            addView(this.searchBackground, LayoutHelper.createFrame(-1.0f, 36.0f, 51, 14.0f, 14.0f, 14.0f, 0.0f));
            ImageView imageView = new ImageView(context);
            this.searchIconImageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.searchIconImageView.setImageResource(R.drawable.smiles_inputsearch);
            this.searchIconImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiSearchIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.searchIconImageView, LayoutHelper.createFrame(36.0f, 36.0f, 51, 16.0f, 14.0f, 0.0f, 0.0f));
            ImageView imageView2 = new ImageView(context);
            this.clearSearchImageView = imageView2;
            imageView2.setScaleType(ImageView.ScaleType.CENTER);
            ImageView imageView3 = this.clearSearchImageView;
            CloseProgressDrawable2 closeProgressDrawable2 = new CloseProgressDrawable2();
            this.progressDrawable = closeProgressDrawable2;
            imageView3.setImageDrawable(closeProgressDrawable2);
            this.progressDrawable.setSide(AndroidUtilities.dp(7.0f));
            this.clearSearchImageView.setScaleX(0.1f);
            this.clearSearchImageView.setScaleY(0.1f);
            this.clearSearchImageView.setAlpha(0.0f);
            this.clearSearchImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiSearchIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.clearSearchImageView, LayoutHelper.createFrame(36.0f, 36.0f, 53, 14.0f, 14.0f, 14.0f, 0.0f));
            this.clearSearchImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$SearchField$tLH6wbgZKjcTOhnviGMA95cQivA
                @Override // android.view.View.OnClickListener
                public final void onClick(View view4) {
                    this.f$0.lambda$new$0$EmojiViewV2$SearchField(view4);
                }
            });
            EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.SearchField.1
                @Override // android.widget.TextView, android.view.View
                public boolean onTouchEvent(MotionEvent event) {
                    if (event.getAction() == 0) {
                        if (!EmojiViewV2.this.delegate.isSearchOpened()) {
                            EmojiViewV2.this.openSearch(SearchField.this);
                        }
                        EmojiViewV2.this.delegate.onSearchOpenClose(type == 1 ? 2 : 1);
                        SearchField.this.searchEditText.requestFocus();
                        AndroidUtilities.showKeyboard(SearchField.this.searchEditText);
                        if (EmojiViewV2.this.trendingGridView != null && EmojiViewV2.this.trendingGridView.getVisibility() == 0) {
                            EmojiViewV2.this.showTrendingTab(false);
                        }
                    }
                    return super.onTouchEvent(event);
                }
            };
            this.searchEditText = editTextBoldCursor;
            editTextBoldCursor.setTextSize(1, 16.0f);
            this.searchEditText.setHintTextColor(Theme.getColor(Theme.key_chat_emojiSearchIcon));
            this.searchEditText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.searchEditText.setBackgroundDrawable(null);
            this.searchEditText.setPadding(0, 0, 0, 0);
            this.searchEditText.setMaxLines(1);
            this.searchEditText.setLines(1);
            this.searchEditText.setSingleLine(true);
            this.searchEditText.setImeOptions(268435459);
            if (type == 0) {
                this.searchEditText.setHint(LocaleController.getString("SearchStickersHint", R.string.SearchStickersHint));
            } else if (type == 1) {
                this.searchEditText.setHint(LocaleController.getString("SearchEmojiHint", R.string.SearchEmojiHint));
            } else if (type == 2) {
                this.searchEditText.setHint(LocaleController.getString("SearchGifsTitle", R.string.SearchGifsTitle));
            }
            this.searchEditText.setCursorColor(Theme.getColor(Theme.key_featuredStickers_addedIcon));
            this.searchEditText.setCursorSize(AndroidUtilities.dp(20.0f));
            this.searchEditText.setCursorWidth(1.5f);
            addView(this.searchEditText, LayoutHelper.createFrame(-1.0f, 40.0f, 51, 54.0f, 12.0f, 46.0f, 0.0f));
            this.searchEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.SearchField.2
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    boolean show = SearchField.this.searchEditText.length() > 0;
                    boolean showed = SearchField.this.clearSearchImageView.getAlpha() != 0.0f;
                    if (show != showed) {
                        SearchField.this.clearSearchImageView.animate().alpha(show ? 1.0f : 0.0f).setDuration(150L).scaleX(show ? 1.0f : 0.1f).scaleY(show ? 1.0f : 0.1f).start();
                    }
                    int i = type;
                    if (i == 0) {
                        EmojiViewV2.this.stickersSearchGridAdapter.search(SearchField.this.searchEditText.getText().toString());
                    } else if (i == 1) {
                        EmojiViewV2.this.emojiSearchAdapter.search(SearchField.this.searchEditText.getText().toString());
                    } else if (i == 2) {
                        EmojiViewV2.this.gifSearchAdapter.search(SearchField.this.searchEditText.getText().toString());
                    }
                }
            });
        }

        public /* synthetic */ void lambda$new$0$EmojiViewV2$SearchField(View v) {
            this.searchEditText.setText("");
            AndroidUtilities.showKeyboard(this.searchEditText);
        }

        public void hideKeyboard() {
            AndroidUtilities.hideKeyboard(this.searchEditText);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void showShadow(boolean show, boolean animated) {
            if (show && this.shadowView.getTag() == null) {
                return;
            }
            if (!show && this.shadowView.getTag() != null) {
                return;
            }
            AnimatorSet animatorSet = this.shadowAnimator;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.shadowAnimator = null;
            }
            this.shadowView.setTag(show ? null : 1);
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.shadowAnimator = animatorSet2;
                Animator[] animatorArr = new Animator[1];
                View view = this.shadowView;
                Property property = View.ALPHA;
                float[] fArr = new float[1];
                fArr[0] = show ? 1.0f : 0.0f;
                animatorArr[0] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property, fArr);
                animatorSet2.playTogether(animatorArr);
                this.shadowAnimator.setDuration(200L);
                this.shadowAnimator.setInterpolator(CubicBezierInterpolator.EASE_OUT);
                this.shadowAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.SearchField.3
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        SearchField.this.shadowAnimator = null;
                    }
                });
                this.shadowAnimator.start();
                return;
            }
            this.shadowView.setAlpha(show ? 1.0f : 0.0f);
        }
    }

    private class ImageViewEmoji extends ImageView {
        private boolean isRecent;

        public ImageViewEmoji(Context context) {
            super(context);
            setScaleType(ImageView.ScaleType.CENTER);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void sendEmoji(String override) {
            String color;
            EmojiViewV2.this.showBottomTab(true, true);
            String code = override != null ? override : (String) getTag();
            SpannableStringBuilder builder = new SpannableStringBuilder();
            builder.append((CharSequence) code);
            if (override != null) {
                if (EmojiViewV2.this.delegate != null) {
                    EmojiViewV2.this.delegate.onEmojiSelected(Emoji.fixEmoji(override));
                    return;
                }
                return;
            }
            if (!this.isRecent && (color = Emoji.emojiColor.get(code)) != null) {
                code = EmojiViewV2.addColorToCode(code, color);
            }
            EmojiViewV2.this.addEmojiToRecent(code);
            if (EmojiViewV2.this.delegate != null) {
                EmojiViewV2.this.delegate.onEmojiSelected(Emoji.fixEmoji(code));
            }
        }

        public void setImageDrawable(Drawable drawable, boolean recent) {
            super.setImageDrawable(drawable);
            this.isRecent = recent;
        }

        @Override // android.widget.ImageView, android.view.View
        public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), View.MeasureSpec.getSize(widthMeasureSpec));
        }
    }

    private class EmojiPopupWindow extends PopupWindow {
        private ViewTreeObserver.OnScrollChangedListener mSuperScrollListener;
        private ViewTreeObserver mViewTreeObserver;

        public EmojiPopupWindow() {
            init();
        }

        public EmojiPopupWindow(Context context) {
            super(context);
            init();
        }

        public EmojiPopupWindow(int width, int height) {
            super(width, height);
            init();
        }

        public EmojiPopupWindow(View contentView) {
            super(contentView);
            init();
        }

        public EmojiPopupWindow(View contentView, int width, int height, boolean focusable) {
            super(contentView, width, height, focusable);
            init();
        }

        public EmojiPopupWindow(View contentView, int width, int height) {
            super(contentView, width, height);
            init();
        }

        private void init() {
            if (EmojiViewV2.superListenerField != null) {
                try {
                    this.mSuperScrollListener = (ViewTreeObserver.OnScrollChangedListener) EmojiViewV2.superListenerField.get(this);
                    EmojiViewV2.superListenerField.set(this, EmojiViewV2.NOP);
                } catch (Exception e) {
                    this.mSuperScrollListener = null;
                }
            }
        }

        private void unregisterListener() {
            ViewTreeObserver viewTreeObserver;
            if (this.mSuperScrollListener != null && (viewTreeObserver = this.mViewTreeObserver) != null) {
                if (viewTreeObserver.isAlive()) {
                    this.mViewTreeObserver.removeOnScrollChangedListener(this.mSuperScrollListener);
                }
                this.mViewTreeObserver = null;
            }
        }

        private void registerListener(View anchor) {
            if (this.mSuperScrollListener != null) {
                ViewTreeObserver vto = anchor.getWindowToken() != null ? anchor.getViewTreeObserver() : null;
                ViewTreeObserver viewTreeObserver = this.mViewTreeObserver;
                if (vto != viewTreeObserver) {
                    if (viewTreeObserver != null && viewTreeObserver.isAlive()) {
                        this.mViewTreeObserver.removeOnScrollChangedListener(this.mSuperScrollListener);
                    }
                    this.mViewTreeObserver = vto;
                    if (vto != null) {
                        vto.addOnScrollChangedListener(this.mSuperScrollListener);
                    }
                }
            }
        }

        @Override // android.widget.PopupWindow
        public void showAsDropDown(View anchor, int xoff, int yoff) {
            try {
                super.showAsDropDown(anchor, xoff, yoff);
                registerListener(anchor);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        @Override // android.widget.PopupWindow
        public void update(View anchor, int xoff, int yoff, int width, int height) {
            super.update(anchor, xoff, yoff, width, height);
            registerListener(anchor);
        }

        @Override // android.widget.PopupWindow
        public void update(View anchor, int width, int height) {
            super.update(anchor, width, height);
            registerListener(anchor);
        }

        @Override // android.widget.PopupWindow
        public void showAtLocation(View parent, int gravity, int x, int y) {
            super.showAtLocation(parent, gravity, x, y);
            unregisterListener();
        }

        @Override // android.widget.PopupWindow
        public void dismiss() {
            setFocusable(false);
            try {
                super.dismiss();
            } catch (Exception e) {
            }
            unregisterListener();
        }
    }

    private class EmojiColorPickerView extends View {
        private Drawable arrowDrawable;
        private int arrowX;
        private Drawable backgroundDrawable;
        private String currentEmoji;
        private RectF rect;
        private Paint rectPaint;
        private int selection;

        public void setEmoji(String emoji, int arrowPosition) {
            this.currentEmoji = emoji;
            this.arrowX = arrowPosition;
            this.rectPaint.setColor(Theme.ACTION_BAR_AUDIO_SELECTOR_COLOR);
            invalidate();
        }

        public String getEmoji() {
            return this.currentEmoji;
        }

        public void setSelection(int position) {
            if (this.selection == position) {
                return;
            }
            this.selection = position;
            invalidate();
        }

        public int getSelection() {
            return this.selection;
        }

        public EmojiColorPickerView(Context context) {
            super(context);
            this.rectPaint = new Paint(1);
            this.rect = new RectF();
            this.backgroundDrawable = getResources().getDrawable(R.drawable.stickers_back_all);
            this.arrowDrawable = getResources().getDrawable(R.drawable.stickers_back_arrow);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            String color;
            this.backgroundDrawable.setBounds(0, 0, getMeasuredWidth(), AndroidUtilities.dp(AndroidUtilities.isTablet() ? 60.0f : 52.0f));
            this.backgroundDrawable.draw(canvas);
            this.arrowDrawable.setBounds(this.arrowX - AndroidUtilities.dp(9.0f), AndroidUtilities.dp(AndroidUtilities.isTablet() ? 55.5f : 47.5f), this.arrowX + AndroidUtilities.dp(9.0f), AndroidUtilities.dp((AndroidUtilities.isTablet() ? 55.5f : 47.5f) + 8.0f));
            this.arrowDrawable.draw(canvas);
            if (this.currentEmoji != null) {
                for (int a = 0; a < 6; a++) {
                    int x = (EmojiViewV2.this.emojiSize * a) + AndroidUtilities.dp((a * 4) + 5);
                    int y = AndroidUtilities.dp(9.0f);
                    if (this.selection == a) {
                        this.rect.set(x, y - ((int) AndroidUtilities.dpf2(3.5f)), EmojiViewV2.this.emojiSize + x, EmojiViewV2.this.emojiSize + y + AndroidUtilities.dp(3.0f));
                        canvas.drawRoundRect(this.rect, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(4.0f), this.rectPaint);
                    }
                    String code = this.currentEmoji;
                    if (a != 0) {
                        if (a == 1) {
                            color = "🏻";
                        } else if (a == 2) {
                            color = "🏼";
                        } else if (a == 3) {
                            color = "🏽";
                        } else if (a == 4) {
                            color = "🏾";
                        } else if (a == 5) {
                            color = "🏿";
                        } else {
                            color = "";
                        }
                        code = EmojiViewV2.addColorToCode(code, color);
                    }
                    Drawable drawable = Emoji.getEmojiBigDrawable(code);
                    if (drawable != null) {
                        drawable.setBounds(x, y, EmojiViewV2.this.emojiSize + x, EmojiViewV2.this.emojiSize + y);
                        drawable.draw(canvas);
                    }
                }
            }
        }
    }

    public EmojiViewV2(boolean needStickers, boolean needGif, Context context, boolean needSearch, TLRPC.ChatFull chatFull) {
        super(context);
        this.views = new ArrayList<>();
        this.firstEmojiAttach = true;
        this.hasRecentEmoji = -1;
        this.firstGifAttach = true;
        this.firstStickersAttach = true;
        this.currentAccount = UserConfig.selectedAccount;
        this.stickerSets = new ArrayList<>();
        this.recentGifs = new ArrayList<>();
        this.recentStickers = new ArrayList<>();
        this.favouriteStickers = new ArrayList<>();
        this.installingStickerSets = new LongSparseArray<>();
        this.removingStickerSets = new LongSparseArray<>();
        this.location = new int[2];
        this.recentTabBum = -2;
        this.favTabBum = -2;
        this.trendingTabNum = -2;
        this.currentBackgroundType = -1;
        this.contentPreviewViewerDelegate = new ContentPreviewViewer.ContentPreviewViewerDelegate() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.1
            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public /* synthetic */ boolean needOpen() {
                return ContentPreviewViewer.ContentPreviewViewerDelegate.CC.$default$needOpen(this);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void sendSticker(TLRPC.Document sticker, Object parent, boolean notify, int scheduleDate) {
                EmojiViewV2.this.delegate.onStickerSelected(null, sticker, parent, notify, scheduleDate);
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean needSend() {
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean canSchedule() {
                return EmojiViewV2.this.delegate.canSchedule();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public boolean isInScheduleMode() {
                return EmojiViewV2.this.delegate.isInScheduleMode();
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void openSet(TLRPC.InputStickerSet set, boolean clearsInputField) {
                if (set != null) {
                    EmojiViewV2.this.delegate.onShowStickerSet(null, set);
                }
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void sendGif(Object gif, boolean notify, int scheduleDate) {
                if (EmojiViewV2.this.gifGridView.getAdapter() == EmojiViewV2.this.gifAdapter) {
                    EmojiViewV2.this.delegate.onGifSelected(null, gif, "gif", notify, scheduleDate);
                } else {
                    if (EmojiViewV2.this.gifGridView.getAdapter() != EmojiViewV2.this.gifSearchAdapter) {
                        return;
                    }
                    EmojiViewV2.this.delegate.onGifSelected(null, gif, EmojiViewV2.this.gifSearchAdapter.bot, notify, scheduleDate);
                }
            }

            @Override // im.uwrkaxlmjj.ui.ContentPreviewViewer.ContentPreviewViewerDelegate
            public void gifAddedOrDeleted() {
                EmojiViewV2 emojiViewV2 = EmojiViewV2.this;
                emojiViewV2.recentGifs = MediaDataController.getInstance(emojiViewV2.currentAccount).getRecentGifs();
                if (EmojiViewV2.this.gifAdapter != null) {
                    EmojiViewV2.this.gifAdapter.notifyDataSetChanged();
                }
            }
        };
        this.searchFieldHeight = AndroidUtilities.dp(64.0f);
        this.needEmojiSearch = needSearch;
        this.tabIcons = new Drawable[]{Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_tab_smiles, Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_tab_gif, Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_tab_stickers, Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected))};
        this.emojiIcons = new Drawable[]{Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_recent, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_smiles, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_cat, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_food, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_activities, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_travel, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_objects, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_other, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_flags, Theme.getColor(Theme.key_chat_emojiPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected))};
        this.stickerIcons = new Drawable[]{Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_recent, Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_faves, Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected)), Theme.createEmojiIconSelectorDrawable(context, R.drawable.smiles_panel_trending, Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), Theme.getColor(Theme.key_chat_emojiPanelIconSelected))};
        this.emojiTitles = new String[]{LocaleController.getString("Emoji1", R.string.Emoji1), LocaleController.getString("Emoji2", R.string.Emoji2), LocaleController.getString("Emoji3", R.string.Emoji3), LocaleController.getString("Emoji4", R.string.Emoji4), LocaleController.getString("Emoji5", R.string.Emoji5), LocaleController.getString("Emoji6", R.string.Emoji6), LocaleController.getString("Emoji7", R.string.Emoji7), LocaleController.getString("Emoji8", R.string.Emoji8)};
        this.showGifs = needGif;
        this.info = chatFull;
        Paint paint = new Paint(1);
        this.dotPaint = paint;
        paint.setColor(Theme.getColor(Theme.key_chat_emojiPanelNewTrending));
        if (Build.VERSION.SDK_INT >= 21) {
            this.outlineProvider = new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.2
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    outline.setRoundRect(view.getPaddingLeft(), view.getPaddingTop(), view.getMeasuredWidth() - view.getPaddingRight(), view.getMeasuredHeight() - view.getPaddingBottom(), AndroidUtilities.dp(6.0f));
                }
            };
        }
        FrameLayout frameLayout = new FrameLayout(context);
        this.emojiContainer = frameLayout;
        this.views.add(frameLayout);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.3
            private boolean ignoreLayout;

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.View
            protected void onMeasure(int widthSpec, int heightSpec) {
                this.ignoreLayout = true;
                int width = View.MeasureSpec.getSize(widthSpec);
                try {
                    EmojiViewV2.this.emojiLayoutManager.setSpanCount(width / AndroidUtilities.dp(AndroidUtilities.isTablet() ? 60.0f : 45.0f));
                    this.ignoreLayout = false;
                } catch (Exception e) {
                }
                super.onMeasure(widthSpec, heightSpec);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                if (EmojiViewV2.this.needEmojiSearch && EmojiViewV2.this.firstEmojiAttach) {
                    this.ignoreLayout = true;
                    EmojiViewV2.this.emojiLayoutManager.scrollToPositionWithOffset(1, 0);
                    EmojiViewV2.this.firstEmojiAttach = false;
                    this.ignoreLayout = false;
                }
                super.onLayout(changed, l, t, r, b);
                EmojiViewV2.this.checkEmojiSearchFieldScroll(true);
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (EmojiViewV2.this.emojiTouchedView != null) {
                    if (event.getAction() == 1 || event.getAction() == 3) {
                        if (EmojiViewV2.this.pickerViewPopup != null && EmojiViewV2.this.pickerViewPopup.isShowing()) {
                            EmojiViewV2.this.pickerViewPopup.dismiss();
                            String color = null;
                            int selection = EmojiViewV2.this.pickerView.getSelection();
                            if (selection == 1) {
                                color = "🏻";
                            } else if (selection == 2) {
                                color = "🏼";
                            } else if (selection == 3) {
                                color = "🏽";
                            } else if (selection == 4) {
                                color = "🏾";
                            } else if (selection == 5) {
                                color = "🏿";
                            }
                            String code = (String) EmojiViewV2.this.emojiTouchedView.getTag();
                            if (!EmojiViewV2.this.emojiTouchedView.isRecent) {
                                if (color != null) {
                                    Emoji.emojiColor.put(code, color);
                                    code = EmojiViewV2.addColorToCode(code, color);
                                } else {
                                    Emoji.emojiColor.remove(code);
                                }
                                EmojiViewV2.this.emojiTouchedView.setImageDrawable(Emoji.getEmojiBigDrawable(code), EmojiViewV2.this.emojiTouchedView.isRecent);
                                EmojiViewV2.this.emojiTouchedView.sendEmoji(null);
                                Emoji.saveEmojiColors();
                            } else {
                                String code2 = code.replace("🏻", "").replace("🏼", "").replace("🏽", "").replace("🏾", "").replace("🏿", "");
                                if (color != null) {
                                    EmojiViewV2.this.emojiTouchedView.sendEmoji(EmojiViewV2.addColorToCode(code2, color));
                                } else {
                                    EmojiViewV2.this.emojiTouchedView.sendEmoji(code2);
                                }
                            }
                        }
                        EmojiViewV2.this.emojiTouchedView = null;
                        EmojiViewV2.this.emojiTouchedX = -10000.0f;
                        EmojiViewV2.this.emojiTouchedY = -10000.0f;
                    } else if (event.getAction() == 2) {
                        boolean ignore = false;
                        if (EmojiViewV2.this.emojiTouchedX != -10000.0f) {
                            if (Math.abs(EmojiViewV2.this.emojiTouchedX - event.getX()) > AndroidUtilities.getPixelsInCM(0.2f, true) || Math.abs(EmojiViewV2.this.emojiTouchedY - event.getY()) > AndroidUtilities.getPixelsInCM(0.2f, false)) {
                                EmojiViewV2.this.emojiTouchedX = -10000.0f;
                                EmojiViewV2.this.emojiTouchedY = -10000.0f;
                            } else {
                                ignore = true;
                            }
                        }
                        if (!ignore) {
                            getLocationOnScreen(EmojiViewV2.this.location);
                            float x = EmojiViewV2.this.location[0] + event.getX();
                            EmojiViewV2.this.pickerView.getLocationOnScreen(EmojiViewV2.this.location);
                            int position = (int) ((x - (EmojiViewV2.this.location[0] + AndroidUtilities.dp(3.0f))) / (EmojiViewV2.this.emojiSize + AndroidUtilities.dp(4.0f)));
                            if (position < 0) {
                                position = 0;
                            } else if (position > 5) {
                                position = 5;
                            }
                            EmojiViewV2.this.pickerView.setSelection(position);
                        }
                    }
                    return true;
                }
                EmojiViewV2.this.emojiLastX = event.getX();
                EmojiViewV2.this.emojiLastY = event.getY();
                return super.onTouchEvent(event);
            }
        };
        this.emojiGridView = recyclerListView;
        recyclerListView.setInstantClick(true);
        RecyclerListView recyclerListView2 = this.emojiGridView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(context, 8);
        this.emojiLayoutManager = gridLayoutManager;
        recyclerListView2.setLayoutManager(gridLayoutManager);
        this.emojiGridView.setTopGlowOffset(AndroidUtilities.dp(38.0f));
        this.emojiGridView.setBottomGlowOffset(AndroidUtilities.dp(48.0f));
        this.emojiGridView.setPadding(0, AndroidUtilities.dp(38.0f), 0, 0);
        this.emojiGridView.setGlowColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        this.emojiGridView.setClipToPadding(false);
        this.emojiLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.4
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                if (EmojiViewV2.this.emojiGridView.getAdapter() != EmojiViewV2.this.emojiSearchAdapter) {
                    if ((EmojiViewV2.this.needEmojiSearch && position == 0) || EmojiViewV2.this.emojiAdapter.positionToSection.indexOfKey(position) >= 0) {
                        return EmojiViewV2.this.emojiLayoutManager.getSpanCount();
                    }
                } else if (position == 0 || (position == 1 && EmojiViewV2.this.emojiSearchAdapter.searchWas && EmojiViewV2.this.emojiSearchAdapter.result.isEmpty())) {
                    return EmojiViewV2.this.emojiLayoutManager.getSpanCount();
                }
                return 1;
            }
        });
        RecyclerListView recyclerListView3 = this.emojiGridView;
        EmojiGridAdapter emojiGridAdapter = new EmojiGridAdapter();
        this.emojiAdapter = emojiGridAdapter;
        recyclerListView3.setAdapter(emojiGridAdapter);
        this.emojiSearchAdapter = new EmojiSearchAdapter();
        this.emojiContainer.addView(this.emojiGridView, LayoutHelper.createFrame(-1, -1.0f));
        this.emojiGridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.5
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && EmojiViewV2.this.emojiSearchField != null) {
                    EmojiViewV2.this.emojiSearchField.hideKeyboard();
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int i, int i2) {
                int iFindFirstVisibleItemPosition = EmojiViewV2.this.emojiLayoutManager.findFirstVisibleItemPosition();
                if (iFindFirstVisibleItemPosition != -1) {
                    int i3 = 0;
                    int size = Emoji.recentEmoji.size() + (EmojiViewV2.this.needEmojiSearch ? 1 : 0);
                    if (iFindFirstVisibleItemPosition >= size) {
                        int i4 = 0;
                        while (true) {
                            if (i4 >= EmojiData.dataColored.length) {
                                break;
                            }
                            int length = EmojiData.dataColored[i4].length + 1;
                            if (iFindFirstVisibleItemPosition < size + length) {
                                i3 = i4 + (!Emoji.recentEmoji.isEmpty() ? 1 : 0);
                                break;
                            } else {
                                size += length;
                                i4++;
                            }
                        }
                    }
                    EmojiViewV2.this.emojiTabs.onPageScrolled(i3, 0);
                }
                EmojiViewV2.this.checkEmojiTabY(recyclerView, i2);
                EmojiViewV2.this.checkEmojiSearchFieldScroll(false);
                EmojiViewV2.this.checkBottomTabScroll(i2);
            }
        });
        this.emojiGridView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.6
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                if (view instanceof ImageViewEmoji) {
                    ImageViewEmoji viewEmoji = (ImageViewEmoji) view;
                    viewEmoji.sendEmoji(null);
                }
            }
        });
        this.emojiGridView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.7
            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
            /* JADX WARN: Removed duplicated region for block: B:54:0x00b7  */
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public boolean onItemClick(android.view.View r20, int r21) {
                /*
                    Method dump skipped, instruction units count: 570
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.EmojiViewV2.AnonymousClass7.onItemClick(android.view.View, int):boolean");
            }
        });
        this.emojiTabs = new ScrollSlidingTabStrip(context);
        if (needSearch) {
            SearchField searchField = new SearchField(context, 1);
            this.emojiSearchField = searchField;
            this.emojiContainer.addView(searchField, new FrameLayout.LayoutParams(-1, this.searchFieldHeight + AndroidUtilities.getShadowHeight()));
            this.emojiSearchField.searchEditText.setOnFocusChangeListener(new View.OnFocusChangeListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.8
                @Override // android.view.View.OnFocusChangeListener
                public void onFocusChange(View v, boolean hasFocus) {
                    if (hasFocus) {
                        EmojiViewV2.this.lastSearchKeyboardLanguage = AndroidUtilities.getCurrentKeyboardLanguage();
                        MediaDataController.getInstance(EmojiViewV2.this.currentAccount).fetchNewEmojiKeywords(EmojiViewV2.this.lastSearchKeyboardLanguage);
                    }
                }
            });
        }
        this.emojiTabs.setShouldExpand(true);
        this.emojiTabs.setIndicatorHeight(-1);
        this.emojiTabs.setUnderlineHeight(-1);
        this.emojiTabs.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        this.emojiContainer.addView(this.emojiTabs, LayoutHelper.createFrame(-1, 38.0f));
        this.emojiTabs.setDelegate(new ScrollSlidingTabStrip.ScrollSlidingTabStripDelegate() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.9
            @Override // im.uwrkaxlmjj.ui.components.ScrollSlidingTabStrip.ScrollSlidingTabStripDelegate
            public void onPageSelected(int i) {
                if (!Emoji.recentEmoji.isEmpty()) {
                    if (i == 0) {
                        EmojiViewV2.this.emojiLayoutManager.scrollToPositionWithOffset(EmojiViewV2.this.needEmojiSearch ? 1 : 0, 0);
                        return;
                    }
                    i--;
                }
                EmojiViewV2.this.emojiGridView.stopScroll();
                EmojiViewV2.this.emojiLayoutManager.scrollToPositionWithOffset(EmojiViewV2.this.emojiAdapter.sectionToPosition.get(i), 0);
                EmojiViewV2.this.checkEmojiTabY(null, 0);
            }
        });
        View view = new View(context);
        this.emojiTabsShadow = view;
        view.setAlpha(0.0f);
        this.emojiTabsShadow.setTag(1);
        this.emojiTabsShadow.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 51);
        layoutParams.topMargin = AndroidUtilities.dp(38.0f);
        this.emojiContainer.addView(this.emojiTabsShadow, layoutParams);
        if (needStickers) {
            if (needGif) {
                FrameLayout frameLayout2 = new FrameLayout(context);
                this.gifContainer = frameLayout2;
                this.views.add(frameLayout2);
                RecyclerListView recyclerListView4 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.10
                    private boolean ignoreLayout;

                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
                    public boolean onInterceptTouchEvent(MotionEvent event) {
                        boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, EmojiViewV2.this.gifGridView, 0, EmojiViewV2.this.contentPreviewViewerDelegate);
                        return super.onInterceptTouchEvent(event) || result;
                    }

                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
                    protected void onLayout(boolean changed, int l, int t, int r, int b) {
                        if (EmojiViewV2.this.firstGifAttach && EmojiViewV2.this.gifAdapter.getItemCount() > 1) {
                            this.ignoreLayout = true;
                            EmojiViewV2.this.gifLayoutManager.scrollToPositionWithOffset(1, 0);
                            EmojiViewV2.this.firstGifAttach = false;
                            this.ignoreLayout = false;
                        }
                        super.onLayout(changed, l, t, r, b);
                        EmojiViewV2.this.checkGifSearchFieldScroll(true);
                    }

                    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
                    public void requestLayout() {
                        if (this.ignoreLayout) {
                            return;
                        }
                        super.requestLayout();
                    }
                };
                this.gifGridView = recyclerListView4;
                recyclerListView4.setClipToPadding(false);
                RecyclerListView recyclerListView5 = this.gifGridView;
                ExtendedGridLayoutManager extendedGridLayoutManager = new ExtendedGridLayoutManager(context, 100) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.11
                    private Size size = new Size();

                    @Override // im.uwrkaxlmjj.ui.components.ExtendedGridLayoutManager
                    protected Size getSizeForItem(int i) {
                        TLRPC.Document document;
                        ArrayList<TLRPC.DocumentAttribute> attributes;
                        ArrayList<TLRPC.DocumentAttribute> attributes2;
                        TLRPC.PhotoSize thumb;
                        if (EmojiViewV2.this.gifGridView.getAdapter() == EmojiViewV2.this.gifAdapter) {
                            document = (TLRPC.Document) EmojiViewV2.this.recentGifs.get(i);
                            attributes = document.attributes;
                        } else if (EmojiViewV2.this.gifSearchAdapter.results.isEmpty()) {
                            document = null;
                            attributes = null;
                        } else {
                            TLRPC.BotInlineResult result = (TLRPC.BotInlineResult) EmojiViewV2.this.gifSearchAdapter.results.get(i);
                            TLRPC.Document document2 = result.document;
                            if (document2 != null) {
                                attributes2 = document2.attributes;
                            } else if (result.content != null) {
                                attributes2 = result.content.attributes;
                            } else if (result.thumb != null) {
                                attributes2 = result.thumb.attributes;
                            } else {
                                attributes2 = null;
                            }
                            document = document2;
                            attributes = attributes2;
                        }
                        Size size = this.size;
                        size.height = 100.0f;
                        size.width = 100.0f;
                        if (document != null && (thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90)) != null && thumb.w != 0 && thumb.h != 0) {
                            this.size.width = thumb.w;
                            this.size.height = thumb.h;
                        }
                        if (attributes != null) {
                            for (int b = 0; b < attributes.size(); b++) {
                                TLRPC.DocumentAttribute attribute = attributes.get(b);
                                if ((attribute instanceof TLRPC.TL_documentAttributeImageSize) || (attribute instanceof TLRPC.TL_documentAttributeVideo)) {
                                    this.size.width = attribute.w;
                                    this.size.height = attribute.h;
                                    break;
                                }
                            }
                        }
                        return this.size;
                    }

                    @Override // im.uwrkaxlmjj.ui.components.ExtendedGridLayoutManager
                    protected int getFlowItemCount() {
                        if (EmojiViewV2.this.gifGridView.getAdapter() == EmojiViewV2.this.gifSearchAdapter && EmojiViewV2.this.gifSearchAdapter.results.isEmpty()) {
                            return 0;
                        }
                        return getItemCount() - 1;
                    }
                };
                this.gifLayoutManager = extendedGridLayoutManager;
                recyclerListView5.setLayoutManager(extendedGridLayoutManager);
                this.gifLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.12
                    @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
                    public int getSpanSize(int position) {
                        return (position == 0 || (EmojiViewV2.this.gifGridView.getAdapter() == EmojiViewV2.this.gifSearchAdapter && EmojiViewV2.this.gifSearchAdapter.results.isEmpty())) ? EmojiViewV2.this.gifLayoutManager.getSpanCount() : EmojiViewV2.this.gifLayoutManager.getSpanSizeForItem(position - 1);
                    }
                });
                this.gifGridView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.13
                    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
                    public void getItemOffsets(android.graphics.Rect outRect, View view2, RecyclerView parent, RecyclerView.State state) {
                        int position = parent.getChildAdapterPosition(view2);
                        if (position != 0) {
                            outRect.left = 0;
                            outRect.bottom = 0;
                            if (!EmojiViewV2.this.gifLayoutManager.isFirstRow(position - 1)) {
                                outRect.top = AndroidUtilities.dp(2.0f);
                            } else {
                                outRect.top = 0;
                            }
                            outRect.right = EmojiViewV2.this.gifLayoutManager.isLastInRow(position + (-1)) ? 0 : AndroidUtilities.dp(2.0f);
                            return;
                        }
                        outRect.left = 0;
                        outRect.top = 0;
                        outRect.bottom = 0;
                        outRect.right = 0;
                    }
                });
                this.gifGridView.setOverScrollMode(2);
                RecyclerListView recyclerListView6 = this.gifGridView;
                GifAdapter gifAdapter = new GifAdapter(context);
                this.gifAdapter = gifAdapter;
                recyclerListView6.setAdapter(gifAdapter);
                this.gifSearchAdapter = new GifSearchAdapter(context);
                this.gifGridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.14
                    @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                    public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                        if (newState == 1) {
                            EmojiViewV2.this.gifSearchField.hideKeyboard();
                        }
                    }

                    @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                    public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                        EmojiViewV2.this.checkGifSearchFieldScroll(false);
                        EmojiViewV2.this.checkBottomTabScroll(dy);
                    }
                });
                this.gifGridView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$7XQN4soMiLF6aLNzAwniHzSyla4
                    @Override // android.view.View.OnTouchListener
                    public final boolean onTouch(View view2, MotionEvent motionEvent) {
                        return this.f$0.lambda$new$1$EmojiViewV2(view2, motionEvent);
                    }
                });
                RecyclerListView.OnItemClickListener onItemClickListener = new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$ydb0Bn4th1r99wIE_QU_q6vtZO8
                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                    public final void onItemClick(View view2, int i) {
                        this.f$0.lambda$new$2$EmojiViewV2(view2, i);
                    }
                };
                this.gifOnItemClickListener = onItemClickListener;
                this.gifGridView.setOnItemClickListener(onItemClickListener);
                this.gifContainer.addView(this.gifGridView, LayoutHelper.createFrame(-1, -1.0f));
                SearchField searchField2 = new SearchField(context, 2);
                this.gifSearchField = searchField2;
                this.gifContainer.addView(searchField2, new FrameLayout.LayoutParams(-1, this.searchFieldHeight + AndroidUtilities.getShadowHeight()));
            }
            this.stickersContainer = new FrameLayout(context);
            MediaDataController.getInstance(this.currentAccount).checkStickers(0);
            MediaDataController.getInstance(this.currentAccount).checkFeaturedStickers();
            RecyclerListView recyclerListView7 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.15
                boolean ignoreLayout;

                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
                public boolean onInterceptTouchEvent(MotionEvent event) {
                    boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, EmojiViewV2.this.stickersGridView, EmojiViewV2.this.getMeasuredHeight(), EmojiViewV2.this.contentPreviewViewerDelegate);
                    return super.onInterceptTouchEvent(event) || result;
                }

                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, android.view.View
                public void setVisibility(int visibility) {
                    if (EmojiViewV2.this.trendingGridView != null && EmojiViewV2.this.trendingGridView.getVisibility() == 0) {
                        super.setVisibility(8);
                    } else {
                        super.setVisibility(visibility);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.View
                protected void onLayout(boolean changed, int l, int t, int r, int b) {
                    if (EmojiViewV2.this.firstStickersAttach && EmojiViewV2.this.stickersGridAdapter.getItemCount() > 0) {
                        this.ignoreLayout = true;
                        EmojiViewV2.this.stickersLayoutManager.scrollToPositionWithOffset(1, 0);
                        EmojiViewV2.this.firstStickersAttach = false;
                        this.ignoreLayout = false;
                    }
                    super.onLayout(changed, l, t, r, b);
                    EmojiViewV2.this.checkStickersSearchFieldScroll(true);
                }

                @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
                public void requestLayout() {
                    if (this.ignoreLayout) {
                        return;
                    }
                    super.requestLayout();
                }
            };
            this.stickersGridView = recyclerListView7;
            GridLayoutManager gridLayoutManager2 = new GridLayoutManager(context, 5);
            this.stickersLayoutManager = gridLayoutManager2;
            recyclerListView7.setLayoutManager(gridLayoutManager2);
            this.stickersLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.16
                @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
                public int getSpanSize(int position) {
                    if (EmojiViewV2.this.stickersGridView.getAdapter() == EmojiViewV2.this.stickersGridAdapter) {
                        if (position == 0) {
                            return EmojiViewV2.this.stickersGridAdapter.stickersPerRow;
                        }
                        if (position != EmojiViewV2.this.stickersGridAdapter.totalItems) {
                            Object object = EmojiViewV2.this.stickersGridAdapter.cache.get(position);
                            if (object == null || (EmojiViewV2.this.stickersGridAdapter.cache.get(position) instanceof TLRPC.Document)) {
                                return 1;
                            }
                        }
                        return EmojiViewV2.this.stickersGridAdapter.stickersPerRow;
                    }
                    if (position != EmojiViewV2.this.stickersSearchGridAdapter.totalItems) {
                        Object object2 = EmojiViewV2.this.stickersSearchGridAdapter.cache.get(position);
                        if (object2 == null || (EmojiViewV2.this.stickersSearchGridAdapter.cache.get(position) instanceof TLRPC.Document)) {
                            return 1;
                        }
                    }
                    return EmojiViewV2.this.stickersGridAdapter.stickersPerRow;
                }
            });
            this.stickersGridView.setPadding(0, AndroidUtilities.dp(52.0f), 0, 0);
            this.stickersGridView.setClipToPadding(false);
            this.views.add(this.stickersContainer);
            this.stickersSearchGridAdapter = new StickersSearchGridAdapter(context);
            RecyclerListView recyclerListView8 = this.stickersGridView;
            StickersGridAdapter stickersGridAdapter = new StickersGridAdapter(context);
            this.stickersGridAdapter = stickersGridAdapter;
            recyclerListView8.setAdapter(stickersGridAdapter);
            this.stickersGridView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$bEHPmYTpxQG8wlTP4_PP7Y2MlYE
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view2, MotionEvent motionEvent) {
                    return this.f$0.lambda$new$3$EmojiViewV2(view2, motionEvent);
                }
            });
            RecyclerListView.OnItemClickListener onItemClickListener2 = new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$RGhyOfMiR_Sak8GEgdR98Q2Rj98
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view2, int i) {
                    this.f$0.lambda$new$4$EmojiViewV2(view2, i);
                }
            };
            this.stickersOnItemClickListener = onItemClickListener2;
            this.stickersGridView.setOnItemClickListener(onItemClickListener2);
            this.stickersGridView.setGlowColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            this.stickersContainer.addView(this.stickersGridView);
            this.stickersTab = new ScrollSlidingTabStrip(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.17
                float downX;
                float downY;
                boolean draggingHorizontally;
                boolean draggingVertically;
                float lastTranslateX;
                float lastX;
                boolean startedScroll;
                VelocityTracker vTracker;
                boolean first = true;
                final int touchslop = ViewConfiguration.get(getContext()).getScaledTouchSlop();

                @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
                public boolean onInterceptTouchEvent(MotionEvent ev) {
                    if (getParent() != null) {
                        getParent().requestDisallowInterceptTouchEvent(true);
                    }
                    if (ev.getAction() == 0) {
                        this.draggingHorizontally = false;
                        this.draggingVertically = false;
                        this.downX = ev.getRawX();
                        this.downY = ev.getRawY();
                    } else if (!this.draggingVertically && !this.draggingHorizontally && EmojiViewV2.this.dragListener != null && Math.abs(ev.getRawY() - this.downY) >= this.touchslop) {
                        this.draggingVertically = true;
                        this.downY = ev.getRawY();
                        EmojiViewV2.this.dragListener.onDragStart();
                        if (this.startedScroll) {
                            EmojiViewV2.this.pager.endFakeDrag();
                            this.startedScroll = false;
                        }
                        return true;
                    }
                    return super.onInterceptTouchEvent(ev);
                }

                @Override // android.widget.HorizontalScrollView, android.view.View
                public boolean onTouchEvent(MotionEvent ev) {
                    if (this.first) {
                        this.first = false;
                        this.lastX = ev.getX();
                    }
                    if (ev.getAction() == 0) {
                        this.draggingHorizontally = false;
                        this.draggingVertically = false;
                        this.downX = ev.getRawX();
                        this.downY = ev.getRawY();
                    } else if (!this.draggingVertically && !this.draggingHorizontally && EmojiViewV2.this.dragListener != null) {
                        if (Math.abs(ev.getRawX() - this.downX) >= this.touchslop) {
                            this.draggingHorizontally = true;
                        } else if (Math.abs(ev.getRawY() - this.downY) >= this.touchslop) {
                            this.draggingVertically = true;
                            this.downY = ev.getRawY();
                            EmojiViewV2.this.dragListener.onDragStart();
                            if (this.startedScroll) {
                                EmojiViewV2.this.pager.endFakeDrag();
                                this.startedScroll = false;
                            }
                        }
                    }
                    if (!this.draggingVertically) {
                        float newTranslationX = EmojiViewV2.this.stickersTab.getTranslationX();
                        if (EmojiViewV2.this.stickersTab.getScrollX() == 0 && newTranslationX == 0.0f) {
                            if (!this.startedScroll && this.lastX - ev.getX() < 0.0f) {
                                if (EmojiViewV2.this.pager.beginFakeDrag()) {
                                    this.startedScroll = true;
                                    this.lastTranslateX = EmojiViewV2.this.stickersTab.getTranslationX();
                                }
                            } else if (this.startedScroll && this.lastX - ev.getX() > 0.0f && EmojiViewV2.this.pager.isFakeDragging()) {
                                EmojiViewV2.this.pager.endFakeDrag();
                                this.startedScroll = false;
                            }
                        }
                        if (this.startedScroll) {
                            try {
                                this.lastTranslateX = newTranslationX;
                            } catch (Exception e) {
                                try {
                                    EmojiViewV2.this.pager.endFakeDrag();
                                } catch (Exception e2) {
                                }
                                this.startedScroll = false;
                                FileLog.e(e);
                            }
                        }
                        this.lastX = ev.getX();
                        if (ev.getAction() == 3 || ev.getAction() == 1) {
                            this.first = true;
                            this.draggingHorizontally = false;
                            this.draggingVertically = false;
                            if (this.startedScroll) {
                                EmojiViewV2.this.pager.endFakeDrag();
                                this.startedScroll = false;
                            }
                        }
                        return this.startedScroll || super.onTouchEvent(ev);
                    }
                    if (this.vTracker == null) {
                        this.vTracker = VelocityTracker.obtain();
                    }
                    this.vTracker.addMovement(ev);
                    if (ev.getAction() != 1 && ev.getAction() != 3) {
                        EmojiViewV2.this.dragListener.onDrag(Math.round(ev.getRawY() - this.downY));
                    } else {
                        this.vTracker.computeCurrentVelocity(1000);
                        float velocity = this.vTracker.getYVelocity();
                        this.vTracker.recycle();
                        this.vTracker = null;
                        if (ev.getAction() == 1) {
                            EmojiViewV2.this.dragListener.onDragEnd(velocity);
                        } else {
                            EmojiViewV2.this.dragListener.onDragCancel();
                        }
                        this.first = true;
                        this.draggingHorizontally = false;
                        this.draggingVertically = false;
                    }
                    return true;
                }
            };
            SearchField searchField3 = new SearchField(context, 0);
            this.stickersSearchField = searchField3;
            this.stickersContainer.addView(searchField3, new FrameLayout.LayoutParams(-1, this.searchFieldHeight + AndroidUtilities.getShadowHeight()));
            RecyclerListView recyclerListView9 = new RecyclerListView(context);
            this.trendingGridView = recyclerListView9;
            recyclerListView9.setItemAnimator(null);
            this.trendingGridView.setLayoutAnimation(null);
            RecyclerListView recyclerListView10 = this.trendingGridView;
            GridLayoutManager gridLayoutManager3 = new GridLayoutManager(context, 5) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.18
                @Override // androidx.recyclerview.widget.GridLayoutManager, androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.RecyclerView.LayoutManager
                public boolean supportsPredictiveItemAnimations() {
                    return false;
                }
            };
            this.trendingLayoutManager = gridLayoutManager3;
            recyclerListView10.setLayoutManager(gridLayoutManager3);
            this.trendingLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.19
                @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
                public int getSpanSize(int position) {
                    if (!(EmojiViewV2.this.trendingGridAdapter.cache.get(position) instanceof Integer) && position != EmojiViewV2.this.trendingGridAdapter.totalItems) {
                        return 1;
                    }
                    return EmojiViewV2.this.trendingGridAdapter.stickersPerRow;
                }
            });
            this.trendingGridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.20
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                    EmojiViewV2.this.checkStickersTabY(recyclerView, dy);
                    EmojiViewV2.this.checkBottomTabScroll(dy);
                }
            });
            this.trendingGridView.setClipToPadding(false);
            this.trendingGridView.setPadding(0, AndroidUtilities.dp(48.0f), 0, 0);
            RecyclerListView recyclerListView11 = this.trendingGridView;
            TrendingGridAdapter trendingGridAdapter = new TrendingGridAdapter(context);
            this.trendingGridAdapter = trendingGridAdapter;
            recyclerListView11.setAdapter(trendingGridAdapter);
            this.trendingGridView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$C3X1puMgw7qMlFTWlB0CbLlc4bs
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view2, int i) {
                    this.f$0.lambda$new$5$EmojiViewV2(view2, i);
                }
            });
            this.trendingGridAdapter.notifyDataSetChanged();
            this.trendingGridView.setGlowColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            this.trendingGridView.setVisibility(8);
            this.stickersContainer.addView(this.trendingGridView);
            this.stickersTab.setUnderlineHeight(AndroidUtilities.getShadowHeight());
            this.stickersTab.setIndicatorHeight(AndroidUtilities.dp(2.0f));
            this.stickersTab.setIndicatorColor(Theme.getColor(Theme.key_chat_emojiPanelStickerPackSelectorLine));
            this.stickersTab.setUnderlineColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
            this.stickersTab.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            this.stickersContainer.addView(this.stickersTab, LayoutHelper.createFrame(-1, 48, 51));
            updateStickerTabs();
            this.stickersTab.setDelegate(new ScrollSlidingTabStrip.ScrollSlidingTabStripDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$Fi4HnwLw2cs9aeNv-AHAjo-R-Jw
                @Override // im.uwrkaxlmjj.ui.components.ScrollSlidingTabStrip.ScrollSlidingTabStripDelegate
                public final void onPageSelected(int i) {
                    this.f$0.lambda$new$6$EmojiViewV2(i);
                }
            });
            this.stickersGridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.21
                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                    if (newState == 1) {
                        EmojiViewV2.this.stickersSearchField.hideKeyboard();
                    }
                }

                @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
                public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                    EmojiViewV2.this.checkScroll();
                    EmojiViewV2.this.checkStickersTabY(recyclerView, dy);
                    EmojiViewV2.this.checkStickersSearchFieldScroll(false);
                    EmojiViewV2.this.checkBottomTabScroll(dy);
                }
            });
        }
        ViewPager viewPager = new ViewPager(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.22
            @Override // androidx.viewpager.widget.ViewPager, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (getParent() != null) {
                    getParent().requestDisallowInterceptTouchEvent(true);
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // androidx.viewpager.widget.ViewPager
            public void setCurrentItem(int i, boolean z) {
                EmojiViewV2.this.startStopVisibleGifs(i == 1);
                if (i == getCurrentItem()) {
                    if (i == 0) {
                        EmojiViewV2.this.emojiGridView.smoothScrollToPosition(EmojiViewV2.this.needEmojiSearch ? 1 : 0);
                        return;
                    } else if (i == 1) {
                        EmojiViewV2.this.gifGridView.smoothScrollToPosition(1);
                        return;
                    } else {
                        EmojiViewV2.this.stickersGridView.smoothScrollToPosition(1);
                        return;
                    }
                }
                super.setCurrentItem(i, z);
            }
        };
        this.pager = viewPager;
        viewPager.setAdapter(new EmojiPagesAdapter());
        View view2 = new View(context);
        this.topShadow = view2;
        view2.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, -1907225));
        addView(this.topShadow, LayoutHelper.createFrame(-1, 6.0f));
        ImageView imageView = new ImageView(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.23
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (event.getAction() == 0) {
                    EmojiViewV2.this.backspacePressed = true;
                    EmojiViewV2.this.backspaceOnce = false;
                    EmojiViewV2.this.postBackspaceRunnable(350);
                } else if (event.getAction() == 3 || event.getAction() == 1) {
                    EmojiViewV2.this.backspacePressed = false;
                    if (!EmojiViewV2.this.backspaceOnce && EmojiViewV2.this.delegate != null && EmojiViewV2.this.delegate.onBackspace()) {
                        EmojiViewV2.this.backspaceButton.performHapticFeedback(3);
                    }
                }
                super.onTouchEvent(event);
                return true;
            }
        };
        this.backspaceButton = imageView;
        imageView.setImageResource(R.drawable.smiles_tab_clear);
        this.backspaceButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackspace), PorterDuff.Mode.MULTIPLY));
        this.backspaceButton.setScaleType(ImageView.ScaleType.CENTER);
        this.backspaceButton.setContentDescription(LocaleController.getString("AccDescrBackspace", R.string.AccDescrBackspace));
        this.backspaceButton.setFocusable(true);
        this.bottomTabContainer = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.24
            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (getParent() != null) {
                    getParent().requestDisallowInterceptTouchEvent(true);
                }
                return super.onInterceptTouchEvent(ev);
            }
        };
        View view3 = new View(context);
        this.shadowLine = view3;
        view3.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
        this.bottomTabContainer.addView(this.shadowLine, new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight()));
        View view4 = new View(context);
        this.bottomTabContainerBackground = view4;
        this.bottomTabContainer.addView(view4, new FrameLayout.LayoutParams(-1, AndroidUtilities.dp(44.0f), 83));
        if (needSearch) {
            addView(this.bottomTabContainer, new FrameLayout.LayoutParams(-1, AndroidUtilities.dp(44.0f) + AndroidUtilities.getShadowHeight(), 83));
            this.bottomTabContainer.addView(this.backspaceButton, LayoutHelper.createFrame(52, 44, 85));
            ImageView imageView2 = new ImageView(context);
            this.stickerSettingsButton = imageView2;
            imageView2.setImageResource(R.drawable.smiles_tab_settings);
            this.stickerSettingsButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackspace), PorterDuff.Mode.MULTIPLY));
            this.stickerSettingsButton.setScaleType(ImageView.ScaleType.CENTER);
            this.stickerSettingsButton.setFocusable(true);
            this.stickerSettingsButton.setContentDescription(LocaleController.getString("Settings", R.string.Settings));
            this.bottomTabContainer.addView(this.stickerSettingsButton, LayoutHelper.createFrame(52, 44, 85));
            this.stickerSettingsButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.25
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (EmojiViewV2.this.delegate != null) {
                        EmojiViewV2.this.delegate.onStickersSettingsClick();
                    }
                }
            });
            PagerSlidingTabStrip pagerSlidingTabStrip = new PagerSlidingTabStrip(context);
            this.typeTabs = pagerSlidingTabStrip;
            pagerSlidingTabStrip.setViewPager(this.pager);
            this.typeTabs.setShouldExpand(false);
            this.typeTabs.setIndicatorHeight(0);
            this.typeTabs.setUnderlineHeight(0);
            this.typeTabs.setTabPaddingLeftRight(AndroidUtilities.dp(10.0f));
            this.bottomTabContainer.addView(this.typeTabs, LayoutHelper.createFrame(-2, 44, 81));
            this.typeTabs.setOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.26
                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                    SearchField currentField;
                    SearchField field;
                    EmojiViewV2 emojiViewV2 = EmojiViewV2.this;
                    emojiViewV2.onPageScrolled(position, (emojiViewV2.getMeasuredWidth() - EmojiViewV2.this.getPaddingLeft()) - EmojiViewV2.this.getPaddingRight(), positionOffsetPixels);
                    boolean z = true;
                    EmojiViewV2.this.showBottomTab(true, true);
                    int p = EmojiViewV2.this.pager.getCurrentItem();
                    if (p == 0) {
                        currentField = EmojiViewV2.this.emojiSearchField;
                    } else {
                        currentField = p == 1 ? EmojiViewV2.this.gifSearchField : EmojiViewV2.this.stickersSearchField;
                    }
                    String currentFieldText = currentField.searchEditText.getText().toString();
                    int a = 0;
                    while (a < 3) {
                        if (a == 0) {
                            field = EmojiViewV2.this.emojiSearchField;
                        } else {
                            field = a == 1 ? EmojiViewV2.this.gifSearchField : EmojiViewV2.this.stickersSearchField;
                        }
                        if (field != null && field != currentField && field.searchEditText != null && !field.searchEditText.getText().toString().equals(currentFieldText)) {
                            field.searchEditText.setText(currentFieldText);
                            field.searchEditText.setSelection(currentFieldText.length());
                        }
                        a++;
                    }
                    EmojiViewV2 emojiViewV22 = EmojiViewV2.this;
                    if ((position != 0 || positionOffset <= 0.0f) && position != 1) {
                        z = false;
                    }
                    emojiViewV22.startStopVisibleGifs(z);
                }

                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageSelected(int position) {
                    EmojiViewV2.this.saveNewPage();
                    EmojiViewV2.this.showBackspaceButton(position == 0, true);
                    EmojiViewV2.this.showStickerSettingsButton(position == 2, true);
                    if (EmojiViewV2.this.delegate.isSearchOpened()) {
                        if (position == 0) {
                            if (EmojiViewV2.this.emojiSearchField != null) {
                                EmojiViewV2.this.emojiSearchField.searchEditText.requestFocus();
                            }
                        } else if (position == 1) {
                            if (EmojiViewV2.this.gifSearchField != null) {
                                EmojiViewV2.this.gifSearchField.searchEditText.requestFocus();
                            }
                        } else if (EmojiViewV2.this.stickersSearchField != null) {
                            EmojiViewV2.this.stickersSearchField.searchEditText.requestFocus();
                        }
                    }
                }

                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageScrollStateChanged(int state) {
                }
            });
            ImageView imageView3 = new ImageView(context);
            this.searchButton = imageView3;
            imageView3.setImageResource(R.drawable.smiles_tab_search);
            this.searchButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackspace), PorterDuff.Mode.MULTIPLY));
            this.searchButton.setScaleType(ImageView.ScaleType.CENTER);
            this.searchButton.setContentDescription(LocaleController.getString("Search", R.string.Search));
            this.searchButton.setFocusable(true);
            this.bottomTabContainer.addView(this.searchButton, LayoutHelper.createFrame(52, 44, 83));
            this.searchButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.27
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    SearchField currentField;
                    int currentItem = EmojiViewV2.this.pager.getCurrentItem();
                    if (currentItem == 0) {
                        currentField = EmojiViewV2.this.emojiSearchField;
                    } else {
                        currentField = currentItem == 1 ? EmojiViewV2.this.gifSearchField : EmojiViewV2.this.stickersSearchField;
                    }
                    if (currentField != null) {
                        currentField.searchEditText.requestFocus();
                        MotionEvent event = MotionEvent.obtain(0L, 0L, 0, 0.0f, 0.0f, 0);
                        currentField.searchEditText.onTouchEvent(event);
                        event.recycle();
                        MotionEvent event2 = MotionEvent.obtain(0L, 0L, 1, 0.0f, 0.0f, 0);
                        currentField.searchEditText.onTouchEvent(event2);
                        event2.recycle();
                    }
                }
            });
        } else {
            addView(this.bottomTabContainer, LayoutHelper.createFrame((Build.VERSION.SDK_INT >= 21 ? 40 : 44) + 20, (Build.VERSION.SDK_INT >= 21 ? 40 : 44) + 12, (LocaleController.isRTL ? 3 : 5) | 80, 0.0f, 0.0f, 2.0f, 0.0f));
            Drawable drawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_chat_emojiPanelBackground), Theme.getColor(Theme.key_chat_emojiPanelBackground));
            if (Build.VERSION.SDK_INT < 21) {
                Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow).mutate();
                shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
                CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable, 0, 0);
                combinedDrawable.setIconSize(AndroidUtilities.dp(40.0f), AndroidUtilities.dp(40.0f));
                drawable = combinedDrawable;
            } else {
                StateListAnimator animator = new StateListAnimator();
                animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.floatingButton, (Property<ImageView, Float>) View.TRANSLATION_Z, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
                animator.addState(new int[0], ObjectAnimator.ofFloat(this.floatingButton, (Property<ImageView, Float>) View.TRANSLATION_Z, AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
                this.backspaceButton.setStateListAnimator(animator);
                this.backspaceButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.28
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view5, Outline outline) {
                        outline.setOval(0, 0, AndroidUtilities.dp(40.0f), AndroidUtilities.dp(40.0f));
                    }
                });
            }
            this.backspaceButton.setPadding(0, 0, AndroidUtilities.dp(2.0f), 0);
            this.backspaceButton.setBackgroundDrawable(drawable);
            this.backspaceButton.setContentDescription(LocaleController.getString("AccDescrBackspace", R.string.AccDescrBackspace));
            this.backspaceButton.setFocusable(true);
            this.bottomTabContainer.addView(this.backspaceButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 40 : 44, Build.VERSION.SDK_INT >= 21 ? 40 : 44, 51, 10.0f, 0.0f, 10.0f, 0.0f));
            this.shadowLine.setVisibility(8);
            this.bottomTabContainerBackground.setVisibility(8);
        }
        addView(this.pager, 0, LayoutHelper.createFrame(-1, -1, 51));
        CorrectlyMeasuringTextView correctlyMeasuringTextView = new CorrectlyMeasuringTextView(context);
        this.mediaBanTooltip = correctlyMeasuringTextView;
        correctlyMeasuringTextView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(3.0f), Theme.getColor(Theme.key_chat_gifSaveHintBackground)));
        this.mediaBanTooltip.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
        this.mediaBanTooltip.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(7.0f));
        this.mediaBanTooltip.setGravity(16);
        this.mediaBanTooltip.setTextSize(1, 14.0f);
        this.mediaBanTooltip.setVisibility(4);
        addView(this.mediaBanTooltip, LayoutHelper.createFrame(-2.0f, -2.0f, 81, 5.0f, 0.0f, 5.0f, 53.0f));
        this.emojiSize = AndroidUtilities.dp(AndroidUtilities.isTablet() ? 40.0f : 32.0f);
        this.pickerView = new EmojiColorPickerView(context);
        EmojiColorPickerView emojiColorPickerView = this.pickerView;
        int iDp = AndroidUtilities.dp(((AndroidUtilities.isTablet() ? 40 : 32) * 6) + 10 + 20);
        this.popupWidth = iDp;
        int iDp2 = AndroidUtilities.dp(AndroidUtilities.isTablet() ? 64.0f : 56.0f);
        this.popupHeight = iDp2;
        EmojiPopupWindow emojiPopupWindow = new EmojiPopupWindow(emojiColorPickerView, iDp, iDp2);
        this.pickerViewPopup = emojiPopupWindow;
        emojiPopupWindow.setOutsideTouchable(true);
        this.pickerViewPopup.setClippingEnabled(true);
        this.pickerViewPopup.setInputMethodMode(2);
        this.pickerViewPopup.setSoftInputMode(0);
        this.pickerViewPopup.getContentView().setFocusableInTouchMode(true);
        this.pickerViewPopup.getContentView().setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$6KA1qAjxU4WnaB4DVHFJHIW6w8w
            @Override // android.view.View.OnKeyListener
            public final boolean onKey(View view5, int i, KeyEvent keyEvent) {
                return this.f$0.lambda$new$7$EmojiViewV2(view5, i, keyEvent);
            }
        });
        this.currentPage = MessagesController.getGlobalEmojiSettings().getInt("selected_page", 0);
        Emoji.loadRecentEmoji();
        this.emojiAdapter.notifyDataSetChanged();
        if (this.typeTabs != null) {
            if (this.views.size() == 1 && this.typeTabs.getVisibility() == 0) {
                this.typeTabs.setVisibility(4);
            } else if (this.views.size() != 1 && this.typeTabs.getVisibility() != 0) {
                this.typeTabs.setVisibility(0);
            }
        }
    }

    public /* synthetic */ boolean lambda$new$1$EmojiViewV2(View v, MotionEvent event) {
        return ContentPreviewViewer.getInstance().onTouch(event, this.gifGridView, 0, this.gifOnItemClickListener, this.contentPreviewViewerDelegate);
    }

    public /* synthetic */ void lambda$new$2$EmojiViewV2(View view, int position) {
        if (this.delegate == null) {
            return;
        }
        int position2 = position - 1;
        if (this.gifGridView.getAdapter() == this.gifAdapter) {
            if (position2 < 0 || position2 >= this.recentGifs.size()) {
                return;
            }
            this.delegate.onGifSelected(view, this.recentGifs.get(position2), "gif", true, 0);
            return;
        }
        RecyclerView.Adapter adapter = this.gifGridView.getAdapter();
        GifSearchAdapter gifSearchAdapter = this.gifSearchAdapter;
        if (adapter != gifSearchAdapter || position2 < 0 || position2 >= gifSearchAdapter.results.size()) {
            return;
        }
        this.delegate.onGifSelected(view, this.gifSearchAdapter.results.get(position2), this.gifSearchAdapter.bot, true, 0);
        this.recentGifs = MediaDataController.getInstance(this.currentAccount).getRecentGifs();
        GifAdapter gifAdapter = this.gifAdapter;
        if (gifAdapter != null) {
            gifAdapter.notifyDataSetChanged();
        }
    }

    public /* synthetic */ boolean lambda$new$3$EmojiViewV2(View v, MotionEvent event) {
        return ContentPreviewViewer.getInstance().onTouch(event, this.stickersGridView, getMeasuredHeight(), this.stickersOnItemClickListener, this.contentPreviewViewerDelegate);
    }

    public /* synthetic */ void lambda$new$4$EmojiViewV2(View view, int position) {
        TLRPC.StickerSetCovered pack;
        RecyclerView.Adapter adapter = this.stickersGridView.getAdapter();
        StickersSearchGridAdapter stickersSearchGridAdapter = this.stickersSearchGridAdapter;
        if (adapter == stickersSearchGridAdapter && (pack = (TLRPC.StickerSetCovered) stickersSearchGridAdapter.positionsToSets.get(position)) != null) {
            this.delegate.onShowStickerSet(pack.set, null);
            return;
        }
        if (!(view instanceof StickerEmojiCell)) {
            return;
        }
        ContentPreviewViewer.getInstance().reset();
        StickerEmojiCell cell = (StickerEmojiCell) view;
        if (cell.isDisabled()) {
            return;
        }
        cell.disable();
        this.delegate.onStickerSelected(cell, cell.getSticker(), cell.getParentObject(), true, 0);
    }

    public /* synthetic */ void lambda$new$5$EmojiViewV2(View view, int position) {
        TLRPC.StickerSetCovered pack = (TLRPC.StickerSetCovered) this.trendingGridAdapter.positionsToSets.get(position);
        if (pack != null) {
            this.delegate.onShowStickerSet(pack.set, null);
        }
    }

    public /* synthetic */ void lambda$new$6$EmojiViewV2(int page) {
        if (page == this.trendingTabNum) {
            if (this.trendingGridView.getVisibility() != 0) {
                showTrendingTab(true);
            }
        } else if (this.trendingGridView.getVisibility() == 0) {
            showTrendingTab(false);
            saveNewPage();
        }
        if (page == this.trendingTabNum) {
            return;
        }
        if (page == this.recentTabBum) {
            this.stickersGridView.stopScroll();
            this.stickersLayoutManager.scrollToPositionWithOffset(this.stickersGridAdapter.getPositionForPack("recent"), 0);
            checkStickersTabY(null, 0);
            ScrollSlidingTabStrip scrollSlidingTabStrip = this.stickersTab;
            int i = this.recentTabBum;
            scrollSlidingTabStrip.onPageScrolled(i, i > 0 ? i : this.stickersTabOffset);
            return;
        }
        if (page == this.favTabBum) {
            this.stickersGridView.stopScroll();
            this.stickersLayoutManager.scrollToPositionWithOffset(this.stickersGridAdapter.getPositionForPack("fav"), 0);
            checkStickersTabY(null, 0);
            ScrollSlidingTabStrip scrollSlidingTabStrip2 = this.stickersTab;
            int i2 = this.favTabBum;
            scrollSlidingTabStrip2.onPageScrolled(i2, i2 > 0 ? i2 : this.stickersTabOffset);
            return;
        }
        int index = page - this.stickersTabOffset;
        if (index >= this.stickerSets.size()) {
            return;
        }
        if (index >= this.stickerSets.size()) {
            index = this.stickerSets.size() - 1;
        }
        this.firstStickersAttach = false;
        this.stickersGridView.stopScroll();
        this.stickersLayoutManager.scrollToPositionWithOffset(this.stickersGridAdapter.getPositionForPack(this.stickerSets.get(index)), 0);
        checkStickersTabY(null, 0);
        checkScroll();
    }

    public /* synthetic */ boolean lambda$new$7$EmojiViewV2(View v, int keyCode, KeyEvent event) {
        EmojiPopupWindow emojiPopupWindow;
        if (keyCode == 82 && event.getRepeatCount() == 0 && event.getAction() == 1 && (emojiPopupWindow = this.pickerViewPopup) != null && emojiPopupWindow.isShowing()) {
            this.pickerViewPopup.dismiss();
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String addColorToCode(String code, String color) {
        String end = null;
        int length = code.length();
        if (length > 2 && code.charAt(code.length() - 2) == 8205) {
            end = code.substring(code.length() - 2);
            code = code.substring(0, code.length() - 2);
        } else if (length > 3 && code.charAt(code.length() - 3) == 8205) {
            end = code.substring(code.length() - 3);
            code = code.substring(0, code.length() - 3);
        }
        String code2 = code + color;
        if (end != null) {
            return code2 + end;
        }
        return code2;
    }

    @Override // android.view.View
    public void setTranslationY(float translationY) {
        View parent;
        super.setTranslationY(translationY);
        if (this.bottomTabContainer.getTag() == null) {
            EmojiViewDelegate emojiViewDelegate = this.delegate;
            if ((emojiViewDelegate == null || !emojiViewDelegate.isSearchOpened()) && (parent = (View) getParent()) != null) {
                float y = (getY() + getMeasuredHeight()) - parent.getHeight();
                this.bottomTabContainer.setTranslationY(-y);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startStopVisibleGifs(boolean start) {
        RecyclerListView recyclerListView = this.gifGridView;
        if (recyclerListView == null) {
            return;
        }
        int count = recyclerListView.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.gifGridView.getChildAt(a);
            if (child instanceof ContextLinkCell) {
                ContextLinkCell cell = (ContextLinkCell) child;
                ImageReceiver imageReceiver = cell.getPhotoImage();
                if (start) {
                    imageReceiver.setAllowStartAnimation(true);
                    imageReceiver.startAnimation();
                } else {
                    imageReceiver.setAllowStartAnimation(false);
                    imageReceiver.stopAnimation();
                }
            }
        }
    }

    public void addEmojiToRecent(String code) {
        if (!Emoji.isValidEmoji(code)) {
            return;
        }
        Emoji.recentEmoji.size();
        Emoji.addRecentEmoji(code);
        if (getVisibility() != 0 || this.pager.getCurrentItem() != 0) {
            Emoji.sortEmoji();
            this.emojiAdapter.notifyDataSetChanged();
        }
        Emoji.saveRecentEmoji();
    }

    public void showSearchField(boolean show) {
        GridLayoutManager layoutManager;
        ScrollSlidingTabStrip tabStrip;
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                layoutManager = this.emojiLayoutManager;
                tabStrip = this.emojiTabs;
            } else if (a == 1) {
                layoutManager = this.gifLayoutManager;
                tabStrip = null;
            } else {
                layoutManager = this.stickersLayoutManager;
                tabStrip = this.stickersTab;
            }
            if (layoutManager != null) {
                int position = layoutManager.findFirstVisibleItemPosition();
                if (show) {
                    if (position == 1 || position == 2) {
                        layoutManager.scrollToPosition(0);
                        if (tabStrip != null) {
                            tabStrip.setTranslationY(0.0f);
                        }
                    }
                } else if (position == 0) {
                    layoutManager.scrollToPositionWithOffset(1, 0);
                }
            }
        }
    }

    public void hideSearchKeyboard() {
        SearchField searchField = this.stickersSearchField;
        if (searchField != null) {
            searchField.hideKeyboard();
        }
        SearchField searchField2 = this.gifSearchField;
        if (searchField2 != null) {
            searchField2.hideKeyboard();
        }
        SearchField searchField3 = this.emojiSearchField;
        if (searchField3 != null) {
            searchField3.hideKeyboard();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openSearch(SearchField searchField) {
        SearchField currentField;
        final RecyclerListView gridView;
        ScrollSlidingTabStrip tabStrip;
        GridLayoutManager layoutManager;
        EmojiViewDelegate emojiViewDelegate;
        AnimatorSet animatorSet = this.searchAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.searchAnimation = null;
        }
        this.firstStickersAttach = false;
        this.firstGifAttach = false;
        this.firstEmojiAttach = false;
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                currentField = this.emojiSearchField;
                gridView = this.emojiGridView;
                tabStrip = this.emojiTabs;
                layoutManager = this.emojiLayoutManager;
            } else if (a == 1) {
                currentField = this.gifSearchField;
                gridView = this.gifGridView;
                tabStrip = null;
                layoutManager = this.gifLayoutManager;
            } else {
                currentField = this.stickersSearchField;
                gridView = this.stickersGridView;
                tabStrip = this.stickersTab;
                layoutManager = this.stickersLayoutManager;
            }
            if (currentField != null) {
                if (currentField != this.gifSearchField && searchField == currentField && (emojiViewDelegate = this.delegate) != null && emojiViewDelegate.isExpanded()) {
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.searchAnimation = animatorSet2;
                    if (tabStrip != null) {
                        animatorSet2.playTogether(ObjectAnimator.ofFloat(tabStrip, (Property<ScrollSlidingTabStrip, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)), ObjectAnimator.ofFloat(gridView, (Property<RecyclerListView, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)), ObjectAnimator.ofFloat(currentField, (Property<SearchField, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(0.0f)));
                    } else {
                        animatorSet2.playTogether(ObjectAnimator.ofFloat(gridView, (Property<RecyclerListView, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(48.0f)), ObjectAnimator.ofFloat(currentField, (Property<SearchField, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(0.0f)));
                    }
                    this.searchAnimation.setDuration(200L);
                    this.searchAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT_QUINT);
                    this.searchAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.29
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (animation.equals(EmojiViewV2.this.searchAnimation)) {
                                gridView.setTranslationY(0.0f);
                                if (gridView != EmojiViewV2.this.stickersGridView) {
                                    if (gridView == EmojiViewV2.this.emojiGridView) {
                                        gridView.setPadding(0, 0, 0, 0);
                                    }
                                } else {
                                    gridView.setPadding(0, AndroidUtilities.dp(4.0f), 0, 0);
                                }
                                EmojiViewV2.this.searchAnimation = null;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (animation.equals(EmojiViewV2.this.searchAnimation)) {
                                EmojiViewV2.this.searchAnimation = null;
                            }
                        }
                    });
                    this.searchAnimation.start();
                } else {
                    currentField.setTranslationY(AndroidUtilities.dp(0.0f));
                    if (tabStrip != null) {
                        tabStrip.setTranslationY(-AndroidUtilities.dp(48.0f));
                    }
                    if (gridView == this.stickersGridView) {
                        gridView.setPadding(0, AndroidUtilities.dp(4.0f), 0, 0);
                    } else if (gridView == this.emojiGridView) {
                        gridView.setPadding(0, 0, 0, 0);
                    }
                    layoutManager.scrollToPositionWithOffset(0, 0);
                }
            }
        }
    }

    private void showEmojiShadow(boolean show, boolean animated) {
        if (show && this.emojiTabsShadow.getTag() == null) {
            return;
        }
        if (!show && this.emojiTabsShadow.getTag() != null) {
            return;
        }
        AnimatorSet animatorSet = this.emojiTabShadowAnimator;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.emojiTabShadowAnimator = null;
        }
        this.emojiTabsShadow.setTag(show ? null : 1);
        if (animated) {
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.emojiTabShadowAnimator = animatorSet2;
            Animator[] animatorArr = new Animator[1];
            View view = this.emojiTabsShadow;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property, fArr);
            animatorSet2.playTogether(animatorArr);
            this.emojiTabShadowAnimator.setDuration(200L);
            this.emojiTabShadowAnimator.setInterpolator(CubicBezierInterpolator.EASE_OUT);
            this.emojiTabShadowAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.30
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    EmojiViewV2.this.emojiTabShadowAnimator = null;
                }
            });
            this.emojiTabShadowAnimator.start();
            return;
        }
        this.emojiTabsShadow.setAlpha(show ? 1.0f : 0.0f);
    }

    public void closeSearch(boolean animated) {
        closeSearch(animated, -1L);
    }

    public void closeSearch(boolean animated, long scrollToSet) {
        SearchField currentField;
        final RecyclerListView gridView;
        final GridLayoutManager layoutManager;
        ScrollSlidingTabStrip tabStrip;
        TLRPC.TL_messages_stickerSet set;
        int pos;
        AnimatorSet animatorSet = this.searchAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.searchAnimation = null;
        }
        int currentItem = this.pager.getCurrentItem();
        if (currentItem == 2 && scrollToSet != -1 && (set = MediaDataController.getInstance(this.currentAccount).getStickerSetById(scrollToSet)) != null && (pos = this.stickersGridAdapter.getPositionForPack(set)) >= 0) {
            this.stickersLayoutManager.scrollToPositionWithOffset(pos, AndroidUtilities.dp(60.0f));
        }
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                currentField = this.emojiSearchField;
                gridView = this.emojiGridView;
                layoutManager = this.emojiLayoutManager;
                tabStrip = this.emojiTabs;
            } else if (a == 1) {
                currentField = this.gifSearchField;
                gridView = this.gifGridView;
                layoutManager = this.gifLayoutManager;
                tabStrip = null;
            } else {
                currentField = this.stickersSearchField;
                gridView = this.stickersGridView;
                layoutManager = this.stickersLayoutManager;
                tabStrip = this.stickersTab;
            }
            if (currentField != null) {
                currentField.searchEditText.setText("");
                if (a == currentItem && animated) {
                    AnimatorSet animatorSet2 = new AnimatorSet();
                    this.searchAnimation = animatorSet2;
                    if (tabStrip != null) {
                        animatorSet2.playTogether(ObjectAnimator.ofFloat(tabStrip, (Property<ScrollSlidingTabStrip, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(gridView, (Property<RecyclerListView, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(48.0f) - this.searchFieldHeight), ObjectAnimator.ofFloat(currentField, (Property<SearchField, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(48.0f) - this.searchFieldHeight));
                    } else {
                        animatorSet2.playTogether(ObjectAnimator.ofFloat(gridView, (Property<RecyclerListView, Float>) View.TRANSLATION_Y, -this.searchFieldHeight), ObjectAnimator.ofFloat(currentField, (Property<SearchField, Float>) View.TRANSLATION_Y, -this.searchFieldHeight));
                    }
                    this.searchAnimation.setDuration(200L);
                    this.searchAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT_QUINT);
                    this.searchAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.31
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (animation.equals(EmojiViewV2.this.searchAnimation)) {
                                layoutManager.findFirstVisibleItemPosition();
                                int firstVisPos = layoutManager.findFirstVisibleItemPosition();
                                int top = 0;
                                if (firstVisPos != -1) {
                                    View firstVisView = layoutManager.findViewByPosition(firstVisPos);
                                    top = (int) (firstVisView.getTop() + gridView.getTranslationY());
                                }
                                gridView.setTranslationY(0.0f);
                                if (gridView != EmojiViewV2.this.stickersGridView) {
                                    if (gridView == EmojiViewV2.this.emojiGridView) {
                                        gridView.setPadding(0, AndroidUtilities.dp(38.0f), 0, 0);
                                    }
                                } else {
                                    gridView.setPadding(0, AndroidUtilities.dp(52.0f), 0, 0);
                                }
                                if (gridView == EmojiViewV2.this.gifGridView) {
                                    layoutManager.scrollToPositionWithOffset(1, 0);
                                } else if (firstVisPos != -1) {
                                    layoutManager.scrollToPositionWithOffset(firstVisPos, top - gridView.getPaddingTop());
                                }
                                EmojiViewV2.this.searchAnimation = null;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (animation.equals(EmojiViewV2.this.searchAnimation)) {
                                EmojiViewV2.this.searchAnimation = null;
                            }
                        }
                    });
                    this.searchAnimation.start();
                } else {
                    layoutManager.scrollToPositionWithOffset(1, 0);
                    currentField.setTranslationY(AndroidUtilities.dp(48.0f) - this.searchFieldHeight);
                    if (tabStrip != null) {
                        tabStrip.setTranslationY(0.0f);
                    }
                    if (gridView == this.stickersGridView) {
                        gridView.setPadding(0, AndroidUtilities.dp(52.0f), 0, 0);
                    } else if (gridView == this.emojiGridView) {
                        gridView.setPadding(0, AndroidUtilities.dp(38.0f), 0, 0);
                    }
                }
            }
        }
        if (!animated) {
            this.delegate.onSearchOpenClose(0);
        }
        showBottomTab(true, animated);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkStickersSearchFieldScroll(boolean isLayout) {
        RecyclerListView recyclerListView;
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
            RecyclerView.ViewHolder holder = this.stickersGridView.findViewHolderForAdapterPosition(0);
            if (holder == null) {
                this.stickersSearchField.showShadow(true, !isLayout);
                return;
            } else {
                this.stickersSearchField.showShadow(holder.itemView.getTop() < this.stickersGridView.getPaddingTop(), !isLayout);
                return;
            }
        }
        if (this.stickersSearchField == null || (recyclerListView = this.stickersGridView) == null) {
            return;
        }
        RecyclerView.ViewHolder holder2 = recyclerListView.findViewHolderForAdapterPosition(0);
        if (holder2 != null) {
            this.stickersSearchField.setTranslationY(holder2.itemView.getTop());
        } else {
            this.stickersSearchField.setTranslationY(-this.searchFieldHeight);
        }
        this.stickersSearchField.showShadow(false, !isLayout);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkBottomTabScroll(float dy) {
        int offset;
        this.lastBottomScrollDy += dy;
        if (this.pager.getCurrentItem() == 0) {
            offset = AndroidUtilities.dp(38.0f);
        } else {
            offset = AndroidUtilities.dp(48.0f);
        }
        float f = this.lastBottomScrollDy;
        if (f >= offset) {
            showBottomTab(false, true);
            return;
        }
        if (f <= (-offset)) {
            showBottomTab(true, true);
        } else if ((this.bottomTabContainer.getTag() == null && this.lastBottomScrollDy < 0.0f) || (this.bottomTabContainer.getTag() != null && this.lastBottomScrollDy > 0.0f)) {
            this.lastBottomScrollDy = 0.0f;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showBackspaceButton(final boolean show, boolean animated) {
        if (show && this.backspaceButton.getTag() == null) {
            return;
        }
        if (!show && this.backspaceButton.getTag() != null) {
            return;
        }
        AnimatorSet animatorSet = this.backspaceButtonAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.backspaceButtonAnimation = null;
        }
        this.backspaceButton.setTag(show ? null : 1);
        if (animated) {
            if (show) {
                this.backspaceButton.setVisibility(0);
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.backspaceButtonAnimation = animatorSet2;
            Animator[] animatorArr = new Animator[3];
            ImageView imageView = this.backspaceButton;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(imageView, (Property<ImageView, Float>) property, fArr);
            ImageView imageView2 = this.backspaceButton;
            Property property2 = View.SCALE_X;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.0f;
            animatorArr[1] = ObjectAnimator.ofFloat(imageView2, (Property<ImageView, Float>) property2, fArr2);
            ImageView imageView3 = this.backspaceButton;
            Property property3 = View.SCALE_Y;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            animatorArr[2] = ObjectAnimator.ofFloat(imageView3, (Property<ImageView, Float>) property3, fArr3);
            animatorSet2.playTogether(animatorArr);
            this.backspaceButtonAnimation.setDuration(200L);
            this.backspaceButtonAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
            this.backspaceButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.32
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (!show) {
                        EmojiViewV2.this.backspaceButton.setVisibility(4);
                    }
                }
            });
            this.backspaceButtonAnimation.start();
            return;
        }
        this.backspaceButton.setAlpha(show ? 1.0f : 0.0f);
        this.backspaceButton.setScaleX(show ? 1.0f : 0.0f);
        this.backspaceButton.setScaleY(show ? 1.0f : 0.0f);
        this.backspaceButton.setVisibility(show ? 0 : 4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showStickerSettingsButton(final boolean show, boolean animated) {
        ImageView imageView = this.stickerSettingsButton;
        if (imageView == null) {
            return;
        }
        if (show && imageView.getTag() == null) {
            return;
        }
        if (!show && this.stickerSettingsButton.getTag() != null) {
            return;
        }
        AnimatorSet animatorSet = this.stickersButtonAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.stickersButtonAnimation = null;
        }
        this.stickerSettingsButton.setTag(show ? null : 1);
        if (animated) {
            if (show) {
                this.stickerSettingsButton.setVisibility(0);
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.stickersButtonAnimation = animatorSet2;
            Animator[] animatorArr = new Animator[3];
            ImageView imageView2 = this.stickerSettingsButton;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(imageView2, (Property<ImageView, Float>) property, fArr);
            ImageView imageView3 = this.stickerSettingsButton;
            Property property2 = View.SCALE_X;
            float[] fArr2 = new float[1];
            fArr2[0] = show ? 1.0f : 0.0f;
            animatorArr[1] = ObjectAnimator.ofFloat(imageView3, (Property<ImageView, Float>) property2, fArr2);
            ImageView imageView4 = this.stickerSettingsButton;
            Property property3 = View.SCALE_Y;
            float[] fArr3 = new float[1];
            fArr3[0] = show ? 1.0f : 0.0f;
            animatorArr[2] = ObjectAnimator.ofFloat(imageView4, (Property<ImageView, Float>) property3, fArr3);
            animatorSet2.playTogether(animatorArr);
            this.stickersButtonAnimation.setDuration(200L);
            this.stickersButtonAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
            this.stickersButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.33
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (!show) {
                        EmojiViewV2.this.stickerSettingsButton.setVisibility(4);
                    }
                }
            });
            this.stickersButtonAnimation.start();
            return;
        }
        this.stickerSettingsButton.setAlpha(show ? 1.0f : 0.0f);
        this.stickerSettingsButton.setScaleX(show ? 1.0f : 0.0f);
        this.stickerSettingsButton.setScaleY(show ? 1.0f : 0.0f);
        this.stickerSettingsButton.setVisibility(show ? 0 : 4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showBottomTab(boolean show, boolean animated) {
        float fDp;
        float fDp2;
        this.lastBottomScrollDy = 0.0f;
        if (show && this.bottomTabContainer.getTag() == null) {
            return;
        }
        if (show || this.bottomTabContainer.getTag() == null) {
            EmojiViewDelegate emojiViewDelegate = this.delegate;
            if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
                return;
            }
            AnimatorSet animatorSet = this.bottomTabContainerAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.bottomTabContainerAnimation = null;
            }
            this.bottomTabContainer.setTag(show ? null : 1);
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.bottomTabContainerAnimation = animatorSet2;
                Animator[] animatorArr = new Animator[2];
                FrameLayout frameLayout = this.bottomTabContainer;
                Property property = View.TRANSLATION_Y;
                float[] fArr = new float[1];
                if (show) {
                    fDp2 = 0.0f;
                } else {
                    fDp2 = AndroidUtilities.dp(this.needEmojiSearch ? 49.0f : 54.0f);
                }
                fArr[0] = fDp2;
                animatorArr[0] = ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr);
                View view = this.shadowLine;
                Property property2 = View.TRANSLATION_Y;
                float[] fArr2 = new float[1];
                if (!show) {
                    fDp = AndroidUtilities.dp(49.0f);
                }
                fArr2[0] = fDp;
                animatorArr[1] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property2, fArr2);
                animatorSet2.playTogether(animatorArr);
                this.bottomTabContainerAnimation.setDuration(200L);
                this.bottomTabContainerAnimation.setInterpolator(CubicBezierInterpolator.EASE_OUT);
                this.bottomTabContainerAnimation.start();
                return;
            }
            FrameLayout frameLayout2 = this.bottomTabContainer;
            if (show) {
                fDp = 0.0f;
            } else {
                fDp = AndroidUtilities.dp(this.needEmojiSearch ? 49.0f : 54.0f);
            }
            frameLayout2.setTranslationY(fDp);
            this.shadowLine.setTranslationY(show ? 0.0f : AndroidUtilities.dp(49.0f));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkStickersTabY(View list, int dy) {
        RecyclerListView recyclerListView;
        RecyclerView.ViewHolder holder;
        if (list == null) {
            ScrollSlidingTabStrip scrollSlidingTabStrip = this.stickersTab;
            this.stickersMinusDy = 0;
            scrollSlidingTabStrip.setTranslationY(0);
            return;
        }
        if (list.getVisibility() != 0) {
            return;
        }
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
            return;
        }
        if (dy > 0 && (recyclerListView = this.stickersGridView) != null && recyclerListView.getVisibility() == 0 && (holder = this.stickersGridView.findViewHolderForAdapterPosition(0)) != null && holder.itemView.getTop() + this.searchFieldHeight >= this.stickersGridView.getPaddingTop()) {
            return;
        }
        int i = this.stickersMinusDy - dy;
        this.stickersMinusDy = i;
        if (i > 0) {
            this.stickersMinusDy = 0;
        } else if (i < (-AndroidUtilities.dp(288.0f))) {
            this.stickersMinusDy = -AndroidUtilities.dp(288.0f);
        }
        this.stickersTab.setTranslationY(Math.max(-AndroidUtilities.dp(48.0f), this.stickersMinusDy));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkEmojiSearchFieldScroll(boolean isLayout) {
        RecyclerListView recyclerListView;
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
            RecyclerView.ViewHolder holder = this.emojiGridView.findViewHolderForAdapterPosition(0);
            if (holder == null) {
                this.emojiSearchField.showShadow(true, !isLayout);
            } else {
                this.emojiSearchField.showShadow(holder.itemView.getTop() < this.emojiGridView.getPaddingTop(), !isLayout);
            }
            showEmojiShadow(false, !isLayout);
            return;
        }
        if (this.emojiSearchField == null || (recyclerListView = this.emojiGridView) == null) {
            return;
        }
        RecyclerView.ViewHolder holder2 = recyclerListView.findViewHolderForAdapterPosition(0);
        if (holder2 != null) {
            this.emojiSearchField.setTranslationY(holder2.itemView.getTop());
        } else {
            this.emojiSearchField.setTranslationY(-this.searchFieldHeight);
        }
        this.emojiSearchField.showShadow(false, !isLayout);
        showEmojiShadow(holder2 == null || ((float) holder2.itemView.getTop()) < ((float) (AndroidUtilities.dp(38.0f) - this.searchFieldHeight)) + this.emojiTabs.getTranslationY(), !isLayout);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkEmojiTabY(View list, int dy) {
        RecyclerListView recyclerListView;
        RecyclerView.ViewHolder holder;
        if (list == null) {
            ScrollSlidingTabStrip scrollSlidingTabStrip = this.emojiTabs;
            this.emojiMinusDy = 0;
            scrollSlidingTabStrip.setTranslationY(0);
            this.emojiTabsShadow.setTranslationY(this.emojiMinusDy);
            return;
        }
        if (list.getVisibility() != 0) {
            return;
        }
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
            return;
        }
        if (dy > 0 && (recyclerListView = this.emojiGridView) != null && recyclerListView.getVisibility() == 0 && (holder = this.emojiGridView.findViewHolderForAdapterPosition(0)) != null) {
            if (holder.itemView.getTop() + (this.needEmojiSearch ? this.searchFieldHeight : 0) >= this.emojiGridView.getPaddingTop()) {
                return;
            }
        }
        int i = this.emojiMinusDy - dy;
        this.emojiMinusDy = i;
        if (i > 0) {
            this.emojiMinusDy = 0;
        } else if (i < (-AndroidUtilities.dp(288.0f))) {
            this.emojiMinusDy = -AndroidUtilities.dp(288.0f);
        }
        this.emojiTabs.setTranslationY(Math.max(-AndroidUtilities.dp(38.0f), this.emojiMinusDy));
        this.emojiTabsShadow.setTranslationY(this.emojiTabs.getTranslationY());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkGifSearchFieldScroll(boolean isLayout) {
        RecyclerListView recyclerListView;
        int position;
        RecyclerListView recyclerListView2 = this.gifGridView;
        if (recyclerListView2 != null) {
            RecyclerView.Adapter adapter = recyclerListView2.getAdapter();
            GifSearchAdapter gifSearchAdapter = this.gifSearchAdapter;
            if (adapter == gifSearchAdapter && !gifSearchAdapter.searchEndReached && this.gifSearchAdapter.reqId == 0 && !this.gifSearchAdapter.results.isEmpty() && (position = this.gifLayoutManager.findLastVisibleItemPosition()) != -1 && position > this.gifLayoutManager.getItemCount() - 5) {
                GifSearchAdapter gifSearchAdapter2 = this.gifSearchAdapter;
                gifSearchAdapter2.search(gifSearchAdapter2.lastSearchImageString, this.gifSearchAdapter.nextSearchOffset, true);
            }
        }
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
            RecyclerView.ViewHolder holder = this.gifGridView.findViewHolderForAdapterPosition(0);
            if (holder == null) {
                this.gifSearchField.showShadow(true, !isLayout);
                return;
            } else {
                this.gifSearchField.showShadow(holder.itemView.getTop() < this.gifGridView.getPaddingTop(), !isLayout);
                return;
            }
        }
        if (this.gifSearchField == null || (recyclerListView = this.gifGridView) == null) {
            return;
        }
        RecyclerView.ViewHolder holder2 = recyclerListView.findViewHolderForAdapterPosition(0);
        if (holder2 != null) {
            this.gifSearchField.setTranslationY(holder2.itemView.getTop());
        } else {
            this.gifSearchField.setTranslationY(-this.searchFieldHeight);
        }
        this.gifSearchField.showShadow(false, !isLayout);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkScroll() {
        int firstTab;
        int firstVisibleItem = this.stickersLayoutManager.findFirstVisibleItemPosition();
        if (firstVisibleItem == -1 || this.stickersGridView == null) {
            return;
        }
        if (this.favTabBum > 0) {
            firstTab = this.favTabBum;
        } else {
            int firstTab2 = this.recentTabBum;
            if (firstTab2 > 0) {
                firstTab = this.recentTabBum;
            } else {
                firstTab = this.stickersTabOffset;
            }
        }
        this.stickersTab.onPageScrolled(this.stickersGridAdapter.getTabForPosition(firstVisibleItem), firstTab);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveNewPage() {
        int newPage;
        ViewPager viewPager = this.pager;
        if (viewPager == null) {
            return;
        }
        int currentItem = viewPager.getCurrentItem();
        if (currentItem == 2) {
            newPage = 1;
        } else if (currentItem == 1) {
            newPage = 2;
        } else {
            newPage = 0;
        }
        if (this.currentPage != newPage) {
            this.currentPage = newPage;
            MessagesController.getGlobalEmojiSettings().edit().putInt("selected_page", newPage).commit();
        }
    }

    public void clearRecentEmoji() {
        Emoji.clearRecentEmoji();
        this.emojiAdapter.notifyDataSetChanged();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showTrendingTab(boolean show) {
        if (show) {
            this.trendingGridView.setVisibility(0);
            this.stickersGridView.setVisibility(8);
            this.stickersSearchField.setVisibility(8);
            ScrollSlidingTabStrip scrollSlidingTabStrip = this.stickersTab;
            int i = this.trendingTabNum;
            int i2 = this.recentTabBum;
            if (i2 <= 0) {
                i2 = this.stickersTabOffset;
            }
            scrollSlidingTabStrip.onPageScrolled(i, i2);
            saveNewPage();
            return;
        }
        this.trendingGridView.setVisibility(8);
        this.stickersGridView.setVisibility(0);
        this.stickersSearchField.setVisibility(0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onPageScrolled(int position, int width, int positionOffsetPixels) {
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate == null) {
            return;
        }
        if (position == 1) {
            emojiViewDelegate.onTabOpened(positionOffsetPixels != 0 ? 2 : 0);
        } else if (position == 2) {
            emojiViewDelegate.onTabOpened(3);
        } else {
            emojiViewDelegate.onTabOpened(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void postBackspaceRunnable(final int time) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$z9lmS1sEbI_45I3ZSY_BsB0bYEE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$postBackspaceRunnable$8$EmojiViewV2(time);
            }
        }, time);
    }

    public /* synthetic */ void lambda$postBackspaceRunnable$8$EmojiViewV2(int time) {
        if (!this.backspacePressed) {
            return;
        }
        EmojiViewDelegate emojiViewDelegate = this.delegate;
        if (emojiViewDelegate != null && emojiViewDelegate.onBackspace()) {
            this.backspaceButton.performHapticFeedback(3);
        }
        this.backspaceOnce = true;
        postBackspaceRunnable(Math.max(50, time - 100));
    }

    public void switchToGifRecent() {
        showBackspaceButton(false, false);
        showStickerSettingsButton(false, false);
        this.pager.setCurrentItem(1, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateEmojiTabs() {
        int i = !Emoji.recentEmoji.isEmpty() ? 1 : 0;
        int i2 = this.hasRecentEmoji;
        if (i2 != -1 && i2 == i) {
            return;
        }
        this.hasRecentEmoji = i;
        this.emojiTabs.removeTabs();
        String[] strArr = {LocaleController.getString("RecentStickers", R.string.RecentStickers), LocaleController.getString("Emoji1", R.string.Emoji1), LocaleController.getString("Emoji2", R.string.Emoji2), LocaleController.getString("Emoji3", R.string.Emoji3), LocaleController.getString("Emoji4", R.string.Emoji4), LocaleController.getString("Emoji5", R.string.Emoji5), LocaleController.getString("Emoji6", R.string.Emoji6), LocaleController.getString("Emoji7", R.string.Emoji7), LocaleController.getString("Emoji8", R.string.Emoji8)};
        for (int i3 = 0; i3 < this.emojiIcons.length; i3++) {
            if (i3 != 0 || !Emoji.recentEmoji.isEmpty()) {
                this.emojiTabs.addIconTab(this.emojiIcons[i3]).setContentDescription(strArr[i3]);
            }
        }
        this.emojiTabs.updateTabStyles();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateStickerTabs() {
        TLObject thumb;
        ScrollSlidingTabStrip scrollSlidingTabStrip = this.stickersTab;
        if (scrollSlidingTabStrip == null) {
            return;
        }
        this.recentTabBum = -2;
        this.favTabBum = -2;
        this.trendingTabNum = -2;
        this.stickersTabOffset = 0;
        int lastPosition = scrollSlidingTabStrip.getCurrentPosition();
        this.stickersTab.removeTabs();
        ArrayList<Long> unread = MediaDataController.getInstance(this.currentAccount).getUnreadStickerSets();
        boolean hasStickers = false;
        TrendingGridAdapter trendingGridAdapter = this.trendingGridAdapter;
        if (trendingGridAdapter != null && trendingGridAdapter.getItemCount() != 0 && !unread.isEmpty()) {
            TextView textViewAddIconTabWithCounter = this.stickersTab.addIconTabWithCounter(this.stickerIcons[2]);
            this.stickersCounter = textViewAddIconTabWithCounter;
            int i = this.stickersTabOffset;
            this.trendingTabNum = i;
            this.stickersTabOffset = i + 1;
            textViewAddIconTabWithCounter.setText(String.format("%d", Integer.valueOf(unread.size())));
        }
        if (!this.favouriteStickers.isEmpty()) {
            int i2 = this.stickersTabOffset;
            this.favTabBum = i2;
            this.stickersTabOffset = i2 + 1;
            this.stickersTab.addIconTab(this.stickerIcons[1]).setContentDescription(LocaleController.getString("FavoriteStickers", R.string.FavoriteStickers));
            hasStickers = true;
        }
        if (!this.recentStickers.isEmpty()) {
            int i3 = this.stickersTabOffset;
            this.recentTabBum = i3;
            this.stickersTabOffset = i3 + 1;
            this.stickersTab.addIconTab(this.stickerIcons[0]).setContentDescription(LocaleController.getString("RecentStickers", R.string.RecentStickers));
            hasStickers = true;
        }
        this.stickerSets.clear();
        this.groupStickerSet = null;
        this.groupStickerPackPosition = -1;
        this.groupStickerPackNum = -10;
        ArrayList<TLRPC.TL_messages_stickerSet> packs = MediaDataController.getInstance(this.currentAccount).getStickerSets(0);
        for (int a = 0; a < packs.size(); a++) {
            TLRPC.TL_messages_stickerSet pack = packs.get(a);
            if (!pack.set.archived && pack.documents != null && !pack.documents.isEmpty()) {
                this.stickerSets.add(pack);
                hasStickers = true;
            }
        }
        if (this.info != null) {
            long hiddenStickerSetId = MessagesController.getEmojiSettings(this.currentAccount).getLong("group_hide_stickers_" + this.info.id, -1L);
            TLRPC.Chat chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.info.id));
            if (chat == null || this.info.stickerset == null || !ChatObject.hasAdminRights(chat)) {
                this.groupStickersHidden = hiddenStickerSetId != -1;
            } else if (this.info.stickerset != null) {
                this.groupStickersHidden = hiddenStickerSetId == this.info.stickerset.id;
            }
            if (this.info.stickerset != null) {
                TLRPC.TL_messages_stickerSet pack2 = MediaDataController.getInstance(this.currentAccount).getGroupStickerSetById(this.info.stickerset);
                if (pack2 != null && pack2.documents != null && !pack2.documents.isEmpty() && pack2.set != null) {
                    TLRPC.TL_messages_stickerSet set = new TLRPC.TL_messages_stickerSet();
                    set.documents = pack2.documents;
                    set.packs = pack2.packs;
                    set.set = pack2.set;
                    if (this.groupStickersHidden) {
                        this.groupStickerPackNum = this.stickerSets.size();
                        this.stickerSets.add(set);
                    } else {
                        this.groupStickerPackNum = 0;
                        this.stickerSets.add(0, set);
                    }
                    this.groupStickerSet = this.info.can_set_stickers ? set : null;
                }
            } else if (this.info.can_set_stickers) {
                TLRPC.TL_messages_stickerSet pack3 = new TLRPC.TL_messages_stickerSet();
                if (this.groupStickersHidden) {
                    this.groupStickerPackNum = this.stickerSets.size();
                    this.stickerSets.add(pack3);
                } else {
                    this.groupStickerPackNum = 0;
                    this.stickerSets.add(0, pack3);
                }
            }
        }
        int a2 = 0;
        while (a2 < this.stickerSets.size()) {
            if (a2 == this.groupStickerPackNum) {
                TLRPC.Chat chat2 = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.info.id));
                if (chat2 == null) {
                    this.stickerSets.remove(0);
                    a2--;
                } else {
                    this.stickersTab.addStickerTab(chat2);
                    hasStickers = true;
                }
            } else {
                TLRPC.TL_messages_stickerSet stickerSet = this.stickerSets.get(a2);
                TLRPC.Document document = stickerSet.documents.get(0);
                if (stickerSet.set.thumb instanceof TLRPC.TL_photoSize) {
                    thumb = stickerSet.set.thumb;
                } else {
                    thumb = document;
                }
                this.stickersTab.addStickerTab(thumb, document, stickerSet).setContentDescription(stickerSet.set.title + ", " + LocaleController.getString("AccDescrStickerSet", R.string.AccDescrStickerSet));
                hasStickers = true;
            }
            a2++;
        }
        TrendingGridAdapter trendingGridAdapter2 = this.trendingGridAdapter;
        if (trendingGridAdapter2 != null && trendingGridAdapter2.getItemCount() != 0 && unread.isEmpty()) {
            this.trendingTabNum = this.stickersTabOffset + this.stickerSets.size();
            this.stickersTab.addIconTab(this.stickerIcons[2]).setContentDescription(LocaleController.getString("FeaturedStickers", R.string.FeaturedStickers));
        }
        this.stickersTab.updateTabStyles();
        if (lastPosition != 0) {
            this.stickersTab.onPageScrolled(lastPosition, lastPosition);
        }
        checkPanels();
        if ((!hasStickers || (this.trendingTabNum == 0 && MediaDataController.getInstance(this.currentAccount).areAllTrendingStickerSetsUnread())) && this.trendingTabNum >= 0) {
            if (this.scrolledToTrending == 0) {
                showTrendingTab(true);
                this.scrolledToTrending = hasStickers ? 2 : 1;
                return;
            }
            return;
        }
        if (this.scrolledToTrending == 1) {
            showTrendingTab(false);
            checkScroll();
            this.stickersTab.cancelPositionAnimation();
        }
    }

    private void checkPanels() {
        int firstTab;
        RecyclerListView recyclerListView;
        if (this.stickersTab == null) {
            return;
        }
        if (this.trendingTabNum == -2 && (recyclerListView = this.trendingGridView) != null && recyclerListView.getVisibility() == 0) {
            this.trendingGridView.setVisibility(8);
            this.stickersGridView.setVisibility(0);
            this.stickersSearchField.setVisibility(0);
        }
        RecyclerListView recyclerListView2 = this.trendingGridView;
        if (recyclerListView2 != null && recyclerListView2.getVisibility() == 0) {
            ScrollSlidingTabStrip scrollSlidingTabStrip = this.stickersTab;
            int i = this.trendingTabNum;
            int i2 = this.recentTabBum;
            if (i2 <= 0) {
                i2 = this.stickersTabOffset;
            }
            scrollSlidingTabStrip.onPageScrolled(i, i2);
            return;
        }
        int position = this.stickersLayoutManager.findFirstVisibleItemPosition();
        if (position != -1) {
            if (this.favTabBum > 0) {
                firstTab = this.favTabBum;
            } else {
                int firstTab2 = this.recentTabBum;
                if (firstTab2 > 0) {
                    firstTab = this.recentTabBum;
                } else {
                    firstTab = this.stickersTabOffset;
                }
            }
            this.stickersTab.onPageScrolled(this.stickersGridAdapter.getTabForPosition(position), firstTab);
        }
    }

    public void addRecentSticker(TLRPC.Document document) {
        if (document == null) {
            return;
        }
        MediaDataController.getInstance(this.currentAccount).addRecentSticker(0, null, document, (int) (System.currentTimeMillis() / 1000), false);
        boolean wasEmpty = this.recentStickers.isEmpty();
        this.recentStickers = MediaDataController.getInstance(this.currentAccount).getRecentStickers(0);
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        if (stickersGridAdapter != null) {
            stickersGridAdapter.notifyDataSetChanged();
        }
        if (wasEmpty) {
            updateStickerTabs();
        }
    }

    public void addRecentGif(TLRPC.Document document) {
        if (document == null) {
            return;
        }
        boolean wasEmpty = this.recentGifs.isEmpty();
        this.recentGifs = MediaDataController.getInstance(this.currentAccount).getRecentGifs();
        GifAdapter gifAdapter = this.gifAdapter;
        if (gifAdapter != null) {
            gifAdapter.notifyDataSetChanged();
        }
        if (wasEmpty) {
            updateStickerTabs();
        }
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (this.isLayout) {
            return;
        }
        super.requestLayout();
    }

    public void updateColors() {
        SearchField searchField;
        if (AndroidUtilities.isInMultiwindow || this.forseMultiwindowLayout) {
            Drawable background = getBackground();
            if (background != null) {
                background.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackground), PorterDuff.Mode.MULTIPLY));
            }
        } else {
            setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            if (this.needEmojiSearch) {
                this.bottomTabContainerBackground.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            }
        }
        ScrollSlidingTabStrip scrollSlidingTabStrip = this.emojiTabs;
        if (scrollSlidingTabStrip != null) {
            scrollSlidingTabStrip.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            this.emojiTabsShadow.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
        }
        for (int a = 0; a < 3; a++) {
            if (a == 0) {
                searchField = this.stickersSearchField;
            } else if (a == 1) {
                searchField = this.emojiSearchField;
            } else {
                searchField = this.gifSearchField;
            }
            if (searchField != null) {
                searchField.backgroundView.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
                searchField.shadowView.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
                searchField.clearSearchImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiSearchIcon), PorterDuff.Mode.MULTIPLY));
                searchField.searchIconImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiSearchIcon), PorterDuff.Mode.MULTIPLY));
                Theme.setDrawableColorByKey(searchField.searchBackground.getBackground(), Theme.key_chat_emojiSearchBackground);
                searchField.searchBackground.invalidate();
                searchField.searchEditText.setHintTextColor(Theme.getColor(Theme.key_chat_emojiSearchIcon));
                searchField.searchEditText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            }
        }
        Paint paint = this.dotPaint;
        if (paint != null) {
            paint.setColor(Theme.getColor(Theme.key_chat_emojiPanelNewTrending));
        }
        RecyclerListView recyclerListView = this.emojiGridView;
        if (recyclerListView != null) {
            recyclerListView.setGlowColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        }
        RecyclerListView recyclerListView2 = this.stickersGridView;
        if (recyclerListView2 != null) {
            recyclerListView2.setGlowColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        }
        RecyclerListView recyclerListView3 = this.trendingGridView;
        if (recyclerListView3 != null) {
            recyclerListView3.setGlowColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        }
        ScrollSlidingTabStrip scrollSlidingTabStrip2 = this.stickersTab;
        if (scrollSlidingTabStrip2 != null) {
            scrollSlidingTabStrip2.setIndicatorColor(Theme.getColor(Theme.key_chat_emojiPanelStickerPackSelectorLine));
            this.stickersTab.setUnderlineColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
            this.stickersTab.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        }
        ImageView imageView = this.backspaceButton;
        if (imageView != null) {
            imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackspace), PorterDuff.Mode.MULTIPLY));
            Theme.setSelectorDrawableColor(this.backspaceButton.getBackground(), Theme.getColor(Theme.key_chat_emojiPanelBackground), false);
            Theme.setSelectorDrawableColor(this.backspaceButton.getBackground(), Theme.getColor(Theme.key_chat_emojiPanelBackground), true);
        }
        ImageView imageView2 = this.stickerSettingsButton;
        if (imageView2 != null) {
            imageView2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackspace), PorterDuff.Mode.MULTIPLY));
        }
        ImageView imageView3 = this.searchButton;
        if (imageView3 != null) {
            imageView3.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackspace), PorterDuff.Mode.MULTIPLY));
        }
        View view = this.shadowLine;
        if (view != null) {
            view.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelShadowLine));
        }
        TextView textView = this.mediaBanTooltip;
        if (textView != null) {
            ((ShapeDrawable) textView.getBackground()).getPaint().setColor(Theme.getColor(Theme.key_chat_gifSaveHintBackground));
            this.mediaBanTooltip.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
        }
        TextView textView2 = this.stickersCounter;
        if (textView2 != null) {
            textView2.setTextColor(Theme.getColor(Theme.key_chat_emojiPanelBadgeText));
            Theme.setDrawableColor(this.stickersCounter.getBackground(), Theme.getColor(Theme.key_chat_emojiPanelBadgeBackground));
            this.stickersCounter.invalidate();
        }
        int a2 = 0;
        while (true) {
            Drawable[] drawableArr = this.tabIcons;
            if (a2 >= drawableArr.length) {
                break;
            }
            Theme.setEmojiDrawableColor(drawableArr[a2], Theme.getColor(Theme.key_chat_emojiBottomPanelIcon), false);
            Theme.setEmojiDrawableColor(this.tabIcons[a2], Theme.getColor(Theme.key_chat_emojiPanelIconSelected), true);
            a2++;
        }
        int a3 = 0;
        while (true) {
            Drawable[] drawableArr2 = this.emojiIcons;
            if (a3 >= drawableArr2.length) {
                break;
            }
            Theme.setEmojiDrawableColor(drawableArr2[a3], Theme.getColor(Theme.key_chat_emojiPanelIcon), false);
            Theme.setEmojiDrawableColor(this.emojiIcons[a3], Theme.getColor(Theme.key_chat_emojiPanelIconSelected), true);
            a3++;
        }
        int a4 = 0;
        while (true) {
            Drawable[] drawableArr3 = this.stickerIcons;
            if (a4 < drawableArr3.length) {
                Theme.setEmojiDrawableColor(drawableArr3[a4], Theme.getColor(Theme.key_chat_emojiPanelIcon), false);
                Theme.setEmojiDrawableColor(this.stickerIcons[a4], Theme.getColor(Theme.key_chat_emojiPanelIconSelected), true);
                a4++;
            } else {
                return;
            }
        }
    }

    @Override // android.widget.FrameLayout, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        this.isLayout = true;
        if (AndroidUtilities.isInMultiwindow || this.forseMultiwindowLayout) {
            if (this.currentBackgroundType != 1) {
                if (Build.VERSION.SDK_INT >= 21) {
                    setOutlineProvider((ViewOutlineProvider) this.outlineProvider);
                    setClipToOutline(true);
                    setElevation(AndroidUtilities.dp(2.0f));
                }
                setBackgroundResource(R.drawable.smiles_popup);
                getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelBackground), PorterDuff.Mode.MULTIPLY));
                if (this.needEmojiSearch) {
                    this.bottomTabContainerBackground.setBackgroundDrawable(null);
                }
                this.currentBackgroundType = 1;
            }
        } else if (this.currentBackgroundType != 0) {
            if (Build.VERSION.SDK_INT >= 21) {
                setOutlineProvider(null);
                setClipToOutline(false);
                setElevation(0.0f);
            }
            setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            if (this.needEmojiSearch) {
                this.bottomTabContainerBackground.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
            }
            this.currentBackgroundType = 0;
        }
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(heightMeasureSpec), 1073741824));
        this.isLayout = false;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if (this.lastNotifyWidth != right - left) {
            this.lastNotifyWidth = right - left;
            reloadStickersAdapter();
        }
        View parent = (View) getParent();
        if (parent != null) {
            int newHeight = bottom - top;
            int newHeight2 = parent.getHeight();
            if (this.lastNotifyHeight != newHeight || this.lastNotifyHeight2 != newHeight2) {
                EmojiViewDelegate emojiViewDelegate = this.delegate;
                if (emojiViewDelegate != null && emojiViewDelegate.isSearchOpened()) {
                    this.bottomTabContainer.setTranslationY(AndroidUtilities.dp(49.0f));
                } else if (this.bottomTabContainer.getTag() == null) {
                    if (newHeight < this.lastNotifyHeight) {
                        this.bottomTabContainer.setTranslationY(0.0f);
                    } else {
                        float y = (getY() + getMeasuredHeight()) - parent.getHeight();
                        this.bottomTabContainer.setTranslationY(-y);
                    }
                }
                this.lastNotifyHeight = newHeight;
                this.lastNotifyHeight2 = newHeight2;
            }
        }
        super.onLayout(changed, left, top, right, bottom);
    }

    private void reloadStickersAdapter() {
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        if (stickersGridAdapter != null) {
            stickersGridAdapter.notifyDataSetChanged();
        }
        TrendingGridAdapter trendingGridAdapter = this.trendingGridAdapter;
        if (trendingGridAdapter != null) {
            trendingGridAdapter.notifyDataSetChanged();
        }
        StickersSearchGridAdapter stickersSearchGridAdapter = this.stickersSearchGridAdapter;
        if (stickersSearchGridAdapter != null) {
            stickersSearchGridAdapter.notifyDataSetChanged();
        }
        if (ContentPreviewViewer.getInstance().isVisible()) {
            ContentPreviewViewer.getInstance().close();
        }
        ContentPreviewViewer.getInstance().reset();
    }

    public void setDelegate(EmojiViewDelegate emojiViewDelegate) {
        this.delegate = emojiViewDelegate;
    }

    public void setDragListener(DragListener listener) {
        this.dragListener = listener;
    }

    public void setChatInfo(TLRPC.ChatFull chatInfo) {
        this.info = chatInfo;
        updateStickerTabs();
    }

    public void invalidateViews() {
        this.emojiGridView.invalidateViews();
    }

    public void setForseMultiwindowLayout(boolean value) {
        this.forseMultiwindowLayout = value;
    }

    public void onOpen(boolean forceEmoji) {
        if (this.currentPage != 0 && this.currentChatId != 0) {
            this.currentPage = 0;
        }
        if (this.currentPage == 0 || forceEmoji || this.views.size() == 1) {
            showBackspaceButton(true, false);
            showStickerSettingsButton(false, false);
            if (this.pager.getCurrentItem() != 0) {
                this.pager.setCurrentItem(0, !forceEmoji);
                return;
            }
            return;
        }
        int i = this.currentPage;
        if (i == 1) {
            showBackspaceButton(false, false);
            showStickerSettingsButton(true, false);
            if (this.pager.getCurrentItem() != 2) {
                this.pager.setCurrentItem(2, false);
            }
            if (this.stickersTab != null) {
                if (this.trendingTabNum == 0 && MediaDataController.getInstance(this.currentAccount).areAllTrendingStickerSetsUnread()) {
                    showTrendingTab(true);
                    return;
                }
                int i2 = this.recentTabBum;
                if (i2 >= 0) {
                    this.stickersTab.selectTab(i2);
                    return;
                }
                int i3 = this.favTabBum;
                if (i3 >= 0) {
                    this.stickersTab.selectTab(i3);
                    return;
                } else {
                    this.stickersTab.selectTab(this.stickersTabOffset);
                    return;
                }
            }
            return;
        }
        if (i == 2) {
            showBackspaceButton(false, false);
            showStickerSettingsButton(false, false);
            if (this.pager.getCurrentItem() != 1) {
                this.pager.setCurrentItem(1, false);
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.newEmojiSuggestionsAvailable);
        if (this.stickersGridAdapter != null) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.stickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recentImagesDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.featuredStickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.groupStickersDidLoad);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$Ak8o0-pOo07g-nM-C1aD_1mbyDY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAttachedToWindow$9$EmojiViewV2();
                }
            });
        }
    }

    public /* synthetic */ void lambda$onAttachedToWindow$9$EmojiViewV2() {
        updateStickerTabs();
        reloadStickersAdapter();
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        if (visibility != 8) {
            Emoji.sortEmoji();
            this.emojiAdapter.notifyDataSetChanged();
            if (this.stickersGridAdapter != null) {
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.stickersDidLoad);
                NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recentDocumentsDidLoad);
                updateStickerTabs();
                reloadStickersAdapter();
            }
            TrendingGridAdapter trendingGridAdapter = this.trendingGridAdapter;
            if (trendingGridAdapter != null) {
                this.trendingLoaded = false;
                trendingGridAdapter.notifyDataSetChanged();
            }
            checkDocuments(true);
            checkDocuments(false);
            MediaDataController.getInstance(this.currentAccount).loadRecents(0, true, true, false);
            MediaDataController.getInstance(this.currentAccount).loadRecents(0, false, true, false);
            MediaDataController.getInstance(this.currentAccount).loadRecents(2, false, true, false);
        }
    }

    public int getCurrentPage() {
        return this.currentPage;
    }

    public void onDestroy() {
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.newEmojiSuggestionsAvailable);
        if (this.stickersGridAdapter != null) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.stickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recentDocumentsDidLoad);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.featuredStickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.groupStickersDidLoad);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        EmojiPopupWindow emojiPopupWindow = this.pickerViewPopup;
        if (emojiPopupWindow != null && emojiPopupWindow.isShowing()) {
            this.pickerViewPopup.dismiss();
        }
    }

    private void checkDocuments(boolean isGif) {
        if (isGif) {
            this.recentGifs = MediaDataController.getInstance(this.currentAccount).getRecentGifs();
            GifAdapter gifAdapter = this.gifAdapter;
            if (gifAdapter != null) {
                gifAdapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        int previousCount = this.recentStickers.size();
        int previousCount2 = this.favouriteStickers.size();
        this.recentStickers = MediaDataController.getInstance(this.currentAccount).getRecentStickers(0);
        this.favouriteStickers = MediaDataController.getInstance(this.currentAccount).getRecentStickers(2);
        for (int a = 0; a < this.favouriteStickers.size(); a++) {
            TLRPC.Document favSticker = this.favouriteStickers.get(a);
            int b = 0;
            while (true) {
                if (b < this.recentStickers.size()) {
                    TLRPC.Document recSticker = this.recentStickers.get(b);
                    if (recSticker.dc_id != favSticker.dc_id || recSticker.id != favSticker.id) {
                        b++;
                    } else {
                        this.recentStickers.remove(b);
                        break;
                    }
                }
            }
        }
        if (previousCount != this.recentStickers.size() || previousCount2 != this.favouriteStickers.size()) {
            updateStickerTabs();
        }
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        if (stickersGridAdapter != null) {
            stickersGridAdapter.notifyDataSetChanged();
        }
        checkPanels();
    }

    public void setStickersBanned(boolean value, int chatId) {
        if (this.typeTabs == null) {
            return;
        }
        if (value) {
            this.currentChatId = chatId;
        } else {
            this.currentChatId = 0;
        }
        View view = this.typeTabs.getTab(2);
        if (view != null) {
            view.setAlpha(this.currentChatId != 0 ? 0.5f : 1.0f);
            if (this.currentChatId != 0 && this.pager.getCurrentItem() != 0) {
                showBackspaceButton(true, true);
                showStickerSettingsButton(false, true);
                this.pager.setCurrentItem(0, false);
            }
        }
    }

    public void showStickerBanHint(boolean gif) {
        TLRPC.Chat chat;
        if (this.mediaBanTooltip.getVisibility() == 0 || (chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(this.currentChatId))) == null) {
            return;
        }
        if (!ChatObject.hasAdminRights(chat) && chat.default_banned_rights != null && chat.default_banned_rights.send_stickers) {
            if (gif) {
                this.mediaBanTooltip.setText(LocaleController.getString("GlobalAttachGifRestricted", R.string.GlobalAttachGifRestricted));
            } else {
                this.mediaBanTooltip.setText(LocaleController.getString("GlobalAttachStickersRestricted", R.string.GlobalAttachStickersRestricted));
            }
        } else {
            if (chat.banned_rights == null) {
                return;
            }
            if (AndroidUtilities.isBannedForever(chat.banned_rights)) {
                if (gif) {
                    this.mediaBanTooltip.setText(LocaleController.getString("AttachGifRestrictedForever", R.string.AttachGifRestrictedForever));
                } else {
                    this.mediaBanTooltip.setText(LocaleController.getString("AttachStickersRestrictedForever", R.string.AttachStickersRestrictedForever));
                }
            } else if (gif) {
                this.mediaBanTooltip.setText(LocaleController.formatString("AttachGifRestricted", R.string.AttachGifRestricted, LocaleController.formatDateForBan(chat.banned_rights.until_date)));
            } else {
                this.mediaBanTooltip.setText(LocaleController.formatString("AttachStickersRestricted", R.string.AttachStickersRestricted, LocaleController.formatDateForBan(chat.banned_rights.until_date)));
            }
        }
        this.mediaBanTooltip.setVisibility(0);
        AnimatorSet AnimatorSet = new AnimatorSet();
        AnimatorSet.playTogether(ObjectAnimator.ofFloat(this.mediaBanTooltip, (Property<TextView, Float>) View.ALPHA, 0.0f, 1.0f));
        AnimatorSet.addListener(new AnonymousClass34());
        AnimatorSet.setDuration(300L);
        AnimatorSet.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.EmojiViewV2$34, reason: invalid class name */
    class AnonymousClass34 extends AnimatorListenerAdapter {
        AnonymousClass34() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$34$vIzBU2dfBydWtParD2VEMpn2A-w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$EmojiViewV2$34();
                }
            }, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$EmojiViewV2$34() {
            if (EmojiViewV2.this.mediaBanTooltip == null) {
                return;
            }
            AnimatorSet AnimatorSet1 = new AnimatorSet();
            AnimatorSet1.playTogether(ObjectAnimator.ofFloat(EmojiViewV2.this.mediaBanTooltip, (Property<TextView, Float>) View.ALPHA, 0.0f));
            AnimatorSet1.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.34.1
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation1) {
                    if (EmojiViewV2.this.mediaBanTooltip != null) {
                        EmojiViewV2.this.mediaBanTooltip.setVisibility(4);
                    }
                }
            });
            AnimatorSet1.setDuration(300L);
            AnimatorSet1.start();
        }
    }

    private void updateVisibleTrendingSets() {
        RecyclerListView gridView;
        TrendingGridAdapter trendingGridAdapter = this.trendingGridAdapter;
        if (trendingGridAdapter == null || trendingGridAdapter == null) {
            return;
        }
        for (int b = 0; b < 2; b++) {
            if (b == 0) {
                try {
                    gridView = this.trendingGridView;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            } else {
                gridView = this.stickersGridView;
            }
            int count = gridView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = gridView.getChildAt(a);
                if (child instanceof FeaturedStickerSetInfoCell) {
                    RecyclerListView.Holder holder = (RecyclerListView.Holder) gridView.getChildViewHolder(child);
                    if (holder != null) {
                        FeaturedStickerSetInfoCell cell = (FeaturedStickerSetInfoCell) child;
                        ArrayList<Long> unreadStickers = MediaDataController.getInstance(this.currentAccount).getUnreadStickerSets();
                        TLRPC.StickerSetCovered stickerSetCovered = cell.getStickerSet();
                        boolean unread = unreadStickers != null && unreadStickers.contains(Long.valueOf(stickerSetCovered.set.id));
                        cell.setStickerSet(stickerSetCovered, unread);
                        if (unread) {
                            MediaDataController.getInstance(this.currentAccount).markFaturedStickersByIdAsRead(stickerSetCovered.set.id);
                        }
                        boolean installing = this.installingStickerSets.indexOfKey(stickerSetCovered.set.id) >= 0;
                        boolean removing = this.removingStickerSets.indexOfKey(stickerSetCovered.set.id) >= 0;
                        if (installing || removing) {
                            if (installing && cell.isInstalled()) {
                                this.installingStickerSets.remove(stickerSetCovered.set.id);
                                installing = false;
                            } else if (removing && !cell.isInstalled()) {
                                this.removingStickerSets.remove(stickerSetCovered.set.id);
                                removing = false;
                            }
                        }
                        cell.setDrawProgress(installing || removing);
                    }
                }
            }
        }
    }

    public boolean areThereAnyStickers() {
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        return stickersGridAdapter != null && stickersGridAdapter.getItemCount() > 0;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.stickersDidLoad) {
            if (((Integer) args[0]).intValue() == 0) {
                TrendingGridAdapter trendingGridAdapter = this.trendingGridAdapter;
                if (trendingGridAdapter != null) {
                    if (this.trendingLoaded) {
                        updateVisibleTrendingSets();
                    } else {
                        trendingGridAdapter.notifyDataSetChanged();
                    }
                }
                updateStickerTabs();
                reloadStickersAdapter();
                checkPanels();
                return;
            }
            return;
        }
        if (id == NotificationCenter.recentDocumentsDidLoad) {
            boolean isGif = ((Boolean) args[0]).booleanValue();
            int type = ((Integer) args[1]).intValue();
            if (isGif || type == 0 || type == 2) {
                checkDocuments(isGif);
                return;
            }
            return;
        }
        if (id == NotificationCenter.featuredStickersDidLoad) {
            if (this.trendingGridAdapter != null) {
                if (this.featuredStickersHash != MediaDataController.getInstance(this.currentAccount).getFeaturesStickersHashWithoutUnread()) {
                    this.trendingLoaded = false;
                }
                if (this.trendingLoaded) {
                    updateVisibleTrendingSets();
                } else {
                    this.trendingGridAdapter.notifyDataSetChanged();
                }
            }
            PagerSlidingTabStrip pagerSlidingTabStrip = this.typeTabs;
            if (pagerSlidingTabStrip != null) {
                int count = pagerSlidingTabStrip.getChildCount();
                for (int a = 0; a < count; a++) {
                    this.typeTabs.getChildAt(a).invalidate();
                }
            }
            updateStickerTabs();
            return;
        }
        if (id == NotificationCenter.groupStickersDidLoad) {
            TLRPC.ChatFull chatFull = this.info;
            if (chatFull != null && chatFull.stickerset != null && this.info.stickerset.id == ((Long) args[0]).longValue()) {
                updateStickerTabs();
                return;
            }
            return;
        }
        if (id == NotificationCenter.emojiDidLoad) {
            RecyclerListView recyclerListView = this.stickersGridView;
            if (recyclerListView != null) {
                int count2 = recyclerListView.getChildCount();
                for (int a2 = 0; a2 < count2; a2++) {
                    View child = this.stickersGridView.getChildAt(a2);
                    if ((child instanceof StickerSetNameCell) || (child instanceof StickerEmojiCell)) {
                        child.invalidate();
                    }
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.newEmojiSuggestionsAvailable && this.emojiGridView != null && this.needEmojiSearch) {
            if ((this.emojiSearchField.progressDrawable.isAnimating() || this.emojiGridView.getAdapter() == this.emojiSearchAdapter) && !TextUtils.isEmpty(this.emojiSearchAdapter.lastSearchEmojiString)) {
                EmojiSearchAdapter emojiSearchAdapter = this.emojiSearchAdapter;
                emojiSearchAdapter.search(emojiSearchAdapter.lastSearchEmojiString);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class TrendingGridAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int stickersPerRow;
        private int totalItems;
        private SparseArray<Object> cache = new SparseArray<>();
        private ArrayList<TLRPC.StickerSetCovered> sets = new ArrayList<>();
        private SparseArray<TLRPC.StickerSetCovered> positionsToSets = new SparseArray<>();

        public TrendingGridAdapter(Context context) {
            this.context = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.totalItems;
        }

        public Object getItem(int i) {
            return this.cache.get(i);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            Object object = this.cache.get(position);
            if (object != null) {
                if (object instanceof TLRPC.Document) {
                    return 0;
                }
                return 2;
            }
            return 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new StickerEmojiCell(this.context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.TrendingGridAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(82.0f), 1073741824));
                    }
                };
            } else if (viewType == 1) {
                view = new EmptyCell(this.context);
            } else if (viewType == 2) {
                view = new FeaturedStickerSetInfoCell(this.context, 17);
                ((FeaturedStickerSetInfoCell) view).setAddOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$TrendingGridAdapter$1-Qq4o0lqy3OFuOuzxH__GnraBI
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreateViewHolder$0$EmojiViewV2$TrendingGridAdapter(view2);
                    }
                });
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$EmojiViewV2$TrendingGridAdapter(View v) {
            FeaturedStickerSetInfoCell parent1 = (FeaturedStickerSetInfoCell) v.getParent();
            TLRPC.StickerSetCovered pack = parent1.getStickerSet();
            if (EmojiViewV2.this.installingStickerSets.indexOfKey(pack.set.id) >= 0 || EmojiViewV2.this.removingStickerSets.indexOfKey(pack.set.id) >= 0) {
                return;
            }
            if (parent1.isInstalled()) {
                EmojiViewV2.this.removingStickerSets.put(pack.set.id, pack);
                EmojiViewV2.this.delegate.onStickerSetRemove(parent1.getStickerSet());
            } else {
                EmojiViewV2.this.installingStickerSets.put(pack.set.id, pack);
                EmojiViewV2.this.delegate.onStickerSetAdd(parent1.getStickerSet());
                parent1.setDrawProgress(true);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                TLRPC.Document sticker = (TLRPC.Document) this.cache.get(position);
                ((StickerEmojiCell) holder.itemView).setSticker(sticker, this.positionsToSets.get(position), false);
                return;
            }
            if (itemViewType == 1) {
                ((EmptyCell) holder.itemView).setHeight(AndroidUtilities.dp(82.0f));
                return;
            }
            if (itemViewType == 2) {
                ArrayList<Long> unreadStickers = MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getUnreadStickerSets();
                TLRPC.StickerSetCovered stickerSetCovered = this.sets.get(((Integer) this.cache.get(position)).intValue());
                boolean unread = unreadStickers != null && unreadStickers.contains(Long.valueOf(stickerSetCovered.set.id));
                FeaturedStickerSetInfoCell cell = (FeaturedStickerSetInfoCell) holder.itemView;
                cell.setStickerSet(stickerSetCovered, unread);
                if (unread) {
                    MediaDataController.getInstance(EmojiViewV2.this.currentAccount).markFaturedStickersByIdAsRead(stickerSetCovered.set.id);
                }
                boolean installing = EmojiViewV2.this.installingStickerSets.indexOfKey(stickerSetCovered.set.id) >= 0;
                boolean removing = EmojiViewV2.this.removingStickerSets.indexOfKey(stickerSetCovered.set.id) >= 0;
                if (installing || removing) {
                    if (installing && cell.isInstalled()) {
                        EmojiViewV2.this.installingStickerSets.remove(stickerSetCovered.set.id);
                        installing = false;
                    } else if (removing && !cell.isInstalled()) {
                        EmojiViewV2.this.removingStickerSets.remove(stickerSetCovered.set.id);
                        removing = false;
                    }
                }
                cell.setDrawProgress(installing || removing);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            int count;
            int i;
            int width = EmojiViewV2.this.getMeasuredWidth();
            if (width == 0) {
                if (AndroidUtilities.isTablet()) {
                    int smallSide = AndroidUtilities.displaySize.x;
                    int leftSide = (smallSide * 35) / 100;
                    if (leftSide < AndroidUtilities.dp(320.0f)) {
                        leftSide = AndroidUtilities.dp(320.0f);
                    }
                    width = smallSide - leftSide;
                } else {
                    width = AndroidUtilities.displaySize.x;
                }
                if (width == 0) {
                    width = 1080;
                }
            }
            this.stickersPerRow = Math.max(5, width / AndroidUtilities.dp(72.0f));
            EmojiViewV2.this.trendingLayoutManager.setSpanCount(this.stickersPerRow);
            if (EmojiViewV2.this.trendingLoaded) {
                return;
            }
            this.cache.clear();
            this.positionsToSets.clear();
            this.sets.clear();
            this.totalItems = 0;
            int startRow = 0;
            ArrayList<TLRPC.StickerSetCovered> packs = MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getFeaturedStickerSets();
            for (int a = 0; a < packs.size(); a++) {
                TLRPC.StickerSetCovered pack = packs.get(a);
                if (!MediaDataController.getInstance(EmojiViewV2.this.currentAccount).isStickerPackInstalled(pack.set.id) && (!pack.covers.isEmpty() || pack.cover != null)) {
                    this.sets.add(pack);
                    this.positionsToSets.put(this.totalItems, pack);
                    SparseArray<Object> sparseArray = this.cache;
                    int i2 = this.totalItems;
                    this.totalItems = i2 + 1;
                    int num = startRow + 1;
                    sparseArray.put(i2, Integer.valueOf(startRow));
                    int i3 = this.totalItems / this.stickersPerRow;
                    if (!pack.covers.isEmpty()) {
                        count = (int) Math.ceil(pack.covers.size() / this.stickersPerRow);
                        for (int b = 0; b < pack.covers.size(); b++) {
                            this.cache.put(this.totalItems + b, pack.covers.get(b));
                        }
                    } else {
                        count = 1;
                        this.cache.put(this.totalItems, pack.cover);
                    }
                    int b2 = 0;
                    while (true) {
                        i = this.stickersPerRow;
                        if (b2 >= count * i) {
                            break;
                        }
                        this.positionsToSets.put(this.totalItems + b2, pack);
                        b2++;
                    }
                    int b3 = this.totalItems;
                    this.totalItems = b3 + (i * count);
                    startRow = num;
                }
            }
            int a2 = this.totalItems;
            if (a2 != 0) {
                EmojiViewV2.this.trendingLoaded = true;
                EmojiViewV2 emojiViewV2 = EmojiViewV2.this;
                emojiViewV2.featuredStickersHash = MediaDataController.getInstance(emojiViewV2.currentAccount).getFeaturesStickersHashWithoutUnread();
            }
            super.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class StickersGridAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int stickersPerRow;
        private int totalItems;
        private SparseArray<Object> rowStartPack = new SparseArray<>();
        private HashMap<Object, Integer> packStartPosition = new HashMap<>();
        private SparseArray<Object> cache = new SparseArray<>();
        private SparseArray<Object> cacheParents = new SparseArray<>();
        private SparseIntArray positionToRow = new SparseIntArray();

        public StickersGridAdapter(Context context) {
            this.context = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int i = this.totalItems;
            if (i != 0) {
                return i + 1;
            }
            return 0;
        }

        public Object getItem(int i) {
            return this.cache.get(i);
        }

        public int getPositionForPack(Object pack) {
            Integer pos = this.packStartPosition.get(pack);
            if (pos == null) {
                return -1;
            }
            return pos.intValue();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 4;
            }
            Object object = this.cache.get(position);
            if (object != null) {
                if (object instanceof TLRPC.Document) {
                    return 0;
                }
                if (object instanceof String) {
                    return 3;
                }
                return 2;
            }
            return 1;
        }

        public int getTabForPosition(int position) {
            if (position == 0) {
                position = 1;
            }
            if (this.stickersPerRow == 0) {
                int width = EmojiViewV2.this.getMeasuredWidth();
                if (width == 0) {
                    width = AndroidUtilities.displaySize.x;
                }
                this.stickersPerRow = width / AndroidUtilities.dp(72.0f);
            }
            int row = this.positionToRow.get(position, Integer.MIN_VALUE);
            if (row == Integer.MIN_VALUE) {
                return (EmojiViewV2.this.stickerSets.size() - 1) + EmojiViewV2.this.stickersTabOffset;
            }
            Object pack = this.rowStartPack.get(row);
            if (pack instanceof String) {
                return "recent".equals(pack) ? EmojiViewV2.this.recentTabBum : EmojiViewV2.this.favTabBum;
            }
            TLRPC.TL_messages_stickerSet set = (TLRPC.TL_messages_stickerSet) pack;
            int idx = EmojiViewV2.this.stickerSets.indexOf(set);
            return EmojiViewV2.this.stickersTabOffset + idx;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new StickerEmojiCell(this.context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.StickersGridAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(82.0f), 1073741824));
                    }
                };
            } else if (viewType == 1) {
                view = new EmptyCell(this.context);
            } else if (viewType == 2) {
                view = new StickerSetNameCell(this.context, false);
                ((StickerSetNameCell) view).setOnIconClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersGridAdapter$usYZ7QHvIgK7Rdo1CaHzVC2sEBk
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreateViewHolder$0$EmojiViewV2$StickersGridAdapter(view2);
                    }
                });
            } else if (viewType == 3) {
                view = new StickerSetGroupInfoCell(this.context);
                ((StickerSetGroupInfoCell) view).setAddOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersGridAdapter$H9htENy5o1SrYu4iu79z7nfZuPc
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreateViewHolder$1$EmojiViewV2$StickersGridAdapter(view2);
                    }
                });
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            } else if (viewType == 4) {
                view = new View(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$EmojiViewV2$StickersGridAdapter(View v) {
            if (EmojiViewV2.this.groupStickerSet != null) {
                if (EmojiViewV2.this.delegate != null) {
                    EmojiViewV2.this.delegate.onStickersGroupClick(EmojiViewV2.this.info.id);
                    return;
                }
                return;
            }
            MessagesController.getEmojiSettings(EmojiViewV2.this.currentAccount).edit().putLong("group_hide_stickers_" + EmojiViewV2.this.info.id, EmojiViewV2.this.info.stickerset != null ? EmojiViewV2.this.info.stickerset.id : 0L).commit();
            EmojiViewV2.this.updateStickerTabs();
            if (EmojiViewV2.this.stickersGridAdapter != null) {
                EmojiViewV2.this.stickersGridAdapter.notifyDataSetChanged();
            }
        }

        public /* synthetic */ void lambda$onCreateViewHolder$1$EmojiViewV2$StickersGridAdapter(View v) {
            if (EmojiViewV2.this.delegate != null) {
                EmojiViewV2.this.delegate.onStickersGroupClick(EmojiViewV2.this.info.id);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            ArrayList<TLRPC.Document> documents;
            int icon;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                TLRPC.Document sticker = (TLRPC.Document) this.cache.get(position);
                StickerEmojiCell cell = (StickerEmojiCell) holder.itemView;
                cell.setSticker(sticker, this.cacheParents.get(position), false);
                cell.setRecent(EmojiViewV2.this.recentStickers.contains(sticker) || EmojiViewV2.this.favouriteStickers.contains(sticker));
                return;
            }
            if (itemViewType == 1) {
                EmptyCell cell2 = (EmptyCell) holder.itemView;
                if (position == this.totalItems) {
                    int row = this.positionToRow.get(position - 1, Integer.MIN_VALUE);
                    if (row == Integer.MIN_VALUE) {
                        cell2.setHeight(1);
                        return;
                    }
                    Object pack = this.rowStartPack.get(row);
                    if (pack instanceof TLRPC.TL_messages_stickerSet) {
                        documents = ((TLRPC.TL_messages_stickerSet) pack).documents;
                    } else if (pack instanceof String) {
                        documents = "recent".equals(pack) ? EmojiViewV2.this.recentStickers : EmojiViewV2.this.favouriteStickers;
                    } else {
                        documents = null;
                    }
                    if (documents == null) {
                        cell2.setHeight(1);
                        return;
                    } else if (!documents.isEmpty()) {
                        int height = EmojiViewV2.this.pager.getHeight() - (((int) Math.ceil(documents.size() / this.stickersPerRow)) * AndroidUtilities.dp(82.0f));
                        cell2.setHeight(height > 0 ? height : 1);
                        return;
                    } else {
                        cell2.setHeight(AndroidUtilities.dp(8.0f));
                        return;
                    }
                }
                cell2.setHeight(AndroidUtilities.dp(82.0f));
                return;
            }
            if (itemViewType != 2) {
                if (itemViewType == 3) {
                    ((StickerSetGroupInfoCell) holder.itemView).setIsLast(position == this.totalItems - 1);
                    return;
                }
                return;
            }
            StickerSetNameCell cell3 = (StickerSetNameCell) holder.itemView;
            if (position == EmojiViewV2.this.groupStickerPackPosition) {
                if (!EmojiViewV2.this.groupStickersHidden || EmojiViewV2.this.groupStickerSet != null) {
                    icon = EmojiViewV2.this.groupStickerSet != null ? R.drawable.stickersclose : R.drawable.stickerset_close;
                } else {
                    icon = 0;
                }
                TLRPC.Chat chat = EmojiViewV2.this.info != null ? MessagesController.getInstance(EmojiViewV2.this.currentAccount).getChat(Integer.valueOf(EmojiViewV2.this.info.id)) : null;
                Object[] objArr = new Object[1];
                objArr[0] = chat != null ? chat.title : "Group Stickers";
                cell3.setText(LocaleController.formatString("CurrentGroupStickers", R.string.CurrentGroupStickers, objArr), icon);
                return;
            }
            Object object = this.cache.get(position);
            if (!(object instanceof TLRPC.TL_messages_stickerSet)) {
                if (object != EmojiViewV2.this.recentStickers) {
                    if (object == EmojiViewV2.this.favouriteStickers) {
                        cell3.setText(LocaleController.getString("FavoriteStickers", R.string.FavoriteStickers), 0);
                        return;
                    }
                    return;
                }
                cell3.setText(LocaleController.getString("RecentStickers", R.string.RecentStickers), 0);
                return;
            }
            TLRPC.TL_messages_stickerSet set = (TLRPC.TL_messages_stickerSet) object;
            if (set.set != null) {
                cell3.setText(set.set.title, 0);
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:22:0x00f4  */
        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void notifyDataSetChanged() {
            /*
                Method dump skipped, instruction units count: 410
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.EmojiViewV2.StickersGridAdapter.notifyDataSetChanged():void");
        }
    }

    private class EmojiGridAdapter extends RecyclerListView.SelectionAdapter {
        private int itemCount;
        private SparseIntArray positionToSection;
        private SparseIntArray sectionToPosition;

        private EmojiGridAdapter() {
            this.positionToSection = new SparseIntArray();
            this.sectionToPosition = new SparseIntArray();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.itemCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int position) {
            return position;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                EmojiViewV2 emojiViewV2 = EmojiViewV2.this;
                view = emojiViewV2.new ImageViewEmoji(emojiViewV2.getContext());
            } else if (viewType == 1) {
                view = new StickerSetNameCell(EmojiViewV2.this.getContext(), true);
            } else {
                view = new View(EmojiViewV2.this.getContext());
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String code;
            String coloredCode;
            boolean recent;
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    StickerSetNameCell cell = (StickerSetNameCell) holder.itemView;
                    cell.setText(EmojiViewV2.this.emojiTitles[this.positionToSection.get(position)], 0);
                    return;
                }
                return;
            }
            ImageViewEmoji imageView = (ImageViewEmoji) holder.itemView;
            if (EmojiViewV2.this.needEmojiSearch) {
                position--;
            }
            int count = Emoji.recentEmoji.size();
            if (position < count) {
                coloredCode = Emoji.recentEmoji.get(position);
                code = coloredCode;
                recent = true;
            } else {
                code = null;
                int a = 0;
                while (true) {
                    if (a >= EmojiData.dataColored.length) {
                        coloredCode = null;
                        break;
                    }
                    int size = EmojiData.dataColored[a].length + 1;
                    if (position < count + size) {
                        coloredCode = EmojiData.dataColored[a][(position - count) - 1];
                        code = coloredCode;
                        String color = Emoji.emojiColor.get(code);
                        if (color != null) {
                            coloredCode = EmojiViewV2.addColorToCode(coloredCode, color);
                        }
                    } else {
                        count += size;
                        a++;
                    }
                }
                recent = false;
            }
            imageView.setImageDrawable(Emoji.getEmojiBigDrawable(coloredCode), recent);
            imageView.setTag(code);
            imageView.setContentDescription(coloredCode);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (EmojiViewV2.this.needEmojiSearch && position == 0) {
                return 2;
            }
            if (this.positionToSection.indexOfKey(position) >= 0) {
                return 1;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            this.positionToSection.clear();
            this.itemCount = Emoji.recentEmoji.size() + (EmojiViewV2.this.needEmojiSearch ? 1 : 0);
            for (int i = 0; i < EmojiData.dataColored.length; i++) {
                this.positionToSection.put(this.itemCount, i);
                this.sectionToPosition.put(i, this.itemCount);
                this.itemCount += EmojiData.dataColored[i].length + 1;
            }
            EmojiViewV2.this.updateEmojiTabs();
            super.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class EmojiSearchAdapter extends RecyclerListView.SelectionAdapter {
        private String lastSearchAlias;
        private String lastSearchEmojiString;
        private ArrayList<MediaDataController.KeywordResult> result;
        private Runnable searchRunnable;
        private boolean searchWas;

        private EmojiSearchAdapter() {
            this.result = new ArrayList<>();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (this.result.isEmpty() && !this.searchWas) {
                return Emoji.recentEmoji.size() + 1;
            }
            if (!this.result.isEmpty()) {
                return this.result.size() + 1;
            }
            return 2;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() == 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                EmojiViewV2 emojiViewV2 = EmojiViewV2.this;
                view = emojiViewV2.new ImageViewEmoji(emojiViewV2.getContext());
            } else if (viewType == 1) {
                view = new View(EmojiViewV2.this.getContext());
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
            } else {
                FrameLayout frameLayout = new FrameLayout(EmojiViewV2.this.getContext()) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.EmojiSearchAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        int parentHeight;
                        View parent2 = (View) EmojiViewV2.this.getParent();
                        if (parent2 != null) {
                            parentHeight = (int) (parent2.getMeasuredHeight() - EmojiViewV2.this.getY());
                        } else {
                            parentHeight = AndroidUtilities.dp(120.0f);
                        }
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(parentHeight - EmojiViewV2.this.searchFieldHeight, 1073741824));
                    }
                };
                TextView textView = new TextView(EmojiViewV2.this.getContext());
                textView.setText(LocaleController.getString("NoEmojiFound", R.string.NoEmojiFound));
                textView.setTextSize(1, 16.0f);
                textView.setTextColor(Theme.getColor(Theme.key_chat_emojiPanelEmptyText));
                frameLayout.addView(textView, LayoutHelper.createFrame(-2.0f, -2.0f, 49, 0.0f, 10.0f, 0.0f, 0.0f));
                ImageView imageView = new ImageView(EmojiViewV2.this.getContext());
                imageView.setScaleType(ImageView.ScaleType.CENTER);
                imageView.setImageResource(R.drawable.smiles_panel_question);
                imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelEmptyText), PorterDuff.Mode.MULTIPLY));
                frameLayout.addView(imageView, LayoutHelper.createFrame(48, 48, 85));
                imageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.EmojiSearchAdapter.2
                    @Override // android.view.View.OnClickListener
                    public void onClick(View v) {
                        Object obj;
                        boolean[] loadingUrl = new boolean[1];
                        BottomSheet.Builder builder = new BottomSheet.Builder(EmojiViewV2.this.getContext());
                        LinearLayout linearLayout = new LinearLayout(EmojiViewV2.this.getContext());
                        linearLayout.setOrientation(1);
                        linearLayout.setPadding(AndroidUtilities.dp(21.0f), 0, AndroidUtilities.dp(21.0f), 0);
                        ImageView imageView1 = new ImageView(EmojiViewV2.this.getContext());
                        imageView1.setImageResource(R.drawable.smiles_info);
                        linearLayout.addView(imageView1, LayoutHelper.createLinear(-2, -2, 49, 0, 15, 0, 0));
                        TextView textView2 = new TextView(EmojiViewV2.this.getContext());
                        textView2.setText(LocaleController.getString("EmojiSuggestions", R.string.EmojiSuggestions));
                        textView2.setTextSize(1, 15.0f);
                        textView2.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
                        textView2.setGravity(LocaleController.isRTL ? 5 : 3);
                        textView2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                        linearLayout.addView(textView2, LayoutHelper.createLinear(-2, -2, 51, 0, 24, 0, 0));
                        TextView textView3 = new TextView(EmojiViewV2.this.getContext());
                        textView3.setText(AndroidUtilities.replaceTags(LocaleController.getString("EmojiSuggestionsInfo", R.string.EmojiSuggestionsInfo)));
                        textView3.setTextSize(1, 15.0f);
                        textView3.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                        textView3.setGravity(LocaleController.isRTL ? 5 : 3);
                        linearLayout.addView(textView3, LayoutHelper.createLinear(-2, -2, 51, 0, 11, 0, 0));
                        TextView textView4 = new TextView(EmojiViewV2.this.getContext());
                        Object[] objArr = new Object[1];
                        if (EmojiSearchAdapter.this.lastSearchAlias == null) {
                            obj = EmojiViewV2.this.lastSearchKeyboardLanguage;
                        } else {
                            obj = EmojiSearchAdapter.this.lastSearchAlias;
                        }
                        objArr[0] = obj;
                        textView4.setText(LocaleController.formatString("EmojiSuggestionsUrl", R.string.EmojiSuggestionsUrl, objArr));
                        textView4.setTextSize(1, 15.0f);
                        textView4.setTextColor(Theme.getColor(Theme.key_dialogTextLink));
                        textView4.setGravity(LocaleController.isRTL ? 5 : 3);
                        linearLayout.addView(textView4, LayoutHelper.createLinear(-2, -2, 51, 0, 18, 0, 16));
                        textView4.setOnClickListener(new AnonymousClass1(loadingUrl, builder));
                        builder.setCustomView(linearLayout);
                        builder.show();
                    }

                    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.EmojiViewV2$EmojiSearchAdapter$2$1, reason: invalid class name */
                    class AnonymousClass1 implements View.OnClickListener {
                        final /* synthetic */ BottomSheet.Builder val$builder;
                        final /* synthetic */ boolean[] val$loadingUrl;

                        AnonymousClass1(boolean[] zArr, BottomSheet.Builder builder) {
                            this.val$loadingUrl = zArr;
                            this.val$builder = builder;
                        }

                        @Override // android.view.View.OnClickListener
                        public void onClick(View v) {
                            String str;
                            boolean[] zArr = this.val$loadingUrl;
                            if (zArr[0]) {
                                return;
                            }
                            zArr[0] = true;
                            final AlertDialog[] progressDialog = {new AlertDialog(EmojiViewV2.this.getContext(), 3)};
                            TLRPC.TL_messages_getEmojiURL req = new TLRPC.TL_messages_getEmojiURL();
                            if (EmojiSearchAdapter.this.lastSearchAlias == null) {
                                str = EmojiViewV2.this.lastSearchKeyboardLanguage[0];
                            } else {
                                str = EmojiSearchAdapter.this.lastSearchAlias;
                            }
                            req.lang_code = str;
                            ConnectionsManager connectionsManager = ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount);
                            final BottomSheet.Builder builder = this.val$builder;
                            final int requestId = connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$EmojiSearchAdapter$2$1$TIM-TTtHDxBCtEUUES57cgkzyA0
                                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                    this.f$0.lambda$onClick$1$EmojiViewV2$EmojiSearchAdapter$2$1(progressDialog, builder, tLObject, tL_error);
                                }
                            });
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$EmojiSearchAdapter$2$1$86rXty4ospGcPyXnwmlcEmERbyw
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onClick$3$EmojiViewV2$EmojiSearchAdapter$2$1(progressDialog, requestId);
                                }
                            }, 1000L);
                        }

                        public /* synthetic */ void lambda$onClick$1$EmojiViewV2$EmojiSearchAdapter$2$1(final AlertDialog[] progressDialog, final BottomSheet.Builder builder, final TLObject response, TLRPC.TL_error error) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$EmojiSearchAdapter$2$1$Dy-7mTr5Yv_yh8Pb5ZYb3LZUy-w
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$0$EmojiViewV2$EmojiSearchAdapter$2$1(progressDialog, response, builder);
                                }
                            });
                        }

                        public /* synthetic */ void lambda$null$0$EmojiViewV2$EmojiSearchAdapter$2$1(AlertDialog[] progressDialog, TLObject response, BottomSheet.Builder builder) {
                            try {
                                progressDialog[0].dismiss();
                            } catch (Throwable th) {
                            }
                            progressDialog[0] = null;
                            if (response instanceof TLRPC.TL_emojiURL) {
                                Browser.openUrl(EmojiViewV2.this.getContext(), ((TLRPC.TL_emojiURL) response).url);
                                builder.getDismissRunnable().run();
                            }
                        }

                        public /* synthetic */ void lambda$onClick$3$EmojiViewV2$EmojiSearchAdapter$2$1(AlertDialog[] progressDialog, final int requestId) {
                            if (progressDialog[0] == null) {
                                return;
                            }
                            progressDialog[0].setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$EmojiSearchAdapter$2$1$YyGDKBEaXv9xBwB6bU6009DiZik
                                @Override // android.content.DialogInterface.OnCancelListener
                                public final void onCancel(DialogInterface dialogInterface) {
                                    this.f$0.lambda$null$2$EmojiViewV2$EmojiSearchAdapter$2$1(requestId, dialogInterface);
                                }
                            });
                            progressDialog[0].show();
                        }

                        public /* synthetic */ void lambda$null$2$EmojiViewV2$EmojiSearchAdapter$2$1(int requestId, DialogInterface dialog) {
                            ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).cancelRequest(requestId, true);
                        }
                    }
                });
                view = frameLayout;
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String coloredCode;
            String code;
            boolean recent;
            if (holder.getItemViewType() == 0) {
                ImageViewEmoji imageView = (ImageViewEmoji) holder.itemView;
                int position2 = position - 1;
                if (this.result.isEmpty() && !this.searchWas) {
                    coloredCode = Emoji.recentEmoji.get(position2);
                    code = coloredCode;
                    recent = true;
                } else {
                    coloredCode = this.result.get(position2).emoji;
                    code = coloredCode;
                    recent = false;
                }
                imageView.setImageDrawable(Emoji.getEmojiBigDrawable(coloredCode), recent);
                imageView.setTag(code);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 1;
            }
            if (position == 1 && this.searchWas && this.result.isEmpty()) {
                return 2;
            }
            return 0;
        }

        public void search(String text) {
            if (TextUtils.isEmpty(text)) {
                this.lastSearchEmojiString = null;
                if (EmojiViewV2.this.emojiGridView.getAdapter() != EmojiViewV2.this.emojiAdapter) {
                    EmojiViewV2.this.emojiGridView.setAdapter(EmojiViewV2.this.emojiAdapter);
                    this.searchWas = false;
                }
                notifyDataSetChanged();
            } else {
                this.lastSearchEmojiString = text.toLowerCase();
            }
            Runnable runnable = this.searchRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
            }
            if (!TextUtils.isEmpty(this.lastSearchEmojiString)) {
                Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.EmojiSearchAdapter.3
                    @Override // java.lang.Runnable
                    public void run() {
                        EmojiViewV2.this.emojiSearchField.progressDrawable.startAnimation();
                        final String query = EmojiSearchAdapter.this.lastSearchEmojiString;
                        String[] newLanguage = AndroidUtilities.getCurrentKeyboardLanguage();
                        if (!Arrays.equals(EmojiViewV2.this.lastSearchKeyboardLanguage, newLanguage)) {
                            MediaDataController.getInstance(EmojiViewV2.this.currentAccount).fetchNewEmojiKeywords(newLanguage);
                        }
                        EmojiViewV2.this.lastSearchKeyboardLanguage = newLanguage;
                        MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getEmojiSuggestions(EmojiViewV2.this.lastSearchKeyboardLanguage, EmojiSearchAdapter.this.lastSearchEmojiString, false, new MediaDataController.KeywordResultCallback() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.EmojiSearchAdapter.3.1
                            @Override // im.uwrkaxlmjj.messenger.MediaDataController.KeywordResultCallback
                            public void run(ArrayList<MediaDataController.KeywordResult> param, String alias) {
                                if (query.equals(EmojiSearchAdapter.this.lastSearchEmojiString)) {
                                    EmojiSearchAdapter.this.lastSearchAlias = alias;
                                    EmojiViewV2.this.emojiSearchField.progressDrawable.stopAnimation();
                                    EmojiSearchAdapter.this.searchWas = true;
                                    if (EmojiViewV2.this.emojiGridView.getAdapter() != EmojiViewV2.this.emojiSearchAdapter) {
                                        EmojiViewV2.this.emojiGridView.setAdapter(EmojiViewV2.this.emojiSearchAdapter);
                                    }
                                    EmojiSearchAdapter.this.result = param;
                                    EmojiSearchAdapter.this.notifyDataSetChanged();
                                }
                            }
                        });
                    }
                };
                this.searchRunnable = runnable2;
                AndroidUtilities.runOnUIThread(runnable2, 300L);
            }
        }
    }

    private class EmojiPagesAdapter extends PagerAdapter implements PagerSlidingTabStrip.IconTabProvider {
        private EmojiPagesAdapter() {
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void destroyItem(ViewGroup viewGroup, int position, Object object) {
            viewGroup.removeView((View) EmojiViewV2.this.views.get(position));
        }

        @Override // im.uwrkaxlmjj.ui.components.PagerSlidingTabStrip.IconTabProvider
        public boolean canScrollToTab(int position) {
            if ((position == 1 || position == 2) && EmojiViewV2.this.currentChatId != 0) {
                EmojiViewV2.this.showStickerBanHint(position == 1);
                return false;
            }
            return true;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            return EmojiViewV2.this.views.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.PagerSlidingTabStrip.IconTabProvider
        public Drawable getPageIconDrawable(int position) {
            return EmojiViewV2.this.tabIcons[position];
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public CharSequence getPageTitle(int position) {
            if (position == 0) {
                return LocaleController.getString("Emoji", R.string.Emoji);
            }
            if (position == 1) {
                return LocaleController.getString("AccDescrGIFs", R.string.AccDescrGIFs);
            }
            if (position == 2) {
                return LocaleController.getString("AccDescrStickers", R.string.AccDescrStickers);
            }
            return null;
        }

        @Override // im.uwrkaxlmjj.ui.components.PagerSlidingTabStrip.IconTabProvider
        public void customOnDraw(Canvas canvas, int position) {
            if (position == 2 && !MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getUnreadStickerSets().isEmpty() && EmojiViewV2.this.dotPaint != null) {
                int x = (canvas.getWidth() / 2) + AndroidUtilities.dp(9.0f);
                int y = (canvas.getHeight() / 2) - AndroidUtilities.dp(8.0f);
                canvas.drawCircle(x, y, AndroidUtilities.dp(5.0f), EmojiViewV2.this.dotPaint);
            }
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public Object instantiateItem(ViewGroup viewGroup, int position) {
            View view = (View) EmojiViewV2.this.views.get(position);
            viewGroup.addView(view);
            return view;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void unregisterDataSetObserver(DataSetObserver observer) {
            if (observer != null) {
                super.unregisterDataSetObserver(observer);
            }
        }
    }

    private class GifAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public GifAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return EmojiViewV2.this.recentGifs.size() + 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i) {
            return i;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 1;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View view;
            if (i == 0) {
                ContextLinkCell contextLinkCell = new ContextLinkCell(this.mContext);
                contextLinkCell.setContentDescription(LocaleController.getString("AttachGif", R.string.AttachGif));
                contextLinkCell.setCanPreviewGif(true);
                view = contextLinkCell;
            } else {
                View view2 = new View(EmojiViewV2.this.getContext());
                view2.setLayoutParams(new RecyclerView.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
                view = view2;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            TLRPC.Document document;
            if (holder.getItemViewType() == 0 && (document = (TLRPC.Document) EmojiViewV2.this.recentGifs.get(position - 1)) != null) {
                ((ContextLinkCell) holder.itemView).setGif(document, false);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            if (holder.itemView instanceof ContextLinkCell) {
                ContextLinkCell cell = (ContextLinkCell) holder.itemView;
                ImageReceiver imageReceiver = cell.getPhotoImage();
                if (EmojiViewV2.this.pager.getCurrentItem() == 1) {
                    imageReceiver.setAllowStartAnimation(true);
                    imageReceiver.startAnimation();
                } else {
                    imageReceiver.setAllowStartAnimation(false);
                    imageReceiver.stopAnimation();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class GifSearchAdapter extends RecyclerListView.SelectionAdapter {
        private TLRPC.User bot;
        private String lastSearchImageString;
        private Context mContext;
        private String nextSearchOffset;
        private int reqId;
        private ArrayList<TLRPC.BotInlineResult> results = new ArrayList<>();
        private HashMap<String, TLRPC.BotInlineResult> resultsMap = new HashMap<>();
        private boolean searchEndReached;
        private Runnable searchRunnable;
        private boolean searchingUser;

        public GifSearchAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return (this.results.isEmpty() ? 1 : this.results.size()) + 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 1;
            }
            if (this.results.isEmpty()) {
                return 2;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                ContextLinkCell cell = new ContextLinkCell(this.mContext);
                cell.setContentDescription(LocaleController.getString("AttachGif", R.string.AttachGif));
                cell.setCanPreviewGif(true);
                view = cell;
            } else if (viewType != 1) {
                FrameLayout frameLayout = new FrameLayout(EmojiViewV2.this.getContext()) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.GifSearchAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        int height = EmojiViewV2.this.gifGridView.getMeasuredHeight();
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec((int) ((((height - EmojiViewV2.this.searchFieldHeight) - AndroidUtilities.dp(8.0f)) / 3) * 1.7f), 1073741824));
                    }
                };
                ImageView imageView = new ImageView(EmojiViewV2.this.getContext());
                imageView.setScaleType(ImageView.ScaleType.CENTER);
                imageView.setImageResource(R.drawable.gif_empty);
                imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelEmptyText), PorterDuff.Mode.MULTIPLY));
                frameLayout.addView(imageView, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 0.0f, 0.0f, 59.0f));
                TextView textView = new TextView(EmojiViewV2.this.getContext());
                textView.setText(LocaleController.getString("NoGIFsFound", R.string.NoGIFsFound));
                textView.setTextSize(1, 16.0f);
                textView.setTextColor(Theme.getColor(Theme.key_chat_emojiPanelEmptyText));
                frameLayout.addView(textView, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 0.0f, 0.0f, 9.0f));
                view = frameLayout;
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            } else {
                view = new View(EmojiViewV2.this.getContext());
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 0) {
                TLRPC.BotInlineResult result = this.results.get(position - 1);
                ContextLinkCell cell = (ContextLinkCell) holder.itemView;
                cell.setLink(result, true, false, false);
            }
        }

        public void search(final String text) {
            if (this.reqId != 0) {
                ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).cancelRequest(this.reqId, true);
                this.reqId = 0;
            }
            if (TextUtils.isEmpty(text)) {
                this.lastSearchImageString = null;
                if (EmojiViewV2.this.gifGridView.getAdapter() != EmojiViewV2.this.gifAdapter) {
                    EmojiViewV2.this.gifGridView.setAdapter(EmojiViewV2.this.gifAdapter);
                }
                notifyDataSetChanged();
            } else {
                this.lastSearchImageString = text.toLowerCase();
            }
            Runnable runnable = this.searchRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
            }
            if (!TextUtils.isEmpty(this.lastSearchImageString)) {
                Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.GifSearchAdapter.2
                    @Override // java.lang.Runnable
                    public void run() {
                        GifSearchAdapter.this.search(text, "", true);
                    }
                };
                this.searchRunnable = runnable2;
                AndroidUtilities.runOnUIThread(runnable2, 300L);
            }
        }

        private void searchBotUser() {
            if (this.searchingUser) {
                return;
            }
            this.searchingUser = true;
            TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
            req.username = MessagesController.getInstance(EmojiViewV2.this.currentAccount).gifSearchBot;
            ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$GifSearchAdapter$WCQgF-c5HIzR8Ik-s6yoHmLcfIM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$searchBotUser$1$EmojiViewV2$GifSearchAdapter(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$searchBotUser$1$EmojiViewV2$GifSearchAdapter(final TLObject response, TLRPC.TL_error error) {
            if (response != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$GifSearchAdapter$9yWYWx1VoQjeEVmxhSvG0pEE0To
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$0$EmojiViewV2$GifSearchAdapter(response);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$null$0$EmojiViewV2$GifSearchAdapter(TLObject response) {
            TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
            MessagesController.getInstance(EmojiViewV2.this.currentAccount).putUsers(res.users, false);
            MessagesController.getInstance(EmojiViewV2.this.currentAccount).putChats(res.chats, false);
            MessagesStorage.getInstance(EmojiViewV2.this.currentAccount).putUsersAndChats(res.users, res.chats, true, true);
            String str = this.lastSearchImageString;
            this.lastSearchImageString = null;
            search(str, "", false);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void search(String query, final String offset, boolean searchUser) {
            if (this.reqId != 0) {
                ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).cancelRequest(this.reqId, true);
                this.reqId = 0;
            }
            this.lastSearchImageString = query;
            TLObject object = MessagesController.getInstance(EmojiViewV2.this.currentAccount).getUserOrChat(MessagesController.getInstance(EmojiViewV2.this.currentAccount).gifSearchBot);
            if (!(object instanceof TLRPC.User)) {
                if (searchUser) {
                    searchBotUser();
                    EmojiViewV2.this.gifSearchField.progressDrawable.startAnimation();
                    return;
                }
                return;
            }
            if (TextUtils.isEmpty(offset)) {
                EmojiViewV2.this.gifSearchField.progressDrawable.startAnimation();
            }
            this.bot = (TLRPC.User) object;
            final TLRPC.TL_messages_getInlineBotResults req = new TLRPC.TL_messages_getInlineBotResults();
            req.query = query == null ? "" : query;
            req.bot = MessagesController.getInstance(EmojiViewV2.this.currentAccount).getInputUser(this.bot);
            req.offset = offset;
            req.peer = new TLRPC.TL_inputPeerEmpty();
            this.reqId = ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$GifSearchAdapter$7uXv_enzFbA0t3VN6qEwAAYNN0M
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$search$3$EmojiViewV2$GifSearchAdapter(req, offset, tLObject, tL_error);
                }
            }, 2);
        }

        public /* synthetic */ void lambda$search$3$EmojiViewV2$GifSearchAdapter(final TLRPC.TL_messages_getInlineBotResults req, final String offset, final TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$GifSearchAdapter$hw9Hq0-6wbaYsgBCAuuiEgjOEKk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$EmojiViewV2$GifSearchAdapter(req, offset, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$2$EmojiViewV2$GifSearchAdapter(TLRPC.TL_messages_getInlineBotResults req, String offset, TLObject response) {
            if (req.query.equals(this.lastSearchImageString)) {
                if (EmojiViewV2.this.gifGridView.getAdapter() != EmojiViewV2.this.gifSearchAdapter) {
                    EmojiViewV2.this.gifGridView.setAdapter(EmojiViewV2.this.gifSearchAdapter);
                }
                if (TextUtils.isEmpty(offset)) {
                    this.results.clear();
                    this.resultsMap.clear();
                    EmojiViewV2.this.gifSearchField.progressDrawable.stopAnimation();
                }
                this.reqId = 0;
                if (response instanceof TLRPC.messages_BotResults) {
                    int addedCount = 0;
                    int oldCount = this.results.size();
                    TLRPC.messages_BotResults res = (TLRPC.messages_BotResults) response;
                    this.nextSearchOffset = res.next_offset;
                    for (int a = 0; a < res.results.size(); a++) {
                        TLRPC.BotInlineResult result = res.results.get(a);
                        if (!this.resultsMap.containsKey(result.id)) {
                            result.query_id = res.query_id;
                            this.results.add(result);
                            this.resultsMap.put(result.id, result);
                            addedCount++;
                        }
                    }
                    this.searchEndReached = oldCount == this.results.size() || TextUtils.isEmpty(this.nextSearchOffset);
                    if (addedCount != 0) {
                        if (oldCount != 0) {
                            notifyItemChanged(oldCount);
                        }
                        notifyItemRangeInserted(oldCount + 1, addedCount);
                        return;
                    } else {
                        if (this.results.isEmpty()) {
                            notifyDataSetChanged();
                            return;
                        }
                        return;
                    }
                }
                notifyDataSetChanged();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class StickersSearchGridAdapter extends RecyclerListView.SelectionAdapter {
        boolean cleared;
        private Context context;
        private int emojiSearchId;
        private int reqId;
        private int reqId2;
        private String searchQuery;
        private int totalItems;
        private SparseArray<Object> rowStartPack = new SparseArray<>();
        private SparseArray<Object> cache = new SparseArray<>();
        private SparseArray<Object> cacheParent = new SparseArray<>();
        private SparseIntArray positionToRow = new SparseIntArray();
        private SparseArray<String> positionToEmoji = new SparseArray<>();
        private ArrayList<TLRPC.StickerSetCovered> serverPacks = new ArrayList<>();
        private ArrayList<TLRPC.TL_messages_stickerSet> localPacks = new ArrayList<>();
        private HashMap<TLRPC.TL_messages_stickerSet, Boolean> localPacksByShortName = new HashMap<>();
        private HashMap<TLRPC.TL_messages_stickerSet, Integer> localPacksByName = new HashMap<>();
        private HashMap<ArrayList<TLRPC.Document>, String> emojiStickers = new HashMap<>();
        private ArrayList<ArrayList<TLRPC.Document>> emojiArrays = new ArrayList<>();
        private SparseArray<TLRPC.StickerSetCovered> positionsToSets = new SparseArray<>();
        private Runnable searchRunnable = new AnonymousClass1();

        static /* synthetic */ int access$13304(StickersSearchGridAdapter x0) {
            int i = x0.emojiSearchId + 1;
            x0.emojiSearchId = i;
            return i;
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.EmojiViewV2$StickersSearchGridAdapter$1, reason: invalid class name */
        class AnonymousClass1 implements Runnable {
            AnonymousClass1() {
            }

            /* JADX INFO: Access modifiers changed from: private */
            public void clear() {
                if (StickersSearchGridAdapter.this.cleared) {
                    return;
                }
                StickersSearchGridAdapter.this.cleared = true;
                StickersSearchGridAdapter.this.emojiStickers.clear();
                StickersSearchGridAdapter.this.emojiArrays.clear();
                StickersSearchGridAdapter.this.localPacks.clear();
                StickersSearchGridAdapter.this.serverPacks.clear();
                StickersSearchGridAdapter.this.localPacksByShortName.clear();
                StickersSearchGridAdapter.this.localPacksByName.clear();
            }

            @Override // java.lang.Runnable
            public void run() {
                int index;
                int index2;
                if (!TextUtils.isEmpty(StickersSearchGridAdapter.this.searchQuery)) {
                    EmojiViewV2.this.stickersSearchField.progressDrawable.startAnimation();
                    StickersSearchGridAdapter.this.cleared = false;
                    final int lastId = StickersSearchGridAdapter.access$13304(StickersSearchGridAdapter.this);
                    final ArrayList<TLRPC.Document> emojiStickersArray = new ArrayList<>(0);
                    final LongSparseArray<TLRPC.Document> emojiStickersMap = new LongSparseArray<>(0);
                    final HashMap<String, ArrayList<TLRPC.Document>> allStickers = MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getAllStickers();
                    if (StickersSearchGridAdapter.this.searchQuery.length() <= 14) {
                        CharSequence emoji = StickersSearchGridAdapter.this.searchQuery;
                        int length = emoji.length();
                        int a = 0;
                        while (a < length) {
                            if (a < length - 1 && ((emoji.charAt(a) == 55356 && emoji.charAt(a + 1) >= 57339 && emoji.charAt(a + 1) <= 57343) || (emoji.charAt(a) == 8205 && (emoji.charAt(a + 1) == 9792 || emoji.charAt(a + 1) == 9794)))) {
                                emoji = TextUtils.concat(emoji.subSequence(0, a), emoji.subSequence(a + 2, emoji.length()));
                                length -= 2;
                                a--;
                            } else if (emoji.charAt(a) == 65039) {
                                emoji = TextUtils.concat(emoji.subSequence(0, a), emoji.subSequence(a + 1, emoji.length()));
                                length--;
                                a--;
                            }
                            a++;
                        }
                        ArrayList<TLRPC.Document> newStickers = allStickers != null ? allStickers.get(emoji.toString()) : null;
                        if (newStickers != null && !newStickers.isEmpty()) {
                            clear();
                            emojiStickersArray.addAll(newStickers);
                            int size = newStickers.size();
                            for (int a2 = 0; a2 < size; a2++) {
                                TLRPC.Document document = newStickers.get(a2);
                                emojiStickersMap.put(document.id, document);
                            }
                            StickersSearchGridAdapter.this.emojiStickers.put(emojiStickersArray, StickersSearchGridAdapter.this.searchQuery);
                            StickersSearchGridAdapter.this.emojiArrays.add(emojiStickersArray);
                        }
                    }
                    if (allStickers != null && !allStickers.isEmpty() && StickersSearchGridAdapter.this.searchQuery.length() > 1) {
                        String[] newLanguage = AndroidUtilities.getCurrentKeyboardLanguage();
                        if (!Arrays.equals(EmojiViewV2.this.lastSearchKeyboardLanguage, newLanguage)) {
                            MediaDataController.getInstance(EmojiViewV2.this.currentAccount).fetchNewEmojiKeywords(newLanguage);
                        }
                        EmojiViewV2.this.lastSearchKeyboardLanguage = newLanguage;
                        MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getEmojiSuggestions(EmojiViewV2.this.lastSearchKeyboardLanguage, StickersSearchGridAdapter.this.searchQuery, false, new MediaDataController.KeywordResultCallback() { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.StickersSearchGridAdapter.1.1
                            @Override // im.uwrkaxlmjj.messenger.MediaDataController.KeywordResultCallback
                            public void run(ArrayList<MediaDataController.KeywordResult> param, String alias) {
                                if (lastId != StickersSearchGridAdapter.this.emojiSearchId) {
                                    return;
                                }
                                boolean added = false;
                                int size2 = param.size();
                                for (int a3 = 0; a3 < size2; a3++) {
                                    String emoji2 = param.get(a3).emoji;
                                    HashMap map = allStickers;
                                    ArrayList<TLRPC.Document> newStickers2 = map != null ? (ArrayList) map.get(emoji2) : null;
                                    if (newStickers2 != null && !newStickers2.isEmpty()) {
                                        AnonymousClass1.this.clear();
                                        if (!StickersSearchGridAdapter.this.emojiStickers.containsKey(newStickers2)) {
                                            StickersSearchGridAdapter.this.emojiStickers.put(newStickers2, emoji2);
                                            StickersSearchGridAdapter.this.emojiArrays.add(newStickers2);
                                            added = true;
                                        }
                                    }
                                }
                                if (added) {
                                    StickersSearchGridAdapter.this.notifyDataSetChanged();
                                }
                            }
                        });
                    }
                    ArrayList<TLRPC.TL_messages_stickerSet> local = MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getStickerSets(0);
                    int size2 = local.size();
                    for (int a3 = 0; a3 < size2; a3++) {
                        TLRPC.TL_messages_stickerSet set = local.get(a3);
                        int index3 = AndroidUtilities.indexOfIgnoreCase(set.set.title, StickersSearchGridAdapter.this.searchQuery);
                        if (index3 >= 0) {
                            if (index3 == 0 || set.set.title.charAt(index3 - 1) == ' ') {
                                clear();
                                StickersSearchGridAdapter.this.localPacks.add(set);
                                StickersSearchGridAdapter.this.localPacksByName.put(set, Integer.valueOf(index3));
                            }
                        } else if (set.set.short_name != null && (index2 = AndroidUtilities.indexOfIgnoreCase(set.set.short_name, StickersSearchGridAdapter.this.searchQuery)) >= 0 && (index2 == 0 || set.set.short_name.charAt(index2 - 1) == ' ')) {
                            clear();
                            StickersSearchGridAdapter.this.localPacks.add(set);
                            StickersSearchGridAdapter.this.localPacksByShortName.put(set, true);
                        }
                    }
                    ArrayList<TLRPC.TL_messages_stickerSet> local2 = MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getStickerSets(3);
                    int size3 = local2.size();
                    for (int a4 = 0; a4 < size3; a4++) {
                        TLRPC.TL_messages_stickerSet set2 = local2.get(a4);
                        int index4 = AndroidUtilities.indexOfIgnoreCase(set2.set.title, StickersSearchGridAdapter.this.searchQuery);
                        if (index4 >= 0) {
                            if (index4 == 0 || set2.set.title.charAt(index4 - 1) == ' ') {
                                clear();
                                StickersSearchGridAdapter.this.localPacks.add(set2);
                                StickersSearchGridAdapter.this.localPacksByName.put(set2, Integer.valueOf(index4));
                            }
                        } else if (set2.set.short_name != null && (index = AndroidUtilities.indexOfIgnoreCase(set2.set.short_name, StickersSearchGridAdapter.this.searchQuery)) >= 0 && (index == 0 || set2.set.short_name.charAt(index - 1) == ' ')) {
                            clear();
                            StickersSearchGridAdapter.this.localPacks.add(set2);
                            StickersSearchGridAdapter.this.localPacksByShortName.put(set2, true);
                        }
                    }
                    if ((!StickersSearchGridAdapter.this.localPacks.isEmpty() || !StickersSearchGridAdapter.this.emojiStickers.isEmpty()) && EmojiViewV2.this.stickersGridView.getAdapter() != EmojiViewV2.this.stickersSearchGridAdapter) {
                        EmojiViewV2.this.stickersGridView.setAdapter(EmojiViewV2.this.stickersSearchGridAdapter);
                    }
                    final TLRPC.TL_messages_searchStickerSets req = new TLRPC.TL_messages_searchStickerSets();
                    req.q = StickersSearchGridAdapter.this.searchQuery;
                    StickersSearchGridAdapter stickersSearchGridAdapter = StickersSearchGridAdapter.this;
                    stickersSearchGridAdapter.reqId = ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersSearchGridAdapter$1$2hgJlYbaa7CsZyUHcpZzlUImnUY
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$run$1$EmojiViewV2$StickersSearchGridAdapter$1(req, tLObject, tL_error);
                        }
                    });
                    if (Emoji.isValidEmoji(StickersSearchGridAdapter.this.searchQuery)) {
                        final TLRPC.TL_messages_getStickers req2 = new TLRPC.TL_messages_getStickers();
                        req2.emoticon = StickersSearchGridAdapter.this.searchQuery;
                        req2.hash = 0;
                        StickersSearchGridAdapter stickersSearchGridAdapter2 = StickersSearchGridAdapter.this;
                        stickersSearchGridAdapter2.reqId2 = ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersSearchGridAdapter$1$x8EItJDZw1rWBQPsLnYEl_IuPus
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                this.f$0.lambda$run$3$EmojiViewV2$StickersSearchGridAdapter$1(req2, emojiStickersArray, emojiStickersMap, tLObject, tL_error);
                            }
                        });
                    }
                    StickersSearchGridAdapter.this.notifyDataSetChanged();
                }
            }

            public /* synthetic */ void lambda$run$1$EmojiViewV2$StickersSearchGridAdapter$1(final TLRPC.TL_messages_searchStickerSets req, final TLObject response, TLRPC.TL_error error) {
                if (response instanceof TLRPC.TL_messages_foundStickerSets) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersSearchGridAdapter$1$NLLJj-4ELB4ij2OuHCLVDH3T2Xo
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$0$EmojiViewV2$StickersSearchGridAdapter$1(req, response);
                        }
                    });
                }
            }

            public /* synthetic */ void lambda$null$0$EmojiViewV2$StickersSearchGridAdapter$1(TLRPC.TL_messages_searchStickerSets req, TLObject response) {
                if (req.q.equals(StickersSearchGridAdapter.this.searchQuery)) {
                    clear();
                    EmojiViewV2.this.stickersSearchField.progressDrawable.stopAnimation();
                    StickersSearchGridAdapter.this.reqId = 0;
                    if (EmojiViewV2.this.stickersGridView.getAdapter() != EmojiViewV2.this.stickersSearchGridAdapter) {
                        EmojiViewV2.this.stickersGridView.setAdapter(EmojiViewV2.this.stickersSearchGridAdapter);
                    }
                    TLRPC.TL_messages_foundStickerSets res = (TLRPC.TL_messages_foundStickerSets) response;
                    StickersSearchGridAdapter.this.serverPacks.addAll(res.sets);
                    StickersSearchGridAdapter.this.notifyDataSetChanged();
                }
            }

            public /* synthetic */ void lambda$run$3$EmojiViewV2$StickersSearchGridAdapter$1(final TLRPC.TL_messages_getStickers req2, final ArrayList emojiStickersArray, final LongSparseArray emojiStickersMap, final TLObject response, TLRPC.TL_error error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersSearchGridAdapter$1$VXgWaGxmRBqUBVEXD8F3bq_lJMo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$EmojiViewV2$StickersSearchGridAdapter$1(req2, response, emojiStickersArray, emojiStickersMap);
                    }
                });
            }

            public /* synthetic */ void lambda$null$2$EmojiViewV2$StickersSearchGridAdapter$1(TLRPC.TL_messages_getStickers req2, TLObject response, ArrayList emojiStickersArray, LongSparseArray emojiStickersMap) {
                if (req2.emoticon.equals(StickersSearchGridAdapter.this.searchQuery)) {
                    StickersSearchGridAdapter.this.reqId2 = 0;
                    if (!(response instanceof TLRPC.TL_messages_stickers)) {
                        return;
                    }
                    TLRPC.TL_messages_stickers res = (TLRPC.TL_messages_stickers) response;
                    int oldCount = emojiStickersArray.size();
                    int size = res.stickers.size();
                    for (int a = 0; a < size; a++) {
                        TLRPC.Document document = res.stickers.get(a);
                        if (emojiStickersMap.indexOfKey(document.id) < 0) {
                            emojiStickersArray.add(document);
                        }
                    }
                    int newCount = emojiStickersArray.size();
                    if (oldCount != newCount) {
                        StickersSearchGridAdapter.this.emojiStickers.put(emojiStickersArray, StickersSearchGridAdapter.this.searchQuery);
                        if (oldCount == 0) {
                            StickersSearchGridAdapter.this.emojiArrays.add(emojiStickersArray);
                        }
                        StickersSearchGridAdapter.this.notifyDataSetChanged();
                    }
                }
            }
        }

        public StickersSearchGridAdapter(Context context) {
            this.context = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int i = this.totalItems;
            if (i != 1) {
                return i + 1;
            }
            return 2;
        }

        public Object getItem(int i) {
            return this.cache.get(i);
        }

        public void search(String text) {
            if (this.reqId != 0) {
                ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).cancelRequest(this.reqId, true);
                this.reqId = 0;
            }
            if (this.reqId2 != 0) {
                ConnectionsManager.getInstance(EmojiViewV2.this.currentAccount).cancelRequest(this.reqId2, true);
                this.reqId2 = 0;
            }
            if (TextUtils.isEmpty(text)) {
                this.searchQuery = null;
                this.localPacks.clear();
                this.emojiStickers.clear();
                this.serverPacks.clear();
                if (EmojiViewV2.this.stickersGridView.getAdapter() != EmojiViewV2.this.stickersGridAdapter) {
                    EmojiViewV2.this.stickersGridView.setAdapter(EmojiViewV2.this.stickersGridAdapter);
                }
                notifyDataSetChanged();
            } else {
                this.searchQuery = text.toLowerCase();
            }
            AndroidUtilities.cancelRunOnUIThread(this.searchRunnable);
            AndroidUtilities.runOnUIThread(this.searchRunnable, 300L);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 4;
            }
            if (position == 1 && this.totalItems == 1) {
                return 5;
            }
            Object object = this.cache.get(position);
            if (object == null) {
                return 1;
            }
            if (object instanceof TLRPC.Document) {
                return 0;
            }
            if (object instanceof TLRPC.StickerSetCovered) {
                return 3;
            }
            return 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new StickerEmojiCell(this.context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.StickersSearchGridAdapter.2
                    @Override // android.widget.FrameLayout, android.view.View
                    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(82.0f), 1073741824));
                    }
                };
            } else if (viewType == 1) {
                view = new EmptyCell(this.context);
            } else if (viewType == 2) {
                view = new StickerSetNameCell(this.context, false);
            } else if (viewType == 3) {
                view = new FeaturedStickerSetInfoCell(this.context, 17);
                ((FeaturedStickerSetInfoCell) view).setAddOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EmojiViewV2$StickersSearchGridAdapter$yz_zPAqayAGSwCTqu5JhlxeMzio
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreateViewHolder$0$EmojiViewV2$StickersSearchGridAdapter(view2);
                    }
                });
            } else if (viewType == 4) {
                view = new View(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, EmojiViewV2.this.searchFieldHeight));
            } else if (viewType == 5) {
                FrameLayout frameLayout = new FrameLayout(this.context) { // from class: im.uwrkaxlmjj.ui.components.EmojiViewV2.StickersSearchGridAdapter.3
                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        int height = EmojiViewV2.this.stickersGridView.getMeasuredHeight();
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec((int) ((((height - EmojiViewV2.this.searchFieldHeight) - AndroidUtilities.dp(8.0f)) / 3) * 1.7f), 1073741824));
                    }
                };
                ImageView imageView = new ImageView(this.context);
                imageView.setScaleType(ImageView.ScaleType.CENTER);
                imageView.setImageResource(R.drawable.stickers_empty);
                imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_emojiPanelEmptyText), PorterDuff.Mode.MULTIPLY));
                frameLayout.addView(imageView, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 0.0f, 0.0f, 59.0f));
                TextView textView = new TextView(this.context);
                textView.setText(LocaleController.getString("NoStickersFound", R.string.NoStickersFound));
                textView.setTextSize(1, 16.0f);
                textView.setTextColor(Theme.getColor(Theme.key_chat_emojiPanelEmptyText));
                frameLayout.addView(textView, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 0.0f, 0.0f, 9.0f));
                view = frameLayout;
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            }
            return new RecyclerListView.Holder(view);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$EmojiViewV2$StickersSearchGridAdapter(View v) {
            FeaturedStickerSetInfoCell parent1 = (FeaturedStickerSetInfoCell) v.getParent();
            TLRPC.StickerSetCovered pack = parent1.getStickerSet();
            if (EmojiViewV2.this.installingStickerSets.indexOfKey(pack.set.id) >= 0 || EmojiViewV2.this.removingStickerSets.indexOfKey(pack.set.id) >= 0) {
                return;
            }
            if (parent1.isInstalled()) {
                EmojiViewV2.this.removingStickerSets.put(pack.set.id, pack);
                EmojiViewV2.this.delegate.onStickerSetRemove(parent1.getStickerSet());
            } else {
                EmojiViewV2.this.installingStickerSets.put(pack.set.id, pack);
                EmojiViewV2.this.delegate.onStickerSetAdd(parent1.getStickerSet());
            }
            parent1.setDrawProgress(true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder viewHolder, int i) {
            Integer numValueOf;
            int itemViewType = viewHolder.getItemViewType();
            boolean z = true;
            z = true;
            boolean z2 = true;
            z = true;
            if (itemViewType == 0) {
                TLRPC.Document document = (TLRPC.Document) this.cache.get(i);
                StickerEmojiCell stickerEmojiCell = (StickerEmojiCell) viewHolder.itemView;
                stickerEmojiCell.setSticker(document, this.cacheParent.get(i), this.positionToEmoji.get(i), false);
                if (!EmojiViewV2.this.recentStickers.contains(document) && !EmojiViewV2.this.favouriteStickers.contains(document)) {
                    z = false;
                }
                stickerEmojiCell.setRecent(z);
                return;
            }
            if (itemViewType == 1) {
                EmptyCell emptyCell = (EmptyCell) viewHolder.itemView;
                if (i == this.totalItems) {
                    int i2 = this.positionToRow.get(i - 1, Integer.MIN_VALUE);
                    if (i2 == Integer.MIN_VALUE) {
                        emptyCell.setHeight(1);
                        return;
                    }
                    Object obj = this.rowStartPack.get(i2);
                    if (obj instanceof TLRPC.TL_messages_stickerSet) {
                        numValueOf = Integer.valueOf(((TLRPC.TL_messages_stickerSet) obj).documents.size());
                    } else if (obj instanceof Integer) {
                        numValueOf = (Integer) obj;
                    } else {
                        numValueOf = null;
                    }
                    if (numValueOf == null) {
                        emptyCell.setHeight(1);
                        return;
                    } else if (numValueOf.intValue() != 0) {
                        int height = EmojiViewV2.this.pager.getHeight() - (((int) Math.ceil(numValueOf.intValue() / EmojiViewV2.this.stickersGridAdapter.stickersPerRow)) * AndroidUtilities.dp(82.0f));
                        emptyCell.setHeight(height > 0 ? height : 1);
                        return;
                    } else {
                        emptyCell.setHeight(AndroidUtilities.dp(8.0f));
                        return;
                    }
                }
                emptyCell.setHeight(AndroidUtilities.dp(82.0f));
                return;
            }
            if (itemViewType == 2) {
                StickerSetNameCell stickerSetNameCell = (StickerSetNameCell) viewHolder.itemView;
                Object obj2 = this.cache.get(i);
                if (obj2 instanceof TLRPC.TL_messages_stickerSet) {
                    TLRPC.TL_messages_stickerSet tL_messages_stickerSet = (TLRPC.TL_messages_stickerSet) obj2;
                    if (!TextUtils.isEmpty(this.searchQuery) && this.localPacksByShortName.containsKey(tL_messages_stickerSet)) {
                        if (tL_messages_stickerSet.set != null) {
                            stickerSetNameCell.setText(tL_messages_stickerSet.set.title, 0);
                        }
                        stickerSetNameCell.setUrl(tL_messages_stickerSet.set.short_name, this.searchQuery.length());
                        return;
                    } else {
                        Integer num = this.localPacksByName.get(tL_messages_stickerSet);
                        if (tL_messages_stickerSet.set != null && num != null) {
                            stickerSetNameCell.setText(tL_messages_stickerSet.set.title, 0, num.intValue(), !TextUtils.isEmpty(this.searchQuery) ? this.searchQuery.length() : 0);
                        }
                        stickerSetNameCell.setUrl(null, 0);
                        return;
                    }
                }
                return;
            }
            if (itemViewType == 3) {
                TLRPC.StickerSetCovered stickerSetCovered = (TLRPC.StickerSetCovered) this.cache.get(i);
                FeaturedStickerSetInfoCell featuredStickerSetInfoCell = (FeaturedStickerSetInfoCell) viewHolder.itemView;
                boolean z3 = EmojiViewV2.this.installingStickerSets.indexOfKey(stickerSetCovered.set.id) >= 0;
                boolean z4 = EmojiViewV2.this.removingStickerSets.indexOfKey(stickerSetCovered.set.id) >= 0;
                if (z3 || z4) {
                    if (z3 && featuredStickerSetInfoCell.isInstalled()) {
                        EmojiViewV2.this.installingStickerSets.remove(stickerSetCovered.set.id);
                        z3 = false;
                    } else if (z4 && !featuredStickerSetInfoCell.isInstalled()) {
                        EmojiViewV2.this.removingStickerSets.remove(stickerSetCovered.set.id);
                        z4 = false;
                    }
                }
                if (!z3 && !z4) {
                    z2 = false;
                }
                featuredStickerSetInfoCell.setDrawProgress(z2);
                int iIndexOfIgnoreCase = TextUtils.isEmpty(this.searchQuery) ? -1 : AndroidUtilities.indexOfIgnoreCase(stickerSetCovered.set.title, this.searchQuery);
                if (iIndexOfIgnoreCase >= 0) {
                    featuredStickerSetInfoCell.setStickerSet(stickerSetCovered, false, iIndexOfIgnoreCase, this.searchQuery.length());
                    return;
                }
                featuredStickerSetInfoCell.setStickerSet(stickerSetCovered, false);
                if (!TextUtils.isEmpty(this.searchQuery) && AndroidUtilities.indexOfIgnoreCase(stickerSetCovered.set.short_name, this.searchQuery) == 0) {
                    featuredStickerSetInfoCell.setUrl(stickerSetCovered.set.short_name, this.searchQuery.length());
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            int i;
            ArrayList<TLRPC.Document> arrayList;
            Object obj;
            this.rowStartPack.clear();
            this.positionToRow.clear();
            this.cache.clear();
            this.positionsToSets.clear();
            this.positionToEmoji.clear();
            this.totalItems = 0;
            int i2 = 0;
            int i3 = -1;
            int size = this.serverPacks.size();
            int size2 = this.localPacks.size();
            int i4 = !this.emojiArrays.isEmpty() ? 1 : 0;
            while (i3 < size + size2 + i4) {
                Object obj2 = null;
                if (i3 == -1) {
                    SparseArray<Object> sparseArray = this.cache;
                    int i5 = this.totalItems;
                    this.totalItems = i5 + 1;
                    sparseArray.put(i5, "search");
                    i2++;
                    i = size;
                } else {
                    int i6 = i3;
                    if (i6 < size2) {
                        TLRPC.TL_messages_stickerSet tL_messages_stickerSet = this.localPacks.get(i6);
                        arrayList = tL_messages_stickerSet.documents;
                        obj = tL_messages_stickerSet;
                        i = size;
                    } else {
                        int i7 = i6 - size2;
                        if (i7 < i4) {
                            int i8 = 0;
                            String str = "";
                            int size3 = this.emojiArrays.size();
                            for (int i9 = 0; i9 < size3; i9++) {
                                ArrayList<TLRPC.Document> arrayList2 = this.emojiArrays.get(i9);
                                String str2 = this.emojiStickers.get(arrayList2);
                                if (str2 != null && !str.equals(str2)) {
                                    str = str2;
                                    this.positionToEmoji.put(this.totalItems + i8, str);
                                }
                                int i10 = 0;
                                int size4 = arrayList2.size();
                                while (i10 < size4) {
                                    int i11 = size;
                                    int i12 = this.totalItems + i8;
                                    String str3 = str;
                                    int i13 = (i8 / EmojiViewV2.this.stickersGridAdapter.stickersPerRow) + i2;
                                    int i14 = size3;
                                    TLRPC.Document document = arrayList2.get(i10);
                                    ArrayList<TLRPC.Document> arrayList3 = arrayList2;
                                    this.cache.put(i12, document);
                                    String str4 = str2;
                                    int i15 = i10;
                                    TLRPC.TL_messages_stickerSet stickerSetById = MediaDataController.getInstance(EmojiViewV2.this.currentAccount).getStickerSetById(MediaDataController.getStickerSetId(document));
                                    if (stickerSetById != null) {
                                        this.cacheParent.put(i12, stickerSetById);
                                    }
                                    this.positionToRow.put(i12, i13);
                                    if (i3 >= size2 && (obj2 instanceof TLRPC.StickerSetCovered)) {
                                        this.positionsToSets.put(i12, (TLRPC.StickerSetCovered) null);
                                    }
                                    i8++;
                                    i10 = i15 + 1;
                                    size = i11;
                                    str = str3;
                                    arrayList2 = arrayList3;
                                    size3 = i14;
                                    str2 = str4;
                                }
                            }
                            i = size;
                            int iCeil = (int) Math.ceil(i8 / EmojiViewV2.this.stickersGridAdapter.stickersPerRow);
                            for (int i16 = 0; i16 < iCeil; i16++) {
                                this.rowStartPack.put(i2 + i16, Integer.valueOf(i8));
                            }
                            this.totalItems += EmojiViewV2.this.stickersGridAdapter.stickersPerRow * iCeil;
                            i2 += iCeil;
                        } else {
                            i = size;
                            TLRPC.StickerSetCovered stickerSetCovered = this.serverPacks.get(i7 - i4);
                            arrayList = stickerSetCovered.covers;
                            obj = stickerSetCovered;
                        }
                    }
                    if (!arrayList.isEmpty()) {
                        int iCeil2 = (int) Math.ceil(arrayList.size() / EmojiViewV2.this.stickersGridAdapter.stickersPerRow);
                        this.cache.put(this.totalItems, obj);
                        if (i3 >= size2 && (obj instanceof TLRPC.StickerSetCovered)) {
                            this.positionsToSets.put(this.totalItems, (TLRPC.StickerSetCovered) obj);
                        }
                        this.positionToRow.put(this.totalItems, i2);
                        int size5 = arrayList.size();
                        for (int i17 = 0; i17 < size5; i17++) {
                            int i18 = i17 + 1 + this.totalItems;
                            int i19 = i2 + 1 + (i17 / EmojiViewV2.this.stickersGridAdapter.stickersPerRow);
                            this.cache.put(i18, arrayList.get(i17));
                            if (obj != null) {
                                this.cacheParent.put(i18, obj);
                            }
                            this.positionToRow.put(i18, i19);
                            if (i3 >= size2 && (obj instanceof TLRPC.StickerSetCovered)) {
                                this.positionsToSets.put(i18, (TLRPC.StickerSetCovered) obj);
                            }
                        }
                        int i20 = iCeil2 + 1;
                        for (int i21 = 0; i21 < i20; i21++) {
                            this.rowStartPack.put(i2 + i21, obj);
                        }
                        this.totalItems += (EmojiViewV2.this.stickersGridAdapter.stickersPerRow * iCeil2) + 1;
                        i2 += iCeil2 + 1;
                    }
                }
                i3++;
                size = i;
            }
            super.notifyDataSetChanged();
        }
    }
}
