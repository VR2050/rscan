package im.uwrkaxlmjj.ui;

import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.Context;
import android.database.DataSetObserver;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.style.CharacterStyle;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import com.google.android.exoplayer2.util.MimeTypes;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BackDrawable;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.MenuDrawable;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.ChatActionCell;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import im.uwrkaxlmjj.ui.cells.DialogCell;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.components.ColorPicker;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ThemePreviewActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    public static final int SCREEN_TYPE_ACCENT_COLOR = 1;
    public static final int SCREEN_TYPE_PREVIEW = 0;
    private ActionBar actionBar2;
    private Runnable applyAccentAction;
    private boolean applyAccentScheduled;
    private Theme.ThemeInfo applyingTheme;
    private FrameLayout buttonsContainer;
    private TextView cancelButton;
    private ColorPicker colorPicker;
    private boolean deleteOnCancel;
    private DialogsAdapter dialogsAdapter;
    private TextView doneButton;
    private View dotsContainer;
    private ImageView floatingButton;
    private int lastPickedColor;
    private RecyclerListView listView;
    private RecyclerListView listView2;
    private MessagesAdapter messagesAdapter;
    private boolean nightTheme;
    private FrameLayout page1;
    private SizeNotifierFrameLayout page2;
    private final int screenType;
    private List<ThemeDescription> themeDescriptions;
    private boolean useDefaultThemeForButtons;
    private ViewPager viewPager;

    public /* synthetic */ void lambda$new$0$ThemePreviewActivity() {
        this.applyAccentScheduled = false;
        applyAccent(this.lastPickedColor);
    }

    public ThemePreviewActivity(Theme.ThemeInfo themeInfo) {
        this(themeInfo, false, 0, false);
    }

    public ThemePreviewActivity(Theme.ThemeInfo themeInfo, boolean deleteFile, int screenType, boolean night) {
        this.useDefaultThemeForButtons = true;
        this.applyAccentAction = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ThemePreviewActivity$LvlJFD9kIozl7B2I3svcK9awpeE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$0$ThemePreviewActivity();
            }
        };
        this.screenType = screenType;
        this.swipeBackEnabled = false;
        this.nightTheme = night;
        this.applyingTheme = themeInfo;
        this.deleteOnCancel = deleteFile;
        if (screenType == 1) {
            Theme.applyThemeTemporary(new Theme.ThemeInfo(themeInfo));
            this.useDefaultThemeForButtons = false;
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.goingToPreviewTheme, new Object[0]);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.page1 = new FrameLayout(context);
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem item = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchExpand() {
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public boolean canCollapseSearch() {
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchCollapse() {
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onTextChanged(EditText editText) {
            }
        });
        item.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
        this.actionBar.setBackButtonDrawable(new MenuDrawable());
        this.actionBar.setAddToContainer(false);
        this.actionBar.setTitle(LocaleController.getString("ThemePreview", R.string.ThemePreview));
        FrameLayout frameLayout = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.2
            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize);
                measureChildWithMargins(ThemePreviewActivity.this.actionBar, widthMeasureSpec, 0, heightMeasureSpec, 0);
                int actionBarHeight = ThemePreviewActivity.this.actionBar.getMeasuredHeight();
                if (ThemePreviewActivity.this.actionBar.getVisibility() == 0) {
                    heightSize -= actionBarHeight;
                }
                FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ThemePreviewActivity.this.listView.getLayoutParams();
                layoutParams.topMargin = actionBarHeight;
                ThemePreviewActivity.this.listView.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
                measureChildWithMargins(ThemePreviewActivity.this.floatingButton, widthMeasureSpec, 0, heightMeasureSpec, 0);
            }

            @Override // android.view.ViewGroup
            protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                boolean result = super.drawChild(canvas, child, drawingTime);
                if (child == ThemePreviewActivity.this.actionBar && ThemePreviewActivity.this.parentLayout != null) {
                    ThemePreviewActivity.this.parentLayout.drawHeaderShadow(canvas, ThemePreviewActivity.this.actionBar.getVisibility() == 0 ? ThemePreviewActivity.this.actionBar.getMeasuredHeight() : 0);
                }
                return result;
            }
        };
        this.page1 = frameLayout;
        frameLayout.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(true);
        this.listView.setItemAnimator(null);
        this.listView.setLayoutAnimation(null);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.page1.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        ImageView imageView = new ImageView(context);
        this.floatingButton = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        Drawable drawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_chats_actionBackground), Theme.getColor(Theme.key_chats_actionPressedBackground));
        if (Build.VERSION.SDK_INT < 21) {
            Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow).mutate();
            shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
            CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable, 0, 0);
            combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
            drawable = combinedDrawable;
        }
        this.floatingButton.setBackgroundDrawable(drawable);
        this.floatingButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chats_actionIcon), PorterDuff.Mode.MULTIPLY));
        this.floatingButton.setImageResource(R.drawable.floating_pencil);
        if (Build.VERSION.SDK_INT >= 21) {
            StateListAnimator animator = new StateListAnimator();
            animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.floatingButton, "translationZ", AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
            animator.addState(new int[0], ObjectAnimator.ofFloat(this.floatingButton, "translationZ", AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
            this.floatingButton.setStateListAnimator(animator);
            this.floatingButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.3
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        this.page1.addView(this.floatingButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, (LocaleController.isRTL ? 3 : 5) | 80, LocaleController.isRTL ? 14.0f : 0.0f, 0.0f, LocaleController.isRTL ? 0.0f : 14.0f, 14.0f));
        DialogsAdapter dialogsAdapter = new DialogsAdapter(context);
        this.dialogsAdapter = dialogsAdapter;
        this.listView.setAdapter(dialogsAdapter);
        SizeNotifierFrameLayout sizeNotifierFrameLayout = new SizeNotifierFrameLayout(context) { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.4
            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize);
                measureChildWithMargins(ThemePreviewActivity.this.actionBar2, widthMeasureSpec, 0, heightMeasureSpec, 0);
                int actionBarHeight = ThemePreviewActivity.this.actionBar2.getMeasuredHeight();
                if (ThemePreviewActivity.this.actionBar2.getVisibility() == 0) {
                    heightSize -= actionBarHeight;
                }
                FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) ThemePreviewActivity.this.listView2.getLayoutParams();
                layoutParams.topMargin = actionBarHeight;
                ThemePreviewActivity.this.listView2.measure(View.MeasureSpec.makeMeasureSpec(widthSize, 1073741824), View.MeasureSpec.makeMeasureSpec(heightSize, 1073741824));
            }

            @Override // android.view.ViewGroup
            protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                boolean result = super.drawChild(canvas, child, drawingTime);
                if (child == ThemePreviewActivity.this.actionBar2 && ThemePreviewActivity.this.parentLayout != null) {
                    ThemePreviewActivity.this.parentLayout.drawHeaderShadow(canvas, ThemePreviewActivity.this.actionBar2.getVisibility() == 0 ? ThemePreviewActivity.this.actionBar2.getMeasuredHeight() : 0);
                }
                return result;
            }
        };
        this.page2 = sizeNotifierFrameLayout;
        sizeNotifierFrameLayout.setBackgroundImage(Theme.getCachedWallpaper(), Theme.isWallpaperMotion());
        this.messagesAdapter = new MessagesAdapter(context);
        ActionBar actionBarCreateActionBar = createActionBar(context);
        this.actionBar2 = actionBarCreateActionBar;
        actionBarCreateActionBar.setBackButtonDrawable(new BackDrawable(false));
        this.page2.addView(this.actionBar2, LayoutHelper.createFrame(-1, -2.0f));
        this.actionBar2.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.5
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ThemePreviewActivity.this.cancelThemeApply();
                }
            }
        });
        if (this.messagesAdapter.showSecretMessages) {
            this.actionBar2.setTitle(LocaleController.getString(R.string.AppName));
            this.actionBar2.setSubtitle(LocaleController.formatPluralString("Members", 505));
        } else {
            String name = this.applyingTheme.info != null ? this.applyingTheme.info.title : this.applyingTheme.getName();
            int index = name.lastIndexOf(".attheme");
            if (index >= 0) {
                name = name.substring(0, index);
            }
            this.actionBar2.setTitle(name);
            if (this.applyingTheme.info != null && this.applyingTheme.info.installs_count > 0) {
                this.actionBar2.setSubtitle(LocaleController.formatPluralString("ThemeInstallCount", this.applyingTheme.info.installs_count));
            } else {
                this.actionBar2.setSubtitle(LocaleController.formatDateOnline((System.currentTimeMillis() / 1000) - 3600));
            }
        }
        RecyclerListView recyclerListView2 = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.6
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean drawChild(Canvas canvas, View child, long drawingTime) {
                RecyclerView.ViewHolder holder;
                AnonymousClass6 anonymousClass6 = this;
                boolean result = super.drawChild(canvas, child, drawingTime);
                if (child instanceof ChatMessageCell) {
                    ChatMessageCell chatMessageCell = (ChatMessageCell) child;
                    chatMessageCell.getMessageObject();
                    ImageReceiver imageReceiver = chatMessageCell.getAvatarImage();
                    if (imageReceiver != null) {
                        int top = child.getTop();
                        if (chatMessageCell.isPinnedBottom() && (holder = ThemePreviewActivity.this.listView2.getChildViewHolder(child)) != null) {
                            int p = holder.getAdapterPosition();
                            int nextPosition = p - 1;
                            if (ThemePreviewActivity.this.listView2.findViewHolderForAdapterPosition(nextPosition) != null) {
                                imageReceiver.setImageY(-AndroidUtilities.dp(1000.0f));
                                imageReceiver.draw(canvas);
                                return result;
                            }
                        }
                        float tx = chatMessageCell.getTranslationX();
                        int y = child.getTop() + chatMessageCell.getLayoutHeight();
                        int maxY = ThemePreviewActivity.this.listView2.getMeasuredHeight() - ThemePreviewActivity.this.listView2.getPaddingBottom();
                        if (y > maxY) {
                            y = maxY;
                        }
                        if (chatMessageCell.isPinnedTop() && (holder = ThemePreviewActivity.this.listView2.getChildViewHolder(child)) != null) {
                            int tries = 0;
                            while (tries < 20) {
                                tries++;
                                int p2 = holder.getAdapterPosition();
                                int prevPosition = p2 + 1;
                                RecyclerView.ViewHolder holder2 = ThemePreviewActivity.this.listView2.findViewHolderForAdapterPosition(prevPosition);
                                if (holder2 == null) {
                                    break;
                                }
                                top = holder2.itemView.getTop();
                                if (y - AndroidUtilities.dp(48.0f) < holder2.itemView.getBottom()) {
                                    tx = Math.min(holder2.itemView.getTranslationX(), tx);
                                }
                                if (!(holder2.itemView instanceof ChatMessageCell)) {
                                    break;
                                }
                                ChatMessageCell cell = (ChatMessageCell) holder2.itemView;
                                if (!cell.isPinnedTop()) {
                                    break;
                                }
                                anonymousClass6 = this;
                            }
                        }
                        if (y - AndroidUtilities.dp(48.0f) < top) {
                            y = top + AndroidUtilities.dp(48.0f);
                        }
                        if (tx != 0.0f) {
                            canvas.save();
                            canvas.translate(tx, 0.0f);
                        }
                        imageReceiver.setImageY(y - AndroidUtilities.dp(44.0f));
                        imageReceiver.draw(canvas);
                        if (tx != 0.0f) {
                            canvas.restore();
                        }
                    }
                }
                return result;
            }
        };
        this.listView2 = recyclerListView2;
        recyclerListView2.setVerticalScrollBarEnabled(true);
        this.listView2.setItemAnimator(null);
        this.listView2.setLayoutAnimation(null);
        this.listView2.setPadding(0, AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f));
        this.listView2.setClipToPadding(false);
        this.listView2.setLayoutManager(new LinearLayoutManager(context, 1, true));
        this.listView2.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.page2.addView(this.listView2, LayoutHelper.createFrame(-1, -1, 51));
        this.listView2.setAdapter(this.messagesAdapter);
        LinearLayout linearLayout = new LinearLayout(context);
        linearLayout.setOrientation(1);
        this.fragmentView = linearLayout;
        ViewPager viewPager = new ViewPager(context);
        this.viewPager = viewPager;
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.7
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                ThemePreviewActivity.this.dotsContainer.invalidate();
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }
        });
        this.viewPager.setAdapter(new PagerAdapter() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.8
            @Override // androidx.viewpager.widget.PagerAdapter
            public int getCount() {
                return 2;
            }

            @Override // androidx.viewpager.widget.PagerAdapter
            public boolean isViewFromObject(View view, Object object) {
                return object == view;
            }

            @Override // androidx.viewpager.widget.PagerAdapter
            public int getItemPosition(Object object) {
                return -1;
            }

            @Override // androidx.viewpager.widget.PagerAdapter
            public Object instantiateItem(ViewGroup container, int position) {
                ThemePreviewActivity themePreviewActivity = ThemePreviewActivity.this;
                View view = position == 0 ? themePreviewActivity.page2 : themePreviewActivity.page1;
                container.addView(view);
                return view;
            }

            @Override // androidx.viewpager.widget.PagerAdapter
            public void destroyItem(ViewGroup container, int position, Object object) {
                container.removeView((View) object);
            }

            @Override // androidx.viewpager.widget.PagerAdapter
            public void unregisterDataSetObserver(DataSetObserver observer) {
                if (observer != null) {
                    super.unregisterDataSetObserver(observer);
                }
            }
        });
        AndroidUtilities.setViewPagerEdgeEffectColor(this.viewPager, Theme.getColor(Theme.key_actionBarDefault));
        linearLayout.addView(this.viewPager, LayoutHelper.createLinear(-1, 0, 1.0f));
        View shadow = new View(context);
        shadow.setBackgroundResource(R.drawable.header_shadow_reverse);
        linearLayout.addView(shadow, LayoutHelper.createLinear(-1, 3, 0, 0, -3, 0, 0));
        if (this.screenType == 1) {
            FrameLayout colorPickerFrame = new FrameLayout(context);
            linearLayout.addView(colorPickerFrame, LayoutHelper.createLinear(-1, -2, 1));
            this.colorPicker = new ColorPicker(context, new ColorPicker.ColorPickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ThemePreviewActivity$tLKkrYzEVtZOVCSY8NtCv02XR_U
                @Override // im.uwrkaxlmjj.ui.components.ColorPicker.ColorPickerDelegate
                public final void setColor(int i) {
                    this.f$0.scheduleApplyAccent(i);
                }
            });
            if (this.applyingTheme.isDark()) {
                this.colorPicker.setMinBrightness(new ColorPicker.BrightnessLimit() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ThemePreviewActivity$m8vw-TrVRa9AvVrkAgBA9rvO618
                    @Override // im.uwrkaxlmjj.ui.components.ColorPicker.BrightnessLimit
                    public final float getLimit(int i, int i2, int i3) {
                        return ThemePreviewActivity.lambda$createView$1(i, i2, i3);
                    }
                });
            } else {
                this.colorPicker.setMaxBrightness(new ColorPicker.BrightnessLimit() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ThemePreviewActivity$H7m3ySrG_Wzdx-SwhCWEB78cHAA
                    @Override // im.uwrkaxlmjj.ui.components.ColorPicker.BrightnessLimit
                    public final float getLimit(int i, int i2, int i3) {
                        return ThemePreviewActivity.lambda$createView$2(i, i2, i3);
                    }
                });
            }
            this.colorPicker.setColor(this.applyingTheme.accentColor);
            colorPickerFrame.addView(this.colorPicker, LayoutHelper.createFrame(-1, 342, 1));
            View shadow2 = new View(context);
            shadow2.setBackgroundColor(301989888);
            linearLayout.addView(shadow2, LayoutHelper.createLinear(-1, 2, 0, 0, -2, 0, 0));
        }
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.buttonsContainer = frameLayout2;
        frameLayout2.setBackgroundColor(getButtonsColor(Theme.key_windowBackgroundWhite));
        linearLayout.addView(this.buttonsContainer, LayoutHelper.createLinear(-1, 48));
        View view = new View(context) { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.9
            private Paint paint = new Paint(1);

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                int selected = ThemePreviewActivity.this.viewPager.getCurrentItem();
                this.paint.setColor(ThemePreviewActivity.this.getButtonsColor(Theme.key_chat_fieldOverlayText));
                int a = 0;
                while (a < 2) {
                    this.paint.setAlpha(a == selected ? 255 : 127);
                    canvas.drawCircle(AndroidUtilities.dp((a * 15) + 3), AndroidUtilities.dp(4.0f), AndroidUtilities.dp(3.0f), this.paint);
                    a++;
                }
            }
        };
        this.dotsContainer = view;
        this.buttonsContainer.addView(view, LayoutHelper.createFrame(22, 8, 17));
        TextView textView = new TextView(context);
        this.cancelButton = textView;
        textView.setTextSize(1, 14.0f);
        this.cancelButton.setTextColor(getButtonsColor(Theme.key_chat_fieldOverlayText));
        this.cancelButton.setGravity(17);
        this.cancelButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_AUDIO_SELECTOR_COLOR, 0));
        this.cancelButton.setPadding(AndroidUtilities.dp(29.0f), 0, AndroidUtilities.dp(29.0f), 0);
        this.cancelButton.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        this.cancelButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.buttonsContainer.addView(this.cancelButton, LayoutHelper.createFrame(-2, -1, 51));
        this.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ThemePreviewActivity$63VDCKNIpzqzZmtS3MMV08BtUkY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$createView$3$ThemePreviewActivity(view2);
            }
        });
        TextView textView2 = new TextView(context);
        this.doneButton = textView2;
        textView2.setTextSize(1, 14.0f);
        this.doneButton.setTextColor(getButtonsColor(Theme.key_chat_fieldOverlayText));
        this.doneButton.setGravity(17);
        this.doneButton.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.ACTION_BAR_AUDIO_SELECTOR_COLOR, 0));
        this.doneButton.setPadding(AndroidUtilities.dp(29.0f), 0, AndroidUtilities.dp(29.0f), 0);
        this.doneButton.setText(LocaleController.getString("ApplyTheme", R.string.ApplyTheme).toUpperCase());
        this.doneButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.buttonsContainer.addView(this.doneButton, LayoutHelper.createFrame(-2, -1, 53));
        this.doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ThemePreviewActivity$LgfhWpodMW_SJWcufbnEnP_gtq8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$createView$4$ThemePreviewActivity(view2);
            }
        });
        this.themeDescriptions = getThemeDescriptionsInternal();
        return this.fragmentView;
    }

    static /* synthetic */ float lambda$createView$1(int r, int g, int b) {
        return 255.0f / ((((r * 0.5f) + (g * 0.8f)) + (b * 0.1f)) + 500.0f);
    }

    static /* synthetic */ float lambda$createView$2(int r, int g, int b) {
        return 255.0f / ((((r * 0.1f) + (g * 1.0f)) + (b * 0.1f)) + 50.0f);
    }

    public /* synthetic */ void lambda$createView$3$ThemePreviewActivity(View v) {
        cancelThemeApply();
    }

    public /* synthetic */ void lambda$createView$4$ThemePreviewActivity(View v) {
        int i = this.screenType;
        if (i == 0) {
            this.parentLayout.rebuildAllFragmentViews(false, false);
            Theme.applyThemeFile(new File(this.applyingTheme.pathToFile), this.applyingTheme.name, this.applyingTheme.info, false);
            getMessagesController().saveTheme(this.applyingTheme, false, false);
        } else if (i == 1) {
            Theme.saveThemeAccent(this.applyingTheme, this.colorPicker.getColor());
            Theme.applyPreviousTheme();
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.needSetDayNightTheme, this.applyingTheme, Boolean.valueOf(this.nightTheme));
        }
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetNewWallpapper);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetNewWallpapper);
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        DialogsAdapter dialogsAdapter = this.dialogsAdapter;
        if (dialogsAdapter != null) {
            dialogsAdapter.notifyDataSetChanged();
        }
        MessagesAdapter messagesAdapter = this.messagesAdapter;
        if (messagesAdapter != null) {
            messagesAdapter.notifyDataSetChanged();
        }
        SizeNotifierFrameLayout sizeNotifierFrameLayout = this.page2;
        if (sizeNotifierFrameLayout != null) {
            sizeNotifierFrameLayout.onResume();
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        SizeNotifierFrameLayout sizeNotifierFrameLayout = this.page2;
        if (sizeNotifierFrameLayout != null) {
            sizeNotifierFrameLayout.onResume();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        Theme.applyPreviousTheme();
        if (this.screenType != 1) {
            this.parentLayout.rebuildAllFragmentViews(false, false);
        }
        if (this.deleteOnCancel && this.applyingTheme.pathToFile != null && !Theme.isThemeInstalled(this.applyingTheme)) {
            new File(this.applyingTheme.pathToFile).delete();
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        SizeNotifierFrameLayout sizeNotifierFrameLayout;
        if (id == NotificationCenter.emojiDidLoad) {
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView == null) {
                return;
            }
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof DialogCell) {
                    DialogCell cell = (DialogCell) child;
                    cell.update(0);
                }
            }
            return;
        }
        if (id == NotificationCenter.didSetNewWallpapper && (sizeNotifierFrameLayout = this.page2) != null) {
            sizeNotifierFrameLayout.setBackgroundImage(Theme.getCachedWallpaper(), Theme.isWallpaperMotion());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void cancelThemeApply() {
        Theme.applyPreviousTheme();
        if (this.screenType != 1) {
            this.parentLayout.rebuildAllFragmentViews(false, false);
        }
        if (this.deleteOnCancel && this.applyingTheme.pathToFile != null && !Theme.isThemeInstalled(this.applyingTheme)) {
            new File(this.applyingTheme.pathToFile).delete();
        }
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getButtonsColor(String key) {
        return this.useDefaultThemeForButtons ? Theme.getDefaultColor(key) : Theme.getColor(key);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void scheduleApplyAccent(int accent) {
        this.lastPickedColor = accent;
        if (!this.applyAccentScheduled) {
            this.applyAccentScheduled = true;
            this.fragmentView.postDelayed(this.applyAccentAction, 16L);
        }
    }

    private void applyAccent(int accent) {
        Theme.applyCurrentThemeAccent(accent);
        int size = this.themeDescriptions.size();
        for (int i = 0; i < size; i++) {
            ThemeDescription description = this.themeDescriptions.get(i);
            description.setColor(Theme.getColor(description.getCurrentKey()), false, false);
        }
        this.listView.invalidateViews();
        this.listView2.invalidateViews();
        this.dotsContainer.invalidate();
    }

    public class DialogsAdapter extends RecyclerListView.SelectionAdapter {
        private ArrayList<DialogCell.CustomDialog> dialogs = new ArrayList<>();
        private Context mContext;

        public DialogsAdapter(Context context) {
            this.mContext = context;
            int date = (int) (System.currentTimeMillis() / 1000);
            DialogCell.CustomDialog customDialog = new DialogCell.CustomDialog();
            customDialog.name = LocaleController.getString("ThemePreviewDialog1", R.string.ThemePreviewDialog1);
            customDialog.message = LocaleController.getString("ThemePreviewDialogMessage1", R.string.ThemePreviewDialogMessage1);
            customDialog.id = 0;
            customDialog.unread_count = 0;
            customDialog.pinned = true;
            customDialog.muted = false;
            customDialog.type = 0;
            customDialog.date = date;
            customDialog.verified = false;
            customDialog.isMedia = false;
            customDialog.sent = true;
            this.dialogs.add(customDialog);
            DialogCell.CustomDialog customDialog2 = new DialogCell.CustomDialog();
            customDialog2.name = LocaleController.getString("ThemePreviewDialog2", R.string.ThemePreviewDialog2);
            customDialog2.message = LocaleController.getString("ThemePreviewDialogMessage2", R.string.ThemePreviewDialogMessage2);
            customDialog2.id = 1;
            customDialog2.unread_count = 2;
            customDialog2.pinned = false;
            customDialog2.muted = false;
            customDialog2.type = 0;
            customDialog2.date = date - 3600;
            customDialog2.verified = false;
            customDialog2.isMedia = false;
            customDialog2.sent = false;
            this.dialogs.add(customDialog2);
            DialogCell.CustomDialog customDialog3 = new DialogCell.CustomDialog();
            customDialog3.name = LocaleController.getString("ThemePreviewDialog3", R.string.ThemePreviewDialog3);
            customDialog3.message = LocaleController.getString("ThemePreviewDialogMessage3", R.string.ThemePreviewDialogMessage3);
            customDialog3.id = 2;
            customDialog3.unread_count = 3;
            customDialog3.pinned = false;
            customDialog3.muted = true;
            customDialog3.type = 0;
            customDialog3.date = date - 7200;
            customDialog3.verified = false;
            customDialog3.isMedia = true;
            customDialog3.sent = false;
            this.dialogs.add(customDialog3);
            DialogCell.CustomDialog customDialog4 = new DialogCell.CustomDialog();
            customDialog4.name = LocaleController.getString("ThemePreviewDialog4", R.string.ThemePreviewDialog4);
            customDialog4.message = LocaleController.getString("ThemePreviewDialogMessage4", R.string.ThemePreviewDialogMessage4);
            customDialog4.id = 3;
            customDialog4.unread_count = 0;
            customDialog4.pinned = false;
            customDialog4.muted = false;
            customDialog4.type = 2;
            customDialog4.date = date - 10800;
            customDialog4.verified = false;
            customDialog4.isMedia = false;
            customDialog4.sent = false;
            this.dialogs.add(customDialog4);
            DialogCell.CustomDialog customDialog5 = new DialogCell.CustomDialog();
            customDialog5.name = LocaleController.getString("ThemePreviewDialog5", R.string.ThemePreviewDialog5);
            customDialog5.message = LocaleController.getString("ThemePreviewDialogMessage5", R.string.ThemePreviewDialogMessage5);
            customDialog5.id = 4;
            customDialog5.unread_count = 0;
            customDialog5.pinned = false;
            customDialog5.muted = false;
            customDialog5.type = 1;
            customDialog5.date = date - 14400;
            customDialog5.verified = false;
            customDialog5.isMedia = false;
            customDialog5.sent = true;
            this.dialogs.add(customDialog5);
            DialogCell.CustomDialog customDialog6 = new DialogCell.CustomDialog();
            customDialog6.name = LocaleController.getString("ThemePreviewDialog6", R.string.ThemePreviewDialog6);
            customDialog6.message = LocaleController.getString("ThemePreviewDialogMessage6", R.string.ThemePreviewDialogMessage6);
            customDialog6.id = 5;
            customDialog6.unread_count = 0;
            customDialog6.pinned = false;
            customDialog6.muted = false;
            customDialog6.type = 0;
            customDialog6.date = date - 18000;
            customDialog6.verified = false;
            customDialog6.isMedia = false;
            customDialog6.sent = false;
            this.dialogs.add(customDialog6);
            DialogCell.CustomDialog customDialog7 = new DialogCell.CustomDialog();
            customDialog7.name = LocaleController.getString("ThemePreviewDialog7", R.string.ThemePreviewDialog7);
            customDialog7.message = LocaleController.getString("ThemePreviewDialogMessage7", R.string.ThemePreviewDialogMessage7);
            customDialog7.id = 6;
            customDialog7.unread_count = 0;
            customDialog7.pinned = false;
            customDialog7.muted = false;
            customDialog7.type = 0;
            customDialog7.date = date - 21600;
            customDialog7.verified = true;
            customDialog7.isMedia = false;
            customDialog7.sent = false;
            this.dialogs.add(customDialog7);
            DialogCell.CustomDialog customDialog8 = new DialogCell.CustomDialog();
            customDialog8.name = LocaleController.getString("ThemePreviewDialog8", R.string.ThemePreviewDialog8);
            customDialog8.message = LocaleController.getString("ThemePreviewDialogMessage8", R.string.ThemePreviewDialogMessage8);
            customDialog8.id = 0;
            customDialog8.unread_count = 0;
            customDialog8.pinned = false;
            customDialog8.muted = false;
            customDialog8.type = 0;
            customDialog8.date = date - 25200;
            customDialog8.verified = true;
            customDialog8.isMedia = false;
            customDialog8.sent = false;
            this.dialogs.add(customDialog8);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.dialogs.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new DialogCell(this.mContext, false, false);
            } else if (viewType == 1) {
                view = new LoadingCell(this.mContext);
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder viewHolder, int i) {
            if (viewHolder.getItemViewType() == 0) {
                DialogCell cell = (DialogCell) viewHolder.itemView;
                cell.useSeparator = i != getItemCount() - 1;
                cell.setDialog(this.dialogs.get(i));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i == this.dialogs.size()) {
                return 1;
            }
            return 0;
        }
    }

    public class MessagesAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private ArrayList<MessageObject> messages;
        private boolean showSecretMessages;

        public MessagesAdapter(Context context) {
            this.showSecretMessages = Utilities.random.nextInt(100) <= 1;
            this.mContext = context;
            this.messages = new ArrayList<>();
            int date = ((int) (System.currentTimeMillis() / 1000)) - 3600;
            if (this.showSecretMessages) {
                TLRPC.TL_user user1 = new TLRPC.TL_user();
                user1.id = Integer.MAX_VALUE;
                user1.first_name = "Me";
                TLRPC.TL_user user2 = new TLRPC.TL_user();
                user2.id = 2147483646;
                user2.first_name = "Serj";
                ArrayList<TLRPC.User> users = new ArrayList<>();
                users.add(user1);
                users.add(user2);
                MessagesController.getInstance(ThemePreviewActivity.this.currentAccount).putUsers(users, true);
                TLRPC.Message message = new TLRPC.TL_message();
                message.message = "Guess why Half-Life 3 was never released.";
                message.date = date + 960;
                message.dialog_id = -1L;
                message.flags = 259;
                message.id = 2147483646;
                message.media = new TLRPC.TL_messageMediaEmpty();
                message.out = false;
                message.to_id = new TLRPC.TL_peerChat();
                message.to_id.chat_id = 1;
                message.from_id = user2.id;
                this.messages.add(new MessageObject(ThemePreviewActivity.this.currentAccount, message, true));
                TLRPC.Message message2 = new TLRPC.TL_message();
                message2.message = "No.\nAnd every unnecessary ping of the dev delays the release for 10 days.\nEvery request for ETA delays the release for 2 weeks.";
                message2.date = date + 960;
                message2.dialog_id = -1L;
                message2.flags = 259;
                message2.id = 1;
                message2.media = new TLRPC.TL_messageMediaEmpty();
                message2.out = false;
                message2.to_id = new TLRPC.TL_peerChat();
                message2.to_id.chat_id = 1;
                message2.from_id = user2.id;
                this.messages.add(new MessageObject(ThemePreviewActivity.this.currentAccount, message2, true));
                TLRPC.Message message3 = new TLRPC.TL_message();
                message3.message = "Is source code for Android coming anytime soon?";
                message3.date = date + 600;
                message3.dialog_id = -1L;
                message3.flags = 259;
                message3.id = 1;
                message3.media = new TLRPC.TL_messageMediaEmpty();
                message3.out = false;
                message3.to_id = new TLRPC.TL_peerChat();
                message3.to_id.chat_id = 1;
                message3.from_id = user1.id;
                this.messages.add(new MessageObject(ThemePreviewActivity.this.currentAccount, message3, true));
            } else {
                TLRPC.Message message4 = new TLRPC.TL_message();
                message4.message = LocaleController.getString("ThemePreviewLine1", R.string.ThemePreviewLine1);
                message4.date = date + 60;
                message4.dialog_id = 1L;
                message4.flags = 259;
                message4.from_id = UserConfig.getInstance(ThemePreviewActivity.this.currentAccount).getClientUserId();
                message4.id = 1;
                message4.media = new TLRPC.TL_messageMediaEmpty();
                message4.out = true;
                message4.to_id = new TLRPC.TL_peerUser();
                message4.to_id.user_id = 0;
                MessageObject replyMessageObject = new MessageObject(ThemePreviewActivity.this.currentAccount, message4, true);
                TLRPC.Message message5 = new TLRPC.TL_message();
                message5.message = LocaleController.getString("ThemePreviewLine2", R.string.ThemePreviewLine2);
                message5.date = date + 960;
                message5.dialog_id = 1L;
                message5.flags = 259;
                message5.from_id = UserConfig.getInstance(ThemePreviewActivity.this.currentAccount).getClientUserId();
                message5.id = 1;
                message5.media = new TLRPC.TL_messageMediaEmpty();
                message5.out = true;
                message5.to_id = new TLRPC.TL_peerUser();
                message5.to_id.user_id = 0;
                this.messages.add(new MessageObject(ThemePreviewActivity.this.currentAccount, message5, true));
                TLRPC.Message message6 = new TLRPC.TL_message();
                message6.date = date + TsExtractor.TS_STREAM_TYPE_HDMV_DTS;
                message6.dialog_id = 1L;
                message6.flags = 259;
                message6.from_id = 0;
                message6.id = 5;
                message6.media = new TLRPC.TL_messageMediaDocument();
                message6.media.flags |= 3;
                message6.media.document = new TLRPC.TL_document();
                message6.media.document.mime_type = MimeTypes.AUDIO_MP4;
                message6.media.document.file_reference = new byte[0];
                TLRPC.TL_documentAttributeAudio audio = new TLRPC.TL_documentAttributeAudio();
                audio.duration = 243;
                audio.performer = LocaleController.getString("ThemePreviewSongPerformer", R.string.ThemePreviewSongPerformer);
                audio.title = LocaleController.getString("ThemePreviewSongTitle", R.string.ThemePreviewSongTitle);
                message6.media.document.attributes.add(audio);
                message6.out = false;
                message6.to_id = new TLRPC.TL_peerUser();
                message6.to_id.user_id = UserConfig.getInstance(ThemePreviewActivity.this.currentAccount).getClientUserId();
                this.messages.add(new MessageObject(ThemePreviewActivity.this.currentAccount, message6, true));
                TLRPC.Message message7 = new TLRPC.TL_message();
                message7.message = LocaleController.getString("ThemePreviewLine3", R.string.ThemePreviewLine3);
                message7.date = date + 60;
                message7.dialog_id = 1L;
                message7.flags = 265;
                message7.from_id = 0;
                message7.id = 1;
                message7.reply_to_msg_id = 5;
                message7.media = new TLRPC.TL_messageMediaEmpty();
                message7.out = false;
                message7.to_id = new TLRPC.TL_peerUser();
                message7.to_id.user_id = UserConfig.getInstance(ThemePreviewActivity.this.currentAccount).getClientUserId();
                MessageObject messageObject = new MessageObject(ThemePreviewActivity.this.currentAccount, message7, true);
                messageObject.customReplyName = LocaleController.getString("ThemePreviewLine3Reply", R.string.ThemePreviewLine3Reply);
                messageObject.replyMessageObject = replyMessageObject;
                this.messages.add(messageObject);
                TLRPC.Message message8 = new TLRPC.TL_message();
                message8.date = date + 120;
                message8.dialog_id = 1L;
                message8.flags = 259;
                message8.from_id = UserConfig.getInstance(ThemePreviewActivity.this.currentAccount).getClientUserId();
                message8.id = 1;
                message8.media = new TLRPC.TL_messageMediaDocument();
                message8.media.flags |= 3;
                message8.media.document = new TLRPC.TL_document();
                message8.media.document.mime_type = "audio/ogg";
                message8.media.document.file_reference = new byte[0];
                TLRPC.TL_documentAttributeAudio audio2 = new TLRPC.TL_documentAttributeAudio();
                audio2.flags = 1028;
                audio2.duration = 3;
                audio2.voice = true;
                audio2.waveform = new byte[]{0, 4, 17, -50, -93, 86, -103, -45, -12, -26, 63, -25, -3, 109, -114, -54, -4, -1, -1, -1, -1, -29, -1, -1, -25, -1, -1, -97, -43, 57, -57, -108, 1, -91, -4, -47, 21, 99, 10, 97, 43, 45, 115, -112, -77, 51, -63, 66, 40, 34, -122, -116, 48, -124, 16, 66, -120, 16, 68, 16, 33, 4, 1};
                message8.media.document.attributes.add(audio2);
                message8.out = true;
                message8.to_id = new TLRPC.TL_peerUser();
                message8.to_id.user_id = 0;
                MessageObject messageObject2 = new MessageObject(ThemePreviewActivity.this.currentAccount, message8, true);
                messageObject2.audioProgressSec = 1;
                messageObject2.audioProgress = 0.3f;
                messageObject2.useCustomPhoto = true;
                this.messages.add(messageObject2);
                this.messages.add(replyMessageObject);
                TLRPC.Message message9 = new TLRPC.TL_message();
                message9.date = date + 10;
                message9.dialog_id = 1L;
                message9.flags = 257;
                message9.from_id = 0;
                message9.id = 1;
                message9.media = new TLRPC.TL_messageMediaPhoto();
                message9.media.flags |= 3;
                message9.media.photo = new TLRPC.TL_photo();
                message9.media.photo.file_reference = new byte[0];
                message9.media.photo.has_stickers = false;
                message9.media.photo.id = 1L;
                message9.media.photo.access_hash = 0L;
                message9.media.photo.date = date;
                TLRPC.TL_photoSize photoSize = new TLRPC.TL_photoSize();
                photoSize.size = 0;
                photoSize.w = SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION;
                photoSize.h = 302;
                photoSize.type = "s";
                photoSize.location = new TLRPC.TL_fileLocationUnavailable();
                message9.media.photo.sizes.add(photoSize);
                message9.message = LocaleController.getString("ThemePreviewLine4", R.string.ThemePreviewLine4);
                message9.out = false;
                message9.to_id = new TLRPC.TL_peerUser();
                message9.to_id.user_id = UserConfig.getInstance(ThemePreviewActivity.this.currentAccount).getClientUserId();
                MessageObject messageObject3 = new MessageObject(ThemePreviewActivity.this.currentAccount, message9, true);
                messageObject3.useCustomPhoto = true;
                this.messages.add(messageObject3);
            }
            TLRPC.Message message10 = new TLRPC.TL_message();
            message10.message = LocaleController.formatDateChat(date);
            message10.id = 0;
            message10.date = date;
            MessageObject messageObject4 = new MessageObject(ThemePreviewActivity.this.currentAccount, message10, false);
            messageObject4.type = 10;
            messageObject4.contentType = 1;
            messageObject4.isDateObject = true;
            this.messages.add(messageObject4);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.messages.size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new ChatMessageCell(this.mContext);
                ChatMessageCell chatMessageCell = (ChatMessageCell) view;
                chatMessageCell.setDelegate(new ChatMessageCell.ChatMessageCellDelegate() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.MessagesAdapter.1
                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean canPerformActions() {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$canPerformActions(this);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didLongPress(ChatMessageCell chatMessageCell2, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPress(this, chatMessageCell2, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didLongPressUserAvatar(ChatMessageCell chatMessageCell2, TLRPC.User user, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didLongPressUserAvatar(this, chatMessageCell2, user, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressBotButton(ChatMessageCell chatMessageCell2, TLRPC.KeyboardButton keyboardButton) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressBotButton(this, chatMessageCell2, keyboardButton);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressCancelSendButton(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressCancelSendButton(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressChannelAvatar(ChatMessageCell chatMessageCell2, TLRPC.Chat chat, int i, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressChannelAvatar(this, chatMessageCell2, chat, i, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressHiddenForward(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressHiddenForward(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressImage(ChatMessageCell chatMessageCell2, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressImage(this, chatMessageCell2, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressInstantButton(ChatMessageCell chatMessageCell2, int i) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressInstantButton(this, chatMessageCell2, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressOther(ChatMessageCell chatMessageCell2, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressOther(this, chatMessageCell2, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressReaction(ChatMessageCell chatMessageCell2, TLRPC.TL_reactionCount tL_reactionCount) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReaction(this, chatMessageCell2, tL_reactionCount);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressRedpkgTransfer(ChatMessageCell chatMessageCell2, MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressRedpkgTransfer(this, chatMessageCell2, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressReplyMessage(ChatMessageCell chatMessageCell2, int i) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressReplyMessage(this, chatMessageCell2, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressShare(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressShare(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressSysNotifyVideoFullPlayer(ChatMessageCell chatMessageCell2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressSysNotifyVideoFullPlayer(this, chatMessageCell2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressUrl(ChatMessageCell chatMessageCell2, CharacterStyle characterStyle, boolean z) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUrl(this, chatMessageCell2, characterStyle, z);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressUserAvatar(ChatMessageCell chatMessageCell2, TLRPC.User user, float f, float f2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressUserAvatar(this, chatMessageCell2, user, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressViaBot(ChatMessageCell chatMessageCell2, String str) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressViaBot(this, chatMessageCell2, str);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didPressVoteButton(ChatMessageCell chatMessageCell2, TLRPC.TL_pollAnswer tL_pollAnswer) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didPressVoteButton(this, chatMessageCell2, tL_pollAnswer);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void didStartVideoStream(MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$didStartVideoStream(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ String getAdminRank(int i) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$getAdminRank(this, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void needOpenWebView(String str, String str2, String str3, String str4, int i, int i2) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$needOpenWebView(this, str, str2, str3, str4, i, i2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean needPlayMessage(MessageObject messageObject) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$needPlayMessage(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void setShouldNotRepeatSticker(MessageObject messageObject) {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$setShouldNotRepeatSticker(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ boolean shouldRepeatSticker(MessageObject messageObject) {
                        return ChatMessageCell.ChatMessageCellDelegate.CC.$default$shouldRepeatSticker(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatMessageCell.ChatMessageCellDelegate
                    public /* synthetic */ void videoTimerReached() {
                        ChatMessageCell.ChatMessageCellDelegate.CC.$default$videoTimerReached(this);
                    }
                });
            } else if (viewType == 1) {
                view = new ChatActionCell(this.mContext);
                ((ChatActionCell) view).setDelegate(new ChatActionCell.ChatActionCellDelegate() { // from class: im.uwrkaxlmjj.ui.ThemePreviewActivity.MessagesAdapter.2
                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didClickImage(ChatActionCell chatActionCell) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didClickImage(this, chatActionCell);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didLongPress(ChatActionCell chatActionCell, float f, float f2) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didLongPress(this, chatActionCell, f, f2);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didPressBotButton(MessageObject messageObject, TLRPC.KeyboardButton keyboardButton) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didPressBotButton(this, messageObject, keyboardButton);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didPressReplyMessage(ChatActionCell chatActionCell, int i) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didPressReplyMessage(this, chatActionCell, i);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void didRedUrl(MessageObject messageObject) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$didRedUrl(this, messageObject);
                    }

                    @Override // im.uwrkaxlmjj.ui.cells.ChatActionCell.ChatActionCellDelegate
                    public /* synthetic */ void needOpenUserProfile(int i) {
                        ChatActionCell.ChatActionCellDelegate.CC.$default$needOpenUserProfile(this, i);
                    }
                });
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            boolean pinnedBotton;
            MessageObject message = this.messages.get(position);
            View view = holder.itemView;
            if (view instanceof ChatMessageCell) {
                ChatMessageCell messageCell = (ChatMessageCell) view;
                boolean pinnedTop = false;
                messageCell.isChat = false;
                int nextType = getItemViewType(position - 1);
                int prevType = getItemViewType(position + 1);
                if (!(message.messageOwner.reply_markup instanceof TLRPC.TL_replyInlineMarkup) && nextType == holder.getItemViewType()) {
                    MessageObject nextMessage = this.messages.get(position - 1);
                    pinnedBotton = nextMessage.isOutOwner() == message.isOutOwner() && Math.abs(nextMessage.messageOwner.date - message.messageOwner.date) <= 300;
                } else {
                    pinnedBotton = false;
                }
                if (prevType == holder.getItemViewType()) {
                    MessageObject prevMessage = this.messages.get(position + 1);
                    if (!(prevMessage.messageOwner.reply_markup instanceof TLRPC.TL_replyInlineMarkup) && prevMessage.isOutOwner() == message.isOutOwner() && Math.abs(prevMessage.messageOwner.date - message.messageOwner.date) <= 300) {
                        pinnedTop = true;
                    }
                } else {
                    pinnedTop = false;
                }
                messageCell.isChat = this.showSecretMessages;
                messageCell.setFullyDraw(true);
                messageCell.setMessageObject(message, null, pinnedBotton, pinnedTop);
                return;
            }
            if (view instanceof ChatActionCell) {
                ChatActionCell actionCell = (ChatActionCell) view;
                actionCell.setMessageObject(message);
                actionCell.setAlpha(1.0f);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i >= 0 && i < this.messages.size()) {
                return this.messages.get(i).contentType;
            }
            return 4;
        }
    }

    private List<ThemeDescription> getThemeDescriptionsInternal() {
        List<ThemeDescription> items = new ArrayList<>();
        items.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
        items.add(new ThemeDescription(this.viewPager, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        items.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        items.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
        items.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        items.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch));
        items.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder));
        items.add(new ThemeDescription(this.actionBar2, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        items.add(new ThemeDescription(this.actionBar2, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        items.add(new ThemeDescription(this.actionBar2, ThemeDescription.FLAG_AB_SUBTITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultSubtitle));
        items.add(new ThemeDescription(this.actionBar2, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
        items.add(new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        items.add(new ThemeDescription(this.listView2, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        items.add(new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionIcon));
        items.add(new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chats_actionBackground));
        items.add(new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_chats_actionPressedBackground));
        if (!this.useDefaultThemeForButtons) {
            items.add(new ThemeDescription(this.buttonsContainer, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
            items.add(new ThemeDescription(this.cancelButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText));
            items.add(new ThemeDescription(this.doneButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_chat_fieldOverlayText));
        }
        ColorPicker colorPicker = this.colorPicker;
        if (colorPicker != null) {
            colorPicker.provideThemeDescriptions(items);
        }
        return items;
    }
}
