package im.uwrkaxlmjj.ui.actionbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.Property;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.components.FireworksEffect;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.SnowflakesEffect;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ActionBar extends FrameLayout {
    public ActionBarMenuOnItemClick actionBarMenuOnItemClick;
    private ActionBarMenu actionMode;
    private AnimatorSet actionModeAnimation;
    private View actionModeExtraView;
    private View[] actionModeHidingViews;
    private View actionModeShowingView;
    private View actionModeTop;
    private View actionModeTranslationView;
    private boolean actionModeVisible;
    private boolean addToContainer;
    private boolean allowOverlayTitle;
    private ImageView backButtonImageView;
    private TextView backTitleTextView;
    private boolean castShadows;
    private boolean clipContent;
    private ActionBarDelegate delegate;
    private int extraHeight;
    private FireworksEffect fireworksEffect;
    private Paint.FontMetricsInt fontMetricsInt;
    private boolean ignoreLayoutRequest;
    private boolean interceptTouches;
    private boolean isBackOverlayVisible;
    protected boolean isSearchFieldVisible;
    protected int itemsActionModeBackgroundColor;
    protected int itemsActionModeColor;
    protected int itemsBackgroundColor;
    protected int itemsColor;
    private Runnable lastRunnable;
    private CharSequence lastTitle;
    private boolean manualStart;
    private ActionBarMenu menu;
    private boolean occupyStatusBar;
    protected BaseFragment parentFragment;
    private Rect rect;
    private SnowflakesEffect snowflakesEffect;
    private SimpleTextView subtitleTextView;
    private boolean supportsHolidayImage;
    private Runnable titleActionRunnable;
    private boolean titleOverlayShown;
    private int titleRightMargin;
    private SimpleTextView titleTextView;

    public interface ActionBarDelegate {
        void onSearchFieldVisibilityChanged(boolean z);
    }

    public static class ActionBarMenuOnItemClick {
        public void onItemClick(int id) {
        }

        public boolean canOpenMenu() {
            return true;
        }
    }

    public ActionBar(Context context) {
        super(context);
        this.occupyStatusBar = Build.VERSION.SDK_INT >= 21;
        this.addToContainer = true;
        this.interceptTouches = true;
        this.castShadows = true;
        setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBar$Ya6ah1aYzAz8Rm6FMKBuhot313I
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$0$ActionBar(view);
            }
        });
    }

    public /* synthetic */ void lambda$new$0$ActionBar(View v) {
        Runnable runnable;
        if (!isSearchFieldVisible() && (runnable = this.titleActionRunnable) != null) {
            runnable.run();
        }
    }

    private void createBackButtonImage() {
        if (this.backButtonImageView != null) {
            return;
        }
        ImageView imageView = new ImageView(getContext());
        this.backButtonImageView = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        this.backButtonImageView.setBackgroundDrawable(Theme.createSelectorDrawable(this.itemsBackgroundColor));
        if (this.itemsColor != 0) {
            this.backButtonImageView.setColorFilter(new PorterDuffColorFilter(this.itemsColor, PorterDuff.Mode.MULTIPLY));
        }
        this.backButtonImageView.setPadding(AndroidUtilities.dp(1.0f), 0, 0, 0);
        addView(this.backButtonImageView, LayoutHelper.createFrame(54, 54, 51));
        this.backButtonImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBar$qP8KDljGxoO0OKjhd7sy74ezfRE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createBackButtonImage$1$ActionBar(view);
            }
        });
        this.backButtonImageView.setContentDescription(LocaleController.getString("AccDescrGoBack", R.string.AccDescrGoBack));
    }

    public /* synthetic */ void lambda$createBackButtonImage$1$ActionBar(View v) {
        if (!this.actionModeVisible && this.isSearchFieldVisible) {
            closeSearchField();
            return;
        }
        ActionBarMenuOnItemClick actionBarMenuOnItemClick = this.actionBarMenuOnItemClick;
        if (actionBarMenuOnItemClick != null) {
            actionBarMenuOnItemClick.onItemClick(-1);
        }
    }

    public void setBackButtonDrawable(Drawable drawable) {
        if (this.backButtonImageView == null) {
            createBackButtonImage();
        }
        this.backButtonImageView.setVisibility(drawable == null ? 8 : 0);
        this.backButtonImageView.setImageDrawable(drawable);
        if (drawable instanceof BackDrawable) {
            BackDrawable backDrawable = (BackDrawable) drawable;
            backDrawable.setRotation(isActionModeShowed() ? 1.0f : 0.0f, false);
            backDrawable.setRotatedColor(this.itemsActionModeColor);
            backDrawable.setColor(this.itemsColor);
        }
    }

    public void setBackButtonContentDescription(CharSequence description) {
        ImageView imageView = this.backButtonImageView;
        if (imageView != null) {
            imageView.setContentDescription(description);
        }
    }

    public void setSupportsHolidayImage(boolean value) {
        this.supportsHolidayImage = value;
        if (value) {
            this.fontMetricsInt = new Paint.FontMetricsInt();
            this.rect = new Rect();
        }
        invalidate();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        Drawable drawable;
        if (this.supportsHolidayImage && !this.titleOverlayShown && !LocaleController.isRTL && ev.getAction() == 0 && (drawable = Theme.getCurrentHolidayDrawable()) != null && drawable.getBounds().contains((int) ev.getX(), (int) ev.getY())) {
            this.manualStart = true;
            if (this.snowflakesEffect == null) {
                this.fireworksEffect = null;
                this.snowflakesEffect = new SnowflakesEffect();
                this.titleTextView.invalidate();
                invalidate();
            } else if (BuildVars.DEBUG_PRIVATE_VERSION) {
                this.snowflakesEffect = null;
                this.fireworksEffect = new FireworksEffect();
                this.titleTextView.invalidate();
                invalidate();
            }
        }
        return super.onInterceptTouchEvent(ev);
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        Drawable drawable;
        boolean clip = this.clipContent && (child == this.titleTextView || child == this.subtitleTextView || child == this.actionMode || child == this.menu || child == this.backButtonImageView);
        if (clip) {
            canvas.save();
            canvas.clipRect(0.0f, (-getTranslationY()) + (this.occupyStatusBar ? AndroidUtilities.statusBarHeight : 0), getMeasuredWidth(), getMeasuredHeight());
        }
        boolean result = super.drawChild(canvas, child, drawingTime);
        if (this.supportsHolidayImage && !this.titleOverlayShown && !LocaleController.isRTL && child == this.titleTextView && (drawable = Theme.getCurrentHolidayDrawable()) != null) {
            TextPaint textPaint = this.titleTextView.getTextPaint();
            textPaint.getFontMetricsInt(this.fontMetricsInt);
            textPaint.getTextBounds((String) this.titleTextView.getText(), 0, 1, this.rect);
            int x = this.titleTextView.getTextStartX() + Theme.getCurrentHolidayDrawableXOffset() + ((this.rect.width() - (drawable.getIntrinsicWidth() + Theme.getCurrentHolidayDrawableXOffset())) / 2);
            int y = this.titleTextView.getTextStartY() + Theme.getCurrentHolidayDrawableYOffset() + ((int) Math.ceil((this.titleTextView.getTextHeight() - this.rect.height()) / 2.0f));
            drawable.setBounds(x, y - drawable.getIntrinsicHeight(), drawable.getIntrinsicWidth() + x, y);
            drawable.draw(canvas);
            if (Theme.canStartHolidayAnimation()) {
                if (this.snowflakesEffect == null) {
                    this.snowflakesEffect = new SnowflakesEffect();
                }
            } else if (!this.manualStart && this.snowflakesEffect != null) {
                this.snowflakesEffect = null;
            }
            SnowflakesEffect snowflakesEffect = this.snowflakesEffect;
            if (snowflakesEffect != null) {
                snowflakesEffect.onDraw(this, canvas);
            } else {
                FireworksEffect fireworksEffect = this.fireworksEffect;
                if (fireworksEffect != null) {
                    fireworksEffect.onDraw(this, canvas);
                }
            }
        }
        if (clip) {
            canvas.restore();
        }
        return result;
    }

    @Override // android.view.View
    public void setTranslationY(float translationY) {
        super.setTranslationY(translationY);
        if (this.clipContent) {
            invalidate();
        }
    }

    public void setBackButtonImage(int resource) {
        if (this.backButtonImageView == null) {
            createBackButtonImage();
        }
        this.backButtonImageView.setVisibility(resource == 0 ? 8 : 0);
        this.backButtonImageView.setImageResource(resource);
    }

    private void createSubtitleTextView() {
        if (this.subtitleTextView != null) {
            return;
        }
        SimpleTextView simpleTextView = new SimpleTextView(getContext());
        this.subtitleTextView = simpleTextView;
        simpleTextView.setGravity(3);
        this.subtitleTextView.setVisibility(8);
        this.subtitleTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubtitle));
        addView(this.subtitleTextView, 0, LayoutHelper.createFrame(-2, -2, 51));
    }

    public void setAddToContainer(boolean value) {
        this.addToContainer = value;
    }

    public boolean getAddToContainer() {
        return this.addToContainer;
    }

    public void setClipContent(boolean value) {
        this.clipContent = value;
    }

    public void setSubtitle(CharSequence value) {
        setSubtitle(value, false);
    }

    public void setSubtitle(CharSequence value, boolean refresh) {
        if (value != null && this.subtitleTextView == null) {
            createSubtitleTextView();
        }
        SimpleTextView simpleTextView = this.subtitleTextView;
        if (simpleTextView != null) {
            simpleTextView.setVisibility((TextUtils.isEmpty(value) || this.isSearchFieldVisible) ? 8 : 0);
            this.subtitleTextView.setText(value);
        }
        if (refresh) {
            this.subtitleTextView.postInvalidate();
            requestLayout();
        }
    }

    private void createBackTitleTextView() {
        if (this.backTitleTextView != null) {
            return;
        }
        TextView textView = new TextView(getContext());
        this.backTitleTextView = textView;
        textView.setGravity(16);
        this.backTitleTextView.setVisibility(8);
        this.backTitleTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubtitle));
        this.backTitleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.backTitleTextView.setBackground(Theme.createSelectorDrawable(this.itemsBackgroundColor));
        this.backTitleTextView.setPadding(AndroidUtilities.dp(8.0f), 0, AndroidUtilities.dp(8.0f), 0);
        addView(this.backTitleTextView, 0, LayoutHelper.createFrame(-2, -1, 8, this.occupyStatusBar ? AndroidUtilities.statusBarHeight : 0, 0, 0));
    }

    public void setBackTitle(CharSequence value) {
        if (value != null && this.backTitleTextView == null) {
            createBackTitleTextView();
        }
        TextView textView = this.backTitleTextView;
        if (textView != null) {
            textView.setVisibility((TextUtils.isEmpty(value) || this.isSearchFieldVisible) ? 8 : 0);
            this.backTitleTextView.setText(value);
        }
    }

    private void createTitleTextView() {
        if (this.titleTextView != null) {
            return;
        }
        SimpleTextView simpleTextView = new SimpleTextView(getContext());
        this.titleTextView = simpleTextView;
        simpleTextView.setGravity(3);
        this.titleTextView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        addView(this.titleTextView, 0, LayoutHelper.createFrame(-2, -2, 51));
    }

    public void setTitleRightMargin(int value) {
        this.titleRightMargin = value;
    }

    public void setTitle(CharSequence value) {
        if (value != null && this.titleTextView == null) {
            createTitleTextView();
        }
        SimpleTextView simpleTextView = this.titleTextView;
        if (simpleTextView != null) {
            this.lastTitle = value;
            simpleTextView.setVisibility((value == null || this.isSearchFieldVisible) ? 4 : 0);
            this.titleTextView.setText(value);
        }
    }

    public void setTitleColor(int color) {
        if (this.titleTextView == null) {
            createTitleTextView();
        }
        this.titleTextView.setTextColor(color);
    }

    public void setSubtitleColor(int color) {
        if (this.subtitleTextView == null) {
            createSubtitleTextView();
        }
        this.subtitleTextView.setTextColor(color);
    }

    public void setPopupItemsColor(int color, boolean icon) {
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu != null) {
            actionBarMenu.setPopupItemsColor(color, icon);
        }
    }

    public void setPopupBackgroundColor(int color) {
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu != null) {
            actionBarMenu.redrawPopup(color);
        }
    }

    public SimpleTextView getSubtitleTextView() {
        return this.subtitleTextView;
    }

    public SimpleTextView getTitleTextView() {
        return this.titleTextView;
    }

    public String getTitle() {
        SimpleTextView simpleTextView = this.titleTextView;
        if (simpleTextView == null) {
            return null;
        }
        return simpleTextView.getText().toString();
    }

    public String getSubtitle() {
        SimpleTextView simpleTextView = this.subtitleTextView;
        if (simpleTextView == null) {
            return null;
        }
        return simpleTextView.getText().toString();
    }

    public ActionBarMenu createMenu() {
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu != null) {
            return actionBarMenu;
        }
        ActionBarMenu actionBarMenu2 = new ActionBarMenu(getContext(), this);
        this.menu = actionBarMenu2;
        addView(actionBarMenu2, 0, LayoutHelper.createFrame(-2, -1, 5));
        return this.menu;
    }

    public void setActionBarMenuOnItemClick(ActionBarMenuOnItemClick listener) {
        this.actionBarMenuOnItemClick = listener;
    }

    public ActionBarMenuOnItemClick getActionBarMenuOnItemClick() {
        return this.actionBarMenuOnItemClick;
    }

    public View getBackButton() {
        return this.backButtonImageView;
    }

    public TextView getBackTitleTextView() {
        return this.backTitleTextView;
    }

    public ActionBarMenu createActionMode() {
        return createActionMode(true);
    }

    public ActionBarMenu createActionMode(boolean needTop) {
        ActionBarMenu actionBarMenu = this.actionMode;
        if (actionBarMenu != null) {
            return actionBarMenu;
        }
        ActionBarMenu actionBarMenu2 = new ActionBarMenu(getContext(), this);
        this.actionMode = actionBarMenu2;
        actionBarMenu2.isActionMode = true;
        this.actionMode.setBackgroundColor(Theme.getColor(Theme.key_actionBarActionModeDefault));
        addView(this.actionMode, indexOfChild(this.backButtonImageView));
        this.actionMode.setPadding(0, this.occupyStatusBar ? AndroidUtilities.statusBarHeight : 0, 0, 0);
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.actionMode.getLayoutParams();
        layoutParams.height = -1;
        layoutParams.width = -1;
        layoutParams.bottomMargin = this.extraHeight;
        layoutParams.gravity = 5;
        this.actionMode.setLayoutParams(layoutParams);
        this.actionMode.setVisibility(4);
        if (this.occupyStatusBar && needTop && this.actionModeTop == null) {
            View view = new View(getContext());
            this.actionModeTop = view;
            view.setBackgroundColor(Theme.getColor(Theme.key_actionBarActionModeDefaultTop));
            addView(this.actionModeTop);
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.actionModeTop.getLayoutParams();
            layoutParams2.height = AndroidUtilities.statusBarHeight;
            layoutParams2.width = -1;
            layoutParams2.gravity = 51;
            this.actionModeTop.setLayoutParams(layoutParams2);
            this.actionModeTop.setVisibility(4);
        }
        return this.actionMode;
    }

    public void showActionMode() {
        showActionMode(null, null, null, null, null, 0);
    }

    public void showActionMode(View extraView, View showingView, View[] hidingViews, final boolean[] hideView, View translationView, int translation) {
        View view;
        if (this.actionMode == null || this.actionModeVisible) {
            return;
        }
        this.actionModeVisible = true;
        ArrayList<Animator> animators = new ArrayList<>();
        animators.add(ObjectAnimator.ofFloat(this.actionMode, (Property<ActionBarMenu, Float>) View.ALPHA, 0.0f, 1.0f));
        if (hidingViews != null) {
            for (int a = 0; a < hidingViews.length; a++) {
                if (hidingViews[a] != null) {
                    animators.add(ObjectAnimator.ofFloat(hidingViews[a], (Property<View, Float>) View.ALPHA, 1.0f, 0.0f));
                }
            }
        }
        if (showingView != null) {
            animators.add(ObjectAnimator.ofFloat(showingView, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f));
        }
        if (translationView != null) {
            animators.add(ObjectAnimator.ofFloat(translationView, (Property<View, Float>) View.TRANSLATION_Y, translation));
            this.actionModeTranslationView = translationView;
        }
        this.actionModeExtraView = extraView;
        this.actionModeShowingView = showingView;
        this.actionModeHidingViews = hidingViews;
        if (this.occupyStatusBar && (view = this.actionModeTop) != null) {
            animators.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f));
        }
        AnimatorSet animatorSet = this.actionModeAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.actionModeAnimation = animatorSet2;
        animatorSet2.playTogether(animators);
        this.actionModeAnimation.setDuration(200L);
        this.actionModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBar.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                ActionBar.this.actionMode.setVisibility(0);
                if (ActionBar.this.occupyStatusBar && ActionBar.this.actionModeTop != null) {
                    ActionBar.this.actionModeTop.setVisibility(0);
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                boolean[] zArr;
                if (ActionBar.this.actionModeAnimation != null && ActionBar.this.actionModeAnimation.equals(animation)) {
                    ActionBar.this.actionModeAnimation = null;
                    if (ActionBar.this.titleTextView != null) {
                        ActionBar.this.titleTextView.setVisibility(4);
                    }
                    if (ActionBar.this.subtitleTextView != null && !TextUtils.isEmpty(ActionBar.this.subtitleTextView.getText())) {
                        ActionBar.this.subtitleTextView.setVisibility(4);
                    }
                    if (ActionBar.this.menu != null) {
                        ActionBar.this.menu.setVisibility(4);
                    }
                    if (ActionBar.this.actionModeHidingViews != null) {
                        for (int a2 = 0; a2 < ActionBar.this.actionModeHidingViews.length; a2++) {
                            if (ActionBar.this.actionModeHidingViews[a2] != null && ((zArr = hideView) == null || a2 >= zArr.length || zArr[a2])) {
                                ActionBar.this.actionModeHidingViews[a2].setVisibility(4);
                            }
                        }
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (ActionBar.this.actionModeAnimation != null && ActionBar.this.actionModeAnimation.equals(animation)) {
                    ActionBar.this.actionModeAnimation = null;
                }
            }
        });
        this.actionModeAnimation.start();
        ImageView imageView = this.backButtonImageView;
        if (imageView != null) {
            Drawable drawable = imageView.getDrawable();
            if (drawable instanceof BackDrawable) {
                ((BackDrawable) drawable).setRotation(1.0f, true);
            }
            this.backButtonImageView.setBackgroundDrawable(Theme.createSelectorDrawable(this.itemsActionModeBackgroundColor));
        }
    }

    public void hideActionMode() {
        View view;
        ActionBarMenu actionBarMenu = this.actionMode;
        if (actionBarMenu == null || !this.actionModeVisible) {
            return;
        }
        actionBarMenu.hideAllPopupMenus();
        this.actionModeVisible = false;
        ArrayList<Animator> animators = new ArrayList<>();
        animators.add(ObjectAnimator.ofFloat(this.actionMode, (Property<ActionBarMenu, Float>) View.ALPHA, 0.0f));
        if (this.actionModeHidingViews != null) {
            int a = 0;
            while (true) {
                View[] viewArr = this.actionModeHidingViews;
                if (a >= viewArr.length) {
                    break;
                }
                if (viewArr != null) {
                    viewArr[a].setVisibility(0);
                    animators.add(ObjectAnimator.ofFloat(this.actionModeHidingViews[a], (Property<View, Float>) View.ALPHA, 1.0f));
                }
                a++;
            }
        }
        View view2 = this.actionModeTranslationView;
        if (view2 != null) {
            animators.add(ObjectAnimator.ofFloat(view2, (Property<View, Float>) View.TRANSLATION_Y, 0.0f));
            this.actionModeTranslationView = null;
        }
        View view3 = this.actionModeShowingView;
        if (view3 != null) {
            animators.add(ObjectAnimator.ofFloat(view3, (Property<View, Float>) View.ALPHA, 0.0f));
        }
        if (this.occupyStatusBar && (view = this.actionModeTop) != null) {
            animators.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) View.ALPHA, 0.0f));
        }
        AnimatorSet animatorSet = this.actionModeAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.actionModeAnimation = animatorSet2;
        animatorSet2.playTogether(animators);
        this.actionModeAnimation.setDuration(200L);
        this.actionModeAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBar.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (ActionBar.this.actionModeAnimation != null && ActionBar.this.actionModeAnimation.equals(animation)) {
                    ActionBar.this.actionModeAnimation = null;
                    ActionBar.this.actionMode.setVisibility(4);
                    if (ActionBar.this.occupyStatusBar && ActionBar.this.actionModeTop != null) {
                        ActionBar.this.actionModeTop.setVisibility(4);
                    }
                    if (ActionBar.this.actionModeExtraView != null) {
                        ActionBar.this.actionModeExtraView.setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (ActionBar.this.actionModeAnimation != null && ActionBar.this.actionModeAnimation.equals(animation)) {
                    ActionBar.this.actionModeAnimation = null;
                }
            }
        });
        this.actionModeAnimation.start();
        if (!this.isSearchFieldVisible) {
            SimpleTextView simpleTextView = this.titleTextView;
            if (simpleTextView != null) {
                simpleTextView.setVisibility(0);
            }
            SimpleTextView simpleTextView2 = this.subtitleTextView;
            if (simpleTextView2 != null && !TextUtils.isEmpty(simpleTextView2.getText())) {
                this.subtitleTextView.setVisibility(0);
            }
        }
        ActionBarMenu actionBarMenu2 = this.menu;
        if (actionBarMenu2 != null) {
            actionBarMenu2.setVisibility(0);
        }
        ImageView imageView = this.backButtonImageView;
        if (imageView != null) {
            Drawable drawable = imageView.getDrawable();
            if (drawable instanceof BackDrawable) {
                ((BackDrawable) drawable).setRotation(0.0f, true);
            }
            this.backButtonImageView.setBackgroundDrawable(Theme.createSelectorDrawable(this.itemsBackgroundColor));
        }
    }

    public void showActionModeTop() {
        if (this.occupyStatusBar && this.actionModeTop == null) {
            View view = new View(getContext());
            this.actionModeTop = view;
            view.setBackgroundColor(Theme.getColor(Theme.key_actionBarActionModeDefaultTop));
            addView(this.actionModeTop);
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.actionModeTop.getLayoutParams();
            layoutParams.height = AndroidUtilities.statusBarHeight;
            layoutParams.width = -1;
            layoutParams.gravity = 51;
            this.actionModeTop.setLayoutParams(layoutParams);
        }
    }

    public void setActionModeTopColor(int color) {
        View view = this.actionModeTop;
        if (view != null) {
            view.setBackgroundColor(color);
        }
    }

    public void setSearchTextColor(int color, boolean placeholder) {
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu != null) {
            actionBarMenu.setSearchTextColor(color, placeholder);
        }
    }

    public void setActionModeColor(int color) {
        ActionBarMenu actionBarMenu = this.actionMode;
        if (actionBarMenu != null) {
            actionBarMenu.setBackgroundColor(color);
        }
    }

    public boolean isActionModeShowed() {
        return this.actionMode != null && this.actionModeVisible;
    }

    protected void onSearchFieldVisibilityChanged(boolean visible) {
        this.isSearchFieldVisible = visible;
        SimpleTextView simpleTextView = this.titleTextView;
        if (simpleTextView != null) {
            simpleTextView.setVisibility(visible ? 4 : 0);
        }
        SimpleTextView simpleTextView2 = this.subtitleTextView;
        if (simpleTextView2 != null && !TextUtils.isEmpty(simpleTextView2.getText())) {
            this.subtitleTextView.setVisibility(visible ? 4 : 0);
        }
        Drawable drawable = this.backButtonImageView.getDrawable();
        if (drawable instanceof MenuDrawable) {
            MenuDrawable menuDrawable = (MenuDrawable) drawable;
            menuDrawable.setRotateToBack(true);
            menuDrawable.setRotation(visible ? 1.0f : 0.0f, true);
        }
        ActionBarDelegate actionBarDelegate = this.delegate;
        if (actionBarDelegate != null) {
            actionBarDelegate.onSearchFieldVisibilityChanged(visible);
        }
    }

    public void setInterceptTouches(boolean value) {
        this.interceptTouches = value;
    }

    public void setExtraHeight(int value) {
        this.extraHeight = value;
        ActionBarMenu actionBarMenu = this.actionMode;
        if (actionBarMenu != null) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) actionBarMenu.getLayoutParams();
            layoutParams.bottomMargin = this.extraHeight;
            this.actionMode.setLayoutParams(layoutParams);
        }
    }

    public void closeSearchField() {
        closeSearchField(true);
    }

    public void closeSearchField(boolean closeKeyboard) {
        ActionBarMenu actionBarMenu;
        if (!this.isSearchFieldVisible || (actionBarMenu = this.menu) == null) {
            return;
        }
        actionBarMenu.closeSearchField(closeKeyboard);
    }

    public void openSearchField(String text, boolean animated) {
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu == null || text == null) {
            return;
        }
        actionBarMenu.openSearchField(!this.isSearchFieldVisible, text, animated);
    }

    public void setSearchFieldText(String text) {
        this.menu.setSearchFieldText(text);
    }

    public void onSearchPressed() {
        this.menu.onSearchPressed();
    }

    @Override // android.view.View
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        ImageView imageView = this.backButtonImageView;
        if (imageView != null) {
            imageView.setEnabled(enabled);
        }
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu != null) {
            actionBarMenu.setEnabled(enabled);
        }
        ActionBarMenu actionBarMenu2 = this.actionMode;
        if (actionBarMenu2 != null) {
            actionBarMenu2.setEnabled(enabled);
        }
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (this.ignoreLayoutRequest) {
            return;
        }
        super.requestLayout();
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int textLeft;
        SimpleTextView simpleTextView;
        SimpleTextView simpleTextView2;
        int menuWidth;
        int width = View.MeasureSpec.getSize(widthMeasureSpec);
        View.MeasureSpec.getSize(heightMeasureSpec);
        int actionBarHeight = getCurrentActionBarHeight();
        int actionBarHeightSpec = View.MeasureSpec.makeMeasureSpec(actionBarHeight, 1073741824);
        this.ignoreLayoutRequest = true;
        View view = this.actionModeTop;
        if (view != null) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) view.getLayoutParams();
            layoutParams.height = AndroidUtilities.statusBarHeight;
        }
        ActionBarMenu actionBarMenu = this.actionMode;
        if (actionBarMenu != null) {
            actionBarMenu.setPadding(0, this.occupyStatusBar ? AndroidUtilities.statusBarHeight : 0, 0, 0);
        }
        this.ignoreLayoutRequest = false;
        setMeasuredDimension(width, (this.occupyStatusBar ? AndroidUtilities.statusBarHeight : 0) + actionBarHeight + this.extraHeight);
        ImageView imageView = this.backButtonImageView;
        if (imageView != null && imageView.getVisibility() != 8) {
            this.backButtonImageView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(54.0f), 1073741824), actionBarHeightSpec);
            textLeft = AndroidUtilities.dp(AndroidUtilities.isTablet() ? 80.0f : 72.0f);
        } else {
            textLeft = AndroidUtilities.dp(AndroidUtilities.isTablet() ? 26.0f : 18.0f);
        }
        TextView textView = this.backTitleTextView;
        if (textView != null && textView.getVisibility() != 8) {
            this.backTitleTextView.setTextSize((AndroidUtilities.isTablet() || getResources().getConfiguration().orientation != 2) ? 14.0f : 12.0f);
            this.backTitleTextView.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(54.0f), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(getCurrentActionBarHeight(), 1073741824));
        }
        ActionBarMenu actionBarMenu2 = this.menu;
        if (actionBarMenu2 != null && actionBarMenu2.getVisibility() != 8) {
            if (this.isSearchFieldVisible) {
                menuWidth = View.MeasureSpec.makeMeasureSpec(width - AndroidUtilities.dp(AndroidUtilities.isTablet() ? 74.0f : 66.0f), 1073741824);
            } else {
                menuWidth = View.MeasureSpec.makeMeasureSpec(width, Integer.MIN_VALUE);
            }
            this.menu.measure(menuWidth, actionBarHeightSpec);
        }
        SimpleTextView simpleTextView3 = this.titleTextView;
        if ((simpleTextView3 != null && simpleTextView3.getVisibility() != 8) || ((simpleTextView = this.subtitleTextView) != null && simpleTextView.getVisibility() != 8)) {
            ActionBarMenu actionBarMenu3 = this.menu;
            int availableWidth = (((width - (actionBarMenu3 != null ? actionBarMenu3.getMeasuredWidth() : 0)) - AndroidUtilities.dp(16.0f)) - textLeft) - this.titleRightMargin;
            SimpleTextView simpleTextView4 = this.titleTextView;
            if (simpleTextView4 != null && simpleTextView4.getVisibility() != 8 && (simpleTextView2 = this.subtitleTextView) != null && simpleTextView2.getVisibility() != 8) {
                this.titleTextView.setTextSize(AndroidUtilities.isTablet() ? 16 : 14);
                this.subtitleTextView.setTextSize(AndroidUtilities.isTablet() ? 14 : 12);
            } else {
                SimpleTextView simpleTextView5 = this.titleTextView;
                if (simpleTextView5 != null && simpleTextView5.getVisibility() != 8) {
                    SimpleTextView simpleTextView6 = this.titleTextView;
                    if (!AndroidUtilities.isTablet() && getResources().getConfiguration().orientation == 2) {
                        i = 14;
                    }
                    simpleTextView6.setTextSize(i);
                }
                SimpleTextView simpleTextView7 = this.subtitleTextView;
                if (simpleTextView7 != null && simpleTextView7.getVisibility() != 8) {
                    this.subtitleTextView.setTextSize((AndroidUtilities.isTablet() || getResources().getConfiguration().orientation != 2) ? 14 : 12);
                }
            }
            SimpleTextView simpleTextView8 = this.titleTextView;
            if (simpleTextView8 != null && simpleTextView8.getVisibility() != 8) {
                this.titleTextView.measure(View.MeasureSpec.makeMeasureSpec(availableWidth, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(24.0f), Integer.MIN_VALUE));
            }
            SimpleTextView simpleTextView9 = this.subtitleTextView;
            if (simpleTextView9 != null && simpleTextView9.getVisibility() != 8) {
                this.subtitleTextView.measure(View.MeasureSpec.makeMeasureSpec(availableWidth, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(20.0f), Integer.MIN_VALUE));
            }
        }
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8 && child != this.titleTextView && child != this.subtitleTextView && child != this.menu) {
                if (child != this.backButtonImageView) {
                    measureChildWithMargins(child, widthMeasureSpec, 0, View.MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 1073741824), 0);
                }
            }
        }
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int childLeft;
        int childTop;
        int textTop;
        int menuLeft;
        ActionBar actionBar = this;
        int additionalTop = actionBar.occupyStatusBar ? AndroidUtilities.statusBarHeight : 0;
        ImageView imageView = actionBar.backButtonImageView;
        int i = 8;
        if (imageView != null && imageView.getVisibility() != 8) {
            ImageView imageView2 = actionBar.backButtonImageView;
            imageView2.layout(0, additionalTop, imageView2.getMeasuredWidth(), actionBar.backButtonImageView.getMeasuredHeight() + additionalTop);
            AndroidUtilities.dp(AndroidUtilities.isTablet() ? 80.0f : 72.0f);
        } else {
            AndroidUtilities.dp(AndroidUtilities.isTablet() ? 26.0f : 18.0f);
        }
        TextView textView = actionBar.backTitleTextView;
        if (textView != null && textView.getVisibility() != 8) {
            ImageView imageView3 = actionBar.backButtonImageView;
            if (imageView3 != null) {
                int backLeft = imageView3.getMeasuredWidth() - AndroidUtilities.dp(8.0f);
                TextView textView2 = actionBar.backTitleTextView;
                textView2.layout(left, additionalTop, textView2.getMeasuredWidth() + backLeft + AndroidUtilities.dp(10.0f), actionBar.backTitleTextView.getMeasuredHeight() + additionalTop);
            } else {
                actionBar.backTitleTextView.layout(AndroidUtilities.dp(12.0f), additionalTop, actionBar.backTitleTextView.getMeasuredWidth() + AndroidUtilities.dp(26.0f), getCurrentActionBarHeight() + additionalTop);
            }
            actionBar.backTitleTextView.setGravity(16);
        }
        ActionBarMenu actionBarMenu = actionBar.menu;
        if (actionBarMenu != null && actionBarMenu.getVisibility() != 8) {
            if (actionBar.isSearchFieldVisible) {
                menuLeft = AndroidUtilities.dp(AndroidUtilities.isTablet() ? 74.0f : 66.0f);
            } else {
                menuLeft = (right - left) - actionBar.menu.getMeasuredWidth();
            }
            ActionBarMenu actionBarMenu2 = actionBar.menu;
            actionBarMenu2.layout(menuLeft, additionalTop, actionBarMenu2.getMeasuredWidth() + menuLeft, actionBar.menu.getMeasuredHeight() + additionalTop);
        }
        SimpleTextView simpleTextView = actionBar.titleTextView;
        int i2 = 2;
        if (simpleTextView != null && simpleTextView.getVisibility() != 8) {
            SimpleTextView simpleTextView2 = actionBar.subtitleTextView;
            if (simpleTextView2 != null && simpleTextView2.getVisibility() != 8) {
                textTop = (((getCurrentActionBarHeight() / 2) - actionBar.titleTextView.getTextHeight()) / 2) + AndroidUtilities.dp((AndroidUtilities.isTablet() || getResources().getConfiguration().orientation != 2) ? 3.0f : 2.0f);
            } else {
                textTop = (getCurrentActionBarHeight() - actionBar.titleTextView.getTextHeight()) / 2;
            }
            int textLeft = (getMeasuredWidth() / 2) - (actionBar.titleTextView.getTextWidth() / 2);
            SimpleTextView simpleTextView3 = actionBar.titleTextView;
            simpleTextView3.layout(textLeft, additionalTop + textTop, simpleTextView3.getMeasuredWidth() + textLeft, additionalTop + textTop + actionBar.titleTextView.getTextHeight());
        }
        SimpleTextView simpleTextView4 = actionBar.subtitleTextView;
        if (simpleTextView4 != null && simpleTextView4.getVisibility() != 8) {
            int currentActionBarHeight = (getCurrentActionBarHeight() / 2) + (((getCurrentActionBarHeight() / 2) - actionBar.subtitleTextView.getTextHeight()) / 2);
            if (AndroidUtilities.isTablet() || getResources().getConfiguration().orientation == 2) {
            }
            int textTop2 = currentActionBarHeight - AndroidUtilities.dp(1.0f);
            int textLeft2 = (getMeasuredWidth() / 2) - (actionBar.subtitleTextView.getTextWidth() / 2);
            SimpleTextView simpleTextView5 = actionBar.subtitleTextView;
            simpleTextView5.layout(textLeft2, additionalTop + textTop2, simpleTextView5.getTextWidth() + textLeft2, additionalTop + textTop2 + actionBar.subtitleTextView.getTextHeight());
        }
        int childCount = getChildCount();
        int i3 = 0;
        while (i3 < childCount) {
            View child = actionBar.getChildAt(i3);
            if (child.getVisibility() != i && child != actionBar.titleTextView && child != actionBar.subtitleTextView && child != actionBar.menu && child != actionBar.backButtonImageView) {
                FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                int width = child.getMeasuredWidth();
                int height = child.getMeasuredHeight();
                int gravity = lp.gravity;
                if (gravity == -1) {
                    gravity = 51;
                }
                int absoluteGravity = gravity & 7;
                int verticalGravity = gravity & 112;
                int i4 = absoluteGravity & 7;
                if (i4 == 1) {
                    int childLeft2 = right - left;
                    childLeft = (((childLeft2 - width) / i2) + lp.leftMargin) - lp.rightMargin;
                } else if (i4 == 5) {
                    int childLeft3 = right - width;
                    childLeft = childLeft3 - lp.rightMargin;
                } else {
                    childLeft = lp.leftMargin;
                }
                if (verticalGravity == 16) {
                    childTop = ((((bottom - top) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                } else if (verticalGravity != 48 && verticalGravity == 80) {
                    int childTop2 = bottom - top;
                    childTop = (childTop2 - height) - lp.bottomMargin;
                } else {
                    childTop = lp.topMargin;
                }
                child.layout(childLeft, childTop, childLeft + width, childTop + height);
            }
            i3++;
            i2 = 2;
            i = 8;
            actionBar = this;
        }
    }

    public void onMenuButtonPressed() {
        ActionBarMenu actionBarMenu;
        if (!isActionModeShowed() && (actionBarMenu = this.menu) != null) {
            actionBarMenu.onMenuButtonPressed();
        }
    }

    protected void onPause() {
        ActionBarMenu actionBarMenu = this.menu;
        if (actionBarMenu != null) {
            actionBarMenu.hideAllPopupMenus();
        }
    }

    public void setAllowOverlayTitle(boolean value) {
        this.allowOverlayTitle = value;
    }

    public void setTitleActionRunnable(Runnable action) {
        this.titleActionRunnable = action;
        this.lastRunnable = action;
    }

    public void setTitleOverlayText(String title, int titleId, Runnable action) {
        if (!this.allowOverlayTitle || this.parentFragment.parentLayout == null) {
            return;
        }
        CharSequence textToSet = title != null ? LocaleController.getString(title, titleId) : this.lastTitle;
        if (textToSet != null && this.titleTextView == null) {
            createTitleTextView();
        }
        if (this.titleTextView != null) {
            this.titleOverlayShown = title != null;
            if (this.supportsHolidayImage) {
                this.titleTextView.invalidate();
                invalidate();
            }
            this.titleTextView.setVisibility((textToSet == null || this.isSearchFieldVisible) ? 4 : 0);
            this.titleTextView.setText(textToSet);
        }
        this.titleActionRunnable = action != null ? action : this.lastRunnable;
    }

    public void setTitleOverlayText2(String title, int titleId, Runnable action) {
        if (!this.allowOverlayTitle) {
            return;
        }
        CharSequence textToSet = title != null ? LocaleController.getString(title, titleId) : this.lastTitle;
        if (textToSet != null && this.titleTextView == null) {
            createTitleTextView();
        }
        if (this.titleTextView != null) {
            this.titleOverlayShown = title != null;
            requestLayout();
            this.titleTextView.setVisibility((textToSet == null || this.isSearchFieldVisible) ? 4 : 0);
            this.titleTextView.setText(textToSet);
        }
        this.titleActionRunnable = action != null ? action : this.lastRunnable;
    }

    public boolean isSearchFieldVisible() {
        return this.isSearchFieldVisible;
    }

    public void setOccupyStatusBar(boolean value) {
        this.occupyStatusBar = value;
        ActionBarMenu actionBarMenu = this.actionMode;
        if (actionBarMenu != null) {
            actionBarMenu.setPadding(0, value ? AndroidUtilities.statusBarHeight : 0, 0, 0);
        }
    }

    public boolean getOccupyStatusBar() {
        return this.occupyStatusBar;
    }

    public void setItemsBackgroundColor(int color, boolean isActionMode) {
        ImageView imageView;
        if (isActionMode) {
            this.itemsActionModeBackgroundColor = color;
            if (this.actionModeVisible && (imageView = this.backButtonImageView) != null) {
                imageView.setBackgroundDrawable(Theme.createSelectorDrawable(color));
            }
            ActionBarMenu actionBarMenu = this.actionMode;
            if (actionBarMenu != null) {
                actionBarMenu.updateItemsBackgroundColor();
                return;
            }
            return;
        }
        this.itemsBackgroundColor = color;
        ImageView imageView2 = this.backButtonImageView;
        if (imageView2 != null) {
            imageView2.setBackgroundDrawable(Theme.createSelectorDrawable(color));
        }
        ActionBarMenu actionBarMenu2 = this.menu;
        if (actionBarMenu2 != null) {
            actionBarMenu2.updateItemsBackgroundColor();
        }
    }

    public void setItemsColor(int color, boolean isActionMode) {
        if (isActionMode) {
            this.itemsActionModeColor = color;
            ActionBarMenu actionBarMenu = this.actionMode;
            if (actionBarMenu != null) {
                actionBarMenu.updateItemsColor();
            }
            ImageView imageView = this.backButtonImageView;
            if (imageView != null) {
                Drawable drawable = imageView.getDrawable();
                if (drawable instanceof BackDrawable) {
                    ((BackDrawable) drawable).setRotatedColor(color);
                    return;
                }
                return;
            }
            return;
        }
        this.itemsColor = color;
        ImageView imageView2 = this.backButtonImageView;
        if (imageView2 != null && color != 0) {
            imageView2.setColorFilter(new PorterDuffColorFilter(this.itemsColor, PorterDuff.Mode.MULTIPLY));
            Drawable drawable2 = this.backButtonImageView.getDrawable();
            if (drawable2 instanceof BackDrawable) {
                ((BackDrawable) drawable2).setColor(color);
            }
        }
        ActionBarMenu actionBarMenu2 = this.menu;
        if (actionBarMenu2 != null) {
            actionBarMenu2.updateItemsColor();
        }
    }

    public void hideContent() {
    }

    public void setCastShadows(boolean value) {
        this.castShadows = value;
    }

    public boolean getCastShadows() {
        return this.castShadows;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        return super.onTouchEvent(event) || this.interceptTouches;
    }

    public static int getCurrentActionBarHeight() {
        if (AndroidUtilities.isTablet()) {
            return AndroidUtilities.dp(56.0f);
        }
        if (AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y) {
            return AndroidUtilities.dp(42.0f);
        }
        return AndroidUtilities.dp(42.0f);
    }

    @Override // android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    public void setDelegate(ActionBarDelegate delegate) {
        this.delegate = delegate;
    }
}
