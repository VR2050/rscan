package im.uwrkaxlmjj.ui.actionbar;

import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.DecelerateInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.components.CloseProgressDrawable2;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ActionBarMenuItem extends FrameLayout {
    private int additionalXOffset;
    private int additionalYOffset;
    private boolean allowCloseAnimation;
    private boolean animateClear;
    private boolean animationEnabled;
    private ImageView clearButton;
    private ActionBarMenuItemDelegate delegate;
    protected ImageView iconView;
    private boolean ignoreOnTextChange;
    private boolean isSearchField;
    private boolean layoutInScreen;
    private ActionBarMenuItemSearchListener listener;
    private int[] location;
    private boolean longClickEnabled;
    protected boolean overrideMenuClick;
    private ActionBarMenu parentMenu;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout popupLayout;
    private ActionBarPopupWindow popupWindow;
    private boolean processedPopupClick;
    private CloseProgressDrawable2 progressDrawable;
    private Rect rect;
    private FrameLayout searchContainer;
    private EditTextBoldCursor searchField;
    private TextView searchFieldCaption;
    private View selectedMenuView;
    private Runnable showMenuRunnable;
    private int subMenuOpenSide;
    protected TextView textView;
    private int yOffset;

    public interface ActionBarMenuItemDelegate {
        void onItemClick(int i);
    }

    public static class ActionBarMenuItemSearchListener {
        public void onSearchExpand() {
        }

        public boolean canCollapseSearch() {
            return true;
        }

        public void onSearchCollapse() {
        }

        public void onTextChanged(EditText editText) {
        }

        public void onSearchPressed(EditText editText) {
        }

        public void onCaptionCleared() {
        }

        public boolean forceShowClear() {
            return false;
        }
    }

    public ActionBarMenuItem(Context context, ActionBarMenu menu, int backgroundColor, int iconColor) {
        this(context, menu, backgroundColor, iconColor, false);
    }

    public ActionBarMenuItem(Context context, ActionBarMenu menu, int backgroundColor, int iconColor, boolean text) {
        super(context);
        this.allowCloseAnimation = true;
        this.animationEnabled = true;
        this.longClickEnabled = true;
        this.animateClear = true;
        if (backgroundColor != 0) {
            setBackgroundDrawable(Theme.createSelectorDrawable(backgroundColor, text ? 5 : 1));
        }
        this.parentMenu = menu;
        if (text) {
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextSize(1, 14.0f);
            this.textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.textView.setGravity(17);
            this.textView.setPadding(AndroidUtilities.dp(4.0f), 0, AndroidUtilities.dp(4.0f), 0);
            if (iconColor != 0) {
                this.textView.setTextColor(iconColor);
            }
            addView(this.textView, LayoutHelper.createFrame(-2, -1.0f));
            return;
        }
        ImageView imageView = new ImageView(context);
        this.iconView = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        addView(this.iconView, LayoutHelper.createFrame(-1, -1.0f));
        if (iconColor != 0) {
            this.iconView.setColorFilter(new PorterDuffColorFilter(iconColor, PorterDuff.Mode.MULTIPLY));
        }
    }

    public void setLongClickEnabled(boolean value) {
        this.longClickEnabled = value;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        ActionBarPopupWindow actionBarPopupWindow;
        ActionBarPopupWindow actionBarPopupWindow2;
        if (event.getActionMasked() == 0) {
            if (this.longClickEnabled && hasSubMenu() && ((actionBarPopupWindow2 = this.popupWindow) == null || (actionBarPopupWindow2 != null && !actionBarPopupWindow2.isShowing()))) {
                Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$E2sqvN4uVW32TIN77PwVq_X3GGc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onTouchEvent$0$ActionBarMenuItem();
                    }
                };
                this.showMenuRunnable = runnable;
                AndroidUtilities.runOnUIThread(runnable, 200L);
            }
        } else if (event.getActionMasked() == 2) {
            if (!hasSubMenu() || ((actionBarPopupWindow = this.popupWindow) != null && (actionBarPopupWindow == null || actionBarPopupWindow.isShowing()))) {
                ActionBarPopupWindow actionBarPopupWindow3 = this.popupWindow;
                if (actionBarPopupWindow3 != null && actionBarPopupWindow3.isShowing()) {
                    getLocationOnScreen(this.location);
                    float x = event.getX() + this.location[0];
                    float y = event.getY();
                    float y2 = y + r5[1];
                    this.popupLayout.getLocationOnScreen(this.location);
                    int[] iArr = this.location;
                    float x2 = x - iArr[0];
                    float y3 = y2 - iArr[1];
                    this.selectedMenuView = null;
                    for (int a = 0; a < this.popupLayout.getItemsCount(); a++) {
                        View child = this.popupLayout.getItemAt(a);
                        child.getHitRect(this.rect);
                        if (((Integer) child.getTag()).intValue() < 100) {
                            if (!this.rect.contains((int) x2, (int) y3)) {
                                child.setPressed(false);
                                child.setSelected(false);
                                if (Build.VERSION.SDK_INT == 21) {
                                    child.getBackground().setVisible(false, false);
                                }
                            } else {
                                child.setPressed(true);
                                child.setSelected(true);
                                if (Build.VERSION.SDK_INT >= 21) {
                                    if (Build.VERSION.SDK_INT == 21) {
                                        child.getBackground().setVisible(true, false);
                                    }
                                    child.drawableHotspotChanged(x2, y3 - child.getTop());
                                }
                                this.selectedMenuView = child;
                            }
                        }
                    }
                }
            } else if (event.getY() > getHeight()) {
                if (getParent() != null) {
                    getParent().requestDisallowInterceptTouchEvent(true);
                }
                toggleSubMenu();
                return true;
            }
        } else {
            ActionBarPopupWindow actionBarPopupWindow4 = this.popupWindow;
            if (actionBarPopupWindow4 != null && actionBarPopupWindow4.isShowing() && event.getActionMasked() == 1) {
                View view = this.selectedMenuView;
                if (view != null) {
                    view.setSelected(false);
                    ActionBarMenu actionBarMenu = this.parentMenu;
                    if (actionBarMenu != null) {
                        actionBarMenu.onItemClick(((Integer) this.selectedMenuView.getTag()).intValue());
                    } else {
                        ActionBarMenuItemDelegate actionBarMenuItemDelegate = this.delegate;
                        if (actionBarMenuItemDelegate != null) {
                            actionBarMenuItemDelegate.onItemClick(((Integer) this.selectedMenuView.getTag()).intValue());
                        }
                    }
                    this.popupWindow.dismiss(this.allowCloseAnimation);
                } else {
                    this.popupWindow.dismiss();
                }
            } else {
                View view2 = this.selectedMenuView;
                if (view2 != null) {
                    view2.setSelected(false);
                    this.selectedMenuView = null;
                }
            }
        }
        return super.onTouchEvent(event);
    }

    public /* synthetic */ void lambda$onTouchEvent$0$ActionBarMenuItem() {
        if (getParent() != null) {
            getParent().requestDisallowInterceptTouchEvent(true);
        }
        toggleSubMenu();
    }

    public void setDelegate(ActionBarMenuItemDelegate delegate) {
        this.delegate = delegate;
    }

    public void setIconColor(int color) {
        ImageView imageView = this.iconView;
        if (imageView != null) {
            imageView.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
        }
        TextView textView = this.textView;
        if (textView != null) {
            textView.setTextColor(color);
        }
        ImageView imageView2 = this.clearButton;
        if (imageView2 != null) {
            imageView2.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
        }
    }

    public void setSubMenuOpenSide(int side) {
        this.subMenuOpenSide = side;
    }

    public void setLayoutInScreen(boolean value) {
        this.layoutInScreen = value;
    }

    private void createPopupLayout() {
        if (this.popupLayout != null) {
            return;
        }
        this.rect = new Rect();
        this.location = new int[2];
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = new ActionBarPopupWindow.ActionBarPopupWindowLayout(getContext());
        this.popupLayout = actionBarPopupWindowLayout;
        actionBarPopupWindowLayout.setPadding(0, 0, 0, 0);
        this.popupLayout.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$d_Zo3APCiiZ9y0en2_l4hdyUZjk
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return this.f$0.lambda$createPopupLayout$1$ActionBarMenuItem(view, motionEvent);
            }
        });
        this.popupLayout.setDispatchKeyEventListener(new ActionBarPopupWindow.OnDispatchKeyEventListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$4NHO1UBDcVwGlgXw5kkfQQYuHAA
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow.OnDispatchKeyEventListener
            public final void onDispatchKeyEvent(KeyEvent keyEvent) {
                this.f$0.lambda$createPopupLayout$2$ActionBarMenuItem(keyEvent);
            }
        });
    }

    public /* synthetic */ boolean lambda$createPopupLayout$1$ActionBarMenuItem(View v, MotionEvent event) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (event.getActionMasked() == 0 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            v.getHitRect(this.rect);
            if (!this.rect.contains((int) event.getX(), (int) event.getY())) {
                this.popupWindow.dismiss();
                return false;
            }
            return false;
        }
        return false;
    }

    public /* synthetic */ void lambda$createPopupLayout$2$ActionBarMenuItem(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
        }
    }

    public void removeAllSubItems() {
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.popupLayout;
        if (actionBarPopupWindowLayout == null) {
            return;
        }
        actionBarPopupWindowLayout.removeInnerViews();
    }

    public void addSubItem(View view, int width, int height) {
        createPopupLayout();
        this.popupLayout.addView(view, new LinearLayout.LayoutParams(width, height));
    }

    public void addSubItem(int id, View view, int width, int height) {
        createPopupLayout();
        view.setLayoutParams(new LinearLayout.LayoutParams(width, height));
        this.popupLayout.addView(view);
        view.setTag(Integer.valueOf(id));
        view.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$bjDHuQ3mLnGv8aT3LScBIoN9GKo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$addSubItem$3$ActionBarMenuItem(view2);
            }
        });
        view.setBackgroundDrawable(Theme.getSelectorDrawable(false));
    }

    public /* synthetic */ void lambda$addSubItem$3$ActionBarMenuItem(View view1) {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            if (this.processedPopupClick) {
                return;
            }
            this.processedPopupClick = true;
            this.popupWindow.dismiss(this.allowCloseAnimation);
        }
        ActionBarMenu actionBarMenu = this.parentMenu;
        if (actionBarMenu != null) {
            actionBarMenu.onItemClick(((Integer) view1.getTag()).intValue());
            return;
        }
        ActionBarMenuItemDelegate actionBarMenuItemDelegate = this.delegate;
        if (actionBarMenuItemDelegate != null) {
            actionBarMenuItemDelegate.onItemClick(((Integer) view1.getTag()).intValue());
        }
    }

    public TextView addSubItem(int id, CharSequence text) {
        createPopupLayout();
        TextView textView = new TextView(getContext());
        textView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItem));
        textView.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        if (!LocaleController.isRTL) {
            textView.setGravity(16);
        } else {
            textView.setGravity(21);
        }
        textView.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
        textView.setTextSize(1, 15.0f);
        textView.setSingleLine(true);
        textView.setEllipsize(TextUtils.TruncateAt.END);
        textView.setTag(Integer.valueOf(id));
        textView.setText(text);
        this.popupLayout.addView(textView);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) textView.getLayoutParams();
        if (LocaleController.isRTL) {
            layoutParams.gravity = 5;
        }
        layoutParams.width = -1;
        layoutParams.height = AndroidUtilities.dp(48.0f);
        textView.setLayoutParams(layoutParams);
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$rSxTCEnPVAreMMjb64nNA8sQAIk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addSubItem$4$ActionBarMenuItem(view);
            }
        });
        return textView;
    }

    public /* synthetic */ void lambda$addSubItem$4$ActionBarMenuItem(View view) {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            if (this.processedPopupClick) {
                return;
            }
            this.processedPopupClick = true;
            this.popupWindow.dismiss(this.allowCloseAnimation);
        }
        ActionBarMenu actionBarMenu = this.parentMenu;
        if (actionBarMenu != null) {
            actionBarMenu.onItemClick(((Integer) view.getTag()).intValue());
            return;
        }
        ActionBarMenuItemDelegate actionBarMenuItemDelegate = this.delegate;
        if (actionBarMenuItemDelegate != null) {
            actionBarMenuItemDelegate.onItemClick(((Integer) view.getTag()).intValue());
        }
    }

    public ActionBarMenuSubItem addSubItem(int id, int icon, CharSequence text) {
        createPopupLayout();
        ActionBarMenuSubItem cell = new ActionBarMenuSubItem(getContext());
        cell.setTextAndIcon(text, icon);
        cell.setTag(Integer.valueOf(id));
        this.popupLayout.addView(cell);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) cell.getLayoutParams();
        if (LocaleController.isRTL) {
            layoutParams.gravity = 5;
        }
        layoutParams.width = -1;
        layoutParams.height = AndroidUtilities.dp(48.0f);
        cell.setLayoutParams(layoutParams);
        cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$sfQ0rdhnzKrO0pmG9JIk-WKua1Y
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addSubItem$5$ActionBarMenuItem(view);
            }
        });
        return cell;
    }

    public /* synthetic */ void lambda$addSubItem$5$ActionBarMenuItem(View view) {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            if (this.processedPopupClick) {
                return;
            }
            this.processedPopupClick = true;
            this.popupWindow.dismiss(this.allowCloseAnimation);
        }
        ActionBarMenu actionBarMenu = this.parentMenu;
        if (actionBarMenu != null) {
            actionBarMenu.onItemClick(((Integer) view.getTag()).intValue());
            return;
        }
        ActionBarMenuItemDelegate actionBarMenuItemDelegate = this.delegate;
        if (actionBarMenuItemDelegate != null) {
            actionBarMenuItemDelegate.onItemClick(((Integer) view.getTag()).intValue());
        }
    }

    public void redrawPopup(int color) {
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.popupLayout;
        if (actionBarPopupWindowLayout != null) {
            actionBarPopupWindowLayout.backgroundDrawable.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
            this.popupLayout.invalidate();
        }
    }

    public void setPopupItemsColor(int color, boolean icon) {
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.popupLayout;
        if (actionBarPopupWindowLayout == null) {
            return;
        }
        int count = actionBarPopupWindowLayout.linearLayout.getChildCount();
        for (int a = 0; a < count; a++) {
            View child = this.popupLayout.linearLayout.getChildAt(a);
            if (child instanceof TextView) {
                ((TextView) child).setTextColor(color);
            } else if (child instanceof ActionBarMenuSubItem) {
                if (icon) {
                    ((ActionBarMenuSubItem) child).setIconColor(color);
                } else {
                    ((ActionBarMenuSubItem) child).setTextColor(color);
                }
            }
        }
    }

    public boolean hasSubMenu() {
        return this.popupLayout != null;
    }

    public void setMenuYOffset(int offset) {
        this.yOffset = offset;
    }

    public void toggleSubMenu() {
        if (this.popupLayout != null) {
            ActionBarMenu actionBarMenu = this.parentMenu;
            if (actionBarMenu != null && actionBarMenu.isActionMode && this.parentMenu.parentActionBar != null && !this.parentMenu.parentActionBar.isActionModeShowed()) {
                return;
            }
            Runnable runnable = this.showMenuRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.showMenuRunnable = null;
            }
            ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
            if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
                this.popupWindow.dismiss();
                return;
            }
            if (this.popupWindow == null) {
                this.popupWindow = new ActionBarPopupWindow(this.popupLayout, -2, -2);
                if (this.animationEnabled && Build.VERSION.SDK_INT >= 19) {
                    this.popupWindow.setAnimationStyle(0);
                } else {
                    this.popupWindow.setAnimationStyle(R.plurals.PopupAnimation);
                }
                boolean z = this.animationEnabled;
                if (!z) {
                    this.popupWindow.setAnimationEnabled(z);
                }
                this.popupWindow.setOutsideTouchable(true);
                this.popupWindow.setClippingEnabled(true);
                if (this.layoutInScreen) {
                    this.popupWindow.setLayoutInScreen(true);
                }
                this.popupWindow.setInputMethodMode(2);
                this.popupWindow.setSoftInputMode(0);
                this.popupLayout.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(1000.0f), Integer.MIN_VALUE));
                this.popupWindow.getContentView().setFocusableInTouchMode(true);
                this.popupWindow.getContentView().setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$Q2x7ws44N_0aYSIG7Vbv2sPH7kk
                    @Override // android.view.View.OnKeyListener
                    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
                        return this.f$0.lambda$toggleSubMenu$6$ActionBarMenuItem(view, i, keyEvent);
                    }
                });
            }
            this.processedPopupClick = false;
            this.popupWindow.setFocusable(true);
            if (this.popupLayout.getMeasuredWidth() == 0) {
                updateOrShowPopup(true, true);
            } else {
                updateOrShowPopup(true, false);
            }
            this.popupWindow.startAnimation();
        }
    }

    public /* synthetic */ boolean lambda$toggleSubMenu$6$ActionBarMenuItem(View v, int keyCode, KeyEvent event) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyCode == 82 && event.getRepeatCount() == 0 && event.getAction() == 1 && (actionBarPopupWindow = this.popupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
            return true;
        }
        return false;
    }

    public void openSearch(boolean openKeyboard) {
        ActionBarMenu actionBarMenu;
        FrameLayout frameLayout = this.searchContainer;
        if (frameLayout == null || frameLayout.getVisibility() == 0 || (actionBarMenu = this.parentMenu) == null) {
            return;
        }
        actionBarMenu.parentActionBar.onSearchFieldVisibilityChanged(toggleSearch(openKeyboard));
    }

    public boolean toggleSearch(boolean openKeyboard) {
        FrameLayout frameLayout = this.searchContainer;
        if (frameLayout == null) {
            return false;
        }
        if (frameLayout.getVisibility() == 0) {
            ActionBarMenuItemSearchListener actionBarMenuItemSearchListener = this.listener;
            if (actionBarMenuItemSearchListener == null || (actionBarMenuItemSearchListener != null && actionBarMenuItemSearchListener.canCollapseSearch())) {
                if (openKeyboard) {
                    AndroidUtilities.hideKeyboard(this.searchField);
                }
                this.searchField.setText("");
                this.searchContainer.setVisibility(8);
                this.searchField.clearFocus();
                setVisibility(0);
                ActionBarMenuItemSearchListener actionBarMenuItemSearchListener2 = this.listener;
                if (actionBarMenuItemSearchListener2 != null) {
                    actionBarMenuItemSearchListener2.onSearchCollapse();
                }
            }
            return false;
        }
        this.searchContainer.setVisibility(0);
        setVisibility(8);
        this.searchField.setText("");
        this.searchField.requestFocus();
        if (openKeyboard) {
            AndroidUtilities.showKeyboard(this.searchField);
        }
        ActionBarMenuItemSearchListener actionBarMenuItemSearchListener3 = this.listener;
        if (actionBarMenuItemSearchListener3 != null) {
            actionBarMenuItemSearchListener3.onSearchExpand();
            return true;
        }
        return true;
    }

    public void closeSubMenu() {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.popupWindow.dismiss();
        }
    }

    public void setIcon(Drawable drawable) {
        ImageView imageView = this.iconView;
        if (imageView == null) {
            return;
        }
        imageView.setImageDrawable(drawable);
    }

    public void setIcon(int resId) {
        ImageView imageView = this.iconView;
        if (imageView == null) {
            return;
        }
        imageView.setImageResource(resId);
    }

    public void setText(CharSequence text) {
        TextView textView = this.textView;
        if (textView == null) {
            return;
        }
        textView.setText(text);
    }

    public View getContentView() {
        ImageView imageView = this.iconView;
        return imageView != null ? imageView : this.textView;
    }

    public void setSearchFieldHint(CharSequence hint) {
        if (this.searchFieldCaption == null) {
            return;
        }
        this.searchField.setHint(hint);
        setContentDescription(hint);
    }

    public void setSearchFieldText(CharSequence text, boolean animated) {
        if (this.searchFieldCaption == null) {
            return;
        }
        this.animateClear = animated;
        this.searchField.setText(text);
        if (!TextUtils.isEmpty(text)) {
            this.searchField.setSelection(text.length());
        }
    }

    public void onSearchPressed() {
        ActionBarMenuItemSearchListener actionBarMenuItemSearchListener = this.listener;
        if (actionBarMenuItemSearchListener != null) {
            actionBarMenuItemSearchListener.onSearchPressed(this.searchField);
        }
    }

    public EditTextBoldCursor getSearchField() {
        return this.searchField;
    }

    public ActionBarMenuItem setOverrideMenuClick(boolean value) {
        this.overrideMenuClick = value;
        return this;
    }

    public ActionBarMenuItem setIsSearchField(boolean value) {
        if (this.parentMenu == null) {
            return this;
        }
        if (value && this.searchContainer == null) {
            FrameLayout frameLayout = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.1
                @Override // android.widget.FrameLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    int width;
                    measureChildWithMargins(ActionBarMenuItem.this.clearButton, widthMeasureSpec, 0, heightMeasureSpec, 0);
                    if (ActionBarMenuItem.this.searchFieldCaption.getVisibility() == 0) {
                        measureChildWithMargins(ActionBarMenuItem.this.searchFieldCaption, widthMeasureSpec, View.MeasureSpec.getSize(widthMeasureSpec) / 2, heightMeasureSpec, 0);
                        width = ActionBarMenuItem.this.searchFieldCaption.getMeasuredWidth() + AndroidUtilities.dp(4.0f);
                    } else {
                        width = 0;
                    }
                    measureChildWithMargins(ActionBarMenuItem.this.searchField, widthMeasureSpec, width, heightMeasureSpec, 0);
                    View.MeasureSpec.getSize(widthMeasureSpec);
                    View.MeasureSpec.getSize(heightMeasureSpec);
                    setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), View.MeasureSpec.getSize(heightMeasureSpec));
                }

                @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
                protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                    int x;
                    super.onLayout(changed, left, top, right, bottom);
                    if (!LocaleController.isRTL && ActionBarMenuItem.this.searchFieldCaption.getVisibility() == 0) {
                        x = ActionBarMenuItem.this.searchFieldCaption.getMeasuredWidth() + AndroidUtilities.dp(4.0f);
                    } else {
                        x = 0;
                    }
                    ActionBarMenuItem.this.searchField.layout(x, ActionBarMenuItem.this.searchField.getTop(), ActionBarMenuItem.this.searchField.getMeasuredWidth() + x, ActionBarMenuItem.this.searchField.getBottom());
                }
            };
            this.searchContainer = frameLayout;
            this.parentMenu.addView(frameLayout, 0, LayoutHelper.createLinear(0, -1, 1.0f, 6, 0, 0, 0));
            this.searchContainer.setVisibility(8);
            TextView textView = new TextView(getContext());
            this.searchFieldCaption = textView;
            textView.setTextSize(1, 18.0f);
            this.searchFieldCaption.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSearch));
            this.searchFieldCaption.setSingleLine(true);
            this.searchFieldCaption.setEllipsize(TextUtils.TruncateAt.END);
            this.searchFieldCaption.setVisibility(8);
            this.searchFieldCaption.setGravity(LocaleController.isRTL ? 5 : 3);
            EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.2
                @Override // android.widget.TextView, android.view.View, android.view.KeyEvent.Callback
                public boolean onKeyDown(int keyCode, KeyEvent event) {
                    if (keyCode == 67 && ActionBarMenuItem.this.searchField.length() == 0 && ActionBarMenuItem.this.searchFieldCaption.getVisibility() == 0 && ActionBarMenuItem.this.searchFieldCaption.length() > 0) {
                        ActionBarMenuItem.this.clearButton.callOnClick();
                        return true;
                    }
                    return super.onKeyDown(keyCode, event);
                }

                @Override // android.widget.TextView, android.view.View
                public boolean onTouchEvent(MotionEvent event) {
                    if (event.getAction() == 0 && !AndroidUtilities.showKeyboard(this)) {
                        clearFocus();
                        requestFocus();
                    }
                    return super.onTouchEvent(event);
                }
            };
            this.searchField = editTextBoldCursor;
            editTextBoldCursor.setCursorWidth(1.5f);
            this.searchField.setCursorColor(Theme.getColor(Theme.key_actionBarDefaultSearch));
            this.searchField.setTextSize(1, 18.0f);
            this.searchField.setHintTextColor(Theme.getColor(Theme.key_actionBarDefaultSearchPlaceholder));
            this.searchField.setTextColor(Theme.getColor(Theme.key_actionBarDefaultSearch));
            this.searchField.setSingleLine(true);
            this.searchField.setBackgroundResource(0);
            this.searchField.setPadding(0, 0, 0, 0);
            int inputType = this.searchField.getInputType() | 524288;
            this.searchField.setInputType(inputType);
            if (Build.VERSION.SDK_INT < 23) {
                this.searchField.setCustomSelectionActionModeCallback(new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.3
                    @Override // android.view.ActionMode.Callback
                    public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                        return false;
                    }

                    @Override // android.view.ActionMode.Callback
                    public void onDestroyActionMode(ActionMode mode) {
                    }

                    @Override // android.view.ActionMode.Callback
                    public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                        return false;
                    }

                    @Override // android.view.ActionMode.Callback
                    public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                        return false;
                    }
                });
            }
            this.searchField.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$L454uyB0SeaIEkRpzsMCtorH2w8
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView2, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$setIsSearchField$7$ActionBarMenuItem(textView2, i, keyEvent);
                }
            });
            this.searchField.addTextChangedListener(new AnonymousClass4());
            this.searchField.setImeOptions(33554435);
            this.searchField.setTextIsSelectable(false);
            if (!LocaleController.isRTL) {
                this.searchContainer.addView(this.searchFieldCaption, LayoutHelper.createFrame(-2.0f, 36.0f, 19, 0.0f, 5.5f, 0.0f, 0.0f));
                this.searchContainer.addView(this.searchField, LayoutHelper.createFrame(-1.0f, 36.0f, 16, 0.0f, 0.0f, 48.0f, 0.0f));
            } else {
                this.searchContainer.addView(this.searchField, LayoutHelper.createFrame(-1.0f, 36.0f, 16, 0.0f, 0.0f, 48.0f, 0.0f));
                this.searchContainer.addView(this.searchFieldCaption, LayoutHelper.createFrame(-2.0f, 36.0f, 21, 0.0f, 5.5f, 48.0f, 0.0f));
            }
            ImageView imageView = new ImageView(getContext()) { // from class: im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.5
                @Override // android.widget.ImageView, android.view.View
                protected void onDetachedFromWindow() {
                    super.onDetachedFromWindow();
                    clearAnimation();
                    if (getTag() == null) {
                        ActionBarMenuItem.this.clearButton.setVisibility(4);
                        ActionBarMenuItem.this.clearButton.setAlpha(0.0f);
                        ActionBarMenuItem.this.clearButton.setRotation(45.0f);
                        ActionBarMenuItem.this.clearButton.setScaleX(0.0f);
                        ActionBarMenuItem.this.clearButton.setScaleY(0.0f);
                        return;
                    }
                    ActionBarMenuItem.this.clearButton.setAlpha(1.0f);
                    ActionBarMenuItem.this.clearButton.setRotation(0.0f);
                    ActionBarMenuItem.this.clearButton.setScaleX(1.0f);
                    ActionBarMenuItem.this.clearButton.setScaleY(1.0f);
                }
            };
            this.clearButton = imageView;
            CloseProgressDrawable2 closeProgressDrawable2 = new CloseProgressDrawable2();
            this.progressDrawable = closeProgressDrawable2;
            imageView.setImageDrawable(closeProgressDrawable2);
            this.clearButton.setColorFilter(new PorterDuffColorFilter(this.parentMenu.parentActionBar.itemsColor, PorterDuff.Mode.MULTIPLY));
            this.clearButton.setScaleType(ImageView.ScaleType.CENTER);
            this.clearButton.setAlpha(0.0f);
            this.clearButton.setRotation(45.0f);
            this.clearButton.setScaleX(0.0f);
            this.clearButton.setScaleY(0.0f);
            this.clearButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$o1MYIPvtHKwkQWj7hQMbA0DYsqg
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$setIsSearchField$8$ActionBarMenuItem(view);
                }
            });
            this.clearButton.setContentDescription(LocaleController.getString("ClearButton", R.string.ClearButton));
            this.searchContainer.addView(this.clearButton, LayoutHelper.createFrame(48, -1, 21));
        }
        this.isSearchField = value;
        return this;
    }

    public /* synthetic */ boolean lambda$setIsSearchField$7$ActionBarMenuItem(TextView v, int actionId, KeyEvent event) {
        if (event == null) {
            return false;
        }
        if ((event.getAction() == 1 && event.getKeyCode() == 84) || (event.getAction() == 0 && event.getKeyCode() == 66)) {
            AndroidUtilities.hideKeyboard(this.searchField);
            ActionBarMenuItemSearchListener actionBarMenuItemSearchListener = this.listener;
            if (actionBarMenuItemSearchListener != null) {
                actionBarMenuItemSearchListener.onSearchPressed(this.searchField);
                return false;
            }
            return false;
        }
        return false;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem$4, reason: invalid class name */
    class AnonymousClass4 implements TextWatcher {
        AnonymousClass4() {
        }

        @Override // android.text.TextWatcher
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        }

        @Override // android.text.TextWatcher
        public void onTextChanged(CharSequence s, int start, int before, int count) {
            if (ActionBarMenuItem.this.ignoreOnTextChange) {
                ActionBarMenuItem.this.ignoreOnTextChange = false;
                return;
            }
            if (ActionBarMenuItem.this.listener != null) {
                ActionBarMenuItem.this.listener.onTextChanged(ActionBarMenuItem.this.searchField);
            }
            if (ActionBarMenuItem.this.clearButton != null) {
                if (!TextUtils.isEmpty(s) || ((ActionBarMenuItem.this.listener != null && ActionBarMenuItem.this.listener.forceShowClear()) || (ActionBarMenuItem.this.searchFieldCaption != null && ActionBarMenuItem.this.searchFieldCaption.getVisibility() == 0))) {
                    if (ActionBarMenuItem.this.clearButton.getTag() == null) {
                        ActionBarMenuItem.this.clearButton.setTag(1);
                        ActionBarMenuItem.this.clearButton.clearAnimation();
                        ActionBarMenuItem.this.clearButton.setVisibility(0);
                        if (ActionBarMenuItem.this.animateClear) {
                            ActionBarMenuItem.this.clearButton.animate().setInterpolator(new DecelerateInterpolator()).alpha(1.0f).setDuration(180L).scaleY(1.0f).scaleX(1.0f).rotation(0.0f).start();
                            return;
                        }
                        ActionBarMenuItem.this.clearButton.setAlpha(1.0f);
                        ActionBarMenuItem.this.clearButton.setRotation(0.0f);
                        ActionBarMenuItem.this.clearButton.setScaleX(1.0f);
                        ActionBarMenuItem.this.clearButton.setScaleY(1.0f);
                        ActionBarMenuItem.this.animateClear = true;
                        return;
                    }
                    return;
                }
                if (ActionBarMenuItem.this.clearButton.getTag() != null) {
                    ActionBarMenuItem.this.clearButton.setTag(null);
                    ActionBarMenuItem.this.clearButton.clearAnimation();
                    if (ActionBarMenuItem.this.animateClear) {
                        ActionBarMenuItem.this.clearButton.animate().setInterpolator(new DecelerateInterpolator()).alpha(0.0f).setDuration(180L).scaleY(0.0f).scaleX(0.0f).rotation(45.0f).withEndAction(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$ActionBarMenuItem$4$K1aYMMQig1gu2rhyLGGPAYrcG8s
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$onTextChanged$0$ActionBarMenuItem$4();
                            }
                        }).start();
                        return;
                    }
                    ActionBarMenuItem.this.clearButton.setAlpha(0.0f);
                    ActionBarMenuItem.this.clearButton.setRotation(45.0f);
                    ActionBarMenuItem.this.clearButton.setScaleX(0.0f);
                    ActionBarMenuItem.this.clearButton.setScaleY(0.0f);
                    ActionBarMenuItem.this.clearButton.setVisibility(4);
                    ActionBarMenuItem.this.animateClear = true;
                }
            }
        }

        public /* synthetic */ void lambda$onTextChanged$0$ActionBarMenuItem$4() {
            ActionBarMenuItem.this.clearButton.setVisibility(4);
        }

        @Override // android.text.TextWatcher
        public void afterTextChanged(Editable s) {
        }
    }

    public /* synthetic */ void lambda$setIsSearchField$8$ActionBarMenuItem(View v) {
        if (this.searchField.length() != 0) {
            this.searchField.setText("");
        } else {
            TextView textView = this.searchFieldCaption;
            if (textView != null && textView.getVisibility() == 0) {
                this.searchFieldCaption.setVisibility(8);
                ActionBarMenuItemSearchListener actionBarMenuItemSearchListener = this.listener;
                if (actionBarMenuItemSearchListener != null) {
                    actionBarMenuItemSearchListener.onCaptionCleared();
                }
            }
        }
        this.searchField.requestFocus();
        AndroidUtilities.showKeyboard(this.searchField);
    }

    public void setShowSearchProgress(boolean show) {
        CloseProgressDrawable2 closeProgressDrawable2 = this.progressDrawable;
        if (closeProgressDrawable2 == null) {
            return;
        }
        if (show) {
            closeProgressDrawable2.startAnimation();
        } else {
            closeProgressDrawable2.stopAnimation();
        }
    }

    public void setSearchFieldCaption(CharSequence caption) {
        if (this.searchFieldCaption == null) {
            return;
        }
        if (TextUtils.isEmpty(caption)) {
            this.searchFieldCaption.setVisibility(8);
        } else {
            this.searchFieldCaption.setVisibility(0);
            this.searchFieldCaption.setText(caption);
        }
    }

    public void setIgnoreOnTextChange() {
        this.ignoreOnTextChange = true;
    }

    public boolean isSearchField() {
        return this.isSearchField;
    }

    public void clearSearchText() {
        EditTextBoldCursor editTextBoldCursor = this.searchField;
        if (editTextBoldCursor == null) {
            return;
        }
        editTextBoldCursor.setText("");
    }

    public ActionBarMenuItem setActionBarMenuItemSearchListener(ActionBarMenuItemSearchListener listener) {
        this.listener = listener;
        return this;
    }

    public ActionBarMenuItem setAllowCloseAnimation(boolean value) {
        this.allowCloseAnimation = value;
        return this;
    }

    public void setPopupAnimationEnabled(boolean value) {
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null) {
            actionBarPopupWindow.setAnimationEnabled(value);
        }
        this.animationEnabled = value;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        ActionBarPopupWindow actionBarPopupWindow = this.popupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            updateOrShowPopup(false, true);
        }
    }

    public void setAdditionalYOffset(int value) {
        this.additionalYOffset = value;
    }

    public void setAdditionalXOffset(int value) {
        this.additionalXOffset = value;
    }

    private void updateOrShowPopup(boolean show, boolean update) {
        int offsetY = 0;
        if (this.parentMenu == null) {
            float scaleY = getScaleY();
            offsetY = (-((int) ((getMeasuredHeight() * scaleY) - ((this.subMenuOpenSide != 2 ? getTranslationY() : 0.0f) / scaleY)))) + this.additionalYOffset;
        }
        int offsetY2 = offsetY + this.yOffset;
        if (show) {
            this.popupLayout.scrollToTop();
        }
        ActionBarMenu actionBarMenu = this.parentMenu;
        if (actionBarMenu != null) {
            View parent = actionBarMenu.parentActionBar;
            if (this.subMenuOpenSide == 0) {
                if (show) {
                    this.popupWindow.showAsDropDown(parent, (((getLeft() + this.parentMenu.getLeft()) + getMeasuredWidth()) - this.popupLayout.getMeasuredWidth()) + ((int) getTranslationX()), offsetY2);
                }
                if (update) {
                    this.popupWindow.update(parent, ((int) getTranslationX()) + (((getLeft() + this.parentMenu.getLeft()) + getMeasuredWidth()) - this.popupLayout.getMeasuredWidth()), offsetY2, -1, -1);
                }
            } else {
                if (show) {
                    this.popupWindow.showAsDropDown(parent, (getLeft() - AndroidUtilities.dp(8.0f)) + ((int) getTranslationX()), offsetY2);
                }
                if (update) {
                    this.popupWindow.update(parent, (getLeft() - AndroidUtilities.dp(8.0f)) + ((int) getTranslationX()), offsetY2, -1, -1);
                }
            }
            this.popupWindow.dimBehind();
            return;
        }
        int i = this.subMenuOpenSide;
        if (i == 0) {
            if (getParent() != null) {
                View parent2 = (View) getParent();
                if (show) {
                    this.popupWindow.showAsDropDown(parent2, ((getLeft() + getMeasuredWidth()) - this.popupLayout.getMeasuredWidth()) + this.additionalXOffset, offsetY2);
                }
                if (update) {
                    this.popupWindow.update(parent2, this.additionalXOffset + ((getLeft() + getMeasuredWidth()) - this.popupLayout.getMeasuredWidth()), offsetY2, -1, -1);
                    return;
                }
                return;
            }
            return;
        }
        if (i == 1) {
            if (show) {
                this.popupWindow.showAsDropDown(this, (-AndroidUtilities.dp(8.0f)) + this.additionalXOffset, offsetY2);
            }
            if (update) {
                this.popupWindow.update(this, (-AndroidUtilities.dp(8.0f)) + this.additionalXOffset, offsetY2, -1, -1);
                return;
            }
            return;
        }
        if (show) {
            this.popupWindow.showAsDropDown(this, (getMeasuredWidth() - this.popupLayout.getMeasuredWidth()) + this.additionalXOffset, offsetY2);
        }
        if (update) {
            this.popupWindow.update(this, (getMeasuredWidth() - this.popupLayout.getMeasuredWidth()) + this.additionalXOffset, offsetY2, -1, -1);
        }
    }

    public void hideSubItem(int id) {
        View view;
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.popupLayout;
        if (actionBarPopupWindowLayout != null && (view = actionBarPopupWindowLayout.findViewWithTag(Integer.valueOf(id))) != null && view.getVisibility() != 8) {
            view.setVisibility(8);
        }
    }

    public boolean isSubItemVisible(int id) {
        View view;
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.popupLayout;
        return (actionBarPopupWindowLayout == null || (view = actionBarPopupWindowLayout.findViewWithTag(Integer.valueOf(id))) == null || view.getVisibility() != 0) ? false : true;
    }

    public void showSubItem(int id) {
        View view;
        ActionBarPopupWindow.ActionBarPopupWindowLayout actionBarPopupWindowLayout = this.popupLayout;
        if (actionBarPopupWindowLayout != null && (view = actionBarPopupWindowLayout.findViewWithTag(Integer.valueOf(id))) != null && view.getVisibility() != 0) {
            view.setVisibility(0);
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        info.setClassName("android.widget.ImageButton");
    }
}
