package im.uwrkaxlmjj.ui.hviews.dialogs;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatDialog;
import androidx.appcompat.widget.AppCompatTextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class XDialog extends AppCompatDialog implements Drawable.Callback {
    private Rect backgroundRect;
    protected FrameLayout buttonsLayout;
    private LinearLayout buttonsLinearLayout;
    private ScrollView contentScrollView;
    private View customView;
    private int customViewOffset;
    private boolean dismissDialogByButtons;
    private Runnable dismissRunnable;
    private int[] itemIcons;
    private ArrayList<XDialogCell> itemViews;
    private CharSequence[] items;
    private int lastScreenWidth;
    CharSequence message;
    private TextView messageTextView;
    private boolean messageTextViewClickable;
    private int negativeButtonColor;
    private DialogInterface.OnClickListener negativeButtonListener;
    private CharSequence negativeButtonText;
    private DialogInterface.OnClickListener neutralButtonListener;
    private CharSequence neutralButtonText;
    private DialogInterface.OnClickListener onBackButtonListener;
    private DialogInterface.OnClickListener onClickListener;
    private DialogInterface.OnDismissListener onDismissListener;
    private int positiveButtonColor;
    private DialogInterface.OnClickListener positiveButtonListener;
    private CharSequence positiveButtonText;
    private LinearLayout scrollContainer;
    private boolean setOutSideCancel;
    private BitmapDrawable[] shadow;
    private Drawable shadowDrawable;
    private CharSequence title;
    private FrameLayout titleContainer;
    private TextView titleTextView;
    private XDialogStyle xDialogStyle;

    public XDialog(Context context) {
        super(context, R.plurals.TransparentDialog);
        this.setOutSideCancel = true;
        this.shadow = new BitmapDrawable[2];
        this.messageTextViewClickable = true;
        this.xDialogStyle = XDialogStyle.IOS;
        this.itemViews = new ArrayList<>();
        this.customViewOffset = 20;
        this.positiveButtonColor = -1;
        this.negativeButtonColor = -1;
        this.dismissDialogByButtons = true;
        this.dismissRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.-$$Lambda$oMa6ukuZ2GPGe0t5bPNPJ7ueSec
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.dismiss();
            }
        };
        this.backgroundRect = new Rect();
        Drawable drawableMutate = context.getResources().getDrawable(R.drawable.popup_fixed_alert).mutate();
        this.shadowDrawable = drawableMutate;
        drawableMutate.setColorFilter(new PorterDuffColorFilter(getThemeColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
        this.shadowDrawable.getPadding(this.backgroundRect);
    }

    public XDialog(Context context, int iRoundCorner) {
        super(context, R.plurals.TransparentDialog);
        this.setOutSideCancel = true;
        this.shadow = new BitmapDrawable[2];
        this.messageTextViewClickable = true;
        this.xDialogStyle = XDialogStyle.IOS;
        this.itemViews = new ArrayList<>();
        this.customViewOffset = 20;
        this.positiveButtonColor = -1;
        this.negativeButtonColor = -1;
        this.dismissDialogByButtons = true;
        this.dismissRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.-$$Lambda$oMa6ukuZ2GPGe0t5bPNPJ7ueSec
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.dismiss();
            }
        };
        this.backgroundRect = new Rect();
        ShapeUtils.ShapeDrawable shapeDrawableCreate = ShapeUtils.create(-1, AndroidUtilities.dp(iRoundCorner));
        this.shadowDrawable = shapeDrawableCreate;
        shapeDrawableCreate.setColorFilter(new PorterDuffColorFilter(getThemeColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
        this.shadowDrawable.getPadding(this.backgroundRect);
    }

    public View getButton(int type) {
        FrameLayout frameLayout = this.buttonsLayout;
        if (frameLayout != null) {
            return frameLayout.findViewWithTag(Integer.valueOf(type));
        }
        return null;
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        int maxWidth;
        super.onCreate(savedInstanceState);
        LinearLayout containerView = new LinearLayout(getContext());
        containerView.setOrientation(1);
        containerView.setBackground(this.shadowDrawable);
        containerView.setFitsSystemWindows(Build.VERSION.SDK_INT >= 21);
        setContentView(containerView);
        if (this.xDialogStyle == XDialogStyle.IOS) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) containerView.getLayoutParams();
            layoutParams.leftMargin = AndroidUtilities.dp(30.0f);
            layoutParams.rightMargin = AndroidUtilities.dp(30.0f);
            containerView.setLayoutParams(layoutParams);
        }
        boolean hasButtons = (this.positiveButtonText == null && this.negativeButtonText == null && this.neutralButtonText == null) ? false : true;
        if (this.title != null) {
            this.titleContainer = new FrameLayout(getContext());
            if (this.xDialogStyle == XDialogStyle.IOS) {
                containerView.addView(this.titleContainer, LayoutHelper.createLinear(-2, -2, 1, 24, 0, 24, 0));
            } else {
                containerView.addView(this.titleContainer, LayoutHelper.createLinear(-2, -2, 24.0f, 0.0f, 24.0f, 0.0f));
            }
            TextView textView = new TextView(getContext());
            this.titleTextView = textView;
            textView.setText(this.title);
            this.titleTextView.setTextColor(getThemeColor(Theme.key_dialogTextBlack));
            this.titleTextView.setTextSize(1, 20.0f);
            this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.titleTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.titleContainer.addView(this.titleTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 0.0f, 19.0f, 0.0f, this.items != null ? 14 : 10));
        }
        this.shadow[0] = (BitmapDrawable) getContext().getResources().getDrawable(R.drawable.header_shadow).mutate();
        this.shadow[1] = (BitmapDrawable) getContext().getResources().getDrawable(R.drawable.header_shadow_reverse).mutate();
        this.shadow[0].setAlpha(0);
        this.shadow[1].setAlpha(0);
        this.shadow[0].setCallback(this);
        this.shadow[1].setCallback(this);
        ScrollView scrollView = new ScrollView(getContext()) { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.XDialog.1
            @Override // android.view.ViewGroup
            protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
                boolean result = super.drawChild(canvas, child, drawingTime);
                if (XDialog.this.shadow[0].getPaint().getAlpha() != 0) {
                    XDialog.this.shadow[0].setBounds(0, getScrollY(), getMeasuredWidth(), getScrollY() + AndroidUtilities.dp(3.0f));
                    XDialog.this.shadow[0].draw(canvas);
                }
                if (XDialog.this.shadow[1].getPaint().getAlpha() != 0) {
                    XDialog.this.shadow[1].setBounds(0, (getScrollY() + getMeasuredHeight()) - AndroidUtilities.dp(3.0f), getMeasuredWidth(), getScrollY() + getMeasuredHeight());
                    XDialog.this.shadow[1].draw(canvas);
                }
                return result;
            }
        };
        this.contentScrollView = scrollView;
        scrollView.setVerticalScrollBarEnabled(false);
        AndroidUtilities.setScrollViewEdgeEffectColor(this.contentScrollView, getThemeColor(Theme.key_dialogScrollGlow));
        containerView.addView(this.contentScrollView, LayoutHelper.createLinear(-1, -2, 0.0f, 0.0f, 0.0f, 0.0f));
        LinearLayout linearLayout = new LinearLayout(getContext());
        this.scrollContainer = linearLayout;
        linearLayout.setOrientation(1);
        this.contentScrollView.addView(this.scrollContainer, new FrameLayout.LayoutParams(-1, -2));
        TextView textView2 = new TextView(getContext());
        this.messageTextView = textView2;
        textView2.setTextColor(getThemeColor(Theme.key_dialogTextBlack));
        this.messageTextView.setTextSize(1, 14.0f);
        this.messageTextView.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
        this.messageTextView.setLinkTextColor(getThemeColor(Theme.key_dialogTextLink));
        if (!this.messageTextViewClickable) {
            this.messageTextView.setClickable(false);
            this.messageTextView.setEnabled(false);
        }
        this.messageTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
        this.scrollContainer.addView(this.messageTextView, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 24, this.title != null ? 4 : 20, 24, (this.customView == null && this.items == null) ? 18 : this.customViewOffset));
        if (!TextUtils.isEmpty(this.message)) {
            this.messageTextView.setText(this.message);
            this.messageTextView.setVisibility(0);
        } else {
            this.messageTextView.setVisibility(8);
        }
        if (this.items != null) {
            int a = 0;
            while (true) {
                CharSequence[] charSequenceArr = this.items;
                if (a >= charSequenceArr.length) {
                    break;
                }
                if (charSequenceArr[a] != null) {
                    XDialogCell cell = new XDialogCell(getContext());
                    CharSequence charSequence = this.items[a];
                    int[] iArr = this.itemIcons;
                    cell.setTextAndIcon(charSequence, iArr != null ? iArr[a] : 0);
                    cell.setTag(Integer.valueOf(a));
                    this.itemViews.add(cell);
                    this.scrollContainer.addView(cell, LayoutHelper.createLinear(-1, 50));
                    cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.-$$Lambda$XDialog$KVhlFMxEVmJbb1sMd-XBp5b9m6Q
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            this.f$0.lambda$onCreate$0$XDialog(view);
                        }
                    });
                }
                a++;
            }
        }
        View view = this.customView;
        if (view != null) {
            if (view.getParent() != null) {
                ViewGroup viewGroup = (ViewGroup) this.customView.getParent();
                viewGroup.removeView(this.customView);
            }
            this.scrollContainer.addView(this.customView, LayoutHelper.createLinear(-1, -2));
        }
        if (hasButtons) {
            if (this.xDialogStyle == XDialogStyle.IOS) {
                this.buttonsLayout = new FrameLayout(getContext());
                View view2 = new View(getContext());
                view2.setBackgroundColor(Theme.getColor(Theme.key_divider));
                containerView.addView(view2, LayoutHelper.createLinear(-1.0f, 0.5f, 0.0f, 30.0f, 0.0f, 0.0f));
                LinearLayout linearLayout2 = new LinearLayout(getContext());
                this.buttonsLinearLayout = linearLayout2;
                this.buttonsLayout.addView(linearLayout2);
            } else {
                FrameLayout frameLayout = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.XDialog.2
                    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
                    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                        int l;
                        int t;
                        int count = getChildCount();
                        View positiveButton = null;
                        int width = right - left;
                        for (int a2 = 0; a2 < count; a2++) {
                            View child = getChildAt(a2);
                            Integer tag = (Integer) child.getTag();
                            if (tag != null) {
                                if (tag.intValue() == -1) {
                                    positiveButton = child;
                                    if (LocaleController.isRTL) {
                                        child.layout(getPaddingLeft(), getPaddingTop(), getPaddingLeft() + child.getMeasuredWidth(), getPaddingTop() + child.getMeasuredHeight());
                                    } else {
                                        child.layout((width - getPaddingRight()) - child.getMeasuredWidth(), getPaddingTop(), width - getPaddingRight(), getPaddingTop() + child.getMeasuredHeight());
                                    }
                                } else if (tag.intValue() == -2) {
                                    if (LocaleController.isRTL) {
                                        int x = getPaddingLeft();
                                        if (positiveButton != null) {
                                            x += positiveButton.getMeasuredWidth() + AndroidUtilities.dp(8.0f);
                                        }
                                        child.layout(x, getPaddingTop(), child.getMeasuredWidth() + x, getPaddingTop() + child.getMeasuredHeight());
                                    } else {
                                        int x2 = (width - getPaddingRight()) - child.getMeasuredWidth();
                                        if (positiveButton != null) {
                                            x2 -= positiveButton.getMeasuredWidth() + AndroidUtilities.dp(8.0f);
                                        }
                                        child.layout(x2, getPaddingTop(), child.getMeasuredWidth() + x2, getPaddingTop() + child.getMeasuredHeight());
                                    }
                                } else if (tag.intValue() == -3) {
                                    if (LocaleController.isRTL) {
                                        child.layout((width - getPaddingRight()) - child.getMeasuredWidth(), getPaddingTop(), width - getPaddingRight(), getPaddingTop() + child.getMeasuredHeight());
                                    } else {
                                        child.layout(getPaddingLeft(), getPaddingTop(), getPaddingLeft() + child.getMeasuredWidth(), getPaddingTop() + child.getMeasuredHeight());
                                    }
                                }
                            } else {
                                int w = child.getMeasuredWidth();
                                int h = child.getMeasuredHeight();
                                if (positiveButton != null) {
                                    l = positiveButton.getLeft() + ((positiveButton.getMeasuredWidth() - w) / 2);
                                    t = positiveButton.getTop() + ((positiveButton.getMeasuredHeight() - h) / 2);
                                } else {
                                    l = 0;
                                    t = 0;
                                }
                                child.layout(l, t, l + w, t + h);
                            }
                        }
                    }

                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                        int totalWidth = 0;
                        int availableWidth = (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
                        int count = getChildCount();
                        for (int a2 = 0; a2 < count; a2++) {
                            View child = getChildAt(a2);
                            if ((child instanceof TextView) && child.getTag() != null) {
                                totalWidth += child.getMeasuredWidth();
                            }
                        }
                        if (totalWidth > availableWidth) {
                            View negative = findViewWithTag(-2);
                            View neuntral = findViewWithTag(-3);
                            if (negative != null && neuntral != null) {
                                if (negative.getMeasuredWidth() < neuntral.getMeasuredWidth()) {
                                    neuntral.measure(View.MeasureSpec.makeMeasureSpec(neuntral.getMeasuredWidth() - (totalWidth - availableWidth), 1073741824), View.MeasureSpec.makeMeasureSpec(neuntral.getMeasuredHeight(), 1073741824));
                                } else {
                                    negative.measure(View.MeasureSpec.makeMeasureSpec(negative.getMeasuredWidth() - (totalWidth - availableWidth), 1073741824), View.MeasureSpec.makeMeasureSpec(negative.getMeasuredHeight(), 1073741824));
                                }
                            }
                        }
                    }
                };
                this.buttonsLayout = frameLayout;
                frameLayout.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
            }
            containerView.addView(this.buttonsLayout, LayoutHelper.createLinear(-1, 52));
            if (this.negativeButtonText != null) {
                AppCompatTextView textView3 = new AppCompatTextView(getContext()) { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.XDialog.3
                    @Override // android.widget.TextView, android.view.View
                    public void setEnabled(boolean enabled) {
                        super.setEnabled(enabled);
                        setAlpha(enabled ? 1.0f : 0.5f);
                    }

                    @Override // android.widget.TextView
                    public void setTextColor(int color) {
                        super.setTextColor(color);
                        setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(color));
                    }
                };
                textView3.setMinWidth(AndroidUtilities.dp(64.0f));
                textView3.setTag(-2);
                textView3.setTextSize(1, 14.0f);
                int themeColor = this.negativeButtonColor;
                if (themeColor == -1) {
                    themeColor = getThemeColor(Theme.key_dialogButton);
                }
                textView3.setTextColor(themeColor);
                textView3.setGravity(17);
                textView3.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView3.setEllipsize(TextUtils.TruncateAt.END);
                textView3.setSingleLine(true);
                textView3.setText(this.negativeButtonText.toString().toUpperCase());
                textView3.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView3.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                if (this.xDialogStyle == XDialogStyle.IOS) {
                    this.buttonsLinearLayout.addView(textView3, LayoutHelper.createLinear(0, 36, 1.0f, 17));
                } else {
                    this.buttonsLayout.addView(textView3, LayoutHelper.createFrame(-2, 36, 53));
                }
                textView3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.-$$Lambda$XDialog$MAxiocXrfq58Kb969ZRtVpkft5E
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view3) {
                        this.f$0.lambda$onCreate$1$XDialog(view3);
                    }
                });
                if (this.xDialogStyle == XDialogStyle.IOS && (this.neutralButtonText != null || this.positiveButtonText != null)) {
                    View view3 = new View(getContext());
                    view3.setBackgroundColor(Theme.getColor(Theme.key_divider));
                    this.buttonsLinearLayout.addView(view3, LayoutHelper.createLinear(0.5f, -1.0f));
                }
            }
            if (this.neutralButtonText != null) {
                AppCompatTextView textView4 = new AppCompatTextView(getContext()) { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.XDialog.4
                    @Override // android.widget.TextView, android.view.View
                    public void setEnabled(boolean enabled) {
                        super.setEnabled(enabled);
                        setAlpha(enabled ? 1.0f : 0.5f);
                    }

                    @Override // android.widget.TextView
                    public void setTextColor(int color) {
                        super.setTextColor(color);
                        setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(color));
                    }
                };
                textView4.setMinWidth(AndroidUtilities.dp(64.0f));
                textView4.setTag(-3);
                textView4.setTextSize(1, 14.0f);
                textView4.setTextColor(getThemeColor(Theme.key_dialogButton));
                textView4.setGravity(17);
                textView4.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView4.setEllipsize(TextUtils.TruncateAt.END);
                textView4.setSingleLine(true);
                textView4.setText(this.neutralButtonText.toString().toUpperCase());
                textView4.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView4.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                if (this.xDialogStyle == XDialogStyle.IOS) {
                    this.buttonsLinearLayout.addView(textView4, LayoutHelper.createLinear(0, 36, 1.0f, 17));
                } else {
                    this.buttonsLayout.addView(textView4, LayoutHelper.createFrame(-2, 36, 53));
                }
                textView4.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.-$$Lambda$XDialog$P9w6jVnJHFJnq7QDov1euihy1_o
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view4) {
                        this.f$0.lambda$onCreate$2$XDialog(view4);
                    }
                });
                if (this.xDialogStyle == XDialogStyle.IOS && this.positiveButtonText != null) {
                    View view4 = new View(getContext());
                    view4.setBackgroundColor(Theme.getColor(Theme.key_divider));
                    this.buttonsLinearLayout.addView(view4, LayoutHelper.createLinear(0.5f, -1.0f));
                }
            }
            if (this.positiveButtonText != null) {
                AppCompatTextView textView5 = new AppCompatTextView(getContext()) { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.XDialog.5
                    @Override // android.widget.TextView, android.view.View
                    public void setEnabled(boolean enabled) {
                        super.setEnabled(enabled);
                        setAlpha(enabled ? 1.0f : 0.5f);
                    }

                    @Override // android.widget.TextView
                    public void setTextColor(int color) {
                        super.setTextColor(color);
                        setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(color));
                    }
                };
                textView5.setMinWidth(AndroidUtilities.dp(64.0f));
                textView5.setTag(-1);
                textView5.setTextSize(1, 14.0f);
                int themeColor2 = this.positiveButtonColor;
                if (themeColor2 == -1) {
                    themeColor2 = getThemeColor(Theme.key_dialogButton);
                }
                textView5.setTextColor(themeColor2);
                textView5.setGravity(17);
                textView5.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView5.setText(this.positiveButtonText.toString().toUpperCase());
                textView5.setBackgroundDrawable(Theme.getRoundRectSelectorDrawable(getThemeColor(Theme.key_dialogButton)));
                textView5.setPadding(AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0);
                if (this.xDialogStyle == XDialogStyle.IOS) {
                    this.buttonsLinearLayout.addView(textView5, LayoutHelper.createLinear(0, 36, 1.0f, 17));
                } else {
                    this.buttonsLayout.addView(textView5, LayoutHelper.createFrame(-2, 36, 53));
                }
                textView5.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hviews.dialogs.-$$Lambda$XDialog$-Tao1QAO0Et_rqVmbpyfY4ZS9Y8
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view5) {
                        this.f$0.lambda$onCreate$3$XDialog(view5);
                    }
                });
            }
        }
        Window window = getWindow();
        WindowManager.LayoutParams params = new WindowManager.LayoutParams();
        params.copyFrom(window.getAttributes());
        params.dimAmount = 0.6f;
        params.flags |= 2;
        this.lastScreenWidth = AndroidUtilities.displaySize.x;
        int calculatedWidth = AndroidUtilities.displaySize.x - AndroidUtilities.dp(48.0f);
        if (AndroidUtilities.isTablet()) {
            if (AndroidUtilities.isSmallTablet()) {
                maxWidth = AndroidUtilities.dp(446.0f);
            } else {
                maxWidth = AndroidUtilities.dp(496.0f);
            }
        } else {
            maxWidth = AndroidUtilities.dp(356.0f);
        }
        params.width = Math.min(maxWidth, calculatedWidth) + this.backgroundRect.left + this.backgroundRect.right;
        View view5 = this.customView;
        if (view5 == null || !canTextInput(view5)) {
            params.flags |= 131072;
        } else {
            params.softInputMode = 4;
        }
        if (Build.VERSION.SDK_INT >= 28) {
            params.layoutInDisplayCutoutMode = 0;
        }
        window.setAttributes(params);
        setCanceledOnTouchOutside(this.setOutSideCancel);
        setCancelable(this.setOutSideCancel);
    }

    public /* synthetic */ void lambda$onCreate$0$XDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.onClickListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, ((Integer) v.getTag()).intValue());
        }
        dismiss();
    }

    public /* synthetic */ void lambda$onCreate$1$XDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.negativeButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
        if (this.dismissDialogByButtons) {
            cancel();
        }
    }

    public /* synthetic */ void lambda$onCreate$2$XDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.neutralButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
        if (this.dismissDialogByButtons) {
            dismiss();
        }
    }

    public /* synthetic */ void lambda$onCreate$3$XDialog(View v) {
        DialogInterface.OnClickListener onClickListener = this.positiveButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -1);
        }
        if (this.dismissDialogByButtons) {
            dismiss();
        }
    }

    private boolean canTextInput(View v) {
        if (v.onCheckIsTextEditor()) {
            return true;
        }
        if (!(v instanceof ViewGroup)) {
            return false;
        }
        ViewGroup vg = (ViewGroup) v;
        int i = vg.getChildCount();
        while (i > 0) {
            i--;
            if (canTextInput(vg.getChildAt(i))) {
                return true;
            }
        }
        return false;
    }

    protected int getThemeColor(String key) {
        return Theme.getColor(key);
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void invalidateDrawable(Drawable who) {
        this.contentScrollView.invalidate();
        this.scrollContainer.invalidate();
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void scheduleDrawable(Drawable who, Runnable what, long when) {
        ScrollView scrollView = this.contentScrollView;
        if (scrollView != null) {
            scrollView.postDelayed(what, when);
        }
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public void unscheduleDrawable(Drawable who, Runnable what) {
        ScrollView scrollView = this.contentScrollView;
        if (scrollView != null) {
            scrollView.removeCallbacks(what);
        }
    }

    @Override // android.app.Dialog
    public void onBackPressed() {
        super.onBackPressed();
        DialogInterface.OnClickListener onClickListener = this.onBackButtonListener;
        if (onClickListener != null) {
            onClickListener.onClick(this, -2);
        }
    }

    public static class Builder {
        private XDialog alertDialog;

        public Builder(Context context) {
            this.alertDialog = new XDialog(context);
        }

        public Builder(Context context, int iRoundCorner) {
            this.alertDialog = new XDialog(context, iRoundCorner);
        }

        public Builder setStyle(XDialogStyle xDialogStyle) {
            this.alertDialog.xDialogStyle = xDialogStyle;
            return this;
        }

        public Builder setItems(CharSequence[] items, DialogInterface.OnClickListener onClickListener) {
            this.alertDialog.items = items;
            this.alertDialog.onClickListener = onClickListener;
            return this;
        }

        public Builder setItems(CharSequence[] items, int[] icons, DialogInterface.OnClickListener onClickListener) {
            this.alertDialog.items = items;
            this.alertDialog.itemIcons = icons;
            this.alertDialog.onClickListener = onClickListener;
            return this;
        }

        public Builder setView(View view) {
            this.alertDialog.customView = view;
            return this;
        }

        public Builder setTitle(CharSequence title) {
            this.alertDialog.title = title;
            return this;
        }

        public Builder setOutSideCancel(boolean flag) {
            this.alertDialog.setOutSideCancel = flag;
            return this;
        }

        public Builder setMessage(CharSequence message) {
            this.alertDialog.message = message;
            return this;
        }

        public Builder setPositiveButton(CharSequence text, DialogInterface.OnClickListener listener) {
            this.alertDialog.positiveButtonText = text;
            this.alertDialog.positiveButtonListener = listener;
            return this;
        }

        public Builder setPositiveButton(CharSequence text, int iColor, DialogInterface.OnClickListener listener) {
            this.alertDialog.positiveButtonText = text;
            this.alertDialog.positiveButtonListener = listener;
            this.alertDialog.positiveButtonColor = iColor;
            return this;
        }

        public Builder setNegativeButton(CharSequence text, DialogInterface.OnClickListener listener) {
            this.alertDialog.negativeButtonText = text;
            this.alertDialog.negativeButtonListener = listener;
            return this;
        }

        public Builder setNegativeButton(CharSequence text, int iColor, DialogInterface.OnClickListener listener) {
            this.alertDialog.negativeButtonText = text;
            this.alertDialog.negativeButtonListener = listener;
            this.alertDialog.negativeButtonColor = iColor;
            return this;
        }

        public Builder setNeutralButton(CharSequence text, DialogInterface.OnClickListener listener) {
            this.alertDialog.neutralButtonText = text;
            this.alertDialog.neutralButtonListener = listener;
            return this;
        }

        public Builder setOnBackButtonListener(DialogInterface.OnClickListener listener) {
            this.alertDialog.onBackButtonListener = listener;
            return this;
        }

        public Builder setCustomViewOffset(int offset) {
            this.alertDialog.customViewOffset = offset;
            return this;
        }

        public XDialog create() {
            return this.alertDialog;
        }

        public XDialog show() {
            try {
                this.alertDialog.show();
            } catch (Exception e) {
                FileLog.e("XDialog show e: " + e.getMessage());
            }
            return this.alertDialog;
        }

        public Runnable getDismissRunnable() {
            return this.alertDialog.dismissRunnable;
        }

        public Builder setOnDismissListener(DialogInterface.OnDismissListener onDismissListener) {
            this.alertDialog.setOnDismissListener(onDismissListener);
            return this;
        }
    }

    public static class XDialogCell extends FrameLayout {
        private ImageView imageView;
        private TextView textView;

        public XDialogCell(Context context) {
            super(context);
            setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_dialogButtonSelector), 2));
            setPadding(AndroidUtilities.dp(23.0f), 0, AndroidUtilities.dp(23.0f), 0);
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.imageView, LayoutHelper.createFrame(-2, 40, (LocaleController.isRTL ? 5 : 3) | 16));
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setLines(1);
            this.textView.setSingleLine(true);
            this.textView.setGravity(1);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            this.textView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            this.textView.setTextSize(1, 16.0f);
            addView(this.textView, LayoutHelper.createFrame(-2, -2, (LocaleController.isRTL ? 5 : 3) | 16));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(48.0f), 1073741824));
        }

        public void setTextColor(int color) {
            this.textView.setTextColor(color);
        }

        public void setGravity(int gravity) {
            this.textView.setGravity(gravity);
        }

        public void setTextAndIcon(CharSequence text, int icon) {
            this.textView.setText(text);
            if (icon != 0) {
                this.imageView.setImageResource(icon);
                this.imageView.setVisibility(0);
                this.textView.setPadding(LocaleController.isRTL ? 0 : AndroidUtilities.dp(56.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(56.0f) : 0, 0);
            } else {
                this.imageView.setVisibility(4);
                this.textView.setPadding(0, 0, 0, 0);
            }
        }
    }
}
