package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ChatMessageCell;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class HintView extends FrameLayout {
    private AnimatorSet animatorSet;
    private ImageView arrowImageView;
    private int currentType;
    private View currentView;
    private Runnable hideRunnable;
    private ImageView imageView;
    private boolean isTopArrow;
    private ChatMessageCell messageCell;
    private String overrideText;
    private TextView textView;

    public HintView(Context context, int type) {
        this(context, type, false);
    }

    public HintView(Context context, int type, boolean topArrow) {
        super(context);
        this.currentType = type;
        this.isTopArrow = topArrow;
        CorrectlyMeasuringTextView correctlyMeasuringTextView = new CorrectlyMeasuringTextView(context);
        this.textView = correctlyMeasuringTextView;
        correctlyMeasuringTextView.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
        this.textView.setTextSize(1, 14.0f);
        this.textView.setMaxLines(2);
        this.textView.setMaxWidth(AndroidUtilities.dp(250.0f));
        this.textView.setGravity(51);
        this.textView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(3.0f), Theme.getColor(Theme.key_chat_gifSaveHintBackground)));
        int i = this.currentType;
        if (i == 2) {
            this.textView.setPadding(AndroidUtilities.dp(7.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(7.0f), AndroidUtilities.dp(7.0f));
        } else {
            this.textView.setPadding(AndroidUtilities.dp(i == 0 ? 54.0f : 5.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(7.0f));
        }
        addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, topArrow ? 6.0f : 0.0f, 0.0f, topArrow ? 0.0f : 6.0f));
        if (type == 0) {
            this.textView.setText(LocaleController.getString("AutoplayVideoInfo", R.string.AutoplayVideoInfo));
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setImageResource(R.drawable.tooltip_sound);
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_gifSaveHintText), PorterDuff.Mode.MULTIPLY));
            addView(this.imageView, LayoutHelper.createFrame(38.0f, 34.0f, 51, 7.0f, 7.0f, 0.0f, 0.0f));
        }
        ImageView imageView2 = new ImageView(context);
        this.arrowImageView = imageView2;
        imageView2.setImageResource(topArrow ? R.drawable.tooltip_arrow_up : R.drawable.tooltip_arrow);
        this.arrowImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_gifSaveHintBackground), PorterDuff.Mode.MULTIPLY));
        addView(this.arrowImageView, LayoutHelper.createFrame(14.0f, 6.0f, (topArrow ? 48 : 80) | 3, 0.0f, 0.0f, 0.0f, 0.0f));
    }

    public void setOverrideText(String text) {
        this.overrideText = text;
        this.textView.setText(text);
        if (this.messageCell != null) {
            ChatMessageCell cell = this.messageCell;
            this.messageCell = null;
            showForMessageCell(cell, false);
        }
    }

    public boolean showForMessageCell(ChatMessageCell cell, boolean animated) {
        int top;
        int centerX;
        if ((this.currentType == 0 && getTag() != null) || this.messageCell == cell) {
            return false;
        }
        Runnable runnable = this.hideRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.hideRunnable = null;
        }
        int top2 = cell.getTop();
        View parentView = (View) cell.getParent();
        if (this.currentType == 0) {
            ImageReceiver imageReceiver = cell.getPhotoImage();
            top = top2 + imageReceiver.getImageY();
            int height = imageReceiver.getImageHeight();
            int bottom = top + height;
            int parentHeight = parentView.getMeasuredHeight();
            if (top <= getMeasuredHeight() + AndroidUtilities.dp(10.0f) || bottom > (height / 4) + parentHeight) {
                return false;
            }
            centerX = cell.getNoSoundIconCenterX();
        } else {
            MessageObject messageObject = cell.getMessageObject();
            String str = this.overrideText;
            if (str == null) {
                this.textView.setText(LocaleController.getString("HidAccount", R.string.HidAccount));
            } else {
                this.textView.setText(str);
            }
            measure(View.MeasureSpec.makeMeasureSpec(1000, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(1000, Integer.MIN_VALUE));
            top = top2 + AndroidUtilities.dp(22.0f);
            if (!messageObject.isOutOwner() && cell.isDrawNameLayout()) {
                top += AndroidUtilities.dp(20.0f);
            }
            if (!this.isTopArrow && top <= getMeasuredHeight() + AndroidUtilities.dp(10.0f)) {
                return false;
            }
            centerX = cell.getForwardNameCenterX();
        }
        int parentWidth = parentView.getMeasuredWidth();
        if (this.isTopArrow) {
            setTranslationY(AndroidUtilities.dp(44.0f));
        } else {
            setTranslationY(top - getMeasuredHeight());
        }
        int iconX = cell.getLeft() + centerX;
        int left = AndroidUtilities.dp(19.0f);
        if (iconX <= parentView.getMeasuredWidth() / 2) {
            setTranslationX(0.0f);
        } else {
            int offset = (parentWidth - getMeasuredWidth()) - AndroidUtilities.dp(38.0f);
            setTranslationX(offset);
            left += offset;
        }
        float arrowX = ((cell.getLeft() + centerX) - left) - (this.arrowImageView.getMeasuredWidth() / 2);
        this.arrowImageView.setTranslationX(arrowX);
        if (iconX > parentView.getMeasuredWidth() / 2) {
            if (arrowX < AndroidUtilities.dp(10.0f)) {
                float diff = arrowX - AndroidUtilities.dp(10.0f);
                setTranslationX(getTranslationX() + diff);
                this.arrowImageView.setTranslationX(arrowX - diff);
            }
        } else if (arrowX > getMeasuredWidth() - AndroidUtilities.dp(24.0f)) {
            float diff2 = (arrowX - getMeasuredWidth()) + AndroidUtilities.dp(24.0f);
            setTranslationX(diff2);
            this.arrowImageView.setTranslationX(arrowX - diff2);
        } else if (arrowX < AndroidUtilities.dp(10.0f)) {
            float diff3 = arrowX - AndroidUtilities.dp(10.0f);
            setTranslationX(getTranslationX() + diff3);
            this.arrowImageView.setTranslationX(arrowX - diff3);
        }
        this.messageCell = cell;
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.animatorSet = null;
        }
        setTag(1);
        setVisibility(0);
        if (!animated) {
            setAlpha(1.0f);
        } else {
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.animatorSet = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this, "alpha", 0.0f, 1.0f));
            this.animatorSet.addListener(new AnonymousClass1());
            this.animatorSet.setDuration(300L);
            this.animatorSet.start();
        }
        return true;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.HintView$1, reason: invalid class name */
    class AnonymousClass1 extends AnimatorListenerAdapter {
        AnonymousClass1() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            HintView.this.animatorSet = null;
            AndroidUtilities.runOnUIThread(HintView.this.hideRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$HintView$1$7qVWwdhf05xFxJ5MSFGEtQW1yU8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$HintView$1();
                }
            }, HintView.this.currentType == 0 ? OkHttpUtils.DEFAULT_MILLISECONDS : AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$HintView$1() {
            HintView.this.hide();
        }
    }

    public boolean showForView(View view, boolean animated) {
        if (this.currentView == view || getTag() != null) {
            return false;
        }
        Runnable runnable = this.hideRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.hideRunnable = null;
        }
        measure(View.MeasureSpec.makeMeasureSpec(1000, Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(1000, Integer.MIN_VALUE));
        int[] position = new int[2];
        view.getLocationInWindow(position);
        int centerX = position[0] + (view.getMeasuredWidth() / 2);
        int top = position[1] - AndroidUtilities.dp(4.0f);
        View parentView = (View) getParent();
        parentView.getLocationInWindow(position);
        int centerX2 = centerX - position[0];
        int top2 = top - position[1];
        if (Build.VERSION.SDK_INT >= 21) {
            top2 -= AndroidUtilities.statusBarHeight;
        }
        int parentWidth = parentView.getMeasuredWidth();
        if (this.isTopArrow) {
            setTranslationY(AndroidUtilities.dp(44.0f));
        } else {
            setTranslationY((top2 - getMeasuredHeight()) - ActionBar.getCurrentActionBarHeight());
        }
        int left = AndroidUtilities.dp(19.0f);
        if (centerX2 <= parentView.getMeasuredWidth() / 2) {
            setTranslationX(0.0f);
        } else {
            int offset = (parentWidth - getMeasuredWidth()) - AndroidUtilities.dp(28.0f);
            setTranslationX(offset);
            left += offset;
        }
        float arrowX = (centerX2 - left) - (this.arrowImageView.getMeasuredWidth() / 2);
        this.arrowImageView.setTranslationX(arrowX);
        if (centerX2 > parentView.getMeasuredWidth() / 2) {
            if (arrowX < AndroidUtilities.dp(10.0f)) {
                float diff = arrowX - AndroidUtilities.dp(10.0f);
                setTranslationX(getTranslationX() + diff);
                this.arrowImageView.setTranslationX(arrowX - diff);
            }
        } else if (arrowX > getMeasuredWidth() - AndroidUtilities.dp(24.0f)) {
            float diff2 = (arrowX - getMeasuredWidth()) + AndroidUtilities.dp(24.0f);
            setTranslationX(diff2);
            this.arrowImageView.setTranslationX(arrowX - diff2);
        } else if (arrowX < AndroidUtilities.dp(10.0f)) {
            float diff3 = arrowX - AndroidUtilities.dp(10.0f);
            setTranslationX(getTranslationX() + diff3);
            this.arrowImageView.setTranslationX(arrowX - diff3);
        }
        this.currentView = view;
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.animatorSet = null;
        }
        setTag(1);
        setVisibility(0);
        if (!animated) {
            setAlpha(1.0f);
        } else {
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.animatorSet = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this, "alpha", 0.0f, 1.0f));
            this.animatorSet.addListener(new AnonymousClass2());
            this.animatorSet.setDuration(300L);
            this.animatorSet.start();
        }
        return true;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.HintView$2, reason: invalid class name */
    class AnonymousClass2 extends AnimatorListenerAdapter {
        AnonymousClass2() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animation) {
            HintView.this.animatorSet = null;
            AndroidUtilities.runOnUIThread(HintView.this.hideRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$HintView$2$I-rl3Nh1sNdR8w4-RktXvwVAUEA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onAnimationEnd$0$HintView$2();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        public /* synthetic */ void lambda$onAnimationEnd$0$HintView$2() {
            HintView.this.hide();
        }
    }

    public void hide() {
        if (getTag() == null) {
            return;
        }
        setTag(null);
        Runnable runnable = this.hideRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.hideRunnable = null;
        }
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.animatorSet = null;
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.animatorSet = animatorSet2;
        animatorSet2.playTogether(ObjectAnimator.ofFloat(this, "alpha", 0.0f));
        this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.HintView.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                HintView.this.setVisibility(4);
                HintView.this.currentView = null;
                HintView.this.messageCell = null;
                HintView.this.animatorSet = null;
            }
        });
        this.animatorSet.setDuration(300L);
        this.animatorSet.start();
    }

    public void setText(CharSequence text) {
        this.textView.setText(text);
    }

    public ChatMessageCell getMessageCell() {
        return this.messageCell;
    }
}
