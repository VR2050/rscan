package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.SystemClock;
import android.os.Vibrator;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.os.CancellationSignal;
import androidx.exifinterface.media.ExifInterface;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.support.fingerprint.FingerprintManagerCompat;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PasscodeView extends FrameLayout {
    private static final int id_fingerprint_imageview = 1001;
    private static final int id_fingerprint_textview = 1000;
    private static final int[] ids = {R.attr.passcode_btn_0, R.attr.passcode_btn_1, R.attr.passcode_btn_2, R.attr.passcode_btn_3, R.attr.passcode_btn_4, R.attr.passcode_btn_5, R.attr.passcode_btn_6, R.attr.passcode_btn_7, R.attr.passcode_btn_8, R.attr.passcode_btn_9, R.attr.passcode_btn_backspace};
    private Drawable backgroundDrawable;
    private FrameLayout backgroundFrameLayout;
    private CancellationSignal cancellationSignal;
    private ImageView checkImage;
    private Runnable checkRunnable;
    private PasscodeViewDelegate delegate;
    private ImageView eraseView;
    private AlertDialog fingerprintDialog;
    private ImageView fingerprintImageView;
    private TextView fingerprintStatusTextView;
    private int keyboardHeight;
    private int lastValue;
    private ArrayList<TextView> lettersTextViews;
    private ArrayList<FrameLayout> numberFrameLayouts;
    private ArrayList<TextView> numberTextViews;
    private FrameLayout numbersFrameLayout;
    private TextView passcodeTextView;
    private EditTextBoldCursor passwordEditText;
    private AnimatingTextView passwordEditText2;
    private FrameLayout passwordFrameLayout;
    private android.graphics.Rect rect;
    private TextView retryTextView;
    private boolean selfCancelled;

    public interface PasscodeViewDelegate {
        void didAcceptedPassword();
    }

    private class AnimatingTextView extends FrameLayout {
        private String DOT;
        private ArrayList<TextView> characterTextViews;
        private AnimatorSet currentAnimation;
        private Runnable dotRunnable;
        private ArrayList<TextView> dotTextViews;
        private StringBuilder stringBuilder;

        public AnimatingTextView(Context context) {
            super(context);
            this.DOT = "•";
            this.characterTextViews = new ArrayList<>(4);
            this.dotTextViews = new ArrayList<>(4);
            this.stringBuilder = new StringBuilder(4);
            for (int a = 0; a < 4; a++) {
                TextView textView = new TextView(context);
                textView.setTextColor(-1);
                textView.setTextSize(1, 36.0f);
                textView.setGravity(17);
                textView.setAlpha(0.0f);
                textView.setPivotX(AndroidUtilities.dp(25.0f));
                textView.setPivotY(AndroidUtilities.dp(25.0f));
                addView(textView);
                FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) textView.getLayoutParams();
                layoutParams.width = AndroidUtilities.dp(50.0f);
                layoutParams.height = AndroidUtilities.dp(50.0f);
                layoutParams.gravity = 51;
                textView.setLayoutParams(layoutParams);
                this.characterTextViews.add(textView);
                TextView textView2 = new TextView(context);
                textView2.setTextColor(-1);
                textView2.setTextSize(1, 36.0f);
                textView2.setGravity(17);
                textView2.setAlpha(0.0f);
                textView2.setText(this.DOT);
                textView2.setPivotX(AndroidUtilities.dp(25.0f));
                textView2.setPivotY(AndroidUtilities.dp(25.0f));
                addView(textView2);
                FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) textView2.getLayoutParams();
                layoutParams2.width = AndroidUtilities.dp(50.0f);
                layoutParams2.height = AndroidUtilities.dp(50.0f);
                layoutParams2.gravity = 51;
                textView2.setLayoutParams(layoutParams2);
                this.dotTextViews.add(textView2);
            }
        }

        private int getXForTextView(int pos) {
            return (((getMeasuredWidth() - (this.stringBuilder.length() * AndroidUtilities.dp(30.0f))) / 2) + (AndroidUtilities.dp(30.0f) * pos)) - AndroidUtilities.dp(10.0f);
        }

        public void appendCharacter(String c) {
            if (this.stringBuilder.length() == 4) {
                return;
            }
            try {
                performHapticFeedback(3);
            } catch (Exception e) {
                FileLog.e(e);
            }
            ArrayList<Animator> animators = new ArrayList<>();
            final int newPos = this.stringBuilder.length();
            this.stringBuilder.append(c);
            TextView textView = this.characterTextViews.get(newPos);
            textView.setText(c);
            textView.setTranslationX(getXForTextView(newPos));
            animators.add(ObjectAnimator.ofFloat(textView, "scaleX", 0.0f, 1.0f));
            animators.add(ObjectAnimator.ofFloat(textView, "scaleY", 0.0f, 1.0f));
            animators.add(ObjectAnimator.ofFloat(textView, "alpha", 0.0f, 1.0f));
            animators.add(ObjectAnimator.ofFloat(textView, "translationY", AndroidUtilities.dp(20.0f), 0.0f));
            TextView textView2 = this.dotTextViews.get(newPos);
            textView2.setTranslationX(getXForTextView(newPos));
            textView2.setAlpha(0.0f);
            animators.add(ObjectAnimator.ofFloat(textView2, "scaleX", 0.0f, 1.0f));
            animators.add(ObjectAnimator.ofFloat(textView2, "scaleY", 0.0f, 1.0f));
            animators.add(ObjectAnimator.ofFloat(textView2, "translationY", AndroidUtilities.dp(20.0f), 0.0f));
            for (int a = newPos + 1; a < 4; a++) {
                TextView textView3 = this.characterTextViews.get(a);
                if (textView3.getAlpha() != 0.0f) {
                    animators.add(ObjectAnimator.ofFloat(textView3, "scaleX", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView3, "scaleY", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView3, "alpha", 0.0f));
                }
                TextView textView4 = this.dotTextViews.get(a);
                if (textView4.getAlpha() != 0.0f) {
                    animators.add(ObjectAnimator.ofFloat(textView4, "scaleX", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView4, "scaleY", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView4, "alpha", 0.0f));
                }
            }
            Runnable runnable = this.dotRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
            }
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.AnimatingTextView.1
                @Override // java.lang.Runnable
                public void run() {
                    if (AnimatingTextView.this.dotRunnable != this) {
                        return;
                    }
                    ArrayList<Animator> animators2 = new ArrayList<>();
                    TextView textView5 = (TextView) AnimatingTextView.this.characterTextViews.get(newPos);
                    animators2.add(ObjectAnimator.ofFloat(textView5, "scaleX", 0.0f));
                    animators2.add(ObjectAnimator.ofFloat(textView5, "scaleY", 0.0f));
                    animators2.add(ObjectAnimator.ofFloat(textView5, "alpha", 0.0f));
                    TextView textView6 = (TextView) AnimatingTextView.this.dotTextViews.get(newPos);
                    animators2.add(ObjectAnimator.ofFloat(textView6, "scaleX", 1.0f));
                    animators2.add(ObjectAnimator.ofFloat(textView6, "scaleY", 1.0f));
                    animators2.add(ObjectAnimator.ofFloat(textView6, "alpha", 1.0f));
                    AnimatingTextView.this.currentAnimation = new AnimatorSet();
                    AnimatingTextView.this.currentAnimation.setDuration(150L);
                    AnimatingTextView.this.currentAnimation.playTogether(animators2);
                    AnimatingTextView.this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.AnimatingTextView.1.1
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (AnimatingTextView.this.currentAnimation != null && AnimatingTextView.this.currentAnimation.equals(animation)) {
                                AnimatingTextView.this.currentAnimation = null;
                            }
                        }
                    });
                    AnimatingTextView.this.currentAnimation.start();
                }
            };
            this.dotRunnable = runnable2;
            AndroidUtilities.runOnUIThread(runnable2, 1500L);
            for (int a2 = 0; a2 < newPos; a2++) {
                TextView textView5 = this.characterTextViews.get(a2);
                animators.add(ObjectAnimator.ofFloat(textView5, "translationX", getXForTextView(a2)));
                animators.add(ObjectAnimator.ofFloat(textView5, "scaleX", 0.0f));
                animators.add(ObjectAnimator.ofFloat(textView5, "scaleY", 0.0f));
                animators.add(ObjectAnimator.ofFloat(textView5, "alpha", 0.0f));
                animators.add(ObjectAnimator.ofFloat(textView5, "translationY", 0.0f));
                TextView textView6 = this.dotTextViews.get(a2);
                animators.add(ObjectAnimator.ofFloat(textView6, "translationX", getXForTextView(a2)));
                animators.add(ObjectAnimator.ofFloat(textView6, "scaleX", 1.0f));
                animators.add(ObjectAnimator.ofFloat(textView6, "scaleY", 1.0f));
                animators.add(ObjectAnimator.ofFloat(textView6, "alpha", 1.0f));
                animators.add(ObjectAnimator.ofFloat(textView6, "translationY", 0.0f));
            }
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.currentAnimation = animatorSet2;
            animatorSet2.setDuration(150L);
            this.currentAnimation.playTogether(animators);
            this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.AnimatingTextView.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (AnimatingTextView.this.currentAnimation != null && AnimatingTextView.this.currentAnimation.equals(animation)) {
                        AnimatingTextView.this.currentAnimation = null;
                    }
                }
            });
            this.currentAnimation.start();
        }

        public String getString() {
            return this.stringBuilder.toString();
        }

        public int length() {
            return this.stringBuilder.length();
        }

        public void eraseLastCharacter() {
            if (this.stringBuilder.length() == 0) {
                return;
            }
            try {
                performHapticFeedback(3);
            } catch (Exception e) {
                FileLog.e(e);
            }
            ArrayList<Animator> animators = new ArrayList<>();
            int deletingPos = this.stringBuilder.length() - 1;
            if (deletingPos != 0) {
                this.stringBuilder.deleteCharAt(deletingPos);
            }
            for (int a = deletingPos; a < 4; a++) {
                TextView textView = this.characterTextViews.get(a);
                if (textView.getAlpha() != 0.0f) {
                    animators.add(ObjectAnimator.ofFloat(textView, "scaleX", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView, "scaleY", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView, "alpha", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView, "translationY", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView, "translationX", getXForTextView(a)));
                }
                TextView textView2 = this.dotTextViews.get(a);
                TextView textView3 = textView2;
                if (textView3.getAlpha() != 0.0f) {
                    animators.add(ObjectAnimator.ofFloat(textView3, "scaleX", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView3, "scaleY", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView3, "alpha", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView3, "translationY", 0.0f));
                    animators.add(ObjectAnimator.ofFloat(textView3, "translationX", getXForTextView(a)));
                }
            }
            if (deletingPos == 0) {
                this.stringBuilder.deleteCharAt(deletingPos);
            }
            for (int a2 = 0; a2 < deletingPos; a2++) {
                TextView textView4 = this.characterTextViews.get(a2);
                animators.add(ObjectAnimator.ofFloat(textView4, "translationX", getXForTextView(a2)));
                TextView textView5 = this.dotTextViews.get(a2);
                animators.add(ObjectAnimator.ofFloat(textView5, "translationX", getXForTextView(a2)));
            }
            Runnable runnable = this.dotRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.dotRunnable = null;
            }
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.currentAnimation = animatorSet2;
            animatorSet2.setDuration(150L);
            this.currentAnimation.playTogether(animators);
            this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.AnimatingTextView.3
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (AnimatingTextView.this.currentAnimation != null && AnimatingTextView.this.currentAnimation.equals(animation)) {
                        AnimatingTextView.this.currentAnimation = null;
                    }
                }
            });
            this.currentAnimation.start();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void eraseAllCharacters(boolean animated) {
            if (this.stringBuilder.length() == 0) {
                return;
            }
            Runnable runnable = this.dotRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.dotRunnable = null;
            }
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentAnimation = null;
            }
            StringBuilder sb = this.stringBuilder;
            sb.delete(0, sb.length());
            if (animated) {
                ArrayList<Animator> animators = new ArrayList<>();
                for (int a = 0; a < 4; a++) {
                    TextView textView = this.characterTextViews.get(a);
                    if (textView.getAlpha() != 0.0f) {
                        animators.add(ObjectAnimator.ofFloat(textView, "scaleX", 0.0f));
                        animators.add(ObjectAnimator.ofFloat(textView, "scaleY", 0.0f));
                        animators.add(ObjectAnimator.ofFloat(textView, "alpha", 0.0f));
                    }
                    TextView textView2 = this.dotTextViews.get(a);
                    if (textView2.getAlpha() != 0.0f) {
                        animators.add(ObjectAnimator.ofFloat(textView2, "scaleX", 0.0f));
                        animators.add(ObjectAnimator.ofFloat(textView2, "scaleY", 0.0f));
                        animators.add(ObjectAnimator.ofFloat(textView2, "alpha", 0.0f));
                    }
                }
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.currentAnimation = animatorSet2;
                animatorSet2.setDuration(150L);
                this.currentAnimation.playTogether(animators);
                this.currentAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.AnimatingTextView.4
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (AnimatingTextView.this.currentAnimation != null && AnimatingTextView.this.currentAnimation.equals(animation)) {
                            AnimatingTextView.this.currentAnimation = null;
                        }
                    }
                });
                this.currentAnimation.start();
                return;
            }
            for (int a2 = 0; a2 < 4; a2++) {
                this.characterTextViews.get(a2).setAlpha(0.0f);
                this.dotTextViews.get(a2).setAlpha(0.0f);
            }
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            Runnable runnable = this.dotRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.dotRunnable = null;
            }
            AnimatorSet animatorSet = this.currentAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentAnimation = null;
            }
            for (int a = 0; a < 4; a++) {
                if (a < this.stringBuilder.length()) {
                    TextView textView = this.characterTextViews.get(a);
                    textView.setAlpha(0.0f);
                    textView.setScaleX(1.0f);
                    textView.setScaleY(1.0f);
                    textView.setTranslationY(0.0f);
                    textView.setTranslationX(getXForTextView(a));
                    TextView textView2 = this.dotTextViews.get(a);
                    textView2.setAlpha(1.0f);
                    textView2.setScaleX(1.0f);
                    textView2.setScaleY(1.0f);
                    textView2.setTranslationY(0.0f);
                    textView2.setTranslationX(getXForTextView(a));
                } else {
                    this.characterTextViews.get(a).setAlpha(0.0f);
                    this.dotTextViews.get(a).setAlpha(0.0f);
                }
            }
            super.onLayout(changed, left, top, right, bottom);
        }
    }

    public PasscodeView(Context context) {
        super(context);
        char c = 0;
        this.keyboardHeight = 0;
        this.rect = new android.graphics.Rect();
        this.checkRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.6
            @Override // java.lang.Runnable
            public void run() {
                PasscodeView.this.checkRetryTextView();
                AndroidUtilities.runOnUIThread(PasscodeView.this.checkRunnable, 100L);
            }
        };
        setWillNotDraw(false);
        setVisibility(8);
        FrameLayout frameLayout = new FrameLayout(context);
        this.backgroundFrameLayout = frameLayout;
        addView(frameLayout);
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.backgroundFrameLayout.getLayoutParams();
        int i = -1;
        layoutParams.width = -1;
        layoutParams.height = -1;
        this.backgroundFrameLayout.setLayoutParams(layoutParams);
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.passwordFrameLayout = frameLayout2;
        addView(frameLayout2);
        FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) this.passwordFrameLayout.getLayoutParams();
        layoutParams2.width = -1;
        layoutParams2.height = -1;
        layoutParams2.gravity = 51;
        this.passwordFrameLayout.setLayoutParams(layoutParams2);
        ImageView imageView = new ImageView(context);
        imageView.setScaleType(ImageView.ScaleType.FIT_XY);
        imageView.setImageResource(R.drawable.passcode_logo);
        this.passwordFrameLayout.addView(imageView);
        FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) imageView.getLayoutParams();
        if (AndroidUtilities.density < 1.0f) {
            layoutParams3.width = AndroidUtilities.dp(30.0f);
            layoutParams3.height = AndroidUtilities.dp(30.0f);
        } else {
            layoutParams3.width = AndroidUtilities.dp(40.0f);
            layoutParams3.height = AndroidUtilities.dp(40.0f);
        }
        layoutParams3.gravity = 81;
        layoutParams3.bottomMargin = AndroidUtilities.dp(100.0f);
        imageView.setLayoutParams(layoutParams3);
        TextView textView = new TextView(context);
        this.passcodeTextView = textView;
        textView.setTextColor(-1);
        this.passcodeTextView.setTextSize(1, 14.0f);
        this.passcodeTextView.setGravity(1);
        this.passwordFrameLayout.addView(this.passcodeTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 81, 0.0f, 0.0f, 0.0f, 62.0f));
        TextView textView2 = new TextView(context);
        this.retryTextView = textView2;
        textView2.setTextColor(-1);
        this.retryTextView.setTextSize(1, 15.0f);
        this.retryTextView.setGravity(1);
        this.retryTextView.setVisibility(4);
        addView(this.retryTextView, LayoutHelper.createFrame(-2, -2, 17));
        AnimatingTextView animatingTextView = new AnimatingTextView(context);
        this.passwordEditText2 = animatingTextView;
        this.passwordFrameLayout.addView(animatingTextView);
        FrameLayout.LayoutParams layoutParams4 = (FrameLayout.LayoutParams) this.passwordEditText2.getLayoutParams();
        layoutParams4.height = -2;
        layoutParams4.width = -1;
        layoutParams4.leftMargin = AndroidUtilities.dp(70.0f);
        layoutParams4.rightMargin = AndroidUtilities.dp(70.0f);
        layoutParams4.bottomMargin = AndroidUtilities.dp(6.0f);
        layoutParams4.gravity = 81;
        this.passwordEditText2.setLayoutParams(layoutParams4);
        EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
        this.passwordEditText = editTextBoldCursor;
        float f = 36.0f;
        editTextBoldCursor.setTextSize(1, 36.0f);
        this.passwordEditText.setTextColor(-1);
        this.passwordEditText.setMaxLines(1);
        this.passwordEditText.setLines(1);
        this.passwordEditText.setGravity(1);
        this.passwordEditText.setSingleLine(true);
        this.passwordEditText.setImeOptions(6);
        this.passwordEditText.setTypeface(Typeface.DEFAULT);
        this.passwordEditText.setBackgroundDrawable(null);
        this.passwordEditText.setCursorColor(-1);
        this.passwordEditText.setCursorSize(AndroidUtilities.dp(32.0f));
        this.passwordFrameLayout.addView(this.passwordEditText);
        FrameLayout.LayoutParams layoutParams5 = (FrameLayout.LayoutParams) this.passwordEditText.getLayoutParams();
        layoutParams5.height = -2;
        layoutParams5.width = -1;
        layoutParams5.leftMargin = AndroidUtilities.dp(70.0f);
        layoutParams5.rightMargin = AndroidUtilities.dp(70.0f);
        layoutParams5.gravity = 81;
        this.passwordEditText.setLayoutParams(layoutParams5);
        this.passwordEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$jGmp631Y6rmoC1mCgqr9o_OIuUw
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView3, int i2, KeyEvent keyEvent) {
                return this.f$0.lambda$new$0$PasscodeView(textView3, i2, keyEvent);
            }
        });
        this.passwordEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.1
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                if (PasscodeView.this.passwordEditText.length() == 4 && SharedConfig.passcodeType == 0) {
                    PasscodeView.this.processDone(false);
                }
            }
        });
        this.passwordEditText.setCustomSelectionActionModeCallback(new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.2
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
        ImageView imageView2 = new ImageView(context);
        this.checkImage = imageView2;
        imageView2.setImageResource(R.drawable.passcode_check);
        this.checkImage.setScaleType(ImageView.ScaleType.CENTER);
        this.checkImage.setBackgroundResource(R.drawable.bar_selector_lock);
        this.passwordFrameLayout.addView(this.checkImage);
        FrameLayout.LayoutParams layoutParams6 = (FrameLayout.LayoutParams) this.checkImage.getLayoutParams();
        layoutParams6.width = AndroidUtilities.dp(60.0f);
        layoutParams6.height = AndroidUtilities.dp(60.0f);
        layoutParams6.bottomMargin = AndroidUtilities.dp(4.0f);
        layoutParams6.rightMargin = AndroidUtilities.dp(10.0f);
        layoutParams6.gravity = 85;
        this.checkImage.setLayoutParams(layoutParams6);
        this.checkImage.setContentDescription(LocaleController.getString("Done", R.string.Done));
        this.checkImage.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$Cro-L22AvYyG6L113p2tM23NnnA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$1$PasscodeView(view);
            }
        });
        FrameLayout lineFrameLayout = new FrameLayout(context);
        lineFrameLayout.setBackgroundColor(654311423);
        this.passwordFrameLayout.addView(lineFrameLayout);
        FrameLayout.LayoutParams layoutParams7 = (FrameLayout.LayoutParams) lineFrameLayout.getLayoutParams();
        layoutParams7.width = -1;
        layoutParams7.height = AndroidUtilities.dp(1.0f);
        layoutParams7.gravity = 83;
        layoutParams7.leftMargin = AndroidUtilities.dp(20.0f);
        layoutParams7.rightMargin = AndroidUtilities.dp(20.0f);
        lineFrameLayout.setLayoutParams(layoutParams7);
        FrameLayout frameLayout3 = new FrameLayout(context);
        this.numbersFrameLayout = frameLayout3;
        addView(frameLayout3);
        FrameLayout.LayoutParams layoutParams8 = (FrameLayout.LayoutParams) this.numbersFrameLayout.getLayoutParams();
        layoutParams8.width = -1;
        layoutParams8.height = -1;
        layoutParams8.gravity = 51;
        this.numbersFrameLayout.setLayoutParams(layoutParams8);
        int i2 = 10;
        this.lettersTextViews = new ArrayList<>(10);
        this.numberTextViews = new ArrayList<>(10);
        this.numberFrameLayouts = new ArrayList<>(10);
        int a = 0;
        while (a < i2) {
            TextView textView3 = new TextView(context);
            textView3.setTextColor(i);
            textView3.setTextSize(1, f);
            textView3.setGravity(17);
            Locale locale = Locale.US;
            Object[] objArr = new Object[1];
            objArr[c] = Integer.valueOf(a);
            textView3.setText(String.format(locale, "%d", objArr));
            this.numbersFrameLayout.addView(textView3);
            FrameLayout.LayoutParams layoutParams9 = (FrameLayout.LayoutParams) textView3.getLayoutParams();
            layoutParams9.width = AndroidUtilities.dp(50.0f);
            layoutParams9.height = AndroidUtilities.dp(50.0f);
            layoutParams9.gravity = 51;
            textView3.setLayoutParams(layoutParams9);
            textView3.setImportantForAccessibility(2);
            this.numberTextViews.add(textView3);
            TextView textView4 = new TextView(context);
            textView4.setTextSize(1, 12.0f);
            textView4.setTextColor(Integer.MAX_VALUE);
            textView4.setGravity(17);
            this.numbersFrameLayout.addView(textView4);
            FrameLayout.LayoutParams layoutParams10 = (FrameLayout.LayoutParams) textView4.getLayoutParams();
            layoutParams10.width = AndroidUtilities.dp(50.0f);
            layoutParams10.height = AndroidUtilities.dp(20.0f);
            layoutParams10.gravity = 51;
            textView4.setLayoutParams(layoutParams10);
            textView4.setImportantForAccessibility(2);
            if (a == 0) {
                textView4.setText(Marker.ANY_NON_NULL_MARKER);
            } else {
                switch (a) {
                    case 2:
                        textView4.setText("ABC");
                        break;
                    case 3:
                        textView4.setText("DEF");
                        break;
                    case 4:
                        textView4.setText("GHI");
                        break;
                    case 5:
                        textView4.setText("JKL");
                        break;
                    case 6:
                        textView4.setText("MNO");
                        break;
                    case 7:
                        textView4.setText("PQRS");
                        break;
                    case 8:
                        textView4.setText("TUV");
                        break;
                    case 9:
                        textView4.setText("WXYZ");
                        break;
                }
            }
            this.lettersTextViews.add(textView4);
            a++;
            c = 0;
            i = -1;
            i2 = 10;
            f = 36.0f;
        }
        ImageView imageView3 = new ImageView(context);
        this.eraseView = imageView3;
        imageView3.setScaleType(ImageView.ScaleType.CENTER);
        this.eraseView.setImageResource(R.drawable.passcode_delete);
        this.numbersFrameLayout.addView(this.eraseView);
        FrameLayout.LayoutParams layoutParams11 = (FrameLayout.LayoutParams) this.eraseView.getLayoutParams();
        layoutParams11.width = AndroidUtilities.dp(50.0f);
        layoutParams11.height = AndroidUtilities.dp(50.0f);
        layoutParams11.gravity = 51;
        this.eraseView.setLayoutParams(layoutParams11);
        for (int a2 = 0; a2 < 11; a2++) {
            FrameLayout frameLayout4 = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.3
                @Override // android.view.View
                public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
                    super.onInitializeAccessibilityNodeInfo(info);
                    info.setClassName("android.widget.Button");
                }
            };
            frameLayout4.setBackgroundResource(R.drawable.bar_selector_lock);
            frameLayout4.setTag(Integer.valueOf(a2));
            if (a2 == 10) {
                frameLayout4.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$A7TABwHgjyrHCED0Uoevd8oFxYo
                    @Override // android.view.View.OnLongClickListener
                    public final boolean onLongClick(View view) {
                        return this.f$0.lambda$new$2$PasscodeView(view);
                    }
                });
                frameLayout4.setContentDescription(LocaleController.getString("AccDescrBackspace", R.string.AccDescrBackspace));
                setNextFocus(frameLayout4, R.attr.passcode_btn_1);
            } else {
                frameLayout4.setContentDescription(a2 + "");
                if (a2 == 0) {
                    setNextFocus(frameLayout4, R.attr.passcode_btn_backspace);
                } else if (a2 == 9) {
                    setNextFocus(frameLayout4, R.attr.passcode_btn_0);
                } else {
                    setNextFocus(frameLayout4, ids[a2 + 1]);
                }
            }
            frameLayout4.setId(ids[a2]);
            frameLayout4.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$KCKaKU16cE8DuIp5zGtmHiRzmSs
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$3$PasscodeView(view);
                }
            });
            this.numberFrameLayouts.add(frameLayout4);
        }
        for (int a3 = 10; a3 >= 0; a3--) {
            FrameLayout frameLayout5 = this.numberFrameLayouts.get(a3);
            this.numbersFrameLayout.addView(frameLayout5);
            FrameLayout.LayoutParams layoutParams12 = (FrameLayout.LayoutParams) frameLayout5.getLayoutParams();
            layoutParams12.width = AndroidUtilities.dp(100.0f);
            layoutParams12.height = AndroidUtilities.dp(100.0f);
            layoutParams12.gravity = 51;
            frameLayout5.setLayoutParams(layoutParams12);
        }
    }

    public /* synthetic */ boolean lambda$new$0$PasscodeView(TextView textView, int i, KeyEvent keyEvent) {
        if (i != 6) {
            return false;
        }
        processDone(false);
        return true;
    }

    public /* synthetic */ void lambda$new$1$PasscodeView(View v) {
        processDone(false);
    }

    public /* synthetic */ boolean lambda$new$2$PasscodeView(View v) {
        this.passwordEditText.setText("");
        this.passwordEditText2.eraseAllCharacters(true);
        return true;
    }

    public /* synthetic */ void lambda$new$3$PasscodeView(View v) {
        int tag = ((Integer) v.getTag()).intValue();
        switch (tag) {
            case 0:
                this.passwordEditText2.appendCharacter("0");
                break;
            case 1:
                this.passwordEditText2.appendCharacter("1");
                break;
            case 2:
                this.passwordEditText2.appendCharacter("2");
                break;
            case 3:
                this.passwordEditText2.appendCharacter(ExifInterface.GPS_MEASUREMENT_3D);
                break;
            case 4:
                this.passwordEditText2.appendCharacter("4");
                break;
            case 5:
                this.passwordEditText2.appendCharacter("5");
                break;
            case 6:
                this.passwordEditText2.appendCharacter("6");
                break;
            case 7:
                this.passwordEditText2.appendCharacter("7");
                break;
            case 8:
                this.passwordEditText2.appendCharacter("8");
                break;
            case 9:
                this.passwordEditText2.appendCharacter("9");
                break;
            case 10:
                this.passwordEditText2.eraseLastCharacter();
                break;
        }
        if (this.passwordEditText2.length() == 4) {
            processDone(false);
        }
    }

    private void setNextFocus(View view, int nextId) {
        view.setNextFocusForwardId(nextId);
        if (Build.VERSION.SDK_INT >= 22) {
            view.setAccessibilityTraversalBefore(nextId);
        }
    }

    public void setDelegate(PasscodeViewDelegate delegate) {
        this.delegate = delegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processDone(boolean fingerprint) {
        if (!fingerprint) {
            if (SharedConfig.passcodeRetryInMs > 0) {
                return;
            }
            String password = "";
            if (SharedConfig.passcodeType != 0) {
                if (SharedConfig.passcodeType == 1) {
                    password = this.passwordEditText.getText().toString();
                }
            } else {
                password = this.passwordEditText2.getString();
            }
            if (password.length() == 0) {
                onPasscodeError();
                return;
            }
            if (!SharedConfig.checkPasscode(password)) {
                SharedConfig.increaseBadPasscodeTries();
                if (SharedConfig.passcodeRetryInMs > 0) {
                    checkRetryTextView();
                }
                this.passwordEditText.setText("");
                this.passwordEditText2.eraseAllCharacters(true);
                onPasscodeError();
                return;
            }
        }
        SharedConfig.badPasscodeTries = 0;
        this.passwordEditText.clearFocus();
        AndroidUtilities.hideKeyboard(this.passwordEditText);
        AnimatorSet AnimatorSet = new AnimatorSet();
        AnimatorSet.setDuration(200L);
        AnimatorSet.playTogether(ObjectAnimator.ofFloat(this, "translationY", AndroidUtilities.dp(20.0f)), ObjectAnimator.ofFloat(this, "alpha", AndroidUtilities.dp(0.0f)));
        AnimatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.4
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                PasscodeView.this.setVisibility(8);
            }
        });
        AnimatorSet.start();
        SharedConfig.appLocked = false;
        SharedConfig.saveConfig();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didSetPasscode, new Object[0]);
        setOnTouchListener(null);
        PasscodeViewDelegate passcodeViewDelegate = this.delegate;
        if (passcodeViewDelegate != null) {
            passcodeViewDelegate.didAcceptedPassword();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void shakeTextView(final float x, final int num) {
        if (num == 6) {
            return;
        }
        AnimatorSet AnimatorSet = new AnimatorSet();
        AnimatorSet.playTogether(ObjectAnimator.ofFloat(this.passcodeTextView, "translationX", AndroidUtilities.dp(x)));
        AnimatorSet.setDuration(50L);
        AnimatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                PasscodeView.this.shakeTextView(num == 5 ? 0.0f : -x, num + 1);
            }
        });
        AnimatorSet.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkRetryTextView() {
        long currentTime = SystemClock.elapsedRealtime();
        if (currentTime > SharedConfig.lastUptimeMillis) {
            SharedConfig.passcodeRetryInMs -= currentTime - SharedConfig.lastUptimeMillis;
            if (SharedConfig.passcodeRetryInMs < 0) {
                SharedConfig.passcodeRetryInMs = 0L;
            }
        }
        SharedConfig.lastUptimeMillis = currentTime;
        SharedConfig.saveConfig();
        if (SharedConfig.passcodeRetryInMs > 0) {
            int value = Math.max(1, (int) Math.ceil(SharedConfig.passcodeRetryInMs / 1000.0d));
            if (value != this.lastValue) {
                this.retryTextView.setText(LocaleController.formatString("TooManyTries", R.string.TooManyTries, LocaleController.formatPluralString("Seconds", value)));
                this.lastValue = value;
            }
            if (this.retryTextView.getVisibility() != 0) {
                this.retryTextView.setVisibility(0);
                this.passwordFrameLayout.setVisibility(4);
                if (this.numbersFrameLayout.getVisibility() == 0) {
                    this.numbersFrameLayout.setVisibility(4);
                }
                AndroidUtilities.hideKeyboard(this.passwordEditText);
                AndroidUtilities.cancelRunOnUIThread(this.checkRunnable);
                AndroidUtilities.runOnUIThread(this.checkRunnable, 100L);
                return;
            }
            return;
        }
        AndroidUtilities.cancelRunOnUIThread(this.checkRunnable);
        if (this.passwordFrameLayout.getVisibility() != 0) {
            this.retryTextView.setVisibility(4);
            this.passwordFrameLayout.setVisibility(0);
            if (SharedConfig.passcodeType == 0) {
                this.numbersFrameLayout.setVisibility(0);
            } else if (SharedConfig.passcodeType == 1) {
                AndroidUtilities.showKeyboard(this.passwordEditText);
            }
        }
    }

    private void onPasscodeError() {
        Vibrator v = (Vibrator) getContext().getSystemService("vibrator");
        if (v != null) {
            v.vibrate(200L);
        }
        shakeTextView(2.0f, 0);
    }

    public void onResume() {
        checkRetryTextView();
        if (this.retryTextView.getVisibility() != 0) {
            if (SharedConfig.passcodeType == 1) {
                EditTextBoldCursor editTextBoldCursor = this.passwordEditText;
                if (editTextBoldCursor != null) {
                    editTextBoldCursor.requestFocus();
                    AndroidUtilities.showKeyboard(this.passwordEditText);
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$yDLLlZQQGiPIs15FUPD_saoo8dc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onResume$4$PasscodeView();
                    }
                }, 200L);
            }
            checkFingerprint();
        }
    }

    public /* synthetic */ void lambda$onResume$4$PasscodeView() {
        EditTextBoldCursor editTextBoldCursor;
        if (this.retryTextView.getVisibility() != 0 && (editTextBoldCursor = this.passwordEditText) != null) {
            editTextBoldCursor.requestFocus();
            AndroidUtilities.showKeyboard(this.passwordEditText);
        }
    }

    public void onPause() {
        AndroidUtilities.cancelRunOnUIThread(this.checkRunnable);
        AlertDialog alertDialog = this.fingerprintDialog;
        if (alertDialog != null) {
            try {
                if (alertDialog.isShowing()) {
                    this.fingerprintDialog.dismiss();
                }
                this.fingerprintDialog = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= 23 && this.cancellationSignal != null) {
                this.cancellationSignal.cancel();
                this.cancellationSignal = null;
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    private void checkFingerprint() {
        Activity parentActivity = (Activity) getContext();
        if (Build.VERSION.SDK_INT >= 23 && parentActivity != null && SharedConfig.useFingerprint && !ApplicationLoader.mainInterfacePaused) {
            try {
                if (this.fingerprintDialog != null) {
                    if (this.fingerprintDialog.isShowing()) {
                        return;
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            try {
                FingerprintManagerCompat fingerprintManager = FingerprintManagerCompat.from(ApplicationLoader.applicationContext);
                if (fingerprintManager.isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints()) {
                    RelativeLayout relativeLayout = new RelativeLayout(getContext());
                    relativeLayout.setPadding(AndroidUtilities.dp(24.0f), 0, AndroidUtilities.dp(24.0f), 0);
                    TextView fingerprintTextView = new TextView(getContext());
                    fingerprintTextView.setId(1000);
                    fingerprintTextView.setTextAppearance(android.R.style.TextAppearance.Material.Subhead);
                    fingerprintTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                    fingerprintTextView.setText(LocaleController.getString("FingerprintInfo", R.string.FingerprintInfo));
                    relativeLayout.addView(fingerprintTextView);
                    RelativeLayout.LayoutParams layoutParams = LayoutHelper.createRelative(-2, -2);
                    layoutParams.addRule(10);
                    layoutParams.addRule(20);
                    fingerprintTextView.setLayoutParams(layoutParams);
                    ImageView imageView = new ImageView(getContext());
                    this.fingerprintImageView = imageView;
                    imageView.setImageResource(R.drawable.ic_fp_40px);
                    this.fingerprintImageView.setId(1001);
                    relativeLayout.addView(this.fingerprintImageView, LayoutHelper.createRelative(-2.0f, -2.0f, 0, 20, 0, 0, 20, 3, 1000));
                    TextView textView = new TextView(getContext());
                    this.fingerprintStatusTextView = textView;
                    textView.setGravity(16);
                    this.fingerprintStatusTextView.setText(LocaleController.getString("FingerprintHelp", R.string.FingerprintHelp));
                    this.fingerprintStatusTextView.setTextAppearance(android.R.style.TextAppearance.Material.Body1);
                    this.fingerprintStatusTextView.setTextColor(Theme.getColor(Theme.key_dialogTextBlack) & 1124073471);
                    relativeLayout.addView(this.fingerprintStatusTextView);
                    RelativeLayout.LayoutParams layoutParams2 = LayoutHelper.createRelative(-2, -2);
                    layoutParams2.setMarginStart(AndroidUtilities.dp(16.0f));
                    layoutParams2.addRule(8, 1001);
                    layoutParams2.addRule(6, 1001);
                    layoutParams2.addRule(17, 1001);
                    this.fingerprintStatusTextView.setLayoutParams(layoutParams2);
                    AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                    builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    builder.setView(relativeLayout);
                    builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    builder.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$8zRcGQ5RJKqdWn1-TrKzJyAg4QQ
                        @Override // android.content.DialogInterface.OnDismissListener
                        public final void onDismiss(DialogInterface dialogInterface) {
                            this.f$0.lambda$checkFingerprint$5$PasscodeView(dialogInterface);
                        }
                    });
                    if (this.fingerprintDialog != null) {
                        try {
                            if (this.fingerprintDialog.isShowing()) {
                                this.fingerprintDialog.dismiss();
                            }
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                    }
                    this.fingerprintDialog = builder.show();
                    CancellationSignal cancellationSignal = new CancellationSignal();
                    this.cancellationSignal = cancellationSignal;
                    this.selfCancelled = false;
                    fingerprintManager.authenticate(null, 0, cancellationSignal, new FingerprintManagerCompat.AuthenticationCallback() { // from class: im.uwrkaxlmjj.ui.components.PasscodeView.7
                        @Override // im.uwrkaxlmjj.messenger.support.fingerprint.FingerprintManagerCompat.AuthenticationCallback
                        public void onAuthenticationError(int errMsgId, CharSequence errString) {
                            if (!PasscodeView.this.selfCancelled && errMsgId != 5) {
                                PasscodeView.this.showFingerprintError(errString);
                            }
                        }

                        @Override // im.uwrkaxlmjj.messenger.support.fingerprint.FingerprintManagerCompat.AuthenticationCallback
                        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                            PasscodeView.this.showFingerprintError(helpString);
                        }

                        @Override // im.uwrkaxlmjj.messenger.support.fingerprint.FingerprintManagerCompat.AuthenticationCallback
                        public void onAuthenticationFailed() {
                            PasscodeView.this.showFingerprintError(LocaleController.getString("FingerprintNotRecognized", R.string.FingerprintNotRecognized));
                        }

                        @Override // im.uwrkaxlmjj.messenger.support.fingerprint.FingerprintManagerCompat.AuthenticationCallback
                        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                            try {
                                if (PasscodeView.this.fingerprintDialog.isShowing()) {
                                    PasscodeView.this.fingerprintDialog.dismiss();
                                }
                            } catch (Exception e3) {
                                FileLog.e(e3);
                            }
                            PasscodeView.this.fingerprintDialog = null;
                            PasscodeView.this.processDone(true);
                        }
                    }, null);
                }
            } catch (Throwable th) {
            }
        }
    }

    public /* synthetic */ void lambda$checkFingerprint$5$PasscodeView(DialogInterface dialog) {
        CancellationSignal cancellationSignal = this.cancellationSignal;
        if (cancellationSignal != null) {
            this.selfCancelled = true;
            try {
                cancellationSignal.cancel();
            } catch (Exception e) {
                FileLog.e(e);
            }
            this.cancellationSignal = null;
        }
    }

    public void onShow() {
        View currentFocus;
        EditTextBoldCursor editTextBoldCursor;
        checkRetryTextView();
        Activity parentActivity = (Activity) getContext();
        if (SharedConfig.passcodeType == 1) {
            if (this.retryTextView.getVisibility() != 0 && (editTextBoldCursor = this.passwordEditText) != null) {
                editTextBoldCursor.requestFocus();
                AndroidUtilities.showKeyboard(this.passwordEditText);
            }
        } else if (parentActivity != null && (currentFocus = parentActivity.getCurrentFocus()) != null) {
            currentFocus.clearFocus();
            AndroidUtilities.hideKeyboard(((Activity) getContext()).getCurrentFocus());
        }
        if (this.retryTextView.getVisibility() != 0) {
            checkFingerprint();
        }
        if (getVisibility() == 0) {
            return;
        }
        setAlpha(1.0f);
        setTranslationY(0.0f);
        if (Theme.isCustomTheme()) {
            this.backgroundDrawable = Theme.getCachedWallpaper();
            this.backgroundFrameLayout.setBackgroundColor(-1090519040);
        } else {
            long selectedBackground = Theme.getSelectedBackgroundId();
            if (selectedBackground == Theme.DEFAULT_BACKGROUND_ID) {
                this.backgroundFrameLayout.setBackgroundColor(-11436898);
            } else {
                Drawable cachedWallpaper = Theme.getCachedWallpaper();
                this.backgroundDrawable = cachedWallpaper;
                if (cachedWallpaper != null) {
                    this.backgroundFrameLayout.setBackgroundColor(-1090519040);
                } else {
                    this.backgroundFrameLayout.setBackgroundColor(-11436898);
                }
            }
        }
        this.passcodeTextView.setText(LocaleController.getString("EnterYourPasscode", R.string.EnterYourPasscode));
        if (SharedConfig.passcodeType == 0) {
            if (this.retryTextView.getVisibility() != 0) {
                this.numbersFrameLayout.setVisibility(0);
            }
            this.passwordEditText.setVisibility(8);
            this.passwordEditText2.setVisibility(0);
            this.checkImage.setVisibility(8);
        } else if (SharedConfig.passcodeType == 1) {
            this.passwordEditText.setFilters(new InputFilter[0]);
            this.passwordEditText.setInputType(TsExtractor.TS_STREAM_TYPE_AC3);
            this.numbersFrameLayout.setVisibility(8);
            this.passwordEditText.setFocusable(true);
            this.passwordEditText.setFocusableInTouchMode(true);
            this.passwordEditText.setVisibility(0);
            this.passwordEditText2.setVisibility(8);
            this.checkImage.setVisibility(0);
        }
        setVisibility(0);
        this.passwordEditText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        this.passwordEditText.setText("");
        this.passwordEditText2.eraseAllCharacters(false);
        setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PasscodeView$RV7SXvxyWNgTvUSlOd4v0SvAm90
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return PasscodeView.lambda$onShow$6(view, motionEvent);
            }
        });
    }

    static /* synthetic */ boolean lambda$onShow$6(View v, MotionEvent event) {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showFingerprintError(CharSequence error) {
        this.fingerprintImageView.setImageResource(R.drawable.ic_fingerprint_error);
        this.fingerprintStatusTextView.setText(error);
        this.fingerprintStatusTextView.setTextColor(-765666);
        Vibrator v = (Vibrator) getContext().getSystemService("vibrator");
        if (v != null) {
            v.vibrate(200L);
        }
        AndroidUtilities.shakeView(this.fingerprintStatusTextView, 2.0f, 0);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        FrameLayout.LayoutParams layoutParams;
        int num;
        FrameLayout.LayoutParams layoutParams2;
        int top;
        int width = View.MeasureSpec.getSize(widthMeasureSpec);
        int height = AndroidUtilities.displaySize.y - (Build.VERSION.SDK_INT >= 21 ? 0 : AndroidUtilities.statusBarHeight);
        if (!AndroidUtilities.isTablet() && getContext().getResources().getConfiguration().orientation == 2) {
            FrameLayout.LayoutParams layoutParams3 = (FrameLayout.LayoutParams) this.passwordFrameLayout.getLayoutParams();
            layoutParams3.width = SharedConfig.passcodeType == 0 ? width / 2 : width;
            layoutParams3.height = AndroidUtilities.dp(140.0f);
            layoutParams3.topMargin = (height - AndroidUtilities.dp(140.0f)) / 2;
            this.passwordFrameLayout.setLayoutParams(layoutParams3);
            layoutParams = (FrameLayout.LayoutParams) this.numbersFrameLayout.getLayoutParams();
            layoutParams.height = height;
            layoutParams.leftMargin = width / 2;
            layoutParams.topMargin = height - layoutParams.height;
            layoutParams.width = width / 2;
            this.numbersFrameLayout.setLayoutParams(layoutParams);
        } else {
            int top2 = 0;
            int left = 0;
            if (AndroidUtilities.isTablet()) {
                if (width > AndroidUtilities.dp(498.0f)) {
                    left = (width - AndroidUtilities.dp(498.0f)) / 2;
                    width = AndroidUtilities.dp(498.0f);
                }
                if (height > AndroidUtilities.dp(528.0f)) {
                    top2 = (height - AndroidUtilities.dp(528.0f)) / 2;
                    height = AndroidUtilities.dp(528.0f);
                }
            }
            FrameLayout.LayoutParams layoutParams4 = (FrameLayout.LayoutParams) this.passwordFrameLayout.getLayoutParams();
            layoutParams4.height = height / 3;
            layoutParams4.width = width;
            layoutParams4.topMargin = top2;
            layoutParams4.leftMargin = left;
            this.passwordFrameLayout.setTag(Integer.valueOf(top2));
            this.passwordFrameLayout.setLayoutParams(layoutParams4);
            FrameLayout.LayoutParams layoutParams5 = (FrameLayout.LayoutParams) this.numbersFrameLayout.getLayoutParams();
            layoutParams5.height = (height / 3) * 2;
            layoutParams5.leftMargin = left;
            layoutParams5.topMargin = (height - layoutParams5.height) + top2;
            layoutParams5.width = width;
            this.numbersFrameLayout.setLayoutParams(layoutParams5);
            layoutParams = layoutParams5;
        }
        int sizeBetweenNumbersX = (layoutParams.width - (AndroidUtilities.dp(50.0f) * 3)) / 4;
        int sizeBetweenNumbersY = (layoutParams.height - (AndroidUtilities.dp(50.0f) * 4)) / 5;
        for (int a = 0; a < 11; a++) {
            if (a == 0) {
                num = 10;
            } else if (a == 10) {
                num = 11;
            } else {
                num = a - 1;
            }
            int row = num / 3;
            int col = num % 3;
            if (a < 10) {
                TextView textView = this.numberTextViews.get(a);
                TextView textView1 = this.lettersTextViews.get(a);
                layoutParams2 = (FrameLayout.LayoutParams) textView.getLayoutParams();
                FrameLayout.LayoutParams layoutParams1 = (FrameLayout.LayoutParams) textView1.getLayoutParams();
                top = ((AndroidUtilities.dp(50.0f) + sizeBetweenNumbersY) * row) + sizeBetweenNumbersY;
                layoutParams2.topMargin = top;
                layoutParams1.topMargin = top;
                int iDp = ((AndroidUtilities.dp(50.0f) + sizeBetweenNumbersX) * col) + sizeBetweenNumbersX;
                layoutParams2.leftMargin = iDp;
                layoutParams1.leftMargin = iDp;
                layoutParams1.topMargin += AndroidUtilities.dp(40.0f);
                textView.setLayoutParams(layoutParams2);
                textView1.setLayoutParams(layoutParams1);
            } else {
                layoutParams2 = (FrameLayout.LayoutParams) this.eraseView.getLayoutParams();
                int top3 = ((AndroidUtilities.dp(50.0f) + sizeBetweenNumbersY) * row) + sizeBetweenNumbersY + AndroidUtilities.dp(8.0f);
                layoutParams2.topMargin = top3;
                layoutParams2.leftMargin = ((AndroidUtilities.dp(50.0f) + sizeBetweenNumbersX) * col) + sizeBetweenNumbersX;
                top = top3 - AndroidUtilities.dp(8.0f);
                this.eraseView.setLayoutParams(layoutParams2);
            }
            FrameLayout frameLayout = this.numberFrameLayouts.get(a);
            FrameLayout.LayoutParams layoutParams12 = (FrameLayout.LayoutParams) frameLayout.getLayoutParams();
            layoutParams12.topMargin = top - AndroidUtilities.dp(17.0f);
            layoutParams12.leftMargin = layoutParams2.leftMargin - AndroidUtilities.dp(25.0f);
            frameLayout.setLayoutParams(layoutParams12);
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        View rootView = getRootView();
        int usableViewHeight = (rootView.getHeight() - AndroidUtilities.statusBarHeight) - AndroidUtilities.getViewInset(rootView);
        getWindowVisibleDisplayFrame(this.rect);
        this.keyboardHeight = usableViewHeight - (this.rect.bottom - this.rect.top);
        if (SharedConfig.passcodeType == 1 && (AndroidUtilities.isTablet() || getContext().getResources().getConfiguration().orientation != 2)) {
            int t = 0;
            if (this.passwordFrameLayout.getTag() != null) {
                t = ((Integer) this.passwordFrameLayout.getTag()).intValue();
            }
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.passwordFrameLayout.getLayoutParams();
            layoutParams.topMargin = ((layoutParams.height + t) - (this.keyboardHeight / 2)) - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
            this.passwordFrameLayout.setLayoutParams(layoutParams);
        }
        super.onLayout(changed, left, top, right, bottom);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (getVisibility() != 0) {
            return;
        }
        Drawable drawable = this.backgroundDrawable;
        if (drawable != null) {
            if ((drawable instanceof ColorDrawable) || (drawable instanceof GradientDrawable)) {
                this.backgroundDrawable.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
                this.backgroundDrawable.draw(canvas);
                return;
            }
            float scaleX = getMeasuredWidth() / this.backgroundDrawable.getIntrinsicWidth();
            float scaleY = (getMeasuredHeight() + this.keyboardHeight) / this.backgroundDrawable.getIntrinsicHeight();
            float scale = scaleX < scaleY ? scaleY : scaleX;
            int width = (int) Math.ceil(this.backgroundDrawable.getIntrinsicWidth() * scale);
            int height = (int) Math.ceil(this.backgroundDrawable.getIntrinsicHeight() * scale);
            int x = (getMeasuredWidth() - width) / 2;
            int y = ((getMeasuredHeight() - height) + this.keyboardHeight) / 2;
            this.backgroundDrawable.setBounds(x, y, x + width, y + height);
            this.backgroundDrawable.draw(canvas);
            return;
        }
        super.onDraw(canvas);
    }
}
