package im.uwrkaxlmjj.ui.components;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.InputFilter;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextWatcher;
import android.text.style.ImageSpan;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.google.android.exoplayer2.C;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.EmojiView;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayoutPhoto;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhotoViewerCaptionEnterView extends FrameLayout implements NotificationCenter.NotificationCenterDelegate, SizeNotifierFrameLayoutPhoto.SizeNotifierFrameLayoutPhotoDelegate {
    float animationProgress;
    private int audioInterfaceState;
    private int captionMaxLength;
    private ActionMode currentActionMode;
    private PhotoViewerCaptionEnterViewDelegate delegate;
    private ImageView emojiButton;
    private int emojiPadding;
    private EmojiView emojiView;
    private boolean forceFloatingEmoji;
    private boolean innerTextChange;
    private int keyboardHeight;
    private int keyboardHeightLand;
    private boolean keyboardVisible;
    private int lastSizeChangeValue1;
    private boolean lastSizeChangeValue2;
    private String lengthText;
    private TextPaint lengthTextPaint;
    private EditTextCaption messageEditText;
    private AnimatorSet runningAnimation;
    private AnimatorSet runningAnimation2;
    private ObjectAnimator runningAnimationAudio;
    private int runningAnimationType;
    private SizeNotifierFrameLayoutPhoto sizeNotifierLayout;
    private View windowView;

    public interface PhotoViewerCaptionEnterViewDelegate {
        void onCaptionEnter();

        void onTextChanged(CharSequence charSequence);

        void onWindowSizeChanged(int i);
    }

    public PhotoViewerCaptionEnterView(Context context, SizeNotifierFrameLayoutPhoto parent, View window) {
        super(context);
        this.captionMaxLength = 1024;
        this.animationProgress = 0.0f;
        setWillNotDraw(false);
        setBackgroundColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
        setFocusable(true);
        setFocusableInTouchMode(true);
        this.windowView = window;
        this.sizeNotifierLayout = parent;
        LinearLayout textFieldContainer = new LinearLayout(context);
        textFieldContainer.setOrientation(0);
        addView(textFieldContainer, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 2.0f, 0.0f, 0.0f, 0.0f));
        FrameLayout frameLayout = new FrameLayout(context);
        textFieldContainer.addView(frameLayout, LayoutHelper.createLinear(0, -2, 1.0f));
        ImageView imageView = new ImageView(context);
        this.emojiButton = imageView;
        imageView.setImageResource(R.drawable.input_smile);
        this.emojiButton.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        this.emojiButton.setPadding(AndroidUtilities.dp(4.0f), AndroidUtilities.dp(1.0f), 0, 0);
        frameLayout.addView(this.emojiButton, LayoutHelper.createFrame(48, 48, 83));
        this.emojiButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoViewerCaptionEnterView$Hq4Vyub5JpRnuNRlkLJkRimVzcQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$0$PhotoViewerCaptionEnterView(view);
            }
        });
        this.emojiButton.setContentDescription(LocaleController.getString("Emoji", R.string.Emoji));
        TextPaint textPaint = new TextPaint(1);
        this.lengthTextPaint = textPaint;
        textPaint.setTextSize(AndroidUtilities.dp(13.0f));
        this.lengthTextPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.lengthTextPaint.setColor(-2500135);
        this.messageEditText = new EditTextCaption(context) { // from class: im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.1
            @Override // im.uwrkaxlmjj.ui.components.EditTextCaption, im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.widget.TextView, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                try {
                    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                } catch (Exception e) {
                    setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), AndroidUtilities.dp(51.0f));
                    FileLog.e(e);
                }
            }

            @Override // android.widget.TextView
            protected void onSelectionChanged(int selStart, int selEnd) {
                super.onSelectionChanged(selStart, selEnd);
                if (selStart != selEnd) {
                    fixHandleView(false);
                } else {
                    fixHandleView(true);
                }
            }
        };
        if (Build.VERSION.SDK_INT >= 23 && this.windowView != null) {
            this.messageEditText.setCustomSelectionActionModeCallback(new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.2
                @Override // android.view.ActionMode.Callback
                public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                    PhotoViewerCaptionEnterView.this.currentActionMode = mode;
                    return true;
                }

                @Override // android.view.ActionMode.Callback
                public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                    int i = Build.VERSION.SDK_INT;
                    return true;
                }

                @Override // android.view.ActionMode.Callback
                public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                    return false;
                }

                @Override // android.view.ActionMode.Callback
                public void onDestroyActionMode(ActionMode mode) {
                    if (PhotoViewerCaptionEnterView.this.currentActionMode == mode) {
                        PhotoViewerCaptionEnterView.this.currentActionMode = null;
                    }
                }
            });
            this.messageEditText.setCustomInsertionActionModeCallback(new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.3
                @Override // android.view.ActionMode.Callback
                public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                    PhotoViewerCaptionEnterView.this.currentActionMode = mode;
                    return true;
                }

                @Override // android.view.ActionMode.Callback
                public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                    int i = Build.VERSION.SDK_INT;
                    return true;
                }

                @Override // android.view.ActionMode.Callback
                public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                    return false;
                }

                @Override // android.view.ActionMode.Callback
                public void onDestroyActionMode(ActionMode mode) {
                    if (PhotoViewerCaptionEnterView.this.currentActionMode == mode) {
                        PhotoViewerCaptionEnterView.this.currentActionMode = null;
                    }
                }
            });
        }
        this.messageEditText.setHint(LocaleController.getString("AddCaption", R.string.AddCaption));
        this.messageEditText.setImeOptions(C.ENCODING_PCM_MU_LAW);
        EditTextCaption editTextCaption = this.messageEditText;
        editTextCaption.setInputType(editTextCaption.getInputType() | 16384);
        this.messageEditText.setMaxLines(4);
        this.messageEditText.setHorizontallyScrolling(false);
        this.messageEditText.setTextSize(1, 18.0f);
        this.messageEditText.setGravity(80);
        this.messageEditText.setPadding(0, AndroidUtilities.dp(11.0f), 0, AndroidUtilities.dp(12.0f));
        this.messageEditText.setBackgroundDrawable(null);
        this.messageEditText.setCursorColor(-1);
        this.messageEditText.setCursorSize(AndroidUtilities.dp(20.0f));
        this.messageEditText.setTextColor(-1);
        this.messageEditText.setHintTextColor(-1291845633);
        InputFilter[] inputFilters = {new InputFilter.LengthFilter(this.captionMaxLength)};
        this.messageEditText.setFilters(inputFilters);
        frameLayout.addView(this.messageEditText, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 52.0f, 0.0f, 6.0f, 0.0f));
        this.messageEditText.setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoViewerCaptionEnterView$49p-JT6XaRMdKlB9DaWZO_fFNLc
            @Override // android.view.View.OnKeyListener
            public final boolean onKey(View view, int i, KeyEvent keyEvent) {
                return this.f$0.lambda$new$1$PhotoViewerCaptionEnterView(view, i, keyEvent);
            }
        });
        this.messageEditText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoViewerCaptionEnterView$1Z_m8h-TyQNyqTZ1bsbPnAYKZuk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$2$PhotoViewerCaptionEnterView(view);
            }
        });
        this.messageEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.4
            boolean processChange = false;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int start, int before, int count) {
                if (!PhotoViewerCaptionEnterView.this.innerTextChange) {
                    if (PhotoViewerCaptionEnterView.this.delegate != null) {
                        PhotoViewerCaptionEnterView.this.delegate.onTextChanged(charSequence);
                    }
                    if (before != count && count - before > 1) {
                        this.processChange = true;
                    }
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
                int charactersLeft = PhotoViewerCaptionEnterView.this.captionMaxLength - PhotoViewerCaptionEnterView.this.messageEditText.length();
                if (charactersLeft <= 128) {
                    PhotoViewerCaptionEnterView.this.lengthText = String.format("%d", Integer.valueOf(charactersLeft));
                } else {
                    PhotoViewerCaptionEnterView.this.lengthText = null;
                }
                PhotoViewerCaptionEnterView.this.invalidate();
                if (!PhotoViewerCaptionEnterView.this.innerTextChange && this.processChange) {
                    ImageSpan[] spans = (ImageSpan[]) editable.getSpans(0, editable.length(), ImageSpan.class);
                    for (ImageSpan imageSpan : spans) {
                        editable.removeSpan(imageSpan);
                    }
                    Emoji.replaceEmoji(editable, PhotoViewerCaptionEnterView.this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
                    this.processChange = false;
                }
            }
        });
        Drawable drawable = Theme.createCircleDrawable(AndroidUtilities.dp(16.0f), -10043398);
        Drawable checkDrawable = context.getResources().getDrawable(R.drawable.input_done).mutate();
        CombinedDrawable combinedDrawable = new CombinedDrawable(drawable, checkDrawable, 0, AndroidUtilities.dp(1.0f));
        combinedDrawable.setCustomSize(AndroidUtilities.dp(32.0f), AndroidUtilities.dp(32.0f));
        ImageView doneButton = new ImageView(context);
        doneButton.setScaleType(ImageView.ScaleType.CENTER);
        doneButton.setImageDrawable(combinedDrawable);
        textFieldContainer.addView(doneButton, LayoutHelper.createLinear(48, 48, 80));
        doneButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoViewerCaptionEnterView$tnEk7wEjRVqoo5kb5or4Jv1pi3Q
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$3$PhotoViewerCaptionEnterView(view);
            }
        });
        doneButton.setContentDescription(LocaleController.getString("Done", R.string.Done));
    }

    public /* synthetic */ void lambda$new$0$PhotoViewerCaptionEnterView(View view) {
        if (!isPopupShowing()) {
            showPopup(1);
        } else {
            openKeyboardInternal();
        }
    }

    public /* synthetic */ boolean lambda$new$1$PhotoViewerCaptionEnterView(View view, int i, KeyEvent keyEvent) {
        if (i == 4) {
            if (this.windowView != null && hideActionMode()) {
                return true;
            }
            if (!this.keyboardVisible && isPopupShowing()) {
                if (keyEvent.getAction() == 1) {
                    showPopup(0);
                }
                return true;
            }
        }
        return false;
    }

    public /* synthetic */ void lambda$new$2$PhotoViewerCaptionEnterView(View view) {
        if (isPopupShowing()) {
            showPopup(AndroidUtilities.usingHardwareInput ? 0 : 2);
        }
    }

    public /* synthetic */ void lambda$new$3$PhotoViewerCaptionEnterView(View view) {
        this.delegate.onCaptionEnter();
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.lengthText != null && getMeasuredHeight() > AndroidUtilities.dp(48.0f)) {
            int width = (int) Math.ceil(this.lengthTextPaint.measureText(this.lengthText));
            int x = (AndroidUtilities.dp(56.0f) - width) / 2;
            canvas.drawText(this.lengthText, x, getMeasuredHeight() - AndroidUtilities.dp(48.0f), this.lengthTextPaint);
            float f = this.animationProgress;
            if (f < 1.0f) {
                this.animationProgress = f + 0.14166667f;
                invalidate();
                if (this.animationProgress >= 1.0f) {
                    this.animationProgress = 1.0f;
                }
                this.lengthTextPaint.setAlpha((int) (this.animationProgress * 255.0f));
                return;
            }
            return;
        }
        this.lengthTextPaint.setAlpha(0);
        this.animationProgress = 0.0f;
    }

    public void setForceFloatingEmoji(boolean value) {
        this.forceFloatingEmoji = value;
    }

    public boolean hideActionMode() {
        ActionMode actionMode;
        if (Build.VERSION.SDK_INT >= 23 && (actionMode = this.currentActionMode) != null) {
            try {
                actionMode.finish();
            } catch (Exception e) {
                FileLog.e(e);
            }
            this.currentActionMode = null;
            return true;
        }
        return false;
    }

    protected void extendActionMode(ActionMode actionMode, Menu menu) {
    }

    private void fixActionMode(ActionMode mode) {
        try {
            Class<?> cls = Class.forName("com.android.internal.view.FloatingActionMode");
            Field fieldToolbar = cls.getDeclaredField("mFloatingToolbar");
            fieldToolbar.setAccessible(true);
            Object toolbar = fieldToolbar.get(mode);
            Class<?> cls2 = Class.forName("com.android.internal.widget.FloatingToolbar");
            Field fieldToolbarPopup = cls2.getDeclaredField("mPopup");
            Field fieldToolbarWidth = cls2.getDeclaredField("mWidthChanged");
            fieldToolbarPopup.setAccessible(true);
            fieldToolbarWidth.setAccessible(true);
            Object popup = fieldToolbarPopup.get(toolbar);
            Field fieldToolbarPopupParent = Class.forName("com.android.internal.widget.FloatingToolbar$FloatingToolbarPopup").getDeclaredField("mParent");
            fieldToolbarPopupParent.setAccessible(true);
            View currentView = (View) fieldToolbarPopupParent.get(popup);
            if (currentView != this.windowView) {
                fieldToolbarPopupParent.set(popup, this.windowView);
                Method method = cls.getDeclaredMethod("updateViewLocationInWindow", new Class[0]);
                method.setAccessible(true);
                method.invoke(mode, new Object[0]);
            }
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    private void onWindowSizeChanged() {
        int size = this.sizeNotifierLayout.getHeight();
        if (!this.keyboardVisible) {
            size -= this.emojiPadding;
        }
        PhotoViewerCaptionEnterViewDelegate photoViewerCaptionEnterViewDelegate = this.delegate;
        if (photoViewerCaptionEnterViewDelegate != null) {
            photoViewerCaptionEnterViewDelegate.onWindowSizeChanged(size);
        }
    }

    public void onCreate() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        this.sizeNotifierLayout.setDelegate(this);
    }

    public void onDestroy() {
        hidePopup();
        if (isKeyboardVisible()) {
            closeKeyboard();
        }
        this.keyboardVisible = false;
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        SizeNotifierFrameLayoutPhoto sizeNotifierFrameLayoutPhoto = this.sizeNotifierLayout;
        if (sizeNotifierFrameLayoutPhoto != null) {
            sizeNotifierFrameLayoutPhoto.setDelegate(null);
        }
    }

    public void setDelegate(PhotoViewerCaptionEnterViewDelegate delegate) {
        this.delegate = delegate;
    }

    public void setFieldText(CharSequence text) {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return;
        }
        editTextCaption.setText(text);
        EditTextCaption editTextCaption2 = this.messageEditText;
        editTextCaption2.setSelection(editTextCaption2.getText().length());
        PhotoViewerCaptionEnterViewDelegate photoViewerCaptionEnterViewDelegate = this.delegate;
        if (photoViewerCaptionEnterViewDelegate != null) {
            photoViewerCaptionEnterViewDelegate.onTextChanged(this.messageEditText.getText());
        }
        int old = this.captionMaxLength;
        int i = MessagesController.getInstance(UserConfig.selectedAccount).maxCaptionLength;
        this.captionMaxLength = i;
        if (old != i) {
            InputFilter[] inputFilters = {new InputFilter.LengthFilter(this.captionMaxLength)};
            this.messageEditText.setFilters(inputFilters);
        }
    }

    public int getSelectionLength() {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return 0;
        }
        try {
            return editTextCaption.getSelectionEnd() - this.messageEditText.getSelectionStart();
        } catch (Exception e) {
            FileLog.e(e);
            return 0;
        }
    }

    public int getCursorPosition() {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return 0;
        }
        return editTextCaption.getSelectionStart();
    }

    private void createEmojiView() {
        if (this.emojiView != null) {
            return;
        }
        EmojiView emojiView = new EmojiView(false, false, getContext(), false, null);
        this.emojiView = emojiView;
        emojiView.setDelegate(new EmojiView.EmojiViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.PhotoViewerCaptionEnterView.5
            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ boolean canSchedule() {
                return EmojiView.EmojiViewDelegate.CC.$default$canSchedule(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ boolean isExpanded() {
                return EmojiView.EmojiViewDelegate.CC.$default$isExpanded(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ boolean isInScheduleMode() {
                return EmojiView.EmojiViewDelegate.CC.$default$isInScheduleMode(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ boolean isSearchOpened() {
                return EmojiView.EmojiViewDelegate.CC.$default$isSearchOpened(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onClearEmojiRecent() {
                EmojiView.EmojiViewDelegate.CC.$default$onClearEmojiRecent(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            /* JADX INFO: renamed from: onGifSelected */
            public /* synthetic */ void lambda$onGifSelected$0$ChatActivityEnterView$35(View view, Object obj, Object obj2, boolean z, int i) {
                EmojiView.EmojiViewDelegate.CC.$default$onGifSelected(this, view, obj, obj2, z, i);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onSearchOpenClose(int i) {
                EmojiView.EmojiViewDelegate.CC.$default$onSearchOpenClose(this, i);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onShowStickerSet(TLRPC.StickerSet stickerSet, TLRPC.InputStickerSet inputStickerSet) {
                EmojiView.EmojiViewDelegate.CC.$default$onShowStickerSet(this, stickerSet, inputStickerSet);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onStickerSelected(View view, TLRPC.Document document, Object obj, boolean z, int i) {
                EmojiView.EmojiViewDelegate.CC.$default$onStickerSelected(this, view, document, obj, z, i);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onStickerSetAdd(TLRPC.StickerSetCovered stickerSetCovered) {
                EmojiView.EmojiViewDelegate.CC.$default$onStickerSetAdd(this, stickerSetCovered);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onStickerSetRemove(TLRPC.StickerSetCovered stickerSetCovered) {
                EmojiView.EmojiViewDelegate.CC.$default$onStickerSetRemove(this, stickerSetCovered);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onStickersGroupClick(int i) {
                EmojiView.EmojiViewDelegate.CC.$default$onStickersGroupClick(this, i);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onStickersSettingsClick() {
                EmojiView.EmojiViewDelegate.CC.$default$onStickersSettingsClick(this);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public /* synthetic */ void onTabOpened(int i) {
                EmojiView.EmojiViewDelegate.CC.$default$onTabOpened(this, i);
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public boolean onBackspace() {
                if (PhotoViewerCaptionEnterView.this.messageEditText.length() == 0) {
                    return false;
                }
                PhotoViewerCaptionEnterView.this.messageEditText.dispatchKeyEvent(new KeyEvent(0, 67));
                return true;
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
            public void onEmojiSelected(String symbol) {
                if (PhotoViewerCaptionEnterView.this.messageEditText.length() + symbol.length() <= PhotoViewerCaptionEnterView.this.captionMaxLength) {
                    int i = PhotoViewerCaptionEnterView.this.messageEditText.getSelectionEnd();
                    if (i < 0) {
                        i = 0;
                    }
                    try {
                        try {
                            PhotoViewerCaptionEnterView.this.innerTextChange = true;
                            CharSequence localCharSequence = Emoji.replaceEmoji(symbol, PhotoViewerCaptionEnterView.this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
                            PhotoViewerCaptionEnterView.this.messageEditText.setText(PhotoViewerCaptionEnterView.this.messageEditText.getText().insert(i, localCharSequence));
                            int j = localCharSequence.length() + i;
                            PhotoViewerCaptionEnterView.this.messageEditText.setSelection(j, j);
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    } finally {
                        PhotoViewerCaptionEnterView.this.innerTextChange = false;
                    }
                }
            }
        });
        this.sizeNotifierLayout.addView(this.emojiView);
    }

    public void addEmojiToRecent(String code) {
        createEmojiView();
        this.emojiView.addEmojiToRecent(code);
    }

    public void replaceWithText(int start, int len, CharSequence text, boolean parseEmoji) {
        try {
            SpannableStringBuilder builder = new SpannableStringBuilder(this.messageEditText.getText());
            builder.replace(start, start + len, text);
            if (parseEmoji) {
                Emoji.replaceEmoji(builder, this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            }
            this.messageEditText.setText(builder);
            if (text.length() + start <= this.messageEditText.length()) {
                this.messageEditText.setSelection(text.length() + start);
            } else {
                this.messageEditText.setSelection(this.messageEditText.length());
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void addMentionText1(int start, int len, CharSequence text, boolean parseEmoji) {
        try {
            SpannableStringBuilder builder = new SpannableStringBuilder(this.messageEditText.getText());
            builder.replace(start, start + len, text);
            if (parseEmoji) {
                Emoji.replaceEmoji(builder, this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            }
            this.messageEditText.setText(builder);
            this.messageEditText.setSelection(text.length() + start);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void setFieldFocused(boolean focus) {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return;
        }
        if (focus) {
            if (!editTextCaption.isFocused()) {
                this.messageEditText.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$PhotoViewerCaptionEnterView$WXeRrcrLF3UzCqtUZIt4D7sJ8K8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$setFieldFocused$4$PhotoViewerCaptionEnterView();
                    }
                }, 600L);
            }
        } else if (editTextCaption.isFocused() && !this.keyboardVisible) {
            this.messageEditText.clearFocus();
        }
    }

    public /* synthetic */ void lambda$setFieldFocused$4$PhotoViewerCaptionEnterView() {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption != null) {
            try {
                editTextCaption.requestFocus();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public CharSequence getFieldCharSequence() {
        return AndroidUtilities.getTrimmedString(this.messageEditText.getText());
    }

    public int getEmojiPadding() {
        return this.emojiPadding;
    }

    public boolean isPopupView(View view) {
        return view == this.emojiView;
    }

    private void showPopup(int show) {
        if (show == 1) {
            if (this.emojiView == null) {
                createEmojiView();
            }
            this.emojiView.setVisibility(0);
            if (this.keyboardHeight <= 0) {
                this.keyboardHeight = MessagesController.getGlobalEmojiSettings().getInt("kbd_height", AndroidUtilities.dp(236.0f));
            }
            if (this.keyboardHeightLand <= 0) {
                this.keyboardHeightLand = MessagesController.getGlobalEmojiSettings().getInt("kbd_height_land3", AndroidUtilities.dp(236.0f));
            }
            int currentHeight = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? this.keyboardHeightLand : this.keyboardHeight;
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.emojiView.getLayoutParams();
            layoutParams.width = AndroidUtilities.displaySize.x;
            layoutParams.height = currentHeight;
            this.emojiView.setLayoutParams(layoutParams);
            if (!AndroidUtilities.isInMultiwindow && !this.forceFloatingEmoji) {
                AndroidUtilities.hideKeyboard(this.messageEditText);
            }
            SizeNotifierFrameLayoutPhoto sizeNotifierFrameLayoutPhoto = this.sizeNotifierLayout;
            if (sizeNotifierFrameLayoutPhoto != null) {
                this.emojiPadding = currentHeight;
                sizeNotifierFrameLayoutPhoto.requestLayout();
                this.emojiButton.setImageResource(R.drawable.input_keyboard);
                onWindowSizeChanged();
                return;
            }
            return;
        }
        ImageView imageView = this.emojiButton;
        if (imageView != null) {
            imageView.setImageResource(R.drawable.input_smile);
        }
        EmojiView emojiView = this.emojiView;
        if (emojiView != null) {
            emojiView.setVisibility(8);
        }
        if (this.sizeNotifierLayout != null) {
            if (show == 0) {
                this.emojiPadding = 0;
            }
            this.sizeNotifierLayout.requestLayout();
            onWindowSizeChanged();
        }
    }

    public void hidePopup() {
        if (isPopupShowing()) {
            showPopup(0);
        }
    }

    private void openKeyboardInternal() {
        showPopup(AndroidUtilities.usingHardwareInput ? 0 : 2);
        openKeyboard();
    }

    public void openKeyboard() {
        int currentSelection;
        try {
            currentSelection = this.messageEditText.getSelectionStart();
        } catch (Exception e) {
            int currentSelection2 = this.messageEditText.length();
            FileLog.e(e);
            currentSelection = currentSelection2;
        }
        MotionEvent event = MotionEvent.obtain(0L, 0L, 0, 0.0f, 0.0f, 0);
        this.messageEditText.onTouchEvent(event);
        event.recycle();
        MotionEvent event2 = MotionEvent.obtain(0L, 0L, 1, 0.0f, 0.0f, 0);
        this.messageEditText.onTouchEvent(event2);
        event2.recycle();
        AndroidUtilities.showKeyboard(this.messageEditText);
        try {
            this.messageEditText.setSelection(currentSelection);
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public boolean isPopupShowing() {
        EmojiView emojiView = this.emojiView;
        return emojiView != null && emojiView.getVisibility() == 0;
    }

    public void closeKeyboard() {
        AndroidUtilities.hideKeyboard(this.messageEditText);
    }

    public boolean isKeyboardVisible() {
        return (AndroidUtilities.usingHardwareInput && getTag() != null) || this.keyboardVisible;
    }

    @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayoutPhoto.SizeNotifierFrameLayoutPhotoDelegate
    public void onSizeChanged(int height, boolean isWidthGreater) {
        boolean z;
        int newHeight;
        if (height > AndroidUtilities.dp(50.0f) && this.keyboardVisible && !AndroidUtilities.isInMultiwindow && !this.forceFloatingEmoji) {
            if (isWidthGreater) {
                this.keyboardHeightLand = height;
                MessagesController.getGlobalEmojiSettings().edit().putInt("kbd_height_land3", this.keyboardHeightLand).commit();
            } else {
                this.keyboardHeight = height;
                MessagesController.getGlobalEmojiSettings().edit().putInt("kbd_height", this.keyboardHeight).commit();
            }
        }
        if (isPopupShowing()) {
            if (isWidthGreater) {
                newHeight = this.keyboardHeightLand;
            } else {
                newHeight = this.keyboardHeight;
            }
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.emojiView.getLayoutParams();
            if (layoutParams.width != AndroidUtilities.displaySize.x || layoutParams.height != newHeight) {
                layoutParams.width = AndroidUtilities.displaySize.x;
                layoutParams.height = newHeight;
                this.emojiView.setLayoutParams(layoutParams);
                if (this.sizeNotifierLayout != null) {
                    this.emojiPadding = layoutParams.height;
                    this.sizeNotifierLayout.requestLayout();
                    onWindowSizeChanged();
                }
            }
        }
        int newHeight2 = this.lastSizeChangeValue1;
        if (newHeight2 == height && this.lastSizeChangeValue2 == isWidthGreater) {
            onWindowSizeChanged();
            return;
        }
        this.lastSizeChangeValue1 = height;
        this.lastSizeChangeValue2 = isWidthGreater;
        boolean oldValue = this.keyboardVisible;
        boolean z2 = height > 0;
        this.keyboardVisible = z2;
        if (z2 && isPopupShowing()) {
            showPopup(0);
        }
        if (this.emojiPadding != 0 && !(z = this.keyboardVisible) && z != oldValue && !isPopupShowing()) {
            this.emojiPadding = 0;
            this.sizeNotifierLayout.requestLayout();
        }
        onWindowSizeChanged();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        EmojiView emojiView;
        if (id == NotificationCenter.emojiDidLoad && (emojiView = this.emojiView) != null) {
            emojiView.invalidateViews();
        }
    }

    public void setAllowTextEntitiesIntersection(boolean value) {
        this.messageEditText.setAllowTextEntitiesIntersection(value);
    }
}
