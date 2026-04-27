package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import android.text.Editable;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.CharacterStyle;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionWrapper;
import android.widget.FrameLayout;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class EditTextCaption extends EditTextBoldCursor {
    private boolean allowTextEntitiesIntersection;
    private String caption;
    private StaticLayout captionLayout;
    private boolean copyPasteShowed;
    private EditTextCaptionDelegate delegate;
    private int hintColor;
    private View.OnKeyListener mKeyListener;
    private int selectionEnd;
    private int selectionStart;
    private int triesCount;
    private int userNameLength;
    private int xOffset;
    private int yOffset;

    public interface EditTextCaptionDelegate {
        void onSpansChanged();
    }

    public EditTextCaption(Context context) {
        super(context);
        this.triesCount = 0;
        this.selectionStart = -1;
        this.selectionEnd = -1;
    }

    public void setCaption(String value) {
        String str = this.caption;
        if ((str == null || str.length() == 0) && (value == null || value.length() == 0)) {
            return;
        }
        String str2 = this.caption;
        if (str2 != null && str2.equals(value)) {
            return;
        }
        this.caption = value;
        if (value != null) {
            this.caption = value.replace('\n', ' ');
        }
        requestLayout();
    }

    public void setDelegate(EditTextCaptionDelegate editTextCaptionDelegate) {
        this.delegate = editTextCaptionDelegate;
    }

    public void setAllowTextEntitiesIntersection(boolean value) {
        this.allowTextEntitiesIntersection = value;
    }

    public void makeSelectedBold() {
        TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
        run.flags |= 1;
        applyTextStyleToSelection(new TextStyleSpan(run));
    }

    public void makeSelectedItalic() {
        TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
        run.flags |= 2;
        applyTextStyleToSelection(new TextStyleSpan(run));
    }

    public void makeSelectedMono() {
        TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
        run.flags |= 4;
        applyTextStyleToSelection(new TextStyleSpan(run));
    }

    public void makeSelectedStrike() {
        TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
        run.flags |= 8;
        applyTextStyleToSelection(new TextStyleSpan(run));
    }

    public void makeSelectedUnderline() {
        TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
        run.flags |= 16;
        applyTextStyleToSelection(new TextStyleSpan(run));
    }

    public void makeSelectedUrl() {
        final int start;
        final int end;
        AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
        builder.setTitle(LocaleController.getString("CreateLink", R.string.CreateLink));
        final EditTextBoldCursor editText = new EditTextBoldCursor(getContext()) { // from class: im.uwrkaxlmjj.ui.components.EditTextCaption.1
            @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.widget.TextView, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f), 1073741824));
            }
        };
        editText.setTextSize(1, 18.0f);
        editText.setText(DefaultWebClient.HTTP_SCHEME);
        editText.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
        editText.setHintText(LocaleController.getString("URL", R.string.URL));
        editText.setHeaderHintColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
        editText.setSingleLine(true);
        editText.setFocusable(true);
        editText.setTransformHintToHeader(true);
        editText.setLineColors(Theme.getColor(Theme.key_windowBackgroundWhiteInputField), Theme.getColor(Theme.key_windowBackgroundWhiteInputFieldActivated), Theme.getColor(Theme.key_windowBackgroundWhiteRedText3));
        editText.setImeOptions(6);
        editText.setBackgroundDrawable(null);
        editText.requestFocus();
        editText.setPadding(0, 0, 0, 0);
        builder.setView(editText);
        if (this.selectionStart >= 0 && this.selectionEnd >= 0) {
            start = this.selectionStart;
            end = this.selectionEnd;
            this.selectionEnd = -1;
            this.selectionStart = -1;
        } else {
            start = getSelectionStart();
            end = getSelectionEnd();
        }
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EditTextCaption$exyJvT6PGC5rTLYF4OnHpUVgyY4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$makeSelectedUrl$0$EditTextCaption(start, end, editText, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.show().setOnShowListener(new DialogInterface.OnShowListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EditTextCaption$s4FxzG7_Yvx_99pZZ3VWGd8v0as
            @Override // android.content.DialogInterface.OnShowListener
            public final void onShow(DialogInterface dialogInterface) {
                EditTextCaption.lambda$makeSelectedUrl$1(editText, dialogInterface);
            }
        });
        ViewGroup.MarginLayoutParams layoutParams = (ViewGroup.MarginLayoutParams) editText.getLayoutParams();
        if (layoutParams != null) {
            if (layoutParams instanceof FrameLayout.LayoutParams) {
                ((FrameLayout.LayoutParams) layoutParams).gravity = 1;
            }
            int iDp = AndroidUtilities.dp(24.0f);
            layoutParams.leftMargin = iDp;
            layoutParams.rightMargin = iDp;
            layoutParams.height = AndroidUtilities.dp(36.0f);
            editText.setLayoutParams(layoutParams);
        }
        editText.setSelection(0, editText.getText().length());
    }

    public /* synthetic */ void lambda$makeSelectedUrl$0$EditTextCaption(int start, int end, EditTextBoldCursor editText, DialogInterface dialogInterface, int i) {
        Editable editable = getText();
        CharacterStyle[] spans = (CharacterStyle[]) editable.getSpans(start, end, CharacterStyle.class);
        if (spans != null && spans.length > 0) {
            for (CharacterStyle oldSpan : spans) {
                int spanStart = editable.getSpanStart(oldSpan);
                int spanEnd = editable.getSpanEnd(oldSpan);
                editable.removeSpan(oldSpan);
                if (spanStart < start) {
                    editable.setSpan(oldSpan, spanStart, start, 33);
                }
                if (spanEnd > end) {
                    editable.setSpan(oldSpan, end, spanEnd, 33);
                }
            }
        }
        try {
            editable.setSpan(new URLSpanReplacement(editText.getText().toString()), start, end, 33);
        } catch (Exception e) {
        }
        EditTextCaptionDelegate editTextCaptionDelegate = this.delegate;
        if (editTextCaptionDelegate != null) {
            editTextCaptionDelegate.onSpansChanged();
        }
    }

    static /* synthetic */ void lambda$makeSelectedUrl$1(EditTextBoldCursor editText, DialogInterface dialog) {
        editText.requestFocus();
        AndroidUtilities.showKeyboard(editText);
    }

    public void makeSelectedRegular() {
        applyTextStyleToSelection(null);
    }

    public void setSelectionOverride(int start, int end) {
        this.selectionStart = start;
        this.selectionEnd = end;
    }

    private void applyTextStyleToSelection(TextStyleSpan span) {
        int start;
        int end;
        if (this.selectionStart >= 0 && this.selectionEnd >= 0) {
            start = this.selectionStart;
            end = this.selectionEnd;
            this.selectionEnd = -1;
            this.selectionStart = -1;
        } else {
            start = getSelectionStart();
            end = getSelectionEnd();
        }
        MediaDataController.addStyleToText(span, start, end, getText(), this.allowTextEntitiesIntersection);
        EditTextCaptionDelegate editTextCaptionDelegate = this.delegate;
        if (editTextCaptionDelegate != null) {
            editTextCaptionDelegate.onSpansChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.widget.TextView, android.view.View
    public void onWindowFocusChanged(boolean hasWindowFocus) {
        if (Build.VERSION.SDK_INT < 23 && !hasWindowFocus && this.copyPasteShowed) {
            return;
        }
        super.onWindowFocusChanged(hasWindowFocus);
    }

    private ActionMode.Callback overrideCallback(final ActionMode.Callback callback) {
        return new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.components.EditTextCaption.2
            @Override // android.view.ActionMode.Callback
            public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                EditTextCaption.this.copyPasteShowed = true;
                return callback.onCreateActionMode(mode, menu);
            }

            @Override // android.view.ActionMode.Callback
            public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                return callback.onPrepareActionMode(mode, menu);
            }

            @Override // android.view.ActionMode.Callback
            public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                if (item.getItemId() == R.attr.menu_regular) {
                    EditTextCaption.this.makeSelectedRegular();
                    mode.finish();
                    return true;
                }
                if (item.getItemId() == R.attr.menu_bold) {
                    EditTextCaption.this.makeSelectedBold();
                    mode.finish();
                    return true;
                }
                if (item.getItemId() == R.attr.menu_italic) {
                    EditTextCaption.this.makeSelectedItalic();
                    mode.finish();
                    return true;
                }
                if (item.getItemId() == R.attr.menu_mono) {
                    EditTextCaption.this.makeSelectedMono();
                    mode.finish();
                    return true;
                }
                if (item.getItemId() == R.attr.menu_link) {
                    EditTextCaption.this.makeSelectedUrl();
                    mode.finish();
                    return true;
                }
                if (item.getItemId() == R.attr.menu_strike) {
                    EditTextCaption.this.makeSelectedStrike();
                    mode.finish();
                    return true;
                }
                if (item.getItemId() == R.attr.menu_underline) {
                    EditTextCaption.this.makeSelectedUnderline();
                    mode.finish();
                    return true;
                }
                try {
                    return callback.onActionItemClicked(mode, item);
                } catch (Exception e) {
                    return true;
                }
            }

            @Override // android.view.ActionMode.Callback
            public void onDestroyActionMode(ActionMode mode) {
                EditTextCaption.this.copyPasteShowed = false;
                callback.onDestroyActionMode(mode);
            }
        };
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.view.View
    public ActionMode startActionMode(ActionMode.Callback callback, int type) {
        return super.startActionMode(overrideCallback(callback), type);
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.view.View
    public ActionMode startActionMode(ActionMode.Callback callback) {
        return super.startActionMode(overrideCallback(callback));
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.widget.TextView, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int index;
        try {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        } catch (Exception e) {
            setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), AndroidUtilities.dp(51.0f));
            FileLog.e(e);
        }
        this.captionLayout = null;
        String str = this.caption;
        if (str != null && str.length() > 0) {
            CharSequence text = getText();
            if (text.length() > 1 && text.charAt(0) == '@' && (index = TextUtils.indexOf(text, ' ')) != -1) {
                TextPaint paint = getPaint();
                CharSequence str2 = text.subSequence(0, index + 1);
                int size = (int) Math.ceil(paint.measureText(text, 0, index + 1));
                int width = (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
                this.userNameLength = str2.length();
                CharSequence captionFinal = TextUtils.ellipsize(this.caption, paint, width - size, TextUtils.TruncateAt.END);
                this.xOffset = size;
                try {
                    StaticLayout staticLayout = new StaticLayout(captionFinal, getPaint(), width - size, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    this.captionLayout = staticLayout;
                    if (staticLayout.getLineCount() > 0) {
                        this.xOffset = (int) (this.xOffset + (-this.captionLayout.getLineLeft(0)));
                    }
                    this.yOffset = ((getMeasuredHeight() - this.captionLayout.getLineBottom(0)) / 2) + AndroidUtilities.dp(0.5f);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
        }
    }

    public String getCaption() {
        return this.caption;
    }

    @Override // android.view.View
    public void setOnKeyListener(View.OnKeyListener l) {
        this.mKeyListener = l;
        super.setOnKeyListener(l);
    }

    @Override // androidx.appcompat.widget.AppCompatEditText, android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        InputConnection ic = super.onCreateInputConnection(outAttrs);
        if (ic != null) {
            return new InnerInputConnection(ic, true);
        }
        return ic;
    }

    private class InnerInputConnection extends InputConnectionWrapper {
        public InnerInputConnection(InputConnection target, boolean mutable) {
            super(target, mutable);
        }

        @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
        public boolean deleteSurroundingText(int beforeLength, int afterLength) {
            boolean ret = false;
            if (beforeLength == 1 && afterLength == 0 && EditTextCaption.this.mKeyListener != null) {
                ret = EditTextCaption.this.mKeyListener.onKey(EditTextCaption.this, 67, new KeyEvent(0, 67));
            }
            return ret || super.deleteSurroundingText(beforeLength, afterLength);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor
    public void setHintColor(int value) {
        super.setHintColor(value);
        this.hintColor = value;
        invalidate();
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        try {
            if (this.captionLayout != null && this.userNameLength == length()) {
                Paint paint = getPaint();
                int oldColor = getPaint().getColor();
                paint.setColor(this.hintColor);
                canvas.save();
                canvas.translate(this.xOffset, this.yOffset);
                this.captionLayout.draw(canvas);
                canvas.restore();
                paint.setColor(oldColor);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.EditTextBoldCursor, android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        if (!TextUtils.isEmpty(this.caption)) {
            if (Build.VERSION.SDK_INT >= 26) {
                info.setHintText(this.caption);
                return;
            }
            info.setText(((Object) info.getText()) + ", " + this.caption);
        }
    }
}
