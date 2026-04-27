package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.GestureDetector;
import android.view.MotionEvent;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.core.content.ContextCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class MryEditText extends AppCompatEditText {
    private Drawable clearButtonDrawable;
    private GestureDetector detector;
    private boolean showClearButton;

    public MryEditText(Context context) {
        this(context, null);
    }

    public MryEditText(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MryEditText(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.MryEditText);
        int style = a.getInteger(2, 0);
        boolean render = a.getBoolean(3, false);
        String textKey = a.getString(5);
        String hintKey = a.getString(1);
        this.showClearButton = a.getBoolean(4, false);
        this.clearButtonDrawable = a.getDrawable(0);
        a.recycle();
        if (style != 0) {
            if (style == 1) {
                setBold();
            } else if (style == 2) {
                setItalic();
            } else if (style == 3) {
                setBoldAndItalic();
            } else if (style == 4) {
                setMono();
            }
        }
        if (getTextColors() == null || render) {
            setHintColor(Theme.key_windowBackgroundWhiteHintText);
            setTextColor(Theme.key_windowBackgroundWhiteBlackText);
        }
        if (textKey != null) {
            setMryText(getResources().getIdentifier(textKey, "string", context.getPackageName()));
        }
        if (hintKey != null) {
            setMryHint(getResources().getIdentifier(hintKey, "string", context.getPackageName()));
        }
        setFocusableInTouchMode(true);
        setShowClearButton(this.showClearButton);
        setClearButtonDrawable(this.clearButtonDrawable);
        AndroidUtilities.handleKeyboardShelterProblem(this);
    }

    @Override // android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.showClearButton && this.clearButtonDrawable != null) {
            int size = AndroidUtilities.dp(40.0f);
            int l = (getMeasuredWidth() - getPaddingEnd()) - size;
            int t = (getMeasuredHeight() - getPaddingTop()) - (size / 2);
            this.clearButtonDrawable.setBounds(l, t, l + size, t + size);
            this.clearButtonDrawable.draw(canvas);
        }
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        GestureDetector gestureDetector;
        if (this.showClearButton && (gestureDetector = this.detector) != null && gestureDetector.onTouchEvent(event)) {
            return true;
        }
        return super.onTouchEvent(event);
    }

    @Override // android.view.View
    public boolean requestFocus(int direction, Rect previouslyFocusedRect) {
        boolean tag = super.requestFocus(direction, previouslyFocusedRect);
        setSelectionEnd();
        return tag;
    }

    @Override // android.widget.TextView
    public void setInputType(int type) {
        super.setInputType(type);
    }

    @Override // android.widget.EditText
    public void setSelection(int index) {
        try {
            super.setSelection(index);
        } catch (Exception e) {
        }
    }

    @Override // android.widget.EditText
    public void setSelection(int start, int stop) {
        try {
            super.setSelection(start, stop);
        } catch (Exception e) {
        }
    }

    public void setSelectionEnd() {
        setSelection(getText() != null ? getText().length() : 0);
    }

    public void setMryText(int resId) {
        setText(LocaleController.getString(resId));
    }

    public void setMryHint(int resId) {
        setHint(LocaleController.getString(resId));
    }

    public void setTextColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setTextColor(Theme.getColor(colorThemeKey));
    }

    public void setHintColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setHintTextColor(Theme.getColor(colorThemeKey));
    }

    public void setBackgroundColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setBackgroundColor(Theme.getColor(colorThemeKey));
    }

    public void setHighlightColor(String colorThemeKey) {
        if (colorThemeKey == null) {
            return;
        }
        super.setHighlightColor(Theme.getColor(colorThemeKey));
    }

    public void setBold() {
        setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
    }

    public void setItalic() {
        setTypeface(AndroidUtilities.getTypeface("fonts/ritalic.ttf"));
    }

    public void setBoldAndItalic() {
        setTypeface(AndroidUtilities.getTypeface("fonts/rmediumitalic.ttf"));
    }

    public void setMono() {
        setTypeface(AndroidUtilities.getTypeface("fonts/rmono.ttf"));
    }

    public void setShowClearButton(boolean showClearButton) {
        this.showClearButton = showClearButton;
        if (showClearButton && this.detector == null) {
            this.detector = new GestureDetector(getContext(), new GestureDetector.SimpleOnGestureListener() { // from class: im.uwrkaxlmjj.ui.hviews.MryEditText.1
                @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
                public boolean onSingleTapUp(MotionEvent e) {
                    if (MryEditText.this.clearButtonDrawable != null) {
                        Rect rect = MryEditText.this.clearButtonDrawable.getBounds();
                        return rect.contains((int) e.getX(), (int) e.getY());
                    }
                    return false;
                }
            });
        }
    }

    public void setClearButtonDrawable(int clearButtonDrawable) {
        this.clearButtonDrawable = ContextCompat.getDrawable(getContext(), clearButtonDrawable);
        invalidate();
    }

    public void setClearButtonDrawable(Drawable clearButtonDrawable) {
        this.clearButtonDrawable = clearButtonDrawable;
        invalidate();
    }
}
