package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext;

import android.content.Context;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionWrapper;
import android.widget.EditText;

/* JADX INFO: loaded from: classes5.dex */
public class KeyDelEditText extends EditText {
    private View.OnKeyListener mKeyListener;

    public KeyDelEditText(Context context) {
        super(context);
    }

    public KeyDelEditText(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public KeyDelEditText(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    @Override // android.view.View
    public void setOnKeyListener(View.OnKeyListener l) {
        this.mKeyListener = l;
        super.setOnKeyListener(l);
    }

    @Override // android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        InputConnection inputConnection = super.onCreateInputConnection(outAttrs);
        if (inputConnection == null) {
            return null;
        }
        return new InnerInputConnection(inputConnection, true);
    }

    private class InnerInputConnection extends InputConnectionWrapper {
        public InnerInputConnection(InputConnection target, boolean mutable) {
            super(target, mutable);
        }

        @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
        public boolean deleteSurroundingText(int beforeLength, int afterLength) {
            boolean ret = false;
            if (beforeLength == 1 && afterLength == 0 && KeyDelEditText.this.mKeyListener != null) {
                ret = KeyDelEditText.this.mKeyListener.onKey(KeyDelEditText.this, 67, new KeyEvent(0, 67));
            }
            return ret || super.deleteSurroundingText(beforeLength, afterLength);
        }
    }
}
