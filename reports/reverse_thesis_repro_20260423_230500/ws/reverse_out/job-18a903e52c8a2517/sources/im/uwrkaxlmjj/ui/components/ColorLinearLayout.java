package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class ColorLinearLayout extends LinearLayout {
    public ColorLinearLayout(Context context) {
        super(context);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
    }

    public ColorLinearLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
    }

    public ColorLinearLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
    }
}
