package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class MryImageView extends MryAlphaImageView {
    private boolean render;

    public MryImageView(Context context) {
        this(context, null);
    }

    public MryImageView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MryImageView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.render = false;
        if (attrs != null) {
            TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.MryImageView);
            this.render = ta.getBoolean(0, false);
            ta.recycle();
        }
        if (this.render) {
            setColorFilterMultiply(Theme.key_actionBarDefaultIcon);
        }
    }
}
