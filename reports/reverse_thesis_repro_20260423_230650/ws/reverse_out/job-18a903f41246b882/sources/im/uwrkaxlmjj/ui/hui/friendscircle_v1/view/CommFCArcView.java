package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.util.AttributeSet;
import android.view.View;
import androidx.core.content.ContextCompat;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class CommFCArcView extends View {
    private String bgColorKey;

    public CommFCArcView(Context context) {
        super(context);
        this.bgColorKey = Theme.key_windowBackgroundWhite;
        init(null, context);
    }

    public CommFCArcView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.bgColorKey = Theme.key_windowBackgroundWhite;
        init(attrs, context);
    }

    public CommFCArcView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.bgColorKey = Theme.key_windowBackgroundWhite;
        init(attrs, context);
    }

    private void init(AttributeSet attrs, Context context) {
        if (attrs != null) {
            TypedArray array = context.obtainStyledAttributes(attrs, R.styleable.CommFCArcView);
            this.bgColorKey = array.getString(0) == null ? Theme.key_windowBackgroundWhite : array.getString(0);
            array.recycle();
        }
        LayerDrawable background = (LayerDrawable) ContextCompat.getDrawable(context, mpEIGo.juqQQs.esbSDO.R.drawable.fc_oval_shape_top);
        GradientDrawable drawableByLayerId1 = (GradientDrawable) background.findDrawableByLayerId(mpEIGo.juqQQs.esbSDO.R.attr.ly_fc_header_oval);
        drawableByLayerId1.setColor(Theme.getColor(this.bgColorKey));
        background.setDrawableByLayerId(mpEIGo.juqQQs.esbSDO.R.attr.ly_fc_header_oval, drawableByLayerId1);
        GradientDrawable drawableByLayerId2 = (GradientDrawable) background.findDrawableByLayerId(mpEIGo.juqQQs.esbSDO.R.attr.ly_fc_header_rect);
        drawableByLayerId2.setColor(Theme.getColor(this.bgColorKey));
        background.setDrawableByLayerId(mpEIGo.juqQQs.esbSDO.R.attr.ly_fc_header_rect, drawableByLayerId2);
        setBackground(background);
    }
}
