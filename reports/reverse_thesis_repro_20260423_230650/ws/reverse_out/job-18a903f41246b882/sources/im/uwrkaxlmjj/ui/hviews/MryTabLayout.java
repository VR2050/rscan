package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.util.AttributeSet;
import com.google.android.material.tabs.TabLayout;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class MryTabLayout extends TabLayout {
    public MryTabLayout(Context context) {
        this(context, null);
    }

    public MryTabLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MryTabLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        if (Theme.getCurrentTheme() != null) {
            if (Theme.getCurrentTheme().isDark()) {
                setTabTextColors(Theme.getColor(Theme.key_actionBarTabUnactiveText), Theme.getColor(Theme.key_actionBarTabActiveText));
                setSelectedTabIndicatorColor(Theme.getColor(Theme.key_actionBarTabActiveText));
            } else {
                setTabTextColors(Theme.getColor(Theme.key_actionBarTabUnactiveText), Theme.getColor(Theme.key_actionBarTabActiveText));
            }
        }
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
    }
}
