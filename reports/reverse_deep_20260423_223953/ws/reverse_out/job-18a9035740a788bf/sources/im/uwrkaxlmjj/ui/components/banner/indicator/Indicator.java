package im.uwrkaxlmjj.ui.components.banner.indicator;

import android.view.View;
import im.uwrkaxlmjj.ui.components.banner.config.IndicatorConfig;
import im.uwrkaxlmjj.ui.components.banner.listener.OnPageChangeListener;

/* JADX INFO: loaded from: classes5.dex */
public interface Indicator extends OnPageChangeListener {
    IndicatorConfig getIndicatorConfig();

    View getIndicatorView();

    void onPageChanged(int i, int i2);
}
