package im.uwrkaxlmjj.ui.wallet.cell;

import android.content.Context;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import com.blankj.utilcode.util.ColorUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hviews.MryFrameLayout;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BtnChargeCell extends FrameLayout {
    private MryFrameLayout container;
    private ImageView ivCheck;
    private TextView tvAmount;

    public BtnChargeCell(Context context) {
        this(context, null);
    }

    public BtnChargeCell(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public BtnChargeCell(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        View view = inflate(context, R.layout.cell_btn_charge_layout, this);
        this.container = (MryFrameLayout) view.findViewById(R.attr.container);
        this.tvAmount = (TextView) view.findViewById(R.attr.tvAmount);
        this.ivCheck = (ImageView) view.findViewById(R.attr.ivCheck);
        this.container.setRadius(AndroidUtilities.dp(8.0f));
        this.ivCheck.setVisibility(8);
    }

    public void setChecked(boolean checked) {
        if (checked) {
            this.ivCheck.setVisibility(0);
            this.tvAmount.setTypeface(Typeface.DEFAULT_BOLD);
            this.tvAmount.setTextColor(ColorUtils.getColor(R.color.text_blue_color));
            this.container.setBackground(Theme.getRoundRectSelectorDrawable(0, ColorUtils.getColor(R.color.bg_btn_light_blue_color)));
            return;
        }
        this.ivCheck.setVisibility(8);
        this.tvAmount.setTypeface(Typeface.DEFAULT);
        this.tvAmount.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
        this.container.setBackground(Theme.getRoundRectSelectorDrawable(0, ColorUtils.getColor(R.color.window_background_gray)));
    }

    public void setText(String text) {
        this.tvAmount.setText(text);
    }
}
