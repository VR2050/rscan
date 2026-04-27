package im.uwrkaxlmjj.ui.wallet.cell;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BankCardSelectCell extends FrameLayout {
    ImageView ivSelect;
    TextView tvName;

    public BankCardSelectCell(Context context) {
        this(context, null);
    }

    public BankCardSelectCell(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public BankCardSelectCell(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        View view = inflate(context, R.layout.item_bank_card_select_layout, this);
        ConstraintLayout clickView = (ConstraintLayout) view.findViewById(R.attr.clickView);
        this.ivSelect = (ImageView) view.findViewById(R.attr.ivSelect);
        this.tvName = (TextView) view.findViewById(R.attr.tvName);
        clickView.setBackground(Theme.getSelectorDrawable(false));
    }

    public void setText(String name, boolean checked) {
        this.tvName.setText(name);
        this.ivSelect.setVisibility(checked ? 0 : 8);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(70.0f), 1073741824));
    }
}
