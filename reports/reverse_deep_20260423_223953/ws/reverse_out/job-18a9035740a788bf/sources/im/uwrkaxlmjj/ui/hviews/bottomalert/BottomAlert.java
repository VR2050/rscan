package im.uwrkaxlmjj.ui.hviews.bottomalert;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;

/* JADX INFO: loaded from: classes5.dex */
public class BottomAlert extends LinearLayout implements View.OnClickListener {
    private int[] itemIcons;
    private CharSequence[] items;
    private LinearLayout llOptionsContainer;
    private Context mContext;
    public BottomAlertDelegate onItemClickListener;
    private TextView tvBtmText;

    public interface BottomAlertDelegate {
        void onItemClick(int i);
    }

    public void build() {
        init();
        invalidate();
    }

    public void setOnItemClickListener(BottomAlertDelegate onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
    }

    public BottomAlert(Context context, CharSequence[] items) {
        super(context);
        this.mContext = context;
        this.items = items;
        init();
    }

    public BottomAlert(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public BottomAlert(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mContext = context;
    }

    public void setItems(CharSequence[] items) {
        this.items = items;
    }

    public void setItemIcons(int[] itemIcons) {
        this.itemIcons = itemIcons;
    }

    public void setTvBtmTextAttr(String text, int colorId) {
        if (text != null) {
            this.tvBtmText.setText(text);
        }
        if (colorId > 0) {
            this.tvBtmText.setTextColor(colorId);
        }
    }

    private void init() {
        this.llOptionsContainer = new LinearLayout(this.mContext);
        if (this.items != null) {
            int i = 0;
            while (true) {
                CharSequence[] charSequenceArr = this.items;
                if (i >= charSequenceArr.length) {
                    break;
                }
                CharSequence content = charSequenceArr[i];
                TextView item = new TextView(this.mContext);
                this.llOptionsContainer.addView(item, LayoutHelper.createLinear(-1, AndroidUtilities.dp(48.0f)));
                item.setGravity(17);
                item.setTag(Integer.valueOf(i));
                item.setText(content);
                item.setOnClickListener(this);
                if (i != item.length() - 1) {
                    View view = new View(this.mContext);
                    view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                    this.llOptionsContainer.addView(view, LayoutHelper.createLinear(-1.0f, 0.5f));
                }
                i++;
            }
        }
        TextView textView = new TextView(this.mContext);
        this.tvBtmText = textView;
        textView.setGravity(17);
        this.llOptionsContainer.addView(this.tvBtmText, LayoutHelper.createLinear(-1, AndroidUtilities.dp(48.0f), 0.0f, 25.0f, 0.0f, 0.0f));
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        BottomAlertDelegate bottomAlertDelegate = this.onItemClickListener;
        if (bottomAlertDelegate != null) {
            bottomAlertDelegate.onItemClick(((Integer) v.getTag()).intValue());
        }
    }
}
