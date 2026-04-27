package im.uwrkaxlmjj.ui.wallet.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.ColorUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PasswordKeyboardAdapter extends RecyclerListView.SelectionAdapter {
    private Context mContext;
    private List<Integer> mNumbers;

    public PasswordKeyboardAdapter(Context context, List<Integer> list) {
        this.mNumbers = new ArrayList();
        this.mContext = context;
        this.mNumbers = list;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        return false;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.mNumbers.size();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType == 0) {
            view = LayoutInflater.from(this.mContext).inflate(R.layout.item_payment_password_number, parent, false);
        } else if (viewType != 1 && viewType == 2) {
            view = new View(this.mContext);
        } else {
            view = new View(this.mContext);
        }
        return new RecyclerListView.Holder(view);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        if (holder.getItemViewType() == 0) {
            TextView tvNumber = (TextView) holder.itemView.findViewById(R.attr.btn_number);
            ImageView ivDelete = (ImageView) holder.itemView.findViewById(R.attr.iv_delete);
            tvNumber.setText(String.valueOf(this.mNumbers.get(position)));
            tvNumber.setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(10.0f), ColorUtils.getColor(R.color.dialog_password_bg)));
            ivDelete.setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(10.0f), ColorUtils.getColor(R.color.dialog_password_bg)));
            if (position == 11) {
                tvNumber.setVisibility(8);
                ivDelete.setVisibility(0);
            } else {
                ivDelete.setVisibility(8);
                tvNumber.setVisibility(0);
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        if (i == 9) {
            return 1;
        }
        return 0;
    }
}
