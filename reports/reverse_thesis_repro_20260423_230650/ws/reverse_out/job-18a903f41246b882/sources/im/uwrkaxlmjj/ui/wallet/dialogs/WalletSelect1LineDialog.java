package im.uwrkaxlmjj.ui.wallet.dialogs;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public abstract class WalletSelect1LineDialog<T> extends WalletSelectAbsDialog<T, WalletSelect1LineDialog, Holder1Line> {
    public WalletSelect1LineDialog(Context context) {
        super(context);
    }

    public WalletSelect1LineDialog(Context context, boolean useNestScrollViewAsParent) {
        super(context, useNestScrollViewAsParent);
    }

    public WalletSelect1LineDialog(Context context, int backgroundType) {
        super(context, backgroundType);
    }

    public WalletSelect1LineDialog(Context context, int backgroundType, boolean useNestScrollViewAsParent) {
        super(context, backgroundType, useNestScrollViewAsParent);
    }

    public WalletSelect1LineDialog(Context context, boolean needFocus, int backgroundType, boolean useNestScrollViewAsParent) {
        super(context, needFocus, backgroundType, useNestScrollViewAsParent);
    }

    @Override // im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog
    public WalletSelect1LineDialog setOnConfrimClickListener(WalletSelectAbsDialog.OnConfirmClickListener<T, WalletSelect1LineDialog> onConfrimClickListener) {
        return (WalletSelect1LineDialog) super.setOnConfrimClickListener((WalletSelectAbsDialog.OnConfirmClickListener) onConfrimClickListener);
    }

    @Override // im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog
    public Holder1Line onCreateViewHolder(ViewGroup parent, int viewType) {
        return new Holder1Line(LayoutInflater.from(getContext()).inflate(R.layout.wallet_dialog_item_select_1line, parent, false));
    }

    @Override // im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog
    public void onBindViewHolder(RecyclerListView.SelectionAdapter adapter, Holder1Line holder, int position, T item) {
        super.onBindViewHolder(adapter, holder, position, (Object) item);
    }

    public static class Holder1Line extends PageHolder {
        public DividerCell divider;
        public ImageView ivIcon;
        public ImageView ivSelect;
        public MryTextView tvTitle;
        public MryTextView tvValue;

        public Holder1Line(View itemView) {
            super(itemView);
            this.ivIcon = (ImageView) itemView.findViewById(R.attr.ivIcon);
            this.tvTitle = (MryTextView) itemView.findViewById(R.attr.tvTitle);
            this.tvValue = (MryTextView) itemView.findViewById(R.attr.tvValue);
            this.ivSelect = (ImageView) itemView.findViewById(R.attr.ivSelect);
            this.divider = (DividerCell) itemView.findViewById(R.attr.divider);
        }
    }
}
