package im.uwrkaxlmjj.ui.fragments;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.cells.DrawerAddCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hcells.PopUserCell;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

/* JADX INFO: loaded from: classes5.dex */
public class AccountsAdapter extends RecyclerListView.SelectionAdapter {
    private ArrayList<Integer> accountNumbers = new ArrayList<>();
    private Context mContext;

    public AccountsAdapter(Context context) {
        this.mContext = context;
        resetItems();
    }

    private void resetItems() {
        this.accountNumbers.clear();
        for (int a = 0; a < 3; a++) {
            if (UserConfig.getInstance(a).isClientActivated()) {
                this.accountNumbers.add(Integer.valueOf(a));
            }
        }
        Collections.sort(this.accountNumbers, new Comparator() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$AccountsAdapter$t94mnxmD3PnqYC7e5QgMPCR3NNE
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return AccountsAdapter.lambda$resetItems$0((Integer) obj, (Integer) obj2);
            }
        });
    }

    static /* synthetic */ int lambda$resetItems$0(Integer o1, Integer o2) {
        long l1 = UserConfig.getInstance(o1.intValue()).loginTime;
        long l2 = UserConfig.getInstance(o2.intValue()).loginTime;
        if (l1 > l2) {
            return 1;
        }
        if (l1 < l2) {
            return -1;
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        int count = 1 + this.accountNumbers.size();
        return count;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void notifyDataSetChanged() {
        super.notifyDataSetChanged();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        return true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType == 0) {
            view = new DrawerAddCell(this.mContext);
        } else {
            view = new PopUserCell(this.mContext);
        }
        view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
        return new RecyclerListView.Holder(view);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        if (holder.getItemViewType() == 1) {
            PopUserCell drawerUserCell = (PopUserCell) holder.itemView;
            drawerUserCell.setAccount(this.accountNumbers.get(position - 1).intValue());
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        if (i == 0) {
            return 0;
        }
        return 1;
    }
}
