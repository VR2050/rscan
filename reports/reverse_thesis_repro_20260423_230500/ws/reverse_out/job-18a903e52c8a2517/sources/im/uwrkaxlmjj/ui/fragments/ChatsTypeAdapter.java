package im.uwrkaxlmjj.ui.fragments;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.cells.PopMenuCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatsTypeAdapter extends RecyclerListView.SelectionAdapter {
    private Context mContext;
    private ArrayList<Integer> iconsList = new ArrayList<>();
    private ArrayList<String> namesList = new ArrayList<>();

    public ChatsTypeAdapter(Context context) {
        this.mContext = context;
        init();
    }

    private void init() {
        if (this.iconsList.isEmpty()) {
            this.iconsList.add(Integer.valueOf(R.id.ic_pop_user_selected));
            this.iconsList.add(Integer.valueOf(R.id.ic_pop_groups_selected));
            this.iconsList.add(Integer.valueOf(R.id.ic_pop_channels_selected));
            this.iconsList.add(Integer.valueOf(R.id.ic_pop_unread_selected));
            this.iconsList.add(Integer.valueOf(R.id.ic_pop_chats_selected));
        }
        if (this.namesList.isEmpty()) {
            this.namesList.add(LocaleController.getString(R.string.Users));
            this.namesList.add(LocaleController.getString(R.string.MyGroups));
            this.namesList.add(LocaleController.getString(R.string.MyChannels));
            this.namesList.add(LocaleController.getString(R.string.UnreadMsg));
            this.namesList.add(LocaleController.getString(R.string.Chats));
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.iconsList.size();
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
        View view = new PopMenuCell(this.mContext);
        view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
        return new RecyclerListView.Holder(view);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        PopMenuCell cell = (PopMenuCell) holder.itemView;
        cell.setTextAndIcon(this.namesList.get(position), this.iconsList.get(position).intValue());
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        return 0;
    }
}
