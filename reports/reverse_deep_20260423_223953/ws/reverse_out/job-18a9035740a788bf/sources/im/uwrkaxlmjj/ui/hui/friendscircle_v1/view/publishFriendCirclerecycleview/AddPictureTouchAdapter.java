package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public abstract class AddPictureTouchAdapter<T, VH extends RecyclerView.ViewHolder> extends ItemTouchAdapter<T, VH> {
    public static final int VIEW_TYPE_ADD_ITEM = 1;
    public static final int VIEW_TYPE_NORMAL = 0;
    private int maxCount;
    private AddPictureOnItemClickListener<T> onItemClickListener;

    public interface AddPictureOnItemClickListener<T> {
        void onItemClick(T t, boolean z);
    }

    protected abstract void onBindViewHolder(VH vh, int i, T t, boolean z);

    public AddPictureTouchAdapter(Context context) {
        super(context);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public final void onBindViewHolder(final VH holder, final int position) {
        holder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.AddPictureTouchAdapter.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (AddPictureTouchAdapter.this.onItemClickListener != null) {
                    AddPictureTouchAdapter.this.onItemClickListener.onItemClick(holder.getItemViewType() == 1 ? null : AddPictureTouchAdapter.this.getItem(position), holder.getItemViewType() == 1);
                }
            }
        });
        onBindViewHolder(holder, position, getItem(position), holder.getItemViewType() == 1);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        return (checkIsFull() || position != getItemCount() - 1) ? 0 : 1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return checkIsFull() ? this.maxCount : getDataCount() + 1;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview.ItemTouchAdapter
    protected void notifyChanged() {
        super.notifyChanged();
        if (checkIsFull()) {
            this.mCannotMovePositionList = null;
        } else {
            this.mCannotMovePositionList = new ArrayList();
            this.mCannotMovePositionList.add(Integer.valueOf(getItemCount() - 1));
        }
    }

    protected boolean checkIsFull() {
        return getDataCount() == this.maxCount;
    }

    public void setMaxCount(int maxCount) {
        this.maxCount = maxCount;
    }

    public int getMaxSelectCount() {
        return this.maxCount;
    }

    public void setOnItemClickListener(AddPictureOnItemClickListener<T> onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
    }
}
