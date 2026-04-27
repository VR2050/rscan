package im.uwrkaxlmjj.ui.expand.viewholders;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.ui.expand.listeners.OnGroupClickListener;

/* JADX INFO: loaded from: classes5.dex */
public abstract class GroupViewHolder extends RecyclerView.ViewHolder implements View.OnClickListener {
    private OnGroupClickListener listener;

    public GroupViewHolder(View itemView) {
        super(itemView);
        itemView.setOnClickListener(this);
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        OnGroupClickListener onGroupClickListener = this.listener;
        if (onGroupClickListener != null) {
            onGroupClickListener.onGroupClick(getAdapterPosition());
        }
    }

    public void setOnGroupClickListener(OnGroupClickListener listener) {
        this.listener = listener;
    }

    public void expand() {
    }

    public void collapse() {
    }
}
