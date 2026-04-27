package im.uwrkaxlmjj.ui.expand;

import android.os.Bundle;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.ui.expand.listeners.ExpandCollapseListener;
import im.uwrkaxlmjj.ui.expand.listeners.GroupExpandCollapseListener;
import im.uwrkaxlmjj.ui.expand.listeners.OnGroupClickListener;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.expand.models.ExpandableList;
import im.uwrkaxlmjj.ui.expand.models.ExpandableListPosition;
import im.uwrkaxlmjj.ui.expand.viewholders.ChildViewHolder;
import im.uwrkaxlmjj.ui.expand.viewholders.GroupViewHolder;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public abstract class ExpandableRecyclerViewAdapter<GVH extends GroupViewHolder, CVH extends ChildViewHolder> extends RecyclerView.Adapter implements ExpandCollapseListener, OnGroupClickListener {
    private static final String EXPAND_STATE_MAP = "expandable_recyclerview_adapter_expand_state_map";
    private ExpandCollapseController expandCollapseController;
    private GroupExpandCollapseListener expandCollapseListener;
    protected ExpandableList expandableList;
    private OnGroupClickListener groupClickListener;

    public abstract void onBindChildViewHolder(CVH cvh, int i, ExpandableGroup expandableGroup, int i2);

    public abstract void onBindGroupViewHolder(GVH gvh, int i, ExpandableGroup expandableGroup);

    public abstract CVH onCreateChildViewHolder(ViewGroup viewGroup, int i);

    public abstract GVH onCreateGroupViewHolder(ViewGroup viewGroup, int i);

    public ExpandableRecyclerViewAdapter(List<? extends ExpandableGroup> groups) {
        ExpandableList expandableList = new ExpandableList(groups);
        this.expandableList = expandableList;
        this.expandCollapseController = new ExpandCollapseController(expandableList, this);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        if (viewType == 1) {
            return onCreateChildViewHolder(parent, viewType);
        }
        if (viewType == 2) {
            GroupViewHolder groupViewHolderOnCreateGroupViewHolder = onCreateGroupViewHolder(parent, viewType);
            groupViewHolderOnCreateGroupViewHolder.setOnGroupClickListener(this);
            return groupViewHolderOnCreateGroupViewHolder;
        }
        throw new IllegalArgumentException("viewType is not valid");
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        ExpandableListPosition listPos = this.expandableList.getUnflattenedPosition(position);
        ExpandableGroup group = this.expandableList.getExpandableGroup(listPos);
        int i = listPos.type;
        if (i == 1) {
            onBindChildViewHolder((ChildViewHolder) holder, position, group, listPos.childPos);
            return;
        }
        if (i == 2) {
            onBindGroupViewHolder((GroupViewHolder) holder, position, group);
            if (isGroupExpanded(group)) {
                ((GroupViewHolder) holder).expand();
            } else {
                ((GroupViewHolder) holder).collapse();
            }
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.expandableList.getVisibleItemCount();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        return this.expandableList.getUnflattenedPosition(position).type;
    }

    @Override // im.uwrkaxlmjj.ui.expand.listeners.ExpandCollapseListener
    public void onGroupExpanded(int positionStart, int itemCount) {
        int headerPosition = positionStart - 1;
        notifyItemChanged(headerPosition);
        if (itemCount > 0) {
            notifyItemRangeInserted(positionStart, itemCount);
            if (this.expandCollapseListener != null) {
                int groupIndex = this.expandableList.getUnflattenedPosition(positionStart).groupPos;
                this.expandCollapseListener.onGroupExpanded(getGroups().get(groupIndex));
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.expand.listeners.ExpandCollapseListener
    public void onGroupCollapsed(int positionStart, int itemCount) {
        int headerPosition = positionStart - 1;
        notifyItemChanged(headerPosition);
        if (itemCount > 0) {
            notifyItemRangeRemoved(positionStart, itemCount);
            if (this.expandCollapseListener != null) {
                int groupIndex = this.expandableList.getUnflattenedPosition(positionStart - 1).groupPos;
                this.expandCollapseListener.onGroupCollapsed(getGroups().get(groupIndex));
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.expand.listeners.OnGroupClickListener
    public boolean onGroupClick(int flatPos) {
        OnGroupClickListener onGroupClickListener = this.groupClickListener;
        if (onGroupClickListener != null) {
            onGroupClickListener.onGroupClick(flatPos);
        }
        return this.expandCollapseController.toggleGroup(flatPos);
    }

    public boolean toggleGroup(int flatPos) {
        return this.expandCollapseController.toggleGroup(flatPos);
    }

    public boolean toggleGroup(ExpandableGroup group) {
        return this.expandCollapseController.toggleGroup(group);
    }

    public boolean isGroupExpanded(int flatPos) {
        return this.expandCollapseController.isGroupExpanded(flatPos);
    }

    public boolean isGroupExpanded(ExpandableGroup group) {
        return this.expandCollapseController.isGroupExpanded(group);
    }

    public void onSaveInstanceState(Bundle savedInstanceState) {
        savedInstanceState.putBooleanArray(EXPAND_STATE_MAP, this.expandableList.expandedGroupIndexes);
    }

    public void onRestoreInstanceState(Bundle savedInstanceState) {
        if (savedInstanceState == null || !savedInstanceState.containsKey(EXPAND_STATE_MAP)) {
            return;
        }
        this.expandableList.expandedGroupIndexes = savedInstanceState.getBooleanArray(EXPAND_STATE_MAP);
        notifyDataSetChanged();
    }

    public void setOnGroupClickListener(OnGroupClickListener listener) {
        this.groupClickListener = listener;
    }

    public void setOnGroupExpandCollapseListener(GroupExpandCollapseListener listener) {
        this.expandCollapseListener = listener;
    }

    public List<? extends ExpandableGroup> getGroups() {
        return this.expandableList.groups;
    }
}
