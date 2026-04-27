package im.uwrkaxlmjj.ui.expand;

import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.expand.models.ExpandableListPosition;
import im.uwrkaxlmjj.ui.expand.viewholders.ChildViewHolder;
import im.uwrkaxlmjj.ui.expand.viewholders.GroupViewHolder;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public abstract class MultiTypeExpandableRecyclerViewAdapter<GVH extends GroupViewHolder, CVH extends ChildViewHolder> extends ExpandableRecyclerViewAdapter<GVH, CVH> {
    public MultiTypeExpandableRecyclerViewAdapter(List<? extends ExpandableGroup> groups) {
        super(groups);
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        if (isGroup(viewType)) {
            GVH gvh = onCreateGroupViewHolder(parent, viewType);
            gvh.setOnGroupClickListener(this);
            return gvh;
        }
        if (isChild(viewType)) {
            CVH cvh = onCreateChildViewHolder(parent, viewType);
            return cvh;
        }
        throw new IllegalArgumentException("viewType is not valid");
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        ExpandableListPosition listPos = this.expandableList.getUnflattenedPosition(position);
        ExpandableGroup group = this.expandableList.getExpandableGroup(listPos);
        if (isGroup(getItemViewType(position))) {
            onBindGroupViewHolder((GroupViewHolder) holder, position, group);
            if (isGroupExpanded(group)) {
                ((GroupViewHolder) holder).expand();
                return;
            } else {
                ((GroupViewHolder) holder).collapse();
                return;
            }
        }
        if (isChild(getItemViewType(position))) {
            onBindChildViewHolder((ChildViewHolder) holder, position, group, listPos.childPos);
        }
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int position) {
        ExpandableListPosition listPosition = this.expandableList.getUnflattenedPosition(position);
        ExpandableGroup group = this.expandableList.getExpandableGroup(listPosition);
        int viewType = listPosition.type;
        if (viewType == 1) {
            return getChildViewType(position, group, listPosition.childPos);
        }
        if (viewType == 2) {
            return getGroupViewType(position, group);
        }
        return viewType;
    }

    public int getChildViewType(int position, ExpandableGroup group, int childIndex) {
        return super.getItemViewType(position);
    }

    public int getGroupViewType(int position, ExpandableGroup group) {
        return super.getItemViewType(position);
    }

    public boolean isGroup(int viewType) {
        return viewType == 2;
    }

    public boolean isChild(int viewType) {
        return viewType == 1;
    }
}
