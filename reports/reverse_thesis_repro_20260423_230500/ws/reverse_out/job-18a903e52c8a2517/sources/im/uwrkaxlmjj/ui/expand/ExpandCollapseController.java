package im.uwrkaxlmjj.ui.expand;

import im.uwrkaxlmjj.ui.expand.listeners.ExpandCollapseListener;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.expand.models.ExpandableList;
import im.uwrkaxlmjj.ui.expand.models.ExpandableListPosition;

/* JADX INFO: loaded from: classes5.dex */
public class ExpandCollapseController {
    private ExpandableList expandableList;
    private ExpandCollapseListener listener;

    public ExpandCollapseController(ExpandableList expandableList, ExpandCollapseListener listener) {
        this.expandableList = expandableList;
        this.listener = listener;
    }

    private void collapseGroup(ExpandableListPosition listPosition) {
        this.expandableList.expandedGroupIndexes[listPosition.groupPos] = false;
        ExpandCollapseListener expandCollapseListener = this.listener;
        if (expandCollapseListener != null) {
            expandCollapseListener.onGroupCollapsed(this.expandableList.getFlattenedGroupIndex(listPosition) + 1, this.expandableList.groups.get(listPosition.groupPos).getItemCount());
        }
    }

    private void expandGroup(ExpandableListPosition listPosition) {
        this.expandableList.expandedGroupIndexes[listPosition.groupPos] = true;
        ExpandCollapseListener expandCollapseListener = this.listener;
        if (expandCollapseListener != null) {
            expandCollapseListener.onGroupExpanded(this.expandableList.getFlattenedGroupIndex(listPosition) + 1, this.expandableList.groups.get(listPosition.groupPos).getItemCount());
        }
    }

    public boolean isGroupExpanded(ExpandableGroup group) {
        int groupIndex = this.expandableList.groups.indexOf(group);
        return this.expandableList.expandedGroupIndexes[groupIndex];
    }

    public boolean isGroupExpanded(int flatPos) {
        ExpandableListPosition listPosition = this.expandableList.getUnflattenedPosition(flatPos);
        return this.expandableList.expandedGroupIndexes[listPosition.groupPos];
    }

    public boolean toggleGroup(int flatPos) {
        ExpandableListPosition listPos = this.expandableList.getUnflattenedPosition(flatPos);
        boolean expanded = this.expandableList.expandedGroupIndexes[listPos.groupPos];
        if (expanded) {
            collapseGroup(listPos);
        } else {
            expandGroup(listPos);
        }
        return expanded;
    }

    public boolean toggleGroup(ExpandableGroup group) {
        ExpandableList expandableList = this.expandableList;
        ExpandableListPosition listPos = expandableList.getUnflattenedPosition(expandableList.getFlattenedGroupIndex(group));
        boolean expanded = this.expandableList.expandedGroupIndexes[listPos.groupPos];
        if (expanded) {
            collapseGroup(listPos);
        } else {
            expandGroup(listPos);
        }
        return expanded;
    }
}
