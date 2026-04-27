package im.uwrkaxlmjj.ui.hui.adapter.grouping;

import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.hui.contacts.MyGroupingActivity;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GenreAdapter extends ExpandableRecyclerViewAdapter<GenreViewHolder, ArtistViewHolder> {
    private MyGroupingActivity activity;
    private Map<Integer, Boolean> expandStateMap;

    public GenreAdapter(List<Genre> groups, MyGroupingActivity activity) {
        super(groups);
        this.expandStateMap = new HashMap();
        this.activity = activity;
    }

    public MyGroupingActivity getActivity() {
        return this.activity;
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public GenreViewHolder onCreateGroupViewHolder(ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_contacts_grouping_layout, parent, false);
        view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        return new GenreViewHolder(view);
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public ArtistViewHolder onCreateChildViewHolder(ViewGroup parent, int viewType) {
        SwipeLayout swipeLayout = new SwipeLayout(parent.getContext()) { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.GenreAdapter.1
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (isExpanded()) {
                    return true;
                }
                return super.onTouchEvent(event);
            }
        };
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_contacts_grouping_child_layout, parent, false);
        swipeLayout.setUpView(view);
        swipeLayout.setNeedDivderBetweenMainAndMenu(false);
        swipeLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        return new ArtistViewHolder(swipeLayout);
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public void onBindChildViewHolder(ArtistViewHolder holder, int flatPosition, ExpandableGroup group, int childIndex) {
        Genre genre = (Genre) group;
        Artist artist = genre.getItems().get(childIndex);
        holder.setUserData(artist, genre, this);
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public void onBindGroupViewHolder(GenreViewHolder holder, int flatPosition, ExpandableGroup group) {
        holder.setGenreData(group, flatPosition, getGroups());
    }

    public void storeExpandState() {
        this.expandStateMap.clear();
        if (this.expandableList.groups != null && this.expandableList.expandedGroupIndexes != null && this.expandableList.groups.size() == this.expandableList.expandedGroupIndexes.length) {
            for (int i = 0; i < this.expandableList.groups.size(); i++) {
                this.expandStateMap.put(Integer.valueOf(((Genre) this.expandableList.groups.get(i)).getGroupId()), Boolean.valueOf(this.expandableList.expandedGroupIndexes[i]));
            }
        }
    }

    public void restoreExpandState() {
        if (this.expandableList.groups != null) {
            this.expandableList.expandedGroupIndexes = new boolean[this.expandableList.groups.size()];
            for (int i = 0; i < this.expandableList.groups.size(); i++) {
                Genre genre = (Genre) this.expandableList.groups.get(i);
                this.expandableList.expandedGroupIndexes[i] = this.expandStateMap.get(Integer.valueOf(genre.getGroupId())) != null ? this.expandStateMap.get(Integer.valueOf(genre.getGroupId())).booleanValue() : false;
            }
        }
    }
}
