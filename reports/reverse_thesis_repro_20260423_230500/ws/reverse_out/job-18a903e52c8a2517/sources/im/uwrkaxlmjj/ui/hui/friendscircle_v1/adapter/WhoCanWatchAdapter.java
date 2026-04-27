package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.components.CheckBox2;
import im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.expand.viewholders.ChildViewHolder;
import im.uwrkaxlmjj.ui.expand.viewholders.GroupViewHolder;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WhoCanWatchAdapter extends ExpandableRecyclerViewAdapter<GroupHoder, ChildHolder> {
    private Context context;

    public WhoCanWatchAdapter(Context context, List list) {
        super(list);
        this.context = context;
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public GroupHoder onCreateGroupViewHolder(ViewGroup parent, int viewType) {
        return new GroupHoder(LayoutInflater.from(this.context).inflate(R.layout.item_fc_who_can_watch_group, parent, false));
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public ChildHolder onCreateChildViewHolder(ViewGroup parent, int viewType) {
        return new ChildHolder(LayoutInflater.from(this.context).inflate(R.layout.item_fc_who_can_watch_child, parent, false));
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public void onBindGroupViewHolder(GroupHoder holder, int flatPosition, ExpandableGroup group) {
        Item item = (Item) group;
        holder.tvTitle.setText(item.getTitle());
        holder.tvSubTitle.setText(item.subTitle);
        holder.checkBox.setChecked(item.isSelected, true);
    }

    @Override // im.uwrkaxlmjj.ui.expand.ExpandableRecyclerViewAdapter
    public void onBindChildViewHolder(ChildHolder holder, int flatPosition, ExpandableGroup group, int childIndex) {
    }

    public static List<Item> createData() {
        List<Item> list = new ArrayList<>();
        list.add(new Item(LocaleController.getString(R.string.TypePrivate2), null));
        list.add(new Item(LocaleController.getString(R.string.TypePrivate2), null));
        return list;
    }

    public static class Item extends ExpandableGroup<ItemChild> {
        public boolean isSelected;
        public String subTitle;

        public Item(String title, List<ItemChild> items) {
            super(title, items);
        }
    }

    public static class ItemChild implements Parcelable {
        public static final Parcelable.Creator<ItemChild> CREATOR = new Parcelable.Creator<ItemChild>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.WhoCanWatchAdapter.ItemChild.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            public ItemChild createFromParcel(Parcel in) {
                return new ItemChild(in);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            public ItemChild[] newArray(int size) {
                return new ItemChild[size];
            }
        };
        public String content;
        public String title;

        public ItemChild(String title) {
            this.title = title;
        }

        protected ItemChild(Parcel in) {
            this.title = in.readString();
            this.content = in.readString();
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel dest, int flags) {
            dest.writeString(this.title);
            dest.writeString(this.content);
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }
    }

    public static class GroupHoder extends GroupViewHolder {
        public CheckBox2 checkBox;
        public ImageView ivArrow;
        public MryTextView tvSubTitle;
        public MryTextView tvTitle;

        public GroupHoder(View itemView) {
            super(itemView);
            this.checkBox = (CheckBox2) itemView.findViewById(R.attr.checkBox);
            this.tvTitle = (MryTextView) itemView.findViewById(R.attr.tvTitle);
            this.tvSubTitle = (MryTextView) itemView.findViewById(R.attr.tvSubTitle);
            this.ivArrow = (ImageView) itemView.findViewById(R.attr.ivArrow);
        }
    }

    public static class ChildHolder extends ChildViewHolder {
        public MryTextView tvContent;
        public MryTextView tvTitle;

        public ChildHolder(View itemView) {
            super(itemView);
            this.tvTitle = (MryTextView) itemView.findViewById(R.attr.tvTitle);
            this.tvContent = (MryTextView) itemView.findViewById(R.attr.tvContent);
        }
    }
}
