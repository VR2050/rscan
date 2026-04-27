package im.uwrkaxlmjj.ui.expand.models;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class ExpandableGroup<T extends Parcelable> implements Parcelable {
    public static final Parcelable.Creator<ExpandableGroup> CREATOR = new Parcelable.Creator<ExpandableGroup>() { // from class: im.uwrkaxlmjj.ui.expand.models.ExpandableGroup.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public ExpandableGroup createFromParcel(Parcel in) {
            return new ExpandableGroup(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public ExpandableGroup[] newArray(int size) {
            return new ExpandableGroup[size];
        }
    };
    private List<T> items;
    private String title;

    public ExpandableGroup(String title, List<T> items) {
        this.title = title;
        this.items = items;
    }

    public String getTitle() {
        return this.title;
    }

    public List<T> getItems() {
        return this.items;
    }

    public int getItemCount() {
        List<T> list = this.items;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    public String toString() {
        return "ExpandableGroup{title='" + this.title + "', items=" + this.items + '}';
    }

    protected ExpandableGroup(Parcel in) {
        this.title = in.readString();
        byte hasItems = in.readByte();
        int size = in.readInt();
        if (hasItems == 1) {
            this.items = new ArrayList(size);
            Class<?> type = (Class) in.readSerializable();
            in.readList(this.items, type.getClassLoader());
            return;
        }
        this.items = null;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.title);
        if (this.items == null) {
            dest.writeByte((byte) 0);
            dest.writeInt(0);
            return;
        }
        dest.writeByte((byte) 1);
        dest.writeInt(this.items.size());
        Class<?> objectsType = this.items.get(0).getClass();
        dest.writeSerializable(objectsType);
        dest.writeList(this.items);
    }
}
