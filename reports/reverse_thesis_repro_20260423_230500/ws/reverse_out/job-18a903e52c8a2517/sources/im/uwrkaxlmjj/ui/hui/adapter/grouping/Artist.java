package im.uwrkaxlmjj.ui.hui.adapter.grouping;

import android.os.Parcel;
import android.os.Parcelable;

/* JADX INFO: loaded from: classes5.dex */
public class Artist implements Parcelable {
    public static final Parcelable.Creator<Artist> CREATOR = new Parcelable.Creator<Artist>() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.Artist.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public Artist createFromParcel(Parcel in) {
            return new Artist(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public Artist[] newArray(int size) {
            return new Artist[size];
        }
    };
    private int userId;

    public Artist(int userId) {
        this.userId = userId;
    }

    protected Artist(Parcel in) {
        this.userId = in.readInt();
    }

    public int getUserId() {
        return this.userId;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Artist)) {
            return false;
        }
        Artist artist = (Artist) o;
        return this.userId == artist.getUserId();
    }

    public int hashCode() {
        return this.userId;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.userId);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }
}
