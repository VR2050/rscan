package im.uwrkaxlmjj.javaBean;

import android.os.Parcel;
import android.os.Parcelable;

/* JADX INFO: loaded from: classes2.dex */
public class AllTokenResponse implements Parcelable {
    public static final Parcelable.Creator<AllTokenResponse> CREATOR = new Parcelable.Creator<AllTokenResponse>() { // from class: im.uwrkaxlmjj.javaBean.AllTokenResponse.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public AllTokenResponse createFromParcel(Parcel in) {
            return new AllTokenResponse(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public AllTokenResponse[] newArray(int size) {
            return new AllTokenResponse[size];
        }
    };
    private String gametoken;
    private String momenttoken;

    public AllTokenResponse(String momenttoken, String gametoken) {
        this.momenttoken = momenttoken;
        this.gametoken = gametoken;
    }

    protected AllTokenResponse(Parcel in) {
        this.momenttoken = in.readString();
        this.gametoken = in.readString();
    }

    public String getMomenttoken() {
        return this.momenttoken;
    }

    public void setMomenttoken(String momenttoken) {
        this.momenttoken = momenttoken;
    }

    public String getGametoken() {
        return this.gametoken;
    }

    public void setGametoken(String gametoken) {
        this.gametoken = gametoken;
    }

    public String toString() {
        return "AllTokenResponse{momenttoken='" + this.momenttoken + "', gametoken='" + this.gametoken + "'}";
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.momenttoken);
        dest.writeString(this.gametoken);
    }
}
