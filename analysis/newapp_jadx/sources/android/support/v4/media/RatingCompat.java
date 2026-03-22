package android.support.v4.media;

import android.media.Rating;
import android.os.Parcel;
import android.os.Parcelable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class RatingCompat implements Parcelable {
    public static final Parcelable.Creator<RatingCompat> CREATOR = new C0015a();

    /* renamed from: c */
    public final int f35c;

    /* renamed from: e */
    public final float f36e;

    /* renamed from: f */
    public Object f37f;

    /* renamed from: android.support.v4.media.RatingCompat$a */
    public static class C0015a implements Parcelable.Creator<RatingCompat> {
        @Override // android.os.Parcelable.Creator
        public RatingCompat createFromParcel(Parcel parcel) {
            return new RatingCompat(parcel.readInt(), parcel.readFloat());
        }

        @Override // android.os.Parcelable.Creator
        public RatingCompat[] newArray(int i2) {
            return new RatingCompat[i2];
        }
    }

    public RatingCompat(int i2, float f2) {
        this.f35c = i2;
        this.f36e = f2;
    }

    /* renamed from: b */
    public static RatingCompat m13b(Object obj) {
        RatingCompat ratingCompat;
        float f2;
        RatingCompat ratingCompat2 = null;
        if (obj != null) {
            Rating rating = (Rating) obj;
            int ratingStyle = rating.getRatingStyle();
            if (!rating.isRated()) {
                switch (ratingStyle) {
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                        ratingCompat2 = new RatingCompat(ratingStyle, -1.0f);
                        break;
                }
            } else {
                switch (ratingStyle) {
                    case 1:
                        ratingCompat = new RatingCompat(1, rating.hasHeart() ? 1.0f : 0.0f);
                        ratingCompat2 = ratingCompat;
                        break;
                    case 2:
                        ratingCompat = new RatingCompat(2, rating.isThumbUp() ? 1.0f : 0.0f);
                        ratingCompat2 = ratingCompat;
                        break;
                    case 3:
                    case 4:
                    case 5:
                        float starRating = rating.getStarRating();
                        if (ratingStyle == 3) {
                            f2 = 3.0f;
                        } else if (ratingStyle == 4) {
                            f2 = 4.0f;
                        } else if (ratingStyle == 5) {
                            f2 = 5.0f;
                        }
                        if (starRating >= 0.0f && starRating <= f2) {
                            ratingCompat2 = new RatingCompat(ratingStyle, starRating);
                            break;
                        }
                        break;
                    case 6:
                        float percentRating = rating.getPercentRating();
                        if (percentRating >= 0.0f && percentRating <= 100.0f) {
                            ratingCompat2 = new RatingCompat(6, percentRating);
                            break;
                        }
                        break;
                    default:
                        return null;
                }
            }
            ratingCompat2.f37f = obj;
        }
        return ratingCompat2;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return this.f35c;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Rating:style=");
        m586H.append(this.f35c);
        m586H.append(" rating=");
        float f2 = this.f36e;
        m586H.append(f2 < 0.0f ? "unrated" : String.valueOf(f2));
        return m586H.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f35c);
        parcel.writeFloat(this.f36e);
    }
}
