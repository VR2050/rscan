package com.jbzd.media.movecartoons.bean.response;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0014\n\u0002\u0010 \n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u0000 D2\u00020\u0001:\u0003DEFB\u0007¢\u0006\u0004\bA\u0010BB\u0011\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\bA\u0010CJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\nR$\u0010\f\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R$\u0010\u0012\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0012\u0010\r\u001a\u0004\b\u0013\u0010\u000f\"\u0004\b\u0014\u0010\u0011R$\u0010\u0015\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0015\u0010\r\u001a\u0004\b\u0016\u0010\u000f\"\u0004\b\u0017\u0010\u0011R\"\u0010\u0018\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\n\"\u0004\b\u001b\u0010\u001cR$\u0010\u001d\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001d\u0010\r\u001a\u0004\b\u001e\u0010\u000f\"\u0004\b\u001f\u0010\u0011R*\u0010!\u001a\n\u0012\u0004\u0012\u00020\u0000\u0018\u00010 8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b!\u0010\"\u001a\u0004\b#\u0010$\"\u0004\b%\u0010&R$\u0010'\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b'\u0010\r\u001a\u0004\b(\u0010\u000f\"\u0004\b)\u0010\u0011R$\u0010*\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b*\u0010\r\u001a\u0004\b+\u0010\u000f\"\u0004\b,\u0010\u0011R$\u0010-\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b-\u0010\r\u001a\u0004\b.\u0010\u000f\"\u0004\b/\u0010\u0011R*\u00101\u001a\n\u0012\u0004\u0012\u000200\u0018\u00010 8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b1\u0010\"\u001a\u0004\b2\u0010$\"\u0004\b3\u0010&R\"\u00104\u001a\u00020\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b4\u0010\r\u001a\u0004\b5\u0010\u000f\"\u0004\b6\u0010\u0011R$\u00107\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b7\u0010\r\u001a\u0004\b8\u0010\u000f\"\u0004\b9\u0010\u0011R*\u0010;\u001a\n\u0012\u0004\u0012\u00020:\u0018\u00010 8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b;\u0010\"\u001a\u0004\b<\u0010$\"\u0004\b=\u0010&R$\u0010>\u001a\u0004\u0018\u00010\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b>\u0010\r\u001a\u0004\b?\u0010\u000f\"\u0004\b@\u0010\u0011¨\u0006G"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "Landroid/os/Parcelable;", "Landroid/os/Parcel;", "parcel", "", "flags", "", "writeToParcel", "(Landroid/os/Parcel;I)V", "describeContents", "()I", "", "end_time", "Ljava/lang/String;", "getEnd_time", "()Ljava/lang/String;", "setEnd_time", "(Ljava/lang/String;)V", "img", "getImg", "setImg", "priceZero", "getPriceZero", "setPriceZero", "level", "I", "getLevel", "setLevel", "(I)V", "old_price", "getOld_price", "setOld_price", "", "items", "Ljava/util/List;", "getItems", "()Ljava/util/List;", "setItems", "(Ljava/util/List;)V", "day_tips", "getDay_tips", "setDay_tips", "description", "getDescription", "setDescription", "price", "getPrice", "setPrice", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "payments", "getPayments", "setPayments", "id", "getId", "setId", "name", "getName", "setName", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$RightsBean;", "rights", "getRights", "setRights", "button_text", "getButton_text", "setButton_text", "<init>", "()V", "(Landroid/os/Parcel;)V", "CREATOR", "PaymentsBean", "RightsBean", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class GroupBean implements Parcelable {

    /* renamed from: CREATOR, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private String button_text;

    @Nullable
    private String day_tips;

    @Nullable
    private String description;

    @Nullable
    private String end_time;

    @NotNull
    private String id;

    @Nullable
    private String img;

    @Nullable
    private List<GroupBean> items;
    private int level;

    @Nullable
    private String name;

    @Nullable
    private String old_price;

    @Nullable
    private List<PaymentsBean> payments;

    @Nullable
    private String price;

    @Nullable
    private String priceZero;

    @Nullable
    private List<RightsBean> rights;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u0005\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u001f\u0010\n\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\t2\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\u000b¨\u0006\u000e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/GroupBean$CREATOR;", "Landroid/os/Parcelable$Creator;", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "Landroid/os/Parcel;", "parcel", "createFromParcel", "(Landroid/os/Parcel;)Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "", "size", "", "newArray", "(I)[Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    /* renamed from: com.jbzd.media.movecartoons.bean.response.GroupBean$CREATOR, reason: from kotlin metadata */
    public static final class Companion implements Parcelable.Creator<GroupBean> {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        @NotNull
        public GroupBean createFromParcel(@NotNull Parcel parcel) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            return new GroupBean(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        @NotNull
        public GroupBean[] newArray(int size) {
            return new GroupBean[size];
        }
    }

    public GroupBean() {
        this.id = "";
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Nullable
    public final String getButton_text() {
        return this.button_text;
    }

    @Nullable
    public final String getDay_tips() {
        return this.day_tips;
    }

    @Nullable
    public final String getDescription() {
        return this.description;
    }

    @Nullable
    public final String getEnd_time() {
        return this.end_time;
    }

    @NotNull
    public final String getId() {
        return this.id;
    }

    @Nullable
    public final String getImg() {
        return this.img;
    }

    @Nullable
    public final List<GroupBean> getItems() {
        return this.items;
    }

    public final int getLevel() {
        return this.level;
    }

    @Nullable
    public final String getName() {
        return this.name;
    }

    @Nullable
    public final String getOld_price() {
        return this.old_price;
    }

    @Nullable
    public final List<PaymentsBean> getPayments() {
        return this.payments;
    }

    @Nullable
    public final String getPrice() {
        return this.price;
    }

    @Nullable
    public final String getPriceZero() {
        return this.priceZero;
    }

    @Nullable
    public final List<RightsBean> getRights() {
        return this.rights;
    }

    public final void setButton_text(@Nullable String str) {
        this.button_text = str;
    }

    public final void setDay_tips(@Nullable String str) {
        this.day_tips = str;
    }

    public final void setDescription(@Nullable String str) {
        this.description = str;
    }

    public final void setEnd_time(@Nullable String str) {
        this.end_time = str;
    }

    public final void setId(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.id = str;
    }

    public final void setImg(@Nullable String str) {
        this.img = str;
    }

    public final void setItems(@Nullable List<GroupBean> list) {
        this.items = list;
    }

    public final void setLevel(int i2) {
        this.level = i2;
    }

    public final void setName(@Nullable String str) {
        this.name = str;
    }

    public final void setOld_price(@Nullable String str) {
        this.old_price = str;
    }

    public final void setPayments(@Nullable List<PaymentsBean> list) {
        this.payments = list;
    }

    public final void setPrice(@Nullable String str) {
        this.price = str;
    }

    public final void setPriceZero(@Nullable String str) {
        this.priceZero = str;
    }

    public final void setRights(@Nullable List<RightsBean> list) {
        this.rights = list;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(@NotNull Parcel parcel, int flags) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.writeString(this.img);
        parcel.writeInt(this.level);
        parcel.writeString(this.day_tips);
        parcel.writeString(this.price);
        parcel.writeString(this.old_price);
        parcel.writeString(this.name);
        parcel.writeString(this.end_time);
        parcel.writeString(this.description);
        parcel.writeString(this.id);
        parcel.writeString(this.button_text);
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0014\u0018\u0000 $2\u00020\u0001:\u0001$B\u0007¢\u0006\u0004\b!\u0010\"B\u0011\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b!\u0010#J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\nR\"\u0010\f\u001a\u00020\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\f\u0010\u000e\"\u0004\b\u000f\u0010\u0010R\"\u0010\u0012\u001a\u00020\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017R$\u0010\u0018\u001a\u0004\u0018\u00010\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0018\u0010\u0013\u001a\u0004\b\u0019\u0010\u0015\"\u0004\b\u001a\u0010\u0017R$\u0010\u001b\u001a\u0004\u0018\u00010\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001b\u0010\u0013\u001a\u0004\b\u001c\u0010\u0015\"\u0004\b\u001d\u0010\u0017R$\u0010\u001e\u001a\u0004\u0018\u00010\u00118\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001e\u0010\u0013\u001a\u0004\b\u001f\u0010\u0015\"\u0004\b \u0010\u0017¨\u0006%"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "Landroid/os/Parcelable;", "Landroid/os/Parcel;", "parcel", "", "flags", "", "writeToParcel", "(Landroid/os/Parcel;I)V", "describeContents", "()I", "", "isChecked", "Z", "()Z", "setChecked", "(Z)V", "", "payment_id", "Ljava/lang/String;", "getPayment_id", "()Ljava/lang/String;", "setPayment_id", "(Ljava/lang/String;)V", "payment_name", "getPayment_name", "setPayment_name", "type", "getType", "setType", "payment_ico", "getPayment_ico", "setPayment_ico", "<init>", "()V", "(Landroid/os/Parcel;)V", "CREATOR", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class PaymentsBean implements Parcelable {

        /* renamed from: CREATOR, reason: from kotlin metadata */
        @NotNull
        public static final Companion INSTANCE = new Companion(null);
        private boolean isChecked;

        @Nullable
        private String payment_ico;

        @NotNull
        private String payment_id;

        @Nullable
        private String payment_name;

        @Nullable
        private String type;

        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u0005\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u001f\u0010\n\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\t2\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\u000b¨\u0006\u000e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean$CREATOR;", "Landroid/os/Parcelable$Creator;", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "Landroid/os/Parcel;", "parcel", "createFromParcel", "(Landroid/os/Parcel;)Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "", "size", "", "newArray", "(I)[Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
        /* renamed from: com.jbzd.media.movecartoons.bean.response.GroupBean$PaymentsBean$CREATOR, reason: from kotlin metadata */
        public static final class Companion implements Parcelable.Creator<PaymentsBean> {
            private Companion() {
            }

            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            @NotNull
            public PaymentsBean createFromParcel(@NotNull Parcel parcel) {
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new PaymentsBean(parcel);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            @NotNull
            public PaymentsBean[] newArray(int size) {
                return new PaymentsBean[size];
            }
        }

        public PaymentsBean() {
            this.payment_id = "";
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Nullable
        public final String getPayment_ico() {
            return this.payment_ico;
        }

        @NotNull
        public final String getPayment_id() {
            return this.payment_id;
        }

        @Nullable
        public final String getPayment_name() {
            return this.payment_name;
        }

        @Nullable
        public final String getType() {
            return this.type;
        }

        /* renamed from: isChecked, reason: from getter */
        public final boolean getIsChecked() {
            return this.isChecked;
        }

        public final void setChecked(boolean z) {
            this.isChecked = z;
        }

        public final void setPayment_ico(@Nullable String str) {
            this.payment_ico = str;
        }

        public final void setPayment_id(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.payment_id = str;
        }

        public final void setPayment_name(@Nullable String str) {
            this.payment_name = str;
        }

        public final void setType(@Nullable String str) {
            this.type = str;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(@NotNull Parcel parcel, int flags) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            parcel.writeString(this.payment_id);
            parcel.writeString(this.payment_ico);
            parcel.writeString(this.payment_name);
            parcel.writeString(this.type);
        }

        /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
        public PaymentsBean(@NotNull Parcel parcel) {
            this();
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            String readString = parcel.readString();
            this.payment_id = readString == null ? "" : readString;
            this.payment_ico = parcel.readString();
            this.payment_name = parcel.readString();
            this.type = parcel.readString();
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u000e\u0018\u0000 \u00182\u00020\u0001:\u0001\u0018B\u0007¢\u0006\u0004\b\u0015\u0010\u0016B\u0011\b\u0016\u0012\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0015\u0010\u0017J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\nR\"\u0010\f\u001a\u00020\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R\"\u0010\u0012\u001a\u00020\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0012\u0010\r\u001a\u0004\b\u0013\u0010\u000f\"\u0004\b\u0014\u0010\u0011¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/GroupBean$RightsBean;", "Landroid/os/Parcelable;", "Landroid/os/Parcel;", "parcel", "", "flags", "", "writeToParcel", "(Landroid/os/Parcel;I)V", "describeContents", "()I", "", "name", "Ljava/lang/String;", "getName", "()Ljava/lang/String;", "setName", "(Ljava/lang/String;)V", "code", "getCode", "setCode", "<init>", "()V", "(Landroid/os/Parcel;)V", "CREATOR", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class RightsBean implements Parcelable {

        /* renamed from: CREATOR, reason: from kotlin metadata */
        @NotNull
        public static final Companion INSTANCE = new Companion(null);

        @NotNull
        private String code;

        @NotNull
        private String name;

        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u0005\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u001f\u0010\n\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\t2\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\u000b¨\u0006\u000e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/GroupBean$RightsBean$CREATOR;", "Landroid/os/Parcelable$Creator;", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$RightsBean;", "Landroid/os/Parcel;", "parcel", "createFromParcel", "(Landroid/os/Parcel;)Lcom/jbzd/media/movecartoons/bean/response/GroupBean$RightsBean;", "", "size", "", "newArray", "(I)[Lcom/jbzd/media/movecartoons/bean/response/GroupBean$RightsBean;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
        /* renamed from: com.jbzd.media.movecartoons.bean.response.GroupBean$RightsBean$CREATOR, reason: from kotlin metadata */
        public static final class Companion implements Parcelable.Creator<RightsBean> {
            private Companion() {
            }

            public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            @NotNull
            public RightsBean createFromParcel(@NotNull Parcel parcel) {
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new RightsBean(parcel);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.Creator
            @NotNull
            public RightsBean[] newArray(int size) {
                return new RightsBean[size];
            }
        }

        public RightsBean() {
            this.code = "";
            this.name = "";
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @NotNull
        public final String getCode() {
            return this.code;
        }

        @NotNull
        public final String getName() {
            return this.name;
        }

        public final void setCode(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.code = str;
        }

        public final void setName(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.name = str;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(@NotNull Parcel parcel, int flags) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            parcel.writeString(this.code);
            parcel.writeString(this.name);
        }

        /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
        public RightsBean(@NotNull Parcel parcel) {
            this();
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            String readString = parcel.readString();
            this.code = readString == null ? "" : readString;
            String readString2 = parcel.readString();
            this.name = readString2 != null ? readString2 : "";
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public GroupBean(@NotNull Parcel parcel) {
        this();
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        this.img = parcel.readString();
        this.level = parcel.readInt();
        this.day_tips = parcel.readString();
        String readString = parcel.readString();
        this.price = readString;
        this.priceZero = Intrinsics.stringPlus(readString, ".00");
        this.old_price = parcel.readString();
        this.name = parcel.readString();
        this.end_time = parcel.readString();
        this.description = parcel.readString();
        String readString2 = parcel.readString();
        this.id = readString2 == null ? "" : readString2;
        this.button_text = parcel.readString();
    }
}
