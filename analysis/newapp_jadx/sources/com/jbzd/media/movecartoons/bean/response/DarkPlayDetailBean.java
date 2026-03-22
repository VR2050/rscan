package com.jbzd.media.movecartoons.bean.response;

import androidx.appcompat.widget.ActivityChooserModel;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b \n\u0002\u0010\u000b\n\u0002\b\u001d\b\u0086\b\u0018\u00002\u00020\u0001B\u00ad\u0002\u0012\n\b\u0002\u0010!\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\"\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010#\u001a\u0004\u0018\u00010\u0002\u0012\u001c\b\u0002\u0010$\u001a\u0016\u0012\u0004\u0012\u00020\b\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\b\u0018\u0001`\t\u0012\u001c\b\u0002\u0010%\u001a\u0016\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u0002\u0018\u0001`\t\u0012\n\b\u0002\u0010&\u001a\u0004\u0018\u00010\r\u0012\n\b\u0002\u0010'\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010(\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010)\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010*\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010+\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010,\u001a\u0004\u0018\u00010\u0015\u0012\n\b\u0002\u0010-\u001a\u0004\u0018\u00010\u0015\u0012\n\b\u0002\u0010.\u001a\u0004\u0018\u00010\u0002\u0012\u001c\b\u0002\u0010/\u001a\u0016\u0012\u0004\u0012\u00020\u001a\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u001a\u0018\u0001`\t\u0012\n\b\u0002\u00100\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u00101\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u00102\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u00103\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u00104\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\bV\u0010WJ\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0012\u0010\u0005\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0004J$\u0010\n\u001a\u0016\u0012\u0004\u0012\u00020\b\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\b\u0018\u0001`\tHÆ\u0003¢\u0006\u0004\b\n\u0010\u000bJ$\u0010\f\u001a\u0016\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u0002\u0018\u0001`\tHÆ\u0003¢\u0006\u0004\b\f\u0010\u000bJ\u0012\u0010\u000e\u001a\u0004\u0018\u00010\rHÆ\u0003¢\u0006\u0004\b\u000e\u0010\u000fJ\u0012\u0010\u0010\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0010\u0010\u0004J\u0012\u0010\u0011\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0011\u0010\u0004J\u0012\u0010\u0012\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0012\u0010\u0004J\u0012\u0010\u0013\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0013\u0010\u0004J\u0012\u0010\u0014\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0014\u0010\u0004J\u0012\u0010\u0016\u001a\u0004\u0018\u00010\u0015HÆ\u0003¢\u0006\u0004\b\u0016\u0010\u0017J\u0012\u0010\u0018\u001a\u0004\u0018\u00010\u0015HÆ\u0003¢\u0006\u0004\b\u0018\u0010\u0017J\u0012\u0010\u0019\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0019\u0010\u0004J$\u0010\u001b\u001a\u0016\u0012\u0004\u0012\u00020\u001a\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u001a\u0018\u0001`\tHÆ\u0003¢\u0006\u0004\b\u001b\u0010\u000bJ\u0012\u0010\u001c\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u001c\u0010\u0004J\u0012\u0010\u001d\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u001d\u0010\u0004J\u0012\u0010\u001e\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u001e\u0010\u0004J\u0012\u0010\u001f\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u001f\u0010\u0004J\u0012\u0010 \u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b \u0010\u0004J¶\u0002\u00105\u001a\u00020\u00002\n\b\u0002\u0010!\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\"\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010#\u001a\u0004\u0018\u00010\u00022\u001c\b\u0002\u0010$\u001a\u0016\u0012\u0004\u0012\u00020\b\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\b\u0018\u0001`\t2\u001c\b\u0002\u0010%\u001a\u0016\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u0002\u0018\u0001`\t2\n\b\u0002\u0010&\u001a\u0004\u0018\u00010\r2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010(\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010)\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010*\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010+\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010,\u001a\u0004\u0018\u00010\u00152\n\b\u0002\u0010-\u001a\u0004\u0018\u00010\u00152\n\b\u0002\u0010.\u001a\u0004\u0018\u00010\u00022\u001c\b\u0002\u0010/\u001a\u0016\u0012\u0004\u0012\u00020\u001a\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u001a\u0018\u0001`\t2\n\b\u0002\u00100\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u00101\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u00102\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u00103\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u00104\u001a\u0004\u0018\u00010\u0002HÆ\u0001¢\u0006\u0004\b5\u00106J\u0010\u00107\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b7\u0010\u0004J\u0010\u00108\u001a\u00020\u0015HÖ\u0001¢\u0006\u0004\b8\u00109J\u001a\u0010<\u001a\u00020;2\b\u0010:\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b<\u0010=R\u001b\u00100\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b0\u0010>\u001a\u0004\b?\u0010\u0004R\u001b\u0010!\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b!\u0010>\u001a\u0004\b@\u0010\u0004R\u001b\u00103\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b3\u0010>\u001a\u0004\bA\u0010\u0004R\u001b\u00104\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b4\u0010>\u001a\u0004\bB\u0010\u0004R\u001b\u0010,\u001a\u0004\u0018\u00010\u00158\u0006@\u0006¢\u0006\f\n\u0004\b,\u0010C\u001a\u0004\bD\u0010\u0017R\u001b\u0010+\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b+\u0010>\u001a\u0004\bE\u0010\u0004R\u001b\u0010#\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b#\u0010>\u001a\u0004\bF\u0010\u0004R-\u0010%\u001a\u0016\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u0002\u0018\u0001`\t8\u0006@\u0006¢\u0006\f\n\u0004\b%\u0010G\u001a\u0004\bH\u0010\u000bR\u001b\u0010&\u001a\u0004\u0018\u00010\r8\u0006@\u0006¢\u0006\f\n\u0004\b&\u0010I\u001a\u0004\bJ\u0010\u000fR\u001b\u0010'\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b'\u0010>\u001a\u0004\bK\u0010\u0004R\u001b\u0010*\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b*\u0010>\u001a\u0004\bL\u0010\u0004R\u001b\u0010-\u001a\u0004\u0018\u00010\u00158\u0006@\u0006¢\u0006\f\n\u0004\b-\u0010C\u001a\u0004\bM\u0010\u0017R-\u0010$\u001a\u0016\u0012\u0004\u0012\u00020\b\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\b\u0018\u0001`\t8\u0006@\u0006¢\u0006\f\n\u0004\b$\u0010G\u001a\u0004\bN\u0010\u000bR\u001b\u0010.\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b.\u0010>\u001a\u0004\bO\u0010\u0004R\u001b\u0010\"\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\"\u0010>\u001a\u0004\bP\u0010\u0004R\u001b\u0010)\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b)\u0010>\u001a\u0004\bQ\u0010\u0004R\u001b\u00102\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b2\u0010>\u001a\u0004\bR\u0010\u0004R-\u0010/\u001a\u0016\u0012\u0004\u0012\u00020\u001a\u0018\u00010\u0007j\n\u0012\u0004\u0012\u00020\u001a\u0018\u0001`\t8\u0006@\u0006¢\u0006\f\n\u0004\b/\u0010G\u001a\u0004\bS\u0010\u000bR\u001b\u00101\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b1\u0010>\u001a\u0004\bT\u0010\u0004R\u001b\u0010(\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b(\u0010>\u001a\u0004\bU\u0010\u0004¨\u0006X"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/DarkPlayDetailBean;", "", "", "component1", "()Ljava/lang/String;", "component2", "component3", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/BannerMedia;", "Lkotlin/collections/ArrayList;", "component4", "()Ljava/util/ArrayList;", "component5", "Lcom/jbzd/media/movecartoons/bean/response/Cert;", "component6", "()Lcom/jbzd/media/movecartoons/bean/response/Cert;", "component7", "component8", "component9", "component10", "component11", "", "component12", "()Ljava/lang/Integer;", "component13", "component14", "Lcom/jbzd/media/movecartoons/bean/response/ChatService;", "component15", "component16", "component17", "component18", "component19", "component20", "id", "name", "img", "media", "tags", "cert", "age", "height", ActivityChooserModel.ATTRIBUTE_WEIGHT, "cup", "price", "face_price", "body_price", "service1", "service2", "description", VideoTypeBean.video_type_point, "deposit", "final_payment", "confirm_message", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/util/ArrayList;Lcom/jbzd/media/movecartoons/bean/response/Cert;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/DarkPlayDetailBean;", "toString", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getDescription", "getId", "getFinal_payment", "getConfirm_message", "Ljava/lang/Integer;", "getFace_price", "getPrice", "getImg", "Ljava/util/ArrayList;", "getTags", "Lcom/jbzd/media/movecartoons/bean/response/Cert;", "getCert", "getAge", "getCup", "getBody_price", "getMedia", "getService1", "getName", "getWeight", "getDeposit", "getService2", "getPoint", "getHeight", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/util/ArrayList;Lcom/jbzd/media/movecartoons/bean/response/Cert;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class DarkPlayDetailBean {

    @Nullable
    private final String age;

    @Nullable
    private final Integer body_price;

    @Nullable
    private final Cert cert;

    @Nullable
    private final String confirm_message;

    @Nullable
    private final String cup;

    @Nullable
    private final String deposit;

    @Nullable
    private final String description;

    @Nullable
    private final Integer face_price;

    @Nullable
    private final String final_payment;

    @Nullable
    private final String height;

    @Nullable
    private final String id;

    @Nullable
    private final String img;

    @Nullable
    private final ArrayList<BannerMedia> media;

    @Nullable
    private final String name;

    @Nullable
    private final String point;

    @Nullable
    private final String price;

    @Nullable
    private final String service1;

    @Nullable
    private final ArrayList<ChatService> service2;

    @Nullable
    private final ArrayList<String> tags;

    @Nullable
    private final String weight;

    public DarkPlayDetailBean() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 1048575, null);
    }

    public DarkPlayDetailBean(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable ArrayList<BannerMedia> arrayList, @Nullable ArrayList<String> arrayList2, @Nullable Cert cert, @Nullable String str4, @Nullable String str5, @Nullable String str6, @Nullable String str7, @Nullable String str8, @Nullable Integer num, @Nullable Integer num2, @Nullable String str9, @Nullable ArrayList<ChatService> arrayList3, @Nullable String str10, @Nullable String str11, @Nullable String str12, @Nullable String str13, @Nullable String str14) {
        this.id = str;
        this.name = str2;
        this.img = str3;
        this.media = arrayList;
        this.tags = arrayList2;
        this.cert = cert;
        this.age = str4;
        this.height = str5;
        this.weight = str6;
        this.cup = str7;
        this.price = str8;
        this.face_price = num;
        this.body_price = num2;
        this.service1 = str9;
        this.service2 = arrayList3;
        this.description = str10;
        this.point = str11;
        this.deposit = str12;
        this.final_payment = str13;
        this.confirm_message = str14;
    }

    @Nullable
    /* renamed from: component1, reason: from getter */
    public final String getId() {
        return this.id;
    }

    @Nullable
    /* renamed from: component10, reason: from getter */
    public final String getCup() {
        return this.cup;
    }

    @Nullable
    /* renamed from: component11, reason: from getter */
    public final String getPrice() {
        return this.price;
    }

    @Nullable
    /* renamed from: component12, reason: from getter */
    public final Integer getFace_price() {
        return this.face_price;
    }

    @Nullable
    /* renamed from: component13, reason: from getter */
    public final Integer getBody_price() {
        return this.body_price;
    }

    @Nullable
    /* renamed from: component14, reason: from getter */
    public final String getService1() {
        return this.service1;
    }

    @Nullable
    public final ArrayList<ChatService> component15() {
        return this.service2;
    }

    @Nullable
    /* renamed from: component16, reason: from getter */
    public final String getDescription() {
        return this.description;
    }

    @Nullable
    /* renamed from: component17, reason: from getter */
    public final String getPoint() {
        return this.point;
    }

    @Nullable
    /* renamed from: component18, reason: from getter */
    public final String getDeposit() {
        return this.deposit;
    }

    @Nullable
    /* renamed from: component19, reason: from getter */
    public final String getFinal_payment() {
        return this.final_payment;
    }

    @Nullable
    /* renamed from: component2, reason: from getter */
    public final String getName() {
        return this.name;
    }

    @Nullable
    /* renamed from: component20, reason: from getter */
    public final String getConfirm_message() {
        return this.confirm_message;
    }

    @Nullable
    /* renamed from: component3, reason: from getter */
    public final String getImg() {
        return this.img;
    }

    @Nullable
    public final ArrayList<BannerMedia> component4() {
        return this.media;
    }

    @Nullable
    public final ArrayList<String> component5() {
        return this.tags;
    }

    @Nullable
    /* renamed from: component6, reason: from getter */
    public final Cert getCert() {
        return this.cert;
    }

    @Nullable
    /* renamed from: component7, reason: from getter */
    public final String getAge() {
        return this.age;
    }

    @Nullable
    /* renamed from: component8, reason: from getter */
    public final String getHeight() {
        return this.height;
    }

    @Nullable
    /* renamed from: component9, reason: from getter */
    public final String getWeight() {
        return this.weight;
    }

    @NotNull
    public final DarkPlayDetailBean copy(@Nullable String id, @Nullable String name, @Nullable String img, @Nullable ArrayList<BannerMedia> media, @Nullable ArrayList<String> tags, @Nullable Cert cert, @Nullable String age, @Nullable String height, @Nullable String weight, @Nullable String cup, @Nullable String price, @Nullable Integer face_price, @Nullable Integer body_price, @Nullable String service1, @Nullable ArrayList<ChatService> service2, @Nullable String description, @Nullable String point, @Nullable String deposit, @Nullable String final_payment, @Nullable String confirm_message) {
        return new DarkPlayDetailBean(id, name, img, media, tags, cert, age, height, weight, cup, price, face_price, body_price, service1, service2, description, point, deposit, final_payment, confirm_message);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof DarkPlayDetailBean)) {
            return false;
        }
        DarkPlayDetailBean darkPlayDetailBean = (DarkPlayDetailBean) other;
        return Intrinsics.areEqual(this.id, darkPlayDetailBean.id) && Intrinsics.areEqual(this.name, darkPlayDetailBean.name) && Intrinsics.areEqual(this.img, darkPlayDetailBean.img) && Intrinsics.areEqual(this.media, darkPlayDetailBean.media) && Intrinsics.areEqual(this.tags, darkPlayDetailBean.tags) && Intrinsics.areEqual(this.cert, darkPlayDetailBean.cert) && Intrinsics.areEqual(this.age, darkPlayDetailBean.age) && Intrinsics.areEqual(this.height, darkPlayDetailBean.height) && Intrinsics.areEqual(this.weight, darkPlayDetailBean.weight) && Intrinsics.areEqual(this.cup, darkPlayDetailBean.cup) && Intrinsics.areEqual(this.price, darkPlayDetailBean.price) && Intrinsics.areEqual(this.face_price, darkPlayDetailBean.face_price) && Intrinsics.areEqual(this.body_price, darkPlayDetailBean.body_price) && Intrinsics.areEqual(this.service1, darkPlayDetailBean.service1) && Intrinsics.areEqual(this.service2, darkPlayDetailBean.service2) && Intrinsics.areEqual(this.description, darkPlayDetailBean.description) && Intrinsics.areEqual(this.point, darkPlayDetailBean.point) && Intrinsics.areEqual(this.deposit, darkPlayDetailBean.deposit) && Intrinsics.areEqual(this.final_payment, darkPlayDetailBean.final_payment) && Intrinsics.areEqual(this.confirm_message, darkPlayDetailBean.confirm_message);
    }

    @Nullable
    public final String getAge() {
        return this.age;
    }

    @Nullable
    public final Integer getBody_price() {
        return this.body_price;
    }

    @Nullable
    public final Cert getCert() {
        return this.cert;
    }

    @Nullable
    public final String getConfirm_message() {
        return this.confirm_message;
    }

    @Nullable
    public final String getCup() {
        return this.cup;
    }

    @Nullable
    public final String getDeposit() {
        return this.deposit;
    }

    @Nullable
    public final String getDescription() {
        return this.description;
    }

    @Nullable
    public final Integer getFace_price() {
        return this.face_price;
    }

    @Nullable
    public final String getFinal_payment() {
        return this.final_payment;
    }

    @Nullable
    public final String getHeight() {
        return this.height;
    }

    @Nullable
    public final String getId() {
        return this.id;
    }

    @Nullable
    public final String getImg() {
        return this.img;
    }

    @Nullable
    public final ArrayList<BannerMedia> getMedia() {
        return this.media;
    }

    @Nullable
    public final String getName() {
        return this.name;
    }

    @Nullable
    public final String getPoint() {
        return this.point;
    }

    @Nullable
    public final String getPrice() {
        return this.price;
    }

    @Nullable
    public final String getService1() {
        return this.service1;
    }

    @Nullable
    public final ArrayList<ChatService> getService2() {
        return this.service2;
    }

    @Nullable
    public final ArrayList<String> getTags() {
        return this.tags;
    }

    @Nullable
    public final String getWeight() {
        return this.weight;
    }

    public int hashCode() {
        String str = this.id;
        int hashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.name;
        int hashCode2 = (hashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.img;
        int hashCode3 = (hashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        ArrayList<BannerMedia> arrayList = this.media;
        int hashCode4 = (hashCode3 + (arrayList == null ? 0 : arrayList.hashCode())) * 31;
        ArrayList<String> arrayList2 = this.tags;
        int hashCode5 = (hashCode4 + (arrayList2 == null ? 0 : arrayList2.hashCode())) * 31;
        Cert cert = this.cert;
        int hashCode6 = (hashCode5 + (cert == null ? 0 : cert.hashCode())) * 31;
        String str4 = this.age;
        int hashCode7 = (hashCode6 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.height;
        int hashCode8 = (hashCode7 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.weight;
        int hashCode9 = (hashCode8 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.cup;
        int hashCode10 = (hashCode9 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.price;
        int hashCode11 = (hashCode10 + (str8 == null ? 0 : str8.hashCode())) * 31;
        Integer num = this.face_price;
        int hashCode12 = (hashCode11 + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.body_price;
        int hashCode13 = (hashCode12 + (num2 == null ? 0 : num2.hashCode())) * 31;
        String str9 = this.service1;
        int hashCode14 = (hashCode13 + (str9 == null ? 0 : str9.hashCode())) * 31;
        ArrayList<ChatService> arrayList3 = this.service2;
        int hashCode15 = (hashCode14 + (arrayList3 == null ? 0 : arrayList3.hashCode())) * 31;
        String str10 = this.description;
        int hashCode16 = (hashCode15 + (str10 == null ? 0 : str10.hashCode())) * 31;
        String str11 = this.point;
        int hashCode17 = (hashCode16 + (str11 == null ? 0 : str11.hashCode())) * 31;
        String str12 = this.deposit;
        int hashCode18 = (hashCode17 + (str12 == null ? 0 : str12.hashCode())) * 31;
        String str13 = this.final_payment;
        int hashCode19 = (hashCode18 + (str13 == null ? 0 : str13.hashCode())) * 31;
        String str14 = this.confirm_message;
        return hashCode19 + (str14 != null ? str14.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("DarkPlayDetailBean(id=");
        m586H.append((Object) this.id);
        m586H.append(", name=");
        m586H.append((Object) this.name);
        m586H.append(", img=");
        m586H.append((Object) this.img);
        m586H.append(", media=");
        m586H.append(this.media);
        m586H.append(", tags=");
        m586H.append(this.tags);
        m586H.append(", cert=");
        m586H.append(this.cert);
        m586H.append(", age=");
        m586H.append((Object) this.age);
        m586H.append(", height=");
        m586H.append((Object) this.height);
        m586H.append(", weight=");
        m586H.append((Object) this.weight);
        m586H.append(", cup=");
        m586H.append((Object) this.cup);
        m586H.append(", price=");
        m586H.append((Object) this.price);
        m586H.append(", face_price=");
        m586H.append(this.face_price);
        m586H.append(", body_price=");
        m586H.append(this.body_price);
        m586H.append(", service1=");
        m586H.append((Object) this.service1);
        m586H.append(", service2=");
        m586H.append(this.service2);
        m586H.append(", description=");
        m586H.append((Object) this.description);
        m586H.append(", point=");
        m586H.append((Object) this.point);
        m586H.append(", deposit=");
        m586H.append((Object) this.deposit);
        m586H.append(", final_payment=");
        m586H.append((Object) this.final_payment);
        m586H.append(", confirm_message=");
        m586H.append((Object) this.confirm_message);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ DarkPlayDetailBean(String str, String str2, String str3, ArrayList arrayList, ArrayList arrayList2, Cert cert, String str4, String str5, String str6, String str7, String str8, Integer num, Integer num2, String str9, ArrayList arrayList3, String str10, String str11, String str12, String str13, String str14, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? "" : str, (i2 & 2) != 0 ? "" : str2, (i2 & 4) != 0 ? "" : str3, (i2 & 8) != 0 ? null : arrayList, (i2 & 16) != 0 ? null : arrayList2, (i2 & 32) != 0 ? null : cert, (i2 & 64) != 0 ? "" : str4, (i2 & 128) != 0 ? "" : str5, (i2 & 256) != 0 ? "" : str6, (i2 & 512) != 0 ? "" : str7, (i2 & 1024) != 0 ? "" : str8, (i2 & 2048) != 0 ? 0 : num, (i2 & 4096) != 0 ? 0 : num2, (i2 & 8192) != 0 ? "" : str9, (i2 & 16384) != 0 ? null : arrayList3, (i2 & 32768) != 0 ? "" : str10, (i2 & 65536) != 0 ? "" : str11, (i2 & 131072) != 0 ? "" : str12, (i2 & 262144) != 0 ? "" : str13, (i2 & 524288) != 0 ? "" : str14);
    }
}
