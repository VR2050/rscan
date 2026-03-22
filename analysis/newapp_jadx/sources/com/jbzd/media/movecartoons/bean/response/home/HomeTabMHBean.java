package com.jbzd.media.movecartoons.bean.response.home;

import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import java.util.ArrayList;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u0000 K2\u00020\u0001:\u0001KB\u0007¢\u0006\u0004\bI\u0010JJ\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004R\"\u0010\u0006\u001a\u00020\u00058\u0016@\u0016X\u0096\u000e¢\u0006\u0012\n\u0004\b\u0006\u0010\u0007\u001a\u0004\b\b\u0010\t\"\u0004\b\n\u0010\u000bR$\u0010\f\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u0004\"\u0004\b\u000f\u0010\u0010R$\u0010\u0011\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0011\u0010\r\u001a\u0004\b\u0012\u0010\u0004\"\u0004\b\u0013\u0010\u0010R6\u0010\u0017\u001a\u0016\u0012\u0004\u0012\u00020\u0015\u0018\u00010\u0014j\n\u0012\u0004\u0012\u00020\u0015\u0018\u0001`\u00168\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001cR$\u0010\u001d\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001d\u0010\r\u001a\u0004\b\u001e\u0010\u0004\"\u0004\b\u001f\u0010\u0010R$\u0010 \u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b \u0010\r\u001a\u0004\b!\u0010\u0004\"\u0004\b\"\u0010\u0010R\"\u0010#\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010\u0007\u001a\u0004\b$\u0010\t\"\u0004\b%\u0010\u000bR$\u0010&\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b&\u0010\r\u001a\u0004\b'\u0010\u0004\"\u0004\b(\u0010\u0010R\"\u0010)\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b)\u0010\u0007\u001a\u0004\b*\u0010\t\"\u0004\b+\u0010\u000bR\"\u0010,\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b,\u0010\u0007\u001a\u0004\b-\u0010\t\"\u0004\b.\u0010\u000bR6\u00100\u001a\u0016\u0012\u0004\u0012\u00020/\u0018\u00010\u0014j\n\u0012\u0004\u0012\u00020/\u0018\u0001`\u00168\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b0\u0010\u0018\u001a\u0004\b1\u0010\u001a\"\u0004\b2\u0010\u001cR$\u00103\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b3\u0010\r\u001a\u0004\b4\u0010\u0004\"\u0004\b5\u0010\u0010R\"\u00106\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b6\u0010\u0007\u001a\u0004\b7\u0010\t\"\u0004\b8\u0010\u000bR$\u00109\u001a\u0004\u0018\u00010\u00158\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b9\u0010:\u001a\u0004\b;\u0010<\"\u0004\b=\u0010>R6\u0010@\u001a\u0016\u0012\u0004\u0012\u00020?\u0018\u00010\u0014j\n\u0012\u0004\u0012\u00020?\u0018\u0001`\u00168\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b@\u0010\u0018\u001a\u0004\bA\u0010\u001a\"\u0004\bB\u0010\u001cR\"\u0010C\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bC\u0010\u0007\u001a\u0004\bD\u0010\t\"\u0004\bE\u0010\u000bR\"\u0010F\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bF\u0010\u0007\u001a\u0004\bG\u0010\t\"\u0004\bH\u0010\u000b¨\u0006L"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabMHBean;", "Lb/b/a/a/a/j/a;", "", "whatType", "()Ljava/lang/String;", "", "itemType", "I", "getItemType", "()I", "setItemType", "(I)V", "show_change_btn", "Ljava/lang/String;", "getShow_change_btn", "setShow_change_btn", "(Ljava/lang/String;)V", "id", "getId", "setId", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "Lkotlin/collections/ArrayList;", "banner", "Ljava/util/ArrayList;", "getBanner", "()Ljava/util/ArrayList;", "setBanner", "(Ljava/util/ArrayList;)V", "page_size", "getPage_size", "setPage_size", "name", "getName", "setName", "style", "getStyle", "setStyle", "more_canvas", "getMore_canvas", "setMore_canvas", "type", "getType", "setType", "number", "getNumber", "setNumber", "Lcom/jbzd/media/movecartoons/bean/response/HomeBlockBean;", "block", "getBlock", "setBlock", "filter", "getFilter", "setFilter", "show_type", "getShow_type", "setShow_type", "ad", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "getAd", "()Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "setAd", "(Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;)V", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "items", "getItems", "setItems", "watch_limit", "getWatch_limit", "setWatch_limit", "nextPage", "getNextPage", "setNextPage", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeTabMHBean implements InterfaceC1296a {
    public static final int type_landscape_2_columns = 2;
    public static final int type_landscape_single = 3;
    public static final int type_landscape_single_2_columns = 1;
    public static final int type_landscape_slide = 5;
    public static final int type_portrait_3_columns = 4;
    public static final int type_portrait_slide = 6;

    @Nullable
    private AdBean ad;

    @Nullable
    private ArrayList<AdBean> banner;

    @Nullable
    private ArrayList<HomeBlockBean> block;

    @Nullable
    private String filter;

    @Nullable
    private String id;
    private int itemType;

    @Nullable
    private ArrayList<VideoItemBean> items;

    @Nullable
    private String more_canvas;

    @Nullable
    private String name;
    private int nextPage = 2;
    private int number;

    @Nullable
    private String page_size;

    @Nullable
    private String show_change_btn;
    private int show_type;
    private int style;
    private int type;
    private int watch_limit;

    @Nullable
    public final AdBean getAd() {
        return this.ad;
    }

    @Nullable
    public final ArrayList<AdBean> getBanner() {
        return this.banner;
    }

    @Nullable
    public final ArrayList<HomeBlockBean> getBlock() {
        return this.block;
    }

    @Nullable
    public final String getFilter() {
        return this.filter;
    }

    @Nullable
    public final String getId() {
        return this.id;
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        return this.itemType;
    }

    @Nullable
    public final ArrayList<VideoItemBean> getItems() {
        return this.items;
    }

    @Nullable
    public final String getMore_canvas() {
        return this.more_canvas;
    }

    @Nullable
    public final String getName() {
        return this.name;
    }

    public final int getNextPage() {
        return this.nextPage;
    }

    public final int getNumber() {
        return this.number;
    }

    @Nullable
    public final String getPage_size() {
        return this.page_size;
    }

    @Nullable
    public final String getShow_change_btn() {
        return this.show_change_btn;
    }

    public final int getShow_type() {
        return this.show_type;
    }

    public final int getStyle() {
        return this.style;
    }

    public final int getType() {
        return this.type;
    }

    public final int getWatch_limit() {
        return this.watch_limit;
    }

    public final void setAd(@Nullable AdBean adBean) {
        this.ad = adBean;
    }

    public final void setBanner(@Nullable ArrayList<AdBean> arrayList) {
        this.banner = arrayList;
    }

    public final void setBlock(@Nullable ArrayList<HomeBlockBean> arrayList) {
        this.block = arrayList;
    }

    public final void setFilter(@Nullable String str) {
        this.filter = str;
    }

    public final void setId(@Nullable String str) {
        this.id = str;
    }

    public void setItemType(int i2) {
        this.itemType = i2;
    }

    public final void setItems(@Nullable ArrayList<VideoItemBean> arrayList) {
        this.items = arrayList;
    }

    public final void setMore_canvas(@Nullable String str) {
        this.more_canvas = str;
    }

    public final void setName(@Nullable String str) {
        this.name = str;
    }

    public final void setNextPage(int i2) {
        this.nextPage = i2;
    }

    public final void setNumber(int i2) {
        this.number = i2;
    }

    public final void setPage_size(@Nullable String str) {
        this.page_size = str;
    }

    public final void setShow_change_btn(@Nullable String str) {
        this.show_change_btn = str;
    }

    public final void setShow_type(int i2) {
        this.show_type = i2;
    }

    public final void setStyle(int i2) {
        this.style = i2;
    }

    public final void setType(int i2) {
        this.type = i2;
    }

    public final void setWatch_limit(int i2) {
        this.watch_limit = i2;
    }

    @NotNull
    public final String whatType() {
        int i2 = this.type;
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? "不明" : "91暗网" : "深网" : "浅网";
    }
}
