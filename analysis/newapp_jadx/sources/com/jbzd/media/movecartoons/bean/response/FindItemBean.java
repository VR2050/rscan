package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import java.util.List;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class FindItemBean implements InterfaceC1296a {
    public static final int type_app = 4;
    public static final int type_collection_long = 2;
    public static final int type_collection_short = 3;
    public static final int type_day_select = 5;
    public static final int type_tag = 1;
    public static final int type_unknown = -1;
    public List<AppItemNew> app_items;
    public String desc;
    public HomeVideoGroupBean group_items;

    /* renamed from: id */
    public String f9951id;
    public String name;
    public List<FoundPickBean> pick_items;
    public List<TagBean> tag_items;
    public String type;

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        char c2;
        String str = this.type;
        if (str == null) {
            return -1;
        }
        str.hashCode();
        switch (str.hashCode()) {
            case 49:
                if (str.equals("1")) {
                    c2 = 0;
                    break;
                }
                c2 = 65535;
                break;
            case 50:
            default:
                c2 = 65535;
                break;
            case 51:
                if (str.equals("3")) {
                    c2 = 1;
                    break;
                }
                c2 = 65535;
                break;
            case 52:
                if (str.equals(HomeDataHelper.type_tag)) {
                    c2 = 2;
                    break;
                }
                c2 = 65535;
                break;
            case 53:
                if (str.equals("5")) {
                    c2 = 3;
                    break;
                }
                c2 = 65535;
                break;
            case 54:
                if (str.equals("6")) {
                    c2 = 4;
                    break;
                }
                c2 = 65535;
                break;
        }
        switch (c2) {
        }
        return -1;
    }
}
