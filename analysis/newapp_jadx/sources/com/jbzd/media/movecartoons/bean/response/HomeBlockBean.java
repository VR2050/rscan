package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.ArrayList;
import java.util.List;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeBlockBean implements InterfaceC1296a {
    public static final int type_2_3_video = 6;
    public static final int type_3_3_video = 7;
    public static final int type_AD = 1;
    public static final int type_ADs = 2;
    public static final int type_banner = 1;
    public static final int type_big_4small_video = 5;
    public static final int type_collection_long = 2;
    public static final int type_collection_short = 3;
    public static final int type_hor_long_video = 8;
    public static final int type_hor_short_video = 9;
    public static final int type_long = 4;
    public static final int type_module_landscape_grid_change = 6;
    public static final int type_module_landscape_hor = 8;
    public static final int type_module_long_grid_big = 7;
    public static final int type_module_portrait_grid = 9;
    public static final int type_module_portrait_hor = 10;
    public static final int type_more_good = 0;
    public static final int type_pre_video = 4;
    public static final int type_short = 5;
    public static final int type_unknown = -1;

    /* renamed from: ad */
    public AdBean f9954ad;
    public ArrayList<AdBean> banner;
    public String filter;
    public List<VideoItemBean> home_long_videos;
    public String ico;

    /* renamed from: id */
    public String f9955id;
    public ArrayList<VideoItemBean> items;
    public VideoItemBean long_video;
    public HomeVideoGroupBean long_video_group;
    public List<VideoItemBean> long_videos;
    public HomeModuleBean module;
    public String name;
    public String page;
    public String page_size;
    public FoundPickBean pickBean;
    public HomeVideoGroupBean short_video_group;
    public List<VideoItemBean> short_videos;
    public int style;
    public boolean isLastTwoLongs = false;
    public int nextPage = 2;
    public int realPage = 1;

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        int i2 = this.style;
        switch (i2) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
                return i2;
            default:
                return -1;
        }
    }
}
