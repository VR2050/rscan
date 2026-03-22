package com.jbzd.media.movecartoons.bean.response.system;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.response.SettledLevelBean;
import com.jbzd.media.movecartoons.bean.response.TypeAdBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes2.dex */
public class SystemInfoBean {
    public String account_login_tips;

    /* renamed from: ad */
    public List<AdBean> f10031ad;
    public String ad_auto_jump;
    public String ad_show_time;
    public String ai_post_nav_name;
    public String app_layer_ad_show_method;
    public String app_start_ad_show_method;
    public String auto_jump_ad;
    public AdBean bottom_ad;
    public List<AdBean> bottom_ads;
    public String can_use;
    public List<MainMenusBean> cartoon_video_nav;
    public String cdn_header;
    public List<CdnPing> cdn_ping;
    public String chat_url;
    public List<AdBean> comics_detail_ads_top;
    public List<MainMenusBean> comics_nav;
    public List<AdBean> dark_index_banner;
    public List<MainMenusBean> dark_post_nav;
    public List<MainMenusBean> dark_tabs;
    public String dark_tips;
    public List<MainMenusBean> dark_video_nav;
    public String day_free;
    public String debug_key;
    public List<AdBean> deep_index_banner;
    public List<MainMenusBean> deep_tabs;
    public String deep_tips;
    public List<MainMenusBean> deep_video_nav;
    public List<String> domains;
    public String download_url;
    public String error_msg;
    public List<AdBean> find_banner;
    public String find_name;
    public List<MainMenusBean> find_tabs;
    public String group_link;
    public AdBean home_ad;
    public List<AdBean> home_ads;
    public String img_key;
    public String index_short_name;
    public String ios_url;
    public String is_verify;
    public List<TypeAdBean> layer;
    public List<AdBean> layer_ad;
    public String min_version;
    public NoticeBean movie_notice;
    public List<AdBean> my_app_banner;
    public List<AdBean> my_index_banner;
    public List<MainMenusBean> normal_video_nav;
    public NoticeBean notice;
    public List<AdBean> novel_detail_ads_top;
    public List<MainMenusBean> novel_nav;
    public List<AdBean> play_index_banner_1;
    public List<AdBean> play_index_banner_2;
    public NoticeBean play_notice_1;
    public NoticeBean play_notice_2;
    public List<MainMenusBean> post_nav;
    public NoticeBean post_notice;
    public List<AdBean> right_float_ad;
    public String service_email;
    public String service_link;
    public List<AdBean> shallow_index_banner;
    public List<MainMenusBean> short_nav;
    public List<MainMenusBean> short_tabs;
    public String site_url;
    public String system_head_img;
    public String tab2_name;
    public String tab3_name;
    public List<MainMenusBean> tabs;
    public String template;
    public TokenBean token;
    public String total_video;
    public String upload_file_max_length;
    public String upload_file_query_url;
    public String upload_file_url;
    public String upload_image_max_length;
    public String upload_image_url;
    public String upload_url;
    public String version;
    public String version_description;
    public String webview_ai_url;
    public String withdraw_fee;
    public String withdraw_min;
    public String withdraw_ratio;
    public String withdraw_rule;
    public String withdraw_tips;
    public List<PointMaxBean> works_max_point;
    public String app_store = "";
    public String upload_token = "";
    public String welcome_msg = "";
    public String nude_welcome_msg = "";
    public String dating_welcome_msg = "";
    public String money_welcome_msg = "";
    public String customer_system_status = "";

    public class CdnPing {
        public String name;
        public String ping_url;

        public CdnPing() {
        }
    }

    public List<SettledLevelBean> getShowMaxPoint() {
        ArrayList arrayList = new ArrayList();
        if (this.works_max_point == null) {
            return arrayList;
        }
        for (int i2 = 0; i2 < this.works_max_point.size(); i2++) {
            PointMaxBean pointMaxBean = this.works_max_point.get(i2);
            if (TextUtils.equals(pointMaxBean.key, "1")) {
                StringBuilder m586H = C1499a.m586H("拥有自己的传媒品牌，拥有专业拍摄团队，后期视\n频剪辑制作团队，最优质的内容创作者\n收益分成比例 ");
                m586H.append(pointMaxBean.ratio_column);
                arrayList.add(new SettledLevelBean("专业工作室", m586H.toString(), C1499a.m582D(C1499a.m586H("视频售价  0-"), pointMaxBean.max, "钻石")));
            } else if (TextUtils.equals(pointMaxBean.key, "2")) {
                StringBuilder m586H2 = C1499a.m586H("个人真实自拍原创视频，视频内带暗网品牌植入，\n能够稳定持续生产视频\n收益分成比例 ");
                m586H2.append(pointMaxBean.ratio_column);
                arrayList.add(new SettledLevelBean("原创大神", m586H2.toString(), C1499a.m582D(C1499a.m586H("视频售价  0-"), pointMaxBean.max, "钻石")));
            } else {
                StringBuilder m586H3 = C1499a.m586H("平日爱好收集整理视频，视频内容来源于网络，非\n本人原创\n收益分成比例 ");
                m586H3.append(pointMaxBean.ratio_column);
                arrayList.add(new SettledLevelBean("资深撸友", m586H3.toString(), C1499a.m582D(C1499a.m586H("视频售价  0-"), pointMaxBean.max, "钻石")));
            }
        }
        return arrayList;
    }

    public boolean isCanUpdate() {
        String str;
        PackageManager packageManager = C4195m.m4792Y().getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
            Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
            str = packageInfo.versionName;
            Intrinsics.checkNotNullExpressionValue(str, "packageInfo.versionName");
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
            str = "";
        }
        return C2354n.m2389F(str, this.version) == -1;
    }

    public boolean isMustUpdate() {
        String str;
        PackageManager packageManager = C4195m.m4792Y().getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getApp().packageManager");
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo(C4195m.m4792Y().getPackageName(), 0);
            Intrinsics.checkNotNullExpressionValue(packageInfo, "pm.getPackageInfo(Utils.getApp().packageName, 0)");
            str = packageInfo.versionName;
            Intrinsics.checkNotNullExpressionValue(str, "packageInfo.versionName");
        } catch (PackageManager.NameNotFoundException e2) {
            e2.printStackTrace();
            str = "";
        }
        return C2354n.m2389F(str, this.min_version) == -1;
    }

    public List<String> randomSixKeywords(List<String> list) {
        if (list == null || list.size() <= 6) {
            return list;
        }
        ArrayList arrayList = new ArrayList(list);
        Collections.shuffle(arrayList);
        return arrayList.subList(0, 6);
    }
}
