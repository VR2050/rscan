package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class UserInfoBean {
    public String account_img;
    public String account_name;
    public String account_slat;
    public String cache_num;
    public String channel_name;
    public String desc;
    public String fans;
    public String follow;
    public String free_num;
    public String gift_point;
    public String group_end_time;
    public String group_id;
    public String group_name;
    public String group_rate;
    public String group_start_time;
    public String group_style;
    public List<String> group_sub_tips;
    public String group_tips;
    public String group_title;
    public List<AdBean> ico_ads;

    /* renamed from: id */
    public String f9992id;
    public String img;
    public String income;
    public String is_password;
    public String is_up;
    public String is_vip;
    public String like;
    public String nickname;
    public String original_point;
    public String parent_id;
    public String parent_name;
    public String phone;
    public String rights_ico;
    public String sex;
    public String share_num;
    public String share_point;
    public String sign;
    public String site_url;
    public String tag_ids;
    public List<TagBean> tags;
    public String total_free_num;
    public String total_user;
    public String user_id;
    public String username;
    public VipGroupBean vip_group;
    public String level = "0";
    public String vip_buy_tips = "";
    public String balance = "";
    public String point = "";
    public Integer total_order = 0;

    public String getGroup_end_time() {
        return this.group_end_time.isEmpty() ? "升级为VIP获取更多权益" : this.group_end_time;
    }

    public boolean getIsAnchorUser() {
        String str = this.is_up;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean getIsVipUser(String str) {
        str.hashCode();
        if (str.equals("1")) {
            String is_vip = this.vip_group.getShallow().is_vip();
            return !(is_vip == null || is_vip.length() == 0) && Intrinsics.areEqual(is_vip, "y");
        }
        if (str.equals("2")) {
            String is_vip2 = this.vip_group.getDeep().is_vip();
            return !(is_vip2 == null || is_vip2.length() == 0) && Intrinsics.areEqual(is_vip2, "y");
        }
        String is_vip3 = this.vip_group.getDark().is_vip();
        return !(is_vip3 == null || is_vip3.length() == 0) && Intrinsics.areEqual(is_vip3, "y");
    }

    public boolean getIsVipUserAnyOne() {
        VipGroupBean vipGroupBean = this.vip_group;
        if (vipGroupBean == null) {
            return false;
        }
        String is_vip = vipGroupBean.getShallow().is_vip();
        if (!(!(is_vip == null || is_vip.length() == 0) && Intrinsics.areEqual(is_vip, "y"))) {
            String is_vip2 = this.vip_group.getDeep().is_vip();
            if (!(!(is_vip2 == null || is_vip2.length() == 0) && Intrinsics.areEqual(is_vip2, "y"))) {
                String is_vip3 = this.vip_group.getDark().is_vip();
                if (!(!(is_vip3 == null || is_vip3.length() == 0) && Intrinsics.areEqual(is_vip3, "y"))) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean isVipUser() {
        String str = this.is_vip;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public int sexy() {
        String str = this.sex;
        str.hashCode();
        if (str.equals("1")) {
            return 1;
        }
        return !str.equals("2") ? 0 : 2;
    }
}
