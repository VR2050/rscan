package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.home.HomeTabBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class VideoItemBean implements Serializable, Cloneable {
    public static final String CATEGORY_RAD_DARK = "3";
    public static final String CATEGORY_RAD_DEEP = "2";
    public static final String CATEGORY_RAD_SURFACE = "1";

    /* renamed from: ad */
    public AdBean f9999ad;
    public String avatar;
    public String canvas;
    public String click;
    public String countdown;
    public String date;
    public String deposit_txt;
    public String desc;
    public int downloadSuccessCount;
    public int downloadTotal;
    public String duration;
    public String duration_show;
    public String f_num;
    public String fans;
    public HomeVideoGroupBean group;
    public String group_id;
    public String has_buy;
    public String height;
    public String ico;
    public List<AdBean> ico_ads;

    /* renamed from: id */
    public String f10000id;
    public String img_x;
    public String img_y;
    public String is_follow;
    public String is_free;
    public String is_hate;
    public String is_like;
    public String is_love;
    public String is_top;
    public String is_vip;
    public String like;
    public List<LinkBean> links;
    public String localUrl;
    public HomeTabBean mHomeTabBean;
    public String module_id;
    public String module_name;
    public String money;
    public String name;
    public String nickname;
    public String number;
    public String pay_type;
    public String play_id;
    public List<VideoDetailBean.PlayLinksBean> play_links;
    public String play_num;
    public String preview_link;
    public List<LinkBean> preview_links;
    public String progress;
    public String promotion_link;
    public String promotion_title;
    public String published_at;
    public String service_txt;
    public String status;
    public String status_text;
    public String status_txt;
    public List<TagBean> tags;
    public String tips;
    public String type;
    public String updated_at;
    public int upgrade_vip_countdown;
    public String upgrade_vip_tips;
    public String user_id;
    public String video_id;
    public VideoDetailBean.VideoUserBean video_user;
    public String vip_point;
    public String width;
    public String play_error_type = "";
    public boolean isSelect = false;
    public boolean isPreviewOver = true;
    public String img_type = "";
    public String link_name = "";
    public String link = "";
    public String love = "";
    public String downloadStatus = "";
    public int curPlayDuration = 0;
    public int realPage = 1;
    public boolean isMore = false;
    public Integer watch_limit = 0;

    /* JADX WARN: Removed duplicated region for block: B:13:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:5:0x001c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void doCountdown() {
        /*
            r6 = this;
            java.lang.String r0 = r6.countdown
            boolean r1 = android.text.TextUtils.isEmpty(r0)
            r2 = 0
            if (r1 == 0) goto La
            goto L19
        La:
            kotlin.jvm.internal.Intrinsics.checkNotNull(r0)     // Catch: java.lang.Exception -> L19
            double r0 = java.lang.Double.parseDouble(r0)     // Catch: java.lang.Exception -> L19
            r3 = 0
            int r5 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r5 <= 0) goto L19
            r0 = 1
            goto L1a
        L19:
            r0 = 0
        L1a:
            if (r0 == 0) goto L3c
            java.lang.String r0 = r6.countdown     // Catch: java.lang.Exception -> L23
            int r2 = java.lang.Integer.parseInt(r0)     // Catch: java.lang.Exception -> L23
            goto L27
        L23:
            r0 = move-exception
            r0.printStackTrace()
        L27:
            int r2 = r2 + (-1)
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            r0.append(r2)
            java.lang.String r1 = ""
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            r6.countdown = r0
        L3c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.bean.response.VideoItemBean.doCountdown():void");
    }

    public String getAllTagText() {
        if (this.tags == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        Iterator<TagBean> it = this.tags.iterator();
        while (it.hasNext()) {
            sb.append(it.next().name);
            sb.append("｜");
        }
        return sb.substring(0, sb.length() - 1);
    }

    public String getBasicType() {
        return isImage() ? "image" : "video";
    }

    public String getDuration_show() {
        if (this.duration.startsWith("00:")) {
            this.duration_show = this.duration.replace("00:", "");
        } else {
            this.duration_show = this.duration;
        }
        return this.duration_show;
    }

    public boolean getHasFollow() {
        return TextUtils.equals(this.is_follow, "y");
    }

    public boolean getHasHate() {
        return TextUtils.equals(this.is_hate, "y");
    }

    public boolean getIsAd() {
        return this.type.equals("ad");
    }

    public boolean getIsFreeVideo() {
        return (getIsMoneyVideo() || getIsVipVideo()) ? false : true;
    }

    public boolean getIsMoneyVideo() {
        String str = this.money;
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        try {
            Intrinsics.checkNotNull(str);
            return Double.parseDouble(str) > ShadowDrawableWrapper.COS_45;
        } catch (Exception unused) {
            return false;
        }
    }

    public boolean getIsVipVideo() {
        return !getIsMoneyVideo() && TextUtils.equals(this.pay_type, VideoTypeBean.video_type_vip);
    }

    public int getLikeNum() {
        try {
            return Integer.parseInt(this.like);
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public List<String> getLinksTxt() {
        ArrayList arrayList = new ArrayList();
        if (this.links == null) {
            return arrayList;
        }
        for (int i2 = 0; i2 < this.links.size(); i2++) {
            arrayList.add(this.links.get(i2).getName());
        }
        return arrayList;
    }

    public int getLoveNum() {
        try {
            return Integer.parseInt(this.love);
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public String getParamType() {
        return isImage() ? "2" : "1";
    }

    public String getPlayLink() {
        List<VideoDetailBean.PlayLinksBean> list = this.play_links;
        return list != null ? this.play_error_type == "none" ? list.get(0).m3u8_url : list.get(0).preview_m3u8_url : "";
    }

    public String getPlayLinkNormal() {
        return this.play_links.get(0).name;
    }

    public boolean hasGroup() {
        return this.group != null;
    }

    public boolean isFree() {
        return TextUtils.equals(this.is_free, "y");
    }

    public boolean isImage() {
        return TextUtils.equals("image", this.canvas);
    }

    public boolean isLong() {
        return TextUtils.equals("long", this.canvas);
    }

    public boolean isShort() {
        return TextUtils.equals("short", this.canvas);
    }

    public boolean isTop() {
        String str = this.is_top;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean likeIsNum() {
        try {
            Integer.parseInt(this.like);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public boolean loveIsNum() {
        try {
            Integer.parseInt(this.love);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public boolean showCountdown() {
        String str = this.countdown;
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        try {
            Intrinsics.checkNotNull(str);
            return Double.parseDouble(str) > ShadowDrawableWrapper.COS_45;
        } catch (Exception unused) {
            return false;
        }
    }

    public boolean showPromotion() {
        return !TextUtils.isEmpty(this.promotion_title);
    }
}
