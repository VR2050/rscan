package com.jbzd.media.movecartoons.bean.response.novel;

import com.jbzd.media.movecartoons.bean.response.comicsinfo.InnerAd;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.User;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class NovelDetailInfoBean implements Serializable {

    /* renamed from: ad */
    public AdBean f10027ad;
    public InnerAd adv_float;
    public InnerAd adv_full;
    public InnerAd adv_inside;
    public String alias_name;
    public String category;
    public String category_name;
    public ArrayList<NovelChapter> chapter;
    public String chapter_count;
    public String chapter_show_num;
    public String click;
    public String comment;
    public String description;
    public String favorite;
    public String has_favorite;
    public String ico;

    /* renamed from: id */
    public String f10028id;
    public String img;
    public String is_adult;
    public String last_chapter_id;
    public String money;
    public String name;
    public String pay_type;
    public String related_filter;
    public ArrayList<NovelItemsBean> related_items;
    public String status;
    public String status_text;
    public String sub_title;
    public List<Tags> tags;
    public String type;
    public String update_date;
    public String update_status;
    public User user;

    public String getAlias_name() {
        return this.alias_name;
    }

    public String getCategory() {
        return this.category;
    }

    public ArrayList<NovelChapter> getChapter() {
        return this.chapter;
    }

    public String getChapter_count() {
        return this.chapter_count;
    }

    public String getChapter_show_num() {
        return this.chapter_show_num;
    }

    public String getClick() {
        return this.click;
    }

    public String getComment() {
        return this.comment;
    }

    public String getDescription() {
        return this.description;
    }

    public String getFavorite() {
        return this.favorite;
    }

    public String getHas_favorite() {
        return this.has_favorite;
    }

    public String getIco() {
        return this.ico;
    }

    public String getId() {
        return this.f10028id;
    }

    public String getImg() {
        return this.img;
    }

    public String getIs_adult() {
        return this.is_adult;
    }

    public String getLast_chapter_id() {
        return this.last_chapter_id;
    }

    public int getLikeNum() {
        try {
            return Integer.parseInt(this.favorite);
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public String getMoney() {
        return this.money;
    }

    public String getName() {
        return this.name;
    }

    public String getPay_type() {
        return this.pay_type;
    }

    public String getRelated_filter() {
        return this.related_filter;
    }

    public ArrayList<NovelItemsBean> getRelated_items() {
        return this.related_items;
    }

    public String getStatus() {
        return this.status;
    }

    public String getStatus_text() {
        return this.status_text;
    }

    public String getSub_title() {
        return this.sub_title;
    }

    public List<Tags> getTags() {
        return this.tags;
    }

    public String getType() {
        return this.type;
    }

    public String getUpdate_date() {
        return this.update_date;
    }

    public String getUpdate_status() {
        return this.update_status;
    }

    public User getUser() {
        return this.user;
    }

    public boolean likeIsNum() {
        try {
            Integer.parseInt(this.favorite);
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public void setAlias_name(String str) {
        this.alias_name = str;
    }

    public void setCategory(String str) {
        this.category = str;
    }

    public void setChapter(ArrayList<NovelChapter> arrayList) {
        this.chapter = arrayList;
    }

    public void setChapter_count(String str) {
        this.chapter_count = str;
    }

    public void setChapter_show_num(String str) {
        this.chapter_show_num = str;
    }

    public void setClick(String str) {
        this.click = str;
    }

    public void setComment(String str) {
        this.comment = str;
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setFavorite(String str) {
        this.favorite = str;
    }

    public void setHas_favorite(String str) {
        this.has_favorite = str;
    }

    public void setIco(String str) {
        this.ico = str;
    }

    public void setId(String str) {
        this.f10028id = str;
    }

    public void setImg(String str) {
        this.img = str;
    }

    public void setIs_adult(String str) {
        this.is_adult = str;
    }

    public void setLast_chapter_id(String str) {
        this.last_chapter_id = str;
    }

    public void setMoney(String str) {
        this.money = str;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setPay_type(String str) {
        this.pay_type = str;
    }

    public void setRelated_filter(String str) {
        this.related_filter = str;
    }

    public void setRelated_items(ArrayList<NovelItemsBean> arrayList) {
        this.related_items = arrayList;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setStatus_text(String str) {
        this.status_text = str;
    }

    public void setSub_title(String str) {
        this.sub_title = str;
    }

    public void setTags(List<Tags> list) {
        this.tags = list;
    }

    public void setType(String str) {
        this.type = str;
    }

    public void setUpdate_date(String str) {
        this.update_date = str;
    }

    public void setUpdate_status(String str) {
        this.update_status = str;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
